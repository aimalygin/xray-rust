//! Sessions in slots, as Xray-core v26.11.9's `slots.go` carries them on
//! a storage that keeps objects by id (Google Drive). Each direction is a
//! ring of slots both ends know by id: segment `n` is written to slot
//! `n % depth` and read from it, with nothing to list. The reader of a
//! direction keeps how far it read in a watermark, and the writer reuses a
//! slot only once that says what was in it before was taken.
//!
//! A slot's description is a frame: `XDRVSL01`, the segment number, a mode
//! (the segment inline, the segment in the body, the end, a failure), the
//! segment's size and CRC-32, and an inline segment, in base64.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use super::gojson;
use super::names::{downlink_prefix, uplink_prefix};
use super::params::Params;
use super::storage::StorageError;
use super::wal::Cancel;

const SLOT_MAGIC: &[u8; 8] = b"XDRVSL01";
const SLOT_HEADER_LEN: usize = 8 + 8 + 1 + 4 + 4;
/// The largest segment that goes in its slot's description, which takes
/// one request less than a body.
pub(crate) const SLOT_INLINE_LIMIT: usize = 14 << 10;
/// Xray-core's `maxSlotIDLen`: the longest slot or watermark id a server takes
/// from a peer's announcement.
#[cfg(test)]
const MAX_SLOT_ID_LEN: usize = 128;
/// So many segments of one size in a row double it, from
/// [`SLOT_INLINE_LIMIT`] up to `segmentBytes`.
const INLINE_RAMP_SEGMENTS: u32 = 8;
/// As the segment writer's: a growing buffer is held at most so many ticks.
const MAX_COALESCED_TICKS: u32 = 8;

pub(crate) const SLOT_INLINE: u8 = 1;
pub(crate) const SLOT_MEDIA: u8 = 2;
pub(crate) const SLOT_END: u8 = 3;
pub(crate) const SLOT_ERR: u8 = 4;

/// The head is asked for between these, a segment behind it soon after it
/// was asked for, then at about the pace segments come.
const SLOT_HUNT_FLOOR: Duration = Duration::from_millis(10);
const SLOT_HUNT_CEILING: Duration = Duration::from_millis(25);
const SLOT_TAIL_MIN: Duration = Duration::from_millis(150);
const SLOT_TAIL_MAX: Duration = Duration::from_millis(800);
const SLOT_FETCH_AHEAD: usize = 12;

const SLOT_ACK_RETRY: Duration = Duration::from_millis(30);
const SLOT_WATERMARK_TTL: Duration = Duration::from_millis(100);
const SLOT_STALL_TIMEOUT: Duration = Duration::from_secs(60);
const SLOT_CLOSE_GRACE: Duration = Duration::from_secs(10);
const SLOT_GONE_TIMEOUT: Duration = Duration::from_secs(60);
/// `slotBodyHedge`: a body read that has not answered in this long, or in
/// twice what its size takes at the rate bodies came, gets a second request.
const SLOT_BODY_HEDGE: Duration = Duration::from_secs(2);
/// `slotReadAhead`: segments past the head asked for at once, not after the
/// tail wait.
const SLOT_READ_AHEAD: usize = 3;
/// `slotReadAheadPoll`: how often such a segment is asked for again while
/// segments come in a burst, one less than `slotReadAheadBurst` apart.
const SLOT_READ_AHEAD_POLL: Duration = Duration::from_millis(40);
const SLOT_READ_AHEAD_BURST: Duration = Duration::from_millis(500);
/// `slotWriteInflight`: segments a writer has on their way at most.
const SLOT_WRITE_INFLIGHT: usize = 12;
/// Description reads the head keeps in flight at most while data moves.
const SLOT_HEAD_READS: usize = 3;

/// `slotStore`: objects written and read again by id, each with a
/// description and a body.
#[async_trait]
pub(crate) trait SlotStore: Send + Sync + fmt::Debug {
    async fn make_slot(&self, name: &str) -> Result<String, StorageError>;
    /// Sets the description of a slot and, with `body`, its body.
    async fn set_slot(
        &self,
        id: &str,
        description: &str,
        body: Option<Bytes>,
    ) -> Result<(), StorageError>;
    async fn read_description(&self, id: &str) -> Result<String, StorageError>;
    async fn read_body(&self, id: &str) -> Result<Bytes, StorageError>;
    /// [`SlotStore::read_description`] on the storage's reserved lane, where
    /// Xray-core sends watermark and head reads (its `laneKey`).
    async fn read_description_lane(&self, id: &str) -> Result<String, StorageError> {
        self.read_description(id).await
    }
    /// A description alone, on the reserved lane: the reader's acks.
    async fn set_slot_lane(&self, id: &str, description: &str) -> Result<(), StorageError> {
        self.set_slot(id, description, None).await
    }
}

/// Go's `crc32.ChecksumIEEE`.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    };
    let mut crc = !0u32;
    for &byte in data {
        crc = TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// `slotFrame`: which segment a slot holds, and either the segment or the
/// size and checksum of the body that does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SlotFrame {
    pub seq: i64,
    pub mode: u8,
    pub size: u32,
    pub crc: u32,
    pub data: Bytes,
}

impl SlotFrame {
    /// `newSlotFrame`.
    pub(crate) fn new(seq: i64, mode: u8, data: &Bytes) -> Self {
        Self {
            seq,
            mode,
            size: data.len() as u32,
            crc: crc32(data),
            data: if mode == SLOT_INLINE {
                data.clone()
            } else {
                Bytes::new()
            },
        }
    }

    /// `encode`.
    pub(crate) fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(SLOT_HEADER_LEN + self.data.len());
        raw.extend_from_slice(SLOT_MAGIC);
        raw.extend_from_slice(&(self.seq as u64).to_be_bytes());
        raw.push(self.mode);
        raw.extend_from_slice(&self.size.to_be_bytes());
        raw.extend_from_slice(&self.crc.to_be_bytes());
        raw.extend_from_slice(&self.data);
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    /// `decodeSlot`: `None` for anything that is no frame, or an inline one
    /// whose segment is not what it says.
    pub(crate) fn decode(description: &str) -> Option<Self> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(description)
            .ok()?;
        if raw.len() < SLOT_HEADER_LEN || &raw[..8] != SLOT_MAGIC {
            return None;
        }
        let u32_at = |at: usize| u32::from_be_bytes(raw[at..at + 4].try_into().unwrap());
        let mut frame = Self {
            seq: u64::from_be_bytes(raw[8..16].try_into().unwrap()) as i64,
            mode: raw[16],
            size: u32_at(17),
            crc: u32_at(21),
            data: Bytes::new(),
        };
        if frame.mode == SLOT_INLINE {
            frame.data = Bytes::copy_from_slice(&raw[SLOT_HEADER_LEN..]);
            if !frame.holds(&frame.data) {
                return None;
            }
        }
        Some(frame)
    }

    /// `holds`: whether `body` is the one the frame is about, which a body
    /// read right after its description need not be yet.
    pub(crate) fn holds(&self, body: &[u8]) -> bool {
        body.len() == self.size as usize && crc32(body) == self.crc
    }
}

/// `slotTable`: the ring of one direction, its slots and its reader's
/// watermark, by id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SlotTable {
    pub slots: Vec<String>,
    pub watermark: String,
}

impl SlotTable {
    fn to_json(&self) -> String {
        let slots: Vec<String> = self.slots.iter().map(|id| gojson::quote(id)).collect();
        format!(
            "{{\"s\":[{}],\"w\":{}}}",
            slots.join(","),
            gojson::quote(&self.watermark)
        )
    }

    #[cfg(test)]
    fn from_json(value: &serde_json::Map<String, serde_json::Value>) -> Result<Self, ()> {
        let slots = match gojson::field(value, "s") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    serde_json::Value::String(id) => Ok(id.clone()),
                    serde_json::Value::Null => Ok(String::new()),
                    _ => Err(()),
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(()),
        };
        Ok(Self {
            slots,
            watermark: gojson::string(value, "w")?,
        })
    }

    fn slot(&self, seq: i64) -> &str {
        &self.slots[(seq % self.slots.len() as i64) as usize]
    }

    fn depth(&self) -> i64 {
        self.slots.len() as i64
    }
}

/// `ring`: what a client announces a session with, the tables named from
/// its side.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ring {
    pub up: SlotTable,
    pub down: SlotTable,
    /// `First`: the first segment of the uplink, which since v26.11.9 a
    /// client may announce with the ring to save the server a read. The
    /// segment still goes to its slot, for a server that does not read this.
    pub first: Option<Bytes>,
}

impl Ring {
    /// `json.Marshal` of the ring.
    pub(crate) fn to_json(&self) -> String {
        // `[]byte` marshals as standard base64, and `omitempty` leaves an
        // empty one out.
        let first = self
            .first
            .as_ref()
            .filter(|first| !first.is_empty())
            .map(|first| {
                format!(
                    ",\"first\":\"{}\"",
                    base64::engine::general_purpose::STANDARD.encode(first)
                )
            })
            .unwrap_or_default();
        format!(
            "{{\"u\":{},\"d\":{}{first}}}",
            self.up.to_json(),
            self.down.to_json()
        )
    }

    /// `decodeRing`: a ring with slots and a watermark each way, as the
    /// server reads an announcement.
    #[cfg(test)]
    pub(crate) fn from_json(payload: &[u8]) -> Option<Self> {
        let root = gojson::root(payload).ok()?;
        let table = |name| match gojson::object(&root, name) {
            Ok(Some(object)) => SlotTable::from_json(object).ok(),
            Ok(None) => Some(SlotTable::default()),
            Err(()) => None,
        };
        let first = match gojson::field(&root, "first") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(text)) => Some(Bytes::from(
                base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .ok()?,
            )),
            Some(_) => return None,
        };
        let ring = Self {
            up: table("u")?,
            down: table("d")?,
            first: first.filter(|first| !first.is_empty()),
        };
        // Since v26.11.9 the server also bounds the slots by `maxConcurrency`
        // and every id by `maxSlotIDLen`, refusing an empty slot id.
        let usable = |t: &SlotTable| {
            !t.slots.is_empty()
                && !t.watermark.is_empty()
                && t.slots.len() <= super::params::MAX_CONCURRENCY
                && t.watermark.len() <= MAX_SLOT_ID_LEN
                && t.slots
                    .iter()
                    .all(|id| !id.is_empty() && id.len() <= MAX_SLOT_ID_LEN)
        };
        (usable(&ring.up) && usable(&ring.down)).then_some(ring)
    }
}

/// `makeRing`: the slots and watermarks of a session, made all at once.
/// The first failure fails it, whatever the rest did.
pub(crate) async fn make_ring(
    store: &Arc<dyn SlotStore>,
    session: &str,
    params: &Params,
) -> Result<Ring, StorageError> {
    // As deep as the concurrency, since v26.11.9 without a limit of its own.
    let depth = params.concurrency.max(2);
    let mut names = Vec::with_capacity(2 * depth + 2);
    for prefix in [uplink_prefix(session), downlink_prefix(session)] {
        for i in 0..depth {
            names.push(format!("{prefix}/s{i}"));
        }
        names.push(format!("{prefix}/w"));
    }
    let made = futures_util::future::join_all(names.iter().map(|name| store.make_slot(name))).await;
    let mut ids = Vec::with_capacity(made.len());
    for result in made {
        ids.push(result?);
    }
    let mut ids = ids.into_iter();
    let mut table = || SlotTable {
        slots: ids.by_ref().take(depth).collect(),
        watermark: ids.next().unwrap_or_default(),
    };
    let up = table();
    let down = table();
    Ok(Ring {
        up,
        down,
        first: None,
    })
}

/// `readWatermark`: how far the reader read, `-1` before it read anything.
async fn read_watermark(store: &Arc<dyn SlotStore>, id: &str) -> Result<i64, StorageError> {
    let description = store.read_description_lane(id).await?;
    if description.is_empty() {
        return Ok(-1);
    }
    description.parse::<i64>().map_err(|error| {
        StorageError::Failed(format!(
            "strconv.ParseInt: parsing {description:?}: {error}"
        ))
    })
}

/// `slotWriter`: buffers what is written and stores it as segments in the
/// slots of its table, one at a time a slot, each once its reader took
/// what the slot held a lap before.
#[derive(Clone, Debug)]
pub(crate) struct SlotWriter {
    inner: Arc<WriterInner>,
}

#[derive(Debug)]
struct WriterInner {
    store: Arc<dyn SlotStore>,
    table: SlotTable,
    params: Params,
    /// A permit for each segment on its way: one a slot, and at most
    /// [`SLOT_WRITE_INFLIGHT`].
    slots: Arc<Semaphore>,
    /// How many permits `slots` holds in all.
    slot_cap: usize,
    /// Where the first segment goes as it is cut, for the announcement.
    first: Mutex<Option<tokio::sync::oneshot::Sender<Bytes>>>,
    state: Mutex<WriterState>,
    ack: tokio::sync::Mutex<Ack>,
    /// When the reader last took something, or the writer closed.
    progress: Mutex<Instant>,
    settled: Notify,
    cancel: Cancel,
}

#[derive(Debug)]
struct WriterState {
    buf: Vec<u8>,
    seq: i64,
    size: usize,
    full: u32,
    last_size: usize,
    held: u32,
    closed: bool,
    err: Option<String>,
    uploading: usize,
    waker: Option<Waker>,
}

#[derive(Debug)]
struct Ack {
    acked: i64,
    acked_at: Option<Instant>,
}

impl SlotWriter {
    /// `newSlotWriter`, its flush loop running.
    pub(crate) fn new(
        store: Arc<dyn SlotStore>,
        table: SlotTable,
        params: Params,
        cancel: Cancel,
    ) -> Self {
        let slot_cap = table.slots.len().min(SLOT_WRITE_INFLIGHT);
        let inner = Arc::new(WriterInner {
            slots: Arc::new(Semaphore::new(slot_cap)),
            slot_cap,
            first: Mutex::new(None),
            state: Mutex::new(WriterState {
                buf: Vec::new(),
                seq: 0,
                size: SLOT_INLINE_LIMIT.min(params.segment_bytes),
                full: 0,
                last_size: 0,
                held: 0,
                closed: false,
                err: None,
                uploading: 0,
                waker: None,
            }),
            ack: tokio::sync::Mutex::new(Ack {
                acked: -1,
                acked_at: None,
            }),
            progress: Mutex::new(Instant::now()),
            settled: Notify::new(),
            store,
            table,
            params,
            cancel,
        });
        tokio::spawn(flush_loop(Arc::clone(&inner)));
        Self { inner }
    }

    /// `Write`: appends `data` and cuts every full segment a free slot
    /// takes. Xray-core's `Write` returns once the full segments are on
    /// their way; here a write that finds a full segment no slot is free for
    /// waits before it adds anything, so that a reader that falls behind
    /// holds the sender back alike.
    pub(crate) fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.inner.state.lock().unwrap();
        if let Some(err) = &state.err {
            return Poll::Ready(Err(io::Error::other(err.clone())));
        }
        if state.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        cut_full(&self.inner, &mut state);
        if state.buf.len() >= state.size {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        state.buf.extend_from_slice(data);
        cut_full(&self.inner, &mut state);
        Poll::Ready(Ok(data.len()))
    }

    /// The first segment once it is cut: Xray-core's `writer.first`, which
    /// its dial reads to announce the session with it.
    pub(crate) fn first_segment(&self) -> tokio::sync::oneshot::Receiver<Bytes> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        *self.inner.first.lock().unwrap() = Some(sender);
        receiver
    }

    /// `fail`: the session failed outside the writer, as when its
    /// announcement could not be stored; writes report it from now on.
    pub(crate) fn fail(&self, error: String) {
        let waker = {
            let mut state = self.inner.state.lock().unwrap();
            state.err.get_or_insert(error);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// `Close`: stores the rest, waits for every segment, then marks the end
    /// in the next slot once its reader took what it held.
    pub(crate) async fn close(&self) -> io::Result<()> {
        let inner = &self.inner;
        {
            let mut state = inner.state.lock().unwrap();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
        }
        loop {
            let pending = {
                let state = inner.state.lock().unwrap();
                !state.buf.is_empty() && state.err.is_none()
            };
            if !pending {
                break;
            }
            let permit = tokio::select! {
                () = inner.cancel.cancelled() => return Err(io::ErrorKind::ConnectionAborted.into()),
                permit = Arc::clone(&inner.slots).acquire_owned() => permit.map_err(|_| io::Error::other("closed"))?,
            };
            let mut state = inner.state.lock().unwrap();
            cut(inner, &mut state, permit);
        }
        let seq = inner.state.lock().unwrap().seq;
        *inner.progress.lock().unwrap() = Instant::now();
        loop {
            let settled = inner.settled.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            if inner.state.lock().unwrap().uploading == 0 {
                break;
            }
            tokio::select! {
                () = inner.cancel.cancelled() => return Err(io::ErrorKind::ConnectionAborted.into()),
                () = settled => {}
            }
        }
        if let Some(err) = inner.state.lock().unwrap().err.clone() {
            return Err(io::Error::other(err));
        }
        await_drained(inner, seq).await.map_err(io::Error::other)?;
        write(inner, seq, SLOT_END, &Bytes::new())
            .await
            .map_err(io::Error::other)
    }
}

/// Cuts while the buffer holds a full segment and a slot is free.
fn cut_full(inner: &Arc<WriterInner>, state: &mut WriterState) {
    while state.buf.len() >= state.size && state.err.is_none() {
        let Ok(permit) = Arc::clone(&inner.slots).try_acquire_owned() else {
            return;
        };
        cut(inner, state, permit);
    }
}

/// `flushLocked` once a slot is free: the next segment off the buffer, the
/// size ramping up after so many full ones and a burst going at once.
fn cut(inner: &Arc<WriterInner>, state: &mut WriterState, permit: OwnedSemaphorePermit) {
    if state.err.is_some() || state.buf.is_empty() {
        return;
    }
    let segment_bytes = inner.params.segment_bytes;
    // The permit of this segment is taken already, as in Xray-core.
    let in_flight = state.uploading + 1;
    // Most write slots busy: the next segments go at the full size.
    if state.size < segment_bytes
        && state.buf.len() >= state.size
        && in_flight * 4 > inner.slot_cap * 3
    {
        state.size = segment_bytes;
        state.full = 0;
    }
    let mut n = state.buf.len().min(state.size);
    if state.buf.len() > 4 * SLOT_INLINE_LIMIT {
        n = state.buf.len().min(segment_bytes);
    }
    // A burst the write slots take in inline segments goes as such, each a
    // request less than a body.
    if n > SLOT_INLINE_LIMIT && state.buf.len() <= 2 * inner.slot_cap * SLOT_INLINE_LIMIT {
        n = SLOT_INLINE_LIMIT;
    }
    if n == state.size && state.size < segment_bytes {
        state.full += 1;
        if state.full == INLINE_RAMP_SEGMENTS {
            state.full = 0;
            state.size = (2 * state.size).min(segment_bytes);
        }
    }
    let chunk = Bytes::from(state.buf.drain(..n).collect::<Vec<u8>>());
    let seq = state.seq;
    state.seq += 1;
    if seq == 0 {
        if let Some(first) = inner.first.lock().unwrap().take() {
            let _ = first.send(chunk.clone());
        }
    }
    state.last_size = state.buf.len();
    state.held = 0;
    state.uploading += 1;
    tokio::spawn(upload(Arc::clone(inner), seq, chunk, permit));
}

/// `upload`: waits for the slot, stores the segment, and on failure leaves
/// a failure mark there for the reader.
async fn upload(inner: Arc<WriterInner>, seq: i64, chunk: Bytes, permit: OwnedSemaphorePermit) {
    let mode = if chunk.len() <= SLOT_INLINE_LIMIT {
        SLOT_INLINE
    } else {
        SLOT_MEDIA
    };
    let stored = match await_drained(&inner, seq).await {
        Err(error) => Err(error),
        Ok(()) => match write(&inner, seq, mode, &chunk).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = write(&inner, seq, SLOT_ERR, &Bytes::new()).await;
                Err(error)
            }
        },
    };
    if let Err(error) = stored {
        let mut state = inner.state.lock().unwrap();
        state
            .err
            .get_or_insert_with(|| format!("failed to store segment {seq} > {error}"));
    }
    drop(permit);
    let waker = {
        let mut state = inner.state.lock().unwrap();
        state.uploading -= 1;
        state.waker.take()
    };
    if let Some(waker) = waker {
        waker.wake();
    }
    inner.settled.notify_waiters();
}

/// `write`: a frame in the slot of `seq`, the segment in its body when it
/// is too large for the description.
async fn write(inner: &WriterInner, seq: i64, mode: u8, data: &Bytes) -> Result<(), StorageError> {
    let description = SlotFrame::new(seq, mode, data).encode();
    let body = (mode == SLOT_MEDIA).then(|| data.clone());
    tokio::select! {
        () = inner.cancel.cancelled() => Err(StorageError::Failed("the session ended".to_owned())),
        result = inner.store.set_slot(inner.table.slot(seq), &description, body) => result,
    }
}

/// `drained`: whether the reader took what the slot of `seq` held a lap
/// before. The watermark is read again only after a while: an old one
/// costs a wait, never what a slot holds.
async fn drained(inner: &WriterInner, seq: i64) -> Result<bool, StorageError> {
    let mut ack = inner.ack.lock().await;
    let before = seq - inner.table.depth();
    if ack.acked >= before {
        return Ok(true);
    }
    if ack
        .acked_at
        .is_some_and(|at| at.elapsed() < SLOT_WATERMARK_TTL)
    {
        return Ok(false);
    }
    let acked = read_watermark(&inner.store, &inner.table.watermark).await?;
    let now = Instant::now();
    ack.acked_at = Some(now);
    if acked > ack.acked {
        ack.acked = acked;
        *inner.progress.lock().unwrap() = now;
    }
    Ok(ack.acked >= before)
}

/// `await`: waits for [`drained`], for a minute at most, or ten seconds
/// without progress once the writer is closed.
async fn await_drained(inner: &WriterInner, seq: i64) -> Result<(), StorageError> {
    let start = Instant::now();
    let mut wait = SLOT_ACK_RETRY;
    loop {
        let result = drained(inner, seq).await;
        if matches!(result, Ok(true)) {
            return Ok(());
        }
        let closed = inner.state.lock().unwrap().closed;
        let still = inner.progress.lock().unwrap().elapsed();
        // Stalled once neither the wait nor the reader moved for a minute.
        if start.elapsed().min(still) > SLOT_STALL_TIMEOUT || closed && still > SLOT_CLOSE_GRACE {
            let cause = match &result {
                Err(error) => format!(" > {error}"),
                Ok(_) => String::new(),
            };
            return Err(StorageError::Failed(format!(
                "the reader took nothing from slot {} for {still:?}{cause}",
                inner.table.slot(seq)
            )));
        }
        wait = if result.is_err() {
            (2 * wait).min(Duration::from_secs(2))
        } else {
            SLOT_ACK_RETRY
        };
        tokio::select! {
            () = inner.cancel.cancelled() => return Err(StorageError::Failed("the session ended".to_owned())),
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// `flushLoop`: each flush interval, the buffer once it stopped growing or
/// grew for eight ticks, a free slot awaited.
async fn flush_loop(inner: Arc<WriterInner>) {
    let mut ticker = tokio::time::interval(inner.params.flush_interval);
    ticker.tick().await;
    loop {
        tokio::select! {
            () = inner.cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let flush = {
            let mut state = inner.state.lock().unwrap();
            if state.closed || state.err.is_some() {
                return;
            }
            !state.buf.is_empty() && ready_to_flush(&mut state)
        };
        if !flush {
            continue;
        }
        let permit = tokio::select! {
            () = inner.cancel.cancelled() => return,
            permit = Arc::clone(&inner.slots).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => return,
            },
        };
        let mut state = inner.state.lock().unwrap();
        cut(&inner, &mut state, permit);
    }
}

fn ready_to_flush(state: &mut WriterState) -> bool {
    let grew = state.buf.len() > state.last_size;
    state.last_size = state.buf.len();
    // With segments on their way, a buffer under half a segment waits for
    // more, up to the same eight ticks.
    if state.uploading > 0 && state.held < MAX_COALESCED_TICKS && state.buf.len() < state.size / 2 {
        state.held += 1;
        return false;
    }
    if grew && state.held < MAX_COALESCED_TICKS {
        state.held += 1;
        return false;
    }
    state.held = 0;
    true
}

/// What a slot reader hands its stream: the error it stopped with, and a
/// wake the stream's writes give it.
#[derive(Debug)]
pub(crate) struct SlotReaderShared {
    state: Mutex<ReaderState>,
    wake: Notify,
    acks: Notify,
    /// `grow`: a fetch saw a segment past the window's end.
    grow: Notify,
    /// Ends the reader when the session failed outside it.
    stop: Cancel,
    eager_window: Duration,
}

#[derive(Debug)]
struct ReaderState {
    head: i64,
    started: bool,
    /// When a segment last came and the time between them, and when one
    /// came, was seen coming or a write woke the reader. Nothing for the
    /// eager window is idle, and `active` fires when that ends.
    hit_at: Instant,
    gap: Duration,
    active_at: Instant,
    active: Arc<Notify>,
    /// The furthest segment a fetch saw in its slot.
    frontier: i64,
    /// Bytes a second the last bodies came at, averaged.
    body_rate: f64,
    err: Option<String>,
}

impl SlotReaderShared {
    /// `Err`: why the reader stopped, or `None` at the end of the direction.
    pub(crate) fn error(&self) -> Option<io::Error> {
        self.state.lock().unwrap().err.clone().map(io::Error::other)
    }

    /// `Wake`: the head is asked for now, as an answer is likely.
    pub(crate) fn wake(&self) {
        self.state.lock().unwrap().touch(self.eager_window);
        self.wake.notify_one();
    }

    /// `setErr` from outside the reader: the session failed, as when its
    /// announcement could not be stored, and the reader stops so that a read
    /// returns the error instead of waiting.
    pub(crate) fn fail(&self, error: String) {
        self.set_err(error);
        self.stop.cancel();
    }

    fn set_err(&self, error: String) {
        self.state.lock().unwrap().err.get_or_insert(error);
    }

    fn is_head(&self, seq: i64) -> bool {
        self.state.lock().unwrap().head == seq
    }

    fn idle(&self) -> bool {
        self.state.lock().unwrap().active_at.elapsed() > self.eager_window
    }

    /// `pace`: about how long segments take to come one after another.
    fn pace(&self) -> Duration {
        let gap = self.state.lock().unwrap().gap;
        gap.clamp(Duration::from_millis(300), Duration::from_secs(3))
    }

    /// `bursting`: a segment came within the last half second.
    fn bursting(&self) -> bool {
        self.state.lock().unwrap().hit_at.elapsed() <= SLOT_READ_AHEAD_BURST
    }

    fn hit(&self) {
        let mut state = self.state.lock().unwrap();
        let gap = state.hit_at.elapsed();
        state.gap = if state.gap.is_zero() {
            gap
        } else {
            (state.gap + gap) / 2
        };
        state.hit_at = Instant::now();
        state.touch(self.eager_window);
    }

    /// `reach`: a fetch saw `seq` in its slot; the window grows to keep
    /// [`SLOT_FETCH_AHEAD`] fetches past it.
    fn reach(&self, seq: i64) {
        let grown = {
            let mut state = self.state.lock().unwrap();
            let grown = seq > state.frontier;
            if grown {
                state.frontier = seq;
            }
            grown
        };
        if grown {
            self.grow.notify_one();
        }
    }
}

impl ReaderState {
    /// `touch`: something came or is likely to.
    fn touch(&mut self, eager_window: Duration) {
        if self.active_at.elapsed() > eager_window {
            let ended = std::mem::replace(&mut self.active, Arc::new(Notify::new()));
            ended.notify_waiters();
        }
        self.active_at = Instant::now();
    }
}

/// What a fetch of one segment found.
#[derive(Debug)]
enum Fetched {
    Body(Bytes),
    End,
    Failed(String),
}

#[derive(Debug, Default)]
struct SlotFetch {
    ready: Cancel,
    /// Fires when the segment becomes the head.
    promoted: Cancel,
    /// `near`: fires when the segment is at most [`SLOT_READ_AHEAD`] past the
    /// head, which asks for it at once instead of after the tail wait.
    near: Cancel,
    result: Mutex<Option<Fetched>>,
}

/// `slotReader`: fetches the segments of its table in order, the head often
/// and those behind it as described for [`SlotReader::find`], and writes its
/// watermark as the head moves.
pub(crate) struct SlotReader {
    store: Arc<dyn SlotStore>,
    table: SlotTable,
    params: Params,
    shared: Arc<SlotReaderShared>,
    cancel: Cancel,
}

impl SlotReader {
    /// Starts the reader and its watermark writer, and returns where its
    /// segments arrive.
    pub(crate) fn spawn(
        store: Arc<dyn SlotStore>,
        table: SlotTable,
        params: Params,
        cancel: Cancel,
    ) -> (mpsc::Receiver<Bytes>, Arc<SlotReaderShared>) {
        let (chunks, received) = mpsc::channel(params.concurrency.max(1));
        let now = Instant::now();
        let shared = Arc::new(SlotReaderShared {
            state: Mutex::new(ReaderState {
                head: 0,
                started: false,
                hit_at: now,
                gap: Duration::ZERO,
                active_at: now,
                active: Arc::new(Notify::new()),
                frontier: 0,
                body_rate: 0.0,
                err: None,
            }),
            wake: Notify::new(),
            acks: Notify::new(),
            grow: Notify::new(),
            stop: Cancel::default(),
            eager_window: params.eager_window,
        });
        let reader = Arc::new(Self {
            store,
            table,
            params,
            shared: Arc::clone(&shared),
            cancel,
        });
        tokio::spawn(Arc::clone(&reader).ack_loop());
        // The sender goes with `run`, so that the stream sees the end when
        // the reader stops, whatever the watermark writer does.
        tokio::spawn(reader.run(chunks));
        (received, shared)
    }

    /// `run`: hands the head on as it comes. Once the first came, the window
    /// of fetches reaches [`SLOT_FETCH_AHEAD`] past the head or past the
    /// furthest segment seen, whichever is further, within the ring.
    async fn run(self: Arc<Self>, chunks: mpsc::Sender<Bytes>) {
        let fetch_cancel = Cancel::default();
        let mut fetches: HashMap<i64, Arc<SlotFetch>> = HashMap::new();
        let depth = self.table.slots.len();
        loop {
            let (head, started, frontier) = {
                let state = self.shared.state.lock().unwrap();
                (state.head, state.started, state.frontier)
            };
            let window = if started {
                let ahead = SLOT_FETCH_AHEAD as i64;
                (frontier - head + ahead).max(ahead).min(depth as i64) as usize
            } else {
                1
            };
            for offset in 0..window {
                let seq = head + offset as i64;
                fetches.entry(seq).or_insert_with(|| {
                    let fetch = Arc::new(SlotFetch::default());
                    if offset <= SLOT_READ_AHEAD {
                        fetch.near.cancel();
                    }
                    tokio::spawn(Arc::clone(&self).fetch(
                        seq,
                        offset,
                        Arc::clone(&fetch),
                        fetch_cancel.clone(),
                    ));
                    fetch
                });
            }
            let fetch = Arc::clone(&fetches[&head]);
            tokio::select! {
                () = self.cancel.cancelled() => break,
                () = self.shared.stop.cancelled() => break,
                () = fetch.ready.cancelled() => {}
                () = self.shared.grow.notified() => continue,
            }
            fetches.remove(&head);
            let found = fetch.result.lock().unwrap().take();
            let body = match found {
                Some(Fetched::Body(body)) => body,
                Some(Fetched::Failed(error)) => {
                    self.shared.set_err(error);
                    break;
                }
                Some(Fetched::End) | None => break,
            };
            {
                let mut state = self.shared.state.lock().unwrap();
                state.head += 1;
                state.started = true;
            }
            if let Some(next) = fetches.get(&(head + 1)) {
                next.promoted.cancel();
                if let Some(near) = fetches.get(&(head + 1 + SLOT_READ_AHEAD as i64)) {
                    near.near.cancel();
                }
            }
            self.shared.acks.notify_one();
            tokio::select! {
                () = self.cancel.cancelled() => break,
                () = self.shared.stop.cancelled() => break,
                sent = chunks.send(body) => if sent.is_err() { break },
            }
        }
        fetch_cancel.cancel();
    }

    /// `fetch`: asks for the slot of `seq` until it holds `seq`.
    async fn fetch(
        self: Arc<Self>,
        seq: i64,
        offset: usize,
        fetch: Arc<SlotFetch>,
        cancel: Cancel,
    ) {
        let found = self.find(seq, offset, &fetch, &cancel).await;
        *fetch.result.lock().unwrap() = found;
        fetch.ready.cancel();
    }

    /// The head is asked for often, through [`SlotReader::read_head`] while
    /// data moves. A segment behind it waits the tail wait, or not at all
    /// once it is near, then is asked for at the pace segments come, or every
    /// [`SLOT_READ_AHEAD_POLL`] while near and in a burst. A slot that holds
    /// a frame of its segment whose body never checks out, or a frame that
    /// does not decode, fails the session after a minute; an empty or absent
    /// slot is idle, not a failure.
    async fn find(
        &self,
        seq: i64,
        offset: usize,
        fetch: &SlotFetch,
        cancel: &Cancel,
    ) -> Option<Fetched> {
        if offset > 0
            && !self
                .hold(
                    cancel,
                    Some(SLOT_TAIL_MIN),
                    Some(&fetch.promoted),
                    Some(&fetch.near),
                    None,
                    false,
                )
                .await
        {
            return None;
        }
        let id = self.table.slot(seq).to_owned();
        let mut backoff = SLOT_HUNT_FLOOR;
        let mut gone_since: Option<Instant> = None;
        let mut visible_since: Option<Instant> = None;
        loop {
            let read = if !self.shared.idle() && self.shared.is_head(seq) {
                self.read_head(&id, seq, cancel).await?
            } else {
                tokio::select! {
                    () = cancel.cancelled() => return None,
                    () = self.cancel.cancelled() => return None,
                    read = self.store.read_description(&id) => read,
                }
            };
            match read {
                Ok(description) => match SlotFrame::decode(&description) {
                    Some(frame) if frame.seq == seq => {
                        self.shared
                            .state
                            .lock()
                            .unwrap()
                            .touch(self.params.eager_window);
                        self.shared.reach(seq);
                        match frame.mode {
                            SLOT_END => return Some(Fetched::End),
                            SLOT_ERR => {
                                return Some(Fetched::Failed(format!(
                                    "the peer could not store segment {seq}"
                                )))
                            }
                            SLOT_INLINE => {
                                self.shared.hit();
                                return Some(Fetched::Body(frame.data));
                            }
                            SLOT_MEDIA => {
                                let body = self
                                    .read_body_hedged(&id, frame.size as usize, cancel)
                                    .await?;
                                let cause = match body {
                                    Ok(body) if frame.holds(&body) => {
                                        self.shared.hit();
                                        return Some(Fetched::Body(body));
                                    }
                                    Ok(_) => String::new(),
                                    Err(error) => format!(" > {error}"),
                                };
                                let since = *visible_since.get_or_insert_with(Instant::now);
                                if since.elapsed() > SLOT_STALL_TIMEOUT {
                                    return Some(Fetched::Failed(format!(
                                        "segment {seq} has no usable body after {SLOT_STALL_TIMEOUT:?}{cause}"
                                    )));
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(_) => {}
                    None if description.is_empty() => visible_since = None,
                    None => {
                        let since = *visible_since.get_or_insert_with(Instant::now);
                        if since.elapsed() > SLOT_STALL_TIMEOUT {
                            return Some(Fetched::Failed(format!(
                                "slot {id} of segment {seq} holds an invalid frame"
                            )));
                        }
                    }
                },
                Err(StorageError::NotFound) => {
                    visible_since = None;
                    match gone_since {
                        None => gone_since = Some(Instant::now()),
                        Some(since)
                            if since.elapsed() > SLOT_GONE_TIMEOUT && self.shared.is_head(seq) =>
                        {
                            return Some(Fetched::Failed(format!(
                                "slot {id} of segment {seq} is gone > {}",
                                StorageError::NotFound
                            )));
                        }
                        Some(_) => {}
                    }
                }
                Err(StorageError::Auth(error)) => return Some(Fetched::Failed(error)),
                Err(StorageError::Failed(_)) => gone_since = None,
            }
            let (head, idle, active) = {
                let state = self.shared.state.lock().unwrap();
                (
                    state.head == seq,
                    state.active_at.elapsed() > self.params.eager_window,
                    Arc::clone(&state.active),
                )
            };
            let held = if head {
                let wait = backoff;
                let mut ceiling = SLOT_HUNT_CEILING;
                if idle {
                    ceiling = ceiling.max(self.params.max_poll_interval);
                }
                backoff = (2 * backoff).min(ceiling);
                self.hold(cancel, Some(wait), None, None, None, true).await
            } else if idle {
                // Only the head is asked for until something comes.
                backoff = SLOT_HUNT_FLOOR;
                self.hold(
                    cancel,
                    None,
                    Some(&fetch.promoted),
                    None,
                    Some(&active),
                    false,
                )
                .await
            } else {
                backoff = SLOT_HUNT_FLOOR;
                let mut wait = self.shared.pace().clamp(SLOT_TAIL_MIN, SLOT_TAIL_MAX);
                let near = fetch.near.is_cancelled();
                if near && self.shared.bursting() {
                    wait = SLOT_READ_AHEAD_POLL;
                }
                let near_signal = (!near).then_some(&fetch.near);
                self.hold(
                    cancel,
                    Some(wait),
                    Some(&fetch.promoted),
                    near_signal,
                    None,
                    false,
                )
                .await
            };
            if !held {
                return None;
            }
        }
    }

    /// `readHead`: the head's description on the reserved lane, asked for
    /// again every [`SLOT_HUNT_CEILING`] and on every wake, up to
    /// [`SLOT_HEAD_READS`] reads at once, until one holds the head or, once
    /// the reader went idle, with the last description read. `None` once the
    /// reader is done.
    async fn read_head(
        &self,
        id: &str,
        seq: i64,
        cancel: &Cancel,
    ) -> Option<Result<String, StorageError>> {
        use futures_util::stream::{FuturesUnordered, StreamExt as _};

        let mut reads = FuturesUnordered::new();
        reads.push(self.store.read_description_lane(id));
        let mut ticker =
            tokio::time::interval_at(Instant::now() + SLOT_HUNT_CEILING, SLOT_HUNT_CEILING);
        let mut last: Option<String> = None;
        loop {
            tokio::select! {
                () = cancel.cancelled() => return None,
                () = self.cancel.cancelled() => return None,
                Some(read) = reads.next(), if !reads.is_empty() => match read {
                    Err(error) => return Some(Err(error)),
                    Ok(description) => {
                        if SlotFrame::decode(&description).is_some_and(|frame| frame.seq == seq) {
                            return Some(Ok(description));
                        }
                        last = Some(description);
                    }
                },
                _ = ticker.tick() => {
                    if self.shared.idle() {
                        if let Some(description) = last.take() {
                            return Some(Ok(description));
                        }
                    } else if reads.len() < SLOT_HEAD_READS {
                        reads.push(self.store.read_description_lane(id));
                    }
                }
                () = self.shared.wake.notified() => {
                    if reads.len() < SLOT_HEAD_READS {
                        reads.push(self.store.read_description_lane(id));
                    }
                }
            }
        }
    }

    /// `readBodyHedged`: a body read that has not answered after
    /// [`SLOT_BODY_HEDGE`], or after twice what `size` takes at the rate
    /// bodies came, gets a second request; the first answer wins and feeds
    /// the rate. `None` once the reader is done.
    async fn read_body_hedged(
        &self,
        id: &str,
        size: usize,
        cancel: &Cancel,
    ) -> Option<Result<Bytes, StorageError>> {
        use futures_util::stream::{FuturesUnordered, StreamExt as _};

        let rate = self.shared.state.lock().unwrap().body_rate;
        let mut delay = SLOT_BODY_HEDGE;
        if rate > 0.0 && size > 0 {
            if let Ok(scaled) = Duration::try_from_secs_f64(2.0 * size as f64 / rate) {
                delay = delay.max(scaled);
            }
        }
        let start = Instant::now();
        let mut reads = FuturesUnordered::new();
        reads.push(self.store.read_body(id));
        let hedge = tokio::time::sleep(delay);
        tokio::pin!(hedge);
        let mut hedged = false;
        loop {
            tokio::select! {
                () = cancel.cancelled() => return None,
                () = self.cancel.cancelled() => return None,
                Some(read) = reads.next(), if !reads.is_empty() => match read {
                    Ok(body) => {
                        let elapsed = start.elapsed().as_secs_f64();
                        if elapsed > 0.0 && !body.is_empty() {
                            let instant = body.len() as f64 / elapsed;
                            let mut state = self.shared.state.lock().unwrap();
                            state.body_rate = if state.body_rate == 0.0 {
                                instant
                            } else {
                                (state.body_rate + instant) / 2.0
                            };
                        }
                        return Some(Ok(body));
                    }
                    Err(error) => {
                        if reads.is_empty() {
                            return Some(Err(error));
                        }
                    }
                },
                () = &mut hedge, if !hedged => {
                    hedged = true;
                    if reads.len() == 1 {
                        reads.push(self.store.read_body(id));
                    }
                }
            }
        }
    }

    /// `hold`: waits `wait` (none: no limit), or until `a` or `b` fires,
    /// `active` fires, or with `woken` a write wakes the reader. False once
    /// the reader is done.
    async fn hold(
        &self,
        cancel: &Cancel,
        wait: Option<Duration>,
        a: Option<&Cancel>,
        b: Option<&Cancel>,
        active: Option<&Arc<Notify>>,
        woken: bool,
    ) -> bool {
        let active_notified = active.map(|notify| notify.notified());
        tokio::pin!(active_notified);
        if let Some(notified) = active_notified.as_mut().as_pin_mut() {
            notified.enable();
        }
        let timer = async {
            match wait {
                Some(wait) => tokio::time::sleep(wait).await,
                None => std::future::pending().await,
            }
        };
        let fired = |signal: Option<&Cancel>| {
            let signal = signal.cloned();
            async move {
                match signal {
                    Some(signal) => signal.cancelled().await,
                    None => std::future::pending().await,
                }
            }
        };
        let a_fired = fired(a);
        let b_fired = fired(b);
        let active_fired = async {
            match active_notified.as_mut().as_pin_mut() {
                Some(notified) => notified.await,
                None => std::future::pending().await,
            }
        };
        let wake = async {
            if woken {
                self.shared.wake.notified().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            () = cancel.cancelled() => false,
            () = self.cancel.cancelled() => false,
            () = self.shared.stop.cancelled() => false,
            () = timer => true,
            () = a_fired => true,
            () = b_fired => true,
            () = active_fired => true,
            () = wake => true,
        }
    }

    /// `ackLoop`: writes the watermark when the head moves, the last head
    /// only if it moved more than once meanwhile, on the reserved lane.
    async fn ack_loop(self: Arc<Self>) {
        let mut acked = -1i64;
        let mut wait = SLOT_ACK_RETRY;
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return,
                () = self.shared.acks.notified() => {}
            }
            loop {
                let want = self.shared.state.lock().unwrap().head - 1;
                if want <= acked {
                    break;
                }
                let mark = want.to_string();
                let set = tokio::select! {
                    () = self.cancel.cancelled() => return,
                    set = self.store.set_slot_lane(&self.table.watermark, &mark) => set,
                };
                if set.is_ok() {
                    acked = want;
                    wait = SLOT_ACK_RETRY;
                    continue;
                }
                wait = (2 * wait).min(Duration::from_secs(5));
                tokio::select! {
                    () = self.cancel.cancelled() => return,
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod memory {
    //! A slot store in memory, with a hook that fails chosen calls.

    use super::*;

    #[derive(Debug, Default)]
    pub(crate) struct MemorySlots {
        pub slots: Mutex<HashMap<String, (String, Bytes)>>,
        pub next: Mutex<u64>,
        pub names: Mutex<HashMap<String, String>>,
        /// Fails `set_slot` for the slot of this id once.
        pub fail_set: Mutex<Option<String>>,
        pub sets: Mutex<Vec<(String, String, bool)>>,
    }

    #[async_trait]
    impl SlotStore for MemorySlots {
        async fn make_slot(&self, name: &str) -> Result<String, StorageError> {
            let mut next = self.next.lock().unwrap();
            *next += 1;
            let id = format!("id{next}");
            self.slots
                .lock()
                .unwrap()
                .insert(id.clone(), (String::new(), Bytes::new()));
            self.names
                .lock()
                .unwrap()
                .insert(id.clone(), name.to_owned());
            Ok(id)
        }

        async fn set_slot(
            &self,
            id: &str,
            description: &str,
            body: Option<Bytes>,
        ) -> Result<(), StorageError> {
            self.sets
                .lock()
                .unwrap()
                .push((id.to_owned(), description.to_owned(), body.is_some()));
            if self.fail_set.lock().unwrap().as_deref() == Some(id) {
                *self.fail_set.lock().unwrap() = None;
                return Err(StorageError::Failed("refused".to_owned()));
            }
            let mut slots = self.slots.lock().unwrap();
            let slot = slots.get_mut(id).ok_or(StorageError::NotFound)?;
            slot.0 = description.to_owned();
            if let Some(body) = body {
                slot.1 = body;
            }
            Ok(())
        }

        async fn read_description(&self, id: &str) -> Result<String, StorageError> {
            let slots = self.slots.lock().unwrap();
            slots
                .get(id)
                .map(|slot| slot.0.clone())
                .ok_or(StorageError::NotFound)
        }

        async fn read_body(&self, id: &str) -> Result<Bytes, StorageError> {
            let slots = self.slots.lock().unwrap();
            slots
                .get(id)
                .map(|slot| slot.1.clone())
                .ok_or(StorageError::NotFound)
        }
    }
}
