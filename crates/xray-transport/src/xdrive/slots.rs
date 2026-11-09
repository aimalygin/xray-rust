//! Sessions in slots, as Xray-core v26.10.31's `slots.go` carries them on
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
const SLOT_DEPTH_LIMIT: usize = 8;
/// So many segments of one size in a row double it, from
/// [`SLOT_INLINE_LIMIT`] up to `segmentBytes`.
const INLINE_RAMP_SEGMENTS: u32 = 8;
/// As the segment writer's: a growing buffer is held at most so many ticks.
const MAX_COALESCED_TICKS: u32 = 8;

pub(crate) const SLOT_INLINE: u8 = 1;
pub(crate) const SLOT_MEDIA: u8 = 2;
pub(crate) const SLOT_END: u8 = 3;
pub(crate) const SLOT_ERR: u8 = 4;

/// The head is asked for between these, a segment behind it at about the
/// pace segments come.
const SLOT_HUNT_FLOOR: Duration = Duration::from_millis(50);
const SLOT_HUNT_CEILING: Duration = Duration::from_millis(200);
const SLOT_TAIL_MIN: Duration = Duration::from_millis(150);
const SLOT_TAIL_MAX: Duration = Duration::from_millis(800);
const SLOT_FETCH_AHEAD: usize = 6;

const SLOT_ACK_RETRY: Duration = Duration::from_millis(100);
const SLOT_WATERMARK_TTL: Duration = Duration::from_millis(250);
const SLOT_STALL_TIMEOUT: Duration = Duration::from_secs(60);
const SLOT_CLOSE_GRACE: Duration = Duration::from_secs(10);
const SLOT_GONE_TIMEOUT: Duration = Duration::from_secs(60);

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
}

impl Ring {
    /// `json.Marshal` of the ring.
    pub(crate) fn to_json(&self) -> String {
        format!(
            "{{\"u\":{},\"d\":{}}}",
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
        let ring = Self {
            up: table("u")?,
            down: table("d")?,
        };
        let usable = |t: &SlotTable| !t.slots.is_empty() && !t.watermark.is_empty();
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
    let depth = params.concurrency.clamp(2, SLOT_DEPTH_LIMIT);
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
    Ok(Ring { up, down })
}

/// `readWatermark`: how far the reader read, `-1` before it read anything.
async fn read_watermark(store: &Arc<dyn SlotStore>, id: &str) -> Result<i64, StorageError> {
    let description = store.read_description(id).await?;
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
    /// A permit for each segment on its way, at most one for each slot.
    slots: Arc<Semaphore>,
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
        let inner = Arc::new(WriterInner {
            slots: Arc::new(Semaphore::new(table.slots.len())),
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
    let mut n = state.buf.len().min(state.size);
    if state.buf.len() > 4 * SLOT_INLINE_LIMIT {
        n = state.buf.len().min(segment_bytes);
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
        if start.elapsed() > SLOT_STALL_TIMEOUT || closed && still > SLOT_CLOSE_GRACE {
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

    fn set_err(&self, error: String) {
        self.state.lock().unwrap().err.get_or_insert(error);
    }

    fn is_head(&self, seq: i64) -> bool {
        self.state.lock().unwrap().head == seq
    }

    /// `pace`: about how long segments take to come one after another.
    fn pace(&self) -> Duration {
        let gap = self.state.lock().unwrap().gap;
        gap.clamp(Duration::from_millis(300), Duration::from_secs(3))
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
    result: Mutex<Option<Fetched>>,
}

/// `slotReader`: fetches the segments of its table in order, the head often
/// and up to six behind it at the pace they come, and writes its watermark
/// as the head moves.
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
                err: None,
            }),
            wake: Notify::new(),
            acks: Notify::new(),
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

    /// `run`: hands the head on as it comes, the slots behind it fetched
    /// ahead once the first came.
    async fn run(self: Arc<Self>, chunks: mpsc::Sender<Bytes>) {
        let fetch_cancel = Cancel::default();
        let mut fetches: HashMap<i64, Arc<SlotFetch>> = HashMap::new();
        let depth = self.table.slots.len();
        loop {
            let (head, started) = {
                let state = self.shared.state.lock().unwrap();
                (state.head, state.started)
            };
            let window = if started {
                SLOT_FETCH_AHEAD.min(depth)
            } else {
                1
            };
            for offset in 0..window {
                let seq = head + offset as i64;
                fetches.entry(seq).or_insert_with(|| {
                    let fetch = Arc::new(SlotFetch::default());
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
                () = fetch.ready.cancelled() => {}
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
            }
            self.shared.acks.notify_one();
            tokio::select! {
                () = self.cancel.cancelled() => break,
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

    async fn find(
        &self,
        seq: i64,
        offset: usize,
        fetch: &SlotFetch,
        cancel: &Cancel,
    ) -> Option<Fetched> {
        if offset > 0 {
            let wait = self.shared.pace() * offset as u32;
            if !self
                .hold(cancel, Some(wait), Some(&fetch.promoted), None, false)
                .await
            {
                return None;
            }
        }
        let id = self.table.slot(seq).to_owned();
        let mut backoff = SLOT_HUNT_FLOOR;
        let mut gone_since: Option<Instant> = None;
        loop {
            let read = tokio::select! {
                () = cancel.cancelled() => return None,
                () = self.cancel.cancelled() => return None,
                read = self.store.read_description(&id) => read,
            };
            match read {
                Ok(description) => {
                    if let Some(frame) = SlotFrame::decode(&description).filter(|f| f.seq == seq) {
                        self.shared
                            .state
                            .lock()
                            .unwrap()
                            .touch(self.params.eager_window);
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
                                if let Ok(body) = self.store.read_body(&id).await {
                                    if frame.holds(&body) {
                                        self.shared.hit();
                                        return Some(Fetched::Body(body));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(StorageError::NotFound) => match gone_since {
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
                },
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
                self.hold(cancel, Some(wait), None, None, true).await
            } else if idle {
                // Only the head is asked for until something comes.
                backoff = SLOT_HUNT_FLOOR;
                self.hold(cancel, None, Some(&fetch.promoted), Some(&active), false)
                    .await
            } else {
                backoff = SLOT_HUNT_FLOOR;
                let wait = self.shared.pace().clamp(SLOT_TAIL_MIN, SLOT_TAIL_MAX);
                self.hold(cancel, Some(wait), Some(&fetch.promoted), None, false)
                    .await
            };
            if !held {
                return None;
            }
        }
    }

    /// `hold`: waits `wait` (none: no limit), or until `promoted` fires,
    /// `active` fires, or with `woken` a write wakes the reader. False once
    /// the reader is done.
    async fn hold(
        &self,
        cancel: &Cancel,
        wait: Option<Duration>,
        promoted: Option<&Cancel>,
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
        let promoted_fired = async {
            match promoted {
                Some(promoted) => promoted.cancelled().await,
                None => std::future::pending().await,
            }
        };
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
            () = timer => true,
            () = promoted_fired => true,
            () = active_fired => true,
            () = wake => true,
        }
    }

    /// `ackLoop`: writes the watermark when the head moves, the last head
    /// only if it moved more than once meanwhile.
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
                    set = self.store.set_slot(&self.table.watermark, &mark, None) => set,
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
