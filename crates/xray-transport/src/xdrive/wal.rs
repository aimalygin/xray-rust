//! A direction carried in numbered segments, as Xray-core v26.10.31's
//! `wal.go` writes and reads them: `%09d.seg` objects of at most
//! `segmentBytes`, `.end` after the last, `.err` where one could not be
//! stored.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::join_all;
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::time::{sleep, Instant, MissedTickBehavior};

use super::names::{object_name, parse_entry, EntryKind, END_SUFFIX, ERR_SUFFIX, SEG_SUFFIX};
use super::params::Params;
use super::storage::{Entry, Storage, StorageError};

/// A writer holds back a growing buffer for at most this many flush ticks,
/// so that a burst goes out in one segment instead of many.
const MAX_COALESCED_TICKS: u32 = 8;

/// A signal that stops a direction's tasks.
#[derive(Clone, Debug, Default)]
pub(crate) struct Cancel(Arc<CancelInner>);

#[derive(Debug, Default)]
struct CancelInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl Cancel {
    pub(crate) fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// `walWriter`: buffers what is written and stores it as segments, at most
/// `concurrency` at a time, each once the buffer holds a full one or has
/// stopped growing.
#[derive(Clone, Debug)]
pub(crate) struct WalWriter {
    inner: Arc<WriterInner>,
}

#[derive(Debug)]
struct WriterInner {
    storage: Arc<dyn Storage>,
    prefix: String,
    params: Params,
    /// One permit for each segment being stored.
    uploads: Arc<Semaphore>,
    state: Mutex<WriterState>,
    /// Notified whenever a segment is done.
    settled: Notify,
    cancel: Cancel,
}

#[derive(Debug, Default)]
struct WriterState {
    buf: Vec<u8>,
    seq: i64,
    last_size: usize,
    held: u32,
    closed: bool,
    err: Option<String>,
    /// Segments cut from the buffer that are not stored yet.
    pending: usize,
    waker: Option<Waker>,
}

impl WriterState {
    fn take_waker(&mut self) -> Option<Waker> {
        self.waker.take()
    }
}

impl WalWriter {
    pub(crate) fn new(
        storage: Arc<dyn Storage>,
        prefix: String,
        params: Params,
        cancel: Cancel,
    ) -> Self {
        let writer = Self::without_flush_loop(storage, prefix, params, cancel);
        tokio::spawn(flush_loop(Arc::clone(&writer.inner)));
        writer
    }

    fn without_flush_loop(
        storage: Arc<dyn Storage>,
        prefix: String,
        params: Params,
        cancel: Cancel,
    ) -> Self {
        Self {
            inner: Arc::new(WriterInner {
                storage,
                prefix,
                params,
                uploads: Arc::new(Semaphore::new(params.concurrency)),
                state: Mutex::new(WriterState::default()),
                settled: Notify::new(),
                cancel,
            }),
        }
    }

    /// A writer whose flush ticks only [`tick`](Self::tick) gives.
    #[cfg(test)]
    pub(super) fn manual(storage: Arc<dyn Storage>, prefix: String, params: Params) -> Self {
        Self::without_flush_loop(storage, prefix, params, Cancel::default())
    }

    /// One pass of the flush loop.
    #[cfg(test)]
    pub(super) fn tick(&self) {
        let _ = on_tick(&self.inner);
    }

    /// Waits until every segment cut so far is stored or refused.
    #[cfg(test)]
    pub(super) async fn settle(&self) {
        self.wait_settled().await;
    }

    async fn wait_settled(&self) {
        loop {
            let settled = self.inner.settled.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            if self.inner.state.lock().unwrap().pending == 0 {
                return;
            }
            settled.await;
        }
    }

    /// `Write`: appends all of `data` to the buffer and cuts every full
    /// segment off it, as Xray-core does.
    ///
    /// Xray-core starts a goroutine for every segment and lets them pile up.
    /// Here no more than twice `concurrency` segments are cut and not yet
    /// stored: the rest of the full ones wait in the buffer, cut as stored
    /// ones make room, and a write waits while a full segment does, so that
    /// a storage slower than the sender holds the sender back instead of
    /// filling memory. Only then can a flush tick find a full segment in the
    /// buffer, where Xray-core would have cut it already.
    pub(crate) fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.inner.state.lock().unwrap();
        if let Some(err) = &state.err {
            return Poll::Ready(Err(io::Error::other(err.clone())));
        }
        if state.closed {
            return Poll::Ready(Err(closed_pipe()));
        }
        cut_full(&self.inner, &mut state);
        if state.buf.len() >= self.inner.params.segment_bytes {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        state.buf.extend_from_slice(data);
        cut_full(&self.inner, &mut state);
        Poll::Ready(Ok(data.len()))
    }

    /// `Close`: stores what the buffer holds, waits for every segment, then
    /// marks the end of the direction after the last one.
    pub(crate) async fn close(&self) -> io::Result<()> {
        {
            let mut state = self.inner.state.lock().unwrap();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            while !state.buf.is_empty() && state.err.is_none() {
                cut(&self.inner, &mut state);
            }
        }
        self.wait_settled().await;
        let (err, seq) = {
            let state = self.inner.state.lock().unwrap();
            (state.err.clone(), state.seq)
        };
        if let Some(err) = err {
            return Err(io::Error::other(err));
        }
        let name = object_name(&self.inner.prefix, seq, END_SUFFIX);
        tokio::select! {
            () = self.inner.cancel.cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
            result = self.inner.storage.put(&name, Bytes::new()) => result.map_err(io::Error::other),
        }
    }
}

/// How many segments may be cut and not yet stored.
fn pending_limit(params: &Params) -> usize {
    params.concurrency.saturating_mul(2)
}

/// Cuts every full segment the pending limit lets.
fn cut_full(inner: &Arc<WriterInner>, state: &mut WriterState) {
    while state.buf.len() >= inner.params.segment_bytes
        && state.pending < pending_limit(&inner.params)
    {
        cut(inner, state);
    }
}

/// `flushLocked`: cuts one segment off the buffer and stores it in the
/// background.
fn cut(inner: &Arc<WriterInner>, state: &mut WriterState) {
    let size = state.buf.len().min(inner.params.segment_bytes);
    let chunk = Bytes::copy_from_slice(&state.buf[..size]);
    state.buf.drain(..size);
    let seq = state.seq;
    state.seq += 1;
    state.last_size = state.buf.len();
    state.held = 0;
    state.pending += 1;
    tokio::spawn(upload(Arc::clone(inner), seq, chunk));
}

/// `upload`: stores one segment, or on failure fails the writer and leaves
/// `.err` in its place for the reader.
async fn upload(inner: Arc<WriterInner>, seq: i64, chunk: Bytes) {
    let permit = tokio::select! {
        () = inner.cancel.cancelled() => None,
        permit = Arc::clone(&inner.uploads).acquire_owned() => permit.ok(),
    };
    if let Some(_permit) = permit {
        let name = object_name(&inner.prefix, seq, SEG_SUFFIX);
        let stored = tokio::select! {
            () = inner.cancel.cancelled() => Ok(()),
            result = inner.storage.put(&name, chunk) => result,
        };
        if let Err(error) = stored {
            fail(&inner, format!("failed to store segment > {error}"));
            let marker = object_name(&inner.prefix, seq, ERR_SUFFIX);
            tokio::select! {
                () = inner.cancel.cancelled() => {}
                _ = inner.storage.put(&marker, Bytes::new()) => {}
            }
        }
    }
    let waker = {
        let mut state = inner.state.lock().unwrap();
        state.pending -= 1;
        if !state.closed && state.err.is_none() {
            cut_full(&inner, &mut state);
        }
        state.take_waker()
    };
    inner.settled.notify_waiters();
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn fail(inner: &WriterInner, error: String) {
    let waker = {
        let mut state = inner.state.lock().unwrap();
        state.err.get_or_insert(error);
        state.take_waker()
    };
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// `flushLoop`: every flush interval, stores the buffer once it stopped
/// growing or was held back long enough.
async fn flush_loop(inner: Arc<WriterInner>) {
    let period = inner.params.flush_interval;
    let mut ticker = tokio::time::interval_at(Instant::now() + period, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = inner.cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        if on_tick(&inner) {
            return;
        }
    }
}

/// One pass of `flushLoop`'s body; true once the loop is done.
fn on_tick(inner: &Arc<WriterInner>) -> bool {
    let mut state = inner.state.lock().unwrap();
    if !state.closed && state.err.is_none() && !state.buf.is_empty() && ready_to_flush(&mut state) {
        // Past the pending limit the segment waits for the next tick.
        if state.pending < pending_limit(&inner.params) {
            cut(inner, &mut state);
        }
    }
    state.closed || state.err.is_some()
}

/// `io.ErrClosedPipe`.
fn closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

/// `readyToFlush`: a buffer that grew since the last tick waits, up to
/// `MAX_COALESCED_TICKS` ticks in a row.
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

/// What a reader hands its stream: the error it stopped with, and a wake
/// the stream's writes give it.
#[derive(Debug, Default)]
pub(crate) struct ReaderShared {
    err: Mutex<Option<String>>,
    wake: Notify,
}

impl ReaderShared {
    /// `Err`: why the reader stopped, or `None` at the end of the direction.
    pub(crate) fn error(&self) -> Option<io::Error> {
        self.err.lock().unwrap().clone().map(io::Error::other)
    }

    fn set_error(&self, error: String) {
        self.err.lock().unwrap().get_or_insert(error);
    }

    /// `Wake`: polls now, as an answer to what was just written is likely.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }
}

/// `walReader`: polls a direction's listing, fetches the segments that
/// follow in order, `concurrency` at a time, and deletes what it read.
pub(crate) struct WalReader {
    storage: Arc<dyn Storage>,
    prefix: String,
    params: Params,
    seq: i64,
    hole_since: Option<Instant>,
    chunks: mpsc::Sender<Bytes>,
    discards: mpsc::Sender<String>,
    shared: Arc<ReaderShared>,
    cancel: Cancel,
}

impl WalReader {
    /// A reader nobody runs: tests call [`poll_once`](Self::poll_once). Its
    /// segments and discards queue up for the caller to take.
    #[cfg(test)]
    pub(super) fn manual(
        storage: Arc<dyn Storage>,
        prefix: String,
        params: Params,
    ) -> (Self, mpsc::Receiver<Bytes>, mpsc::Receiver<String>) {
        let (chunks, received) = mpsc::channel(1024);
        let (discards, discarded) = mpsc::channel(discard_queue(&params));
        let reader = Self {
            storage,
            prefix,
            params,
            seq: 0,
            hole_since: None,
            chunks,
            discards,
            shared: Arc::new(ReaderShared::default()),
            cancel: Cancel::default(),
        };
        (reader, received, discarded)
    }

    /// One `poll`: whether it advanced, whether it reached the end, and why
    /// it failed, with the number it reads next.
    #[cfg(test)]
    pub(super) async fn poll_once(&mut self) -> (bool, bool, Option<String>, i64) {
        let polled = self.poll().await;
        (polled.advanced, polled.eof, polled.error, self.seq)
    }

    /// Starts the reader and returns where its segments arrive.
    pub(crate) fn spawn(
        storage: Arc<dyn Storage>,
        prefix: String,
        params: Params,
        cancel: Cancel,
    ) -> (mpsc::Receiver<Bytes>, Arc<ReaderShared>) {
        let (chunks, received) = mpsc::channel(params.concurrency);
        let (discards, discarded) = mpsc::channel(discard_queue(&params));
        let shared = Arc::new(ReaderShared::default());
        tokio::spawn(discard_loop(
            Arc::clone(&storage),
            discarded,
            params.concurrency,
            cancel.clone(),
        ));
        let reader = Self {
            storage,
            prefix,
            params,
            seq: 0,
            hole_since: None,
            chunks,
            discards,
            shared: Arc::clone(&shared),
            cancel,
        };
        tokio::spawn(reader.run());
        (received, shared)
    }

    /// `run`: polls every `min_poll_interval` while data moves and for the
    /// eager window after, then twice as seldom each time up to
    /// `max_poll_interval`; a wake polls again at once, but no sooner than
    /// `min_poll_interval` after the last poll.
    async fn run(mut self) {
        let mut delay = self.params.min_poll_interval;
        let mut active = Instant::now();
        loop {
            let polled = Instant::now();
            let outcome = self.poll().await;
            if let Some(error) = outcome.error {
                self.shared.set_error(error);
                return;
            }
            if outcome.eof {
                return;
            }
            if outcome.advanced {
                active = Instant::now();
                delay = self.params.min_poll_interval;
            } else if active.elapsed() < self.params.eager_window {
                delay = self.params.min_poll_interval;
            } else {
                delay = (delay * 2).min(self.params.max_poll_interval);
            }
            let shared = Arc::clone(&self.shared);
            tokio::select! {
                () = self.cancel.cancelled() => return,
                () = sleep(delay) => {}
                () = shared.wake.notified() => {
                    active = Instant::now();
                    delay = self.params.min_poll_interval;
                    let rest = self.params.min_poll_interval.saturating_sub(polled.elapsed());
                    if rest > Duration::ZERO {
                        tokio::select! {
                            () = self.cancel.cancelled() => return,
                            () = sleep(rest) => {}
                        }
                    }
                }
            }
        }
    }

    /// `poll`: one listing, and every segment it lets the reader take.
    async fn poll(&mut self) -> Polled {
        let mut polled = Polled::default();
        let listed = tokio::select! {
            () = self.cancel.cancelled() => return polled.end(),
            listed = self.storage.list(&self.prefix) => match listed {
                Ok(listed) => listed,
                Err(error) => return polled.fail(error.to_string()),
            },
        };
        if listed.is_empty() {
            return polled;
        }
        let mut pending: HashMap<i64, (EntryKind, Entry)> = HashMap::with_capacity(listed.len());
        let mut ahead = false;
        for entry in listed {
            let Some((seq, kind)) = parse_entry(&entry.name) else {
                continue;
            };
            ahead |= seq > self.seq;
            pending.insert(seq, (kind, entry));
        }
        if !pending.contains_key(&self.seq) && ahead {
            match self.hole_since {
                None => self.hole_since = Some(Instant::now()),
                Some(since) if since.elapsed() >= self.params.hole_timeout => {
                    return polled.fail(format!(
                        "segment {} never arrived while later ones did, the peer lost it",
                        self.seq
                    ));
                }
                Some(_) => {}
            }
        } else {
            self.hole_since = None;
        }
        loop {
            if let Some((EntryKind::Failed, entry)) = pending.get(&self.seq) {
                self.discard(&entry.name);
                return polled.fail(format!("the peer could not store segment {}", self.seq));
            }
            let batch = match self.next_batch(&pending) {
                Batch::Done => return polled.end(),
                Batch::Segments(batch) if batch.is_empty() => return polled,
                Batch::Segments(batch) => batch,
            };
            let chunks = match self.fetch(&batch).await {
                Ok(chunks) => chunks,
                // Listed but gone or not there yet: the next poll sees.
                Err(StorageError::NotFound) => return polled,
                Err(error) => return polled.fail(error.to_string()),
            };
            for (chunk, entry) in chunks.into_iter().zip(&batch) {
                tokio::select! {
                    () = self.cancel.cancelled() => return polled.end(),
                    sent = self.chunks.send(chunk) => {
                        if sent.is_err() {
                            return polled.end();
                        }
                    }
                }
                self.seq += 1;
                polled.advanced = true;
                self.discard(&entry.name);
            }
        }
    }

    /// `nextBatch`: the segments that follow on from the next one, up to
    /// `concurrency`, or the end when that is what comes next.
    fn next_batch(&self, pending: &HashMap<i64, (EntryKind, Entry)>) -> Batch {
        let mut batch = Vec::new();
        for offset in 0..self.params.concurrency as i64 {
            let Some((kind, entry)) = pending.get(&(self.seq + offset)) else {
                break;
            };
            match kind {
                EntryKind::Segment => batch.push(entry.clone()),
                EntryKind::End if offset == 0 => {
                    self.discard(&entry.name);
                    return Batch::Done;
                }
                _ => break,
            }
        }
        Batch::Segments(batch)
    }

    /// `fetch`: the batch's segments, all asked for at once; the first
    /// failure in order wins.
    async fn fetch(&self, batch: &[Entry]) -> Result<Vec<Bytes>, StorageError> {
        let requests = batch.iter().map(|entry| async move {
            match &entry.inline {
                Some(inline) => Ok(inline.clone()),
                None => {
                    let name = format!("{}/{}", self.prefix, entry.name);
                    self.storage.get(&name).await
                }
            }
        });
        let fetched = tokio::select! {
            () = self.cancel.cancelled() => return Err(StorageError::Failed("the session is closed".to_owned())),
            fetched = join_all(requests) => fetched,
        };
        fetched.into_iter().collect()
    }

    /// `discard`: deletes an object it read, in the background; when too
    /// many wait already, the server's collection takes it later.
    fn discard(&self, name: &str) {
        let _ = self.discards.try_send(format!("{}/{name}", self.prefix));
    }
}

/// What one poll did: whether it took a segment, whether the direction
/// ended, and why it failed, as `poll`'s three results.
#[derive(Default)]
struct Polled {
    advanced: bool,
    eof: bool,
    error: Option<String>,
}

impl Polled {
    fn end(mut self) -> Self {
        self.eof = true;
        self
    }

    fn fail(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }
}

enum Batch {
    Segments(Vec<Entry>),
    Done,
}

/// How many reads may wait to be deleted: four times `concurrency`, as in
/// Xray-core; past that a read object is left to the server's collection.
fn discard_queue(params: &Params) -> usize {
    4 * params.concurrency
}

/// `discardLoop`: deletes what the reader read, `concurrency` at a time,
/// until the session closes.
async fn discard_loop(
    storage: Arc<dyn Storage>,
    mut names: mpsc::Receiver<String>,
    concurrency: usize,
    cancel: Cancel,
) {
    let slots = Arc::new(Semaphore::new(concurrency));
    let mut deletes = tokio::task::JoinSet::new();
    loop {
        let name = tokio::select! {
            () = cancel.cancelled() => break,
            name = names.recv() => match name {
                Some(name) => name,
                None => break,
            },
        };
        let permit = tokio::select! {
            () = cancel.cancelled() => break,
            permit = Arc::clone(&slots).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let storage = Arc::clone(&storage);
        let cancel = cancel.clone();
        deletes.spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = cancel.cancelled() => {}
                _ = storage.delete(&name) => {}
            }
        });
        while deletes.try_join_next().is_some() {}
    }
    while deletes.join_next().await.is_some() {}
}
