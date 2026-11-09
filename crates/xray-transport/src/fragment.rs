//! Bounded Xray FinalMask `fragment` below TLS/REALITY. `tlshello` rebuilds
//! the first write's handshake record as smaller records, keeping its
//! handshake bytes; a write selector cuts the selected writes into raw
//! pieces, each its own socket write.
use crate::{BoxedTransportStream, TransportStream};
use rand::Rng;
use std::{
    future::Future,
    io::{self, IoSlice},
    ops::RangeInclusive,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Wake, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most of one write staged at once; the rest of a longer write
/// continues it in the next call.
const MAX_STAGED_WRITE: usize = 65_536;
const MAX_RECORD: usize = 16_384;
const MAX_SPLITS: usize = 4096;
const MAX_TOTAL_DELAY_MS: u64 = 10_000;

/// The writes the mask cuts, as Xray's `packets` selects them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FragmentPackets {
    /// `tlshello`: the first write's complete TLS handshake record, sent as
    /// smaller records.
    TlsHello,
    /// Empty: every write, cut into raw pieces.
    AllWrites,
    /// The writes so numbered, counting from one, cut into raw pieces.
    Writes(RangeInclusive<u64>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpFragmentConfig {
    packets: FragmentPackets,
    lengths: Vec<RangeInclusive<u32>>,
    delays_ms: Vec<RangeInclusive<u32>>,
    max_split: RangeInclusive<u32>,
}

impl TcpFragmentConfig {
    pub fn new(
        lengths: Vec<RangeInclusive<u32>>,
        delays_ms: Vec<RangeInclusive<u32>>,
        max_split: RangeInclusive<u32>,
    ) -> io::Result<Self> {
        let valid = |ranges: &[RangeInclusive<u32>], min: u32, max: u32| {
            (1..=16).contains(&ranges.len())
                && ranges
                    .iter()
                    .all(|r| !r.is_empty() && *r.start() >= min && *r.end() <= max)
        };
        if !valid(&lengths, 1, MAX_RECORD as u32)
            || !valid(&delays_ms, 0, 1000)
            || max_split.is_empty()
            || *max_split.end() > MAX_SPLITS as u32
        {
            return Err(invalid(
                "fragment length/delay/count is outside bounded tlshello support",
            ));
        }
        Ok(Self {
            packets: FragmentPackets::TlsHello,
            lengths,
            delays_ms,
            max_split,
        })
    }

    /// Selects the writes the mask cuts, [`FragmentPackets::TlsHello`] unless
    /// set. Write numbers start at one, and their range is not reversed.
    pub fn with_packets(mut self, packets: FragmentPackets) -> io::Result<Self> {
        if let FragmentPackets::Writes(writes) = &packets {
            if *writes.start() == 0 || writes.is_empty() {
                return Err(invalid(
                    "fragment write numbers start at one and their range is not reversed",
                ));
            }
        }
        self.packets = packets;
        Ok(self)
    }

    /// Whether the write numbered `write` is cut into raw pieces.
    fn cuts(&self, write: u64) -> bool {
        match &self.packets {
            FragmentPackets::TlsHello => false,
            FragmentPackets::AllWrites => true,
            FragmentPackets::Writes(writes) => writes.contains(&write),
        }
    }

    /// Whether a write after the one numbered `write` can be cut.
    fn cuts_after(&self, write: u64) -> bool {
        match &self.packets {
            FragmentPackets::TlsHello => false,
            FragmentPackets::AllWrites => true,
            FragmentPackets::Writes(writes) => write < *writes.end(),
        }
    }

    /// Cuts `input`, one selected write or the next part of one, into raw
    /// pieces as Xray-core cuts a write: each piece its own write followed by
    /// its delay, the `maxSplit`th taking the rest. It stops at 4096 pieces or
    /// ten seconds of delays and stages only the bytes it took.
    fn plan_pieces(&self, mut input: Vec<u8>, split: &mut Split) -> Pending {
        let mut rng = rand::thread_rng();
        let mut cuts = Vec::new();
        let mut offset = 0;
        let mut total_delay = 0u64;
        while offset < input.len() && cuts.len() < MAX_SPLITS {
            let index = split.pieces;
            let last = split.limit > 0 && index + 1 >= split.limit;
            let end = if last {
                input.len()
            } else {
                let lengths = &self.lengths[index.min(self.lengths.len() - 1)];
                (offset + rng.gen_range(lengths.clone()) as usize).min(input.len())
            };
            let delays = &self.delays_ms[index.min(self.delays_ms.len() - 1)];
            let delay = u64::from(rng.gen_range(delays.clone()));
            if total_delay + delay > MAX_TOTAL_DELAY_MS {
                break;
            }
            total_delay += delay;
            cuts.push((end, Duration::from_millis(delay)));
            split.pieces += 1;
            split.rest = last;
            offset = end;
        }
        input.truncate(offset);
        Pending {
            wire: input,
            cuts,
            written: 0,
            cut: 0,
            sleep: None,
        }
    }

    fn plan(&self, input: &[u8]) -> io::Result<Option<Pending>> {
        // Xray only examines its first write and passes incomplete/non-handshake
        // records through. Do not scan application data for a later ClientHello.
        if input.len() <= 5 || input[0] != 22 {
            return Ok(None);
        }
        let record_len = u16::from_be_bytes([input[3], input[4]]) as usize;
        if input.len() < record_len + 5 {
            return Ok(None);
        }
        if record_len > MAX_RECORD || record_len == 0 {
            return Err(invalid(
                "tlshello record exceeds the bounded plaintext record size",
            ));
        }
        let record = &input[5..5 + record_len];
        let mut rng = rand::thread_rng();
        let limit = rng.gen_range(self.max_split.clone()) as usize;
        let merged = self.delays_ms.len() == 1 && *self.delays_ms[0].end() == 0;
        let mut wire = Vec::with_capacity(input.len() + 256);
        let mut cuts = Vec::new();
        let mut offset = 0;
        let mut total_delay = 0u64;
        let mut count = 0;
        while offset < record.len() {
            if count == MAX_SPLITS {
                return Err(invalid("tlshello plan exceeds 4096 fragments"));
            }
            let lengths = &self.lengths[count.min(self.lengths.len() - 1)];
            let length = rng.gen_range(lengths.clone()) as usize;
            let end = if limit > 0 && count + 1 >= limit {
                record.len()
            } else {
                (offset + length).min(record.len())
            };
            wire.extend_from_slice(&input[..3]);
            wire.extend_from_slice(&((end - offset) as u16).to_be_bytes());
            wire.extend_from_slice(&record[offset..end]);
            if !merged {
                let delays = &self.delays_ms[count.min(self.delays_ms.len() - 1)];
                let delay = rng.gen_range(delays.clone()) as u64;
                total_delay += delay;
                if total_delay > MAX_TOTAL_DELAY_MS {
                    return Err(invalid("tlshello plan exceeds ten seconds of delays"));
                }
                cuts.push((wire.len(), Duration::from_millis(delay)));
            }
            offset = end;
            count += 1;
        }
        if merged {
            cuts.push((wire.len(), Duration::ZERO));
        }
        if input.len() > record_len + 5 {
            wire.extend_from_slice(&input[record_len + 5..]);
            cuts.push((wire.len(), Duration::ZERO));
        }
        Ok(Some(Pending {
            wire,
            cuts,
            written: 0,
            cut: 0,
            sleep: None,
        }))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct Pending {
    wire: Vec<u8>,
    cuts: Vec<(usize, Duration)>,
    written: usize,
    cut: usize,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

/// The piece numbering of one selected write, which a write taken in parts
/// carries into its next call.
#[derive(Clone, Copy, Debug, Default)]
struct Split {
    /// Pieces cut so far.
    pieces: usize,
    /// The `maxSplit` drawn for the write: the piece so numbered takes the
    /// rest. Zero sets no limit.
    limit: usize,
    /// The limit was reached: the rest of the write goes through whole.
    rest: bool,
}

impl Split {
    fn draw(config: &TcpFragmentConfig) -> Self {
        Self {
            limit: rand::thread_rng().gen_range(config.max_split.clone()) as usize,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy)]
enum Side {
    Read = 0,
    Write = 1,
}

/// The tasks waiting on staged writes. The halves of a split stream both
/// drive the drain, while its timer and socket wake only the task that
/// polled them last, so each of those wakes every waiter.
#[derive(Default)]
struct DrainWaiters(Mutex<[Option<Waker>; 2]>);

impl DrainWaiters {
    fn slots(&self) -> std::sync::MutexGuard<'_, [Option<Waker>; 2]> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn register(&self, side: Side, waker: &Waker) {
        let mut slots = self.slots();
        let slot = &mut slots[side as usize];
        if !slot
            .as_ref()
            .is_some_and(|current| current.will_wake(waker))
        {
            *slot = Some(waker.clone());
        }
    }

    /// Wakes every waiter but `current`.
    fn wake_others(&self, current: &Waker) {
        let waiters = {
            let mut slots = self.slots();
            [slots[0].take(), slots[1].take()]
        };
        for waiter in waiters.into_iter().flatten() {
            if !waiter.will_wake(current) {
                waiter.wake();
            }
        }
    }

    fn wake_all(&self) {
        let waiters = {
            let mut slots = self.slots();
            [slots[0].take(), slots[1].take()]
        };
        for waiter in waiters.into_iter().flatten() {
            waiter.wake();
        }
    }
}

impl Wake for DrainWaiters {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

/// Owns all accepted bytes until flushed. No background task can outlive this
/// stream; dropping a cancelled handshake drops its socket, bytes and timer.
pub(crate) struct FragmentStream {
    inner: BoxedTransportStream,
    /// `None` once no later write can be cut.
    config: Option<Arc<TcpFragmentConfig>>,
    pending: Option<Pending>,
    failed: bool,
    /// The writes begun under a write selector, counting from one.
    writes: u64,
    /// The last write call took part of its input: the next continues that
    /// write, as Go's `Write` takes a write whole.
    continuing: bool,
    /// The piece numbering of the selected write that continues.
    split: Split,
    waiters: Arc<DrainWaiters>,
}

impl FragmentStream {
    pub(crate) fn new(inner: BoxedTransportStream, config: Arc<TcpFragmentConfig>) -> Self {
        Self {
            inner,
            config: Some(config),
            pending: None,
            failed: false,
            writes: 0,
            continuing: false,
            split: Split::default(),
            waiters: Arc::default(),
        }
    }

    /// Sends what is staged. Every task that waits here is woken as the
    /// drain moves, whichever of them the timer or socket wakes.
    fn poll_drain(&mut self, cx: &mut Context<'_>, side: Side) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fragmented write failed",
            )));
        }
        if self.pending.is_none() {
            return Poll::Ready(Ok(()));
        }
        self.waiters.register(side, cx.waker());
        let waker = Waker::from(Arc::clone(&self.waiters));
        let result = self.drain(&mut Context::from_waker(&waker));
        if result.is_ready() {
            self.waiters.wake_others(cx.waker());
        }
        result
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fragmented write failed",
            )));
        }
        let Some(pending) = &mut self.pending else {
            return Poll::Ready(Ok(()));
        };
        // A ready socket and thousands of tiny records must still yield.
        for _ in 0..64 {
            if let Some(sleep) = &mut pending.sleep {
                ready!(sleep.as_mut().poll(cx));
                pending.sleep = None;
            }
            if pending.cut == pending.cuts.len() {
                self.pending = None;
                return Poll::Ready(Ok(()));
            }
            let (end, delay) = pending.cuts[pending.cut];
            if pending.written < end {
                match ready!(
                    Pin::new(&mut *self.inner).poll_write(cx, &pending.wire[pending.written..end])
                ) {
                    Ok(0) => {
                        self.failed = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "fragment socket closed",
                        )));
                    }
                    Ok(n) => pending.written += n,
                    Err(error) => {
                        self.failed = true;
                        return Poll::Ready(Err(error));
                    }
                }
                if pending.written < end {
                    continue;
                }
            }
            pending.cut += 1;
            if !delay.is_zero() {
                pending.sleep = Some(Box::pin(tokio::time::sleep(delay)));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn stage(&mut self, input: &[u8]) -> io::Result<bool> {
        let Some(config) = self.config.take() else {
            return Ok(false);
        };
        match config.plan(input) {
            Ok(Some(pending)) => {
                self.pending = Some(pending);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// The configuration while a write selector can still cut a write.
    fn cutting(&self) -> Option<Arc<TcpFragmentConfig>> {
        self.config
            .as_ref()
            .filter(|config| config.packets != FragmentPackets::TlsHello)
            .cloned()
    }

    /// One write call under a write selector. A selected write is staged as
    /// raw pieces, only its first part when it is long; any other goes
    /// through unchanged.
    fn poll_write_pieces(
        &mut self,
        cx: &mut Context<'_>,
        config: &TcpFragmentConfig,
        input: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let total = input.iter().map(|part| part.len()).sum::<usize>();
        if total == 0 {
            return Poll::Ready(Ok(0));
        }
        let (write, split) = if self.continuing {
            (self.writes, self.split)
        } else {
            (self.writes + 1, Split::draw(config))
        };
        if !config.cuts(write) || split.rest {
            let written = ready!(match input {
                [only] => Pin::new(&mut *self.inner).poll_write(cx, only),
                _ => Pin::new(&mut *self.inner).poll_write_vectored(cx, input),
            })?;
            self.finish_write(config, write, split, written < total);
            return Poll::Ready(Ok(written));
        }
        let mut staged = Vec::with_capacity(total.min(MAX_STAGED_WRITE));
        for part in input {
            let length = part.len().min(MAX_STAGED_WRITE - staged.len());
            staged.extend_from_slice(&part[..length]);
            if staged.len() == MAX_STAGED_WRITE {
                break;
            }
        }
        let mut split = split;
        let pending = config.plan_pieces(staged, &mut split);
        let taken = pending.wire.len();
        self.pending = Some(pending);
        self.finish_write(config, write, split, taken < total);
        // Start sending at once; a failure surfaces on the next call.
        let _ = self.poll_drain(cx, Side::Write);
        Poll::Ready(Ok(taken))
    }

    fn finish_write(
        &mut self,
        config: &TcpFragmentConfig,
        write: u64,
        split: Split,
        partial: bool,
    ) {
        self.writes = write;
        self.continuing = partial;
        self.split = split;
        if !partial && !config.cuts_after(write) {
            self.config = None;
        }
    }
}

impl AsyncRead for FragmentStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        // Reads do not wait for staged writes, as Go's reads never wait on its
        // writer's sleeps, but they drive them for a caller that reads before
        // it flushes.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx, Side::Read) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut *this.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for FragmentStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx, Side::Write))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(config) = this.cutting() {
            return this.poll_write_pieces(cx, &config, &[IoSlice::new(input)]);
        }
        let accepted = input.len().min(MAX_STAGED_WRITE);
        if this.stage(&input[..accepted])? {
            // Buffer acceptance is explicit. Returning Pending after emitting a
            // prefix would violate AsyncWrite's cancellation/partial-write rules.
            let _ = this.poll_drain(cx, Side::Write);
            return Poll::Ready(Ok(accepted));
        }
        Pin::new(&mut *this.inner).poll_write(cx, input)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx, Side::Write))?;
        if let Some(config) = this.cutting() {
            return this.poll_write_pieces(cx, &config, input);
        }
        if this.config.is_some() {
            let Some(first) = input.iter().find(|part| !part.is_empty()) else {
                return Poll::Ready(Ok(0));
            };
            if first[0] == 22 {
                let mut joined = Vec::new();
                for part in input {
                    let length = part.len().min(MAX_STAGED_WRITE - joined.len());
                    joined.extend_from_slice(&part[..length]);
                    if joined.len() == MAX_STAGED_WRITE {
                        break;
                    }
                }
                if this.stage(&joined)? {
                    let _ = this.poll_drain(cx, Side::Write);
                    return Poll::Ready(Ok(joined.len()));
                }
            } else {
                this.config = None;
            }
        }
        Pin::new(&mut *this.inner).poll_write_vectored(cx, input)
    }
    fn is_write_vectored(&self) -> bool {
        self.config.is_some() || self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx, Side::Write))?;
        Pin::new(&mut *this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx, Side::Write))?;
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl TransportStream for FragmentStream {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(Err(error)) = this.poll_drain(cx, Side::Read) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut *this.inner).poll_read_direct(cx, output)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx, Side::Write))?;
        // The carriers beneath write directly as they write: the write is
        // counted and cut as any other.
        if let Some(config) = this.cutting() {
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            return this.poll_write_pieces(cx, &config, &[IoSlice::new(input)]);
        }
        Pin::new(&mut *this.inner).poll_write_direct(cx, input)
    }
    fn into_io_halves(self: Box<Self>) -> (crate::ParallelRead, crate::ParallelWrite) {
        if self.config.is_none() && self.pending.is_none() && !self.failed {
            self.inner.into_io_halves()
        } else {
            let (read, write) = tokio::io::split(self);
            (Box::new(read), Box::new(write))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::AsyncWriteExt;

    #[derive(Default)]
    struct Capture {
        writes: Vec<(tokio::time::Instant, Vec<u8>)>,
        dropped: bool,
    }
    struct Sink {
        capture: Arc<Mutex<Capture>>,
        chunk: usize,
        /// Reads never complete, and never wake their task.
        silent: bool,
    }
    impl Drop for Sink {
        fn drop(&mut self) {
            self.capture.lock().unwrap().dropped = true;
        }
    }
    impl AsyncRead for Sink {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.silent {
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Sink {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            let count = input.len().min(self.chunk);
            self.capture
                .lock()
                .unwrap()
                .writes
                .push((tokio::time::Instant::now(), input[..count].to_vec()));
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl TransportStream for Sink {
        fn poll_read_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.poll_read(cx, output)
        }
        fn poll_write_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.poll_write(cx, input)
        }
    }

    fn stream(config: TcpFragmentConfig, chunk: usize) -> (FragmentStream, Arc<Mutex<Capture>>) {
        stream_over(config, chunk, false)
    }
    fn stream_over(
        config: TcpFragmentConfig,
        chunk: usize,
        silent: bool,
    ) -> (FragmentStream, Arc<Mutex<Capture>>) {
        let capture = Arc::new(Mutex::new(Capture::default()));
        (
            FragmentStream::new(
                Box::new(Sink {
                    capture: capture.clone(),
                    chunk,
                    silent,
                }),
                Arc::new(config),
            ),
            capture,
        )
    }
    fn cutting(
        packets: FragmentPackets,
        lengths: RangeInclusive<u32>,
        delays: RangeInclusive<u32>,
        max_split: RangeInclusive<u32>,
    ) -> TcpFragmentConfig {
        TcpFragmentConfig::new(vec![lengths], vec![delays], max_split)
            .unwrap()
            .with_packets(packets)
            .unwrap()
    }
    fn writes(capture: &Arc<Mutex<Capture>>) -> Vec<Vec<u8>> {
        capture
            .lock()
            .unwrap()
            .writes
            .iter()
            .map(|(_, bytes)| bytes.clone())
            .collect()
    }
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }
    fn bytes(capture: &Arc<Mutex<Capture>>) -> Vec<u8> {
        capture
            .lock()
            .unwrap()
            .writes
            .iter()
            .flat_map(|(_, b)| b.clone())
            .collect()
    }
    fn payloads(mut wire: &[u8]) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        while !wire.is_empty() {
            assert_eq!(&wire[..3], &[22, 3, 1]);
            let length = u16::from_be_bytes([wire[3], wire[4]]) as usize;
            records.push(wire[5..5 + length].to_vec());
            wire = &wire[5 + length..];
        }
        records
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_partial_writes_preserve_transcript_and_later_records() {
        let config = TcpFragmentConfig::new(vec![3..=3], vec![2..=2], 0..=0).unwrap();
        let (mut stream, capture) = stream(config, 3);
        let payload = b"hello-world";
        let input = record(payload);
        assert_eq!(stream.write(&input).await.unwrap(), input.len());
        stream.flush().await.unwrap();
        let emitted = payloads(&bytes(&capture));
        assert_eq!(
            emitted.iter().map(Vec::len).collect::<Vec<_>>(),
            [3, 3, 3, 2]
        );
        assert_eq!(emitted.concat(), payload);
        {
            let writes = capture.lock().unwrap();
            for record in 1..4 {
                assert_eq!(
                    writes.writes[record * 3].0 - writes.writes[(record - 1) * 3].0,
                    Duration::from_millis(2)
                );
            }
        }
        let before = bytes(&capture).len();
        stream.write_all(&input).await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(&bytes(&capture)[before..], input);
    }

    #[tokio::test]
    async fn zero_delay_merges_records_and_preserves_vectored_tail() {
        let config = TcpFragmentConfig::new(vec![1..=1, 2..=2], vec![0..=0], 3..=3).unwrap();
        let (mut stream, capture) = stream(config, usize::MAX);
        let hello = record(b"synthetic-finalized-reality-handshake");
        let tail = [20, 3, 3, 0, 1, 1];
        let inputs = [
            IoSlice::new(&hello[..2]),
            IoSlice::new(&hello[2..]),
            IoSlice::new(&tail),
        ];
        assert_eq!(
            stream.write_vectored(&inputs).await.unwrap(),
            hello.len() + tail.len()
        );
        stream.flush().await.unwrap();
        let data = bytes(&capture);
        assert_eq!(&data[data.len() - tail.len()..], &tail);
        let emitted = payloads(&data[..data.len() - tail.len()]);
        assert_eq!(emitted.len(), 3);
        assert_eq!(emitted[0].len(), 1);
        assert_eq!(emitted[1].len(), 2);
        assert_eq!(emitted.concat(), &hello[5..]);
        assert_eq!(
            capture.lock().unwrap().writes.len(),
            2,
            "one merged ClientHello write, one unchanged tail"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_drops_pending_records_and_timer() {
        let config = TcpFragmentConfig::new(vec![2..=2], vec![100..=100], 0..=0).unwrap();
        let (mut stream, capture) = stream(config, usize::MAX);
        stream.write_all(&record(b"synthetic-hello")).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(1), stream.flush())
                .await
                .is_err()
        );
        assert_eq!(payloads(&bytes(&capture)), [b"sy".to_vec()]);
        drop(stream);
        tokio::time::advance(Duration::from_secs(20)).await;
        assert!(capture.lock().unwrap().dropped);
        assert_eq!(payloads(&bytes(&capture)), [b"sy".to_vec()]);
    }

    #[tokio::test]
    async fn non_tls_and_incomplete_first_write_do_not_fragment_later_data() {
        for input in [b"GET / HTTP/1.1\r\n".to_vec(), vec![22, 3, 1, 0, 10, 1]] {
            let config = TcpFragmentConfig::new(vec![1..=1], vec![0..=0], 0..=0).unwrap();
            let (mut stream, capture) = stream(config, usize::MAX);
            stream.write_all(&input).await.unwrap();
            let next = record(b"unchanged second write");
            stream.write_all(&next).await.unwrap();
            stream.flush().await.unwrap();
            assert_eq!(bytes(&capture), [input, next].concat());
        }
    }

    #[test]
    fn planned_work_is_bounded_before_any_socket_write() {
        assert!(TcpFragmentConfig::new(vec![0..=1], vec![0..=0], 0..=0).is_err());
        assert!(TcpFragmentConfig::new(vec![1..=2; 17], vec![0..=0], 0..=0).is_err());
        assert!(TcpFragmentConfig::new(vec![1..=2], vec![1001..=1001], 0..=0).is_err());
        assert!(TcpFragmentConfig::new(vec![1..=2], vec![0..=0], 4097..=4097).is_err());
        let count = TcpFragmentConfig::new(vec![1..=1], vec![0..=0], 0..=0).unwrap();
        assert!(count.plan(&record(&vec![1; 4097])).is_err());
        let delay = TcpFragmentConfig::new(vec![1..=1], vec![1000..=1000], 0..=0).unwrap();
        assert!(delay.plan(&record(&[1; 11])).is_err());
        let limited = TcpFragmentConfig::new(vec![1..=1], vec![0..=0], 1..=1).unwrap();
        let large = record(&vec![1; MAX_RECORD]);
        assert_eq!(limited.plan(&large).unwrap().unwrap().wire, large);
    }

    #[tokio::test]
    async fn selected_writes_go_as_raw_pieces_and_the_others_unchanged() {
        let config = cutting(FragmentPackets::Writes(2..=3), 2..=2, 0..=0, 0..=0);
        let (mut stream, capture) = stream(config, usize::MAX);
        for input in [&b"aaaa"[..], b"bbbbb", b"cc", b"dddd"] {
            stream.write_all(input).await.unwrap();
            stream.flush().await.unwrap();
        }
        assert_eq!(
            writes(&capture),
            [&b"aaaa"[..], b"bb", b"bb", b"b", b"cc", b"dddd"].map(<[u8]>::to_vec)
        );
        assert!(
            stream.config.is_none(),
            "no write after the third is cut, so the mask steps aside"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn every_write_is_cut_with_a_delay_after_each_piece() {
        let config = cutting(FragmentPackets::AllWrites, 3..=3, 5..=5, 0..=0);
        let (mut stream, capture) = stream(config, usize::MAX);
        let start = tokio::time::Instant::now();
        stream.write_all(b"abcdefg").await.unwrap();
        stream.flush().await.unwrap();
        // Go's `Write` sleeps after its last piece too.
        assert_eq!(start.elapsed(), Duration::from_millis(15));
        stream.write_all(b"hi").await.unwrap();
        stream.flush().await.unwrap();
        let writes = capture.lock().unwrap().writes.clone();
        let pieces: Vec<_> = writes.iter().map(|(_, bytes)| bytes.clone()).collect();
        assert_eq!(
            pieces,
            [&b"abc"[..], b"def", b"g", b"hi"].map(<[u8]>::to_vec)
        );
        let times: Vec<_> = writes.iter().map(|(at, _)| *at - start).collect();
        assert_eq!(
            times,
            [0, 5, 10, 15].map(Duration::from_millis),
            "each piece waits for the delay after the one before"
        );
    }

    #[tokio::test]
    async fn the_max_split_piece_takes_the_rest_of_its_write() {
        let config = cutting(FragmentPackets::AllWrites, 1..=1, 0..=0, 2..=2);
        let (mut stream, capture) = stream(config, usize::MAX);
        stream.write_all(b"abcdef").await.unwrap();
        stream.write_all(b"gh").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(
            writes(&capture),
            [&b"a"[..], b"bcdef", b"g", b"h"].map(<[u8]>::to_vec)
        );
    }

    #[tokio::test]
    async fn a_long_write_keeps_its_number_and_pieces_across_calls() {
        let long = vec![7; MAX_STAGED_WRITE + 4464];
        let config = cutting(
            FragmentPackets::Writes(1..=1),
            16_384..=16_384,
            0..=0,
            0..=0,
        );
        let (mut whole, capture) = stream(config, usize::MAX);
        whole.write_all(&long).await.unwrap();
        whole.write_all(b"xyz").await.unwrap();
        whole.flush().await.unwrap();
        let lengths: Vec<_> = writes(&capture).iter().map(Vec::len).collect();
        assert_eq!(lengths, [16_384, 16_384, 16_384, 16_384, 4464, 3]);
        assert_eq!(writes(&capture).concat(), [long, b"xyz".to_vec()].concat());

        // A piece that reaches maxSplit takes the rest of the write, the part
        // the next call brings included.
        let long = vec![7; MAX_STAGED_WRITE + 4464];
        let config = cutting(
            FragmentPackets::Writes(1..=1),
            16_384..=16_384,
            0..=0,
            3..=3,
        );
        let (mut limited, capture) = stream(config, usize::MAX);
        limited.write_all(&long).await.unwrap();
        limited.flush().await.unwrap();
        let lengths: Vec<_> = writes(&capture).iter().map(Vec::len).collect();
        assert_eq!(lengths, [16_384, 16_384, 32_768, 4464]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_delay_bound_stages_part_of_a_write_and_continues_it() {
        let config = cutting(FragmentPackets::Writes(1..=1), 1..=1, 1000..=1000, 0..=0);
        let (mut stream, capture) = stream(config, usize::MAX);
        let input = *b"twenty-five bytes of data";
        assert_eq!(
            stream.write(&input).await.unwrap(),
            10,
            "ten seconds of delays"
        );
        stream.write_all(&input[10..]).await.unwrap();
        stream.write_all(b"after").await.unwrap();
        stream.flush().await.unwrap();
        let mut expected: Vec<_> = input.iter().map(|byte| vec![*byte]).collect();
        expected.push(b"after".to_vec());
        assert_eq!(writes(&capture), expected, "one write, cut whole");
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiting_reader_alone_drives_the_staged_pieces() {
        let config = cutting(FragmentPackets::AllWrites, 2..=2, 10..=10, 0..=0);
        let (stream, capture) = stream_over(config, usize::MAX, true);
        let (mut read, mut write) = Box::new(stream).into_io_halves();
        write.write_all(b"abcdef").await.unwrap();
        let reader = tokio::spawn(async move {
            let mut byte = [0];
            let _ = tokio::io::AsyncReadExt::read(&mut read, &mut byte).await;
        });
        tokio::task::yield_now().await;
        // The writer polls the timer after the reader, then gives up on its
        // flush: the timer wakes only the task that polled it last.
        assert!(tokio::time::timeout(Duration::ZERO, write.flush())
            .await
            .is_err());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            writes(&capture),
            [&b"ab"[..], b"cd", b"ef"].map(<[u8]>::to_vec)
        );
        reader.abort();
    }

    #[test]
    fn write_numbers_start_at_one_and_never_run_backwards() {
        let base = || TcpFragmentConfig::new(vec![1..=2], vec![0..=0], 0..=0).unwrap();
        assert!(base().with_packets(FragmentPackets::Writes(0..=3)).is_err());
        #[allow(clippy::reversed_empty_ranges)]
        let reversed = FragmentPackets::Writes(3..=2);
        assert!(base().with_packets(reversed).is_err());
        assert!(base().with_packets(FragmentPackets::Writes(1..=1)).is_ok());
        assert!(base().with_packets(FragmentPackets::AllWrites).is_ok());
    }
}
