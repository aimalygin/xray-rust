//! Bounded, one-shot Xray `tlshello` record fragmentation below TLS/REALITY.
//! Handshake bytes are unchanged; only the record envelopes are rebuilt.
use crate::{BoxedTransportStream, TransportStream};
use rand::Rng;
use std::{
    future::Future,
    io::{self, IoSlice},
    ops::RangeInclusive,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_FIRST_WRITE: usize = 65_536;
const MAX_RECORD: usize = 16_384;
const MAX_SPLITS: usize = 4096;
const MAX_TOTAL_DELAY_MS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpFragmentConfig {
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
            lengths,
            delays_ms,
            max_split,
        })
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

/// Owns all accepted bytes until flushed. No background task can outlive this
/// stream; dropping a cancelled handshake drops its socket, bytes and timer.
pub(crate) struct FragmentStream {
    inner: BoxedTransportStream,
    config: Option<Arc<TcpFragmentConfig>>,
    pending: Option<Pending>,
    failed: bool,
}

impl FragmentStream {
    pub(crate) fn new(inner: BoxedTransportStream, config: Arc<TcpFragmentConfig>) -> Self {
        Self {
            inner,
            config: Some(config),
            pending: None,
            failed: false,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fragmented handshake failed",
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
        ready!(this.poll_drain(cx))?;
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
        ready!(this.poll_drain(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let accepted = input.len().min(MAX_FIRST_WRITE);
        if this.stage(&input[..accepted])? {
            // Buffer acceptance is explicit. Returning Pending after emitting a
            // prefix would violate AsyncWrite's cancellation/partial-write rules.
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
        ready!(this.poll_drain(cx))?;
        if this.config.is_some() {
            let Some(first) = input.iter().find(|part| !part.is_empty()) else {
                return Poll::Ready(Ok(0));
            };
            if first[0] == 22 {
                let mut joined = Vec::new();
                for part in input {
                    let length = part.len().min(MAX_FIRST_WRITE - joined.len());
                    joined.extend_from_slice(&part[..length]);
                    if joined.len() == MAX_FIRST_WRITE {
                        break;
                    }
                }
                if this.stage(&joined)? {
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
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
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
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_read_direct(cx, output)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
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
        let capture = Arc::new(Mutex::new(Capture::default()));
        (
            FragmentStream::new(
                Box::new(Sink {
                    capture: capture.clone(),
                    chunk,
                }),
                Arc::new(config),
            ),
            capture,
        )
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
}
