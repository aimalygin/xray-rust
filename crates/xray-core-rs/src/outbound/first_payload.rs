//! Request headers held back so they leave together with the first payload.
//!
//! Xray-core buffers an outbound request header and waits a bounded time for
//! the first client payload, so header and payload go out in one write and,
//! over TLS or REALITY, in one record. Only when the wait expires does it
//! send the header alone (`proxy/vless/outbound/outbound.go:311-345`,
//! `proxy/trojan/client.go:102-123`). Writing the header eagerly instead
//! gives the first record a fixed, header-only size.
use super::*;
use std::future::Future;
use std::task::ready;
use tokio::time::Sleep;

/// Xray-core's VLESS wait for the first payload
/// (`ReadMultiBufferTimeout(time.Millisecond * 500)`).
pub(super) const VLESS_FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(500);
/// Xray-core's Trojan wait (`buf.CopyOnceTimeout(..., time.Millisecond*100)`).
pub(super) const TROJAN_FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(100);

/// Carrier wrapper that prepends a held request header to the first write.
///
/// The header and the first payload are handed to the carrier in a single
/// `poll_write`, which TLS seals into a single record. A flush or shutdown
/// before any payload sends the header alone.
pub(super) struct HeldHeader {
    inner: BoxedTransportStream,
    pending: Zeroizing<Vec<u8>>,
    pending_pos: usize,
    merged: bool,
}

impl HeldHeader {
    pub(super) fn new(inner: BoxedTransportStream, header: &[u8]) -> Self {
        Self {
            inner,
            pending: Zeroizing::new(header.to_vec()),
            pending_pos: 0,
            merged: false,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match ready!(
                Pin::new(&mut *self.inner).poll_write(cx, &self.pending[self.pending_pos..])
            )? {
                0 => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                n => self.pending_pos += n,
            }
        }
        if !self.pending.is_empty() {
            // Wipe the header copy as soon as it has been handed over.
            self.pending = Zeroizing::new(Vec::new());
            self.pending_pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for HeldHeader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for HeldHeader {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.merged && !input.is_empty() {
            this.merged = true;
            this.pending.extend_from_slice(input);
            // The payload is owned now; a pending carrier finishes it on the
            // next write or flush.
            if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
                return Poll::Ready(Err(error));
            }
            return Poll::Ready(Ok(input.len()));
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_write(cx, input)
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

impl TransportStream for HeldHeader {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read_direct(cx, output)
    }

    #[cfg(target_os = "linux")]
    fn raw_read_direct(&mut self) -> xray_transport::RawRead<'_> {
        self.inner.raw_read_direct()
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Direct mode only starts after padded writes, so the header is gone.
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_shutdown_direct(cx)
    }
}

/// Outer wrapper that bounds how long a held header waits for a payload.
///
/// The relay polls reads from the start, so the deadline is driven from
/// `poll_read`: once it expires without a write, `on_timeout` runs (Vision
/// queues its empty padding frame there) and the stream is flushed, which
/// sends the held header. Any write, flush or shutdown disarms it.
pub(super) struct FirstPayloadDeadline<S> {
    inner: S,
    deadline: Option<Pin<Box<Sleep>>>,
    on_timeout: fn(&mut S) -> io::Result<()>,
    flushing: bool,
}

impl<S> FirstPayloadDeadline<S> {
    pub(super) fn new(inner: S, wait: Duration, on_timeout: fn(&mut S) -> io::Result<()>) -> Self {
        Self {
            inner,
            deadline: Some(Box::pin(tokio::time::sleep(wait))),
            on_timeout,
            flushing: false,
        }
    }

    fn disarm(&mut self) {
        self.deadline = None;
        self.flushing = false;
    }
}

impl<S: TransportStream> FirstPayloadDeadline<S> {
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(deadline) = &mut self.deadline {
            if deadline.as_mut().poll(cx).is_ready() {
                self.deadline = None;
                (self.on_timeout)(&mut self.inner)?;
                self.flushing = true;
            }
        }
        if self.flushing {
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.flushing = false;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: TransportStream> AsyncRead for FirstPayloadDeadline<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_expired(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<S: TransportStream> AsyncWrite for FirstPayloadDeadline<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !input.is_empty() {
            this.disarm();
        }
        Pin::new(&mut this.inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.disarm();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.disarm();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: TransportStream> TransportStream for FirstPayloadDeadline<S> {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_expired(cx))?;
        Pin::new(&mut this.inner).poll_read_direct(cx, output)
    }

    #[cfg(target_os = "linux")]
    fn raw_read(&mut self) -> xray_transport::RawRead<'_> {
        // Reads drive the deadline and the flush that follows it.
        if self.deadline.is_some() || self.flushing {
            return xray_transport::RawRead::NotYet;
        }
        self.inner.raw_read()
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !input.is_empty() {
            this.disarm();
        }
        Pin::new(&mut this.inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.disarm();
        Pin::new(&mut this.inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.disarm();
        Pin::new(&mut this.inner).poll_shutdown_direct(cx)
    }
}

/// Timeout action for protocols whose held header is sent alone.
pub(super) fn flush_header_alone<S>(_: &mut S) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;

    type Writes = Arc<Mutex<Vec<Vec<u8>>>>;

    /// Carrier that records every `poll_write` and never yields read data.
    #[derive(Default)]
    struct Recorder {
        writes: Writes,
        timeouts: usize,
    }

    impl AsyncRead for Recorder {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(input.to_vec());
            Poll::Ready(Ok(input.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl TransportStream for Recorder {
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

    const HEADER: &[u8] = b"request-header";

    fn held(wait: Duration) -> (FirstPayloadDeadline<HeldHeader>, Writes) {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let stream = FirstPayloadDeadline::new(
            HeldHeader::new(Box::new(recorder), HEADER),
            wait,
            flush_header_alone,
        );
        (stream, writes)
    }

    #[tokio::test(start_paused = true)]
    async fn header_and_first_payload_share_one_carrier_write() {
        let (mut stream, writes) = held(TROJAN_FIRST_PAYLOAD_WAIT);
        assert!(writes.lock().unwrap().is_empty());
        stream.write_all(b"first payload").await.unwrap();
        stream.write_all(b"second").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(
            *writes.lock().unwrap(),
            [b"request-headerfirst payload".to_vec(), b"second".to_vec()]
        );
        // A late deadline must not emit anything once the header is gone.
        tokio::time::advance(TROJAN_FIRST_PAYLOAD_WAIT * 2).await;
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_millis(1), stream.read(&mut byte)).await;
        assert!(read.is_err());
        assert_eq!(writes.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn header_is_sent_alone_only_after_the_wait_expires() {
        let (mut stream, writes) = held(VLESS_FIRST_PAYLOAD_WAIT);
        let mut byte = [0; 1];
        let early = VLESS_FIRST_PAYLOAD_WAIT - Duration::from_millis(1);
        assert!(tokio::time::timeout(early, stream.read(&mut byte))
            .await
            .is_err());
        assert!(writes.lock().unwrap().is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(2), stream.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(*writes.lock().unwrap(), [HEADER.to_vec()]);
        stream.write_all(b"late payload").await.unwrap();
        assert_eq!(
            *writes.lock().unwrap(),
            [HEADER.to_vec(), b"late payload".to_vec()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_action_runs_once_before_the_flush() {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let mut stream = FirstPayloadDeadline::new(recorder, TROJAN_FIRST_PAYLOAD_WAIT, |inner| {
            inner.timeouts += 1;
            inner.writes.lock().unwrap().push(b"padding".to_vec());
            Ok(())
        });
        let mut byte = [0; 1];
        let wait = TROJAN_FIRST_PAYLOAD_WAIT * 3;
        assert!(tokio::time::timeout(wait, stream.read(&mut byte))
            .await
            .is_err());
        assert_eq!(stream.inner.timeouts, 1);
        assert_eq!(*writes.lock().unwrap(), [b"padding".to_vec()]);
    }

    fn vision(recorder: Recorder) -> FirstPayloadDeadline<VisionOutboundStream> {
        let carrier: BoxedTransportStream = Box::new(HeldHeader::new(Box::new(recorder), HEADER));
        let stream = VlessResponseStream::new(VisionTransportStream::new(carrier));
        FirstPayloadDeadline::new(
            VisionOutboundStream::new(VisionStream::new(
                stream,
                [7; 16],
                xray_proxy::vless::DEFAULT_VISION_SEED,
            )),
            VLESS_FIRST_PAYLOAD_WAIT,
            |stream| stream.inner.queue_empty_padding_frame(),
        )
    }

    /// Header, UUID and the padded frame header in front of the content.
    const VISION_PREFIX: usize = HEADER.len() + 16 + 5;

    #[tokio::test(start_paused = true)]
    async fn vision_header_leaves_with_the_padded_first_payload() {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let mut stream = vision(recorder);
        stream.write_all(b"client hello").await.unwrap();
        stream.flush().await.unwrap();
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "no empty padding frame before the payload");
        assert!(writes[0].starts_with(HEADER));
        assert_eq!(writes[0][HEADER.len()..][..16], [7; 16]);
        assert_eq!(writes[0][VISION_PREFIX..][..12], *b"client hello");
    }

    #[tokio::test(start_paused = true)]
    async fn vision_timeout_pads_an_empty_frame_behind_the_header() {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let mut stream = vision(recorder);
        let mut byte = [0; 1];
        let wait = VLESS_FIRST_PAYLOAD_WAIT + Duration::from_millis(1);
        assert!(tokio::time::timeout(wait, stream.read(&mut byte))
            .await
            .is_err());
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].starts_with(HEADER));
        assert_eq!(writes[0][HEADER.len()..][..16], [7; 16]);
        // Empty content with Xray's long padding (seed 900 + random 0..500).
        let frame = &writes[0][HEADER.len() + 16..];
        assert_eq!(frame[1..3], [0, 0]);
        let padding = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        assert!((900..1400).contains(&padding), "{padding}");
        assert_eq!(writes[0].len(), VISION_PREFIX + padding);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_without_payload_still_sends_the_header() {
        let (mut stream, writes) = held(TROJAN_FIRST_PAYLOAD_WAIT);
        stream.shutdown().await.unwrap();
        assert_eq!(*writes.lock().unwrap(), [HEADER.to_vec()]);
    }
}
