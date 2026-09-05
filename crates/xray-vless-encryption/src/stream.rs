use std::{
    future::Future,
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{Aead, HeaderMask, MAX_NONCE, TAG_LEN},
    invalid_data,
    session::{Candidate, Lease},
    CipherSuite,
};

const WRITE_PLAINTEXT: usize = 8192;
const MAX_CIPHERTEXT: usize = 16640;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(feature = "fuzzing")]
#[path = "fuzzing.rs"]
pub mod fuzzing;

/// Bounded, cancellation-safe encrypted records. Buffered plaintext and
/// session material are wiped on drop. Vision alone may explicitly transition
/// each direction to the carrier, retaining random-mode TLS header masking.
pub struct EncryptedStream<S> {
    inner: S,
    united: Zeroizing<[u8; 96]>,
    write_aead: Aead,
    read_aead: Option<Aead>,
    write_mask: Option<HeaderMask>,
    read_mask: Option<HeaderMask>,
    pending: Zeroizing<Vec<u8>>,
    pending_pos: usize,
    header: [u8; 5],
    header_pos: usize,
    body: Zeroizing<Vec<u8>>,
    body_pos: usize,
    plain_pos: usize,
    plain_len: usize,
    padding: bool,
    failed: bool,
    eof: bool,
    write_closed: bool,
    direct_read: Option<DirectHeader>,
    direct_write: Option<DirectHeader>,
    prewrite: Option<Zeroizing<Vec<u8>>>,
    server_random: [u8; 16],
    server_random_pos: usize,
    resumed_random: bool,
    resumed_suite: CipherSuite,
    pub(crate) candidate: Option<Candidate>,
    lease: Option<Lease>,
    confirmation_deadline: Option<Pin<Box<Sleep>>>,
}

/// Incremental XorConn framing. The CTR state is shared with the preceding
/// encrypted records; only inner TLS headers consume its next bytes.
#[derive(Default)]
struct DirectHeader {
    header: [u8; 5],
    position: usize,
    skip: usize,
}

impl DirectHeader {
    fn apply(&mut self, data: &mut [u8], mask: &mut HeaderMask, writing: bool) -> io::Result<()> {
        for byte in data {
            if self.skip > 0 {
                self.skip -= 1;
                continue;
            }
            if writing {
                self.header[self.position] = *byte;
            }
            mask.apply(std::slice::from_mut(byte))?;
            if !writing {
                self.header[self.position] = *byte;
            }
            self.position += 1;
            if self.position == 5 {
                let length = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                // Same boundary as Xray's XorConn/DecodeHeader. On an invalid
                // header upstream resumes masking at the next byte; the inner
                // TLS engine owns authentication and rejects malformed TLS.
                self.skip =
                    if self.header[..3] == [23, 3, 3] && (17..=MAX_CIPHERTEXT).contains(&length) {
                        length
                    } else {
                        0
                    };
                self.position = 0;
            }
        }
        Ok(())
    }
}

impl<S> EncryptedStream<S> {
    pub(crate) fn new(
        inner: S,
        united: Zeroizing<[u8; 96]>,
        write_aead: Aead,
        read_aead: Option<Aead>,
        masks: Option<(HeaderMask, HeaderMask)>,
        padding_len: usize,
    ) -> Self {
        let (write_mask, read_mask) = masks.map_or((None, None), |(a, b)| (Some(a), Some(b)));
        let suite = write_aead.suite;
        Self {
            inner,
            united,
            write_aead,
            read_aead,
            write_mask,
            read_mask,
            pending: Zeroizing::new(Vec::with_capacity(5 + WRITE_PLAINTEXT + TAG_LEN)),
            pending_pos: 0,
            header: [0; 5],
            header_pos: 0,
            body: Zeroizing::new(vec![0; padding_len]),
            body_pos: 0,
            plain_pos: 0,
            plain_len: 0,
            padding: padding_len > 0,
            failed: false,
            eof: false,
            write_closed: false,
            direct_read: None,
            direct_write: None,
            prewrite: None,
            server_random: [0; 16],
            server_random_pos: 0,
            resumed_random: false,
            resumed_suite: suite,
            candidate: None,
            lease: None,
            confirmation_deadline: None,
        }
    }

    pub(crate) fn resumed(
        inner: S,
        united: Zeroizing<[u8; 96]>,
        write_aead: Aead,
        write_mask: Option<HeaderMask>,
        prefix: Vec<u8>,
        lease: Lease,
        confirmation_deadline: Instant,
    ) -> Self {
        let suite = write_aead.suite;
        let random = write_mask.is_some();
        Self {
            inner,
            united,
            write_aead,
            read_aead: None,
            write_mask,
            read_mask: None,
            pending: Zeroizing::new(Vec::with_capacity(5 + WRITE_PLAINTEXT + TAG_LEN)),
            pending_pos: 0,
            header: [0; 5],
            header_pos: 0,
            body: Zeroizing::new(Vec::new()),
            body_pos: 0,
            plain_pos: 0,
            plain_len: 0,
            padding: false,
            failed: false,
            eof: false,
            write_closed: false,
            direct_read: None,
            direct_write: None,
            prewrite: Some(Zeroizing::new(prefix)),
            server_random: [0; 16],
            server_random_pos: 0,
            resumed_random: random,
            resumed_suite: suite,
            candidate: None,
            lease: Some(lease),
            confirmation_deadline: Some(Box::pin(tokio::time::sleep_until(confirmation_deadline))),
        }
    }

    fn check_confirmation_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.lease.is_none() {
            self.confirmation_deadline = None;
            return Ok(());
        }
        if self
            .confirmation_deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "VLESS encryption resumption confirmation timed out",
            ));
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: io::Error) -> Poll<io::Result<T>> {
        self.failed = true;
        self.pending.zeroize();
        self.body.zeroize();
        // A resumed stream is trusted only after its first authenticated
        // server record. Invalidate the leased ticket at the first failure so
        // another connection cannot race with a poisoned stream that remains
        // alive in caller state.
        drop(self.lease.take());
        self.confirmation_deadline = None;
        self.candidate.take();
        Poll::Ready(Err(error))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedStream<S> {
    /// Transition the read direction after an authenticated Vision Direct
    /// command. Drain already authenticated plaintext before reading the carrier.
    /// This must only be called by a negotiated Vision stream; inner TLS now
    /// owns payload authentication. Outer carrier security is never bypassed.
    pub fn poll_read_vision_direct(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(invalid_data()));
        }
        if let Err(error) = self.check_confirmation_deadline(cx) {
            return self.fail(error);
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.direct_read.is_none() {
            if self.padding
                || self.read_aead.is_none()
                || self.header_pos != 0
                || (self.plain_pos == self.plain_len && !self.body.is_empty())
            {
                return self.fail(invalid_data());
            }
            self.direct_read = Some(DirectHeader::default());
        }
        // AsyncRead routes here only once the last decrypted record is drained.
        if self.plain_pos < self.plain_len {
            return Pin::new(self).poll_read(cx, output);
        }
        if let Poll::Ready(Err(error)) = self.poll_flush_pending(cx) {
            return Poll::Ready(Err(error));
        }
        let start = output.filled().len();
        if let Err(error) = ready!(Pin::new(&mut self.inner).poll_read(cx, output)) {
            return self.fail(error);
        }
        if let Some(mask) = &mut self.read_mask {
            if let Err(error) = self
                .direct_read
                .as_mut()
                .expect("direct read initialized")
                .apply(&mut output.filled_mut()[start..], mask, false)
            {
                // Do not expose bytes from a failed mask operation.
                output.set_filled(start);
                return self.fail(error);
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Transition the write direction only after Vision's Direct frame. Pending
    /// encrypted bytes are flushed first. Random-mode header state advances when
    /// input is accepted, and buffered output survives cancellation/backpressure.
    pub fn poll_write_vision_direct(
        &mut self,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed {
            return Poll::Ready(Err(invalid_data()));
        }
        if let Err(error) = self.check_confirmation_deadline(cx) {
            return self.fail(error);
        }
        if self.write_closed {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.prewrite.is_some() {
            return self.fail(invalid_data());
        }
        ready!(self.poll_flush_pending(cx))?;
        let state = self.direct_write.get_or_insert_with(DirectHeader::default);
        let n = input.len().min(WRITE_PLAINTEXT);
        self.pending.extend_from_slice(&input[..n]);
        if let Some(mask) = &mut self.write_mask {
            if let Err(error) = state.apply(&mut self.pending, mask, true) {
                return self.fail(error);
            }
        }
        if let Poll::Ready(Err(error)) = self.drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(n))
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]))
            {
                Ok(0) => return self.fail(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(n) => self.pending_pos += n,
                Err(error) => return self.fail(error),
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        match ready!(Pin::new(&mut self.inner).poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => self.fail(error),
        }
    }

    fn seal_record(&mut self, input: &[u8]) -> io::Result<()> {
        let length = (input.len() + TAG_LEN) as u16;
        let [hi, lo] = length.to_be_bytes();
        let header = [23, 3, 3, hi, lo];
        // Seal in the reusable output buffer, then make room for the header.
        self.pending.extend_from_slice(input);
        let rekey = self.write_aead.nonce == MAX_NONCE;
        self.write_aead.seal(&mut self.pending, &header)?;
        let len = self.pending.len();
        self.pending.resize(len + 5, 0);
        self.pending.copy_within(..len, 5);
        self.pending[..5].copy_from_slice(&header);
        if rekey {
            self.write_aead =
                Aead::new(&self.pending, self.united.as_ref(), self.write_aead.suite)?;
        }
        if let Some(mask) = &mut self.write_mask {
            mask.apply(&mut self.pending[..5])?;
        }
        if let Some(prefix) = self.prewrite.take() {
            let mut joined = Zeroizing::new(Vec::with_capacity(prefix.len() + self.pending.len()));
            joined.extend_from_slice(&prefix);
            joined.extend_from_slice(&self.pending);
            self.pending.zeroize();
            self.pending = joined;
        }
        Ok(())
    }

    fn open_record(&mut self) -> io::Result<()> {
        // Preserve the authenticated ciphertext context before in-place open.
        let read_aead = self.read_aead.as_mut().ok_or_else(invalid_data)?;
        let rekey = if read_aead.nonce == MAX_NONCE {
            let mut context = Vec::with_capacity(5 + self.body.len());
            context.extend_from_slice(&self.header);
            context.extend_from_slice(&self.body);
            Some(Aead::new(&context, self.united.as_ref(), read_aead.suite)?)
        } else {
            None
        };
        let len = read_aead.open(&mut self.body, &self.header)?;
        if let Some(next) = rekey {
            self.read_aead = Some(next);
        }
        if let Some(lease) = self.lease.take() {
            lease.confirm();
        }
        self.confirmation_deadline = None;
        self.plain_len = len;
        self.plain_pos = 0;
        self.header_pos = 0;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid_data()));
        }
        if let Err(error) = this.check_confirmation_deadline(cx) {
            return this.fail(error);
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.direct_read.is_some() && this.plain_pos == this.plain_len {
            return this.poll_read_vision_direct(cx, output);
        }
        // A caller may write a request then immediately read without flushing.
        // Make progress on a queued request, but do not block receiving while
        // the peer applies write backpressure: both directions may be active.
        if let Poll::Ready(Err(error)) = this.poll_flush_pending(cx) {
            return Poll::Ready(Err(error));
        }
        loop {
            if this.plain_pos < this.plain_len {
                let n = output.remaining().min(this.plain_len - this.plain_pos);
                let bytes = &mut this.body[this.plain_pos..this.plain_pos + n];
                output.put_slice(bytes);
                bytes.zeroize();
                this.plain_pos += n;
                if this.plain_pos == this.plain_len {
                    this.body.zeroize();
                    this.body.clear();
                    this.body_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.read_aead.is_none() {
                while this.server_random_pos < this.server_random.len() {
                    let start = this.server_random_pos;
                    let mut buf = ReadBuf::new(&mut this.server_random[start..]);
                    if let Err(error) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buf)) {
                        return this.fail(error);
                    }
                    let n = buf.filled().len();
                    if n == 0 {
                        return this.fail(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    this.server_random_pos += n;
                }
                match Aead::new(
                    &this.server_random,
                    this.united.as_ref(),
                    this.resumed_suite,
                ) {
                    Ok(aead) => this.read_aead = Some(aead),
                    Err(error) => return this.fail(error),
                }
                if this.resumed_random {
                    this.read_mask =
                        Some(HeaderMask::new(this.united.as_ref(), &this.server_random));
                }
                this.server_random.zeroize();
            }
            if !this.padding && this.body.is_empty() {
                while this.header_pos < 5 {
                    let mut buf = ReadBuf::new(&mut this.header[this.header_pos..]);
                    if let Err(error) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buf)) {
                        return this.fail(error);
                    }
                    let n = buf.filled().len();
                    if n == 0 {
                        if this.header_pos == 0 {
                            // EOF before the first authenticated resumed
                            // record is a failed resumption, not confirmation.
                            drop(this.lease.take());
                            this.confirmation_deadline = None;
                            this.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        return this.fail(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    this.header_pos += n;
                }
                if let Some(mask) = &mut this.read_mask {
                    if let Err(error) = mask.apply(&mut this.header) {
                        return this.fail(error);
                    }
                }
                let length = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
                if this.header[..3] != [23, 3, 3] || !(17..=MAX_CIPHERTEXT).contains(&length) {
                    return this.fail(invalid_data());
                }
                this.body.resize(length, 0);
                this.body_pos = 0;
            }
            while this.body_pos < this.body.len() {
                let mut buf = ReadBuf::new(&mut this.body[this.body_pos..]);
                if let Err(error) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buf)) {
                    return this.fail(error);
                }
                let n = buf.filled().len();
                if n == 0 {
                    return this.fail(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                this.body_pos += n;
            }
            if this.padding {
                if let Err(error) = this
                    .read_aead
                    .as_mut()
                    .expect("read AEAD initialized")
                    .open(&mut this.body, &[])
                {
                    return this.fail(error);
                }
                this.body.zeroize();
                this.body.clear();
                this.body_pos = 0;
                this.padding = false;
                if let Some(candidate) = this.candidate.take() {
                    candidate.publish();
                }
            } else if let Err(error) = this.open_record() {
                return this.fail(error);
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid_data()));
        }
        if let Err(error) = this.check_confirmation_deadline(cx) {
            return this.fail(error);
        }
        if this.write_closed {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.direct_write.is_some() {
            return this.poll_write_vision_direct(cx, input);
        }
        ready!(this.drain(cx))?;
        let n = input.len().min(WRITE_PLAINTEXT);
        if let Err(error) = this.seal_record(&input[..n]) {
            return this.fail(error);
        }
        // Ownership transfers now, even if the carrier applies backpressure.
        // A cancelled subsequent write/flush retains this ciphertext and nonce.
        if let Poll::Ready(Err(error)) = this.drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid_data()));
        }
        if let Err(error) = this.check_confirmation_deadline(cx) {
            return this.fail(error);
        }
        this.poll_flush_pending(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid_data()));
        }
        if let Err(error) = this.check_confirmation_deadline(cx) {
            return this.fail(error);
        }
        ready!(this.poll_flush_pending(cx))?;
        match ready!(Pin::new(&mut this.inner).poll_shutdown(cx)) {
            Ok(()) => {
                this.write_closed = true;
                drop(this.lease.take());
                this.confirmation_deadline = None;
                Poll::Ready(Ok(()))
            }
            Err(error) => this.fail(error),
        }
    }
}
