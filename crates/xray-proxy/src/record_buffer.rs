//! Bounded ciphertext read-ahead and in-place plaintext storage in one allocation.
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};
use zeroize::Zeroizing;

// Largest accepted SS2022 ciphertext body plus a length record. VMess fits too.
const MAX_FRAME: usize = 65535 + 16;
const PREFIX: usize = 18;
const MAX_BUFFER: usize = MAX_FRAME + PREFIX;

pub(crate) struct RecordBuffer {
    bytes: Zeroizing<Vec<u8>>,
    start: usize,
    filled: usize,
    needed: usize,
    prefix: usize,
    read_ahead: usize,
}

impl RecordBuffer {
    pub(crate) fn new(needed: usize, prefix: usize) -> Self {
        assert!(needed <= MAX_FRAME && prefix <= PREFIX);
        Self {
            bytes: Zeroizing::new(Vec::new()),
            start: 0,
            filled: 0,
            needed,
            prefix,
            read_ahead: 0,
        }
    }

    /// Grow on the next read, after the caller has erased the current plaintext.
    /// This is a capacity floor, never a requirement to fill the buffer.
    pub(crate) fn set_read_ahead(&mut self, bytes: usize) {
        assert!(bytes <= MAX_BUFFER);
        self.read_ahead = bytes;
    }

    /// Only expose the current frame, never unauthenticated following records.
    pub(crate) fn frame(&mut self) -> &mut [u8] {
        debug_assert!(self.filled - self.start >= self.needed);
        &mut self.bytes[self.start..self.start + self.needed]
    }

    /// The caller must erase consumed plaintext before advancing. Remaining
    /// bytes are ciphertext; compaction cannot duplicate live plaintext.
    pub(crate) fn advance(&mut self, needed: usize) {
        assert!(needed <= MAX_FRAME);
        debug_assert!(self.filled - self.start >= self.needed);
        self.start += self.needed;
        if self.start == self.filled {
            self.start = 0;
            self.filled = 0;
        }
        self.needed = needed;
    }

    /// false is a clean boundary EOF; a partial frame is always an error.
    pub(crate) fn poll_frame<S: AsyncRead + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        if self.filled - self.start >= self.needed {
            return Poll::Ready(Ok(true));
        }
        // A prefix plus the current body fits in the same allocation. Round
        // by 64 bytes to avoid repeated growth for VMess's random padding.
        // No eager full-record buffer, second plaintext buffer or global pool.
        let size = (self.needed + self.prefix)
            .next_multiple_of(64)
            .max(self.read_ahead)
            .min(MAX_BUFFER);
        if self.bytes.len() < size {
            let extra = size - self.bytes.len();
            self.bytes.reserve_exact(extra);
            self.bytes.resize(size, 0);
        }
        if self.start + self.needed > self.bytes.len() {
            self.bytes.copy_within(self.start..self.filled, 0);
            self.filled -= self.start;
            self.start = 0;
        }
        while self.filled - self.start < self.needed {
            let mut read = ReadBuf::new(&mut self.bytes[self.filled..]);
            ready!(Pin::new(&mut *inner).poll_read(cx, &mut read))?;
            let n = read.filled().len();
            if n == 0 {
                return Poll::Ready(if self.filled == self.start {
                    Ok(false)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                });
            }
            self.filled += n;
        }
        Poll::Ready(Ok(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, task::Waker};
    use zeroize::Zeroize;

    #[derive(Default)]
    struct Source {
        bytes: VecDeque<u8>,
        reads: usize,
        closed: bool,
    }
    impl AsyncRead for Source {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.reads += 1;
            if self.bytes.is_empty() && !self.closed {
                return Poll::Pending;
            }
            while out.remaining() > 0 {
                let Some(byte) = self.bytes.pop_front() else {
                    break;
                };
                out.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn read_ahead_coalesces_records_but_never_waits_to_fill_capacity() {
        let mut source = Source::default();
        let mut buffer = RecordBuffer::new(2, 2);
        let mut cx = Context::from_waker(Waker::noop());
        buffer.set_read_ahead(16 * 1024);
        assert!(buffer.bytes.is_empty());
        for _ in 0..2 {
            source.bytes.extend([1; 2]);
            source.bytes.extend([2; 8190]);
        }
        for _ in 0..2 {
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(true))
            ));
            assert_eq!(buffer.frame(), &[1; 2]);
            buffer.frame().zeroize();
            buffer.advance(8190);
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(true))
            ));
            assert!(buffer.frame().iter().all(|&b| b == 2));
            buffer.frame().zeroize();
            buffer.advance(2);
        }
        assert_eq!(source.reads, 1);
        assert_eq!(buffer.bytes.capacity(), 16 * 1024);
        // A short prefix succeeds immediately even though the capacity is large.
        source.bytes.extend([3; 2]);
        assert!(matches!(
            buffer.poll_frame(&mut source, &mut cx),
            Poll::Ready(Ok(true))
        ));
        assert_eq!(buffer.frame(), &[3; 2]);
    }

    #[test]
    fn coalesces_prefix_and_payload_without_a_second_allocation() {
        let mut source = Source::default();
        let mut buffer = RecordBuffer::new(18, 18);
        let mut cx = Context::from_waker(Waker::noop());
        // After learning one body size, a whole subsequent record fits in a
        // single read. Authentication/plaintext erasure are the caller's job.
        for _ in 0..5 {
            source.bytes.extend([1; 18]);
            source.bytes.extend([2; 8192]);
            let before = source.reads;
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(true))
            ));
            assert_eq!(buffer.frame(), &[1; 18]);
            buffer.frame().zeroize();
            buffer.advance(8192);
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(true))
            ));
            assert!(buffer.frame().iter().all(|b| *b == 2));
            buffer.frame().zeroize();
            buffer.advance(18);
            assert!(source.reads - before <= 2);
            if before != 0 {
                assert_eq!(source.reads - before, 1);
            }
            assert!(buffer.bytes.len() <= 8192 + PREFIX + 63);
            assert!(buffer.bytes.capacity() <= 8192 + PREFIX + 63);
        }
    }

    #[test]
    fn vmess_two_byte_prefix_keeps_an_eight_kib_record_in_eight_kib_storage() {
        let mut source = Source::default();
        let mut buffer = RecordBuffer::new(2, 2);
        let mut cx = Context::from_waker(Waker::noop());
        source.bytes.extend(vec![1; 8192]);
        assert!(matches!(
            buffer.poll_frame(&mut source, &mut cx),
            Poll::Ready(Ok(true))
        ));
        buffer.frame().zeroize();
        buffer.advance(8190);
        assert!(matches!(
            buffer.poll_frame(&mut source, &mut cx),
            Poll::Ready(Ok(true))
        ));
        assert_eq!(buffer.bytes.len(), 8192);
        assert_eq!(buffer.bytes.capacity(), 8192);
    }

    #[test]
    fn mixed_and_maximum_frames_survive_compaction_with_bounded_storage() {
        let sizes = [18, 8192, 2, 100, MAX_FRAME, 18, 1, 16384];
        let mut source = Source::default();
        for (i, size) in sizes.iter().enumerate() {
            source.bytes.extend(vec![i as u8 + 1; *size]);
        }
        source.closed = true;
        let mut buffer = RecordBuffer::new(sizes[0], 18);
        let mut cx = Context::from_waker(Waker::noop());
        for (i, size) in sizes.iter().enumerate() {
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(true))
            ));
            assert_eq!(buffer.frame(), vec![i as u8 + 1; *size]);
            buffer.frame().zeroize();
            buffer.advance(*sizes.get(i + 1).unwrap_or(&18));
            assert!(buffer.bytes.len() <= MAX_BUFFER);
            assert!(buffer.bytes.capacity() <= MAX_BUFFER);
        }
        assert!(matches!(
            buffer.poll_frame(&mut source, &mut cx),
            Poll::Ready(Ok(false))
        ));
    }

    #[test]
    fn cancellation_compaction_and_eof_preserve_exact_frame_boundaries() {
        let mut cx = Context::from_waker(Waker::noop());
        for split in 0..100 {
            let mut source = Source::default();
            let mut buffer = RecordBuffer::new(2, 2);
            source.bytes.extend([7; 2]);
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(true))
            ));
            buffer.frame().zeroize();
            buffer.advance(100);
            source.bytes.extend(vec![8; split]);
            assert!(buffer.poll_frame(&mut source, &mut cx).is_pending());
            source.bytes.extend(vec![8; 100 - split]);
            source.bytes.extend([9; 2]);
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(true))
            ));
            assert_eq!(buffer.frame(), &[8; 100]);
            buffer.frame().zeroize();
            buffer.advance(2);
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(true))
            ));
            assert_eq!(buffer.frame(), &[9; 2]);
            buffer.frame().zeroize();
            buffer.advance(2);
            source.closed = true;
            assert!(matches!(
                buffer.poll_frame(&mut source, &mut cx),
                Poll::Ready(Ok(false))
            ));
            source.bytes.push_back(1);
            assert!(
                matches!(buffer.poll_frame(&mut source, &mut cx), Poll::Ready(Err(e)) if e.kind()==io::ErrorKind::UnexpectedEof)
            );
        }
    }
}
