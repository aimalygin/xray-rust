//! What one relay direction reads into.
//!
//! A direction reads into a small buffer of its own until a read fills it.
//! From then on its reads take twice as much each time one fills, up to the
//! cap, exactly as when the direction grew a buffer of its own; but the
//! memory past the small buffer is lent by the process, and the direction
//! gives it back as soon as a read finds nothing to take, and takes it again
//! when data returns.
//!
//! A direction that grew its own buffer kept it until its connection closed:
//! up to 128 KiB for each direction that ever moved bulk, however long ago.
//! Lent buffers are held only by the directions moving data at this moment,
//! so a process with many connections that are open but quiet keeps what its
//! busiest moment needed rather than the sum over all of them.

use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use xray_transport::MemoryClass;

/// The size of a lent buffer: the default cap of one read.
pub(super) const LENT_BUFFER_SIZE: usize = super::DEFAULT_COPY_BUFFER_SIZE;

/// Free buffers the process keeps for the next direction that needs one, by
/// memory class: 8 MiB and 2 MiB. One given back beyond that is freed.
const KEPT_BUFFERS: usize = 64;
const KEPT_BUFFERS_CONSTRAINED: usize = 16;

fn kept_buffers(class: MemoryClass) -> usize {
    match class {
        MemoryClass::Standard => KEPT_BUFFERS,
        MemoryClass::Constrained => KEPT_BUFFERS_CONSTRAINED,
    }
}

fn process_keeps() -> usize {
    kept_buffers(xray_transport::memory_class())
}

/// The large buffers no direction holds right now.
pub(super) struct Pool {
    free: Mutex<Vec<Box<[u8]>>>,
    /// How many free buffers to keep.
    keep: fn() -> usize,
    /// Whether each thread keeps the buffer it got back last beside those.
    thread_spare: bool,
}

thread_local! {
    /// The buffer this thread got back last, for [`PROCESS_POOL`]. A stream
    /// that reads in several steps finds nothing between them many times a
    /// second, and its direction gives its buffer back each time; the
    /// direction that takes one next on this thread is most often the same
    /// one, and gets it without the lock the pool's list needs.
    static THREAD_SPARE: Cell<Option<Box<[u8]>>> = const { Cell::new(None) };
}

/// The pool every relay in the process shares.
pub(super) static PROCESS_POOL: Pool = Pool {
    free: Mutex::new(Vec::new()),
    keep: process_keeps,
    thread_spare: true,
};

impl Pool {
    /// A pool of its own, without the threads' spares.
    #[cfg(test)]
    const fn new(keep: fn() -> usize) -> Self {
        Self {
            free: Mutex::new(Vec::new()),
            keep,
            thread_spare: false,
        }
    }

    /// The buffer given back last, which is the one most likely still in the
    /// processor's cache, or a new one.
    fn take(&self) -> Box<[u8]> {
        if self.thread_spare {
            // No spare is reachable while the thread is ending.
            if let Ok(Some(buffer)) = THREAD_SPARE.try_with(Cell::take) {
                return buffer;
            }
        }
        let kept = self
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        kept.unwrap_or_else(|| vec![0; LENT_BUFFER_SIZE].into_boxed_slice())
    }

    fn give_back(&self, buffer: Box<[u8]>) {
        let buffer = if self.thread_spare {
            // The thread keeps the newest; the one it kept goes to the list.
            // A thread that is ending keeps none, and the buffer is freed.
            match THREAD_SPARE.try_with(|spare| spare.replace(Some(buffer))) {
                Ok(Some(displaced)) => displaced,
                Ok(None) | Err(_) => return,
            }
        } else {
            buffer
        };
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        if free.len() < (self.keep)() {
            free.push(buffer);
        }
    }

    #[cfg(test)]
    fn free_buffers(&self) -> usize {
        self.free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Where reads past the small buffer go.
enum Large {
    None,
    /// From the pool, and back to it when a read finds nothing.
    Lent(Box<[u8]>),
    /// A cap above [`LENT_BUFFER_SIZE`] is the configuration asking for
    /// larger reads than the pool lends; the direction grows and keeps such
    /// a buffer.
    Owned(Vec<u8>),
}

pub(super) struct RelayBuffer<'p> {
    pool: &'p Pool,
    small: Box<[u8]>,
    large: Large,
    /// The most a read takes at all.
    cap: usize,
    /// The most the next read takes: the small buffer's size, doubled by
    /// every read that fills it, up to the cap. It never shrinks.
    limit: usize,
    /// Whether the last read went into the large buffer.
    read_into_large: bool,
}

impl<'p> RelayBuffer<'p> {
    pub(super) fn new(cap: usize, pool: &'p Pool) -> Self {
        let small = vec![0; cap.min(super::INITIAL_COPY_BUFFER_SIZE)].into_boxed_slice();
        Self {
            pool,
            limit: small.len(),
            small,
            large: Large::None,
            cap,
            read_into_large: false,
        }
    }

    /// Reads once. The bytes are [`Self::filled`] until the next call.
    pub(super) fn poll_read<R: AsyncRead + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        reader: Pin<&mut R>,
    ) -> Poll<io::Result<usize>> {
        let limit = self.limit;
        let into_large = limit > self.small.len();
        let target = if into_large {
            if matches!(self.large, Large::None) {
                self.large = if self.cap > LENT_BUFFER_SIZE {
                    Large::Owned(Vec::new())
                } else {
                    Large::Lent(self.pool.take())
                };
            }
            match &mut self.large {
                Large::Lent(buffer) => &mut buffer[..limit],
                Large::Owned(buffer) => {
                    if buffer.len() < limit {
                        buffer.resize(limit, 0);
                    }
                    &mut buffer[..limit]
                }
                Large::None => unreachable!("a read past the small buffer has its large one"),
            }
        } else {
            &mut self.small[..]
        };
        let mut read = ReadBuf::new(target);
        match reader.poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let len = read.filled().len();
                self.read_into_large = into_large;
                if len == limit && limit < self.cap {
                    self.limit = (limit * 2).min(self.cap);
                }
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                self.give_back();
                Poll::Pending
            }
        }
    }

    /// The first `len` bytes of the last read.
    pub(super) fn filled(&self, len: usize) -> &[u8] {
        if self.read_into_large {
            match &self.large {
                Large::Lent(buffer) => &buffer[..len],
                Large::Owned(buffer) => &buffer[..len],
                Large::None => unreachable!("the last read's buffer is held until the next read"),
            }
        } else {
            &self.small[..len]
        }
    }

    /// Returns a lent buffer to the pool.
    fn give_back(&mut self) {
        if matches!(self.large, Large::Lent(_)) {
            if let Large::Lent(buffer) = std::mem::replace(&mut self.large, Large::None) {
                self.pool.give_back(buffer);
            }
        }
    }
}

impl Drop for RelayBuffer<'_> {
    fn drop(&mut self) {
        self.give_back();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::task::Waker;

    use super::*;

    const SMALL: usize = super::super::INITIAL_COPY_BUFFER_SIZE;
    const KIB: usize = 1024;

    fn keep_two() -> usize {
        2
    }

    /// What a reader does at each read: hands over that many bytes, or has
    /// nothing yet.
    enum Step {
        Bytes(usize),
        Nothing,
    }

    /// As many bytes as the read takes.
    const FULL: Step = Step::Bytes(usize::MAX);

    struct Scripted {
        steps: VecDeque<Step>,
        /// The value of the next byte, so that order and content are checked.
        next: u8,
    }

    impl Scripted {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                next: 0,
            }
        }
    }

    impl AsyncRead for Scripted {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.steps.pop_front() {
                Some(Step::Bytes(len)) => {
                    let len = len.min(buf.remaining());
                    for _ in 0..len {
                        let byte = self.next;
                        buf.put_slice(&[byte]);
                        self.next = byte.wrapping_add(1);
                    }
                    Poll::Ready(Ok(()))
                }
                Some(Step::Nothing) => Poll::Pending,
                None => Poll::Ready(Ok(())),
            }
        }
    }

    /// One read: its length, or `None` when the reader had nothing.
    fn read(buffer: &mut RelayBuffer<'_>, reader: &mut Scripted) -> Option<usize> {
        let mut cx = Context::from_waker(Waker::noop());
        match buffer.poll_read(&mut cx, Pin::new(reader)) {
            Poll::Ready(result) => Some(result.expect("a scripted read does not fail")),
            Poll::Pending => None,
        }
    }

    fn holds_lent(buffer: &RelayBuffer<'_>) -> bool {
        matches!(buffer.large, Large::Lent(_))
    }

    /// A direction whose reads reached the cap.
    fn grown<'p>(pool: &'p Pool) -> RelayBuffer<'p> {
        let mut buffer = RelayBuffer::new(LENT_BUFFER_SIZE, pool);
        let mut reader = Scripted::new((0..6).map(|_| FULL));
        for _ in 0..6 {
            read(&mut buffer, &mut reader);
        }
        assert_eq!(buffer.limit, LENT_BUFFER_SIZE);
        buffer
    }

    #[test]
    fn reads_double_while_they_fill_as_a_grown_buffer_did() {
        let pool = Pool::new(keep_two);
        let mut buffer = RelayBuffer::new(LENT_BUFFER_SIZE, &pool);
        let mut reader = Scripted::new([
            Step::Bytes(100),
            FULL,
            FULL,
            Step::Bytes(5 * KIB),
            FULL,
            FULL,
            FULL,
            FULL,
            FULL,
        ]);

        assert_eq!(read(&mut buffer, &mut reader), Some(100));
        assert_eq!(read(&mut buffer, &mut reader), Some(SMALL));
        assert!(
            !holds_lent(&buffer),
            "the read that fills it is still its own"
        );
        assert_eq!(read(&mut buffer, &mut reader), Some(8 * KIB));
        assert!(holds_lent(&buffer));
        // A read that does not fill leaves the size where it is.
        assert_eq!(read(&mut buffer, &mut reader), Some(5 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(16 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(32 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(64 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(128 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(128 * KIB));
    }

    #[test]
    fn a_read_that_finds_nothing_gives_the_lent_buffer_back() {
        let pool = Pool::new(keep_two);
        let mut buffer = grown(&pool);
        assert!(holds_lent(&buffer));
        assert_eq!(pool.free_buffers(), 0);
        let mut reader = Scripted::new([Step::Nothing, Step::Bytes(10), FULL, Step::Nothing]);

        assert_eq!(read(&mut buffer, &mut reader), None);
        assert!(!holds_lent(&buffer));
        assert_eq!(pool.free_buffers(), 1);

        // The size reached stays: the next reads take the buffer again,
        // however little the first brings.
        assert_eq!(read(&mut buffer, &mut reader), Some(10));
        assert!(holds_lent(&buffer));
        assert_eq!(pool.free_buffers(), 0);
        assert_eq!(read(&mut buffer, &mut reader), Some(LENT_BUFFER_SIZE));
        assert_eq!(read(&mut buffer, &mut reader), None);
        assert_eq!(pool.free_buffers(), 1);
    }

    #[test]
    fn the_last_read_stays_readable_until_the_next() {
        let pool = Pool::new(keep_two);
        let mut buffer = RelayBuffer::new(LENT_BUFFER_SIZE, &pool);
        let mut reader = Scripted::new([
            Step::Bytes(7),
            FULL,
            Step::Bytes(6000),
            Step::Nothing,
            Step::Bytes(3),
            FULL,
        ]);
        let mut expected = 0u8;
        let mut total = 0;
        for _ in 0..6 {
            let Some(len) = read(&mut buffer, &mut reader) else {
                continue;
            };
            for byte in buffer.filled(len) {
                assert_eq!(*byte, expected);
                expected = expected.wrapping_add(1);
            }
            total += len;
        }
        assert_eq!(total, 7 + SMALL + 6000 + 3 + 8 * KIB);
    }

    #[test]
    fn directions_share_one_buffer_when_they_move_bulk_in_turn() {
        let pool = Pool::new(keep_two);
        let mut addresses = Vec::new();
        for _ in 0..8 {
            let buffer = grown(&pool);
            let Large::Lent(lent) = &buffer.large else {
                panic!("a grown direction holds a lent buffer");
            };
            addresses.push(lent.as_ptr());
        }
        assert!(addresses.iter().all(|address| *address == addresses[0]));
        assert_eq!(pool.free_buffers(), 1, "the last one came back on drop");
    }

    #[test]
    fn the_pool_keeps_no_more_free_buffers_than_it_may() {
        let pool = Pool::new(keep_two);
        let mut directions: Vec<_> = (0..5).map(|_| grown(&pool)).collect();
        assert_eq!(pool.free_buffers(), 0);
        directions.truncate(1);
        assert_eq!(pool.free_buffers(), 2);
        directions.clear();
        assert_eq!(pool.free_buffers(), 2);
    }

    #[test]
    fn a_read_takes_no_more_than_the_cap() {
        let pool = Pool::new(keep_two);
        // Below the small size the direction never takes a large buffer.
        let mut tiny = RelayBuffer::new(KIB, &pool);
        let mut reader = Scripted::new([FULL, FULL]);
        assert_eq!(read(&mut tiny, &mut reader), Some(KIB));
        assert_eq!(read(&mut tiny, &mut reader), Some(KIB));
        assert!(matches!(tiny.large, Large::None));

        // Between the two sizes its reads stop at the cap in a lent buffer.
        let mut middle = RelayBuffer::new(12 * KIB, &pool);
        let mut reader = Scripted::new([FULL, FULL, FULL, FULL]);
        assert_eq!(read(&mut middle, &mut reader), Some(SMALL));
        assert_eq!(read(&mut middle, &mut reader), Some(8 * KIB));
        assert_eq!(read(&mut middle, &mut reader), Some(12 * KIB));
        assert_eq!(read(&mut middle, &mut reader), Some(12 * KIB));
        assert!(holds_lent(&middle));
    }

    #[test]
    fn a_cap_above_the_lent_size_grows_a_buffer_of_its_own() {
        let pool = Pool::new(keep_two);
        let cap = 4 * LENT_BUFFER_SIZE;
        let mut buffer = RelayBuffer::new(cap, &pool);
        let mut reader = Scripted::new((0..8).map(|_| FULL).chain([Step::Nothing, FULL]));
        let mut sizes = Vec::new();
        for _ in 0..8 {
            sizes.push(read(&mut buffer, &mut reader).expect("a full read"));
        }
        assert_eq!(
            sizes,
            [4, 8, 16, 32, 64, 128, 256, 512].map(|kib| kib * KIB)
        );
        assert_eq!(read(&mut buffer, &mut reader), None);
        assert!(matches!(buffer.large, Large::Owned(_)), "kept while idle");
        assert_eq!(read(&mut buffer, &mut reader), Some(cap));
        drop(buffer);
        assert_eq!(pool.free_buffers(), 0);
    }

    #[test]
    fn a_thread_keeps_the_buffer_it_got_back_last_without_the_list() {
        let pool = Pool {
            free: Mutex::new(Vec::new()),
            keep: keep_two,
            thread_spare: true,
        };
        let first = pool.take();
        let second = pool.take();
        let (first_at, second_at) = (first.as_ptr(), second.as_ptr());

        pool.give_back(first);
        assert_eq!(pool.free_buffers(), 0, "the thread holds it");
        let first = pool.take();
        assert_eq!(first.as_ptr(), first_at);

        // With one held already, the newer stays and the older goes to the
        // list.
        pool.give_back(first);
        pool.give_back(second);
        assert_eq!(pool.free_buffers(), 1);
        let newer = pool.take();
        let older = pool.take();
        assert_eq!(newer.as_ptr(), second_at);
        assert_eq!(older.as_ptr(), first_at);
        assert_eq!(pool.free_buffers(), 0);
    }

    #[test]
    fn a_constrained_process_keeps_fewer_free_buffers() {
        assert_eq!(kept_buffers(MemoryClass::Standard), 64);
        assert_eq!(kept_buffers(MemoryClass::Constrained), 16);
    }
}
