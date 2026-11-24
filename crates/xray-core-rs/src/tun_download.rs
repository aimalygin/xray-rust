use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RemoteReadEnd {
    Closed,
    Failed,
}

/// Coalesce only immediately available data, up to `limit` bytes (at most
/// [`TCP_DOWNLOAD_CHUNK_SIZE`]). H2/TLS readers can return one small frame
/// per poll even when more frames are ready; handing each frame to the stack
/// separately adds avoidable task/channel round trips. Preserve a terminal
/// result following data so the bridge delivers those bytes first.
///
/// The reads go into a buffer on the stack of the poll that makes them, and
/// what they took is copied out at its own size: one allocation and one copy
/// per batch, and a flow waiting for its remote keeps no read buffer.
pub(super) async fn read_remote_batch<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> (Bytes, Option<RemoteReadEnd>) {
    debug_assert!(limit > 0 && limit <= TCP_DOWNLOAD_CHUNK_SIZE);
    std::future::poll_fn(|cx| {
        let mut storage = [std::mem::MaybeUninit::<u8>::uninit(); TCP_DOWNLOAD_CHUNK_SIZE];
        let mut buffer =
            tokio::io::ReadBuf::uninit(&mut storage[..limit.min(TCP_DOWNLOAD_CHUNK_SIZE)]);
        let mut end = None;
        while buffer.remaining() > 0 {
            let before = buffer.filled().len();
            match std::pin::Pin::new(&mut *reader).poll_read(cx, &mut buffer) {
                std::task::Poll::Pending if before == 0 => return std::task::Poll::Pending,
                std::task::Poll::Pending => break,
                std::task::Poll::Ready(Err(_)) => {
                    end = Some(RemoteReadEnd::Failed);
                    break;
                }
                std::task::Poll::Ready(Ok(())) if buffer.filled().len() == before => {
                    end = Some(RemoteReadEnd::Closed);
                    break;
                }
                std::task::Poll::Ready(Ok(())) => {}
            }
        }
        std::task::Poll::Ready((Bytes::copy_from_slice(buffer.filled()), end))
    })
    .await
}

/// [`read_remote_batch`] that does not start before `not_before`. The wait
/// reads nothing, so dropping the future during it loses no data.
pub(super) async fn read_remote_batch_after<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
    not_before: Option<TokioInstant>,
) -> (Bytes, Option<RemoteReadEnd>) {
    if let Some(not_before) = not_before {
        tokio::time::sleep_until(not_before).await;
    }
    read_remote_batch(reader, limit).await
}

/// When a one-way download trickles in one segment at a time, every segment
/// costs the whole chain of wake-ups from the remote socket to the TUN
/// descriptor, and that chain, not the bytes, is what the CPU time goes to.
/// After a small read of such a stream the next read waits for `delay`, so
/// that it takes several segments at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DownloadCoalescePolicy {
    /// How long the read after a small one waits.
    pub(super) delay: Duration,
    /// A read below this drained the socket; a larger one already carried
    /// several segments and the next read follows at once.
    pub(super) small_read_bytes: usize,
    /// Reads further apart than this do not belong to one stream.
    pub(super) max_read_gap: Duration,
    /// How long a stream must have run before a read waits. It keeps `delay`
    /// a small share of the stream's duration: a response that arrives in
    /// less time than this is never delayed.
    pub(super) min_stream_age: Duration,
}

pub(super) const MOBILE_DOWNLOAD_COALESCE_POLICY: DownloadCoalescePolicy = DownloadCoalescePolicy {
    delay: Duration::from_millis(1),
    small_read_bytes: 8 * 1024,
    max_read_gap: Duration::from_millis(5),
    min_stream_age: Duration::from_millis(25),
};

/// Decides, read by read, whether the next read of one flow's remote waits.
/// A stream is a run of reads no further apart than `max_read_gap` with no
/// client upload between them: a request/response exchange uploads between
/// its reads and therefore never waits.
#[derive(Debug)]
pub(super) struct DownloadCoalescer {
    policy: Option<DownloadCoalescePolicy>,
    stream_started_at: Option<TokioInstant>,
    last_read_at: Option<TokioInstant>,
    upload_since_read: bool,
    read_not_before: Option<TokioInstant>,
}

impl DownloadCoalescer {
    pub(super) fn new(policy: Option<DownloadCoalescePolicy>) -> Self {
        Self {
            policy,
            stream_started_at: None,
            last_read_at: None,
            upload_since_read: false,
            read_not_before: None,
        }
    }

    /// The client wrote to the remote: what the remote sends next answers
    /// that write, so a wait already armed is dropped.
    pub(super) fn record_upload(&mut self) {
        self.upload_since_read = true;
        self.read_not_before = None;
    }

    pub(super) fn record_read(&mut self, now: TokioInstant, bytes: usize) {
        let Some(policy) = self.policy else {
            return;
        };
        let continues = !self.upload_since_read
            && self
                .last_read_at
                .is_some_and(|last| now.duration_since(last) <= policy.max_read_gap);
        let started = match self.stream_started_at {
            Some(started) if continues => started,
            _ => now,
        };
        self.stream_started_at = Some(started);
        self.last_read_at = Some(now);
        self.upload_since_read = false;
        self.read_not_before = (bytes < policy.small_read_bytes
            && now.duration_since(started) >= policy.min_stream_age)
            .then(|| now + policy.delay);
    }

    /// The instant the next read may start, if it has to wait.
    pub(super) fn read_not_before(&self) -> Option<TokioInstant> {
        self.read_not_before
    }
}

#[derive(Debug)]
pub(super) struct DownloadDelivery {
    accepted: tokio::sync::oneshot::Sender<()>,
    // Cancellation of the sending future must not unlock another DNS writer
    // while its previous chunk is still in the event or pending-data queue.
    _serial: Arc<tokio::sync::OwnedMutexGuard<()>>,
}

impl DownloadDelivery {
    pub(super) fn complete(self) {
        let _ = self.accepted.send(());
    }

    #[cfg(test)]
    pub(super) fn test() -> Self {
        Self {
            accepted: tokio::sync::oneshot::channel().0,
            _serial: Arc::new(
                Arc::new(tokio::sync::Mutex::new(()))
                    .try_lock_owned()
                    .unwrap(),
            ),
        }
    }
}

/// Serializes complete writes (including DNS frames) within one TCP flow.
/// An acknowledgement permits another chunk only when the stack has room in
/// its bounded prefetch queue. There is at most one unacknowledged 64 KiB chunk
/// per flow, including deferred data; admitted chunks cannot fill the previous
/// multi-megabyte queues or stop the shared control/UDP channel.
pub(super) async fn send_remote_data(
    stack_tx: &mpsc::Sender<StackEvent>,
    serial: &Arc<tokio::sync::Mutex<()>>,
    handle: SocketHandle,
    generation: u64,
    mut data: Bytes,
) -> Result<(), ()> {
    let serial = Arc::new(serial.clone().lock_owned().await);
    let split_frame = data.len() > TCP_DOWNLOAD_CHUNK_SIZE;
    while !data.is_empty() {
        let chunk = if !split_frame {
            std::mem::take(&mut data)
        } else {
            // Do not retain an entire DNS response in a small queued slice.
            let take = data.len().min(TCP_DOWNLOAD_CHUNK_SIZE);
            let chunk = Bytes::copy_from_slice(&data[..take]);
            data = data.slice(take..);
            chunk
        };
        let (accepted, delivered) = tokio::sync::oneshot::channel();
        stack_tx
            .send(StackEvent::RemoteData {
                handle,
                generation,
                data: chunk,
                delivery: DownloadDelivery {
                    accepted,
                    _serial: serial.clone(),
                },
            })
            .await
            .map_err(|_| ())?;
        delivered.await.map_err(|_| ())?;
    }
    Ok(())
}

pub(super) type PendingDownload<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Option<Result<(), ()>>> + Send + 'a>>;

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: DownloadCoalescePolicy = MOBILE_DOWNLOAD_COALESCE_POLICY;
    const SEGMENT: usize = 1448;

    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    /// One segment per millisecond from `start` until the stream is old
    /// enough to wait; returns the instant of the last read.
    fn trickle_until_waiting(
        coalescer: &mut DownloadCoalescer,
        start: TokioInstant,
    ) -> TokioInstant {
        let mut at = start;
        while at.duration_since(start) < POLICY.min_stream_age {
            coalescer.record_read(at, SEGMENT);
            assert_eq!(coalescer.read_not_before(), None);
            at += ms(1);
        }
        coalescer.record_read(at, SEGMENT);
        assert_eq!(coalescer.read_not_before(), Some(at + POLICY.delay));
        at
    }

    #[test]
    fn long_one_way_trickle_delays_the_next_read() {
        let mut coalescer = DownloadCoalescer::new(Some(POLICY));
        let at = trickle_until_waiting(&mut coalescer, TokioInstant::now());

        // The delayed reads keep the stream going, so it keeps waiting.
        let next = at + POLICY.delay + ms(1);
        coalescer.record_read(next, 4 * SEGMENT);
        assert_eq!(coalescer.read_not_before(), Some(next + POLICY.delay));
    }

    #[test]
    fn read_that_carried_several_segments_is_followed_at_once() {
        let mut coalescer = DownloadCoalescer::new(Some(POLICY));
        let at = trickle_until_waiting(&mut coalescer, TokioInstant::now());

        coalescer.record_read(at + ms(2), POLICY.small_read_bytes);
        assert_eq!(coalescer.read_not_before(), None);
    }

    #[test]
    fn upload_drops_an_armed_wait_and_restarts_the_stream() {
        let mut coalescer = DownloadCoalescer::new(Some(POLICY));
        let at = trickle_until_waiting(&mut coalescer, TokioInstant::now());

        coalescer.record_upload();
        assert_eq!(coalescer.read_not_before(), None);

        // The answer to that upload starts a new stream, however soon it comes.
        coalescer.record_read(at + ms(1), SEGMENT);
        assert_eq!(coalescer.read_not_before(), None);
        trickle_until_waiting(&mut coalescer, at + ms(1));
    }

    #[test]
    fn pause_longer_than_the_gap_restarts_the_stream() {
        let mut coalescer = DownloadCoalescer::new(Some(POLICY));
        let at = trickle_until_waiting(&mut coalescer, TokioInstant::now());

        let resumed = at + POLICY.max_read_gap + ms(1);
        coalescer.record_read(resumed, SEGMENT);
        assert_eq!(coalescer.read_not_before(), None);
        trickle_until_waiting(&mut coalescer, resumed);
    }

    #[test]
    fn without_a_policy_no_read_waits() {
        let mut coalescer = DownloadCoalescer::new(None);
        let start = TokioInstant::now();
        for millis in 0..100 {
            coalescer.record_read(start + ms(millis), SEGMENT);
            assert_eq!(coalescer.read_not_before(), None);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_read_waits_for_its_instant_and_loses_nothing_when_dropped() {
        let (mut remote, mut local) = tokio::io::duplex(64);
        remote.write_all(b"abc").await.unwrap();

        // Dropped during the wait: the bytes stay in the reader.
        let far = TokioInstant::now() + Duration::from_secs(60);
        assert!(read_remote_batch_after(&mut local, 16, Some(far))
            .now_or_never()
            .is_none());

        let started = TokioInstant::now();
        let (data, end) = read_remote_batch_after(&mut local, 16, Some(started + ms(1))).await;
        assert_eq!(started.elapsed(), ms(1));
        assert_eq!(&data[..], b"abc");
        assert_eq!(end, None);

        let (data, end) = {
            remote.write_all(b"d").await.unwrap();
            read_remote_batch_after(&mut local, 16, None).await
        };
        assert_eq!(started.elapsed(), ms(1));
        assert_eq!(&data[..], b"d");
        assert_eq!(end, None);
    }
}
