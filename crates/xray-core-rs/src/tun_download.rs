use super::*;
use bytes::BufMut as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RemoteReadEnd {
    Closed,
    Failed,
}

/// What a remote read starts in, on the stack: a flow waiting for its remote
/// holds no read buffer.
const TCP_DOWNLOAD_PROBE_SIZE: usize = 8 * 1024;

enum ReadStep {
    Read,
    Pending,
    End(RemoteReadEnd),
}

fn poll_read_step<R: AsyncRead + Unpin>(
    reader: &mut R,
    cx: &mut std::task::Context<'_>,
    buffer: &mut tokio::io::ReadBuf<'_>,
) -> ReadStep {
    let before = buffer.filled().len();
    match std::pin::Pin::new(reader).poll_read(cx, buffer) {
        std::task::Poll::Pending => ReadStep::Pending,
        std::task::Poll::Ready(Err(_)) => ReadStep::End(RemoteReadEnd::Failed),
        std::task::Poll::Ready(Ok(())) if buffer.filled().len() == before => {
            ReadStep::End(RemoteReadEnd::Closed)
        }
        std::task::Poll::Ready(Ok(())) => ReadStep::Read,
    }
}

/// Coalesce only immediately available data, up to `limit` bytes. H2/TLS
/// readers can return one small frame per poll even when more frames are
/// ready; handing each frame to the stack separately adds avoidable
/// task/channel round trips. Preserve a terminal result following data so the
/// bridge delivers those bytes first.
///
/// A read that waits for its remote holds no heap buffer. It starts in a
/// buffer on the stack and returns a copy of what that holds; only data that
/// fills it continues in a chunk of `limit` bytes, which is handed on without
/// another copy. A chunk filled to less than half is copied to its own size,
/// so the stack's prefetch queue never keeps more than twice the bytes it
/// counts.
pub(super) async fn read_remote_batch<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> (Bytes, Option<RemoteReadEnd>) {
    debug_assert!(limit > 0);
    std::future::poll_fn(|cx| {
        let mut probe = [std::mem::MaybeUninit::<u8>::uninit(); TCP_DOWNLOAD_PROBE_SIZE];
        let mut probe =
            tokio::io::ReadBuf::uninit(&mut probe[..limit.min(TCP_DOWNLOAD_PROBE_SIZE)]);
        let mut end = None;
        while probe.remaining() > 0 {
            match poll_read_step(reader, cx, &mut probe) {
                ReadStep::Read => {}
                ReadStep::Pending if probe.filled().is_empty() => {
                    return std::task::Poll::Pending;
                }
                ReadStep::Pending => break,
                ReadStep::End(read_end) => {
                    end = Some(read_end);
                    break;
                }
            }
        }
        if probe.remaining() > 0 || end.is_some() || probe.filled().len() == limit {
            return std::task::Poll::Ready((Bytes::copy_from_slice(probe.filled()), end));
        }

        let mut chunk = BytesMut::with_capacity(limit);
        chunk.extend_from_slice(probe.filled());
        while chunk.len() < limit {
            let room = limit - chunk.len();
            let mut spare = tokio::io::ReadBuf::uninit(&mut chunk.spare_capacity_mut()[..room]);
            let step = poll_read_step(reader, cx, &mut spare);
            let read = spare.filled().len();
            // SAFETY: `ReadBuf` reports `read` initialized bytes at the start
            // of the spare capacity it was given.
            unsafe { chunk.advance_mut(read) };
            match step {
                ReadStep::Read => {}
                ReadStep::Pending => break,
                ReadStep::End(read_end) => {
                    end = Some(read_end);
                    break;
                }
            }
        }
        let data = if chunk.len() < limit / 2 {
            Bytes::copy_from_slice(&chunk)
        } else {
            chunk.freeze()
        };
        std::task::Poll::Ready((data, end))
    })
    .await
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
