use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RemoteReadEnd {
    Closed,
    Failed,
}

/// Coalesce only immediately available data. H2/TLS readers can return one
/// small frame per poll even when more frames are ready; handing each frame
/// to the stack separately adds avoidable task/channel round trips. Preserve
/// a terminal result following data so the bridge delivers those bytes first.
pub(super) async fn read_remote_batch<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> (usize, Option<RemoteReadEnd>) {
    debug_assert!(!buffer.is_empty());
    std::future::poll_fn(|cx| {
        let mut total = 0;
        loop {
            let mut read = tokio::io::ReadBuf::new(&mut buffer[total..]);
            match std::pin::Pin::new(&mut *reader).poll_read(cx, &mut read) {
                std::task::Poll::Pending if total == 0 => return std::task::Poll::Pending,
                std::task::Poll::Pending => return std::task::Poll::Ready((total, None)),
                std::task::Poll::Ready(Err(_)) => {
                    return std::task::Poll::Ready((total, Some(RemoteReadEnd::Failed)));
                }
                std::task::Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    return std::task::Poll::Ready((total, Some(RemoteReadEnd::Closed)));
                }
                std::task::Poll::Ready(Ok(())) => total += read.filled().len(),
            }
            if total == buffer.len() {
                return std::task::Poll::Ready((total, None));
            }
        }
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
