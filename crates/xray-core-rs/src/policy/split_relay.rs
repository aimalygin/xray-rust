//! Bounded, demand-driven parallelism for owned VMess codec halves.
use super::{copy_direction_with_counter, CopyActivity};
use crate::connection::ConnectionTraffic;
use std::{io, time::Duration};
#[cfg(test)]
use tokio::io::{split, AsyncReadExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

// Each direction has one writer. Keep its progress word on a separate cache
// line, including on targets with 128-byte lines; the coordinator only reads.
#[repr(align(128))]
struct IdleActivity {
    origin: tokio::time::Instant,
    elapsed_ns: std::sync::atomic::AtomicU64,
    bulk_elapsed_ns: std::sync::atomic::AtomicU64,
    bulk: std::sync::atomic::AtomicBool,
}
impl IdleActivity {
    fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            elapsed_ns: std::sync::atomic::AtomicU64::new(0),
            bulk_elapsed_ns: std::sync::atomic::AtomicU64::new(0),
            bulk: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn last(&self) -> tokio::time::Instant {
        self.origin
            + Duration::from_nanos(self.elapsed_ns.load(std::sync::atomic::Ordering::Relaxed))
    }
    fn last_bulk(&self) -> tokio::time::Instant {
        self.origin
            + Duration::from_nanos(
                self.bulk_elapsed_ns
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
    }
}
const PARALLEL_BURST_BYTES: usize = 64 * 1024;
const PARALLEL_QUIET: Duration = Duration::from_millis(100);

struct BurstActivity {
    clock: std::sync::Arc<IdleActivity>,
    changed: std::sync::Arc<tokio::sync::Notify>,
    previous_bulk: tokio::time::Instant,
    bytes: usize,
}
impl CopyActivity for BurstActivity {
    #[inline]
    fn record(&mut self, bytes: usize) {
        use std::sync::atomic::Ordering::{Relaxed, Release};
        let now = tokio::time::Instant::now();
        let nanos = now
            .duration_since(self.clock.origin)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        // A direction has exactly one polling owner, including across migration.
        self.clock.elapsed_ns.store(nanos, Relaxed);
        // Short RPCs may be frequent indefinitely. They extend the connection
        // idle deadline, but must neither earn nor retain a bulk task lease.
        if bytes < super::INITIAL_COPY_BUFFER_SIZE {
            return;
        }
        if now.duration_since(self.previous_bulk) >= PARALLEL_QUIET {
            self.bytes = 0;
            self.clock.bulk.store(false, Relaxed);
        }
        self.previous_bulk = now;
        let before = self.bytes;
        self.bytes = self.bytes.saturating_add(bytes);
        self.clock.bulk_elapsed_ns.store(nanos, Relaxed);
        if before < PARALLEL_BURST_BYTES && self.bytes >= PARALLEL_BURST_BYTES {
            self.clock.bulk.store(true, Release);
            self.changed.notify_one();
        }
    }
}

fn recent_duplex(up: &IdleActivity, down: &IdleActivity) -> bool {
    use std::sync::atomic::Ordering::Acquire;
    up.bulk.load(Acquire)
        && down.bulk.load(Acquire)
        && up.last_bulk().min(down.last_bulk()) + PARALLEL_QUIET > tokio::time::Instant::now()
}

type CopyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<u64>> + Send>>;
type AdmissionFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError>,
            > + Send,
    >,
>;

enum UplinkResult {
    Complete(io::Result<u64>),
    // Returning the entire pinned future retains buffers and a partial write's
    // cursor. No I/O operation is cancelled and restarted during migration.
    Quiet(CopyFuture),
}

async fn run_parallel_uplink(
    mut upload: CopyFuture,
    permit: tokio::sync::OwnedSemaphorePermit,
    up: std::sync::Arc<IdleActivity>,
    down: std::sync::Arc<IdleActivity>,
) -> (tokio::sync::OwnedSemaphorePermit, UplinkResult) {
    let quiet = tokio::time::sleep(PARALLEL_QUIET);
    tokio::pin!(quiet);
    loop {
        tokio::select! {
            result = &mut upload => return (permit, UplinkResult::Complete(result)),
            () = &mut quiet => {
                if !recent_duplex(&up, &down) {
                    return (permit, UplinkResult::Quiet(upload));
                }
                quiet.as_mut().reset(up.last_bulk().min(down.last_bulk()) + PARALLEL_QUIET);
            },
        }
    }
}

/// Owned codec halves run locally by default. Only sustained duplex traffic
/// may move the uplink future into one additional task, under a shared quota.
/// A quiet direction returns the same future to the owner without losing I/O
/// state. JoinSet cancels the child if its owner is externally dropped.
pub(crate) async fn copy_split_with_idle_timeout<R, W>(
    budget: std::sync::Arc<tokio::sync::Semaphore>,
    inbound: (R, W),
    outbound: (xray_transport::ParallelRead, xray_transport::ParallelWrite),
    idle: Duration,
    buffer_size: usize,
    traffic: std::sync::Arc<ConnectionTraffic>,
    close: impl std::future::Future<Output = ()>,
) -> io::Result<(u64, u64)>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (mut a_read, mut a_write) = inbound;
    let (mut b_read, mut b_write) = outbound;
    let up = std::sync::Arc::new(IdleActivity::new());
    let down = std::sync::Arc::new(IdleActivity::new());
    let changed = std::sync::Arc::new(tokio::sync::Notify::new());
    let reporter = |clock: &std::sync::Arc<IdleActivity>| BurstActivity {
        clock: clock.clone(),
        changed: changed.clone(),
        previous_bulk: clock.origin,
        bytes: 0,
    };
    let up_reporter = reporter(&up);
    let down_reporter = reporter(&down);
    let up_traffic = traffic.clone();
    let mut upload: Option<CopyFuture> = Some(Box::pin(async move {
        // Sniffed initial payload can already be buffered in the codec.
        b_write.flush().await?;
        copy_direction_with_counter(
            &mut a_read,
            &mut b_write,
            up_reporter,
            buffer_size,
            Some(&up_traffic.uplink_bytes),
        )
        .await
    }));
    let mut download: CopyFuture = Box::pin(async move {
        copy_direction_with_counter(
            &mut b_read,
            &mut a_write,
            down_reporter,
            buffer_size,
            Some(&traffic.downlink_bytes),
        )
        .await
    });
    let mut tasks = tokio::task::JoinSet::new();
    let mut admission: Option<AdmissionFuture> = None;
    let mut allow_parallel = tokio::runtime::Handle::current().metrics().num_workers() > 1;
    let deadline = tokio::time::sleep(idle);
    tokio::pin!(deadline, close);
    let (mut up_total, mut down_total) = (None, None);
    let outcome = loop {
        if let (Some(up), Some(down)) = (up_total, down_total) {
            break Ok((up, down));
        }
        let eligible =
            allow_parallel && upload.is_some() && down_total.is_none() && recent_duplex(&up, &down);
        if !eligible {
            admission = None;
        } else if admission.is_none() {
            // Waiting for admission never blocks either copy direction.
            admission = Some(Box::pin(budget.clone().acquire_owned()));
        }
        tokio::select! {
            result = async { upload.as_mut().unwrap().await }, if upload.is_some() => {
                upload = None;
                match result { Ok(n) => up_total = Some(n), Err(e) => break Err(e) }
            },
            result = &mut download, if down_total.is_none() => {
                match result { Ok(n) => down_total = Some(n), Err(e) => break Err(e) }
            },
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Some(Ok((_permit, UplinkResult::Complete(Ok(n))))) => up_total = Some(n),
                    Some(Ok((_permit, UplinkResult::Complete(Err(e))))) => break Err(e),
                    Some(Ok((_permit, UplinkResult::Quiet(future)))) => upload = Some(future),
                    Some(Err(e)) => break Err(io::Error::other(e)),
                    None => unreachable!("nonempty relay task set"),
                }
            },
            result = async { admission.as_mut().unwrap().await }, if admission.is_some() => {
                admission = None;
                if let Ok(permit) = result {
                    if recent_duplex(&up, &down) && down_total.is_none() {
                        tasks.spawn(run_parallel_uplink(upload.take().unwrap(), permit, up.clone(), down.clone()));
                    }
                } else {
                    allow_parallel = false;
                }
            },
            () = changed.notified() => {},
            () = &mut deadline => {
                let expires = up.last().max(down.last()) + idle;
                if expires <= tokio::time::Instant::now() {
                    break Err(io::Error::new(io::ErrorKind::TimedOut, "connection idle timeout"));
                }
                deadline.as_mut().reset(expires);
            },
            () = &mut close => break Err(io::ErrorKind::Interrupted.into()),
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context, Poll},
    };
    use tokio::io::ReadBuf;

    fn test_budget() -> Arc<tokio::sync::Semaphore> {
        Arc::new(tokio::sync::Semaphore::new(1))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parallel_half_close_backpressure_and_exact_accounting() {
        let (mut client, inbound) = tokio::io::duplex(128);
        let (outbound, mut server) = tokio::io::duplex(128);
        let (read, write) = split(outbound);
        let traffic = Arc::new(ConnectionTraffic::default());
        let relay = tokio::spawn(copy_split_with_idle_timeout(
            test_budget(),
            split(inbound),
            (Box::new(read), Box::new(write)),
            Duration::from_secs(5),
            32768,
            traffic.clone(),
            std::future::pending(),
        ));
        let client_task = tokio::spawn(async move {
            client.write_all(&vec![0x47; 131072]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, vec![0x53; 65536]);
        });
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, vec![0x47; 131072]);
            server.write_all(&vec![0x53; 65536]).await.unwrap();
            server.shutdown().await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            client_task.await.unwrap();
            server_task.await.unwrap();
            assert_eq!(relay.await.unwrap().unwrap(), (131072, 65536));
        })
        .await
        .unwrap();
        assert_eq!(traffic.uplink_bytes.load(Ordering::Relaxed), 131072);
        assert_eq!(traffic.downlink_bytes.load(Ordering::Relaxed), 65536);
    }

    struct PendingIo {
        dropped: Arc<AtomicUsize>,
        fail_read: bool,
    }
    impl Drop for PendingIo {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl AsyncRead for PendingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.fail_read {
                Poll::Ready(Err(io::ErrorKind::InvalidData.into()))
            } else {
                Poll::Pending
            }
        }
    }
    impl AsyncWrite for PendingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    fn pending_halves(
        dropped: &Arc<AtomicUsize>,
        fail: bool,
    ) -> (xray_transport::ParallelRead, xray_transport::ParallelWrite) {
        (
            Box::new(PendingIo {
                dropped: dropped.clone(),
                fail_read: fail,
            }),
            Box::new(PendingIo {
                dropped: dropped.clone(),
                fail_read: false,
            }),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn parallel_close_idle_and_error_join_both_halves() {
        for reason in ["close", "idle", "error"] {
            let dropped = Arc::new(AtomicUsize::new(0));
            let (_peer, inbound) = tokio::io::duplex(128);
            let close = async {
                if reason != "close" {
                    std::future::pending::<()>().await;
                }
            };
            let error = copy_split_with_idle_timeout(
                test_budget(),
                split(inbound),
                pending_halves(&dropped, reason == "error"),
                Duration::from_secs(3),
                8192,
                Arc::default(),
                close,
            )
            .await
            .unwrap_err();
            let kind = match reason {
                "close" => io::ErrorKind::Interrupted,
                "idle" => io::ErrorKind::TimedOut,
                _ => io::ErrorKind::InvalidData,
            };
            assert_eq!(error.kind(), kind);
            assert_eq!(dropped.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn parallel_owner_abort_cancels_children_without_detaching() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let (_peer, inbound) = tokio::io::duplex(128);
        let budget = Arc::new(tokio::sync::Semaphore::new(1));
        let relay = tokio::spawn(copy_split_with_idle_timeout(
            budget.clone(),
            split(inbound),
            pending_halves(&dropped, false),
            Duration::from_secs(60),
            8192,
            Arc::default(),
            std::future::pending(),
        ));
        tokio::task::yield_now().await;
        assert_eq!(budget.available_permits(), 1);
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
        for _ in 0..10 {
            if dropped.load(Ordering::SeqCst) == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert_eq!(budget.available_permits(), 1);
    }

    #[tokio::test]
    async fn parallel_flushes_prefilled_writer_before_waiting_for_inbound() {
        let (mut client, inbound) = tokio::io::duplex(128);
        let (outbound, mut server) = tokio::io::duplex(128);
        let (read, write) = split(outbound);
        let mut write = tokio::io::BufWriter::new(write);
        write.write_all(b"sniffed").await.unwrap();
        let relay = tokio::spawn(copy_split_with_idle_timeout(
            test_budget(),
            split(inbound),
            (Box::new(read), Box::new(write)),
            Duration::from_secs(2),
            8192,
            Arc::default(),
            std::future::pending(),
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut request = [0; 7];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"sniffed");
            server.write_all(b"response").await.unwrap();
            server.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response");
            client.shutdown().await.unwrap();
            assert_eq!(relay.await.unwrap().unwrap(), (0, 8));
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn parallel_activity_deadline_tracks_both_directions_without_notifications() {
        for uplink in [true, false] {
            let (mut client, inbound) = tokio::io::duplex(128);
            let (outbound, mut server) = tokio::io::duplex(128);
            let (read, write) = split(outbound);
            let relay = tokio::spawn(copy_split_with_idle_timeout(
                test_budget(),
                split(inbound),
                (Box::new(read), Box::new(write)),
                Duration::from_secs(3),
                8192,
                Arc::default(),
                std::future::pending(),
            ));
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(2)).await;
            let mut byte = [0; 1];
            if uplink {
                client.write_all(b"x").await.unwrap();
                server.read_exact(&mut byte).await.unwrap();
            } else {
                server.write_all(b"x").await.unwrap();
                client.read_exact(&mut byte).await.unwrap();
            }
            assert_eq!(&byte, b"x");
            tokio::time::advance(Duration::from_secs(2)).await;
            tokio::task::yield_now().await;
            assert!(!relay.is_finished());
            tokio::time::advance(Duration::from_secs(2)).await;
            assert_eq!(
                relay.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }
    async fn wait_for_admission(budget: &tokio::sync::Semaphore, available: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while budget.available_permits() != available {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplex_admission_releases_on_quiet_reacquires_and_aborts_without_leaks() {
        let (client, inbound) = tokio::io::duplex(16 * 1024);
        let (outbound, server) = tokio::io::duplex(16 * 1024);
        let (mut client_read, mut client_write) = split(client);
        let (mut server_read, mut server_write) = split(server);
        let (read, write) = split(outbound);
        let budget = test_budget();
        let traffic = Arc::new(ConnectionTraffic::default());
        let relay = tokio::spawn(copy_split_with_idle_timeout(
            budget.clone(),
            split(inbound),
            (Box::new(read), Box::new(write)),
            Duration::from_secs(5),
            32768,
            traffic.clone(),
            std::future::pending(),
        ));
        // Initially idle connections never occupy admission.
        tokio::task::yield_now().await;
        assert_eq!(budget.available_permits(), 1);
        let mut chatty_bytes = 0;
        for cycle in 0..2 {
            let request = vec![0x31 + cycle; 256 * 1024];
            let response = vec![0x71 + cycle; 256 * 1024];
            let mut received_up = vec![0; request.len()];
            let mut received_down = vec![0; response.len()];
            tokio::time::timeout(Duration::from_secs(2), async {
                let (up, up_read, down, down_read) = tokio::join!(
                    client_write.write_all(&request),
                    server_read.read_exact(&mut received_up),
                    server_write.write_all(&response),
                    client_read.read_exact(&mut received_down),
                );
                up.unwrap();
                up_read.unwrap();
                down.unwrap();
                down_read.unwrap();
            })
            .await
            .unwrap();
            assert_eq!(received_up, request);
            assert_eq!(received_down, response);
            wait_for_admission(&budget, 0).await;
            if cycle == 0 {
                // Keep the connection active with short exchanges after bulk.
                // Admission must still return while the I/O keeps succeeding.
                tokio::time::timeout(Duration::from_secs(1), async {
                    let request = [0x19; 1024];
                    let mut received = [0; 1024];
                    while budget.available_permits() == 0 {
                        let (written, read) = tokio::join!(
                            client_write.write_all(&request),
                            server_read.read_exact(&mut received)
                        );
                        written.unwrap();
                        read.unwrap();
                        assert_eq!(received, request);
                        let (written, read) = tokio::join!(
                            server_write.write_all(&request),
                            client_read.read_exact(&mut received)
                        );
                        written.unwrap();
                        read.unwrap();
                        assert_eq!(received, request);
                        chatty_bytes += 1024;
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
                assert!(chatty_bytes > 0);
            }
        }
        // A duplex reader can consume the last write on another worker before
        // write_all returns and the relay records that write. Receiving every
        // byte is not a barrier for the counters, so wait for both updates
        // before aborting the still-open relay. A missing update still fails.
        let expected = 512 * 1024 + chatty_bytes;
        tokio::time::timeout(Duration::from_secs(2), async {
            while traffic.uplink_bytes.load(Ordering::Relaxed) != expected
                || traffic.downlink_bytes.load(Ordering::Relaxed) != expected
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("relay must account for all received bytes before cancellation");
        assert_eq!(traffic.uplink_bytes.load(Ordering::Relaxed), expected);
        assert_eq!(
            traffic.downlink_bytes.load(Ordering::Relaxed),
            512 * 1024 + chatty_bytes
        );
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
        wait_for_admission(&budget, 1).await;
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), client_read.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), server_read.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn quiet_migration_preserves_partial_write_all_cursor_and_half_close() {
        let (mut writer, mut reader) = tokio::io::duplex(3);
        let payload = b"pending partial write";
        let future: CopyFuture = Box::pin(async move {
            writer.write_all(payload).await?;
            writer.shutdown().await?;
            Ok(payload.len() as u64)
        });
        let budget = test_budget();
        let child = tokio::spawn(run_parallel_uplink(
            future,
            budget.clone().try_acquire_owned().unwrap(),
            Arc::new(IdleActivity::new()),
            Arc::new(IdleActivity::new()),
        ));
        tokio::task::yield_now().await;
        assert!(!child.is_finished());
        tokio::time::advance(PARALLEL_QUIET).await;
        let (permit, UplinkResult::Quiet(future)) = child.await.unwrap() else {
            panic!("blocked write must return its pending future");
        };
        assert_eq!(budget.available_permits(), 0);
        drop(permit);
        let mut received = Vec::new();
        let (written, read) = tokio::join!(future, reader.read_to_end(&mut received));
        assert_eq!(written.unwrap(), payload.len() as u64);
        assert_eq!(read.unwrap(), payload.len());
        assert_eq!(received, payload);
        assert_eq!(budget.available_permits(), 1);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn frequent_small_requests_never_occupy_parallel_admission() {
        let (mut client, inbound) = tokio::io::duplex(1024);
        let (outbound, mut server) = tokio::io::duplex(1024);
        let (read, write) = split(outbound);
        let budget = test_budget();
        let relay = tokio::spawn(copy_split_with_idle_timeout(
            budget.clone(),
            split(inbound),
            (Box::new(read), Box::new(write)),
            Duration::from_secs(2),
            32768,
            Arc::default(),
            std::future::pending(),
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            let request = [0x37; 1024];
            let mut up = [0; 1024];
            let mut down = [0; 1024];
            for _ in 0..256 {
                let (written, read) =
                    tokio::join!(client.write_all(&request), server.read_exact(&mut up));
                written.unwrap();
                read.unwrap();
                assert_eq!(up, request);
                let (written, read) =
                    tokio::join!(server.write_all(&up), client.read_exact(&mut down));
                written.unwrap();
                read.unwrap();
                assert_eq!(down, request);
                tokio::task::yield_now().await;
                assert_eq!(
                    budget.available_permits(),
                    1,
                    "short RPCs must not monopolize bulk admission"
                );
            }
        })
        .await
        .unwrap();
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
    }
}
