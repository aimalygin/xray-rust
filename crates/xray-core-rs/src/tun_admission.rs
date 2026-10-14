//! Optional host policy for new TUN flows. No host code runs on the packet loop.
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{oneshot, watch};

/// Addresses are the original application tuple, before FakeDNS restoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunFlow {
    pub id: u64,
    /// IP protocol number: TCP (6) or UDP (17).
    pub protocol: u8,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// Called concurrently on a bounded host-worker pool. Must return promptly.
/// Do not call core lifecycle methods from this callback.
pub trait TunFlowAdmission: Send + Sync + 'static {
    fn admit(&self, flow: TunFlow) -> bool;
}

impl<F: Fn(TunFlow) -> bool + Send + Sync + 'static> TunFlowAdmission for F {
    fn admit(&self, flow: TunFlow) -> bool {
        self(flow)
    }
}

/// A timeout bounds the decision, not the execution of arbitrary host code.
/// Four process-wide workers and 64 queued jobs bound stalled callbacks, even
/// across repeated core recreation. Queued cancelled jobs do not call the host.
#[derive(Clone)]
pub struct TunAdmissionPolicy {
    callback: Arc<dyn TunFlowAdmission>,
    timeout: Duration,
    fail_open: bool,
}

impl TunAdmissionPolicy {
    pub fn new(
        callback: Arc<dyn TunFlowAdmission>,
        timeout: Duration,
        fail_open: bool,
    ) -> Result<Self, &'static str> {
        if timeout < Duration::from_millis(1) || timeout > Duration::from_secs(5) {
            return Err("TUN admission timeout must be in 1..5000 ms");
        }
        Ok(Self {
            callback,
            timeout,
            fail_open,
        })
    }

    pub(crate) async fn admit(&self, flow: TunFlow, mut shutdown: watch::Receiver<bool>) -> bool {
        if *shutdown.borrow() {
            return false;
        }
        let (tx, rx) = oneshot::channel();
        let job = Job {
            callback: Arc::clone(&self.callback),
            flow,
            result: tx,
        };
        let Some(pool) = WORKERS.get_or_init(worker_pool) else {
            return self.fail_open;
        };
        if pool.try_send(job).is_err() {
            return self.fail_open;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => false,
            result = tokio::time::timeout(self.timeout, rx) => {
                match result {
                    Ok(Ok(allowed)) => allowed,
                    _ => self.fail_open,
                }
            }
        }
    }
}

struct Job {
    callback: Arc<dyn TunFlowAdmission>,
    flow: TunFlow,
    result: oneshot::Sender<bool>,
}

static WORKERS: OnceLock<Option<mpsc::SyncSender<Job>>> = OnceLock::new();

fn worker_pool() -> Option<mpsc::SyncSender<Job>> {
    let (tx, rx) = mpsc::sync_channel::<Job>(64);
    let rx = Arc::new(Mutex::new(rx));
    for index in 0..4 {
        let rx = Arc::clone(&rx);
        std::thread::Builder::new()
            .name(format!("xray-tun-policy-{index}"))
            .spawn(move || loop {
                let job = match rx.lock() {
                    Ok(receiver) => receiver.recv(),
                    Err(_) => return,
                };
                let Ok(job) = job else {
                    return;
                };
                if job.result.is_closed() {
                    continue;
                }
                let allowed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    job.callback.admit(job.flow)
                }))
                .unwrap_or(false);
                let _ = job.result.send(allowed);
            })
            .ok()?;
    }
    Some(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn flow() -> TunFlow {
        TunFlow {
            id: 1,
            protocol: 6,
            source: "198.18.0.2:1000".parse().unwrap(),
            destination: "198.18.0.3:443".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn admission_timeout_cancel_and_panic_are_bounded() {
        let (stop, shutdown) = watch::channel(false);
        for fail_open in [false, true] {
            let policy = TunAdmissionPolicy::new(
                Arc::new(|_| {
                    std::thread::sleep(Duration::from_millis(50));
                    true
                }),
                Duration::from_millis(5),
                fail_open,
            )
            .unwrap();
            assert_eq!(policy.admit(flow(), shutdown.clone()).await, fail_open);
        }
        let panic_policy = TunAdmissionPolicy::new(
            Arc::new(|_| panic!("host panic")),
            Duration::from_secs(1),
            true,
        )
        .unwrap();
        assert!(!panic_policy.admit(flow(), shutdown.clone()).await);
        stop.send_replace(true);
        assert!(!panic_policy.admit(flow(), shutdown).await);
    }

    #[test]
    fn blocking_workers_and_queue_are_bounded_and_cancelled_jobs_skip_host() {
        let pool = worker_pool().unwrap();
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let entered = Arc::new(AtomicUsize::new(0));
        let callback: Arc<dyn TunFlowAdmission> = {
            let gate = Arc::clone(&gate);
            let entered = Arc::clone(&entered);
            Arc::new(move |_| {
                entered.fetch_add(1, Ordering::SeqCst);
                let (lock, wake) = &*gate;
                let mut ready = lock.lock().unwrap();
                while !*ready {
                    ready = wake.wait(ready).unwrap();
                }
                true
            })
        };
        let mut running = Vec::new();
        for _ in 0..4 {
            let (result, rx) = oneshot::channel();
            assert!(pool
                .try_send(Job {
                    callback: Arc::clone(&callback),
                    flow: flow(),
                    result
                })
                .is_ok());
            running.push(rx);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while entered.load(Ordering::SeqCst) < 4 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut queued = Vec::new();
        for _ in 0..64 {
            let (result, rx) = oneshot::channel();
            assert!(pool
                .try_send(Job {
                    callback: Arc::clone(&callback),
                    flow: flow(),
                    result
                })
                .is_ok());
            queued.push(rx);
        }
        let (result, _rx) = oneshot::channel();
        assert!(pool
            .try_send(Job {
                callback,
                flow: flow(),
                result
            })
            .is_err());
        drop(queued); // Simulate timed out or stopped cores.
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        for result in running {
            assert!(result.blocking_recv().unwrap());
        }
        drop(pool);
        assert_eq!(entered.load(Ordering::SeqCst), 4);
    }
}
