//! VLESS `testpre`: carrier connections opened ahead of the requests that
//! take them, as Xray-core's VLESS outbound keeps them.
//!
//! On its first request the outbound starts `testpre` dialers. Each opens one
//! carrier connection (TCP, then TLS or REALITY and the transport's own
//! handshake), holds it until a request takes it, waits 200 ms and opens the
//! next. A request takes the first connection held; one held longer than two
//! minutes is closed and the next taken. Xray-core retries a failed dial at
//! once and lets a request wait for as long as it takes; here a failed dial
//! waits before the next, doubling up to ten seconds, and a request gives up
//! after sixteen seconds, the time Xray-core's system dialer allows a dial.
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::Instant,
};
use xray_transport::{BoxedTransportStream, TransportDialer};

use crate::CoreError;

/// How long a connection opened ahead may wait for a request.
const LIFETIME: Duration = Duration::from_secs(120);
/// The pause after a dialer hands its connection over.
const REFILL_DELAY: Duration = Duration::from_millis(200);
/// The first and the longest pause after a failed dial.
const RETRY_FIRST: Duration = Duration::from_millis(200);
const RETRY_MAX: Duration = Duration::from_secs(10);
/// How long a request waits for a connection.
const WAIT: Duration = Duration::from_secs(16);

/// Where the next connection goes: the server and download candidates and
/// the dialer of the latest request, so a dialer follows DNS changes and the
/// request's chain.
pub(super) struct DialSpec {
    pub(super) server: Vec<SocketAddr>,
    pub(super) download: Vec<SocketAddr>,
    pub(super) dialer: TransportDialer,
}

/// Opens one carrier connection, or `None` once the outbound is gone.
#[async_trait]
pub(super) trait Opener: Send + Sync + 'static {
    async fn open(&self, spec: &DialSpec) -> Option<Result<BoxedTransportStream, CoreError>>;
}

struct Ready {
    stream: BoxedTransportStream,
    expires: Instant,
}

type Request = oneshot::Sender<Ready>;

enum State {
    Idle,
    Running {
        spec: watch::Sender<Arc<DialSpec>>,
        requests: mpsc::UnboundedSender<Request>,
        dialers: Vec<JoinHandle<()>>,
    },
    Closed,
}

pub(super) struct PreConnections {
    dialers: u32,
    state: Mutex<State>,
    /// Dialers stopped by [`Self::close`], for [`Self::join`].
    stopped: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for PreConnections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreConnections")
            .field("dialers", &self.dialers)
            .finish_non_exhaustive()
    }
}

impl PreConnections {
    /// `dialers` connections kept ahead; `None` for zero, which keeps none.
    pub(super) fn new(dialers: u32) -> Option<Self> {
        (dialers > 0).then(|| Self {
            dialers,
            state: Mutex::new(State::Idle),
            stopped: Mutex::new(Vec::new()),
        })
    }

    /// A connection opened ahead. The first call starts the dialers with
    /// the opener `start` makes; every call hands them its `spec`.
    pub(super) async fn take(
        &self,
        spec: DialSpec,
        start: impl FnOnce() -> Arc<dyn Opener>,
    ) -> Result<BoxedTransportStream, CoreError> {
        let requests = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            match &mut *state {
                State::Closed => return Err(closed()),
                State::Running {
                    spec: latest,
                    requests,
                    ..
                } => {
                    latest.send_replace(Arc::new(spec));
                    requests.clone()
                }
                State::Idle => {
                    let (latest, spec) = watch::channel(Arc::new(spec));
                    let (requests, queue) = mpsc::unbounded_channel();
                    let queue = Arc::new(tokio::sync::Mutex::new(queue));
                    let opener = start();
                    let dialers = (0..self.dialers)
                        .map(|_| {
                            tokio::spawn(dial(
                                spec.clone(),
                                Arc::clone(&queue),
                                Arc::clone(&opener),
                            ))
                        })
                        .collect();
                    let sender = requests.clone();
                    *state = State::Running {
                        spec: latest,
                        requests,
                        dialers,
                    };
                    sender
                }
            }
        };
        let deadline = Instant::now() + WAIT;
        loop {
            let (request, response) = oneshot::channel();
            requests.send(request).map_err(|_| closed())?;
            let ready = match tokio::time::timeout_at(deadline, response).await {
                Ok(Ok(ready)) => ready,
                Ok(Err(_)) => return Err(closed()),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no VLESS testpre connection opened in time",
                    )
                    .into())
                }
            };
            // An expired connection closes as it drops.
            if Instant::now() < ready.expires {
                return Ok(ready.stream);
            }
        }
    }

    /// Stops the dialers and closes the connections they hold.
    pub(super) fn close(&self) {
        let state = std::mem::replace(
            &mut *self.state.lock().unwrap_or_else(PoisonError::into_inner),
            State::Closed,
        );
        if let State::Running { dialers, .. } = state {
            for dialer in &dialers {
                dialer.abort();
            }
            self.stopped
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(dialers);
        }
    }

    /// Waits for the dialers [`Self::close`] stopped.
    pub(super) async fn join(&self) {
        let stopped =
            std::mem::take(&mut *self.stopped.lock().unwrap_or_else(PoisonError::into_inner));
        for dialer in stopped {
            let _ = dialer.await;
        }
    }
}

impl Drop for PreConnections {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        if let State::Running { dialers, .. } = state {
            for dialer in dialers {
                dialer.abort();
            }
        }
    }
}

fn closed() -> CoreError {
    io::Error::new(io::ErrorKind::NotConnected, "the VLESS outbound is closed").into()
}

/// One dialer: open a connection, hand it to the next request, pause, again.
async fn dial(
    spec: watch::Receiver<Arc<DialSpec>>,
    queue: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Request>>>,
    opener: Arc<dyn Opener>,
) {
    let mut retry = RETRY_FIRST;
    loop {
        let current = Arc::clone(&spec.borrow());
        let stream = match opener.open(&current).await {
            None => return,
            Some(Ok(stream)) => stream,
            Some(Err(_)) => {
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(RETRY_MAX);
                continue;
            }
        };
        retry = RETRY_FIRST;
        let mut ready = Ready {
            stream,
            expires: Instant::now() + LIFETIME,
        };
        loop {
            let request = queue.lock().await.recv().await;
            let Some(request) = request else {
                return;
            };
            // A request that gave up hands the connection back.
            match request.send(ready) {
                Ok(()) => break,
                Err(back) => ready = back,
            }
        }
        tokio::time::sleep(REFILL_DELAY).await;
    }
}

#[cfg(test)]
mod tests;
