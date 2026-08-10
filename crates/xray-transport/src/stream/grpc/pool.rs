//! One HTTP/2 connection per gRPC outbound, and the dial that fills it.
//!
//! Xray keeps a `globalDialerMap` of `*grpc.ClientConn` keyed by destination
//! plus stream settings and reuses the entry unless it has gone to
//! `connectivity.Shutdown`
//! (`Xray-core/transport/internet/grpc/dial.go:46-49,89-91`). Every gRPC flow
//! to one server therefore rides one connection and becomes one more HTTP/2
//! stream on it — which is the point of the transport, and the reason gRPC
//! cannot be applied to a socket the way the other stream transports are:
//! wrapping takes one socket and gives back one stream, and gRPC's Nth flow
//! wants no socket at all.
//!
//! The key is narrower here than in Xray. One [`GrpcTransport`] belongs to one
//! outbound, which has one destination and one set of stream settings, so the
//! outbound *is* the key and the map collapses to a single slot.
//!
//! grpc-go's idleness manager also closes the transport under a `ClientConn`
//! that has had no RPC for `idleTimeout`, which defaults to thirty minutes and
//! which Xray never overrides (`grpc@v1.81.0/dialoptions.go:715`,
//! `clientconn.go:257`). The slot below follows that lifecycle: its timer is
//! reset when the last call closes, and retirement drops the pooled
//! `SendRequest` without disturbing any stream that was already opened.
//!
//! **What the pool holding a connection between flows does change is the
//! keepalive**, and that half is not deferred: "no call open" is this
//! transport's steady state rather than an edge case, so grpc-go's dormancy is
//! reproduced in [`super::keepalive`] instead of being written off as an
//! idle-connection detail.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};
use xray_routing::Target;

use super::config::GrpcConfig;
use super::h2client::{
    build_grpc_call, h2_handshake, open_grpc_call, H2Connection, H2ConnectionIdleWatch,
};
use crate::{
    utls_tls::TlsAlpnPolicy, BoxedTransportStream, ConnectorConfig, HappyEyeballsConfig,
    TransportDialer, TransportError,
};

/// Xray supplies grpc-go's `MinConnectTimeout` as five seconds
/// (`Xray-core/transport/internet/grpc/dial.go:92-100`). One shared attempt is
/// bounded by the same interval so a blackholed security or h2 handshake does
/// not pin every flow behind the operating system's TCP timeout.
const COLD_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// grpc-go's default `ClientConn` idle timeout, which Xray does not override.
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The dial-ready gRPC transport: its settings, and the connection its flows
/// share.
///
/// **The pool is behind an `Arc` and that is load-bearing.** `TransportLayer`
/// is `Clone`, and the cached router clones an outbound out of its `OnceLock`
/// for every session it routes, so a pool that deep-copied would hand each
/// flow a private one — every flow dialling, which is the opposite of a pool.
#[derive(Debug, Clone)]
pub struct GrpcTransport {
    config: GrpcConfig,
    pool: Arc<GrpcConnectionPool>,
}

impl GrpcTransport {
    pub fn new(config: GrpcConfig) -> Self {
        Self {
            config,
            pool: Arc::new(GrpcConnectionPool::new()),
        }
    }

    /// The settings this transport dials with.
    ///
    /// **`pub` because the test that needs it is in another crate**, and no
    /// narrower visibility crosses that: `xray-core-rs`'s own `#[cfg(test)]`
    /// module resolves a `grpcSettings` block into one of these and reads back
    /// what it resolved. That is the whole reason, and it is a different reason
    /// from [`Self::holds_a_live_connection`]'s — see there. Hidden so that
    /// nothing outside a test finds it and reaches past `TransportLayer` into a
    /// dialled transport's settings.
    #[doc(hidden)]
    pub fn config(&self) -> &GrpcConfig {
        &self.config
    }

    /// Whether two handles would dial into the same pooled connection.
    ///
    /// The question a caller actually has is about the pool's identity, not
    /// the settings': two `GrpcTransport`s resolved from identical config are
    /// *not* one pool. `Arc::ptr_eq` answers it, and this wrapper is what lets
    /// it be asked from outside the crate without making the pool type public.
    /// `pub` for the same reason [`Self::config`] is — a caller in another
    /// crate — though for a different test in it. This one is read by
    /// `two_selections_of_one_grpc_outbound_share_a_pool` in
    /// `crates/xray-core-rs/src/outbound.rs`, which checks that `xray-core-rs`'s
    /// cached router hands every session the one pool; `config` is read by the
    /// authority tests and `every_grpc_setting_reaches_the_dial_ready_config`
    /// in that same module — named rather than cited by line, since a test name
    /// survives an edit above it and a line number does not.
    #[doc(hidden)]
    pub fn shares_pool_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pool, &other.pool)
    }

    /// Whether the pool is holding a connection it would hand the next flow.
    ///
    /// A point-in-time answer, and only useful as one: nothing may act on it,
    /// because the connection can die between the question and the use. It
    /// exists so a test can wait for a retirement it would otherwise have to
    /// race.
    ///
    /// **`pub` by convention rather than by necessity**, which is where this
    /// differs from [`Self::config`]. Its only caller is this crate's own
    /// `tests/stream_grpc_tests.rs`, and those are integration tests — a
    /// separate crate, so they cannot reach a `pub(crate)`. But nothing forced
    /// them to be integration tests, and an in-src `#[cfg(test)]` module here
    /// would let this be private — [`super::test_only`] is where that trade is
    /// argued and where the modules of this crate that went the other way are
    /// named. The gRPC transport keeps its tests outside so that the framing
    /// and the pool are driven across the crate boundary a real caller sits on,
    /// and pays for that with this. Hidden rather than left in the rendered
    /// API, because nothing outside those tests should find it and be tempted
    /// to branch on it. Its sibling is
    /// [`GrpcStream::connection_is_finished`].
    ///
    /// [`GrpcStream::connection_is_finished`]:
    ///     super::test_only::GrpcStream::connection_is_finished
    #[doc(hidden)]
    pub async fn holds_a_live_connection(&self) -> bool {
        match &*self.pool.state.lock().await {
            PoolState::Ready(connection) => connection.is_live(),
            PoolState::Empty | PoolState::Dialing(_) => false,
        }
    }

    /// Opens one flow, dialling only if the pool has nothing live.
    ///
    /// `pub(crate)` because its one caller anywhere is
    /// [`TransportDialer::connect_stream`](crate::TransportDialer::connect_stream),
    /// which is the door every transport is dispatched through and the only one
    /// that should exist: a caller reaching this directly would be choosing the
    /// gRPC arm for itself, which is the shape of bug the enum exists to stop.
    ///
    /// **The dial goes through [`TransportDialer::connect_resolved`]**, the
    /// same method every other transport reaches through `connect_stream`.
    /// That is not tidiness: a socket opened anywhere else misses Android's
    /// `VpnService.protect(fd)` and routes straight back into the tunnel it is
    /// supposed to be leaving. Reaching the shared method is also what brings
    /// the REALITY preconnect and the Happy Eyeballs race along at no cost.
    ///
    /// **A cold dial is a shared task, and that is the single-flighting.**
    /// Without it, N flows arriving on an empty pool each pay a TCP connect and
    /// a TLS or REALITY handshake, and N-1 of the connections they open are
    /// dropped on the floor. Every waiter observes the one task's result; the
    /// task is independent of the first waiter's cancellation and bounded by
    /// [`COLD_DIAL_TIMEOUT`].
    ///
    /// The state lock is held across [`open_grpc_call`]. That costs a little
    /// concurrency on
    /// a warm pool and buys the one thing a check-then-use split cannot have:
    /// the liveness test and the stream it justifies are one step, so a
    /// connection that ends in between is never the one a flow is handed.
    ///
    pub(crate) async fn open_stream(
        &self,
        dialer: &TransportDialer,
        connector: &ConnectorConfig,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        // Before any pool state for the same reason as before: a static config
        // error must not start a shared TCP/TLS/REALITY attempt.
        let mut call = Some(build_grpc_call(&self.config)?);
        // A live-but-refusing connection (normally GOAWAY under an open call)
        // gets one replacement. A call refused by that fresh replacement is
        // returned rather than becoming an unbounded redial loop.
        let mut may_replace_refusing_connection = true;

        loop {
            let mut state = self.pool.state.lock().await;
            match &mut *state {
                PoolState::Ready(connection) => {
                    if !connection.is_live()
                        || connection.has_been_idle_for(self.pool.connection_idle_timeout)
                    {
                        *state = PoolState::Empty;
                        continue;
                    }

                    let current_call = call
                        .take()
                        .expect("a gRPC call is rebuilt before every retry");
                    match open_grpc_call(connection, current_call).await {
                        Ok(stream) => return Ok(Box::new(stream)),
                        Err(error) => {
                            *state = PoolState::Empty;
                            if !may_replace_refusing_connection {
                                return Err(error);
                            }
                            may_replace_refusing_connection = false;
                            call = Some(build_grpc_call(&self.config)?);
                        }
                    }
                }
                PoolState::Dialing(attempt) => {
                    let attempt = Arc::clone(attempt);
                    drop(state);
                    attempt.wait().await?;
                    // The connection this attempt produced is already the
                    // replacement. If it refuses a call, surface that error.
                    may_replace_refusing_connection = false;
                }
                PoolState::Empty => {
                    let attempt = Arc::new(DialAttempt::new());
                    *state = PoolState::Dialing(Arc::clone(&attempt));
                    self.pool.spawn_dial(
                        dialer.clone(),
                        connector.clone(),
                        original_target.clone(),
                        candidates.to_vec(),
                        happy_eyeballs.copied(),
                        self.config.clone(),
                        Arc::clone(&attempt),
                    );
                    drop(state);
                    attempt.wait().await?;
                    may_replace_refusing_connection = false;
                }
            }
        }
    }
}

/// The one connection a [`GrpcTransport`]'s flows share.
///
/// Empty until the first flow, and empty again once a connection has been
/// retired. **Retirement is on the driver having *finished*, not on it having
/// failed**: a graceful `GOAWAY(NO_ERROR)` resolves h2's connection future as
/// `Ok(())` (`h2-0.4.15/src/proto/connection.rs:216-235`), so a pool that
/// looked for an `Err` would go on handing out a connection whose peer has
/// already said goodbye.
struct GrpcConnectionPool {
    state: Mutex<PoolState>,
    cold_dial_timeout: Duration,
    connection_idle_timeout: Duration,
}

enum PoolState {
    Empty,
    Dialing(Arc<DialAttempt>),
    Ready(H2Connection),
}

#[derive(Clone)]
enum DialOutcome {
    Pending,
    Ready,
    Failed(Arc<str>),
}

struct DialAttempt {
    outcome: watch::Sender<DialOutcome>,
}

impl DialAttempt {
    fn new() -> Self {
        let (outcome, _) = watch::channel(DialOutcome::Pending);
        Self { outcome }
    }

    fn complete(&self, outcome: DialOutcome) {
        self.outcome.send_replace(outcome);
    }

    async fn wait(&self) -> Result<(), TransportError> {
        let mut outcome = self.outcome.subscribe();
        loop {
            match outcome.borrow().clone() {
                DialOutcome::Pending => {}
                DialOutcome::Ready => return Ok(()),
                DialOutcome::Failed(reason) => {
                    return Err(TransportError::Grpc(reason.to_string()))
                }
            }
            // `self` owns the sender for the whole wait, so closure would be
            // an internal lifecycle bug rather than a connection failure.
            if outcome.changed().await.is_err() {
                return Err(TransportError::Grpc(
                    "shared gRPC connection attempt disappeared".to_owned(),
                ));
            }
        }
    }
}

impl GrpcConnectionPool {
    fn new() -> Self {
        Self {
            state: Mutex::new(PoolState::Empty),
            cold_dial_timeout: COLD_DIAL_TIMEOUT,
            connection_idle_timeout: CONNECTION_IDLE_TIMEOUT,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_dial(
        self: &Arc<Self>,
        dialer: TransportDialer,
        connector: ConnectorConfig,
        original_target: Target,
        candidates: Vec<SocketAddr>,
        happy_eyeballs: Option<HappyEyeballsConfig>,
        config: GrpcConfig,
        attempt: Arc<DialAttempt>,
    ) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let timeout = pool.cold_dial_timeout;
            let dialled = tokio::time::timeout(timeout, async {
                let io = dialer
                    .connect_resolved_with_alpn_policy(
                        &connector,
                        &original_target,
                        &candidates,
                        happy_eyeballs.as_ref(),
                        TlsAlpnPolicy::Http2,
                    )
                    .await?;
                h2_handshake(io, &config).await
            })
            .await;

            match dialled {
                Ok(Ok(connection)) => {
                    let idle_watch = connection.idle_watch();
                    let installed = {
                        let mut state = pool.state.lock().await;
                        let current = matches!(
                            &*state,
                            PoolState::Dialing(current) if Arc::ptr_eq(current, &attempt)
                        );
                        if current {
                            *state = PoolState::Ready(connection);
                        }
                        current
                    };

                    if installed {
                        attempt.complete(DialOutcome::Ready);
                        pool.spawn_idle_retirement(idle_watch);
                    } else {
                        attempt.complete(DialOutcome::Failed(Arc::from(
                            "shared gRPC connection attempt was superseded",
                        )));
                    }
                }
                Ok(Err(error)) => {
                    let reason: Arc<str> =
                        Arc::from(format!("gRPC connection attempt failed: {error}"));
                    pool.fail_attempt(&attempt, reason).await;
                }
                Err(_) => {
                    let reason: Arc<str> = Arc::from(format!(
                        "gRPC connection attempt timed out after {:?}",
                        pool.cold_dial_timeout
                    ));
                    pool.fail_attempt(&attempt, reason).await;
                }
            }
        });
    }

    async fn fail_attempt(&self, attempt: &Arc<DialAttempt>, reason: Arc<str>) {
        let mut state = self.state.lock().await;
        if matches!(
            &*state,
            PoolState::Dialing(current) if Arc::ptr_eq(current, attempt)
        ) {
            *state = PoolState::Empty;
        }
        drop(state);
        attempt.complete(DialOutcome::Failed(reason));
    }

    fn spawn_idle_retirement(self: &Arc<Self>, idle: H2ConnectionIdleWatch) {
        let pool = Arc::downgrade(self);
        let timeout = self.connection_idle_timeout;
        tokio::spawn(async move {
            loop {
                idle.wait_until_idle_for(timeout).await;
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                let mut state = pool.state.lock().await;
                let current = matches!(
                    &*state,
                    PoolState::Ready(connection) if idle.watches(connection)
                );
                if !current {
                    return;
                }
                // A call may have opened between the timer firing and this
                // task acquiring the pool lock. Recheck under the same lock
                // every call opening uses before retiring the slot.
                if idle.has_been_idle_for(timeout) {
                    *state = PoolState::Empty;
                    return;
                }
            }
        });
    }
}

impl fmt::Debug for GrpcConnectionPool {
    /// Hand-written because `TransportLayer` derives `Debug` and gets printed
    /// in outbound diagnostics: `try_lock` keeps that from blocking, or
    /// deadlocking against a dial that is holding the lock on this task.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (state, live) = match self.state.try_lock() {
            Ok(state) => match &*state {
                PoolState::Empty => ("empty", None),
                PoolState::Dialing(_) => ("dialing", None),
                PoolState::Ready(connection) => ("ready", Some(connection.is_live())),
            },
            Err(_) => ("locked", None),
        };
        formatter
            .debug_struct("GrpcConnectionPool")
            .field("state", &state)
            .field("live_connection", &live)
            .finish()
    }
}
