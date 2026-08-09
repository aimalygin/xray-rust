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
//! **One thing a `*grpc.ClientConn` does that this slot does not: go idle.**
//! grpc-go's idleness manager closes the transport under a `ClientConn` that
//! has had no RPC for `idleTimeout`, which defaults to thirty minutes and
//! which Xray never overrides (`grpc@v1.81.0/dialoptions.go:715`,
//! `clientconn.go:257`); the next dial rebuilds it. A slot here is held until
//! it dies or is retired, so a proxy left untouched overnight keeps a socket
//! open that Xray would have dropped. Closing it on a timer needs a count of
//! the calls in flight, which h2 does not expose, and the same count is what
//! grpc-go's keepalive dormancy turns on — see [`super::resolve_keepalive`]
//! for the other half of that gap.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;
use xray_routing::Target;

use super::config::GrpcConfig;
use super::h2client::{build_grpc_request, h2_handshake, open_grpc_call, H2Connection};
use crate::{
    BoxedTransportStream, ConnectorConfig, HappyEyeballsConfig, TransportDialer, TransportError,
};

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
            pool: Arc::new(GrpcConnectionPool::default()),
        }
    }

    /// Whether the pool is holding a connection it would hand the next flow.
    ///
    /// A point-in-time answer, and only useful as one: nothing may act on it,
    /// because the connection can die between the question and the use. It
    /// exists so a test can wait for a retirement it would otherwise have to
    /// race.
    pub async fn holds_a_live_connection(&self) -> bool {
        self.pool
            .connection
            .lock()
            .await
            .as_ref()
            .is_some_and(H2Connection::is_live)
    }

    /// Opens one flow, dialling only if the pool has nothing live.
    ///
    /// **The dial goes through [`TransportDialer::connect_resolved`]**, the
    /// same method every other transport reaches through `connect_stream`.
    /// That is not tidiness: a socket opened anywhere else misses Android's
    /// `VpnService.protect(fd)` and routes straight back into the tunnel it is
    /// supposed to be leaving. Reaching the shared method is also what brings
    /// the REALITY preconnect and the Happy Eyeballs race along at no cost.
    ///
    /// **The lock is held across the dial, and that is the single-flighting.**
    /// Without it, N flows arriving on a cold pool each miss, each pay a TCP
    /// connect and a TLS or REALITY handshake, and N-1 of the connections they
    /// open are then dropped on the floor — the exact cost pooling exists to
    /// remove, paid at the worst possible moment. It has to be a
    /// [`tokio::sync::Mutex`] for the same reason: a `std` guard held across
    /// an `.await` is not `Send`, and both callers of `connect_stream` are
    /// spawned.
    ///
    /// Holding it across [`open_grpc_call`] too costs a little concurrency on
    /// a warm pool and buys the one thing a check-then-use split cannot have:
    /// the liveness test and the stream it justifies are one step, so a
    /// connection that ends in between is never the one a flow is handed.
    ///
    /// **The larger cost the lock accepts is that there is no dial timeout
    /// under it.** [`crate::connect_tcp_stream`] is a bare
    /// `TcpStream::connect` (`crates/xray-transport/src/lib.rs:425`), so
    /// against a server whose SYNs are blackholed every flow on this outbound
    /// queues behind one hung dial and they fail one after another, at N times
    /// the OS connect timeout rather than together. grpc-go is not this shape:
    /// its `ClientConn` connects in the background under Xray's
    /// `MinConnectTimeout` of five seconds and its half-second-to-nineteen-
    /// second backoff (`Xray-core/transport/internet/grpc/dial.go:92-100`),
    /// and an RPC that arrives while the channel is in `TRANSIENT_FAILURE`
    /// fails at once instead of waiting. Closing that needs a dial timeout the
    /// crate does not have anywhere — none of the other transports has one
    /// either — so it is deferred rather than papered over here.
    pub async fn open_stream(
        &self,
        dialer: &TransportDialer,
        connector: &ConnectorConfig,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let mut pooled = self.pool.connection.lock().await;

        if let Some(connection) = pooled.as_ref().filter(|connection| connection.is_live()) {
            // Built ahead of the call and propagated rather than swallowed,
            // because the two failures below are unrelated: an unbuildable
            // request is a static config error that would be identical on a
            // brand-new connection, so treating it as a dead connection would
            // retire a healthy one and redial for nothing, once per flow.
            // [`build_grpc_request`] has the rest of that reasoning.
            let request = build_grpc_request(&self.config)?;
            if let Ok(stream) = open_grpc_call(connection, request).await {
                return Ok(Box::new(stream));
            }
            // Reached when a connection this task had just called live refused
            // the call anyway: h2 keeps a `Connection` future running until
            // every stream on it has ended, so a peer's `GOAWAY` leaves the
            // driver alive and unable to open anything new until the last
            // tunnel drains. grpc-go answers the same frame by building a
            // fresh transport under the same `ClientConn`; retiring and
            // redialling here is the closest thing to it, and the alternative
            // is failing every flow for as long as the drain lasts.
            //
            // Dropping the error is safe only because of the line above it:
            // past the build, the sole thing an error out of `open_grpc_call`
            // can say is that this connection would not carry the call, which
            // is exactly what the redial answers. Whatever the redial hits is
            // the error a caller sees.
        }
        *pooled = None;

        // Before the dial for the same reason: a config error should not cost
        // a TCP connect and a REALITY handshake first.
        let request = build_grpc_request(&self.config)?;
        let io = dialer
            .connect_resolved(connector, original_target, candidates, happy_eyeballs)
            .await?;
        let connection = h2_handshake(io, &self.config).await?;
        let stream = open_grpc_call(&connection, request).await?;
        *pooled = Some(connection);
        Ok(Box::new(stream))
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
#[derive(Default)]
struct GrpcConnectionPool {
    connection: Mutex<Option<H2Connection>>,
}

impl fmt::Debug for GrpcConnectionPool {
    /// Hand-written because `TransportLayer` derives `Debug` and gets printed
    /// in outbound diagnostics: `try_lock` keeps that from blocking, or
    /// deadlocking against a dial that is holding the lock on this task.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let live = match self.connection.try_lock() {
            Ok(connection) => connection.as_ref().map(H2Connection::is_live),
            Err(_) => None,
        };
        formatter
            .debug_struct("GrpcConnectionPool")
            .field("live_connection", &live)
            .finish()
    }
}
