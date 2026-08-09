//! Opening an HTTP/2 connection, and one gRPC call on it.
//!
//! Xray dials gRPC with `insecure.NewCredentials()` and applies TLS itself in
//! the dial option's `WithContextDialer`
//! (`Xray-core/transport/internet/grpc/dial.go:103-157`), so this takes an
//! already-connected, already-secured stream and speaks h2 over it. The scheme
//! stays `http` for the same reason: grpc-go believes the connection is
//! plaintext.
//!
//! Nothing here decides *where* a connection comes from. The pieces are
//! deliberately separate — [`h2_handshake`] runs once per connection,
//! [`build_grpc_call`] and [`open_grpc_call`] once per flow — because that
//! is the seam [`super::pool`] needs: it keeps the first and repeats the rest,
//! and it needs the request built before it decides anything about a
//! connection.

use std::sync::Arc;

use bytes::Bytes;
use h2::client::{self, SendRequest};
use http::uri::Scheme;
use http::{Method, Request, Uri, Version};
use tokio::task::JoinHandle;

use super::config::{resolve_keepalive, GrpcConfig};
use super::framing::HunkMode;
use super::keepalive::{OpenCalls, Pings, WatchedIo};
use super::path::grpc_request_path;
use super::stream::GrpcStream;
use crate::{BoxedTransportStream, TransportError};

/// grpc-go's `defaultWindowSize`
/// (`grpc@v1.81.0/internal/transport/defaults.go:28`), which is also HTTP/2's
/// own default and so the value a `SETTINGS_INITIAL_WINDOW_SIZE` entry would
/// be restating.
const DEFAULT_WINDOW_SIZE: u32 = 65535;

/// The spawned task that drives one HTTP/2 connection.
///
/// h2's `Connection` *is* the connection: no frame is read from or written to
/// the socket unless it is polled, and dropping it tears down every stream on
/// it. So it is spawned, and the handle is shared by everything that needs it
/// alive — the pool holding the connection, and every call open on it.
///
/// **Completion is not success.** A graceful `GOAWAY(NO_ERROR)` resolves the
/// future as `Ok(())` — `take_error` maps `(NO_ERROR, NO_ERROR)` to `Ok`
/// (`h2-0.4.15/src/proto/connection.rs:216-235`) — so anything that retires a
/// connection only when the driver returns `Err` will keep handing out a dead
/// one. [`H2ConnectionDriver::is_finished`] is the question to ask instead.
///
/// The handle is deliberately *not* aborted on drop. Dropping both halves of a
/// stream is what makes h2 emit `RST_STREAM`, and an abort in the same drop
/// would swallow it before the driver could flush it; letting the task run out
/// instead lets the reset, and the connection's own `GOAWAY`, reach the peer.
#[derive(Debug)]
pub(crate) struct H2ConnectionDriver {
    task: JoinHandle<Result<(), h2::Error>>,
}

impl H2ConnectionDriver {
    /// Whether the connection is over, gracefully or otherwise.
    pub(crate) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// A live HTTP/2 connection, and the task that drives it.
///
/// Holding the [`SendRequest`] is what keeps the connection open with no call
/// on it: h2 closes a connection once nothing references it and no stream is
/// left. That is the difference between a pooled connection and the one
/// [`open_grpc_h2_stream`] opens, which drops its handle and so dies with the
/// call.
#[derive(Debug)]
pub(crate) struct H2Connection {
    send_request: SendRequest<Bytes>,
    driver: Arc<H2ConnectionDriver>,
    /// Shared with the keepalive, which pings only a connection that has one —
    /// see [`super::keepalive`].
    calls: Arc<OpenCalls>,
}

impl H2Connection {
    /// Whether this connection is still worth handing a call to.
    ///
    /// Completion is not success — see [`H2ConnectionDriver`] — so this asks
    /// whether the driver is *finished*, not whether it failed.
    pub(crate) fn is_live(&self) -> bool {
        !self.driver.is_finished()
    }
}

/// Completes the HTTP/2 handshake over `io` and spawns the connection's driver.
///
/// This is where the two connection-level `grpcSettings` are applied, because
/// this is the only place a connection is created.
///
/// **`initialWindowsSize` reaches the wire through three gates in grpc-go and
/// they collapse to one condition here.** The dial option is attached only
/// above zero (`Xray-core/transport/internet/grpc/dial.go:177-179`); the
/// transport adopts the value only at `defaultWindowSize` or more
/// (`grpc@v1.81.0/internal/transport/http2_client.go:383-385`); and the
/// `SETTINGS_INITIAL_WINDOW_SIZE` entry is written only when the adopted value
/// differs from that default (`http2_client.go:435-447`). 65535 passes the
/// first two and is stopped by the third, so applying the builder knob at
/// exactly 65535 would put an entry on the wire that grpc-go never writes.
/// Anything below it changes nothing, and h2's default is the same 65535.
///
/// A second effect is worth not conflating with those three:
/// `WithInitialWindowSize` also sets `StaticWindowSize`
/// (`grpc@v1.81.0/dialoptions.go:213-218`), which switches off grpc-go's BDP
/// estimator (`http2_client.go:386-391`) and the WINDOW_UPDATEs it would send
/// as the connection warms up. Reproducing BDP pings is outside the parity bar
/// and is not attempted either way.
///
/// `initial_connection_window_size` is deliberately left alone: h2 answers it
/// with a WINDOW_UPDATE right behind SETTINGS, and grpc-go writes one only
/// above `defaultWindowSize` for the *connection* window
/// (`http2_client.go:453-458`), which Xray never configures. The opening bytes
/// of a connection are exactly what a censor fingerprints.
///
/// **The `PingPong` handle is taken before the driver is spawned**, because it
/// can be taken only once and only from the `Connection`, which the spawn
/// moves.
///
/// **The socket is wrapped before the handshake and not after**, for the same
/// reason: past it h2 owns the socket, and [`WatchedIo`] is the only way the
/// keepalive can see the reads grpc-go suppresses a ping on.
pub(crate) async fn h2_handshake(
    mut io: BoxedTransportStream,
    config: &GrpcConfig,
) -> Result<H2Connection, TransportError> {
    // Here because here is the last place it can be: the handshake below moves
    // `io` into h2's `Connection`, so an outbound's `release_record_alignment`
    // (`crates/xray-core-rs/src/outbound.rs:1873,1967`) only ever reaches
    // `GrpcStream` and its default no-op. Unconditional is sound because the
    // alignment serves a Vision direct-mode unwrap and nothing else, and
    // `validate_connector_flow` refuses Vision on every non-`Raw` transport.
    // Held, it costs two socket reads per TLS record for the tunnel's whole
    // life (`penetrating_tls.rs`, `TlsRecordReadLimiter`).
    io.release_record_alignment();

    let mut builder = client::Builder::new();
    if config.initial_windows_size > DEFAULT_WINDOW_SIZE {
        builder.initial_window_size(config.initial_windows_size);
    }

    let keepalive = resolve_keepalive(config);
    let (io, last_read) = WatchedIo::new(io, keepalive);
    let (send_request, mut connection) = builder
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|error| grpc_error("http/2 handshake failed", &error))?;

    let calls = Arc::new(OpenCalls::default());
    let pings = keepalive.zip(last_read).and_then(|(keepalive, last_read)| {
        connection.ping_pong().map(|ping_pong| Pings {
            ping_pong,
            keepalive,
            last_read,
            calls: Arc::clone(&calls),
        })
    });

    let driver = Arc::new(H2ConnectionDriver {
        task: tokio::spawn(drive(connection, pings)),
    });
    Ok(H2Connection {
        send_request,
        driver,
        calls,
    })
}

/// Polls the connection, and pings it if keepalive was configured.
///
/// The two run in one task because neither works without the other: a `Ping`
/// is written and its `Pong` read by the connection being polled, so a
/// keepalive on a task of its own would wait for an acknowledgement nothing
/// was moving. Losing the race also has to end the connection — grpc-go treats
/// an unacknowledged ping as a connection error, "keepalive ping failed to
/// receive ACK within timeout" (`http2_client.go:1754-1757`) — and dropping
/// the `Connection` out of the `select!` is exactly that.
async fn drive(
    connection: client::Connection<WatchedIo, Bytes>,
    pings: Option<Pings>,
) -> Result<(), h2::Error> {
    let Some(pings) = pings else {
        return connection.await;
    };

    tokio::select! {
        outcome = connection => outcome,
        // The pool asks `is_finished`, not what the task returned, so a
        // keepalive that gave up retires the connection just as an error
        // would — see `H2ConnectionDriver`.
        () = pings.run() => Ok(()),
    }
}

/// One gRPC call, ready to be opened on a connection: its HEADERS block and the
/// message its replies will be read as.
///
/// **The two travel together so that they cannot disagree.** They are two
/// halves of one choice — `multiMode` picks `TunMulti` over `Tun` in the
/// `:path` *and* `MultiHunk` over `Hunk` on the wire (see [`HunkMode`]) — and
/// the failure when they part company is silent: a single-mode decoder on a
/// `TunMulti` call hands the caller only the last chunk of every message it
/// reads, with no error to notice. [`build_grpc_call`] derives one [`HunkMode`]
/// and gives it to both, so there is no second value to get backwards and no
/// way to reach [`open_grpc_call`] with a request whose mode was left behind.
pub(crate) struct GrpcCall {
    request: Request<()>,
    mode: HunkMode,
}

/// The HEADERS block one gRPC call opens with, built out of `config` alone.
///
/// **Separate from [`open_grpc_call`], and built by [`super::pool`] before it
/// looks at a connection, because the two fail for unrelated reasons.**
/// Everything here comes from static configuration and nothing from the
/// connection, so a failure is identical on every flow and says nothing about
/// any connection's health. Folded into the call it would reach the pool as
/// "this connection refused the call", which retires a healthy shared
/// connection and pays a TCP connect plus a TLS or REALITY handshake to be
/// told the same thing again — once per flow, for as long as the config
/// stands. It is also ahead of the first frame a flow puts on the wire: a call
/// that cannot even be built should not open a stream and then abandon it,
/// because a HEADERS immediately followed by a RST_STREAM is not a shape
/// grpc-go produces.
///
/// The seven fields this puts in the frame are the seven a grpc-go v1.81.0
/// client sends and nothing more; which of them a server actually reads, and
/// which are there only to fit the population, is pinned in
/// `tests/stream_grpc_tests.rs`, `stream_grpc_request_headers_tests`.
///
/// `config.authority` is `grpcSettings.authority` once the caller has resolved
/// it through Xray's fallbacks (`dial.go:159-167`, then grpc-go's own
/// `initAuthority` precedence in `clientconn.go:1956-1988`, which ends at the
/// dial target's `host:port` — it is never empty in practice), and goes out
/// untouched; a value that is not an authority at all never reaches this
/// function, having failed when the config was built. The `:path` is derived
/// here rather than carried, because `multiMode` picks a different stream name
/// and the mode is a property of the dial. `config.user_agent` is sent even
/// when empty, because grpc-go appends the header unconditionally
/// (`grpc@v1.81.0/internal/transport/http2_client.go:578`), which is how
/// Xray's `"golang"` setting — mapped to `""` by
/// [`super::resolve_user_agent`] — reaches the wire.
pub(crate) fn build_grpc_call(config: &GrpcConfig) -> Result<GrpcCall, TransportError> {
    // The one place `multiMode` becomes a mode. Everything downstream takes
    // this value rather than reading the config again, which is what makes a
    // `:path` and a decoder that disagree unrepresentable — see [`GrpcCall`].
    let mode = if config.multi_mode {
        HunkMode::Multi
    } else {
        HunkMode::Single
    };

    // The URI has to be absolute: with `Version::HTTP_2` and no scheme plus
    // authority, `send_request` fails with `MissingUriSchemeAndAuthority`
    // (`h2-0.4.15/src/client.rs:1644`), because those two are where `:scheme`
    // and `:authority` come from. `http` even over TLS, for the reason the
    // module doc gives: grpc-go believes the transport is plaintext.
    //
    // Of the three parts only the path can fail to parse. The scheme is a
    // constant and the authority arrived already parsed — deliberately, so a
    // static config error is reported once at startup rather than once per
    // dial; [`GrpcConfig::authority`] has the reasoning and the grpc-go
    // divergence it costs. `grpc_request_path` percent-escapes everything
    // outside Go's `encodePathSegment` keep-set, so in practice it cannot fail
    // either, but "in practice" is not something to unwrap on: a path is the
    // one part of this URI a future caller could supply.
    let path = grpc_request_path(&config.service_name, mode);
    let uri = Uri::builder()
        .scheme(Scheme::HTTP)
        .authority(config.authority.clone())
        .path_and_query(path.as_str())
        .build()
        .map_err(|error| grpc_error(&format!("invalid gRPC request path {path:?}"), &error))?;

    // Nothing below is redundant, however little of it a server reads. A stock
    // grpc-go inbound validates `:method` and `content-type` and no more —
    // `te` and `user-agent` are never looked at
    // (`http2_server.go:417-427,495-497,548-556`) — but grpc-go's *client*
    // sends both on every call, unconditionally, so a dial missing either
    // stands out from the population it is hiding in.
    let request = Request::builder()
        .version(Version::HTTP_2)
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("user-agent", &config.user_agent)
        .header("te", "trailers")
        .body(())
        .map_err(|error| grpc_error("could not build the gRPC request", &error))?;

    Ok(GrpcCall { request, mode })
}

/// Opens one bidirectional POST on `connection` and returns it as a byte
/// stream.
///
/// `call` comes from [`build_grpc_call`] rather than being built here, so that
/// the only thing an error out of this function can mean is that the connection
/// would not carry the call — which is what [`super::pool`] acts on.
///
/// The `SendRequest` is cloned rather than borrowed, so each call gets its own
/// `pending` slot. h2 refuses a second stream queued behind a still-unopened
/// one on the *same* handle — `UserError::Rejected`
/// (`h2-0.4.15/src/proto/streams/streams.rs:252-256`) — and past the peer's
/// MAX_CONCURRENT_STREAMS that is where a pooled connection's second flow
/// would land.
///
/// The response is **not** awaited here. grpc-go's server writes its response
/// HEADERS on the first message rather than on accept
/// (`internal/transport/http2_server.go:1142-1146`), and Xray's inbound has
/// nothing to send until the tunnel it opened does, so waiting would deadlock
/// every dial. The returned stream awaits it on its first read.
pub(crate) async fn open_grpc_call(
    connection: &H2Connection,
    call: GrpcCall,
) -> Result<GrpcStream, TransportError> {
    // Not a concurrency gate despite the name — h2 parks a stream past the
    // peer's advertised MAX_CONCURRENT_STREAMS rather than refusing it — but
    // it is the point at which a connection that has already failed says so,
    // which on the pooled path is the difference between an error here and a
    // stream the peer will never answer. A `GOAWAY` of any reason, `NO_ERROR`
    // included, is one of those failures
    // (`h2-0.4.15/src/proto/streams/streams.rs:762,1004,1722-1728`).
    let mut send_request = connection
        .send_request
        .clone()
        .ready()
        .await
        .map_err(|error| grpc_error("http/2 connection is not ready", &error))?;

    // `end_of_stream: false` is what makes this a tunnel rather than a
    // one-shot POST: the request body stays open for the life of the call.
    let (response, uplink) = send_request
        .send_request(call.request, false)
        .map_err(|error| grpc_error("could not send the gRPC request", &error))?;

    // Counted in here rather than in `GrpcStream::new`, because this is where
    // grpc-go counts it: `initStream` runs as the HEADERS is written, and it
    // is also what signals the keepalive out of dormancy
    // (`grpc@v1.81.0/internal/transport/http2_client.go:805-822`).
    Ok(GrpcStream::new(
        response,
        uplink,
        call.mode,
        Arc::clone(&connection.driver),
        connection.calls.open(),
    ))
}

/// One gRPC call on a connection of its own, which dies with it.
///
/// Every dial through
/// [`connect_stream`](crate::TransportDialer::connect_stream) goes to
/// [`super::GrpcTransport`] and its pool instead. This is the unpooled form,
/// which the h2 tests exercise; it is built out of the same two halves as the
/// pooled path so that neither can drift from the other.
pub async fn open_grpc_h2_stream(
    io: BoxedTransportStream,
    config: &GrpcConfig,
) -> Result<GrpcStream, TransportError> {
    let call = build_grpc_call(config)?;
    let connection = h2_handshake(io, config).await?;
    open_grpc_call(&connection, call).await
    // `connection` is dropped here on purpose. Its `SendRequest` is the last
    // outside reference, and h2 closes a connection once nothing references it
    // and no stream is left, so letting it go is what makes this connection
    // die with the one call it was opened for.
}

fn grpc_error(context: &str, error: &dyn std::fmt::Display) -> TransportError {
    TransportError::Grpc(format!("{context}: {error}"))
}
