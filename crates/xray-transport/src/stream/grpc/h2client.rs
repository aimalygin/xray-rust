//! Opening one gRPC call as an HTTP/2 POST.
//!
//! Xray dials gRPC with `insecure.NewCredentials()` and applies TLS itself in
//! the dial option's `WithContextDialer`
//! (`Xray-core/transport/internet/grpc/dial.go:103-157`), so this takes an
//! already-connected, already-secured stream and speaks h2 over it. The scheme
//! stays `http` for the same reason: grpc-go believes the connection is
//! plaintext.
//!
//! Nothing here chooses or reuses the connection. One call gets one connection;
//! the pool that changes that is a later task, and keeping the connection's
//! origin out of this file is what lets it change without touching the stream
//! adapter.

use h2::client;
use http::uri::Scheme;
use http::{Method, Request, Uri, Version};
use tokio::task::JoinHandle;

use super::config::GrpcConfig;
use super::path::grpc_request_path;
use super::stream::GrpcStream;
use crate::{BoxedTransportStream, TransportError};

/// The spawned task that drives one HTTP/2 connection.
///
/// h2's `Connection` *is* the connection: no frame is read from or written to
/// the socket unless it is polled, and dropping it tears down every stream on
/// it. So it is spawned, and the handle rides along with the stream that needs
/// it alive.
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

/// Opens one bidirectional POST over `io` and returns it as a byte stream.
///
/// The seven fields this puts in the HEADERS frame are the seven a grpc-go
/// v1.81.0 client sends and nothing more; which of them a server actually
/// reads, and which are there only to fit the population, is pinned in
/// `tests/stream_grpc_tests.rs`, `stream_grpc_request_headers_tests`.
///
/// `config.authority` is `grpcSettings.authority` once the caller has resolved
/// it through Xray's fallbacks (`dial.go:159-167`, then grpc-go's own
/// `initAuthority` precedence in `clientconn.go:1956-1988`, which ends at the
/// dial target's `host:port` — it is never empty in practice), and goes out
/// untouched; a value that is not an authority at all never reaches this
/// function, having failed when the config was built. The `:path` is derived
/// here rather than carried, because `multiMode` picks a different stream name
/// and the mode is a property of the dial. `config.user_agent` is
/// sent even when empty, because grpc-go appends the header unconditionally
/// (`grpc@v1.81.0/internal/transport/http2_client.go:578`), which is how
/// Xray's `"golang"` setting — mapped to `""` by
/// [`super::resolve_user_agent`] — reaches the wire.
///
/// The keepalive triple and `initial_windows_size` are not read here. They are
/// connection properties, and this function's connection lives exactly as long
/// as the one call it opens; they belong to the pool that replaces it.
///
/// The response is **not** awaited here. grpc-go's server writes its response
/// HEADERS on the first message rather than on accept
/// (`internal/transport/http2_server.go:1142-1146`), and Xray's inbound has
/// nothing to send until the tunnel it opened does, so waiting would deadlock
/// every dial. The returned stream awaits it on its first read.
pub async fn open_grpc_h2_stream(
    mut io: BoxedTransportStream,
    config: &GrpcConfig,
) -> Result<GrpcStream, TransportError> {
    // Ahead of every byte of I/O below, because it reads nothing but `config`.
    // A request this dial cannot even build should not first put the preface
    // and SETTINGS on the wire and then hang up without a HEADERS frame: those
    // opening bytes are the ones a censor fingerprints — the handshake comment
    // below is about nothing else — and a complete h2 handshake followed by
    // silence is not a shape grpc-go produces.
    //
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
    let path = grpc_request_path(&config.service_name, config.multi_mode);
    let uri = Uri::builder()
        .scheme(Scheme::HTTP)
        .authority(config.authority.clone())
        .path_and_query(path.as_str())
        .build()
        .map_err(|error| grpc_error(&format!("invalid gRPC request path {path:?}"), &error))?;

    // Here because here is the last place it can be: the handshake below moves
    // `io` into h2's `Connection`, so an outbound's `release_record_alignment`
    // (`crates/xray-core-rs/src/outbound.rs:1873,1967`) only ever reaches
    // `GrpcStream` and its default no-op. Unconditional is sound because the
    // alignment serves a Vision direct-mode unwrap and nothing else, and
    // `validate_connector_flow` refuses Vision on every non-`Raw` transport.
    // Held, it costs two socket reads per TLS record for the tunnel's whole
    // life (`penetrating_tls.rs`, `TlsRecordReadLimiter`).
    io.release_record_alignment();

    // The bare handshake, with no `Builder` knobs: it puts the 24-byte preface
    // and an *empty* SETTINGS frame on the wire, which is what grpc-go emits
    // under Xray's defaults. Setting `initial_connection_window_size` in
    // particular would add a WINDOW_UPDATE right behind SETTINGS that grpc-go
    // never sends, and the opening bytes of the connection are exactly what a
    // censor fingerprints.
    let (send_request, connection) = client::handshake(io)
        .await
        .map_err(|error| grpc_error("http/2 handshake failed", &error))?;
    let driver = H2ConnectionDriver {
        task: tokio::spawn(connection),
    };

    // Not a concurrency gate despite the name — it returns ready past the
    // peer's advertised MAX_CONCURRENT_STREAMS, and h2 parks the excess — but
    // it is still the point at which the handshake's outcome surfaces.
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|error| grpc_error("http/2 connection is not ready", &error))?;

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

    // `end_of_stream: false` is what makes this a tunnel rather than a
    // one-shot POST: the request body stays open for the life of the call.
    let (response, uplink) = send_request
        .send_request(request, false)
        .map_err(|error| grpc_error("could not send the gRPC request", &error))?;

    // `send_request` is dropped here on purpose. It is the connection's last
    // outside reference, and h2 closes a connection once nothing references it
    // and no stream is left, so letting it go is what makes this connection
    // die with the one call it was opened for.
    Ok(GrpcStream::new(response, uplink, driver))
}

fn grpc_error(context: &str, error: &dyn std::fmt::Display) -> TransportError {
    TransportError::Grpc(format!("{context}: {error}"))
}
