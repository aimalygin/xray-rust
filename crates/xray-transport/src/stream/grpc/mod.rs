//! Xray's gRPC stream transport: VLESS bytes inside `Hunk` messages on one
//! bidirectional HTTP/2 stream.

mod config;
mod framing;
mod h2client;
mod keepalive;
mod path;
mod pool;
mod stream;

pub use config::{resolve_user_agent, Authority, GrpcConfig};
pub use pool::GrpcTransport;

/// This transport's internals, gathered behind one door, and the whole reason
/// any of them is `pub`.
///
/// **This is not API, and `#[doc(hidden)]` is not a visibility.** Every name
/// in here is still `pub` and still nameable from any crate in this workspace
/// as `xray_transport::stream::grpc_test_only::*`, and the types drag their
/// inherent methods and trait impls along with them. What the module buys is
/// discoverability, not unreachability. Four names out of this transport are
/// meant to be found: the two types the outbound builds (`GrpcConfig`,
/// `GrpcTransport`), the [`Authority`] the first of them holds, and
/// [`resolve_user_agent`], which the outbound calls to fill it in. The rest are
/// gathered here rather than re-exported beside those four so that nothing
/// outside a test reaches one by autocomplete and takes it for a supported
/// entry point.
///
/// Most of these are here because `tests/stream_grpc_tests.rs` names them.
/// [`GrpcKeepalive`] is not: no test imports it — the keepalive tests reach its
/// fields through the value [`resolve_keepalive`] returns — and it is here only
/// so that that return type stays nameable by whoever can call the function.
///
/// [`open_grpc_h2_stream`](h2client::open_grpc_h2_stream) is why the module
/// exists rather than a `#[doc(hidden)]` on each name. It takes a
/// caller-supplied stream and opens a call on it, which is a whole dial that
/// never goes near
/// [`TransportDialer::connect_resolved`](crate::TransportDialer::connect_resolved)
/// — the method `GrpcTransport::open_stream` reaches precisely because a socket
/// opened anywhere else misses Android's `VpnService.protect(fd)` and routes
/// back into the tunnel it is leaving. A public function whose own doc comment
/// warns you off it is worse than no function. Gathering it behind a door
/// labelled `test_only` does not lock the door — the function is still `pub`
/// and still callable as `stream::grpc_test_only::open_grpc_h2_stream` — it
/// only stops anyone arriving at it by accident. Making it genuinely
/// unreachable means an in-src `#[cfg(test)]` module, which is the trade below.
///
/// **The alternative, argued here and nowhere else.** Moving these tests into
/// `#[cfg(test)]` modules under `src/stream/` would make every name above
/// private, and the shape is available: `happy_eyeballs.rs`, `dns.rs`,
/// `reality_rustls.rs`, `utls_shaping.rs` and `penetrating_tls.rs` each carry
/// an in-src `#[cfg(test)] mod tests`, and no module of this transport does.
/// It is declined so that the framing and the pool are exercised across the
/// crate boundary a real caller sits on; see the header of
/// `tests/stream_grpc_tests.rs`. So integration tests here are a convention,
/// not a constraint — but that is one claim, and it belongs in one place.
/// [`GrpcTransport::holds_a_live_connection`],
/// [`GrpcStream::connection_is_finished`](stream::GrpcStream::connection_is_finished)
/// and that test header each point back here rather than restate it, so this
/// stays one claim to check instead of four copies to keep in step.
///
/// [`GrpcKeepalive`]: config::GrpcKeepalive
/// [`resolve_keepalive`]: config::resolve_keepalive
#[doc(hidden)]
pub mod test_only {
    pub use super::config::{resolve_keepalive, GrpcKeepalive};
    pub use super::framing::{encode_hunk, HunkDecoder, HunkMode, MAX_HUNK_PAYLOAD_LEN};
    pub use super::h2client::open_grpc_h2_stream;
    pub use super::path::grpc_request_path;
    pub use super::stream::GrpcStream;
}
