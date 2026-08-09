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

/// The internals `tests/stream_grpc_tests.rs` reaches for, and the whole reason
/// any of them is `pub`.
///
/// **This is not API.** Four names out of this transport are: the two types the
/// outbound builds (`GrpcConfig`, `GrpcTransport`), the [`Authority`] the first
/// of them holds, and [`resolve_user_agent`], which the outbound calls to fill
/// it in. Everything below is a unit under test that happens to live in a
/// library crate, and it is gathered here rather than re-exported beside those
/// four so that nothing outside a test can reach one by autocomplete and take
/// it for a supported entry point.
///
/// [`open_grpc_h2_stream`](h2client::open_grpc_h2_stream) is why the module
/// exists rather than a `#[doc(hidden)]` on each name. It takes a
/// caller-supplied stream and opens a call on it, which is a whole dial that
/// never goes near
/// [`TransportDialer::connect_resolved`](crate::TransportDialer::connect_resolved)
/// — the method `GrpcTransport::open_stream` reaches precisely because a socket
/// opened anywhere else misses Android's `VpnService.protect(fd)` and routes
/// back into the tunnel it is leaving. A public function whose own doc comment
/// warns you off it is worse than no function; a private one the tests can
/// still drive is what was wanted.
///
/// The alternative — moving these tests into `#[cfg(test)]` modules under
/// `src/stream/` so nothing has to be `pub` at all — is available and is not
/// taken. This transport's tests are integration tests by convention, so that
/// the framing and the pool are exercised across the crate boundary a real
/// caller sits on; see the header of `tests/stream_grpc_tests.rs`. What is
/// *not* claimed is that integration tests were forced on it: six modules
/// elsewhere in this crate are `#[cfg(test)]` and in-src.
#[doc(hidden)]
pub mod test_only {
    pub use super::config::{resolve_keepalive, GrpcKeepalive};
    pub use super::framing::{encode_hunk, HunkDecoder, HunkMode, MAX_HUNK_PAYLOAD_LEN};
    pub use super::h2client::open_grpc_h2_stream;
    pub use super::path::grpc_request_path;
    pub use super::stream::GrpcStream;
}
