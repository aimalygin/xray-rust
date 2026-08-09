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
/// **This is not API**, but it is still in the crate's semver promise: a
/// `#[doc(hidden)] pub` name is hidden from rustdoc, not from a downstream
/// `use`. What the module buys is discoverability, not unreachability. Four
/// names out of this transport are meant to be found: the two types the
/// outbound builds (`GrpcConfig`, `GrpcTransport`), the [`Authority`] the first
/// of them holds, and [`resolve_user_agent`], which the outbound calls to fill
/// it in. The rest are gathered here rather than re-exported beside those four
/// so that nothing outside a test reaches one by autocomplete and takes it for
/// a supported entry point.
///
/// Eight of the nine are named by that file. [`GrpcKeepalive`] is the
/// exception: no test imports it — they reach its fields through the value
/// [`resolve_keepalive`] returns — and it is here only so that that return
/// type is nameable by whoever can call the function.
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
/// That alternative — moving these tests into `#[cfg(test)]` modules under
/// `src/stream/` so nothing has to be `pub` at all — is available and is not
/// taken. This transport's tests are integration tests by convention, so that
/// the framing and the pool are exercised across the crate boundary a real
/// caller sits on; see the header of `tests/stream_grpc_tests.rs`. What is
/// *not* claimed is that integration tests were forced on it: five modules
/// elsewhere in this crate are in-src `#[cfg(test)] mod tests`
/// (`happy_eyeballs.rs`, `dns.rs`, `reality_rustls.rs`, `utls_shaping.rs`,
/// `penetrating_tls.rs`).
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
