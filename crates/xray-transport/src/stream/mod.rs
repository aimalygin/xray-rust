//! Stream transports layered over the security layer.
//!
//! Xray applies its transport framing after TLS, not inside it, so this layer
//! takes an already-secured stream and wraps it. Everything above — the VLESS
//! request header, Vision, XUDP — is unaware of which transport produced the
//! stream it was handed.

mod grpc;
mod http_headers;
mod httpupgrade;
mod masquerade;
mod websocket;
mod websocket_frame;

/// Test scaffolding, not API: `tests/stream_grpc_tests.rs` imports from here
/// and nothing else may. The four gRPC names on the line below are the
/// transport's whole public surface; `grpc::test_only` says why the rest is
/// behind a door with its purpose in the name.
#[doc(hidden)]
pub use grpc::test_only as grpc_test_only;
pub use grpc::{resolve_user_agent, Authority, GrpcConfig, GrpcTransport};
pub use http_headers::{serialize_request, HeaderMap};
pub use httpupgrade::{connect_httpupgrade, HttpUpgradeConfig};
pub use masquerade::{
    apply_masquerade, apply_masquerade_with_versions, BrowserVersions, VersionOffsets,
};
pub use websocket::{accept_key_for, connect_websocket, encode_early_data, WebSocketConfig};

/// The transport layered over the security layer. `Raw` is a no-op.
///
/// Deliberately **not** named `StreamTransport`: `xray_config::StreamTransport`
/// is the parsed config shape, this is the dial-ready one with the host
/// precedence already resolved. Two types with one name across two crates in
/// the same call chain is how the wrong one gets imported.
///
/// Three of the four are a wrapper around one socket: hand them a dialled
/// stream and they hand one back. [`Grpc`](Self::Grpc) is not, because its
/// flows share an HTTP/2 connection and its Nth flow wants no socket at all.
/// So there is no method here that applies a layer to a stream — the variants
/// are dispatched by
/// [`TransportDialer::connect_stream`](crate::TransportDialer::connect_stream),
/// which is where "does this call need a socket" can be answered per variant.
#[derive(Debug, Clone)]
pub enum TransportLayer {
    Raw,
    WebSocket(WebSocketConfig),
    HttpUpgrade(HttpUpgradeConfig),
    Grpc(GrpcTransport),
}

pub use websocket_frame::{encode_client_frames, FrameDecoder, FrameEvent, MAX_FRAME_PAYLOAD};
