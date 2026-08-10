//! Stream transports layered over the security layer.
//!
//! Xray applies its transport framing after TLS, not inside it, so this layer
//! takes an already-secured stream and wraps it. Everything above — the VLESS
//! request header, Vision, XUDP — is unaware of which transport produced the
//! stream it was handed.
//!
//! **Most of what this module re-exports is test scaffolding.** Every
//! transport here is driven from a `tests/stream_*_tests.rs`, an integration
//! test is a separate crate, and so each internal one of them touches has to
//! be `pub`. What genuinely crosses this package's boundary is
//! [`TransportLayer`] and what `xray-core-rs` builds it out of —
//! [`WebSocketConfig`], [`HttpUpgradeConfig`], the gRPC surface, and XHTTP's
//! normalized config and persistent transport handle.
//! Nothing outside this package names anything else here: [`connect_websocket`]
//! and [`connect_httpupgrade`] have one caller each in `dialer.rs` and would
//! otherwise be `pub(crate)`, and what `http_headers`, `masquerade` and
//! `websocket_frame` export is called only from inside this crate and from
//! `tests/`. The workspace sets `publish = false`, so the cost is not a semver
//! promise — nothing outside this repository can depend on any of it. The cost
//! is that every crate inside it can, and can take a frame decoder or a header
//! builder for an entry point.
//!
//! gRPC is the one transport that answers that, with `grpc::test_only`
//! (re-exported below as `grpc_test_only`): a single `#[doc(hidden)]` module
//! wearing its purpose in its name, leaving four supported names beside it.
//! **That is the shape a transport added to this layer should copy.** The
//! websocket and httpupgrade modules still export their scaffolding flat, and
//! this pass left it where it is rather than churn working code; the trade is
//! argued once, on `grpc::test_only`.

mod grpc;
mod http_headers;
mod httpupgrade;
mod masquerade;
mod websocket;
mod websocket_frame;
mod xhttp;

/// Test scaffolding, not API: `tests/stream_grpc_tests.rs` imports from here
/// and nothing else should. The five gRPC names on the line below are the
/// transport's whole *supported* surface. `grpc::test_only` says what is
/// behind this door, why each name is there, and why it is a door and not a
/// lock.
#[doc(hidden)]
pub use grpc::test_only as grpc_test_only;
pub use grpc::{resolve_user_agent, Authority, GrpcConfig, GrpcTransport, HeaderValue};
pub use http_headers::{serialize_request, HeaderMap};
pub use httpupgrade::{connect_httpupgrade, HttpUpgradeConfig};
pub use masquerade::{
    apply_masquerade, apply_masquerade_with_versions, BrowserVersions, VersionOffsets,
};
pub use websocket::{accept_key_for, connect_websocket, encode_early_data, WebSocketConfig};
#[doc(hidden)]
pub use xhttp::composer_test_only as xhttp_composer_test_only;
#[doc(hidden)]
pub use xhttp::h2_test_only as xhttp_h2_test_only;
#[doc(hidden)]
pub use xhttp::h3_test_only as xhttp_h3_test_only;
#[doc(hidden)]
pub use xhttp::test_only as xhttp_h1_test_only;
#[doc(hidden)]
pub use xhttp::transport_test_only as xhttp_transport_test_only;
pub use xhttp::{
    H3Congestion, H3QuicConfig, H3QuicVersion, H3UdpHopConfig, XhttpConfig, XhttpConfigInput,
    XhttpEndpoint, XhttpHttpVersion, XhttpMetadataPlacement, XhttpMode, XhttpModeSelection,
    XhttpPaddingMethod, XhttpPaddingPlacement, XhttpRange, XhttpScheme, XhttpTransport,
    XhttpUplinkDataPlacement, XhttpXmuxPolicy,
};

/// The transport layered over the security layer. `Raw` is a no-op.
///
/// Deliberately **not** named `StreamTransport`: `xray_config::StreamTransport`
/// is the parsed config shape, this is the dial-ready one with the host
/// precedence already resolved. Two types with one name across two crates in
/// the same call chain is how the wrong one gets imported.
///
/// The upgrade transports wrap one socket. [`Grpc`](Self::Grpc) and
/// [`Xhttp`](Self::Xhttp) instead retain connection pools, so their next
/// logical flow may need no new socket at all. There is therefore no method
/// here that blindly applies a layer to one stream — the variants are
/// dispatched by
/// [`TransportDialer::connect_stream`](crate::TransportDialer::connect_stream),
/// which is where "does this call need a socket" can be answered per variant.
#[derive(Debug, Clone)]
pub enum TransportLayer {
    Raw,
    WebSocket(WebSocketConfig),
    HttpUpgrade(HttpUpgradeConfig),
    Grpc(GrpcTransport),
    Xhttp(XhttpTransport),
}

pub use websocket_frame::{encode_client_frames, FrameDecoder, FrameEvent, MAX_FRAME_PAYLOAD};
