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

pub use grpc::grpc_request_path;
pub use http_headers::{serialize_request, HeaderMap};
pub use httpupgrade::{connect_httpupgrade, HttpUpgradeConfig};
pub use masquerade::{
    apply_masquerade, apply_masquerade_with_versions, BrowserVersions, VersionOffsets,
};
pub use websocket::{accept_key_for, connect_websocket, encode_early_data, WebSocketConfig};

use crate::{BoxedTransportStream, TransportError};

/// The transport layered over the security layer. `Raw` is a no-op.
///
/// Deliberately **not** named `StreamTransport`: `xray_config::StreamTransport`
/// is the parsed config shape, this is the dial-ready one with the host
/// precedence already resolved. Two types with one name across two crates in
/// the same call chain is how the wrong one gets imported.
#[derive(Debug, Clone)]
pub enum TransportLayer {
    Raw,
    WebSocket(WebSocketConfig),
    HttpUpgrade(HttpUpgradeConfig),
}

impl TransportLayer {
    pub async fn wrap(
        &self,
        stream: BoxedTransportStream,
    ) -> Result<BoxedTransportStream, TransportError> {
        match self {
            Self::Raw => Ok(stream),
            Self::WebSocket(config) => connect_websocket(stream, config).await,
            Self::HttpUpgrade(config) => connect_httpupgrade(stream, config).await,
        }
    }
}
pub use websocket_frame::{encode_client_frames, FrameDecoder, FrameEvent, MAX_FRAME_PAYLOAD};
