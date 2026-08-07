//! Stream transports layered over the security layer.
//!
//! Xray applies its transport framing after TLS, not inside it, so this layer
//! takes an already-secured stream and wraps it. Everything above — the VLESS
//! request header, Vision, XUDP — is unaware of which transport produced the
//! stream it was handed.

mod http_headers;
mod httpupgrade;
mod masquerade;
mod websocket;
mod websocket_frame;

pub use http_headers::{serialize_request, HeaderMap};
pub use httpupgrade::{connect_httpupgrade, HttpUpgradeConfig};
pub use masquerade::{
    apply_masquerade, apply_masquerade_with_versions, BrowserVersions, VersionOffsets,
};
pub use websocket::{accept_key_for, connect_websocket, encode_early_data, WebSocketConfig};
pub use websocket_frame::{encode_client_frames, FrameDecoder, FrameEvent, MAX_FRAME_PAYLOAD};
