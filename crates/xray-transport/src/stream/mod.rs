//! Stream transports layered over the security layer.
//!
//! Xray applies its transport framing after TLS, not inside it, so this layer
//! takes an already-secured stream and wraps it. Everything above — the VLESS
//! request header, Vision, XUDP — is unaware of which transport produced the
//! stream it was handed.

mod http_headers;
mod masquerade;

pub use http_headers::{serialize_request, HeaderMap};
pub use masquerade::{apply_masquerade, apply_masquerade_with_versions, BrowserVersions};
