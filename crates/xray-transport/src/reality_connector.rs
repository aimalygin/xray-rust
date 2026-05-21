//! REALITY connector boundary.
//!
//! Oracle/source: `Xray-core/transport/internet/reality/reality.go::UClient`.
//! Pure session-id sealing and ClientHello patching live in `crate::reality`.
//!
//! This connector remains non-networked until Chrome/uTLS-compatible ClientHello generation
//! and REALITY certificate verification exist.
//!
//! Future `RealityConnector::connect` implementation notes:
//!
//! 1. Build a Chrome-compatible TLS 1.3 ClientHello and expose its raw bytes,
//!    random, session-id offset, and ECDHE key share.
//! 2. Compute the X25519 shared secret with the server public key.
//! 3. Call `seal_reality_client_hello`.
//! 4. Complete the TLS handshake.
//! 5. Verify the REALITY certificate HMAC.
//!
//! VLESS should only see an async byte stream once live REALITY is implemented.

use std::fmt;

use crate::RealityClientConfig;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct RealityHandshakePlan {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

impl fmt::Debug for RealityHandshakePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityHandshakePlan")
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("public_key", &self.public_key)
            .field("short_id", &"<redacted>")
            .field("spider_x", &self.spider_x)
            .finish()
    }
}

impl Drop for RealityHandshakePlan {
    fn drop(&mut self) {
        self.short_id.zeroize();
    }
}

#[derive(Clone)]
pub struct RealityConnector {
    config: RealityClientConfig,
}

impl fmt::Debug for RealityConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityConnector")
            .field("config", &self.config)
            .finish()
    }
}

impl RealityConnector {
    pub fn new(config: RealityClientConfig) -> Self {
        Self { config }
    }

    pub fn is_fingerprint_supported(&self) -> bool {
        matches!(self.config.fingerprint.as_str(), "chrome")
    }

    pub fn handshake_plan(&self) -> RealityHandshakePlan {
        RealityHandshakePlan {
            server_name: self.config.server_name.clone(),
            fingerprint: self.config.fingerprint.clone(),
            public_key: self.config.public_key,
            short_id: self.config.short_id.clone(),
            spider_x: self.config.spider_x.clone(),
        }
    }
}
