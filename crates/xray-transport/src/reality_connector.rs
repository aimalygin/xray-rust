//! REALITY connector boundary.
//!
//! Future `RealityConnector::connect` implementation notes:
//!
//! 1. Build a Chrome-compatible TLS 1.3 ClientHello.
//! 2. Put Xray version, unix time, and `shortId` into the 32-byte session id.
//! 3. Compute X25519 shared secret with the server public key.
//! 4. Derive the auth key with HKDF-SHA256, salt `hello.random[..20]`, info `REALITY`.
//! 5. AES-GCM seal the first 16 bytes of the session id with nonce `hello.random[20..32]`
//!    and associated data equal to the raw ClientHello.
//! 6. Replace the session id bytes in the raw ClientHello.
//! 7. Complete TLS handshake and verify the REALITY certificate HMAC.
//!
//! This logic stays inside `xray-transport`; VLESS should only see an async byte stream.

use crate::RealityClientConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityHandshakePlan {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

#[derive(Debug, Clone)]
pub struct RealityConnector {
    config: RealityClientConfig,
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
