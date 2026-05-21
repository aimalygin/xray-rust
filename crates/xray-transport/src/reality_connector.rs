//! REALITY connector boundary.
//!
//! Oracle/source: `Xray-core/transport/internet/reality/reality.go::UClient`.
//! Pure session-id sealing, ClientHello patching, and certificate HMAC
//! verification live in `crate::reality`.
//!
//! This connector remains non-networked until Chrome/uTLS-compatible ClientHello generation
//! and a complete REALITY TLS handshake exist.
//!
//! Future `RealityConnector::connect` implementation notes:
//!
//! 1. Build or integrate a Chrome-compatible TLS 1.3 ClientHello provider that
//!    exposes raw bytes, random, session-id offset, and local ECDHE private key.
//! 2. Feed that provider output into `prepare_reality_handshake`.
//! 3. Write the patched ClientHello to the network stream and complete TLS.
//! 4. Call `verify_reality_certificate_der` on the leaf certificate with the
//!    derived auth key from `RealityPreparedHandshake`.
//! 5. Expose the protected stream to VLESS only after REALITY verification.
//!
//! VLESS should only see an async byte stream once live REALITY is implemented.

use std::fmt;

use crate::{
    reality::{
        prepare_reality_handshake, validate_reality_client_hello_metadata, RealityError,
        RealityHandshakeInput, RealityPreparedClientHello, RealityPreparedHandshake,
    },
    RealityClientConfig,
};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityClientHelloRequest<'a> {
    pub server_name: &'a str,
    pub fingerprint: &'a str,
}

pub trait RealityClientHelloProvider: Send + Sync {
    fn prepare_client_hello(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, RealityError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityHandshakeContext {
    pub version: [u8; 3],
    pub unix_time: u32,
}

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

    pub fn prepare_handshake(
        &self,
        provider: &dyn RealityClientHelloProvider,
        context: RealityHandshakeContext,
    ) -> Result<RealityPreparedHandshake, RealityError> {
        if !self.is_fingerprint_supported() {
            return Err(RealityError::UnsupportedRealityFingerprint(
                self.config.fingerprint.clone(),
            ));
        }

        let prepared_client_hello = provider.prepare_client_hello(RealityClientHelloRequest {
            server_name: &self.config.server_name,
            fingerprint: &self.config.fingerprint,
        })?;
        validate_reality_client_hello_metadata(&prepared_client_hello)?;

        prepare_reality_handshake(RealityHandshakeInput {
            version: context.version,
            unix_time: context.unix_time,
            short_id: self.config.short_id.clone(),
            server_public_key: self.config.public_key,
            prepared_client_hello,
        })
    }
}
