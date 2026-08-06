//! Shapes plain-TLS ClientHellos with uTLS fingerprint profiles.
//!
//! Xray-core sends a uTLS-shaped ClientHello on every TLS connection, not just
//! REALITY ones, defaulting to `chrome` when `tlsSettings.fingerprint` is
//! unset. This module is the plain-TLS half of that: it applies a profile's
//! shape while leaving the hello random, session id, and key share to rustls,
//! which is exactly what separates it from `reality_rustls`'s customizer.

use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::client::{
    CapturesClientHello, ClientHelloAlpnProtocols, ClientHelloContext, ClientHelloCustomizer,
    ClientHelloPlan,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, Error as RustlsError};

use crate::utls_profiles::{profile_for_fingerprint, UtlsClientHelloProfile};
use crate::utls_shaping::apply_utls_profile;
use crate::{TlsClientConfig, TransportError};

/// The one configured ALPN list Xray rebuilds the ClientHello for. Anything
/// else leaves the fingerprint profile's own ALPN in place.
const ALPN_OVERRIDE_TRIGGER: &str = "http/1.1";

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// Every ClientHello record carries the legacy 0x0301 version for middlebox
/// compatibility, whatever version the handshake actually negotiates.
const TLS_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x01];
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Resolves a normalized fingerprint to a shaping profile.
///
/// `None` means the hello is left unshaped: either no fingerprint was
/// configured, or it was Xray's `unsafe` sentinel.
pub(crate) fn shaping_profile(
    fingerprint: Option<&str>,
) -> Result<Option<&'static UtlsClientHelloProfile>, TransportError> {
    let Some(fingerprint) = fingerprint else {
        return Ok(None);
    };
    if fingerprint == xray_utls::UNSAFE_TLS_FINGERPRINT {
        return Ok(None);
    }

    profile_for_fingerprint(fingerprint)
        .map(Some)
        .ok_or_else(|| TransportError::UnsupportedTlsFingerprint(fingerprint.to_owned()))
}

/// Applies the fingerprint's ClientHello shape to an ordinary TLS handshake.
///
/// Unlike the REALITY customizer this sets no hello random, no session id, and
/// no fixed key share — those carry REALITY's authentication and have no place
/// in a plain handshake.
pub(crate) struct UtlsClientHelloCustomizer {
    profile: &'static UtlsClientHelloProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
    capture: Option<Arc<PlainClientHelloCapture>>,
}

impl UtlsClientHelloCustomizer {
    pub(crate) fn new(profile: &'static UtlsClientHelloProfile, alpn: &[String]) -> Self {
        Self {
            profile,
            alpn_override: alpn_override_for(alpn),
            capture: None,
        }
    }

    fn with_capture(mut self, capture: Arc<PlainClientHelloCapture>) -> Self {
        self.capture = Some(capture);
        self
    }
}

/// Mirrors `UConn.WebsocketHandshakeContext`: the hello is rebuilt with ALPN
/// forced to `http/1.1` only when the configured list is exactly that.
fn alpn_override_for(alpn: &[String]) -> Option<Vec<Vec<u8>>> {
    match alpn {
        [only] if only == ALPN_OVERRIDE_TRIGGER => {
            Some(vec![ALPN_OVERRIDE_TRIGGER.as_bytes().to_vec()])
        }
        _ => None,
    }
}

impl fmt::Debug for UtlsClientHelloCustomizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UtlsClientHelloCustomizer")
            .field("profile", &self.profile)
            .field("alpn_override", &self.alpn_override)
            .field("capture", &self.capture.is_some())
            .finish()
    }
}

impl ClientHelloCustomizer for UtlsClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        let mut plan = apply_utls_profile(ClientHelloPlan::new(), self.profile)?;

        // Plan setters are last-write-wins, so this replaces the profile's own
        // ALPN list rather than adding a second extension.
        if let Some(protocols) = &self.alpn_override {
            plan = plan.with_alpn_protocols(ClientHelloAlpnProtocols::try_from(protocols.clone())?);
        }
        if let Some(capture) = &self.capture {
            plan = plan.with_capture(capture.clone());
        }

        Ok(Some(plan))
    }
}

#[derive(Debug, Default)]
pub(crate) struct PlainClientHelloCapture {
    bytes: Mutex<Option<Vec<u8>>>,
}

impl PlainClientHelloCapture {
    fn take(&self) -> Result<Vec<u8>, TransportError> {
        let mut bytes = self.bytes.lock().map_err(|_| {
            TransportError::TlsConfig("ClientHello capture lock was poisoned".to_owned())
        })?;
        bytes.take().ok_or_else(|| {
            TransportError::TlsConfig("rustls did not capture a ClientHello".to_owned())
        })
    }
}

impl CapturesClientHello for PlainClientHelloCapture {
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), RustlsError> {
        let mut captured = self.bytes.lock().map_err(|_| {
            RustlsError::General("ClientHello capture lock was poisoned".to_owned())
        })?;
        *captured = Some(bytes.to_vec());
        Ok(())
    }
}

/// Produces the ClientHello a plain-TLS connection would send, without opening
/// a socket. Exposed for byte-parity tests against Xray-core.
///
/// The returned bytes are one TLS handshake record: a 5-byte record header
/// followed by the ClientHello message, whether or not the hello was shaped.
pub fn plain_tls_client_hello_bytes(config: &TlsClientConfig) -> Result<Vec<u8>, TransportError> {
    let (client_config, capture) = match shaping_profile(config.fingerprint.as_deref())? {
        Some(profile) => {
            let capture = Arc::new(PlainClientHelloCapture::default());
            let mut client_config = crate::tls::shaped_client_config(config.allow_insecure)?;
            client_config.client_hello_customizer = Some(Arc::new(
                UtlsClientHelloCustomizer::new(profile, &config.alpn)
                    .with_capture(Arc::clone(&capture)),
            ));
            (client_config, Some(capture))
        }
        None => (crate::tls::base_client_config(config.allow_insecure)?, None),
    };

    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| TransportError::InvalidTlsServerName(config.server_name.clone()))?;
    let mut connection = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
    // Emitting the hello is what runs the capture hook; draining it also gives
    // the unshaped path the only copy it can read.
    let mut first_flight = Vec::new();
    connection
        .write_tls(&mut first_flight)
        .map_err(TransportError::Tcp)?;

    match capture {
        // The capture hook yields the bare handshake message, so frame it the
        // way the record layer would have.
        Some(capture) => framed_handshake_record(&capture.take()?),
        // Unshaped: rustls emitted its own hello, and the drained first flight
        // already carries its record header.
        None => Ok(first_flight),
    }
}

fn framed_handshake_record(handshake: &[u8]) -> Result<Vec<u8>, TransportError> {
    let length = u16::try_from(handshake.len()).map_err(|_| {
        TransportError::TlsConfig("ClientHello does not fit in one TLS record".to_owned())
    })?;
    let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + handshake.len());
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&TLS_LEGACY_RECORD_VERSION);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(handshake);
    Ok(record)
}
