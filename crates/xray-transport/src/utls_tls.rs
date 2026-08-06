//! Shapes plain-TLS ClientHellos with uTLS fingerprint profiles.
//!
//! Xray-core sends a uTLS-shaped ClientHello on every TLS connection, not just
//! REALITY ones, defaulting to `chrome` when `tlsSettings.fingerprint` is
//! unset. This module is the plain-TLS half of that: it applies a profile's
//! shape while leaving the hello random, session id, and key share to rustls,
//! which is exactly what separates it from `reality_rustls`'s customizer.

use std::sync::Arc;

use rustls::client::{ClientHelloContext, ClientHelloCustomizer, ClientHelloPlan};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, Error as RustlsError};

use crate::utls_profiles::{profile_for_fingerprint, UtlsClientHelloProfile};
use crate::utls_shaping::{apply_alpn_override, apply_utls_profile};
use crate::{TlsClientConfig, TransportError};

/// The one configured ALPN list the RAW transport rebuilds the ClientHello
/// for. Anything else leaves the fingerprint profile's own ALPN in place.
const ALPN_OVERRIDE_TRIGGER: &str = "http/1.1";

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
#[derive(Debug)]
pub(crate) struct UtlsClientHelloCustomizer {
    profile: &'static UtlsClientHelloProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
}

impl UtlsClientHelloCustomizer {
    pub(crate) fn new(profile: &'static UtlsClientHelloProfile, alpn: &[String]) -> Self {
        Self {
            profile,
            alpn_override: alpn_override_for(alpn),
        }
    }
}

/// Implements the RAW transport's gate, not `WebsocketHandshakeContext`'s own
/// rule. Which handshake Xray calls is transport-dependent, and only RAW is
/// reachable today:
///
/// - RAW (`tcp/dialer.go`) calls `WebsocketHandshakeContext` — which forces
///   `http/1.1` — only when the configured list is exactly `["http/1.1"]`,
///   and the plain `HandshakeContext` otherwise. So every other list keeps the
///   profile's own ALPN, which is what this returns.
/// - ws (`websocket/dialer.go`) and httpupgrade (`httpupgrade/dialer.go`) call
///   `WebsocketHandshakeContext` unconditionally, so there the inner rule
///   governs: force `http/1.1` for every list *except* exactly
///   `["h2", "http/1.1"]`.
///
/// Those two transports land in a later plan and need their own gate. Widening
/// this one to match `WebsocketHandshakeContext` would be wrong for RAW.
fn alpn_override_for(alpn: &[String]) -> Option<Vec<Vec<u8>>> {
    match alpn {
        [only] if only == ALPN_OVERRIDE_TRIGGER => {
            Some(vec![ALPN_OVERRIDE_TRIGGER.as_bytes().to_vec()])
        }
        _ => None,
    }
}

impl ClientHelloCustomizer for UtlsClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        let mut plan = apply_utls_profile(ClientHelloPlan::new(), self.profile)?;

        if let Some(protocols) = &self.alpn_override {
            plan = apply_alpn_override(plan, self.profile, protocols)?;
        }

        Ok(Some(plan))
    }
}

/// Builds the rustls config one `TlsClientConfig` asks for: shaped by its
/// fingerprint profile, or rustls' own ClientHello when it names none.
///
/// `TlsConnector` and `plain_tls_client_hello_bytes` both route through this,
/// so the bytes the parity tests inspect stay the bytes a real connection
/// sends. Note which builder each branch picks — the shaped one runs on
/// aws-lc-rs because current profiles plan an X25519MLKEM768 key share that
/// *ring* does not carry, while the unshaped branch must stay on *ring* so
/// that asking for no shaping reproduces the pre-shaping ClientHello exactly.
pub(crate) fn build_client_config(
    config: &TlsClientConfig,
) -> Result<rustls::ClientConfig, TransportError> {
    let client_config = match shaping_profile(config.fingerprint.as_deref())? {
        Some(profile) => {
            let mut client_config = crate::tls::shaped_client_config(config.allow_insecure)?;
            client_config.client_hello_customizer = Some(Arc::new(UtlsClientHelloCustomizer::new(
                profile,
                &config.alpn,
            )));
            client_config
        }
        None => crate::tls::base_client_config(config.allow_insecure)?,
    };

    Ok(client_config)
}

/// Produces the ClientHello a plain-TLS connection would send, without opening
/// a socket. Exposed for byte-parity tests against Xray-core.
///
/// The returned bytes are the connection's whole first flight: one TLS
/// handshake record, header included, shaped or not.
pub fn plain_tls_client_hello_bytes(config: &TlsClientConfig) -> Result<Vec<u8>, TransportError> {
    let client_config = build_client_config(config)?;

    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| TransportError::InvalidTlsServerName(config.server_name.clone()))?;
    let mut connection = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
    let mut first_flight = Vec::new();
    connection
        .write_tls(&mut first_flight)
        .map_err(TransportError::Tcp)?;

    Ok(first_flight)
}
