//! Shapes plain-TLS ClientHellos with uTLS fingerprint profiles.
//!
//! Xray-core sends a uTLS-shaped ClientHello on every TLS connection, not just
//! REALITY ones, defaulting to `chrome` when `tlsSettings.fingerprint` is
//! unset. This module is the plain-TLS half of that: it applies a profile's
//! shape while leaving the hello random and key share to rustls, which is
//! exactly what separates it from `reality_rustls`'s customizer.

use rand::{rngs::OsRng, RngCore};
use rustls::client::{
    ClientHelloContext, ClientHelloCustomizer, ClientHelloPlan, ClientHelloSessionId,
};
use rustls::Error as RustlsError;

use crate::utls_profiles::{profile_for_fingerprint, UtlsClientHelloProfile};
use crate::utls_shaping::{apply_alpn_override, apply_utls_profile, profile_offers_tls13};
use crate::TransportError;

const ALPN_HTTP11: &str = "http/1.1";
const ALPN_H2: &str = "h2";

/// Selects the uTLS handshake entry point Xray uses for a stream transport.
///
/// A configured ALPN list alone is not enough to derive this: RAW, HTTP
/// clients, and WebSocket deliberately treat the same list differently,
/// while gRPC must never negotiate HTTP/1.1. Keeping the distinction in the
/// TLS config cache also prevents one outbound from reusing another
/// transport's ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TlsAlpnPolicy {
    Raw,
    /// Xray's ordinary HTTP-client handshake, used by XHTTP/2.
    ///
    /// A shaped ClientHello retains the profile's ALPN extension. Stock TLS
    /// retains a configured list, or supplies Go's default HTTP pair when the
    /// list is empty.
    HttpClient,
    Http1Upgrade,
    Http2,
}

/// Resolves a normalized fingerprint to a shaping profile.
///
/// `None` means the hello is left unshaped: either no fingerprint was
/// configured, or it was Xray's `unsafe` sentinel.
///
/// The configured name comes back alongside the profile so that a caller
/// refusing the profile can name what the user wrote. That is not always the
/// name the profile answers to — `random` and `randomized` resolve to a drawn
/// one — and the name in a config file is the one worth reporting.
pub(crate) fn shaping_profile(
    fingerprint: Option<&str>,
) -> Result<Option<(&str, &'static UtlsClientHelloProfile)>, TransportError> {
    let Some(fingerprint) = fingerprint else {
        return Ok(None);
    };
    if fingerprint == xray_utls::UNSAFE_TLS_FINGERPRINT {
        return Ok(None);
    }

    profile_for_fingerprint(fingerprint)
        .map(|profile| Some((fingerprint, profile)))
        .ok_or_else(|| TransportError::UnsupportedTlsFingerprint(fingerprint.to_owned()))
}

/// Applies the fingerprint's ClientHello shape to an ordinary TLS handshake.
///
/// Unlike the REALITY customizer this sets no hello random and no fixed key
/// share — those carry REALITY's authentication and have no place in a plain
/// handshake. It does set a session id, but only for TLS-1.2-era profiles and
/// only to a fresh random value: see `parroted_session_id`.
#[derive(Debug)]
pub(crate) struct UtlsClientHelloCustomizer {
    profile: &'static UtlsClientHelloProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
}

impl UtlsClientHelloCustomizer {
    pub(crate) fn new(
        profile: &'static UtlsClientHelloProfile,
        alpn: &[String],
        policy: TlsAlpnPolicy,
    ) -> Self {
        Self {
            profile,
            alpn_override: alpn_override_for(alpn, policy),
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
/// - XHTTP/2 calls the ordinary `HandshakeContext`, so a shaped profile keeps
///   its own ALPN rather than being rewritten to gRPC's `h2`-only offer.
///
fn alpn_override_for(alpn: &[String], policy: TlsAlpnPolicy) -> Option<Vec<Vec<u8>>> {
    match policy {
        TlsAlpnPolicy::Raw => match alpn {
            [only] if only == ALPN_HTTP11 => Some(vec![ALPN_HTTP11.as_bytes().to_vec()]),
            _ => None,
        },
        TlsAlpnPolicy::HttpClient => None,
        TlsAlpnPolicy::Http1Upgrade => match alpn {
            [h2, http11] if h2 == ALPN_H2 && http11 == ALPN_HTTP11 => None,
            _ => Some(vec![ALPN_HTTP11.as_bytes().to_vec()]),
        },
        TlsAlpnPolicy::Http2 => Some(vec![ALPN_H2.as_bytes().to_vec()]),
    }
}

/// ALPN applied to an unshaped (`unsafe`) ClientHello for the same handshake
/// policy. Unlike a shaped profile, stock TLS has no embedded ALPN to keep.
pub(crate) fn unshaped_alpn_protocols(
    configured: &[String],
    policy: TlsAlpnPolicy,
) -> Vec<Vec<u8>> {
    match policy {
        TlsAlpnPolicy::Raw => configured
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect(),
        TlsAlpnPolicy::HttpClient if configured.is_empty() => {
            vec![ALPN_H2.as_bytes().to_vec(), ALPN_HTTP11.as_bytes().to_vec()]
        }
        TlsAlpnPolicy::HttpClient => configured
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect(),
        TlsAlpnPolicy::Http1Upgrade if matches!(configured, [h2, http11] if h2 == ALPN_H2 && http11 == ALPN_HTTP11) => {
            configured
                .iter()
                .map(|protocol| protocol.as_bytes().to_vec())
                .collect()
        }
        TlsAlpnPolicy::Http1Upgrade => vec![ALPN_HTTP11.as_bytes().to_vec()],
        TlsAlpnPolicy::Http2 => vec![ALPN_H2.as_bytes().to_vec()],
    }
}

impl ClientHelloCustomizer for UtlsClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        let mut plan = apply_utls_profile(ClientHelloPlan::new(), self.profile, context)?;

        if !profile_offers_tls13(self.profile) {
            plan = plan.with_session_id(parroted_session_id()?);
        }
        if let Some(protocols) = &self.alpn_override {
            plan = apply_alpn_override(plan, self.profile, protocols)?;
        }

        Ok(Some(plan))
    }
}

/// The 32 random bytes uTLS puts in every ClientHello's legacy session id.
///
/// Go fills it for any connection that is not QUIC, with no version test at all
/// (`utls@v1.8.3-0.20260301010127-aa6edf4b11af/handshake_client.go:126-136`),
/// and `BuildHandshakeState` on each TLS-1.2-era parrot does report 32 bytes.
/// rustls disagrees: it empties the field as soon as its config stops offering
/// TLS 1.3 (`rustls/src/client/hs.rs:125`), which is exactly the config those
/// parrots need. Restoring the field is therefore part of capping the version,
/// not a separate nicety — capping alone would leave the hello 32 bytes shorter
/// than any client it is imitating.
///
/// Redrawn per connection, because Go redraws it per hello.
fn parroted_session_id() -> Result<ClientHelloSessionId, RustlsError> {
    let mut session_id = vec![0u8; 32];
    OsRng
        .try_fill_bytes(&mut session_id)
        .map_err(|error| RustlsError::General(format!("session id needs randomness: {error}")))?;

    ClientHelloSessionId::try_from(session_id)
}

#[cfg(test)]
mod tests {
    use super::{alpn_override_for, unshaped_alpn_protocols, TlsAlpnPolicy};

    fn configured(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn stream_transport_alpn_policies_are_distinct() {
        let empty = configured(&[]);
        let h2 = configured(&["h2"]);
        let pair = configured(&["h2", "http/1.1"]);

        assert_eq!(alpn_override_for(&h2, TlsAlpnPolicy::Raw), None);
        assert_eq!(
            alpn_override_for(&h2, TlsAlpnPolicy::HttpClient),
            None,
            "XHTTP keeps a shaped profile's ALPN"
        );
        assert_eq!(
            alpn_override_for(&empty, TlsAlpnPolicy::Http1Upgrade),
            Some(vec![b"http/1.1".to_vec()])
        );
        assert_eq!(
            alpn_override_for(&pair, TlsAlpnPolicy::Http1Upgrade),
            None,
            "Xray preserves its exact h2/http1 compatibility exception"
        );
        assert_eq!(
            alpn_override_for(&empty, TlsAlpnPolicy::Http2),
            Some(vec![b"h2".to_vec()])
        );

        assert_eq!(
            unshaped_alpn_protocols(&empty, TlsAlpnPolicy::Http1Upgrade),
            vec![b"http/1.1".to_vec()]
        );
        assert_eq!(
            unshaped_alpn_protocols(&empty, TlsAlpnPolicy::HttpClient),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            unshaped_alpn_protocols(&h2, TlsAlpnPolicy::HttpClient),
            vec![b"h2".to_vec()],
            "an explicit stock-TLS ALPN list is preserved"
        );
        assert_eq!(
            unshaped_alpn_protocols(&empty, TlsAlpnPolicy::Http2),
            vec![b"h2".to_vec()]
        );
    }
}
