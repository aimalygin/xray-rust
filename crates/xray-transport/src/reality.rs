use std::fmt;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use thiserror::Error;
use x509_parser::{
    oid_registry::OID_SIG_ED25519,
    prelude::{FromDer, X509Certificate},
};
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_MAX_SHORT_ID_LEN: usize = 8;

pub struct RealitySessionIdInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub hello_random: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityClientHelloPatch {
    pub session_id_offset: usize,
}

pub struct RealityPreparedClientHello {
    pub fingerprint: String,
    pub raw_client_hello: Vec<u8>,
    pub hello_random: [u8; 32],
    pub session_id_offset: usize,
    pub local_x25519_private_key: [u8; 32],
}

impl fmt::Debug for RealityPreparedClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityPreparedClientHello")
            .field("fingerprint", &self.fingerprint)
            .field("raw_client_hello_len", &self.raw_client_hello.len())
            .field("hello_random", &"<redacted>")
            .field("session_id_offset", &self.session_id_offset)
            .field("local_x25519_private_key", &"<redacted>")
            .finish()
    }
}

impl Drop for RealityPreparedClientHello {
    fn drop(&mut self) {
        self.local_x25519_private_key.zeroize();
    }
}

pub struct RealityHandshakeInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub server_public_key: [u8; 32],
    pub prepared_client_hello: RealityPreparedClientHello,
}

impl fmt::Debug for RealityHandshakeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityHandshakeInput")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &"<redacted>")
            .field("server_public_key", &self.server_public_key)
            .field("prepared_client_hello", &self.prepared_client_hello)
            .finish()
    }
}

impl Drop for RealityHandshakeInput {
    fn drop(&mut self) {
        self.short_id.zeroize();
    }
}

pub struct RealityPreparedHandshake {
    pub patched_client_hello: Vec<u8>,
    pub auth_key: [u8; 32],
    pub session_id: [u8; 32],
}

impl fmt::Debug for RealityPreparedHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityPreparedHandshake")
            .field("patched_client_hello_len", &self.patched_client_hello.len())
            .field("auth_key", &"<redacted>")
            .field("session_id", &"<redacted>")
            .finish()
    }
}

impl Drop for RealityPreparedHandshake {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.session_id.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RealityCertificateInput<'a> {
    pub auth_key: &'a [u8; 32],
    pub ed25519_public_key: &'a [u8; 32],
    pub certificate_signature: &'a [u8],
}

impl fmt::Debug for RealityCertificateInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityCertificateInput")
            .field("auth_key", &"<redacted>")
            .field("ed25519_public_key", &"<redacted>")
            .field("certificate_signature", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityCertificateVerification {
    Verified,
    NotReality,
}

impl fmt::Debug for RealitySessionIdInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealitySessionIdInput")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &"<redacted>")
            .field("shared_secret", &"<redacted>")
            .field("hello_random", &"<redacted>")
            .finish()
    }
}

impl Drop for RealitySessionIdInput {
    fn drop(&mut self) {
        self.short_id.zeroize();
        self.shared_secret.zeroize();
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityError {
    #[error("reality short id cannot exceed 8 bytes")]
    ShortIdTooLong,
    #[error("client hello session id range {offset}..{end} is out of bounds for {len} bytes")]
    InvalidSessionIdRange {
        offset: usize,
        end: usize,
        len: usize,
    },
    #[error("unsupported REALITY fingerprint {0}")]
    UnsupportedRealityFingerprint(String),
    #[error("reality X25519 shared secret was all zero")]
    AllZeroSharedSecret,
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("aead seal failed")]
    Aead,
    #[error("invalid reality certificate DER")]
    InvalidRealityCertificateDer,
    #[error("invalid reality certificate bit string")]
    InvalidRealityCertificateBitString,
    #[error("invalid reality Ed25519 public key length {len}")]
    InvalidRealityCertificatePublicKey { len: usize },
}

/// Derives Xray-core's REALITY auth key from the X25519 shared secret.
///
/// Xray-core uses HKDF-SHA256 with `hello.Random[..20]` as salt and
/// `REALITY` as info. The resulting key is used both for ClientHello
/// session-id sealing and REALITY certificate binding.
pub fn derive_reality_auth_key(
    shared_secret: &[u8; 32],
    hello_random: &[u8; 32],
) -> Result<[u8; 32], RealityError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&hello_random[..20]), shared_secret);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key[..])
        .map_err(|_| RealityError::Hkdf)?;
    Ok(auth_key)
}

/// Builds the sealed 32-byte REALITY session id.
///
/// `raw_client_hello_before_seal` must be the pre-seal raw ClientHello bytes
/// with the target session-id range already zeroed. Xray-core uses those bytes
/// as AEAD associated data before copying the sealed session id back.
pub fn build_reality_session_id(
    input: &RealitySessionIdInput,
    raw_client_hello_before_seal: &[u8],
) -> Result<[u8; 32], RealityError> {
    validate_reality_short_id(input)?;

    let mut session_id_prefix = Zeroizing::new([0u8; 16]);
    session_id_prefix[..3].copy_from_slice(&input.version);
    session_id_prefix[4..8].copy_from_slice(&input.unix_time.to_be_bytes());
    session_id_prefix[8..8 + input.short_id.len()].copy_from_slice(&input.short_id);

    let auth_key = Zeroizing::new(derive_reality_auth_key(
        &input.shared_secret,
        &input.hello_random,
    )?);

    let cipher = Aes256Gcm::new_from_slice(&auth_key[..]).map_err(|_| RealityError::Aead)?;
    let nonce = Nonce::from_slice(&input.hello_random[20..]);
    let tag = cipher
        .encrypt_in_place_detached(
            nonce,
            raw_client_hello_before_seal,
            session_id_prefix.as_mut(),
        )
        .map_err(|_| RealityError::Aead)?;

    let mut session_id = [0u8; 32];
    session_id[..16].copy_from_slice(session_id_prefix.as_ref());
    session_id[16..].copy_from_slice(&tag);
    Ok(session_id)
}

/// Verifies Xray-core's non-ML-DSA REALITY certificate binding.
///
/// Xray-core recognizes a REALITY peer certificate when
/// `HMAC-SHA512(auth_key, ed25519_public_key)` equals the leaf certificate
/// signature bytes. The auth key is the derived REALITY auth key, not the raw
/// X25519 shared secret.
pub fn verify_reality_certificate_binding(
    input: RealityCertificateInput<'_>,
) -> RealityCertificateVerification {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(input.auth_key)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(input.ed25519_public_key);

    if mac.verify_slice(input.certificate_signature).is_ok() {
        RealityCertificateVerification::Verified
    } else {
        RealityCertificateVerification::NotReality
    }
}

/// Parses a leaf certificate DER and verifies Xray-core's REALITY HMAC binding.
///
/// This is only the REALITY recognition step. Normal x509 fallback validation
/// stays outside this primitive.
pub fn verify_reality_certificate_der(
    auth_key: &[u8; 32],
    leaf_der: &[u8],
) -> Result<RealityCertificateVerification, RealityError> {
    let (remaining, certificate) = X509Certificate::from_der(leaf_der)
        .map_err(|_| RealityError::InvalidRealityCertificateDer)?;
    if !remaining.is_empty() {
        return Err(RealityError::InvalidRealityCertificateDer);
    }

    let public_key_info = certificate.public_key();
    if public_key_info.algorithm.algorithm != OID_SIG_ED25519 {
        return Ok(RealityCertificateVerification::NotReality);
    }
    if public_key_info.algorithm.parameters.is_some()
        || (certificate.signature_algorithm.algorithm == OID_SIG_ED25519
            && certificate.signature_algorithm.parameters.is_some())
    {
        return Err(RealityError::InvalidRealityCertificateDer);
    }
    if public_key_info.subject_public_key.unused_bits != 0
        || certificate.signature_value.unused_bits != 0
    {
        return Err(RealityError::InvalidRealityCertificateBitString);
    }

    let public_key = public_key_info.subject_public_key.data.as_ref();
    let public_key: &[u8; 32] =
        public_key
            .try_into()
            .map_err(|_| RealityError::InvalidRealityCertificatePublicKey {
                len: public_key.len(),
            })?;

    Ok(verify_reality_certificate_binding(
        RealityCertificateInput {
            auth_key,
            ed25519_public_key: public_key,
            certificate_signature: certificate.signature_value.data.as_ref(),
        },
    ))
}

/// Seals and patches the REALITY session id bytes into a raw ClientHello.
///
/// Invalid session-id ranges and overlong `short_id` values return before mutating
/// `raw_client_hello`. On success, the configured session-id range is first zeroed
/// for associated-data construction and then rewritten with the sealed bytes.
pub fn seal_reality_client_hello(
    input: &RealitySessionIdInput,
    patch: RealityClientHelloPatch,
    raw_client_hello: &mut [u8],
) -> Result<[u8; REALITY_SESSION_ID_LEN], RealityError> {
    validate_reality_short_id(input)?;

    let offset = patch.session_id_offset;
    let len = raw_client_hello.len();
    let end =
        offset
            .checked_add(REALITY_SESSION_ID_LEN)
            .ok_or(RealityError::InvalidSessionIdRange {
                offset,
                end: usize::MAX,
                len,
            })?;

    if end > len {
        return Err(RealityError::InvalidSessionIdRange { offset, end, len });
    }

    raw_client_hello[offset..end].fill(0);
    let session_id = build_reality_session_id(input, raw_client_hello)?;
    raw_client_hello[offset..end].copy_from_slice(&session_id);

    Ok(session_id)
}

fn validate_reality_short_id(input: &RealitySessionIdInput) -> Result<(), RealityError> {
    if input.short_id.len() > REALITY_MAX_SHORT_ID_LEN {
        return Err(RealityError::ShortIdTooLong);
    }

    Ok(())
}
