use std::fmt;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

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
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("aead seal failed")]
    Aead,
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

    let hkdf = Hkdf::<Sha256>::new(Some(&input.hello_random[..20]), &input.shared_secret);
    let mut auth_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"REALITY", &mut auth_key[..])
        .map_err(|_| RealityError::Hkdf)?;

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
