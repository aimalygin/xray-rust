use std::fmt;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

pub struct RealitySessionIdInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub hello_random: [u8; 32],
}

impl fmt::Debug for RealitySessionIdInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealitySessionIdInput")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &self.short_id)
            .field("shared_secret", &"<redacted>")
            .field("hello_random", &"<redacted>")
            .finish()
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

pub fn build_reality_session_id(
    input: &RealitySessionIdInput,
    raw_client_hello_before_seal: &[u8],
) -> Result<[u8; 32], RealityError> {
    if input.short_id.len() > 8 {
        return Err(RealityError::ShortIdTooLong);
    }

    let mut session_id_prefix = [0u8; 16];
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
        .encrypt_in_place_detached(nonce, raw_client_hello_before_seal, &mut session_id_prefix)
        .map_err(|_| RealityError::Aead)?;

    let mut session_id = [0u8; 32];
    session_id[..16].copy_from_slice(&session_id_prefix);
    session_id[16..].copy_from_slice(&tag);
    Ok(session_id)
}
