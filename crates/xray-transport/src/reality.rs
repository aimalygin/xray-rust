use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityHelloInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub hello_random_prefix: [u8; 20],
    pub hello_random_suffix: [u8; 12],
    pub hello_raw: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityError {
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("aead seal failed")]
    Aead,
}

pub fn build_reality_session_id(input: &RealityHelloInput) -> Result<[u8; 32], RealityError> {
    let mut session_id_prefix = [0u8; 16];
    session_id_prefix[..3].copy_from_slice(&input.version);
    session_id_prefix[4..8].copy_from_slice(&input.unix_time.to_be_bytes());

    let short_id_len = input.short_id.len().min(8);
    session_id_prefix[8..8 + short_id_len].copy_from_slice(&input.short_id[..short_id_len]);

    let hkdf = Hkdf::<Sha256>::new(Some(&input.hello_random_prefix), &input.shared_secret);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|_| RealityError::Hkdf)?;

    let cipher = Aes256Gcm::new_from_slice(&auth_key).map_err(|_| RealityError::Aead)?;
    let nonce = Nonce::from_slice(&input.hello_random_suffix);
    let mut sealed = session_id_prefix.to_vec();
    cipher
        .encrypt_in_place(nonce, input.hello_raw.as_slice(), &mut sealed)
        .map_err(|_| RealityError::Aead)?;

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&sealed);
    Ok(session_id)
}
