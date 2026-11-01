//! Classic Shadowsocks AEAD ("AEAD-2017") client codecs, matching Xray-core
//! v26.10.21 `proxy/shadowsocks`: EVP_BytesToKey(MD5) master keys, HKDF-SHA1
//! "ss-subkey" session keys, little-endian nonce counters starting at zero,
//! 2-byte sealed length records and one-shot UDP packets. Stream ciphers and
//! the `none` method are not accepted, as in the reference.
mod stream;
mod udp;
pub use stream::ClientStream;
pub use udp::UdpSession;

use aws_lc_rs::{
    aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305},
    hkdf::{KeyType, Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY},
};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Tag, XChaCha20Poly1305,
};
use md5::{Digest, Md5};
use std::{fmt, io};
use zeroize::{Zeroize, Zeroizing};

pub const TAG_LENGTH: usize = 16;
/// SIP004 payload cap. Xray's reader does not enforce it, but every writer
/// does (Xray itself never exceeds 8158 bytes); a larger length is refused.
pub const MAX_PAYLOAD_LENGTH: usize = 0x3FFF;
/// Xray's writer seals at most one 8192-byte buffer per record, including
/// the sealed length and both tags (`common/crypto/auth.go` writeStream).
pub const MAX_WRITE_PAYLOAD: usize = 8192 - 2 - 2 * TAG_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Cipher {
    /// Exactly the names of Xray-core's `cipherFromString`; callers lowercase.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "aes-128-gcm" | "aead_aes_128_gcm" => Self::Aes128Gcm,
            "aes-256-gcm" | "aead_aes_256_gcm" => Self::Aes256Gcm,
            "chacha20-poly1305" | "aead_chacha20_poly1305" | "chacha20-ietf-poly1305" => {
                Self::ChaCha20Poly1305
            }
            "xchacha20-poly1305" | "aead_xchacha20_poly1305" | "xchacha20-ietf-poly1305" => {
                Self::XChaCha20Poly1305
            }
            _ => return None,
        })
    }
    /// Key, subkey and salt lengths are equal for every AEAD method.
    pub fn key_len(self) -> usize {
        if self == Self::Aes128Gcm {
            16
        } else {
            32
        }
    }
    fn nonce_len(self) -> usize {
        if self == Self::XChaCha20Poly1305 {
            24
        } else {
            12
        }
    }
}

/// The password-derived master key. Debug output is redacted.
pub struct Method {
    cipher: Cipher,
    key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksAeadMethod")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl Method {
    /// `name` is matched case-insensitively, as Xray-core lowercases it.
    pub fn new(name: &str, password: &str) -> io::Result<Self> {
        let cipher = Cipher::parse(&name.to_lowercase())
            .ok_or_else(|| invalid("unsupported Shadowsocks AEAD method"))?;
        Self::with_cipher(cipher, password)
    }
    pub fn with_cipher(cipher: Cipher, password: &str) -> io::Result<Self> {
        if password.is_empty() {
            return Err(invalid("Shadowsocks password is not specified"));
        }
        Ok(Self {
            cipher,
            key: evp_bytes_to_key(password.as_bytes(), cipher.key_len()),
        })
    }
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// OpenSSL EVP_BytesToKey with MD5, no salt and one round, truncated to the
/// key length (Xray-core `passwordToCipherKey`).
fn evp_bytes_to_key(password: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(Vec::with_capacity(len + 16));
    let mut digest = Md5::digest(password);
    key.extend_from_slice(&digest);
    while key.len() < len {
        let mut hasher = Md5::new();
        hasher.update(digest);
        hasher.update(password);
        digest.zeroize();
        digest = hasher.finalize();
        key.extend_from_slice(&digest);
    }
    digest.zeroize();
    key.truncate(len);
    key
}

struct Len(usize);
impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA1(master key, salt, "ss-subkey"), one subkey per salt.
fn subkey(method: &Method, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let len = method.cipher.key_len();
    let mut out = Zeroizing::new([0; 32]);
    Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
        .extract(&method.key)
        .expand(&[b"ss-subkey"], Len(len))
        .and_then(|okm| okm.fill(&mut out[..len]))
        .expect("HKDF-SHA1 output within its limit");
    out
}

enum Engine {
    Ietf(crate::aead::Key),
    X(Box<XChaCha20Poly1305>),
}

/// One direction's AEAD with Xray's counter nonce: little-endian, starting
/// at zero (`GenerateAEADNonceWithSize`). Exhaustion fails closed rather
/// than wrapping into a reused nonce.
pub(super) struct Records {
    engine: Engine,
    nonce: [u8; 24],
    nonce_len: usize,
    exhausted: bool,
}

impl Records {
    pub(super) fn new(method: &Method, salt: &[u8]) -> Self {
        let key = subkey(method, salt);
        let key = &key[..method.cipher.key_len()];
        let engine = match method.cipher {
            Cipher::Aes128Gcm => Engine::Ietf(crate::aead::Key::new(&AES_128_GCM, key)),
            Cipher::Aes256Gcm => Engine::Ietf(crate::aead::Key::new(&AES_256_GCM, key)),
            Cipher::ChaCha20Poly1305 => {
                Engine::Ietf(crate::aead::Key::new(&CHACHA20_POLY1305, key))
            }
            Cipher::XChaCha20Poly1305 => Engine::X(Box::new(
                XChaCha20Poly1305::new_from_slice(key).expect("32-byte XChaCha20 key"),
            )),
        };
        Self {
            engine,
            nonce: [0; 24],
            nonce_len: method.cipher.nonce_len(),
            exhausted: false,
        }
    }
    fn next(&mut self) -> io::Result<[u8; 24]> {
        if self.exhausted {
            return Err(invalid("Shadowsocks AEAD nonce exhausted"));
        }
        let nonce = self.nonce;
        self.exhausted = true;
        for n in &mut self.nonce[..self.nonce_len] {
            *n = n.wrapping_add(1);
            if *n != 0 {
                self.exhausted = false;
                break;
            }
        }
        Ok(nonce)
    }
    pub(super) fn seal(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        self.seal_from(bytes, 0)
    }
    /// Encrypt `bytes[start..]` in place and append its tag.
    pub(super) fn seal_from(&mut self, bytes: &mut Vec<u8>, start: usize) -> io::Result<()> {
        let nonce = self.next()?;
        match &self.engine {
            Engine::Ietf(key) => key.seal_from(nonce[..12].try_into().unwrap(), &[], bytes, start),
            Engine::X(key) => {
                match key.encrypt_inout_detached((&nonce).into(), &[], (&mut bytes[start..]).into())
                {
                    Ok(tag) => {
                        bytes.extend_from_slice(&tag);
                        Ok(())
                    }
                    Err(_) => {
                        bytes[start..].zeroize();
                        Err(invalid("AEAD encryption failed"))
                    }
                }
            }
        }
    }
    /// Authenticate and decrypt a sealed record in place; returns its length.
    /// The whole input is erased on failure.
    pub(super) fn open(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let nonce = self.next()?;
        match &self.engine {
            Engine::Ietf(key) => key.open_slice(nonce[..12].try_into().unwrap(), &[], bytes),
            Engine::X(key) => {
                let Some(len) = bytes.len().checked_sub(TAG_LENGTH) else {
                    bytes.zeroize();
                    return Err(invalid("AEAD authentication failed"));
                };
                let (text, tag) = bytes.split_at_mut(len);
                let tag = Tag::try_from(&*tag).expect("16-byte tag");
                if key
                    .decrypt_inout_detached((&nonce).into(), &[], text.into(), &tag)
                    .is_err()
                {
                    bytes.zeroize();
                    return Err(invalid("AEAD authentication failed"));
                }
                Ok(len)
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
    fn oracle() -> serde_json::Value {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/v08/protocol-primitives.json"
        ))
        .unwrap();
        v["shadowsocksAead"].clone()
    }
    pub(crate) fn fixtures() -> Vec<serde_json::Value> {
        oracle()["cases"].as_array().unwrap().clone()
    }
    pub(crate) fn method(case: &serde_json::Value) -> std::sync::Arc<Method> {
        std::sync::Arc::new(
            Method::new(
                case["method"].as_str().unwrap(),
                case["password"].as_str().unwrap(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn accepted_method_names_match_pinned_go_config_builder() {
        let methods = oracle()["methods"].as_array().unwrap().clone();
        assert!(methods.len() > 16);
        for case in methods {
            let name = case["method"].as_str().unwrap();
            let expected = match case["class"].as_str().unwrap() {
                "AES_128_GCM" => Some(Cipher::Aes128Gcm),
                "AES_256_GCM" => Some(Cipher::Aes256Gcm),
                "CHACHA20_POLY1305" => Some(Cipher::ChaCha20Poly1305),
                "XCHACHA20_POLY1305" => Some(Cipher::XChaCha20Poly1305),
                "rejected" | "shadowsocks2022" => None,
                other => panic!("unknown class {other}"),
            };
            assert_eq!(Cipher::parse(&name.to_lowercase()), expected, "{name:?}");
            assert_eq!(
                Method::new(name, "synthetic").ok().map(|m| m.cipher),
                expected,
                "{name:?}"
            );
            let facade = crate::shadowsocks::Method::new(name, "AQEBAQEBAQEBAQEBAQEBAQ==");
            match case["class"].as_str().unwrap() {
                "rejected" => assert!(facade.is_err(), "{name:?}"),
                "shadowsocks2022" => assert!(facade.unwrap().is_2022(), "{name:?}"),
                _ => assert!(!facade.unwrap().is_2022(), "{name:?}"),
            }
        }
    }

    #[test]
    fn master_keys_match_pinned_go_and_debug_is_redacted() {
        for case in fixtures() {
            let method = method(&case);
            assert_eq!(*method.key, unhex(case["key"].as_str().unwrap()));
            assert_eq!(
                method.cipher.key_len(),
                case["saltLength"].as_u64().unwrap() as usize
            );
            let debug = format!("{method:?}");
            assert!(!debug.contains(case["password"].as_str().unwrap()));
            assert!(!debug.contains(case["key"].as_str().unwrap()));
        }
        let error = Method::new("aes-128-gcm", "").unwrap_err();
        assert!(error.to_string().contains("password"));
    }

    #[test]
    fn nonce_counter_is_little_endian_and_fails_closed_at_exhaustion() {
        for (name, len) in [("aes-128-gcm", 12), ("xchacha20-poly1305", 24)] {
            let mut records = Records::new(&Method::new(name, "synthetic").unwrap(), &[0; 32]);
            assert_eq!(records.next().unwrap(), [0; 24]);
            let mut one = [0; 24];
            one[0] = 1;
            assert_eq!(records.next().unwrap(), one);
            records.nonce = [0; 24];
            records.nonce[..len].fill(0xff);
            assert!(records.next().is_ok());
            assert!(records.next().is_err());
            assert!(records.seal(&mut vec![1]).is_err());
        }
    }
}
