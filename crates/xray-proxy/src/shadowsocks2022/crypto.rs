use super::*;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

pub(super) fn derive(context: &str, key: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(context));
    hasher.update(key);
    hasher.update(salt);
    let mut out = Zeroizing::new([0; 32]);
    Zeroizing::new(hasher.finalize_xof()).fill(out.as_mut());
    out
}
#[allow(clippy::large_enum_variant)]
pub(super) enum Aead {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}
impl Aead {
    pub(super) fn session(method: &Method, salt: &[u8]) -> Self {
        let key = derive("shadowsocks 2022 session subkey", method.psk(), salt);
        match method.cipher {
            Cipher::Aes128Gcm => Self::Aes128(Aes128Gcm::new_from_slice(&key[..16]).unwrap()),
            Cipher::Aes256Gcm => Self::Aes256(Aes256Gcm::new_from_slice(&*key).unwrap()),
            Cipher::ChaCha20Poly1305 => {
                Self::ChaCha(ChaCha20Poly1305::new_from_slice(&*key).unwrap())
            }
        }
    }
    pub(super) fn seal(&self, nonce: &[u8; 12], bytes: &mut Vec<u8>) -> io::Result<()> {
        let result = match self {
            Self::Aes128(c) => c.encrypt_in_place(nonce.into(), &[], bytes),
            Self::Aes256(c) => c.encrypt_in_place(nonce.into(), &[], bytes),
            Self::ChaCha(c) => c.encrypt_in_place(nonce.into(), &[], bytes),
        };
        result.map_err(|_| invalid("Shadowsocks 2022 encryption failed"))
    }
    pub(super) fn open(&self, nonce: &[u8; 12], bytes: &mut Vec<u8>) -> io::Result<()> {
        let result = match self {
            Self::Aes128(c) => c.decrypt_in_place(nonce.into(), &[], bytes),
            Self::Aes256(c) => c.decrypt_in_place(nonce.into(), &[], bytes),
            Self::ChaCha(c) => c.decrypt_in_place(nonce.into(), &[], bytes),
        };
        result.map_err(|_| invalid("Shadowsocks 2022 authentication failed"))
    }
}
pub(super) fn block(key: &[u8], block: &mut [u8; 16], decrypt: bool) {
    match key.len() {
        16 => {
            let c = aes::Aes128::new_from_slice(key).unwrap();
            if decrypt {
                c.decrypt_block(block.into())
            } else {
                c.encrypt_block(block.into())
            }
        }
        32 => {
            let c = aes::Aes256::new_from_slice(key).unwrap();
            if decrypt {
                c.decrypt_block(block.into())
            } else {
                c.encrypt_block(block.into())
            }
        }
        _ => unreachable!("validated AES key"),
    }
}
pub(super) fn identity_hash(key: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    hasher.update(key);
    let mut out = Zeroizing::new([0; 16]);
    Zeroizing::new(hasher.finalize_xof()).fill(out.as_mut());
    out
}
pub(super) struct Records {
    aead: Aead,
    nonce: [u8; 12],
    exhausted: bool,
}
impl Records {
    pub(super) fn new(method: &Method, salt: &[u8]) -> Self {
        Self {
            aead: Aead::session(method, salt),
            nonce: [0; 12],
            exhausted: false,
        }
    }
    fn next(&mut self) -> io::Result<[u8; 12]> {
        if self.exhausted {
            return Err(invalid("Shadowsocks 2022 nonce exhausted"));
        }
        let nonce = self.nonce;
        self.exhausted = true;
        for n in &mut self.nonce {
            *n = n.wrapping_add(1);
            if *n != 0 {
                self.exhausted = false;
                break;
            }
        }
        Ok(nonce)
    }
    pub(super) fn seal(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.next()?;
        self.aead.seal(&nonce, bytes)
    }
    pub(super) fn open(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.next()?;
        self.aead.open(&nonce, bytes)
    }
}
