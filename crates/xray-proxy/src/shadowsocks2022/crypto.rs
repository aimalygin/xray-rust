use super::*;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

pub(super) fn derive(context: &str, key: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(context));
    hasher.update(key);
    hasher.update(salt);
    let mut out = Zeroizing::new([0; 32]);
    Zeroizing::new(hasher.finalize_xof()).fill(out.as_mut());
    out
}
pub(super) struct Aead(crate::aead::Key);
impl Aead {
    pub(super) fn session(method: &Method, salt: &[u8]) -> Self {
        let key = derive("shadowsocks 2022 session subkey", method.psk(), salt);
        let algorithm = match method.cipher {
            Cipher::Aes128Gcm => &AES_128_GCM,
            Cipher::Aes256Gcm => &AES_256_GCM,
            Cipher::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        };
        Self(crate::aead::Key::new(
            algorithm,
            &key[..method.cipher.key_len()],
        ))
    }
    pub(super) fn seal(&self, nonce: &[u8; 12], bytes: &mut Vec<u8>) -> io::Result<()> {
        self.0.seal(nonce, &[], bytes)
    }
    pub(super) fn seal_from(
        &self,
        nonce: &[u8; 12],
        bytes: &mut Vec<u8>,
        start: usize,
    ) -> io::Result<()> {
        self.0.seal_from(nonce, &[], bytes, start)
    }
    pub(super) fn open(&self, nonce: &[u8; 12], bytes: &mut Vec<u8>) -> io::Result<()> {
        self.0.open(nonce, &[], bytes)
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
    pub(super) fn seal_from(&mut self, bytes: &mut Vec<u8>, start: usize) -> io::Result<()> {
        let nonce = self.next()?;
        self.aead.seal_from(&nonce, bytes, start)
    }
    pub(super) fn open(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let nonce = self.next()?;
        self.aead.0.open_slice(&nonce, &[], bytes)
    }
}
