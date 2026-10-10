//! VMess KDF composition and record counters; AEAD uses the shared provider.
use super::*;
use aes::cipher::{BlockEncrypt, KeyInit};
use aws_lc_rs::aead::{AES_128_GCM, CHACHA20_POLY1305};
use sha2::{Digest, Sha256};

pub(super) fn md5(data: &[u8]) -> Zeroizing<[u8; 16]> {
    use md5::Digest;
    let mut digest = md5::Md5::digest(data);
    let out = Zeroizing::new(digest.as_slice().try_into().unwrap());
    digest.as_mut_slice().zeroize();
    out
}
pub(super) fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut digest = Sha256::digest(data);
    let out = Zeroizing::new(digest.as_slice().try_into().unwrap());
    digest[..].zeroize();
    out
}
// Each path element wraps the preceding hash in HMAC. It is not repeated
// ordinary HMAC-SHA256 with intermediate digests as keys.
fn nested_hmac(path: &[&[u8]], data: &[u8]) -> Zeroizing<[u8; 32]> {
    let Some((key, prefix)) = path.split_last() else {
        return sha256(data);
    };
    let mut block = Zeroizing::new([0; 64]);
    if key.len() > 64 {
        block[..32].copy_from_slice(&*nested_hmac(prefix, key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Zeroizing::new(Vec::with_capacity(64 + data.len()));
    inner.extend(block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(data);
    let hash = nested_hmac(prefix, &inner);
    let mut outer = Zeroizing::new(Vec::with_capacity(96));
    outer.extend(block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&*hash);
    nested_hmac(prefix, &outer)
}
pub(super) fn kdf(key: &[u8], path: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut full = Vec::with_capacity(path.len() + 1);
    full.push(b"VMess AEAD KDF".as_slice());
    full.extend_from_slice(path);
    nested_hmac(&full, key)
}
pub(super) struct Aead(crate::aead::Key);
impl Aead {
    pub(super) fn new(cipher: Cipher, key: &[u8; 16]) -> Self {
        match cipher {
            Cipher::Aes128Gcm => Self(crate::aead::Key::new(&AES_128_GCM, key)),
            Cipher::ChaCha20Poly1305 => {
                let first = md5(key);
                let second = md5(&*first);
                let mut derived = Zeroizing::new([0; 32]);
                derived[..16].copy_from_slice(&*first);
                derived[16..].copy_from_slice(&*second);
                Self(crate::aead::Key::new(&CHACHA20_POLY1305, &*derived))
            }
        }
    }
    pub(super) fn seal(&self, nonce: &[u8; 12], aad: &[u8], bytes: &mut Vec<u8>) -> io::Result<()> {
        self.0.seal(nonce, aad, bytes)
    }
    pub(super) fn open(&self, nonce: &[u8; 12], aad: &[u8], bytes: &mut [u8]) -> io::Result<usize> {
        self.0.open_slice(nonce, aad, bytes)
    }
}
pub(super) fn auth_id(command_key: &[u8], timestamp: u64, random: &[u8; 4]) -> Zeroizing<[u8; 16]> {
    let key = kdf(command_key, &[b"AES Auth ID Encryption"]);
    let mut bytes = Zeroizing::new([0; 16]);
    bytes[..8].copy_from_slice(&timestamp.to_be_bytes());
    bytes[8..12].copy_from_slice(random);
    let crc = crc32fast::hash(&bytes[..12]);
    bytes[12..].copy_from_slice(&crc.to_be_bytes());
    aes::Aes128::new_from_slice(&key[..16])
        .unwrap()
        .encrypt_block((&mut *bytes).into());
    bytes
}
pub(super) fn header_aead(
    key: &[u8],
    iv: &[u8],
    key_path: &[&[u8]],
    iv_path: &[&[u8]],
) -> (Aead, Zeroizing<[u8; 12]>) {
    let key = kdf(key, key_path);
    let nonce = kdf(iv, iv_path);
    (
        Aead::new(Cipher::Aes128Gcm, key[..16].try_into().unwrap()),
        Zeroizing::new(nonce[..12].try_into().unwrap()),
    )
}
pub(super) struct Counter {
    aead: Aead,
    iv: Zeroizing<[u8; 12]>,
    next: Option<u16>,
}
impl Counter {
    pub(super) fn new(cipher: Cipher, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            aead: Aead::new(cipher, key),
            iv: Zeroizing::new(iv[..12].try_into().unwrap()),
            next: Some(0),
        }
    }
    fn nonce(&mut self) -> io::Result<[u8; 12]> {
        let next = self
            .next
            .ok_or_else(|| invalid("VMess nonce counter exhausted"))?;
        self.next = next.checked_add(1);
        self.iv[..2].copy_from_slice(&next.to_be_bytes());
        Ok(*self.iv)
    }
    #[cfg(test)]
    pub(super) fn seal(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        let nonce = self.nonce()?;
        self.aead.seal(&nonce, &[], bytes)
    }
    pub(super) fn seal_from(&mut self, bytes: &mut Vec<u8>, start: usize) -> io::Result<()> {
        let nonce = self.nonce()?;
        self.aead.0.seal_from(&nonce, &[], bytes, start)
    }
    pub(super) fn open(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let nonce = self.nonce()?;
        self.aead.open(&nonce, &[], bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vmess_counter_rejects_wrap_and_modified_authentication_tags() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            let mut writer = Counter::new(cipher, &[1; 16], &[2; 16]);
            writer.next = Some(u16::MAX);
            let mut data = vec![1];
            writer.seal(&mut data).unwrap();
            assert!(writer.seal(&mut vec![1]).is_err());
            let mut writer = Counter::new(cipher, &[1; 16], &[2; 16]);
            let mut data = vec![1];
            writer.seal(&mut data).unwrap();
            let last = data.len() - 1;
            data[last] ^= 1;
            let mut reader = Counter::new(cipher, &[1; 16], &[2; 16]);
            assert!(reader.open(&mut data).is_err());
        }
    }
}
