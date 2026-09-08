use std::io;

use aes::Aes256;
use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ctr::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

use crate::{crypto_error, invalid_data};

pub(crate) const TAG_LEN: usize = 16;
pub(crate) const MAX_NONCE: [u8; 12] = [0xff; 12];

/// The pinned peer detects the client's AEAD from the authenticated length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Default for CipherSuite {
    fn default() -> Self {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            return Self::Aes256Gcm;
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("pclmulqdq") {
            return Self::Aes256Gcm;
        }
        Self::ChaCha20Poly1305
    }
}

pub(crate) fn derive(context: &[u8], material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key_bytes(context));
    hasher.update(material);
    let mut output = Zeroizing::new([0; 32]);
    // Zeroize the XOF state as well as the material-bearing hasher.
    let mut reader = Zeroizing::new(hasher.finalize_xof());
    reader.fill(output.as_mut());
    output
}

pub(crate) struct Aead {
    key: LessSafeKey,
    pub(crate) nonce: [u8; 12],
    pub(crate) suite: CipherSuite,
}

impl Aead {
    pub(crate) fn new(context: &[u8], material: &[u8], suite: CipherSuite) -> io::Result<Self> {
        let key = derive(context, material);
        let algorithm = match suite {
            CipherSuite::Aes256Gcm => &aead::AES_256_GCM,
            CipherSuite::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        };
        Ok(Self {
            key: LessSafeKey::new(
                UnboundKey::new(algorithm, key.as_ref()).map_err(|_| crypto_error())?,
            ),
            nonce: [0; 12],
            suite,
        })
    }

    fn advance(&mut self) -> Nonce {
        for byte in self.nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        Nonce::assume_unique_for_key(self.nonce)
    }

    pub(crate) fn seal(&mut self, data: &mut Vec<u8>, aad: &[u8]) -> io::Result<()> {
        let nonce = self.advance();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), data)
            .map_err(|_| crypto_error())
    }

    pub(crate) fn open(&mut self, data: &mut [u8], aad: &[u8]) -> io::Result<usize> {
        let nonce = self.advance();
        self.key
            .open_in_place(nonce, Aad::from(aad), data)
            .map(|plain| plain.len())
            .map_err(|_| invalid_data())
    }

    // Reserved nonce for the server's NFS-authenticated 1-RTT reply. This does
    // not advance the client's NFS message counter.
    pub(crate) fn open_server_hello(&self, data: &mut [u8]) -> io::Result<usize> {
        self.key
            .open_in_place(Nonce::assume_unique_for_key(MAX_NONCE), Aad::empty(), data)
            .map(|plain| plain.len())
            .map_err(|_| invalid_data())
    }
}

pub(crate) struct HeaderMask(ctr::Ctr128BE<Aes256>);

impl HeaderMask {
    pub(crate) fn new(material: &[u8], iv: &[u8; 16]) -> Self {
        let key = derive(b"VLESS", material);
        Self(ctr::Ctr128BE::<Aes256>::new((&*key).into(), iv.into()))
    }

    pub(crate) fn apply(&mut self, data: &mut [u8]) -> io::Result<()> {
        self.0.try_apply_keystream(data).map_err(|_| crypto_error())
    }
}
