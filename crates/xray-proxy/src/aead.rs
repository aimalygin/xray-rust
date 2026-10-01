//! Shared record AEAD using the workspace's existing accelerated provider.
//! Protocol owners retain nonce allocation, exhaustion and replay checks.
use aws_lc_rs::aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey};
use std::io;
use zeroize::Zeroize;

pub(crate) struct Key(LessSafeKey);

impl Key {
    /// All callers supply fixed-size, protocol-derived keys. AWS-LC owns and
    /// cleans up its key schedule; callers zeroize the temporary key material.
    pub(crate) fn new(algorithm: &'static Algorithm, key: &[u8]) -> Self {
        Self(LessSafeKey::new(
            UnboundKey::new(algorithm, key).expect("fixed-size AEAD key"),
        ))
    }

    pub(crate) fn seal(&self, nonce: &[u8; 12], aad: &[u8], bytes: &mut Vec<u8>) -> io::Result<()> {
        self.seal_from(nonce, aad, bytes, 0)
    }

    /// Encrypt a record after an already encoded prefix without a second buffer.
    pub(crate) fn seal_from(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        bytes: &mut Vec<u8>,
        start: usize,
    ) -> io::Result<()> {
        // Protocol writers reserve the full frame before copying plaintext.
        // Other callers may grow here only after encryption has succeeded.
        match self.0.seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut bytes[start..],
        ) {
            Ok(tag) => {
                bytes.extend_from_slice(tag.as_ref());
                Ok(())
            }
            Err(_) => {
                bytes[start..].zeroize();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AEAD encryption failed",
                ))
            }
        }
    }

    pub(crate) fn open(&self, nonce: &[u8; 12], aad: &[u8], bytes: &mut Vec<u8>) -> io::Result<()> {
        match self
            .0
            .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), bytes)
        {
            Ok(plain) => {
                let len = plain.len();
                bytes.truncate(len);
                Ok(())
            }
            Err(_) => {
                // A provider may modify the input before rejecting its tag.
                // Never leave unauthenticated plaintext available to a caller.
                bytes.as_mut_slice().zeroize();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AEAD authentication failed",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};
    use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
    use chacha20poly1305::ChaCha20Poly1305;

    fn compare<C: AeadInPlace + KeyInit>(algorithm: &'static Algorithm, key: &[u8]) {
        let candidate = Key::new(algorithm, key);
        let reference = C::new_from_slice(key).unwrap();
        for size in [0, 2, 16, 1200, 8192, 65535] {
            for aad in [b"".as_slice(), b"authenticated header"] {
                let mut nonce = [0; 12];
                nonce[..8].copy_from_slice(&(size as u64).to_le_bytes());
                nonce[8] = aad.len() as u8;
                let plain: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                let mut expected = plain.clone();
                reference
                    .encrypt_in_place(
                        aes_gcm::aead::Nonce::<C>::from_slice(&nonce),
                        aad,
                        &mut expected,
                    )
                    .unwrap();
                let mut sealed = plain.clone();
                candidate.seal(&nonce, aad, &mut sealed).unwrap();
                assert_eq!(sealed, expected);
                candidate.open(&nonce, aad, &mut sealed).unwrap();
                assert_eq!(sealed, plain);
                for fault in 0..4 {
                    let mut bad = expected.clone();
                    let mut wrong_nonce = nonce;
                    let mut wrong_aad = aad.to_vec();
                    match fault {
                        0 => *bad.last_mut().unwrap() ^= 1,
                        1 => {
                            bad.truncate(15);
                        }
                        2 => wrong_nonce[0] ^= 1,
                        3 => wrong_aad.push(1),
                        _ => unreachable!(),
                    }
                    assert!(candidate.open(&wrong_nonce, &wrong_aad, &mut bad).is_err());
                    assert!(bad.iter().all(|&b| b == 0));
                }
            }
        }
    }

    #[test]
    fn providers_agree_on_wire_bytes_and_reject_modified_inputs() {
        compare::<Aes128Gcm>(&AES_128_GCM, &[7; 16]);
        compare::<Aes256Gcm>(&AES_256_GCM, &[7; 32]);
        compare::<ChaCha20Poly1305>(&CHACHA20_POLY1305, &[7; 32]);
    }
}
