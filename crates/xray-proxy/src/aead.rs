//! Shared record AEAD using the workspace's existing accelerated provider.
//! Protocol owners retain nonce allocation, exhaustion and replay checks.
use aws_lc_rs::aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::io;
use zeroize::{Zeroize, Zeroizing};

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
        let len = self.open_slice(nonce, aad, bytes)?;
        bytes.truncate(len);
        Ok(())
    }

    pub(crate) fn open_slice(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        bytes: &mut [u8],
    ) -> io::Result<usize> {
        match self
            .0
            .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), bytes)
        {
            Ok(plain) => Ok(plain.len()),
            Err(_) => {
                // A provider may modify the input before rejecting its tag.
                // Never leave unauthenticated plaintext available to a caller.
                bytes.zeroize();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AEAD authentication failed",
                ))
            }
        }
    }
}

/// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03) on the provider's IETF
/// ChaCha20-Poly1305, which is about twice as fast as the portable
/// RustCrypto AEAD on aarch64: HChaCha20 derives a subkey from the first 16
/// nonce bytes, and the last 8 follow four zero bytes as the IETF nonce.
/// Every caller changes those first 16 bytes per record, so the subkey is
/// derived per record rather than cached.
pub(crate) struct XChaChaKey(Zeroizing<[u8; 32]>);

impl XChaChaKey {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self(Zeroizing::new(
            key.try_into().expect("32-byte XChaCha20 key"),
        ))
    }

    fn ietf(&self, nonce: &[u8; 24]) -> (Key, [u8; 12]) {
        // Borrowed views, so no unzeroized copy of the master key is made.
        let key: &chacha20::Key = (&*self.0).into();
        let input = (&nonce[..16]).try_into().unwrap();
        let mut subkey: Zeroizing<[u8; 32]> =
            Zeroizing::new(chacha20::hchacha::<chacha20::R20>(key, input).into());
        let ietf = Key::new(&CHACHA20_POLY1305, &subkey[..]);
        subkey.zeroize();
        let mut ietf_nonce = [0; 12];
        ietf_nonce[4..].copy_from_slice(&nonce[16..]);
        (ietf, ietf_nonce)
    }

    pub(crate) fn seal(&self, nonce: &[u8; 24], aad: &[u8], bytes: &mut Vec<u8>) -> io::Result<()> {
        self.seal_from(nonce, aad, bytes, 0)
    }

    pub(crate) fn seal_from(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        bytes: &mut Vec<u8>,
        start: usize,
    ) -> io::Result<()> {
        let (key, nonce) = self.ietf(nonce);
        key.seal_from(&nonce, aad, bytes, start)
    }

    pub(crate) fn open(&self, nonce: &[u8; 24], aad: &[u8], bytes: &mut Vec<u8>) -> io::Result<()> {
        let len = self.open_slice(nonce, aad, bytes)?;
        bytes.truncate(len);
        Ok(())
    }

    pub(crate) fn open_slice(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        bytes: &mut [u8],
    ) -> io::Result<usize> {
        let (key, nonce) = self.ietf(nonce);
        key.open_slice(&nonce, aad, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit};
    use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM};
    use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

    fn compare<C: AeadInOut + KeyInit>(algorithm: &'static Algorithm, key: &[u8]) {
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
                    .encrypt_in_place(nonce.as_slice().try_into().unwrap(), aad, &mut expected)
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

    /// draft-irtf-cfrg-xchacha-03 A.3.1, the AEAD_XChaCha20_Poly1305 vector.
    #[test]
    fn xchacha_matches_the_draft_vector() {
        let hex = |s: &str| -> Vec<u8> {
            let s: String = s.split_whitespace().collect();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only \
one tip for the future, sunscreen would be it.";
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let expected = hex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52e
             c0875924c1c7987947deafd8780acf49",
        );
        let key = XChaChaKey::new(&key);
        let mut sealed = plain.to_vec();
        key.seal(&nonce, &aad, &mut sealed).unwrap();
        assert_eq!(sealed, expected);
        key.open(&nonce, &aad, &mut sealed).unwrap();
        assert_eq!(sealed, plain);
    }

    #[test]
    fn xchacha_agrees_with_the_portable_aead_and_rejects_modified_inputs() {
        let raw_key = [9; 32];
        let candidate = XChaChaKey::new(&raw_key);
        let reference = XChaCha20Poly1305::new_from_slice(&raw_key).unwrap();
        for size in [0, 2, 16, 1200, 8192, 16383, 65535] {
            for aad in [b"".as_slice(), b"authenticated header"] {
                let mut nonce = [0; 24];
                nonce[..8].copy_from_slice(&(size as u64).to_le_bytes());
                nonce[16] = aad.len() as u8;
                nonce[23] = 0xa5;
                let plain: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                let mut expected = plain.clone();
                reference
                    .encrypt_in_place((&nonce).into(), aad, &mut expected)
                    .unwrap();
                let mut sealed = plain.clone();
                candidate.seal(&nonce, aad, &mut sealed).unwrap();
                assert_eq!(sealed, expected);
                candidate.open(&nonce, aad, &mut sealed).unwrap();
                assert_eq!(sealed, plain);
                // The subkey nonce half, the IETF half, the tag and the AAD
                // must each be authenticated.
                for fault in 0..4 {
                    let mut bad = expected.clone();
                    let mut wrong_nonce = nonce;
                    let mut wrong_aad = aad.to_vec();
                    match fault {
                        0 => *bad.last_mut().unwrap() ^= 1,
                        1 => wrong_nonce[0] ^= 1,
                        2 => wrong_nonce[23] ^= 1,
                        3 => wrong_aad.push(1),
                        _ => unreachable!(),
                    }
                    assert!(candidate.open(&wrong_nonce, &wrong_aad, &mut bad).is_err());
                    assert!(bad.iter().all(|&b| b == 0));
                }
            }
        }
    }
}
