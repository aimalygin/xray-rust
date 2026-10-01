use super::*;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake128Reader,
};

/// One AEAD and SHAKE state per direction. No counter wraps are permitted.
pub(super) struct Records {
    body: crypto::Counter,
    length: Option<crypto::Counter>,
    mask: Shake128Reader,
    batch_padding: bool,
}
impl Records {
    pub(super) fn new(
        cipher: Cipher,
        key: &[u8; 16],
        iv: &[u8; 16],
        auth_length: Option<(&[u8; 16], &[u8; 16])>,
    ) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv);
        let length = auth_length.map(|(key, iv)| {
            let key = crypto::kdf(key, &[b"auth_len"]);
            crypto::Counter::new(cipher, key[..16].try_into().unwrap(), iv)
        });
        Self {
            body: crypto::Counter::new(cipher, key, iv),
            length,
            mask: shake.finalize_xof(),
            // Keep AES on its measured per-record path: batching improved
            // one flow but regressed eight-flow uploads in repeated controls.
            batch_padding: cipher == Cipher::ChaCha20Poly1305,
        }
    }
    pub(super) fn size_bytes(&self) -> usize {
        if self.length.is_some() {
            18
        } else {
            2
        }
    }
    pub(super) fn max_payload(&self) -> usize {
        8192 - 16 - self.size_bytes() - 64
    }
    fn next_mask(&mut self) -> u16 {
        let mut bytes = [0; 2];
        self.mask.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
    #[cfg(test)]
    pub(super) fn seal(&mut self, payload: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut output = Zeroizing::new(Vec::new());
        self.seal_into(payload, &mut output)?;
        Ok(output)
    }
    pub(super) fn seal_into(&mut self, payload: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        if payload.len() > self.max_payload() || !output.is_empty() {
            return Err(invalid(
                "VMess payload exceeds record limit or pending frame",
            ));
        }
        let padding = (self.next_mask() % 64) as usize;
        let size = payload.len() + 16 + padding;
        // Grow lazily and at most to the existing 8 KiB record limit. Rounding
        // avoids reallocating when the next record's random padding is longer.
        output.reserve_exact((self.size_bytes() + size).next_power_of_two().min(8192));
        if let Some(cipher) = &mut self.length {
            output.extend_from_slice(&((size - 16) as u16).to_be_bytes());
            cipher.seal(output)?;
        } else {
            output.extend_from_slice(&((size as u16) ^ self.next_mask()).to_be_bytes());
        }
        let start = output.len();
        output.extend_from_slice(payload);
        self.body.seal_from(output, start)?;
        let start = output.len();
        output.resize(start + padding, 0);
        if self.batch_padding {
            padding::fill(&mut output[start..])?;
        } else {
            random(&mut output[start..])?;
        }
        Ok(())
    }
    pub(super) fn decode_length(&mut self, bytes: &mut [u8]) -> io::Result<(usize, usize)> {
        let padding = (self.next_mask() % 64) as usize;
        let size = if let Some(cipher) = &mut self.length {
            cipher.open(bytes)?;
            u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize + 16
        } else {
            u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize ^ self.next_mask() as usize
        };
        if size < 16 + padding || size > 65535 {
            return Err(invalid("invalid VMess record length"));
        }
        Ok((size, padding))
    }
    #[cfg(any(test, feature = "fuzzing"))]
    pub(super) fn open(&mut self, bytes: &mut Vec<u8>, padding: usize) -> io::Result<()> {
        let len = self.open_slice(bytes, padding)?;
        bytes.truncate(len);
        Ok(())
    }
    pub(super) fn open_slice(&mut self, bytes: &mut [u8], padding: usize) -> io::Result<usize> {
        if padding > bytes.len() {
            return Err(invalid("invalid VMess record padding"));
        }
        let end = bytes.len() - padding;
        self.body.open(&mut bytes[..end])
    }
}

// Only public, unauthenticated record padding uses this cache. Never use it for
// session keys, IVs, nonces or authentication material. Those retain fresh OS
// randomness. Sharing 256 bytes per thread avoids a buffer per connection and
// amortizes small OS random requests without introducing a different RNG.
mod padding {
    use super::*;
    use std::cell::RefCell;

    struct Entropy {
        bytes: Zeroizing<[u8; 256]>,
        used: usize,
    }

    impl Entropy {
        fn new() -> Self {
            Self {
                bytes: Zeroizing::new([0; 256]),
                used: 256,
            }
        }

        fn fill_with(
            &mut self,
            output: &mut [u8],
            refill: impl FnOnce(&mut [u8]) -> io::Result<()>,
        ) -> io::Result<()> {
            if output.len() > 63 {
                return Err(invalid("VMess padding exceeds record limit"));
            }
            if output.len() > self.bytes.len() - self.used {
                // A failed/partial refill must not expose any of its bytes or
                // permit reuse of bytes returned before the failure.
                self.used = self.bytes.len();
                if let Err(error) = refill(self.bytes.as_mut()) {
                    self.bytes.zeroize();
                    return Err(error);
                }
                self.used = 0;
            }
            output.copy_from_slice(&self.bytes[self.used..self.used + output.len()]);
            self.used += output.len();
            Ok(())
        }
    }

    pub(super) fn fill(output: &mut [u8]) -> io::Result<()> {
        thread_local! {
            static ENTROPY: RefCell<Entropy> = RefCell::new(Entropy::new());
        }
        ENTROPY.with(|entropy| entropy.borrow_mut().fill_with(output, random))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn padding_consumes_each_byte_once_and_refills_at_the_boundary() {
            let mut entropy = Entropy::new();
            let mut refills = 0;
            for expected in 0..12 {
                let mut output = [0; 32];
                entropy
                    .fill_with(&mut output, |bytes| {
                        for (index, byte) in bytes.iter_mut().enumerate() {
                            *byte = (refills * 8 + index / 32) as u8;
                        }
                        refills += 1;
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(output, [expected; 32]);
            }
            assert_eq!(refills, 2);
        }

        #[test]
        fn padding_refill_error_leaves_output_untouched_and_forces_a_fresh_refill() {
            let mut entropy = Entropy::new();
            let mut output = [9; 63];
            for _ in 0..4 {
                entropy
                    .fill_with(&mut output, |bytes| {
                        bytes.fill(1);
                        Ok(())
                    })
                    .unwrap();
            }
            output.fill(9);
            assert!(entropy
                .fill_with(&mut output, |bytes| {
                    bytes[..7].fill(2);
                    Err(invalid("injected entropy failure"))
                })
                .is_err());
            assert_eq!(output, [9; 63]);
            assert!(entropy.bytes.iter().all(|byte| *byte == 0));
            entropy
                .fill_with(&mut output, |bytes| {
                    bytes.fill(3);
                    Ok(())
                })
                .unwrap();
            assert_eq!(output, [3; 63]);
        }

        #[test]
        fn empty_padding_does_not_request_entropy_and_oversize_is_rejected() {
            let mut entropy = Entropy::new();
            entropy
                .fill_with(&mut [], |_| panic!("empty padding refill"))
                .unwrap();
            assert!(entropy
                .fill_with(&mut [0; 64], |_| panic!("oversize refill"))
                .is_err());
        }
    }
}
