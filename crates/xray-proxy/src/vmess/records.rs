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
        random(&mut output[start..])?;
        Ok(())
    }
    pub(super) fn decode_length(&mut self, bytes: &mut Vec<u8>) -> io::Result<(usize, usize)> {
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
    pub(super) fn open(&mut self, bytes: &mut Vec<u8>, padding: usize) -> io::Result<()> {
        if padding > bytes.len() {
            return Err(invalid("invalid VMess record padding"));
        }
        bytes.truncate(bytes.len() - padding);
        self.body.open(bytes)
    }
}
