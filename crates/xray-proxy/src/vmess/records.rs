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
    pub(super) fn seal(&mut self, payload: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        if payload.len() > self.max_payload() {
            return Err(invalid("VMess payload exceeds record limit"));
        }
        let padding = (self.next_mask() % 64) as usize;
        let size = payload.len() + 16 + padding;
        let mut length = Zeroizing::new(if let Some(cipher) = &mut self.length {
            let mut data = ((size - 16) as u16).to_be_bytes().to_vec();
            cipher.seal(&mut data)?;
            data
        } else {
            ((size as u16) ^ self.next_mask()).to_be_bytes().to_vec()
        });
        let mut body = Zeroizing::new(payload.to_vec());
        self.body.seal(&mut body)?;
        length.extend_from_slice(&body);
        let start = length.len();
        length.resize(start + padding, 0);
        random(&mut length[start..])?;
        Ok(length)
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
