//! AES-128-CFB8, the cipher Minecraft turns on after its key exchange, with
//! the shared secret as key and IV.
use aes::{
    cipher::{BlockCipherEncrypt, KeyInit},
    Aes128,
};

pub(crate) struct Cfb8 {
    cipher: Aes128,
    register: [u8; 16],
    decrypt: bool,
}

impl Cfb8 {
    pub(crate) fn new(secret: &[u8; 16], decrypt: bool) -> Self {
        Self {
            cipher: Aes128::new_from_slice(secret).expect("16-byte key"),
            register: *secret,
            decrypt,
        }
    }

    /// Encrypts or decrypts `data` in place, one byte per block.
    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            let mut block = self.register.into();
            self.cipher.encrypt_block(&mut block);
            let input = *byte;
            *byte ^= block[0];
            let cipher_byte = if self.decrypt { input } else { *byte };
            self.register.copy_within(1.., 0);
            self.register[15] = cipher_byte;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// NIST SP 800-38A, F.3.7 and F.3.8: CFB8-AES128.
    #[test]
    fn matches_the_nist_vectors() {
        let key: [u8; 16] = unhex("2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plain = unhex("6bc1bee22e409f96e93d7e117393172aae2d");
        let cipher = unhex("3b79424c9c0dd436bace9e0ed4586a4f32b9");
        for (decrypt, input, output) in [(false, &plain, &cipher), (true, &cipher, &plain)] {
            let mut stream = Cfb8::new(&key, decrypt);
            stream.register = iv;
            let mut data = input.clone();
            stream.apply(&mut data);
            assert_eq!(&data, output, "decrypt {decrypt}");
        }
    }

    #[test]
    fn decryption_undoes_encryption_across_calls() {
        let secret = *b"0123456789abcdef";
        let plain: Vec<u8> = (0..=255).collect();
        let mut data = plain.clone();
        let mut encrypt = Cfb8::new(&secret, false);
        encrypt.apply(&mut data[..100]);
        encrypt.apply(&mut data[100..]);
        assert_ne!(data, plain);
        let mut decrypt = Cfb8::new(&secret, true);
        for chunk in data.chunks_mut(7) {
            decrypt.apply(chunk);
        }
        assert_eq!(data, plain);
    }
}
