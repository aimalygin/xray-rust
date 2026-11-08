//! The RSA key Xray-core's xmc mask derives from the password, and the
//! PKCS #1 v1.5 encryption its client sends the shared secret with.
use num_bigint::BigUint;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    sync::{Mutex, OnceLock},
};

/// The public half of the derived key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicKey {
    n: BigUint,
    e: BigUint,
    /// The key as `x509.MarshalPKIXPublicKey` writes it, which the server
    /// sends and the client compares.
    pub(crate) pkix: Vec<u8>,
}

/// `DeriveRSAKey`'s public key, derived once per password.
pub(crate) fn derived_public_key(password: &str) -> PublicKey {
    static CACHE: OnceLock<Mutex<HashMap<String, PublicKey>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(key) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(password)
    {
        return key.clone();
    }
    let (p, q) = primes(password);
    let n = &p * &q;
    let e = BigUint::from(65_537u32);
    let key = PublicKey {
        pkix: pkix(&n, &e),
        n,
        e,
    };
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(password.to_owned(), key.clone());
    key
}

/// `DeriveRSAKey`'s two primes, the second moved past the first if they meet.
fn primes(password: &str) -> (BigUint, BigUint) {
    let p = derive_prime(&mut Sha256Stream::new(password, "-p-prime"));
    let mut q = derive_prime(&mut Sha256Stream::new(password, "-q-prime"));
    while p == q {
        q = next_prime(q + 2u32);
    }
    (p, q)
}

/// The server's half, for tests that play Xray's server.
#[cfg(test)]
pub(crate) struct PrivateKey {
    n: BigUint,
    d: BigUint,
}

#[cfg(test)]
pub(crate) fn derived_private_key(password: &str) -> PrivateKey {
    let (p, q) = primes(password);
    let phi = (&p - 1u32) * (&q - 1u32);
    PrivateKey {
        d: BigUint::from(65_537u32)
            .modinv(&phi)
            .expect("65537 is coprime to phi"),
        n: p * q,
    }
}

#[cfg(test)]
impl PrivateKey {
    /// `rsa.DecryptPKCS1v15`: the message, or `None` for a block that is
    /// not 0x00 0x02, eight or more nonzero bytes and 0x00.
    pub(crate) fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        let size = (self.n.bits() as usize).div_ceil(8);
        if cipher.len() != size {
            return None;
        }
        let plain = BigUint::from_bytes_be(cipher)
            .modpow(&self.d, &self.n)
            .to_bytes_be();
        let mut block = vec![0u8; size - plain.len()];
        block.extend_from_slice(&plain);
        if block[0] != 0 || block[1] != 2 {
            return None;
        }
        let separator = 2 + block[2..].iter().position(|byte| *byte == 0)?;
        (separator >= 10).then(|| block[separator + 1..].to_vec())
    }
}

/// `sha256Stream`: SHA-256 of the seed and `-<counter>`, block after block.
struct Sha256Stream {
    seed: Vec<u8>,
    counter: u64,
    buffer: Vec<u8>,
}

impl Sha256Stream {
    fn new(password: &str, label: &str) -> Self {
        Self {
            seed: [password.as_bytes(), label.as_bytes()].concat(),
            counter: 0,
            buffer: Vec::new(),
        }
    }

    fn read(&mut self, out: &mut [u8]) {
        while self.buffer.len() < out.len() {
            let mut hash = Sha256::new();
            hash.update(&self.seed);
            hash.update(format!("-{}", self.counter).as_bytes());
            self.counter += 1;
            self.buffer.extend_from_slice(&hash.finalize());
        }
        out.copy_from_slice(&self.buffer[..out.len()]);
        self.buffer.drain(..out.len());
    }
}

/// `derivePrime`: 512 bits with the top two and the lowest set, then the
/// first prime from there whose `p - 1` is coprime to 65537.
fn derive_prime(stream: &mut Sha256Stream) -> BigUint {
    let mut bytes = [0u8; 64];
    stream.read(&mut bytes);
    bytes[0] |= 0xc0;
    bytes[63] |= 0x01;
    next_prime(BigUint::from_bytes_be(&bytes))
}

/// The first odd candidate from `p` up that is prime with `p - 1` coprime to
/// 65537. Go's `ProbablyPrime(20)` and this test agree on every candidate:
/// neither rejects a prime, and a composite passing either is beyond
/// reach for these sizes.
fn next_prime(mut p: BigUint) -> BigUint {
    let e = BigUint::from(65_537u32);
    loop {
        if is_probable_prime(&p) && (&p - 1u32) % &e != BigUint::from(0u32) {
            return p;
        }
        p += 2u32;
    }
}

const SMALL_PRIMES: [u32; 30] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113,
];

/// Trial division, then Miller-Rabin with the first 30 primes as bases.
fn is_probable_prime(n: &BigUint) -> bool {
    let zero = BigUint::from(0u32);
    for prime in SMALL_PRIMES {
        if *n == BigUint::from(prime) {
            return true;
        }
        if n % prime == zero {
            return false;
        }
    }
    let one = BigUint::from(1u32);
    let n_minus_one = n - 1u32;
    let shift = n_minus_one.trailing_zeros().unwrap_or(0);
    let d = &n_minus_one >> shift;
    'bases: for base in SMALL_PRIMES {
        let mut x = BigUint::from(base).modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 1..shift {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_one {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

/// `SubjectPublicKeyInfo` for an RSA key, as Go's x509 package writes it.
fn pkix(n: &BigUint, e: &BigUint) -> Vec<u8> {
    let rsa_key = der(0x30, &[der_integer(n), der_integer(e)].concat());
    let algorithm = der(
        0x30,
        &[
            der(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            ),
            vec![0x05, 0x00],
        ]
        .concat(),
    );
    let key = der(0x03, &[&[0u8][..], &rsa_key].concat());
    der(0x30, &[algorithm, key].concat())
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        len @ 0..=127 => out.push(len as u8),
        len @ 128..=255 => out.extend([0x81, len as u8]),
        len => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(body);
    out
}

fn der_integer(value: &BigUint) -> Vec<u8> {
    let mut bytes = value.to_bytes_be();
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der(0x02, &bytes)
}

impl PublicKey {
    /// `rsa.EncryptPKCS1v15`: 0x00 0x02, nonzero random padding, 0x00, the
    /// message, raised to `e` modulo `n`.
    pub(crate) fn encrypt(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        let size = (self.n.bits() as usize).div_ceil(8);
        if message.len() + 11 > size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message too long for RSA key size",
            ));
        }
        let mut block = vec![0u8; size];
        block[1] = 0x02;
        let padding = size - message.len() - 3;
        let mut rng = rand::thread_rng();
        for byte in &mut block[2..2 + padding] {
            *byte = rng.gen_range(1..=255);
        }
        block[size - message.len()..].copy_from_slice(message);
        let cipher = BigUint::from_bytes_be(&block).modpow(&self.e, &self.n);
        let mut out = cipher.to_bytes_be();
        while out.len() < size {
            out.insert(0, 0);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
