//! Isolate AEAD cost from sockets, scheduling, framing and allocation.
//! Run the built executable as: aead_backends [rustcrypto|aws-lc] [iterations].
//! Each iteration seals and opens one 8 KiB record with a unique nonce. Contexts
//! and the buffer are reused; both providers must recover the original bytes.
use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};
use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use chacha20poly1305::ChaCha20Poly1305;
use std::{hint::black_box, time::Instant};

fn rustcrypto<C: AeadInPlace + KeyInit>(iterations: u64, key: &[u8]) -> f64 {
    let cipher = C::new_from_slice(key).unwrap();
    let mut data = vec![0x5a; 8192];
    data.reserve(16);
    let started = Instant::now();
    for i in 0..iterations {
        let mut nonce = [0; 12];
        nonce[..8].copy_from_slice(&i.to_le_bytes());
        let nonce = aes_gcm::aead::Nonce::<C>::from_slice(&nonce);
        cipher.encrypt_in_place(nonce, b"", &mut data).unwrap();
        cipher.decrypt_in_place(nonce, b"", &mut data).unwrap();
        black_box(&mut data);
    }
    let seconds = started.elapsed().as_secs_f64();
    assert_eq!(data, vec![0x5a; 8192]);
    seconds
}

fn aws_lc(iterations: u64, algorithm: &'static aead::Algorithm, key: &[u8]) -> f64 {
    let cipher = LessSafeKey::new(UnboundKey::new(algorithm, key).unwrap());
    let mut data = vec![0x5a; 8192];
    data.reserve(16);
    let started = Instant::now();
    for i in 0..iterations {
        let mut nonce = [0; 12];
        nonce[..8].copy_from_slice(&i.to_le_bytes());
        cipher
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
            .unwrap();
        let len = cipher
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
            .unwrap()
            .len();
        data.truncate(len);
        black_box(&mut data);
    }
    let seconds = started.elapsed().as_secs_f64();
    assert_eq!(data, vec![0x5a; 8192]);
    seconds
}

fn main() {
    let args: Vec<_> = std::env::args().filter(|arg| arg != "--bench").collect();
    let backend = args.get(1).map(String::as_str).unwrap_or("all");
    let iterations: u64 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(32768);
    assert!(["all", "rustcrypto", "aws-lc"].contains(&backend));
    assert!((1..=10_000_000).contains(&iterations));
    for provider in ["rustcrypto", "aws-lc"] {
        if backend != "all" && backend != provider {
            continue;
        }
        for algorithm in ["aes128", "aes256", "chacha20"] {
            let seconds = match (provider, algorithm) {
                ("rustcrypto", "aes128") => rustcrypto::<Aes128Gcm>(iterations, &[7; 16]),
                ("rustcrypto", "aes256") => rustcrypto::<Aes256Gcm>(iterations, &[7; 32]),
                ("rustcrypto", "chacha20") => rustcrypto::<ChaCha20Poly1305>(iterations, &[7; 32]),
                ("aws-lc", "aes128") => aws_lc(iterations, &aead::AES_128_GCM, &[7; 16]),
                ("aws-lc", "aes256") => aws_lc(iterations, &aead::AES_256_GCM, &[7; 32]),
                ("aws-lc", "chacha20") => aws_lc(iterations, &aead::CHACHA20_POLY1305, &[7; 32]),
                _ => unreachable!(),
            };
            println!(
                "{}",
                serde_json::json!({"backend":provider,"algorithm":algorithm,"iterations":iterations,"record_bytes":8192,"seconds":seconds,"mib_per_second":iterations as f64 * 8192.0 * 2.0 / 1048576.0 / seconds})
            );
        }
    }
}
