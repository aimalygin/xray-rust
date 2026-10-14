//! Reused 8 KiB delivered-plaintext buffer; no allocation in the timed loop.
#[path = "../src/erase.rs"]
mod erase;
use std::{hint::black_box, time::Instant};
use zeroize::Zeroize;

fn main() {
    let iterations = if cfg!(debug_assertions) { 1 } else { 32768 };
    for name in ["byte-zeroize", "word-zeroize"] {
        let mut data = vec![0x5a; 8192];
        let start = Instant::now();
        for _ in 0..iterations {
            data.fill(0x5a);
            if name == "byte-zeroize" {
                black_box(&mut data[..]).zeroize();
            } else {
                erase::erase(black_box(&mut data));
            }
            black_box(&data);
        }
        let seconds = start.elapsed().as_secs_f64();
        assert!(data.iter().all(|b| *b == 0));
        println!(
            "{}",
            serde_json::json!({"erasure":name, "iterations":iterations, "record_bytes":8192, "seconds":seconds, "mib_per_second":iterations as f64 * 8192.0 / 1048576.0 / seconds, "smoke":cfg!(debug_assertions)})
        );
    }
}
