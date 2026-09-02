#![no_main]

use libfuzzer_sys::fuzz_target;
use xray_core_rs::sniff_quic_initial_sni_for_fuzzing;

fuzz_target!(|data: &[u8]| {
    let _ = sniff_quic_initial_sni_for_fuzzing(data);
});
