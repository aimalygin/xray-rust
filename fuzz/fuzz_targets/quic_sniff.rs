#![no_main]

use libfuzzer_sys::fuzz_target;
use xray_core_rs::sniff_quic_initial_sni_for_fuzzing;

fuzz_target!(|data: &[u8]| {
    let _ = sniff_quic_initial_sni_for_fuzzing([data]);
    // The same bytes as two datagrams of one flow, split where the first two
    // bytes say, so reassembly across datagrams is exercised too.
    if let [high, low, rest @ ..] = data {
        let split = usize::from(u16::from_be_bytes([*high, *low])).min(rest.len());
        let (first, second) = rest.split_at(split);
        let _ = sniff_quic_initial_sni_for_fuzzing([first, second]);
    }
});
