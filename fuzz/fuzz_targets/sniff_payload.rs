#![no_main]

//! The HTTP, TLS ClientHello and BitTorrent sniffers on a TCP flow's first
//! bytes, read in growing prefixes, and the uTP and QUIC sniffers on a UDP
//! flow's first datagram.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((&flags, payload)) = data.split_first() {
        xray_core_rs::sniff_initial_payload_for_fuzzing(flags, payload);
    }
});
