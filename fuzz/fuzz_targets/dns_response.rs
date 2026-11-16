#![no_main]

//! A DNS server's answers, which an on-path forger can race: the resolver's
//! A/AAAA response checks and the system resolver's SRV/TXT reading.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xray_transport::fuzzing::dns_response(data));
