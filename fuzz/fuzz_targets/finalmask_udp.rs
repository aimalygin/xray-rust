#![no_main]

//! What the finalmask UDP masks read: Salamander with Gecko reassembly,
//! `header-custom` and sudoku over a scripted socket, and the xdns, xicmp
//! and realm decoders.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xray_transport::fuzzing::finalmask_udp(data));
