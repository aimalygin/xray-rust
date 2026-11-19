#![no_main]

//! What the finalmask TCP masks read from the server: the `header-custom`
//! handshake, the sudoku stream and the xmc login and stream.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xray_transport::fuzzing::finalmask_tcp(data));
