#![no_main]

//! The server's mKCP datagrams through each `mkcp-legacy`, Salamander,
//! `header-custom` and sudoku mask stack into a connection's engine.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xray_transport::fuzzing::kcp(data));
