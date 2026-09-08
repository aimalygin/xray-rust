#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| xray_vless_encryption::fuzzing::records(data));
