#![no_main]

//! A MASQUE proxy's CONNECT-IP capsule stream and the packets it carries.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xray_transport::fuzzing::masque_capsules(data));
