#![no_main]

use libfuzzer_sys::fuzz_target;
use xray_config::parse_xray_json;

fuzz_target!(|data: &[u8]| {
    if let Ok(json) = std::str::from_utf8(data) {
        let _ = parse_xray_json(json);
    }
});
