#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use xray_proxy::{
    mux,
    shadowsocks2022::{Method, UdpSession},
    trojan, vmess,
};

fuzz_target!(|data: &[u8]| {
    let _ = trojan::decode_udp_packet(data);
    let mut tail = data;
    for _ in 0..128 {
        match mux::decode(tail) {
            Ok(Some((frame, n))) => {
                assert!(n <= mux::MAX_FRAME && n > 0);
                assert!(frame.payload.is_none_or(|p| p.len() <= mux::MAX_PAYLOAD));
                tail = &tail[n..];
            }
            _ => break,
        }
    }
    vmess::fuzz_records(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = trojan::TrojanAuth::new(text);
        let _ = Method::new("2022-blake3-aes-128-gcm", text);
    }
    for (name, key) in [
        ("2022-blake3-aes-128-gcm", "AQEBAQEBAQEBAQEBAQEBAQ=="),
        (
            "2022-blake3-aes-256-gcm",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        ),
        (
            "2022-blake3-chacha20-poly1305",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        ),
    ] {
        let method = Arc::new(Method::new(name, key).unwrap());
        let mut session = UdpSession::new(method).unwrap();
        let _ = session.decode(data);
        let _ = session.decode(data); // malformed/replayed input cannot panic
    }
});
