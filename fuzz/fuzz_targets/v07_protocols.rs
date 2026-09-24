#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};
use xray_proxy::hysteria::*;
use xray_proxy::wireguard::*;

fuzz_target!(|data: &[u8]| {
    let _ = decode_tcp_request(data);
    let _ = decode_tcp_response(data);
    let _ = decode_udp_message(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = KeyMaterial::parse(text);
        let _ = text.parse::<AllowedIp>();
    }

    let now = Instant::now();
    let mut assembler = Reassembler::new(7, 4096, Duration::from_secs(5)).unwrap();
    // Length-prefixed datagrams exercise state transitions, not only one parse.
    let mut tail = data;
    let mut tick = 0;
    while tail.len() >= 2 {
        let size = usize::from(u16::from_be_bytes([tail[0], tail[1]]));
        tail = &tail[2..];
        let Some(wire) = tail.get(..size) else { break };
        tail = &tail[size..];
        if let Ok(message) = decode_udp_message(wire) {
            let _ = assembler.feed(&message, now + Duration::from_millis(tick));
            assert!(assembler.buffered_payload_bytes() <= 4096);
        }
        tick += 100;
    }
    assembler.expire(now + Duration::from_secs(100000));
    assert_eq!(assembler.buffered_payload_bytes(), 0);

    // Enter successful fragmentation/reassembly paths on bounded arbitrary input.
    let payload = &data[..data.len().min(4096)];
    if !payload.is_empty() {
        let full = UdpMessage {
            session_id: 7,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 1,
            address: "example.com:53",
            payload,
        };
        let mtu = full.header_length() + 1 + usize::from(data[0]);
        if let Ok(fragments) = fragment_udp_message(&full, mtu) {
            for fragment in fragments.iter().rev() {
                let wire = encode_udp_message(fragment).unwrap();
                assert!(wire.len() <= mtu);
                let decoded = decode_udp_message(&wire).unwrap();
                if let Some(complete) = assembler.feed(&decoded, now).unwrap() {
                    assert_eq!(complete.payload, payload);
                }
                assert!(assembler.buffered_payload_bytes() <= 4096);
            }
            assert_eq!(assembler.buffered_payload_bytes(), 0);
        }
    }

    if data.len() >= 17 {
        let address: std::net::IpAddr =
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[..16]).unwrap()).into();
        if let Ok(prefix) = AllowedIp::new(address, data[16]) {
            let routes = PeerRoutes::new(2, &[(prefix, 0), (prefix, 1)]).unwrap();
            assert_eq!(routes.lookup(address), Some(1));
            assert!(!routes.accepts_source(0, address));
        }
    }
});
