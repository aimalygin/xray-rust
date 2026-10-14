use std::net::IpAddr;

use serde_json::Value;
use xray_proxy::trojan::*;
use xray_routing::{Network, Target, TargetAddr};

fn target(address: &str, port: u16, network: Network) -> Target {
    let addr = match address.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(ip),
        Err(_) => TargetAddr::Domain(address.to_owned()),
    };
    Target::new(addr, port, network)
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn request_and_udp_bytes_match_pinned_xray() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/v08/protocol-primitives.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["xrayCoreCommit"],
        "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
    );
    for case in fixture["trojanRequests"].as_array().unwrap() {
        let auth = TrojanAuth::new(case["password"].as_str().unwrap()).unwrap();
        let network = match case["network"].as_str().unwrap() {
            "tcp" => Network::Tcp,
            "udp" => Network::Udp,
            _ => panic!("unknown fixture network"),
        };
        let destination = target(
            case["address"].as_str().unwrap(),
            case["port"].as_u64().unwrap().try_into().unwrap(),
            network,
        );
        assert_eq!(
            encode_request_header(&auth, &destination)
                .unwrap()
                .as_bytes(),
            unhex(case["wire"].as_str().unwrap())
        );
    }
    for case in fixture["trojanUdpPackets"].as_array().unwrap() {
        let wire = unhex(case["wire"].as_str().unwrap());
        let payload = unhex(case["payload"].as_str().unwrap());
        let packet = UdpPacket {
            target: target(
                case["address"].as_str().unwrap(),
                case["port"].as_u64().unwrap().try_into().unwrap(),
                Network::Udp,
            ),
            payload: &payload,
        };
        assert_eq!(encode_udp_packet(&packet).unwrap(), wire);
        assert_eq!(decode_udp_packet(&wire).unwrap(), (packet, wire.len()));
    }
}

#[test]
fn every_truncation_can_be_retried_and_concatenated_frames_remain_separate() {
    for address in ["192.0.2.1", "2001:db8::1", "example.test"] {
        let packet = UdpPacket {
            target: target(address, 53, Network::Udp),
            payload: b"\0\xff\r\nreply",
        };
        let wire = encode_udp_packet(&packet).unwrap();
        for length in 0..wire.len() {
            assert_eq!(
                decode_udp_packet(&wire[..length]),
                Err(WireError::Incomplete)
            );
        }
        let mut joined = wire.clone();
        joined.extend_from_slice(&wire);
        let (first, consumed) = decode_udp_packet(&joined).unwrap();
        assert_eq!(first, packet);
        assert_eq!(consumed, wire.len());
        assert_eq!(decode_udp_packet(&joined[consumed..]).unwrap().0, packet);
        // The payload borrows the input instead of allocating an attacker-sized copy.
        assert_eq!(
            first.payload.as_ptr(),
            joined[consumed - packet.payload.len()..].as_ptr()
        );
    }
}

#[test]
fn udp_limits_are_checked_before_waiting_for_payload() {
    let destination = target(&"a".repeat(MAX_DOMAIN_LENGTH), 65535, Network::Udp);
    let payload = vec![7; MAX_UDP_PAYLOAD_LENGTH];
    let packet = UdpPacket {
        target: destination,
        payload: &payload,
    };
    let wire = encode_udp_packet(&packet).unwrap();
    assert_eq!(wire.len(), MAX_UDP_FRAME_LENGTH);
    assert_eq!(decode_udp_packet(&wire).unwrap().0, packet);
    let oversized = vec![0; MAX_UDP_PAYLOAD_LENGTH + 1];
    assert_eq!(
        encode_udp_packet(&UdpPacket {
            payload: &oversized,
            ..packet
        }),
        Err(WireError::PayloadLength)
    );
    // IPv4 address, port 53, declared 8193-byte payload; no delimiter or payload.
    assert_eq!(
        decode_udp_packet(&[1, 192, 0, 2, 1, 0, 53, 0x20, 1]),
        Err(WireError::PayloadLength)
    );
    assert_eq!(
        decode_udp_packet(&[1, 192, 0, 2, 1, 0, 53, 255, 255]),
        Err(WireError::PayloadLength)
    );
}

#[test]
fn malformed_addresses_ports_and_delimiters_fail_closed() {
    for kind in [0, 2, 5, 255] {
        assert_eq!(decode_udp_packet(&[kind]), Err(WireError::AddressType));
    }
    assert_eq!(decode_udp_packet(&[3, 0]), Err(WireError::Domain));
    assert_eq!(decode_udp_packet(&[3, 1, 0xff]), Err(WireError::Domain));
    assert_eq!(decode_udp_packet(&[3, 1, b'\0']), Err(WireError::Domain));
    let mut wire = encode_udp_packet(&UdpPacket {
        target: target("192.0.2.1", 53, Network::Udp),
        payload: b"reply",
    })
    .unwrap();
    wire[9] = b'\n';
    assert_eq!(decode_udp_packet(&wire), Err(WireError::Delimiter));
    wire[5..7].fill(0);
    assert_eq!(decode_udp_packet(&wire), Err(WireError::Port));
}

#[test]
fn encoding_validates_before_emitting_credentials_or_wrapping_lengths() {
    let auth = TrojanAuth::new("v08-test-password").unwrap();
    for domain in [
        "".to_owned(),
        "a".repeat(256),
        "bad\0host".to_owned(),
        "bad host".to_owned(),
    ] {
        let destination = target(&domain, 443, Network::Tcp);
        assert_eq!(
            encode_request_header(&auth, &destination).unwrap_err(),
            WireError::Domain
        );
    }
    assert_eq!(
        encode_request_header(&auth, &target("192.0.2.1", 0, Network::Tcp)).unwrap_err(),
        WireError::Port
    );
    assert_eq!(
        encode_udp_packet(&UdpPacket {
            target: target("example.test", 53, Network::Tcp),
            payload: &[],
        }),
        Err(WireError::Network)
    );
    let wire = encode_udp_packet(&UdpPacket {
        target: target("example.test", 53, Network::Udp),
        payload: &[],
    })
    .unwrap();
    assert!(decode_udp_packet(&wire).unwrap().0.payload.is_empty());
}

#[test]
fn credential_bounds_and_debug_output_do_not_disclose_secrets() {
    assert_eq!(TrojanAuth::new("").unwrap_err(), WireError::PasswordLength);
    assert!(TrojanAuth::new(&"a".repeat(MAX_PASSWORD_LENGTH)).is_ok());
    assert_eq!(
        TrojanAuth::new(&"a".repeat(MAX_PASSWORD_LENGTH + 1)).unwrap_err(),
        WireError::PasswordLength
    );
    let auth = TrojanAuth::new("v08-test-password").unwrap();
    assert_eq!(format!("{auth:?}"), "TrojanAuth(<redacted>)");
    let header =
        encode_request_header(&auth, &target("private.example.test", 443, Network::Tcp)).unwrap();
    assert_eq!(format!("{header:?}"), "RequestHeader(<redacted>)");
    let packet = UdpPacket {
        target: target("private.example.test", 53, Network::Udp),
        payload: b"private data",
    };
    assert_eq!(
        format!("{packet:?}"),
        "UdpPacket { payload_length: 12, .. }"
    );
}
