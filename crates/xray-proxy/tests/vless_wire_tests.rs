use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;
use xray_proxy::vless::{encode_request_header, VlessCommand, VlessRequest, WireError};
use xray_routing::{Network, Target, TargetAddr};

#[test]
fn encodes_vless_tcp_header_with_vision_flow() {
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Tcp,
        target: Target::new(
            TargetAddr::Domain("example.com".to_owned()),
            443,
            Network::Tcp,
        ),
        flow: Some("xtls-rprx-vision".to_owned()),
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         12\
         0a1078746c732d727072782d766973696f6e\
         01\
         01bb\
         02\
         0b6578616d706c652e636f6d",
    );

    assert_eq!(encoded, expected);
}

#[test]
fn encodes_no_flow_as_zero_length_addons() {
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Tcp,
        target: Target::new(TargetAddr::Domain("a.test".to_owned()), 443, Network::Tcp),
        flow: None,
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         00\
         01\
         01bb\
         02\
         06612e74657374",
    );

    assert_eq!(encoded, expected);
}

#[test]
fn omits_non_vision_flow_from_addons() {
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Tcp,
        target: Target::new(TargetAddr::Domain("a.test".to_owned()), 443, Network::Tcp),
        flow: Some("other-flow".to_owned()),
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         00\
         01\
         01bb\
         02\
         06612e74657374",
    );

    assert_eq!(encoded, expected);
}

#[test]
fn encodes_ipv4_address() {
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Tcp,
        target: Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            80,
            Network::Tcp,
        ),
        flow: None,
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         00\
         01\
         0050\
         01\
         c0000201",
    );

    assert_eq!(encoded, expected);
}

#[test]
fn encodes_ipv6_address() {
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Tcp,
        target: Target::new(
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))),
            443,
            Network::Tcp,
        ),
        flow: None,
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         00\
         01\
         01bb\
         03\
         20010db8000000000000000000000001",
    );

    assert_eq!(encoded, expected);
}

#[test]
fn encodes_udp_command_with_target_bytes() {
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Udp,
        target: Target::new(TargetAddr::Domain("dns.test".to_owned()), 53, Network::Udp),
        flow: None,
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         00\
         02\
         0035\
         02\
         08646e732e74657374",
    );

    assert_eq!(encoded, expected);
}

#[test]
fn mux_header_stops_after_command_byte() {
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Mux,
        target: Target::new(
            TargetAddr::Domain("must-not-appear.test".to_owned()),
            443,
            Network::Tcp,
        ),
        flow: None,
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         00\
         03",
    );

    assert_eq!(encoded, expected);
}

#[test]
fn reverse_header_stops_after_command_byte() {
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Reverse,
        target: Target::new(
            TargetAddr::Domain("must-not-appear.test".to_owned()),
            443,
            Network::Tcp,
        ),
        flow: None,
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         00\
         04",
    );

    assert_eq!(encoded, expected);
}

#[test]
fn domain_length_255_succeeds() {
    let domain = "a".repeat(255);
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Tcp,
        target: Target::new(TargetAddr::Domain(domain), 443, Network::Tcp),
        flow: None,
    };

    let encoded = encode_request_header(&request).unwrap();

    assert_eq!(encoded[22], 0xff);
    assert_eq!(encoded.len(), 23 + 255);
}

#[test]
fn domain_length_256_returns_error() {
    let domain = "a".repeat(256);
    let request = VlessRequest {
        user_id: test_uuid(),
        command: VlessCommand::Tcp,
        target: Target::new(TargetAddr::Domain(domain), 443, Network::Tcp),
        flow: None,
    };

    let encoded = encode_request_header(&request);

    assert_eq!(encoded, Err(WireError::DomainTooLong(256)));
}

fn test_uuid() -> Uuid {
    Uuid::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ])
}

fn hex_bytes(input: &str) -> Vec<u8> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    clean
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
