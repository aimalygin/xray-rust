use uuid::Uuid;
use xray_proxy::vless::{encode_request_header, VlessCommand, VlessRequest};
use xray_routing::{Network, Target, TargetAddr};

#[test]
fn encodes_vless_tcp_header_with_vision_flow() {
    let request = VlessRequest {
        user_id: Uuid::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]),
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
