use std::time::{Duration, Instant};

use serde_json::Value;
use xray_proxy::hysteria::*;
use xray_proxy::wireguard::*;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/v07/protocol-primitives.json"
    ))
    .unwrap()
}

fn unhex(input: &str) -> Vec<u8> {
    assert!(input.len().is_multiple_of(2));
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn tcp_bytes_match_pinned_xray_functions() {
    let fixture = fixture();
    for case in fixture["tcpRequests"].as_array().unwrap() {
        let expected = unhex(case["wire"].as_str().unwrap());
        let request = TcpRequest {
            address: case["address"].as_str().unwrap(),
            padding: &[],
        };
        assert_eq!(encode_tcp_request(&request).unwrap(), expected);
        let mut with_data = expected.clone();
        with_data.extend_from_slice(b"application data");
        assert_eq!(
            decode_tcp_request(&with_data).unwrap(),
            (request, expected.len())
        );
    }
    for case in fixture["tcpResponses"].as_array().unwrap() {
        let expected = unhex(case["wire"].as_str().unwrap());
        let response = TcpResponse {
            status: u8::from(!case["ok"].as_bool().unwrap()),
            message: case["message"].as_str().unwrap().as_bytes(),
            padding: &[],
        };
        assert_eq!(encode_tcp_response(&response).unwrap(), expected);
        assert_eq!(
            decode_tcp_response(&expected).unwrap(),
            (response, expected.len())
        );
    }
}

#[test]
fn udp_fragment_bytes_and_reassembly_match_pinned_xray() {
    let fixture = fixture();
    let full_wire = unhex(fixture["udp"]["wire"].as_str().unwrap());
    let full = decode_udp_message(&full_wire).unwrap();
    assert_eq!(full.session_id, 0x01020304);
    assert_eq!(encode_udp_message(&full).unwrap(), full_wire);
    let fragments = fragment_udp_message(
        &full,
        fixture["udp"]["maxDatagramSize"].as_u64().unwrap() as usize,
    )
    .unwrap();
    let expected = fixture["udp"]["fragments"].as_array().unwrap();
    assert_eq!(fragments.len(), expected.len());
    for (fragment, expected) in fragments.iter().zip(expected) {
        assert_eq!(
            encode_udp_message(fragment).unwrap(),
            unhex(expected.as_str().unwrap())
        );
    }
    let mut assembler =
        Reassembler::new(full.session_id, MAX_UDP_PAYLOAD, Duration::from_secs(5)).unwrap();
    let now = Instant::now();
    let mut complete = None;
    for fragment in fragments.iter().rev() {
        complete = assembler.feed(fragment, now).unwrap();
    }
    let complete = complete.unwrap();
    assert_eq!(complete.payload, full.payload);
    assert_eq!(complete.address, full.address);
    assert_eq!(assembler.buffered_payload_bytes(), 0);
}

#[test]
fn key_spellings_match_xray_with_fixed_decoded_length() {
    for case in fixture()["keys"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let key = KeyMaterial::parse(input).unwrap();
        assert_eq!(
            key.expose_bytes().as_slice(),
            unhex(case["decodedHex"].as_str().unwrap())
        );
        assert_eq!(format!("{key:?}"), "KeyMaterial(<redacted>)");
    }
}

#[test]
fn allowed_ip_lookup_and_source_checks_match_xrays_wireguard_engine() {
    let fixture = fixture();
    let routes: Vec<_> = fixture["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["prefix"]
                    .as_str()
                    .unwrap()
                    .parse::<AllowedIp>()
                    .unwrap(),
                item["peer"].as_u64().unwrap() as usize,
            )
        })
        .collect();
    let table = PeerRoutes::new(routes.len(), &routes).unwrap();
    for item in fixture["lookups"].as_array().unwrap() {
        let address = item["address"].as_str().unwrap().parse().unwrap();
        let expected = item["peer"].as_u64().unwrap() as usize;
        assert_eq!(table.lookup(address), Some(expected));
        for peer in 0..=routes.len() {
            assert_eq!(table.accepts_source(peer, address), peer == expected);
        }
    }
}
