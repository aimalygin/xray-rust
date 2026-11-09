//! The xicmp mask against Xray-core's own code, from
//! `tests/fixtures/xicmp/vectors.json`, which `tools/xicmp-oracle` records
//! in the pinned checkout.
use super::message;

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/xicmp/vectors.json"
    ))
    .unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn echoes_are_the_bytes_xrays_marshal_writes() {
    let vectors = vectors();
    let cases = vectors["echoes"].as_array().unwrap();
    for case in cases {
        let v6 = case["v6"].as_bool().unwrap();
        let request = case["side"] == "request";
        let kind = match (v6, request) {
            (false, true) => message::ECHO_REQUEST_V4,
            (false, false) => message::ECHO_REPLY_V4,
            (true, true) => message::ECHO_REQUEST_V6,
            (true, false) => message::ECHO_REPLY_V6,
        };
        let mut data = case["clientId"].as_str().map(unhex).unwrap_or_default();
        data.extend(unhex(case["payload"].as_str().unwrap()));
        let id = case["id"].as_u64().unwrap() as u16;
        let seq = case["seq"].as_u64().unwrap() as u16;
        assert_eq!(
            message::echo(kind, id, seq, &data),
            unhex(case["message"].as_str().unwrap()),
            "{case}"
        );
    }
    assert!(cases.len() >= 40);
}

#[test]
fn checksums_are_those_of_x_net_icmp() {
    for case in vectors()["checksums"].as_array().unwrap() {
        let bytes = unhex(case["bytes"].as_str().unwrap());
        assert_eq!(
            u64::from(message::checksum(&bytes)),
            case["checksum"].as_u64().unwrap(),
            "{} bytes",
            bytes.len()
        );
    }
}

#[test]
fn messages_read_as_parse_message_reads_them() {
    let vectors = vectors();
    let cases = vectors["parses"].as_array().unwrap();
    for case in cases {
        let v6 = case["v6"].as_bool().unwrap();
        let bytes = unhex(case["message"].as_str().unwrap());
        let parsed = message::parse_echo(&bytes, v6);
        if case["echo"].as_bool().unwrap_or(false) {
            let echo = parsed.unwrap_or_else(|| panic!("{case}"));
            assert_eq!(u64::from(echo.kind), case["type"].as_u64().unwrap());
            assert_eq!(u64::from(echo.id), case["id"].as_u64().unwrap());
            assert_eq!(u64::from(echo.seq), case["seq"].as_u64().unwrap());
            assert_eq!(
                echo.data,
                unhex(case["data"].as_str().unwrap_or_default()),
                "{case}"
            );
        } else {
            // Not an echo to Go: an error or another message type.
            assert!(parsed.is_none(), "{case}");
        }
    }
    assert!(cases.len() >= 150);
}
