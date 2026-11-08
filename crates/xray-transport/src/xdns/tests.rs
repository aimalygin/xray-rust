//! What Xray-core's own xdns code does (`tools/xdns-oracle`), checked
//! against this one. `XRAY_XDNS_VECTORS` names a fresh, larger run.
use super::{
    domain::{type_bits, Domain},
    message::{self, Read},
};
use base64::Engine as _;
use serde_json::Value;

const ALL_TYPES: [u16; 4] = [1, 5, 16, 28];

fn vectors() -> Value {
    let text = match std::env::var("XRAY_XDNS_VECTORS") {
        Ok(path) => std::fs::read_to_string(path).unwrap(),
        Err(_) => include_str!("../../../../tests/fixtures/xdns/vectors.json").to_owned(),
    };
    serde_json::from_str(&text).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn base64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

fn int(value: &Value) -> i32 {
    value.as_i64().unwrap() as i32
}

fn domain_of(case: &Value, name_key: &str, edns0: u16) -> Domain {
    Domain::new(
        case[name_key].as_str().unwrap(),
        int(&case["lenLimit"]),
        int(&case["labelLimit"]),
        &ALL_TYPES,
        edns0,
    )
    .unwrap()
}

#[test]
fn domains_read_as_xray_reads_them_or_fail_closed() {
    for case in vectors()["domains"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let edns0 = case["edns0"].as_i64().unwrap() as i32;
        let got = Domain::new(
            name,
            int(&case["lenLimit"]),
            int(&case["labelLimit"]),
            &ALL_TYPES,
            edns0 as u16,
        );
        match case["error"].as_str() {
            // The configuration makes the IDNA check, not the client.
            Some(error) if error.starts_with("idna:") => {}
            Some(error) => assert!(got.is_err(), "{name:?}: Xray refuses with {error}"),
            None if !case["packs"].as_bool().unwrap() => {
                assert!(got.is_err(), "{name:?}: Xray's client would panic on it")
            }
            None => {
                let capacity: usize = case["show"]
                    .as_str()
                    .unwrap()
                    .rsplit(' ')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(got.unwrap().capacity(), capacity, "{name:?}");
            }
        }
    }
}

#[test]
fn names_decode_as_xray_decodes_them() {
    let domain = Domain::new("t.example.com", 255, 63, &ALL_TYPES, 0).unwrap();
    for case in vectors()["names"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert_eq!(
            domain.decode(name.as_bytes()),
            hex(case["decoded"].as_str().unwrap()),
            "{name:?}"
        );
    }
}

#[test]
fn names_encode_as_xray_encodes_them() {
    for case in vectors()["encodings"].as_array().unwrap() {
        let domain = domain_of(case, "domain", 0);
        let data = hex(case["data"].as_str().unwrap());
        let name = domain.encode(&data);
        assert_eq!(
            std::str::from_utf8(&name).unwrap(),
            case["name"].as_str().unwrap()
        );
        assert_eq!(domain.decode(&name), data);
    }
}

#[test]
fn queries_pack_as_xray_packs_them() {
    for case in vectors()["queries"].as_array().unwrap() {
        let edns0 = case["edns0"].as_u64().unwrap() as u16;
        let domain = domain_of(case, "domain", edns0);
        let qtype = case["type"].as_u64().unwrap() as u16;
        let data = hex(case["data"].as_str().unwrap());
        assert_eq!(data[0] & 3, type_bits(qtype));
        let query = message::query(
            case["id"].as_u64().unwrap() as u16,
            &domain.encode(&data),
            qtype,
            domain.edns0(),
        );
        assert_eq!(query, base64(case["query"].as_str().unwrap()), "{case}");
    }
}

fn answering(vectors: &Value) -> Vec<Domain> {
    vectors["answering"]
        .as_array()
        .unwrap()
        .iter()
        .map(|spec| {
            Domain::new(
                spec["name"].as_str().unwrap(),
                int(&spec["lenLimit"]),
                int(&spec["labelLimit"]),
                &ALL_TYPES,
                spec["edns0"].as_u64().unwrap() as u16,
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn answers_read_back_what_xrays_server_framed() {
    let vectors = vectors();
    let domains = answering(&vectors);
    for case in vectors["responses"].as_array().unwrap() {
        let packets: Vec<Vec<u8>> = case["packets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|packet| hex(packet.as_str().unwrap()))
            .collect();
        match message::read(&base64(case["response"].as_str().unwrap()), &domains) {
            Read::Answer { packets: got, .. } => assert_eq!(got, packets, "{case}"),
            other => panic!("{case}: {other:?}"),
        }
    }
}

#[test]
fn every_response_is_read_as_xrays_client_reads_it() {
    let vectors = vectors();
    let domains = answering(&vectors);
    let reads = vectors["reads"].as_array().unwrap();
    for case in reads {
        let response = base64(case["response"].as_str().unwrap());
        let got = message::read(&response, &domains);
        let packets: Vec<Vec<u8>> = case["packets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|packet| hex(packet.as_str().unwrap()))
            .collect();
        let expected = match case["stage"].as_str() {
            Some("unpack") => Read::Unpack,
            Some("header") => Read::Header,
            Some("domain") => Read::Domain,
            None => Read::Answer {
                decoded: case["decoded"].as_str().map(hex).unwrap_or_default(),
                packets,
            },
            Some(other) => panic!("stage {other}"),
        };
        assert_eq!(got, expected, "{}", case["response"]);
    }
    // The corpus reaches every stage.
    for stage in ["unpack", "header", "domain"] {
        assert!(reads.iter().any(|case| case["stage"] == stage), "{stage}");
    }
    assert!(reads
        .iter()
        .any(|case| case["packets"].as_array().is_some_and(|p| !p.is_empty())));
}
