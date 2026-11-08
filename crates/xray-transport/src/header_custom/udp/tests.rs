use super::*;
use crate::header_custom::{CustomArg, CustomExpr};

fn item() -> CustomItem {
    CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: vec![],
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    }
}

fn config(standalone: bool) -> Arc<HeaderCustomUdpConfig> {
    Arc::new(HeaderCustomUdpConfig {
        standalone,
        client: vec![CustomItem {
            packet: b"hi".to_vec(),
            capture: "hello".into(),
            ..item()
        }],
        server: vec![CustomItem {
            reuse: "hello".into(),
            ..item()
        }],
    })
}

fn peer() -> SocketAddr {
    "192.0.2.1:443".parse().unwrap()
}

/// Xray-core's state lifetime, spelled out so that the constant is checked.
const FIVE_SECONDS: Duration = Duration::from_secs(5);

#[test]
fn prefix_captures_are_per_peer_and_expire_after_five_seconds() {
    let mut mask = UdpHeader::new(config(false)).unwrap();
    let now = Instant::now();
    assert!(
        matches!(mask.write(b"payload", None, peer(), now), Write::Packet(p) if p == b"hipayload")
    );
    assert!(mask.read(b"xypayload", peer(), now).is_none());
    assert!(mask.read(b"h", peer(), now).is_none());
    let other = "192.0.2.2:443".parse().unwrap();
    assert!(mask.read(b"hipayload", other, now).is_none());
    assert_eq!(mask.read(b"hipayload", peer(), now), Some(2));
    assert_eq!(mask.read(b"hipayload", peer(), now + FIVE_SECONDS), Some(2));
    assert!(mask
        .read(
            b"hipayload",
            peer(),
            now + FIVE_SECONDS * 2 + Duration::from_nanos(1)
        )
        .is_none());
}

#[test]
fn standalone_waits_for_exact_reply_then_renews_without_sliding_ttl() {
    let mut mask = UdpHeader::new(config(true)).unwrap();
    let now = Instant::now();
    assert!(matches!(mask.write(b"payload", None, peer(), now), Write::Handshake(p) if p == b"hi"));
    assert!(matches!(
        mask.write(b"payload", None, peer(), now),
        Write::Waiting
    ));
    // Non-replies are delivered unchanged, including replies from other peers.
    assert_eq!(
        mask.read(b"hi", "192.0.2.2:443".parse().unwrap(), now),
        Some(0)
    );
    assert_eq!(mask.read(b"hix", peer(), now), Some(0));
    assert_eq!(mask.read(b"no", peer(), now), Some(0));
    assert!(mask.waiting());
    assert_eq!(mask.read(b"hi", peer(), now), None);
    assert!(!mask.waiting());
    for elapsed in [Duration::ZERO, FIVE_SECONDS] {
        assert!(
            matches!(mask.write(b"payload", None, peer(), now + elapsed), Write::Packet(p) if p == b"payload")
        );
    }
    assert!(matches!(
        mask.write(
            b"payload",
            None,
            peer(),
            now + FIVE_SECONDS + Duration::from_nanos(1)
        ),
        Write::Handshake(_)
    ));
}

#[test]
fn empty_standalone_sequences_still_exchange_empty_datagrams() {
    let mut mask = UdpHeader::new(Arc::new(HeaderCustomUdpConfig {
        standalone: true,
        ..Default::default()
    }))
    .unwrap();
    let now = Instant::now();
    assert!(
        matches!(mask.write(b"payload", None, peer(), now), Write::Handshake(p) if p.is_empty())
    );
    assert_eq!(mask.read(b"", peer(), now), None);
    assert!(
        matches!(mask.write(b"payload", None, peer(), now), Write::Packet(p) if p == b"payload")
    );
}

#[test]
fn addresses_exist_only_when_writing() {
    let metadata = CustomItem {
        transform: Some(CustomExpr {
            op: "be16".into(),
            args: vec![CustomArg::Metadata("remote_port".into())],
        }),
        ..item()
    };
    let mut mask = UdpHeader::new(Arc::new(HeaderCustomUdpConfig {
        client: vec![metadata.clone()],
        server: vec![metadata],
        standalone: false,
    }))
    .unwrap();
    let now = Instant::now();
    assert!(matches!(mask.write(b"p", None, peer(), now), Write::Packet(p) if p == [1, 187, b'p']));
    assert!(mask.read(&[1, 187, b'p'], peer(), now).is_none());
}

#[test]
fn invalid_or_oversized_headers_and_size_changes_do_not_panic() {
    let mut cfg = (*config(false)).clone();
    cfg.client[0] = CustomItem {
        reuse: "missing".into(),
        ..item()
    };
    assert!(UdpHeader::new(Arc::new(cfg.clone())).is_err());
    cfg.client[0] = CustomItem {
        rand: 4097,
        ..item()
    };
    assert!(UdpHeader::new(Arc::new(cfg)).is_err());
    let mut mask = UdpHeader::new(config(false)).unwrap();
    assert!(matches!(
        mask.write(&vec![0; 4095], None, peer(), Instant::now()),
        Write::Drop
    ));
    // measure(truncate) succeeds, evaluation fails: this drops the packet.
    let mut cfg = (*config(false)).clone();
    cfg.client[0].transform = Some(CustomExpr {
        op: "truncate".into(),
        args: vec![CustomArg::Bytes(vec![]), CustomArg::U64(2)],
    });
    cfg.client[0].packet.clear();
    let mut mask = UdpHeader::new(Arc::new(cfg)).unwrap();
    assert!(matches!(
        mask.write(b"p", None, peer(), Instant::now()),
        Write::Drop
    ));
}

#[test]
fn random_replies_capture_actual_bytes_and_write_fallback_survives_expiry() {
    let mut mask = UdpHeader::new(Arc::new(HeaderCustomUdpConfig {
        client: vec![CustomItem {
            transform: Some(CustomExpr {
                op: "truncate".into(),
                args: vec![CustomArg::Reuse("saved".into()), CustomArg::U64(2)],
            }),
            ..item()
        }],
        server: vec![CustomItem {
            rand: 2,
            capture: "saved".into(),
            ..item()
        }],
        standalone: false,
    }))
    .unwrap();
    let now = Instant::now();
    assert!(matches!(mask.write(b"p", None, peer(), now), Write::Drop));
    assert_eq!(mask.read(b"XYdata", peer(), now), Some(2));
    assert!(
        matches!(mask.write(b"p", None, peer(), now + FIVE_SECONDS * 2), Write::Packet(p) if p == b"XYp")
    );
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Decode the small JSON vocabulary used by the independently generated cases.
fn oracle_items(items: &serde_json::Value) -> Vec<CustomItem> {
    use base64::Engine as _;
    use serde_json::Value as Json;
    fn bytes(kind: &Json, value: &Json) -> Vec<u8> {
        match kind.as_str().unwrap_or("") {
            "str" => value.as_str().unwrap().as_bytes().to_vec(),
            "hex" => unhex(value.as_str().unwrap()),
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(value.as_str().unwrap())
                .unwrap(),
            _ => value
                .as_array()
                .map(|v| v.iter().map(|n| n.as_u64().unwrap() as u8).collect())
                .unwrap_or_default(),
        }
    }
    fn expr(value: &Json) -> CustomExpr {
        CustomExpr {
            op: value["op"].as_str().unwrap().into(),
            args: value["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|arg| {
                    if let Some(n) = arg["u64"].as_u64() {
                        CustomArg::U64(n)
                    } else if let Some(name) = arg["reuse"].as_str() {
                        CustomArg::Reuse(name.into())
                    } else if let Some(name) = arg["metadata"].as_str() {
                        CustomArg::Metadata(name.into())
                    } else if arg["transform"].is_object() {
                        CustomArg::Transform(expr(&arg["transform"]))
                    } else {
                        CustomArg::Bytes(bytes(&arg["type"], &arg["bytes"]))
                    }
                })
                .collect(),
        }
    }
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| CustomItem {
            packet: bytes(&i["type"], &i["packet"]),
            rand: i["rand"].as_i64().unwrap_or(0) as i32,
            rand_range: i["randRange"]
                .as_u64()
                .map(|n| (n as u8, n as u8))
                .unwrap_or((0, 255)),
            capture: i["capture"].as_str().unwrap_or("").into(),
            reuse: i["reuse"].as_str().unwrap_or("").into(),
            transform: i["transform"].is_object().then(|| expr(&i["transform"])),
            ..item()
        })
        .collect()
}

#[test]
fn udp_writes_and_replies_match_xray_core_oracle() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/header-custom/udp-vectors.json"
    ))
    .unwrap();
    let local = "192.0.2.10:40000".parse().unwrap();
    let remote = "198.51.100.20:443".parse().unwrap();
    for case in cases.as_array().unwrap() {
        let settings = &case["settings"];
        let mut mask = UdpHeader::new(Arc::new(HeaderCustomUdpConfig {
            standalone: settings["mode"] == "standalone",
            client: oracle_items(&settings["client"]),
            server: oracle_items(&settings["server"]),
        }))
        .unwrap();
        let sent: Vec<_> = case["clientToServer"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| unhex(s.as_str().unwrap()))
            .collect();
        let replies: Vec<_> = case["serverToClient"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| unhex(s.as_str().unwrap()))
            .collect();
        let mut outgoing = sent.iter();
        let mut incoming = replies.iter();
        for i in 0..2 {
            let payload = format!("PAYLOAD{i}").into_bytes();
            let now = Instant::now();
            let mut write = mask.write(&payload, Some(local), remote, now);
            if let Write::Handshake(request) = write {
                assert_eq!(&request, outgoing.next().unwrap(), "{}", case["name"]);
                assert_eq!(mask.read(incoming.next().unwrap(), remote, now), None);
                write = mask.write(&payload, Some(local), remote, now);
            }
            let Write::Packet(packet) = write else {
                panic!("{}: no payload", case["name"])
            };
            assert_eq!(&packet, outgoing.next().unwrap(), "{}", case["name"]);
            let reply = incoming.next().unwrap();
            let offset = mask.read(reply, remote, now).unwrap();
            assert_eq!(&reply[offset..], payload);
        }
        assert!(outgoing.next().is_none());
        assert!(incoming.next().is_none());
    }
}

#[test]
fn standalone_evaluates_items_that_only_prefix_mode_measures() {
    // A computed pad length cannot be measured, only evaluated.
    let padded = CustomItem {
        transform: Some(CustomExpr {
            op: "pad".into(),
            args: vec![
                CustomArg::Bytes(b"x".to_vec()),
                CustomArg::Transform(CustomExpr {
                    op: "add".into(),
                    args: vec![CustomArg::U64(1), CustomArg::U64(2)],
                }),
                CustomArg::Bytes(b"-".to_vec()),
            ],
        }),
        ..item()
    };
    let config = |standalone| {
        Arc::new(HeaderCustomUdpConfig {
            standalone,
            client: vec![padded.clone()],
            server: vec![],
        })
    };
    assert!(UdpHeader::new(config(false)).is_err());
    let mut mask = UdpHeader::new(config(true)).unwrap();
    assert!(matches!(
        mask.write(b"p", None, peer(), Instant::now()),
        Write::Handshake(request) if request == b"x--"
    ));
}

#[test]
fn oversized_nested_measurements_return_errors() {
    let huge = CustomArg::Transform(CustomExpr {
        op: "truncate".into(),
        args: vec![CustomArg::Bytes(vec![]), CustomArg::U64(u64::MAX)],
    });
    let cfg = HeaderCustomUdpConfig {
        client: vec![],
        server: vec![CustomItem {
            transform: Some(CustomExpr {
                op: "concat".into(),
                args: vec![huge.clone(), huge],
            }),
            ..item()
        }],
        standalone: false,
    };
    assert!(UdpHeader::new(Arc::new(cfg)).is_err());
}
