use serde_json::{json, Value};
use xray_config::{parse_xray_json, FragmentRange, NoiseSegment};
fn profile(noise: Value) -> Value {
    json!({"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"example.com","port":443},
        "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"example.com"},
            "hysteriaSettings":{"version":2,"auth":"synthetic"},"finalmask":{"udp":[{"type":"noise","settings":noise}]}}}]})
}
#[test]
fn encodings_ranges_and_order_match_pinned_xray() {
    let mut p = profile(
        json!({"reset":"20-10","noise":[{"rand":"24-16","randRange":"9-7","delay":"2-1"},
        {"type":"str","packet":" hi "}, {"type":"base64","packet":"AAEC"}, {"type":"hex","packet":"00ff"}, {"packet":[0,128,255]}]}),
    );
    let n = parse_xray_json(&p.to_string()).unwrap().config.outbounds[0]
        .stream
        .udp_noise
        .clone()
        .unwrap();
    assert_eq!(n.reset_secs, FragmentRange { from: 10, to: 20 });
    assert_eq!(n.items[0].random_length, FragmentRange { from: 16, to: 24 });
    assert_eq!(n.items[0].random_bytes, FragmentRange { from: 7, to: 9 });
    assert_eq!(n.items[1].packet, b" hi ");
    assert_eq!(n.items[2].packet, [0, 1, 2]);
    assert_eq!(n.items[3].packet, [0, 255]);
    assert_eq!(n.items[4].packet, [0, 128, 255]);
    let masks = p["outbounds"][0]["streamSettings"]["finalmask"]["udp"]
        .as_array_mut()
        .unwrap();
    masks.push(json!({"type":"salamander","settings":{"password":"synthetic"}}));
    assert!(
        parse_xray_json(&p.to_string()).unwrap().config.outbounds[0]
            .stream
            .udp_noise
            .as_ref()
            .unwrap()
            .before_salamander
    );
    p["outbounds"][0]["streamSettings"]["finalmask"]["udp"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(
        !parse_xray_json(&p.to_string()).unwrap().config.outbounds[0]
            .stream
            .udp_noise
            .as_ref()
            .unwrap()
            .before_salamander
    );
}
#[test]
fn malformed_and_unbounded_noise_is_rejected() {
    for n in [
        json!({"reset":-1}),
        json!({"noise":vec![json!({"rand":1});17]}),
        json!({"noise":[{"rand":4097}]}),
        json!({"noise":[{"rand":1,"packet":null}]}),
        json!({"noise":[{"randRange":256}]}),
        json!({"noise":[{"delay":1001}]}),
        json!({"noise":vec![json!({"delay":1000});11]}),
        json!({"noise":[{"type":"base64","packet":"??"}]}),
        json!({"noise":[{"type":"str","packet":"a".repeat(4097)}]}),
        json!({"noise":[{"packet":[256]}]}),
        json!({"noise":[{"type":"rand","packet":"4-8"}]}),
        json!({"unknown":true}),
    ] {
        assert!(
            parse_xray_json(&profile(n.clone()).to_string()).is_err(),
            "{n}"
        );
    }
}
#[test]
fn exact_h3_only_and_no_change_when_absent() {
    let mut p = profile(json!({"noise":[{"rand":16}]}));
    // A proxy over XHTTP: freedom takes UDP masks on any network.
    p["outbounds"][0] = json!({"protocol":"vless",
        "settings":{"address":"example.com","port":443,"id":"27848739-7e62-4138-9fd3-098a63964b6b","encryption":"none"},
        "streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"example.com","alpn":["h3"]},"finalmask":p["outbounds"][0]["streamSettings"]["finalmask"]}});
    assert!(parse_xray_json(&p.to_string()).is_ok());
    p["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] = json!(["h2"]);
    assert!(parse_xray_json(&p.to_string()).is_err());
    p["outbounds"][0]["streamSettings"]["finalmask"] = Value::Null;
    assert!(parse_xray_json(&p.to_string()).unwrap().config.outbounds[0]
        .stream
        .udp_noise
        .is_none());
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// A segment as the noise-exp oracle writes what Xray-core read.
fn oracle_segment(value: &Value) -> NoiseSegment {
    let size = FragmentRange {
        from: value["min"].as_u64().unwrap_or(0) as u32,
        to: value["max"].as_u64().unwrap_or(0) as u32,
    };
    match value["kind"].as_str().unwrap() {
        "BYTES" => NoiseSegment::Bytes(decode_hex(value["bytes"].as_str().unwrap_or(""))),
        "RANDOM" => NoiseSegment::Random(size),
        "RANDOM_ASCII" => NoiseSegment::RandomLetters(size),
        "RANDOM_DIGIT" => NoiseSegment::RandomDigits(size),
        "TIMESTAMP" => NoiseSegment::Timestamp,
        "COUNTER" => NoiseSegment::Counter,
        "NONCE" => NoiseSegment::Nonce,
        kind => panic!("unknown segment kind {kind}"),
    }
}

/// Every `exp` packet the oracle ran through Xray-core v26.10.31's own
/// configuration reads here into the same segments, or is refused as there;
/// past 4096 bytes it is refused here alone.
#[test]
fn exp_packets_read_as_xray_core_reads_them() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/noise/exp-vectors.json"
    ))
    .unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 60);
    for case in cases {
        let mut item = json!({"type": "exp", "packet": case["packet"]});
        if let Some(rand) = case.get("rand") {
            item["rand"] = rand.clone();
        }
        let parsed = parse_xray_json(&profile(json!({"noise": [item]})).to_string());
        let Some(expected) = case.get("segments") else {
            assert!(parsed.is_err(), "Xray-core refuses {case}");
            continue;
        };
        let expected: Vec<_> = expected
            .as_array()
            .unwrap()
            .iter()
            .map(oracle_segment)
            .collect();
        if expected.iter().map(NoiseSegment::max_len).sum::<usize>() > 4096 {
            assert!(parsed.is_err(), "past the 4096-byte bound: {case}");
            continue;
        }
        let parsed = parsed.unwrap_or_else(|error| panic!("{case}: {:?}", error.diagnostics));
        let noise = parsed.config.outbounds[0].stream.udp_noise.clone().unwrap();
        assert_eq!(noise.items[0].segments, expected, "{case}");
        assert!(noise.items[0].packet.is_empty());
    }
}

#[test]
fn exp_items_keep_their_bounds_and_scripts_wait_for_lua() {
    let parse = |noise: Value| parse_xray_json(&profile(noise).to_string());
    // The type is read in any case, and a delay still follows the packet.
    let parsed =
        parse(json!({"noise":[{"type":"ExP","packet":"<b 01><c>","delay":"5-1"}]})).unwrap();
    let item = &parsed.config.outbounds[0]
        .stream
        .udp_noise
        .as_ref()
        .unwrap()
        .items[0];
    assert_eq!(item.delay_ms, FragmentRange { from: 1, to: 5 });
    assert_eq!(
        item.segments,
        [NoiseSegment::Bytes(vec![1]), NoiseSegment::Counter]
    );
    // Xray-core skips randRange's bounds for an exp item.
    assert!(parse(json!({"noise":[{"type":"exp","packet":"<c>","randRange":"0-300"}]})).is_ok());
    for noise in [
        json!({"noise":[{"type":"exp","packet":"<r 4000><r 89><n>"}]}),
        json!({"noise":[{"type":"exp","packet":"<c>","delay":1001}]}),
        json!({"noise":[{"type":"exp","packet":["<c>"]}]}),
        json!({"noise":[{"type":"exp"}]}),
        json!({"script":"return {}"}),
        json!({"script":"return {}","noise":[{"rand":1}]}),
        json!({"noise":[{"type":"hex","packet":"+a+b"}]}),
    ] {
        assert!(parse(noise.clone()).is_err(), "{noise}");
    }
    // The largest packet may take exactly 4096 bytes; an empty script is none.
    assert!(parse(json!({"noise":[{"type":"exp","packet":"<r 4000><r 88><n>"}]})).is_ok());
    assert!(parse(json!({"script":"","noise":[{"type":"exp","packet":"<c>"}]})).is_ok());
}

/// Salamander, Gecko with it, reaches XHTTP over HTTP/3 and MASQUE over
/// HTTP/3 at the stream, its place among the other masks recorded by them;
/// a TCP carrier refuses it.
#[test]
fn salamander_and_gecko_reach_every_quic_carrier() {
    let xhttp = |masks: Value| {
        json!({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,
            "users":[{"id":"27848739-7e62-4138-9fd3-098a63964b6b","encryption":"none"}]}]},
            "streamSettings":{"network":"xhttp","security":"tls",
                "tlsSettings":{"serverName":"example.com","alpn":["h3"]},"finalmask":{"udp":masks}}}]})
    };
    let masks = json!([
        {"type":"noise","settings":{"noise":[{"rand":4}]}},
        {"type":"salamander","settings":{"password":"synthetic","packetSize":"1200-512"}},
    ]);
    let parsed = parse_xray_json(&xhttp(masks.clone()).to_string()).unwrap();
    let stream = &parsed.config.outbounds[0].stream;
    let salamander = stream.udp_salamander.as_ref().unwrap();
    assert_eq!(salamander.password.as_str(), "synthetic");
    assert_eq!(
        salamander.gecko_packet_size,
        Some(FragmentRange {
            from: 512,
            to: 1200
        })
    );
    assert!(stream.udp_noise.as_ref().unwrap().before_salamander);

    let masque = json!({"outbounds":[{"protocol":"masque","settings":{"address":"masque.example","port":443},
        "streamSettings":{"network":"masque","security":"tls","tlsSettings":{"serverName":"masque.example"},
            "finalmask":{"udp":[{"type":"salamander","settings":{"password":"synthetic"}}]}}}]});
    let parsed = parse_xray_json(&masque.to_string()).unwrap();
    assert!(parsed.config.outbounds[0].stream.udp_salamander.is_some());

    // Hysteria keeps its own.
    let hysteria = profile(json!({"noise":[{"rand":4}]}));
    let mut with_salamander = hysteria.clone();
    with_salamander["outbounds"][0]["streamSettings"]["finalmask"]["udp"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"salamander","settings":{"password":"synthetic"}}));
    let parsed = parse_xray_json(&with_salamander.to_string()).unwrap();
    assert!(parsed.config.outbounds[0].stream.udp_salamander.is_none());

    // XHTTP over HTTP/2 and a raw TCP carrier have no datagrams to mask.
    let mut h2 = xhttp(json!([{"type":"salamander","settings":{"password":"synthetic"}}]));
    h2["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] = json!(["h2"]);
    let error = parse_xray_json(&h2.to_string()).unwrap_err();
    assert!(
        error
            .diagnostics
            .iter()
            .any(|d| d.message.contains("Salamander requires Hysteria, mKCP")),
        "{:?}",
        error.diagnostics
    );
}
