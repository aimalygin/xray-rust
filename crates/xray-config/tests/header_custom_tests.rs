//! The `header-custom` TCP mask, read as Xray-core v26.10.31's
//! `HeaderCustomTCP.Build` reads it.
use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, HeaderCustomArg, HeaderCustomExpr, HeaderCustomItem,
    HeaderCustomTcp,
};

fn config(tcp: Value) -> String {
    json!({"outbounds": [{"protocol": "vless",
        "settings": {"vnext": [{"address": "server.example", "port": 443,
            "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]},
        "streamSettings": {"security": "tls", "tlsSettings": {"serverName": "server.example"},
            "finalmask": {"tcp": tcp}}}]})
    .to_string()
}

fn header(settings: Value) -> Result<HeaderCustomTcp, Vec<String>> {
    match parse_xray_json(&config(
        json!([{"type": "header-custom", "settings": settings}]),
    )) {
        Ok(parsed) => Ok(parsed.config.outbounds[0]
            .stream
            .tcp_header_custom
            .clone()
            .unwrap()),
        Err(error) => Err(error
            .diagnostics
            .into_iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .map(|diagnostic| {
                format!(
                    "{}: {}",
                    diagnostic.path.unwrap_or_default(),
                    diagnostic.message
                )
            })
            .collect()),
    }
}

fn item(item: Value) -> Result<HeaderCustomItem, Vec<String>> {
    header(json!({"clients": [[item]]})).map(|header| header.clients[0][0].clone())
}

fn refused(settings: Value, expected: &str) {
    let errors = header(settings.clone()).expect_err(&settings.to_string());
    assert!(
        errors.iter().any(|error| error.contains(expected)),
        "{settings}: {errors:?}"
    );
}

fn plain() -> HeaderCustomItem {
    HeaderCustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: Vec::new(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    }
}

#[test]
fn absent_or_null_parts_are_empty() {
    for settings in [
        json!(null),
        json!({}),
        json!({"clients": null, "servers": null, "errors": null}),
    ] {
        assert_eq!(header(settings).unwrap(), HeaderCustomTcp::default());
    }
    let parsed = header(json!({"clients": [null, [], [{}]]})).unwrap();
    assert_eq!(parsed.clients, [vec![], vec![], vec![plain()]]);
    // Go leaves a null item as the zero item, in either form.
    assert_eq!(item(json!(null)).unwrap(), plain());
    let udp = udp_config(json!({"client": [null], "server": [null, {}]}));
    let parsed = parse_xray_json(&udp.to_string()).unwrap();
    let parsed = parsed.config.outbounds[0]
        .stream
        .udp_header_custom
        .clone()
        .unwrap();
    assert_eq!(parsed.client, [plain()]);
    assert_eq!(parsed.server, [plain(), plain()]);
}

#[test]
fn each_kind_of_item_reads() {
    let parsed = header(json!({
        "clients": [[
            {"packet": [1, 2]},
            {"packet": "AAEC"},
            {"type": "STR", "packet": "hi", "capture": "greeting"},
            {"type": "hex", "packet": "0aFF"},
            {"type": "base64", "packet": "aGk="},
            {"rand": 3, "randRange": "200-100", "delay": "-5-10"},
            {"reuse": "greeting"},
            {"transform": {"op": "concat", "args": [
                {"type": "str", "bytes": "a"}, {"u64": 7}, {"reuse": "greeting"},
                {"metadata": "local_port"}, {"transform": {"op": "be16", "args": [{"u64": 1}]}}]}}
        ]],
        "servers": [[{"packet": null}]],
        "errors": [[{"type": "str", "packet": "nope"}]]
    }))
    .unwrap();
    let items = &parsed.clients[0];
    assert_eq!(items[0].packet, [1, 2]);
    // Go decodes a JSON string into []byte as base64.
    assert_eq!(items[1].packet, [0, 1, 2]);
    assert_eq!(
        (items[2].packet.as_slice(), items[2].capture.as_str()),
        (&b"hi"[..], "greeting")
    );
    assert_eq!(items[3].packet, [10, 255]);
    assert_eq!(items[4].packet, b"hi");
    assert_eq!(
        (items[5].rand, items[5].rand_range, items[5].delay),
        (3, (100, 200), (-5, 10))
    );
    assert_eq!(items[6].reuse, "greeting");
    assert_eq!(
        items[7].transform,
        Some(HeaderCustomExpr {
            op: "concat".into(),
            args: vec![
                HeaderCustomArg::Bytes(b"a".to_vec()),
                HeaderCustomArg::U64(7),
                HeaderCustomArg::Reuse("greeting".into()),
                HeaderCustomArg::Metadata("local_port".into()),
                HeaderCustomArg::Transform(HeaderCustomExpr {
                    op: "be16".into(),
                    args: vec![HeaderCustomArg::U64(1)],
                }),
            ],
        })
    );
    assert_eq!(parsed.servers[0][0], plain());
    assert_eq!(parsed.errors[0][0].packet, b"nope");
}

#[test]
fn one_kind_per_item() {
    for (item, why) in [
        (json!({"packet": [1], "rand": 2}), "packet and rand"),
        (
            json!({"packet": null, "reuse": "x"}),
            "a null packet still counts",
        ),
        (
            json!({"rand": 1, "transform": {"op": "be16", "args": [{"u64": 1}]}}),
            "rand and transform",
        ),
        (json!({"capture": "x"}), "a capture with nothing to capture"),
    ] {
        let errors = self::item(item.clone()).expect_err(why);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("exactly one item kind must be set")),
            "{item}: {errors:?}"
        );
    }
    // A non-positive rand is no kind at all.
    assert_eq!(
        item(json!({"rand": -4, "packet": [1]})).unwrap().packet,
        [1]
    );
}

#[test]
fn names_ranges_and_bytes_are_checked() {
    for (bad, expected) in [
        (
            json!({"capture": "1x", "packet": [1]}),
            "invalid variable name",
        ),
        (json!({"reuse": "a-b"}), "invalid variable name"),
        (json!({"rand": 1, "randRange": "-1-5"}), "invalid randRange"),
        (json!({"rand": 1, "randRange": 256}), "invalid randRange"),
        (
            json!({"rand": 1, "randRange": "x"}),
            "invalid integer range",
        ),
        (
            json!({"delay": 1.5, "packet": [1]}),
            "invalid integer range",
        ),
        (json!({"rand": 65_537}), "rand is at most 65536"),
        (
            json!({"type": "hex", "packet": "abc"}),
            "invalid packet or type",
        ),
        (
            json!({"type": "hex", "packet": "+f"}),
            "invalid packet or type",
        ),
        (json!({"type": "str"}), "invalid packet or type"),
        (
            json!({"type": "rot", "packet": "x"}),
            "invalid packet or type",
        ),
        (json!({"packet": [256]}), "invalid packet or type"),
        (
            json!({"packet": "x", "extra": 1}),
            "unsupported field `extra`",
        ),
    ] {
        let errors = item(bad.clone()).expect_err(&bad.to_string());
        assert!(
            errors.iter().any(|error| error.contains(expected)),
            "{bad}: {errors:?}"
        );
    }
    assert_eq!(item(json!({"rand": 65_536})).unwrap().rand, 65_536);
    assert_eq!(
        item(json!({"capture": "_ok9", "packet": [1]}))
            .unwrap()
            .capture,
        "_ok9"
    );
}

#[test]
fn transforms_need_an_op_and_args_each_with_one_value() {
    let transform = |transform: Value| json!({"clients": [[{"transform": transform}]]});
    for (bad, expected) in [
        (json!({"args": [{"u64": 1}]}), "transform op is required"),
        (json!({"op": "be16"}), "transform args are required"),
        (
            json!({"op": "be16", "args": []}),
            "transform args are required",
        ),
        (
            json!({"op": "be16", "args": [{}]}),
            "transform arg must set exactly one value",
        ),
        (
            json!({"op": "be16", "args": [{"u64": 1, "reuse": "x"}]}),
            "transform arg must set exactly one value",
        ),
        (
            json!({"op": "be16", "args": [{"bytes": null, "u64": 1}]}),
            "transform arg must set exactly one value",
        ),
        (
            json!({"op": "be16", "args": [{"u64": -1}]}),
            "must fit in u64",
        ),
        (
            json!({"op": "be16", "args": [{"reuse": "9"}]}),
            "invalid variable name",
        ),
        (
            json!({"op": "be16", "args": [{"type": "hex", "bytes": "z"}]}),
            "invalid bytes or type",
        ),
        (
            json!({"op": "be16", "args": [{"transform": {"op": "x"}}]}),
            "transform args are required",
        ),
        (
            json!({"op": "be16", "args": [{"u64": 1, "x": 1}]}),
            "unsupported field `x`",
        ),
    ] {
        refused(transform(bad), expected);
    }
    // Xray checks neither the op name nor the metadata name until it runs.
    let parsed = header(transform(
        json!({"op": "rot13", "args": [{"metadata": "anything"}]}),
    ))
    .unwrap();
    assert_eq!(parsed.clients[0][0].transform.as_ref().unwrap().op, "rot13");
}

#[test]
fn the_mask_list_takes_a_fragment_first_then_header_custom() {
    let fragment = json!({"type": "fragment", "settings": {"packets": "tlshello", "length": "100-200", "delay": "10-20"}});
    let header = json!({"type": "header-custom", "settings": {"clients": [[{"packet": [1]}]]}});
    let parsed = parse_xray_json(&config(json!([fragment.clone(), header.clone()]))).unwrap();
    let stream = &parsed.config.outbounds[0].stream;
    assert!(stream.tcp_fragment.is_some() && stream.tcp_header_custom.is_some());
    for (masks, expected) in [
        (
            json!([header.clone(), fragment.clone()]),
            "would cut the header-custom handshake",
        ),
        (
            json!([header.clone(), header.clone()]),
            "only one fragment, one header-custom and one sudoku",
        ),
        (
            json!([{"type": "sudoku"}, header.clone()]),
            "sudoku must be the last TCP mask",
        ),
    ] {
        let errors = parse_xray_json(&config(masks.clone()))
            .unwrap_err()
            .diagnostics;
        assert!(
            errors.iter().any(|error| error.message.contains(expected)),
            "{masks}: {errors:?}"
        );
    }
    // Case-insensitive type, as there.
    let upper = json!([{"type": "HEADER-CUSTOM", "settings": null}]);
    assert!(parse_xray_json(&config(upper)).is_ok());
}

#[test]
fn settings_must_be_objects_of_arrays() {
    refused(
        json!("x"),
        "header-custom settings must be an object or null",
    );
    refused(
        json!({"clients": {}}),
        "header-custom sequences must be an array or null",
    );
    refused(
        json!({"clients": [{}]}),
        "a header-custom sequence must be an array or null",
    );
    refused(
        json!({"clients": [[5]]}),
        "a header-custom item must be an object",
    );
    refused(json!({"other": []}), "unsupported field `other`");
}

fn udp_config(settings: Value) -> Value {
    let mut value: Value = serde_json::from_str(&config(json!([]))).unwrap();
    value["outbounds"][0]["streamSettings"] = json!({"network":"kcp",
        "finalmask":{"udp":[{"type":"header-custom","settings":settings}]}});
    value
}

#[test]
fn udp_modes_and_items_are_parsed_in_mask_order() {
    for (mode, standalone) in [("", false), ("prefix", false), ("standalone", true)] {
        let mut cfg = udp_config(json!({"mode":mode,"client":[
            {"type":"str","packet":"hi","capture":"greeting"},
            {"rand":2,"randRange":"2-4"}],"server":[{"reuse":"greeting"}]}));
        cfg["outbounds"][0]["streamSettings"]["finalmask"]["udp"]
            .as_array_mut()
            .unwrap()
            .insert(
                0,
                json!({"type":"mkcp-legacy","settings":{"header":"srtp"}}),
            );
        let parsed = parse_xray_json(&cfg.to_string()).unwrap();
        let stream = &parsed.config.outbounds[0].stream;
        let header = stream.udp_header_custom.as_ref().unwrap();
        assert_eq!(header.standalone, standalone);
        assert_eq!(header.client[0].packet, b"hi");
        assert_eq!(header.client[1].rand_range, (2, 4));
        assert_eq!(header.server[0].reuse, "greeting");
        let xray_config::StreamTransport::Kcp(kcp) = &stream.transport else {
            panic!("not kcp")
        };
        assert_eq!(
            kcp.masks,
            [
                xray_config::KcpMask::Header(xray_config::KcpHeader::Srtp),
                xray_config::KcpMask::HeaderCustom
            ]
        );
    }
    for settings in [
        json!(null),
        json!({}),
        json!({"mode":null,"client":null,"server":null}),
    ] {
        let parsed = parse_xray_json(&udp_config(settings).to_string()).unwrap();
        assert_eq!(
            parsed.config.outbounds[0].stream.udp_header_custom,
            Some(Default::default())
        );
    }
}

#[test]
fn udp_rejects_invalid_settings_tcp_fields_and_other_carriers() {
    for (settings, expected) in [
        (json!({"mode":"PREFIX"}), "unknown udp mode"),
        (json!({"mode":1}), "must be a string"),
        (json!({"client":{}}), "array or null"),
        (json!({"client":[{"delay":1}]}), "unsupported field `delay`"),
        (json!({"clients":[]}), "unsupported field `clients`"),
        (
            json!({"server":[{"rand":2,"packet":[1]}]}),
            "exactly one item kind",
        ),
    ] {
        let errors = parse_xray_json(&udp_config(settings).to_string()).unwrap_err();
        assert!(
            errors
                .diagnostics
                .iter()
                .any(|d| d.message.contains(expected)),
            "{errors:?}"
        );
    }
    let mut cfg = udp_config(json!({}));
    cfg["outbounds"][0]["streamSettings"]["network"] = "raw".into();
    let errors = parse_xray_json(&cfg.to_string()).unwrap_err();
    assert!(errors
        .diagnostics
        .iter()
        .any(|d| d.message.contains("requires mKCP")));
    let mut cfg = udp_config(json!({}));
    let masks = cfg["outbounds"][0]["streamSettings"]["finalmask"]["udp"]
        .as_array_mut()
        .unwrap();
    masks.push(masks[0].clone());
    assert!(parse_xray_json(&cfg.to_string()).is_err());
}

fn quic_config(network: &str, alpn: &[&str], udp: Value) -> Value {
    let mut value: Value = serde_json::from_str(&config(json!([]))).unwrap();
    value["outbounds"][0]["streamSettings"] = json!({"network":network,"security":"tls",
        "tlsSettings":{"serverName":"server.example","alpn":alpn},
        "finalmask":{"udp":udp,"quicParams":{"disableChromeParrot":true}}});
    if network == "hysteria" {
        value["outbounds"][0] = json!({"tag":"proxy","protocol":"hysteria",
            "settings":{"version":2,"address":"192.0.2.1","port":443},
            "streamSettings":value["outbounds"][0]["streamSettings"].clone()});
        value["outbounds"][0]["streamSettings"]["hysteriaSettings"] =
            json!({"version":2,"auth":"synthetic"});
    }
    value
}

#[test]
fn udp_header_custom_takes_its_place_on_hysteria_and_xhttp_h3() {
    let header = json!({"type":"header-custom","settings":{"mode":"standalone",
        "client":[{"type":"str","packet":"hi"}],"server":[{"type":"str","packet":"ok"}]}});
    let salamander = json!({"type":"salamander","settings":{"password":"synthetic"}});
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"nz"}]}});
    for (udp, before_salamander, before_noise) in [
        (json!([header]), false, false),
        (json!([header, salamander]), true, false),
        (json!([salamander, header]), false, false),
        (json!([noise, header, salamander]), true, false),
        (json!([header, noise]), false, true),
    ] {
        let parsed = parse_xray_json(&quic_config("hysteria", &["h3"], udp.clone()).to_string())
            .unwrap_or_else(|e| panic!("{udp}: {e:?}"));
        let parsed = parsed.config.outbounds[0]
            .stream
            .udp_header_custom
            .clone()
            .unwrap();
        assert!(parsed.standalone);
        assert_eq!(
            (parsed.before_salamander, parsed.before_noise),
            (before_salamander, before_noise),
            "{udp}"
        );
    }
    let parsed =
        parse_xray_json(&quic_config("xhttp", &["h3"], json!([noise, header])).to_string())
            .unwrap();
    let parsed = parsed.config.outbounds[0]
        .stream
        .udp_header_custom
        .clone()
        .unwrap();
    assert!(!parsed.before_noise);
    // XHTTP over TCP has no datagrams to mask.
    let errors =
        parse_xray_json(&quic_config("xhttp", &["h2"], json!([header])).to_string()).unwrap_err();
    assert!(errors
        .diagnostics
        .iter()
        .any(|d| d.message.contains("requires mKCP, Hysteria or XHTTP")));
    // Xray-core's state never matches under udphop: refused.
    let hop = json!({"type":"udphop","settings":{"mode":"intervalLocal","remotePorts":"443,8443"}});
    let errors =
        parse_xray_json(&quic_config("hysteria", &["h3"], json!([header, hop])).to_string())
            .unwrap_err();
    assert!(errors
        .diagnostics
        .iter()
        .any(|d| d.message.contains("cannot be combined with udphop")));
}
