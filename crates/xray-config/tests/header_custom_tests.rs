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
            "fragments the handshake",
        ),
        (
            json!([header.clone(), header.clone()]),
            "only one fragment and one header-custom",
        ),
        (
            json!([{"type": "sudoku"}]),
            "only one fragment and one header-custom",
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
