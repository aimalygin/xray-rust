use serde_json::{json, Value};
use xray_config::{parse_xray_json, FragmentRange};

fn settings() -> Value {
    json!({"packets":"tlshello","length":"100-200","delay":0,"maxSplit":8})
}
fn profile(fragment: Value) -> Value {
    json!({"outbounds":[{"protocol":"freedom","streamSettings":{"finalmask":{"tcp":[{"type":"FrAgMeNt","settings":fragment}]}}}]})
}
fn legacy_profile() -> Value {
    json!({"outbounds":[
        {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com"},"sockopt":{"dialerProxy":"fragment"}}},
        {"protocol":"freedom","tag":"fragment","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"1-2","maxSplit":8}}}
    ]})
}

#[test]
fn finalmask_sequences_override_scalars_and_normalize_ranges() {
    let mut config = settings();
    config["length"] = json!(0);
    config["lengths"] = json!([1, "200-100"]);
    config["delays"] = json!([0, "2-1"]);
    let parsed = parse_xray_json(&profile(config).to_string()).unwrap();
    let fragment = parsed.config.outbounds[0]
        .stream
        .tcp_fragment
        .as_ref()
        .unwrap();
    assert_eq!(
        fragment.lengths,
        [
            FragmentRange { from: 1, to: 1 },
            FragmentRange { from: 100, to: 200 }
        ]
    );
    assert_eq!(
        fragment.delays_ms,
        [
            FragmentRange { from: 0, to: 0 },
            FragmentRange { from: 1, to: 2 }
        ]
    );
    assert_eq!(fragment.max_split, FragmentRange { from: 8, to: 8 });
}

#[test]
fn legacy_dialer_proxy_normalizes_only_dedicated_fragment_handlers() {
    let config = legacy_profile();
    let parsed = parse_xray_json(&config.to_string()).unwrap();
    assert_eq!(
        parsed.config.outbounds[0].stream.tcp_fragment,
        parsed.config.outbounds[1].stream.tcp_fragment
    );
    for (path, value) in [
        (
            "/outbounds/0/streamSettings/sockopt/dialerProxy",
            json!("missing"),
        ),
        (
            "/outbounds/0/streamSettings/sockopt/dialerProxy",
            json!("proxy"),
        ),
        ("/outbounds/0/streamSettings/sockopt/dialerProxy", json!(5)),
        ("/outbounds/1/settings/fragment/packets", json!("1-3")),
        ("/outbounds/1/settings/fragment/interval", Value::Null),
    ] {
        let mut invalid = config.clone();
        *invalid.pointer_mut(path).unwrap() = value;
        assert!(
            parse_xray_json(&invalid.to_string()).is_err(),
            "{path}: {invalid}"
        );
    }
    for extra in [
        json!({"sockopt":{}}),
        json!({"sockopt":{"dialerProxy":"proxy"}}),
        json!({"security":"tls"}),
    ] {
        let mut invalid = config.clone();
        invalid["outbounds"][1]["streamSettings"] = extra;
        assert!(parse_xray_json(&invalid.to_string()).is_err(), "{invalid}");
    }
    let mut invalid = config;
    invalid["outbounds"][0]["streamSettings"]["finalmask"] =
        profile(settings())["outbounds"][0]["streamSettings"]["finalmask"].clone();
    assert!(parse_xray_json(&invalid.to_string()).is_err());
}

#[test]
fn unsupported_masks_and_unbounded_values_fail_closed() {
    for (key, value) in [
        ("packets", json!("")),
        ("packets", json!("1-3")),
        ("length", json!(0)),
        ("length", json!(-1)),
        ("length", json!(16385)),
        ("lengths", json!([0, 1])),
        ("lengths", json!(vec![1; 17])),
        ("delay", json!(1001)),
        ("maxSplit", json!(4097)),
        ("interval", json!(0)),
        ("unknown", json!(true)),
    ] {
        let mut value_settings = settings();
        value_settings[key] = value;
        let raw = profile(value_settings).to_string();
        assert!(parse_xray_json(&raw).is_err(), "{raw}");
    }
    for mask in [
        json!({}),
        json!([{"type":"noise"}]),
        json!([{"type":"fragment","settings":settings()},{"type":"fragment","settings":settings()}]),
    ] {
        let mut config = profile(settings());
        config["outbounds"][0]["streamSettings"]["finalmask"]["tcp"] = mask;
        assert!(parse_xray_json(&config.to_string()).is_err());
    }
    for protocol in ["dns", "blackhole"] {
        let mut config = profile(settings());
        config["outbounds"][0]["protocol"] = json!(protocol);
        assert!(parse_xray_json(&config.to_string()).is_err());
    }
    let mut config = legacy_profile();
    config["outbounds"][0]["streamSettings"]["network"] = json!("xhttp");
    config["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] = json!(["h3"]);
    assert!(parse_xray_json(&config.to_string()).is_err());
}
