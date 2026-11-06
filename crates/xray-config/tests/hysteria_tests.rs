use serde_json::{json, Value};
use xray_config::{parse_xray_json, Network, OutboundSettings, StreamSecurity, StreamTransport};

fn example() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/configs/hysteria2.json"
    ))
    .unwrap()
}

#[test]
fn hysteria2_canonical_profile_and_method_alias() {
    for method in [false, true] {
        let mut value = example();
        if method {
            value["outbounds"][0]["streamSettings"]["method"] = json!("hysteria");
            value["outbounds"][0]["streamSettings"]["network"] = json!("raw");
        }
        let parsed = parse_xray_json(&value.to_string()).unwrap();
        assert!(parsed.diagnostics.is_empty());
        let outbound = &parsed.config.outbounds[0];
        assert_eq!(outbound.stream.network, Network::Udp);
        assert!(matches!(outbound.settings, OutboundSettings::Hysteria(_)));
        let StreamTransport::Hysteria(auth) = &outbound.stream.transport else {
            panic!()
        };
        assert_eq!(auth.auth.as_str(), "synthetic-example-auth");
        assert!(!format!("{outbound:?}").contains("synthetic-example-auth"));
        let StreamSecurity::Tls(tls) = &outbound.stream.security else {
            panic!()
        };
        assert!(tls.fingerprint.is_none(), "Hysteria uses native QUIC TLS");
    }
}

#[test]
fn hysteria2_rejects_unsupported_or_inconsistent_settings_without_exposing_auth() {
    for (path, replacement) in [
        ("/outbounds/0/settings/version", json!(1)),
        ("/outbounds/0/settings/version", Value::Null),
        ("/outbounds/0/settings/port", json!(0)),
        ("/outbounds/0/settings/port", json!(65536)),
        ("/outbounds/0/settings/address", json!("bad address")),
        ("/outbounds/0/settings/address", json!("")),
        ("/outbounds/0/streamSettings/network", json!("raw")),
        ("/outbounds/0/streamSettings/security", json!("none")),
        (
            "/outbounds/0/streamSettings/tlsSettings/alpn",
            json!(["h2"]),
        ),
        (
            "/outbounds/0/streamSettings/hysteriaSettings/version",
            json!(1),
        ),
        (
            "/outbounds/0/streamSettings/hysteriaSettings/auth",
            json!(""),
        ),
        (
            "/outbounds/0/streamSettings/hysteriaSettings/auth",
            json!("secret\r\nheader"),
        ),
        (
            "/outbounds/0/streamSettings/hysteriaSettings/auth",
            json!("x".repeat(4097)),
        ),
    ] {
        let mut value = example();
        *value.pointer_mut(path).unwrap() = replacement;
        let error = parse_xray_json(&value.to_string()).unwrap_err();
        assert!(
            !format!("{error:?}").contains("synthetic-example-auth"),
            "{path}"
        );
        assert!(!format!("{error:?}").contains("secret"), "{path}");
    }
    for (parent, key, value) in [
        (
            "/outbounds/0",
            "proxySettings",
            json!({"tag":"direct","transportLayer":true}),
        ),
        ("/outbounds/0/settings", "udpIdleTimeout", json!(60)),
        (
            "/outbounds/0/streamSettings",
            "finalmask",
            json!({"quicParams":{"bbrProfile":"aggressive"}}),
        ),
        (
            "/outbounds/0/streamSettings",
            "sockopt",
            json!({"dialerProxy":"direct"}),
        ),
        (
            "/outbounds/0/streamSettings",
            "sockopt",
            json!({"domainStrategy":"UseIPv4"}),
        ),
        (
            "/outbounds/0/streamSettings/tlsSettings",
            "fingerprint",
            json!("chrome"),
        ),
        (
            "/outbounds/0/streamSettings/tlsSettings",
            "allowInsecure",
            json!(true),
        ),
        (
            "/outbounds/0/streamSettings/hysteriaSettings",
            "up",
            json!(100),
        ),
        (
            "/outbounds/0/streamSettings/hysteriaSettings",
            "obfs",
            json!("salamander"),
        ),
    ] {
        let mut config = example();
        config.pointer_mut(parent).unwrap()[key] = value;
        assert!(
            parse_xray_json(&config.to_string()).is_err(),
            "accepted {parent}/{key}"
        );
    }
}

#[test]
fn hysteria2_takes_socket_options_for_its_quic_socket() {
    let mut config = example();
    config["outbounds"][0]["streamSettings"]["sockopt"] = json!({
        "mark": 255,
        "interface": "eth0",
        "tcpFastOpen": true,
        "customSockopt": [{"network": "udp", "level": "41", "opt": "67", "value": "1", "type": "int"}],
        "happyEyeballs": {"tryDelayMs": 250}
    });
    let parsed = parse_xray_json(&config.to_string()).expect("Hysteria socket options parse");
    let options = parsed.config.outbounds[0]
        .stream
        .socket_options
        .as_ref()
        .expect("socket options kept");
    assert_eq!(options.mark, 255);
    assert_eq!(options.interface, "eth0");
    assert_eq!(options.tcp_fast_open, 256);
    assert_eq!(options.custom.len(), 1);
}

#[test]
fn hysteria2_omitted_alpn_and_empty_fingerprint_use_h3_without_shaping() {
    let mut config = example();
    let tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
        .as_object_mut()
        .unwrap();
    tls.remove("alpn");
    tls.insert("fingerprint".into(), json!(""));
    assert!(parse_xray_json(&config.to_string()).is_ok());
    config["outbounds"][0]["protocol"] = json!("freedom");
    config["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("settings");
    assert!(parse_xray_json(&config.to_string()).is_err());
}

#[test]
fn hysteria_salamander_hopping_and_fail_closed_masks() {
    let mut config = example();
    config["outbounds"][0]["streamSettings"]["finalmask"] = json!({
        "udp":[{"type":"salamander","settings":{"password":"synthetic-secret"}}],
        "quicParams":{"udpHop":{"ports":"8443,9000-9002", "interval":"5-8"}}
    });
    let parsed = parse_xray_json(&config.to_string()).unwrap();
    let stream = &parsed.config.outbounds[0].stream;
    let StreamTransport::Hysteria(settings) = &stream.transport else {
        panic!()
    };
    assert_eq!(
        settings.salamander_password.as_deref().unwrap().as_str(),
        "synthetic-secret"
    );
    assert!(!format!("{stream:?}").contains("synthetic-secret"));
    assert_eq!(
        stream.quic_params.as_ref().unwrap().udp_hop.ports,
        [8443, 9000, 9001, 9002]
    );
    for mask in [
        json!([{"type":"salamander","settings":{"password":"abc"}}]),
        json!([{"type":"salamander","settings":{"password":"synthetic-secret", "packetSize":"0-512"}}]),
        json!([{"type":"salamander","settings":{"password":"synthetic-secret", "unknown":true}}]),
        json!([{"type":"noise","settings":{"noise":[{"rand":4097}]}}]),
        json!([{"type":"salamander","settings":{"password":"synthetic-secret"}}, {"type":"salamander","settings":{"password":"synthetic-secret"}}]),
        json!({"type":"salamander"}),
    ] {
        let mut invalid = config.clone();
        invalid["outbounds"][0]["streamSettings"]["finalmask"]["udp"] = mask;
        let error = parse_xray_json(&invalid.to_string()).unwrap_err();
        assert!(!format!("{error:?}").contains("synthetic-secret"));
    }
    for quic in [
        json!({"bbrProfile":"conservative"}),
        json!({"congestion":"force-brutal"}),
        json!({"udpHop":{"ports":"1-65535,1"}}),
        json!({"udpHop":{"ports":443,"interval":4}}),
    ] {
        let mut invalid = config.clone();
        invalid["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"] = quic;
        assert!(parse_xray_json(&invalid.to_string()).is_err());
    }
    config["outbounds"][0]["streamSettings"]["method"] = json!("HYSTERIA");
    config["outbounds"][0]["streamSettings"]["network"] = json!("raw");
    assert!(parse_xray_json(&config.to_string()).is_ok());
}

#[test]
fn salamander_packet_size_selects_gecko_like_xray() {
    let parse = |size: Value| {
        let mut config = example();
        config["outbounds"][0]["streamSettings"]["finalmask"] = json!({
            "udp":[{"type":"salamander","settings":{"password":"synthetic-secret","packetSize":size}}]
        });
        parse_xray_json(&config.to_string()).map(|parsed| {
            let StreamTransport::Hysteria(settings) = &parsed.config.outbounds[0].stream.transport
            else {
                panic!()
            };
            assert!(settings.salamander_password.is_some());
            settings.gecko_packet_size.map(|r| (r.from, r.to))
        })
    };
    // Xray's Int32Range: an upper bound of zero or less keeps Salamander.
    for plain in [
        Value::Null,
        json!(0),
        json!("0"),
        json!(""),
        json!(-5),
        json!("-5"),
        json!("-10--1"),
    ] {
        assert_eq!(parse(plain.clone()).unwrap(), None, "{plain}");
    }
    for (size, expected) in [
        (json!(512), (512, 512)),
        (json!("512"), (512, 512)),
        (json!("200-400"), (200, 400)),
        (json!("400-200"), (200, 400)),
        (json!("1-2048"), (1, 2048)),
    ] {
        assert_eq!(parse(size.clone()).unwrap(), Some(expected), "{size}");
    }
    for invalid in [
        json!("0-512"),
        json!("-5-10"),
        json!(2049),
        json!("100-2049"),
        json!(true),
        json!(1.5),
        json!("abc"),
        json!("5-"),
        json!({"from":1,"to":2}),
        json!(4_294_967_296_i64),
    ] {
        let error = parse(invalid.clone()).unwrap_err();
        let text = format!("{error:?}");
        assert!(text.contains("packetSize"), "{invalid}: {text}");
        assert!(!text.contains("synthetic-secret"));
    }
}
