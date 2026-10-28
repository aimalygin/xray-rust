use serde_json::{json, Value};
use xray_config::{parse_xray_json, OutboundSettings};

fn hysteria() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/configs/hysteria2.json"
    ))
    .unwrap()
}

#[test]
fn dialer_proxy_matches_legacy_and_rejects_conflicts() {
    let mut raw = json!({"outbounds":[
        {"tag":"entry","protocol":"http","settings":{"address":"192.0.2.10","port":8080},
        "streamSettings":{"sockopt":{"dialerProxy":"exit"}}},
        {"tag":"exit","protocol":"freedom"}
    ]});
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert!(parsed.diagnostics.is_empty());
    let edge = parsed.config.outbounds[0].proxy_settings.clone();
    assert_eq!(edge.as_ref().unwrap().tag, "exit");
    assert!(edge.as_ref().unwrap().transport_layer);
    raw["outbounds"][0]["proxySettings"] = json!({"tag":"exit","transportLayer":true});
    assert!(parse_xray_json(&raw.to_string()).is_err());
    raw["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("streamSettings");
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert_eq!(parsed.config.outbounds[0].proxy_settings, edge);
    assert!(parsed
        .diagnostics
        .iter()
        .any(|d| d.message.contains("legacy proxySettings")));
}

#[test]
fn udp_hop_mask_normalizes_supported_mode_and_rejects_unimplemented_modes() {
    let mut raw = hysteria();
    let settings = json!({"mode":"intervalRemote,intervalLocal","remotePorts":"443,8443-8444","interval":"10-5"});
    raw["outbounds"][0]["streamSettings"]["finalmask"]["udp"] =
        json!([{"type":"UDPHOP","settings":settings}]);
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert!(parsed.diagnostics.is_empty());
    let hop = &parsed.config.outbounds[0]
        .stream
        .quic_params
        .as_ref()
        .unwrap()
        .udp_hop;
    assert_eq!(hop.ports, [443, 8443, 8444]);
    assert_eq!((hop.interval.from, hop.interval.to), (5, 10));
    for (key, bad) in [
        ("mode", json!("intervalRemote")),
        ("mode", json!("perConnRemote")),
        ("mode", json!("intervalLocal")),
        ("remoteIPs", json!(["192.0.2.1"])),
        ("remotePorts", json!([])),
        ("remotePorts", json!(0)),
        ("interval", json!("0-5")),
        ("interval", json!(4)),
    ] {
        let mut invalid = raw.clone();
        invalid["outbounds"][0]["streamSettings"]["finalmask"]["udp"][0]["settings"][key] = bad;
        assert!(parse_xray_json(&invalid.to_string()).is_err(), "{key}");
    }
    raw["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"]["udpHop"] =
        json!({"ports":443});
    assert!(parse_xray_json(&raw.to_string()).is_err());
}

#[test]
fn quic_fingerprint_limit_is_explicit_and_unimplemented_controls_fail_closed() {
    let mut raw = hysteria();
    raw["outbounds"][0]["streamSettings"]
        .as_object_mut()
        .unwrap()
        .remove("finalmask");
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert!(parsed
        .diagnostics
        .iter()
        .any(|d| d.message.contains("ChromeParrot")));
    for key in [
        "disableChromeParrot",
        "disableGSO",
        "disableStatelessReset",
        "brutalDisableLossCompensation",
    ] {
        for bad in [Value::Null, json!(false), json!("true")] {
            let mut invalid = hysteria();
            invalid["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"][key] = bad;
            assert!(parse_xray_json(&invalid.to_string()).is_err(), "{key}");
        }
    }
}

#[test]
fn wireguard_remote_dns_defaults_literals_and_legacy_diagnostic() {
    let raw: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/configs/wireguard.json"
    ))
    .unwrap();
    for (value, count) in [
        (Value::Null, 4),
        (json!([]), 4),
        (json!(["192.0.2.53", "2001:db8::53"]), 2),
    ] {
        let mut raw = raw.clone();
        raw["outbounds"][0]["settings"]["remoteDNS"] = value;
        let parsed = parse_xray_json(&raw.to_string()).unwrap();
        let OutboundSettings::Wireguard(settings) = &parsed.config.outbounds[0].settings else {
            panic!()
        };
        assert_eq!(settings.remote_dns.len(), count);
        raw["outbounds"][0]["settings"]["domainStrategy"] = json!("ForceIPv4");
        assert!(parse_xray_json(&raw.to_string())
            .unwrap()
            .diagnostics
            .iter()
            .any(|d| d.message.contains("legacy WireGuard")));
    }
    for bad in [
        json!(["dns.example"]),
        json!(["0.0.0.0"]),
        json!(["::"]),
        json!(["fe80::1"]),
        json!(vec!["192.0.2.53"; 9]),
    ] {
        let mut raw = raw.clone();
        raw["outbounds"][0]["settings"]["remoteDNS"] = bad;
        assert!(parse_xray_json(&raw.to_string()).is_err());
    }
}
