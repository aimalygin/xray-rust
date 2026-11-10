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
fn null_proxy_settings_is_absent_as_in_xray() {
    // Xray decodes null into a nil *json.RawMessage (infra/conf/xray.go), so panel output with
    // explicit null fields loads with or without dialerProxy.
    let mut raw = json!({"outbounds":[
        {"tag":"entry","protocol":"http","settings":{"address":"192.0.2.10","port":8080},
        "proxySettings":null,"streamSettings":{"sockopt":{"dialerProxy":"exit"}}},
        {"tag":"exit","protocol":"freedom"}
    ]});
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(
        parsed.config.outbounds[0]
            .proxy_settings
            .as_ref()
            .unwrap()
            .tag,
        "exit"
    );
    raw["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("streamSettings");
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert!(parsed.diagnostics.is_empty());
    assert!(parsed.config.outbounds[0].proxy_settings.is_none());
}

#[test]
fn udp_hop_mask_reads_every_xray_mode_and_remote_ips() {
    let mut raw = hysteria();
    let settings = json!({"mode":"intervalRemote,intervalLocal","remotePorts":"443,8443-8444","interval":"10-5"});
    raw["outbounds"][0]["streamSettings"]["finalmask"]["udp"] =
        json!([{"type":"UDPHOP","settings":settings}]);
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert!(parsed.diagnostics.is_empty());
    let hop = |raw: &Value| {
        parse_xray_json(&raw.to_string()).unwrap().config.outbounds[0]
            .stream
            .quic_params
            .clone()
            .unwrap()
            .udp_hop
    };
    let both = hop(&raw);
    assert_eq!(both.ports, [443, 8443, 8444]);
    assert_eq!((both.interval.from, both.interval.to), (5, 10));
    assert_eq!(
        (both.local, both.remote, both.remote_once),
        (true, true, false)
    );
    // Each mode alone, in any case and repeated, as Xray reads them.
    for (mode, expected) in [
        ("intervalLocal", (true, false, false)),
        ("INTERVALREMOTE", (false, true, false)),
        ("perConnRemote", (false, false, true)),
        (
            "perConnRemote,intervalLocal,perconnremote",
            (true, false, true),
        ),
    ] {
        let mut one = raw.clone();
        one["outbounds"][0]["streamSettings"]["finalmask"]["udp"][0]["settings"]["mode"] =
            json!(mode);
        let read = hop(&one);
        assert_eq!(
            (read.local, read.remote, read.remote_once),
            expected,
            "{mode}"
        );
    }
    // Remote IPs are IPs or prefixes, and no ports are needed with them.
    let mut ips = raw.clone();
    let settings = &mut ips["outbounds"][0]["streamSettings"]["finalmask"]["udp"][0]["settings"];
    settings["remoteIPs"] = json!(["192.0.2.7", "198.51.100.0/24", "2001:db8::/64"]);
    settings["remotePorts"] = json!(null);
    let read = hop(&ips);
    assert!(read.ports.is_empty());
    assert_eq!(
        read.remote_ips
            .iter()
            .map(|cidr| (cidr.network().to_string(), cidr.prefix()))
            .collect::<Vec<_>>(),
        [
            ("192.0.2.7".to_owned(), 32),
            ("198.51.100.0".to_owned(), 24),
            ("2001:db8::".to_owned(), 64),
        ]
    );
    for (key, bad) in [
        // Xray splits the mode without trimming and refuses an empty part.
        ("mode", json!("intervalLocal, intervalRemote")),
        ("mode", json!("")),
        ("mode", json!(null)),
        ("mode", json!("intervalLocal,")),
        ("mode", json!("perConn")),
        ("mode", json!(1)),
        ("remoteIPs", json!(["192.0.2.1/33"])),
        ("remoteIPs", json!(["example.com"])),
        ("remoteIPs", json!(["[2001:db8::1]"])),
        ("remoteIPs", json!(["192.0.2.0/024"])),
        ("remoteIPs", json!("192.0.2.1")),
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

fn xhttp(alpn: Value, finalmask: Value) -> Value {
    json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"server.example","port":443,
            "users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},
        "streamSettings":{"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"server.example","alpn":alpn},
            "finalmask":finalmask}}]})
}

#[test]
fn udp_hop_mask_hops_xhttp_over_h3_like_hysteria() {
    let mask = json!({"type":"udphop","settings":{"mode":"intervalLocal,intervalRemote",
        "remotePorts":"20000-20002","interval":"5-10"}});
    let parrot = json!({"disableChromeParrot":true});
    let raw = xhttp(json!(["h3"]), json!({"udp":[mask],"quicParams":parrot}));
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let hop = &parsed.config.outbounds[0]
        .stream
        .quic_params
        .as_ref()
        .unwrap()
        .udp_hop;
    assert_eq!(hop.ports, [20000, 20001, 20002]);
    assert_eq!((hop.interval.from, hop.interval.to), (5, 10));
    // Without exact h3 ALPN XHTTP runs over TCP, where there is nothing to hop.
    for alpn in [json!(["h2"]), json!(["h3", "h2"])] {
        let raw = xhttp(alpn.clone(), json!({"udp":[mask]}));
        assert!(parse_xray_json(&raw.to_string()).is_err(), "{alpn}");
    }
}

#[test]
fn udp_hop_mask_is_last_as_xray_dials_it() {
    let hop =
        json!({"type":"udphop","settings":{"mode":"intervalLocal","remotePorts":"20000-20002"}});
    let salamander = json!({"type":"salamander","settings":{"password":"synthetic"}});
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"nz"}]}});
    let parrot = json!({"disableChromeParrot":true});
    let with = |udp: Value| {
        let mut raw = hysteria();
        raw["outbounds"][0]["streamSettings"]["finalmask"] = json!({"udp":udp,"quicParams":parrot});
        parse_xray_json(&raw.to_string())
    };
    for udp in [
        json!([hop]),
        json!([salamander, hop]),
        json!([noise, salamander, hop]),
        json!([salamander, noise, hop]),
    ] {
        let parsed = with(udp.clone()).unwrap_or_else(|e| panic!("{udp}: {e:?}"));
        let hop = &parsed.config.outbounds[0]
            .stream
            .quic_params
            .as_ref()
            .unwrap()
            .udp_hop;
        assert_eq!(hop.ports, [20000, 20001, 20002], "{udp}");
    }
    // Xray-core reverses the list and dials only an outermost udphop; a mask
    // after it fails every dial with "incorrect index".
    for udp in [json!([hop, salamander]), json!([salamander, hop, noise])] {
        let errors = with(udp.clone()).unwrap_err();
        assert!(
            errors
                .diagnostics
                .iter()
                .any(|d| d.message.contains("must be the last UDP mask")),
            "{udp}: {errors:?}"
        );
    }
}

#[test]
fn legacy_udp_hop_hint_points_only_quic_carriers_at_the_udphop_mask() {
    let hint = |raw: &Value| -> String {
        let parsed = parse_xray_json(&raw.to_string()).unwrap();
        let [message] = parsed
            .diagnostics
            .into_iter()
            .map(|d| d.message)
            .filter(|message| message.contains("legacy udpHop"))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        message
    };
    let legacy = json!({"udpHop":{"ports":"443"},"disableChromeParrot":true});
    let mut hysteria = hysteria();
    hysteria["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"] = legacy.clone();
    let h3 = xhttp(json!(["h3"]), json!({"quicParams":legacy}));
    for raw in [hysteria, h3] {
        assert!(hint(&raw).contains("migrate to finalmask.udp udphop"));
    }
    let h2 = xhttp(
        json!(["h2"]),
        json!({"quicParams":{"udpHop":{"ports":"443"}}}),
    );
    let message = hint(&h2);
    assert!(message.contains("has no effect"), "{message}");
}

#[test]
fn chrome_parrot_needs_no_acknowledgement_and_transport_switches_parse_as_go_bools() {
    // ChromeParrot is Xray's default and ours: a Hysteria outbound without
    // finalmask parses clean.
    let mut raw = hysteria();
    raw["outbounds"][0]["streamSettings"]
        .as_object_mut()
        .unwrap()
        .remove("finalmask");
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    assert!(
        !parsed
            .diagnostics
            .iter()
            .any(|d| d.message.contains("ChromeParrot")),
        "{:?}",
        parsed.diagnostics
    );
    // Go leaves a bool false for null and rejects a string.
    for key in [
        "disableChromeParrot",
        "disableGSO",
        "disableStatelessReset",
        "brutalDisableLossCompensation",
    ] {
        let mut invalid = hysteria();
        invalid["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"][key] = json!("true");
        assert!(parse_xray_json(&invalid.to_string()).is_err(), "{key}");
        for (value, expected) in [
            (Value::Null, false),
            (json!(false), false),
            (json!(true), true),
        ] {
            let mut raw = hysteria();
            raw["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"][key] = value;
            let parsed =
                parse_xray_json(&raw.to_string()).unwrap_or_else(|e| panic!("{key}: {e:?}"));
            let quic = parsed.config.outbounds[0]
                .stream
                .quic_params
                .as_ref()
                .unwrap();
            let actual = match key {
                "disableChromeParrot" => quic.disable_chrome_parrot,
                "disableGSO" => quic.disable_gso,
                "disableStatelessReset" => quic.disable_stateless_reset,
                _ => quic.brutal_disable_loss_compensation,
            };
            assert_eq!(actual, expected, "{key}");
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
            .any(|d| d.message.contains("WireGuard domainStrategy is not read")));
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

/// The legacy spelling hops the local socket and the remote port together,
/// and only when it has ports to hop between.
#[test]
fn legacy_udp_hop_hops_both_ways_and_only_with_ports() {
    let hop = |udp_hop: Value| {
        let mut raw = hysteria();
        raw["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"] =
            json!({"udpHop": udp_hop, "disableChromeParrot": true});
        let hop = parse_xray_json(&raw.to_string()).unwrap().config.outbounds[0]
            .stream
            .quic_params
            .clone()
            .unwrap()
            .udp_hop;
        (hop.local, hop.remote, hop.remote_once)
    };
    assert_eq!(hop(json!({"ports": "443,8443"})), (true, true, false));
    assert_eq!(hop(json!({"ports": null})), (false, false, false));
    assert_eq!(hop(json!({"ports": 0})), (false, false, false));
}
