use serde_json::{json, Value};
use xray_config::{parse_xray_json, FragmentPackets, FragmentRange, TcpFragmentSettings};

/// A fragment mask folded from a dedicated freedom handler: the handler's own
/// mask, which also carries the handler's `finalRules` for connections from a
/// VLESS reverse proxy (none here).
fn assert_folded(folded: &Option<TcpFragmentSettings>, handler: &Option<TcpFragmentSettings>) {
    let folded = folded.as_ref().expect("a folded mask");
    assert_eq!(folded.folded_final_rules, Some(Vec::new()));
    assert_eq!(
        Some(TcpFragmentSettings {
            folded_final_rules: None,
            ..folded.clone()
        }),
        *handler
    );
}

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
fn dialer_proxy_chain_through_a_fragment_user_does_not_depend_on_outbound_order() {
    let legacy = legacy_profile();
    let vless = legacy["outbounds"][0].clone();
    let fragment = legacy["outbounds"][1].clone();
    let mut entry = vless.clone();
    entry["tag"] = json!("entry");
    entry["streamSettings"]["sockopt"]["dialerProxy"] = json!("chain");
    let chain = json!({"protocol":"freedom","tag":"chain",
        "streamSettings":{"sockopt":{"dialerProxy":"fragment"}}});
    // Xray resolves dialerProxy tags at dial time, so both orders are one config.
    for outbounds in [
        [entry.clone(), chain.clone(), fragment.clone()],
        [chain.clone(), fragment.clone(), entry.clone()],
    ] {
        let parsed = parse_xray_json(&json!({ "outbounds": outbounds }).to_string())
            .unwrap_or_else(|error| panic!("{outbounds:?}: {error:?}"));
        let by_tag = |tag: &str| {
            parsed
                .config
                .outbounds
                .iter()
                .find(|o| o.tag.as_deref() == Some(tag))
                .unwrap()
        };
        assert_folded(
            &by_tag("chain").stream.tcp_fragment,
            &by_tag("fragment").stream.tcp_fragment,
        );
        assert!(by_tag("entry").stream.tcp_fragment.is_none());
        assert_eq!(
            by_tag("entry").proxy_settings.as_ref().unwrap().tag,
            "chain"
        );
    }
}

#[test]
fn freedom_fragment_parses_with_the_upstream_deprecation_warning() {
    let parsed = parse_xray_json(&legacy_profile().to_string()).unwrap();
    let warnings: Vec<_> = parsed
        .diagnostics
        .iter()
        .map(|d| (d.path.as_deref(), d.message.as_str()))
        .collect();
    assert_eq!(
        warnings,
        [(
            Some("$.outbounds[1].settings.fragment"),
            "freedom `fragment` is deprecated; use a fragment mask in `streamSettings.finalmask.tcp`"
        )]
    );
    assert!(parsed.config.outbounds[1].stream.tcp_fragment.is_some());

    let finalmask = parse_xray_json(&profile(settings()).to_string()).unwrap();
    assert!(finalmask.diagnostics.is_empty());
}

#[test]
fn legacy_dialer_proxy_normalizes_only_dedicated_fragment_handlers() {
    let config = legacy_profile();
    let parsed = parse_xray_json(&config.to_string()).unwrap();
    assert_folded(
        &parsed.config.outbounds[0].stream.tcp_fragment,
        &parsed.config.outbounds[1].stream.tcp_fragment,
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
        ("/outbounds/1/settings/fragment/packets", json!("0-3")),
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

/// Xray-core opens the socket in the freedom handler, whose `sockopt` is
/// empty, so the caller's socket options never reach it; what the caller's
/// dial reads is kept.
#[test]
fn an_inlined_fragment_handler_drops_the_callers_socket_options() {
    let mut config = legacy_profile();
    config["outbounds"][0]["streamSettings"]["sockopt"] = json!({
        "dialerProxy": "fragment", "mark": 5, "interface": "eth0", "tcpKeepAliveIdle": 30,
        "customSockopt": [{"opt": "1", "type": "int"}],
        "happyEyeballs": {"tryDelayMs": 250}
    });
    let parsed = parse_xray_json(&config.to_string()).unwrap();
    let options = parsed.config.outbounds[0]
        .stream
        .socket_options
        .clone()
        .unwrap();
    assert_eq!(
        options,
        xray_config::SocketOptions {
            happy_eyeballs: options.happy_eyeballs,
            ..xray_config::SocketOptions::default()
        }
    );
    assert_eq!(
        options.happy_eyeballs.map(|settings| settings.try_delay_ms),
        Some(250)
    );
}

#[test]
fn unsupported_masks_and_unbounded_values_fail_closed() {
    for (key, value) in [
        ("packets", json!("0")),
        ("packets", json!("0-3")),
        ("packets", json!("3-1")),
        ("packets", json!("-1-3")),
        ("packets", json!("1-")),
        ("packets", json!("tls hello")),
        ("packets", json!(1)),
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

/// `packets` as Xray-core reads it: `tlshello` in any case, empty or absent
/// for every write, one write number or a `from-to` range counting from one.
#[test]
fn write_selectors_read_as_xray_reads_them() {
    let packets = |config: &Value| {
        parse_xray_json(&config.to_string())
            .unwrap()
            .config
            .outbounds[0]
            .stream
            .tcp_fragment
            .as_ref()
            .unwrap()
            .packets
    };
    for (value, expected) in [
        (json!("TLSHello"), FragmentPackets::TlsHello),
        (json!(""), FragmentPackets::AllWrites),
        (Value::Null, FragmentPackets::AllWrites),
        (json!("1-3"), FragmentPackets::Writes { from: 1, to: 3 }),
        (json!("5"), FragmentPackets::Writes { from: 5, to: 5 }),
        (json!("+2-4"), FragmentPackets::Writes { from: 2, to: 4 }),
    ] {
        let mut fragment = settings();
        fragment["packets"] = value.clone();
        assert_eq!(packets(&profile(fragment)), expected, "{value}");
    }
    let mut fragment = settings();
    fragment.as_object_mut().unwrap().remove("packets");
    assert_eq!(packets(&profile(fragment)), FragmentPackets::AllWrites);

    // The deprecated freedom spelling reads `packets` the same way, and its
    // handler's selector reaches the outbound that dials through it.
    let mut legacy = legacy_profile();
    legacy["outbounds"][1]["settings"]["fragment"]["packets"] = json!("1-3");
    let parsed = parse_xray_json(&legacy.to_string()).unwrap();
    assert_eq!(
        parsed.config.outbounds[0]
            .stream
            .tcp_fragment
            .as_ref()
            .unwrap()
            .packets,
        FragmentPackets::Writes { from: 1, to: 3 }
    );
}

/// Raw pieces go on any TCP carrier of a proxy, TLS or not, as Xray-core
/// cuts every TCP dial; `tlshello` still needs a TLS record.
#[test]
fn raw_pieces_need_a_tcp_carrier_but_no_tls() {
    let socks = |packets: &str| {
        json!({"outbounds":[{"protocol":"socks","settings":{"address":"192.0.2.10","port":1080},
            "streamSettings":{"finalmask":{"tcp":[{"type":"fragment","settings":
                {"packets":packets,"length":"1-5","delay":0}}]}}}]})
    };
    let refused = |config: &Value, message: &str| {
        let error = parse_xray_json(&config.to_string()).unwrap_err();
        assert!(
            error
                .diagnostics
                .iter()
                .any(|d| d.message.contains(message)),
            "{config}: {:?}",
            error.diagnostics
        );
    };
    assert!(parse_xray_json(&socks("1-3").to_string()).is_ok());
    assert!(parse_xray_json(&socks("").to_string()).is_ok());
    refused(&socks("tlshello"), "tlshello fragmentation requires");
    let mut websocket = socks("1-3");
    websocket["outbounds"][0]["streamSettings"]["network"] = json!("ws");
    assert!(parse_xray_json(&websocket.to_string()).is_ok());

    let mut kcp = socks("1-3");
    kcp["outbounds"][0]["streamSettings"]["network"] = json!("kcp");
    refused(&kcp, "fragmentation requires a TCP carrier");
    let mut blackhole = socks("1-3");
    blackhole["outbounds"][0]["protocol"] = json!("blackhole");
    blackhole["outbounds"][0]["settings"] = json!({});
    refused(&blackhole, "fragmentation requires a TCP carrier");
    let mut loopback = socks("1-3");
    loopback["outbounds"][0]["protocol"] = json!("loopback");
    loopback["outbounds"][0]["settings"] = json!({"inboundTag": "again"});
    refused(&loopback, "fragmentation requires a TCP carrier");

    // A raw freedom outbound cuts the writes it sends to the destination.
    let mut freedom = settings();
    freedom["packets"] = json!("1-2");
    assert!(parse_xray_json(&profile(freedom).to_string()).is_ok());
}
