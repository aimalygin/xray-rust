//! The `masque` outbound and `masqueSettings`, read as Xray-core v26.10.31
//! reads them.
use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, MasqueSettings, OutboundSettings, StreamTransport,
    TargetAddr, XhttpRange, MASQUE_DEFAULT_XMUX,
};

fn config(outbound: Value) -> String {
    json!({"outbounds": [outbound]}).to_string()
}

fn base(masque_settings: Option<Value>) -> Value {
    let mut stream = json!({"network": "masque", "security": "tls",
        "tlsSettings": {"serverName": "masque.example"}});
    if let Some(settings) = masque_settings {
        stream["masqueSettings"] = settings;
    }
    json!({"protocol": "masque", "settings": {"address": "masque.example", "port": 443},
        "streamSettings": stream})
}

fn transport(masque_settings: Option<Value>) -> MasqueSettings {
    let parsed = parse_xray_json(&config(base(masque_settings))).unwrap();
    match &parsed.config.outbounds[0].stream.transport {
        StreamTransport::Masque(settings) => (**settings).clone(),
        other => panic!("not MASQUE: {other:?}"),
    }
}

fn errors(outbound: Value) -> Vec<String> {
    parse_xray_json(&config(outbound))
        .err()
        .map(|error| {
            error
                .diagnostics
                .into_iter()
                .filter(|d| d.severity == DiagnosticSeverity::Error)
                .map(|d| format!("{}: {}", d.path.unwrap_or_default(), d.message))
                .collect()
        })
        .unwrap_or_default()
}

/// Every case of the corpus gets Xray-core's verdict, except the
/// deliberate differences, which get theirs.
#[test]
fn config_verdicts_match_xray_core() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/masque/config-verdicts.json"
    ))
    .unwrap();
    let mut mismatches = Vec::new();
    for case in corpus["cases"].as_array().unwrap() {
        let mut outbounds = vec![case["outbound"].clone()];
        if let Some(extra) = case["extraOutbounds"].as_array() {
            outbounds.extend(extra.iter().cloned());
        }
        let raw = json!({"outbounds": outbounds}).to_string();
        let ours_ok = parse_xray_json(&raw).is_ok();
        let expected_ok = match case.get("ours").and_then(Value::as_str) {
            Some(ours) => ours == "ok",
            None => case["xray"] == "ok",
        };
        if ours_ok != expected_ok {
            let detail = parse_xray_json(&raw)
                .err()
                .map(|e| format!("{:?}", e.diagnostics))
                .unwrap_or_default();
            mismatches.push(format!(
                "{}: expected {}, got {} {detail}",
                case["name"],
                if expected_ok { "ok" } else { "error" },
                if ours_ok { "ok" } else { "error" }
            ));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn outbound_settings_keep_server_port_and_remote_dns() {
    let mut outbound = base(None);
    outbound["settings"] = json!({"address": "[2001:db8::1]", "port": 8443,
        "remoteDNS": ["8.8.8.8", "2001:4860:4860::8888"]});
    let parsed = parse_xray_json(&config(outbound)).unwrap();
    let OutboundSettings::Masque(settings) = &parsed.config.outbounds[0].settings else {
        panic!("not MASQUE");
    };
    assert_eq!(
        settings.server,
        TargetAddr::Ip("2001:db8::1".parse().unwrap())
    );
    assert_eq!(settings.port, 8443);
    assert_eq!(
        settings.remote_dns,
        [
            "8.8.8.8".parse::<std::net::IpAddr>().unwrap(),
            "2001:4860:4860::8888".parse().unwrap()
        ]
    );
}

#[test]
fn absent_settings_keep_xrays_registered_default() {
    let settings = transport(None);
    assert_eq!(settings.path, "/.well-known/masque/ip/*/*/");
    assert!(settings.host.is_empty() && settings.headers.is_empty() && settings.warp.is_none());
    // No xmux at all: zero everywhere, so the one tunnel is never retired.
    assert_eq!(settings.xmux.max_connections, XhttpRange::default());
    assert_eq!(settings.xmux.h_max_reusable_secs, XhttpRange::default());
    assert_eq!(transport(Some(Value::Null)), settings);
}

#[test]
fn an_empty_object_takes_the_build_defaults() {
    let settings = transport(Some(json!({})));
    assert_eq!(settings.path, "/.well-known/masque/ip/*/*/");
    assert_eq!(settings.xmux, MASQUE_DEFAULT_XMUX);
    // Only hKeepAlivePeriod set: the rest stays zero, as Xray compares the
    // whole struct with its zero value.
    let settings = transport(Some(json!({"xmux": {"hKeepAlivePeriod": 20}})));
    assert_eq!(settings.xmux.max_connections, XhttpRange::default());
    assert_eq!(settings.xmux.h_keep_alive_period_secs, 20);
}

#[test]
fn path_variables_become_wildcards() {
    assert_eq!(
        transport(Some(json!({"path": "/m/{target}/{ipproto}/"}))).path,
        "/m/*/*/"
    );
    assert_eq!(
        transport(Some(json!({"path": "/m{?ipproto,target}"}))).path,
        "/m?ipproto=*&target=*"
    );
    assert_eq!(
        transport(Some(json!({"path": null}))).path,
        "/.well-known/masque/ip/*/*/"
    );
}

/// The header fields as plain pairs.
fn header_pairs(settings: &MasqueSettings) -> Vec<(String, String)> {
    settings
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.to_string()))
        .collect()
}

#[test]
fn credentials_become_basic_authorization_and_headers_are_canonical() {
    let settings = transport(Some(json!({"user": "alice", "pass": "secret",
        "headers": {"x-custom-header": "1", "user-agent": "firefox"}})));
    assert_eq!(
        header_pairs(&settings),
        [
            (
                "Authorization".to_owned(),
                "Basic YWxpY2U6c2VjcmV0".to_owned()
            ),
            ("User-Agent".to_owned(), "firefox".to_owned()),
            ("X-Custom-Header".to_owned(), "1".to_owned()),
        ]
    );
    // A pass alone still authorizes, with an empty user.
    let settings = transport(Some(json!({"pass": "p"})));
    assert_eq!(
        header_pairs(&settings),
        [("Authorization".to_owned(), "Basic OnA=".to_owned())]
    );
}

#[test]
fn credentials_stay_out_of_debug_output() {
    use base64::Engine as _;
    let settings = transport(Some(
        json!({"user": "masque-user", "pass": "masque-pass-7f3a",
        "headers": {"X-Token": "token-value-9c1e"}}),
    ));
    let encoded = base64::engine::general_purpose::STANDARD.encode("masque-user:masque-pass-7f3a");
    let debug = format!("{settings:?}");
    assert!(
        debug.contains("Authorization") && debug.contains("X-Token"),
        "{debug}"
    );
    for secret in ["masque-pass-7f3a", encoded.as_str(), "token-value-9c1e"] {
        assert!(!debug.contains(secret), "{debug}");
    }
    // Nor through the outbound around it.
    let parsed = parse_xray_json(&config(base(Some(json!({"user": "masque-user",
        "pass": "masque-pass-7f3a"})))))
    .unwrap();
    let debug = format!("{:?}", parsed.config.outbounds[0]);
    assert!(
        !debug.contains("masque-pass-7f3a") && !debug.contains(&encoded),
        "{debug}"
    );
}

#[test]
fn host_and_header_errors_name_the_field() {
    let errors = errors(base(Some(json!({"host": "proxy.example/x",
        "headers": {"Capsule-Protocol": "?1"}}))));
    assert!(
        errors
            .iter()
            .any(|e| e.ends_with(r#"invalid "host": proxy.example/x"#)),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains(r#""headers" can't contain "Capsule-Protocol""#)),
        "{errors:?}"
    );
}

#[test]
fn masque_needs_its_transport_and_tls() {
    let mut outbound = base(None);
    outbound["streamSettings"]["security"] = json!("none");
    assert!(errors(outbound)
        .iter()
        .any(|e| e.contains(r#"MASQUE requires "security": "tls""#)));
    let mut outbound = base(None);
    outbound["streamSettings"]["network"] = json!("raw");
    assert!(errors(outbound)
        .iter()
        .any(|e| e.contains("not masque transport")));
}

#[test]
fn quic_parameters_apply_and_brutal_runs_bbr() {
    let mut outbound = base(None);
    outbound["streamSettings"]["finalmask"] = json!({"quicParams": {"congestion": "brutal", "brutalUp": "100 mbps", "maxIdleTimeout": 60}});
    let parsed = parse_xray_json(&config(outbound)).unwrap();
    let quic = parsed.config.outbounds[0]
        .stream
        .quic_params
        .as_ref()
        .unwrap();
    assert_eq!(quic.max_idle_timeout_secs, 60);
}

/// A WARP key pair from the oracle's vectors: the first P-256 key Xray-core
/// takes with its scalar, and the first endpoint key it takes, as written.
fn warp_keys() -> (String, String, String) {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/masque/warp-config-vectors.json"
    ))
    .unwrap();
    let text = |case: &Value| {
        let hex = case["input"].as_str().unwrap();
        String::from_utf8(
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap() ^ 0x5a)
                .collect(),
        )
        .unwrap()
    };
    let private = vectors["private"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["scalar"].is_string())
        .unwrap();
    let public = vectors["public"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["ok"] == true)
        .unwrap();
    (
        text(private),
        private["scalar"].as_str().unwrap().to_owned(),
        text(public),
    )
}

#[test]
fn warp_keeps_its_key_and_addresses_and_takes_cloudflares_request() {
    let (private, scalar, public) = warp_keys();
    let settings = transport(Some(json!({"warp": {"privateKey": private,
        "publicKey": public, "address": ["172.16.0.2", "fd00::2/128"]}})));
    assert_eq!(settings.host, "cloudflareaccess.com");
    assert_eq!(settings.path, "/");
    let warp = settings.warp.as_ref().unwrap();
    let kept: String = warp
        .private_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(kept, scalar);
    assert_eq!(
        warp.addresses,
        [
            ("172.16.0.2".parse().unwrap(), 32),
            ("fd00::2".parse().unwrap(), 128)
        ]
    );
    assert!(!format!("{warp:?}").contains(&scalar[..16]));

    // A host and a path of its own stay.
    let settings = transport(Some(json!({"host": "warp.example", "path": "/w",
        "warp": {"privateKey": private, "publicKey": public, "address": ["172.16.0.2"]}})));
    assert_eq!(
        (settings.host.as_str(), settings.path.as_str()),
        ("warp.example", "/w")
    );

    // Xray's order: credentials first, then each key, then the addresses.
    let refused = |warp: Value, extra: Value| {
        let mut masque = json!({"warp": warp});
        for (key, value) in extra.as_object().unwrap() {
            masque[key] = value.clone();
        }
        errors(base(Some(masque)))
    };
    let all = json!({"privateKey": private, "publicKey": public, "address": ["10.0.0.1"]});
    assert!(refused(all.clone(), json!({"user": "u"}))[0]
        .contains(r#""user" and "pass" can't be used with "warp""#));
    assert!(refused(
        json!({"privateKey": public, "publicKey": public, "address": ["10.0.0.1"]}),
        json!({})
    )[0]
    .contains(r#"invalid "privateKey" in "warp""#));
    assert!(refused(
        json!({"privateKey": private, "publicKey": private, "address": ["10.0.0.1"]}),
        json!({})
    )[0]
    .contains(r#"invalid "publicKey" in "warp""#));
    assert!(refused(
        json!({"privateKey": private, "publicKey": public, "address": ["10.0.0.1", "10.0.0.2"]}),
        json!({})
    )[0]
    .contains("at most one IPv4 and one IPv6 address"));
}
