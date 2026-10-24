use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, OutboundProtocol, OutboundSettings, SocksOutboundSettings, StreamSecurity,
    TargetAddr,
};
use xray_proxy::inbound::SocksAccount;

const USER: &str = "synthetic-socks-user";
const PASS: &str = "synthetic-socks-pass";

fn profile(settings: Value) -> Value {
    json!({"outbounds":[{"tag":"proxy","protocol":"socks","settings":settings}]})
}

fn flat() -> Value {
    json!({"address":"socks.example","port":1080,"user":USER,"pass":PASS,"level":7,"email":"a@example.test"})
}

fn legacy() -> Value {
    json!({"servers":[{"address":"socks.example","port":1080,"users":[{"user":USER,"pass":PASS,"level":7,"email":"a@example.test"}]}]})
}

fn settings(raw: &Value) -> SocksOutboundSettings {
    let parsed = parse_xray_json(&raw.to_string()).expect("socks outbound parses");
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let outbound = &parsed.config.outbounds[0];
    assert_eq!(outbound.settings.protocol(), OutboundProtocol::Socks);
    let OutboundSettings::Socks(settings) = &outbound.settings else {
        panic!("expected SOCKS settings, got {:?}", outbound.settings);
    };
    settings.clone()
}

/// Asserts that parsing fails with an error at `path` and never echoes a credential.
fn rejects_at(raw: &Value, path: &str) {
    let error = parse_xray_json(&raw.to_string()).unwrap_err();
    let rendered = format!("{error:?}");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|d| d.path.as_deref() == Some(path)),
        "missing {path}: {rendered}"
    );
    assert!(
        !rendered.contains(USER) && !rendered.contains(PASS),
        "{rendered}"
    );
}

#[test]
fn flattened_and_legacy_forms_normalize_with_redacted_credentials() {
    let flat = settings(&profile(flat()));
    assert_eq!(flat, settings(&profile(legacy())));
    assert_eq!(flat.server, TargetAddr::Domain("socks.example".into()));
    assert_eq!(flat.port, 1080);
    assert_eq!(flat.level, 7);
    assert_eq!(
        flat.account,
        SocksAccount::new(USER.as_bytes(), PASS.as_bytes())
    );
    let debug = format!("{flat:?}");
    assert!(!debug.contains(USER) && !debug.contains(PASS), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    let mut raw = profile(json!({"address":"[2001:db8::1]","port":1080}));
    raw["outbounds"][0]["protocol"] = json!("SOCKS");
    assert_eq!(
        settings(&raw).server,
        TargetAddr::Ip("2001:db8::1".parse().unwrap())
    );
}

#[test]
fn credentials_are_optional_in_both_forms() {
    for raw in [
        json!({"address":"192.0.2.10","port":1080}),
        json!({"address":"192.0.2.10","port":1080,"level":3}),
        json!({"servers":[{"address":"192.0.2.10","port":1080}]}),
        json!({"servers":[{"address":"192.0.2.10","port":1080,"users":[]}]}),
    ] {
        let parsed = settings(&profile(raw.clone()));
        assert_eq!(parsed.account, None, "{raw}");
        assert_eq!(parsed.server, TargetAddr::Ip("192.0.2.10".parse().unwrap()));
    }
    assert_eq!(
        settings(&profile(
            json!({"address":"192.0.2.10","port":1080,"level":3})
        ))
        .level,
        3
    );
}

#[test]
fn invalid_shapes_and_credentials_are_rejected_at_their_paths_without_secrets() {
    let settings_path = "$.outbounds[0].settings";
    let server_path = "$.outbounds[0].settings.servers[0]";
    let user_path = "$.outbounds[0].settings.servers[0].users[0]";
    let mut mixed = flat();
    mixed["servers"] = legacy()["servers"].clone();
    let user = legacy()["servers"][0]["users"][0].clone();
    let server_with_users = |users: Value| {
        let mut raw = legacy();
        raw["servers"][0]["users"] = users;
        raw
    };
    let mut cases = vec![
        (json!(null), settings_path.to_owned()),
        (json!([]), settings_path.to_owned()),
        (mixed, settings_path.to_owned()),
        (
            json!({"servers":[legacy()["servers"][0], legacy()["servers"][0]]}),
            format!("{settings_path}.servers"),
        ),
        (json!({"servers":[]}), format!("{settings_path}.servers")),
        (json!({"servers":null}), format!("{settings_path}.servers")),
        (json!({"servers":[null]}), server_path.to_owned()),
        (
            server_with_users(json!([user, user])),
            format!("{server_path}.users"),
        ),
        (
            server_with_users(json!({"user":USER})),
            format!("{server_path}.users"),
        ),
        (server_with_users(json!([null])), user_path.to_owned()),
        (server_with_users(json!([{}])), user_path.to_owned()),
        (
            server_with_users(json!([{"level":1}])),
            user_path.to_owned(),
        ),
        (
            server_with_users(json!([{"user":USER,"pass":PASS,"extra":true}])),
            format!("{user_path}.extra"),
        ),
        (
            json!({"servers":[{"address":"socks.example","port":1080,"user":USER,"pass":PASS}]}),
            format!("{server_path}.user"),
        ),
    ];
    // Without one half, the missing half is reported.
    for (key, path) in [("pass", "pass"), ("user", "user")] {
        let mut raw = flat();
        raw.as_object_mut().unwrap().remove(key);
        cases.push((raw, format!("{settings_path}.{path}")));
        let mut raw = user.clone();
        raw.as_object_mut().unwrap().remove(key);
        cases.push((
            server_with_users(json!([raw])),
            format!("{user_path}.{path}"),
        ));
    }
    for (key, value) in [
        ("user", json!("")),
        ("pass", json!("")),
        ("user", json!("u".repeat(256))),
        ("pass", json!("p".repeat(256))),
        ("user", json!(1)),
        ("pass", json!(null)),
        ("level", json!(256)),
        ("level", json!(-1)),
        ("email", json!(false)),
    ] {
        let mut raw = flat();
        raw[key] = value.clone();
        cases.push((raw, format!("{settings_path}.{key}")));
        let mut raw = user.clone();
        raw[key] = value;
        cases.push((
            server_with_users(json!([raw])),
            format!("{user_path}.{key}"),
        ));
    }
    for (key, value) in [
        ("port", json!(0)),
        ("port", json!(65536)),
        ("port", json!("1080")),
        ("address", json!("")),
        ("address", json!("bad host")),
        ("address", json!("bad\u{0}host")),
        ("address", json!("a".repeat(256))),
        ("address", json!(1)),
        ("extra", json!(true)),
    ] {
        let mut raw = flat();
        raw[key] = value.clone();
        cases.push((raw, format!("{settings_path}.{key}")));
        let mut raw = legacy();
        raw["servers"][0][key] = value;
        cases.push((raw, format!("{server_path}.{key}")));
    }
    for (raw, path) in cases {
        rejects_at(&profile(raw), &path);
    }
}

#[test]
fn stream_settings_allow_raw_with_none_or_tls_only() {
    let with_stream = |stream: Value| {
        let mut raw = profile(flat());
        raw["outbounds"][0]["streamSettings"] = stream;
        raw
    };
    for stream in [
        json!({}),
        json!({"network":"raw"}),
        json!({"network":"tcp","security":"none"}),
        json!({"network":"tcp","security":"tls","tlsSettings":{"serverName":"socks.example"}}),
    ] {
        settings(&with_stream(stream));
    }
    let parsed = parse_xray_json(
        &with_stream(json!({"security":"tls","tlsSettings":{"serverName":"socks.example"}}))
            .to_string(),
    )
    .unwrap();
    assert!(matches!(
        parsed.config.outbounds[0].stream.security,
        StreamSecurity::Tls(_)
    ));
    for (stream, path) in [
        (json!({"network":"ws"}), "network"),
        (json!({"network":"grpc"}), "network"),
        (json!({"network":"httpupgrade"}), "network"),
        (json!({"network":"xhttp"}), "network"),
        (
            json!({"network":"raw","security":"reality","realitySettings":{
                "serverName":"socks.example","fingerprint":"chrome",
                "publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","shortId":"02030405"}}),
            "security",
        ),
    ] {
        rejects_at(
            &with_stream(stream),
            &format!("$.outbounds[0].streamSettings.{path}"),
        );
    }
}

#[test]
fn plaintext_public_servers_with_credentials_are_allowed() {
    for address in ["8.8.8.8", "public.example.com"] {
        let mut raw = flat();
        raw["address"] = json!(address);
        let parsed = settings(&profile(raw));
        assert!(!parsed.server.is_xray_plaintext_server_exempt());
        assert!(parsed.account.is_some());
    }
}

#[test]
fn mux_is_rejected_and_chaining_is_accepted() {
    let mut raw = profile(flat());
    raw["outbounds"][0]["mux"] = json!({"enabled": true});
    rejects_at(&raw, "$.outbounds[0].mux.enabled");
    raw["outbounds"][0]["mux"] = json!({"enabled": false});
    settings(&raw);

    let chained = json!({"outbounds":[
        {"tag":"entry","protocol":"socks","settings":flat(),
            "proxySettings":{"tag":"exit","transportLayer":true}},
        {"tag":"exit","protocol":"socks","settings":{"address":"192.0.2.10","port":1080}}
    ]});
    let parsed = parse_xray_json(&chained.to_string()).expect("chained SOCKS parses");
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    assert_eq!(
        parsed.config.outbounds[0]
            .proxy_settings
            .as_ref()
            .map(|p| p.tag.as_str()),
        Some("exit")
    );
}
