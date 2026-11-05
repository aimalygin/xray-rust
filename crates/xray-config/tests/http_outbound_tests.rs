use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, HttpOutboundSettings, OutboundProtocol, OutboundSettings, StreamSecurity,
    StreamTransport, TargetAddr,
};
use xray_proxy::outbound::HttpAccount;

const USER: &str = "synthetic-http-user";
const PASS: &str = "synthetic-http-pass";

fn profile(settings: Value) -> Value {
    json!({"outbounds":[{"tag":"proxy","protocol":"http","settings":settings}]})
}

fn flat() -> Value {
    json!({"address":"proxy.example","port":3128,"user":USER,"pass":PASS,"level":7,"email":"a@example.test"})
}

fn legacy() -> Value {
    json!({"servers":[{"address":"proxy.example","port":3128,"users":[{"user":USER,"pass":PASS,"level":7,"email":"a@example.test"}]}]})
}

fn settings(raw: &Value) -> HttpOutboundSettings {
    let parsed = parse_xray_json(&raw.to_string()).expect("http outbound parses");
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let outbound = &parsed.config.outbounds[0];
    assert_eq!(outbound.settings.protocol(), OutboundProtocol::Http);
    let OutboundSettings::Http(settings) = &outbound.settings else {
        panic!("expected HTTP settings, got {:?}", outbound.settings);
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
    assert_eq!(flat.server, TargetAddr::Domain("proxy.example".into()));
    assert_eq!(flat.port, 3128);
    assert_eq!(flat.level, 7);
    assert_eq!(flat.account, HttpAccount::new(USER, PASS));
    let debug = format!("{flat:?}");
    assert!(!debug.contains(USER) && !debug.contains(PASS), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    let mut raw = profile(json!({"address":"[2001:db8::1]","port":3128}));
    raw["outbounds"][0]["protocol"] = json!("HTTP");
    assert_eq!(
        settings(&raw).server,
        TargetAddr::Ip("2001:db8::1".parse().unwrap())
    );
}

#[test]
fn credentials_are_optional_and_pass_defaults_to_empty() {
    for raw in [
        json!({"address":"192.0.2.20","port":3128}),
        json!({"address":"192.0.2.20","port":3128,"level":3}),
        json!({"servers":[{"address":"192.0.2.20","port":3128}]}),
        json!({"servers":[{"address":"192.0.2.20","port":3128,"users":[]}]}),
    ] {
        let parsed = settings(&profile(raw.clone()));
        assert_eq!(parsed.account, None, "{raw}");
        assert_eq!(parsed.server, TargetAddr::Ip("192.0.2.20".parse().unwrap()));
    }
    // RFC 7617 allows an empty password; token-only proxies rely on it.
    for raw in [
        json!({"address":"192.0.2.20","port":3128,"user":USER}),
        json!({"address":"192.0.2.20","port":3128,"user":USER,"pass":""}),
        json!({"servers":[{"address":"192.0.2.20","port":3128,"users":[{"user":USER}]}]}),
    ] {
        assert_eq!(
            settings(&profile(raw.clone())).account,
            HttpAccount::new(USER, ""),
            "{raw}"
        );
    }
    let colon = json!({"address":"192.0.2.20","port":3128,"user":USER,"pass":"a:b:c"});
    assert_eq!(
        settings(&profile(colon)).account,
        HttpAccount::new(USER, "a:b:c")
    );
}

#[test]
fn custom_headers_read_as_xray_core_sets_them() {
    let names = |headers: Value| {
        let mut raw = flat();
        raw["headers"] = headers;
        settings(&profile(raw))
            .headers
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>()
    };
    // Go's Header.Set canonicalizes names, and a later alike name replaces.
    let set = names(json!({"x-lower": "a", "X-UPPER": "b", "x_under-score": "c"}));
    assert!(set.contains(&"X-Lower".to_owned()), "{set:?}");
    assert!(set.contains(&"X-Upper".to_owned()), "{set:?}");
    assert!(set.contains(&"X_under-Score".to_owned()), "{set:?}");
    let mut raw = flat();
    raw["headers"] = json!({"x-a": "1", "X-A": "2"});
    let headers = settings(&profile(raw)).headers;
    assert_eq!(headers.len(), 1);
    // serde_json keeps keys sorted, so `x-a` comes last and wins.
    let target = xray_routing::Target::new(
        xray_routing::TargetAddr::Domain("example.test".to_owned()),
        443,
        xray_routing::Network::Tcp,
    );
    assert_eq!(headers[0].1.render(None, &target), "1");
    // Templates and null values are accepted in both forms; Debug shows no
    // value.
    for headers in [
        json!({"X-Target": "{{.Target}}", "X-Source": "{{ .Source.Address }}", "X-Null": null}),
        json!({"Proxy-Authorization": "Bearer synthetic-token"}),
    ] {
        let mut raw = flat();
        raw["headers"] = headers.clone();
        let parsed = settings(&profile(raw));
        assert!(!format!("{parsed:?}").contains("synthetic-token"));
        let mut raw = legacy();
        raw["headers"] = headers;
        settings(&profile(raw));
    }
}

#[test]
fn empty_headers_are_accepted_in_both_forms() {
    for headers in [json!(null), json!({})] {
        let mut raw = flat();
        raw["headers"] = headers.clone();
        settings(&profile(raw));
        let mut raw = legacy();
        raw["headers"] = headers;
        settings(&profile(raw));
    }
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
        // Xray sends empty Basic credentials for these.
        (server_with_users(json!([{}])), user_path.to_owned()),
        (
            server_with_users(json!([{"pass":PASS}])),
            user_path.to_owned(),
        ),
        (
            server_with_users(json!([{"level":1}])),
            user_path.to_owned(),
        ),
        (
            server_with_users(json!([{"user":USER,"pass":PASS,"extra":true}])),
            format!("{user_path}.extra"),
        ),
        (
            json!({"servers":[{"address":"proxy.example","port":3128,"user":USER,"pass":PASS}]}),
            format!("{server_path}.user"),
        ),
        (
            json!({"servers":[{"address":"proxy.example","port":3128,"headers":{}}]}),
            format!("{server_path}.headers"),
        ),
    ];
    // Xray silently drops a flat `pass` without `user`.
    let mut lone_pass = flat();
    lone_pass.as_object_mut().unwrap().remove("user");
    cases.push((lone_pass, format!("{settings_path}.pass")));
    for (key, value) in [
        ("user", json!("")),
        ("user", json!("user:name")),
        ("user", json!("user\u{7f}")),
        ("pass", json!("pass\nword")),
        ("user", json!("u".repeat(1025))),
        ("pass", json!("p".repeat(1025))),
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
        ("port", json!("3128")),
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
    for (headers, path) in [
        (json!([]), "headers".to_owned()),
        (json!("X: y"), "headers".to_owned()),
        (json!({"X-Number": 1}), "headers.X-Number".to_owned()),
        (json!({"Bad Name": "x"}), "headers.Bad Name".to_owned()),
        (json!({"": "x"}), "headers.".to_owned()),
        (json!({"X-Nul": "a\u{0}b"}), "headers.X-Nul".to_owned()),
        (
            json!({"X-Long": "x".repeat(8 * 1024 + 1)}),
            "headers.X-Long".to_owned(),
        ),
        (
            json!({"X-Func": "{{printf \"%s\" .Target}}"}),
            "headers.X-Func".to_owned(),
        ),
        (
            json!({"X-Field": "{{.Target.Domain}}"}),
            "headers.X-Field".to_owned(),
        ),
        (json!({"X-Open": "{{.Target"}), "headers.X-Open".to_owned()),
    ] {
        let mut raw = flat();
        raw["headers"] = headers.clone();
        cases.push((raw, format!("{settings_path}.{path}")));
        let mut raw = legacy();
        raw["headers"] = headers;
        cases.push((raw, format!("{settings_path}.{path}")));
    }
    let many: serde_json::Map<String, Value> = (0..65)
        .map(|index| (format!("X-{index}"), json!("x")))
        .collect();
    let mut raw = flat();
    raw["headers"] = Value::Object(many);
    cases.push((raw, format!("{settings_path}.headers")));
    for (raw, path) in cases {
        rejects_at(&profile(raw), &path);
    }
}

#[test]
fn stream_settings_accept_every_transport_and_its_security() {
    let with_stream = |stream: Value| {
        let mut raw = profile(flat());
        raw["outbounds"][0]["streamSettings"] = stream;
        raw
    };
    let stream_of = |stream: Value| {
        let parsed = parse_xray_json(&with_stream(stream).to_string()).expect("HTTP stream parses");
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        parsed.config.outbounds[0].stream.clone()
    };
    for stream in [
        json!({"network":"raw"}),
        json!({"network":"tcp","security":"none"}),
        json!({"security":"tls","tlsSettings":{"serverName":"proxy.example","alpn":["http/1.1"]}}),
        json!({"security":"tls","tlsSettings":{"serverName":"proxy.example","fingerprint":"chrome"}}),
        // TLS offers what Xray-core offers; the proxy's pick decides the
        // tunnel's HTTP version.
        json!({"security":"tls","tlsSettings":{"serverName":"proxy.example","alpn":["h2"]}}),
        json!({"security":"tls","tlsSettings":{"serverName":"proxy.example","alpn":["h2","http/1.1"]}}),
        json!({"security":"tls","tlsSettings":{"serverName":"proxy.example","alpn":["http/1.1","http/1.1"]}}),
    ] {
        settings(&with_stream(stream));
    }
    let tls = json!({"serverName":"proxy.example"});
    let reality = json!({"serverName":"proxy.example","fingerprint":"chrome",
        "publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","shortId":"02030405"});
    // Xray-core puts no transport or security restriction on its HTTP client.
    for (stream, transport, security) in [
        (json!({}), "raw", "none"),
        (
            json!({"network":"tcp","security":"tls","tlsSettings":tls}),
            "raw",
            "tls",
        ),
        (
            json!({"network":"raw","security":"reality","realitySettings":reality}),
            "raw",
            "reality",
        ),
        (
            json!({"network":"ws","wsSettings":{"path":"/proxy"}}),
            "ws",
            "none",
        ),
        (
            json!({"network":"ws","security":"tls","tlsSettings":tls}),
            "ws",
            "tls",
        ),
        (
            json!({"network":"httpupgrade","security":"tls","tlsSettings":tls}),
            "httpupgrade",
            "tls",
        ),
        (
            json!({"network":"grpc","grpcSettings":{"serviceName":"proxy"}}),
            "grpc",
            "none",
        ),
        (
            json!({"network":"grpc","security":"reality","realitySettings":reality}),
            "grpc",
            "reality",
        ),
        (
            json!({"network":"xhttp","xhttpSettings":{"path":"/proxy"}}),
            "xhttp",
            "none",
        ),
        (
            json!({"network":"xhttp","security":"reality","realitySettings":reality}),
            "xhttp",
            "reality",
        ),
    ] {
        let parsed = stream_of(stream.clone());
        let parsed_transport = match parsed.transport {
            StreamTransport::Raw => "raw",
            StreamTransport::WebSocket(_) => "ws",
            StreamTransport::HttpUpgrade(_) => "httpupgrade",
            StreamTransport::Grpc(_) => "grpc",
            StreamTransport::Xhttp(_) => "xhttp",
            StreamTransport::Hysteria(_) => "hysteria",
        };
        let parsed_security = match parsed.security {
            StreamSecurity::None => "none",
            StreamSecurity::Tls(_) => "tls",
            StreamSecurity::Reality(_) => "reality",
        };
        assert_eq!(
            (parsed_transport, parsed_security),
            (transport, security),
            "{stream}"
        );
    }
    // A plaintext XHTTP download leg to a public server is accepted, as a
    // plaintext public HTTP proxy is.
    stream_of(
        json!({"network":"xhttp","xhttpSettings":{"path":"/up","downloadSettings":{
        "address":"198.51.100.20","port":443,"network":"xhttp","xhttpSettings":{"path":"/down"}}}}),
    );
    // Only what every outbound refuses stays refused: REALITY over WebSocket
    // as in Xray-core, and the Hysteria transport outside its own outbound.
    for (stream, path) in [
        (
            json!({"network":"ws","security":"reality","realitySettings":reality}),
            "security",
        ),
        (
            json!({"network":"hysteria","hysteriaSettings":{"version":2,"auth":"synthetic"}}),
            "network",
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
        {"tag":"entry","protocol":"http","settings":flat(),
            "proxySettings":{"tag":"exit","transportLayer":true}},
        {"tag":"exit","protocol":"socks","settings":{"address":"192.0.2.10","port":1080}}
    ]});
    let parsed = parse_xray_json(&chained.to_string()).expect("chained HTTP parses");
    assert_eq!(parsed.diagnostics.len(), 1);
    assert!(parsed.diagnostics[0]
        .message
        .contains("legacy proxySettings"));
    assert_eq!(
        parsed.config.outbounds[0]
            .proxy_settings
            .as_ref()
            .map(|p| p.tag.as_str()),
        Some("exit")
    );
}
