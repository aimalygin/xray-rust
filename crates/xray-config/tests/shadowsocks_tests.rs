use serde_json::{json, Value};
use xray_config::{parse_xray_json, OutboundSettings};

fn profile(settings: Value) -> Value {
    json!({"outbounds":[{"protocol":"shadowsocks","settings":settings,"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.test"}}}]})
}
fn server() -> Value {
    json!({"address":"example.test","port":443,"password":"AQEBAQEBAQEBAQEBAQEBAQ==","method":"2022-blake3-aes-128-gcm","level":7})
}

#[test]
fn flattened_and_legacy_forms_normalize_with_redacted_credentials() {
    let flat = parse_xray_json(&profile(server()).to_string()).unwrap();
    let legacy = parse_xray_json(&profile(json!({"servers":[server()]})).to_string()).unwrap();
    assert_eq!(flat.config, legacy.config);
    let OutboundSettings::Shadowsocks2022(settings) = &flat.config.outbounds[0].settings else {
        panic!("Shadowsocks2022")
    };
    assert_eq!(settings.level, 7);
    assert_eq!(settings.password.as_str(), "AQEBAQEBAQEBAQEBAQEBAQ==");
    assert!(!format!("{:?}", flat.config).contains(settings.password.as_str()));
}

#[test]
fn invalid_credentials_shapes_and_options_are_rejected_without_secrets() {
    let mut cases = vec![
        json!(null),
        json!({"servers":[]}),
        json!({"servers":[server(),server()]}),
        json!({"servers":[null]}),
    ];
    let mut mixed = server();
    mixed["servers"] = json!([server()]);
    cases.push(mixed);
    for (key, value) in [
        ("password", json!("")),
        ("password", json!("a".repeat(8193))),
        ("password", json!(1)),
        ("port", json!(0)),
        ("port", json!(65536)),
        ("level", json!(256)),
        ("level", json!(-1)),
        ("flow", json!("xtls-rprx-vision")),
        ("flow", json!(false)),
        ("address", json!("bad\u{0}host")),
        ("extra", json!(true)),
    ] {
        let mut settings = server();
        settings[key] = value;
        cases.push(settings);
    }
    for settings in cases {
        let error = parse_xray_json(&profile(settings).to_string()).unwrap_err();
        assert!(!format!("{error:?}").contains("AQEBAQEBAQEBAQEBAQEBAQ=="));
    }
}

fn error_paths(settings: Value) -> Vec<String> {
    parse_xray_json(&profile(settings).to_string())
        .unwrap_err()
        .diagnostics
        .into_iter()
        .filter_map(|d| d.path)
        .collect()
}

#[test]
fn methods_follow_xray_names_and_public_encrypted_transport() {
    // Exactly the strings Xray-core v26.10.21 accepts, case-insensitively.
    for method in [
        "aes-128-gcm",
        "AES-128-GCM",
        "aead_aes_128_gcm",
        "aes-256-gcm",
        "aead_aes_256_gcm",
        "chacha20-poly1305",
        "aead_chacha20_poly1305",
        "chacha20-ietf-poly1305",
        "xchacha20-poly1305",
        "aead_xchacha20_poly1305",
        "xchacha20-ietf-poly1305",
        "2022-BLAKE3-AES-128-GCM",
    ] {
        let mut settings = server();
        settings["method"] = json!(method);
        let parsed = parse_xray_json(&profile(settings).to_string()).unwrap();
        let OutboundSettings::Shadowsocks2022(settings) = &parsed.config.outbounds[0].settings
        else {
            panic!("Shadowsocks")
        };
        assert_eq!(settings.method, method);
    }
    // No `none`/`plain`, stream ciphers or unknown 2022 methods (Xray rejects them).
    for method in [
        "none",
        "plain",
        "rc4-md5",
        "aes-128-cfb",
        "chacha20-ietf",
        "2022-unknown",
    ] {
        let mut settings = server();
        settings["method"] = json!(method);
        assert_eq!(
            error_paths(settings),
            ["$.outbounds[0].settings.method"],
            "{method}"
        );
    }
    let mut settings = json!({"servers":[server()]});
    settings["servers"][0]["method"] = json!("aes-128-gcm");
    settings["servers"][0]["password"] = json!("");
    assert_eq!(
        error_paths(settings),
        ["$.outbounds[0].settings.servers[0].password"]
    );
    let mut value = profile(server());
    value["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("streamSettings");
    assert!(parse_xray_json(&value.to_string()).is_ok());
}

#[test]
fn aead_passwords_are_free_text_redacted_and_mux_is_allowed() {
    let password = "synthetic пароль:with:colons and spaces";
    let mut settings = server();
    settings["method"] = json!("chacha20-ietf-poly1305");
    settings["password"] = json!(password);
    let mut value = profile(settings);
    value["outbounds"][0]["mux"] = json!({"enabled": true, "concurrency": 4});
    let parsed = parse_xray_json(&value.to_string()).unwrap();
    assert!(!format!("{:?}", parsed.config).contains("пароль"));
    let OutboundSettings::Shadowsocks2022(settings) = &parsed.config.outbounds[0].settings else {
        panic!("Shadowsocks")
    };
    assert_eq!(settings.password.as_str(), password);
}
