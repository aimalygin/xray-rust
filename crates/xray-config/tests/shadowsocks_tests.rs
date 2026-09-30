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

#[test]
fn ss2022_only_methods_and_public_encrypted_transport() {
    for method in ["aes-128-gcm", "chacha20-poly1305", "2022-unknown"] {
        let mut settings = server();
        settings["method"] = json!(method);
        assert!(parse_xray_json(&profile(settings).to_string()).is_err());
    }
    let mut value = profile(server());
    value["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("streamSettings");
    assert!(parse_xray_json(&value.to_string()).is_ok());
}
