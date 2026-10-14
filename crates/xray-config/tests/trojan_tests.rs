use serde_json::{json, Value};
use xray_config::{parse_xray_json, OutboundSettings};

fn profile(settings: Value) -> Value {
    json!({"outbounds":[{"protocol":"trojan","settings":settings,"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.test"}}}]})
}
fn server() -> Value {
    json!({"address":"example.test","port":443,"password":"synthetic-trojan-test-secret","level":7})
}

#[test]
fn flattened_and_legacy_forms_normalize_with_redacted_credentials() {
    let flat = parse_xray_json(&profile(server()).to_string()).unwrap();
    let legacy = parse_xray_json(&profile(json!({"servers":[server()]})).to_string()).unwrap();
    assert_eq!(flat.config, legacy.config);
    let OutboundSettings::Trojan(settings) = &flat.config.outbounds[0].settings else {
        panic!("Trojan")
    };
    assert_eq!(settings.level, 7);
    assert_eq!(settings.password.as_str(), "synthetic-trojan-test-secret");
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
        ("password", json!("a".repeat(4097))),
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
        assert!(!format!("{error:?}").contains("synthetic-trojan-test-secret"));
    }
}

#[test]
fn plaintext_policy_applies_after_both_settings_forms_are_normalized() {
    for legacy in [false, true] {
        for address in ["8.8.8.8", "public.example.com"] {
            let mut settings = server();
            settings["address"] = json!(address);
            let mut value = profile(if legacy {
                json!({"servers":[settings]})
            } else {
                settings
            });
            value["outbounds"][0]
                .as_object_mut()
                .unwrap()
                .remove("streamSettings");
            assert!(parse_xray_json(&value.to_string()).is_err());
        }
        let settings = if legacy {
            json!({"servers":[server()]})
        } else {
            server()
        };
        let mut value = profile(settings);
        value["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = json!(true);
        assert!(parse_xray_json(&value.to_string()).is_err());
    }
}
