use serde_json::{json, Value};
use xray_config::{parse_xray_json, OutboundSettings};

const ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
fn profile(settings: Value) -> Value {
    json!({"outbounds":[{"protocol":"vmess","settings":settings}]})
}
fn user() -> Value {
    json!({"id":ID,"security":"auto","alterId":0,"level":65536,"experiments":"AuthenticatedLength|NoTerminationSignal"})
}
fn server() -> Value {
    let mut settings = user();
    settings["address"] = json!("example.test");
    settings["port"] = json!(443);
    settings
}

#[test]
fn flattened_and_legacy_vmess_preserve_options_level_and_redact_uuid() {
    let flat = parse_xray_json(&profile(server()).to_string()).unwrap();
    let legacy = parse_xray_json(
        &profile(json!({"vnext":[{"address":"example.test","port":443,"users":[user()]}]}))
            .to_string(),
    )
    .unwrap();
    assert_eq!(flat.config, legacy.config);
    let OutboundSettings::Vmess(settings) = &flat.config.outbounds[0].settings else {
        panic!("VMess")
    };
    assert_eq!(settings.level, 65536);
    assert!(settings.options.authenticated_length && settings.options.no_termination_signal);
    assert_eq!(
        settings.user_id.as_slice(),
        uuid::Uuid::parse_str(ID).unwrap().as_bytes()
    );
    assert!(!format!("{:?}", flat.config).contains(ID));
}

#[test]
fn malformed_vmess_credentials_and_legacy_authentication_fail_closed() {
    let mut cases = vec![
        json!(null),
        json!({"vnext":[]}),
        json!({"vnext":[null]}),
        json!({"vnext":[{"address":"example.test","port":443,"users":[]}]}),
        json!({"vnext":[{"address":"example.test","port":443,"users":[user(),user()]}]}),
    ];
    let mut mixed = server();
    mixed["vnext"] = json!([]);
    cases.push(mixed);
    for (key, value) in [
        ("id", json!("synthetic-secret")),
        ("id", json!(1)),
        ("security", json!("none")),
        ("security", json!("aes-128-cfb")),
        ("security", json!(false)),
        ("alterId", json!(1)),
        ("alterId", json!("0")),
        ("alterId", json!(-1)),
        ("port", json!(0)),
        ("port", json!(65536)),
        ("level", json!(-1)),
        (
            "experiments",
            json!("AuthenticatedLength|AuthenticatedLength"),
        ),
        ("experiments", json!("unknown")),
        ("experiments", json!(true)),
        ("email", json!(7)),
        ("flow", json!("xtls-rprx-vision")),
        ("address", json!("bad\u{0}host")),
        ("extra", json!(true)),
    ] {
        let mut settings = server();
        settings[key] = value;
        cases.push(settings);
    }
    for settings in cases {
        let error = parse_xray_json(&profile(settings).to_string()).unwrap_err();
        let diagnostic = format!("{error:?}");
        assert!(!diagnostic.contains(ID) && !diagnostic.contains("synthetic-secret"));
    }
}
