//! Remnawave's XRAY_JSON subscription format (xray-json.generator.service.ts)
//! names every profile in a root `remarks`, writes `enableSessionResumption`
//! into every TLS host and sing-box `uot`/`UoTVersion` into every Shadowsocks
//! server. Xray-core v26.10.31 ignores the labels and the Shadowsocks pair, and
//! reads `enableSessionResumption` as a boolean that its uTLS path never uses.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity};

fn vless_tls(tls: Value) -> Value {
    json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": "proxy.example",
            "port": 443,
            "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none", "flow": ""}]
        }]},
        "streamSettings": {"network": "tcp", "tcpSettings": {}, "security": "tls", "tlsSettings": tls}
    })
}

fn shadowsocks(server: Value) -> Value {
    json!({
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {"servers": [server]},
        "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "proxy.example"}}
    })
}

fn ss_server() -> Value {
    json!({
        "address": "proxy.example",
        "port": 443,
        "password": "AQEBAQEBAQEBAQEBAQEBAQ==",
        "method": "2022-blake3-aes-128-gcm"
    })
}

fn tls() -> Value {
    json!({"serverName": "proxy.example", "fingerprint": "chrome", "alpn": ["h2", "http/1.1"]})
}

fn with(mut object: Value, key: &str, value: Value) -> Value {
    object[key] = value;
    object
}

fn profile(outbound: Value) -> Value {
    json!({"outbounds": [outbound]})
}

fn labelled(outbound: Value) -> Value {
    json!({
        "remarks": "Example host",
        "meta": {"serverDescription": "Synthetic description"},
        "outbounds": [outbound]
    })
}

fn error_paths(raw: &Value) -> Vec<String> {
    parse_xray_json(&raw.to_string())
        .unwrap_err()
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .filter_map(|diagnostic| diagnostic.path)
        .collect()
}

fn warning_paths(raw: &Value) -> Vec<String> {
    parse_xray_json(&raw.to_string())
        .unwrap()
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
        .filter_map(|diagnostic| diagnostic.path)
        .collect()
}

#[test]
fn remnawave_labels_and_inert_fields_parse_to_the_same_config() {
    for (plain, remnawave) in [
        (
            profile(vless_tls(tls())),
            labelled(vless_tls(with(
                tls(),
                "enableSessionResumption",
                json!(false),
            ))),
        ),
        (
            profile(vless_tls(tls())),
            labelled(vless_tls(with(
                tls(),
                "enableSessionResumption",
                json!(true),
            ))),
        ),
        (
            profile(shadowsocks(ss_server())),
            labelled(shadowsocks(with(
                with(ss_server(), "uot", json!(false)),
                "UoTVersion",
                json!(2),
            ))),
        ),
    ] {
        let plain = parse_xray_json(&plain.to_string()).unwrap();
        let remnawave = parse_xray_json(&remnawave.to_string()).unwrap();
        assert_eq!(plain.config, remnawave.config);
        assert!(
            remnawave.diagnostics.is_empty(),
            "{:?}",
            remnawave.diagnostics
        );
    }
}

#[test]
fn null_labels_and_options_read_as_absent() {
    let raw = json!({
        "remarks": null,
        "meta": null,
        "outbounds": [vless_tls(with(tls(), "enableSessionResumption", Value::Null))]
    });
    assert!(parse_xray_json(&raw.to_string()).is_ok());
    let raw = profile(shadowsocks(with(
        with(ss_server(), "uot", Value::Null),
        "UoTVersion",
        Value::Null,
    )));
    assert!(warning_paths(&raw).is_empty());
}

#[test]
fn uot_true_is_ignored_with_a_warning() {
    let raw = labelled(shadowsocks(with(
        with(ss_server(), "uot", json!(true)),
        "UoTVersion",
        json!(1),
    )));
    assert_eq!(
        warning_paths(&raw),
        ["$.outbounds[0].settings.servers[0].uot"]
    );

    let mut flat = shadowsocks(Value::Null);
    flat["settings"] = with(ss_server(), "uot", json!(true));
    assert_eq!(
        warning_paths(&profile(flat)),
        ["$.outbounds[0].settings.uot"]
    );
}

#[test]
fn mistyped_labels_and_options_are_rejected() {
    let cases = [
        (
            json!({"remarks": 42, "outbounds": [vless_tls(tls())]}),
            "$.remarks",
        ),
        (
            json!({"meta": "description", "outbounds": [vless_tls(tls())]}),
            "$.meta",
        ),
        (
            profile(vless_tls(with(
                tls(),
                "enableSessionResumption",
                json!("true"),
            ))),
            "$.outbounds[0].streamSettings.tlsSettings.enableSessionResumption",
        ),
        (
            profile(shadowsocks(with(ss_server(), "uot", json!("false")))),
            "$.outbounds[0].settings.servers[0].uot",
        ),
        (
            profile(shadowsocks(with(ss_server(), "UoTVersion", json!(-1)))),
            "$.outbounds[0].settings.servers[0].UoTVersion",
        ),
    ];
    for (raw, path) in cases {
        assert_eq!(error_paths(&raw), [path], "{raw}");
    }
}
