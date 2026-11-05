//! Xray `loopback` outbound settings, as Xray-core v26.10.31 reads them.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, LoopbackOutboundSettings, OutboundSettings};

fn config(outbound: Value) -> String {
    json!({"inbounds": [], "outbounds": [outbound]}).to_string()
}

fn settings(outbound: Value) -> LoopbackOutboundSettings {
    let parsed = parse_xray_json(&config(outbound.clone()))
        .unwrap_or_else(|error| panic!("{outbound} should parse: {:?}", error.diagnostics));
    match &parsed.config.outbounds[0].settings {
        OutboundSettings::Loopback(settings) => settings.clone(),
        other => panic!("expected loopback settings, got {other:?}"),
    }
}

fn rejection(outbound: Value) -> String {
    let error = parse_xray_json(&config(outbound.clone()))
        .expect_err(&format!("{outbound} should be rejected"));
    error.diagnostics[0].path.clone().unwrap_or_default()
}

#[test]
fn loopback_settings_read_as_xray_core_reads_them() {
    let tag = |outbound: Value| settings(outbound).inbound_tag;
    assert_eq!(
        tag(json!({"protocol": "loopback", "settings": {"inboundTag": "again"}})),
        "again"
    );
    // The protocol name ignores case, as for every outbound.
    assert_eq!(
        tag(json!({"protocol": "Loopback", "settings": {"inboundTag": "again"}})),
        "again"
    );
    for outbound in [
        json!({"protocol": "loopback"}),
        json!({"protocol": "loopback", "settings": null}),
        json!({"protocol": "loopback", "settings": {}}),
        json!({"protocol": "loopback", "settings": {"inboundTag": null}}),
    ] {
        assert_eq!(tag(outbound.clone()), "", "{outbound}");
    }
    // Sniffing that is off, or `null`, is accepted.
    for sniffing in [
        json!(null),
        json!({}),
        json!({"enabled": false, "destOverride": ["tls"]}),
    ] {
        let outbound = json!({"protocol": "loopback",
            "settings": {"inboundTag": "again", "sniffing": sniffing}});
        assert_eq!(tag(outbound), "again");
    }
}

#[test]
fn loopback_settings_reject_what_the_parser_refuses() {
    let base = "$.outbounds[0].settings";
    for (outbound, path) in [
        (
            json!({"protocol": "loopback", "settings": "x"}),
            base.to_owned(),
        ),
        (
            json!({"protocol": "loopback", "settings": {"inboundTag": 1}}),
            format!("{base}.inboundTag"),
        ),
        (
            json!({"protocol": "loopback", "settings": {"sniffing": "x"}}),
            format!("{base}.sniffing"),
        ),
        (
            json!({"protocol": "loopback", "settings": {"sniffing": {"destOverride": ["ftp"]}}}),
            format!("{base}.sniffing.destOverride[0]"),
        ),
        // Enabled sniffing is not supported yet.
        (
            json!({"protocol": "loopback", "settings": {"sniffing": {"enabled": true}}}),
            format!("{base}.sniffing"),
        ),
        // Unknown fields fail, where Go would ignore them.
        (
            json!({"protocol": "loopback", "settings": {"inboundTag": "a", "tag": "b"}}),
            format!("{base}.tag"),
        ),
    ] {
        assert_eq!(rejection(outbound.clone()), path, "{outbound}");
    }
}
