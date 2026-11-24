//! Keys Xray-core accepts that change nothing for this client. Full Xray JSON
//! subscriptions carry them (root apps, removed knobs, server-side TLS
//! fields); each is accepted with a warning naming what is ignored, while a
//! value Go's decoding would refuse, or one whose omission would widen trust,
//! still fails.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, Diagnostic, DiagnosticSeverity};

fn vless(stream: Value) -> Value {
    json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": "proxy.example",
            "port": 443,
            "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]
        }]},
        "streamSettings": stream
    })
}

fn tls_profile(tls: Value) -> Value {
    json!({"outbounds": [vless(json!({
        "network": "tcp",
        "security": "tls",
        "tlsSettings": tls
    }))]})
}

fn warnings_of(raw: &Value) -> Vec<Diagnostic> {
    parse_xray_json(&raw.to_string())
        .unwrap_or_else(|error| panic!("{raw}: {error:?}"))
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
        .collect()
}

fn warning_at<'a>(diagnostics: &'a [Diagnostic], path: &str) -> &'a str {
    diagnostics
        .iter()
        .find(|diagnostic| diagnostic.path.as_deref() == Some(path))
        .map(|diagnostic| diagnostic.message.as_str())
        .unwrap_or_else(|| panic!("no warning at {path}: {diagnostics:?}"))
}

fn error_paths(raw: &Value) -> Vec<String> {
    parse_xray_json(&raw.to_string())
        .expect_err("config must be refused")
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .filter_map(|diagnostic| diagnostic.path)
        .collect()
}

#[test]
fn root_apps_without_a_runtime_are_ignored_with_warnings() {
    let raw = json!({
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "metrics": {"tag": "metrics_out"},
        "version": {"min": "25.1.1", "max": ""},
        "geodata": {
            "cron": "0 4 * * *",
            "outbound": "proxy",
            "assets": [{"url": "https://geodata.example/geosite.dat", "file": "geosite.dat"}]
        },
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    });
    let warnings = warnings_of(&raw);
    for (path, text) in [
        ("$.stats", "traffic counters"),
        ("$.api", "gRPC API"),
        ("$.metrics", "metrics endpoint"),
        ("$.version", "version range"),
        ("$.geodata", "never downloads"),
    ] {
        let message = warning_at(&warnings, path);
        assert!(message.contains("is ignored"), "{path}: {message}");
        assert!(message.contains(text), "{path}: {message}");
    }
    assert_eq!(warnings.len(), 5, "{warnings:?}");
}

#[test]
fn null_root_apps_are_silent_and_other_values_fail_as_go_decoding_fails() {
    let raw = json!({
        "stats": null, "api": null, "metrics": null, "version": null, "geodata": null,
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    });
    assert!(warnings_of(&raw).is_empty());

    for key in ["stats", "api", "metrics", "version", "geodata"] {
        let raw = json!({key: "on", "outbounds": [{"tag": "direct", "protocol": "freedom"}]});
        assert_eq!(error_paths(&raw), [format!("$.{key}")], "{key}");
    }
    let raw = json!({"version": {"min": 26}, "outbounds": []});
    assert_eq!(error_paths(&raw), ["$.version.min"]);
}

#[test]
fn routing_domain_matcher_is_ignored_with_a_warning() {
    for matcher in [json!("hybrid"), json!("linear"), json!(null)] {
        let raw = json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"domainStrategy": "AsIs", "domainMatcher": matcher, "rules": []}
        });
        let warnings = warnings_of(&raw);
        let message = warning_at(&warnings, "$.routing.domainMatcher");
        assert!(message.contains("is ignored"), "{message}");
    }
}

#[test]
fn client_side_tls_knobs_are_type_checked_and_ignored_with_warnings() {
    let raw = tls_profile(json!({
        "serverName": "proxy.example",
        "fingerprint": "chrome",
        "minVersion": "1.2",
        "maxVersion": "1.3",
        "cipherSuites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA256",
        "curvePreferences": ["X25519", "CurveP256"],
        "useSystemCA": true,
        "show": false
    }));
    let warnings = warnings_of(&raw);
    let base = "$.outbounds[0].streamSettings.tlsSettings";
    for key in ["minVersion", "maxVersion", "cipherSuites"] {
        let message = warning_at(&warnings, &format!("{base}.{key}"));
        assert!(message.contains("uTLS fingerprint"), "{key}: {message}");
    }
    assert!(warning_at(&warnings, &format!("{base}.curvePreferences")).contains("key shares"));
    assert!(warning_at(&warnings, &format!("{base}.useSystemCA")).contains("Mozilla roots"));
    assert!(warning_at(&warnings, &format!("{base}.show")).contains("REALITY"));
    assert_eq!(warnings.len(), 6, "{warnings:?}");

    // The defaults Xray-core writes into exported profiles say nothing.
    let raw = tls_profile(json!({
        "serverName": "proxy.example",
        "minVersion": "",
        "maxVersion": "",
        "cipherSuites": "",
        "curvePreferences": [],
        "disableSystemRoot": false,
        "useSystemCA": false,
        "echConfigList": ""
    }));
    assert!(warnings_of(&raw).is_empty());

    for (key, value) in [
        ("minVersion", json!(1.2)),
        ("cipherSuites", json!(["TLS_AES_128_GCM_SHA256"])),
        ("curvePreferences", json!(25519)),
        ("useSystemCA", json!("yes")),
        ("echConfigList", json!({})),
    ] {
        let raw = tls_profile(json!({"serverName": "proxy.example", key: value}));
        assert_eq!(
            error_paths(&raw),
            [format!("$.outbounds[0].streamSettings.tlsSettings.{key}")],
            "{key}"
        );
    }
}

/// With `fingerprint: "unsafe"` Xray-core's crypto/tls applies these four,
/// and the rustls handshake here would not: a `minVersion` of 1.3 would
/// accept a TLS 1.2 server. They fail there instead of being ignored.
#[test]
fn the_unsafe_fingerprint_refuses_the_tls_knobs_xray_core_applies_to_it() {
    let base = "$.outbounds[0].streamSettings.tlsSettings";
    for (key, value) in [
        ("minVersion", json!("1.3")),
        ("maxVersion", json!("1.2")),
        (
            "cipherSuites",
            json!("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        ),
        ("curvePreferences", json!(["X25519MLKEM768"])),
        ("curvePreferences", json!("X25519")),
    ] {
        let raw = tls_profile(json!({
            "serverName": "proxy.example",
            "fingerprint": "unsafe",
            key: value
        }));
        assert_eq!(error_paths(&raw), [format!("{base}.{key}")], "{key}");
    }

    // What says nothing still says nothing, and the fields no handshake
    // reads keep their warnings.
    let raw = tls_profile(json!({
        "serverName": "proxy.example",
        "fingerprint": "unsafe",
        "minVersion": "",
        "maxVersion": "",
        "cipherSuites": "",
        "curvePreferences": [],
        "useSystemCA": true
    }));
    let warnings = warnings_of(&raw);
    assert!(warning_at(&warnings, &format!("{base}.useSystemCA")).contains("Mozilla roots"));
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

#[test]
fn ech_config_list_fails_rather_than_connecting_without_ech() {
    // Xray-core fails a connection it cannot give ECH; connecting without it
    // would send the server name in the clear, so the config is refused.
    let raw = tls_profile(json!({
        "serverName": "proxy.example",
        "echConfigList": "AEX+DQBBpQAgACB/synthetic/ech/config/list/AAQAAQABAA5wdWJsaWMuZXhhbXBsZQAA"
    }));
    let error = parse_xray_json(&raw.to_string()).expect_err("ECH must not be dropped");
    let path = "$.outbounds[0].streamSettings.tlsSettings.echConfigList";
    let diagnostic = error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.path.as_deref() == Some(path))
        .unwrap_or_else(|| panic!("no error at {path}: {:?}", error.diagnostics));
    assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
    assert!(
        diagnostic.message.contains("Encrypted Client Hello"),
        "{}",
        diagnostic.message
    );
    assert_eq!(error_paths(&raw), [path]);
}

#[test]
fn disable_system_root_is_accepted_only_where_pins_decide_trust() {
    let pin = "0000000000000000000000000000000000000000000000000000000000000000";
    let raw = tls_profile(json!({
        "serverName": "proxy.example",
        "disableSystemRoot": true,
        "pinnedPeerCertSha256": pin
    }));
    let warnings = warnings_of(&raw);
    assert!(warning_at(
        &warnings,
        "$.outbounds[0].streamSettings.tlsSettings.disableSystemRoot"
    )
    .contains("pinnedPeerCertSha256"));

    for pins in [None, Some(""), Some(" , ")] {
        let mut tls = json!({"serverName": "proxy.example", "disableSystemRoot": true});
        if let Some(pins) = pins {
            tls["pinnedPeerCertSha256"] = json!(pins);
        }
        assert_eq!(
            error_paths(&tls_profile(tls)),
            ["$.outbounds[0].streamSettings.tlsSettings.disableSystemRoot"],
            "{pins:?}"
        );
    }
}

#[test]
fn removed_socket_and_mkcp_knobs_are_ignored_with_warnings() {
    let raw = json!({"outbounds": [vless(json!({
        "network": "tcp",
        "sockopt": {"tcpNoDelay": true, "tcpFastOpen": true}
    }))]});
    let warnings = warnings_of(&raw);
    assert!(warning_at(
        &warnings,
        "$.outbounds[0].streamSettings.sockopt.tcpNoDelay"
    )
    .contains("TCP_NODELAY"));

    let raw = json!({"outbounds": [vless(json!({
        "network": "kcp",
        "kcpSettings": {
            "mtu": 1350,
            "congestion": false,
            "readBufferSize": 2,
            "writeBufferSize": 2
        }
    }))]});
    let warnings = warnings_of(&raw);
    for key in ["congestion", "readBufferSize", "writeBufferSize"] {
        let message = warning_at(
            &warnings,
            &format!("$.outbounds[0].streamSettings.kcpSettings.{key}"),
        );
        assert!(
            message.contains("Xray-core v26 ignores"),
            "{key}: {message}"
        );
    }
}

#[test]
fn unknown_keys_next_to_the_inert_ones_still_fail() {
    let raw = json!({
        "stats": {},
        "statistics": {},
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    });
    assert_eq!(error_paths(&raw), ["$.statistics"]);

    let raw = tls_profile(json!({"serverName": "proxy.example", "masterKeyLog": "keys.log"}));
    assert_eq!(
        error_paths(&raw),
        ["$.outbounds[0].streamSettings.tlsSettings.masterKeyLog"]
    );
}
