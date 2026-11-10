//! `xdriveSettings` and the outbounds XDRIVE carries, read as Xray-core
//! v26.10.31 reads them.
use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, xdrive_default_xmux, DiagnosticSeverity, StreamTransport, TargetAddr,
    XdriveService, XdriveSettings, XhttpRange,
};

const ENCRYPTION: &str =
    "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I";

fn outbound(xdrive: Value, stream: Value) -> Value {
    let mut stream_settings = json!({"network": "xdrive", "xdriveSettings": xdrive});
    for (key, value) in stream.as_object().unwrap() {
        stream_settings[key] = value.clone();
    }
    json!({"protocol": "vless",
        "settings": {"address": "127.0.0.1", "port": 443,
            "id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": ENCRYPTION},
        "streamSettings": stream_settings, "mux": {"enabled": true}})
}

fn settings_with(xdrive: Value, stream: Value) -> XdriveSettings {
    let raw = json!({"outbounds": [outbound(xdrive, stream)]}).to_string();
    let parsed = parse_xray_json(&raw).unwrap();
    match &parsed.config.outbounds[0].stream.transport {
        StreamTransport::Xdrive(settings) => (**settings).clone(),
        other => panic!("not XDRIVE: {other:?}"),
    }
}

fn settings(xdrive: Value) -> XdriveSettings {
    settings_with(xdrive, json!({}))
}

fn errors(raw: Value) -> Vec<String> {
    parse_xray_json(&json!({"outbounds": [raw]}).to_string())
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
        "../../../tests/fixtures/xdrive/config-verdicts.json"
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
fn local_keeps_its_folder_and_the_numbers_as_written() {
    let parsed = settings(json!({"service": "local", "remoteFolder": "/srv/xdrive",
        "segmentBytes": 65536, "flushIntervalMs": 5, "pollIntervalMs": 10,
        "maxPollIntervalMs": 0, "sessionTtlSeconds": 60, "concurrency": 100,
        "eagerWindowMs": null, "holeTimeoutMs": 4294967295u32}));
    assert_eq!(parsed.service, XdriveService::Local);
    assert_eq!(parsed.remote_folder, "/srv/xdrive");
    assert_eq!(
        (
            parsed.segment_bytes,
            parsed.flush_interval_ms,
            parsed.poll_interval_ms,
            parsed.max_poll_interval_ms,
            parsed.session_ttl_seconds,
            parsed.concurrency,
            parsed.eager_window_ms,
            parsed.hole_timeout_ms
        ),
        (65536, 5, 10, 0, 60, 100, 0, u32::MAX)
    );
    assert!(parsed.secrets.is_empty() && parsed.template.is_none() && parsed.s3.is_none());
    assert_eq!(parsed.xmux, xdrive_default_xmux(1));
}

#[test]
fn absent_settings_keep_xrays_registered_default() {
    let raw = json!({"outbounds": [{"protocol": "vless",
        "settings": {"address": "127.0.0.1", "port": 443,
            "id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": ENCRYPTION},
        "streamSettings": {"network": "xdrive"}, "mux": {"enabled": true}}]})
    .to_string();
    let parsed = parse_xray_json(&raw).unwrap();
    let StreamTransport::Xdrive(xdrive) = &parsed.config.outbounds[0].stream.transport else {
        panic!("not XDRIVE");
    };
    assert_eq!(xdrive.service, XdriveService::Unset);
    // No xmux at all, as the registered default has none.
    assert_eq!(xdrive.xmux.max_connections, XhttpRange::default());
    assert_eq!(xdrive.xmux.h_max_reusable_secs, XhttpRange::default());
}

#[test]
fn google_drive_takes_four_connections_unless_over_h3() {
    let drive = json!({"service": "google-drive", "remoteFolder": "f", "secrets": ["a", "b", "c"]});
    assert_eq!(settings(drive.clone()).xmux, xdrive_default_xmux(4));
    let tls = |alpn: Value| json!({"security": "tls", "tlsSettings": {"alpn": alpn}});
    assert_eq!(
        settings_with(drive.clone(), tls(json!(["h3"]))).xmux,
        xdrive_default_xmux(1)
    );
    assert_eq!(
        settings_with(drive.clone(), tls(json!(["h2"]))).xmux,
        xdrive_default_xmux(4)
    );
    assert_eq!(
        settings_with(drive.clone(), tls(json!(["h3", "h2"]))).xmux,
        xdrive_default_xmux(4)
    );
    // Every other service takes one, over any protocol.
    let template = json!({"service": "template", "template": {}});
    assert_eq!(settings(template).xmux, xdrive_default_xmux(1));
    // The deprecated spelling is Google Drive, with a warning.
    let raw = json!({"outbounds": [outbound(
        json!({"service": "Google Drive", "remoteFolder": "f", "secrets": ["a", "b", "c"]}),
        json!({}))]})
    .to_string();
    let parsed = parse_xray_json(&raw).unwrap();
    assert!(parsed
        .diagnostics
        .iter()
        .any(|d| d.severity == DiagnosticSeverity::Warning && d.message.contains("deprecated")));
    let StreamTransport::Xdrive(xdrive) = &parsed.config.outbounds[0].stream.transport else {
        panic!("not XDRIVE");
    };
    assert_eq!(xdrive.service, XdriveService::GoogleDrive);
    assert_eq!(xdrive.xmux, xdrive_default_xmux(4));
}

#[test]
fn an_xmux_with_any_field_set_stays_as_written() {
    let parsed = settings(json!({"service": "google-drive", "remoteFolder": "f",
        "secrets": ["a", "b", "c"],
        "xmux": {"maxConcurrency": "1-2", "hMaxRequestTimes": 100, "hKeepAlivePeriod": -1}}));
    assert_eq!(parsed.xmux.max_concurrency, XhttpRange { from: 1, to: 2 });
    assert_eq!(parsed.xmux.max_connections, XhttpRange::default());
    assert_eq!(
        parsed.xmux.h_max_request_times,
        XhttpRange { from: 100, to: 100 }
    );
    assert_eq!(parsed.xmux.h_max_reusable_secs, XhttpRange::default());
    assert_eq!(parsed.xmux.h_keep_alive_period_secs, -1);
}

#[test]
fn secrets_keep_their_order_and_null_reads_empty() {
    let parsed = settings(json!({"service": "google-drive", "remoteFolder": "f",
        "secrets": ["client", null, "refresh"]}));
    let secrets: Vec<&str> = parsed.secrets.iter().map(|s| s.as_str()).collect();
    assert_eq!(secrets, ["client", "", "refresh"]);
}

#[test]
fn s3_defaults_to_path_style_and_only_s3_keeps_the_block() {
    let base = json!({"service": "s3", "remoteFolder": "prefix/",
        "secrets": ["AKIDEXAMPLE", "secret"],
        "s3": {"endpoint": "https://s3.example/root", "bucket": "b"}});
    let parsed = settings(base.clone());
    let s3 = parsed.s3.unwrap();
    assert!(s3.path_style);
    assert_eq!(s3.endpoint, "https://s3.example/root");
    assert_eq!(s3.region, "");
    assert_eq!(s3.bucket, "b");
    let mut virtual_hosted = base;
    virtual_hosted["s3"]["pathStyle"] = json!(false);
    assert!(!settings(virtual_hosted).s3.unwrap().path_style);
    let local = settings(json!({"service": "local", "remoteFolder": "/x",
        "s3": {"endpoint": "ftp://x"}}));
    assert!(local.s3.is_none());
}

#[test]
fn templates_keep_their_value_whatever_it_is() {
    let parsed = settings(json!({"service": "template", "template": null}));
    assert_eq!(parsed.template.as_deref().map(String::as_str), Some("null"));
    let parsed = settings(json!({"service": "template", "template": {"put": {"url": "u"}}}));
    let template: Value = serde_json::from_str(parsed.template.as_ref().unwrap()).unwrap();
    assert_eq!(template, json!({"put": {"url": "u"}}));
}

#[test]
fn debug_hides_secrets_and_the_template() {
    let parsed = settings(json!({"service": "template", "secrets": ["hunter2-secret"],
        "template": {"auth": {"header": {"Authorization": "Bearer top-secret-token"}}}}));
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("hunter2-secret"), "{debug}");
    assert!(!debug.contains("top-secret-token"), "{debug}");
    assert!(debug.contains("secrets: 1"), "{debug}");
}

#[test]
fn refusals_name_xrays_reasons() {
    let local = json!({"service": "local", "remoteFolder": "/x"});
    let vless = |settings: Value, mux: Value| {
        let mut raw = outbound(local.clone(), json!({}));
        for (key, value) in settings.as_object().unwrap() {
            raw["settings"][key] = value.clone();
        }
        raw["mux"] = mux;
        errors(raw)
    };
    let joined = |errors: Vec<String>| errors.join("\n");
    assert!(joined(vless(
        json!({"encryption": "none"}),
        json!({"enabled": true})
    ))
    .contains(r#"needs VLESS "encryption""#));
    assert!(joined(vless(json!({}), json!({"enabled": false}))).contains(r#"needs "mux" enabled"#));
    assert!(joined(vless(
        json!({}),
        json!({"enabled": true, "xudpProxyUDP443": "skip"})
    ))
    .contains(r#"needs "mux" enabled"#));
    assert!(
        joined(vless(json!({"testpre": 2}), json!({"enabled": true})))
            .contains(r#"doesn't support VLESS "testpre""#)
    );
    assert!(joined(vless(
        json!({"flow": "xtls-rprx-vision"}),
        json!({"enabled": true, "concurrency": -1})
    ))
    .contains(r#"doesn't support VLESS "flow""#));
    let trojan = json!({"protocol": "trojan",
        "settings": {"address": "x.example", "port": 443, "password": "p"},
        "streamSettings": {"network": "xdrive", "xdriveSettings": local}, "mux": {"enabled": true}});
    assert!(joined(errors(trojan)).contains("can only be used by VLESS"));
    let drive = json!({"service": "google-drive", "remoteFolder": "f", "secrets": ["a", "b", "c"]});
    let h3 = json!({"security": "tls", "tlsSettings": {"alpn": ["h3"]},
        "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "p"}}]}});
    assert!(joined(errors(outbound(drive, h3)))
        .contains(r#"the only "udp" mask that works is "noise", not "salamander""#));
}

#[test]
fn fronting_takes_the_streams_address_and_port() {
    let fronting = |stream: Value| {
        settings_with(json!({"service": "local", "remoteFolder": "/f"}), stream).fronting
    };
    assert_eq!(
        fronting(json!({"address": " [::1] ", "port": 8443})),
        Some((TargetAddr::Ip("::1".parse().unwrap()), 8443))
    );
    assert_eq!(
        fronting(json!({"address": "front.example"})),
        Some((TargetAddr::Domain("front.example".to_owned()), 0))
    );
    assert_eq!(fronting(json!({"port": 8443})), None);
    assert_eq!(fronting(json!({"address": null, "port": null})), None);
}
