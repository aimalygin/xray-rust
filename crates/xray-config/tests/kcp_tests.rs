//! mKCP's `kcpSettings` and `mkcp-legacy` masks, read as Xray-core v26.10.31
//! reads them.
use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, KcpHeader, KcpMask, KcpSettings, StreamSecurity,
    StreamTransport,
};

fn outbound(stream: Value) -> Value {
    json!({"outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "server.example", "port": 443,
            "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]},
        "streamSettings": stream,
    }]})
}

fn kcp(stream: Value) -> KcpSettings {
    let parsed = parse_xray_json(&outbound(stream).to_string()).unwrap();
    match &parsed.config.outbounds[0].stream.transport {
        StreamTransport::Kcp(kcp) => kcp.clone(),
        other => panic!("not mKCP: {other:?}"),
    }
}

fn errors(stream: Value) -> Vec<String> {
    parse_xray_json(&outbound(stream).to_string())
        .err()
        .map(|error| {
            error
                .diagnostics
                .into_iter()
                .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
                .map(|diagnostic| {
                    format!(
                        "{}: {}",
                        diagnostic.path.unwrap_or_default(),
                        diagnostic.message
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn warnings(stream: Value) -> Vec<String> {
    parse_xray_json(&outbound(stream).to_string())
        .unwrap()
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
        .map(|diagnostic| diagnostic.message)
        .collect()
}

fn masks(masks: Value) -> Vec<KcpMask> {
    kcp(json!({"network": "kcp", "finalmask": {"udp": masks}})).masks
}

#[test]
fn both_names_select_mkcp_with_xray_defaults() {
    for network in ["kcp", "mkcp", "KCP", "mKCP"] {
        assert_eq!(kcp(json!({"network": network})), KcpSettings::default());
    }
    assert_eq!(
        kcp(json!({"network": "kcp", "kcpSettings": null})),
        KcpSettings::default()
    );
    let defaults = KcpSettings::default();
    assert_eq!(
        (
            defaults.mtu,
            defaults.tti,
            defaults.uplink_capacity,
            defaults.downlink_capacity,
            defaults.cwnd_multiplier,
            defaults.max_sending_window
        ),
        (1350, 50, 5, 20, 1, 2 * 1024 * 1024)
    );
}

#[test]
fn every_field_is_read_and_null_keeps_the_default() {
    let settings = kcp(json!({"network": "kcp", "kcpSettings": {
        "mtu": 1200, "tti": 20, "uplinkCapacity": 100, "downlinkCapacity": 0,
        "cwndMultiplier": 4, "maxSendingWindow": 1200,
    }}));
    assert_eq!(
        (
            settings.mtu,
            settings.tti,
            settings.uplink_capacity,
            settings.downlink_capacity,
            settings.cwnd_multiplier,
            settings.max_sending_window
        ),
        (1200, 20, 100, 0, 4, 1200)
    );
    let settings = kcp(json!({"network": "kcp", "kcpSettings": {
        "mtu": null, "tti": null, "uplinkCapacity": null, "downlinkCapacity": null,
        "cwndMultiplier": null, "maxSendingWindow": null, "header": null, "seed": null,
    }}));
    assert_eq!(settings, KcpSettings::default());
}

#[test]
fn bounds_are_xrays() {
    let accepted = [
        json!({"mtu": 21, "maxSendingWindow": 21}),
        json!({"mtu": 8192}),
        json!({"tti": 10}),
        json!({"tti": 1000}),
        json!({"mtu": 1350, "maxSendingWindow": 1350}),
    ];
    for settings in accepted {
        kcp(json!({"network": "kcp", "kcpSettings": settings}));
    }
    let refused = [
        (json!({"mtu": 20}), "mtu: MTU must be at least 21"),
        (json!({"mtu": 0}), "mtu: MTU must be at least 21"),
        (json!({"mtu": 8193}), "mtu: MTU must be at most 8192"),
        (json!({"tti": 9}), "tti: TTI must be between 10 and 1000"),
        (json!({"tti": 1001}), "tti: TTI must be between 10 and 1000"),
        (
            json!({"cwndMultiplier": 0}),
            "cwndMultiplier: CwndMultiplier must be at least 1",
        ),
        (
            json!({"maxSendingWindow": 1349}),
            "maxSendingWindow: MaxSendingWindow must be at least 1350",
        ),
        (
            json!({"mtu": 21, "maxSendingWindow": 20}),
            "maxSendingWindow: MaxSendingWindow must be at least 21",
        ),
    ];
    for (settings, expected) in refused {
        let errors = errors(json!({"network": "kcp", "kcpSettings": settings}));
        assert!(
            errors.iter().any(|error| error.contains(expected)),
            "{settings}: {errors:?}"
        );
    }
}

#[test]
fn fields_must_decode_as_go_decodes_them() {
    for settings in [
        json!({"mtu": -1}),
        json!({"mtu": 1350.5}),
        json!({"mtu": "1350"}),
        json!({"mtu": 4_294_967_296_u64}),
        json!({"tti": true}),
        json!({"uplinkCapacity": [1]}),
        json!({"seed": 5}),
        json!({"seed": {}}),
        json!({"unknown": 1}),
    ] {
        assert!(
            !errors(json!({"network": "kcp", "kcpSettings": settings.clone()})).is_empty(),
            "{settings}"
        );
    }
    for settings in [json!("x"), json!(5), json!([])] {
        assert!(
            !errors(json!({"network": "kcp", "kcpSettings": settings.clone()})).is_empty(),
            "{settings}"
        );
    }
    // `header` is raw JSON there: any value decodes.
    for header in [
        json!(5),
        json!("wechat-video"),
        json!([1]),
        json!({"type": 7}),
    ] {
        kcp(json!({"network": "kcp", "kcpSettings": {"header": header}}));
    }
}

#[test]
fn the_old_header_and_seed_warn_that_they_are_ignored() {
    let ignored = warnings(json!({"network": "kcp", "kcpSettings": {
        "header": {"type": "wechat-video"}, "seed": "secret",
    }}));
    assert_eq!(
        ignored
            .iter()
            .filter(|warning| warning.contains("ignores kcpSettings"))
            .count(),
        2,
        "{ignored:?}"
    );
    let quiet = warnings(json!({"network": "kcp", "kcpSettings": {
        "header": {"type": "none"}, "seed": "",
    }}));
    assert!(
        !quiet.iter().any(|warning| warning.contains("ignores")),
        "{quiet:?}"
    );
    // Ignored or not, the settings are the same.
    assert_eq!(
        kcp(json!({"network": "kcp", "kcpSettings": {
            "header": {"type": "wechat-video"}, "seed": "secret",
        }})),
        KcpSettings::default()
    );
}

#[test]
fn kcp_settings_under_another_network_are_still_checked() {
    let raw = json!({"network": "raw", "kcpSettings": {"mtu": 1200}});
    assert!(warnings(raw)
        .iter()
        .any(|warning| warning.contains("`kcpSettings` is ignored")));
    assert!(
        errors(json!({"network": "raw", "kcpSettings": {"mtu": 10}}))
            .iter()
            .any(|error| error.contains("MTU must be at least 21"))
    );
}

#[test]
fn tls_rides_on_mkcp_and_reality_does_not() {
    let parsed = parse_xray_json(
        &outbound(json!({"network": "kcp", "security": "tls",
            "tlsSettings": {"serverName": "server.example"}}))
        .to_string(),
    )
    .unwrap();
    assert!(matches!(
        parsed.config.outbounds[0].stream.security,
        StreamSecurity::Tls(_)
    ));
    let refused = errors(json!({"network": "kcp", "security": "reality",
        "realitySettings": {"serverName": "server.example", "fingerprint": "chrome",
            "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405"}}));
    assert!(
        refused
            .iter()
            .any(|error| error.contains("REALITY only supports RAW, XHTTP and gRPC")),
        "{refused:?}"
    );
}

#[test]
fn mkcp_legacy_builds_as_xray_builds_it() {
    let cases = [
        (json!({"type": "mkcp-legacy"}), KcpMask::Original),
        (
            json!({"type": "mkcp-legacy", "settings": null}),
            KcpMask::Original,
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": null, "value": ""}}),
            KcpMask::Original,
        ),
        (
            json!({"type": "MKCP-LEGACY", "settings": {"value": "seed"}}),
            KcpMask::Aes128Gcm("seed".to_owned().into()),
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "dns"}}),
            KcpMask::Header(KcpHeader::Dns("www.baidu.com".into())),
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "DNS", "value": "a.example"}}),
            KcpMask::Header(KcpHeader::Dns("a.example".into())),
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "dtls", "value": "x"}}),
            KcpMask::Header(KcpHeader::Dtls),
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "srtp"}}),
            KcpMask::Header(KcpHeader::Srtp),
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "Utp"}}),
            KcpMask::Header(KcpHeader::Utp),
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "wechat"}}),
            KcpMask::Header(KcpHeader::Wechat),
        ),
        // Go's strings.ToLower maps the dotted capital I to i and the Kelvin
        // sign to k, so these match too.
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "W\u{130}REGUARD"}}),
            KcpMask::Header(KcpHeader::Wireguard),
        ),
        (
            json!({"type": "m\u{212a}cp-legacy", "settings": {"header": "wireguard"}}),
            KcpMask::Header(KcpHeader::Wireguard),
        ),
    ];
    for (mask, expected) in cases {
        assert_eq!(masks(json!([mask.clone()])), [expected], "{mask}");
    }
}

#[test]
fn malformed_mkcp_legacy_is_refused() {
    let cases = [
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "wechat-video"}}),
            "invalid header wechat-video",
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": "none"}}),
            "invalid header none",
        ),
        (
            json!({"type": "mkcp-legacy", "settings": 5}),
            "settings must be an object or null",
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"header": 5}}),
            "must be a string or null",
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"value": []}}),
            "must be a string or null",
        ),
        (
            json!({"type": "mkcp-legacy", "settings": {"seed": "x"}}),
            "unsupported field `seed`",
        ),
    ];
    for (mask, expected) in cases {
        let errors = errors(json!({"network": "kcp", "finalmask": {"udp": [mask.clone()]}}));
        assert!(
            errors.iter().any(|error| error.contains(expected)),
            "{mask}: {errors:?}"
        );
    }
}

#[test]
fn masks_keep_their_array_order_around_noise() {
    let stream = json!({"network": "kcp", "finalmask": {"udp": [
        {"type": "mkcp-legacy", "settings": {"value": "seed"}},
        {"type": "noise", "settings": {"noise": [{"rand": 10}]}},
        {"type": "mkcp-legacy", "settings": {"header": "wechat"}},
        {"type": "mkcp-legacy"},
        {"type": "mkcp-legacy", "settings": {"header": "srtp"}},
    ]}});
    let parsed = parse_xray_json(&outbound(stream).to_string()).unwrap();
    let outbound = &parsed.config.outbounds[0];
    let StreamTransport::Kcp(kcp) = &outbound.stream.transport else {
        panic!("not mKCP");
    };
    assert_eq!(
        kcp.masks,
        [
            KcpMask::Aes128Gcm("seed".to_owned().into()),
            KcpMask::Noise,
            KcpMask::Header(KcpHeader::Wechat),
            KcpMask::Original,
            KcpMask::Header(KcpHeader::Srtp),
        ]
    );
    assert_eq!(outbound.stream.udp_noise.as_ref().unwrap().items.len(), 1);
}

#[test]
fn mkcp_legacy_needs_mkcp_and_mkcp_takes_no_quic_masks() {
    let legacy = json!([{"type": "mkcp-legacy"}]);
    let raw = errors(json!({"network": "raw", "finalmask": {"udp": legacy.clone()}}));
    assert!(
        raw.iter()
            .any(|error| error.contains("mkcp-legacy requires mKCP")),
        "{raw:?}"
    );
    let salamander = errors(json!({"network": "kcp", "finalmask": {"udp": [
        {"type": "salamander", "settings": {"password": "synthetic"}}]}}));
    assert!(
        salamander
            .iter()
            .any(|error| error.contains("Salamander requires Hysteria")),
        "{salamander:?}"
    );
    let hop = errors(json!({"network": "kcp", "finalmask": {"udp": [
        {"type": "udphop", "settings": {"remotePorts": "1000-2000"}}]}}));
    assert!(
        hop.iter().any(|error| error.contains("udphop requires")),
        "{hop:?}"
    );
}

#[test]
fn mask_debug_hides_the_seed() {
    let debug = format!("{:?}", KcpMask::Aes128Gcm("hunter2".to_owned().into()));
    assert!(!debug.contains("hunter2"), "{debug}");
}
