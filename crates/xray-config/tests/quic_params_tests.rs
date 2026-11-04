//! `finalmask.quicParams` as Xray-core v26.10.31's Hysteria and XHTTP H3
//! dialers read it.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity, QuicBbrProfile, QuicCongestion};

fn hysteria(quic: Value) -> String {
    let mut raw: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/configs/hysteria2.json"
    ))
    .unwrap();
    raw["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"] = quic;
    raw.to_string()
}

fn xhttp(alpn: &str, quic: Value) -> String {
    json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"server.example","port":443,
            "users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},
        "streamSettings":{"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"server.example","alpn":[alpn]},
            "finalmask":{"quicParams":quic}}}]})
    .to_string()
}

fn error_path(raw: &str) -> Option<String> {
    let error = parse_xray_json(raw).err()?;
    error
        .diagnostics
        .iter()
        .find(|d| d.severity == DiagnosticSeverity::Error)
        .and_then(|d| d.path.clone())
}

const QUIC: &str = "$.outbounds[0].streamSettings.finalmask.quicParams";

#[test]
fn hysteria_takes_every_quic_parameter_its_dialer_reads() {
    let parsed = parse_xray_json(&hysteria(json!({
        "disableChromeParrot": true,
        "congestion": "Brutal",
        "brutalUp": "100 mbps",
        "brutalDown": "200 mbps",
        "brutalDisableLossCompensation": true,
        "disableGSO": true,
        "disableStatelessReset": true,
        "maxIdleTimeout": 60,
        "keepAlivePeriod": 10,
        "initStreamReceiveWindow": 8388608,
        "maxStreamReceiveWindow": 8388608,
        "initConnectionReceiveWindow": 20971520,
        "maxConnectionReceiveWindow": 20971520,
        "disablePathMTUDiscovery": true,
        "maxIncomingStreams": 1024
    })))
    .expect("Xray-core accepts this Hysteria quicParams block");
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let quic = parsed.config.outbounds[0]
        .stream
        .quic_params
        .as_ref()
        .unwrap();
    assert_eq!(quic.congestion, QuicCongestion::Brutal);
    // Xray's bandwidth units are binary: 1 mbps is 2^20 bits per second.
    assert_eq!(quic.brutal_up_bytes_per_sec, 100 << 17);
    assert_eq!(quic.brutal_down_bytes_per_sec, 200 << 17);
    assert!(quic.brutal_disable_loss_compensation && quic.disable_gso);
    assert!(quic.disable_stateless_reset && quic.disable_path_mtu_discovery);
    assert_eq!(
        (quic.max_idle_timeout_secs, quic.keep_alive_period_secs),
        (60, 10)
    );
    assert_eq!(quic.init_connection_receive_window, 20_971_520);
}

#[test]
fn bbr_profiles_other_than_standard_are_refused_where_bbr_may_run() {
    for raw in [
        hysteria(json!({"bbrProfile": "conservative"})),
        hysteria(json!({"congestion": "bbr", "bbrProfile": "aggressive"})),
        // Hysteria falls back to BBR when the server announces no rate.
        hysteria(
            json!({"congestion": "brutal", "brutalUp": "10 mbps", "bbrProfile": "aggressive"}),
        ),
        xhttp("h3", json!({"bbrProfile": "aggressive"})),
        xhttp(
            "h3",
            json!({"congestion": "bbr", "bbrProfile": "conservative"}),
        ),
    ] {
        assert_eq!(
            error_path(&raw),
            Some(format!("{QUIC}.bbrProfile")),
            "{raw}"
        );
    }
    for raw in [
        hysteria(json!({"congestion": "reno", "bbrProfile": "conservative"})),
        hysteria(
            json!({"congestion": "force-brutal", "brutalUp": "10 mbps", "bbrProfile": "aggressive"}),
        ),
        xhttp(
            "h3",
            json!({"congestion": "reno", "bbrProfile": "aggressive"}),
        ),
        // Off h3, Xray does not consult quicParams at all.
        xhttp("h2", json!({"bbrProfile": "conservative"})),
    ] {
        let parsed = parse_xray_json(&raw).unwrap_or_else(|e| panic!("{raw}: {e:?}"));
        let quic = parsed.config.outbounds[0]
            .stream
            .quic_params
            .as_ref()
            .unwrap();
        assert_ne!(quic.bbr_profile, QuicBbrProfile::Standard);
    }
}

#[test]
fn plain_brutal_needs_a_hysteria_server() {
    assert_eq!(
        error_path(&xhttp(
            "h3",
            json!({"congestion": "brutal", "brutalUp": "10 mbps"})
        )),
        Some(format!("{QUIC}.congestion")),
        "Xray's XHTTP dialer panics on it"
    );
    for raw in [
        xhttp(
            "h3",
            json!({"congestion": "force-brutal", "brutalUp": "10 mbps"}),
        ),
        xhttp("h2", json!({"congestion": "brutal"})),
        hysteria(json!({"congestion": "brutal"})),
    ] {
        parse_xray_json(&raw).unwrap_or_else(|e| panic!("{raw}: {e:?}"));
    }
}
