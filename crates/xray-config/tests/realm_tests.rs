//! The `realm` mask's settings against what Xray-core's `Realm.Build` does
//! with them, from `tests/fixtures/realm/vectors.json`, which
//! `tools/realm-oracle` records in the pinned checkout.
use serde_json::{json, Value};
use xray_config::{parse_xray_json, RealmIpMode, RealmPortMapping, RealmScheme};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../tests/fixtures/realm/vectors.json")).unwrap()
}

fn config(stream: Value) -> String {
    json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"server.example","port":443,
            "users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},
        "streamSettings":stream}]})
    .to_string()
}

fn kcp(masks: Value) -> String {
    config(json!({"network":"kcp","finalmask":{"udp":masks}}))
}

fn realm(settings: Value) -> Value {
    json!({"type":"realm","settings":settings})
}

fn parse_realm(settings: Value) -> Result<xray_config::RealmMask, Vec<String>> {
    match parse_xray_json(&kcp(json!([realm(settings)]))) {
        Ok(parsed) => Ok(parsed.config.outbounds[0].stream.udp_realm.clone().unwrap()),
        Err(error) => Err(error
            .diagnostics
            .into_iter()
            .map(|d| format!("{}: {}", d.path.unwrap_or_default(), d.message))
            .collect()),
    }
}

fn refused(text: &str, expected: &str) {
    let errors: Vec<String> = parse_xray_json(text)
        .unwrap_err()
        .diagnostics
        .into_iter()
        .map(|d| d.message)
        .collect();
    assert!(
        errors.iter().any(|error| error.contains(expected)),
        "{expected:?} not in {errors:?}"
    );
}

/// What xray-rust refuses on purpose where Xray-core accepts the URL and
/// then fails every dial, or carries bytes it cannot keep.
fn deliberately_refused(case: &Value) -> bool {
    let text = |key: &str| case[key].as_str().unwrap_or_default();
    let port_ok = text("port")
        .parse::<u32>()
        .is_ok_and(|port| (1..=65_535).contains(&port));
    let host = text("host");
    let host_ok = !host.contains(':') || host.parse::<std::net::Ipv6Addr>().is_ok();
    // Go's JSON writes a byte that is not UTF-8 as U+FFFD.
    let token_ok = !text("token").contains('\u{FFFD}')
        && !text("token")
            .bytes()
            .any(|b| (b < b' ' && b != b'\t') || b == 0x7f);
    let id_ok = !text("id").contains('\u{FFFD}');
    !(port_ok && host_ok && token_ok && id_ok)
}

#[test]
fn urls_read_as_realm_build_reads_them() {
    let vectors = vectors();
    let (mut matched, mut deliberate) = (0, 0);
    for case in vectors["urls"].as_array().unwrap() {
        let url = case["url"].as_str().unwrap();
        let parsed = parse_realm(json!({"url": url, "stunServers": ["stun.example:3478"]}));
        if case.get("error").is_some() {
            assert!(
                parsed.is_err(),
                "{url:?} is refused by Xray-core: {parsed:?}"
            );
            matched += 1;
            continue;
        }
        if deliberately_refused(case) {
            assert!(parsed.is_err(), "{url:?} should be refused here");
            deliberate += 1;
            continue;
        }
        let mask = parsed.unwrap_or_else(|errors| panic!("{url:?}: {errors:?}"));
        let scheme = match mask.scheme {
            RealmScheme::Https => "https",
            RealmScheme::Http => "http",
        };
        assert_eq!(scheme, case["scheme"], "{url:?}");
        assert_eq!(mask.host, case["host"].as_str().unwrap(), "{url:?}");
        assert_eq!(mask.port_text, case["port"].as_str().unwrap(), "{url:?}");
        assert_eq!(
            mask.token.as_str(),
            case["token"].as_str().unwrap(),
            "{url:?}"
        );
        assert_eq!(mask.id, case["id"].as_str().unwrap(), "{url:?}");
        matched += 1;
    }
    assert!(matched > 50 && deliberate >= 8, "{matched} {deliberate}");
}

#[test]
fn stun_servers_read_as_realm_build_and_the_client_read_them() {
    for case in vectors()["stunServers"].as_array().unwrap() {
        let server = case["server"].as_str().unwrap();
        let parsed = parse_realm(json!({"url": "realm://t@host/x", "stunServers": [server]}));
        // Xray-core skips a server whose port does not read and sends
        // nothing to one out of range; both are refused here.
        let usable = case.get("error").is_none()
            && case["port"]
                .as_i64()
                .is_some_and(|port| (1..=65_535).contains(&port));
        match parsed {
            Ok(mask) => {
                assert!(usable, "{server:?} accepted");
                assert_eq!(
                    i64::from(mask.stun_servers[0].port),
                    case["port"].as_i64().unwrap()
                );
            }
            Err(_) => assert!(!usable, "{server:?} refused"),
        }
    }
}

#[test]
fn other_settings_read_as_realm_build_reads_them() {
    for case in vectors()["settings"].as_array().unwrap() {
        let settings = &case["settings"];
        let parsed = parse_realm(settings.clone());
        if case.get("error").is_some() {
            assert!(parsed.is_err(), "{settings} is refused by Xray-core");
            continue;
        }
        let mask = parsed.unwrap_or_else(|errors| panic!("{settings}: {errors:?}"));
        let expected = match case["ipMode"].as_str().unwrap_or_default() {
            "v4" => RealmIpMode::V4,
            "v6" => RealmIpMode::V6,
            _ => RealmIpMode::Dual,
        };
        assert_eq!(mask.ip_mode, expected, "{settings}");
        let mapping = case.get("portMapping").map(|m| RealmPortMapping {
            enabled: m["enabled"].as_bool().unwrap(),
            timeout: m["timeout"].as_i64().unwrap(),
            lifetime: m["lifetime"].as_i64().unwrap(),
        });
        assert_eq!(mask.port_mapping, mapping, "{settings}");
    }
}

#[test]
fn realm_is_the_last_mask_and_runs_only_where_it_can() {
    let minimal =
        json!({"url":"realm://t@rendezvous.example/name","stunServers":["stun.example.net:3478"]});
    // Inside realm, the carrier's masks run on its datagrams.
    parse_xray_json(&kcp(json!([
        {"type":"mkcp-legacy","settings":{"value":"seed"}},
        {"type":"noise","settings":{"noise":[{"rand":"10-20"}]}},
        realm(minimal.clone())
    ])))
    .unwrap();
    refused(
        &kcp(
            json!([realm(minimal.clone()), {"type":"noise","settings":{"noise":[{"rand":"10-20"}]}}]),
        ),
        "realm must be the last UDP mask",
    );
    refused(
        &kcp(
            json!([{"type":"header-custom","settings":{"client":[{"packet":[1]}],"server":[{"packet":[2]}]}}, realm(minimal.clone())]),
        ),
        "cannot be combined with realm",
    );
    refused(
        &config(json!({"network":"raw","finalmask":{"udp":[realm(minimal.clone())]}})),
        "requires mKCP, Hysteria or XHTTP",
    );
    refused(
        &kcp(json!([realm(minimal.clone()), realm(minimal)])),
        "one realm",
    );
}

#[test]
fn tls_config_reads_as_tls_settings_do() {
    let mask = parse_realm(json!({
        "url":"realm://t@rendezvous.example/name","stunServers":["stun.example.net:3478"],
        "tlsConfig":{"serverName":"front.example","pinnedPeerCertSha256":"00".repeat(32),"fingerprint":"firefox"}
    }))
    .unwrap();
    let tls = mask.tls.unwrap();
    assert_eq!(tls.server_name.as_deref(), Some("front.example"));
    assert_eq!(tls.pinned_peer_cert_sha256, vec![[0u8; 32]]);
    for bad in [
        json!({"fingerprint":"nope"}),
        json!({"allowInsecure":true}),
        json!({"pinnedPeerCertSha256":"zz"}),
        json!({"echConfigList":"x"}),
    ] {
        assert!(parse_realm(json!({
            "url":"realm://t@rendezvous.example/name","stunServers":["stun.example.net:3478"],
            "tlsConfig":bad
        }))
        .is_err());
    }
}
