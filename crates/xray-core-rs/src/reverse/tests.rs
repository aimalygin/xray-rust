use super::*;

#[test]
fn the_monitor_opens_a_tunnel_when_none_is_active_or_each_holds_more_than_16() {
    assert!(wants_tunnel(0, 0));
    assert!(wants_tunnel(0, 100));
    assert!(!wants_tunnel(1, 0));
    assert!(!wants_tunnel(1, 16));
    assert!(wants_tunnel(1, 17));
    // Xray-core divides in whole numbers: 33 over 2 is 16.
    assert!(!wants_tunnel(2, 33));
    assert!(wants_tunnel(2, 34));
}

#[test]
fn a_tunnel_is_active_until_it_closes_or_drains() {
    let tunnel = TunnelState::default();
    assert!(tunnel.is_active());
    tunnel.draining.store(true, Ordering::Release);
    assert!(!tunnel.is_active());
    let tunnel = TunnelState::default();
    tunnel.closed.store(true, Ordering::Release);
    assert!(!tunnel.is_active());
}

#[test]
fn bridges_are_the_vless_outbounds_with_reverse() {
    let config = xray_config::parse_xray_json(
        &serde_json::json!({"outbounds": [
            {"protocol": "freedom"},
            {"protocol": "vless", "settings": {"address": "portal.example", "port": 443,
                "id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}},
            {"protocol": "vless", "settings": {"address": "portal.example", "port": 443,
                "id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none",
                "level": 3, "email": "b@example.com", "reverse": {"tag": "r-in"}}},
        ]})
        .to_string(),
    )
    .unwrap()
    .config;
    let found = bridges(&config);
    assert_eq!(found.len(), 1);
    let (index, reverse, level) = &found[0];
    assert_eq!((*index, *level), (2, 3));
    assert_eq!(reverse.tag, "r-in");
    assert_eq!(reverse.email, "b@example.com");
}

#[test]
fn a_session_without_an_email_names_no_user() {
    assert_eq!(client_label(None), "unknown");
    assert_eq!(
        client_label(Some("192.0.2.1:7".parse().unwrap())),
        "192.0.2.1:7"
    );
}
