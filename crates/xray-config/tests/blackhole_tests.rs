use base64::Engine as _;
use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, BlackholeOutboundSettings, BlackholeResponse, DiagnosticSeverity,
    OutboundProtocol, OutboundSettings, RoutingRuleTarget,
};

/// The shape managed Android subscriptions ship: a proxy, `direct` and a
/// `block` blackhole that deny rules (ads, QUIC) route to.
fn subscription(block: Value) -> Value {
    json!({
        "inbounds": [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
            "port": 10808, "settings": {"auth": "noauth", "udp": true}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            block
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "domain": ["domain:ads.example"], "outboundTag": "block"},
            {"type": "field", "network": "udp", "port": "443", "outboundTag": "block"},
            {"type": "field", "ip": ["192.0.2.0/24"], "outboundTag": "block"}
        ]}
    })
}

fn block_settings(raw: &Value) -> BlackholeOutboundSettings {
    let parsed = parse_xray_json(&raw.to_string()).expect("blackhole config parses");
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let outbound = &parsed.config.outbounds[1];
    assert_eq!(outbound.tag.as_deref(), Some("block"));
    assert_eq!(outbound.settings.protocol(), OutboundProtocol::Blackhole);
    assert!(parsed
        .config
        .routing
        .rules
        .iter()
        .all(|rule| rule.target == RoutingRuleTarget::Outbound("block".to_owned())));
    let OutboundSettings::Blackhole(settings) = &outbound.settings else {
        panic!("expected blackhole settings, got {:?}", outbound.settings);
    };
    settings.clone()
}

#[test]
fn accepts_xray_blackhole_settings_shapes() {
    for (block, response) in [
        (
            json!({"tag": "block", "protocol": "blackhole"}),
            BlackholeResponse::None,
        ),
        (
            json!({"tag": "block", "protocol": "Blackhole", "settings": {}}),
            BlackholeResponse::None,
        ),
        (
            json!({"tag": "block", "protocol": "blackhole", "settings": null}),
            BlackholeResponse::None,
        ),
        (
            json!({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "none"}}}),
            BlackholeResponse::None,
        ),
        (
            json!({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}),
            BlackholeResponse::Http,
        ),
        (
            json!({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "HTTP"}}}),
            BlackholeResponse::Http,
        ),
        // Xray's `block` alias.
        (
            json!({"tag": "block", "protocol": "block", "settings": {"response": {"type": "http"}}}),
            BlackholeResponse::Http,
        ),
        (
            json!({"tag": "block", "protocol": "blackhole", "settings": {"response": {
                "type": "custom", "customResponseData": "SFRUUC8xLjEgNDA0IE5vdCBGb3VuZA0KDQo="}}}),
            BlackholeResponse::Custom(b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec()),
        ),
        (
            json!({"tag": "block", "protocol": "blackhole", "settings": {"response": {
                "type": "Custom", "customResponseData": null}}}),
            BlackholeResponse::Custom(Vec::new()),
        ),
        (
            json!({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "custom"}}}),
            BlackholeResponse::Custom(Vec::new()),
        ),
        // Like Xray, other types ignore the data, even when it is not base64.
        (
            json!({"tag": "block", "protocol": "blackhole", "settings": {"response": {
                "type": "http", "customResponseData": "not base64"}}}),
            BlackholeResponse::Http,
        ),
    ] {
        let settings = block_settings(&subscription(block.clone()));
        assert_eq!(settings.response, response, "{block}");
    }
}

#[test]
fn rejects_responses_xray_rejects_and_unknown_fields_with_paths() {
    for (settings, path) in [
        (json!("http"), "$.outbounds[1].settings"),
        (json!([]), "$.outbounds[1].settings"),
        (
            json!({"response": null}),
            "$.outbounds[1].settings.response",
        ),
        (
            json!({"response": "http"}),
            "$.outbounds[1].settings.response",
        ),
        (
            json!({"response": {}}),
            "$.outbounds[1].settings.response.type",
        ),
        (
            json!({"response": {"type": null}}),
            "$.outbounds[1].settings.response.type",
        ),
        (
            json!({"response": {"type": 1}}),
            "$.outbounds[1].settings.response.type",
        ),
        (
            json!({"response": {"type": ""}}),
            "$.outbounds[1].settings.response.type",
        ),
        (
            json!({"response": {"type": "redirect"}}),
            "$.outbounds[1].settings.response.type",
        ),
        (
            json!({"responses": {"type": "http"}}),
            "$.outbounds[1].settings.responses",
        ),
        (
            json!({"response": {"type": "http", "body": "blocked"}}),
            "$.outbounds[1].settings.response.body",
        ),
        (
            json!({"response": {"type": "custom", "customResponseData": 403}}),
            "$.outbounds[1].settings.response.customResponseData",
        ),
        // Go's StdEncoding requires padding.
        (
            json!({"response": {"type": "custom", "customResponseData": "SGk"}}),
            "$.outbounds[1].settings.response.customResponseData",
        ),
        (
            json!({"response": {"type": "custom", "customResponseData": "not base64"}}),
            "$.outbounds[1].settings.response.customResponseData",
        ),
        (
            json!({"response": {"type": "custom", "customResponseData":
                base64::engine::general_purpose::STANDARD.encode(vec![0u8; 65_536])}}),
            "$.outbounds[1].settings.response.customResponseData",
        ),
    ] {
        let raw =
            subscription(json!({"tag": "block", "protocol": "blackhole", "settings": settings}));
        let error = parse_xray_json(&raw.to_string()).expect_err(&settings.to_string());
        assert!(
            error
                .diagnostics
                .iter()
                .any(|d| d.severity == DiagnosticSeverity::Error && d.path.as_deref() == Some(path)),
            "{settings}: {:?}",
            error.diagnostics
        );
    }
}

#[test]
fn unknown_response_type_is_not_echoed() {
    let raw = subscription(json!({"tag": "block", "protocol": "blackhole",
        "settings": {"response": {"type": "private-fixture-value\r\n"}}}));
    let error = parse_xray_json(&raw.to_string()).unwrap_err();
    assert!(!format!("{error:?}").contains("private-fixture-value"));

    let raw = subscription(json!({"tag": "block", "protocol": "blackhole",
        "settings": {"response": {"type": "custom", "customResponseData": "private-fixture-value"}}}));
    let error = parse_xray_json(&raw.to_string()).unwrap_err();
    assert!(!format!("{error:?}").contains("private-fixture-value"));
}

#[test]
fn custom_response_size_bound_is_inclusive() {
    let largest = vec![0x5a; 65_535];
    let settings = block_settings(&subscription(
        json!({"tag": "block", "protocol": "blackhole",
        "settings": {"response": {"type": "custom",
            "customResponseData": base64::engine::general_purpose::STANDARD.encode(&largest)}}}),
    ));
    assert_eq!(settings.response, BlackholeResponse::Custom(largest));
}

#[test]
fn blackhole_keeps_the_generic_outbound_guards() {
    for (field, value) in [
        ("sendThrough", json!("192.0.2.1")),
        ("mux", json!({"enabled": true})),
        ("unknownField", json!(true)),
    ] {
        let mut block = json!({"tag": "block", "protocol": "blackhole"});
        block[field] = value;
        let error = parse_xray_json(&subscription(block).to_string()).unwrap_err();
        assert!(
            error.diagnostics.iter().any(|d| d
                .path
                .as_deref()
                .is_some_and(|p| p.starts_with(&format!("$.outbounds[1].{field}")))),
            "{field}: {:?}",
            error.diagnostics
        );
    }
}
