//! The bridge side of the VLESS reverse proxy, read as Xray-core v26.10.31
//! reads it, and its legacy reverse proxy refused as there.
use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, OutboundSettings, SniffingDestination,
    VlessOutboundSettings, VlessReverseSettings,
};

const ID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";

fn bridge(settings: Value) -> Value {
    let mut base =
        json!({"address": "portal.example", "port": 443, "id": ID, "encryption": "none"});
    base.as_object_mut()
        .unwrap()
        .extend(settings.as_object().unwrap().clone());
    json!({"outbounds": [{"tag": "portal", "protocol": "vless", "settings": base}]})
}

fn vless(config: &Value) -> VlessOutboundSettings {
    let parsed = parse_xray_json(&config.to_string())
        .unwrap_or_else(|error| panic!("{config}: {:?}", error.diagnostics));
    let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings else {
        panic!("vless");
    };
    vless.clone()
}

fn errors(config: &Value) -> Vec<(String, String)> {
    parse_xray_json(&config.to_string())
        .err()
        .map(|error| {
            error
                .diagnostics
                .into_iter()
                .filter(|d| d.severity == DiagnosticSeverity::Error)
                .map(|d| (d.path.unwrap_or_default(), d.message))
                .collect()
        })
        .unwrap_or_default()
}

/// Every case of the corpus gets Xray-core's verdict, except the
/// deliberate differences, which get theirs.
#[test]
fn config_verdicts_match_xray_core() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reverse/config-verdicts.json"
    ))
    .unwrap();
    let mut mismatches = Vec::new();
    for case in corpus["cases"].as_array().unwrap() {
        let raw = case["config"].to_string();
        let parsed = parse_xray_json(&raw);
        let expected_ok = match case.get("ours").and_then(Value::as_str) {
            Some(ours) => ours == "ok",
            None => case["xray"] == "ok",
        };
        if parsed.is_ok() != expected_ok {
            mismatches.push(format!(
                "{}: expected {}, got {:?}",
                case["name"],
                if expected_ok { "ok" } else { "error" },
                parsed.err().map(|error| error.diagnostics)
            ));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn the_simplified_form_makes_a_bridge_with_its_tag_email_and_sniffing() {
    let settings = vless(&bridge(json!({
        "email": "bridge@example.com",
        "reverse": {"tag": "r-in", "sniffing": {"enabled": true, "destOverride": ["http", "tls"],
            "routeOnly": true}},
    })));
    let reverse = settings.reverse.expect("a bridge");
    assert_eq!(reverse.tag, "r-in");
    assert_eq!(reverse.email, "bridge@example.com");
    let sniffing = reverse.sniffing.expect("sniffing is on");
    assert!(sniffing.route_only);
    assert_eq!(
        sniffing.dest_override,
        [SniffingDestination::Http, SniffingDestination::Tls]
    );

    // Without email the user is empty, and sniffing that is off is none.
    let settings = vless(&bridge(json!({
        "reverse": {"tag": "r-in", "sniffing": {"enabled": false, "destOverride": ["quic"]}},
    })));
    assert_eq!(
        settings.reverse,
        Some(VlessReverseSettings {
            tag: "r-in".to_owned(),
            email: String::new(),
            sniffing: None,
        })
    );
}

#[test]
fn no_reverse_or_a_null_one_is_an_ordinary_outbound() {
    assert_eq!(vless(&bridge(json!({}))).reverse, None);
    assert_eq!(vless(&bridge(json!({"reverse": null}))).reverse, None);
    // The vnext form never reads the simplified form's reverse.
    let config = json!({"outbounds": [{"protocol": "vless", "settings": {
        "vnext": [{"address": "portal.example", "port": 443,
            "users": [{"id": ID, "encryption": "none"}]}],
        "reverse": {"tag": ""}}}]});
    assert_eq!(vless(&config).reverse, None);
}

#[test]
fn a_bridge_keeps_no_connections_ahead() {
    let settings = vless(&bridge(json!({"testpre": 8, "reverse": {"tag": "r-in"}})));
    assert_eq!(settings.users[0].pre_connections, 0);
    let settings = vless(&bridge(json!({"testpre": 8})));
    assert_eq!(settings.users[0].pre_connections, 8);
}

#[test]
fn refusals_carry_xrays_messages_at_their_paths() {
    for (settings, path, message) in [
        (
            json!({"reverse": {}}),
            "$.outbounds[0].settings.reverse.tag",
            "VLESS reverse: \"tag\" can't be empty",
        ),
        (
            json!({"reverse": {"tag": null}}),
            "$.outbounds[0].settings.reverse.tag",
            "VLESS reverse: \"tag\" can't be empty",
        ),
        (
            json!({"reverse": {"tag": 1}}),
            "$.outbounds[0].settings.reverse.tag",
            "field `tag` must be a string or null",
        ),
        (
            json!({"reverse": "r-in"}),
            "$.outbounds[0].settings.reverse",
            "field `reverse` must be an object or null",
        ),
        (
            json!({"reverse": {"tag": "r-in", "sniffing": {"destOverride": ["bogus"]}}}),
            "$.outbounds[0].settings.reverse.sniffing.destOverride[0]",
            "unknown sniffing destOverride `bogus`",
        ),
        (
            json!({"reverse": {"tag": "r-in", "domain": "reverse.example"}}),
            "$.outbounds[0].settings.reverse.domain",
            "unsupported field `domain`",
        ),
    ] {
        let config = bridge(settings);
        let found = errors(&config);
        assert!(
            found.iter().any(|(p, m)| p == path && m == message),
            "{config}: {found:?}"
        );
    }

    let config = json!({"outbounds": [{"protocol": "vless", "settings": {"vnext": [{
        "address": "portal.example", "port": 443,
        "users": [{"id": ID, "encryption": "none", "reverse": {"tag": "r-in"}}]}]}}]});
    assert!(errors(&config).contains(&(
        "$.outbounds[0].settings.vnext[0].users[0].reverse".to_owned(),
        "VLESS users: please use simplified outbound's config style to use \"reverse\"".to_owned()
    )));
}

#[test]
fn the_legacy_reverse_proxy_is_refused_unless_null() {
    let message = "The feature \"legacy reverse\" has been removed and migrated to \"VLESS Reverse Proxy\". Please update your config(s) according to release note and documentation.";
    for reverse in [
        json!({"bridges": [{"tag": "bridge", "domain": "reverse.example"}]}),
        json!({"portals": [{"tag": "portal", "domain": "reverse.example"}]}),
        json!({}),
        json!("bridge"),
    ] {
        let config = json!({"reverse": reverse, "outbounds": [{"protocol": "freedom"}]});
        assert_eq!(
            errors(&config),
            [("$.reverse".to_owned(), message.to_owned())],
            "{config}"
        );
    }
    let config = json!({"reverse": null, "outbounds": [{"protocol": "freedom"}]});
    assert!(parse_xray_json(&config.to_string()).is_ok());
}
