//! Inbound sniffing settings read as Xray-core v26.10.31 reads them.

use std::net::IpAddr;

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, InboundSniffingConfig, SniffingDestination,
};

fn config(sniffing: Value) -> String {
    json!({
        "inbounds": [{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": 1080,
            "settings": {"auth": "noauth"},
            "sniffing": sniffing
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    })
    .to_string()
}

fn sniffing(sniffing: Value) -> Option<InboundSniffingConfig> {
    let raw = config(sniffing);
    let parsed = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    parsed.config.inbounds[0].sniffing.clone()
}

fn enabled(mut fields: Value) -> InboundSniffingConfig {
    fields["enabled"] = json!(true);
    sniffing(fields).expect("sniffing is enabled")
}

fn rejection(sniffing: Value) -> String {
    let raw = config(sniffing);
    let error = parse_xray_json(&raw).expect_err(&format!("{raw} should be rejected"));
    error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .and_then(|diagnostic| diagnostic.path.clone())
        .unwrap_or_default()
}

fn ip(text: &str) -> Option<IpAddr> {
    Some(text.parse().unwrap())
}

#[test]
fn dest_override_reads_as_xray_core_reads_it() {
    use SniffingDestination::{Http, Quic, Tls};
    for (raw, expected) in [
        (json!(["HTTP", "Tls", "QUIC"]), vec![Http, Tls, Quic]),
        (json!(["https", "SSL"]), vec![Tls, Tls]),
        (json!("http,tls"), vec![Http, Tls]),
        // Fake IPs are turned back into domains whenever dns.fakeIp is on.
        (json!(["fakedns", "FakeDNS+Others", "http"]), vec![Http]),
        (Value::Null, vec![]),
    ] {
        let parsed = enabled(json!({ "destOverride": raw.clone() }));
        assert_eq!(parsed.dest_override, expected, "{raw}");
    }

    let path = "$.inbounds[0].sniffing.destOverride";
    for (raw, at) in [
        (json!(["bittorrent"]), "[0]"),
        (json!(["http", null]), "[1]"),
        (json!("http, tls"), "[1]"),
        (json!([5]), "[0]"),
        (json!(5), ""),
    ] {
        let fields = json!({"enabled": true, "destOverride": raw.clone()});
        assert_eq!(rejection(fields), format!("{path}{at}"), "{raw}");
    }
}

#[test]
fn every_field_is_checked_while_sniffing_is_off() {
    for (fields, path) in [
        (
            json!({"enabled": false, "destOverride": ["bittorrent"]}),
            "$.inbounds[0].sniffing.destOverride[0]",
        ),
        (
            json!({"domainsExcluded": ["regexp:("]}),
            "$.inbounds[0].sniffing.domainsExcluded[0]",
        ),
        (
            json!({"ipsExcluded": ["10.0.0.0/33"]}),
            "$.inbounds[0].sniffing.ipsExcluded[0]",
        ),
    ] {
        assert_eq!(rejection(fields.clone()), path, "{fields}");
    }
    let off = json!({"enabled": false, "destOverride": "http", "ipsExcluded": "10.0.0.0/8"});
    assert_eq!(sniffing(off), None);
    // Go leaves a `null` object unset.
    assert_eq!(sniffing(Value::Null), None);
}

#[test]
fn domains_excluded_holds_domain_rules() {
    let parsed = enabled(json!({
        "domainsExcluded": ["push.apple.com", "full:exact.test", "domain:suffix.test", "foo:bar"]
    }));
    // Plain text, even with an unknown prefix, is a substring.
    assert!(parsed.excludes(None, "courier.push.apple.com"));
    assert!(parsed.excludes(None, "a.foo:bar.test"));
    assert!(parsed.excludes(None, "exact.test"));
    assert!(!parsed.excludes(None, "www.exact.test"));
    assert!(parsed.excludes(None, "www.suffix.test"));
    assert!(!parsed.excludes(None, "other.test"));

    // Rules match as routing rules do: a pattern's terminal dot counts, as
    // Xray-core matches sniffed names against patterns as written.
    let dotted = enabled(json!({"domainsExcluded": ["full:exact.test."]}));
    assert!(!dotted.excludes(None, "exact.test"));

    // A string is split at commas, and a `null` entry is an empty substring,
    // which every domain contains.
    let split = enabled(json!({"domainsExcluded": "a.test,b.test"}));
    assert!(split.excludes(None, "b.test"));
    let every = enabled(json!({"domainsExcluded": [null]}));
    assert!(every.excludes(None, "anything.test"));
}

#[test]
fn ips_excluded_holds_ip_rules_for_ip_destinations() {
    let parsed = enabled(json!({"ipsExcluded": "10.0.0.0/8, 2001:db8::1"}));
    assert!(parsed.excludes(ip("10.1.2.3"), "routed.test"));
    assert!(parsed.excludes(ip("2001:db8::1"), "routed.test"));
    assert!(!parsed.excludes(ip("192.0.2.1"), "routed.test"));
    // A destination given as a name is never checked against IP rules.
    assert!(!parsed.excludes(None, "routed.test"));

    let inverse = enabled(json!({"ipsExcluded": ["!10.0.0.0/8"]}));
    assert!(inverse.excludes(ip("192.0.2.1"), "routed.test"));
    assert!(!inverse.excludes(ip("10.1.2.3"), "routed.test"));
}
