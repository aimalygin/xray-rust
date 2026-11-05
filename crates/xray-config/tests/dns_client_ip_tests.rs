//! `dns.clientIp` and a server's own `clientIp`, read as Xray-core v26.10.31
//! reads them: an IP address as Xray-core reads an address, a domain refused.

use std::net::IpAddr;

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity, DnsConfig, DnsServerConfig};

fn dns(dns: Value) -> DnsConfig {
    let raw = json!({"dns": dns, "outbounds": [{"protocol": "freedom"}]}).to_string();
    parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
        .config
        .dns
}

fn error_path(dns: Value) -> String {
    let raw = json!({"dns": dns, "outbounds": [{"protocol": "freedom"}]}).to_string();
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
fn the_global_client_ip_is_read_as_xray_core_reads_an_address() {
    for (raw, expected) in [
        (json!("203.0.113.77"), ip("203.0.113.77")),
        (json!("2001:db8::1"), ip("2001:db8::1")),
        (json!("[2001:db8::1]"), ip("2001:db8::1")),
        // An IPv4-mapped address is IPv4, and Go trims spaces around one.
        (json!("::ffff:198.51.100.9"), ip("198.51.100.9")),
        (json!(" 203.0.113.5 "), ip("203.0.113.5")),
        (Value::Null, None),
    ] {
        let parsed = dns(json!({"clientIp": raw, "servers": ["192.0.2.53"]}));
        assert_eq!(parsed.client_ip, expected, "{raw}");
    }
    assert_eq!(dns(json!({"servers": ["192.0.2.53"]})).client_ip, None);
}

#[test]
fn a_servers_own_client_ip_stays_its_own() {
    let parsed = dns(json!({
        "clientIp": "203.0.113.77",
        "servers": [
            {"address": "192.0.2.53", "clientIp": "198.51.100.200"},
            {"address": "192.0.2.54", "clientIp": null},
            {"address": "192.0.2.55"},
            "192.0.2.56"
        ]
    }));
    let own: Vec<_> = parsed
        .servers
        .iter()
        .map(DnsServerConfig::client_ip)
        .collect();
    assert_eq!(own, [ip("198.51.100.200"), None, None, None]);
    assert_eq!(parsed.client_ip, ip("203.0.113.77"));
}

#[test]
fn a_client_ip_that_is_not_an_ip_address_is_refused() {
    for raw in [
        json!("example.com"),
        json!(""),
        json!("203.0.113.77:53"),
        json!(5),
        json!([]),
    ] {
        assert_eq!(
            error_path(json!({"clientIp": raw, "servers": ["192.0.2.53"]})),
            "$.dns.clientIp",
            "{raw}"
        );
        assert_eq!(
            error_path(json!({"servers": [{"address": "192.0.2.53", "clientIp": raw}]})),
            "$.dns.servers[0].clientIp",
            "{raw}"
        );
    }
}
