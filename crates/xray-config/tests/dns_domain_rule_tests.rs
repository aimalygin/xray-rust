//! Domain rules in DNS servers' `domains`, `dns.hosts` keys and the DNS
//! outbound's rules, and the outbound's `qType`, read as Xray-core v26.10.31
//! reads them.

use std::net::{IpAddr, Ipv4Addr};

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, DnsHostTarget, DnsNameServerConfig, DnsOutboundRuleAction,
    DnsOutboundSettings, DnsServerConfig, OutboundSettings,
};

const HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fn first_error_path(raw: &str) -> String {
    let error = parse_xray_json(raw).expect_err(&format!("{raw} should be rejected"));
    error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .and_then(|diagnostic| diagnostic.path.clone())
        .unwrap_or_default()
}

fn dns_config(dns: Value) -> String {
    json!({
        "dns": dns,
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    })
    .to_string()
}

fn server_with_domains(domains: Value) -> DnsNameServerConfig {
    let raw = dns_config(json!({
        "servers": [{"address": "192.0.2.53", "domains": domains}]
    }));
    let parsed = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    match &parsed.config.dns.servers[0] {
        DnsServerConfig::Policy(server) => (**server).clone(),
        other => panic!("expected a policy server, got {other:?}"),
    }
}

fn hosts(hosts: Value) -> xray_config::DomainHostIndex<DnsHostTarget> {
    let raw = dns_config(json!({ "hosts": hosts }));
    let parsed = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    parsed.config.dns.hosts
}

fn dns_outbound_config(rules: Value) -> String {
    json!({
        "outbounds": [{
            "tag": "dns-out",
            "protocol": "dns",
            "settings": { "rules": rules }
        }]
    })
    .to_string()
}

fn dns_outbound(rules: Value) -> DnsOutboundSettings {
    let raw = dns_outbound_config(rules);
    let parsed = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    match &parsed.config.outbounds[0].settings {
        OutboundSettings::Dns(settings) => settings.clone(),
        other => panic!("expected a DNS outbound, got {other:?}"),
    }
}

#[test]
fn server_domains_read_as_parse_domain_rules_reads_them() {
    let matches =
        |entry: Value, name: &str| server_with_domains(json!([entry])).domains.matches(name);
    // An empty substring, keyword or regexp matches every name.
    for entry in ["", "keyword:", "regexp:"] {
        assert!(matches(json!(entry), "localhost"), "{entry:?}");
    }
    // Go reads a `null` entry as an empty string.
    assert!(matches(Value::Null, "anything.test"));
    // DNS names lose their trailing dot before matching, so an empty suffix
    // and an empty full name match none.
    assert!(!matches(json!("domain:"), "localhost"));
    assert!(!matches(json!("full:"), "localhost"));
    // Anything without a known prefix is a substring, colon and all.
    assert!(matches(json!("foo:bar"), "a.foo:bar.test"));
    assert!(!matches(json!("foo:bar"), "foo.bar"));
    assert!(matches(json!("dotless:host"), "localhost"));
    assert!(!matches(json!("dotless:host"), "host.test"));

    // A string is split at commas, untrimmed.
    let split = server_with_domains(json!("full:a.test,full:b.test, full:c.test"));
    assert!(split.domains.matches("a.test"));
    assert!(split.domains.matches("b.test"));
    assert!(!split.domains.matches("c.test"));
    // A `null` list is no list.
    assert!(server_with_domains(Value::Null).domains.is_empty());
}

#[test]
fn server_domain_errors_name_the_entry() {
    for (domains, path) in [
        (json!(["regexp:("]), "$.dns.servers[0].domains[0]"),
        (
            json!(["a.test", "dotless:a.b"]),
            "$.dns.servers[0].domains[1]",
        ),
        (json!("a.test,regexp:("), "$.dns.servers[0].domains[1]"),
        (json!([5]), "$.dns.servers[0].domains[0]"),
        (json!(5), "$.dns.servers[0].domains"),
    ] {
        let raw = dns_config(json!({
            "servers": [{"address": "192.0.2.53", "domains": domains}]
        }));
        assert_eq!(first_error_path(&raw), path, "{domains}");
    }
}

#[test]
fn hosts_keys_read_as_parse_domain_rule_reads_them() {
    let index = hosts(json!({
        "foo:bar": "192.0.2.1",
        "plain.test": "192.0.2.1",
        "": "192.0.2.1",
        "full:": "192.0.2.1",
        "domain:": "192.0.2.1"
    }));
    let target = Some(&DnsHostTarget::Ip(HOST));
    // A key without a known prefix is the whole name, colon and all.
    assert_eq!(index.lookup("foo:bar"), target);
    assert_eq!(index.lookup("a.foo:bar.test"), None);
    assert_eq!(index.lookup("plain.test"), target);
    assert_eq!(index.lookup("www.plain.test"), None);
    // Empty names, full or suffix, match no query.
    assert_eq!(index.lookup("localhost"), None);

    // An empty keyword maps every name.
    let every = hosts(json!({"keyword:": "192.0.2.1"}));
    assert_eq!(every.lookup("localhost"), target);
    assert_eq!(every.lookup("www.example.com"), target);
}

#[test]
fn hosts_key_errors_name_the_key() {
    for key in ["regexp:(", "dotless:a.b"] {
        let raw = dns_config(json!({ "hosts": { key: "192.0.2.1" } }));
        assert_eq!(
            first_error_path(&raw),
            format!("$.dns.hosts.{key}"),
            "{key}"
        );
    }
}

#[test]
fn hosts_hash_values_are_xray_rcode_answers() {
    let index = hosts(json!({
        "ads.example.com": "#3",
        "empty.test": "#0",
        "refused.test": "#+5",
        "max.test": "#15",
        "alias.test": "ads.example.com"
    }));
    assert_eq!(
        index.lookup("ads.example.com"),
        Some(&DnsHostTarget::Rcode(3))
    );
    assert_eq!(index.lookup("empty.test"), Some(&DnsHostTarget::Rcode(0)));
    assert_eq!(index.lookup("refused.test"), Some(&DnsHostTarget::Rcode(5)));
    assert_eq!(index.lookup("max.test"), Some(&DnsHostTarget::Rcode(15)));
    assert_eq!(
        index.lookup("alias.test"),
        Some(&DnsHostTarget::Domain("ads.example.com".to_owned()))
    );
}

#[test]
fn hosts_rcode_outside_the_header_field_is_rejected() {
    for target in ["#", "#16", "#-1", "#65539", "#3.0", "#nx", "# 3"] {
        let raw = dns_config(json!({ "hosts": { "ads.example.com": target } }));
        let error = parse_xray_json(&raw).expect_err(&format!("{target} should be rejected"));
        let diagnostic = error
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .expect("rcode error");
        assert_eq!(
            diagnostic.path.as_deref(),
            Some("$.dns.hosts.ads.example.com"),
            "{target}"
        );
        assert!(
            diagnostic.message.contains("RCODE from 0 to 15"),
            "{target}"
        );
    }
}

#[test]
fn dns_outbound_domain_is_a_condition_once_it_has_an_entry() {
    let drop = |domain: Value| dns_outbound(json!([{"action": "drop", "domain": domain}]));
    // No list, `null` or `[]` sets no condition.
    for domain in [Value::Null, json!([])] {
        let settings = drop(domain.clone());
        assert_eq!(settings.rules[0].domain_matchers, None, "{domain}");
        assert_eq!(
            settings.action_for(16, "a.test"),
            DnsOutboundRuleAction::Drop
        );
    }
    let absent = dns_outbound(json!([{"action": "drop"}]));
    assert_eq!(absent.rules[0].domain_matchers, None);

    // An empty substring or a `null` entry matches every name.
    for domain in [json!([""]), json!([null]), json!("")] {
        let settings = drop(domain.clone());
        assert!(settings.rules[0].domain_matchers.is_some(), "{domain}");
        assert_eq!(
            settings.action_for(16, "a.test"),
            DnsOutboundRuleAction::Drop,
            "{domain}"
        );
    }
    // A string is split at commas, and text with an unknown prefix is a
    // substring.
    let split = drop(json!("full:a.test,foo:bar"));
    assert_eq!(split.action_for(16, "a.test"), DnsOutboundRuleAction::Drop);
    assert_eq!(
        split.action_for(16, "x.foo:bar"),
        DnsOutboundRuleAction::Drop
    );
    assert_eq!(
        split.action_for(16, "b.test"),
        DnsOutboundRuleAction::Return
    );

    let raw = dns_outbound_config(json!([{"action": "drop", "domain": ["ext-site:"]}]));
    assert_eq!(
        first_error_path(&raw),
        "$.outbounds[0].settings.rules[0].domain[0]"
    );
}

#[test]
fn dns_outbound_qtype_reads_as_a_port_list() {
    let drop = |qtype: Value| dns_outbound(json!([{"action": "drop", "qType": qtype}]));
    // A reversed range adds no type, and a rule with no type answers every
    // type.
    let reversed = drop(json!("24-23"));
    assert!(reversed.rules[0].qtype_ranges.is_empty());
    assert_eq!(
        reversed.action_for(16, "a.test"),
        DnsOutboundRuleAction::Drop
    );
    // Next to a real range it adds nothing.
    let mixed = drop(json!("1-2,24-23"));
    assert_eq!(mixed.action_for(2, "a.test"), DnsOutboundRuleAction::Drop);
    assert_eq!(
        mixed.action_for(16, "a.test"),
        DnsOutboundRuleAction::Return
    );
    // Entries are trimmed, and empty ones add no type.
    let spaced = drop(json!(" 16 , ,28"));
    assert_eq!(spaced.action_for(16, "a.test"), DnsOutboundRuleAction::Drop);
    assert_eq!(spaced.action_for(28, "a.test"), DnsOutboundRuleAction::Drop);
    assert_eq!(
        spaced.action_for(65, "a.test"),
        DnsOutboundRuleAction::Return
    );

    // A single type reads as a JSON integer, a range's ends as digits.
    let path = "$.outbounds[0].settings.rules[0].qType";
    for (qtype, at) in [
        (json!("053"), "[0]"),
        (json!("+53"), "[0]"),
        (json!("1-+2"), "[0]"),
        (json!("65536"), "[0]"),
        (json!([16]), ""),
        // Deliberately rejected: Xray-core would truncate it to 16 bits.
        (json!(65_617), ""),
    ] {
        let raw = dns_outbound_config(json!([{"action": "drop", "qType": qtype}]));
        assert_eq!(first_error_path(&raw), format!("{path}{at}"), "{qtype}");
    }
    assert_eq!(
        drop(json!("01-02")).action_for(2, "a.test"),
        DnsOutboundRuleAction::Drop
    );
}

#[test]
fn qtype_entries_count_against_the_qtype_budget() {
    let qtype = vec!["16"; 65_537].join(",");
    let raw = dns_outbound_config(json!([{"action": "drop", "qType": qtype}]));
    let error = parse_xray_json(&raw).expect_err("65537 qType entries exceed the budget");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("DNS qtype selector budget")),
        "{:?}",
        error.diagnostics
    );
}

/// Deliberately unlike Xray-core: a DNS pattern ending in a dot matches the
/// name without it. Xray-core drops the dot from the query but not from the
/// pattern, so there such a pattern never matches.
#[test]
fn a_dns_pattern_ending_in_a_dot_matches_the_name_without_it() {
    assert!(server_with_domains(json!(["full:x.test."]))
        .domains
        .matches("x.test"));
    assert_eq!(
        hosts(json!({"full:x.test.": "192.0.2.1"})).lookup("x.test"),
        Some(&DnsHostTarget::Ip(HOST))
    );
    let settings = dns_outbound(json!([{"action": "drop", "domain": ["full:x.test."]}]));
    assert_eq!(
        settings.action_for(16, "x.test"),
        DnsOutboundRuleAction::Drop
    );
}
