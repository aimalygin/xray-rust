//! `dns.enableParallelQuery` and the policy key each server gets, as
//! Xray-core v26.10.31's config builder writes it.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity, DnsConfig, DEFAULT_DNS_POLICY_KEY};

fn dns(dns: Value) -> DnsConfig {
    let raw = json!({"dns": dns, "outbounds": [{"protocol": "freedom"}]}).to_string();
    parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
        .config
        .dns
}

#[test]
fn parallel_query_is_a_boolean() {
    for (raw, expected) in [
        (json!(true), true),
        (json!(false), false),
        (Value::Null, false),
    ] {
        let parsed = dns(json!({"enableParallelQuery": raw, "servers": ["192.0.2.53"]}));
        assert_eq!(parsed.enable_parallel_query, expected, "{raw}");
    }
    assert!(!dns(json!({"servers": ["192.0.2.53"]})).enable_parallel_query);

    let raw =
        json!({"dns": {"enableParallelQuery": "yes"}, "outbounds": [{"protocol": "freedom"}]})
            .to_string();
    let error = parse_xray_json(&raw).expect_err("a string is not a boolean");
    assert!(error.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Error
            && diagnostic.path.as_deref() == Some("$.dns.enableParallelQuery")
    }));
}

#[test]
fn servers_without_policy_fields_share_the_default_key() {
    let parsed = dns(json!({"servers": [
        "192.0.2.53",
        "tcp://192.0.2.54",
        {"address": "192.0.2.55", "port": 5353, "timeoutMs": 900, "finalQuery": false},
        {"address": "192.0.2.56", "tag": null, "domains": null, "clientIp": null}
    ]}));
    for server in &parsed.servers {
        assert_eq!(server.policy_key(), DEFAULT_DNS_POLICY_KEY);
    }
    assert_eq!(
        DEFAULT_DNS_POLICY_KEY,
        "client=none|skip=0|qs=|tag=|domains=[]|expected=[]|expect=[]|unexpected=[]|"
    );
}

#[test]
fn a_servers_key_reads_its_fields_as_written() {
    let parsed = dns(json!({"servers": [{
        "address": "192.0.2.53",
        "clientIp": "2001:db8::1",
        "skipFallback": true,
        "queryStrategy": "UseIPv4",
        "tag": " DNS-A ",
        "domains": ["domain:B.test", "domain:a.test"],
        "expectedIPs": "10.0.0.0/8,192.168.0.0/16",
        "expectIPs": ["172.16.0.0/12"],
        "unexpectedIPs": []
    }, {
        "address": "192.0.2.54",
        "clientIp": "203.0.113.7",
        "queryStrategy": "use_ipv4",
        "domains": "domain:b.test,domain:a.test"
    }, {
        "address": "192.0.2.55",
        "domains": ["domain:x.test", null]
    }]}));
    assert_eq!(
        parsed.servers[0].policy_key(),
        "client=[2001:db8::1]|skip=1|qs=useipv4|tag=dns-a|domains=domain:a.test,domain:b.test|\
         expected=10.0.0.0/8,192.168.0.0/16|expect=172.16.0.0/12|unexpected=[]|"
    );
    // queryStrategy stays as written: use_ipv4 is not useipv4 here. A
    // comma-separated string is split before it is sorted.
    assert_eq!(
        parsed.servers[1].policy_key(),
        "client=203.0.113.7|skip=0|qs=use_ipv4|tag=|domains=domain:a.test,domain:b.test|\
         expected=[]|expect=[]|unexpected=[]|"
    );
    // A null entry is an empty string, as Go reads it.
    assert_eq!(
        parsed.servers[2].policy_key(),
        "client=none|skip=0|qs=|tag=|domains=,domain:x.test|expected=[]|expect=[]|unexpected=[]|"
    );
}
