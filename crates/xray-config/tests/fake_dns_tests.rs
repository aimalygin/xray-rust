//! Xray-core's FakeDNS: a `fakedns` entry in `dns.servers`, with the pools of
//! root `fakeDns`, read as the core's `dns.fakeIp`.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity, DnsFakeIpConfig, IpCidr, ParsedConfig};

fn parse(raw: &Value) -> ParsedConfig {
    parse_xray_json(&raw.to_string()).unwrap_or_else(|error| panic!("{raw}: {error:?}"))
}

fn warnings(parsed: &ParsedConfig) -> Vec<(String, String)> {
    parsed
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
        .map(|diagnostic| {
            (
                diagnostic.path.clone().unwrap_or_default(),
                diagnostic.message.clone(),
            )
        })
        .collect()
}

fn error_paths(raw: &Value) -> Vec<String> {
    parse_xray_json(&raw.to_string())
        .expect_err("config must be refused")
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .filter_map(|diagnostic| diagnostic.path)
        .collect()
}

fn fake_ip(pool: &str, prefix: u8, pool_size: u32) -> DnsFakeIpConfig {
    DnsFakeIpConfig {
        enabled: true,
        ipv4_pool: IpCidr::new(pool.parse().unwrap(), prefix).unwrap(),
        pool_size,
        ttl: 60,
    }
}

fn profile(extra: Value) -> Value {
    let mut raw = json!({
        "inbounds": [{"tag": "tun-in", "protocol": "tun",
            "sniffing": {"enabled": true, "destOverride": ["fakedns", "http", "tls"]}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    });
    for (key, value) in extra.as_object().unwrap() {
        raw[key] = value.clone();
    }
    raw
}

#[test]
fn fakedns_first_hands_out_xrays_automatic_pool_for_every_name() {
    let parsed = parse(&profile(
        json!({"dns": {"servers": ["fakedns", "192.0.2.53"]}}),
    ));
    assert_eq!(
        parsed.config.dns.fake_ip,
        Some(fake_ip("198.18.0.0", 15, 32_768))
    );
    // Destination lookups never ask `fakedns`.
    assert_eq!(parsed.config.dns.servers.len(), 1);
    assert!(warnings(&parsed).is_empty(), "{:?}", warnings(&parsed));

    // Xray-core's IPv4-only automatic pool is larger.
    let parsed = parse(&profile(json!({"dns": {
        "queryStrategy": "UseIPv4",
        "servers": [{"address": "FakeDNS"}, "192.0.2.53"]
    }})));
    assert_eq!(
        parsed.config.dns.fake_ip,
        Some(fake_ip("198.18.0.0", 15, 65_535))
    );
}

#[test]
fn root_fake_dns_pools_map_onto_the_fake_ip_pool() {
    let parsed = parse(&profile(json!({
        "fakeDns": {"ipPool": "198.19.0.0/16", "poolSize": 1000},
        "dns": {"servers": ["fakedns"]}
    })));
    assert_eq!(
        parsed.config.dns.fake_ip,
        Some(fake_ip("198.19.0.0", 16, 1000))
    );
    assert!(parsed.config.dns.servers.is_empty());

    // The array form, spelled as Go's case-insensitive decoding also takes
    // it: the first IPv4 pool is used, IPv6 pools are not.
    let parsed = parse(&profile(json!({
        "fakedns": [
            {"ipPool": "fc00::/18", "poolSize": 65535},
            {"ipPool": "198.18.0.0/15", "poolSize": 65535},
            {"ipPool": "198.20.0.0/16"}
        ],
        "dns": {"servers": ["fakedns", "192.0.2.53"]}
    })));
    assert_eq!(
        parsed.config.dns.fake_ip,
        Some(fake_ip("198.18.0.0", 15, 65_535))
    );
    let warnings = warnings(&parsed);
    assert!(
        warnings
            .iter()
            .any(|(path, message)| path == "$.fakedns[0]" && message.contains("IPv6 fake pool")),
        "{warnings:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|(path, message)| path == "$.fakedns[2]" && message.contains("first IPv4")),
        "{warnings:?}"
    );

    // An absent or zero poolSize takes up to 65535 addresses.
    let parsed = parse(&profile(json!({
        "fakeDns": {"ipPool": "198.19.0.0/24", "poolSize": 0},
        "dns": {"servers": ["fakedns"]}
    })));
    assert_eq!(parsed.config.dns.fake_ip.unwrap().pool_size, 254);
}

#[test]
fn the_mapping_is_the_one_dns_fake_ip_spells_out() {
    let xray = parse(&profile(json!({
        "fakeDns": {"ipPool": "198.19.0.0/16", "poolSize": 32768},
        "dns": {"servers": ["fakedns", "192.0.2.53"]}
    })));
    let native = parse(&profile(json!({"dns": {
        "fakeIp": {"enabled": true, "ipv4Pool": "198.19.0.0/16", "poolSize": 32768, "ttl": 60},
        "servers": ["192.0.2.53"]
    }})));
    assert_eq!(xray.config.dns, native.config.dns);
}

#[test]
fn a_fakedns_xray_reaches_only_for_some_names_warns_that_every_name_is_faked() {
    for servers in [
        json!(["192.0.2.53", "fakedns"]),
        json!([{"address": "fakedns", "domains": ["domain:lan"]}, "192.0.2.53"]),
        json!(["fakedns", {"address": "192.0.2.53", "domains": ["domain:example.net"]}]),
    ] {
        let parsed = parse(&profile(json!({"dns": {"servers": servers}})));
        assert!(parsed.config.dns.fake_ip.is_some(), "{servers}");
        assert!(
            warnings(&parsed)
                .iter()
                .any(|(path, message)| path.starts_with("$.dns.servers[")
                    && message.contains("every name")),
            "{servers}: {:?}",
            warnings(&parsed)
        );
    }
}

#[test]
fn fakedns_without_an_ipv4_pool_stays_off_with_a_warning() {
    let parsed = parse(&profile(json!({
        "fakeDns": {"ipPool": "fc00::/18", "poolSize": 65535},
        "dns": {"servers": ["fakedns", "192.0.2.53"]}
    })));
    assert_eq!(parsed.config.dns.fake_ip, None);
    assert_eq!(parsed.config.dns.servers.len(), 1);
    assert!(warnings(&parsed)
        .iter()
        .any(|(path, message)| path == "$.dns.servers[0]" && message.contains("no IPv4 pool")));

    let parsed = parse(&profile(json!({"dns": {
        "queryStrategy": "UseIPv6",
        "servers": ["fakedns", "192.0.2.53"]
    }})));
    assert_eq!(parsed.config.dns.fake_ip, None);
    assert!(warnings(&parsed)
        .iter()
        .any(|(_, message)| message.contains("UseIPv6")));
}

#[test]
fn unused_pools_and_explicit_fake_ip_win_with_warnings() {
    let parsed = parse(&profile(json!({
        "fakeDns": {"ipPool": "198.18.0.0/15", "poolSize": 65535},
        "dns": {"servers": ["192.0.2.53"]}
    })));
    assert_eq!(parsed.config.dns.fake_ip, None);
    assert!(warnings(&parsed)
        .iter()
        .any(|(path, message)| path == "$.fakeDns" && message.contains("no dns server")));

    let parsed = parse(&profile(json!({
        "fakeDns": {"ipPool": "198.18.0.0/15", "poolSize": 65535}
    })));
    assert!(warnings(&parsed)
        .iter()
        .any(|(path, _)| path == "$.fakeDns"));

    let parsed = parse(&profile(json!({
        "fakeDns": {"ipPool": "198.19.0.0/16", "poolSize": 100},
        "dns": {
            "fakeIp": {"enabled": true, "ipv4Pool": "198.20.0.0/16", "poolSize": 200, "ttl": 30},
            "servers": ["fakedns"]
        }
    })));
    assert_eq!(
        parsed.config.dns.fake_ip,
        Some(DnsFakeIpConfig {
            ttl: 30,
            ..fake_ip("198.20.0.0", 16, 200)
        })
    );
    assert!(warnings(&parsed)
        .iter()
        .any(|(_, message)| message.contains("dns.fakeIp")));
}

#[test]
fn malformed_pools_fail_as_xray_core_fails_them() {
    for (fake_dns, path) in [
        (json!("198.18.0.0/15"), "$.fakeDns"),
        (
            json!({"ipPool": "198.18.0.1", "poolSize": 10}),
            "$.fakeDns.ipPool",
        ),
        (json!({"ipPool": 1918, "poolSize": 10}), "$.fakeDns.ipPool"),
        (json!({"poolSize": 10}), "$.fakeDns.ipPool"),
        (
            json!({"ipPool": "198.18.0.0/15", "poolSize": -1}),
            "$.fakeDns.poolSize",
        ),
        (
            json!({"ipPool": "198.18.0.0/24", "poolSize": 1000}),
            "$.fakeDns.poolSize",
        ),
        (
            json!({"ipPool": "198.18.0.0/15", "lruSize": 10}),
            "$.fakeDns.lruSize",
        ),
        (json!([{"ipPool": "198.18.0.0/15"}, 7]), "$.fakeDns[1]"),
    ] {
        let raw = profile(json!({"fakeDns": fake_dns, "dns": {"servers": ["fakedns"]}}));
        assert_eq!(error_paths(&raw), [path], "{fake_dns}");
    }

    let raw = profile(json!({
        "fakeDns": {"ipPool": "198.18.0.0/15"},
        "fakedns": {"ipPool": "198.19.0.0/16"},
        "dns": {"servers": ["fakedns"]}
    }));
    assert_eq!(error_paths(&raw), ["$.fakedns"]);

    // A fakedns entry is checked as an object server is.
    let raw = profile(json!({"dns": {"servers": [{"address": "fakedns", "pool": "x"}]}}));
    assert_eq!(error_paths(&raw), ["$.dns.servers[0].pool"]);
}
