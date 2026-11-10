//! Freedom's `redirect` and `userLevel`, read as Xray-core v26.10.31 reads
//! them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, FreedomNoise, FreedomNoiseFamily, FreedomNoisePacket,
    FreedomOutboundSettings, FreedomRedirect, OutboundSettings, TargetAddr,
};

fn parse(settings: Value) -> FreedomOutboundSettings {
    let raw = json!({"outbounds": [{"protocol": "freedom", "settings": settings}]}).to_string();
    let parsed = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    let OutboundSettings::Freedom(settings) = &parsed.config.outbounds[0].settings else {
        panic!("freedom parses to freedom");
    };
    settings.clone()
}

fn redirect(raw: Value) -> FreedomRedirect {
    parse(json!({ "redirect": raw })).redirect
}

fn rejection(settings: Value) -> (String, String) {
    let raw = json!({"outbounds": [{"protocol": "freedom", "settings": settings}]}).to_string();
    let error = parse_xray_json(&raw).expect_err(&format!("{raw} should be rejected"));
    let diagnostic = error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .expect("an error diagnostic");
    (
        diagnostic.path.clone().unwrap_or_default(),
        diagnostic.message.clone(),
    )
}

fn to(address: Option<TargetAddr>, port: u16) -> FreedomRedirect {
    FreedomRedirect {
        address,
        port: NonZeroU16::new(port),
    }
}

fn ip(address: impl Into<IpAddr>) -> Option<TargetAddr> {
    Some(TargetAddr::Ip(address.into()))
}

#[test]
fn redirect_replaces_what_xray_replaces() {
    let cases = [
        ("1.1.1.1:53", to(ip(Ipv4Addr::new(1, 1, 1, 1)), 53)),
        (
            "dns.example:853",
            to(Some(TargetAddr::Domain("dns.example".to_owned())), 853),
        ),
        (
            "[2001:db8::1]:443",
            to(ip("2001:db8::1".parse::<Ipv6Addr>().unwrap()), 443),
        ),
        // A v4-mapped address is IPv4, as Go's IPAddress makes it.
        (
            "[::ffff:192.0.2.1]:80",
            to(ip(Ipv4Addr::new(192, 0, 2, 1)), 80),
        ),
        // ParseAddress trims a host that starts or ends with a non-alphanumeric.
        (" 192.0.2.7:8080", to(ip(Ipv4Addr::new(192, 0, 2, 7)), 8080)),
        (
            "0080.example:0080",
            to(Some(TargetAddr::Domain("0080.example".to_owned())), 80),
        ),
        // An empty host, 0.0.0.0 and :: keep the address; port 0 keeps the port.
        (":53", to(None, 53)),
        ("0.0.0.0:443", to(None, 443)),
        ("[::]:443", to(None, 443)),
        ("192.0.2.1:0", to(ip(Ipv4Addr::new(192, 0, 2, 1)), 0)),
        (":0", FreedomRedirect::default()),
    ];
    for (raw, expected) in cases {
        assert_eq!(redirect(json!(raw)), expected, "{raw}");
    }
    assert!(redirect(json!("")).is_empty());
    assert!(redirect(Value::Null).is_empty());
    assert!(parse(json!({})).redirect.is_empty());
}

#[test]
fn redirect_rejects_what_go_rejects() {
    for raw in [
        "192.0.2.1",          // missing port in address
        "[2001:db8::1]",      // missing port in address
        "2001:db8::1:53",     // too many colons in address
        "[2001:db8::1]x:53",  // missing port in address
        "[2001:db8::1]:x:53", // too many colons in address
        "[2001:db8::1:53",    // missing ']' in address
        "a]b:53",             // unexpected ']' in address
        "a[b:53",             // unexpected '[' in address
        "192.0.2.1:",         // empty port
        "192.0.2.1:+53",      // ParseUint takes no sign
        "192.0.2.1:-1",
        "192.0.2.1:65536",      // PortFromInt
        "192.0.2.1:4294967296", // ParseUint bitSize 32
        "192.0.2.1:53 ",
    ] {
        let (path, _) = rejection(json!({ "redirect": raw }));
        assert_eq!(path, "$.outbounds[0].settings.redirect", "{raw}");
    }
    for raw in [json!(53), json!(true), json!(["1.1.1.1:53"])] {
        let (path, message) = rejection(json!({ "redirect": raw }));
        assert_eq!(path, "$.outbounds[0].settings.redirect");
        assert!(message.contains("must be a string"), "{message}");
    }
}

#[test]
fn user_level_is_a_go_uint32() {
    assert_eq!(parse(json!({})).user_level, 0);
    assert_eq!(parse(json!({"userLevel": null})).user_level, 0);
    assert_eq!(parse(json!({"userLevel": 7})).user_level, 7);
    assert_eq!(
        parse(json!({"userLevel": 4_294_967_295_u64})).user_level,
        u32::MAX
    );
    for raw in [
        json!(-1),
        json!(1.5),
        json!(1.0),
        json!("1"),
        json!(4_294_967_296_u64),
    ] {
        let (path, _) = rejection(json!({ "userLevel": raw }));
        assert_eq!(path, "$.outbounds[0].settings.userLevel", "{raw}");
    }
}

#[test]
fn settings_combine_with_the_other_freedom_options() {
    let settings = parse(json!({
        "redirect": "192.0.2.1:8443",
        "userLevel": 2,
        "domainStrategy": "UseIPv4",
        "fragment": {"packets": "tlshello", "length": "100-200", "interval": "1-2"}
    }));
    assert_eq!(settings.user_level, 2);
    assert_eq!(settings.redirect, to(ip(Ipv4Addr::new(192, 0, 2, 1)), 8443));
}

#[test]
fn proxy_protocol_keeps_only_versions_one_and_two() {
    use xray_config::ProxyProtocolVersion;
    let version = |raw: Value| parse(json!({ "proxyProtocol": raw })).proxy_protocol;
    assert_eq!(version(json!(1)), Some(ProxyProtocolVersion::V1));
    assert_eq!(version(json!(2)), Some(ProxyProtocolVersion::V2));
    // Xray-core accepts any uint32 and ignores what is not 1 or 2.
    for ignored in [json!(0), json!(3), json!(4_294_967_295_u64), Value::Null] {
        assert_eq!(version(ignored.clone()), None, "{ignored}");
    }
    assert_eq!(parse(json!({})).proxy_protocol, None);
    for raw in [
        json!(-1),
        json!(1.5),
        json!("1"),
        json!(true),
        json!(4_294_967_296_u64),
    ] {
        let (path, _) = rejection(json!({ "proxyProtocol": raw }));
        assert_eq!(path, "$.outbounds[0].settings.proxyProtocol", "{raw}");
    }
}

fn final_rule(rule: Value) -> xray_config::FreedomFinalRule {
    let mut rules = parse(json!({ "finalRules": [rule] })).final_rules;
    assert_eq!(rules.len(), 1);
    rules.remove(0)
}

#[test]
fn final_rules_read_as_xray_reads_them() {
    use xray_config::{FreedomBlockDelay, FreedomRuleAction, Network, RoutingPortRange};

    assert!(parse(json!({})).final_rules.is_empty());
    assert!(parse(json!({"finalRules": null})).final_rules.is_empty());
    assert!(parse(json!({"finalRules": []})).final_rules.is_empty());

    let rule = final_rule(json!({"action": "Block"}));
    assert_eq!(rule.action, FreedomRuleAction::Block);
    assert_eq!(rule.networks, None);
    assert_eq!(rule.port_ranges, None);
    assert_eq!(rule.ip_matchers, None);
    assert_eq!(rule.block_delay, None);
    assert_eq!(
        final_rule(json!({"action": "ALLOW"})).action,
        FreedomRuleAction::Allow
    );

    // NetworkList: unknown names are kept as networks nothing travels over.
    let networks = |raw: Value| final_rule(json!({"action": "block", "network": raw})).networks;
    assert_eq!(
        networks(json!("tcp,udp")),
        Some(vec![Network::Tcp, Network::Udp])
    );
    assert_eq!(networks(json!("UDP")), Some(vec![Network::Udp]));
    assert_eq!(networks(json!("tcp, udp")), Some(vec![Network::Tcp]));
    assert_eq!(networks(json!("unix")), Some(vec![]));
    assert_eq!(networks(json!("")), Some(vec![]));
    assert_eq!(
        networks(json!(["udp", null, "quic"])),
        Some(vec![Network::Udp])
    );
    assert_eq!(networks(json!([])), None);
    assert_eq!(networks(Value::Null), None);

    // PortList, as in routing rules. A final rule checks ports only once the
    // list has a range, so a numeric zero applies to every port, while a
    // reversed range, which Xray-core keeps, applies to none.
    let ports = |raw: Value| final_rule(json!({"action": "block", "port": raw})).port_ranges;
    assert_eq!(
        ports(json!("53, 443,1000-2000")),
        Some(vec![
            RoutingPortRange::single(53),
            RoutingPortRange::single(443),
            RoutingPortRange::new(1000, 2000).unwrap(),
        ])
    );
    assert_eq!(
        ports(json!(8443)),
        Some(vec![RoutingPortRange::single(8443)])
    );
    assert_eq!(ports(json!(0)), None);
    assert_eq!(ports(json!("")), None);
    assert_eq!(ports(json!("0")), Some(vec![RoutingPortRange::single(0)]));
    assert_eq!(ports(json!("2-1")), Some(vec![]));
    assert_eq!(
        ports(json!("2-1,53")),
        Some(vec![RoutingPortRange::single(53)])
    );

    // StringList of routing IP rules; an empty list sets no condition.
    let ips = |raw: Value| final_rule(json!({"action": "block", "ip": raw})).ip_matchers;
    // Go's ParseAddress trims the space after a comma.
    let listed = ips(json!("10.0.0.0/8, 192.0.2.1")).expect("an address condition");
    assert!(listed.matches("10.1.2.3".parse().unwrap()));
    assert!(listed.matches("192.0.2.1".parse().unwrap()));
    assert!(!listed.matches("192.0.2.2".parse().unwrap()));
    let inverse = ips(json!(["!192.0.2.0/24"])).expect("an address condition");
    assert!(!inverse.matches("192.0.2.9".parse().unwrap()));
    assert!(inverse.matches("198.51.100.1".parse().unwrap()));
    assert_eq!(ips(json!([])), None);

    // Int32Range of seconds, in either order, under `delay` and under the
    // deprecated `blockDelay`.
    let seconds = |min_secs, max_secs| Some(FreedomBlockDelay { min_secs, max_secs });
    for field in ["delay", "blockDelay"] {
        let delay = |raw: Value| final_rule(json!({"action": "block", field: raw})).block_delay;
        assert_eq!(delay(json!(5)), seconds(5, 5), "{field}");
        assert_eq!(delay(json!("10-5")), seconds(5, 10), "{field}");
        assert_eq!(delay(json!("")), seconds(0, 0), "{field}");
        assert_eq!(delay(Value::Null), None, "{field}");
    }
}

#[test]
fn final_rule_delay_and_log_level_read_as_xray_reads_them() {
    use xray_config::{FreedomBlockDelay, FreedomRuleAction, FreedomRuleLogLevel};
    let seconds = |min_secs, max_secs| Some(FreedomBlockDelay { min_secs, max_secs });

    // `blockDelay` takes the place of `delay` when both are set, as
    // Xray-core's Build copies it over with a deprecation warning.
    let freedom =
        |settings: Value| json!({"outbounds": [{"protocol": "freedom", "settings": settings}]});
    let (settings, warned) = warnings(&freedom(json!({
        "finalRules": [{"action": "block", "delay": 7, "blockDelay": "1-2"}]
    })));
    assert_eq!(settings.final_rules[0].block_delay, seconds(1, 2));
    assert_eq!(warned, ["$.outbounds[0].settings.finalRules[0].blockDelay"]);
    let (settings, warned) = warnings(&freedom(json!({
        "finalRules": [{"action": "block", "delay": 7, "blockDelay": null}]
    })));
    assert_eq!(settings.final_rules[0].block_delay, seconds(7, 7));
    assert!(warned.is_empty(), "{warned:?}");

    let level = |raw: Value| final_rule(json!({"action": "block", "logLevel": raw})).log_level;
    assert_eq!(level(Value::Null), FreedomRuleLogLevel::Info);
    assert_eq!(level(json!("")), FreedomRuleLogLevel::Info);
    assert_eq!(level(json!("Info")), FreedomRuleLogLevel::Info);
    assert_eq!(level(json!("NONE")), FreedomRuleLogLevel::None);
    assert_eq!(level(json!("debug")), FreedomRuleLogLevel::Debug);
    assert_eq!(level(json!("Warning")), FreedomRuleLogLevel::Warning);
    assert_eq!(level(json!("error")), FreedomRuleLogLevel::Error);
    // Go's strings.ToLower maps İ to a plain i.
    assert_eq!(level(json!("İNFO")), FreedomRuleLogLevel::Info);

    // An allow rule keeps the defaults and takes an empty or null level.
    for rule in [
        json!({"action": "allow"}),
        json!({"action": "allow", "logLevel": ""}),
        json!({"action": "allow", "logLevel": null, "delay": null, "blockDelay": null}),
    ] {
        let allowed = final_rule(rule.clone());
        assert_eq!(allowed.action, FreedomRuleAction::Allow, "{rule}");
        assert_eq!(allowed.block_delay, None, "{rule}");
        assert_eq!(allowed.log_level, FreedomRuleLogLevel::Info, "{rule}");
    }
}

#[test]
fn final_rule_delay_and_log_level_reject_what_xray_rejects() {
    let rule_path = "$.outbounds[0].settings.finalRules[0]";
    for (rule, field, message) in [
        (
            json!({"action": "allow", "delay": 5}),
            "delay",
            "only supported for block",
        ),
        (
            json!({"action": "allow", "blockDelay": 5}),
            "blockDelay",
            "only supported for block",
        ),
        (
            json!({"action": "allow", "delay": 5, "blockDelay": 1}),
            "blockDelay",
            "only supported for block",
        ),
        (
            json!({"action": "allow", "logLevel": "info"}),
            "logLevel",
            "only supported for block",
        ),
        // Xray-core refuses an allow rule's level before it reads its value.
        (
            json!({"action": "allow", "logLevel": "loud"}),
            "logLevel",
            "only supported for block",
        ),
        (
            json!({"action": "block", "logLevel": "loud"}),
            "logLevel",
            "loud",
        ),
        (
            json!({"action": "block", "logLevel": "warn"}),
            "logLevel",
            "warn",
        ),
        (
            json!({"action": "block", "logLevel": 1}),
            "logLevel",
            "string",
        ),
        (
            json!({"action": "block", "delay": "x"}),
            "delay",
            "delay must be",
        ),
        (
            json!({"action": "block", "delay": 1.5}),
            "delay",
            "delay must be",
        ),
        (
            json!({"action": "block", "delay": "-5-10"}),
            "delay",
            "delay must be",
        ),
    ] {
        let (path, error) = rejection(json!({ "finalRules": [rule.clone()] }));
        assert_eq!(path, format!("{rule_path}.{field}"), "{rule}");
        assert!(error.contains(message), "{rule}: {error}");
    }
}

#[test]
fn final_rules_reject_what_xray_rejects() {
    let rule_path = "$.outbounds[0].settings.finalRules[0]";
    for (rule, field) in [
        (json!({}), "action"),
        (json!({"action": "deny"}), "action"),
        (json!({"action": 1}), "action"),
        (json!({"action": "block", "network": 5}), "network"),
        (
            json!({"action": "block", "network": ["tcp", 5]}),
            "network[1]",
        ),
        (json!({"action": "block", "port": "x"}), "port[0]"),
        (json!({"action": "block", "port": 65_536}), "port"),
        (json!({"action": "block", "port": -1}), "port"),
        (json!({"action": "block", "ip": ""}), "ip[0]"),
        (json!({"action": "block", "ip": [5]}), "ip[0]"),
        (json!({"action": "block", "ip": ["300.0.0.1"]}), "ip[0]"),
        (json!({"action": "block", "ip": 5}), "ip"),
        (
            json!({"action": "block", "blockDelay": {"from": 1, "to": 2}}),
            "blockDelay",
        ),
        (json!({"action": "block", "blockDelay": 1.5}), "blockDelay"),
        (json!({"action": "block", "blockDelay": "x"}), "blockDelay"),
    ] {
        let (path, _) = rejection(json!({ "finalRules": [rule.clone()] }));
        assert_eq!(path, format!("{rule_path}.{field}"), "{rule}");
    }
    let (path, _) = rejection(json!({"finalRules": {"action": "block"}}));
    assert_eq!(path, "$.outbounds[0].settings.finalRules");
    let (path, _) = rejection(json!({"finalRules": [null]}));
    assert_eq!(path, rule_path);

    // Deliberate: Xray-core accepts these, and a negative or wrapped delay
    // later panics or never holds the connection; an unknown field is
    // silently ignored there.
    for (rule, field) in [
        (
            json!({"action": "block", "blockDelay": "-5-10"}),
            "blockDelay",
        ),
        (
            json!({"action": "block", "blockDelay": "2147483648"}),
            "blockDelay",
        ),
        (
            json!({"action": "block", "domain": ["example.com"]}),
            "domain",
        ),
    ] {
        let (path, _) = rejection(json!({ "finalRules": [rule.clone()] }));
        assert_eq!(path, format!("{rule_path}.{field}"), "{rule}");
    }
}

fn warnings(raw: &Value) -> (xray_config::FreedomOutboundSettings, Vec<String>) {
    let raw = raw.to_string();
    let parsed = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    let warnings = parsed
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
        .filter_map(|diagnostic| diagnostic.path.clone())
        .collect();
    let OutboundSettings::Freedom(settings) = &parsed.config.outbounds[0].settings else {
        panic!("freedom parses to freedom");
    };
    (settings.clone(), warnings)
}

#[test]
fn ips_blocked_is_ignored_with_a_warning() {
    for raw in [json!(["10.0.0.0/8"]), json!("10.0.0.0/8"), json!([null])] {
        let (settings, warnings) = warnings(
            &json!({"outbounds": [{"protocol": "freedom", "settings": {"ipsBlocked": raw}}]}),
        );
        assert!(settings.final_rules.is_empty());
        assert_eq!(warnings, ["$.outbounds[0].settings.ipsBlocked"]);
    }
    let (_, warnings) = warnings(
        &json!({"outbounds": [{"protocol": "freedom", "settings": {"ipsBlocked": null}}]}),
    );
    assert!(warnings.is_empty());
    for raw in [json!(5), json!([5]), json!({})] {
        let (path, _) = rejection(json!({ "ipsBlocked": raw }));
        assert_eq!(path, "$.outbounds[0].settings.ipsBlocked");
    }
}

#[test]
fn final_rules_are_ignored_through_dialer_proxy() {
    let (settings, warnings) = warnings(&json!({"outbounds": [
        {"protocol": "freedom", "settings": {"finalRules": [{"action": "block"}]},
         "streamSettings": {"sockopt": {"dialerProxy": "next"}}},
        {"tag": "next", "protocol": "freedom"}
    ]}));
    assert!(settings.final_rules.is_empty());
    assert_eq!(warnings, ["$.outbounds[0].settings.finalRules"]);
}

#[test]
fn an_empty_condition_matches_nothing_and_an_absent_one_everything() {
    use xray_config::{
        deciding_final_rule, FreedomFinalRule, FreedomRuleAction, IpMatcherSet, Network,
        RoutingPortRange,
    };
    let any = FreedomFinalRule {
        action: FreedomRuleAction::Block,
        networks: None,
        port_ranges: None,
        ip_matchers: None,
        block_delay: None,
        log_level: Default::default(),
    };
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    assert!(any.applies(Network::Tcp, ip, 1));
    assert!(any.applies(Network::Udp, ip, 65_535));
    // Xray-core keeps an unknown network as one nothing travels over, and an
    // `ip` list that builds no ranges as a matcher that matches nothing.
    let no_network = FreedomFinalRule {
        networks: Some(Vec::new()),
        ..any.clone()
    };
    assert!(!no_network.applies(Network::Tcp, ip, 1));
    let no_address = FreedomFinalRule {
        ip_matchers: Some(IpMatcherSet::default()),
        ..any.clone()
    };
    assert!(!no_address.applies(Network::Tcp, ip, 1));
    let port = FreedomFinalRule {
        port_ranges: Some(vec![RoutingPortRange::new(50, 60).unwrap()]),
        ..any.clone()
    };
    assert!(port.applies(Network::Tcp, ip, 55));
    assert!(!port.applies(Network::Tcp, ip, 61));
    let rules = [no_network, port.clone(), any];
    assert_eq!(
        deciding_final_rule(&rules, Network::Tcp, ip, 55),
        Some(&port)
    );
    assert_eq!(deciding_final_rule(&rules[..2], Network::Tcp, ip, 61), None);
}

fn noise(item: Value) -> FreedomNoise {
    parse(json!({ "noises": [item] })).noises.remove(0)
}

#[test]
fn noises_read_as_xray_core_reads_them() {
    let bytes = |item| match noise(item).packet {
        FreedomNoisePacket::Bytes(bytes) => bytes,
        other => panic!("not bytes: {other:?}"),
    };
    // The packet is trimmed, then read as its type says.
    assert_eq!(
        bytes(json!({"type": "str", "packet": "  spaced  "})),
        b"spaced"
    );
    assert_eq!(bytes(json!({"type": "str", "packet": null})), b"");
    assert_eq!(
        bytes(json!({"type": "hex", "packet": "48656C6c6f"})),
        b"Hello"
    );
    // Base64 in either alphabet, padding anywhere ignored, line breaks too.
    for packet in ["SGVsbG8=", "SGVsbG8", "SG=VsbG8", "SGVs\nbG8"] {
        assert_eq!(
            bytes(json!({"type": "base64", "packet": packet})),
            b"Hello",
            "{packet}"
        );
    }
    assert_eq!(
        bytes(json!({"type": "base64", "packet": "+/+/"})),
        [0xfb, 0xff, 0xbf]
    );
    assert_eq!(
        bytes(json!({"type": "base64", "packet": "-_-_"})),
        [0xfb, 0xff, 0xbf]
    );
    // A random length keeps the order written.
    assert_eq!(
        noise(json!({"type": "rand", "packet": "32-16"})).packet,
        FreedomNoisePacket::Random(32, 16)
    );
    assert_eq!(
        noise(json!({"type": "rand", "packet": " 7 "})).packet,
        FreedomNoisePacket::Random(7, 7)
    );

    // Delays order their bounds; applyTo ignores case.
    let timed = noise(json!({"type": "str", "packet": "x", "delay": "10-5", "applyTo": "IPv6"}));
    assert_eq!(timed.delay_ms, (5, 10));
    assert_eq!(timed.apply_to, FreedomNoiseFamily::Ipv6);
    let plain = noise(json!({"type": "str", "packet": "x", "delay": 3, "applyTo": "all"}));
    assert_eq!(plain.delay_ms, (3, 3));
    assert_eq!(plain.apply_to, FreedomNoiseFamily::Ip);
    assert_eq!(
        noise(json!({"type": "str", "packet": "x"})).delay_ms,
        (0, 0)
    );

    // The bounds themselves are accepted.
    let most = vec![json!({"type": "str", "packet": "x"}); 16];
    assert_eq!(parse(json!({ "noises": most })).noises.len(), 16);
    let longest = "x".repeat(4096);
    assert_eq!(bytes(json!({"type": "str", "packet": longest})).len(), 4096);
    assert_eq!(
        noise(json!({"type": "rand", "packet": "4096-1"})).packet,
        FreedomNoisePacket::Random(4096, 1)
    );
    assert_eq!(
        noise(json!({"type": "str", "packet": "x", "delay": "1000-0"})).delay_ms,
        (0, 1000)
    );
}

#[test]
fn noises_warn_that_they_are_deprecated() {
    let raw = json!({"outbounds": [{"protocol": "freedom",
        "settings": {"noises": [{"type": "str", "packet": "x"}]}}]})
    .to_string();
    let parsed = parse_xray_json(&raw).unwrap();
    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.path.as_deref() == Some("$.outbounds[0].settings.noises")
    }));
    // `null` and `[]` set none.
    assert!(parse(json!({"noises": null})).noises.is_empty());
    assert!(parse(json!({"noises": []})).noises.is_empty());
}

#[test]
fn noises_reject_what_xray_core_rejects() {
    let base = "$.outbounds[0].settings";
    for (settings, path) in [
        // The `noise` object is removed in Xray-core.
        (json!({"noise": {}}), format!("{base}.noise")),
        (json!({"noises": "x"}), format!("{base}.noises")),
        // Xray-core panics on a `null` entry.
        (json!({"noises": [null]}), format!("{base}.noises[0]")),
        (
            json!({"noises": [{"type": "RAND", "packet": "5"}]}),
            format!("{base}.noises[0].type"),
        ),
        (
            json!({"noises": [{"packet": "x"}]}),
            format!("{base}.noises[0].type"),
        ),
        (
            json!({"noises": [{"type": "rand", "packet": "0-10"}]}),
            format!("{base}.noises[0].packet"),
        ),
        (
            json!({"noises": [{"type": "rand", "packet": ""}]}),
            format!("{base}.noises[0].packet"),
        ),
        (
            json!({"noises": [{"type": "hex", "packet": "abc"}]}),
            format!("{base}.noises[0].packet"),
        ),
        (
            json!({"noises": [{"type": "base64", "packet": "!!"}]}),
            format!("{base}.noises[0].packet"),
        ),
        (
            json!({"noises": [{"type": "str", "packet": "x", "delay": 1.5}]}),
            format!("{base}.noises[0].delay"),
        ),
        (
            json!({"noises": [{"type": "str", "packet": "x", "applyTo": "ipv5"}]}),
            format!("{base}.noises[0].applyTo"),
        ),
        // Bounds Xray-core does not set.
        (
            json!({"noises": [{"type": "rand", "packet": "-5"}]}),
            format!("{base}.noises[0].packet"),
        ),
        (
            json!({"noises": [{"type": "rand", "packet": "4097"}]}),
            format!("{base}.noises[0].packet"),
        ),
        (
            json!({"noises": [{"type": "str", "packet": "x", "delay": 1001}]}),
            format!("{base}.noises[0].delay"),
        ),
        (
            json!({"noises": [{"type": "str", "packet": "x", "delay": -1}]}),
            format!("{base}.noises[0].delay"),
        ),
        (
            json!({"noises": [{"type": "str", "packet": "x".repeat(4097)}]}),
            format!("{base}.noises[0].packet"),
        ),
    ] {
        assert_eq!(rejection(settings.clone()).0, path, "{settings}");
    }
    let many = vec![json!({"type": "str", "packet": "x"}); 17];
    assert_eq!(
        rejection(json!({ "noises": many })).0,
        format!("{base}.noises")
    );
}

/// Every case of the corpus gets Xray-core's verdict, except the
/// deliberate differences, which get theirs. scripts/check-xray-verdicts.sh
/// rechecks the recorded verdicts against the pinned Xray-core.
#[test]
fn config_verdicts_match_xray_core() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/freedom/config-verdicts.json"
    ))
    .unwrap();
    let mut mismatches = Vec::new();
    for case in corpus["cases"].as_array().unwrap() {
        let raw = json!({"outbounds": [case["outbound"].clone()]}).to_string();
        let parsed = parse_xray_json(&raw);
        let expected_ok = match case.get("ours").and_then(Value::as_str) {
            Some(ours) => ours == "ok",
            None => case["xray"] == "ok",
        };
        if parsed.is_ok() != expected_ok {
            let detail = parsed
                .err()
                .map(|e| format!("{:?}", e.diagnostics))
                .unwrap_or_default();
            mismatches.push(format!(
                "{}: expected {}: {detail}",
                case["name"], case["xray"]
            ));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}
