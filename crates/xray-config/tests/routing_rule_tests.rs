//! Routing rules read as Xray-core v26.10.31 reads them.

use std::net::{IpAddr, Ipv4Addr};

use serde_json::{json, Value};
use xray_config::{
    go_lowercase, parse_xray_json, ContentAttributes, DiagnosticSeverity, Network, RouteContext,
    RoutingPortRange, RoutingRule, RoutingRuleTarget,
};

fn config(rules: Value) -> String {
    json!({
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "proxy", "protocol": "freedom"}
        ],
        "routing": {
            "rules": rules,
            "balancers": [{"tag": "pool", "selector": ["proxy"]}]
        }
    })
    .to_string()
}

fn rule(rule: Value) -> RoutingRule {
    let raw = config(json!([rule]));
    let parsed = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    parsed.config.routing.rules[0].clone()
}

fn rejection(rule: Value) -> String {
    let raw = config(json!([rule]));
    let error = parse_xray_json(&raw).expect_err(&format!("{raw} should be rejected"));
    error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .and_then(|diagnostic| diagnostic.path.clone())
        .unwrap_or_default()
}

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[test]
fn type_is_not_read() {
    for rule_type in [
        None,
        Some(json!("field")),
        Some(json!("chinaip")),
        Some(json!(5)),
    ] {
        let mut raw = json!({"port": "53", "outboundTag": "direct"});
        if let Some(rule_type) = &rule_type {
            raw["type"] = rule_type.clone();
        }
        assert!(rule(raw).matches_port(Some(53)), "{rule_type:?}");
    }
}

#[test]
fn a_nonempty_outbound_tag_wins_over_the_balancer() {
    let target = |raw: Value| rule(raw).target;
    assert_eq!(
        target(json!({"port": "1", "outboundTag": "direct", "balancerTag": "pool"})),
        RoutingRuleTarget::Outbound("direct".to_owned())
    );
    assert_eq!(
        target(json!({"port": "1", "outboundTag": "", "balancerTag": "pool"})),
        RoutingRuleTarget::Balancer("pool".to_owned())
    );
    assert_eq!(
        target(json!({"port": "1", "outboundTag": null, "balancerTag": "pool"})),
        RoutingRuleTarget::Balancer("pool".to_owned())
    );
    let rules = "$.routing.rules[0]";
    for (raw, path) in [
        (json!({"port": "1"}), "outboundTag"),
        (json!({"port": "1", "outboundTag": ""}), "outboundTag"),
        (json!({"port": "1", "outboundTag": 5}), "outboundTag"),
        (json!({"port": "1", "balancerTag": 5}), "balancerTag"),
        (
            json!({"port": "1", "balancerTag": "missing"}),
            "balancerTag",
        ),
        (
            json!({"port": "1", "outboundTag": "direct", "ruleTag": 5}),
            "ruleTag",
        ),
    ] {
        assert_eq!(rejection(raw.clone()), format!("{rules}.{path}"), "{raw}");
    }
}

#[test]
fn a_rule_without_a_condition_is_refused() {
    for raw in [
        json!({"outboundTag": "direct"}),
        json!({"outboundTag": "direct", "network": []}),
        json!({"outboundTag": "direct", "ip": [], "domain": [], "inboundTag": []}),
        json!({"outboundTag": "direct", "port": null, "localOS": null}),
        // `domains` replaces `domain`, and empty it leaves no condition.
        json!({"outboundTag": "direct", "domain": ["example.com"], "domains": []}),
    ] {
        assert_eq!(rejection(raw.clone()), "$.routing.rules[0]", "{raw}");
    }
}

#[test]
fn string_lists_take_a_comma_separated_string() {
    let tagged = rule(json!({"inboundTag": "socks-in,tun-in", "outboundTag": "direct"}));
    assert!(tagged.matches_inbound(Some("tun-in")));
    assert!(!tagged.matches_inbound(Some("http-in")));

    let addressed = rule(json!({"ip": "10.0.0.0/8, 127.0.0.1", "outboundTag": "direct"}));
    assert!(addressed.matches_ip(Some(&LOOPBACK)));
    assert!(addressed.matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4)))));

    // Domain entries are not trimmed: " b.test" is a substring with a space.
    let named = rule(json!({"domain": "a.test, b.test", "outboundTag": "direct"}));
    assert!(named.matches_domain(Some("a.test")));
    assert!(!named.matches_domain(Some("b.test")));
    let named = rule(json!({"domains": "full:a.test", "outboundTag": "direct"}));
    assert!(named.matches_domain(Some("a.test")));
    assert!(!named.matches_domain(Some("www.a.test")));
}

#[test]
fn empty_tags_match_no_connection() {
    // Xray-core drops an empty tag from the list and never matches a
    // connection without one.
    for raw in [json!(""), json!([null])] {
        let rule = rule(json!({"inboundTag": raw, "outboundTag": "direct"}));
        assert!(!rule.matches_inbound(Some("socks-in")), "{raw}");
        assert!(!rule.matches_inbound(Some("")), "{raw}");
        assert!(!rule.matches_inbound(None), "{raw}");
    }
    let wildcard = rule(json!({"inboundTag": [], "port": "1", "outboundTag": "direct"}));
    assert!(wildcard.matches_inbound(None));
}

#[test]
fn networks_xray_core_does_not_know_match_nothing() {
    let networks = |raw: Value| rule(json!({"network": raw, "outboundTag": "direct"})).networks;
    assert_eq!(
        networks(json!("tcp,UDP")),
        Some(vec![Network::Tcp, Network::Udp])
    );
    assert_eq!(networks(json!("tcp, udp")), Some(vec![Network::Tcp]));
    assert_eq!(networks(json!(["udp", null])), Some(vec![Network::Udp]));
    for nothing in [json!(""), json!("quic"), json!(" tcp"), json!(["unix"])] {
        let rule = rule(json!({"network": nothing.clone(), "outboundTag": "direct"}));
        assert_eq!(rule.networks, Some(vec![]), "{nothing}");
        assert!(!rule.matches_network(Some(Network::Tcp)), "{nothing}");
        assert!(!rule.matches_network(Some(Network::Udp)), "{nothing}");
    }
    let any = rule(json!({"network": [], "port": "1", "outboundTag": "direct"}));
    assert_eq!(any.networks, None);
}

#[test]
fn any_port_given_sets_a_port_condition() {
    let ports = |raw: Value| rule(json!({"port": raw, "outboundTag": "direct"})).port_ranges;
    assert_eq!(
        ports(json!("53, 443,1000-2000")),
        Some(vec![
            RoutingPortRange::single(53),
            RoutingPortRange::single(443),
            RoutingPortRange::new(1000, 2000).unwrap(),
        ])
    );
    assert_eq!(
        ports(json!("053-060")),
        Some(vec![RoutingPortRange::new(53, 60).unwrap()])
    );
    // A zero, an empty list and a reversed range give a condition that no
    // port meets, so the rule never matches.
    for nothing in [json!(0), json!(""), json!(","), json!("2-1")] {
        let rule = rule(json!({"port": nothing.clone(), "outboundTag": "direct"}));
        assert_eq!(rule.port_ranges, Some(vec![]), "{nothing}");
        assert!(!rule.matches_port(Some(2)), "{nothing}");
    }
    assert_eq!(
        ports(json!("2-1,53")),
        Some(vec![RoutingPortRange::single(53)])
    );
    assert_eq!(ports(json!("0")), Some(vec![RoutingPortRange::single(0)]));

    let rules = "$.routing.rules[0]";
    for (raw, path) in [
        // A single port reads as a JSON integer, a range end as digits.
        (json!("053"), "port[0]"),
        (json!("+53"), "port[0]"),
        (json!("+53-60"), "port[0]"),
        (json!("1e2"), "port[0]"),
        (json!("53 - 60"), "port[0]"),
        (json!("65536"), "port[0]"),
        (json!("1-65536"), "port[0]"),
        (json!("env:PORT"), "port[0]"),
        (json!([53]), "port"),
        (json!(-1), "port"),
        (json!(53.5), "port"),
        // Deliberate: Xray-core truncates a number above 65535 to 16 bits.
        (json!(65_617), "port"),
    ] {
        let raw = json!({"port": raw, "outboundTag": "direct"});
        assert_eq!(rejection(raw.clone()), format!("{rules}.{path}"), "{raw}");
    }
}

#[test]
fn domain_rules_read_as_parse_domain_rules_reads_them() {
    let matches = |entry: &str, domain: &str| {
        rule(json!({"domain": [entry], "outboundTag": "direct"})).matches_domain(Some(domain))
    };
    // An empty substring, keyword or regexp matches every domain.
    for entry in ["", "keyword:", "regexp:"] {
        assert!(matches(entry, "localhost"), "{entry:?}");
    }
    // An empty suffix matches only names ending in a dot, and an empty full
    // name matches none.
    assert!(!matches("domain:", "localhost"));
    assert!(matches("domain:", "example.com."));
    assert!(!matches("full:", "localhost"));
    // Anything without a known prefix is a substring, colon and all.
    assert!(matches("foo:bar", "a.foo:bar.test"));
    assert!(!matches("foo:bar", "foo.bar"));
    assert!(matches("dotless:host", "localhost"));
    assert!(!matches("dotless:host", "host.test"));
    let null = rule(json!({"domain": [null], "outboundTag": "direct"}));
    assert!(null.matches_domain(Some("anything.test")));

    let rules = "$.routing.rules[0]";
    for (entry, path) in [("dotless:a.b", "domain[0]"), ("regexp:(", "domain[0]")] {
        let raw = json!({"domain": [entry], "outboundTag": "direct"});
        assert_eq!(rejection(raw.clone()), format!("{rules}.{path}"), "{raw}");
    }
}

#[test]
fn domains_replaces_domain_but_both_must_parse() {
    let both = rule(json!({
        "domain": ["only-domain.test"],
        "domains": ["only-domains.test"],
        "outboundTag": "direct"
    }));
    assert!(!both.matches_domain(Some("only-domain.test")));
    assert!(both.matches_domain(Some("only-domains.test")));
    let raw = json!({"domain": ["regexp:("], "domains": ["a.test"], "outboundTag": "direct"});
    assert_eq!(rejection(raw), "$.routing.rules[0].domain[0]");
}

fn route<'a>(source: &str, local: &str, user: Option<&'a str>) -> RouteContext<'a> {
    RouteContext {
        attributes: None,
        protocol: None,
        inbound_tag: Some("socks-in"),
        source: Some(source.parse().unwrap()),
        local: Some(local.parse().unwrap()),
        user,
    }
}

fn applies(rule: &RoutingRule, route: &RouteContext<'_>) -> bool {
    rule.matches_route(route, None, Some(&LOOPBACK), Some(Network::Tcp), Some(443))
}

#[test]
fn source_ip_falls_back_to_source_only_when_absent_or_null() {
    let client = route("10.1.2.3:5000", "127.0.0.1:1080", None);
    let other = route("192.0.2.1:5000", "127.0.0.1:1080", None);
    for raw in [
        json!({"source": ["10.0.0.0/8"], "outboundTag": "direct"}),
        json!({"sourceIP": "10.0.0.0/8", "outboundTag": "direct"}),
        json!({"sourceIP": null, "source": "10.0.0.0/8", "outboundTag": "direct"}),
        json!({"sourceIP": ["10.0.0.0/8"], "source": ["192.0.2.0/24"], "outboundTag": "direct"}),
    ] {
        let parsed = rule(raw.clone());
        assert!(applies(&parsed, &client), "{raw}");
        assert!(!applies(&parsed, &other), "{raw}");
    }
    // A given `sourceIP`, even empty, hides `source`; with nothing else the
    // rule has no condition.
    assert_eq!(
        rejection(json!({"sourceIP": [], "source": ["192.0.2.0/24"], "outboundTag": "direct"})),
        "$.routing.rules[0]"
    );
    // Go still decodes the hidden `source`.
    assert_eq!(
        rejection(json!({"sourceIP": ["10.0.0.0/8"], "source": 5, "outboundTag": "direct"})),
        "$.routing.rules[0].source"
    );
    // A v4-mapped source is the IPv4 address.
    let mapped = route("[::ffff:10.1.2.3]:5000", "127.0.0.1:1080", None);
    assert!(applies(
        &rule(json!({"source": "10.0.0.0/8", "outboundTag": "direct"})),
        &mapped
    ));
    // A connection without a source matches no source rule.
    let unknown = RouteContext::inbound(Some("socks-in"));
    assert!(!applies(
        &rule(json!({"source": "0.0.0.0/0", "outboundTag": "direct"})),
        &unknown
    ));
}

#[test]
fn source_and_local_ports_read_as_port_lists() {
    let client = route("10.1.2.3:5000", "127.0.0.1:1080", None);
    let ports =
        rule(json!({"sourcePort": "4000-6000", "localPort": 1080, "outboundTag": "direct"}));
    assert!(applies(&ports, &client));
    assert!(!applies(
        &ports,
        &route("10.1.2.3:7000", "127.0.0.1:1080", None)
    ));
    assert!(!applies(
        &ports,
        &route("10.1.2.3:5000", "127.0.0.1:1081", None)
    ));
    // As for `port`, any value sets a condition, so 0 matches no port.
    let zero = rule(json!({"sourcePort": 0, "outboundTag": "direct"}));
    assert!(!applies(&zero, &client));
    // An unknown port reads as 0, as in Xray-core.
    let from_zero = rule(json!({"localPort": "0", "outboundTag": "direct"}));
    assert!(applies(
        &from_zero,
        &RouteContext::inbound(Some("socks-in"))
    ));
    assert!(!applies(&from_zero, &client));

    let rules = "$.routing.rules[0]";
    for (raw, path) in [
        (
            json!({"sourcePort": "053", "outboundTag": "direct"}),
            "sourcePort[0]",
        ),
        (
            json!({"localPort": 65536, "outboundTag": "direct"}),
            "localPort",
        ),
        (
            json!({"localIP": ["10.0.0.0/33"], "outboundTag": "direct"}),
            "localIP[0]",
        ),
    ] {
        assert_eq!(rejection(raw.clone()), format!("{rules}.{path}"), "{raw}");
    }
}

#[test]
fn local_ip_matches_the_address_the_connection_arrived_on() {
    let parsed = rule(json!({"localIP": ["127.0.0.0/8"], "outboundTag": "direct"}));
    assert!(applies(
        &parsed,
        &route("10.1.2.3:5000", "127.0.0.1:1080", None)
    ));
    assert!(!applies(
        &parsed,
        &route("10.1.2.3:5000", "192.0.2.1:1080", None)
    ));
    assert!(!applies(&parsed, &RouteContext::inbound(Some("socks-in"))));
}

#[test]
fn users_are_names_and_patterns() {
    let users =
        rule(json!({"user": ["alice", "regexp:^team-", "", "regexp:"], "outboundTag": "direct"}));
    let as_user = |user| route("10.1.2.3:5000", "127.0.0.1:1080", Some(user));
    assert!(applies(&users, &as_user("alice")));
    assert!(applies(&users, &as_user("team-blue")));
    assert!(!applies(&users, &as_user("Alice")));
    assert!(!applies(&users, &as_user("my-team-blue")));
    // `regexp:` with nothing after it is a name.
    assert!(applies(&users, &as_user("regexp:")));
    assert!(!applies(
        &users,
        &route("10.1.2.3:5000", "127.0.0.1:1080", None)
    ));

    // Any entry sets a condition, though an empty name matches no user.
    let empty = rule(json!({"user": [""], "outboundTag": "direct"}));
    assert!(!applies(&empty, &as_user("alice")));
    assert_eq!(
        rejection(json!({"user": [], "outboundTag": "direct"})),
        "$.routing.rules[0]"
    );

    // A pattern that does not compile is ignored with a warning, as Xray-core
    // ignores it.
    let raw = config(json!([{"user": ["regexp:(", "bob"], "outboundTag": "direct"}]));
    let parsed = parse_xray_json(&raw).expect("an invalid user pattern is ignored");
    assert_eq!(
        parsed.diagnostics[0].path.as_deref(),
        Some("$.routing.rules[0].user[0]")
    );
    assert_eq!(parsed.diagnostics[0].severity, DiagnosticSeverity::Warning);
    let ignored = &parsed.config.routing.rules[0];
    assert!(applies(ignored, &as_user("bob")));
    assert!(!applies(ignored, &as_user("(")));
}

#[test]
fn protocols_match_the_sniffed_protocol_by_prefix() {
    let applies_to = |rule: &RoutingRule, protocol: Option<&str>| {
        let route = RouteContext {
            protocol,
            ..RouteContext::inbound(Some("socks-in"))
        };
        rule.matches_route(&route, None, Some(&LOOPBACK), Some(Network::Tcp), Some(443))
    };
    let http = rule(json!({"protocol": ["http", "bittorrent"], "outboundTag": "direct"}));
    assert!(applies_to(&http, Some("http1")));
    assert!(applies_to(&http, Some("bittorrent")));
    assert!(!applies_to(&http, Some("tls")));
    // A flow without a sniffed protocol matches no protocol rule.
    assert!(!applies_to(&http, None));

    // A string is split at commas, untrimmed.
    let split = rule(json!({"protocol": "tls, quic", "outboundTag": "direct"}));
    assert!(applies_to(&split, Some("tls")));
    assert!(!applies_to(&split, Some("quic")));
    // Any entry sets a condition, though empty names match nothing.
    let empty = rule(json!({"protocol": [""], "outboundTag": "direct"}));
    assert!(!applies_to(&empty, Some("tls")));
    assert_eq!(
        rejection(json!({"protocol": [], "outboundTag": "direct"})),
        "$.routing.rules[0]"
    );
    assert_eq!(
        rejection(json!({"protocol": [5], "outboundTag": "direct"})),
        "$.routing.rules[0].protocol[0]"
    );
}

fn attributes(entries: &[(&str, &str)]) -> ContentAttributes {
    let mut attributes = ContentAttributes::default();
    for (name, value) in entries {
        attributes.set(name, (*value).to_owned());
    }
    attributes
}

#[test]
fn attrs_match_every_named_attribute_by_pattern() {
    let applies_to = |rule: &RoutingRule, attributes: Option<&ContentAttributes>| {
        let route = RouteContext {
            attributes,
            ..RouteContext::inbound(Some("socks-in"))
        };
        rule.matches_route(&route, None, Some(&LOOPBACK), Some(Network::Tcp), Some(443))
    };
    // Names are lowercased; patterns match anywhere, case-sensitively.
    let curl = rule(json!({
        "attrs": {"User-Agent": "^curl/", ":method": "GET"},
        "outboundTag": "direct"
    }));
    let request = attributes(&[
        (":method", "GET"),
        (":path", "/"),
        ("user-agent", "curl/8.7"),
    ]);
    assert!(applies_to(&curl, Some(&request)));
    let lower = attributes(&[(":method", "get"), ("user-agent", "curl/8.7")]);
    assert!(!applies_to(&curl, Some(&lower)));
    // Every named attribute must be there, and a flow without attributes
    // matches no attrs at all.
    let without_agent = attributes(&[(":method", "GET")]);
    assert!(!applies_to(&curl, Some(&without_agent)));
    assert!(!applies_to(&curl, None));

    // An empty or `null` pattern only needs the attribute to be there.
    let present = rule(json!({"attrs": {"cookie": null, "x-a": ""}, "outboundTag": "direct"}));
    assert!(applies_to(
        &present,
        Some(&attributes(&[("cookie", ""), ("x-a", "1")]))
    ));
    assert!(!applies_to(&present, Some(&attributes(&[("cookie", "")]))));
    // A later attribute replaces an earlier one of the same name.
    let replaced = attributes(&[("Host", "a.example"), ("host", "b.example")]);
    let host = rule(json!({"attrs": {"host": "^b"}, "outboundTag": "direct"}));
    assert!(applies_to(&host, Some(&replaced)));
}

#[test]
fn attrs_read_as_xray_core_reads_them() {
    // `null` and `{}` set no condition, so the rule needs another.
    for attrs in [json!(null), json!({})] {
        assert_eq!(
            rejection(json!({"attrs": attrs, "outboundTag": "direct"})),
            "$.routing.rules[0]"
        );
        assert!(
            rule(json!({"attrs": attrs, "port": 80, "outboundTag": "direct"}))
                .attributes
                .is_none()
        );
    }
    for (attrs, path) in [
        (json!([]), "$.routing.rules[0].attrs"),
        (json!("x"), "$.routing.rules[0].attrs"),
        (json!({"a": 5}), "$.routing.rules[0].attrs.a"),
        (json!({"a": ["x"]}), "$.routing.rules[0].attrs.a"),
        // Xray-core panics on a pattern that does not compile.
        (json!({"a": "("}), "$.routing.rules[0].attrs.a"),
    ] {
        assert_eq!(
            rejection(json!({"attrs": attrs, "outboundTag": "direct"})),
            path,
            "{attrs}"
        );
    }
}

#[test]
fn names_lowercase_as_go_lowercases_them() {
    assert_eq!(go_lowercase("X-Forwarded-For"), "x-forwarded-for");
    assert_eq!(go_lowercase("user-agent"), "user-agent");
    // Each character on its own, unlike Rust's `str::to_lowercase`.
    assert_eq!(go_lowercase("İSTANBUL"), "istanbul");
    assert_eq!(go_lowercase("ΟΔΟΣ"), "οδοσ");
}
