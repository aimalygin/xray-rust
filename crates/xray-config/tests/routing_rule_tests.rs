//! Routing rules read as Xray-core v26.10.31 reads them.

use std::net::{IpAddr, Ipv4Addr};

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, Network, RoutingPortRange, RoutingRule, RoutingRuleTarget,
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
