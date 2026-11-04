//! `sockopt.domainStrategy`, and the freedom and outbound spellings that
//! Xray-core v26.10.31 migrates into it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, AddressFamilies, DiagnosticSeverity, DomainStrategy, ParsedConfig,
};

const VLESS: &str = r#"{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com"}}}"#;

fn profile(outbound: Value) -> String {
    json!({ "outbounds": [outbound] }).to_string()
}

fn parse(outbound: Value) -> ParsedConfig {
    parse_xray_json(&profile(outbound.clone()))
        .unwrap_or_else(|error| panic!("{outbound} should parse: {:?}", error.diagnostics))
}

fn strategy(outbound: Value) -> DomainStrategy {
    parse(outbound).config.outbounds[0]
        .stream
        .socket_options
        .as_ref()
        .map_or(DomainStrategy::AsIs, |options| options.domain_strategy)
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

fn rejection(outbounds: Value) -> (String, String) {
    let raw = json!({ "outbounds": outbounds }).to_string();
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

fn freedom_sockopt(name: Value) -> Value {
    json!({"protocol":"freedom","streamSettings":{"sockopt":{"domainStrategy":name}}})
}

#[test]
fn every_xray_name_parses_ignoring_case() {
    let names = [
        ("AsIs", DomainStrategy::AsIs),
        ("UseIP", DomainStrategy::UseIp),
        ("UseIPv4", DomainStrategy::UseIpv4),
        ("UseIPv6", DomainStrategy::UseIpv6),
        ("UseIPv4v6", DomainStrategy::UseIpv4v6),
        ("UseIPv6v4", DomainStrategy::UseIpv6v4),
        ("ForceIP", DomainStrategy::ForceIp),
        ("ForceIPv4", DomainStrategy::ForceIpv4),
        ("ForceIPv6", DomainStrategy::ForceIpv6),
        ("ForceIPv4v6", DomainStrategy::ForceIpv4v6),
        ("ForceIPv6v4", DomainStrategy::ForceIpv6v4),
    ];
    for (name, expected) in names {
        assert_eq!(strategy(freedom_sockopt(json!(name))), expected, "{name}");
        let shouted = name.to_ascii_uppercase();
        assert_eq!(strategy(freedom_sockopt(json!(shouted))), expected);
        let whispered = name.to_ascii_lowercase();
        assert_eq!(strategy(freedom_sockopt(json!(whispered))), expected);
    }
    // Go decodes the field into a string, so null and "" are AsIs.
    assert_eq!(strategy(freedom_sockopt(Value::Null)), DomainStrategy::AsIs);
    assert_eq!(strategy(freedom_sockopt(json!(""))), DomainStrategy::AsIs);
}

#[test]
fn strategies_follow_xrays_table() {
    use AddressFamilies::{Both, Ipv4, Ipv6};
    // Xray-core's `strategy` table: whether it resolves, forces, prefers and falls back.
    let table = [
        (DomainStrategy::AsIs, false, false, Both, None),
        (DomainStrategy::UseIp, true, false, Both, None),
        (DomainStrategy::UseIpv4, true, false, Ipv4, None),
        (DomainStrategy::UseIpv6, true, false, Ipv6, None),
        (DomainStrategy::UseIpv4v6, true, false, Ipv4, Some(Ipv6)),
        (DomainStrategy::UseIpv6v4, true, false, Ipv6, Some(Ipv4)),
        (DomainStrategy::ForceIp, true, true, Both, None),
        (DomainStrategy::ForceIpv4, true, true, Ipv4, None),
        (DomainStrategy::ForceIpv6, true, true, Ipv6, None),
        (DomainStrategy::ForceIpv4v6, true, true, Ipv4, Some(Ipv6)),
        (DomainStrategy::ForceIpv6v4, true, true, Ipv6, Some(Ipv4)),
    ];
    for (strategy, resolves, forces, preferred, fallback) in table {
        assert_eq!(strategy.has_strategy(), resolves, "{strategy:?}");
        assert_eq!(strategy.force_ip(), forces, "{strategy:?}");
        assert_eq!(strategy.preferred(), preferred, "{strategy:?}");
        assert_eq!(strategy.fallback(), fallback, "{strategy:?}");
    }
}

#[test]
fn udp_flows_prefer_the_family_of_their_original_address() {
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert_eq!(
        DomainStrategy::UseIp.for_original_ip(v4),
        DomainStrategy::UseIpv4v6
    );
    assert_eq!(
        DomainStrategy::UseIp.for_original_ip(v6),
        DomainStrategy::UseIpv6v4
    );
    assert_eq!(
        DomainStrategy::ForceIp.for_original_ip(v4),
        DomainStrategy::ForceIpv4v6
    );
    assert_eq!(
        DomainStrategy::ForceIp.for_original_ip(v6),
        DomainStrategy::ForceIpv6v4
    );
    // Strategies that name a family keep it, as GetDynamicStrategy does.
    for strategy in [
        DomainStrategy::AsIs,
        DomainStrategy::UseIpv4,
        DomainStrategy::UseIpv6,
        DomainStrategy::UseIpv6v4,
        DomainStrategy::ForceIpv6,
        DomainStrategy::ForceIpv4v6,
    ] {
        assert_eq!(strategy.for_original_ip(v4), strategy);
        assert_eq!(strategy.for_original_ip(v6), strategy);
    }
}

#[test]
fn unknown_and_mistyped_strategies_are_rejected() {
    let (path, message) = rejection(json!([freedom_sockopt(json!("UseIPv5"))]));
    assert_eq!(path, "$.outbounds[0].streamSettings.sockopt.domainStrategy");
    assert!(message.contains("unsupported domain strategy `UseIPv5`"));
    let (path, _) = rejection(json!([freedom_sockopt(json!(4))]));
    assert_eq!(path, "$.outbounds[0].streamSettings.sockopt.domainStrategy");

    let (path, _) = rejection(json!([
        {"protocol":"freedom","settings":{"domainStrategy":"UseIP4"}}
    ]));
    assert_eq!(path, "$.outbounds[0].settings.domainStrategy");
    let (path, _) = rejection(json!([
        {"protocol":"freedom","settings":{"domainStrategy":true}}
    ]));
    assert_eq!(path, "$.outbounds[0].settings.domainStrategy");
    let (path, _) = rejection(json!([
        {"protocol":"freedom","targetStrategy":"PreferIPv4"}
    ]));
    assert_eq!(path, "$.outbounds[0].targetStrategy");
}

#[test]
fn freedom_settings_migrate_into_sockopt_with_xrays_notice() {
    let parsed = parse(json!({"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}));
    let options = parsed.config.outbounds[0]
        .stream
        .socket_options
        .as_ref()
        .expect("the strategy lands in sockopt");
    assert_eq!(options.domain_strategy, DomainStrategy::UseIpv4);
    assert_eq!(options.happy_eyeballs, None);
    let notices = warnings(&parsed);
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0].0, "$.outbounds[0].settings.domainStrategy");
    assert!(notices[0].1.contains("deprecated"));

    // AsIs migrates nothing and draws no notice.
    let parsed = parse(json!({"protocol":"freedom","settings":{"domainStrategy":"AsIs"}}));
    assert_eq!(parsed.config.outbounds[0].stream.socket_options, None);
    assert!(warnings(&parsed).is_empty());
}

#[test]
fn freedom_target_strategy_wins_over_its_domain_strategy() {
    // Go reads `targetStrategy` first and never looks at the other name.
    assert_eq!(
        strategy(json!({"protocol":"freedom",
            "settings":{"targetStrategy":"ForceIPv6","domainStrategy":"not a strategy"}})),
        DomainStrategy::ForceIpv6
    );
    assert_eq!(
        strategy(json!({"protocol":"freedom",
            "settings":{"targetStrategy":"","domainStrategy":"UseIPv6v4"}})),
        DomainStrategy::UseIpv6v4
    );
    assert_eq!(
        strategy(json!({"protocol":"freedom",
            "settings":{"targetStrategy":null,"domainStrategy":"UseIP"}})),
        DomainStrategy::UseIp
    );
}

#[test]
fn migrated_strategies_replace_the_sockopt_value() {
    let happy = json!({"tryDelayMs":250});
    let parsed = parse(json!({"protocol":"freedom",
        "settings":{"domainStrategy":"ForceIPv4"},
        "streamSettings":{"sockopt":{"domainStrategy":"UseIPv6","happyEyeballs":happy}}}));
    let options = parsed.config.outbounds[0]
        .stream
        .socket_options
        .as_ref()
        .unwrap();
    assert_eq!(options.domain_strategy, DomainStrategy::ForceIpv4);
    assert_eq!(
        options.happy_eyeballs.map(|settings| settings.try_delay_ms),
        Some(250)
    );

    // An AsIs freedom value leaves sockopt alone.
    assert_eq!(
        strategy(
            json!({"protocol":"freedom","settings":{"domainStrategy":"AsIs"},
            "streamSettings":{"sockopt":{"domainStrategy":"UseIPv6"}}})
        ),
        DomainStrategy::UseIpv6
    );
}

#[test]
fn an_outbound_target_strategy_wins_on_freedom() {
    let parsed = parse(json!({"protocol":"freedom","targetStrategy":"UseIPv4v6",
        "settings":{"domainStrategy":"ForceIPv6"},
        "streamSettings":{"sockopt":{"domainStrategy":"UseIP"}}}));
    let options = parsed.config.outbounds[0]
        .stream
        .socket_options
        .as_ref()
        .unwrap();
    assert_eq!(options.domain_strategy, DomainStrategy::UseIpv4v6);
    // Xray-core prints only the targetStrategy notice in this case.
    let notices = warnings(&parsed);
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0].0, "$.outbounds[0].targetStrategy");

    assert_eq!(
        strategy(json!({"protocol":"direct","targetStrategy":"forceip"})),
        DomainStrategy::ForceIp
    );
    assert_eq!(
        strategy(json!({"protocol":"freedom","targetStrategy":"AsIs",
            "settings":{"domainStrategy":"UseIPv6"}})),
        DomainStrategy::UseIpv6
    );
}

#[test]
fn other_outbounds_accept_only_as_is() {
    let vless: Value = serde_json::from_str(VLESS).unwrap();
    for name in ["AsIs", "asis", ""] {
        let mut outbound = vless.clone();
        outbound["targetStrategy"] = json!(name);
        outbound["streamSettings"]["sockopt"] = json!({"domainStrategy": name});
        parse(outbound);
    }

    let mut outbound = vless.clone();
    outbound["streamSettings"]["sockopt"] = json!({"domainStrategy":"UseIPv4"});
    let (path, message) = rejection(json!([outbound]));
    assert_eq!(path, "$.outbounds[0].streamSettings.sockopt.domainStrategy");
    assert!(message.contains("only on freedom"));

    let mut outbound = vless.clone();
    outbound["targetStrategy"] = json!("UseIP");
    let (path, message) = rejection(json!([outbound]));
    assert_eq!(path, "$.outbounds[0].targetStrategy");
    assert!(message.contains("only on freedom"));
}

#[test]
fn a_fragment_dialer_with_a_domain_strategy_is_not_inlined() {
    let mut vless: Value = serde_json::from_str(VLESS).unwrap();
    vless["streamSettings"]["sockopt"] = json!({"dialerProxy":"fragment"});
    let fragment = json!({"protocol":"freedom","tag":"fragment","settings":{
        "domainStrategy":"UseIPv4",
        "fragment":{"packets":"tlshello","length":"100-200","interval":"1-2"}}});
    let (path, message) = rejection(json!([vless, fragment]));
    assert_eq!(path, "$.outbounds[0].streamSettings.sockopt.dialerProxy");
    assert!(message.contains("domain strategy"), "{message}");

    // AsIs keeps the dedicated handler inlinable.
    let mut fragment = fragment;
    fragment["settings"]["domainStrategy"] = json!("AsIs");
    let raw = json!({ "outbounds": [vless, fragment] }).to_string();
    let parsed = parse_xray_json(&raw).expect("AsIs fragment handler inlines");
    assert!(parsed.config.outbounds[0].stream.tcp_fragment.is_some());
}
