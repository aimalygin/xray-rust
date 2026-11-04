//! Freedom's `redirect` and `userLevel`, read as Xray-core v26.10.31 reads
//! them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, FreedomOutboundSettings, FreedomRedirect,
    OutboundSettings, TargetAddr,
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
