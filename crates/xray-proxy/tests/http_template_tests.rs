//! Custom HTTP outbound header values as Xray-core fills them in.

use std::net::SocketAddr;

use xray_proxy::outbound::HttpHeaderTemplate;
use xray_routing::{Network, Target, TargetAddr};

fn render(text: &str, source: Option<&str>, target: Target) -> String {
    HttpHeaderTemplate::parse(text)
        .unwrap_or_else(|error| panic!("{text}: {error}"))
        .render(
            source.map(|source| source.parse::<SocketAddr>().unwrap()),
            &target,
        )
}

fn tcp(addr: TargetAddr, port: u16) -> Target {
    Target::new(addr, port, Network::Tcp)
}

#[test]
fn fields_render_as_xray_core_prints_them() {
    let v4 = tcp(TargetAddr::Ip("192.0.2.7".parse().unwrap()), 443);
    let v6 = tcp(TargetAddr::Ip("2001:db8::1".parse().unwrap()), 8443);
    let mapped = tcp(TargetAddr::Ip("::ffff:192.0.2.7".parse().unwrap()), 80);
    let domain = tcp(TargetAddr::Domain("example.test".to_owned()), 443);
    let source = Some("127.0.0.1:54321");
    for (text, target, expected) in [
        ("static value", v4.clone(), "static value"),
        ("{{.Target}}", v4.clone(), "tcp:192.0.2.7:443"),
        ("{{.Target}}", v6.clone(), "tcp:[2001:db8::1]:8443"),
        ("{{.Target}}", mapped.clone(), "tcp:192.0.2.7:80"),
        ("{{.Target}}", domain.clone(), "tcp:example.test:443"),
        ("{{.Target.Address}}", v6.clone(), "[2001:db8::1]"),
        ("{{.Target.Port}}", v6.clone(), "8443"),
        ("{{.Target.Network}}", v4.clone(), "TCP"),
        ("{{.Target.NetAddr}}", domain.clone(), "example.test:443"),
        ("{{ .Source }}", v4.clone(), "tcp:127.0.0.1:54321"),
        (
            "to {{.Target.Address}} from {{.Source.Address}}",
            domain.clone(),
            "to example.test from 127.0.0.1",
        ),
        ("{{/* a comment */}}x", v4.clone(), "x"),
        ("{{/* a }} in it */}}x", v4.clone(), "x"),
        // Trim markers take the white space beside them.
        ("a  {{- .Target.Port -}}  b", v4.clone(), "a443b"),
        ("a {{-.Target.Port}}", v4.clone(), "a {{-.Target.Port}}"),
        // Go's Header.Write turns line breaks into spaces and trims.
        ("  one\r\ntwo  ", v4.clone(), "one  two"),
        ("lone }} stays", v4.clone(), "lone }} stays"),
    ] {
        if text == "a {{-.Target.Port}}" {
            assert!(HttpHeaderTemplate::parse(text).is_err());
            continue;
        }
        assert_eq!(render(text, source, target), expected, "{text}");
    }
    // Without an inbound, the source is Xray-core's empty one.
    assert_eq!(render("{{.Source}}", None, v4.clone()), "tcp:0.0.0.0:0");
    assert_eq!(
        render("{{.Source}}", Some("[::1]:5000"), v4.clone()),
        "tcp:[::1]:5000"
    );
    assert_eq!(
        render("{{.Source.Address}}", Some("[::ffff:127.0.0.1]:5000"), v4),
        "127.0.0.1"
    );
}

#[test]
fn only_the_source_needs_the_client() {
    assert!(!HttpHeaderTemplate::parse("{{.Target}} x")
        .unwrap()
        .uses_source());
    assert!(HttpHeaderTemplate::parse("{{.Source.Port}}")
        .unwrap()
        .uses_source());
}

#[test]
fn other_actions_are_refused() {
    for text in [
        "{{.}}",
        "{{.Dest}}",
        "{{.Target.Domain}}",
        "{{.Target.Address.IP}}",
        "{{printf \"%s\" .Target}}",
        "{{.Target | len}}",
        "{{if .Target}}x{{end}}",
        "{{$x := .Target}}",
        "{{\"literal\"}}",
        "{{.Target",
        "{{/* open",
        "{{-3}}",
    ] {
        assert!(HttpHeaderTemplate::parse(text).is_err(), "{text}");
    }
}

#[test]
fn the_raw_value_is_what_http2_sends() {
    let target = tcp(TargetAddr::Domain("example.com".into()), 443);
    let template = HttpHeaderTemplate::parse("  one\r\n{{.Target.Port}}\t").unwrap();
    // Go's HTTP/2 client sends the template's output as it is; only
    // HTTP/1.1's Header.Write turns line breaks into spaces and trims.
    assert_eq!(template.render_raw(None, &target), "  one\r\n443\t");
    assert_eq!(template.render(None, &target), "one  443");
}
