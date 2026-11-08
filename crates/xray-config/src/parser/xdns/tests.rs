use super::*;

/// Every domain Xray-core's `NewDomain` was asked about
/// (`tools/xdns-oracle`): what it refuses is refused, and what it accepts
/// is accepted unless its client then fails to pack it.
#[test]
fn domains_check_as_xray_checks_them() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/xdns/vectors.json"
    ))
    .unwrap();
    for case in vectors["domains"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let got = check_domain(
            name,
            case["lenLimit"].as_i64().unwrap() as i32,
            case["labelLimit"].as_i64().unwrap() as i32,
            case["edns0"].as_i64().unwrap() as u16,
        );
        let accepted = case.get("error").is_none() && case["packs"].as_bool().unwrap();
        assert_eq!(got.is_ok(), accepted, "{name:?}: {got:?} vs {case}");
    }
}

#[test]
fn punycode_decodes_as_go_does() {
    assert_eq!(punycode_decode("e1aybc").as_deref(), Some("тест"));
    assert_eq!(punycode_decode("ls8h").as_deref(), Some("💩"));
    assert_eq!(punycode_decode("bcher-kva").as_deref(), Some("bücher"));
    assert_eq!(punycode_decode("abc-").as_deref(), Some("abc"));
    assert_eq!(punycode_decode("").as_deref(), Some(""));
    assert_eq!(punycode_decode("-"), None);
    assert_eq!(punycode_decode("zz9"), None);
    assert!(idna_to_ascii("xn--abc-.example").is_err());
    assert!(idna_to_ascii("XN--zz9.example").is_ok());
    assert!(idna_to_ascii("a\u{FFFD}b.example").is_err());
}

#[test]
fn resolver_addresses_read_as_xray_reads_them() {
    let udp = |addr: &str| XdnsResolver {
        protocol: XdnsProtocol::Udp,
        address: addr.parse().unwrap(),
    };
    let tcp = |addr: &str| XdnsResolver {
        protocol: XdnsProtocol::Tcp,
        address: addr.parse().unwrap(),
    };
    for (input, expected) in [
        ("1.1.1.1", udp("1.1.1.1:53")),
        ("1.1.1.1:5353", udp("1.1.1.1:5353")),
        ("udp://8.8.8.8", udp("8.8.8.8:53")),
        ("UDP://8.8.8.8:0053/path?x#y", udp("8.8.8.8:53")),
        ("udp://user@8.8.8.8:54", udp("8.8.8.8:54")),
        ("tcp://9.9.9.9", tcp("9.9.9.9:53")),
        ("tcp://[2001:db8::1]:853", tcp("[2001:db8::1]:853")),
        ("udp://[2001:db8::1]", udp("[2001:db8::1]:53")),
        ("8.8.8.8:", udp("8.8.8.8:53")),
    ] {
        assert_eq!(resolver_address(input), Ok(expected), "{input}");
    }
    for input in [
        "https://dns.google/dns-query",
        "tls://1.1.1.1",
        "dns.google",
        "udp://:53",
        "udp://8.8.8.8:0",
        "udp://8.8.8.8:65536",
        "udp://8.8.8.8:+53",
        "udp://8.8.8.8:5:3",
        "2001:db8::1",
        "udp://[2001:db8::1",
        "udp://[2001:db8::1]x",
    ] {
        assert!(resolver_address(input).is_err(), "{input}");
    }
}
