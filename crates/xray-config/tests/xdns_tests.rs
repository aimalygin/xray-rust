use serde_json::{json, Value};
use xray_config::{parse_xray_json, KcpMask, XdnsDomain, XdnsProtocol, XdnsResolver};

fn config(stream: Value) -> String {
    json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"server.example","port":443,
            "users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},
        "streamSettings":stream}]})
    .to_string()
}

fn kcp(masks: Value) -> String {
    config(json!({"network":"kcp","finalmask":{"udp":masks}}))
}

fn xdns(settings: Value) -> Value {
    json!({"type":"xdns","settings":settings})
}

fn minimal() -> Value {
    json!({"domains":[{"names":["t.example.com"]}],"resolvers":[{"addrs":["1.1.1.1"]}]})
}

fn errors(text: &str) -> Vec<String> {
    parse_xray_json(text)
        .unwrap_err()
        .diagnostics
        .into_iter()
        .map(|d| d.message)
        .collect()
}

fn refused(text: &str, expected: &str) {
    let errors = errors(text);
    assert!(
        errors.iter().any(|error| error.contains(expected)),
        "{expected:?} not in {errors:?}"
    );
}

#[test]
fn settings_read_as_xray_builds_them() {
    let parsed = parse_xray_json(&kcp(json!([xdns(json!({
        "domains":[
            {"names":["t.example.com","A.Example.ORG"],"types":[1,65552],"edns0":66632},
            {"names":["x.example.net"],"lenLimit":100,"labelLimit":20,"types":null}
        ],
        "resolvers":[
            {"addrs":["1.1.1.1","8.8.8.8:5353"],"worker":0},
            {"addrs":["tcp://9.9.9.9","udp://[2001:db8::1]:53"],"worker":8}
        ],
        "extraPoll":3
    }))])))
    .unwrap();
    let mask = parsed.config.outbounds[0].stream.udp_xdns.clone().unwrap();
    let domain = |name: &str, len_limit, label_limit, types: Vec<u16>, edns0| XdnsDomain {
        name: name.into(),
        len_limit,
        label_limit,
        types,
        edns0,
    };
    // One entry per name; zero limits read as 255 and 63; sizes and types
    // keep their low 16 bits, as Go converts them.
    assert_eq!(
        mask.domains,
        [
            domain("t.example.com", 255, 63, vec![1, 16], 1096),
            domain("A.Example.ORG", 255, 63, vec![1, 16], 1096),
            domain("x.example.net", 100, 20, vec![], 0),
        ]
    );
    let resolver = |protocol, address: &str| XdnsResolver {
        protocol,
        address: address.parse().unwrap(),
    };
    assert_eq!(
        mask.resolvers,
        [
            resolver(XdnsProtocol::Udp, "1.1.1.1:53"),
            resolver(XdnsProtocol::Udp, "8.8.8.8:5353"),
            resolver(XdnsProtocol::Tcp, "9.9.9.9:53"),
            resolver(XdnsProtocol::Udp, "[2001:db8::1]:53"),
        ]
    );
    assert_eq!(mask.extra_poll, 3);
}

#[test]
fn xdns_is_the_outermost_of_mkcps_masks() {
    let legacy = json!({"type":"mkcp-legacy","settings":{"value":"seed"}});
    let parsed = parse_xray_json(&kcp(json!([legacy, xdns(minimal())]))).unwrap();
    let stream = &parsed.config.outbounds[0].stream;
    assert!(stream.udp_xdns.is_some());
    let xray_config::StreamTransport::Kcp(settings) = &stream.transport else {
        panic!("mKCP");
    };
    assert!(matches!(settings.masks[..], [KcpMask::Aes128Gcm(_)]));
    // A mask listed after it is one Xray-core dials and never uses.
    refused(
        &kcp(json!([xdns(minimal()), legacy])),
        "xdns must be the last UDP mask",
    );
}

#[test]
fn domains_are_checked_as_new_domain_checks_them() {
    for (domain, expected) in [
        (json!({"names":["a..b"]}), "empty label"),
        (
            json!({"names":["t.example.com"],"lenLimit":256}),
            "lenLimit must be 0 to 255",
        ),
        (
            json!({"names":["t.example.com"],"labelLimit":64}),
            "labelLimit must be 0 to 63",
        ),
        (
            json!({"names":["t.example.com"],"edns0":511}),
            "edns0 must be 0 or 512",
        ),
        (
            json!({"names":["t.example.com"],"lenLimit":43}),
            "under 17 bytes",
        ),
        (
            json!({"names":["t.example.com"],"lenLimit":14}),
            "shorter than the domain",
        ),
        (json!({"names":["xn--zz9.example"]}), "not valid IDNA"),
        // Go accepts these and its client panics at the first query.
        (json!({"names":["t.example.com."]}), "1 to 63 bytes"),
        (json!({"names":[""]}), "1 to 63 bytes"),
        (
            json!({"names":[format!("{}.com", "a".repeat(64))]}),
            "1 to 63 bytes",
        ),
        // Xray reads types at dial, where one it does not know fails it.
        (
            json!({"names":["t.example.com"],"types":[15]}),
            "record types",
        ),
        (
            json!({"names":["t.example.com"],"lenLimit":1.5}),
            "32-bit integer",
        ),
        (
            json!({"names":["t.example.com"],"seed":1}),
            "unsupported field `seed`",
        ),
    ] {
        let settings = json!({"domains":[domain],"resolvers":[{"addrs":["1.1.1.1"]}]});
        refused(&kcp(json!([xdns(settings)])), expected);
    }
    // Xray builds an empty list and fails every dial.
    refused(
        &kcp(json!([xdns(
            json!({"domains":[{"names":[]}],"resolvers":[{"addrs":["1.1.1.1"]}]})
        )])),
        "xdns needs a domain name",
    );
}

#[test]
fn resolvers_are_ip_addresses_over_udp_or_tcp() {
    for (resolver, expected) in [
        (json!({"addrs":["dns.google"]}), "must be an IP address"),
        (
            json!({"addrs":["https://dns.google/dns-query"]}),
            "DNS over HTTPS resolvers are not supported",
        ),
        (json!({"addrs":["tls://1.1.1.1"]}), "udp:// or tcp://"),
        (json!({"addrs":["1.1.1.1:0"]}), "port from 1 to 65535"),
        (
            json!({"addrs":["1.1.1.1"],"tlsConfig":{"serverName":"x"}}),
            "for DNS over HTTPS",
        ),
        (
            json!({"addrs":["1.1.1.1"],"worker":"many"}),
            "32-bit integer",
        ),
        (json!({"addrs":"1.1.1.1"}), "array of strings"),
    ] {
        let settings = json!({"domains":[{"names":["t.example.com"]}],"resolvers":[resolver]});
        refused(&kcp(json!([xdns(settings)])), expected);
    }
    refused(
        &kcp(json!([xdns(
            json!({"domains":[{"names":["t.example.com"]}]})
        )])),
        "xdns needs a resolver address",
    );
    for extra in [-1, 4] {
        let mut settings = minimal();
        settings["extraPoll"] = extra.into();
        refused(&kcp(json!([xdns(settings)])), "extraPoll must be 0 to 3");
    }
}

#[test]
fn carriers_and_masks_it_cannot_run_with_are_refused() {
    refused(
        &config(json!({"network":"raw","finalmask":{"udp":[xdns(minimal())]}})),
        "an xdns UDP mask requires mKCP, Hysteria or XHTTP",
    );
    let hop = json!({"type":"udphop","settings":{"mode":"intervalLocal","remotePorts":"443,8443"}});
    let hysteria = json!({"outbounds":[{"tag":"proxy","protocol":"hysteria",
        "settings":{"version":2,"address":"192.0.2.1","port":443},
        "streamSettings":{"network":"hysteria","security":"tls",
            "tlsSettings":{"serverName":"server.example","alpn":["h3"]},
            "hysteriaSettings":{"version":2,"auth":"synthetic"},
            "finalmask":{"udp":[hop, xdns(minimal())],
                "quicParams":{"disableChromeParrot":true}}}}]});
    refused(&hysteria.to_string(), "cannot be combined with udphop");
    let sudoku = json!({"type":"sudoku","settings":{"password":"secret"}});
    refused(
        &config(json!({"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"server.example","alpn":["h3"]},
            "finalmask":{"udp":[sudoku, xdns(minimal())]}})),
        "sudoku UDP mask cannot run under xdns on QUIC",
    );
    // On mKCP a small enough mtu keeps sudoku's datagrams within xdns's.
    assert!(parse_xray_json(&kcp(json!([sudoku, xdns(minimal())]))).is_ok());
    refused(&kcp(json!([xdns(minimal()), xdns(minimal())])), "one xdns");
}
