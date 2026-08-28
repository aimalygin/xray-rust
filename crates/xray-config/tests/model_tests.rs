use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use xray_config::{
    CoreConfig, Diagnostic, DiagnosticSeverity, DnsConfig, DnsIpFilter, DnsOutboundRule,
    DnsOutboundRuleAction, DnsOutboundSettings, DnsQTypeRange, DnsQueryStrategy, DomainMatcher,
    HappyEyeballsSettings, InboundConfig, InboundProtocol, IpCidr, IpMatcher, Network,
    OutboundConfig, OutboundProtocol, OutboundSettings, RealitySettings, RealityShortId,
    RegexMatcher, RoutingConfig, RoutingPortRange, RoutingRule, SocketOptions, StreamSecurity,
    StreamSettings, StreamTransport, TargetAddr, VlessOutboundSettings, VlessUser,
};

#[test]
fn diagnostic_carries_json_path() {
    let diagnostic = Diagnostic::error("$.outbounds[0].settings", "unsupported protocol field");
    assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
    assert_eq!(diagnostic.path.as_deref(), Some("$.outbounds[0].settings"));
    assert_eq!(diagnostic.message, "unsupported protocol field");
}

#[test]
fn normalized_model_can_represent_vless_reality_vision() {
    let public_key = [1; 32];
    let short_id = RealityShortId::try_from_slice(&[2, 3, 4, 5]).unwrap();

    let outbound = OutboundConfig {
        tag: Some("proxy".to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::Reality(RealitySettings {
                server_name: "www.example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key,
                short_id,
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            }),
            quic_params: None,
            socket_options: None,
        },
        settings: OutboundSettings::Vless(VlessOutboundSettings {
            server: TargetAddr::Domain("server.example".to_owned()),
            port: 443,
            users: vec![VlessUser {
                id: "00010203-0405-0607-0809-0a0b0c0d0e0f".parse().unwrap(),
                encryption: "none".to_owned(),
                flow: Some("xtls-rprx-vision".to_owned()),
                level: 0,
            }],
        }),
    };

    let inbound = InboundConfig {
        tag: Some("socks".to_owned()),
        protocol: InboundProtocol::Socks,
        listen: "127.0.0.1".to_owned(),
        port: 1080,
        allow_unauthenticated_lan: false,
        sniffing: None,
        user_level: None,
    };

    let config = CoreConfig {
        inbounds: vec![inbound],
        outbounds: vec![outbound],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    };

    let expected = CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 1080,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![OutboundConfig {
            tag: Some("proxy".to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Reality(RealitySettings {
                    server_name: "www.example.com".to_owned(),
                    fingerprint: "chrome".to_owned(),
                    public_key: [1; 32],
                    short_id: RealityShortId::try_from_slice(&[2, 3, 4, 5]).unwrap(),
                    spider_x: "/".to_owned(),
                    mldsa65_verify: None,
                }),
                quic_params: None,
                socket_options: None,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Domain("server.example".to_owned()),
                port: 443,
                users: vec![VlessUser {
                    id: "00010203-0405-0607-0809-0a0b0c0d0e0f".parse().unwrap(),
                    encryption: "none".to_owned(),
                    flow: Some("xtls-rprx-vision".to_owned()),
                    level: 0,
                }],
            }),
        }],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    };

    assert_eq!(config, expected);
    assert_eq!(
        config.outbounds[0].settings.protocol(),
        OutboundProtocol::Vless
    );

    let OutboundSettings::Vless(settings) = &config.outbounds[0].settings else {
        panic!("expected vless outbound");
    };
    assert_eq!(
        settings.server,
        TargetAddr::Domain("server.example".to_owned())
    );

    let StreamSecurity::Reality(reality) = &config.outbounds[0].stream.security else {
        panic!("expected Reality stream security");
    };
    assert_eq!(reality.public_key, [1; 32]);
    assert_eq!(reality.short_id.as_slice(), &[2, 3, 4, 5]);
}

#[test]
fn normalized_model_can_represent_freedom_outbound() {
    let outbound = OutboundConfig {
        tag: Some("direct".to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::None,
            quic_params: None,
            socket_options: None,
        },
        settings: OutboundSettings::Freedom,
    };

    assert_eq!(outbound.settings.protocol(), OutboundProtocol::Freedom);
}

#[test]
fn dns_outbound_rules_use_first_match_and_xray_defaults() {
    let settings = DnsOutboundSettings {
        rules: vec![
            DnsOutboundRule {
                action: DnsOutboundRuleAction::Direct,
                r_code: 0,
                qtype_ranges: vec![DnsQTypeRange::single(1)],
                domain_matchers: vec![DomainMatcher::Suffix("internal.example".to_owned())],
            },
            DnsOutboundRule {
                action: DnsOutboundRuleAction::Drop,
                r_code: 0,
                qtype_ranges: vec![DnsQTypeRange::single(1)],
                domain_matchers: Vec::new(),
            },
        ],
        ..Default::default()
    };

    assert_eq!(
        settings.action_for(1, "api.internal.example."),
        DnsOutboundRuleAction::Direct
    );
    assert_eq!(
        settings.action_for(1, "public.example"),
        DnsOutboundRuleAction::Drop
    );
    assert_eq!(
        settings.action_for(28, "public.example"),
        DnsOutboundRuleAction::Hijack
    );
    assert_eq!(
        settings.action_for(65, "public.example"),
        DnsOutboundRuleAction::Return
    );

    let regexp_settings = DnsOutboundSettings {
        rules: vec![DnsOutboundRule {
            action: DnsOutboundRuleAction::Direct,
            r_code: 0,
            qtype_ranges: vec![DnsQTypeRange::single(1)],
            domain_matchers: vec![DomainMatcher::Regex(
                RegexMatcher::new(r"^api\.internal\.example$").expect("valid domain regexp"),
            )],
        }],
        ..Default::default()
    };
    assert_eq!(
        regexp_settings.action_for(1, "API.INTERNAL.EXAMPLE."),
        DnsOutboundRuleAction::Direct
    );
}

#[test]
fn dns_qtype_and_routing_port_ranges_enforce_ordered_bounds() {
    assert!(DnsQTypeRange::new(28, 1).is_err());
    assert!(RoutingPortRange::new(54, 53).is_err());
    assert!(DnsQTypeRange::new(23, 24)
        .expect("ordered qtype range")
        .contains(24));
    assert!(RoutingPortRange::new(53, 53)
        .expect("ordered port range")
        .contains(53));
}

#[test]
fn routing_network_and_port_selectors_fail_closed_without_target_metadata() {
    let rule = RoutingRule {
        inbound_tags: Vec::new(),
        networks: vec![Network::Udp],
        port_ranges: vec![RoutingPortRange::single(53)],
        domain_matchers: Vec::new(),
        ip_matchers: Vec::new(),
        outbound_tag: "dns-out".to_owned(),
    };

    assert!(!rule.matches(None, None, None));
    assert!(rule.matches_target(None, None, None, Some(Network::Udp), Some(53)));
    assert!(!rule.matches_target(None, None, None, Some(Network::Tcp), Some(53)));
    assert!(!rule.matches_target(None, None, None, Some(Network::Udp), Some(853)));
}

#[test]
fn normalized_model_uses_xray_happy_eyeballs_defaults() {
    let stream = StreamSettings {
        network: Network::Tcp,
        transport: StreamTransport::Raw,
        security: StreamSecurity::None,
        quic_params: None,
        socket_options: Some(SocketOptions {
            happy_eyeballs: Some(HappyEyeballsSettings::default()),
        }),
    };

    assert_eq!(
        stream
            .socket_options
            .and_then(|options| options.happy_eyeballs),
        Some(HappyEyeballsSettings {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay_ms: 0,
            max_concurrent_try: 4,
        })
    );
}

#[test]
fn normalized_model_uses_xray_dns_query_strategy_default() {
    assert_eq!(DnsConfig::default().query_strategy, DnsQueryStrategy::UseIp);
}

#[test]
fn normalized_model_can_represent_inbound_tag_routing_rule() {
    let routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: vec!["socks-in".to_owned()],
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: "direct".to_owned(),
        }],
        ..Default::default()
    };

    assert!(routing.rules[0].matches_inbound(Some("socks-in")));
    assert!(!routing.rules[0].matches_inbound(Some("http-in")));
    assert!(!routing.rules[0].matches_inbound(None));
}

#[test]
fn normalized_model_can_represent_domain_routing_rule() {
    let routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: vec![
                DomainMatcher::Keyword("ample".to_owned()),
                DomainMatcher::Suffix("example.com".to_owned()),
                DomainMatcher::Full("exact.test".to_owned()),
                DomainMatcher::Regex(RegexMatcher::new("^re-[a-z]+\\.test$").unwrap()),
            ],
            ip_matchers: Vec::new(),
            outbound_tag: "proxy".to_owned(),
        }],
        ..Default::default()
    };

    assert!(routing.rules[0].matches_domain(Some("api.example.com")));
    assert!(routing.rules[0].matches_domain(Some("API.EXAMPLE.COM")));
    assert!(routing.rules[0].matches_domain(Some("example.com")));
    assert!(routing.rules[0].matches_domain(Some("sample.test")));
    assert!(routing.rules[0].matches_domain(Some("EXACT.test")));
    assert!(routing.rules[0].matches_domain(Some("RE-api.test")));
    assert!(!routing.rules[0].matches_domain(Some("notexact.test")));
    assert!(!routing.rules[0].matches_domain(None));
}

#[test]
fn normalized_model_can_represent_ip_routing_rule() {
    let routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: vec![
                IpMatcher::Cidr(IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap()),
                IpMatcher::Private,
            ],
            outbound_tag: "direct".to_owned(),
        }],
        ..Default::default()
    };

    assert!(routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))));
    assert!(routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))));
    assert!(routing.rules[0].matches_ip(Some(&IpAddr::V6(Ipv6Addr::LOCALHOST))));
    assert!(!routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
    assert!(!routing.rules[0].matches_ip(None));
}

#[test]
fn normalized_model_applies_inverse_ip_matchers_as_a_conjunction() {
    let routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: vec![
                IpMatcher::Not(Box::new(IpMatcher::Cidr(
                    IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap(),
                ))),
                IpMatcher::Not(Box::new(IpMatcher::Cidr(
                    IpCidr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16).unwrap(),
                ))),
                IpMatcher::Cidr(
                    IpCidr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24).unwrap(),
                ),
            ],
            outbound_tag: "direct".to_owned(),
        }],
        ..Default::default()
    };

    assert!(routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
    assert!(routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))));
    assert!(!routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))));
    assert!(!routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))));
}

#[test]
fn dns_ip_filter_keeps_custom_and_geoip_inverse_unions_separate() {
    let filter = DnsIpFilter {
        custom_matchers: vec![IpMatcher::Not(Box::new(IpMatcher::Cidr(
            IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap(),
        )))],
        geoip_matchers: vec![IpMatcher::Not(Box::new(IpMatcher::Cidr(
            IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 16).unwrap(),
        )))],
        soft: false,
    };

    assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))));
    assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(10, 42, 1, 1))));
    assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
}

#[test]
fn dns_ip_filter_scopes_inverse_matchers_by_address_family() {
    let filter = DnsIpFilter {
        custom_matchers: vec![IpMatcher::Not(Box::new(IpMatcher::Cidr(
            IpCidr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap(),
        )))],
        geoip_matchers: Vec::new(),
        soft: false,
    };

    assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    assert!(!filter.matches(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn ip_cidr_canonicalizes_ipv4_mapped_ipv6_addresses() {
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
    let cidr = IpCidr::new(mapped, 24).unwrap();

    assert_eq!(cidr.network(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(cidr.prefix(), 24);
    assert!(DnsIpFilter {
        custom_matchers: vec![IpMatcher::Cidr(cidr)],
        geoip_matchers: Vec::new(),
        soft: false,
    }
    .matches(&mapped));
    assert_eq!(
        IpCidr::new(mapped, 120).unwrap_err(),
        xray_config::ConfigModelError::InvalidCidrPrefix {
            prefix: 120,
            max: 32,
        }
    );
    assert_eq!(IpCidr::full(mapped).prefix(), 32);
}

#[test]
fn xray_plaintext_server_ip_exemptions_match_v26_7_28_ranges() {
    for address in [
        "0.42.0.1",
        "10.42.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.31.255.254",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "febf::1",
        "ff02::1",
        "::ffff:192.0.2.1",
    ] {
        let server = TargetAddr::Ip(address.parse().unwrap());
        assert!(
            server.is_xray_plaintext_server_exempt(),
            "{address} should be exempt"
        );
    }

    for address in [
        "1.1.1.1",
        "100.128.0.1",
        "169.253.255.255",
        "172.32.0.1",
        "192.0.1.1",
        "192.0.3.1",
        "192.88.100.1",
        "198.17.255.255",
        "198.20.0.1",
        "203.0.114.1",
        "223.255.255.255",
        "::2",
        "2001:db8::1",
        "fe7f::1",
        "fec0::1",
    ] {
        let server = TargetAddr::Ip(address.parse().unwrap());
        assert!(
            !server.is_xray_plaintext_server_exempt(),
            "{address} should require transport security"
        );
    }
}

#[test]
fn xray_plaintext_server_domain_exemptions_normalize_case_and_one_trailing_dot() {
    for domain in [
        "lan",
        "printer.lan",
        "localdomain",
        "service.example",
        "invalid",
        "localhost",
        "host.test",
        "host.local",
        "resolver.home.arpa",
        "service.internal",
        "router",
        "a",
        "a-1",
        "PRINTER.LAN.",
        "ROUTER.",
    ] {
        let server = TargetAddr::Domain(domain.to_owned());
        assert!(
            server.is_xray_plaintext_server_exempt(),
            "{domain:?} should be exempt"
        );
    }

    for domain in [
        "example.com",
        "lan.example.com",
        "public.invalid.example.com",
        "123",
        "-router",
        "router-",
        "under_score",
        "router..",
    ] {
        let server = TargetAddr::Domain(domain.to_owned());
        assert!(
            !server.is_xray_plaintext_server_exempt(),
            "{domain:?} should require transport security"
        );
    }

    let max_dotless = TargetAddr::Domain(format!("a{}z", "-".repeat(61)));
    assert!(max_dotless.is_xray_plaintext_server_exempt());
    let overlong_dotless = TargetAddr::Domain("a".repeat(64));
    assert!(!overlong_dotless.is_xray_plaintext_server_exempt());
}

#[test]
fn reality_short_id_rejects_more_than_eight_bytes() {
    let error = RealityShortId::try_from_slice(&[0; 9]).unwrap_err();

    assert_eq!(error.to_string(), "reality short id cannot exceed 8 bytes");
}
