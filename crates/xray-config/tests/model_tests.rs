use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use xray_config::{
    CoreConfig, Diagnostic, DiagnosticSeverity, DomainMatcher, InboundConfig, InboundProtocol,
    IpCidr, IpMatcher, Network, OutboundConfig, OutboundProtocol, OutboundSettings,
    RealitySettings, RealityShortId, RoutingConfig, RoutingRule, StreamSecurity, StreamSettings,
    TargetAddr, VlessOutboundSettings, VlessUser,
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
            security: StreamSecurity::Reality(RealitySettings {
                server_name: "www.example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key,
                short_id,
                spider_x: "/".to_owned(),
            }),
        },
        settings: OutboundSettings::Vless(VlessOutboundSettings {
            server: TargetAddr::Domain("server.example".to_owned()),
            port: 443,
            users: vec![VlessUser {
                id: "00010203-0405-0607-0809-0a0b0c0d0e0f".parse().unwrap(),
                encryption: "none".to_owned(),
                flow: Some("xtls-rprx-vision".to_owned()),
            }],
        }),
    };

    let inbound = InboundConfig {
        tag: Some("socks".to_owned()),
        protocol: InboundProtocol::Socks,
        listen: "127.0.0.1".to_owned(),
        port: 1080,
    };

    let config = CoreConfig {
        inbounds: vec![inbound],
        outbounds: vec![outbound],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig::default(),
        dns: Default::default(),
    };

    let expected = CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 1080,
        }],
        outbounds: vec![OutboundConfig {
            tag: Some("proxy".to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                security: StreamSecurity::Reality(RealitySettings {
                    server_name: "www.example.com".to_owned(),
                    fingerprint: "chrome".to_owned(),
                    public_key: [1; 32],
                    short_id: RealityShortId::try_from_slice(&[2, 3, 4, 5]).unwrap(),
                    spider_x: "/".to_owned(),
                }),
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Domain("server.example".to_owned()),
                port: 443,
                users: vec![VlessUser {
                    id: "00010203-0405-0607-0809-0a0b0c0d0e0f".parse().unwrap(),
                    encryption: "none".to_owned(),
                    flow: Some("xtls-rprx-vision".to_owned()),
                }],
            }),
        }],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig::default(),
        dns: Default::default(),
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
            security: StreamSecurity::None,
        },
        settings: OutboundSettings::Freedom,
    };

    assert_eq!(outbound.settings.protocol(), OutboundProtocol::Freedom);
}

#[test]
fn normalized_model_can_represent_inbound_tag_routing_rule() {
    let routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: vec!["socks-in".to_owned()],
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: "direct".to_owned(),
        }],
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
            domain_matchers: vec![
                DomainMatcher::Suffix("example.com".to_owned()),
                DomainMatcher::Full("exact.test".to_owned()),
            ],
            ip_matchers: Vec::new(),
            outbound_tag: "proxy".to_owned(),
        }],
    };

    assert!(routing.rules[0].matches_domain(Some("api.example.com")));
    assert!(routing.rules[0].matches_domain(Some("example.com")));
    assert!(routing.rules[0].matches_domain(Some("EXACT.test")));
    assert!(!routing.rules[0].matches_domain(Some("notexact.test")));
    assert!(!routing.rules[0].matches_domain(None));
}

#[test]
fn normalized_model_can_represent_ip_routing_rule() {
    let routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: vec![
                IpMatcher::Cidr(IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap()),
                IpMatcher::Private,
            ],
            outbound_tag: "direct".to_owned(),
        }],
    };

    assert!(routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))));
    assert!(routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))));
    assert!(routing.rules[0].matches_ip(Some(&IpAddr::V6(Ipv6Addr::LOCALHOST))));
    assert!(!routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
    assert!(!routing.rules[0].matches_ip(None));
}

#[test]
fn reality_short_id_rejects_more_than_eight_bytes() {
    let error = RealityShortId::try_from_slice(&[0; 9]).unwrap_err();

    assert_eq!(error.to_string(), "reality short id cannot exceed 8 bytes");
}
