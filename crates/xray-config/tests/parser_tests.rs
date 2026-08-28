use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use prost::Message;
use xray_config::{
    parse_xray_json, parse_xray_json_with_geodata_dirs, DiagnosticSeverity, DnsFakeIpConfig,
    DnsHostTarget, DnsIpFilter, DnsNameServerConfig, DnsOutboundRuleAction, DnsOutboundSettings,
    DnsQueryStrategy, DnsServerConfig, DnsServerEndpoint, DnsServerTransport,
    HappyEyeballsSettings, InboundProtocol, IpCidr, Network, OutboundSettings, QuicBbrProfile,
    QuicCongestion, QuicIntervalRange, QuicParamsSettings, QuicUdpHopSettings, RealityShortId,
    RoutingDomainStrategy, SniffingDestination, StreamSecurity, StreamTransport, TargetAddr,
    XhttpMode, XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement, XhttpRange,
    XhttpSettings, XhttpUplinkDataPlacement,
};

#[test]
fn parses_vless_reality_vision_subset() {
    let raw = include_str!("../../../tests/fixtures/configs/vless_reality_vision.json");
    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(parsed.config.inbounds.len(), 2);
    assert_eq!(parsed.config.outbounds.len(), 1);
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(parsed.config.default_outbound_tag.as_deref(), Some("proxy"));
    assert_eq!(parsed.config.outbounds[0].tag.as_deref(), Some("proxy"));
    assert!(parsed.config.outbounds[0].stream.socket_options.is_none());

    let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings else {
        panic!("expected vless outbound");
    };
    assert_eq!(
        vless.server,
        TargetAddr::Domain("server.example".to_owned())
    );
    assert_eq!(vless.port, 443);
    assert_eq!(vless.users[0].flow.as_deref(), Some("xtls-rprx-vision"));

    let StreamSecurity::Reality(reality) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected reality security");
    };
    assert_eq!(reality.public_key, [1; 32]);
    assert_eq!(
        reality.short_id,
        RealityShortId::try_from_slice(&[2, 3, 4, 5]).unwrap()
    );
}

#[test]
fn parses_reality_mldsa65_verify_key() {
    let mldsa65_verify = base64url_no_padding(&[0x5a; 1952]);
    let raw = vless_raw_with_reality_settings(&format!(
        r#"
                "serverName": "server.example",
                "fingerprint": "chrome",
                "publicKey": "{}",
                "shortId": "02030405",
                "mldsa65Verify": "{mldsa65_verify}"
        "#,
        valid_public_key()
    ));

    let parsed = parse_xray_json(&raw).expect("config should parse");
    let StreamSecurity::Reality(reality) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected reality security");
    };

    assert_eq!(reality.mldsa65_verify.as_deref(), Some(&[0x5a; 1952][..]));
}

#[test]
fn rejects_invalid_reality_mldsa65_verify_length_with_path() {
    let mldsa65_verify = base64url_no_padding(&[0x5a; 1951]);
    let raw = vless_raw_with_reality_settings(&format!(
        r#"
                "serverName": "server.example",
                "fingerprint": "chrome",
                "publicKey": "{}",
                "shortId": "02030405",
                "mldsa65Verify": "{mldsa65_verify}"
        "#,
        valid_public_key()
    ));

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.mldsa65Verify",
    );
}

#[test]
fn parses_mobile_vless_reality_vision_split_routing_fixture() {
    let raw = include_str!(
        "../../../tests/fixtures/configs/mobile_vless_reality_vision_split_routing.json"
    );
    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(parsed.config.inbounds.len(), 3);
    assert_eq!(parsed.config.inbounds[0].tag.as_deref(), Some("tun-in"));
    assert_eq!(parsed.config.inbounds[0].protocol, InboundProtocol::Tun);
    assert_eq!(parsed.config.outbounds.len(), 2);
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(parsed.config.default_outbound_tag.as_deref(), Some("proxy"));
    assert_eq!(parsed.config.routing.rules.len(), 2);
    assert!(matches!(
        parsed.config.outbounds[1].settings,
        OutboundSettings::Freedom
    ));
    assert!(
        parsed.config.routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))))
    );
    assert!(parsed.config.routing.rules[0]
        .matches_ip(Some(&IpAddr::V6("fd12:3456:789a::1".parse().unwrap()))));
    assert!(parsed.config.routing.rules[1].matches_domain(Some("captive.apple.com")));
    assert!(parsed.config.routing.rules[1].matches_domain(Some("printer.lan.example")));
}

#[test]
fn parses_mobile_vless_xhttp_packet_up_legacy_extra_fixture() {
    let raw =
        include_str!("../../../tests/fixtures/configs/vless_xhttp_packet_up_legacy_extra.json");
    let parsed = parse_xray_json(raw).expect("XHTTP mobile config should parse");

    assert_eq!(parsed.config.inbounds.len(), 1);
    assert_eq!(parsed.config.inbounds[0].protocol, InboundProtocol::Tun);
    assert_eq!(parsed.config.outbounds.len(), 2);
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("edge.example"));
    assert_eq!(xhttp.path, "/");
    assert_eq!(xhttp.mode, XhttpMode::PacketUp);
    assert_eq!(
        xhttp.sc_max_each_post_bytes,
        XhttpRange {
            from: 500_000,
            to: 500_000
        }
    );
    assert_eq!(xhttp.xmux.max_connections, XhttpRange { from: 16, to: 16 });
    assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
    assert_eq!(parsed.diagnostics[0].severity, DiagnosticSeverity::Warning);
    assert!(parsed.diagnostics[0]
        .message
        .contains("scMaxConcurrentPosts"));
}

#[test]
fn rejects_apple_importer_tls_allow_insecure_fail_closed() {
    let raw = include_str!("../../../tests/fixtures/configs/vless_xhttp_tls_importer.json");
    assert_parse_error_path(
        raw,
        "$.outbounds[0].streamSettings.tlsSettings.allowInsecure",
    );
}

#[test]
fn parses_apple_importer_vless_xhttp_reality_fields_and_extra() {
    let raw = include_str!("../../../tests/fixtures/configs/vless_xhttp_reality_importer.json");
    let parsed = parse_xray_json(raw).expect("Apple XHTTP+REALITY config should parse");
    let outbound = &parsed.config.outbounds[0];

    let StreamSecurity::Reality(reality) = &outbound.stream.security else {
        panic!("expected REALITY security");
    };
    assert_eq!(reality.server_name, "reality.example");
    assert_eq!(reality.fingerprint, "chrome");
    assert_eq!(reality.public_key, [1; 32]);
    assert_eq!(reality.short_id.as_slice(), &[2, 3, 4, 5]);
    assert_eq!(reality.spider_x, "/spider");
    assert!(reality.mldsa65_verify.is_none());

    let OutboundSettings::Vless(vless) = &outbound.settings else {
        panic!("expected VLESS outbound");
    };
    assert!(vless.users[0].flow.is_none());

    let StreamTransport::Xhttp(xhttp) = &outbound.stream.transport else {
        panic!("expected XHTTP transport");
    };
    assert_eq!(xhttp.host.as_deref(), Some("front.example"));
    assert_eq!(xhttp.path, "/reality");
    assert_eq!(xhttp.mode, XhttpMode::Auto);
    assert_eq!(xhttp.x_padding_bytes, XhttpRange { from: 10, to: 20 });
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn unsupported_modern_tls_fields_fail_closed_on_apple_xhttp_shape() {
    let base: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/configs/vless_xhttp_tls_importer.json"
    ))
    .unwrap();

    for (key, value) in [
        ("echConfigList", "unsupported-ech"),
        ("disableSystemRoot", "unsupported-root-policy"),
        ("certificates", "unsupported-custom-trust"),
        ("pinnedPeerCertChainSha256", "unsupported-chain-pin"),
    ] {
        let mut candidate = base.clone();
        let tls_settings = candidate
            .pointer_mut("/outbounds/0/streamSettings/tlsSettings")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap();
        tls_settings.remove("allowInsecure");
        tls_settings.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));

        let error = match parse_xray_json(&candidate.to_string()) {
            Ok(_) => panic!("unsupported TLS field {key} must fail closed"),
            Err(error) => error,
        };
        let expected_path = format!("$.outbounds[0].streamSettings.tlsSettings.{key}");
        assert!(
            error.diagnostics.iter().any(|diagnostic| {
                diagnostic.severity == DiagnosticSeverity::Error
                    && diagnostic.path.as_deref() == Some(expected_path.as_str())
            }),
            "{key}: {:?}",
            error.diagnostics
        );
    }
}

#[test]
fn parses_tun_inbound_without_port_as_packet_boundary_inbound() {
    let raw = r#"{
        "inbounds": [
            {
              "tag": "tun-in",
              "protocol": "tun",
              "settings": { "userLevel": 0 }
            }
        ],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(parsed.config.inbounds[0].port, 0);
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn parses_the_config_the_apple_vless_url_importer_generates() {
    // Unknown keys are a hard config error, so the importer's sniffing and
    // queryStrategy blocks have to match what the parser accepts verbatim.
    let raw = r#"{
      "dns" : {
        "fakeIp" : {
          "enabled" : true,
          "ipv4Pool" : "198.19.0.0/16",
          "poolSize" : 32768,
          "ttl" : 60
        },
        "queryStrategy" : "UseIPv4"
      },
      "inbounds" : [
        {
          "listen" : "127.0.0.1",
          "port" : 0,
          "protocol" : "tun",
          "settings" : {},
          "sniffing" : {
            "destOverride" : ["http", "tls", "quic"],
            "enabled" : true,
            "metadataOnly" : false
          },
          "tag" : "tun-in"
        }
      ],
      "outbounds" : [
        {
          "protocol" : "vless",
          "settings" : {
            "vnext" : [
              {
                "address" : "203.0.113.7",
                "port" : 443,
                "users" : [
                  {
                    "encryption" : "none",
                    "flow" : "xtls-rprx-vision",
                    "id" : "49c1a053-d257-466d-a900-048ff5173866"
                  }
                ]
              }
            ]
          },
          "streamSettings" : {
            "network" : "tcp",
            "realitySettings" : {
              "fingerprint" : "chrome",
              "publicKey" : "3jNx5A3WTFKhvCj3IPljaxbcBjCxhH2dVCNobKv_X1c",
              "serverName" : "example.com",
              "shortId" : "1c5694e878",
              "spiderX" : ""
            },
            "security" : "reality"
          },
          "tag" : "proxy"
        },
        {
          "protocol" : "freedom",
          "settings" : {},
          "tag" : "direct"
        }
      ],
      "routing" : {
        "domainStrategy" : "AsIs",
        "rules" : [
          {
            "ip" : ["geoip:private", "127.0.0.0/8", "fd00::/8"],
            "outboundTag" : "direct",
            "type" : "field"
          }
        ]
      }
    }"#;

    let parsed = parse_xray_json(raw).expect("importer config should parse");

    let sniffing = parsed.config.inbounds[0]
        .sniffing
        .as_ref()
        .expect("enabled sniffing should be modeled");
    assert_eq!(
        sniffing.dest_override,
        [
            SniffingDestination::Http,
            SniffingDestination::Tls,
            SniffingDestination::Quic
        ]
    );
    assert!(!sniffing.metadata_only);
    assert_eq!(parsed.config.dns.query_strategy, DnsQueryStrategy::UseIpv4);
}

#[test]
fn parses_xray_core_reality_split_routing_fixture() {
    // Xray-core oracle:
    // REPO_ROOT=/path/to/xray-rust
    // go run ./main run -test -format json \
    //   < "$REPO_ROOT/tests/fixtures/configs/xray_core_reality_split_routing_full.json"
    // Expected: Configuration OK.
    let raw =
        include_str!("../../../tests/fixtures/configs/xray_core_reality_split_routing_full.json");

    let parsed = parse_xray_json(raw).expect("fixture accepted by xray-core should parse");

    assert_eq!(
        parsed.config.routing.domain_strategy,
        RoutingDomainStrategy::IpIfNonMatch
    );
    assert!(parsed.config.routing.rules[0].matches_domain(Some("api.direct.example")));
    assert!(
        parsed.config.routing.rules[1].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))))
    );
    assert!(
        parsed.config.inbounds[0]
            .sniffing
            .as_ref()
            .expect("enabled sniffing should be modeled")
            .route_only
    );
    assert_eq!(parsed.config.dns.servers.len(), 3);
    assert!(parsed.config.policy.levels.contains_key(&0));

    let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings else {
        panic!("expected vless outbound");
    };
    assert_eq!(vless.users[0].level, 8);
}

#[test]
fn sets_default_outbound_tag_to_first_outbound_tag() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.default_outbound_tag.as_deref(), Some("proxy"));
}

#[test]
fn parses_freedom_outbound_as_direct_tcp_default() {
    let raw = r#"{
        "inbounds": [],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(
        parsed.config.default_outbound_tag.as_deref(),
        Some("direct")
    );
    assert_eq!(parsed.config.outbounds[0].tag.as_deref(), Some("direct"));
    assert!(matches!(
        parsed.config.outbounds[0].settings,
        OutboundSettings::Freedom
    ));
}

#[test]
fn parses_xray_dns_outbound_rules_rewrite_and_user_level() {
    let raw = raw_with_dns_outbound_settings(
        r#"{
          "rewriteNetwork": "tcp",
          "rewriteAddress": "192.0.2.53",
          "rewritePort": 53,
          "network": "UDP",
          "address": "dns.example",
          "port": 5353,
          "userLevel": 7,
          "rules": [{
            "action": "DiReCt",
            "qType": "1,3,23-24,24",
            "domain": ["domain:example.com", "full:exact.test"]
          }, {
            "action": "drop",
            "qType": 28,
            "domain": "keyword:ads"
          }]
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("dns outbound should parse");
    let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };

    assert_eq!(settings.rewrite_network, Some(Network::Udp));
    assert_eq!(
        settings.rewrite_address,
        Some(TargetAddr::Domain("dns.example".to_owned()))
    );
    assert_eq!(settings.rewrite_port, 5353);
    assert_eq!(settings.user_level, 7);
    assert_eq!(settings.rules.len(), 2);
    assert_eq!(settings.rules[0].qtype_ranges.len(), 3);
    assert_eq!(settings.rules[0].qtype_ranges[2].start(), 23);
    assert_eq!(settings.rules[0].qtype_ranges[2].end(), 24);
    assert_eq!(
        settings.action_for(1, "api.example.com."),
        DnsOutboundRuleAction::Direct
    );
    assert_eq!(
        settings.action_for(28, "ads-cdn.test"),
        DnsOutboundRuleAction::Drop
    );
}

#[test]
fn dns_outbound_non_empty_legacy_network_shadows_canonical_semantic_errors() {
    for canonical in ["unix", "unsupported"] {
        let raw = raw_with_dns_outbound_settings(&format!(
            r#"{{ "rewriteNetwork": "{canonical}", "network": "tcp" }}"#,
        ));

        let parsed = parse_xray_json(&raw).expect("legacy network must shadow canonical value");
        let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
            panic!("expected dns outbound");
        };

        assert_eq!(settings.rewrite_network, Some(Network::Tcp));
        assert!(parsed.diagnostics.is_empty());
    }
}

#[test]
fn dns_outbound_empty_or_null_legacy_network_does_not_shadow_canonical_value() {
    for legacy in [r#""""#, "null"] {
        let raw = raw_with_dns_outbound_settings(&format!(
            r#"{{ "rewriteNetwork": "udp", "network": {legacy} }}"#,
        ));

        let parsed = parse_xray_json(&raw).expect("empty legacy network must not shadow canonical");
        let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
            panic!("expected dns outbound");
        };

        assert_eq!(settings.rewrite_network, Some(Network::Udp));
        assert!(parsed.diagnostics.is_empty());

        let invalid = raw_with_dns_outbound_settings(&format!(
            r#"{{ "rewriteNetwork": "unix", "network": {legacy} }}"#,
        ));
        assert_parse_error_path(&invalid, "$.outbounds[0].settings.rewriteNetwork");
    }
}

#[test]
fn dns_outbound_legacy_address_shadows_canonical_env_and_empty_values() {
    for canonical in [r#""env:DNS_SERVER""#, r#""""#] {
        let raw = raw_with_dns_outbound_settings(&format!(
            r#"{{ "rewriteAddress": {canonical}, "address": "192.0.2.53" }}"#,
        ));

        let parsed = parse_xray_json(&raw).expect("legacy address must shadow canonical value");
        let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
            panic!("expected dns outbound");
        };

        assert_eq!(
            settings.rewrite_address,
            Some(TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))))
        );
        assert!(parsed.diagnostics.is_empty());
    }
}

#[test]
fn dns_outbound_null_legacy_address_does_not_shadow_canonical_value() {
    let raw =
        raw_with_dns_outbound_settings(r#"{ "rewriteAddress": "192.0.2.53", "address": null }"#);

    let parsed = parse_xray_json(&raw).expect("null legacy address must not shadow canonical");
    let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };

    assert_eq!(
        settings.rewrite_address,
        Some(TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))))
    );
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn dns_outbound_legacy_aliases_do_not_hide_json_type_errors() {
    for (settings, path) in [
        (
            r#"{ "rewriteNetwork": false, "network": "tcp" }"#,
            "$.outbounds[0].settings.rewriteNetwork",
        ),
        (
            r#"{ "rewriteNetwork": "tcp", "network": false }"#,
            "$.outbounds[0].settings.network",
        ),
        (
            r#"{ "rewriteAddress": false, "address": "192.0.2.53" }"#,
            "$.outbounds[0].settings.rewriteAddress",
        ),
        (
            r#"{ "rewriteAddress": "192.0.2.53", "address": false }"#,
            "$.outbounds[0].settings.address",
        ),
    ] {
        let raw = raw_with_dns_outbound_settings(settings);
        assert_parse_error_path(&raw, path);
    }
}

#[test]
fn omitted_or_null_dns_outbound_settings_use_xray_defaults() {
    for settings in [None, Some("null")] {
        let settings =
            settings.map_or_else(String::new, |settings| format!(",\"settings\":{settings}"));
        let raw = format!(
            r#"{{
              "inbounds": [],
              "outbounds": [{{ "tag": "dns-out", "protocol": "DNS"{settings} }}]
            }}"#
        );

        let parsed = parse_xray_json(&raw).expect("default dns outbound should parse");
        let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
            panic!("expected dns outbound");
        };
        assert_eq!(settings, &DnsOutboundSettings::default());
    }
}

#[test]
fn dns_outbound_numeric_zero_qtype_is_wildcard_but_string_zero_is_type_zero() {
    let numeric = parse_xray_json(&raw_with_dns_outbound_settings(
        r#"{ "rules": [{ "action": "direct", "qType": 0 }] }"#,
    ))
    .expect("numeric zero should parse");
    let string = parse_xray_json(&raw_with_dns_outbound_settings(
        r#"{ "rules": [{ "action": "direct", "qType": "0" }] }"#,
    ))
    .expect("string zero should parse");
    let OutboundSettings::Dns(numeric) = &numeric.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };
    let OutboundSettings::Dns(string) = &string.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };

    assert_eq!(
        numeric.action_for(65, "example.com"),
        DnsOutboundRuleAction::Direct
    );
    assert_eq!(
        string.action_for(0, "example.com"),
        DnsOutboundRuleAction::Direct
    );
    assert_eq!(
        string.action_for(65, "example.com"),
        DnsOutboundRuleAction::Return
    );
}

#[test]
fn parses_canonical_dns_outbound_return_qtype_and_rcode() {
    let parsed = parse_xray_json(&raw_with_dns_outbound_settings(
        r#"{
          "rules": [{
            "action": "ReTuRn",
            "qType": "16,64-65",
            "rCode": 3
          }]
        }"#,
    ))
    .expect("canonical DNS outbound rule should parse");
    let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };

    assert!(parsed.diagnostics.is_empty());
    assert_eq!(settings.rules[0].action, DnsOutboundRuleAction::Return);
    assert_eq!(settings.rules[0].r_code, 3);
    assert_eq!(settings.rules[0].qtype_ranges.len(), 2);
    assert_eq!(
        settings.action_for(65, "example.com"),
        DnsOutboundRuleAction::Return
    );
}

#[test]
fn dns_outbound_lowercase_qtype_and_reject_remain_warned_aliases() {
    let parsed = parse_xray_json(&raw_with_dns_outbound_settings(
        r#"{ "rules": [{ "action": "Reject", "qtype": 65 }] }"#,
    ))
    .expect("unambiguous legacy aliases should parse");
    let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };

    assert_eq!(settings.rules[0].action, DnsOutboundRuleAction::Return);
    assert_eq!(settings.rules[0].r_code, 5);
    assert_eq!(parsed.diagnostics.len(), 2);
    assert!(parsed
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning));
}

#[test]
fn dns_outbound_reject_alias_allows_explicit_rcode_override() {
    let parsed = parse_xray_json(&raw_with_dns_outbound_settings(
        r#"{ "rules": [{ "action": "Reject", "rCode": 2 }] }"#,
    ))
    .expect("explicit rCode should disambiguate the legacy action");
    let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };

    assert_eq!(settings.rules[0].action, DnsOutboundRuleAction::Return);
    assert_eq!(settings.rules[0].r_code, 2);
}

#[test]
fn rejects_mixed_canonical_and_legacy_dns_qtype_spellings() {
    let raw = raw_with_dns_outbound_settings(
        r#"{ "rules": [{ "action": "return", "qType": 16, "qtype": 65 }] }"#,
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.rules[0].qtype");
}

#[test]
fn normalizes_legacy_dns_outbound_policy_with_deprecation_warning() {
    let raw = raw_with_dns_outbound_settings(r#"{ "nonIPQuery": "skip", "blockTypes": [65, 28] }"#);

    let parsed = parse_xray_json(&raw).expect("legacy dns outbound should parse");
    let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };

    assert_eq!(settings.rules.len(), 3);
    assert_eq!(
        settings.action_for(65, "example.com"),
        DnsOutboundRuleAction::Drop
    );
    assert_eq!(
        settings.action_for(1, "example.com"),
        DnsOutboundRuleAction::Hijack
    );
    assert_eq!(
        settings.action_for(16, "example.com"),
        DnsOutboundRuleAction::Direct
    );
    assert_eq!(parsed.diagnostics.len(), 1);
    assert_eq!(parsed.diagnostics[0].severity, DiagnosticSeverity::Warning);
}

#[test]
fn legacy_dns_outbound_reject_mode_maps_to_return_refused() {
    let parsed = parse_xray_json(&raw_with_dns_outbound_settings(
        r#"{ "nonIPQuery": "reject", "blockTypes": [65] }"#,
    ))
    .expect("legacy reject policy should parse");
    let OutboundSettings::Dns(settings) = &parsed.config.outbounds[0].settings else {
        panic!("expected dns outbound");
    };

    assert_eq!(settings.rules[0].action, DnsOutboundRuleAction::Return);
    assert_eq!(settings.rules[0].r_code, 5);
    assert_eq!(settings.rules[2].action, DnsOutboundRuleAction::Return);
    assert_eq!(settings.rules[2].r_code, 5);
}

#[test]
fn rejects_mixed_legacy_and_modern_dns_outbound_rules() {
    let raw = raw_with_dns_outbound_settings(r#"{ "rules": [], "blockTypes": [65] }"#);

    assert_parse_error_path(&raw, "$.outbounds[0].settings.rules");
}

#[test]
fn rejects_invalid_dns_outbound_fields_with_precise_paths() {
    for (settings, path) in [
        ("false", "$.outbounds[0].settings"),
        (r#"{ "unknown": true }"#, "$.outbounds[0].settings.unknown"),
        (
            r#"{ "rewriteNetwork": "unix" }"#,
            "$.outbounds[0].settings.rewriteNetwork",
        ),
        (
            r#"{ "rewriteAddress": "" }"#,
            "$.outbounds[0].settings.rewriteAddress",
        ),
        (
            r#"{ "rewritePort": 65536 }"#,
            "$.outbounds[0].settings.rewritePort",
        ),
        (
            r#"{ "userLevel": -1 }"#,
            "$.outbounds[0].settings.userLevel",
        ),
        (r#"{ "rules": {} }"#, "$.outbounds[0].settings.rules"),
        (r#"{ "rules": [null] }"#, "$.outbounds[0].settings.rules[0]"),
        (
            r#"{ "rules": [{}] }"#,
            "$.outbounds[0].settings.rules[0].action",
        ),
        (
            r#"{ "rules": [{ "action": "allow" }] }"#,
            "$.outbounds[0].settings.rules[0].action",
        ),
        (
            r#"{ "rules": [{ "action": "drop", "qType": "24-23" }] }"#,
            "$.outbounds[0].settings.rules[0].qType[0]",
        ),
        (
            r#"{ "rules": [{ "action": "drop", "qType": "65536" }] }"#,
            "$.outbounds[0].settings.rules[0].qType[0]",
        ),
        (
            r#"{ "rules": [{ "action": "drop", "qType": [] }] }"#,
            "$.outbounds[0].settings.rules[0].qType",
        ),
        (
            r#"{ "rules": [{ "action": "return", "rCode": 65536 }] }"#,
            "$.outbounds[0].settings.rules[0].rCode",
        ),
        (
            r#"{ "rules": [{ "action": "drop", "domain": [42] }] }"#,
            "$.outbounds[0].settings.rules[0].domain[0]",
        ),
        (
            r#"{ "nonIPQuery": "DROP" }"#,
            "$.outbounds[0].settings.nonIPQuery",
        ),
        (
            r#"{ "blockTypes": [-1] }"#,
            "$.outbounds[0].settings.blockTypes[0]",
        ),
    ] {
        let raw = raw_with_dns_outbound_settings(settings);
        assert_parse_error_path(&raw, path);
    }
}

#[test]
fn rejects_dns_outbound_rewrite_address_environment_reference_explicitly() {
    let raw = raw_with_dns_outbound_settings(r#"{ "rewriteAddress": "env:DNS_SERVER" }"#);

    let error = parse_xray_json(&raw).expect_err("DNS rewrite env references are unsupported");

    assert_eq!(error.diagnostics.len(), 1);
    assert_eq!(
        error.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].settings.rewriteAddress")
    );
    assert_eq!(
        error.diagnostics[0].message,
        "dns rewrite address environment references are not supported"
    );
}

#[test]
fn rejects_dns_outbound_rule_count_above_global_budget() {
    let rule = r#"{ "action": "direct" }"#;
    let rules = std::iter::repeat_n(rule, 4_097)
        .collect::<Vec<_>>()
        .join(",");
    let raw = raw_with_dns_outbound_settings(&format!(r#"{{ "rules": [{rules}] }}"#));

    assert_parse_error_path(&raw, "$.outbounds[0].settings.rules");
}

#[test]
fn parses_socks_inbound_with_udp_enabled() {
    let raw = r#"{
        "inbounds": [
            {
              "tag": "socks-in",
              "protocol": "socks",
              "listen": "127.0.0.1",
              "port": 1080,
              "settings": { "auth": "noauth", "udp": true }
            }
        ],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(parsed.config.inbounds[0].protocol, InboundProtocol::Socks);
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn parses_dns_fake_ip_ipv4_pool() {
    let raw = r#"{
        "dns": {
          "fakeIp": {
            "enabled": true,
            "ipv4Pool": "198.18.0.0/15",
            "ttl": 120
          }
        },
        "inbounds": [
            { "tag": "tun-in", "protocol": "tun", "port": 0, "settings": {} }
        ],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(
        parsed.config.dns.fake_ip,
        Some(DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15).unwrap(),
            pool_size: 32_768,
            ttl: 120,
        })
    );
}

#[test]
fn parses_explicit_dns_fake_ip_pool_size() {
    let raw = r#"{
        "dns": {
          "fakeIp": {
            "enabled": true,
            "ipv4Pool": "198.18.0.0/15",
            "poolSize": 4096
          }
        },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(parsed.config.dns.fake_ip.unwrap().pool_size, 4_096);
}

#[test]
fn defaults_dns_fake_ip_pool_size_to_usable_address_count_for_small_pool() {
    let raw = r#"{
        "dns": {
          "fakeIp": {
            "enabled": true,
            "ipv4Pool": "198.19.0.1/32"
          }
        },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(parsed.config.dns.fake_ip.unwrap().pool_size, 1);
}

#[test]
fn rejects_zero_dns_fake_ip_pool_size() {
    let raw = r#"{
        "dns": {
          "fakeIp": {
            "enabled": true,
            "ipv4Pool": "198.18.0.0/15",
            "poolSize": 0
          }
        },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    assert_parse_error_path(raw, "$.dns.fakeIp.poolSize");
}

#[test]
fn rejects_zero_dns_fake_ip_ttl() {
    let raw = r#"{
        "dns": {
          "fakeIp": {
            "enabled": true,
            "ipv4Pool": "198.18.0.0/15",
            "poolSize": 1024,
            "ttl": 0
          }
        },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    assert_parse_error_path(raw, "$.dns.fakeIp.ttl");
}

#[test]
fn rejects_dns_fake_ip_pool_size_exceeding_reserved_address_adjusted_capacity() {
    let raw = r#"{
        "dns": {
          "fakeIp": {
            "enabled": true,
            "ipv4Pool": "198.18.0.0/29",
            "poolSize": 5
          }
        },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    assert_parse_error_path(raw, "$.dns.fakeIp.poolSize");
}

#[test]
fn rejects_dns_fake_ip_pool_containing_only_tun_reserved_addresses() {
    let raw = r#"{
        "dns": {
          "fakeIp": {
            "enabled": true,
            "ipv4Pool": "198.18.0.0/30"
          }
        },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    assert_parse_error_path(raw, "$.dns.fakeIp.ipv4Pool");
}

#[test]
fn rejects_dns_fake_ip_without_ipv4_pool_when_enabled() {
    let raw = r#"{
        "dns": { "fakeIp": { "enabled": true } },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    assert_parse_error_path(raw, "$.dns.fakeIp.ipv4Pool");
}

#[test]
fn rejects_freedom_redirect_with_path() {
    let raw = r#"{
        "inbounds": [],
        "outbounds": [
            {
              "tag": "direct",
              "protocol": "freedom",
              "settings": { "redirect": "127.0.0.1:80" }
            }
        ]
    }"#;

    assert_parse_error_path(raw, "$.outbounds[0].settings.redirect");
}

#[test]
fn parses_ip_if_non_match_routing_domain_strategy() {
    let raw = raw_with_routing(r#""domainStrategy": "IPIfNonMatch""#);

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(
        parsed.config.routing.domain_strategy,
        RoutingDomainStrategy::IpIfNonMatch
    );
}

#[test]
fn rejects_unknown_routing_domain_strategy_with_path() {
    let raw = raw_with_routing(r#""domainStrategy": "IPOnDemand""#);

    assert_parse_error_path(&raw, "$.routing.domainStrategy");
}

#[test]
fn parses_field_routing_rule_with_inbound_tag() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "inboundTag": ["socks-in"],
          "outboundTag": "proxy"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.routing.rules.len(), 1);
    assert_eq!(
        parsed.config.routing.rules[0].inbound_tags,
        vec!["socks-in".to_owned()]
    );
    assert!(parsed.config.routing.rules[0].domain_matchers.is_empty());
    assert!(parsed.config.routing.rules[0].ip_matchers.is_empty());
    assert_eq!(parsed.config.routing.rules[0].outbound_tag, "proxy");
}

#[test]
fn parses_xray_routing_network_and_port_selectors() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "network": "udp,TCP,udp",
          "port": "53,5353,8000-8002,8002",
          "outboundTag": "dns-out"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("network and port routing should parse");
    let rule = &parsed.config.routing.rules[0];

    assert_eq!(rule.networks, vec![Network::Udp, Network::Tcp]);
    assert_eq!(rule.port_ranges.len(), 3);
    assert!(rule.matches_target(None, None, None, Some(Network::Udp), Some(53)));
    assert!(rule.matches_target(None, None, None, Some(Network::Tcp), Some(8_001)));
    assert!(!rule.matches_target(None, None, None, Some(Network::Udp), Some(443)));
    assert!(!rule.matches(None, None, None));
}

#[test]
fn parses_routing_network_array_and_numeric_port() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "network": ["udp"],
          "port": 53,
          "outboundTag": "dns-out"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("routing selectors should parse");
    let rule = &parsed.config.routing.rules[0];

    assert_eq!(rule.networks, vec![Network::Udp]);
    assert!(rule.port_ranges[0].contains(53));
}

#[test]
fn rejects_invalid_routing_network_and_port_selectors_with_paths() {
    for (fields, path) in [
        (
            r#""network": "unix", "outboundTag": "proxy""#,
            "$.routing.rules[0].network[0]",
        ),
        (
            r#""network": [42], "outboundTag": "proxy""#,
            "$.routing.rules[0].network[0]",
        ),
        (
            r#""port": "54-53", "outboundTag": "proxy""#,
            "$.routing.rules[0].port[0]",
        ),
        (
            r#""port": 65536, "outboundTag": "proxy""#,
            "$.routing.rules[0].port",
        ),
        (
            r#""port": [], "outboundTag": "proxy""#,
            "$.routing.rules[0].port",
        ),
    ] {
        let raw = raw_with_routing(&format!(r#""rules": [{{ "type": "field", {fields} }}]"#));
        assert_parse_error_path(&raw, path);
    }
}

#[test]
fn parses_field_routing_rule_with_rule_tag() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "inboundTag": ["socks-in"],
          "outboundTag": "proxy",
          "ruleTag": "api-rule"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.routing.rules.len(), 1);
}

#[test]
fn accepts_routing_rule_with_missing_outbound_tag_reference() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "inboundTag": ["api"],
          "outboundTag": "api"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.routing.rules[0].outbound_tag, "api");
}

#[test]
fn parses_field_routing_rule_with_domain_suffix() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "domain": ["domain:example.com"],
          "outboundTag": "proxy"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.routing.rules.len(), 1);
    assert!(parsed.config.routing.rules[0].matches_domain(Some("api.example.com")));
    assert!(parsed.config.routing.rules[0].matches_domain(Some("example.com")));
    assert!(!parsed.config.routing.rules[0].matches_domain(Some("other.test")));
}

#[test]
fn parses_field_routing_rule_with_plain_keyword_domain_and_domains_alias() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "domain": ["example"],
          "domains": ["keyword:api", "full:exact.test"],
          "outboundTag": "proxy"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.routing.rules.len(), 1);
    assert!(parsed.config.routing.rules[0].matches_domain(Some("cdn-example.test")));
    assert!(parsed.config.routing.rules[0].matches_domain(Some("service-api.test")));
    assert!(parsed.config.routing.rules[0].matches_domain(Some("EXACT.test")));
    assert!(!parsed.config.routing.rules[0].matches_domain(Some("service.test")));
}

#[test]
fn parses_field_routing_ip_matchers() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "ip": ["10.0.0.0/8", "192.168.1.1", "geoip:private", "fd00::/8"],
          "outboundTag": "proxy"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.routing.rules.len(), 1);
    assert!(
        parsed.config.routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1))))
    );
    assert!(
        parsed.config.routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))))
    );
    assert!(parsed.config.routing.rules[0].matches_ip(Some(&IpAddr::V6(Ipv6Addr::LOCALHOST))));
    assert!(parsed.config.routing.rules[0]
        .matches_ip(Some(&IpAddr::V6("fd12:3456:789a::1".parse().unwrap()))));
    assert!(
        !parsed.config.routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))))
    );
}

#[test]
fn parses_field_routing_inverse_ip_matchers() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "ip": ["!10.0.0.0/8", "!192.168.0.0/16", "203.0.113.0/24"],
          "outboundTag": "proxy"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert_eq!(parsed.config.routing.rules.len(), 1);
    assert!(parsed.config.routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
    assert!(parsed.config.routing.rules[0]
        .matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))));
    assert!(
        !parsed.config.routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1))))
    );
    assert!(!parsed.config.routing.rules[0]
        .matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))));
}

#[test]
fn parses_geosite_and_geoip_dat_routing_matchers() {
    let asset_dir = unique_temp_dir("geosite-geoip");
    write_geosite_dat(
        &asset_dir,
        "geosite.dat",
        &[TestGeoSite {
            code: "TEST".to_owned(),
            domain: vec![
                site_domain(0, "sample", &[]),
                site_domain(1, "^re-[a-z]+\\.test$", &[]),
                site_domain(2, "example.com", &[]),
                site_domain(3, "exact.test", &[]),
                site_domain(2, "ads.example.com", &["ads"]),
            ],
        }],
    );
    write_geoip_dat(
        &asset_dir,
        "geoip.dat",
        &[TestGeoIp {
            code: "TEST".to_owned(),
            cidr: vec![
                geo_cidr(&[203, 0, 113, 0], 24),
                geo_cidr(
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
            ],
            reverse_match: false,
        }],
    );
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "domain": ["geosite:test"],
          "ip": ["geoip:test"],
          "outboundTag": "proxy"
        }, {
          "type": "field",
          "domain": ["geosite:test@ads"],
          "outboundTag": "proxy"
        }]"#,
    );

    let parsed =
        parse_xray_json_with_geodata_dirs(&raw, &[asset_dir]).expect("config should parse");

    let all_site_rule = &parsed.config.routing.rules[0];
    assert!(all_site_rule.matches_domain(Some("cdn-sample.test")));
    assert!(all_site_rule.matches_domain(Some("re-api.test")));
    assert!(all_site_rule.matches_domain(Some("api.example.com")));
    assert!(all_site_rule.matches_domain(Some("EXACT.test")));
    assert!(all_site_rule.matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))));
    assert!(all_site_rule.matches_ip(Some(&IpAddr::V6("2001:db8::1".parse().unwrap()))));
    assert!(!all_site_rule.matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))));

    let ads_rule = &parsed.config.routing.rules[1];
    assert!(ads_rule.matches_domain(Some("ads.example.com")));
    assert!(!ads_rule.matches_domain(Some("api.example.com")));
    assert!(!ads_rule.matches_domain(Some("cdn-sample.test")));
}

#[test]
fn parses_ext_geodata_rules_from_named_files_and_inverse_geoip() {
    let asset_dir = unique_temp_dir("ext-geodata");
    write_geosite_dat(
        &asset_dir,
        "custom-site.dat",
        &[TestGeoSite {
            code: "CUSTOM".to_owned(),
            domain: vec![site_domain(2, "direct.test", &[])],
        }],
    );
    write_geoip_dat(
        &asset_dir,
        "custom-ip.dat",
        &[TestGeoIp {
            code: "CUSTOM".to_owned(),
            cidr: vec![geo_cidr(&[198, 51, 100, 0], 24)],
            reverse_match: false,
        }],
    );
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "domain": ["ext-domain:custom-site.dat:custom"],
          "ip": ["!ext-ip:custom-ip.dat:custom"],
          "outboundTag": "proxy"
        }]"#,
    );

    let parsed =
        parse_xray_json_with_geodata_dirs(&raw, &[asset_dir]).expect("config should parse");

    assert!(parsed.config.routing.rules[0].matches_domain(Some("api.direct.test")));
    assert!(parsed.config.routing.rules[0].matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
    assert!(!parsed.config.routing.rules[0]
        .matches_ip(Some(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)))));
}

#[test]
fn rejects_missing_geodata_code_with_path() {
    let asset_dir = unique_temp_dir("missing-geodata-code");
    write_geosite_dat(
        &asset_dir,
        "geosite.dat",
        &[TestGeoSite {
            code: "OTHER".to_owned(),
            domain: vec![site_domain(2, "example.com", &[])],
        }],
    );
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "domain": ["geosite:missing"],
          "outboundTag": "proxy"
        }]"#,
    );

    let err = parse_xray_json_with_geodata_dirs(&raw, &[asset_dir]).unwrap_err();

    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(
        err.diagnostics[0].path.as_deref(),
        Some("$.routing.rules[0].domain[0]")
    );
}

#[test]
fn rejects_geosite_attribute_selection_with_no_matchers() {
    let asset_dir = unique_temp_dir("empty-geosite-attrs");
    write_geosite_dat(
        &asset_dir,
        "geosite.dat",
        &[TestGeoSite {
            code: "TEST".to_owned(),
            domain: vec![site_domain(2, "ads.example.com", &["ads"])],
        }],
    );
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "domain": ["geosite:test@missing"],
          "outboundTag": "proxy"
        }]"#,
    );

    let err = parse_xray_json_with_geodata_dirs(&raw, &[asset_dir]).unwrap_err();

    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(
        err.diagnostics[0].path.as_deref(),
        Some("$.routing.rules[0].domain[0]")
    );
}

#[test]
fn rejects_missing_routing_ip_geoip_with_path() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "ip": ["geoip:cn"],
          "outboundTag": "proxy"
        }]"#,
    );

    assert_parse_error_path(&raw, "$.routing.rules[0].ip[0]");
}

#[test]
fn rejects_invalid_routing_ip_cidr_with_path() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "ip": ["10.0.0.0/33"],
          "outboundTag": "proxy"
        }]"#,
    );

    assert_parse_error_path(&raw, "$.routing.rules[0].ip[0]");
}

#[test]
fn rejects_missing_routing_domain_geosite_with_path() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "domain": ["geosite:cn"],
          "outboundTag": "proxy"
        }]"#,
    );

    assert_parse_error_path(&raw, "$.routing.rules[0].domain[0]");
}

#[test]
fn parses_field_routing_rule_with_regex_domain_matcher() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "domains": ["regexp:.*\\.example\\.com$"],
          "outboundTag": "proxy"
        }]"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");

    assert!(parsed.config.routing.rules[0].matches_domain(Some("api.example.com")));
    assert!(!parsed.config.routing.rules[0].matches_domain(Some("example.com")));
}

#[test]
fn rejects_routing_rule_count_above_global_budget_before_building_rules() {
    let rule = r#"{"type":"field","domain":["full:example.test"],"outboundTag":"proxy"}"#;
    let rules = std::iter::repeat_n(rule, 4_097)
        .collect::<Vec<_>>()
        .join(",");
    let raw = raw_with_routing(&format!(r#""rules":[{rules}]"#));

    let error = parse_xray_json(&raw).unwrap_err();

    assert_eq!(
        error.diagnostics[0].path.as_deref(),
        Some("$.routing.rules")
    );
    assert!(error.diagnostics[0].message.contains("4097 rules"));
    assert!(error.diagnostics[0].message.contains("maximum supported"));
}

#[test]
fn rejects_unsupported_routing_rule_field_with_path() {
    let raw = raw_with_routing(
        r#""rules": [{
          "type": "field",
          "attrs": ["example"],
          "outboundTag": "proxy"
        }]"#,
    );

    assert_parse_error_path(&raw, "$.routing.rules[0].attrs");
}

#[test]
fn rejects_missing_routing_rule_outbound_tag_with_path() {
    let raw = raw_with_routing(r#""rules": [{ "type": "field" }]"#);

    assert_parse_error_path(&raw, "$.routing.rules[0].outboundTag");
}

#[test]
fn rejects_non_empty_routing_balancers_with_path() {
    let raw = raw_with_routing(r#""balancers": [{ "tag": "fallback" }]"#);

    assert_parse_error_path(&raw, "$.routing.balancers");
}

#[test]
fn parses_enabled_inbound_sniffing() {
    let raw = raw_with_inbound_extra(
        r#""sniffing": {
          "enabled": true,
          "destOverride": ["http", "tls", "quic"],
          "metadataOnly": false,
          "routeOnly": true,
          "excludedDomains": []
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");
    let sniffing = parsed.config.inbounds[0]
        .sniffing
        .as_ref()
        .expect("enabled sniffing should be modeled");

    assert_eq!(
        sniffing.dest_override,
        vec![
            SniffingDestination::Http,
            SniffingDestination::Tls,
            SniffingDestination::Quic
        ]
    );
    assert!(sniffing.route_only);
}

#[test]
fn rejects_socks_password_auth_with_path() {
    let raw = raw_with_socks_settings(r#""auth": "password""#);

    assert_parse_error_path(&raw, "$.inbounds[0].settings.auth");
}

#[test]
fn rejects_socks_udp_non_bool_with_path() {
    let raw = raw_with_socks_settings(r#""udp": "yes""#);

    assert_parse_error_path(&raw, "$.inbounds[0].settings.udp");
}

#[test]
fn rejects_enabled_mux_with_path() {
    let raw = raw_with_outbound_extra(r#""mux": { "enabled": true }"#);

    assert_parse_error_path(&raw, "$.outbounds[0].mux.enabled");
}

#[test]
fn accepts_disabled_mux_with_concurrency() {
    let raw = raw_with_outbound_extra(r#""mux": { "enabled": false, "concurrency": 8 }"#);

    parse_xray_json(&raw).expect("config should parse");
}

#[test]
fn rejects_send_through_with_path() {
    let raw = raw_with_outbound_extra(r#""sendThrough": "127.0.0.2""#);

    assert_parse_error_path(&raw, "$.outbounds[0].sendThrough");
}

#[test]
fn rejects_tls_allow_insecure_true_with_path() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "allowInsecure": true"#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.tlsSettings.allowInsecure",
    );
}

#[test]
fn tls_allow_insecure_false_and_null_keep_verification_enabled() {
    for value in ["false", "null"] {
        let raw = raw_with_tls_settings(&format!(
            r#""serverName": "server.example", "allowInsecure": {value}"#
        ));
        let parsed = parse_xray_json(&raw).expect("false/null preserve certificate verification");
        let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
            panic!("expected TLS security");
        };
        assert!(!tls.allow_insecure);
    }
}

#[test]
fn rejects_tls_allow_insecure_non_bool_with_path() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "allowInsecure": "yes""#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.tlsSettings.allowInsecure",
    );
}

#[test]
fn rejects_non_string_tls_server_name_with_path() {
    let raw = raw_with_tls_settings(r#""serverName": 42"#);

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.tlsSettings.serverName");
}

#[test]
fn rejects_tls_from_mitm_context_sentinels_with_paths() {
    let server_name = raw_with_tls_settings(r#""serverName": "FrOmMiTm""#);
    assert_parse_error_path(
        &server_name,
        "$.outbounds[0].streamSettings.tlsSettings.serverName",
    );

    let alpn = raw_with_tls_settings(r#""serverName": "server.example", "alpn": ["FROMMITM"]"#);
    assert_parse_error_path(&alpn, "$.outbounds[0].streamSettings.tlsSettings.alpn[0]");

    let verification_name = raw_with_tls_settings(
        r#""serverName": "server.example", "verifyPeerCertByName": "cert.example, FrOmMiTm""#,
    );
    assert_parse_error_path(
        &verification_name,
        "$.outbounds[0].streamSettings.tlsSettings.verifyPeerCertByName",
    );
}

#[test]
fn parses_tls_fingerprint() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "fingerprint": "firefox""#);
    let parsed = parse_xray_json(&raw).expect("a TLS fingerprint should be accepted");

    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected tls security");
    };
    assert_eq!(tls.fingerprint.as_deref(), Some("firefox"));
}

#[test]
fn parses_tls_peer_certificate_pins_with_xray_hex_grammar() {
    let openssl = (0u8..32)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let compact = "aa".repeat(32);
    let raw = raw_with_tls_settings(&format!(
        r#""serverName": "server.example", "pinnedPeerCertSha256": " , {openssl},, {compact} , ""#
    ));
    let parsed = parse_xray_json(&raw).expect("valid full-DER SHA-256 pins should parse");

    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected tls security");
    };
    assert_eq!(
        tls.pinned_peer_cert_sha256,
        vec![std::array::from_fn(|index| index as u8), [0xaa; 32]]
    );
    assert!(!tls.allow_insecure);
}

#[test]
fn parses_tls_verification_names_with_xray_comma_and_trim_grammar() {
    let raw = raw_with_tls_settings(
        r#""serverName": "sni.example", "verifyPeerCertByName": " first.example , , 127.0.0.1, SECOND.example ""#,
    );
    let parsed = parse_xray_json(&raw).expect("valid TLS verification names should parse");

    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected tls security");
    };
    assert_eq!(
        tls.verify_peer_cert_by_name,
        ["first.example", "127.0.0.1", "SECOND.example"]
    );
    assert_eq!(tls.server_name.as_deref(), Some("sni.example"));
}

#[test]
fn accepts_empty_and_null_tls_verification_name_strings() {
    for value in [r#"" , , ""#, "null"] {
        let raw = raw_with_tls_settings(&format!(
            r#""serverName": "server.example", "verifyPeerCertByName": {value}"#
        ));
        let parsed = parse_xray_json(&raw).expect("empty Xray verification names should be inert");
        let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
            panic!("expected tls security");
        };
        assert!(tls.verify_peer_cert_by_name.is_empty());
    }
}

#[test]
fn rejects_non_string_tls_verification_names_with_path() {
    for value in ["42", r#"["server.example"]"#] {
        let raw = raw_with_tls_settings(&format!(
            r#""serverName": "server.example", "verifyPeerCertByName": {value}"#
        ));
        assert_parse_error_path(
            &raw,
            "$.outbounds[0].streamSettings.tlsSettings.verifyPeerCertByName",
        );
    }
}

#[test]
fn accepts_empty_and_null_tls_peer_certificate_pin_strings() {
    for value in ["\" , , \"", "null"] {
        let raw = raw_with_tls_settings(&format!(
            r#""serverName": "server.example", "pinnedPeerCertSha256": {value}"#
        ));
        let parsed = parse_xray_json(&raw).expect("empty Xray pin settings should be inert");
        let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
            panic!("expected tls security");
        };
        assert!(tls.pinned_peer_cert_sha256.is_empty());
    }
}

#[test]
fn rejects_invalid_tls_peer_certificate_pins_with_path() {
    let too_short = "00".repeat(31);
    for value in [
        "42".to_owned(),
        r#""abcd""#.to_owned(),
        format!(r#""{too_short}""#),
        r#""gg""#.to_owned(),
    ] {
        let raw = raw_with_tls_settings(&format!(
            r#""serverName": "server.example", "pinnedPeerCertSha256": {value}"#
        ));
        assert_parse_error_path(
            &raw,
            "$.outbounds[0].streamSettings.tlsSettings.pinnedPeerCertSha256",
        );
    }
}

#[test]
fn defaults_missing_tls_fingerprint_to_chrome() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example""#);
    let parsed = parse_xray_json(&raw).expect("TLS without a fingerprint should parse");

    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected tls security");
    };
    assert_eq!(
        tls.fingerprint.as_deref(),
        Some("chrome"),
        "an absent fingerprint means chrome, matching Xray's GetFingerprint(\"\")"
    );
}

/// `unsafe` is a sentinel, not a profile name: it has to survive normalization
/// intact so the transport can recognize it and leave the hello unshaped.
#[test]
fn passes_the_unsafe_tls_fingerprint_sentinel_through() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "fingerprint": "UNSAFE""#);
    let parsed = parse_xray_json(&raw).expect("the unsafe sentinel should be accepted");

    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected tls security");
    };
    assert_eq!(tls.fingerprint.as_deref(), Some("unsafe"));
}

#[test]
fn parses_tls_alpn_list() {
    let raw =
        raw_with_tls_settings(r#""serverName": "server.example", "alpn": ["h2", "http/1.1"]"#);
    let parsed = parse_xray_json(&raw).expect("a TLS alpn list should be accepted");

    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected tls security");
    };
    assert_eq!(tls.alpn, ["h2".to_owned(), "http/1.1".to_owned()]);
}

#[test]
fn rejects_unsupported_tls_fingerprint_with_path() {
    let raw =
        raw_with_tls_settings(r#""serverName": "server.example", "fingerprint": "nosuchbrowser""#);

    let error = parse_xray_json(&raw).expect_err("an unknown fingerprint must be rejected");

    assert_eq!(error.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(
        error.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].streamSettings.tlsSettings.fingerprint")
    );
    assert!(
        error.diagnostics[0].message.contains("nosuchbrowser"),
        "the error must name the fingerprint, got: {}",
        error.diagnostics[0].message
    );
}

#[test]
fn rejects_non_string_tls_fingerprint_with_path() {
    for value in ["42", "false", r#"{"browser":"chrome"}"#] {
        let raw = raw_with_tls_settings(&format!(
            r#""serverName": "server.example", "fingerprint": {value}"#
        ));

        assert_parse_error_path(
            &raw,
            "$.outbounds[0].streamSettings.tlsSettings.fingerprint",
        );
    }
}

#[test]
fn rejects_non_array_tls_alpn_with_path() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "alpn": "h2""#);

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.tlsSettings.alpn");
}

#[test]
fn rejects_non_string_tls_alpn_entry_with_path() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "alpn": ["h2", 42]"#);

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.tlsSettings.alpn[1]");
}

#[test]
fn rejects_tcp_header_type_with_path() {
    let raw = raw_with_tcp_settings(r#""header": { "type": "http" }"#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.tcpSettings.header.type",
    );
}

#[test]
fn parses_raw_settings_alias() {
    let raw = raw_with_raw_settings(r#""header": { "type": "none" }"#);

    let parsed = parse_xray_json(&raw).expect("rawSettings alias should parse");

    assert_eq!(parsed.config.outbounds[0].stream.network, Network::Tcp);
}

#[test]
fn rejects_raw_header_type_with_path() {
    let raw = raw_with_raw_settings(r#""header": { "type": "http" }"#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.rawSettings.header.type",
    );
}

#[test]
fn parses_empty_sockopt_without_enabling_happy_eyeballs() {
    let raw = raw_with_sockopt("{}");
    let parsed = parse_xray_json(&raw).expect("empty sockopt should parse");

    assert!(parsed.config.outbounds[0]
        .stream
        .socket_options
        .as_ref()
        .is_some_and(|options| options.happy_eyeballs.is_none()));
}

#[test]
fn parses_empty_happy_eyeballs_with_xray_defaults() {
    let raw = raw_with_sockopt(r#"{ "happyEyeballs": {} }"#);
    let parsed = parse_xray_json(&raw).expect("empty happyEyeballs should use defaults");

    assert_eq!(
        parsed.config.outbounds[0]
            .stream
            .socket_options
            .as_ref()
            .and_then(|options| options.happy_eyeballs),
        Some(HappyEyeballsSettings::default())
    );
}

#[test]
fn parses_explicit_happy_eyeballs_raw_integer_values() {
    let raw = raw_with_sockopt(
        r#"{
          "happyEyeballs": {
            "prioritizeIPv6": true,
            "interleave": 0,
            "tryDelayMs": 18446744073709551615,
            "maxConcurrentTry": 4294967295
          }
        }"#,
    );
    let parsed = parse_xray_json(&raw).expect("happyEyeballs settings should parse");

    assert_eq!(
        parsed.config.outbounds[0]
            .stream
            .socket_options
            .as_ref()
            .and_then(|options| options.happy_eyeballs),
        Some(HappyEyeballsSettings {
            prioritize_ipv6: true,
            interleave: 0,
            try_delay_ms: u64::MAX,
            max_concurrent_try: u32::MAX,
        })
    );
}

#[test]
fn preserves_explicit_zero_happy_eyeballs_integer_values() {
    let raw = raw_with_sockopt(
        r#"{
          "happyEyeballs": {
            "interleave": 0,
            "tryDelayMs": 0,
            "maxConcurrentTry": 0
          }
        }"#,
    );
    let parsed = parse_xray_json(&raw).expect("zero values should not be replaced by defaults");

    assert_eq!(
        parsed.config.outbounds[0]
            .stream
            .socket_options
            .as_ref()
            .and_then(|options| options.happy_eyeballs),
        Some(HappyEyeballsSettings {
            prioritize_ipv6: false,
            interleave: 0,
            try_delay_ms: 0,
            max_concurrent_try: 0,
        })
    );
}

#[test]
fn rejects_non_object_sockopt_with_path() {
    let raw = raw_with_sockopt("false");

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.sockopt");
}

#[test]
fn rejects_unknown_sockopt_field_with_path() {
    let raw = raw_with_sockopt(r#"{ "mark": 1 }"#);

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.sockopt.mark");
}

#[test]
fn rejects_non_object_happy_eyeballs_with_path() {
    let raw = raw_with_sockopt(r#"{ "happyEyeballs": true }"#);

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.sockopt.happyEyeballs");
}

#[test]
fn rejects_unknown_happy_eyeballs_field_with_path() {
    let raw = raw_with_sockopt(r#"{ "happyEyeballs": { "delay": 250 } }"#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.sockopt.happyEyeballs.delay",
    );
}

#[test]
fn rejects_non_boolean_happy_eyeballs_preference_with_path() {
    let raw = raw_with_sockopt(r#"{ "happyEyeballs": { "prioritizeIPv6": 1 } }"#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.sockopt.happyEyeballs.prioritizeIPv6",
    );
}

#[test]
fn rejects_happy_eyeballs_interleave_overflow_with_path() {
    let raw = raw_with_sockopt(r#"{ "happyEyeballs": { "interleave": 4294967296 } }"#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.sockopt.happyEyeballs.interleave",
    );
}

#[test]
fn rejects_negative_happy_eyeballs_try_delay_with_path() {
    let raw = raw_with_sockopt(r#"{ "happyEyeballs": { "tryDelayMs": -1 } }"#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.sockopt.happyEyeballs.tryDelayMs",
    );
}

#[test]
fn rejects_non_integer_happy_eyeballs_max_concurrency_with_path() {
    let raw = raw_with_sockopt(r#"{ "happyEyeballs": { "maxConcurrentTry": 4.5 } }"#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.sockopt.happyEyeballs.maxConcurrentTry",
    );
}

#[test]
fn parses_dns_servers_and_hosts() {
    let raw = r#"{
        "dns": {
          "servers": [
            "192.0.2.53",
            "192.0.2.54:5353",
            "2001:db8::53",
            "[2001:db8::54]:5353",
            "dns.example",
            "dns-alt.example:5353"
          ],
          "hosts": {
            "domain:service.example": "alias.example",
            "full:resolver.example": "192.0.2.53"
          }
        },
        "inbounds": [],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(
        parsed.config.dns.servers[0],
        DnsServerConfig::Ip(SocketAddr::from(([192, 0, 2, 53], 53)))
    );
    assert_eq!(
        parsed.config.dns.servers[1],
        DnsServerConfig::Ip(SocketAddr::from(([192, 0, 2, 54], 5353)))
    );
    assert_eq!(
        parsed.config.dns.servers[2],
        DnsServerConfig::Ip(SocketAddr::new(
            IpAddr::V6("2001:db8::53".parse().unwrap()),
            53,
        ))
    );
    assert_eq!(
        parsed.config.dns.servers[3],
        DnsServerConfig::Ip(SocketAddr::new(
            IpAddr::V6("2001:db8::54".parse().unwrap()),
            5353,
        ))
    );
    assert_eq!(
        parsed.config.dns.servers[4],
        DnsServerConfig::Domain {
            domain: "dns.example".to_owned(),
            port: 53,
        }
    );
    assert_eq!(
        parsed.config.dns.servers[5],
        DnsServerConfig::Domain {
            domain: "dns-alt.example".to_owned(),
            port: 5353,
        }
    );
    assert!(parsed.config.dns.hosts[0]
        .matcher
        .matches("www.service.example"));
    assert_eq!(
        parsed.config.dns.hosts[0].target,
        DnsHostTarget::Domain("alias.example".to_owned())
    );
    assert_eq!(
        parsed.config.dns.hosts[1].target,
        DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)))
    );
}

#[test]
fn parses_tcp_dns_string_shorthand_as_default_policy() {
    let raw = raw_with_dns_servers(r#""tcp://192.0.2.53""#);

    let parsed = parse_xray_json(&raw).expect("TCP DNS shorthand should parse");
    assert_eq!(
        parsed.config.dns.servers,
        [DnsServerConfig::Policy(DnsNameServerConfig {
            endpoint: DnsServerEndpoint::Ip(SocketAddr::from(([192, 0, 2, 53], 53))),
            transport: DnsServerTransport::TcpRouted,
            domains: Vec::new(),
            expected_ips: DnsIpFilter::default(),
            unexpected_ips: DnsIpFilter::default(),
            tag: String::new(),
            timeout_ms: 0,
            skip_fallback: false,
            query_strategy: DnsQueryStrategy::UseIp,
            final_query: false,
        })]
    );
}

#[test]
fn parses_case_insensitive_tcp_dns_schemes_and_authority_forms() {
    let raw = raw_with_dns_servers(
        r#"
          "TcP://dns.example:5353",
          "TCP+LOCAL://[2001:db8::53]",
          "tcp+local://192.0.2.54:8053"
        "#,
    );

    let parsed = parse_xray_json(&raw).expect("TCP DNS authority forms should parse");
    let actual = parsed
        .config
        .dns
        .servers
        .iter()
        .map(|server| (server.transport(), server.endpoint()))
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        [
            (
                DnsServerTransport::TcpRouted,
                DnsServerEndpoint::Domain {
                    domain: "dns.example".to_owned(),
                    port: 5353,
                },
            ),
            (
                DnsServerTransport::TcpLocal,
                DnsServerEndpoint::Ip(SocketAddr::new(
                    IpAddr::V6("2001:db8::53".parse().unwrap()),
                    53,
                )),
            ),
            (
                DnsServerTransport::TcpLocal,
                DnsServerEndpoint::Ip(SocketAddr::from(([192, 0, 2, 54], 8053))),
            ),
        ]
    );
}

#[test]
fn tcp_dns_object_ignores_object_port_and_keeps_policy_fields() {
    let raw = raw_with_dns_servers(
        r#"{
          "address": "TCP://dns.example",
          "port": 5353,
          "domains": ["full:internal.example"],
          "skipFallback": true
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("TCP DNS object should parse");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("TCP DNS object must remain a policy server");
    };

    assert_eq!(
        (
            server.transport,
            &server.endpoint,
            server.domains[0].matches("internal.example"),
            server.skip_fallback,
        ),
        (
            DnsServerTransport::TcpRouted,
            &DnsServerEndpoint::Domain {
                domain: "dns.example".to_owned(),
                port: 53,
            },
            true,
            true,
        )
    );
}

#[test]
fn classic_dns_shorthands_report_classic_transport() {
    let raw = raw_with_dns_servers(r#""192.0.2.53", "dns.example""#);
    let parsed = parse_xray_json(&raw).expect("classic DNS shorthands should parse");

    assert!(parsed
        .config
        .dns
        .servers
        .iter()
        .all(|server| server.transport() == DnsServerTransport::Classic));
}

#[test]
fn rejects_non_authority_tcp_dns_urls() {
    for address in [
        "tcp://",
        "tcp:/dns.example",
        "tcp://user@dns.example",
        "tcp://dns.example/path",
        "tcp://dns.example?query",
        "tcp://dns.example#fragment",
        "tcp://2001:db8::53",
        "tcp://[2001:db8::53",
        "tcp://[not-an-ip]",
        "tcp://[192.0.2.53]",
        "tcp://dns.example:0",
        "tcp://dns.example:65536",
        "tcp://dns.example:+53",
        "tcp://dns.example:not-a-port",
        "tcp://dns example",
    ] {
        let raw = raw_with_dns_servers(&format!(r#""{address}""#));

        assert_parse_error_path(&raw, "$.dns.servers[0]");
    }
}

#[test]
fn rejects_invalid_tcp_dns_object_address_at_address_path() {
    let raw = raw_with_dns_servers(r#"{ "address": "tcp://dns.example/path", "port": 5353 }"#);

    assert_parse_error_path(&raw, "$.dns.servers[0].address");
}

#[test]
fn rejects_tunnel_local_tcp_dns_urls() {
    for address in [
        "tcp://198.18.0.1",
        "tcp://198.18.0.2:5353",
        "tcp+local://[::ffff:198.18.0.1]",
        "tcp+local://[::ffff:198.18.0.2]:5353",
    ] {
        let raw = raw_with_dns_servers(&format!(r#""{address}""#));

        assert_parse_error_path(&raw, "$.dns.servers[0]");
    }
}

#[test]
fn parses_xray_dns_server_objects_and_fallback_policy() {
    let raw = r#"{
        "dns": {
          "tag": "dns-global",
          "queryStrategy": "UseIP",
          "disableFallback": true,
          "disableFallbackIfMatch": true,
          "servers": [
            {
              "address": "192.0.2.53",
              "port": 5353,
              "domains": [
                "domain:internal.example",
                "full:resolver.example",
                "dotless:localhost",
                "dotless:"
              ],
              "tag": "dns-first",
              "timeoutMs": 1750,
              "skipFallback": true,
              "queryStrategy": "UseIPv4",
              "finalQuery": true
            },
            {
              "address": "dns.example",
              "tag": null,
              "domains": "keyword:corp,full:exact.example"
            }
          ]
        },
        "inbounds": [],
        "outbounds": [
          { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("object DNS servers should parse");
    assert!(parsed.config.dns.disable_fallback);
    assert!(parsed.config.dns.disable_fallback_if_match);
    assert_eq!(parsed.config.dns.tag, "dns-global");

    let DnsServerConfig::Policy(first) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };
    assert_eq!(
        first.endpoint,
        DnsServerEndpoint::Ip(SocketAddr::from(([192, 0, 2, 53], 5353)))
    );
    assert!(first.domains[0].matches("service.internal.example"));
    assert!(first.domains[1].matches("resolver.example"));
    assert!(!first.domains[1].matches("www.resolver.example"));
    assert!(first.domains[2].matches("my-localhost-service"));
    assert!(!first.domains[2].matches("localhost.example"));
    assert!(first.domains[3].matches("printer"));
    assert!(!first.domains[3].matches("printer.lan"));
    assert!(first.skip_fallback);
    assert_eq!(first.tag, "dns-first");
    assert_eq!(
        parsed.config.dns.servers[0].effective_tag(&parsed.config.dns.tag),
        "dns-first"
    );
    assert_eq!(first.timeout_ms, 1_750);
    assert_eq!(parsed.config.dns.servers[0].timeout_ms(), 1_750);
    assert_eq!(first.query_strategy, DnsQueryStrategy::UseIpv4);
    assert!(first.final_query);

    let DnsServerConfig::Policy(second) = &parsed.config.dns.servers[1] else {
        panic!("expected policy DNS server");
    };
    assert_eq!(
        second,
        &DnsNameServerConfig {
            endpoint: DnsServerEndpoint::Domain {
                domain: "dns.example".to_owned(),
                port: 53,
            },
            transport: DnsServerTransport::Classic,
            domains: second.domains.clone(),
            expected_ips: DnsIpFilter::default(),
            unexpected_ips: DnsIpFilter::default(),
            tag: String::new(),
            timeout_ms: 0,
            skip_fallback: false,
            query_strategy: DnsQueryStrategy::UseIp,
            final_query: false,
        }
    );
    assert!(second.domains[0].matches("my-corp-zone.example"));
    assert!(second.domains[1].matches("exact.example"));
    assert_eq!(
        parsed.config.dns.servers[1].effective_tag(&parsed.config.dns.tag),
        "dns-global"
    );
    assert_eq!(parsed.config.dns.servers[1].timeout_ms(), 4_000);
}

#[test]
fn applies_xray_dns_tag_inheritance_without_generating_runtime_tags() {
    for (global_tag, expected_global) in [
        (None, ""),
        (Some("null"), ""),
        (Some(r#""dns-global""#), "dns-global"),
    ] {
        let global_field = global_tag.map_or(String::new(), |value| format!(r#", "tag": {value}"#));
        let raw = format!(
            r#"{{
              "dns": {{
                "servers": [
                  "192.0.2.1",
                  {{ "address": "192.0.2.2" }},
                  {{ "address": "192.0.2.3", "tag": null }},
                  {{ "address": "192.0.2.4", "tag": "" }},
                  {{ "address": "192.0.2.5", "tag": "dns-override" }}
                ]{global_field}
              }},
              "inbounds": [],
              "outbounds": [{{ "protocol": "freedom", "tag": "direct" }}]
            }}"#
        );
        let parsed = parse_xray_json(&raw).expect("Xray DNS tags should parse");

        assert_eq!(parsed.config.dns.tag, expected_global);
        for server in &parsed.config.dns.servers[..4] {
            assert_eq!(
                server.effective_tag(&parsed.config.dns.tag),
                expected_global
            );
        }
        assert_eq!(
            parsed.config.dns.servers[4].effective_tag(&parsed.config.dns.tag),
            "dns-override"
        );
    }
}

#[test]
fn rejects_non_string_xray_dns_tags_at_the_exact_path() {
    for invalid in ["false", "42", "[]", "{}"] {
        let raw = format!(
            r#"{{
              "dns": {{ "tag": {invalid} }},
              "inbounds": [],
              "outbounds": [{{ "protocol": "freedom", "tag": "direct" }}]
            }}"#
        );
        assert_parse_error_path(&raw, "$.dns.tag");

        let raw = raw_with_dns_servers(&format!(
            r#"{{ "address": "192.0.2.53", "tag": {invalid} }}"#
        ));
        assert_parse_error_path(&raw, "$.dns.servers[0].tag");
    }
}

#[test]
fn parses_xray_dns_ip_filter_string_lists_and_soft_markers() {
    let raw = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": "*,192.0.2.0/24,!198.51.100.0/24",
          "unexpectedIPs": ["*", "10.0.0.0/8"]
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("DNS IP filters should parse");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };

    assert!(server.expected_ips.soft);
    assert_eq!(server.expected_ips.custom_matchers.len(), 2);
    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    assert!(!server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    assert!(server.unexpected_ips.soft);
    assert!(server
        .unexpected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(!server
        .unexpected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn dns_ip_filters_canonicalize_ipv4_mapped_literals_like_xray() {
    let raw = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": ["::ffff:192.0.2.0/24"]
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("mapped IPv4 DNS matcher should parse");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };
    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));

    let invalid = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": ["::ffff:192.0.2.0/120"]
        }"#,
    );
    assert_parse_error_path(&invalid, "$.dns.servers[0].expectedIPs[0]");
}

#[test]
fn dns_ip_filters_accept_xray_address_whitespace_brackets_and_empty_prefix() {
    let raw = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": "192.0.2.1, 198.51.100.1/,[2001:db8::1]"
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("Xray address forms should parse");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };

    assert_eq!(server.expected_ips.custom_matchers.len(), 3);
    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    assert!(server
        .expected_ips
        .matches(&IpAddr::V6("2001:db8::1".parse().unwrap())));
}

#[test]
fn uses_expect_ips_alias_only_when_expected_ips_is_empty() {
    let raw = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": [],
          "expectIPs": "192.0.2.0/24"
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("empty expectedIPs should use expectIPs");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };

    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
}

#[test]
fn treats_null_dns_ip_string_lists_as_empty() {
    let raw = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": null,
          "expectIPs": "192.0.2.0/24",
          "unexpectedIPs": null
        }, {
          "address": "192.0.2.54",
          "expectIPs": null
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("null StringList should behave as empty");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };

    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    assert!(server.unexpected_ips.is_empty());
    let DnsServerConfig::Policy(server_with_null_alias) = &parsed.config.dns.servers[1] else {
        panic!("expected policy DNS server");
    };
    assert!(server_with_null_alias.expected_ips.is_empty());
}

#[test]
fn nonempty_expected_ips_wins_without_parsing_expect_ips_rules() {
    let raw = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": ["*"],
          "expectIPs": ["not-an-ip"]
        }"#,
    );

    let parsed = parse_xray_json(&raw).expect("nonempty expectedIPs should suppress expectIPs");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };

    assert!(server.expected_ips.soft);
    assert!(server.expected_ips.is_empty());
}

#[test]
fn parses_dns_geoip_ext_rules_and_repeated_inverse_prefixes() {
    let asset_dir = unique_temp_dir("dns-ip-filters");
    write_geoip_dat(
        &asset_dir,
        "geoip.dat",
        &[TestGeoIp {
            code: "TEST".to_owned(),
            cidr: vec![geo_cidr(&[203, 0, 113, 0], 24)],
            reverse_match: false,
        }],
    );
    write_geoip_dat(
        &asset_dir,
        "custom-ip.dat",
        &[TestGeoIp {
            code: "CUSTOM".to_owned(),
            cidr: vec![geo_cidr(&[198, 51, 100, 0], 24)],
            reverse_match: false,
        }],
    );
    let raw = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": ["!!geoip:test", "ext:custom-ip.dat:custom"],
          "unexpectedIPs": ["!ext-ip:custom-ip.dat:custom"]
        }"#,
    );

    let parsed = parse_xray_json_with_geodata_dirs(&raw, std::slice::from_ref(&asset_dir))
        .expect("DNS geodata IP filters should parse");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };
    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    assert!(server
        .unexpected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert!(!server
        .unexpected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));

    fs::remove_dir_all(asset_dir).unwrap();
}

#[test]
fn dns_ip_filters_ignore_geoip_asset_reverse_flag() {
    let asset_dir = unique_temp_dir("dns-geoip-asset-reverse");
    write_geoip_dat(
        &asset_dir,
        "geoip.dat",
        &[TestGeoIp {
            code: "TEST".to_owned(),
            cidr: vec![geo_cidr(&[203, 0, 113, 0], 24)],
            reverse_match: true,
        }],
    );
    let raw = r#"{
      "dns": {
        "servers": [{
          "address": "192.0.2.53",
          "expectedIPs": ["geoip:test"]
        }]
      },
      "routing": {
        "rules": [{
          "type": "field",
          "ip": ["geoip:test"],
          "outboundTag": "direct"
        }]
      },
      "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    let parsed = parse_xray_json_with_geodata_dirs(raw, std::slice::from_ref(&asset_dir))
        .expect("DNS GeoIP filter should parse");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };
    let inside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let outside = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

    assert!(server.expected_ips.matches(&inside));
    assert!(!server.expected_ips.matches(&outside));
    assert!(!parsed.config.routing.rules[0].matches_ip(Some(&inside)));
    assert!(parsed.config.routing.rules[0].matches_ip(Some(&outside)));

    fs::remove_dir_all(asset_dir).unwrap();
}

#[test]
fn dns_geoip_private_uses_the_configured_xray_asset() {
    let asset_dir = unique_temp_dir("dns-geoip-private");
    write_geoip_dat(
        &asset_dir,
        "geoip.dat",
        &[TestGeoIp {
            code: "PRIVATE".to_owned(),
            cidr: vec![geo_cidr(&[203, 0, 113, 0], 24)],
            reverse_match: false,
        }],
    );
    let raw = raw_with_dns_servers(
        r#"{
          "address": "192.0.2.53",
          "expectedIPs": ["geoip:private"]
        }"#,
    );

    let parsed = parse_xray_json_with_geodata_dirs(&raw, std::slice::from_ref(&asset_dir))
        .expect("DNS geoip:private should load the Xray asset");
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };

    assert!(server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    assert!(!server
        .expected_ips
        .matches(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

    fs::remove_dir_all(asset_dir).unwrap();
}

#[test]
fn rejects_dns_server_object_strategy_disjoint_from_global_strategy() {
    let raw = r#"{
        "dns": {
          "queryStrategy": "UseIPv4",
          "servers": [{ "address": "192.0.2.53", "queryStrategy": "UseIPv6" }]
        },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;

    assert_parse_error_path(raw, "$.dns.servers[0].queryStrategy");
}

#[test]
fn rejects_invalid_dns_server_object_fields_with_precise_paths() {
    for (server, path) in [
        (r#"{}"#, "$.dns.servers[0].address"),
        (r#"{ "address": 42 }"#, "$.dns.servers[0].address"),
        (
            r#"{ "address": "192.0.2.53", "port": 65536 }"#,
            "$.dns.servers[0].port",
        ),
        (
            r#"{ "address": "192.0.2.53", "domains": [42] }"#,
            "$.dns.servers[0].domains[0]",
        ),
        (
            r#"{ "address": "192.0.2.53", "domains": ["dotless:bad.rule"] }"#,
            "$.dns.servers[0].domains[0]",
        ),
        (
            r#"{ "address": "192.0.2.53", "expectedIPs": 42 }"#,
            "$.dns.servers[0].expectedIPs",
        ),
        (
            r#"{ "address": "192.0.2.53", "expectedIPs": [42] }"#,
            "$.dns.servers[0].expectedIPs[0]",
        ),
        (
            r#"{ "address": "192.0.2.53", "expectedIPs": ["10.0.0.0/33"] }"#,
            "$.dns.servers[0].expectedIPs[0]",
        ),
        (
            r#"{ "address": "192.0.2.53", "unexpectedIPs": "not-an-ip" }"#,
            "$.dns.servers[0].unexpectedIPs[0]",
        ),
        (
            r#"{ "address": "192.0.2.53", "timeoutMs": -1 }"#,
            "$.dns.servers[0].timeoutMs",
        ),
        (
            r#"{ "address": "192.0.2.53", "timeoutMs": 1.5 }"#,
            "$.dns.servers[0].timeoutMs",
        ),
        (
            r#"{ "address": "192.0.2.53", "timeoutMs": "1000" }"#,
            "$.dns.servers[0].timeoutMs",
        ),
        (
            r#"{ "address": "192.0.2.53", "timeoutMs": true }"#,
            "$.dns.servers[0].timeoutMs",
        ),
        (
            r#"{ "address": "192.0.2.53", "timeoutMs": 1e3 }"#,
            "$.dns.servers[0].timeoutMs",
        ),
        (
            r#"{ "address": "192.0.2.53", "timeoutMs": [] }"#,
            "$.dns.servers[0].timeoutMs",
        ),
        (
            r#"{ "address": "192.0.2.53", "timeoutMs": {} }"#,
            "$.dns.servers[0].timeoutMs",
        ),
        (
            r#"{ "address": "192.0.2.53", "timeoutMs": 4611686018428 }"#,
            "$.dns.servers[0].timeoutMs",
        ),
        (
            r#"{ "address": "192.0.2.53", "expectedIPs": ["192.0.2.0/24"], "expectIPs": [42] }"#,
            "$.dns.servers[0].expectIPs[0]",
        ),
    ] {
        let raw = raw_with_dns_servers(server);
        assert_parse_error_path(&raw, path);
    }
}

#[test]
fn rejects_special_xray_dns_clients_until_their_transport_is_implemented() {
    for address in ["localhost", "LOCALHOST", "fakedns", "FakeDns"] {
        let raw = raw_with_dns_servers(&format!(r#"{{ "address": "{address}" }}"#));
        assert_parse_error_path(&raw, "$.dns.servers[0].address");
    }
}

#[test]
fn rejects_surrounding_whitespace_in_dns_server_addresses() {
    for (server, path) in [
        (r#"" dns.example""#, "$.dns.servers[0]"),
        (
            r#"{ "address": "dns.example " }"#,
            "$.dns.servers[0].address",
        ),
    ] {
        let raw = raw_with_dns_servers(server);
        assert_parse_error_path(&raw, path);
    }
}

#[test]
fn maps_zero_object_dns_server_port_to_xray_default() {
    let raw = raw_with_dns_servers(r#"{ "address": "192.0.2.53", "port": 0 }"#);
    let parsed = parse_xray_json(&raw).expect("Xray object port zero should mean port 53");

    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected policy DNS server");
    };
    assert_eq!(
        server.endpoint,
        DnsServerEndpoint::Ip(SocketAddr::from(([192, 0, 2, 53], 53)))
    );
}

#[test]
fn maps_zero_and_null_dns_timeout_to_default_and_accepts_safe_boundary() {
    for (timeout, raw_timeout, effective_timeout) in [
        ("0", 0, 4_000),
        ("null", 0, 4_000),
        ("4611686018427", 4_611_686_018_427, 4_611_686_018_427),
    ] {
        let raw = raw_with_dns_servers(&format!(
            r#"{{ "address": "192.0.2.53", "timeoutMs": {timeout} }}"#
        ));
        let parsed =
            parse_xray_json(&raw).expect("Xray zero-like timeout should select its default");

        let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
            panic!("expected policy DNS server");
        };
        assert_eq!(server.timeout_ms, raw_timeout);
        assert_eq!(parsed.config.dns.servers[0].timeout_ms(), effective_timeout);
    }
}

#[test]
fn parses_xray_dns_query_strategy_aliases() {
    for (raw_strategy, expected) in [
        ("UseIP", DnsQueryStrategy::UseIp),
        ("use_ip", DnsQueryStrategy::UseIp),
        ("use-ip", DnsQueryStrategy::UseIp),
        ("UseIP4", DnsQueryStrategy::UseIpv4),
        ("UseIPv4", DnsQueryStrategy::UseIpv4),
        ("use_ip4", DnsQueryStrategy::UseIpv4),
        ("use_ipv4", DnsQueryStrategy::UseIpv4),
        ("use_ip_v4", DnsQueryStrategy::UseIpv4),
        ("use-ip4", DnsQueryStrategy::UseIpv4),
        ("use-ipv4", DnsQueryStrategy::UseIpv4),
        ("use-ip-v4", DnsQueryStrategy::UseIpv4),
        ("UseIP6", DnsQueryStrategy::UseIpv6),
        ("UseIPv6", DnsQueryStrategy::UseIpv6),
        ("use_ip6", DnsQueryStrategy::UseIpv6),
        ("use_ipv6", DnsQueryStrategy::UseIpv6),
        ("use_ip_v6", DnsQueryStrategy::UseIpv6),
        ("use-ip6", DnsQueryStrategy::UseIpv6),
        ("use-ipv6", DnsQueryStrategy::UseIpv6),
        ("use-ip-v6", DnsQueryStrategy::UseIpv6),
    ] {
        let raw = raw_with_dns_query_strategy(&format!(r#""{raw_strategy}""#));
        let parsed = parse_xray_json(&raw).expect("queryStrategy alias should parse");

        assert_eq!(parsed.config.dns.query_strategy, expected, "{raw_strategy}");
    }
}

#[test]
fn rejects_dns_use_system_until_route_capability_is_available() {
    for strategy in [
        "UseSys",
        "UseSystem",
        "use_sys",
        "use_system",
        "use-sys",
        "use-system",
    ] {
        let raw = raw_with_dns_query_strategy(&format!(r#""{strategy}""#));
        let error = parse_xray_json(&raw).unwrap_err();

        assert_eq!(
            error.diagnostics[0].path.as_deref(),
            Some("$.dns.queryStrategy")
        );
        assert!(error.diagnostics[0]
            .message
            .contains("requires platform route capability"));
    }
}

#[test]
fn rejects_invalid_dns_query_strategy_with_path() {
    for raw_strategy in ["42", r#""prefer-fast""#, r#""use-i-p-v4""#] {
        let raw = raw_with_dns_query_strategy(raw_strategy);
        assert_parse_error_path(&raw, "$.dns.queryStrategy");
    }
}

#[test]
fn parses_dns_host_ip_array_preserving_address_order() {
    let raw = raw_with_dns_host_target(r#"["192.0.2.10", "2001:db8::10"]"#);
    let parsed = parse_xray_json(&raw).expect("DNS host IP array should parse");

    assert_eq!(
        parsed.config.dns.hosts[0].target,
        DnsHostTarget::Ips(vec![
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V6("2001:db8::10".parse().unwrap()),
        ])
    );
}

#[test]
fn unprefixed_dns_host_key_is_an_exact_match_like_xray() {
    let raw = r#"{
        "dns": { "hosts": { "proxy.example": "192.0.2.10" } },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;
    let parsed = parse_xray_json(raw).expect("bare DNS host key should parse");
    let mapping = &parsed.config.dns.hosts[0];

    assert!(mapping.matcher.matches("proxy.example"));
    assert!(!mapping.matcher.matches("www.proxy.example"));
    assert!(!mapping.matcher.matches("unrelated-proxy.example.test"));
    assert_eq!(
        mapping.target,
        DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
}

#[test]
fn unprefixed_dns_host_key_accepts_ip_arrays() {
    let raw = r#"{
        "dns": {
          "hosts": { "proxy.example": ["192.0.2.10", "2001:db8::10"] }
        },
        "inbounds": [],
        "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;
    let parsed = parse_xray_json(raw).expect("bare DNS host IP array should parse");

    assert!(parsed.config.dns.hosts[0].matcher.matches("proxy.example"));
    assert_eq!(
        parsed.config.dns.hosts[0].target,
        DnsHostTarget::Ips(vec![
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V6("2001:db8::10".parse().unwrap()),
        ])
    );
}

#[test]
fn rejects_empty_dns_host_ip_array_with_path() {
    let raw = raw_with_dns_host_target("[]");

    assert_parse_error_path(&raw, "$.dns.hosts.full:server.example");
}

#[test]
fn rejects_domain_in_dns_host_ip_array_with_item_path() {
    let raw = raw_with_dns_host_target(r#"["192.0.2.10", "alias.example"]"#);

    assert_parse_error_path(&raw, "$.dns.hosts.full:server.example[1]");
}

#[test]
fn rejects_non_string_in_dns_host_ip_array_with_item_path() {
    let raw = raw_with_dns_host_target(r#"["192.0.2.10", 42]"#);

    assert_parse_error_path(&raw, "$.dns.hosts.full:server.example[1]");
}

#[test]
fn rejects_non_string_or_array_dns_host_target_with_path() {
    let raw = raw_with_dns_host_target(r#"{ "address": "192.0.2.10" }"#);

    assert_parse_error_path(&raw, "$.dns.hosts.full:server.example");
}

#[test]
fn accepts_eight_dns_servers() {
    let raw = raw_with_dns_servers(
        r#"
          "192.0.2.1",
          "192.0.2.2",
          "192.0.2.3",
          "192.0.2.4",
          "192.0.2.5",
          "192.0.2.6",
          "192.0.2.7",
          "192.0.2.8"
        "#,
    );

    let parsed = parse_xray_json(&raw).expect("eight DNS servers should be supported");

    assert_eq!(parsed.config.dns.servers.len(), 8);
}

#[test]
fn rejects_more_than_eight_dns_servers() {
    let raw = raw_with_dns_servers(
        r#"
          "192.0.2.1",
          "192.0.2.2",
          "192.0.2.3",
          "192.0.2.4",
          "192.0.2.5",
          "192.0.2.6",
          "192.0.2.7",
          "192.0.2.8",
          "192.0.2.9"
        "#,
    );

    let error = parse_xray_json(&raw).unwrap_err();

    assert_eq!(error.diagnostics[0].path.as_deref(), Some("$.dns.servers"));
    assert!(error.diagnostics[0].message.contains("9 servers"));
    assert!(error.diagnostics[0]
        .message
        .contains("maximum supported per configuration is 8"));
}

#[test]
fn rejects_zero_port_for_ipv4_dns_server() {
    assert_dns_server_zero_port_rejected("192.0.2.53:0");
}

#[test]
fn rejects_zero_port_for_bracketed_ipv6_dns_server() {
    assert_dns_server_zero_port_rejected("[2001:db8::53]:0");
}

#[test]
fn rejects_zero_port_for_domain_dns_server() {
    assert_dns_server_zero_port_rejected("dns.example:0");
}

#[test]
fn rejects_tunnel_local_dns_addresses_as_upstreams() {
    for server in [
        "198.18.0.1",
        "198.18.0.1:53",
        "::ffff:198.18.0.1",
        "[::ffff:198.18.0.1]:53",
        "198.18.0.1:5353",
        "[::ffff:198.18.0.1]:5353",
        "198.18.0.2",
        "198.18.0.2:53",
        "::ffff:198.18.0.2",
        "[::ffff:198.18.0.2]:53",
        "198.18.0.2:5353",
        "[::ffff:198.18.0.2]:5353",
    ] {
        let raw = raw_with_dns_servers(&format!(r#""{server}""#));
        let error = parse_xray_json(&raw).unwrap_err();

        assert_eq!(
            error.diagnostics[0].path.as_deref(),
            Some("$.dns.servers[0]")
        );
        assert_eq!(
            error.diagnostics[0].message,
            "dns server cannot point at a tunnel-local DNS address"
        );
    }
}

#[test]
fn parses_bracketed_ipv6_dns_server_with_numeric_scope_id() {
    let raw = raw_with_dns_servers(r#""[fe80::53%2]:5353""#);
    let parsed = parse_xray_json(&raw).unwrap();

    let DnsServerConfig::Ip(SocketAddr::V6(server)) = parsed.config.dns.servers[0] else {
        panic!("numeric IPv6 scope id must remain an IP-literal upstream");
    };
    assert_eq!(server.ip(), &"fe80::53".parse::<Ipv6Addr>().unwrap());
    assert_eq!(server.scope_id(), 2);
    assert_eq!(server.port(), 5353);
}

#[test]
fn parses_policy_level_fields_as_optional_values() {
    let raw = r#"{
        "policy": {
          "levels": {
            "0": {
              "handshake": 10,
              "connIdle": 300,
              "bufferSize": 8,
              "statsUserUplink": true
            },
            "8": {
              "statsUserDownlink": true
            }
          }
        },
        "inbounds": [],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    let level0 = parsed.config.policy.levels.get(&0).expect("level 0");
    assert_eq!(level0.handshake, Some(10));
    assert_eq!(level0.conn_idle, Some(300));
    assert_eq!(level0.uplink_only, None);
    assert_eq!(level0.downlink_only, None);
    assert_eq!(level0.buffer_size, Some(8));
    assert!(level0.stats_user_uplink);

    let level8 = parsed.config.policy.levels.get(&8).expect("level 8");
    assert_eq!(level8.handshake, None);
    assert_eq!(level8.conn_idle, None);
    assert_eq!(level8.buffer_size, None);
    assert!(level8.stats_user_downlink);
}

#[test]
fn rejects_unsupported_outbound_protocol_with_path() {
    let raw = r#"{
        "inbounds": [],
        "outbounds": [
            { "protocol": "trojan", "settings": {} }
        ]
    }"#;

    let err = parse_xray_json(raw).unwrap_err();
    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(
        err.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].protocol")
    );
}

#[test]
fn rejects_invalid_reality_public_key_length_with_path() {
    let raw = r#"{
        "inbounds": [],
        "outbounds": [{
        "tag": "proxy",
        "protocol": "vless",
        "settings": { "vnext": [{ "address": "server.example", "port": 443, "users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }] }] },
        "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "serverName": "server.example", "fingerprint": "chrome", "publicKey": "AQE", "shortId": "02030405" } }
      }]
    }"#;

    let err = parse_xray_json(raw).unwrap_err();
    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(
        err.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].streamSettings.realitySettings.publicKey")
    );
}

#[test]
fn rejects_invalid_reality_public_key_tail_bits_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF",
        "02030405",
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.publicKey",
    );
}

#[test]
fn rejects_missing_vless_users_with_path() {
    let raw = vless_raw("", "", 443, valid_public_key(), "02030405");

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].users");
}

#[test]
fn rejects_empty_vless_users_with_path() {
    let raw = vless_raw(r#""users": []"#, "", 443, valid_public_key(), "02030405");

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].users");
}

#[test]
fn rejects_empty_vless_server_address_with_path() {
    let raw = vless_raw_with_address(
        "",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].address");
}

#[test]
fn rejects_zero_vless_port_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        0,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].port");
}

#[test]
fn rejects_unsupported_vless_user_encryption_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "aes-128-gcm" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].users[0].encryption");
}

#[test]
fn accepts_missing_none_and_explicit_none_vless_user_encryption() {
    for users in [
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "none" }]"#,
    ] {
        let raw = vless_raw(users, "", 443, valid_public_key(), "02030405");

        let parsed = parse_xray_json(&raw).expect("config should parse");
        let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings else {
            panic!("expected vless outbound");
        };
        assert_eq!(vless.users[0].encryption, "none");
    }
}

#[test]
fn plaintext_vless_accepts_xray_private_test_and_dotless_servers() {
    for address in [
        "10.42.0.1",
        "192.0.2.10",
        "::1",
        "[::1]",
        "[ ::1 ]",
        "fc00::1",
        "printer.LAN.",
        "EDGE",
    ] {
        let raw = raw_with_stream_settings_and_address(
            address,
            r#""network": "tcp", "security": "none""#,
        );
        parse_xray_json(&raw).unwrap_or_else(|error| panic!("{address} should be exempt: {error}"));
    }
}

#[test]
fn plaintext_vless_intentionally_rejects_public_legacy_vnext_servers() {
    // Xray v26.7.28 accidentally applies this guard only to its simplified
    // top-level VLESS shape. The supported xray-rust `vnext` shape is stricter
    // by design so a legacy profile cannot silently retain public plaintext.
    for address in [
        "8.8.8.8",
        "2606:4700:4700::1111",
        "[2606:4700:4700::1111]",
        "proxy.example.com",
        "123",
    ] {
        let raw = raw_with_stream_settings_and_address(
            address,
            r#""network": "tcp", "security": "none""#,
        );
        let error = parse_xray_json(&raw).unwrap_err();
        assert_eq!(
            error.diagnostics[0].path.as_deref(),
            Some("$.outbounds[0].settings.vnext[0].address")
        );
        assert_eq!(
            error.diagnostics[0].message,
            "vless without TLS or other encryption is prohibited unless the server address is a private IP or domain"
        );
    }

    for stream_settings in [r#""network": "tcp""#, r#""network": "tcp", "security": """#] {
        let raw = raw_with_stream_settings_and_address("proxy.example.com", stream_settings);
        assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].address");
    }
}

#[test]
fn public_vless_servers_remain_valid_with_tls_or_reality() {
    let tls = raw_with_stream_settings_and_address(
        "proxy.example.com",
        r#""network": "tcp", "security": "tls", "tlsSettings": { "serverName": "proxy.example.com" }"#,
    );
    parse_xray_json(&tls).expect("TLS should permit a public VLESS server");

    let reality = vless_raw_with_address(
        "2606:4700:4700::1111",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "none" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );
    parse_xray_json(&reality).expect("REALITY should permit a public VLESS server");
}

#[test]
fn accepts_vless_user_security_auto_and_parses_level() {
    let raw = vless_raw(
        r#""users": [{
          "id": "00010203-0405-0607-0809-0a0b0c0d0e0f",
          "security": "auto",
          "level": 8
        }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    let parsed = parse_xray_json(&raw).expect("config should parse");
    let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings else {
        panic!("expected vless outbound");
    };

    assert_eq!(vless.users[0].level, 8);
}

#[test]
fn rejects_unsupported_vless_user_flow_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "flow": "xtls-rprx-direct" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].users[0].flow");
}

#[test]
fn accepts_missing_empty_and_vision_vless_user_flow() {
    for (users, expected_flow) in [
        (
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
            None,
        ),
        (
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "flow": "" }]"#,
            None,
        ),
        (
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "flow": "xtls-rprx-vision" }]"#,
            Some("xtls-rprx-vision"),
        ),
        (
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "flow": "xtls-rprx-vision-udp443" }]"#,
            Some("xtls-rprx-vision-udp443"),
        ),
    ] {
        let raw = vless_raw(users, "", 443, valid_public_key(), "02030405");

        let parsed = parse_xray_json(&raw).expect("config should parse");
        let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings else {
            panic!("expected vless outbound");
        };
        assert_eq!(vless.users[0].flow.as_deref(), expected_flow);
    }
}

#[test]
fn rejects_multiple_vless_vnext_entries_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        r#", { "address": "backup.example", "port": 443, "users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }] }"#,
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext");
}

#[test]
fn rejects_malformed_reality_short_id_with_path() {
    for short_id in ["123", "0203040z", "000102030405060708"] {
        let raw = vless_raw(
            r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
            "",
            443,
            valid_public_key(),
            short_id,
        );

        assert_parse_error_path(
            &raw,
            "$.outbounds[0].streamSettings.realitySettings.shortId",
        );
    }
}

#[test]
fn rejects_vless_port_overflow_with_path() {
    let raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        65536,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].settings.vnext[0].port");
}

#[test]
fn parses_raw_stream_network_alias() {
    let raw = vless_raw_with_network(
        "raw",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    let parsed = parse_xray_json(&raw).expect("`raw` network alias should parse");

    assert_eq!(parsed.config.outbounds[0].stream.network, Network::Tcp);
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn rejects_udp_stream_network_with_path() {
    let raw = vless_raw_with_network(
        "udp",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.network");
}

#[test]
fn rejects_other_stream_network_with_path() {
    // The example moved off `grpc` when this crate learned to parse it; `kcp`
    // is still a network xray-core has and xray-rust does not.
    let raw = vless_raw_with_network(
        "kcp",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.network");
}

#[test]
fn rejects_non_string_stream_network_with_path() {
    // Falling back to `tcp` here would dial plain TCP against a server
    // expecting the transport the rest of `streamSettings` describes.
    assert_parse_error_path(
        &raw_with_stream_settings(r#""network": 5, "security": "none""#),
        "$.outbounds[0].streamSettings.network",
    );
}

#[test]
fn null_stream_network_selects_raw_like_xray_pointer_config() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": null, "security": "none""#,
    ))
    .expect("null network is an absent TransportProtocol pointer");

    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::Raw
    ));
}

#[test]
fn stream_method_alias_has_priority_but_both_fields_require_string_shape() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""method": "raw", "network": "not-a-transport", "security": "none""#,
    ))
    .expect("method must override the legacy network spelling");
    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::Raw
    ));

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""method": null, "network": "ws", "security": "none", "wsSettings": {}"#,
    ))
    .expect("null method must fall through to network");
    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::WebSocket(_)
    ));

    assert_parse_error_path(
        &raw_with_stream_settings(r#""method": "raw", "network": 5, "security": "none""#),
        "$.outbounds[0].streamSettings.network",
    );
    assert_parse_error_path(
        &raw_with_stream_settings(r#""method": 5, "network": "raw", "security": "none""#),
        "$.outbounds[0].streamSettings.method",
    );
}

#[test]
fn uppercase_stream_networks_parse_the_way_xray_lowercases_them() {
    for network in ["RAW", "TCP", "Raw"] {
        let parsed = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none""#
        )))
        .unwrap_or_else(|_| panic!("`{network}` must parse as the raw transport"));

        assert_eq!(
            parsed.config.outbounds[0].stream.transport,
            StreamTransport::Raw
        );
    }

    for network in ["WS", "WebSocket"] {
        let parsed = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none""#
        )))
        .unwrap_or_else(|_| panic!("`{network}` must parse as the websocket transport"));

        assert!(matches!(
            parsed.config.outbounds[0].stream.transport,
            StreamTransport::WebSocket(_)
        ));
    }
}

#[test]
fn rejects_non_string_stream_security_with_path() {
    // Defaulting to `none` would silently strip TLS off the outbound and send
    // the tunnel out in plaintext.
    assert_parse_error_path(
        &raw_with_stream_settings(r#""network": "tcp", "security": 5"#),
        "$.outbounds[0].streamSettings.security",
    );
}

#[test]
fn rejects_null_stream_security_with_path() {
    assert_parse_error_path(
        &raw_with_stream_settings(r#""network": "tcp", "security": null"#),
        "$.outbounds[0].streamSettings.security",
    );
}

#[test]
fn uppercase_stream_security_parses_the_way_xray_lowercases_it() {
    for security in ["NONE", "None"] {
        let parsed = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "tcp", "security": "{security}""#
        )))
        .unwrap_or_else(|_| panic!("`{security}` must parse as no stream security"));

        assert_eq!(
            parsed.config.outbounds[0].stream.security,
            StreamSecurity::None
        );
    }

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "tcp", "security": "TLS",
           "tlsSettings": {"serverName": "server.example"}"#,
    ))
    .expect("`TLS` must parse as tls");

    assert!(matches!(
        parsed.config.outbounds[0].stream.security,
        StreamSecurity::Tls(_)
    ));
}

#[test]
fn empty_stream_security_means_none_like_xray() {
    // Xray's arm is `case "", "none":`, and generated configs lean on it.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "tcp", "security": """#,
    ))
    .expect("an empty security must parse as no stream security");

    assert_eq!(
        parsed.config.outbounds[0].stream.security,
        StreamSecurity::None
    );
}

#[test]
fn removed_xtls_security_says_it_was_removed() {
    let error = parse_xray_json(&raw_with_stream_settings(
        r#""network": "tcp", "security": "xtls""#,
    ))
    .expect_err("legacy xtls must be rejected");

    assert_eq!(
        error.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].streamSettings.security")
    );
    assert!(
        error.diagnostics[0].message.contains("removed"),
        "xtls must say it was removed, got: {:?}",
        error.diagnostics
    );
}

#[test]
fn tcp_and_raw_networks_parse_as_the_raw_transport() {
    for network in ["tcp", "raw"] {
        let parsed = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none""#
        )))
        .expect("the raw transport must parse");

        assert_eq!(
            parsed.config.outbounds[0].stream.transport,
            StreamTransport::Raw
        );
    }
}

#[test]
fn ws_network_parses_with_its_settings() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/chat", "host": "cdn.example.com",
                          "headers": {"X-Thing": "v"}, "heartbeatPeriod": 30}"#,
    ))
    .expect("a ws outbound must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/chat");
    assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
    assert_eq!(ws.headers, vec![("X-Thing".to_owned(), "v".to_owned())]);
    assert_eq!(ws.heartbeat_period_secs, 30);
    assert_eq!(ws.early_data_bytes, 0);
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn websocket_is_an_alias_for_ws() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "websocket", "security": "none""#,
    ))
    .expect("the websocket alias must parse");

    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::WebSocket(_)
    ));
    assert_eq!(parsed.config.outbounds[0].stream.network, Network::Tcp);
}

#[test]
fn httpupgrade_network_parses_with_its_settings() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "httpupgrade", "security": "none",
           "httpupgradeSettings": {"path": "/up?ed=32", "host": "cdn.example.com",
                                   "headers": {"X-Thing": "v"}}"#,
    ))
    .expect("an httpupgrade outbound must parse");

    let StreamTransport::HttpUpgrade(httpupgrade) = &parsed.config.outbounds[0].stream.transport
    else {
        panic!("expected an httpupgrade transport");
    };
    assert_eq!(httpupgrade.path, "/up");
    assert_eq!(httpupgrade.host.as_deref(), Some("cdn.example.com"));
    assert_eq!(
        httpupgrade.headers,
        vec![("X-Thing".to_owned(), "v".to_owned())]
    );
    assert_eq!(httpupgrade.early_data_bytes, 32);
    assert_eq!(parsed.config.outbounds[0].stream.network, Network::Tcp);
}

#[test]
fn a_network_without_its_settings_block_still_gets_a_transport() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "httpupgrade", "security": "none""#,
    ))
    .expect("an omitted settings block must parse");

    let StreamTransport::HttpUpgrade(httpupgrade) = &parsed.config.outbounds[0].stream.transport
    else {
        panic!("expected an httpupgrade transport");
    };
    assert_eq!(httpupgrade.path, "/");
    assert_eq!(httpupgrade.host, None);
    assert!(httpupgrade.headers.is_empty());
}

#[test]
fn grpc_network_parses_with_its_settings() {
    // Every key `GRPCConfig` declares, spelled as it is spelled there
    // (`Xray-core/infra/conf/grpc.go:8-17`): five snake_case, `serviceName`
    // and `multiMode` camelCase, `authority` neither. Go's decoder matches the
    // tag, so a camelCase `idleTimeout` reaches xray-core as nothing at all.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "grpc", "security": "none",
           "grpcSettings": {"authority": "authority.example",
                            "serviceName": "GunService",
                            "multiMode": true,
                            "user_agent": "custom-agent/1.0",
                            "idle_timeout": 60,
                            "health_check_timeout": 20,
                            "permit_without_stream": true,
                            "initial_windows_size": 65536}"#,
    ))
    .expect("a grpc outbound must parse");

    let StreamTransport::Grpc(grpc) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a grpc transport");
    };
    assert_eq!(grpc.authority.as_deref(), Some("authority.example"));
    assert_eq!(grpc.service_name, "GunService");
    assert!(grpc.multi_mode);
    assert_eq!(grpc.user_agent.as_deref(), Some("custom-agent/1.0"));
    assert_eq!(grpc.idle_timeout_secs, 60);
    assert_eq!(grpc.health_check_timeout_secs, 20);
    assert!(grpc.permit_without_stream);
    assert_eq!(grpc.initial_windows_size, 65_536);
    assert_eq!(parsed.config.outbounds[0].stream.network, Network::Tcp);
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn a_grpc_network_without_its_settings_block_still_gets_a_transport() {
    // `StreamConfig.Build` only appends a transport entry when the block is
    // present, and `GetTransportSettingsFor` then falls through to
    // `CreateTransportConfig` for a zero-valued one
    // (`Xray-core/transport/internet/config.go:71-81`). A zero `serviceName`
    // is what makes the stock client dial `//Tun`.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "grpc", "security": "none""#,
    ))
    .expect("an omitted grpcSettings block must parse");

    let StreamTransport::Grpc(grpc) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a grpc transport");
    };
    assert_eq!(grpc.authority, None);
    assert_eq!(grpc.service_name, "");
    assert!(!grpc.multi_mode);
    assert_eq!(grpc.user_agent, None);
    assert_eq!(grpc.idle_timeout_secs, 0);
    assert_eq!(grpc.health_check_timeout_secs, 0);
    assert!(!grpc.permit_without_stream);
    assert_eq!(grpc.initial_windows_size, 0);
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn negative_grpc_numbers_clamp_to_zero_instead_of_failing() {
    // The only validation `GRPCConfig.Build` performs: three negative-to-zero
    // clamps (`Xray-core/infra/conf/grpc.go:20-29`). Rejecting these would
    // refuse a config xray-core accepts and quietly normalizes.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "grpc", "security": "none",
           "grpcSettings": {"idle_timeout": -1,
                            "health_check_timeout": -5,
                            "initial_windows_size": -100}"#,
    ))
    .expect("negative grpc numbers must parse");

    let StreamTransport::Grpc(grpc) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a grpc transport");
    };
    assert_eq!(grpc.idle_timeout_secs, 0);
    assert_eq!(grpc.health_check_timeout_secs, 0);
    assert_eq!(grpc.initial_windows_size, 0);
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn rejects_grpc_numbers_past_int32_with_path() {
    // The clamp is the *only* normalization; the width still binds. Go's
    // decoder refuses one past `int32` outright — "cannot unmarshal number
    // 2147483648 into Go struct field GRPCConfig.idle_timeout of type int32" —
    // so silently truncating would be more permissive than the reference.
    for key in [
        "idle_timeout",
        "health_check_timeout",
        "initial_windows_size",
    ] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "grpc", "security": "none",
                   "grpcSettings": {{"{key}": 2147483648}}"#
            )),
            &format!("$.outbounds[0].streamSettings.grpcSettings.{key}"),
        );
    }
}

#[test]
fn an_arbitrary_grpc_user_agent_is_passed_through() {
    // `user_agent` reaches `grpc.Config` untouched; the magic values are
    // resolved at dial time (`transport/internet/grpc/dial.go:193-205`), so
    // anything else is a literal UA rather than a config error.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "grpc", "security": "none",
           "grpcSettings": {"user_agent": "not-a-known-browser"}"#,
    ))
    .expect("an arbitrary grpc user agent must parse");

    let StreamTransport::Grpc(grpc) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a grpc transport");
    };
    assert_eq!(grpc.user_agent.as_deref(), Some("not-a-known-browser"));
}

#[test]
fn rejects_non_string_grpc_service_name_with_path() {
    // Go fails the whole config here — "cannot unmarshal number into Go struct
    // field GRPCConfig.serviceName of type string" — so a silent default would
    // dial `//Tun` against a server expecting a named service.
    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "grpc", "security": "none", "grpcSettings": {"serviceName": 5}"#,
        ),
        "$.outbounds[0].streamSettings.grpcSettings.serviceName",
    );
}

#[test]
fn rejects_camel_case_grpc_key_spellings_with_path() {
    // The camelCase spelling of each of the five snake_case keys. Go's decoder
    // matches the struct tag, so `idleTimeout` is an unknown key upstream and
    // is dropped without a word; accepting it would make a config work here
    // that does nothing there.
    for key in [
        "idleTimeout",
        "healthCheckTimeout",
        "permitWithoutStream",
        "initialWindowsSize",
        "userAgent",
    ] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "grpc", "security": "none", "grpcSettings": {{"{key}": 1}}"#
            )),
            &format!("$.outbounds[0].streamSettings.grpcSettings.{key}"),
        );
    }
}

#[test]
fn rejects_the_gun_stream_network_with_path() {
    // `gun` was the transport's original name, but v26.7.28 has no such arm in
    // `TransportProtocol.Build` and no `gunSettings` key anywhere in the tree:
    // both are "unknown transport protocol: gun". Accepting either would let a
    // profile parse here and fail against a real server.
    assert_parse_error_path(
        &raw_with_stream_settings(r#""network": "gun", "security": "none""#),
        "$.outbounds[0].streamSettings.network",
    );
    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "grpc", "security": "none", "gunSettings": {"serviceName": "S"}"#,
        ),
        "$.outbounds[0].streamSettings.gunSettings",
    );
}

#[test]
fn xhttp_and_splithttp_aliases_parse_with_xray_defaults() {
    for (network, settings_key) in [
        ("xhttp", "xhttpSettings"),
        ("splithttp", "splithttpSettings"),
    ] {
        let parsed = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none", "{settings_key}": {{}}"#
        )))
        .unwrap_or_else(|error| panic!("{network} must parse: {error:?}"));

        let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
            panic!("expected xhttp for {network}");
        };
        assert_eq!(xhttp.mode, XhttpMode::Auto);
        assert_eq!(xhttp.x_padding_key, "x_padding");
        assert_eq!(xhttp.x_padding_header, "X-Padding");
        assert_eq!(
            xhttp.x_padding_placement,
            XhttpPaddingPlacement::QueryInHeader
        );
        assert_eq!(xhttp.x_padding_method, XhttpPaddingMethod::RepeatX);
        assert_eq!(xhttp.uplink_http_method, "POST");
        assert_eq!(xhttp.session_placement, XhttpPlacement::Path);
        assert_eq!(xhttp.seq_placement, XhttpPlacement::Path);
        assert_eq!(xhttp.uplink_data_placement, XhttpUplinkDataPlacement::Auto);
        assert_eq!(xhttp.uplink_data_key, "X-Data");
        assert_eq!(xhttp.xmux.max_concurrency, XhttpRange::default());
        assert_eq!(xhttp.xmux.max_connections, XhttpRange { from: 3, to: 3 });
        assert_eq!(
            xhttp.xmux.h_max_request_times,
            XhttpRange { from: 600, to: 900 }
        );
        assert_eq!(
            xhttp.xmux.h_max_reusable_secs,
            XhttpRange {
                from: 1_800,
                to: 3_000
            }
        );
        assert!(
            parsed.diagnostics.is_empty(),
            "{network}: {:?}",
            parsed.diagnostics
        );
    }
}

#[test]
fn xhttp_null_value_fields_normalize_to_go_zero_defaults() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "host": null, "path": null, "mode": null, "headers": null,
             "xPaddingBytes": null, "xPaddingObfsMode": null,
             "xPaddingKey": null, "xPaddingHeader": null,
             "xPaddingPlacement": null, "xPaddingMethod": null,
             "uplinkHTTPMethod": null,
             "sessionIDPlacement": null, "sessionIDKey": null,
             "sessionIDTable": null, "sessionIDLength": null,
             "seqPlacement": null, "seqKey": null,
             "uplinkDataPlacement": null, "uplinkDataKey": null,
             "uplinkChunkSize": null,
             "noGRPCHeader": null, "noSSEHeader": null,
             "scMaxEachPostBytes": null, "scMinPostsIntervalMs": null,
             "scMaxBufferedPosts": null, "scStreamUpServerSecs": null,
             "serverMaxHeaderBytes": null, "xmux": null,
             "downloadSettings": null
           }"#,
    ))
    .expect("null must leave every non-pointer Go field at its zero value");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.as_ref(), &XhttpSettings::default());
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

#[test]
fn xhttp_null_header_value_and_xmux_fields_follow_go_decoding() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "headers": {"X-Null": null},
             "xmux": {
               "maxConcurrency": null, "maxConnections": null,
               "cMaxReuseTimes": null, "hMaxRequestTimes": null,
               "hMaxReusableSecs": null, "hKeepAlivePeriod": null
             }
           }"#,
    ))
    .expect("null map values and xmux fields must decode to Go zero values");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    let expected = XhttpSettings {
        headers: vec![("X-Null".to_owned(), String::new())],
        ..XhttpSettings::default()
    };
    assert_eq!(xhttp.as_ref(), &expected);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

#[test]
fn xhttp_case_variant_headers_canonicalize_without_losing_values() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "headers": {"X-Foo": "first", "x-foo": "second"}
           }"#,
    ))
    .expect("case-variant XHTTP headers must preserve both Add values");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(
        xhttp.headers,
        vec![
            ("X-Foo".to_owned(), "first".to_owned()),
            ("X-Foo".to_owned(), "second".to_owned()),
        ]
    );
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

#[test]
fn xhttp_full_v26_7_28_config_surface_is_normalized() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "host": "cdn.example.com", "path": "/split", "mode": "packet-up",
             "headers": {"X-Test": "yes"},
             "xPaddingBytes": "1000-100", "xPaddingObfsMode": true,
             "xPaddingKey": "pad", "xPaddingHeader": "X-Pad",
             "xPaddingPlacement": "cookie", "xPaddingMethod": "tokenish",
             "uplinkHTTPMethod": "get",
             "sessionIDPlacement": "header", "sessionIDTable": "Base62",
             "sessionIDLength": "9-6", "seqPlacement": "query",
             "uplinkDataPlacement": "cookie", "uplinkChunkSize": 4096,
             "noGRPCHeader": true, "noSSEHeader": true,
             "scMaxEachPostBytes": "2000000-1000000",
             "scMinPostsIntervalMs": "20", "scMaxBufferedPosts": 31,
             "scStreamUpServerSecs": "90-120", "serverMaxHeaderBytes": 8192,
             "xmux": {
               "maxConnections": "4-2", "cMaxReuseTimes": 8,
               "hMaxRequestTimes": "50-60", "hMaxReusableSecs": 300,
               "hKeepAlivePeriod": 15
             }
           }"#,
    ))
    .expect("the complete supported XHTTP surface must parse");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("cdn.example.com"));
    assert_eq!(xhttp.path, "/split");
    assert_eq!(xhttp.mode, XhttpMode::PacketUp);
    assert_eq!(xhttp.headers, vec![("X-Test".to_owned(), "yes".to_owned())]);
    assert_eq!(
        xhttp.x_padding_bytes,
        XhttpRange {
            from: 100,
            to: 1000
        }
    );
    assert!(xhttp.x_padding_obfs_mode);
    assert_eq!(xhttp.x_padding_key, "pad");
    assert_eq!(xhttp.x_padding_header, "X-Pad");
    assert_eq!(xhttp.x_padding_placement, XhttpPaddingPlacement::Cookie);
    assert_eq!(xhttp.x_padding_method, XhttpPaddingMethod::Tokenish);
    assert_eq!(xhttp.uplink_http_method, "GET");
    assert_eq!(xhttp.session_placement, XhttpPlacement::Header);
    assert_eq!(xhttp.session_key, "X-Session");
    assert_eq!(xhttp.session_id_table, "Base62");
    assert_eq!(xhttp.session_id_length, XhttpRange { from: 6, to: 9 });
    assert_eq!(xhttp.seq_placement, XhttpPlacement::Query);
    assert_eq!(xhttp.seq_key, "x_seq");
    assert_eq!(
        xhttp.uplink_data_placement,
        XhttpUplinkDataPlacement::Cookie
    );
    assert_eq!(xhttp.uplink_data_key, "x_data");
    assert_eq!(
        xhttp.uplink_chunk_size,
        XhttpRange {
            from: 4096,
            to: 4096
        }
    );
    assert!(xhttp.no_grpc_header);
    assert!(xhttp.no_sse_header);
    assert_eq!(
        xhttp.sc_max_each_post_bytes,
        XhttpRange {
            from: 1_000_000,
            to: 2_000_000
        }
    );
    assert_eq!(
        xhttp.sc_min_posts_interval_ms,
        XhttpRange { from: 20, to: 20 }
    );
    assert_eq!(xhttp.sc_max_buffered_posts, 31);
    assert_eq!(
        xhttp.sc_stream_up_server_secs,
        XhttpRange { from: 90, to: 120 }
    );
    assert_eq!(xhttp.server_max_header_bytes, 8192);
    assert_eq!(xhttp.xmux.max_connections, XhttpRange { from: 2, to: 4 });
    assert_eq!(xhttp.xmux.max_concurrency, XhttpRange::default());
    assert_eq!(xhttp.xmux.c_max_reuse_times, XhttpRange { from: 8, to: 8 });
    assert_eq!(xhttp.xmux.h_keep_alive_period_secs, 15);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

#[test]
fn xhttp_settings_take_priority_over_splithttp_settings() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "splithttp", "security": "none",
           "splithttpSettings": {"host": "legacy.example", "mode": "packet-up"},
           "xhttpSettings": {"host": "current.example", "mode": "stream-one"}"#,
    ))
    .expect("the current XHTTP spelling must win");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("current.example"));
    assert_eq!(xhttp.mode, XhttpMode::StreamOne);
    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.path.as_deref() == Some("$.outbounds[0].streamSettings.splithttpSettings")
            && diagnostic.message.contains("takes priority")
    }));
}

#[test]
fn null_xhttp_aliases_are_absent_go_pointers() {
    let assert_zero_xmux = |xhttp: &XhttpSettings| {
        assert_eq!(xhttp.xmux.max_concurrency, XhttpRange::default());
        assert_eq!(xhttp.xmux.max_connections, XhttpRange::default());
        assert_eq!(xhttp.xmux.c_max_reuse_times, XhttpRange::default());
        assert_eq!(xhttp.xmux.h_max_request_times, XhttpRange::default());
        assert_eq!(xhttp.xmux.h_max_reusable_secs, XhttpRange::default());
        assert_eq!(xhttp.xmux.h_keep_alive_period_secs, 0);
    };

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": null,
           "splithttpSettings": {"host": "legacy.example", "mode": "packet-up"}"#,
    ))
    .expect("a null current pointer must fall through to the legacy block");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("legacy.example"));
    assert_eq!(xhttp.mode, XhttpMode::PacketUp);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "splithttp", "security": "none",
           "xhttpSettings": {"host": "current.example"},
           "splithttpSettings": null"#,
    ))
    .expect("a null legacy pointer must not trigger an alias warning");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("current.example"));
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": null, "splithttpSettings": null"#,
    ))
    .expect("two null pointers must select the zero-valued XHTTP config");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.mode, XhttpMode::Auto);
    assert_zero_xmux(xhttp);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""method": "xhttp", "security": "none""#,
    ))
    .expect("missing settings pointers must select the registry's zero-valued XHTTP config");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_zero_xmux(xhttp);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "raw", "security": "none", "xhttpSettings": null"#,
    ))
    .expect("a null XHTTP pointer is not an ignored transport block");
    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::Raw
    ));
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

#[test]
fn lower_priority_splithttp_settings_are_shape_checked_only() {
    // These values are invalid under SplitHTTPConfig.Build, but that method is
    // invoked only for xhttpSettings after priority is applied. Their JSON
    // types are valid, so Go accepts the config and ignores the legacy block.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {"host": "current.example", "mode": "stream-one"},
           "splithttpSettings": {
             "mode": "not-a-mode", "headers": {"Host": "ignored.example"},
             "xPaddingBytes": "0-100", "uplinkDataPlacement": "cookie",
             "xmux": {"maxConcurrency": 1, "maxConnections": 1}
           }"#,
    ))
    .expect("semantic validation must apply only to the winning alias");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("current.example"));
    assert_eq!(xhttp.mode, XhttpMode::StreamOne);
    assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
    assert_eq!(parsed.diagnostics[0].severity, DiagnosticSeverity::Warning);
}

#[test]
fn lower_priority_splithttp_null_fields_are_valid_decode_shapes() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {"host": "current.example", "mode": "stream-one"},
           "splithttpSettings": {
             "host": null, "path": null, "mode": null,
             "headers": {"X-Null": null},
             "xPaddingBytes": null, "xPaddingObfsMode": null,
             "xPaddingKey": null, "xPaddingHeader": null,
             "xPaddingPlacement": null, "xPaddingMethod": null,
             "uplinkHTTPMethod": null,
             "sessionIDPlacement": null, "sessionIDKey": null,
             "sessionIDTable": null, "sessionIDLength": null,
             "seqPlacement": null, "seqKey": null,
             "uplinkDataPlacement": null, "uplinkDataKey": null,
             "uplinkChunkSize": null,
             "noGRPCHeader": null, "noSSEHeader": null,
             "scMaxEachPostBytes": null, "scMinPostsIntervalMs": null,
             "scMaxBufferedPosts": null, "scStreamUpServerSecs": null,
             "serverMaxHeaderBytes": null,
             "xmux": {
               "maxConcurrency": null, "maxConnections": null,
               "cMaxReuseTimes": null, "hMaxRequestTimes": null,
               "hMaxReusableSecs": null, "hKeepAlivePeriod": null
             },
             "downloadSettings": null
           }"#,
    ))
    .expect("the ignored alias must still accept every Go-valid null decode shape");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("current.example"));
    assert_eq!(xhttp.mode, XhttpMode::StreamOne);
    assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
    assert_eq!(parsed.diagnostics[0].severity, DiagnosticSeverity::Warning);
    assert_eq!(
        parsed.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].streamSettings.splithttpSettings")
    );
}

#[test]
fn lower_priority_splithttp_settings_still_require_decodable_types() {
    for (fragment, path) in [
        (r#""host": 5"#, "host"),
        (r#""xPaddingBytes": "not-a-range""#, "xPaddingBytes"),
        (r#""headers": {"X-Test": 5}"#, "headers.X-Test"),
        (
            r#""xmux": {"hKeepAlivePeriod": "forever"}"#,
            "xmux.hKeepAlivePeriod",
        ),
    ] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "xhttp", "security": "none",
                   "xhttpSettings": {{"mode": "stream-one"}},
                   "splithttpSettings": {{{fragment}}}"#
            )),
            &format!("$.outbounds[0].streamSettings.splithttpSettings.{path}"),
        );
    }
}

#[test]
fn xhttp_rejects_invalid_modes_placements_methods_and_limits() {
    for (fragment, path) in [
        (r#""mode": "burst""#, "mode"),
        (r#""xPaddingPlacement": "body""#, "xPaddingPlacement"),
        (r#""xPaddingMethod": "random""#, "xPaddingMethod"),
        (r#""sessionIDPlacement": "body""#, "sessionIDPlacement"),
        (r#""seqPlacement": "auto""#, "seqPlacement"),
        (r#""uplinkDataPlacement": "query""#, "uplinkDataPlacement"),
        (
            r#""mode": "stream-up", "uplinkDataPlacement": "cookie""#,
            "uplinkDataPlacement",
        ),
        (
            r#""mode": "stream-one", "uplinkHTTPMethod": "GET""#,
            "uplinkHTTPMethod",
        ),
        (r#""xPaddingBytes": "0-100""#, "xPaddingBytes"),
        (r#""serverMaxHeaderBytes": -1"#, "serverMaxHeaderBytes"),
    ] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "xhttp", "security": "none", "xhttpSettings": {{{fragment}}}"#
            )),
            &format!("$.outbounds[0].streamSettings.xhttpSettings.{path}"),
        );
    }
}

#[test]
fn selected_xhttp_custom_session_id_generation_reaches_the_normalized_model() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""method": "xhttp", "security": "none",
           "xhttpSettings": {"sessionIDTable": "Base62", "sessionIDLength": "9-6"}"#,
    ))
    .expect("a valid custom session ID generator must be available to the XHTTP runtime");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.session_id_table, "Base62");
    assert_eq!(xhttp.session_id_length, XhttpRange { from: 6, to: 9 });
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

#[test]
fn unselected_xhttp_custom_session_id_uses_upstream_validation_only() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""method": "raw", "network": "xhttp", "security": "none",
           "xhttpSettings": {"sessionIDTable": "Base62", "sessionIDLength": 8}"#,
    ))
    .expect("a valid custom session ID generator is inert when XHTTP is not selected");
    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::Raw
    ));
    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.path.as_deref() == Some("$.outbounds[0].streamSettings.xhttpSettings")
            && diagnostic.message.contains("selected stream transport")
    }));

    for (table, length, path) in [
        (
            "Base62",
            r#""0-8""#,
            "$.outbounds[0].streamSettings.xhttpSettings.sessionIDLength",
        ),
        (
            "Base62",
            "5",
            "$.outbounds[0].streamSettings.xhttpSettings.sessionIDTable",
        ),
        (
            "\u{e9}",
            "32",
            "$.outbounds[0].streamSettings.xhttpSettings.sessionIDTable",
        ),
    ] {
        let error = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""method": "raw", "network": "xhttp", "security": "none",
                   "xhttpSettings": {{"sessionIDTable": "{table}", "sessionIDLength": {length}}}"#,
        )))
        .unwrap_err();
        assert!(error.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Error
                && diagnostic.path.as_deref() == Some(path)
        }));
    }
}

#[test]
fn xhttp_uplink_http_method_is_a_valid_ascii_token() {
    for method in [
        r#""POST\r\nX-Evil: 1""#,
        r#""POST GET""#,
        r#""méthod""#,
        r#""\u0000PING""#,
    ] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "xhttp", "security": "none",
                   "xhttpSettings": {{"mode": "packet-up", "uplinkHTTPMethod": {method}}}"#
            )),
            "$.outbounds[0].streamSettings.xhttpSettings.uplinkHTTPMethod",
        );
    }

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {"mode": "packet-up", "uplinkHTTPMethod": "m-search*"}"#,
    ))
    .expect("RFC tchar extension methods must remain supported");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.uplink_http_method, "M-SEARCH*");
}

#[test]
fn xhttp_rejects_invalid_ranges_and_conflicting_xmux_limits() {
    for value in [r#""1-two""#, r#"1.5"#, r#""2147483648""#] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "xhttp", "security": "none",
                   "xhttpSettings": {{"uplinkChunkSize": {value}}}"#
            )),
            "$.outbounds[0].streamSettings.xhttpSettings.uplinkChunkSize",
        );
    }

    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "xhttp", "security": "none",
               "xhttpSettings": {"xmux": {"maxConcurrency": 2, "maxConnections": 3}}"#,
        ),
        "$.outbounds[0].streamSettings.xhttpSettings.xmux",
    );
}

#[test]
fn xhttp_ranges_accept_signed_single_empty_and_reversed_forms() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "uplinkChunkSize": "-1919--810",
             "scMaxEachPostBytes": "",
             "scMinPostsIntervalMs": -7,
             "scStreamUpServerSecs": "120-90"
           }"#,
    ))
    .expect("all Int32Range forms accepted by Xray must parse");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(
        xhttp.uplink_chunk_size,
        XhttpRange {
            from: -1919,
            to: -810
        }
    );
    assert_eq!(xhttp.sc_max_each_post_bytes, XhttpRange::default());
    assert_eq!(
        xhttp.sc_min_posts_interval_ms,
        XhttpRange { from: -7, to: -7 }
    );
    assert_eq!(
        xhttp.sc_stream_up_server_secs,
        XhttpRange { from: 90, to: 120 }
    );
}

#[test]
fn xhttp_rejects_host_header_and_effective_download_settings() {
    for (fragment, path) in [
        (r#""headers": {"hOsT": "bad.example"}"#, "headers"),
        (r#""downloadSettings": {}"#, "downloadSettings"),
        (
            r#""extra": {"downloadSettings": {}}"#,
            "extra.downloadSettings",
        ),
    ] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "xhttp", "security": "none", "xhttpSettings": {{{fragment}}}"#
            )),
            &format!("$.outbounds[0].streamSettings.xhttpSettings.{path}"),
        );
    }
}

#[test]
fn xhttp_extra_supports_the_legacy_packet_up_share_profile() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "host": "edge.example", "path": "/", "mode": "packet-up",
             "headers": {"X-Outer": "discarded"},
             "scMaxEachPostBytes": 1,
             "extra": {
               "noGRPCHeader": false,
               "scMaxConcurrentPosts": 100,
               "scMaxEachPostBytes": "500000",
               "scMinPostsIntervalMs": "60",
               "xmux": {
                 "cMaxReuseTimes": 0,
                 "hKeepAlivePeriod": 0,
                 "hMaxRequestTimes": "600-900",
                 "hMaxReusableSecs": "1800-3000",
                 "maxConnections": 16
               },
               "xPaddingBytes": "100-1000"
             }
           }"#,
    ))
    .expect("the legacy packet-up share profile must parse");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("edge.example"));
    assert_eq!(xhttp.path, "/");
    assert_eq!(xhttp.mode, XhttpMode::PacketUp);
    assert!(
        xhttp.headers.is_empty(),
        "outer non-identity fields are replaced"
    );
    assert!(!xhttp.no_grpc_header);
    assert_eq!(
        xhttp.sc_max_each_post_bytes,
        XhttpRange {
            from: 500_000,
            to: 500_000
        }
    );
    assert_eq!(
        xhttp.sc_min_posts_interval_ms,
        XhttpRange { from: 60, to: 60 }
    );
    assert_eq!(
        xhttp.x_padding_bytes,
        XhttpRange {
            from: 100,
            to: 1_000
        }
    );
    assert_eq!(xhttp.xmux.max_connections, XhttpRange { from: 16, to: 16 });
    assert_eq!(xhttp.xmux.max_concurrency, XhttpRange::default());
    assert_eq!(xhttp.xmux.c_max_reuse_times, XhttpRange::default());
    assert_eq!(
        xhttp.xmux.h_max_request_times,
        XhttpRange { from: 600, to: 900 }
    );
    assert_eq!(
        xhttp.xmux.h_max_reusable_secs,
        XhttpRange {
            from: 1_800,
            to: 3_000
        }
    );
    assert_eq!(xhttp.xmux.h_keep_alive_period_secs, 0);
    assert_eq!(parsed.diagnostics.len(), 1, "{:?}", parsed.diagnostics);
    assert_eq!(parsed.diagnostics[0].severity, DiagnosticSeverity::Warning);
    assert_eq!(
        parsed.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].streamSettings.xhttpSettings.extra.scMaxConcurrentPosts")
    );
    assert!(parsed.diagnostics[0].message.contains("ignored"));
}

#[test]
fn xhttp_extra_replaces_outer_fields_but_preserves_outer_identity() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "host": "outer.example", "path": "/outer", "mode": "stream-one",
             "xPaddingBytes": "0-100",
             "downloadSettings": {},
             "extra": {
               "host": "inner.example", "path": "/inner", "mode": "not-a-mode",
               "xPaddingBytes": "10-20"
             }
           }"#,
    ))
    .expect("outer non-identity semantics are discarded before Build validation");

    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host.as_deref(), Some("outer.example"));
    assert_eq!(xhttp.path, "/outer");
    assert_eq!(xhttp.mode, XhttpMode::StreamOne);
    assert_eq!(xhttp.x_padding_bytes, XhttpRange { from: 10, to: 20 });
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

#[test]
fn xhttp_extra_null_and_missing_outer_identity_follow_xray_build() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {"extra": null}"#,
    ))
    .expect("extra null is a zero-valued replacement");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.as_ref(), &XhttpSettings::default());
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "extra": {
               "host": "discarded.example", "path": "/discarded", "mode": "packet-up",
               "xPaddingBytes": 25
             }
           }"#,
    ))
    .expect("missing outer identity must erase the replacement identity");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(xhttp.host, None);
    assert_eq!(xhttp.path, "");
    assert_eq!(xhttp.mode, XhttpMode::Auto);
    assert_eq!(xhttp.x_padding_bytes, XhttpRange { from: 25, to: 25 });
}

#[test]
fn xhttp_extra_rejects_non_object_and_decode_invalid_fields() {
    for (fragment, path) in [
        (r#""extra": []"#, "extra"),
        (r#""extra": "{}""#, "extra"),
        (r#""extra": 7"#, "extra"),
        (r#""extra": {"host": 7}"#, "extra.host"),
        (r#""extra": {"futureField": 7}"#, "extra.futureField"),
        (r#""host": 7, "extra": {}"#, "host"),
    ] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "xhttp", "security": "none", "xhttpSettings": {{{fragment}}}"#
            )),
            &format!("$.outbounds[0].streamSettings.xhttpSettings.{path}"),
        );
    }
}

#[test]
fn xhttp_nested_extra_is_inert_and_legacy_concurrent_posts_is_never_mapped() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "xhttpSettings": {
             "mode": "packet-up",
             "scMaxConcurrentPosts": {"old": true},
             "extra": {
               "scMaxConcurrentPosts": "100",
               "extra": {"scMaxEachPostBytes": 999999},
               "scMaxEachPostBytes": 123
             }
           }"#,
    ))
    .expect("removed and nested RawMessage fields must remain import-compatible");
    let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected xhttp");
    };
    assert_eq!(
        xhttp.sc_max_each_post_bytes,
        XhttpRange { from: 123, to: 123 }
    );
    assert_eq!(xhttp.sc_max_buffered_posts, 0);
    assert_eq!(parsed.diagnostics.len(), 3, "{:?}", parsed.diagnostics);
    assert!(parsed.diagnostics.iter().all(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && (diagnostic.message.contains("ignored")
                || diagnostic.message.contains("replacement only once"))
    }));
}

#[test]
fn finalmask_quic_params_full_v26_surface_is_normalized() {
    let parsed = parse_xray_json(&raw_with_quic_params(
        r#"
          "congestion": "BRUTAL",
          "bbrProfile": "AGGRESSIVE",
          "brutalUp": "512 kbps",
          "brutalDown": "8 Mbps",
          "udpHop": { "ports": "443, 1000-1002, 443", "interval": "30-10" },
          "initStreamReceiveWindow": 16384,
          "maxStreamReceiveWindow": 32768,
          "initConnectionReceiveWindow": 65536,
          "maxConnectionReceiveWindow": 131072,
          "maxIdleTimeout": 120,
          "keepAlivePeriod": 60,
          "disablePathMTUDiscovery": true,
          "maxIncomingStreams": 8,
          "debug": true
        "#,
    ))
    .expect("full finalmask QUIC parameters should parse");

    assert!(parsed.diagnostics.is_empty());
    assert_eq!(
        parsed.config.outbounds[0].stream.quic_params,
        Some(QuicParamsSettings {
            congestion: QuicCongestion::Brutal,
            bbr_profile: QuicBbrProfile::Aggressive,
            brutal_up_bytes_per_sec: 65_536,
            brutal_down_bytes_per_sec: 1_048_576,
            udp_hop: QuicUdpHopSettings {
                ports: vec![443, 1000, 1001, 1002, 443],
                interval: QuicIntervalRange { from: 10, to: 30 },
            },
            init_stream_receive_window: 16_384,
            max_stream_receive_window: 32_768,
            init_connection_receive_window: 65_536,
            max_connection_receive_window: 131_072,
            max_idle_timeout_secs: 120,
            keep_alive_period_secs: 60,
            disable_path_mtu_discovery: true,
            max_incoming_streams: 8,
            debug: true,
        })
    );
}

#[test]
fn finalmask_quic_params_preserves_pointer_presence_and_xray_defaults() {
    for stream_settings in [
        r#""network": "xhttp", "security": "none""#,
        r#""network": "xhttp", "security": "none", "finalmask": null"#,
        r#""network": "xhttp", "security": "none", "finalmask": {}"#,
        r#""network": "xhttp", "security": "none", "finalmask": {"quicParams": null}"#,
    ] {
        let parsed = parse_xray_json(&raw_with_stream_settings(stream_settings))
            .expect("absent QUIC pointer should parse");
        assert_eq!(parsed.config.outbounds[0].stream.quic_params, None);
    }

    let parsed = parse_xray_json(&raw_with_quic_params(
        r#"
          "congestion": null,
          "bbrProfile": null,
          "brutalUp": null,
          "brutalDown": null,
          "udpHop": null,
          "initStreamReceiveWindow": null,
          "maxStreamReceiveWindow": null,
          "initConnectionReceiveWindow": null,
          "maxConnectionReceiveWindow": null,
          "maxIdleTimeout": null,
          "keepAlivePeriod": null,
          "disablePathMTUDiscovery": null,
          "maxIncomingStreams": null,
          "debug": null
        "#,
    ))
    .expect("null scalar values should retain Go zero defaults");
    assert_eq!(
        parsed.config.outbounds[0].stream.quic_params,
        Some(QuicParamsSettings::default())
    );
}

#[test]
fn finalmask_empty_masks_are_accepted_but_nonempty_masks_fail_closed() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "xhttp", "security": "none",
           "finalmask": {"tcp": [], "udp": [], "quicParams": {}}"#,
    ))
    .expect("empty final masks should parse");
    assert_eq!(
        parsed.config.outbounds[0].stream.quic_params,
        Some(QuicParamsSettings::default())
    );

    for mask in ["tcp", "udp"] {
        assert_parse_error_path(
            &raw_with_stream_settings(&format!(
                r#""network": "xhttp", "security": "none",
                   "finalmask": {{"{mask}": [{{"type": "example"}}]}}"#
            )),
            &format!("$.outbounds[0].streamSettings.finalmask.{mask}"),
        );
    }
}

#[test]
fn finalmask_udp_hop_zero_and_null_normalize_to_empty_defaults() {
    for udp_hop in [
        r#""udpHop": {"ports": 0, "interval": 0}"#,
        r#""udpHop": {"ports": null, "interval": null}"#,
    ] {
        let parsed = parse_xray_json(&raw_with_quic_params(udp_hop))
            .expect("zero and null are Xray's empty UDP-hop values");
        let quic = parsed.config.outbounds[0]
            .stream
            .quic_params
            .as_ref()
            .expect("explicit QUIC params");
        assert!(quic.udp_hop.ports.is_empty());
        assert_eq!(quic.udp_hop.interval, QuicIntervalRange::default());
    }
}

#[test]
fn finalmask_accepts_every_upstream_congestion_name_case_insensitively() {
    for (configured, expected) in [
        ("", QuicCongestion::Default),
        ("brutal", QuicCongestion::Brutal),
        ("RENO", QuicCongestion::Reno),
        ("BbR", QuicCongestion::Bbr),
        ("force-brutal", QuicCongestion::ForceBrutal),
    ] {
        let parsed = parse_xray_json(&raw_with_quic_params(&format!(
            r#""congestion": "{configured}", "brutalUp": "512kbps""#
        )))
        .expect("upstream congestion spelling should parse");
        assert_eq!(
            parsed.config.outbounds[0]
                .stream
                .quic_params
                .as_ref()
                .expect("explicit QUIC params")
                .congestion,
            expected
        );
    }
}

#[test]
fn finalmask_quic_params_rejects_invalid_values_at_exact_paths() {
    let cases = [
        (r#""congestion": "cubic""#, "congestion"),
        (r#""bbrProfile": "fast""#, "bbrProfile"),
        (r#""brutalUp": 524288"#, "brutalUp"),
        (r#""brutalUp": "not-a-rate""#, "brutalUp"),
        (r#""brutalUp": "524287bps""#, "brutalUp"),
        (r#""brutalDown": "524287bps""#, "brutalDown"),
        (r#""congestion": "force-brutal""#, "congestion"),
        (r#""udpHop": {"ports": "0"}"#, "udpHop.ports"),
        (r#""udpHop": {"ports": "65536"}"#, "udpHop.ports"),
        (r#""udpHop": {"ports": "10-9"}"#, "udpHop.ports"),
        (r#""udpHop": {"ports": "env:QUIC_PORTS"}"#, "udpHop.ports"),
        (r#""udpHop": {"interval": 4}"#, "udpHop.interval"),
        (
            r#""initStreamReceiveWindow": 16383"#,
            "initStreamReceiveWindow",
        ),
        (
            r#""maxStreamReceiveWindow": 16383"#,
            "maxStreamReceiveWindow",
        ),
        (
            r#""initConnectionReceiveWindow": 16383"#,
            "initConnectionReceiveWindow",
        ),
        (
            r#""maxConnectionReceiveWindow": 16383"#,
            "maxConnectionReceiveWindow",
        ),
        (r#""maxIdleTimeout": 3"#, "maxIdleTimeout"),
        (r#""maxIdleTimeout": 121"#, "maxIdleTimeout"),
        (r#""keepAlivePeriod": 1"#, "keepAlivePeriod"),
        (r#""keepAlivePeriod": 61"#, "keepAlivePeriod"),
        (r#""maxIncomingStreams": -1"#, "maxIncomingStreams"),
        (r#""maxIncomingStreams": 7"#, "maxIncomingStreams"),
        (
            r#""disablePathMTUDiscovery": "true""#,
            "disablePathMTUDiscovery",
        ),
        (r#""debug": 1"#, "debug"),
    ];

    for (fragment, path) in cases {
        assert_parse_error_path(
            &raw_with_quic_params(fragment),
            &format!("$.outbounds[0].streamSettings.finalmask.quicParams.{path}"),
        );
    }
}

#[test]
fn finalmask_json_field_casing_is_exact_and_unknown_fields_fail_closed() {
    for (stream_settings, path) in [
        (
            r#""network": "xhttp", "security": "none", "finalMask": {}"#,
            "$.outbounds[0].streamSettings.finalMask",
        ),
        (
            r#""network": "xhttp", "security": "none",
               "finalmask": {"quicparams": {}}"#,
            "$.outbounds[0].streamSettings.finalmask.quicparams",
        ),
        (
            r#""network": "xhttp", "security": "none",
               "finalmask": {"quicParams": {"disablePathMtuDiscovery": true}}"#,
            "$.outbounds[0].streamSettings.finalmask.quicParams.disablePathMtuDiscovery",
        ),
    ] {
        assert_parse_error_path(&raw_with_stream_settings(stream_settings), path);
    }
}

#[test]
fn the_ed_query_parameter_is_stripped_from_the_path() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?ed=2048"}"#,
    ))
    .expect("an ed path must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x", "ed never reaches the wire");
    assert_eq!(ws.early_data_bytes, 2048);
}

#[test]
fn the_remaining_query_is_re_encoded_alphabetically() {
    // Go's url.Values.Encode() sorts, so a path that keeps its query comes out
    // reordered. The server compares the whole path, so we must match.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?zulu=1&alpha=2&ed=64"}"#,
    ))
    .expect("a multi-parameter path must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x?alpha=2&zulu=1");
    assert_eq!(ws.early_data_bytes, 64);
}

#[test]
fn a_non_numeric_ed_value_is_still_stripped() {
    // Go's `Ed, _ := strconv.Atoi(...)` swallows the error and leaves ed zero,
    // but the deletion happens either way.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?ed=lots&keep=1"}"#,
    ))
    .expect("a non-numeric ed must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x?keep=1");
    assert_eq!(ws.early_data_bytes, 0);
}

#[test]
fn a_query_without_ed_is_left_byte_for_byte_alone() {
    // Xray only rewrites the path inside the `q.Get("ed") != ""` branch, so a
    // path that never mentions ed keeps its original parameter order and
    // escaping. Sorting it here would be a path mismatch on the wire.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?zulu=1&alpha=2"}"#,
    ))
    .expect("a query without ed must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x?zulu=1&alpha=2");
    assert_eq!(ws.early_data_bytes, 0);
}

#[test]
fn an_empty_ed_value_is_not_an_ed_at_all() {
    // `q.Get("ed")` returns "" for `?ed=`, so Xray skips the whole rewrite and
    // sends `ed=` verbatim.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?ed=&zulu=1"}"#,
    ))
    .expect("an empty ed must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x?ed=&zulu=1");
    assert_eq!(ws.early_data_bytes, 0);
}

#[test]
fn a_repeated_ed_takes_the_first_value_and_drops_every_copy() {
    // `Values.Get` reads the first entry and `Values.Del` removes them all.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?ed=16&ed=32"}"#,
    ))
    .expect("a repeated ed must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x");
    assert_eq!(ws.early_data_bytes, 16);
}

#[test]
fn the_kept_query_is_percent_encoded_the_way_go_encodes_it() {
    // url.Values round-trips through QueryUnescape/QueryEscape, so `+` means a
    // space on the way in and comes back out as `+`, and a bare key gains `=`.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?b=a+b&a&ed=8"}"#,
    ))
    .expect("an escaped query must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x?a=&b=a+b");
    assert_eq!(ws.early_data_bytes, 8);
}

#[test]
fn an_empty_path_becomes_a_single_slash() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none", "wsSettings": {}"#,
    ))
    .expect("wsSettings may be empty");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/");
}

#[test]
fn a_relative_path_gains_its_leading_slash() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none", "wsSettings": {"path": "chat"}"#,
    ))
    .expect("a relative path must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/chat");
}

#[test]
fn ws_folds_a_host_header_into_host_with_a_deprecation_warning() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"headers": {"host": "cdn.example.com", "X-Thing": "v"}}"#,
    ))
    .expect("headers.host must parse for ws");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
    assert_eq!(ws.headers, vec![("X-Thing".to_owned(), "v".to_owned())]);
    assert_eq!(parsed.diagnostics.len(), 1);
    assert_eq!(
        parsed.diagnostics[0].severity,
        DiagnosticSeverity::Warning,
        "{:?}",
        parsed.diagnostics
    );
    assert_eq!(
        parsed.diagnostics[0].path.as_deref(),
        Some("$.outbounds[0].streamSettings.wsSettings.headers")
    );
}

#[test]
fn an_explicit_ws_host_wins_over_a_host_header() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"host": "wins.example.com",
                          "headers": {"Host": "loses.example.com"}}"#,
    ))
    .expect("headers.Host must parse for ws");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.host.as_deref(), Some("wins.example.com"));
    assert!(ws.headers.is_empty(), "the folded header is still removed");
}

#[test]
fn httpupgrade_rejects_a_host_header_inside_headers() {
    // ws folds headers.Host into host with a deprecation warning; httpupgrade
    // makes it a hard error.
    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "httpupgrade", "security": "none",
               "httpupgradeSettings": {"headers": {"Host": "x"}}"#,
        ),
        "$.outbounds[0].streamSettings.httpupgradeSettings.headers",
    );
}

#[test]
fn ws_canonicalizes_header_names_but_httpupgrade_keeps_them_literal() {
    // Xray's ws config goes through Go's `header.Add`, which MIME-canonicalizes
    // the key; httpupgrade assigns into the map directly so that people can
    // send `Sec-WebSocket-*` with their own casing. The split is deliberate and
    // visible on the wire.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"headers": {"accept-language": "en", "SEC-ch-ua": "x"}}"#,
    ))
    .expect("lowercase ws headers must parse");

    let StreamTransport::WebSocket(ws) = &parsed.config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(
        sorted_header_names(&ws.headers),
        vec!["Accept-Language", "Sec-Ch-Ua"]
    );

    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "httpupgrade", "security": "none",
           "httpupgradeSettings": {"headers": {"accept-language": "en", "SEC-ch-ua": "x"}}"#,
    ))
    .expect("lowercase httpupgrade headers must parse");

    let StreamTransport::HttpUpgrade(httpupgrade) = &parsed.config.outbounds[0].stream.transport
    else {
        panic!("expected an httpupgrade transport");
    };
    assert_eq!(
        sorted_header_names(&httpupgrade.headers),
        vec!["SEC-ch-ua", "accept-language"]
    );
}

/// Header order in the model is whatever the JSON object iteration produced;
/// only the serializer's sort is observable on the wire, so tests compare the
/// names sorted the same way it sorts them.
fn sorted_header_names(headers: &[(String, String)]) -> Vec<&str> {
    let mut names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable_by_key(|name| name.as_bytes());
    names
}

#[test]
fn removed_transports_say_they_were_removed() {
    for network in ["h2", "h3", "http", "quic"] {
        let error = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none""#
        )))
        .expect_err("a removed transport must be rejected");
        assert!(
            error
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("removed")),
            "{network} must say it was removed, got: {:?}",
            error.diagnostics
        );
    }
}

#[test]
fn transports_xray_still_has_but_we_do_not_say_so() {
    for network in ["kcp", "mkcp", "hysteria"] {
        let error = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none""#
        )))
        .expect_err("an unimplemented transport must be rejected");
        assert_eq!(
            error.diagnostics[0].path.as_deref(),
            Some("$.outbounds[0].streamSettings.network")
        );
        assert!(
            error.diagnostics[0].message.contains("not supported"),
            "{network} got: {:?}",
            error.diagnostics
        );
    }
}

#[test]
fn a_settings_block_the_network_will_not_consume_warns() {
    // Xray's StreamConfig.Build builds every block that is present and only
    // picks one at dial time, so this parses — but silently as plain TCP,
    // which is the copy-paste worth naming.
    for (network, ignored) in [
        ("raw", "wsSettings"),
        ("raw", "httpupgradeSettings"),
        ("ws", "httpupgradeSettings"),
        ("ws", "tcpSettings"),
        ("httpupgrade", "wsSettings"),
        ("httpupgrade", "rawSettings"),
        ("raw", "grpcSettings"),
        ("grpc", "wsSettings"),
        ("raw", "xhttpSettings"),
        ("grpc", "splithttpSettings"),
    ] {
        let parsed = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none", "{ignored}": {{}}"#
        )))
        .unwrap_or_else(|error| panic!("{network} with {ignored} must parse: {error:?}"));

        let warning = parsed
            .diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.path.as_deref()
                    == Some(&format!("$.outbounds[0].streamSettings.{ignored}"))
            })
            .unwrap_or_else(|| {
                panic!(
                    "{network} must flag {ignored}, got: {:?}",
                    parsed.diagnostics
                )
            });
        assert_eq!(warning.severity, DiagnosticSeverity::Warning);
    }
}

#[test]
fn a_settings_block_the_network_will_not_consume_is_still_validated() {
    // Xray builds the block regardless of the network, so a config that fails
    // to build there must fail here; skipping it would make us more lenient
    // than the reference, not equal to it.
    let error = parse_xray_json(&raw_with_stream_settings(
        r#""network": "raw", "security": "none",
           "httpupgradeSettings": {"headers": {"Host": "x"}}"#,
    ))
    .expect_err("an unconsumed block still has to build");

    assert!(
        error.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Error
                && diagnostic.path.as_deref()
                    == Some("$.outbounds[0].streamSettings.httpupgradeSettings.headers")
        }),
        "got: {:?}",
        error.diagnostics
    );
}

#[test]
fn a_consumed_settings_block_does_not_warn() {
    for (network, consumed) in [
        ("raw", "tcpSettings"),
        ("raw", "rawSettings"),
        ("ws", "wsSettings"),
        ("httpupgrade", "httpupgradeSettings"),
        ("grpc", "grpcSettings"),
        ("xhttp", "xhttpSettings"),
        ("splithttp", "splithttpSettings"),
    ] {
        let parsed = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none", "{consumed}": {{}}"#
        )))
        .expect("a matching settings block must parse");

        assert!(
            parsed.diagnostics.is_empty(),
            "{network} with {consumed} got: {:?}",
            parsed.diagnostics
        );
    }
}

#[test]
fn rejects_unknown_ws_settings_field_with_path() {
    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "ws", "security": "none", "wsSettings": {"nope": 1}"#,
        ),
        "$.outbounds[0].streamSettings.wsSettings.nope",
    );
}

#[test]
fn rejects_non_string_ws_path_with_path() {
    // A silently ignored path would dial `/` and 404 against a real server.
    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "ws", "security": "none", "wsSettings": {"path": 8}"#,
        ),
        "$.outbounds[0].streamSettings.wsSettings.path",
    );
}

#[test]
fn rejects_non_string_httpupgrade_host_with_path() {
    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "httpupgrade", "security": "none",
               "httpupgradeSettings": {"host": true}"#,
        ),
        "$.outbounds[0].streamSettings.httpupgradeSettings.host",
    );
}

#[test]
fn rejects_non_string_ws_header_value_with_path() {
    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "ws", "security": "none", "wsSettings": {"headers": {"X-Thing": 1}}"#,
        ),
        "$.outbounds[0].streamSettings.wsSettings.headers.X-Thing",
    );
}

#[test]
fn rejects_missing_reality_server_name_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "chrome""#,
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.serverName",
    );
}

#[test]
fn rejects_empty_reality_server_name_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "chrome""#,
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.serverName",
    );
}

#[test]
fn defaults_missing_reality_fingerprint_to_chrome() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405""#,
    );

    let parsed = parse_xray_json(&raw).expect("missing REALITY fingerprint should default");
    let StreamSecurity::Reality(reality) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected reality security");
    };

    assert_eq!(reality.fingerprint, "chrome");
}

#[test]
fn parses_xray_core_reality_fingerprints() {
    for fingerprint in xray_utls::XRAY_REALITY_CAPABLE_FINGERPRINTS {
        let raw = vless_raw_with_reality_settings(&format!(
            r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "{fingerprint}""#,
        ));
        let parsed = parse_xray_json(&raw)
            .unwrap_or_else(|_| panic!("fingerprint `{fingerprint}` should parse"));
        let StreamSecurity::Reality(reality) = &parsed.config.outbounds[0].stream.security else {
            panic!("expected reality security");
        };

        assert_eq!(reality.fingerprint, *fingerprint);
    }
}

#[test]
fn rejects_known_reality_fingerprints_without_x25519_key_share() {
    for fingerprint in xray_utls::XRAY_REALITY_INCAPABLE_FINGERPRINTS {
        let raw = vless_raw_with_reality_settings(&format!(
            r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "{fingerprint}""#,
        ));
        let err = match parse_xray_json(&raw) {
            Ok(_) => panic!("fingerprint `{fingerprint}` should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
        assert_eq!(
            err.diagnostics[0].path.as_deref(),
            Some("$.outbounds[0].streamSettings.realitySettings.fingerprint")
        );
        assert!(
            err.diagnostics[0]
                .message
                .contains("does not support REALITY"),
            "{fingerprint}: {}",
            err.diagnostics[0].message
        );
    }
}

#[test]
fn normalizes_reality_fingerprint_case_like_xray_core() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "FireFox""#,
    );

    let parsed = parse_xray_json(&raw).expect("REALITY fingerprint should be case-insensitive");
    let StreamSecurity::Reality(reality) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected reality security");
    };

    assert_eq!(reality.fingerprint, "firefox");
}

#[test]
fn accepts_reality_allow_insecure_false() {
    let raw = vless_raw_with_reality_settings(&format!(
        r#""serverName": "server.example", "publicKey": "{}", "shortId": "02030405", "fingerprint": "chrome", "allowInsecure": false"#,
        valid_public_key()
    ));

    parse_xray_json(&raw).expect("config should parse");
}

#[test]
fn rejects_unsupported_reality_fingerprint_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "madeup-browser""#,
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.fingerprint",
    );
}

fn assert_parse_error_path(raw: &str, path: &str) {
    let err = parse_xray_json(raw).unwrap_err();
    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(err.diagnostics[0].path.as_deref(), Some(path));
}

fn assert_dns_server_zero_port_rejected(server: &str) {
    let raw = raw_with_dns_servers(&format!(r#""{server}""#));
    let error = parse_xray_json(&raw).unwrap_err();

    assert_eq!(
        error.diagnostics[0].path.as_deref(),
        Some("$.dns.servers[0]")
    );
    assert_eq!(
        error.diagnostics[0].message,
        "dns server port must be greater than zero"
    );
}

fn raw_with_dns_servers(servers: &str) -> String {
    format!(
        r#"{{
          "dns": {{ "servers": [{servers}] }},
          "inbounds": [],
          "outbounds": [{{ "tag": "direct", "protocol": "freedom" }}]
        }}"#
    )
}

fn raw_with_dns_host_target(target: &str) -> String {
    format!(
        r#"{{
          "dns": {{ "hosts": {{ "full:server.example": {target} }} }},
          "inbounds": [],
          "outbounds": [{{ "tag": "direct", "protocol": "freedom" }}]
        }}"#
    )
}

fn raw_with_dns_query_strategy(strategy: &str) -> String {
    format!(
        r#"{{
          "dns": {{ "queryStrategy": {strategy} }},
          "inbounds": [],
          "outbounds": [{{ "tag": "direct", "protocol": "freedom" }}]
        }}"#
    )
}

fn raw_with_dns_outbound_settings(settings: &str) -> String {
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "dns-out",
            "protocol": "dns",
            "settings": {settings}
          }}]
        }}"#
    )
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "xray-config-{name}-{}-{timestamp}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp geodata dir should be created");
    dir
}

fn write_geosite_dat(asset_dir: &Path, file_name: &str, entries: &[TestGeoSite]) {
    let bodies = entries
        .iter()
        .map(Message::encode_to_vec)
        .collect::<Vec<_>>();
    write_xray_dat(asset_dir.join(file_name), &bodies);
}

fn write_geoip_dat(asset_dir: &Path, file_name: &str, entries: &[TestGeoIp]) {
    let bodies = entries
        .iter()
        .map(Message::encode_to_vec)
        .collect::<Vec<_>>();
    write_xray_dat(asset_dir.join(file_name), &bodies);
}

fn write_xray_dat(path: PathBuf, bodies: &[Vec<u8>]) {
    let mut bytes = Vec::new();
    for body in bodies {
        bytes.push(0);
        encode_varint(body.len() as u64, &mut bytes);
        bytes.extend_from_slice(body);
    }
    fs::write(path, bytes).expect("xray dat fixture should be written");
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push(value as u8 | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn site_domain(r#type: i32, value: &str, attrs: &[&str]) -> TestDomain {
    TestDomain {
        r#type,
        value: value.to_owned(),
        attribute: attrs
            .iter()
            .map(|attr| TestDomainAttribute {
                key: (*attr).to_owned(),
            })
            .collect(),
    }
}

fn geo_cidr(ip: &[u8], prefix: u32) -> TestCidr {
    TestCidr {
        ip: ip.to_owned(),
        prefix,
    }
}

#[derive(Clone, PartialEq, Message)]
struct TestGeoSite {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<TestDomain>,
}

#[derive(Clone, PartialEq, Message)]
struct TestDomain {
    #[prost(enumeration = "TestDomainType", tag = "1")]
    r#type: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<TestDomainAttribute>,
}

#[derive(Clone, PartialEq, Message)]
struct TestDomainAttribute {
    #[prost(string, tag = "1")]
    key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum TestDomainType {
    Substr = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, Message)]
struct TestGeoIp {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<TestCidr>,
    #[prost(bool, tag = "3")]
    reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
struct TestCidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

fn valid_public_key() -> &'static str {
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
}

fn base64url_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let value = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        encoded.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[(value & 0x3f) as usize] as char);
    }
    match chunks.remainder() {
        [first] => {
            let value = (*first as u32) << 16;
            encoded.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
            encoded.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        }
        [first, second] => {
            let value = ((*first as u32) << 16) | ((*second as u32) << 8);
            encoded.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
            encoded.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
            encoded.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        }
        [] => {}
        _ => unreachable!("chunks_exact remainder is at most two bytes"),
    }
    encoded
}

fn raw_with_routing(routing: &str) -> String {
    let mut raw = vless_raw(
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );
    raw.insert_str(
        raw.rfind('}').expect("config object end"),
        &format!(r#","routing":{{{routing}}}"#),
    );
    raw
}

fn raw_with_inbound_extra(extra: &str) -> String {
    let extra_comma = if extra.is_empty() { "" } else { "," };
    format!(
        r#"{{
          "inbounds": [{{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": 1080
            {extra_comma}
            {extra}
          }}],
          "outbounds": []
        }}"#
    )
}

fn raw_with_socks_settings(settings: &str) -> String {
    raw_with_inbound_extra(&format!(r#""settings": {{{settings}}}"#))
}

fn raw_with_outbound_extra(extra: &str) -> String {
    let extra_comma = if extra.is_empty() { "" } else { "," };
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "server.example",
                  "port": 443,
                  "users": [{{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }}]
                }}
              ]
            }},
            "streamSettings": {{ "network": "tcp", "security": "none" }}
            {extra_comma}
            {extra}
          }}]
        }}"#
    )
}

fn raw_with_tls_settings(tls_settings: &str) -> String {
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "server.example",
                  "port": 443,
                  "users": [{{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }}]
                }}
              ]
            }},
            "streamSettings": {{
              "network": "tcp",
              "security": "tls",
              "tlsSettings": {{ {tls_settings} }}
            }}
          }}]
        }}"#
    )
}

fn raw_with_stream_settings(stream_settings: &str) -> String {
    raw_with_stream_settings_and_address("server.example", stream_settings)
}

fn raw_with_stream_settings_and_address(address: &str, stream_settings: &str) -> String {
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "{address}",
                  "port": 443,
                  "users": [{{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }}]
                }}
              ]
            }},
            "streamSettings": {{ {stream_settings} }}
          }}]
        }}"#
    )
}

fn raw_with_quic_params(quic_params: &str) -> String {
    raw_with_stream_settings(&format!(
        r#""network": "xhttp", "security": "none",
           "finalmask": {{"quicParams": {{{quic_params}}}}}"#
    ))
}

fn raw_with_tcp_settings(tcp_settings: &str) -> String {
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "server.example",
                  "port": 443,
                  "users": [{{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }}]
                }}
              ]
            }},
            "streamSettings": {{
              "network": "tcp",
              "security": "none",
              "tcpSettings": {{ {tcp_settings} }}
            }}
          }}]
        }}"#
    )
}

fn raw_with_raw_settings(raw_settings: &str) -> String {
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "server.example",
                  "port": 443,
                  "users": [{{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }}]
                }}
              ]
            }},
            "streamSettings": {{
              "network": "raw",
              "security": "none",
              "rawSettings": {{ {raw_settings} }}
            }}
          }}]
        }}"#
    )
}

fn raw_with_sockopt(sockopt: &str) -> String {
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
              "tag": "direct",
              "protocol": "freedom",
              "streamSettings": {{
                  "network": "tcp",
                  "security": "none",
                  "sockopt": {sockopt}
              }}
          }}]
        }}"#
    )
}

fn vless_raw(
    users_field: &str,
    extra_vnext: &str,
    port: u32,
    public_key: &str,
    short_id: &str,
) -> String {
    vless_raw_with_address(
        "server.example",
        users_field,
        extra_vnext,
        port,
        public_key,
        short_id,
    )
}

fn vless_raw_with_address(
    address: &str,
    users_field: &str,
    extra_vnext: &str,
    port: u32,
    public_key: &str,
    short_id: &str,
) -> String {
    vless_raw_with_network_and_address(
        "tcp",
        address,
        users_field,
        extra_vnext,
        port,
        public_key,
        short_id,
    )
}

fn vless_raw_with_network(
    network: &str,
    users_field: &str,
    extra_vnext: &str,
    port: u32,
    public_key: &str,
    short_id: &str,
) -> String {
    vless_raw_with_network_and_address(
        network,
        "server.example",
        users_field,
        extra_vnext,
        port,
        public_key,
        short_id,
    )
}

fn vless_raw_with_network_and_address(
    network: &str,
    address: &str,
    users_field: &str,
    extra_vnext: &str,
    port: u32,
    public_key: &str,
    short_id: &str,
) -> String {
    let users_comma = if users_field.is_empty() { "" } else { "," };

    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "{address}",
                  "port": {port}
                  {users_comma}
                  {users_field}
                }}
                {extra_vnext}
              ]
            }},
            "streamSettings": {{
              "network": "{network}",
              "security": "reality",
              "realitySettings": {{
                "serverName": "server.example",
                "fingerprint": "chrome",
                "publicKey": "{public_key}",
                "shortId": "{short_id}"
              }}
            }}
          }}]
        }}"#
    )
}

fn vless_raw_with_reality_settings(reality_settings: &str) -> String {
    format!(
        r#"{{
          "inbounds": [],
          "outbounds": [{{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {{
              "vnext": [
                {{
                  "address": "server.example",
                  "port": 443,
                  "users": [{{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }}]
                }}
              ]
            }},
            "streamSettings": {{
              "network": "tcp",
              "security": "reality",
              "realitySettings": {{
                {reality_settings}
              }}
            }}
          }}]
        }}"#
    )
}

#[test]
fn allow_insecure_tls_is_a_hard_error() {
    let raw = r#"{
        "inbounds": [
            {
              "tag": "socks-in",
              "protocol": "socks",
              "listen": "127.0.0.1",
              "port": 1080,
              "settings": { "auth": "noauth", "udp": false }
            }
        ],
        "outbounds": [
            {
              "tag": "proxy",
              "protocol": "vless",
              "settings": {
                "vnext": [
                  {
                    "address": "example.com",
                    "port": 443,
                    "users": [ { "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" } ]
                  }
                ]
              },
              "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": { "serverName": "example.com", "allowInsecure": true }
              }
            }
        ]
    }"#;

    assert_parse_error_path(
        raw,
        "$.outbounds[0].streamSettings.tlsSettings.allowInsecure",
    );
}

#[test]
fn wildcard_listen_produces_warning_diagnostic() {
    let raw = r#"{
        "inbounds": [
            {
              "tag": "socks-in",
              "protocol": "socks",
              "listen": "0.0.0.0",
              "port": 1080,
              "settings": {
                "auth": "noauth",
                "udp": false,
                "allowUnauthenticatedLan": true
              }
            }
        ],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert!(parsed.config.inbounds[0].allow_unauthenticated_lan);
    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.path.as_deref() == Some("$.inbounds[0].listen")
    }));
}

#[test]
fn unauthenticated_proxy_listener_requires_explicit_lan_opt_in() {
    for protocol in ["socks", "http"] {
        let raw = format!(
            r#"{{
                "inbounds": [{{
                  "tag": "proxy-in",
                  "protocol": "{protocol}",
                  "listen": "192.0.2.10",
                  "port": 1080,
                  "settings": {{}}
                }}],
                "outbounds": [
                    {{ "tag": "direct", "protocol": "freedom" }}
                ]
            }}"#
        );

        let error = parse_xray_json(&raw).unwrap_err();

        assert!(error.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Error
                && diagnostic.path.as_deref() == Some("$.inbounds[0].listen")
                && diagnostic.message.contains("allowUnauthenticatedLan=true")
        }));
    }
}

#[test]
fn explicit_lan_opt_in_accepts_non_loopback_listener_with_warning() {
    let raw = r#"{
        "inbounds": [{
          "tag": "http-in",
          "protocol": "http",
          "listen": "192.0.2.10",
          "port": 8080,
          "settings": { "allowUnauthenticatedLan": true }
        }],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("explicit LAN opt-in should parse");

    assert!(parsed.config.inbounds[0].allow_unauthenticated_lan);
    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.path.as_deref() == Some("$.inbounds[0].listen")
            && diagnostic.message.contains("explicitly exposed")
    }));
}

#[test]
fn reality_is_rejected_for_ws_and_httpupgrade() {
    // Xray refuses this at config-build time
    // (`infra/conf/transport_internet.go`, "REALITY only supports RAW, XHTTP
    // and gRPC for now."). Without the same refusal a profile builds cleanly
    // here and then fails on the wire against a real server.
    for network in ["ws", "httpupgrade"] {
        let error = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "reality",
               "realitySettings": {{"serverName": "server.example",
                                    "fingerprint": "chrome",
                                    "publicKey": "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
                                    "shortId": "02030405"}}"#
        )))
        .expect_err("REALITY must be rejected for this transport");

        assert!(
            error
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("REALITY only supports")),
            "{network} must echo Xray's message, got: {:?}",
            error.diagnostics
        );
        assert!(
            error.diagnostics.iter().any(|diagnostic| {
                diagnostic.path.as_deref() == Some("$.outbounds[0].streamSettings.security")
            }),
            "{network} must point at the security field, got: {:?}",
            error.diagnostics
        );
    }
}

#[test]
fn reality_is_accepted_on_grpc() {
    // `if config.ProtocolName != "tcp" && config.ProtocolName != "splithttp"
    // && config.ProtocolName != "grpc"` (`Xray-core/infra/conf/
    // transport_internet.go:1989`) — so the message our guard has always
    // quoted names gRPC because Xray really does build it, and REALITY over
    // gRPC is the deployment this transport mostly exists for.
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "grpc", "security": "reality",
           "grpcSettings": {"serviceName": "GunService"},
           "realitySettings": {"serverName": "server.example",
                               "fingerprint": "chrome",
                               "publicKey": "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
                               "shortId": "02030405"}"#,
    ))
    .expect("REALITY + gRPC is a configuration xray-core builds");

    assert!(matches!(
        parsed.config.outbounds[0].stream.security,
        StreamSecurity::Reality(_)
    ));
    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::Grpc(_)
    ));
}

#[test]
fn reality_is_accepted_on_both_xhttp_network_spellings() {
    for (network, settings_key) in [
        ("xhttp", "xhttpSettings"),
        ("splithttp", "splithttpSettings"),
    ] {
        let parsed = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "reality",
               "{settings_key}": {{"mode": "stream-one"}},
               "realitySettings": {{"serverName": "server.example",
                                     "fingerprint": "chrome",
                                     "publicKey": "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
                                     "shortId": "02030405"}}"#
        )))
        .unwrap_or_else(|error| panic!("REALITY + {network} must parse: {error:?}"));

        assert!(matches!(
            parsed.config.outbounds[0].stream.security,
            StreamSecurity::Reality(_)
        ));
        assert!(matches!(
            parsed.config.outbounds[0].stream.transport,
            StreamTransport::Xhttp(_)
        ));
    }
}

#[test]
fn reality_stays_valid_on_the_raw_transport() {
    let parsed = parse_xray_json(&raw_with_stream_settings(
        r#""network": "raw", "security": "reality",
           "realitySettings": {"serverName": "server.example",
                               "fingerprint": "chrome",
                               "publicKey": "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
                               "shortId": "02030405"}"#,
    ))
    .expect("REALITY over raw must keep parsing");

    assert!(matches!(
        parsed.config.outbounds[0].stream.security,
        StreamSecurity::Reality(_)
    ));
}
