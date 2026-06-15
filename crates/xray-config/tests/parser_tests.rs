use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use prost::Message;
use xray_config::{
    parse_xray_json, parse_xray_json_with_geodata_dirs, DiagnosticSeverity, DnsFakeIpConfig,
    InboundProtocol, IpCidr, OutboundSettings, RealityShortId, StreamSecurity, TargetAddr,
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
            ttl: 120,
        })
    );
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
fn rejects_non_as_is_routing_domain_strategy_with_path() {
    let raw = raw_with_routing(r#""domainStrategy": "IPIfNonMatch""#);

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
fn rejects_enabled_inbound_sniffing_with_path() {
    let raw = raw_with_inbound_extra(r#""sniffing": { "enabled": true }"#);

    assert_parse_error_path(&raw, "$.inbounds[0].sniffing.enabled");
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
fn rejects_send_through_with_path() {
    let raw = raw_with_outbound_extra(r#""sendThrough": "127.0.0.2""#);

    assert_parse_error_path(&raw, "$.outbounds[0].sendThrough");
}

#[test]
fn parses_tls_allow_insecure_for_compatibility() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "allowInsecure": true"#);
    let parsed = parse_xray_json(&raw).unwrap();

    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected tls security");
    };
    assert!(tls.allow_insecure);
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
fn rejects_tls_fingerprint_with_path() {
    let raw = raw_with_tls_settings(r#""serverName": "server.example", "fingerprint": "chrome""#);

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.tlsSettings.fingerprint",
    );
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
    let raw = vless_raw_with_network(
        "ws",
        r#""users": [{ "id": "00010203-0405-0607-0809-0a0b0c0d0e0f" }]"#,
        "",
        443,
        valid_public_key(),
        "02030405",
    );

    assert_parse_error_path(&raw, "$.outbounds[0].streamSettings.network");
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
fn rejects_missing_reality_fingerprint_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405""#,
    );

    assert_parse_error_path(
        &raw,
        "$.outbounds[0].streamSettings.realitySettings.fingerprint",
    );
}

#[test]
fn rejects_unsupported_reality_fingerprint_with_path() {
    let raw = vless_raw_with_reality_settings(
        r#""serverName": "server.example", "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "shortId": "02030405", "fingerprint": "firefox""#,
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
fn allow_insecure_tls_produces_warning_diagnostic() {
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

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.path.as_deref()
                == Some("$.outbounds[0].streamSettings.tlsSettings.allowInsecure")
    }));
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
              "settings": { "auth": "noauth", "udp": false }
            }
        ],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" }
        ]
    }"#;

    let parsed = parse_xray_json(raw).expect("config should parse");

    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.path.as_deref() == Some("$.inbounds[0].listen")
    }));
}
