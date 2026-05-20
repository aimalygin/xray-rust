use std::net::{IpAddr, Ipv4Addr};

use uuid::Uuid;
use xray_config::{
    CoreConfig, Network, OutboundConfig, OutboundSettings, RealitySettings, RealityShortId,
    StreamSecurity, StreamSettings, TargetAddr, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::{select_vless_tcp_outbound, CoreError};

fn vless_outbound(security: StreamSecurity, server: TargetAddr) -> OutboundConfig {
    OutboundConfig {
        tag: Some("proxy".to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security,
        },
        settings: OutboundSettings::Vless(VlessOutboundSettings {
            server,
            port: 443,
            users: vec![VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: None,
            }],
        }),
    }
}

fn config_with_outbound(outbound: OutboundConfig) -> CoreConfig {
    CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![outbound],
        default_outbound_tag: None,
    }
}

fn reality_security() -> StreamSecurity {
    StreamSecurity::Reality(RealitySettings {
        server_name: "example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [7; 32],
        short_id: RealityShortId::try_from_slice(&[1, 2, 3, 4]).unwrap(),
        spider_x: "/".to_owned(),
    })
}

#[test]
fn selects_raw_tcp_vless_outbound_with_ip_server() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server.port, 443);
}

#[test]
fn rejects_reality_outbound_for_raw_tcp_runtime_path() {
    let config = config_with_outbound(vless_outbound(
        reality_security(),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
    ));

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(
        result,
        Err(CoreError::UnsupportedOutboundSecurity)
    ));
}

#[test]
fn rejects_domain_vless_server_until_dns_exists() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Domain("example.com".to_owned()),
    ));

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(
        result,
        Err(CoreError::UnsupportedOutboundServerAddress)
    ));
}
