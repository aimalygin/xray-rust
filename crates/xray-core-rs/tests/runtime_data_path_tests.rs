use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use smoltcp::iface::{
    Config as SmolInterfaceConfig, Interface as SmolInterface, SocketHandle, SocketSet,
};
use smoltcp::phy::{
    ChecksumCapabilities, Device as SmolDevice, DeviceCapabilities as SmolDeviceCapabilities,
    Medium as SmolMedium, RxToken as SmolRxToken, TxToken as SmolTxToken,
};
use smoltcp::socket::tcp as smol_tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress as SmolHardwareAddress, IpAddress as SmolIpAddress, IpCidr as SmolIpCidr,
    Ipv4Address as SmolIpv4Address,
};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Duration, Instant as TokioInstant};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use xray_config::{
    CoreConfig, DomainMatcher, InboundConfig, InboundProtocol, IpCidr, IpMatcher, Network,
    OutboundConfig, OutboundSettings, RealitySettings, RealityShortId, RoutingConfig, RoutingRule,
    StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::{select_vless_tcp_outbound, Core, CoreError};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{DnsResolver, TlsConnector, TransportDialer, TransportError};
use xray_tun::TunEndpoint;

const TEST_UUID_BYTES: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

fn vless_outbound(security: StreamSecurity, server: TargetAddr, port: u16) -> OutboundConfig {
    OutboundConfig {
        tag: Some("proxy".to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security,
        },
        settings: OutboundSettings::Vless(VlessOutboundSettings {
            server,
            port,
            users: vec![VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: None,
            }],
        }),
    }
}

fn freedom_outbound() -> OutboundConfig {
    OutboundConfig {
        tag: Some("direct".to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security: StreamSecurity::None,
        },
        settings: OutboundSettings::Freedom,
    }
}

fn config_with_outbound(outbound: OutboundConfig) -> CoreConfig {
    CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![outbound],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
    }
}

fn allocate_unused_loopback_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

#[derive(Debug, Clone, Default)]
struct EmptyDnsResolver;

#[async_trait]
impl DnsResolver for EmptyDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
    }
}

#[derive(Debug, Clone)]
struct StaticDnsResolver {
    domain: &'static str,
    addr: SocketAddr,
}

#[async_trait]
impl DnsResolver for StaticDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        if domain == self.domain && port == self.addr.port() {
            Ok(self.addr)
        } else {
            Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
        }
    }
}

fn runtime_config_with_freedom_outbound() -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![freedom_outbound()],
        default_outbound_tag: Some("direct".to_owned()),
        routing: RoutingConfig::default(),
    }
}

fn runtime_tun_config_with_freedom_outbound() -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("tun-in".to_owned()),
            protocol: InboundProtocol::Tun,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![freedom_outbound()],
        default_outbound_tag: Some("direct".to_owned()),
        routing: RoutingConfig::default(),
    }
}

fn runtime_tun_config_with_routed_freedom_outbound(unused_proxy_port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("tun-in".to_owned()),
            protocol: InboundProtocol::Tun,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![
            vless_outbound(
                StreamSecurity::None,
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                unused_proxy_port,
            ),
            freedom_outbound(),
        ],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig {
            rules: vec![RoutingRule {
                inbound_tags: vec!["tun-in".to_owned()],
                domain_matchers: Vec::new(),
                ip_matchers: Vec::new(),
                outbound_tag: "direct".to_owned(),
            }],
        },
    }
}

fn runtime_tun_config_with_vless_server(vless_addr: SocketAddr) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("tun-in".to_owned()),
            protocol: InboundProtocol::Tun,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(vless_addr.ip()),
            vless_addr.port(),
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
    }
}

fn runtime_config_with_routed_freedom_outbound(unused_proxy_port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![
            vless_outbound(
                StreamSecurity::None,
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                unused_proxy_port,
            ),
            freedom_outbound(),
        ],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig {
            rules: vec![RoutingRule {
                inbound_tags: vec!["socks-in".to_owned()],
                domain_matchers: Vec::new(),
                ip_matchers: Vec::new(),
                outbound_tag: "direct".to_owned(),
            }],
        },
    }
}

fn runtime_config_with_domain_routed_freedom_outbound(unused_proxy_port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![
            vless_outbound(
                StreamSecurity::None,
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                unused_proxy_port,
            ),
            freedom_outbound(),
        ],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig {
            rules: vec![RoutingRule {
                inbound_tags: Vec::new(),
                domain_matchers: vec![DomainMatcher::Suffix("example.com".to_owned())],
                ip_matchers: Vec::new(),
                outbound_tag: "direct".to_owned(),
            }],
        },
    }
}

fn runtime_config_with_ip_routed_freedom_outbound(unused_proxy_port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![
            vless_outbound(
                StreamSecurity::None,
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                unused_proxy_port,
            ),
            freedom_outbound(),
        ],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig {
            rules: vec![RoutingRule {
                inbound_tags: Vec::new(),
                domain_matchers: Vec::new(),
                ip_matchers: vec![IpMatcher::Cidr(
                    IpCidr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8).unwrap(),
                )],
                outbound_tag: "direct".to_owned(),
            }],
        },
    }
}

fn runtime_config_with_vless_server(vless_addr: SocketAddr) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(vless_addr.ip()),
            vless_addr.port(),
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
    }
}

fn runtime_http_config_with_vless_server(vless_addr: SocketAddr) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("http-in".to_owned()),
            protocol: InboundProtocol::Http,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(vless_addr.ip()),
            vless_addr.port(),
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
    }
}

fn runtime_config_with_vless_domain_server(domain: &str, port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Domain(domain.to_owned()),
            port,
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
    }
}

fn runtime_config_with_tls_vless_domain_server(
    domain: &str,
    port: u16,
    server_name: &str,
) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::Tls(TlsSettings {
                server_name: Some(server_name.to_owned()),
                fingerprint: None,
            }),
            TargetAddr::Domain(domain.to_owned()),
            port,
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
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

fn tls_security() -> StreamSecurity {
    StreamSecurity::Tls(TlsSettings {
        server_name: Some("example.com".to_owned()),
        fingerprint: Some("chrome".to_owned()),
    })
}

#[test]
fn selects_raw_tcp_vless_outbound_with_ip_server() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server().port, 443);
}

#[test]
fn selects_default_outbound_tag_when_present() {
    let mut first = vless_outbound(
        StreamSecurity::None,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        1080,
    );
    first.tag = Some("direct".to_owned());
    let mut second = vless_outbound(
        StreamSecurity::None,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))),
        443,
    );
    second.tag = Some("proxy".to_owned());
    let config = CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![first, second],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig::default(),
    };

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server().port, 443);
}

#[test]
fn selects_reality_vless_outbound_for_handshake_provider_path() {
    let config = config_with_outbound(vless_outbound(
        reality_security(),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server().port, 443);
    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Reality(config)
            if config.server_name == "example.com"
                && config.fingerprint == "chrome"
                && config.public_key == [7; 32]
                && config.short_id == vec![1, 2, 3, 4]
                && config.spider_x == "/"
    ));
}

#[test]
fn rejects_tls_fingerprint_for_runtime_path() {
    let config = config_with_outbound(vless_outbound(
        tls_security(),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    ));

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(
        result,
        Err(CoreError::UnsupportedOutboundSecurity)
    ));
}

#[test]
fn selects_tls_vless_outbound_without_fingerprint() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some("server.example".to_owned()),
            fingerprint: None,
        }),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server().port, 443);
    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Tls(config) if config.server_name == "server.example"
    ));
}

#[test]
fn selects_tls_explicit_server_name_over_domain_outbound() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some("override.example".to_owned()),
            fingerprint: None,
        }),
        TargetAddr::Domain("vless.test".to_owned()),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Tls(config) if config.server_name == "override.example"
    ));
}

#[test]
fn selects_tls_server_name_from_domain_outbound_when_missing() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: None,
            fingerprint: None,
        }),
        TargetAddr::Domain("vless.test".to_owned()),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Tls(config) if config.server_name == "vless.test"
    ));
}

#[test]
fn rejects_tls_empty_server_name() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some("".to_owned()),
            fingerprint: None,
        }),
        TargetAddr::Domain("vless.test".to_owned()),
        443,
    ));

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(
        result,
        Err(CoreError::UnsupportedOutboundSecurity)
    ));
}

#[test]
fn rejects_tls_ip_server_without_server_name() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: None,
            fingerprint: None,
        }),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    ));

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(
        result,
        Err(CoreError::UnsupportedOutboundSecurity)
    ));
}

#[test]
fn rejects_tls_fingerprint_without_plain_rustls_downgrade() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some("server.example".to_owned()),
            fingerprint: Some("chrome".to_owned()),
        }),
        TargetAddr::Domain("vless.test".to_owned()),
        443,
    ));

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(
        result,
        Err(CoreError::UnsupportedOutboundSecurity)
    ));
}

#[test]
fn selects_domain_vless_server_for_dns_resolution() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Domain("vless.test".to_owned()),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server().port, 443);
    assert_eq!(
        selected.server().addr,
        RoutingTargetAddr::Domain("vless.test".to_owned())
    );
}

#[test]
fn rejects_vision_flow_for_raw_tcp_runtime_path() {
    let mut outbound = vless_outbound(
        StreamSecurity::None,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    );
    let OutboundSettings::Vless(settings) = &mut outbound.settings else {
        panic!("expected vless outbound");
    };
    settings.users[0].flow = Some("xtls-rprx-vision".to_owned());
    let config = config_with_outbound(outbound);

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(result, Err(CoreError::UnsupportedOutboundFlow)));
}

#[test]
fn selects_tls_vision_outbound_for_protected_stream_boundary() {
    let mut outbound = vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some("example.com".to_owned()),
            fingerprint: None,
        }),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    );
    let OutboundSettings::Vless(settings) = &mut outbound.settings else {
        panic!("expected vless outbound");
    };
    settings.users[0].flow = Some("xtls-rprx-vision".to_owned());
    let config = config_with_outbound(outbound);

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.user().flow.as_deref(), Some("xtls-rprx-vision"));
    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Tls(_)
    ));
}

#[test]
fn selects_reality_vision_outbound_for_protected_stream_boundary() {
    let mut outbound = vless_outbound(
        reality_security(),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    );
    let OutboundSettings::Vless(settings) = &mut outbound.settings else {
        panic!("expected vless outbound");
    };
    settings.users[0].flow = Some("xtls-rprx-vision".to_owned());
    let config = config_with_outbound(outbound);

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.user().flow.as_deref(), Some("xtls-rprx-vision"));
    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Reality(_)
    ));
}

#[tokio::test]
async fn vless_tcp_open_reports_dns_failure_for_unresolved_server_domain() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Domain("missing.test".to_owned()),
        443,
    ));
    let outbound = select_vless_tcp_outbound(&config).unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        80,
        RoutingNetwork::Tcp,
    );

    let result =
        xray_core_rs::open_vless_tcp_stream_with_resolver(&outbound, &target, &EmptyDnsResolver)
            .await;

    assert!(matches!(
        result,
        Err(CoreError::Transport(TransportError::NoResolvedAddress(domain, 443)))
            if domain == "missing.test"
    ));
}

#[tokio::test]
async fn socks_client_reaches_echo_target_through_vless_tcp_outbound() {
    timeout(Duration::from_secs(2), run_socks_to_vless_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn socks_client_reaches_echo_target_through_freedom_outbound() {
    timeout(Duration::from_secs(2), run_socks_to_freedom_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_tcp_client_completes_handshake_through_freedom_outbound() {
    timeout(Duration::from_secs(2), run_tun_tcp_handshake_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_tcp_client_reaches_echo_target_through_freedom_outbound() {
    timeout(Duration::from_secs(2), run_tun_tcp_freedom_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_tcp_client_reaches_echo_target_through_vless_tcp_outbound() {
    timeout(Duration::from_secs(2), run_tun_tcp_vless_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_tcp_client_uses_inbound_tag_routing_rule_to_reach_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_tun_tcp_routed_freedom_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_client_uses_inbound_tag_routing_rule_to_reach_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_to_routed_freedom_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_client_uses_domain_routing_rule_to_reach_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_to_domain_routed_freedom_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_client_uses_ip_routing_rule_to_reach_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_to_ip_routed_freedom_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_client_reaches_echo_target_through_domain_vless_server() {
    timeout(
        Duration::from_secs(2),
        run_domain_vless_server_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_client_preserves_domain_target_through_domain_vless_server() {
    timeout(
        Duration::from_secs(2),
        run_domain_target_preservation_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_client_reaches_echo_target_through_vless_tls_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_to_vless_tls_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn http_client_reaches_echo_target_through_vless_tcp_outbound() {
    timeout(Duration::from_secs(2), run_http_to_vless_echo_scenario())
        .await
        .unwrap();
}

async fn run_socks_to_vless_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (vless_addr, vless_handle) = spawn_fake_vless_server().await;
    let config = runtime_config_with_vless_server(vless_addr);

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello runtime").await.unwrap();
    let mut echoed = vec![0; "hello runtime".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello runtime");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_to_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let config = runtime_config_with_freedom_outbound();

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello freedom runtime").await.unwrap();
    let mut echoed = vec![0; "hello freedom runtime".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello freedom runtime");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_tcp_handshake_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpClient::new();
    client.connect(echo_addr);

    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    assert!(client.may_send());
    core.stop().await.unwrap();
    echo_handle.abort();
}

async fn run_tun_tcp_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpClient::new();
    client.connect(echo_addr);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    client.send_payload(b"hello tun");
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= "hello tun".len()
    })
    .await;

    assert_eq!(received, b"hello tun");
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_tcp_vless_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (vless_addr, vless_handle) = spawn_fake_vless_server().await;
    let mut core = Core::new(runtime_tun_config_with_vless_server(vless_addr)).unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpClient::new();
    client.connect(echo_addr);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    client.send_payload(b"hello tun vless");
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= "hello tun vless".len()
    })
    .await;

    assert_eq!(received, b"hello tun vless");
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_tcp_routed_freedom_echo_scenario() {
    let unused_proxy_port = allocate_unused_loopback_port();
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = Core::new(runtime_tun_config_with_routed_freedom_outbound(
        unused_proxy_port,
    ))
    .unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpClient::new();
    client.connect(echo_addr);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    client.send_payload(b"hello tun routed");
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= "hello tun routed".len()
    })
    .await;

    assert_eq!(received, b"hello tun routed");
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_to_routed_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let config = runtime_config_with_routed_freedom_outbound(allocate_unused_loopback_port());

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello routed freedom").await.unwrap();
    let mut echoed = vec![0; "hello routed freedom".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello routed freedom");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_to_domain_routed_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let resolver = StaticDnsResolver {
        domain: "api.example.com",
        addr: echo_addr,
    };
    let config =
        runtime_config_with_domain_routed_freedom_outbound(allocate_unused_loopback_port());

    let mut core = Core::with_dns_resolver(config, Arc::new(resolver)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect_domain(&mut client, "api.example.com", echo_addr.port()).await;

    client
        .write_all(b"hello domain routed freedom")
        .await
        .unwrap();
    let mut echoed = vec![0; "hello domain routed freedom".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello domain routed freedom");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_to_ip_routed_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let config = runtime_config_with_ip_routed_freedom_outbound(allocate_unused_loopback_port());

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello ip routed freedom").await.unwrap();
    let mut echoed = vec![0; "hello ip routed freedom".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello ip routed freedom");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_http_to_vless_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (vless_addr, vless_handle) = spawn_fake_vless_server().await;
    let config = runtime_http_config_with_vless_server(vless_addr);

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let http_addr = core.inbound_addr(Some("http-in")).unwrap();

    let mut client = TcpStream::connect(http_addr).await.unwrap();
    http_connect(&mut client, echo_addr).await;

    client.write_all(b"hello http runtime").await.unwrap();
    let mut echoed = vec![0; "hello http runtime".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello http runtime");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_to_vless_tls_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (client_config, server_config) = tls_test_configs();
    let (vless_addr, vless_handle) = spawn_fake_tls_vless_server(server_config).await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config =
        runtime_config_with_tls_vless_domain_server("vless.test", vless_addr.port(), "vless.test");
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));

    let mut core =
        Core::with_runtime_dependencies(config, Arc::new(resolver), Arc::new(dialer)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello tls runtime").await.unwrap();
    let mut echoed = vec![0; "hello tls runtime".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello tls runtime");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_domain_vless_server_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (vless_addr, vless_handle) = spawn_fake_vless_server().await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config = runtime_config_with_vless_domain_server("vless.test", vless_addr.port());

    let mut core = Core::with_dns_resolver(config, Arc::new(resolver)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello dns runtime").await.unwrap();
    let mut echoed = vec![0; "hello dns runtime".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello dns runtime");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_domain_target_preservation_scenario() {
    let expected_target = Target::new(
        RoutingTargetAddr::Domain("example.com".to_owned()),
        443,
        RoutingNetwork::Tcp,
    );
    let (vless_addr, vless_handle) = spawn_vless_target_assertion_server(expected_target).await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config = runtime_config_with_vless_domain_server("vless.test", vless_addr.port());

    let mut core = Core::with_dns_resolver(config, Arc::new(resolver)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect_domain(&mut client, "example.com", 443).await;

    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

struct TunTcpClient {
    iface: SmolInterface,
    device: TestPacketDevice,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
}

impl TunTcpClient {
    fn new() -> Self {
        let mut device = TestPacketDevice::new(1500);
        let mut iface_config = SmolInterfaceConfig::new(SmolHardwareAddress::Ip);
        iface_config.random_seed = 0x7475_6e74_6573_7401;
        let mut iface = SmolInterface::new(iface_config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(SmolIpCidr::new(SmolIpAddress::v4(10, 10, 0, 2), 24))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(SmolIpv4Address::new(10, 10, 0, 1))
            .unwrap();

        let tcp_socket = smol_tcp::Socket::new(
            smol_tcp::SocketBuffer::new(vec![0; 8192]),
            smol_tcp::SocketBuffer::new(vec![0; 8192]),
        );
        let mut sockets = SocketSet::new(Vec::new());
        let tcp = sockets.add(tcp_socket);

        Self {
            iface,
            device,
            sockets,
            tcp,
        }
    }

    fn connect(&mut self, target: SocketAddr) {
        let SocketAddr::V4(target) = target else {
            panic!("TUN TCP test client currently covers IPv4 targets only");
        };
        self.sockets
            .get_mut::<smol_tcp::Socket>(self.tcp)
            .connect(self.iface.context(), (*target.ip(), target.port()), 49152)
            .unwrap();
    }

    fn may_send(&mut self) -> bool {
        self.sockets.get::<smol_tcp::Socket>(self.tcp).may_send()
    }

    fn send_payload(&mut self, payload: &[u8]) {
        self.sockets
            .get_mut::<smol_tcp::Socket>(self.tcp)
            .send_slice(payload)
            .unwrap();
    }

    fn recv_available(&mut self) -> Vec<u8> {
        let mut received = Vec::new();
        let socket = self.sockets.get_mut::<smol_tcp::Socket>(self.tcp);
        while socket.can_recv() {
            socket
                .recv(|data| {
                    received.extend_from_slice(data);
                    (data.len(), ())
                })
                .unwrap();
        }
        received
    }

    fn poll(&mut self) {
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }
}

async fn pump_tun_until(
    client: &mut TunTcpClient,
    tun: &TunEndpoint,
    mut is_done: impl FnMut(&mut TunTcpClient) -> bool,
) {
    let deadline = TokioInstant::now() + Duration::from_millis(750);
    loop {
        client.poll();
        while let Some(packet) = client.device.pop_outbound() {
            tun.push_inbound(packet).await.unwrap();
        }
        while let Some(packet) = tun.try_poll_outbound().await.unwrap() {
            client.device.push_inbound(packet);
        }
        client.poll();

        if is_done(client) {
            return;
        }
        assert!(
            TokioInstant::now() < deadline,
            "timed out waiting for TUN TCP client state"
        );
        sleep(Duration::from_millis(5)).await;
    }
}

#[derive(Debug)]
struct TestPacketDevice {
    mtu: usize,
    inbound: VecDeque<Bytes>,
    outbound: VecDeque<Bytes>,
}

impl TestPacketDevice {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
        }
    }

    fn push_inbound(&mut self, packet: Bytes) {
        self.inbound.push_back(packet);
    }

    fn pop_outbound(&mut self) -> Option<Bytes> {
        self.outbound.pop_front()
    }
}

impl SmolDevice for TestPacketDevice {
    type RxToken<'a>
        = TestRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TestTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            TestRxToken { packet },
            TestTxToken {
                mtu: self.mtu,
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TestTxToken {
            mtu: self.mtu,
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> SmolDeviceCapabilities {
        let mut capabilities = SmolDeviceCapabilities::default();
        capabilities.medium = SmolMedium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = None;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

#[derive(Debug)]
struct TestRxToken {
    packet: Bytes,
}

impl SmolRxToken for TestRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[derive(Debug)]
struct TestTxToken<'a> {
    mtu: usize,
    outbound: &'a mut VecDeque<Bytes>,
}

impl SmolTxToken for TestTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len.min(self.mtu)];
        let result = f(&mut packet);
        self.outbound.push_back(Bytes::from(packet));
        result
    }
}

async fn spawn_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut read_half, mut write_half) = stream.split();
        tokio::io::copy(&mut read_half, &mut write_half)
            .await
            .unwrap();
    });
    (addr, handle)
}

async fn spawn_fake_vless_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_header(&mut inbound).await;
        let mut target_stream = TcpStream::connect(target).await.unwrap();
        inbound.write_all(&[0, 0]).await.unwrap();
        copy_bidirectional(&mut inbound, &mut target_stream)
            .await
            .unwrap();
    });
    (addr, handle)
}

async fn spawn_vless_target_assertion_server(
    expected_target: Target,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_target(&mut inbound).await;
        assert_eq!(target, expected_target);
    });
    (addr, handle)
}

fn tls_test_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["vless.test".to_owned()])
            .expect("generate self-signed certificate");
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add test root");
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider should support default TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();

    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider should support default TLS versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("build TLS server config");

    (Arc::new(client_config), Arc::new(server_config))
}

async fn spawn_fake_tls_vless_server(
    server_config: Arc<rustls::ServerConfig>,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut inbound = acceptor.accept(stream).await.unwrap();
        let target = read_vless_header(&mut inbound).await;
        let mut target_stream = TcpStream::connect(target).await.unwrap();
        inbound.write_all(&[0, 0]).await.unwrap();
        if let Err(error) = copy_bidirectional(&mut inbound, &mut target_stream).await {
            assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        }
    });

    (addr, handle)
}

async fn socks5_connect(client: &mut TcpStream, target: SocketAddr) {
    let SocketAddr::V4(target) = target else {
        panic!("this E2E covers IPv4 SOCKS targets only");
    };

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

async fn socks5_connect_domain(client: &mut TcpStream, domain: &str, port: u16) {
    let domain_len = u8::try_from(domain.len()).unwrap();

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 3, domain_len];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

async fn http_connect(client: &mut TcpStream, target: SocketAddr) {
    let authority = target.to_string();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();

    let response = read_http_response_head(client).await;
    let response = std::str::from_utf8(&response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200 Connection Established\r\n"),
        "unexpected HTTP CONNECT response: {response:?}"
    );
}

async fn read_http_response_head(client: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    loop {
        response.push(client.read_u8().await.unwrap());
        if response.ends_with(b"\r\n\r\n") {
            return response;
        }
    }
}

async fn read_vless_target<S>(stream: &mut S) -> Target
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await.unwrap();
    assert_eq!(version, 0);

    let mut uuid = [0; 16];
    stream.read_exact(&mut uuid).await.unwrap();
    assert_eq!(uuid, TEST_UUID_BYTES);

    let addons_len = stream.read_u8().await.unwrap();
    assert_eq!(addons_len, 0);
    let mut addons = vec![0; usize::from(addons_len)];
    stream.read_exact(&mut addons).await.unwrap();

    let command = stream.read_u8().await.unwrap();
    assert_eq!(command, 1);

    let port = stream.read_u16().await.unwrap();
    let address_type = stream.read_u8().await.unwrap();
    let addr = match address_type {
        1 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await.unwrap();
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        2 => {
            let len = stream.read_u8().await.unwrap();
            let mut domain = vec![0; usize::from(len)];
            stream.read_exact(&mut domain).await.unwrap();
            RoutingTargetAddr::Domain(String::from_utf8(domain).unwrap())
        }
        3 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await.unwrap();
            RoutingTargetAddr::Ip(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        other => panic!("unsupported VLESS address type {other}"),
    };

    Target::new(addr, port, RoutingNetwork::Tcp)
}

async fn read_vless_header<S>(stream: &mut S) -> SocketAddr
where
    S: AsyncRead + Unpin,
{
    let target = read_vless_target(stream).await;
    let RoutingTargetAddr::Ip(ip) = target.addr else {
        panic!("this E2E expects an IP VLESS target");
    };
    SocketAddr::new(ip, target.port)
}
