use std::collections::{BTreeMap, VecDeque};
use std::future::pending;
use std::io::{Cursor, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload as AeadPayload};
use aes_gcm::{Aes128Gcm, Nonce};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Sha256;
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
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Duration, Instant as TokioInstant};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use xray_config::{
    parse_xray_json, CoreConfig, DnsConfig, DnsFakeIpConfig, DnsHostMapping, DnsHostTarget,
    DnsNameServerConfig, DnsQueryStrategy, DnsServerConfig, DnsServerEndpoint, DomainMatcher,
    InboundConfig, InboundProtocol, InboundSniffingConfig, IpCidr, IpMatcher, Network,
    OutboundConfig, OutboundSettings, PolicyConfig, PolicyLevelConfig, RealitySettings,
    RealityShortId, RoutingConfig, RoutingDomainStrategy, RoutingRule, SniffingDestination,
    StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::{
    select_tcp_outbound_for_session, select_tcp_outbound_for_session_with_resolver,
    select_vless_tcp_outbound, Core, CoreError, DnsBootstrapMode, RuntimeLogConfig, RuntimeLogger,
    TcpOutbound, TunRuntimeOptions, TunRuntimeProfile,
};
use xray_proxy::inbound::{encode_socks5_udp_datagram, parse_socks5_udp_datagram};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, read_udp_packet, read_xudp_packet,
    unpad_vision_block, VisionCommand, VisionPadding,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{
    BoxedTransportStream, DnsResolver, RealityClientConfig, RealityTlsEngine, TlsConnector,
    TransportDialer, TransportError, TransportStream,
};
use xray_tun::{TunEndpoint, TunError, TunStats};

const ICMPV4_PROTOCOL: u8 = 1;
const ICMPV6_PROTOCOL: u8 = 58;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const TEST_UUID_BYTES: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

fn vless_outbound(security: StreamSecurity, server: TargetAddr, port: u16) -> OutboundConfig {
    OutboundConfig {
        tag: Some("proxy".to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security,
            socket_options: None,
        },
        settings: OutboundSettings::Vless(VlessOutboundSettings {
            server,
            port,
            users: vec![VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: None,
                level: 0,
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
            socket_options: None,
        },
        settings: OutboundSettings::Freedom,
    }
}

fn tagged_dns_server(endpoint: DnsServerEndpoint, tag: &str) -> DnsServerConfig {
    tagged_dns_server_with_transport(endpoint, tag, xray_config::DnsServerTransport::Classic)
}

fn tagged_dns_server_with_transport(
    endpoint: DnsServerEndpoint,
    tag: &str,
    transport: xray_config::DnsServerTransport,
) -> DnsServerConfig {
    DnsServerConfig::Policy(DnsNameServerConfig {
        endpoint,
        transport,
        domains: Vec::new(),
        expected_ips: Default::default(),
        unexpected_ips: Default::default(),
        tag: tag.to_owned(),
        timeout_ms: 0,
        skip_fallback: false,
        query_strategy: DnsQueryStrategy::UseIp,
        final_query: false,
    })
}

fn config_with_outbound(outbound: OutboundConfig) -> CoreConfig {
    CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![outbound],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn allocate_unused_loopback_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn full_xray_core_fixture_config() -> CoreConfig {
    let fixture =
        include_str!("../../../tests/fixtures/configs/xray_core_reality_split_routing_full.json");
    parse_xray_json(fixture)
        .expect("xray-core-compatible fixture should parse")
        .config
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

#[derive(Debug, Default)]
struct PendingRealityOpenState {
    started: AtomicUsize,
    active: AtomicUsize,
}

impl PendingRealityOpenState {
    fn started(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
struct PendingRealityEngine {
    state: Arc<PendingRealityOpenState>,
}

struct PendingRealityOpenGuard {
    state: Arc<PendingRealityOpenState>,
}

impl Drop for PendingRealityOpenGuard {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl RealityTlsEngine for PendingRealityEngine {
    async fn connect(
        &self,
        _config: &RealityClientConfig,
        _target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        self.state.active.fetch_add(1, Ordering::SeqCst);
        self.state.started.fetch_add(1, Ordering::SeqCst);
        let _guard = PendingRealityOpenGuard {
            state: Arc::clone(&self.state),
        };
        pending::<Result<BoxedTransportStream, TransportError>>().await
    }
}

#[derive(Debug, Clone)]
struct FailingRealityEngine {
    attempts: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, Copy)]
struct PanickingRealityEngine;

#[async_trait]
impl RealityTlsEngine for PanickingRealityEngine {
    async fn connect(
        &self,
        _config: &RealityClientConfig,
        _target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        panic!("injected Reality engine panic");
    }
}

#[async_trait]
impl RealityTlsEngine for FailingRealityEngine {
    async fn connect(
        &self,
        _config: &RealityClientConfig,
        _target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(TransportError::Tls(std::io::Error::new(
            ErrorKind::ConnectionReset,
            "injected Reality handshake failure",
        )))
    }
}

#[derive(Debug, Clone)]
struct StalledWriteRealityEngine;

#[async_trait]
impl RealityTlsEngine for StalledWriteRealityEngine {
    async fn connect(
        &self,
        _config: &RealityClientConfig,
        _target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        Ok(Box::new(StalledAfterFirstWriteStream {
            accepted_first_write: false,
        }))
    }
}

struct StalledAfterFirstWriteStream {
    accepted_first_write: bool,
}

impl AsyncRead for StalledAfterFirstWriteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for StalledAfterFirstWriteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.accepted_first_write {
            Poll::Pending
        } else {
            self.accepted_first_write = true;
            Poll::Ready(Ok(input.len()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TransportStream for StalledAfterFirstWriteStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

fn runtime_config_with_freedom_outbound() -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![freedom_outbound()],
        default_outbound_tag: Some("direct".to_owned()),
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_socks_config_with_level_0_policy(policy: PolicyLevelConfig) -> CoreConfig {
    let mut config = runtime_config_with_freedom_outbound();
    config.policy = PolicyConfig {
        levels: BTreeMap::from([(0, policy)]),
        system: Default::default(),
    };
    config
}

fn runtime_tun_config_with_freedom_outbound() -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("tun-in".to_owned()),
            protocol: InboundProtocol::Tun,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![freedom_outbound()],
        default_outbound_tag: Some("direct".to_owned()),
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_tun_config_with_routed_freedom_outbound(unused_proxy_port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("tun-in".to_owned()),
            protocol: InboundProtocol::Tun,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
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
            ..Default::default()
        },
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_tun_config_with_route_only_quic_sniffing(unused_proxy_port: u16) -> CoreConfig {
    let mut config = runtime_tun_config_with_routed_freedom_outbound(unused_proxy_port);
    config.inbounds[0].sniffing = Some(InboundSniffingConfig {
        enabled: true,
        dest_override: vec![SniffingDestination::Quic],
        metadata_only: false,
        route_only: true,
    });
    config.routing.rules[0].inbound_tags = Vec::new();
    config.routing.rules[0].domain_matchers =
        vec![DomainMatcher::Suffix("quic.example".to_owned())];
    config
}

fn runtime_tun_config_with_fake_ip_domain_routed_freedom_outbound(
    unused_proxy_port: u16,
) -> CoreConfig {
    let mut config = runtime_tun_config_with_routed_freedom_outbound(unused_proxy_port);
    config.routing.rules[0].domain_matchers = vec![DomainMatcher::Suffix("example.com".to_owned())];
    config.dns = DnsConfig {
        fake_ip: Some(DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15).unwrap(),
            pool_size: 32_768,
            ttl: 60,
        }),
        ..Default::default()
    };
    config
}

fn runtime_tun_config_with_mobile_fake_dns_freedom(dns_server: SocketAddr) -> CoreConfig {
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.dns = DnsConfig {
        servers: vec![DnsServerConfig::Ip(dns_server)],
        fake_ip: Some(DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15).unwrap(),
            pool_size: 32_768,
            ttl: 60,
        }),
        ..Default::default()
    };
    config
}

fn runtime_tun_config_with_dns_proxy_servers(servers: Vec<SocketAddr>) -> CoreConfig {
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.dns.servers = servers.into_iter().map(DnsServerConfig::Ip).collect();
    config
}

fn runtime_tun_dns_proxy_config_routing_second_upstream_to_freedom(
    first: SocketAddr,
    second: SocketAddr,
) -> CoreConfig {
    let broken_vless = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_unused_loopback_port()));
    let mut config = runtime_tun_config_with_vless_server(broken_vless);
    config.outbounds.push(freedom_outbound());
    let prefix = if second.is_ipv4() { 32 } else { 128 };
    config.routing.rules = vec![RoutingRule {
        inbound_tags: vec!["dns-route".to_owned()],
        domain_matchers: Vec::new(),
        ip_matchers: vec![IpMatcher::Cidr(IpCidr::new(second.ip(), prefix).unwrap())],
        outbound_tag: "direct".to_owned(),
    }];
    config.dns.tag = "dns-global".to_owned();
    config.dns.servers = vec![
        DnsServerConfig::Ip(first),
        tagged_dns_server(DnsServerEndpoint::Ip(second), "dns-route"),
    ];
    config
}

fn runtime_tun_config_with_fake_ip_ip_if_non_match_routed_freedom_outbound(
    unused_proxy_port: u16,
) -> CoreConfig {
    let mut config = runtime_tun_config_with_routed_freedom_outbound(unused_proxy_port);
    config.routing.rules[0].ip_matchers = vec![IpMatcher::Cidr(
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8).unwrap(),
    )];
    config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
    config.dns = DnsConfig {
        fake_ip: Some(DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15).unwrap(),
            pool_size: 32_768,
            ttl: 60,
        }),
        ..Default::default()
    };
    config
}

fn runtime_tun_config_with_vless_server(vless_addr: SocketAddr) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("tun-in".to_owned()),
            protocol: InboundProtocol::Tun,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(vless_addr.ip()),
            vless_addr.port(),
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_socks_config_with_vless_server(vless_addr: SocketAddr) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(vless_addr.ip()),
            vless_addr.port(),
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_socks_config_with_vless_server_user_level(
    vless_addr: SocketAddr,
    user_level: u32,
) -> CoreConfig {
    let mut config = runtime_socks_config_with_vless_server(vless_addr);
    let OutboundSettings::Vless(settings) = &mut config.outbounds[0].settings else {
        panic!("expected vless outbound");
    };
    settings.users[0].level = user_level;
    config
}

fn runtime_tun_config_with_tls_vision_vless_domain_server(
    domain: &str,
    port: u16,
    server_name: &str,
) -> CoreConfig {
    let mut outbound = vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some(server_name.to_owned()),
            fingerprint: None,
            allow_insecure: false,
        }),
        TargetAddr::Domain(domain.to_owned()),
        port,
    );
    let OutboundSettings::Vless(settings) = &mut outbound.settings else {
        panic!("expected vless outbound");
    };
    settings.users[0].flow = Some("xtls-rprx-vision".to_owned());

    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("tun-in".to_owned()),
            protocol: InboundProtocol::Tun,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![outbound],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_tun_config_with_reality_vision_vless_server(port: u16) -> CoreConfig {
    let mut outbound = vless_outbound(
        reality_security(),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port,
    );
    let OutboundSettings::Vless(settings) = &mut outbound.settings else {
        panic!("expected vless outbound");
    };
    settings.users[0].flow = Some("xtls-rprx-vision".to_owned());

    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("tun-in".to_owned()),
            protocol: InboundProtocol::Tun,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![outbound],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_socks_config_with_tls_vision_vless_domain_server(
    domain: &str,
    port: u16,
    server_name: &str,
) -> CoreConfig {
    let mut config =
        runtime_tun_config_with_tls_vision_vless_domain_server(domain, port, server_name);
    config.inbounds[0].tag = Some("socks-in".to_owned());
    config.inbounds[0].protocol = InboundProtocol::Socks;
    config
}

fn runtime_config_with_routed_freedom_outbound(unused_proxy_port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
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
            ..Default::default()
        },
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_config_with_domain_routed_freedom_outbound(unused_proxy_port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
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
            ..Default::default()
        },
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_socks_config_with_route_only_http_sniffing(unused_proxy_port: u16) -> CoreConfig {
    let mut config = runtime_config_with_domain_routed_freedom_outbound(unused_proxy_port);
    config.inbounds[0].sniffing = Some(InboundSniffingConfig {
        enabled: true,
        dest_override: vec![SniffingDestination::Http],
        metadata_only: false,
        route_only: true,
    });
    config.routing.rules[0].domain_matchers =
        vec![DomainMatcher::Suffix("routed.example".to_owned())];
    config
}

fn runtime_socks_config_with_route_only_quic_sniffing(unused_proxy_port: u16) -> CoreConfig {
    let mut config = runtime_config_with_domain_routed_freedom_outbound(unused_proxy_port);
    config.inbounds[0].sniffing = Some(InboundSniffingConfig {
        enabled: true,
        dest_override: vec![SniffingDestination::Quic],
        metadata_only: false,
        route_only: true,
    });
    config.routing.rules[0].domain_matchers =
        vec![DomainMatcher::Suffix("quic.example".to_owned())];
    config
}

fn runtime_config_with_ip_routed_freedom_outbound(unused_proxy_port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
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
            ..Default::default()
        },
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_config_with_ip_if_non_match_routed_freedom_outbound(
    inbound_protocol: InboundProtocol,
    inbound_tag: &str,
    unused_proxy_port: u16,
) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some(inbound_tag.to_owned()),
            protocol: inbound_protocol,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
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
            domain_strategy: RoutingDomainStrategy::IpIfNonMatch,
        },
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_config_with_vless_server(vless_addr: SocketAddr) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(vless_addr.ip()),
            vless_addr.port(),
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_http_config_with_vless_server(vless_addr: SocketAddr) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("http-in".to_owned()),
            protocol: InboundProtocol::Http,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(vless_addr.ip()),
            vless_addr.port(),
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn runtime_config_with_vless_domain_server(domain: &str, port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Domain(domain.to_owned()),
            port,
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
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
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::Tls(TlsSettings {
                server_name: Some(server_name.to_owned()),
                fingerprint: None,
                allow_insecure: false,
            }),
            TargetAddr::Domain(domain.to_owned()),
            port,
        )],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn reality_security() -> StreamSecurity {
    reality_security_with_fingerprint("chrome")
}

fn reality_security_with_fingerprint(fingerprint: &str) -> StreamSecurity {
    StreamSecurity::Reality(RealitySettings {
        server_name: "example.com".to_owned(),
        fingerprint: fingerprint.to_owned(),
        public_key: [7; 32],
        short_id: RealityShortId::try_from_slice(&[1, 2, 3, 4]).unwrap(),
        spider_x: "/".to_owned(),
        mldsa65_verify: None,
    })
}

fn tls_security() -> StreamSecurity {
    StreamSecurity::Tls(TlsSettings {
        server_name: Some("example.com".to_owned()),
        fingerprint: Some("chrome".to_owned()),
        allow_insecure: false,
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
fn full_xray_core_fixture_builds_core() {
    let config = full_xray_core_fixture_config();

    Core::new(config).expect("full xray-core fixture should build a core");
}

#[test]
fn full_xray_core_fixture_routes_reserved_domain_direct() {
    let config = full_xray_core_fixture_config();
    let target = Target::new(
        RoutingTargetAddr::Domain("api.direct.example".to_owned()),
        443,
        RoutingNetwork::Tcp,
    );

    let outbound = select_tcp_outbound_for_session(&config, None, &target)
        .expect("reserved domain rule should select direct");

    assert!(matches!(outbound, TcpOutbound::Freedom));
}

#[test]
fn full_xray_core_fixture_routes_reserved_cidr_direct() {
    let config = full_xray_core_fixture_config();
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))),
        443,
        RoutingNetwork::Tcp,
    );

    let outbound = select_tcp_outbound_for_session(&config, None, &target)
        .expect("reserved CIDR rule should select direct");

    assert!(matches!(outbound, TcpOutbound::Freedom));
}

#[tokio::test]
async fn full_xray_core_fixture_routes_inbound_rule_before_ip_if_non_match_dns() {
    let config = full_xray_core_fixture_config();
    let target = Target::new(
        RoutingTargetAddr::Domain("not-ru.example".to_owned()),
        443,
        RoutingNetwork::Tcp,
    );

    let outbound = select_tcp_outbound_for_session_with_resolver(
        &config,
        Some("inbound_49783"),
        &target,
        &EmptyDnsResolver,
    )
    .await
    .expect("inbound-tag rule should select proxy before DNS second pass");

    assert!(matches!(outbound, TcpOutbound::Vless(_)));
}

#[test]
fn full_xray_core_fixture_missing_api_outbound_fails_only_when_selected() {
    let config = full_xray_core_fixture_config();
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
        RoutingNetwork::Tcp,
    );

    let error = select_tcp_outbound_for_session(&config, Some("api"), &target).unwrap_err();

    assert!(matches!(error, CoreError::NoSupportedOutbound));
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
        dns: Default::default(),
        policy: Default::default(),
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
fn selects_reality_vless_outbound_preserves_non_default_fingerprint() {
    let config = config_with_outbound(vless_outbound(
        reality_security_with_fingerprint("hellochrome_131"),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Reality(config)
            if config.fingerprint == "hellochrome_131"
    ));
}

#[test]
fn parsed_config_reality_fingerprint_reaches_transport_config() {
    let raw = r#"{
        "inbounds": [],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "203.0.113.10",
                            "port": 443,
                            "users": [
                                {
                                    "id": "00010203-0405-0607-0809-0a0b0c0d0e0f",
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.com",
                        "fingerprint": "hellochrome_131",
                        "publicKey": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
                        "shortId": "01020304",
                        "spiderX": "/"
                    }
                }
            }
        ]
    }"#;
    let parsed = parse_xray_json(raw).unwrap();

    let selected = select_vless_tcp_outbound(&parsed.config).unwrap();

    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Reality(config)
            if config.fingerprint == "hellochrome_131"
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
            allow_insecure: false,
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
            allow_insecure: false,
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
            allow_insecure: false,
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
            allow_insecure: false,
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
            allow_insecure: false,
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
            allow_insecure: false,
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
            allow_insecure: false,
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
async fn socks_policy_handshake_timeout_closes_idle_client() {
    timeout(
        Duration::from_secs(2),
        run_socks_policy_handshake_timeout_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_policy_conn_idle_timeout_closes_idle_tunnel() {
    timeout(
        Duration::from_secs(2),
        run_socks_policy_conn_idle_timeout_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_policy_vless_user_level_conn_idle_closes_idle_tunnel() {
    timeout(
        Duration::from_secs(2),
        run_socks_policy_vless_user_level_conn_idle_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_udp_client_reaches_echo_target_through_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_udp_freedom_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_udp_client_reaches_echo_target_through_vless_udp_outbound() {
    timeout(Duration::from_secs(2), run_socks_udp_vless_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn socks_udp_client_reaches_echo_target_through_vless_xudp_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_udp_vless_xudp_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_udp_client_reaches_echo_target_through_vision_xudp_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_udp_vision_xudp_echo_scenario(),
    )
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
async fn tun_tcp_clients_reach_same_target_concurrently_through_freedom_outbound() {
    timeout(
        Duration::from_secs(3),
        run_tun_tcp_concurrent_same_target_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_tcp_timings_stay_zero_when_collection_disabled() {
    let stats = timeout(
        Duration::from_secs(2),
        run_tun_tcp_freedom_echo_scenario_with_options(TunRuntimeOptions::default()),
    )
    .await
    .unwrap();

    assert_eq!(stats.tcp_open_events, 0);
    assert_eq!(stats.tcp_first_byte_events, 0);
}

#[tokio::test]
async fn tun_tcp_timings_record_when_collection_enabled() {
    let stats = timeout(
        Duration::from_secs(2),
        run_tun_tcp_freedom_echo_scenario_with_options(TunRuntimeOptions {
            collect_tcp_timings: true,
            ..TunRuntimeOptions::default()
        }),
    )
    .await
    .unwrap();

    assert!(stats.tcp_open_events >= 1);
    assert!(stats.tcp_first_byte_events >= 1);
}

#[tokio::test]
async fn tun_tcp_timings_record_when_runtime_logger_enabled() {
    let stats = timeout(
        Duration::from_secs(2),
        run_tun_tcp_freedom_echo_scenario_with_runtime_logger(),
    )
    .await
    .unwrap();

    assert!(stats.tcp_open_events >= 1);
    assert!(stats.tcp_first_byte_events >= 1);
}

#[tokio::test]
async fn tun_tcp_client_reaches_echo_target_through_vless_tcp_outbound() {
    timeout(Duration::from_secs(2), run_tun_tcp_vless_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_tcp_upload_backpressures_instead_of_aborting_when_remote_write_stalls() {
    timeout(
        Duration::from_secs(2),
        run_tun_tcp_upload_backpressure_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_reality_blackhole_respects_policy_handshake_timeout() {
    timeout(
        Duration::from_secs(4),
        run_tun_reality_blackhole_handshake_timeout_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_reality_blackhole_pending_opens_are_cancelled_on_core_stop() {
    timeout(
        Duration::from_secs(3),
        run_tun_reality_blackhole_stop_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_reality_blackhole_bounds_pending_opens_for_low_memory_profile() {
    timeout(
        Duration::from_secs(3),
        run_tun_reality_pending_open_budget_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_reality_blackhole_keeps_upload_in_tcp_window_until_remote_open() {
    timeout(
        Duration::from_secs(3),
        run_tun_reality_pre_open_upload_backpressure_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_reality_open_error_burst_keeps_tun_runtime_available() {
    timeout(
        Duration::from_secs(3),
        run_tun_reality_open_error_burst_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_reality_bridge_panic_isolated_and_logged_without_stopping_runtime() {
    timeout(
        Duration::from_secs(3),
        run_tun_reality_bridge_panic_scenario(),
    )
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
async fn tun_replies_to_ipv4_icmp_echo_request() {
    timeout(Duration::from_secs(2), run_tun_icmp_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_replies_to_ipv6_icmp_echo_request() {
    timeout(Duration::from_secs(2), run_tun_icmpv6_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_malformed_packet_storm_keeps_runtime_available() {
    timeout(
        Duration::from_secs(3),
        run_tun_malformed_packet_storm_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_udp_client_reaches_echo_target_through_freedom_outbound() {
    timeout(Duration::from_secs(2), run_tun_udp_freedom_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_udp_route_only_quic_sniffing_uses_sni_for_routing() {
    timeout(
        Duration::from_secs(2),
        run_tun_udp_route_only_quic_sniffing_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_udp_flow_uses_domain_routing_rule() {
    timeout(
        Duration::from_secs(2),
        run_tun_fake_dns_udp_domain_routing_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_restored_domain_reaches_udp_freedom_through_routed_static_only_dns() {
    timeout(
        Duration::from_secs(3),
        run_tun_fake_dns_static_only_udp_freedom_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_restored_domain_reaches_ipv6_udp_freedom_through_routed_static_only_dns() {
    timeout(
        Duration::from_secs(3),
        run_tun_fake_dns_static_only_ipv6_udp_freedom_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_restored_domain_reaches_tcp_freedom_through_routed_static_only_dns() {
    timeout(
        Duration::from_secs(3),
        run_tun_fake_dns_static_only_tcp_freedom_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_routed_resolver_preserves_domain_upstream_through_vless() {
    timeout(
        Duration::from_secs(3),
        run_tun_fake_dns_domain_upstream_vless_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_without_servers_preserves_domain_for_default_vless() {
    timeout(
        Duration::from_secs(3),
        run_tun_fake_dns_static_only_vless_remote_resolution_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_https_query_returns_nodata_from_original_resolver_address() {
    timeout(
        Duration::from_secs(2),
        run_tun_fake_dns_https_nodata_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_pool_rolls_over_from_original_resolver_address() {
    timeout(
        Duration::from_secs(2),
        run_tun_fake_dns_pool_rollover_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_forwards_udp_wire_response_from_local_anchor() {
    timeout(Duration::from_secs(2), run_tun_dns_proxy_udp_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_adapts_to_local_tcp_upstream_without_routing() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_to_local_tcp_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_adapts_to_routed_tcp_upstream_over_vless() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_to_routed_tcp_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_tcp_servfail_fails_over_to_next_upstream() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_to_tcp_status_failover_scenario(0x8182, 0x2221),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_tcp_truncated_response_fails_over_to_next_upstream() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_to_tcp_status_failover_scenario(0x8380, 0x2222),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_fails_over_to_second_server() {
    timeout(
        Duration::from_secs(3),
        run_tun_dns_proxy_udp_failover_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_returns_servfail_when_all_servers_time_out() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_servfail_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_truncates_response_larger_than_tun_mtu() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_truncated_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_rejects_oversized_response_with_wrong_transaction_id() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_oversized_wrong_id_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_ignores_wrong_question_from_selected_upstream() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_wrong_question_then_valid_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_uses_vless_outbound_and_keeps_anchor_source() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_vless_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_sends_domain_upstream_to_vless_without_local_resolution() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_vless_domain_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_freedom_uses_static_bootstrap_mapping() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_static_bootstrap_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_freedom_resolves_terminal_bootstrap_alias() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_bootstrap_alias_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_ip_if_non_match_skips_static_bootstrap_ip_routing() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_static_ip_skip_routing_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_ip_if_non_match_skips_bootstrap_resolver_ip_routing() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_dynamic_ip_skip_routing_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_static_only_skips_unbootstrapped_domain_and_fails_over() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_static_only_failover_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_static_only_returns_servfail_without_usable_upstream() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_static_only_failure_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_allows_cold_vless_attempt_beyond_freedom_timeout() {
    timeout(
        Duration::from_secs(3),
        run_tun_dns_proxy_udp_delayed_vless_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_uses_vision_xudp_with_independent_global_id() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_vision_xudp_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_udp_reselects_outbound_for_each_upstream() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_udp_routed_failover_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_forwards_pipelined_tcp_stream_through_freedom() {
    timeout(Duration::from_secs(2), run_tun_dns_proxy_tcp_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_tcp_local_bypasses_configured_routing() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_tcp_local_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_tcp_fails_over_to_second_server() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_tcp_failover_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_tcp_reselects_outbound_for_each_upstream() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_tcp_routed_failover_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_tcp_routed_domain_uses_second_bootstrap_candidate() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_tcp_routed_domain_candidate_fallback_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_tcp_resets_client_when_all_servers_fail() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_tcp_failure_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_tcp_uses_vless_outbound() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_tcp_vless_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_dns_proxy_tcp_sends_domain_upstream_to_vless_without_local_resolution() {
    timeout(
        Duration::from_secs(2),
        run_tun_dns_proxy_tcp_vless_domain_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_mode_answers_pipelined_tcp_queries_at_anchor() {
    timeout(
        Duration::from_secs(2),
        run_tun_fake_dns_tcp_scenario(Ipv4Addr::new(198, 18, 0, 1)),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_mode_intercepts_pipelined_tcp_queries_to_external_resolver() {
    timeout(
        Duration::from_secs(2),
        run_tun_fake_dns_tcp_scenario(Ipv4Addr::new(8, 8, 8, 8)),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_fake_dns_udp_ip_if_non_match_uses_dns_second_pass_to_reach_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_tun_fake_dns_udp_ip_if_non_match_routed_freedom_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_udp_client_reaches_echo_target_through_vless_udp_outbound() {
    timeout(Duration::from_secs(2), run_tun_udp_vless_echo_scenario())
        .await
        .unwrap();
}

#[tokio::test]
async fn tun_udp_client_reaches_echo_target_through_vless_xudp_outbound() {
    timeout(
        Duration::from_secs(2),
        run_tun_udp_vless_xudp_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_udp_client_reaches_echo_target_through_vision_xudp_outbound() {
    timeout(
        Duration::from_secs(2),
        run_tun_udp_vision_xudp_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_regular_vision_udp443_is_rejected_with_icmp() {
    timeout(
        Duration::from_secs(2),
        run_tun_regular_vision_udp443_rejection_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_regular_vision_udp443_storm_releases_flows_with_logging_on_and_off() {
    timeout(
        Duration::from_secs(8),
        run_tun_regular_vision_udp443_rejection_storm_scenario(),
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
async fn socks_client_route_only_http_sniffing_uses_host_for_routing() {
    timeout(
        Duration::from_secs(2),
        run_socks_route_only_http_sniffing_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_client_route_only_http_sniffing_handles_split_host_header() {
    timeout(
        Duration::from_secs(2),
        run_socks_route_only_http_sniffing_split_echo_scenario(),
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
async fn socks_client_ip_if_non_match_uses_dns_second_pass_to_reach_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_to_ip_if_non_match_routed_freedom_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_udp_client_ip_if_non_match_uses_dns_second_pass_to_reach_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_socks_udp_ip_if_non_match_routed_freedom_echo_scenario(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_udp_client_route_only_quic_sniffing_uses_sni_for_routing() {
    timeout(
        Duration::from_secs(2),
        run_socks_udp_route_only_quic_sniffing_echo_scenario(),
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

#[tokio::test]
async fn http_client_ip_if_non_match_uses_dns_second_pass_to_reach_freedom_outbound() {
    timeout(
        Duration::from_secs(2),
        run_http_to_ip_if_non_match_routed_freedom_echo_scenario(),
    )
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

async fn run_socks_policy_handshake_timeout_scenario() {
    let config = runtime_socks_config_with_level_0_policy(PolicyLevelConfig {
        handshake: Some(0),
        ..Default::default()
    });

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    let mut byte = [0; 1];
    let read = timeout(Duration::from_millis(200), client.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
    core.stop().await.unwrap();
}

async fn run_socks_policy_conn_idle_timeout_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let config = runtime_socks_config_with_level_0_policy(PolicyLevelConfig {
        conn_idle: Some(0),
        ..Default::default()
    });

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    let mut byte = [0; 1];
    let read = timeout(Duration::from_millis(200), client.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_policy_vless_user_level_conn_idle_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (vless_addr, vless_handle) = spawn_fake_vless_server().await;
    let mut config = runtime_socks_config_with_vless_server_user_level(vless_addr, 8);
    config.policy = PolicyConfig {
        levels: BTreeMap::from([(
            8,
            PolicyLevelConfig {
                conn_idle: Some(0),
                ..Default::default()
            },
        )]),
        system: Default::default(),
    };

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    let mut byte = [0; 1];
    let read = timeout(Duration::from_millis(200), client.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
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

async fn run_socks_udp_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let config = runtime_config_with_freedom_outbound();

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut control = TcpStream::connect(socks_addr).await.unwrap();
    let relay_addr = socks5_udp_associate(&mut control).await;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(echo_addr.ip()),
        echo_addr.port(),
        RoutingNetwork::Udp,
    );
    let request = encode_socks5_udp_datagram(&target, b"hello socks udp").unwrap();

    socket.send_to(&request, relay_addr).await.unwrap();
    let mut response = vec![0; 2048];
    let (len, _) = socket.recv_from(&mut response).await.unwrap();
    let response = parse_socks5_udp_datagram(&response[..len]).unwrap();

    assert_eq!(&response.payload[..], b"hello socks udp");
    drop(socket);
    drop(control);
    core.stop().await.unwrap();
    echo_handle.abort();
}

async fn socks_udp_roundtrip(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) -> Bytes {
    let target = Target::new(
        RoutingTargetAddr::Ip(target_addr.ip()),
        target_addr.port(),
        RoutingNetwork::Udp,
    );
    socks_udp_roundtrip_target(socks_addr, target, payload).await
}

async fn socks_udp_roundtrip_target(
    socks_addr: SocketAddr,
    target: Target,
    payload: &[u8],
) -> Bytes {
    let mut control = TcpStream::connect(socks_addr).await.unwrap();
    let relay_addr = socks5_udp_associate(&mut control).await;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let request = encode_socks5_udp_datagram(&target, payload).unwrap();

    socket.send_to(&request, relay_addr).await.unwrap();
    let mut response = vec![0; 2048];
    let (len, _) = socket.recv_from(&mut response).await.unwrap();
    let response = parse_socks5_udp_datagram(&response[..len]).unwrap();
    drop(socket);
    drop(control);
    response.payload
}

async fn run_socks_udp_ip_if_non_match_routed_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let resolver = StaticDnsResolver {
        domain: "udp-ip-route.example.test",
        addr: echo_addr,
    };
    let config = runtime_config_with_ip_if_non_match_routed_freedom_outbound(
        InboundProtocol::Socks,
        "socks-in",
        allocate_unused_loopback_port(),
    );
    let mut core = Core::with_dns_resolver(config, Arc::new(resolver)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
    let target = Target::new(
        RoutingTargetAddr::Domain("udp-ip-route.example.test".to_owned()),
        echo_addr.port(),
        RoutingNetwork::Udp,
    );

    let payload =
        socks_udp_roundtrip_target(socks_addr, target, b"hello udp ip if non match").await;

    assert_eq!(&payload[..], b"hello udp ip if non match");
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_udp_route_only_quic_sniffing_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let config =
        runtime_socks_config_with_route_only_quic_sniffing(allocate_unused_loopback_port());

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let payload = quic_initial_packet_with_sni("quic.example");
    let echoed = socks_udp_roundtrip(socks_addr, echo_addr, &payload).await;

    assert_eq!(echoed, Bytes::from(payload));
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_udp_vless_echo_scenario() {
    let (vless_addr, vless_handle) =
        spawn_fake_vless_udp_server_for_payload(b"hello socks vless udp").await;
    let echo_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let mut core = Core::new(runtime_socks_config_with_vless_server(vless_addr)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let payload = socks_udp_roundtrip(socks_addr, echo_addr, b"hello socks vless udp").await;

    assert_eq!(&payload[..], b"hello socks vless udp");
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_udp_vless_xudp_echo_scenario() {
    let (vless_addr, vless_handle) =
        spawn_fake_vless_xudp_server_for_payload(b"hello socks vless xudp").await;
    let echo_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        allocate_unused_loopback_port(),
    );
    let mut core = Core::new(runtime_socks_config_with_vless_server(vless_addr)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let payload = socks_udp_roundtrip(socks_addr, echo_addr, b"hello socks vless xudp").await;

    assert_eq!(&payload[..], b"hello socks vless xudp");
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_udp_vision_xudp_echo_scenario() {
    let (client_config, server_config) = tls_test_configs();
    let echo_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        allocate_unused_loopback_port(),
    );
    let (vless_addr, vless_handle) =
        spawn_fake_tls_vision_xudp_server(server_config, echo_addr).await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config = runtime_socks_config_with_tls_vision_vless_domain_server(
        "vless.test",
        vless_addr.port(),
        "vless.test",
    );
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
    let mut core =
        Core::with_runtime_dependencies(config, Arc::new(resolver), Arc::new(dialer)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let payload = socks_udp_roundtrip(socks_addr, echo_addr, b"hello vision xudp").await;

    assert_eq!(&payload[..], b"hello vision xudp");
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
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
    let _ = run_tun_tcp_freedom_echo_scenario_with_options(TunRuntimeOptions::default()).await;
}

async fn run_tun_tcp_concurrent_same_target_echo_scenario() {
    let flow_count = 8usize;
    let (echo_addr, echo_handle) = spawn_multi_echo_server(flow_count).await;
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpMultiClient::new(flow_count);
    client.connect_all(echo_addr);
    pump_multi_tun_until(&mut client, core.tun(), TunTcpMultiClient::all_may_send).await;

    let expected = (0..flow_count)
        .map(|index| format!("hello concurrent tun {index}").into_bytes())
        .collect::<Vec<_>>();
    for (index, payload) in expected.iter().enumerate() {
        client.send_payload(index, payload);
    }

    let mut received = vec![Vec::new(); flow_count];
    pump_multi_tun_until(&mut client, core.tun(), |client| {
        for (index, received) in received.iter_mut().enumerate() {
            received.extend_from_slice(&client.recv_available(index));
        }
        received
            .iter()
            .zip(expected.iter())
            .all(|(actual, expected)| actual.len() >= expected.len())
    })
    .await;

    assert_eq!(received, expected);
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_tcp_freedom_echo_scenario_with_options(
    tun_runtime_options: TunRuntimeOptions,
) -> TunStats {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = Core::with_tun_runtime_options(
        runtime_tun_config_with_freedom_outbound(),
        tun_runtime_options,
    )
    .unwrap();
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
    let stats = core.tun().stats().await;
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
    stats
}

async fn run_tun_tcp_freedom_echo_scenario_with_runtime_logger() -> TunStats {
    let _log_dir = create_runtime_log_temp_dir("xray-rust-runtime-data-path");
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.set_runtime_logger(
        RuntimeLogger::new(RuntimeLogConfig::directory(&_log_dir.path)).unwrap(),
    );
    core.start().await.unwrap();

    let mut client = TunTcpClient::new();
    client.connect(echo_addr);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    client.send_payload(b"hello tun logger");
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= "hello tun logger".len()
    })
    .await;

    assert_eq!(received, b"hello tun logger");
    let stats = core.tun().stats().await;
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
    stats
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

async fn run_tun_tcp_upload_backpressure_scenario() {
    let (client_config, _) = tls_test_configs();
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
            .with_reality_engine(Arc::new(StalledWriteRealityEngine));
    let mut core = Core::with_runtime_dependencies(
        runtime_tun_config_with_reality_vision_vless_server(443),
        Arc::new(EmptyDnsResolver),
        Arc::new(dialer),
    )
    .unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpClient::new();
    client.connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443));
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    let payload = vec![0x5a; 1024 * 1024];
    let mut sent = 0;
    let deadline = TokioInstant::now() + Duration::from_millis(750);

    while sent < payload.len() {
        client.poll();
        if client.may_send() {
            let remaining = payload.len() - sent;
            let chunk_len = remaining.min(8192);
            client.send_payload(&payload[sent..sent + chunk_len]);
            sent += chunk_len;
        }
        pump_tun_once(&mut client, core.tun()).await;

        assert!(
            client.is_open(),
            "TUN TCP flow should stay open and apply backpressure when remote writes stall"
        );
        assert!(
            TokioInstant::now() < deadline,
            "timed out filling stalled upload path"
        );
    }

    core.stop().await.unwrap();
}

const TUN_REALITY_BLACKHOLE_FLOW_COUNT: usize = 32;

async fn start_tun_reality_blackhole(
    handshake_seconds: Option<u32>,
) -> (Core, TunTcpMultiClient, Arc<PendingRealityOpenState>) {
    let state = Arc::new(PendingRealityOpenState::default());
    let (client_config, _) = tls_test_configs();
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
            .with_reality_engine(Arc::new(PendingRealityEngine {
                state: Arc::clone(&state),
            }));
    let mut config = runtime_tun_config_with_reality_vision_vless_server(443);
    if let Some(handshake) = handshake_seconds {
        config.policy = PolicyConfig {
            levels: BTreeMap::from([(
                0,
                PolicyLevelConfig {
                    handshake: Some(handshake),
                    ..Default::default()
                },
            )]),
            system: Default::default(),
        };
    }
    let mut core =
        Core::with_runtime_dependencies(config, Arc::new(EmptyDnsResolver), Arc::new(dialer))
            .unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpMultiClient::new(TUN_REALITY_BLACKHOLE_FLOW_COUNT);
    client.connect_all(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
        443,
    ));
    pump_multi_tun_until(&mut client, core.tun(), |client| {
        client.all_may_send() && state.started() == TUN_REALITY_BLACKHOLE_FLOW_COUNT
    })
    .await;

    assert_eq!(state.active(), TUN_REALITY_BLACKHOLE_FLOW_COUNT);
    let stats = core.tun().stats().await;
    assert_eq!(
        stats.active_tcp_flows as usize,
        TUN_REALITY_BLACKHOLE_FLOW_COUNT
    );

    (core, client, state)
}

async fn run_tun_reality_blackhole_handshake_timeout_scenario() {
    let (mut core, _client, state) = start_tun_reality_blackhole(Some(1)).await;

    sleep(Duration::from_millis(1_100)).await;
    let active_after_timeout = state.active();
    let stats = core.tun().stats().await;
    core.stop().await.unwrap();

    assert_eq!(
        active_after_timeout, 0,
        "TUN Reality opens ignored policy.levels[0].handshake"
    );
    assert!(
        stats.tcp_open_errors >= TUN_REALITY_BLACKHOLE_FLOW_COUNT as u64,
        "timed-out TUN opens were not recorded as errors: {stats:?}"
    );
}

async fn run_tun_reality_blackhole_stop_scenario() {
    let (mut core, _client, state) = start_tun_reality_blackhole(None).await;

    core.stop().await.unwrap();
    sleep(Duration::from_millis(100)).await;

    assert_eq!(
        state.active(),
        0,
        "Core::stop left detached TUN Reality open tasks alive"
    );
}

async fn run_tun_reality_pending_open_budget_scenario() {
    const FLOW_COUNT: usize = 64;
    const LOW_MEMORY_PENDING_OPEN_LIMIT: usize = 32;

    let state = Arc::new(PendingRealityOpenState::default());
    let (client_config, _) = tls_test_configs();
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
            .with_reality_engine(Arc::new(PendingRealityEngine {
                state: Arc::clone(&state),
            }));
    let mut core = Core::with_runtime_dependencies_and_tun_options(
        runtime_tun_config_with_reality_vision_vless_server(443),
        Arc::new(EmptyDnsResolver),
        Arc::new(dialer),
        TunRuntimeOptions::with_profile(TunRuntimeProfile::LowMemory),
    )
    .unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpMultiClient::new(FLOW_COUNT);
    client.connect_targets(|index| {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
            10_000 + u16::try_from(index).unwrap(),
        )
    });
    pump_multi_tun_until(&mut client, core.tun(), |_| {
        state.started() == LOW_MEMORY_PENDING_OPEN_LIMIT
    })
    .await;
    sleep(Duration::from_millis(100)).await;

    let stats = core.tun().stats().await;
    assert_eq!(state.started(), LOW_MEMORY_PENDING_OPEN_LIMIT);
    assert_eq!(state.active(), LOW_MEMORY_PENDING_OPEN_LIMIT);
    assert_eq!(
        stats.active_tcp_flows as usize,
        LOW_MEMORY_PENDING_OPEN_LIMIT
    );
    assert!(stats.tcp_open_errors >= (FLOW_COUNT - LOW_MEMORY_PENDING_OPEN_LIMIT) as u64);

    core.stop().await.unwrap();
    sleep(Duration::from_millis(50)).await;
    assert_eq!(state.active(), 0);
}

async fn run_tun_reality_pre_open_upload_backpressure_scenario() {
    let (mut core, mut client, state) = start_tun_reality_blackhole(None).await;
    let payload = vec![0x5a; 8 * 1024];
    for index in 0..TUN_REALITY_BLACKHOLE_FLOW_COUNT {
        client.send_payload(index, &payload);
    }
    for _ in 0..25 {
        pump_multi_tun_once(&mut client, core.tun()).await;
    }

    let stats = core.tun().stats().await;
    assert_eq!(state.active(), TUN_REALITY_BLACKHOLE_FLOW_COUNT);
    assert_eq!(stats.tcp_stack_to_remote_bytes, 0);
    assert_eq!(stats.tcp_pending_upload_bytes, 0);

    core.stop().await.unwrap();
}

async fn run_tun_reality_open_error_burst_scenario() {
    const FLOW_COUNT: usize = 128;

    let attempts = Arc::new(AtomicUsize::new(0));
    let (client_config, _) = tls_test_configs();
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
            .with_reality_engine(Arc::new(FailingRealityEngine {
                attempts: Arc::clone(&attempts),
            }));
    let config = runtime_tun_config_with_reality_vision_vless_server(443);
    let mut core =
        Core::with_runtime_dependencies(config, Arc::new(EmptyDnsResolver), Arc::new(dialer))
            .unwrap();
    core.start().await.unwrap();

    let mut client = TunTcpMultiClient::new(FLOW_COUNT);
    client.connect_all(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
        443,
    ));
    pump_multi_tun_until(&mut client, core.tun(), |_| {
        attempts.load(Ordering::SeqCst) == FLOW_COUNT
    })
    .await;

    let deadline = TokioInstant::now() + Duration::from_secs(1);
    let stats = loop {
        let stats = core.tun().stats().await;
        if stats.tcp_open_errors >= FLOW_COUNT as u64 {
            break stats;
        }
        assert!(
            TokioInstant::now() < deadline,
            "timed out waiting for injected Reality failures: {stats:?}"
        );
        sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(stats.tcp_open_events, 0);

    let request = ipv4_icmp_echo_request(
        Ipv4Addr::new(10, 10, 0, 2),
        Ipv4Addr::new(10, 10, 0, 1),
        0x1301,
        8,
        b"alive after Reality failures",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();
    let reply = poll_tun_outbound_until(core.tun(), is_ipv4_icmp_echo_reply).await;
    assert_ipv4_icmp_echo_reply(
        &reply,
        Ipv4Addr::new(10, 10, 0, 1),
        Ipv4Addr::new(10, 10, 0, 2),
        0x1301,
        8,
        b"alive after Reality failures",
    );

    core.stop().await.unwrap();
}

async fn run_tun_reality_bridge_panic_scenario() {
    let log_dir = create_runtime_log_temp_dir("xray-rust-tun-bridge-panic");
    let (client_config, _) = tls_test_configs();
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config))
            .with_reality_engine(Arc::new(PanickingRealityEngine));
    let mut core = Core::with_runtime_dependencies(
        runtime_tun_config_with_reality_vision_vless_server(443),
        Arc::new(EmptyDnsResolver),
        Arc::new(dialer),
    )
    .unwrap();
    core.set_runtime_logger(
        RuntimeLogger::new(RuntimeLogConfig::directory(&log_dir.path)).unwrap(),
    );
    core.start().await.unwrap();

    let mut client = TunTcpClient::new();
    client.connect(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
        443,
    ));

    let deadline = TokioInstant::now() + Duration::from_secs(1);
    loop {
        pump_tun_once(&mut client, core.tun()).await;
        let log = std::fs::read_to_string(log_dir.path.join("xray-error.log")).unwrap();
        let stats = core.tun().stats().await;
        if log.contains("Debug tunBridgeTask failed error=<redacted>")
            && stats.active_tcp_flows == 0
        {
            assert!(!log.contains("injected Reality engine panic"));
            break;
        }
        assert!(
            TokioInstant::now() < deadline,
            "timed out waiting for TUN bridge panic diagnostic"
        );
    }

    let request = ipv4_icmp_echo_request(
        Ipv4Addr::new(10, 10, 0, 2),
        Ipv4Addr::new(10, 10, 0, 1),
        0x1302,
        9,
        b"alive after bridge panic",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();
    let reply = poll_tun_outbound_until(core.tun(), is_ipv4_icmp_echo_reply).await;
    assert_ipv4_icmp_echo_reply(
        &reply,
        Ipv4Addr::new(10, 10, 0, 1),
        Ipv4Addr::new(10, 10, 0, 2),
        0x1302,
        9,
        b"alive after bridge panic",
    );

    core.stop().await.unwrap();
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

async fn run_tun_icmp_echo_scenario() {
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.start().await.unwrap();

    let request = ipv4_icmp_echo_request(
        Ipv4Addr::new(10, 10, 0, 2),
        Ipv4Addr::new(10, 10, 0, 1),
        0x1201,
        7,
        b"mobile ping",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), is_ipv4_icmp_echo_reply).await;
    assert_ipv4_icmp_echo_reply(
        &reply,
        Ipv4Addr::new(10, 10, 0, 1),
        Ipv4Addr::new(10, 10, 0, 2),
        0x1201,
        7,
        b"mobile ping",
    );
    core.stop().await.unwrap();
}

async fn run_tun_icmpv6_echo_scenario() {
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.start().await.unwrap();

    let source = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let request = ipv6_icmp_echo_request(source, destination, 0x2201, 9, b"mobile ping v6");
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), is_ipv6_icmp_echo_reply).await;
    assert_ipv6_icmp_echo_reply(&reply, destination, source, 0x2201, 9, b"mobile ping v6");
    core.stop().await.unwrap();
}

async fn run_tun_malformed_packet_storm_scenario() {
    const PACKET_COUNT: usize = 4096;

    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.start().await.unwrap();

    for index in 0..PACKET_COUNT {
        let packet = malformed_tun_packet(index);
        loop {
            match core.tun().push_inbound(packet.clone()).await {
                Ok(()) => break,
                Err(TunError::QueueFull) => sleep(Duration::from_millis(1)).await,
                Err(error) => panic!("failed to enqueue malformed TUN packet: {error}"),
            }
        }
    }

    let request = ipv4_icmp_echo_request(
        Ipv4Addr::new(10, 10, 0, 2),
        Ipv4Addr::new(10, 10, 0, 1),
        0x1401,
        9,
        b"alive after malformed packets",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();
    let reply = poll_tun_outbound_until(core.tun(), is_ipv4_icmp_echo_reply).await;
    assert_ipv4_icmp_echo_reply(
        &reply,
        Ipv4Addr::new(10, 10, 0, 1),
        Ipv4Addr::new(10, 10, 0, 2),
        0x1401,
        9,
        b"alive after malformed packets",
    );

    let stats = core.tun().stats().await;
    assert!(stats.inbound_packets >= (PACKET_COUNT + 1) as u64);
    core.stop().await.unwrap();
}

async fn run_tun_udp_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let SocketAddr::V4(echo_addr_v4) = echo_addr else {
        panic!("UDP TUN test expects IPv4 echo server");
    };
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let request = ipv4_udp_packet(
        client_addr,
        49152,
        *echo_addr_v4.ip(),
        echo_addr_v4.port(),
        b"hello tun udp",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .map(|payload| payload == b"hello tun udp")
            .unwrap_or(false)
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        *echo_addr_v4.ip(),
        echo_addr_v4.port(),
        client_addr,
        49152,
        b"hello tun udp",
    );
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_udp_route_only_quic_sniffing_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let SocketAddr::V4(echo_addr_v4) = echo_addr else {
        panic!("UDP TUN QUIC sniffing test expects IPv4 echo server");
    };
    let config = runtime_tun_config_with_route_only_quic_sniffing(allocate_unused_loopback_port());
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let payload = quic_initial_packet_with_sni("quic.example");
    let request = ipv4_udp_packet(
        client_addr,
        49153,
        *echo_addr_v4.ip(),
        echo_addr_v4.port(),
        &payload,
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .map(|reply_payload| reply_payload == payload.as_slice())
            .unwrap_or(false)
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        *echo_addr_v4.ip(),
        echo_addr_v4.port(),
        client_addr,
        49153,
        &payload,
    );
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_fake_dns_udp_domain_routing_scenario() {
    let unused_proxy_port = allocate_unused_loopback_port();
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let SocketAddr::V4(echo_addr_v4) = echo_addr else {
        panic!("UDP TUN fake DNS test expects IPv4 echo server");
    };
    let config = runtime_tun_config_with_fake_ip_domain_routed_freedom_outbound(unused_proxy_port);
    let mut core = Core::with_dns_resolver(
        config,
        Arc::new(StaticDnsResolver {
            domain: "www.example.com",
            addr: echo_addr,
        }),
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let dns_query = build_dns_a_query(0x1203, "www.example.com");
    let dns_request = ipv4_udp_packet(
        client_addr,
        53_000,
        Ipv4Addr::new(1, 1, 1, 1),
        53,
        &dns_query,
    );
    core.tun()
        .push_inbound(Bytes::from(dns_request))
        .await
        .unwrap();

    let dns_reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .and_then(dns_response_answer_ipv4)
            .is_some()
    })
    .await;
    let fake_ip = ipv4_udp_payload(&dns_reply)
        .and_then(dns_response_answer_ipv4)
        .unwrap();
    assert_eq!(fake_ip, Ipv4Addr::new(198, 18, 0, 3));

    let request = ipv4_udp_packet(
        client_addr,
        49_152,
        fake_ip,
        echo_addr_v4.port(),
        b"hello fake dns",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .map(|payload| payload == b"hello fake dns")
            .unwrap_or(false)
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        fake_ip,
        echo_addr_v4.port(),
        client_addr,
        49_152,
        b"hello fake dns",
    );
    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_fake_dns_static_only_udp_freedom_scenario() {
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let SocketAddr::V4(echo_addr_v4) = echo_addr else {
        panic!("UDP fake DNS routed resolver test expects IPv4 echo server");
    };
    let (dns_server, dns_handle) = spawn_udp_tcp_dns_a_responder(*echo_addr_v4.ip()).await;
    let mut config = runtime_tun_config_with_mobile_fake_dns_freedom(dns_server);
    let unavailable_proxy = allocate_unused_loopback_port();
    config.outbounds.insert(
        0,
        vless_outbound(
            StreamSecurity::None,
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            unavailable_proxy,
        ),
    );
    config.default_outbound_tag = Some("proxy".to_owned());
    config.routing.rules = vec![
        RoutingRule {
            inbound_tags: vec!["dns-route".to_owned()],
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: "direct".to_owned(),
        },
        RoutingRule {
            inbound_tags: Vec::new(),
            domain_matchers: vec![DomainMatcher::Full("mobile-udp.example".to_owned())],
            ip_matchers: Vec::new(),
            outbound_tag: "direct".to_owned(),
        },
    ];
    config.dns.tag = "dns-global".to_owned();
    config.dns.servers = vec![
        DnsServerConfig::Domain {
            domain: "unbootstrapped.mobile.test".to_owned(),
            port: 53,
        },
        tagged_dns_server(
            DnsServerEndpoint::Domain {
                domain: "MOBILE.RESOLVER.TEST.".to_owned(),
                port: dns_server.port(),
            },
            "dns-route",
        ),
    ];
    config.dns.hosts = vec![DnsHostMapping {
        matcher: DomainMatcher::Full("mobile.resolver.test".to_owned()),
        target: DnsHostTarget::Ip(dns_server.ip()),
    }];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let fake_ip = request_tun_fake_ip(&core, 53_020, "mobile-udp.example").await;
    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            49_160,
            fake_ip,
            echo_addr_v4.port(),
            b"mobile routed dns udp",
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(b"mobile routed dns udp".as_slice())
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        fake_ip,
        echo_addr_v4.port(),
        client_addr,
        49_160,
        b"mobile routed dns udp",
    );

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), dns_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_fake_dns_static_only_ipv6_udp_freedom_scenario() {
    let (echo_addr, echo_handle) = spawn_ipv6_udp_echo_server().await;
    let SocketAddr::V6(echo_addr_v6) = echo_addr else {
        panic!("UDP fake DNS routed resolver test expects IPv6 echo server");
    };
    let (dns_server, dns_handle) = spawn_udp_dns_aaaa_responder(*echo_addr_v6.ip()).await;
    let config = runtime_tun_config_with_mobile_fake_dns_freedom(dns_server);
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let fake_ip = request_tun_fake_ip(&core, 53_024, "mobile-udp-v6.example").await;
    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            49_164,
            fake_ip,
            echo_addr_v6.port(),
            b"mobile routed dns udp v6",
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(b"mobile routed dns udp v6".as_slice())
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        fake_ip,
        echo_addr_v6.port(),
        client_addr,
        49_164,
        b"mobile routed dns udp v6",
    );

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), dns_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_fake_dns_static_only_tcp_freedom_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let SocketAddr::V4(echo_addr_v4) = echo_addr else {
        panic!("TCP fake DNS routed resolver test expects IPv4 echo server");
    };
    let (dns_server, dns_handle) = spawn_udp_dns_a_responder(*echo_addr_v4.ip()).await;
    let config = runtime_tun_config_with_mobile_fake_dns_freedom(dns_server);
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let fake_ip = request_tun_fake_ip(&core, 53_021, "mobile-tcp.example").await;
    let mut client = TunTcpClient::new();
    client.connect(SocketAddr::new(IpAddr::V4(fake_ip), echo_addr_v4.port()));
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;
    client.send_payload(b"mobile routed dns tcp");
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= b"mobile routed dns tcp".len()
    })
    .await;
    assert_eq!(received, b"mobile routed dns tcp");

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), dns_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_fake_dns_domain_upstream_vless_scenario() {
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let SocketAddr::V4(echo_addr_v4) = echo_addr else {
        panic!("domain DNS upstream test expects IPv4 echo server");
    };
    let dns_target = Target::new(
        RoutingTargetAddr::Domain("resolver.remote.test".to_owned()),
        53,
        RoutingNetwork::Udp,
    );
    let (vless_addr, vless_handle) =
        spawn_fake_vless_dynamic_dns_a_server(dns_target, *echo_addr_v4.ip()).await;
    let mut config =
        runtime_tun_config_with_fake_ip_domain_routed_freedom_outbound(vless_addr.port());
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: "resolver.remote.test".to_owned(),
        port: 53,
    }];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let fake_ip = request_tun_fake_ip(&core, 53_022, "www.example.com").await;
    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            49_161,
            fake_ip,
            echo_addr_v4.port(),
            b"domain dns through vless",
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(b"domain dns through vless".as_slice())
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        fake_ip,
        echo_addr_v4.port(),
        client_addr,
        49_161,
        b"domain dns through vless",
    );

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

async fn run_tun_fake_dns_static_only_vless_remote_resolution_scenario() {
    let domain = "remote-resolution.example";
    let destination_port = 8_443;
    let payload = b"fake-only vless remote resolution";
    let expected_target = Target::new(
        RoutingTargetAddr::Domain(domain.to_owned()),
        destination_port,
        RoutingNetwork::Udp,
    );
    let (vless_addr, vless_handle) =
        spawn_fake_vless_xudp_target_server(expected_target, payload).await;
    let mut config = runtime_tun_config_with_vless_server(vless_addr);
    config.dns.fake_ip = Some(DnsFakeIpConfig {
        enabled: true,
        ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15).unwrap(),
        pool_size: 32_768,
        ttl: 60,
    });
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let fake_ip = request_tun_fake_ip(&core, 53_023, domain).await;
    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            49_162,
            fake_ip,
            destination_port,
            payload,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(payload.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        fake_ip,
        destination_port,
        client_addr,
        49_162,
        payload,
    );

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn request_tun_fake_ip(core: &Core, client_port: u16, domain: &str) -> Ipv4Addr {
    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let query = build_dns_a_query(client_port, domain);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            Ipv4Addr::new(1, 1, 1, 1),
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .and_then(dns_response_answer_ipv4)
            .is_some()
    })
    .await;
    ipv4_udp_payload(&reply)
        .and_then(dns_response_answer_ipv4)
        .unwrap()
}

async fn run_tun_fake_dns_https_nodata_scenario() {
    let unused_proxy_port = allocate_unused_loopback_port();
    let config = runtime_tun_config_with_fake_ip_domain_routed_freedom_outbound(unused_proxy_port);
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let dns_anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_002;
    let dns_query = build_dns_query(0x1205, "www.example.com", 65, 1);
    let dns_request = ipv4_udp_packet(client_addr, client_port, dns_anchor, 53, &dns_query);
    core.tun()
        .push_inbound(Bytes::from(dns_request))
        .await
        .unwrap();

    let mut expected_response = dns_query;
    expected_response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    let dns_reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected_response.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(
        &dns_reply,
        dns_anchor,
        53,
        client_addr,
        client_port,
        &expected_response,
    );

    core.stop().await.unwrap();
}

async fn run_tun_fake_dns_pool_rollover_scenario() {
    let unused_proxy_port = allocate_unused_loopback_port();
    let mut config =
        runtime_tun_config_with_fake_ip_domain_routed_freedom_outbound(unused_proxy_port);
    let fake_ip = config.dns.fake_ip.as_mut().unwrap();
    fake_ip.ipv4_pool = IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1)), 32).unwrap();
    fake_ip.pool_size = 1;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let dns_anchor = Ipv4Addr::new(198, 18, 0, 1);
    let first_query = build_dns_a_query(0x1206, "first.example.com");
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            53_003,
            dns_anchor,
            53,
            &first_query,
        )))
        .await
        .unwrap();
    let first_reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .and_then(dns_response_answer_ipv4)
            .is_some()
    })
    .await;
    let first_fake_ip = ipv4_udp_payload(&first_reply)
        .and_then(dns_response_answer_ipv4)
        .unwrap();

    let second_client_port = 53_004;
    let second_query = build_dns_a_query(0x1207, "second.example.com");
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            second_client_port,
            dns_anchor,
            53,
            &second_query,
        )))
        .await
        .unwrap();
    let dns_reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet).is_some_and(|payload| {
            payload.get(0..2) == Some(&0x1207_u16.to_be_bytes())
                && dns_response_answer_ipv4(payload) == Some(first_fake_ip)
        })
    })
    .await;
    let response = ipv4_udp_payload(&dns_reply).unwrap();
    assert_ipv4_udp_packet(
        &dns_reply,
        dns_anchor,
        53,
        client_addr,
        second_client_port,
        response,
    );

    core.stop().await.unwrap();
}

async fn run_tun_dns_proxy_udp_scenario() {
    let (upstream, upstream_handle) = spawn_udp_dns_responder(0).await;
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![upstream])).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_010;
    let query = build_dns_query(0x2201, "proxy.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_to_local_tcp_scenario() {
    let (upstream, upstream_handle) = spawn_tcp_dns_responder().await;
    let broken_proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_unused_loopback_port()));
    let mut config = runtime_tun_config_with_vless_server(broken_proxy);
    config.dns.servers = vec![tagged_dns_server_with_transport(
        DnsServerEndpoint::Ip(upstream),
        "must-not-route",
        xray_config::DnsServerTransport::TcpLocal,
    )];
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_019;
    let query = build_dns_query(0x2219, "tcp-local.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_to_routed_tcp_scenario() {
    let upstream = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 5_353));
    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_020;
    let query = build_dns_query(0x2220, "tcp-routed.example", 65, 1);
    let expected_target = Target::new(
        RoutingTargetAddr::Ip(upstream.ip()),
        upstream.port(),
        RoutingNetwork::Tcp,
    );
    let (vless_server, vless_handle) =
        spawn_fake_vless_dns_tcp_query_server(expected_target, query.clone()).await;
    let mut config = runtime_tun_config_with_vless_server(vless_server);
    config.dns.servers = vec![tagged_dns_server_with_transport(
        DnsServerEndpoint::Ip(upstream),
        "dns-routed",
        xray_config::DnsServerTransport::TcpRouted,
    )];
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_to_tcp_status_failover_scenario(
    first_response_flags: u16,
    transaction_id: u16,
) {
    let (first, first_handle) = spawn_tcp_dns_responder_with_flags(first_response_flags).await;
    let (second, second_handle) = spawn_tcp_dns_responder().await;
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.dns.servers = vec![
        tagged_dns_server_with_transport(
            DnsServerEndpoint::Ip(first),
            "dns-first",
            xray_config::DnsServerTransport::TcpLocal,
        ),
        tagged_dns_server_with_transport(
            DnsServerEndpoint::Ip(second),
            "dns-fallback",
            xray_config::DnsServerTransport::TcpLocal,
        ),
    ];
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_021;
    let query = build_dns_query(transaction_id, "tcp-status-failover.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);
    assert!(core.tun().stats().await.udp_remote_read_errors >= 1);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), first_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), second_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_failover_scenario() {
    let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let blackhole_addr = blackhole.local_addr().unwrap();
    let (upstream, upstream_handle) = spawn_udp_dns_responder(0).await;
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![
        blackhole_addr,
        upstream,
    ]))
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_011;
    let query = build_dns_query(0x2202, "failover.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply =
        poll_tun_outbound_until_with_timeout(core.tun(), Duration::from_millis(1_500), |packet| {
            ipv4_udp_payload(packet) == Some(expected.as_slice())
        })
        .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);
    assert!(core.tun().stats().await.udp_remote_read_errors >= 1);

    core.stop().await.unwrap();
    drop(blackhole);
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_routed_failover_scenario() {
    let first = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let (second, upstream_handle) = spawn_udp_dns_responder(0).await;
    let config = runtime_tun_dns_proxy_config_routing_second_upstream_to_freedom(first, second);
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_015;
    let query = build_dns_query(0x2206, "routed-failover.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);
    assert!(core.tun().stats().await.udp_open_errors >= 1);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_servfail_scenario() {
    let blackhole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let blackhole_addr = blackhole.local_addr().unwrap();
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![
        blackhole_addr,
    ]))
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_012;
    let query = build_dns_query(0x2203, "unavailable.example", 65, 1);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply =
        poll_tun_outbound_until_with_timeout(core.tun(), Duration::from_millis(1_500), |packet| {
            ipv4_udp_payload(packet).is_some_and(|payload| {
                payload.len() >= 4
                    && payload[0..2] == query[0..2]
                    && u16::from_be_bytes([payload[2], payload[3]]) & 0x000f == 2
            })
        })
        .await;
    let payload = ipv4_udp_payload(&reply).unwrap();
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, payload);
    let stats = core.tun().stats().await;
    assert_eq!(stats.udp_open_errors, 0);
    assert!(stats.udp_remote_read_errors >= 1);

    core.stop().await.unwrap();
    drop(blackhole);
}

async fn run_tun_dns_proxy_udp_truncated_scenario() {
    let (upstream, upstream_handle) = spawn_udp_dns_responder(2_000).await;
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![upstream])).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_013;
    let query = build_dns_query(0x2204, "large.example", 65, 1);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet).is_some_and(|payload| {
            payload.len() >= 12
                && payload[0..2] == query[0..2]
                && u16::from_be_bytes([payload[2], payload[3]]) & 0x0200 != 0
        })
    })
    .await;
    let payload = ipv4_udp_payload(&reply).unwrap();
    assert!(payload.len() <= 1_472);
    assert_eq!(u16::from_be_bytes([payload[6], payload[7]]), 0);
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, payload);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_oversized_wrong_id_scenario() {
    let (upstream, upstream_handle) =
        spawn_udp_dns_responder_with_transaction_id(2_000, Some(0x9999)).await;
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![upstream])).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_016;
    let query = build_dns_query(0x2207, "wrong-id.example", 65, 1);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply =
        poll_tun_outbound_until_with_timeout(core.tun(), Duration::from_millis(1_500), |packet| {
            ipv4_udp_payload(packet).is_some_and(|payload| {
                payload.len() >= 12
                    && payload[0..2] == query[0..2]
                    && u16::from_be_bytes([payload[2], payload[3]]) & 0x000f == 2
            })
        })
        .await;
    let payload = ipv4_udp_payload(&reply).unwrap();
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    assert_eq!(flags & 0x000f, 2);
    assert_eq!(flags & 0x0200, 0);
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, payload);
    assert!(core.tun().stats().await.udp_remote_read_errors >= 1);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_wrong_question_then_valid_scenario() {
    let (upstream, upstream_handle) = spawn_udp_dns_wrong_question_then_valid_responder().await;
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![upstream])).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_027;
    let query = build_dns_query(0x2208, "expected.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_vless_scenario() {
    let upstream = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let query = build_dns_query(0x2205, "vless-proxy.example", 65, 1);
    let (vless_addr, vless_handle) = spawn_fake_vless_dns_server(upstream, query.clone()).await;
    let mut config = runtime_tun_config_with_vless_server(vless_addr);
    config.dns.servers = vec![DnsServerConfig::Ip(upstream)];
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_014;
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_vless_domain_scenario() {
    let upstream_domain = "resolver.example";
    let upstream_port = 5_353;
    let query = build_dns_query(0x2210, "domain-vless.example", 65, 1);
    let expected_target = Target::new(
        RoutingTargetAddr::Domain(upstream_domain.to_owned()),
        upstream_port,
        RoutingNetwork::Udp,
    );
    let (vless_addr, vless_handle) =
        spawn_fake_vless_xudp_dns_target_server(expected_target, query.clone()).await;
    let mut config = runtime_tun_config_with_vless_server(vless_addr);
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: upstream_domain.to_owned(),
        port: upstream_port,
    }];
    let mut core = Core::with_dns_resolver(config, Arc::new(EmptyDnsResolver)).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_019;
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_static_bootstrap_scenario() {
    let (upstream, upstream_handle) = spawn_udp_dns_responder(0).await;
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: "resolver.bootstrap.test".to_owned(),
        port: upstream.port(),
    }];
    config.dns.hosts = vec![DnsHostMapping {
        matcher: DomainMatcher::Full("resolver.bootstrap.test".to_owned()),
        target: DnsHostTarget::Ip(upstream.ip()),
    }];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_020;
    let query = build_dns_query(0x2211, "static-bootstrap.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_bootstrap_alias_scenario() {
    let (upstream, upstream_handle) = spawn_udp_dns_responder(0).await;
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: "resolver.bootstrap.test".to_owned(),
        port: upstream.port(),
    }];
    config.dns.hosts = vec![DnsHostMapping {
        matcher: DomainMatcher::Full("resolver.bootstrap.test".to_owned()),
        target: DnsHostTarget::Domain("resolver.bootstrap.target".to_owned()),
    }];
    let mut core = Core::with_dns_resolver(
        config,
        Arc::new(StaticDnsResolver {
            domain: "resolver.bootstrap.target",
            addr: upstream,
        }),
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_025;
    let query = build_dns_query(0x2214, "bootstrap-alias.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_static_ip_skip_routing_scenario() {
    let (upstream, upstream_handle) = spawn_udp_dns_responder(0).await;
    let broken_vless = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_unused_loopback_port()));
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.outbounds.push(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Ip(broken_vless.ip()),
        broken_vless.port(),
    ));
    config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
    config.routing.rules = vec![RoutingRule {
        inbound_tags: vec!["dns-route".to_owned()],
        domain_matchers: Vec::new(),
        ip_matchers: vec![IpMatcher::Cidr(
            IpCidr::new(upstream.ip(), if upstream.is_ipv4() { 32 } else { 128 }).unwrap(),
        )],
        outbound_tag: "proxy".to_owned(),
    }];
    config.dns.tag = "dns-route".to_owned();
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: "resolver.static-route.test".to_owned(),
        port: upstream.port(),
    }];
    config.dns.hosts = vec![DnsHostMapping {
        matcher: DomainMatcher::Full("resolver.static-route.test".to_owned()),
        target: DnsHostTarget::Ip(upstream.ip()),
    }];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_026;
    let query = build_dns_query(0x2215, "static-route.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_dynamic_ip_skip_routing_scenario() {
    let (upstream, upstream_handle) = spawn_udp_dns_responder(0).await;
    let broken_vless = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_unused_loopback_port()));
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.outbounds.push(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Ip(broken_vless.ip()),
        broken_vless.port(),
    ));
    config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
    config.routing.rules = vec![RoutingRule {
        inbound_tags: vec!["dns-route".to_owned()],
        domain_matchers: Vec::new(),
        ip_matchers: vec![IpMatcher::Cidr(
            IpCidr::new(upstream.ip(), if upstream.is_ipv4() { 32 } else { 128 }).unwrap(),
        )],
        outbound_tag: "proxy".to_owned(),
    }];
    config.dns.tag = "dns-route".to_owned();
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: "resolver.dynamic-route.test".to_owned(),
        port: upstream.port(),
    }];
    let mut core = Core::with_dns_resolver(
        config,
        Arc::new(StaticDnsResolver {
            domain: "resolver.dynamic-route.test",
            addr: upstream,
        }),
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_028;
    let query = build_dns_query(0x2216, "dynamic-route.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_static_only_failover_scenario() {
    let (upstream, upstream_handle) = spawn_udp_dns_responder(0).await;
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.dns.servers = vec![
        DnsServerConfig::Domain {
            domain: "unbootstrapped.invalid".to_owned(),
            port: 53,
        },
        DnsServerConfig::Ip(upstream),
    ];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_021;
    let query = build_dns_query(0x2212, "static-failover.example", 65, 1);
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);
    assert!(core.tun().stats().await.udp_open_errors >= 1);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_static_only_failure_scenario() {
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: "unbootstrapped.invalid".to_owned(),
        port: 53,
    }];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_022;
    let query = build_dns_query(0x2213, "static-failure.example", 65, 1);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet).is_some_and(|payload| {
            payload.len() >= 4
                && payload[0..2] == query[0..2]
                && u16::from_be_bytes([payload[2], payload[3]]) & 0x000f == 2
        })
    })
    .await;
    let payload = ipv4_udp_payload(&reply).unwrap();
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, payload);

    core.stop().await.unwrap();
}

async fn run_tun_dns_proxy_udp_delayed_vless_scenario() {
    let upstream = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 54), 53));
    let query = build_dns_query(0x2208, "cold-vless.example", 65, 1);
    let (vless_addr, vless_handle) =
        spawn_fake_vless_dns_server_with_delay(upstream, query.clone(), Duration::from_millis(900))
            .await;
    let mut config = runtime_tun_config_with_vless_server(vless_addr);
    config.dns.servers = vec![DnsServerConfig::Ip(upstream)];
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_017;
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply =
        poll_tun_outbound_until_with_timeout(core.tun(), Duration::from_millis(1_800), |packet| {
            ipv4_udp_payload(packet) == Some(expected.as_slice())
        })
        .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_udp_vision_xudp_scenario() {
    let (client_config, server_config) = tls_test_configs();
    let upstream = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 55), 53));
    let query = build_dns_query(0x2209, "vision-xudp.example", 65, 1);
    let (vless_addr, vless_handle) =
        spawn_fake_tls_vision_xudp_dns_server(server_config, upstream, query.clone()).await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let mut config = runtime_tun_config_with_tls_vision_vless_domain_server(
        "vless.test",
        vless_addr.port(),
        "vless.test",
    );
    config.dns.servers = vec![DnsServerConfig::Ip(upstream)];
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
    let mut core =
        Core::with_runtime_dependencies(config, Arc::new(resolver), Arc::new(dialer)).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let anchor = Ipv4Addr::new(198, 18, 0, 1);
    let client_port = 53_018;
    let mut expected = query.clone();
    expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client_addr,
            client_port,
            anchor,
            53,
            &query,
        )))
        .await
        .unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(expected.as_slice())
    })
    .await;
    assert_ipv4_udp_packet(&reply, anchor, 53, client_addr, client_port, &expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

fn pipelined_dns_tcp_queries() -> Vec<u8> {
    let mut stream = Vec::new();
    for (id, domain) in [
        (0x2301, "first.tcp.example"),
        (0x2302, "second.tcp.example"),
    ] {
        let query = build_dns_a_query(id, domain);
        stream.extend_from_slice(&(query.len() as u16).to_be_bytes());
        stream.extend_from_slice(&query);
    }
    stream
}

async fn run_tun_dns_proxy_tcp_scenario() {
    let (upstream, upstream_handle) = spawn_echo_server().await;
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![upstream])).unwrap();
    core.start().await.unwrap();

    let anchor = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53));
    let mut client = TunTcpClient::new();
    client.connect(anchor);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    let expected = pipelined_dns_tcp_queries();
    client.send_payload(&expected);
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= expected.len()
    })
    .await;
    assert_eq!(received, expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_tcp_local_scenario() {
    let (upstream, upstream_handle) = spawn_echo_server().await;
    let broken_proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_unused_loopback_port()));
    let mut config = runtime_tun_config_with_vless_server(broken_proxy);
    config.dns.servers = vec![tagged_dns_server_with_transport(
        DnsServerEndpoint::Ip(upstream),
        "must-not-route",
        xray_config::DnsServerTransport::TcpLocal,
    )];
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let anchor = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53));
    let mut client = TunTcpClient::new();
    client.connect(anchor);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    let expected = pipelined_dns_tcp_queries();
    client.send_payload(&expected);
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= expected.len()
    })
    .await;
    assert_eq!(received, expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_tcp_failover_scenario() {
    let unavailable = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_unused_loopback_port()));
    let (upstream, upstream_handle) = spawn_echo_server().await;
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![
        unavailable,
        upstream,
    ]))
    .unwrap();
    core.start().await.unwrap();

    let anchor = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53));
    let mut client = TunTcpClient::new();
    client.connect(anchor);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    let expected = pipelined_dns_tcp_queries();
    client.send_payload(&expected);
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= expected.len()
    })
    .await;
    assert_eq!(received, expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_tcp_routed_failover_scenario() {
    let first = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let (second, upstream_handle) = spawn_echo_server().await;
    let config = runtime_tun_dns_proxy_config_routing_second_upstream_to_freedom(first, second);
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let anchor = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53));
    let mut client = TunTcpClient::new();
    client.connect(anchor);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    let expected = pipelined_dns_tcp_queries();
    client.send_payload(&expected);
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= expected.len()
    })
    .await;
    assert_eq!(received, expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_tcp_routed_domain_candidate_fallback_scenario() {
    let (upstream, upstream_handle) = spawn_echo_server().await;
    let refused = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), upstream.port()));
    let upstream_domain = "routed-bootstrap.resolver.test";
    let mut config = runtime_tun_config_with_freedom_outbound();
    config.dns.servers = vec![tagged_dns_server_with_transport(
        DnsServerEndpoint::Domain {
            domain: upstream_domain.to_owned(),
            port: upstream.port(),
        },
        "dns-route",
        xray_config::DnsServerTransport::TcpRouted,
    )];
    config.dns.hosts = vec![DnsHostMapping {
        matcher: DomainMatcher::Full(upstream_domain.to_owned()),
        target: DnsHostTarget::Ips(vec![refused.ip(), upstream.ip()]),
    }];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let anchor = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53));
    let mut client = TunTcpClient::new();
    client.connect(anchor);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    let expected = pipelined_dns_tcp_queries();
    client.send_payload(&expected);
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= expected.len()
    })
    .await;
    assert_eq!(received, expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_tcp_failure_scenario() {
    let unavailable = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_unused_loopback_port()));
    let mut core = Core::new(runtime_tun_config_with_dns_proxy_servers(vec![unavailable])).unwrap();
    core.start().await.unwrap();

    let anchor = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53));
    let mut client = TunTcpClient::new();
    client.connect(anchor);
    let reset_flags = pump_tun_until_tcp_reset(&mut client, core.tun()).await;
    assert!(!client.is_open());
    assert_eq!(reset_flags & 0x05, 0x04, "expected RST without FIN");
    assert!(core.tun().stats().await.tcp_open_errors >= 1);

    core.stop().await.unwrap();
}

async fn run_tun_dns_proxy_tcp_vless_scenario() {
    let (upstream, upstream_handle) = spawn_echo_server().await;
    let (vless_addr, vless_handle) = spawn_fake_vless_server().await;
    let mut config = runtime_tun_config_with_vless_server(vless_addr);
    config.dns.servers = vec![DnsServerConfig::Ip(upstream)];
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let anchor = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53));
    let mut client = TunTcpClient::new();
    client.connect(anchor);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    let expected = pipelined_dns_tcp_queries();
    client.send_payload(&expected);
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= expected.len()
    })
    .await;
    assert_eq!(received, expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_dns_proxy_tcp_vless_domain_scenario() {
    let upstream_domain = "resolver-tcp.example";
    let upstream_port = 5_353;
    let expected = pipelined_dns_tcp_queries();
    let expected_target = Target::new(
        RoutingTargetAddr::Domain(upstream_domain.to_owned()),
        upstream_port,
        RoutingNetwork::Tcp,
    );
    let (vless_addr, vless_handle) =
        spawn_fake_vless_dns_tcp_target_server(expected_target, expected.clone()).await;
    let mut config = runtime_tun_config_with_vless_server(vless_addr);
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: upstream_domain.to_owned(),
        port: upstream_port,
    }];
    let mut core = Core::with_dns_resolver(config, Arc::new(EmptyDnsResolver)).unwrap();
    core.start().await.unwrap();

    let anchor = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53));
    let mut client = TunTcpClient::new();
    client.connect(anchor);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    client.send_payload(&expected);
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        received.len() >= expected.len()
    })
    .await;
    assert_eq!(received, expected);

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_fake_dns_tcp_scenario(dns_destination: Ipv4Addr) {
    let (upstream, accepted, upstream_handle) = spawn_tcp_accept_probe().await;
    let mut config = runtime_tun_config_with_dns_proxy_servers(vec![upstream]);
    config.dns.fake_ip = Some(DnsFakeIpConfig {
        enabled: true,
        ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15).unwrap(),
        pool_size: 32_768,
        ttl: 60,
    });
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let dns_endpoint = SocketAddr::from((dns_destination, 53));
    let mut client = TunTcpClient::new();
    client.connect(dns_endpoint);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;

    let queries = pipelined_dns_tcp_queries();
    client.send_payload(&queries);
    let mut received = Vec::new();
    pump_tun_until(&mut client, core.tun(), |client| {
        received.extend_from_slice(&client.recv_available());
        complete_dns_tcp_messages(&received).is_some_and(|messages| messages.len() == 2)
    })
    .await;
    let responses = complete_dns_tcp_messages(&received).unwrap();
    assert_eq!(&responses[0][0..2], &0x2301_u16.to_be_bytes());
    assert_eq!(
        dns_response_answer_ipv4(&responses[0]),
        Some(Ipv4Addr::new(198, 18, 0, 3))
    );
    assert_eq!(&responses[1][0..2], &0x2302_u16.to_be_bytes());
    assert_eq!(
        dns_response_answer_ipv4(&responses[1]),
        Some(Ipv4Addr::new(198, 18, 0, 4))
    );
    assert!(client.is_open());

    core.stop().await.unwrap();
    timeout(Duration::from_secs(1), upstream_handle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
}

fn complete_dns_tcp_messages(stream: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut messages = Vec::new();
    let mut offset = 0usize;
    while offset < stream.len() {
        let prefix_end = offset.checked_add(2)?;
        let prefix = stream.get(offset..prefix_end)?;
        let message_len = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        let message_end = prefix_end.checked_add(message_len)?;
        messages.push(stream.get(prefix_end..message_end)?.to_vec());
        offset = message_end;
    }
    Some(messages)
}

async fn run_tun_fake_dns_udp_ip_if_non_match_routed_freedom_scenario() {
    let unused_proxy_port = allocate_unused_loopback_port();
    let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
    let SocketAddr::V4(echo_addr_v4) = echo_addr else {
        panic!("UDP TUN fake DNS IPIfNonMatch test expects IPv4 echo server");
    };
    let (dns_server, dns_handle) = spawn_udp_dns_a_responder(*echo_addr_v4.ip()).await;
    let mut config =
        runtime_tun_config_with_fake_ip_ip_if_non_match_routed_freedom_outbound(unused_proxy_port);
    config.routing.rules.insert(
        0,
        RoutingRule {
            inbound_tags: vec!["dns-route".to_owned()],
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: "direct".to_owned(),
        },
    );
    config.dns.tag = "dns-route".to_owned();
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: "MOBILE.RESOLVER.EXAMPLE.COM.".to_owned(),
        port: dns_server.port(),
    }];
    config.dns.hosts = vec![DnsHostMapping {
        matcher: DomainMatcher::Full("mobile.resolver.example.com".to_owned()),
        target: DnsHostTarget::Ip(dns_server.ip()),
    }];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let dns_query = build_dns_a_query(0x1204, "www.example.com");
    let dns_request = ipv4_udp_packet(
        client_addr,
        53_001,
        Ipv4Addr::new(1, 1, 1, 1),
        53,
        &dns_query,
    );
    core.tun()
        .push_inbound(Bytes::from(dns_request))
        .await
        .unwrap();

    let dns_reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .and_then(dns_response_answer_ipv4)
            .is_some()
    })
    .await;
    let fake_ip = ipv4_udp_payload(&dns_reply)
        .and_then(dns_response_answer_ipv4)
        .unwrap();
    assert_eq!(fake_ip, Ipv4Addr::new(198, 18, 0, 3));

    let request = ipv4_udp_packet(
        client_addr,
        49_153,
        fake_ip,
        echo_addr_v4.port(),
        b"hello tun ip if non match",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .map(|payload| payload == b"hello tun ip if non match")
            .unwrap_or(false)
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        fake_ip,
        echo_addr_v4.port(),
        client_addr,
        49_153,
        b"hello tun ip if non match",
    );
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), dns_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_udp_vless_echo_scenario() {
    let (vless_addr, vless_handle) = spawn_fake_vless_udp_server().await;
    let echo_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let mut core = Core::new(runtime_tun_config_with_vless_server(vless_addr)).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let request = ipv4_udp_packet(
        client_addr,
        49153,
        Ipv4Addr::LOCALHOST,
        echo_addr.port(),
        b"hello tun vless udp",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .map(|payload| payload == b"hello tun vless udp")
            .unwrap_or(false)
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        Ipv4Addr::LOCALHOST,
        echo_addr.port(),
        client_addr,
        49153,
        b"hello tun vless udp",
    );
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_udp_vless_xudp_echo_scenario() {
    let (vless_addr, vless_handle) = spawn_fake_vless_xudp_server().await;
    let echo_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        allocate_unused_loopback_port(),
    );
    let mut core = Core::new(runtime_tun_config_with_vless_server(vless_addr)).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let request = ipv4_udp_packet(
        client_addr,
        49154,
        Ipv4Addr::LOCALHOST,
        echo_addr.port(),
        b"hello tun vless xudp",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .map(|payload| payload == b"hello tun vless xudp")
            .unwrap_or(false)
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        Ipv4Addr::LOCALHOST,
        echo_addr.port(),
        client_addr,
        49154,
        b"hello tun vless xudp",
    );
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_udp_vision_xudp_echo_scenario() {
    let (client_config, server_config) = tls_test_configs();
    let echo_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        allocate_unused_loopback_port(),
    );
    let (vless_addr, vless_handle) =
        spawn_fake_tls_vision_xudp_server(server_config, echo_addr).await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config = runtime_tun_config_with_tls_vision_vless_domain_server(
        "vless.test",
        vless_addr.port(),
        "vless.test",
    );
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));

    let mut core =
        Core::with_runtime_dependencies(config, Arc::new(resolver), Arc::new(dialer)).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let request = ipv4_udp_packet(
        client_addr,
        49154,
        Ipv4Addr::LOCALHOST,
        echo_addr.port(),
        b"hello vision xudp",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet)
            .map(|payload| payload == b"hello vision xudp")
            .unwrap_or(false)
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        Ipv4Addr::LOCALHOST,
        echo_addr.port(),
        client_addr,
        49154,
        b"hello vision xudp",
    );
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_tun_regular_vision_udp443_rejection_scenario() {
    // Regular `xtls-rprx-vision` cannot carry UDP/443 (QUIC). Matching upstream
    // xray-core, the core must reject it and reply with ICMP port-unreachable so
    // the client falls back to TCP. No VLESS stream is ever opened, so no fake
    // server is contacted.
    let (client_config, _server_config) = tls_test_configs();
    let vless_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        allocate_unused_loopback_port(),
    );
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config = runtime_tun_config_with_tls_vision_vless_domain_server(
        "vless.test",
        vless_addr.port(),
        "vless.test",
    );
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
    let mut core = Core::with_runtime_dependencies_and_tun_options(
        config,
        Arc::new(resolver),
        Arc::new(dialer),
        TunRuntimeOptions::default(),
    )
    .unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let request = ipv4_udp_packet(
        client_addr,
        49155,
        Ipv4Addr::LOCALHOST,
        443,
        b"hello vision xudp",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();

    let reply = poll_tun_outbound_until(core.tun(), is_ipv4_icmp_port_unreachable).await;
    // The ICMP port-unreachable is addressed back to the originating client.
    assert_eq!(&reply[16..20], &client_addr.octets());

    let stats = core.tun().stats().await;
    assert!(stats.udp_vision_udp443_rejections >= 1);
    assert_eq!(stats.udp_remote_open_events, 0);
    core.stop().await.unwrap();
}

async fn run_tun_regular_vision_udp443_rejection_storm_scenario() {
    const FLOW_COUNT: usize = 256;

    for logging_enabled in [false, true] {
        let (client_config, _server_config) = tls_test_configs();
        let vless_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            allocate_unused_loopback_port(),
        );
        let resolver = StaticDnsResolver {
            domain: "vless.test",
            addr: vless_addr,
        };
        let config = runtime_tun_config_with_tls_vision_vless_domain_server(
            "vless.test",
            vless_addr.port(),
            "vless.test",
        );
        let dialer =
            TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
        let mut core = Core::with_runtime_dependencies_and_tun_options(
            config,
            Arc::new(resolver),
            Arc::new(dialer),
            TunRuntimeOptions::default(),
        )
        .unwrap();
        let log_dir =
            logging_enabled.then(|| create_runtime_log_temp_dir("xray-rust-udp443-storm"));
        if let Some(log_dir) = &log_dir {
            core.set_runtime_logger(
                RuntimeLogger::new(RuntimeLogConfig::directory(&log_dir.path)).unwrap(),
            );
        }
        core.start().await.unwrap();

        let started = TokioInstant::now();
        let client_addr = Ipv4Addr::new(10, 10, 0, 2);
        for index in 0..FLOW_COUNT {
            let source_port = 40_000 + u16::try_from(index).unwrap();
            let request = ipv4_udp_packet(
                client_addr,
                source_port,
                Ipv4Addr::new(203, 0, 113, 9),
                443,
                b"instagram quic probe",
            );
            core.tun().push_inbound(Bytes::from(request)).await.unwrap();
        }

        let deadline = TokioInstant::now() + Duration::from_secs(3);
        let stats = loop {
            while core.tun().try_poll_outbound().await.unwrap().is_some() {}
            let stats = core.tun().stats().await;
            if stats.udp_vision_udp443_rejections >= FLOW_COUNT as u64
                && stats.active_udp_flows == 0
            {
                break stats;
            }
            assert!(
                TokioInstant::now() < deadline,
                "timed out draining UDP/443 storm with logging={logging_enabled}: {stats:?}"
            );
            sleep(Duration::from_millis(5)).await;
        };

        assert_eq!(stats.udp_vision_udp443_rejections, FLOW_COUNT as u64);
        assert_eq!(stats.active_udp_flows, 0);
        assert_eq!(stats.udp_remote_open_events, 0);
        core.stop().await.unwrap();

        if let Some(log_dir) = &log_dir {
            let error_log = std::fs::read_to_string(log_dir.path.join("xray-error.log")).unwrap();
            assert!(error_log.contains("Debug udpVisionUDP443Rejected"));
        }
        eprintln!(
            "UDP/443 storm logging={logging_enabled} flows={FLOW_COUNT} elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }
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
    let IpAddr::V4(echo_ip) = echo_addr.ip() else {
        panic!("loopback echo server must use IPv4");
    };
    let (dns_server, dns_handle) = spawn_udp_dns_a_responder(echo_ip).await;
    let mut config =
        runtime_config_with_domain_routed_freedom_outbound(allocate_unused_loopback_port());
    config.dns.servers = vec![DnsServerConfig::Domain {
        domain: "MOBILE.RESOLVER.EXAMPLE.COM.".to_owned(),
        port: dns_server.port(),
    }];
    config.dns.hosts = vec![DnsHostMapping {
        matcher: DomainMatcher::Full("mobile.resolver.example.com".to_owned()),
        target: DnsHostTarget::Ip(dns_server.ip()),
    }];

    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
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
    timeout(Duration::from_secs(1), dns_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_route_only_http_sniffing_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let config =
        runtime_socks_config_with_route_only_http_sniffing(allocate_unused_loopback_port());

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    let request = b"GET / HTTP/1.1\r\nHost: routed.example\r\n\r\n";
    client.write_all(request).await.unwrap();
    let mut echoed = vec![0; request.len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, request);
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}

async fn run_socks_route_only_http_sniffing_split_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let config =
        runtime_socks_config_with_route_only_http_sniffing(allocate_unused_loopback_port());

    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    let first = b"GET / HTTP/1.1\r\nHost: rout";
    let second = b"ed.example\r\n\r\n";
    client.write_all(first).await.unwrap();
    sleep(Duration::from_millis(10)).await;
    client.write_all(second).await.unwrap();

    let mut echoed = vec![0; first.len() + second.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed[..first.len()], first);
    assert_eq!(&echoed[first.len()..], second);

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

async fn run_socks_to_ip_if_non_match_routed_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let resolver = StaticDnsResolver {
        domain: "ip-route.example.test",
        addr: echo_addr,
    };
    let config = runtime_config_with_ip_if_non_match_routed_freedom_outbound(
        InboundProtocol::Socks,
        "socks-in",
        allocate_unused_loopback_port(),
    );

    let mut core = Core::with_dns_resolver(config, Arc::new(resolver)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect_domain(&mut client, "ip-route.example.test", echo_addr.port()).await;

    client.write_all(b"hello ip if non match").await.unwrap();
    let mut echoed = vec![0; "hello ip if non match".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello ip if non match");
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

async fn run_http_to_ip_if_non_match_routed_freedom_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let IpAddr::V4(echo_ip) = echo_addr.ip() else {
        panic!("loopback echo server must use IPv4");
    };
    let (dns_server, dns_handle) = spawn_udp_dns_a_responder(echo_ip).await;
    let mut config = runtime_config_with_ip_if_non_match_routed_freedom_outbound(
        InboundProtocol::Http,
        "http-in",
        allocate_unused_loopback_port(),
    );
    config.dns.servers = vec![DnsServerConfig::Ip(dns_server)];

    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();
    let http_addr = core.inbound_addr(Some("http-in")).unwrap();

    let mut client = TcpStream::connect(http_addr).await.unwrap();
    http_connect_domain(&mut client, "http-ip-route.example.test", echo_addr.port()).await;

    client
        .write_all(b"hello http ip if non match")
        .await
        .unwrap();
    let mut echoed = vec![0; "hello http ip if non match".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello http ip if non match");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), dns_handle)
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

    fn is_open(&mut self) -> bool {
        self.sockets.get::<smol_tcp::Socket>(self.tcp).is_open()
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

struct TunTcpMultiClient {
    iface: SmolInterface,
    device: TestPacketDevice,
    sockets: SocketSet<'static>,
    tcp: Vec<SocketHandle>,
}

impl TunTcpMultiClient {
    fn new(flow_count: usize) -> Self {
        let mut device = TestPacketDevice::new(1500);
        let mut iface_config = SmolInterfaceConfig::new(SmolHardwareAddress::Ip);
        iface_config.random_seed = 0x7475_6e74_6573_7402;
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

        let mut sockets = SocketSet::new(Vec::new());
        let tcp = (0..flow_count)
            .map(|_| {
                sockets.add(smol_tcp::Socket::new(
                    smol_tcp::SocketBuffer::new(vec![0; 8192]),
                    smol_tcp::SocketBuffer::new(vec![0; 8192]),
                ))
            })
            .collect();

        Self {
            iface,
            device,
            sockets,
            tcp,
        }
    }

    fn connect_all(&mut self, target: SocketAddr) {
        self.connect_targets(|_| target);
    }

    fn connect_targets(&mut self, mut target_for_index: impl FnMut(usize) -> SocketAddr) {
        for (index, handle) in self.tcp.iter().copied().enumerate() {
            let SocketAddr::V4(target) = target_for_index(index) else {
                panic!("TUN TCP test client currently covers IPv4 targets only");
            };
            let target_endpoint = (*target.ip(), target.port());
            let source_port = 49152 + u16::try_from(index).unwrap();
            self.sockets
                .get_mut::<smol_tcp::Socket>(handle)
                .connect(self.iface.context(), target_endpoint, source_port)
                .unwrap();
        }
    }

    fn all_may_send(&mut self) -> bool {
        self.tcp
            .iter()
            .copied()
            .all(|handle| self.sockets.get::<smol_tcp::Socket>(handle).may_send())
    }

    fn send_payload(&mut self, index: usize, payload: &[u8]) {
        self.sockets
            .get_mut::<smol_tcp::Socket>(self.tcp[index])
            .send_slice(payload)
            .unwrap();
    }

    fn recv_available(&mut self, index: usize) -> Vec<u8> {
        let mut received = Vec::new();
        let socket = self.sockets.get_mut::<smol_tcp::Socket>(self.tcp[index]);
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

    fn state_summary(&self) -> String {
        self.tcp
            .iter()
            .copied()
            .enumerate()
            .map(|(index, handle)| {
                let socket = self.sockets.get::<smol_tcp::Socket>(handle);
                format!(
                    "#{index}:open={} active={} may_send={} can_recv={}",
                    socket.is_open(),
                    socket.is_active(),
                    socket.may_send(),
                    socket.can_recv()
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
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

async fn pump_multi_tun_until(
    client: &mut TunTcpMultiClient,
    tun: &TunEndpoint,
    mut is_done: impl FnMut(&mut TunTcpMultiClient) -> bool,
) {
    let deadline = TokioInstant::now() + Duration::from_millis(1500);
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
            "timed out waiting for concurrent TUN TCP client state: {}",
            client.state_summary()
        );
        sleep(Duration::from_millis(5)).await;
    }
}

async fn pump_multi_tun_once(client: &mut TunTcpMultiClient, tun: &TunEndpoint) {
    client.poll();
    while let Some(packet) = client.device.pop_outbound() {
        tun.push_inbound(packet).await.unwrap();
    }
    while let Some(packet) = tun.try_poll_outbound().await.unwrap() {
        client.device.push_inbound(packet);
    }
    client.poll();
    sleep(Duration::from_millis(1)).await;
}

async fn pump_tun_once(client: &mut TunTcpClient, tun: &TunEndpoint) {
    client.poll();
    while let Some(packet) = client.device.pop_outbound() {
        tun.push_inbound(packet).await.unwrap();
    }
    while let Some(packet) = tun.try_poll_outbound().await.unwrap() {
        client.device.push_inbound(packet);
    }
    client.poll();
    sleep(Duration::from_millis(1)).await;
}

async fn pump_tun_until_tcp_reset(client: &mut TunTcpClient, tun: &TunEndpoint) -> u8 {
    let deadline = TokioInstant::now() + Duration::from_millis(750);
    loop {
        client.poll();
        while let Some(packet) = client.device.pop_outbound() {
            tun.push_inbound(packet).await.unwrap();
        }
        while let Some(packet) = tun.try_poll_outbound().await.unwrap() {
            let reset_flags = ipv4_tcp_flags(&packet).filter(|flags| flags & 0x04 != 0);
            client.device.push_inbound(packet);
            client.poll();
            if let Some(flags) = reset_flags {
                return flags;
            }
        }
        assert!(
            TokioInstant::now() < deadline,
            "timed out waiting for TUN TCP reset"
        );
        sleep(Duration::from_millis(5)).await;
    }
}

fn ipv4_tcp_flags(packet: &[u8]) -> Option<u8> {
    if packet.first().map(|byte| byte >> 4) != Some(4) || packet.get(9) != Some(&TCP_PROTOCOL) {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f).checked_mul(4)?;
    packet.get(header_len.checked_add(13)?).copied()
}

async fn poll_tun_outbound_until(tun: &TunEndpoint, is_done: impl FnMut(&[u8]) -> bool) -> Bytes {
    poll_tun_outbound_until_with_timeout(tun, Duration::from_millis(750), is_done).await
}

async fn poll_tun_outbound_until_with_timeout(
    tun: &TunEndpoint,
    wait: Duration,
    mut is_done: impl FnMut(&[u8]) -> bool,
) -> Bytes {
    let deadline = TokioInstant::now() + wait;
    loop {
        while let Some(packet) = tun.try_poll_outbound().await.unwrap() {
            if is_done(&packet) {
                return packet;
            }
        }

        assert!(
            TokioInstant::now() < deadline,
            "timed out waiting for TUN outbound packet"
        );
        sleep(Duration::from_millis(5)).await;
    }
}

fn malformed_tun_packet(index: usize) -> Bytes {
    let len = index % 97;
    let mut packet = vec![0; len];
    let mut state = (index as u64)
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    for byte in &mut packet {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        *byte = state.wrapping_mul(2_685_821_657_736_338_717) as u8;
    }

    match index % 4 {
        0 => {
            if !packet.is_empty() {
                packet[0] = 0x45;
            }
            if packet.len() > 9 {
                packet[9] = UDP_PROTOCOL;
            }
        }
        1 => {
            if !packet.is_empty() {
                packet[0] = 0x60;
            }
            if packet.len() > 6 {
                packet[6] = UDP_PROTOCOL;
            }
        }
        2 => {
            if !packet.is_empty() {
                packet[0] = 0x45;
            }
            if packet.len() > 9 {
                packet[9] = 6;
            }
            if packet.len() > 33 {
                packet[33] = 0;
            }
        }
        _ => {
            if !packet.is_empty() {
                packet[0] &= 0x0f;
            }
        }
    }

    Bytes::from(packet)
}

fn ipv4_icmp_echo_request(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ident: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = ICMPV4_PROTOCOL;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let icmp = &mut packet[20..];
    icmp[0] = 8;
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let icmp_checksum = internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

fn ipv6_icmp_echo_request(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    ident: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 40 + icmp_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    packet[6] = ICMPV6_PROTOCOL;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());

    let icmp = &mut packet[40..];
    icmp[0] = 128;
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let checksum = ipv6_transport_checksum(source, destination, ICMPV6_PROTOCOL, icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    packet
}

fn ipv4_udp_packet(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = UDP_PROTOCOL;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum = nonzero_udp_checksum(ipv4_udp_checksum(source, destination, udp));
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    packet
}

fn is_ipv4_icmp_echo_reply(packet: &[u8]) -> bool {
    packet.len() >= 28 && packet[0] >> 4 == 4 && packet[9] == ICMPV4_PROTOCOL && packet[20] == 0
}

fn is_ipv4_icmp_port_unreachable(packet: &[u8]) -> bool {
    packet.len() >= 28
        && packet[0] >> 4 == 4
        && packet[9] == ICMPV4_PROTOCOL
        && packet[20] == 3
        && packet[21] == 3
}

fn is_ipv6_icmp_echo_reply(packet: &[u8]) -> bool {
    packet.len() >= 48 && packet[0] >> 4 == 6 && packet[6] == ICMPV6_PROTOCOL && packet[40] == 129
}

fn ipv4_udp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != UDP_PROTOCOL {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let udp_len = usize::from(u16::from_be_bytes([
        packet[header_len + 4],
        packet[header_len + 5],
    ]));
    if udp_len < 8 || packet.len() < header_len + udp_len {
        return None;
    }
    Some(&packet[header_len + 8..header_len + udp_len])
}

fn build_dns_a_query(id: u16, domain: &str) -> Vec<u8> {
    build_dns_query(id, domain, 1, 1)
}

fn build_dns_query(id: u16, domain: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());
    packet
}

fn dns_response_answer_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 16 {
        return None;
    }
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]);
    if answer_count == 0 {
        return None;
    }
    let mut offset = 12usize;
    loop {
        let len = usize::from(*packet.get(offset)?);
        offset += 1;
        if len == 0 {
            break;
        }
        offset = offset.checked_add(len)?;
        if offset > packet.len() {
            return None;
        }
    }
    offset = offset.checked_add(4)?;
    if packet.get(offset)? & 0xc0 != 0xc0 {
        return None;
    }
    offset = offset.checked_add(2 + 2 + 2 + 4)?;
    let rdlen = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
    offset += 2;
    if rdlen != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
        *packet.get(offset + 2)?,
        *packet.get(offset + 3)?,
    ))
}

fn assert_ipv4_icmp_echo_reply(
    packet: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    ident: u16,
    sequence: u16,
    payload: &[u8],
) {
    assert_eq!(packet[0] >> 4, 4);
    assert_eq!(packet[9], ICMPV4_PROTOCOL);
    assert_eq!(&packet[12..16], &source.octets());
    assert_eq!(&packet[16..20], &destination.octets());
    assert_eq!(internet_checksum(&packet[..20]), 0);

    let icmp = &packet[20..];
    assert_eq!(icmp[0], 0);
    assert_eq!(icmp[1], 0);
    assert_eq!(internet_checksum(icmp), 0);
    assert_eq!(u16::from_be_bytes([icmp[4], icmp[5]]), ident);
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), sequence);
    assert_eq!(&icmp[8..], payload);
}

fn assert_ipv6_icmp_echo_reply(
    packet: &[u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    ident: u16,
    sequence: u16,
    payload: &[u8],
) {
    assert_eq!(packet[0] >> 4, 6);
    assert_eq!(packet[6], ICMPV6_PROTOCOL);
    assert_eq!(&packet[8..24], &source.octets());
    assert_eq!(&packet[24..40], &destination.octets());

    let icmp = &packet[40..];
    assert_eq!(icmp[0], 129);
    assert_eq!(icmp[1], 0);
    assert_eq!(
        ipv6_transport_checksum(source, destination, ICMPV6_PROTOCOL, icmp),
        0
    );
    assert_eq!(u16::from_be_bytes([icmp[4], icmp[5]]), ident);
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), sequence);
    assert_eq!(&icmp[8..], payload);
}

fn assert_ipv4_udp_packet(
    packet: &[u8],
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) {
    assert_eq!(packet[0] >> 4, 4);
    assert_eq!(packet[9], UDP_PROTOCOL);
    assert_eq!(&packet[12..16], &source.octets());
    assert_eq!(&packet[16..20], &destination.octets());
    assert_eq!(internet_checksum(&packet[..20]), 0);

    let udp = &packet[20..];
    assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), source_port);
    assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), destination_port);
    assert_eq!(
        u16::from_be_bytes([udp[4], udp[5]]),
        (8 + payload.len()) as u16
    );
    assert_eq!(ipv4_udp_checksum(source, destination, udp), 0);
    assert_eq!(&udp[8..], payload);
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv6_transport_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(payload);
    internet_checksum(&pseudo)
}

fn ipv4_udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&[0, UDP_PROTOCOL]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    internet_checksum(&pseudo)
}

fn nonzero_udp_checksum(checksum: u16) -> u16 {
    if checksum == 0 {
        u16::MAX
    } else {
        checksum
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

async fn spawn_tcp_accept_probe() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_for_task = Arc::clone(&accepted);
    let handle = tokio::spawn(async move {
        if timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_ok()
        {
            accepted_for_task.fetch_add(1, Ordering::SeqCst);
        }
    });
    (addr, accepted, handle)
}

async fn spawn_multi_echo_server(connection_count: usize) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut handles = Vec::with_capacity(connection_count);
        for _ in 0..connection_count {
            let (mut stream, _) = listener.accept().await.unwrap();
            handles.push(tokio::spawn(async move {
                let (mut read_half, mut write_half) = stream.split();
                let _ = tokio::io::copy(&mut read_half, &mut write_half).await;
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    });
    (addr, handle)
}

struct RuntimeLogTempDir {
    path: std::path::PathBuf,
}

impl Drop for RuntimeLogTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn create_runtime_log_temp_dir(prefix: &str) -> RuntimeLogTempDir {
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!("{prefix}-{}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return RuntimeLogTempDir { path },
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create temp log dir {path:?}: {error}"),
        }
    }
    panic!("failed to allocate temp log dir for {prefix}");
}

async fn spawn_udp_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buffer = [0; 2048];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        socket.send_to(&buffer[..len], peer).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_ipv6_udp_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buffer = [0; 2048];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        socket.send_to(&buffer[..len], peer).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_udp_dns_responder(extra_bytes: usize) -> (SocketAddr, JoinHandle<()>) {
    spawn_udp_dns_responder_with_transaction_id(extra_bytes, None).await
}

async fn spawn_udp_dns_wrong_question_then_valid_responder() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buffer = [0_u8; 1232];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        let transaction_id = u16::from_be_bytes([query[0], query[1]]);
        let mut unrelated = build_dns_query(transaction_id, "unrelated.example", 65, 1);
        unrelated[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        socket.send_to(&unrelated, peer).await.unwrap();

        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        socket.send_to(&response, peer).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_udp_dns_a_responder(answer: Ipv4Addr) -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        for _ in 0..2 {
            let mut buffer = [0_u8; 1232];
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = &buffer[..len];
            assert!(query.len() >= 16, "DNS query must contain a question");
            let response = match u16::from_be_bytes([query[len - 4], query[len - 3]]) {
                1 => build_dns_a_response_for_query(query, answer),
                28 => build_dns_nodata_response_for_query(query),
                record_type => panic!("unexpected DNS query type {record_type}"),
            };
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    (addr, handle)
}

async fn spawn_tcp_dns_responder() -> (SocketAddr, JoinHandle<()>) {
    spawn_tcp_dns_responder_with_flags(0x8180).await
}

async fn spawn_tcp_dns_responder_with_flags(response_flags: u16) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let query_len = usize::from(tcp.read_u16().await.unwrap());
        let mut response = vec![0_u8; query_len];
        tcp.read_exact(&mut response).await.unwrap();
        response[2..4].copy_from_slice(&response_flags.to_be_bytes());
        tcp.write_u16(u16::try_from(response.len()).unwrap())
            .await
            .unwrap();
        tcp.write_all(&response).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_udp_dns_aaaa_responder(answer: Ipv6Addr) -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        for _ in 0..2 {
            let mut buffer = [0_u8; 1232];
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = &buffer[..len];
            assert!(query.len() >= 16, "DNS query must contain a question");
            let response = match u16::from_be_bytes([query[len - 4], query[len - 3]]) {
                1 => build_dns_nodata_response_for_query(query),
                28 => build_dns_aaaa_response_for_query(query, answer),
                record_type => panic!("unexpected DNS query type {record_type}"),
            };
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    (addr, handle)
}

async fn spawn_udp_tcp_dns_a_responder(answer: Ipv4Addr) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let handle = tokio::spawn(async move {
        for _ in 0..2 {
            let mut udp_query = [0_u8; 1232];
            let (udp_len, udp_peer) = udp.recv_from(&mut udp_query).await.unwrap();
            let query = &udp_query[..udp_len];
            assert!(query.len() >= 16, "DNS query must contain a question");
            match u16::from_be_bytes([query[udp_len - 4], query[udp_len - 3]]) {
                1 => {
                    let mut truncated = Vec::with_capacity(query.len());
                    truncated.extend_from_slice(&query[..2]);
                    truncated.extend_from_slice(&0x8380_u16.to_be_bytes());
                    truncated.extend_from_slice(&1_u16.to_be_bytes());
                    truncated.extend_from_slice(&0_u16.to_be_bytes());
                    truncated.extend_from_slice(&0_u16.to_be_bytes());
                    truncated.extend_from_slice(&0_u16.to_be_bytes());
                    truncated.extend_from_slice(&query[12..]);
                    udp.send_to(&truncated, udp_peer).await.unwrap();

                    let (mut tcp, _) = listener.accept().await.unwrap();
                    let query_len = usize::from(tcp.read_u16().await.unwrap());
                    let mut query = vec![0_u8; query_len];
                    tcp.read_exact(&mut query).await.unwrap();
                    let response = build_dns_a_response_for_query(&query, answer);
                    tcp.write_u16(u16::try_from(response.len()).unwrap())
                        .await
                        .unwrap();
                    tcp.write_all(&response).await.unwrap();
                }
                28 => {
                    let response = build_dns_nodata_response_for_query(query);
                    udp.send_to(&response, udp_peer).await.unwrap();
                }
                record_type => panic!("unexpected DNS query type {record_type}"),
            }
        }
    });
    (addr, handle)
}

fn build_dns_a_response_for_query(query: &[u8], answer: Ipv4Addr) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len() + 16);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..]);
    response.extend_from_slice(&0xC00C_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&answer.octets());
    response
}

fn build_dns_aaaa_response_for_query(query: &[u8], answer: Ipv6Addr) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len() + 28);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..]);
    response.extend_from_slice(&0xC00C_u16.to_be_bytes());
    response.extend_from_slice(&28_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&16_u16.to_be_bytes());
    response.extend_from_slice(&answer.octets());
    response
}

fn build_dns_nodata_response_for_query(query: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len());
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..]);
    response
}

async fn spawn_udp_dns_responder_with_transaction_id(
    extra_bytes: usize,
    transaction_id: Option<u16>,
) -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buffer = vec![0; u16::MAX as usize];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let mut response = buffer[..len].to_vec();
        assert!(response.len() >= 12, "DNS query must contain a header");
        if let Some(transaction_id) = transaction_id {
            response[0..2].copy_from_slice(&transaction_id.to_be_bytes());
        }
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response.resize(response.len() + extra_bytes, 0x5a);
        socket.send_to(&response, peer).await.unwrap();
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
        if let Err(error) = copy_bidirectional(&mut inbound, &mut target_stream).await {
            assert_eq!(error.kind(), ErrorKind::ConnectionReset);
        }
    });
    (addr, handle)
}

async fn spawn_fake_vless_udp_server() -> (SocketAddr, JoinHandle<()>) {
    spawn_fake_vless_udp_server_for_payload(b"hello tun vless udp").await
}

async fn spawn_fake_vless_udp_server_for_payload(
    expected_payload: &'static [u8],
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_target_with_command(&mut inbound, 2).await;
        assert_eq!(target.network, RoutingNetwork::Udp);
        inbound.write_all(&[0, 0]).await.unwrap();

        let payload = read_udp_packet(&mut inbound).await.unwrap();
        assert_eq!(&payload[..], expected_payload);
        inbound
            .write_all(&encode_udp_packet(&payload).unwrap())
            .await
            .unwrap();
    });
    (addr, handle)
}

async fn spawn_fake_vless_xudp_target_server(
    expected_target: Target,
    expected_payload: &'static [u8],
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        read_vless_mux_header(&mut inbound).await;
        inbound.write_all(&[0, 0]).await.unwrap();

        let packet = read_xudp_packet(&mut inbound).await.unwrap();
        let target = packet.source.expect("xudp new frame carries target");
        assert_eq!(target, expected_target);
        assert_eq!(&packet.payload[..], expected_payload);
        let response = encode_xudp_keep_packet(Some(&target), &packet.payload).unwrap();
        inbound.write_all(&response).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_fake_vless_dns_server(
    expected_upstream: SocketAddr,
    expected_query: Vec<u8>,
) -> (SocketAddr, JoinHandle<()>) {
    spawn_fake_vless_dns_server_with_delay(expected_upstream, expected_query, Duration::ZERO).await
}

async fn spawn_fake_vless_dns_server_with_delay(
    expected_upstream: SocketAddr,
    expected_query: Vec<u8>,
    response_delay: Duration,
) -> (SocketAddr, JoinHandle<()>) {
    spawn_fake_vless_dns_target_server(
        Target::new(
            RoutingTargetAddr::Ip(expected_upstream.ip()),
            expected_upstream.port(),
            RoutingNetwork::Udp,
        ),
        expected_query,
        response_delay,
    )
    .await
}

async fn spawn_fake_vless_dns_target_server(
    expected_target: Target,
    expected_query: Vec<u8>,
    response_delay: Duration,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_target_with_command(&mut inbound, 2).await;
        assert_eq!(target, expected_target);
        inbound.write_all(&[0, 0]).await.unwrap();

        let payload = read_udp_packet(&mut inbound).await.unwrap();
        assert_eq!(&payload[..], expected_query);
        sleep(response_delay).await;
        let mut response = payload.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        inbound
            .write_all(&encode_udp_packet(&response).unwrap())
            .await
            .unwrap();
    });
    (addr, handle)
}

async fn spawn_fake_vless_dynamic_dns_a_server(
    expected_target: Target,
    answer: Ipv4Addr,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_target_with_command(&mut inbound, 2).await;
        assert_eq!(target, expected_target);
        inbound.write_all(&[0, 0]).await.unwrap();

        let query = read_udp_packet(&mut inbound).await.unwrap();
        let response = build_dns_a_response_for_query(&query, answer);
        inbound
            .write_all(&encode_udp_packet(&response).unwrap())
            .await
            .unwrap();
    });
    (addr, handle)
}

async fn spawn_fake_vless_dns_tcp_target_server(
    expected_target: Target,
    expected_payload: Vec<u8>,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_target_with_command(&mut inbound, 1).await;
        assert_eq!(target, expected_target);
        inbound.write_all(&[0, 0]).await.unwrap();

        let mut payload = vec![0; expected_payload.len()];
        inbound.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, expected_payload);
        inbound.write_all(&payload).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_fake_vless_dns_tcp_query_server(
    expected_target: Target,
    expected_query: Vec<u8>,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let target = read_vless_target_with_command(&mut inbound, 1).await;
        assert_eq!(target, expected_target);
        inbound.write_all(&[0, 0]).await.unwrap();

        let query_len = usize::from(inbound.read_u16().await.unwrap());
        let mut response = vec![0_u8; query_len];
        inbound.read_exact(&mut response).await.unwrap();
        assert_eq!(response, expected_query);
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        inbound
            .write_u16(u16::try_from(response.len()).unwrap())
            .await
            .unwrap();
        inbound.write_all(&response).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_fake_vless_xudp_dns_target_server(
    expected_target: Target,
    expected_query: Vec<u8>,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        read_vless_mux_header(&mut inbound).await;
        inbound.write_all(&[0, 0]).await.unwrap();

        let packet = read_xudp_packet(&mut inbound).await.unwrap();
        let target = packet.source.expect("xudp new frame carries DNS target");
        assert_eq!(target, expected_target);
        assert_eq!(&packet.payload[..], expected_query);
        let mut response = packet.payload.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let response = encode_xudp_keep_packet(Some(&target), &response).unwrap();
        inbound.write_all(&response).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_fake_vless_xudp_server() -> (SocketAddr, JoinHandle<()>) {
    spawn_fake_vless_xudp_server_for_payload(b"hello tun vless xudp").await
}

async fn spawn_fake_vless_xudp_server_for_payload(
    expected_payload: &'static [u8],
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        read_vless_mux_header(&mut inbound).await;
        inbound.write_all(&[0, 0]).await.unwrap();

        let packet = read_xudp_packet(&mut inbound).await.unwrap();
        let target = packet.source.expect("xudp new frame carries target");
        assert_eq!(target.network, RoutingNetwork::Udp);
        assert_eq!(&packet.payload[..], expected_payload);

        let response = encode_xudp_keep_packet(Some(&target), &packet.payload).unwrap();
        inbound.write_all(&response).await.unwrap();
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

async fn spawn_fake_tls_vision_xudp_server(
    server_config: Arc<rustls::ServerConfig>,
    expected_target: SocketAddr,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut inbound = acceptor.accept(stream).await.unwrap();
        read_vless_mux_header(&mut inbound).await;
        inbound.write_all(&[0, 0]).await.unwrap();

        let vision_payload = read_vision_payload(&mut inbound).await;
        let mut cursor = Cursor::new(vision_payload.to_vec());
        let packet = read_xudp_packet(&mut cursor).await.unwrap();
        let target = packet.source.expect("xudp new frame carries target");
        assert_eq!(target.network, RoutingNetwork::Udp);
        assert_eq!(target.port, expected_target.port());
        assert_eq!(
            target.addr,
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(&packet.payload[..], b"hello vision xudp");

        let response = encode_xudp_keep_packet(Some(&target), &packet.payload).unwrap();
        let mut padding = VisionPadding::new(TEST_UUID_BYTES, [0, 0, 0, 0]);
        let padded = padding
            .pad(BytesMut::from(&response[..]), VisionCommand::Continue, 0)
            .unwrap();
        inbound.write_all(&padded).await.unwrap();
    });

    (addr, handle)
}

async fn spawn_fake_tls_vision_xudp_dns_server(
    server_config: Arc<rustls::ServerConfig>,
    expected_upstream: SocketAddr,
    expected_query: Vec<u8>,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut inbound = acceptor.accept(stream).await.unwrap();
        read_vless_mux_header(&mut inbound).await;
        inbound.write_all(&[0, 0]).await.unwrap();

        let vision_payload = read_vision_payload(&mut inbound).await;
        let metadata_len = usize::from(u16::from_be_bytes([vision_payload[0], vision_payload[1]]));
        assert_eq!(metadata_len, 20, "IPv4 NEW frame metadata layout changed");
        let metadata = &vision_payload[2..2 + metadata_len];
        assert_eq!(metadata[2], 1, "DNS query must open a new XUDP session");
        assert_eq!(
            &metadata[metadata.len() - 8..],
            &[0; 8],
            "per-query DNS XUDP streams use the independent GlobalID"
        );

        let mut cursor = Cursor::new(vision_payload.to_vec());
        let packet = read_xudp_packet(&mut cursor).await.unwrap();
        let target = packet.source.expect("xudp new frame carries target");
        assert_eq!(target.network, RoutingNetwork::Udp);
        assert_eq!(target.port, expected_upstream.port());
        assert_eq!(target.addr, RoutingTargetAddr::Ip(expected_upstream.ip()));
        assert_eq!(&packet.payload[..], expected_query);

        let mut response = packet.payload.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let response = encode_xudp_keep_packet(Some(&target), &response).unwrap();
        let mut padding = VisionPadding::new(TEST_UUID_BYTES, [0, 0, 0, 0]);
        let padded = padding
            .pad(BytesMut::from(&response[..]), VisionCommand::Continue, 0)
            .unwrap();
        inbound.write_all(&padded).await.unwrap();
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

async fn socks5_udp_associate(client: &mut TcpStream) -> SocketAddr {
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    client
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ))
}

fn quic_initial_packet_with_sni(host: &str) -> Vec<u8> {
    const INITIAL_SALT: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let scid = [0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    let packet_number = 0u64;
    let packet_number_len = 1usize;

    let handshake = tls_client_hello_handshake_with_sni(host);
    let mut plaintext = Vec::new();
    plaintext.push(0x06);
    encode_quic_varint(0, &mut plaintext);
    encode_quic_varint(handshake.len() as u64, &mut plaintext);
    plaintext.extend_from_slice(&handshake);

    let initial_secret = {
        let hk = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), &dcid);
        let mut secret = [0u8; 32];
        hk.expand(&hkdf_label(32, b"client in"), &mut secret)
            .expect("initial secret label is valid");
        secret
    };
    let hk = Hkdf::<Sha256>::from_prk(&initial_secret).expect("initial secret is valid");
    let mut key = [0u8; 16];
    hk.expand(&hkdf_label(16, b"quic key"), &mut key)
        .expect("key label is valid");
    let mut iv = [0u8; 12];
    hk.expand(&hkdf_label(12, b"quic iv"), &mut iv)
        .expect("iv label is valid");
    let mut hp = [0u8; 16];
    hk.expand(&hkdf_label(16, b"quic hp"), &mut hp)
        .expect("hp label is valid");

    let mut header = Vec::new();
    header.push(0xc0);
    header.extend_from_slice(&1u32.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(&dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(&scid);
    encode_quic_varint(0, &mut header);
    encode_quic_varint(
        packet_number_len as u64 + plaintext.len() as u64 + 16,
        &mut header,
    );
    let packet_number_offset = header.len();
    header.push(packet_number as u8);

    let mut nonce = iv;
    for (index, byte) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    let cipher = Aes128Gcm::new_from_slice(&key).expect("key length is valid");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            AeadPayload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .expect("fixture encryption should succeed");

    let mut packet = header;
    packet.extend_from_slice(&ciphertext);

    let sample_offset = packet_number_offset + 4;
    let mask = {
        let cipher = Aes128::new_from_slice(&hp).expect("hp key length is valid");
        let mut block = aes::cipher::Block::<Aes128>::clone_from_slice(
            &packet[sample_offset..sample_offset + 16],
        );
        cipher.encrypt_block(&mut block);
        block
    };
    packet[0] ^= mask[0] & 0x0f;
    for index in 0..packet_number_len {
        packet[packet_number_offset + index] ^= mask[index + 1];
    }
    packet
}

fn tls_client_hello_handshake_with_sni(host: &str) -> Vec<u8> {
    let mut sni_entry = Vec::new();
    sni_entry.push(0);
    sni_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_entry.extend_from_slice(host.as_bytes());

    let mut sni_extension = Vec::new();
    sni_extension.extend_from_slice(&((sni_entry.len()) as u16).to_be_bytes());
    sni_extension.extend_from_slice(&sni_entry);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_extension);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    handshake.extend_from_slice(&[
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ]);
    handshake.extend_from_slice(&body);
    handshake
}

fn encode_quic_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 16_384 {
        let encoded = (value as u16) | 0x4000;
        output.extend_from_slice(&encoded.to_be_bytes());
    } else {
        panic!("test varint value is too large: {value}");
    }
}

fn hkdf_label(length: u16, label: &[u8]) -> Vec<u8> {
    let full_label_len = b"tls13 ".len() + label.len();
    let mut output = Vec::with_capacity(2 + 1 + full_label_len + 1);
    output.extend_from_slice(&length.to_be_bytes());
    output.push(full_label_len as u8);
    output.extend_from_slice(b"tls13 ");
    output.extend_from_slice(label);
    output.push(0);
    output
}

async fn http_connect(client: &mut TcpStream, target: SocketAddr) {
    let authority = target.to_string();
    http_connect_authority(client, &authority).await;
}

async fn http_connect_domain(client: &mut TcpStream, domain: &str, port: u16) {
    let authority = format!("{domain}:{port}");
    http_connect_authority(client, &authority).await;
}

async fn http_connect_authority(client: &mut TcpStream, authority: &str) {
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
    read_vless_target_with_command(stream, 1).await
}

async fn read_vless_target_with_command<S>(stream: &mut S, expected_command: u8) -> Target
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
    assert_eq!(command, expected_command);

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

    let network = match command {
        1 => RoutingNetwork::Tcp,
        2 => RoutingNetwork::Udp,
        other => panic!("unsupported VLESS command {other}"),
    };
    Target::new(addr, port, network)
}

async fn read_vless_mux_header<S>(stream: &mut S)
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await.unwrap();
    assert_eq!(version, 0);

    let mut uuid = [0; 16];
    stream.read_exact(&mut uuid).await.unwrap();
    assert_eq!(uuid, TEST_UUID_BYTES);

    let addons_len = stream.read_u8().await.unwrap();
    let mut addons = vec![0; usize::from(addons_len)];
    stream.read_exact(&mut addons).await.unwrap();

    let command = stream.read_u8().await.unwrap();
    assert_eq!(command, 3);
}

async fn read_vision_payload<S>(stream: &mut S) -> BytesMut
where
    S: AsyncRead + Unpin,
{
    let mut header = vec![0; 21];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(&header[..16], &TEST_UUID_BYTES);

    let content_len = usize::from(u16::from_be_bytes([header[17], header[18]]));
    let padding_len = usize::from(u16::from_be_bytes([header[19], header[20]]));
    let mut rest = vec![0; content_len + padding_len];
    stream.read_exact(&mut rest).await.unwrap();
    header.extend_from_slice(&rest);

    let block = unpad_vision_block(&header, &TEST_UUID_BYTES).unwrap();
    assert_eq!(block.command, VisionCommand::Continue);
    block.payload
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
