use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use uuid::Uuid;
use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
    RealitySettings, RealityShortId, StreamSecurity, StreamSettings, TargetAddr, TlsSettings,
    VlessOutboundSettings, VlessUser,
};
use xray_core_rs::{Core, CoreError, select_vless_tcp_outbound};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{DnsResolver, TransportError};

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

fn config_with_outbound(outbound: OutboundConfig) -> CoreConfig {
    CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![outbound],
        default_outbound_tag: None,
    }
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
    };

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server().port, 443);
}

#[test]
fn rejects_reality_outbound_for_raw_tcp_runtime_path() {
    let config = config_with_outbound(vless_outbound(
        reality_security(),
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
fn rejects_tls_outbound_for_raw_tcp_runtime_path() {
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
    let OutboundSettings::Vless(settings) = &mut outbound.settings;
    settings.users[0].flow = Some("xtls-rprx-vision".to_owned());
    let config = config_with_outbound(outbound);

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(result, Err(CoreError::UnsupportedOutboundFlow)));
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

async fn run_domain_vless_server_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (vless_addr, vless_handle) = spawn_fake_vless_server().await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config = runtime_config_with_vless_domain_server("vless.test", vless_addr.port());

    let mut core = Core::with_dns_resolver(config, std::sync::Arc::new(resolver)).unwrap();
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

    let mut core = Core::with_dns_resolver(config, std::sync::Arc::new(resolver)).unwrap();
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

async fn read_vless_target(stream: &mut TcpStream) -> Target {
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

async fn read_vless_header(stream: &mut TcpStream) -> SocketAddr {
    let target = read_vless_target(stream).await;
    let RoutingTargetAddr::Ip(ip) = target.addr else {
        panic!("this E2E expects an IP VLESS target");
    };
    SocketAddr::new(ip, target.port)
}
