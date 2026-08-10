use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use xray_config::{
    CoreConfig, DnsQueryStrategy, DnsServerConfig, InboundConfig, InboundProtocol, Network,
    OutboundConfig, OutboundSettings, PolicyConfig, PolicyLevelConfig, RoutingConfig, RoutingRule,
    StreamSecurity, StreamSettings, StreamTransport,
};
use xray_core_rs::{
    Core, CoreError, CoreState, DnsBootstrapMode, RuntimeLogConfig, RuntimeLogger,
    StartupProbeError, StartupProbeOptions, TunRuntimeOptions,
};
use xray_transport::{DnsResolver, TransportDialer, TransportError};

fn freedom(tag: &str) -> OutboundConfig {
    OutboundConfig {
        tag: Some(tag.to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::None,
            quic_params: None,
            socket_options: None,
        },
        settings: OutboundSettings::Freedom,
    }
}

fn config_with_outbounds(outbounds: Vec<OutboundConfig>, default: Option<&str>) -> CoreConfig {
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
        outbounds,
        default_outbound_tag: default.map(ToOwned::to_owned),
        routing: RoutingConfig::default(),
        dns: Default::default(),
        policy: Default::default(),
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
struct DelayedDnsResolver {
    domain: &'static str,
    addr: SocketAddr,
    delay: Duration,
}

#[async_trait]
impl DnsResolver for DelayedDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        tokio::time::sleep(self.delay).await;
        if domain == self.domain && port == self.addr.port() {
            Ok(self.addr)
        } else {
            Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
        }
    }
}

async fn spawn_http_status_once(status: u16, expected_target: &'static str) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 512];
        let read = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..read])
            .starts_with(&format!("GET {expected_target} HTTP/1.1\r\n")));
        let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n");
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    addr
}

async fn spawn_udp_dns_a_once(answer: Ipv4Addr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buffer = [0_u8; 1232];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = &buffer[..len];
        assert!(query.len() >= 16, "DNS query must contain one question");
        let record_type = u16::from_be_bytes([query[len - 4], query[len - 3]]);
        assert_eq!(record_type, 1, "fixture expects one IPv4 query");

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
        socket.send_to(&response, peer).await.unwrap();
    });
    (addr, handle)
}

async fn spawn_http_status_then_echo_once(
    status: u16,
    expected_target: &'static str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut probe, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 512];
        let read = probe.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..read])
            .starts_with(&format!("GET {expected_target} HTTP/1.1\r\n")));
        let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n");
        probe.write_all(response.as_bytes()).await.unwrap();
        drop(probe);

        let (mut tunneled, _) = listener.accept().await.unwrap();
        let mut byte = [0_u8; 1];
        tunneled.read_exact(&mut byte).await.unwrap();
        tunneled.write_all(&byte).await.unwrap();
    });
    (addr, handle)
}

async fn socks5_connect_domain(client: &mut TcpStream, domain: &str, port: u16) {
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 3, u8::try_from(domain.len()).unwrap()];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

async fn spawn_http_split_status_once(status: u16) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 512];
        let read = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /health HTTP/1.1\r\n"));
        stream.write_all(b"HTTP/1.1 ").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let response = format!("{status} Test\r\nContent-Length: 0\r\n\r\n");
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    addr
}

async fn spawn_http_expect_custom_host_once() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_host = format!("probe.test:{}", addr.port());
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 1024];
        let read = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("GET /health HTTP/1.1\r\n"));
        assert!(request.contains(&format!("\r\nHost: {expected_host}\r\n")));
        stream
            .write_all(b"HTTP/1.1 204 Test\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    addr
}

async fn spawn_stalled_http_once() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    addr
}

fn probe_url(addr: SocketAddr) -> String {
    format!("http://probe.test:{}/health", addr.port())
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

#[tokio::test]
async fn startup_probe_succeeds_for_http_2xx_response() {
    let addr = spawn_http_status_once(204, "/health").await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn startup_probe_warms_shared_routed_dns_for_listener_in_static_only_mode() {
    let (addr, target_handle) = spawn_http_status_then_echo_once(204, "/health").await;
    let (dns_server, dns_handle) = spawn_udp_dns_a_once(Ipv4Addr::LOCALHOST).await;
    let mut config = config_with_outbounds(vec![freedom("direct")], Some("direct"));
    config.dns.query_strategy = DnsQueryStrategy::UseIpv4;
    config.dns.servers = vec![DnsServerConfig::Ip(dns_server)];
    let mut core = Core::with_tun_runtime_options(
        config,
        TunRuntimeOptions {
            dns_bootstrap: DnsBootstrapMode::StaticOnly,
            ..TunRuntimeOptions::default()
        },
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        socks5_connect_domain(&mut client, "probe.test", addr.port()),
    )
    .await
    .unwrap();
    client.write_all(b"x").await.unwrap();
    let mut echoed = [0_u8; 1];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"x");
    drop(client);
    core.stop().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), target_handle)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), dns_handle)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn startup_probe_fails_for_http_4xx_response_and_rolls_back_start() {
    let addr = spawn_http_status_once(404, "/health").await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    let error = core.start().await.unwrap_err();

    assert!(matches!(error, CoreError::StartupProbe(_)));
    assert_eq!(core.state(), CoreState::Stopped);
}

#[tokio::test]
async fn startup_probe_failure_is_written_to_runtime_error_log() {
    let addr = spawn_http_status_once(404, "/health?token=private").await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let log_dir = unique_temp_dir("xray-startup-probe-log");
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: format!("http://probe.test:{}/health?token=private", addr.port()),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });
    core.set_runtime_logger(
        RuntimeLogger::new(RuntimeLogConfig::directory(&log_dir))
            .expect("runtime logger should open files"),
    );

    let error = core.start().await.unwrap_err();

    assert!(matches!(error, CoreError::StartupProbe(_)));
    drop(core);
    let error_log =
        std::fs::read_to_string(log_dir.join("xray-error.log")).expect("error log should exist");
    assert!(error_log.contains("Debug startupProbe start"));
    assert!(error_log.contains("Debug startupProbe fail"));
    assert!(error_log.contains("error=<redacted>"));
    assert!(!error_log.contains("HTTP status 404"));
    assert!(error_log.contains(&format!("url=http://<redacted-host>:{}", addr.port())));
    assert!(!error_log.contains("probe.test"));
    assert!(!error_log.contains("/health"));
    assert!(!error_log.contains("token=private"));
}

#[tokio::test]
async fn startup_probe_accepts_http_3xx_response() {
    let addr = spawn_http_status_once(302, "/health").await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn startup_probe_timeout_rolls_back_start() {
    let addr = spawn_stalled_http_once().await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_millis(100),
        outbound_tag: Some("direct".to_owned()),
    });

    let error = core.start().await.unwrap_err();

    assert!(
        matches!(
            error,
            CoreError::StartupProbe(StartupProbeError::Timeout { .. })
        ),
        "expected startup probe timeout, got {error:?}"
    );
    assert_eq!(core.state(), CoreState::Stopped);
}

#[tokio::test]
async fn startup_probe_uses_probe_timeout_when_policy_handshake_is_short() {
    let addr = spawn_http_status_once(204, "/health").await;
    let mut config = config_with_outbounds(vec![freedom("direct")], Some("direct"));
    config.policy = PolicyConfig {
        levels: BTreeMap::from([(
            0,
            PolicyLevelConfig {
                handshake: Some(1),
                ..Default::default()
            },
        )]),
        system: Default::default(),
    };
    let mut core = Core::with_runtime_dependencies(
        config,
        Arc::new(DelayedDnsResolver {
            domain: "probe.test",
            addr,
            delay: Duration::from_millis(1500),
        }),
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn startup_probe_uses_default_outbound_directly_without_routing_rules() {
    let addr = spawn_http_status_once(204, "/health").await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut config = config_with_outbounds(vec![freedom("direct")], Some("direct"));
    config.routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: "missing".to_owned(),
        }],
        ..Default::default()
    };
    let mut core = Core::with_runtime_dependencies(
        config,
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_secs(2),
        outbound_tag: None,
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn startup_probe_succeeds_when_http_status_line_is_split_across_reads() {
    let addr = spawn_http_split_status_once(204).await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn startup_probe_sends_custom_port_in_host_header() {
    let addr = spawn_http_expect_custom_host_once().await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: probe_url(addr),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}
