use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
    RoutingConfig, RoutingRule, StreamSecurity, StreamSettings,
};
use xray_core_rs::{Core, CoreError, CoreState, StartupProbeError, StartupProbeOptions};
use xray_transport::{DnsResolver, TransportDialer, TransportError};

fn freedom(tag: &str) -> OutboundConfig {
    OutboundConfig {
        tag: Some(tag.to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security: StreamSecurity::None,
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
        }],
        outbounds,
        default_outbound_tag: default.map(ToOwned::to_owned),
        routing: RoutingConfig::default(),
        dns: Default::default(),
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

async fn spawn_http_status_once(status: u16) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 512];
        let read = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /health HTTP/1.1\r\n"));
        let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n");
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    addr
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

#[tokio::test]
async fn startup_probe_succeeds_for_http_2xx_response() {
    let addr = spawn_http_status_once(204).await;
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
async fn startup_probe_fails_for_http_4xx_response_and_rolls_back_start() {
    let addr = spawn_http_status_once(404).await;
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
async fn startup_probe_accepts_http_3xx_response() {
    let addr = spawn_http_status_once(302).await;
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
async fn startup_probe_uses_default_outbound_directly_without_routing_rules() {
    let addr = spawn_http_status_once(204).await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut config = config_with_outbounds(vec![freedom("direct")], Some("direct"));
    config.routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: "missing".to_owned(),
        }],
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
