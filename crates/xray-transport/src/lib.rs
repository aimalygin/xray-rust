use async_trait::async_trait;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpStream;
use xray_routing::{Target, TargetAddr};

pub mod reality;
pub mod reality_connector;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorConfig {
    Tcp,
    Tls(TlsClientConfig),
    Reality(RealityClientConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientConfig {
    pub server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("domain resolution is required for {0}")]
    NeedsDns(String),
    #[error("dns lookup failed for {domain}:{port}: {source}")]
    Dns {
        domain: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("dns lookup returned no addresses for {0}:{1}")]
    NoResolvedAddress(String, u16),
    #[error("tcp connect failed: {0}")]
    Tcp(std::io::Error),
    #[error("tls connect failed")]
    Tls,
    #[error("{0} connector config is not supported by TcpConnector")]
    UnsupportedConnectorConfig(&'static str),
    #[error("unsupported REALITY fingerprint {0}")]
    UnsupportedRealityFingerprint(String),
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        let mut addrs = tokio::net::lookup_host((domain, port))
            .await
            .map_err(|source| TransportError::Dns {
                domain: domain.to_owned(),
                port,
                source,
            })?;

        addrs
            .next()
            .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
    }
}

#[async_trait]
pub trait TransportConnector: Send + Sync {
    type Stream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError>;

    fn describe_target(&self, target: &Target) -> String {
        match &target.addr {
            TargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
            TargetAddr::Domain(domain) => format!("{domain}:{}", target.port),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpConnector {
    config: ConnectorConfig,
}

impl TcpConnector {
    pub fn new(config: ConnectorConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl TransportConnector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError> {
        match &self.config {
            ConnectorConfig::Tcp => {}
            ConnectorConfig::Tls(_) => {
                return Err(TransportError::UnsupportedConnectorConfig("tls"));
            }
            ConnectorConfig::Reality(_) => {
                return Err(TransportError::UnsupportedConnectorConfig("reality"));
            }
        }

        let addr = match &target.addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
            TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
        };

        TcpStream::connect(addr).await.map_err(TransportError::Tcp)
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
