use async_trait::async_trait;
use std::fmt;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use xray_routing::{Target, TargetAddr};
use zeroize::Zeroize;

mod dialer;
pub mod reality;
pub mod reality_connector;
pub mod reality_runtime;
mod tls;

pub use dialer::TransportDialer;
pub use reality_runtime::{
    RealityHandshakeContextProvider, RealityRuntimeEngine, SystemRealityHandshakeContextProvider,
};
pub use tls::TlsConnector;

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

#[derive(Clone, PartialEq, Eq)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

impl fmt::Debug for RealityClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityClientConfig")
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("public_key", &self.public_key)
            .field("short_id", &"<redacted>")
            .field("spider_x", &self.spider_x)
            .finish()
    }
}

impl Drop for RealityClientConfig {
    fn drop(&mut self) {
        self.short_id.zeroize();
    }
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
    #[error("tls connect failed: {0}")]
    Tls(std::io::Error),
    #[error("tls configuration failed: {0}")]
    TlsConfig(String),
    #[error("invalid tls server name `{0}`")]
    InvalidTlsServerName(String),
    #[error("{0} connector config is not supported by TcpConnector")]
    UnsupportedConnectorConfig(&'static str),
    #[error("unsupported REALITY fingerprint {0}")]
    UnsupportedRealityFingerprint(String),
    #[error("reality handshake failed: {0}")]
    Reality(#[from] reality::RealityError),
    #[error("REALITY live TLS completion is not implemented")]
    RealityTlsCompletionUnsupported,
}

/// Resolves a domain and configured port into the concrete socket address to dial.
///
/// Callers pass the configured port and dial the returned `SocketAddr` as-is.
/// This keeps platform-specific DNS and deterministic test resolvers explicit.
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

pub trait TransportStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TransportStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedTransportStream = Box<dyn TransportStream>;

#[async_trait]
pub trait RealityTlsEngine: Send + Sync {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError>;
}

#[async_trait]
pub trait TransportConnector: Send + Sync {
    async fn connect(&self, target: &Target) -> Result<BoxedTransportStream, TransportError>;

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
    async fn connect(&self, target: &Target) -> Result<BoxedTransportStream, TransportError> {
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

        let stream = TcpStream::connect(addr)
            .await
            .map_err(TransportError::Tcp)?;
        Ok(Box::new(stream))
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
