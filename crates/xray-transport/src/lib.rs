use async_trait::async_trait;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io, sync::Arc};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use xray_routing::{Target, TargetAddr};
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

mod dialer;
mod penetrating_tls;
pub mod reality;
pub mod reality_connector;
pub mod reality_runtime;
mod reality_rustls;
mod tls;

pub use dialer::TransportDialer;
pub(crate) use penetrating_tls::{CapturedTcpStream, PenetratingTlsStream, ServerReadLog};
pub use reality_connector::{RealityTlsSession, RealityTlsSessionProvider};
pub use reality_runtime::{
    RealityHandshakeContextProvider, RealityRuntimeEngine, SystemRealityHandshakeContextProvider,
};
pub use reality_rustls::RustlsRealityTlsSessionProvider;
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
    pub allow_insecure: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
    pub mldsa65_verify: Option<Vec<u8>>,
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
            .field(
                "mldsa65_verify_len",
                &self.mldsa65_verify.as_ref().map(Vec::len),
            )
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
    #[error("socket protection failed: {0}")]
    SocketProtection(std::io::Error),
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

const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const DNS_CACHE_MAX_ENTRIES: usize = 256;

/// TTL cache over another resolver. Proxy clients open a new outbound
/// connection per session; resolving the (usually single) server domain on
/// every connect adds tens of milliseconds on mobile networks.
pub struct CachingDnsResolver {
    inner: Arc<dyn DnsResolver>,
    ttl: std::time::Duration,
    cache: std::sync::Mutex<
        std::collections::HashMap<(String, u16), (SocketAddr, std::time::Instant)>,
    >,
}

impl CachingDnsResolver {
    pub fn new(inner: Arc<dyn DnsResolver>) -> Self {
        Self::with_ttl(inner, DNS_CACHE_TTL)
    }

    pub fn with_ttl(inner: Arc<dyn DnsResolver>, ttl: std::time::Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl DnsResolver for CachingDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        let key = (domain.to_owned(), port);
        let now = std::time::Instant::now();
        {
            let cache = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some((addr, stored_at)) = cache.get(&key) {
                if now.duration_since(*stored_at) < self.ttl {
                    return Ok(*addr);
                }
            }
        }

        let addr = self.inner.resolve(domain, port).await?;

        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.retain(|_, (_, stored_at)| now.duration_since(*stored_at) < self.ttl);
        }
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.clear();
        }
        cache.insert(key, (addr, now));
        Ok(addr)
    }
}

pub trait TransportStream: AsyncRead + AsyncWrite + Send + Unpin {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

impl TransportStream for TcpStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

impl TransportStream for tokio::io::DuplexStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

impl TransportStream for tokio_rustls::client::TlsStream<TcpStream> {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

pub type BoxedTransportStream = Box<dyn TransportStream>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketHandle {
    raw: i64,
}

impl SocketHandle {
    pub fn raw(self) -> i64 {
        self.raw
    }

    #[cfg(unix)]
    fn from_tcp_socket(socket: &TcpSocket) -> Self {
        Self {
            raw: socket.as_raw_fd() as i64,
        }
    }

    #[cfg(unix)]
    fn from_udp_socket(socket: &UdpSocket) -> Self {
        Self {
            raw: socket.as_raw_fd() as i64,
        }
    }

    #[cfg(windows)]
    fn from_tcp_socket(socket: &TcpSocket) -> Self {
        Self {
            raw: socket.as_raw_socket() as i64,
        }
    }

    #[cfg(windows)]
    fn from_udp_socket(socket: &UdpSocket) -> Self {
        Self {
            raw: socket.as_raw_socket() as i64,
        }
    }
}

pub trait SocketProtector: Send + Sync {
    fn protect(&self, socket: SocketHandle) -> io::Result<()>;
}

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

pub struct TcpConnector {
    config: ConnectorConfig,
    socket_protector: Option<Arc<dyn SocketProtector>>,
}

impl fmt::Debug for TcpConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpConnector")
            .field("config", &self.config)
            .field("socket_protector", &self.socket_protector.is_some())
            .finish()
    }
}

impl Clone for TcpConnector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            socket_protector: self.socket_protector.clone(),
        }
    }
}

impl TcpConnector {
    pub fn new(config: ConnectorConfig) -> Self {
        Self {
            config,
            socket_protector: None,
        }
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.socket_protector = Some(protector);
        self
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

        let stream = connect_tcp_target(target, self.socket_protector.as_deref()).await?;
        Ok(Box::new(stream))
    }
}

pub async fn connect_tcp_target(
    target: &Target,
    socket_protector: Option<&dyn SocketProtector>,
) -> Result<TcpStream, TransportError> {
    let addr = match &target.addr {
        TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
        TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
    };

    connect_tcp_stream(addr, socket_protector).await
}

pub async fn connect_tcp_stream(
    addr: SocketAddr,
    socket_protector: Option<&dyn SocketProtector>,
) -> Result<TcpStream, TransportError> {
    let stream = match socket_protector {
        None => TcpStream::connect(addr)
            .await
            .map_err(TransportError::Tcp)?,
        Some(socket_protector) => {
            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .map_err(TransportError::Tcp)?;

            socket_protector
                .protect(SocketHandle::from_tcp_socket(&socket))
                .map_err(TransportError::SocketProtection)?;

            socket.connect(addr).await.map_err(TransportError::Tcp)?
        }
    };

    // The relay carries many latency-sensitive small frames (VLESS headers,
    // Vision blocks, TLS records); Nagle would delay them behind ACKs.
    stream.set_nodelay(true).map_err(TransportError::Tcp)?;
    Ok(stream)
}

pub fn protect_udp_socket(
    socket: &UdpSocket,
    socket_protector: Option<&dyn SocketProtector>,
) -> Result<(), TransportError> {
    if let Some(protector) = socket_protector {
        protector
            .protect(SocketHandle::from_udp_socket(socket))
            .map_err(TransportError::SocketProtection)?;
    }

    Ok(())
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
