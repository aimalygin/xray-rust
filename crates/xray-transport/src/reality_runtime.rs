use std::{
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use tokio::net::TcpStream;
use xray_routing::{Target, TargetAddr};

use crate::{
    reality::RealityError,
    reality_connector::{RealityClientHelloProvider, RealityConnector, RealityHandshakeContext},
    BoxedTransportStream, DnsResolver, RealityClientConfig, RealityTlsEngine, SystemDnsResolver,
    TransportError,
};

const REALITY_HANDSHAKE_VERSION: [u8; 3] = [1, 8, 0];

pub trait RealityHandshakeContextProvider: Send + Sync {
    fn context(&self) -> RealityHandshakeContext;
}

#[derive(Debug, Clone, Default)]
pub struct SystemRealityHandshakeContextProvider;

impl RealityHandshakeContextProvider for SystemRealityHandshakeContextProvider {
    fn context(&self) -> RealityHandshakeContext {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(u32::MAX as u64) as u32);

        RealityHandshakeContext {
            version: REALITY_HANDSHAKE_VERSION,
            unix_time,
        }
    }
}

#[derive(Clone)]
pub struct RealityRuntimeEngine {
    client_hello_provider: Arc<dyn RealityClientHelloProvider>,
    dns_resolver: Arc<dyn DnsResolver>,
    context_provider: Arc<dyn RealityHandshakeContextProvider>,
}

impl fmt::Debug for RealityRuntimeEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityRuntimeEngine")
            .field("client_hello_provider", &"<dyn RealityClientHelloProvider>")
            .field("dns_resolver", &"<dyn DnsResolver>")
            .field("context_provider", &"<dyn RealityHandshakeContextProvider>")
            .finish()
    }
}

impl RealityRuntimeEngine {
    pub fn new(client_hello_provider: Arc<dyn RealityClientHelloProvider>) -> Self {
        Self {
            client_hello_provider,
            dns_resolver: Arc::new(SystemDnsResolver),
            context_provider: Arc::new(SystemRealityHandshakeContextProvider),
        }
    }

    pub fn with_dns_resolver(mut self, dns_resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = dns_resolver;
        self
    }

    pub fn with_context_provider(
        mut self,
        context_provider: Arc<dyn RealityHandshakeContextProvider>,
    ) -> Self {
        self.context_provider = context_provider;
        self
    }

    async fn resolve_socket_addr(&self, target: &Target) -> Result<SocketAddr, TransportError> {
        match &target.addr {
            TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
            TargetAddr::Domain(domain) => self.dns_resolver.resolve(domain, target.port).await,
        }
    }
}

#[async_trait]
impl RealityTlsEngine for RealityRuntimeEngine {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        let connector = RealityConnector::new(config.clone());
        if !connector.is_fingerprint_supported() {
            return Err(
                RealityError::UnsupportedRealityFingerprint(config.fingerprint.clone()).into(),
            );
        }

        let context = self.context_provider.context();
        let _prepared =
            connector.prepare_handshake(self.client_hello_provider.as_ref(), context)?;
        let addr = self.resolve_socket_addr(target).await?;
        let _stream = TcpStream::connect(addr)
            .await
            .map_err(TransportError::Tcp)?;

        Err(TransportError::RealityTlsCompletionUnsupported)
    }
}
