use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use xray_routing::Target;

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
}

#[async_trait]
impl RealityTlsEngine for RealityRuntimeEngine {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        _target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        let connector = RealityConnector::new(config.clone());
        if !connector.is_fingerprint_supported() {
            return Err(
                RealityError::UnsupportedRealityFingerprint(config.fingerprint.clone()).into(),
            );
        }

        let _ = &self.client_hello_provider;

        Err(TransportError::RealityTlsCompletionUnsupported)
    }
}
