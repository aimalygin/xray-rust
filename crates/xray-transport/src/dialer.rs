use std::{fmt, sync::Arc};

use crate::{
    BoxedTransportStream, ConnectorConfig, RealityRuntimeEngine, RealityTlsEngine,
    RustlsRealityTlsSessionProvider, TcpConnector, TlsConnector, TransportConnector,
    TransportError,
};
use xray_routing::Target;

#[derive(Clone)]
pub struct TransportDialer {
    tls: TlsConnector,
    reality: Option<Arc<dyn RealityTlsEngine>>,
}

impl fmt::Debug for TransportDialer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportDialer")
            .field("tls", &self.tls)
            .field("reality_engine", &self.reality.is_some())
            .finish()
    }
}

impl TransportDialer {
    pub fn system() -> Result<Self, TransportError> {
        Ok(Self {
            tls: TlsConnector::system()?,
            reality: Some(Arc::new(RealityRuntimeEngine::new(Arc::new(
                RustlsRealityTlsSessionProvider::new(),
            )))),
        })
    }

    pub fn with_tls_connector(tls: TlsConnector) -> Self {
        Self { tls, reality: None }
    }

    pub fn with_reality_engine(mut self, reality: Arc<dyn RealityTlsEngine>) -> Self {
        self.reality = Some(reality);
        self
    }

    pub async fn connect(
        &self,
        config: &ConnectorConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        match config {
            ConnectorConfig::Tcp => {
                TcpConnector::new(ConnectorConfig::Tcp)
                    .connect(target)
                    .await
            }
            ConnectorConfig::Tls(tls_config) => self.tls.connect(target, tls_config).await,
            ConnectorConfig::Reality(reality_config) => match &self.reality {
                Some(reality) => reality.connect(reality_config, target).await,
                None => Err(TransportError::UnsupportedConnectorConfig("reality")),
            },
        }
    }
}
