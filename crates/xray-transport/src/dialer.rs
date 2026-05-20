use crate::{
    BoxedTransportStream, ConnectorConfig, TcpConnector, TlsConnector, TransportConnector,
    TransportError,
};
use xray_routing::Target;

#[derive(Debug, Clone)]
pub struct TransportDialer {
    tls: TlsConnector,
}

impl TransportDialer {
    pub fn system() -> Result<Self, TransportError> {
        Ok(Self {
            tls: TlsConnector::system()?,
        })
    }

    pub fn with_tls_connector(tls: TlsConnector) -> Self {
        Self { tls }
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
            ConnectorConfig::Reality(_) => {
                Err(TransportError::UnsupportedConnectorConfig("reality"))
            }
        }
    }
}
