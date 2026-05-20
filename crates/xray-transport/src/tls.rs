use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as TokioTlsConnector;
use xray_routing::{Target, TargetAddr};

use crate::{BoxedTransportStream, TlsClientConfig, TransportError};

#[derive(Debug, Clone)]
pub struct TlsConnector {
    client_config: Arc<rustls::ClientConfig>,
}

impl TlsConnector {
    pub fn system() -> Result<Self, TransportError> {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let client_config = rustls_client_config(root_store)?;

        Ok(Self::with_client_config(Arc::new(client_config)))
    }

    pub fn with_client_config(client_config: Arc<rustls::ClientConfig>) -> Self {
        Self { client_config }
    }

    pub async fn connect(
        &self,
        target: &Target,
        config: &TlsClientConfig,
    ) -> Result<BoxedTransportStream, TransportError> {
        let server_name = rustls::pki_types::ServerName::try_from(config.server_name.clone())
            .map_err(|_| TransportError::InvalidTlsServerName(config.server_name.clone()))?;

        let addr = match &target.addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
            TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
        };

        let stream = TcpStream::connect(addr)
            .await
            .map_err(TransportError::Tcp)?;
        let stream = TokioTlsConnector::from(Arc::clone(&self.client_config))
            .connect(server_name, stream)
            .await
            .map_err(TransportError::Tls)?;

        Ok(Box::new(stream))
    }
}

fn rustls_client_config(
    root_store: rustls::RootCertStore,
) -> Result<rustls::ClientConfig, TransportError> {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| TransportError::TlsConfig(error.to_string()))
        .map(|builder| {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        })
}
