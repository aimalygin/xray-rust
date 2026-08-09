use std::{fmt, io, net::SocketAddr, sync::Arc};

use crate::stream::{connect_httpupgrade, connect_websocket, TransportLayer};
use crate::{
    connect_tcp_happy_eyeballs, connect_tcp_stream, connect_tcp_target, BoxedTransportStream,
    ConnectorConfig, HappyEyeballsConfig, RealityRuntimeEngine, RealityTlsEngine,
    RustlsRealityTlsSessionProvider, SocketProtector, TlsConnector, TransportError,
};
use xray_routing::{Target, TargetAddr};

#[derive(Clone)]
pub struct TransportDialer {
    tls: TlsConnector,
    reality: Option<Arc<dyn RealityTlsEngine>>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
}

impl fmt::Debug for TransportDialer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportDialer")
            .field("tls", &self.tls)
            .field("reality_engine", &self.reality.is_some())
            .field("socket_protector", &self.socket_protector.is_some())
            .finish()
    }
}

impl TransportDialer {
    pub fn system() -> Result<Self, TransportError> {
        Self::system_with_socket_protector(None)
    }

    pub fn system_with_socket_protector(
        socket_protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<Self, TransportError> {
        let tls = match socket_protector.clone() {
            Some(protector) => TlsConnector::system()?.with_socket_protector(protector),
            None => TlsConnector::system()?,
        };
        let mut reality =
            RealityRuntimeEngine::new(Arc::new(RustlsRealityTlsSessionProvider::new()));
        if let Some(protector) = socket_protector.clone() {
            reality = reality.with_socket_protector(protector);
        }

        Ok(Self {
            tls,
            reality: Some(Arc::new(reality)),
            socket_protector,
        })
    }

    pub fn with_tls_connector(tls: TlsConnector) -> Self {
        Self {
            tls,
            reality: None,
            socket_protector: None,
        }
    }

    pub fn with_reality_engine(mut self, reality: Arc<dyn RealityTlsEngine>) -> Self {
        self.reality = Some(reality);
        self
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.tls = self.tls.with_socket_protector(Arc::clone(&protector));
        self.socket_protector = Some(protector);
        self
    }

    pub fn socket_protector(&self) -> Option<&dyn SocketProtector> {
        self.socket_protector.as_deref()
    }

    pub fn socket_protector_arc(&self) -> Option<Arc<dyn SocketProtector>> {
        self.socket_protector.clone()
    }

    pub async fn connect(
        &self,
        config: &ConnectorConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        match config {
            ConnectorConfig::Tcp => Ok(Box::new(
                connect_tcp_target(target, self.socket_protector.as_deref()).await?,
            )),
            ConnectorConfig::Tls(tls_config) => self.tls.connect(target, tls_config).await,
            ConnectorConfig::Reality(reality_config) => match &self.reality {
                Some(reality) => reality.connect(reality_config, target).await,
                None => Err(TransportError::UnsupportedConnectorConfig("reality")),
            },
        }
    }

    /// Dials through the security layer, then applies the stream transport.
    ///
    /// The candidate race and the REALITY preconnect stay entirely inside
    /// [`connect_resolved`](Self::connect_resolved), which is why every arm
    /// below reaches it rather than opening a socket of its own — a socket
    /// opened anywhere else misses Android's `VpnService.protect(fd)`.
    ///
    /// gRPC is the arm that does not dial *first*. Its flows share one HTTP/2
    /// connection, so whether this call needs a socket at all is a question
    /// only its pool can answer, and it is handed `connect_resolved` to ask
    /// with.
    pub async fn connect_stream(
        &self,
        config: &ConnectorConfig,
        transport: &TransportLayer,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let dial =
            move || self.connect_resolved(config, original_target, candidates, happy_eyeballs);

        match transport {
            TransportLayer::Raw => dial().await,
            TransportLayer::WebSocket(websocket) => {
                connect_websocket(dial().await?, websocket).await
            }
            TransportLayer::HttpUpgrade(upgrade) => {
                connect_httpupgrade(dial().await?, upgrade).await
            }
            TransportLayer::Grpc(grpc) => {
                grpc.open_stream(self, config, original_target, candidates, happy_eyeballs)
                    .await
            }
        }
    }

    /// Connects a transport to an already resolved list of TCP candidates.
    ///
    /// Happy Eyeballs is enabled only when the policy has a non-zero delay and
    /// at least two candidates, matching Xray's feature-off sentinels. Without
    /// it, the first candidate preserves the legacy deterministic behavior.
    pub async fn connect_resolved(
        &self,
        config: &ConnectorConfig,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let first = candidates
            .first()
            .copied()
            .ok_or_else(|| no_resolved_candidates_error(original_target))?;
        let race_config =
            happy_eyeballs.filter(|config| !config.try_delay.is_zero() && candidates.len() >= 2);

        match config {
            ConnectorConfig::Tcp => match race_config {
                Some(race_config) => Ok(Box::new(
                    connect_tcp_happy_eyeballs(
                        candidates,
                        self.socket_protector.as_deref(),
                        race_config,
                    )
                    .await?,
                )),
                None => Ok(Box::new(
                    connect_tcp_stream(first, self.socket_protector.as_deref()).await?,
                )),
            },
            ConnectorConfig::Tls(tls_config) => match race_config {
                Some(race_config) => {
                    self.tls
                        .connect_candidates(candidates, tls_config, race_config)
                        .await
                }
                None => self.tls.connect_socket_addr(first, tls_config).await,
            },
            ConnectorConfig::Reality(reality_config) => {
                let Some(reality) = &self.reality else {
                    return Err(TransportError::UnsupportedConnectorConfig("reality"));
                };

                let Some(race_config) = race_config else {
                    return reality
                        .connect_socket_addr(reality_config, original_target, first)
                        .await;
                };
                let Some(prepared) =
                    reality.prepare_preconnected(reality_config, original_target)?
                else {
                    // Legacy engines remain usable. They may override
                    // `connect_socket_addr` to preserve scoped IPv6 metadata.
                    return reality
                        .connect_socket_addr(reality_config, original_target, first)
                        .await;
                };
                let stream = connect_tcp_happy_eyeballs(
                    candidates,
                    self.socket_protector.as_deref(),
                    race_config,
                )
                .await?;

                prepared.complete(stream).await
            }
        }
    }
}

fn no_resolved_candidates_error(target: &Target) -> TransportError {
    match &target.addr {
        TargetAddr::Domain(domain) => {
            TransportError::NoResolvedAddress(domain.clone(), target.port)
        }
        TargetAddr::Ip(ip) => TransportError::Tcp(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no resolved TCP candidates for {ip}:{}", target.port),
        )),
    }
}
