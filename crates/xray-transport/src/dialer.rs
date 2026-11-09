use std::{fmt, io, net::SocketAddr, sync::Arc};

use tokio::io::AsyncWriteExt;

use crate::happy_eyeballs::{
    connect_tcp_dual_stack_with_peer, connect_tcp_happy_eyeballs_with_peer,
};
use crate::stream::{connect_httpupgrade, connect_websocket, TransportLayer};
use crate::utls_tls::TlsAlpnPolicy;
use crate::{
    canonicalize_socket_addr, connect_tcp_stream, connect_tcp_target, BoxedTransportStream,
    ConnectorConfig, HappyEyeballsConfig, RealityRuntimeEngine, RealityTlsEngine, RecordResolver,
    ResolvedTcpConnector, RouteProbe, RustlsRealityTlsSessionProvider, SocketOptions,
    SocketOptionsProtector, SocketOptionsReport, SocketProtector, SystemRecordResolver,
    SystemRouteProbe, TlsConnector, TransportError,
};
use xray_routing::{Target, TargetAddr};

#[derive(Clone)]
pub struct TransportDialer {
    tls: TlsConnector,
    reality: Option<Arc<dyn RealityTlsEngine>>,
    /// The protector every socket this dialer opens goes through: the
    /// platform's, wrapped with `socket_options` when there are some.
    socket_protector: Option<Arc<dyn SocketProtector>>,
    /// The platform's own protector, which socket options wrap.
    platform_protector: Option<Arc<dyn SocketProtector>>,
    socket_options: Option<Arc<SocketOptions>>,
    socket_options_report: Option<SocketOptionsReport>,
    resolved_tcp_connector: Option<Arc<dyn ResolvedTcpConnector>>,
    tcp_fragment: Option<Arc<crate::TcpFragmentConfig>>,
    /// What most dialers leave unset, behind one pointer: every open future
    /// holds dialers.
    replaced: Option<Arc<Replaced>>,
}

/// What [`TransportDialer::with_route_probe`],
/// [`TransportDialer::with_record_resolver`],
/// [`TransportDialer::with_tcp_header_custom`],
/// [`TransportDialer::with_tcp_sudoku`] and [`TransportDialer::with_tcp_xmc`]
/// set.
#[derive(Clone, Default)]
struct Replaced {
    route_probe: Option<Arc<dyn RouteProbe>>,
    record_resolver: Option<Arc<dyn RecordResolver>>,
    tcp_header_custom: Option<Arc<crate::header_custom::HeaderCustomTcpConfig>>,
    tcp_sudoku: Option<Arc<crate::sudoku::SudokuConfig>>,
    tcp_xmc: Option<Arc<crate::xmc::XmcConfig>>,
    realm_resolver: Option<Arc<dyn crate::DnsResolver>>,
}

#[derive(Clone)]
pub(crate) struct H3DialMaterial {
    pub(crate) server_name: String,
    pub(crate) tls_config: Arc<rustls::ClientConfig>,
    pub(crate) socket_protector: Option<Arc<dyn SocketProtector>>,
}

impl fmt::Debug for TransportDialer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportDialer")
            .field("tls", &self.tls)
            .field("reality_engine", &self.reality.is_some())
            .field("socket_protector", &self.socket_protector.is_some())
            .field("socket_options", &self.socket_options)
            .field(
                "resolved_tcp_connector",
                &self.resolved_tcp_connector.is_some(),
            )
            .field(
                "route_probe",
                &self
                    .replaced
                    .as_ref()
                    .and_then(|replaced| replaced.route_probe.as_ref()),
            )
            .field(
                "record_resolver",
                &self
                    .replaced
                    .as_ref()
                    .is_some_and(|replaced| replaced.record_resolver.is_some()),
            )
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
            socket_protector: socket_protector.clone(),
            platform_protector: socket_protector,
            socket_options: None,
            socket_options_report: None,
            resolved_tcp_connector: None,
            tcp_fragment: None,
            replaced: None,
        })
    }

    pub fn with_tls_connector(tls: TlsConnector) -> Self {
        let socket_protector = tls.socket_protector_arc();
        Self {
            tls,
            reality: None,
            socket_protector: socket_protector.clone(),
            platform_protector: socket_protector,
            socket_options: None,
            socket_options_report: None,
            resolved_tcp_connector: None,
            tcp_fragment: None,
            replaced: None,
        }
    }

    /// Answers the SRV and TXT lookups of `addressPortStrategy` in place of
    /// Go's resolver.
    pub fn with_record_resolver(mut self, resolver: Arc<dyn RecordResolver>) -> Self {
        Arc::make_mut(self.replaced.get_or_insert_with(Default::default)).record_resolver =
            Some(resolver);
        self
    }

    /// The resolver for `addressPortStrategy` lookups: the one set with
    /// [`Self::with_record_resolver`], else Go's behind the platform's
    /// protector.
    pub fn record_resolver(&self) -> Arc<dyn RecordResolver> {
        match self
            .replaced
            .as_ref()
            .and_then(|replaced| replaced.record_resolver.as_ref())
        {
            Some(resolver) => Arc::clone(resolver),
            None => Arc::new(SystemRecordResolver::new(self.platform_protector.clone())),
        }
    }

    /// Resolves the STUN servers' and rendezvous's names of a `realm`
    /// mask, as the outbound's server name is resolved.
    pub fn with_realm_resolver(mut self, resolver: Arc<dyn crate::DnsResolver>) -> Self {
        Arc::make_mut(self.replaced.get_or_insert_with(Default::default)).realm_resolver =
            Some(resolver);
        self
    }

    /// What a `realm` mask's introduction takes from this dialer: the
    /// resolver set with [`Self::with_realm_resolver`], else the platform's,
    /// and the platform's socket protection, which its connection to the
    /// rendezvous goes through.
    pub fn realm_env(&self) -> crate::realm::RealmEnv {
        crate::realm::RealmEnv {
            resolver: self
                .replaced
                .as_ref()
                .and_then(|replaced| replaced.realm_resolver.clone())
                .unwrap_or_else(|| Arc::new(crate::SystemDnsResolver)),
            tls: self.tls.clone(),
            protector: self.platform_protector.clone(),
        }
    }

    pub fn with_reality_engine(mut self, reality: Arc<dyn RealityTlsEngine>) -> Self {
        self.reality = Some(reality);
        self
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.platform_protector = Some(protector);
        self.rewrap_socket_protector()
    }

    /// Applies `options` to every socket this dialer opens, after the
    /// platform's protection and in place of any options set before.
    pub fn with_socket_options(mut self, options: Arc<SocketOptions>) -> Self {
        self.socket_options = Some(options);
        self.rewrap_socket_protector()
    }

    /// Receives each socket option that failed without failing its dial.
    pub fn with_socket_options_report(mut self, report: SocketOptionsReport) -> Self {
        self.socket_options_report = Some(report);
        self.rewrap_socket_protector()
    }

    /// The options set with [`Self::with_socket_options`].
    pub fn socket_options(&self) -> Option<&Arc<SocketOptions>> {
        self.socket_options.as_ref()
    }

    fn rewrap_socket_protector(mut self) -> Self {
        let protector = match &self.socket_options {
            Some(options) => Some(Arc::new(SocketOptionsProtector::new(
                self.platform_protector.clone(),
                Arc::clone(options),
                self.socket_options_report.clone(),
            )) as Arc<dyn SocketProtector>),
            None => self.platform_protector.clone(),
        };
        if let Some(protector) = &protector {
            self.tls = self.tls.with_socket_protector(Arc::clone(protector));
        }
        self.socket_protector = protector;
        self
    }

    pub fn with_resolved_tcp_connector(mut self, connector: Arc<dyn ResolvedTcpConnector>) -> Self {
        self.resolved_tcp_connector = Some(connector);
        self
    }

    pub fn with_tcp_fragment(mut self, config: Arc<crate::TcpFragmentConfig>) -> Self {
        self.tcp_fragment = Some(config);
        self
    }

    /// Runs this `header-custom` handshake on every TCP carrier as soon as it
    /// connects, before the fragment mask, TLS or REALITY.
    pub fn with_tcp_header_custom(
        mut self,
        config: Arc<crate::header_custom::HeaderCustomTcpConfig>,
    ) -> Self {
        Arc::make_mut(self.replaced.get_or_insert_with(Default::default)).tcp_header_custom =
            Some(config);
        self
    }

    fn tcp_header_custom(&self) -> Option<&crate::header_custom::HeaderCustomTcpConfig> {
        self.replaced
            .as_ref()
            .and_then(|replaced| replaced.tcp_header_custom.as_deref())
    }

    /// Wraps every TCP carrier in the `sudoku` mask as soon as it connects,
    /// outside the `header-custom` handshake, the fragment mask, TLS and
    /// REALITY.
    pub fn with_tcp_sudoku(mut self, config: Arc<crate::sudoku::SudokuConfig>) -> Self {
        Arc::make_mut(self.replaced.get_or_insert_with(Default::default)).tcp_sudoku = Some(config);
        self
    }

    fn tcp_sudoku(&self) -> Option<&crate::sudoku::SudokuConfig> {
        self.replaced
            .as_ref()
            .and_then(|replaced| replaced.tcp_sudoku.as_deref())
    }

    /// Logs every TCP carrier in through the `xmc` mask as soon as it
    /// connects, outside the `header-custom` handshake, the fragment mask,
    /// TLS and REALITY.
    pub fn with_tcp_xmc(mut self, config: Arc<crate::xmc::XmcConfig>) -> Self {
        Arc::make_mut(self.replaced.get_or_insert_with(Default::default)).tcp_xmc = Some(config);
        self
    }

    fn tcp_xmc(&self) -> Option<&crate::xmc::XmcConfig> {
        self.replaced
            .as_ref()
            .and_then(|replaced| replaced.tcp_xmc.as_deref())
    }

    /// Whether a mask that transforms every byte, `sudoku` or `xmc`, sits
    /// outermost on the wire.
    fn has_wire_mask(&self) -> bool {
        self.tcp_sudoku().is_some() || self.tcp_xmc().is_some()
    }

    /// A connected carrier, whose remote end is `remote`, in the mask the
    /// TCP mask list puts outside the `header-custom` handshake: `sudoku` or
    /// `xmc`, when one is set.
    async fn wire_carrier(
        &self,
        stream: BoxedTransportStream,
        remote: SocketAddr,
    ) -> Result<BoxedTransportStream, TransportError> {
        if let Some(config) = self.tcp_sudoku() {
            return Ok(Box::new(
                crate::sudoku::SudokuStream::new(stream, config).map_err(TransportError::Tcp)?,
            ));
        }
        if let Some(config) = self.tcp_xmc() {
            return Ok(Box::new(
                crate::xmc::connect(stream, config, remote)
                    .await
                    .map_err(TransportError::Tcp)?,
            ));
        }
        Ok(stream)
    }

    /// This dialer with its own sockets instead of the outbound that
    /// [`Self::with_resolved_tcp_connector`] carried TCP through.
    pub fn without_resolved_tcp_connector(mut self) -> Self {
        self.resolved_tcp_connector = None;
        self
    }

    pub fn socket_protector(&self) -> Option<&dyn SocketProtector> {
        self.socket_protector.as_deref()
    }

    /// Replaces the system's route probe, as a test or a platform that knows
    /// its routes better may.
    pub fn with_route_probe(mut self, probe: Arc<dyn RouteProbe>) -> Self {
        Arc::make_mut(self.replaced.get_or_insert_with(Default::default)).route_probe = Some(probe);
        self
    }

    /// The probe that reports which address families the system has a route
    /// for: the one set with [`Self::with_route_probe`], or a new
    /// [`SystemRouteProbe`] whose sockets this dialer protects. Keep the
    /// returned probe; its result is cached.
    pub fn route_probe(&self) -> Arc<dyn RouteProbe> {
        self.replaced
            .as_ref()
            .and_then(|replaced| replaced.route_probe.clone())
            .unwrap_or_else(|| {
                Arc::new(SystemRouteProbe::new(self.socket_protector.clone()))
                    as Arc<dyn RouteProbe>
            })
    }

    /// Whether TCP carriers go through another outbound (`dialerProxy`)
    /// instead of a direct socket.
    pub fn carries_tcp_through_outbound(&self) -> bool {
        self.resolved_tcp_connector.is_some()
    }

    /// The same trust policy and socket protector used by this dialer.
    pub fn tls_connector(&self) -> &TlsConnector {
        &self.tls
    }

    pub fn socket_protector_arc(&self) -> Option<Arc<dyn SocketProtector>> {
        self.socket_protector.clone()
    }

    /// The TLS material of an HTTP/3 dial, with Xray's ChromeParrot
    /// ClientHello when `chrome_parrot` is set.
    pub(crate) fn h3_dial_material(
        &self,
        config: &ConnectorConfig,
        chrome_parrot: bool,
    ) -> Result<H3DialMaterial, TransportError> {
        if self.tcp_fragment.is_some() {
            return Err(TransportError::UnsupportedConnectorConfig(
                "TCP fragmentation over QUIC",
            ));
        }
        if self.resolved_tcp_connector.is_some() {
            return Err(TransportError::UnsupportedChainedTransport("XHTTP HTTP/3"));
        }
        match config {
            ConnectorConfig::Tls(tls) => Ok(H3DialMaterial {
                server_name: tls.server_name.clone(),
                tls_config: self.tls.h3_client_config_for(tls, b"h3", chrome_parrot)?,
                socket_protector: self.socket_protector.clone(),
            }),
            ConnectorConfig::Tcp => Err(TransportError::UnsupportedHttp3Security("TCP")),
            ConnectorConfig::Reality(_) => Err(TransportError::UnsupportedHttp3Security("REALITY")),
        }
    }

    pub async fn connect(
        &self,
        config: &ConnectorConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        if self.tcp_fragment.is_some() {
            let address = match &target.addr {
                TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
                TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
            };
            return self
                .connect_resolved(config, target, &[address], None)
                .await;
        }
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
    /// gRPC and XHTTP are the arms that do not dial *first*. Their flows may
    /// share an HTTP connection, so whether this call needs a socket at all is
    /// a question only their pools can answer. Both receive this dialer and
    /// ask through `connect_resolved_with_alpn_policy` when they need one.
    pub async fn connect_stream(
        &self,
        config: &ConnectorConfig,
        transport: &TransportLayer,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        match transport {
            TransportLayer::Raw => {
                self.connect_resolved_with_alpn_policy(
                    config,
                    original_target,
                    candidates,
                    happy_eyeballs,
                    TlsAlpnPolicy::Raw,
                )
                .await
            }
            TransportLayer::WebSocket(websocket) => {
                connect_websocket(
                    self.connect_resolved_with_alpn_policy(
                        config,
                        original_target,
                        candidates,
                        happy_eyeballs,
                        TlsAlpnPolicy::Http1Upgrade,
                    )
                    .await?,
                    websocket,
                )
                .await
            }
            TransportLayer::HttpUpgrade(upgrade) => {
                connect_httpupgrade(
                    self.connect_resolved_with_alpn_policy(
                        config,
                        original_target,
                        candidates,
                        happy_eyeballs,
                        TlsAlpnPolicy::Http1Upgrade,
                    )
                    .await?,
                    upgrade,
                )
                .await
            }
            TransportLayer::Grpc(grpc) => {
                grpc.open_stream(self, config, original_target, candidates, happy_eyeballs)
                    .await
            }
            TransportLayer::Xhttp(xhttp) => xhttp
                .open_stream(self, config, original_target, candidates, happy_eyeballs)
                .await
                .map_err(|error| TransportError::Xhttp(error.to_string())),
            TransportLayer::Kcp(kcp) => {
                self.connect_kcp(config, kcp, original_target, candidates)
                    .await
            }
            TransportLayer::Xdrive(xdrive) => xdrive.open_stream().await,
        }
    }

    /// An mKCP stream to the first candidate, with TLS on it as Xray-core's
    /// `DialKCP` puts it: the TLS of the raw transport. REALITY never rides
    /// on mKCP, and a chain cannot carry its UDP.
    async fn connect_kcp(
        &self,
        config: &ConnectorConfig,
        kcp: &crate::kcp::KcpConfig,
        original_target: &Target,
        candidates: &[SocketAddr],
    ) -> Result<BoxedTransportStream, TransportError> {
        if self.resolved_tcp_connector.is_some() {
            return Err(TransportError::UnsupportedChainedTransport("mKCP"));
        }
        let prepared = match config {
            ConnectorConfig::Tcp => None,
            ConnectorConfig::Tls(tls) => Some(self.tls.prepare_stream(tls, TlsAlpnPolicy::Raw)?),
            ConnectorConfig::Reality(_) => {
                return Err(TransportError::UnsupportedConnectorConfig(
                    "reality over mKCP",
                ))
            }
        };
        if candidates.is_empty() {
            return Err(no_resolved_candidates_error(original_target));
        }
        let realm = kcp.realm.as_ref().map(|_| self.realm_env());
        let stream: BoxedTransportStream = Box::new(
            crate::kcp::connect(
                candidates,
                self.socket_protector.clone(),
                kcp,
                realm.as_ref(),
            )
            .await?,
        );
        match prepared {
            None => Ok(stream),
            Some(prepared) => {
                self.tls
                    .connect_prepared_penetrating_stream(stream, prepared)
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
        self.connect_resolved_with_alpn_policy(
            config,
            original_target,
            candidates,
            happy_eyeballs,
            TlsAlpnPolicy::Raw,
        )
        .await
    }

    /// Opens a direct raw TCP/TLS carrier and returns the actual TCP peer.
    ///
    /// Protocols such as SOCKS UDP need the winner of the candidate race when
    /// the server advertises an unspecified relay IP. A chained stream cannot
    /// supply that direct-peer guarantee and is rejected before dialing.
    pub async fn connect_raw_stream_with_peer(
        &self,
        config: &ConnectorConfig,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<(BoxedTransportStream, SocketAddr), TransportError> {
        if self.resolved_tcp_connector.is_some() {
            return Err(TransportError::UnsupportedChainedTransport(
                "UDP association",
            ));
        }
        // Validate TLS before opening the protected socket, as connect_stream does.
        let prepared = match config {
            ConnectorConfig::Tcp => None,
            ConnectorConfig::Tls(tls) => Some(self.tls.prepare_stream(tls, TlsAlpnPolicy::Raw)?),
            ConnectorConfig::Reality(_) => {
                return Err(TransportError::UnsupportedConnectorConfig(
                    "UDP association REALITY",
                ));
            }
        };
        let (tcp, peer) = self
            .connect_direct_tcp(original_target, candidates, happy_eyeballs)
            .await?;
        let stream = self.masked_direct_carrier(tcp, peer).await?;
        let stream = self.mask_tcp_carrier(stream);
        let stream = match prepared {
            Some(prepared) => {
                self.tls
                    .connect_prepared_penetrating_stream(stream, prepared)
                    .await?
            }
            None => stream,
        };
        Ok((stream, peer))
    }

    /// Opens a raw TCP carrier as [`Self::connect_resolved`] does with
    /// [`ConnectorConfig::Tcp`], first writing `preamble(peer)` on the bare
    /// carrier, beneath any fragment mask.
    ///
    /// `peer` is the direct TCP peer, or `None` when a resolved connector
    /// carries the stream through another outbound.
    pub async fn connect_tcp_with_preamble(
        &self,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
        preamble: impl FnOnce(Option<SocketAddr>) -> Vec<u8> + Send,
    ) -> Result<BoxedTransportStream, TransportError> {
        let (mut stream, peer): (BoxedTransportStream, _) = match &self.resolved_tcp_connector {
            Some(connector) => (
                connector
                    .connect_resolved(original_target, candidates, happy_eyeballs)
                    .await?,
                None,
            ),
            None => {
                let (tcp, peer) = self
                    .connect_direct_tcp(original_target, candidates, happy_eyeballs)
                    .await?;
                (Box::new(tcp), Some(peer))
            }
        };
        let preamble = preamble(peer);
        stream
            .write_all(&preamble)
            .await
            .map_err(TransportError::Tcp)?;
        stream.flush().await.map_err(TransportError::Tcp)?;
        Ok(self.mask_tcp_carrier(stream))
    }

    pub(crate) async fn connect_resolved_with_alpn_policy(
        &self,
        config: &ConnectorConfig,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
        alpn_policy: TlsAlpnPolicy,
    ) -> Result<BoxedTransportStream, TransportError> {
        match config {
            ConnectorConfig::Tcp => {
                self.connect_tcp_carrier(original_target, candidates, happy_eyeballs)
                    .await
            }
            ConnectorConfig::Tls(tls_config) => {
                // Validate the complete TLS shape before the proxy or the
                // platform socket performs any I/O.
                let prepared = self.tls.prepare_stream(tls_config, alpn_policy)?;
                let stream = self
                    .connect_tcp_carrier(original_target, candidates, happy_eyeballs)
                    .await?;
                match alpn_policy {
                    // The raw transport hands this TLS session to VLESS
                    // itself, so it is the session Vision unwraps into direct
                    // mode, as REALITY's is.
                    TlsAlpnPolicy::Raw => {
                        self.tls
                            .connect_prepared_penetrating_stream(stream, prepared)
                            .await
                    }
                    // HTTP framing sits between this session and VLESS, so
                    // Vision never reaches it: there Vision requires VLESS
                    // encryption, and Direct strips only that layer.
                    TlsAlpnPolicy::HttpClient
                    | TlsAlpnPolicy::Http1Upgrade
                    | TlsAlpnPolicy::Http2 => {
                        self.tls.connect_prepared_stream(stream, prepared).await
                    }
                }
            }
            ConnectorConfig::Reality(reality_config) => {
                if self.resolved_tcp_connector.is_some() {
                    return Err(TransportError::UnsupportedChainedTransport("REALITY"));
                }
                let Some(reality) = &self.reality else {
                    return Err(TransportError::UnsupportedConnectorConfig("reality"));
                };

                let first = candidates
                    .first()
                    .copied()
                    .ok_or_else(|| no_resolved_candidates_error(original_target))?;
                let race_config = happy_eyeballs
                    .filter(|config| !config.try_delay.is_zero() && candidates.len() >= 2);

                if let Some(fragment) = &self.tcp_fragment {
                    let prepared = reality
                        .prepare_preconnected(reality_config, original_target)?
                        .ok_or(TransportError::UnsupportedConnectorConfig(
                            "REALITY tlshello fragmentation",
                        ))?;
                    let (stream, peer) = self
                        .connect_candidates(candidates, first, race_config)
                        .await?;
                    if self.has_wire_mask() {
                        let stream = self.masked_direct_carrier(stream, peer).await?;
                        let stream = crate::fragment::FragmentStream::new(stream, fragment.clone());
                        return prepared.complete_over_stream(Box::new(stream)).await;
                    }
                    let mut stream = stream;
                    self.direct_header_custom_handshake(&mut stream, peer)
                        .await?;
                    return prepared.complete_fragmented(stream, fragment.clone()).await;
                }

                // The socket is this dialer's, so it carries this dialer's
                // protection and socket options.
                let Some(prepared) =
                    reality.prepare_preconnected(reality_config, original_target)?
                else {
                    // A legacy engine dials its own socket, which this
                    // dialer cannot run the handshake on or mask.
                    if self.tcp_header_custom().is_some() {
                        return Err(TransportError::UnsupportedConnectorConfig(
                            "REALITY header-custom",
                        ));
                    }
                    if self.tcp_sudoku().is_some() {
                        return Err(TransportError::UnsupportedConnectorConfig("REALITY sudoku"));
                    }
                    if self.tcp_xmc().is_some() {
                        return Err(TransportError::UnsupportedConnectorConfig("REALITY xmc"));
                    }
                    // Legacy engines remain usable. They may override
                    // `connect_socket_addr` to preserve scoped IPv6 metadata.
                    return reality
                        .connect_socket_addr(reality_config, original_target, first)
                        .await;
                };
                let (stream, peer) = self
                    .connect_candidates(candidates, first, race_config)
                    .await?;
                if self.has_wire_mask() {
                    let stream = self.masked_direct_carrier(stream, peer).await?;
                    return prepared.complete_over_stream(stream).await;
                }
                let mut stream = stream;
                self.direct_header_custom_handshake(&mut stream, peer)
                    .await?;

                prepared.complete(stream).await
            }
        }
    }

    async fn connect_tcp_carrier(
        &self,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let stream = self
            .connect_tcp_carrier_unmasked(original_target, candidates, happy_eyeballs)
            .await?;
        Ok(self.mask_tcp_carrier(stream))
    }

    fn mask_tcp_carrier(&self, stream: BoxedTransportStream) -> BoxedTransportStream {
        match &self.tcp_fragment {
            Some(config) => Box::new(crate::fragment::FragmentStream::new(stream, config.clone())),
            None => stream,
        }
    }

    async fn connect_tcp_carrier_unmasked(
        &self,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        if let Some(connector) = &self.resolved_tcp_connector {
            let stream = connector
                .connect_resolved(original_target, candidates, happy_eyeballs)
                .await?;
            // Xray's chained connection says 0.0.0.0:0 for both of its ends.
            let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
            let mut stream = self.wire_carrier(stream, unspecified).await?;
            self.header_custom_handshake(&mut stream, unspecified, unspecified)
                .await?;
            return Ok(stream);
        }

        let (stream, peer) = self
            .connect_direct_tcp(original_target, candidates, happy_eyeballs)
            .await?;
        self.masked_direct_carrier(stream, peer).await
    }

    /// A direct carrier in `sudoku` or `xmc`, then past the `header-custom`
    /// handshake, which reads the socket's own addresses.
    async fn masked_direct_carrier(
        &self,
        mut stream: tokio::net::TcpStream,
        peer: SocketAddr,
    ) -> Result<BoxedTransportStream, TransportError> {
        if !self.has_wire_mask() {
            self.direct_header_custom_handshake(&mut stream, peer)
                .await?;
            return Ok(Box::new(stream));
        }
        let local = stream.local_addr().map_err(TransportError::Tcp)?;
        let mut stream = self.wire_carrier(Box::new(stream), peer).await?;
        self.header_custom_handshake(&mut stream, local, peer)
            .await?;
        Ok(stream)
    }

    /// The `header-custom` handshake over a direct socket connected to `peer`.
    async fn direct_header_custom_handshake(
        &self,
        stream: &mut tokio::net::TcpStream,
        peer: SocketAddr,
    ) -> Result<(), TransportError> {
        if self.tcp_header_custom().is_none() {
            return Ok(());
        }
        let local = stream.local_addr().map_err(TransportError::Tcp)?;
        self.header_custom_handshake(stream, local, peer).await
    }

    async fn header_custom_handshake<S>(
        &self,
        stream: &mut S,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(), TransportError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    {
        let Some(config) = self.tcp_header_custom() else {
            return Ok(());
        };
        crate::header_custom::client_handshake(stream, config, Some(local), Some(remote))
            .await
            .map_err(TransportError::Tcp)
    }

    /// Connects a direct TCP socket and returns it with the address it
    /// connected to.
    async fn connect_direct_tcp(
        &self,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<(tokio::net::TcpStream, SocketAddr), TransportError> {
        let first = candidates
            .first()
            .copied()
            .ok_or_else(|| no_resolved_candidates_error(original_target))?;
        let race_config =
            happy_eyeballs.filter(|config| !config.try_delay.is_zero() && candidates.len() >= 2);
        self.connect_candidates(candidates, first, race_config)
            .await
    }

    /// Races configured `happyEyeballs`; otherwise dials like Go's
    /// `net.Dialer`, which Xray-core uses, so a dual-stack host whose first
    /// address is unreachable still connects through another.
    ///
    /// Returns the address the socket connected to, which Go's
    /// `Conn.RemoteAddr` reports even when Linux TCP Fast Open has deferred
    /// the handshake and the kernel has no peer to report yet.
    async fn connect_candidates(
        &self,
        candidates: &[SocketAddr],
        first: SocketAddr,
        race_config: Option<&HappyEyeballsConfig>,
    ) -> Result<(tokio::net::TcpStream, SocketAddr), TransportError> {
        let protector = self.socket_protector.as_deref();
        match race_config {
            Some(race) => connect_tcp_happy_eyeballs_with_peer(candidates, protector, race).await,
            None if candidates.len() >= 2 => {
                connect_tcp_dual_stack_with_peer(candidates, protector).await
            }
            None => {
                let peer = canonicalize_socket_addr(first);
                Ok((connect_tcp_stream(peer, protector).await?, peer))
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
