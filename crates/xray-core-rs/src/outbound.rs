use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_config::{
    CoreConfig, DnsOutboundSettings, Network, OutboundConfig, OutboundSettings, QuicParamsSettings,
    RoutingBalancerStrategy, RoutingConfig, RoutingDomainStrategy, RoutingLeastLoadSettings,
    RoutingRule, RoutingRuleTarget, StreamSecurity, StreamSettings, StreamTransport, TargetAddr,
    VlessUser, XhttpSettings,
};
use xray_proxy::vless::{
    encode_request_header, VisionStream, VisionStreamIo, VlessCommand, VlessRequest,
    VlessResponseStream, DEFAULT_VISION_SEED,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::stream::{
    resolve_user_agent, Authority, GrpcConfig, GrpcTransport, H3Congestion, H3QuicConfig,
    H3UdpHopConfig, HeaderMap, HeaderValue, HttpUpgradeConfig, TransportLayer, WebSocketConfig,
    XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpHttpVersion, XhttpMetadataPlacement,
    XhttpModeSelection, XhttpPaddingMethod, XhttpPaddingPlacement, XhttpRange, XhttpScheme,
    XhttpTransport, XhttpUplinkDataPlacement, XhttpXmuxPolicy,
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, DnsResolver, HappyEyeballsConfig, RealityClientConfig,
    ResolvedTcpConnector, SystemDnsResolver, TlsClientConfig, TransportDialer, TransportError,
    TransportStream,
};

use crate::policy::effective_policy_for_level;
use crate::{CompiledDnsOutboundPolicy, CoreError};

#[cfg(test)]
use xray_config::RoutingBalancer;

const VISION_FLOW: &str = "xtls-rprx-vision";
const VISION_UDP443_FLOW: &str = "xtls-rprx-vision-udp443";
const DNS_OUTBOUND_HARD_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const LEAST_LOAD_HEALTH_WINDOW: usize = 16;
const COST_MILLIONTHS_ONE: u64 = 1_000_000;
const LEAST_LOAD_RTT_BITS: u32 = 27;
const LEAST_LOAD_RTT_MAX: u64 = (1 << LEAST_LOAD_RTT_BITS) - 1;
static NEXT_DNS_OUTBOUND_RUNTIME_IDENTITY: AtomicU64 = AtomicU64::new(1);
static NEXT_OUTBOUND_GRAPH_RUNTIME_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisionFlow {
    None,
    Vision,
    VisionUdp443,
}

impl VisionFlow {
    fn uses_vision(self) -> bool {
        matches!(self, Self::Vision | Self::VisionUdp443)
    }

    fn allows_udp443(self) -> bool {
        matches!(self, Self::VisionUdp443)
    }

    fn request_flow(self) -> Option<String> {
        self.uses_vision().then(|| VISION_FLOW.to_owned())
    }
}

struct VlessOutboundStream {
    inner: VlessResponseStream<BoxedTransportStream>,
}

impl VlessOutboundStream {
    fn new(inner: VlessResponseStream<BoxedTransportStream>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for VlessOutboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for VlessOutboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl TransportStream for VlessOutboundStream {
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

struct VisionTransportStream {
    inner: BoxedTransportStream,
}

impl VisionTransportStream {
    fn new(inner: BoxedTransportStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for VisionTransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for VisionTransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl VisionStreamIo for VisionTransportStream {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read_direct(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown_direct(cx)
    }
}

struct VisionOutboundStream {
    inner: VisionStream<VlessResponseStream<VisionTransportStream>>,
}

impl VisionOutboundStream {
    fn new(inner: VisionStream<VlessResponseStream<VisionTransportStream>>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for VisionOutboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for VisionOutboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl TransportStream for VisionOutboundStream {
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

#[derive(Debug, Clone)]
pub struct VlessTcpOutbound {
    payload: Arc<VlessTcpOutboundPayload>,
}

#[derive(Debug)]
struct VlessTcpOutboundPayload {
    server: Target,
    user: VlessUser,
    transport: ConnectorConfig,
    /// The dial-ready framing layered over the security layer, with the host
    /// precedence already resolved. Only `Raw` admits Vision.
    transport_layer: TransportLayer,
    happy_eyeballs: Option<HappyEyeballsConfig>,
}

#[derive(Debug, Clone)]
pub struct DnsOutbound {
    payload: Arc<DnsOutboundPayload>,
}

#[derive(Debug)]
struct DnsOutboundPayload {
    runtime_identity: u64,
    settings: DnsOutboundSettings,
    policy: CompiledDnsOutboundPolicy,
    stream_network: Network,
    tcp_connector: DnsTcpConnector,
    happy_eyeballs: DnsHappyEyeballsMode,
    conn_idle_timeout: Duration,
    operation_timeout: Duration,
}

/// TCP connector selected from the DNS outbound's own `streamSettings`.
///
/// Xray derives an omitted TLS server name from the rewritten destination at
/// dial time, so that case cannot be represented by a static connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsTcpConnector {
    Static(ConnectorConfig),
    /// Only the server name waits for the rewritten destination, so the rest
    /// of the shape is carried here rather than rebuilt per dial.
    TlsFromTarget {
        allow_insecure: bool,
        pinned_peer_cert_sha256: Vec<[u8; 32]>,
        verify_peer_cert_by_name: Vec<String>,
        alpn: Vec<String>,
        fingerprint: Option<String>,
    },
}

/// Distinguishes an omitted Happy Eyeballs policy from Xray's explicit
/// feature-off sentinel. DNS supplies its mobile-friendly fallback only when
/// the setting is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsHappyEyeballsMode {
    DnsDefault,
    Disabled,
    Configured(HappyEyeballsConfig),
}

#[derive(Debug, Clone)]
pub enum TcpOutbound {
    Freedom,
    FreedomHappyEyeballs(HappyEyeballsConfig),
    Vless(Box<VlessTcpOutbound>),
    Chained {
        outbound: Box<TcpOutbound>,
        proxy: Box<TcpOutbound>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedTcpOutbound {
    pub(crate) outbound: TcpOutbound,
    pub(crate) tag: Option<String>,
}

#[derive(Debug, Clone)]
pub enum UdpOutbound {
    Freedom,
    Vless(Box<VlessTcpOutbound>),
}

/// One configured handler selected for a TCP session. DNS remains a message
/// handler rather than pretending to be a byte-stream transport.
#[derive(Debug, Clone)]
pub(crate) enum TcpSessionOutbound {
    Transport(TcpOutbound),
    Dns(DnsOutbound),
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedTcpSessionOutbound {
    pub(crate) outbound: TcpSessionOutbound,
    pub(crate) tag: Option<String>,
}

/// One configured handler selected for a UDP session. Keeping this combined
/// result avoids performing routing (and an IPIfNonMatch lookup) twice.
#[derive(Debug, Clone)]
pub(crate) enum UdpSessionOutbound {
    Transport(UdpOutbound),
    Dns(DnsOutbound),
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedUdpSessionOutbound {
    pub(crate) outbound: UdpSessionOutbound,
    pub(crate) tag: Option<String>,
}

impl DnsOutbound {
    #[cfg(test)]
    pub(crate) fn new(settings: DnsOutboundSettings) -> Self {
        Self::new_with_conn_idle(
            settings,
            crate::policy::EffectivePolicy::default().conn_idle,
        )
    }

    #[cfg(test)]
    fn new_with_conn_idle(settings: DnsOutboundSettings, conn_idle_timeout: Duration) -> Self {
        Self::new_with_transport(
            settings,
            Network::Tcp,
            DnsTcpConnector::Static(ConnectorConfig::Tcp),
            DnsHappyEyeballsMode::DnsDefault,
            conn_idle_timeout,
        )
    }

    fn new_with_stream(
        settings: DnsOutboundSettings,
        stream: &StreamSettings,
        conn_idle_timeout: Duration,
    ) -> Result<Self, CoreError> {
        if !stream_transport_is_dialable(stream) {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let tcp_connector = dns_tcp_connector(stream)?;
        let happy_eyeballs = dns_happy_eyeballs_mode(stream);
        Ok(Self::new_with_transport(
            settings,
            stream.network,
            tcp_connector,
            happy_eyeballs,
            conn_idle_timeout,
        ))
    }

    fn new_with_transport(
        settings: DnsOutboundSettings,
        stream_network: Network,
        tcp_connector: DnsTcpConnector,
        happy_eyeballs: DnsHappyEyeballsMode,
        conn_idle_timeout: Duration,
    ) -> Self {
        let policy = CompiledDnsOutboundPolicy::new(&settings);
        let operation_timeout = conn_idle_timeout.min(DNS_OUTBOUND_HARD_OPERATION_TIMEOUT);
        Self {
            payload: Arc::new(DnsOutboundPayload {
                runtime_identity: NEXT_DNS_OUTBOUND_RUNTIME_IDENTITY
                    .fetch_add(1, Ordering::Relaxed),
                settings,
                policy,
                stream_network,
                tcp_connector,
                happy_eyeballs,
                conn_idle_timeout,
                operation_timeout,
            }),
        }
    }

    pub fn settings(&self) -> &DnsOutboundSettings {
        &self.payload.settings
    }

    pub fn policy(&self) -> &CompiledDnsOutboundPolicy {
        &self.payload.policy
    }

    pub(crate) fn conn_idle_timeout(&self) -> Duration {
        self.payload.conn_idle_timeout
    }

    pub(crate) fn operation_timeout(&self) -> Duration {
        self.payload.operation_timeout
    }

    pub(crate) fn tcp_connector_for(&self, target: &Target) -> Result<ConnectorConfig, CoreError> {
        if self.payload.stream_network != Network::Tcp {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        match &self.payload.tcp_connector {
            DnsTcpConnector::Static(connector) => Ok(connector.clone()),
            DnsTcpConnector::TlsFromTarget {
                allow_insecure,
                pinned_peer_cert_sha256,
                verify_peer_cert_by_name,
                alpn,
                fingerprint,
            } => {
                let server_name = match &target.addr {
                    RoutingTargetAddr::Domain(domain) if !domain.is_empty() => domain.clone(),
                    RoutingTargetAddr::Domain(_) => {
                        return Err(CoreError::UnsupportedOutboundSecurity);
                    }
                    RoutingTargetAddr::Ip(ip) => ip.to_string(),
                };
                Ok(ConnectorConfig::Tls(TlsClientConfig {
                    server_name,
                    allow_insecure: *allow_insecure,
                    pinned_peer_cert_sha256: pinned_peer_cert_sha256.clone(),
                    verify_peer_cert_by_name: verify_peer_cert_by_name.clone(),
                    alpn: alpn.clone(),
                    fingerprint: fingerprint.clone(),
                }))
            }
        }
    }

    pub(crate) fn happy_eyeballs_mode(&self) -> DnsHappyEyeballsMode {
        self.payload.happy_eyeballs
    }

    pub(crate) fn supports_direct_udp(&self) -> bool {
        matches!(
            self.payload.tcp_connector,
            DnsTcpConnector::Static(ConnectorConfig::Tcp)
        )
    }

    /// Stable identity of one compiled DNS outbound for runtime resource
    /// partitioning. Clones share it; separately compiled handlers never do,
    /// even when their public settings happen to compare equal.
    pub(crate) fn runtime_identity(&self) -> u64 {
        self.payload.runtime_identity
    }

    /// Applies Xray's component-wise DNS rewrite while retaining the original
    /// destination for every omitted field.
    pub fn rewrite_target(&self, original: &Target) -> Target {
        let settings = self.settings();
        let addr = settings.rewrite_address.as_ref().map_or_else(
            || original.addr.clone(),
            |address| match address {
                TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
                TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
            },
        );
        let port = if settings.rewrite_port == 0 {
            original.port
        } else {
            settings.rewrite_port
        };
        let network = match settings.rewrite_network {
            None => original.network,
            Some(Network::Tcp) => RoutingNetwork::Tcp,
            Some(Network::Udp) => RoutingNetwork::Udp,
        };
        Target::new(addr, port, network)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessUdpFraming {
    LengthPrefixed,
    Xudp,
}

impl VlessTcpOutbound {
    pub fn server(&self) -> &Target {
        &self.payload.server
    }

    pub fn transport(&self) -> &ConnectorConfig {
        &self.payload.transport
    }

    pub fn transport_layer(&self) -> &TransportLayer {
        &self.payload.transport_layer
    }

    pub fn user(&self) -> &VlessUser {
        &self.payload.user
    }

    pub(crate) fn happy_eyeballs(&self) -> Option<&HappyEyeballsConfig> {
        self.payload.happy_eyeballs.as_ref()
    }

    /// True for the regular `xtls-rprx-vision` flow, which (matching upstream
    /// xray-core) cannot carry UDP/443 and must refuse it so QUIC apps fall back
    /// to TCP. The `xtls-rprx-vision-udp443` variant returns false.
    pub(crate) fn blocks_udp443(&self) -> bool {
        validate_connector_flow(
            self.user().flow.as_deref(),
            self.transport(),
            self.transport_layer(),
        )
        .map(|flow| flow.uses_vision() && !flow.allows_udp443())
        .unwrap_or(false)
    }
}

impl TcpOutbound {
    pub(crate) fn primary(&self) -> &Self {
        match self {
            Self::Chained { outbound, .. } => outbound.primary(),
            outbound => outbound,
        }
    }

    pub(crate) fn freedom_happy_eyeballs(&self) -> Option<&HappyEyeballsConfig> {
        match self.primary() {
            Self::Freedom => None,
            Self::FreedomHappyEyeballs(config) => Some(config),
            Self::Vless(_) => None,
            Self::Chained { .. } => unreachable!("primary outbound is never a chain wrapper"),
        }
    }
}

#[derive(Clone)]
struct OutboundProxyTcpConnector {
    outbound: TcpOutbound,
    server_candidates: Box<[SocketAddr]>,
    transport_dialer: TransportDialer,
}

#[async_trait]
impl ResolvedTcpConnector for OutboundProxyTcpConnector {
    async fn connect_resolved(
        &self,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        match self.outbound.primary() {
            TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => {
                self.transport_dialer
                    .connect_resolved(
                        &ConnectorConfig::Tcp,
                        original_target,
                        candidates,
                        self.outbound.freedom_happy_eyeballs().or(happy_eyeballs),
                    )
                    .await
            }
            TcpOutbound::Vless(outbound) => open_vless_tcp_stream_with_resolved_server_and_dialer(
                outbound,
                original_target,
                &self.server_candidates,
                &self.transport_dialer,
            )
            .await
            .map_err(|error| TransportError::ChainedOutbound(error.to_string())),
            TcpOutbound::Chained { .. } => {
                unreachable!("primary outbound is never a chain wrapper")
            }
        }
    }
}

fn prepare_outbound_proxy_dialer<'a>(
    proxy: &'a TcpOutbound,
    dns_resolver: &'a dyn DnsResolver,
    transport_dialer: &'a TransportDialer,
) -> Pin<Box<dyn Future<Output = Result<TransportDialer, CoreError>> + Send + 'a>> {
    Box::pin(async move {
        let (outbound, nested_proxy) = match proxy {
            TcpOutbound::Chained { outbound, proxy } => (outbound.as_ref(), Some(proxy.as_ref())),
            outbound => (outbound, None),
        };
        let transport_dialer = match nested_proxy {
            Some(proxy) => {
                prepare_outbound_proxy_dialer(proxy, dns_resolver, transport_dialer).await?
            }
            None => transport_dialer.clone(),
        };
        let requires_local_resolution = nested_proxy
            .map(proxy_chain_requires_local_resolution)
            .unwrap_or(true);
        let server_candidates = match outbound.primary() {
            TcpOutbound::Vless(vless) if requires_local_resolution => {
                resolve_server_candidates(vless.server(), dns_resolver)
                    .await?
                    .into_boxed_slice()
            }
            TcpOutbound::Vless(_) => Box::default(),
            TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => Box::default(),
            TcpOutbound::Chained { .. } => {
                unreachable!("a compiled chain wrapper has one plain primary outbound")
            }
        };
        let connector_dialer = transport_dialer.clone();
        Ok(
            transport_dialer.with_resolved_tcp_connector(Arc::new(OutboundProxyTcpConnector {
                outbound: outbound.clone(),
                server_candidates,
                transport_dialer: connector_dialer,
            })),
        )
    })
}

fn proxy_chain_requires_local_resolution(proxy: &TcpOutbound) -> bool {
    match proxy.primary() {
        TcpOutbound::Vless(_) => false,
        TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => match proxy {
            TcpOutbound::Chained { proxy, .. } => proxy_chain_requires_local_resolution(proxy),
            _ => true,
        },
        TcpOutbound::Chained { .. } => unreachable!("primary outbound is never a chain wrapper"),
    }
}

/// Every build failure the router is allowed to memoize.
///
/// **Not `Copy` since the gRPC config errors joined it**, which is the price of
/// an error that names the value it rejected. `from_core_error` panics on
/// anything absent from this list, so a new `CoreError` returned by a builder
/// has to be added here too or the cached path turns a config error into a
/// crash.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CachedOutboundError {
    NoSupportedOutbound,
    UnsupportedOutboundNetwork,
    UnsupportedOutboundSecurity,
    UnsupportedOutboundServerAddress,
    UnsupportedOutboundFlow,
    InvalidGrpcAuthority(String),
    UnrepresentableGrpcAuthority { key: &'static str, value: String },
    InvalidGrpcUserAgent(String),
    InvalidXhttpConfiguration(String),
    UnsupportedOutboundProxyNetwork(&'static str),
}

impl CachedOutboundError {
    fn from_core_error(error: CoreError) -> Self {
        match error {
            CoreError::NoSupportedOutbound => Self::NoSupportedOutbound,
            CoreError::UnsupportedOutboundNetwork => Self::UnsupportedOutboundNetwork,
            CoreError::UnsupportedOutboundSecurity => Self::UnsupportedOutboundSecurity,
            CoreError::UnsupportedOutboundServerAddress => Self::UnsupportedOutboundServerAddress,
            CoreError::UnsupportedOutboundFlow => Self::UnsupportedOutboundFlow,
            CoreError::InvalidGrpcAuthority(authority) => Self::InvalidGrpcAuthority(authority),
            CoreError::UnrepresentableGrpcAuthority { key, value } => {
                Self::UnrepresentableGrpcAuthority { key, value }
            }
            CoreError::InvalidGrpcUserAgent(user_agent) => Self::InvalidGrpcUserAgent(user_agent),
            CoreError::InvalidXhttpConfiguration(message) => {
                Self::InvalidXhttpConfiguration(message)
            }
            CoreError::UnsupportedOutboundProxyNetwork(network) => {
                Self::UnsupportedOutboundProxyNetwork(network)
            }
            other => unreachable!("outbound compilation returned non-cacheable error: {other}"),
        }
    }

    fn into_core_error(self) -> CoreError {
        match self {
            Self::NoSupportedOutbound => CoreError::NoSupportedOutbound,
            Self::UnsupportedOutboundNetwork => CoreError::UnsupportedOutboundNetwork,
            Self::UnsupportedOutboundSecurity => CoreError::UnsupportedOutboundSecurity,
            Self::UnsupportedOutboundServerAddress => CoreError::UnsupportedOutboundServerAddress,
            Self::UnsupportedOutboundFlow => CoreError::UnsupportedOutboundFlow,
            Self::InvalidGrpcAuthority(authority) => CoreError::InvalidGrpcAuthority(authority),
            Self::UnrepresentableGrpcAuthority { key, value } => {
                CoreError::UnrepresentableGrpcAuthority { key, value }
            }
            Self::InvalidGrpcUserAgent(user_agent) => CoreError::InvalidGrpcUserAgent(user_agent),
            Self::InvalidXhttpConfiguration(message) => {
                CoreError::InvalidXhttpConfiguration(message)
            }
            Self::UnsupportedOutboundProxyNetwork(network) => {
                CoreError::UnsupportedOutboundProxyNetwork(network)
            }
        }
    }
}

#[derive(Debug, Default)]
struct CachedOutboundEntry {
    tcp: OnceLock<Result<TcpOutbound, CachedOutboundError>>,
    udp: OnceLock<Result<UdpOutbound, CachedOutboundError>>,
    dns: OnceLock<Result<DnsOutbound, CachedOutboundError>>,
    vless: OnceLock<Result<VlessTcpOutbound, CachedOutboundError>>,
}

/// Opaque identity of one configured node in one immutable outbound graph.
///
/// The graph identity prevents a node selected from one core configuration
/// from being compiled accidentally by another core's factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboundNodeId {
    graph_identity: u64,
    index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundNodeKind {
    Freedom,
    Vless,
    Dns,
    Selector,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutboundProxyGraphError {
    #[error("outbound {outbound:?} proxy target {target:?} was not found")]
    TargetNotFound { outbound: String, target: String },
    #[error("outbound {outbound:?} proxySettings.transportLayer must be true")]
    TransportLayerRequired { outbound: String },
    #[error("outbound proxy cycle detected: {path:?}")]
    Cycle { path: Vec<String> },
    #[error("outbound {outbound:?} cannot participate in a proxy chain: {reason}")]
    UnsupportedNode {
        outbound: String,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundNode {
    id: OutboundNodeId,
    tag: Option<String>,
    kind: OutboundNodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSelectorGroup {
    node: OutboundNodeId,
    tag: String,
    members: Box<[OutboundNodeId]>,
    strategy: RoutingBalancerStrategy,
    least_load_costs: Box<[u64]>,
    fallback_tag: Option<String>,
}

impl OutboundSelectorGroup {
    pub fn node(&self) -> OutboundNodeId {
        self.node
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn members(&self) -> &[OutboundNodeId] {
        &self.members
    }

    pub fn strategy(&self) -> &RoutingBalancerStrategy {
        &self.strategy
    }

    pub fn fallback_tag(&self) -> Option<&str> {
        self.fallback_tag.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSelectorGroupSnapshot {
    pub tag: String,
    pub candidates: Vec<String>,
    pub override_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSelectionSnapshot {
    pub revision: u64,
    pub groups: Vec<OutboundSelectorGroupSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundHealthState {
    Unknown,
    Healthy,
    Unhealthy,
}

impl OutboundHealthState {
    const UNKNOWN: u8 = 0;
    const HEALTHY: u8 = 1;
    const UNHEALTHY: u8 = 2;

    fn from_u8(value: u8) -> Self {
        match value {
            Self::HEALTHY => Self::Healthy,
            Self::UNHEALTHY => Self::Unhealthy,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundHealthFailure {
    Timeout,
    Transport,
    Tls,
    Io,
    MalformedHttpResponse,
    HttpStatus(u16),
}

impl OutboundHealthFailure {
    const NONE: usize = 0;
    const TIMEOUT: usize = 1;
    const TRANSPORT: usize = 2;
    const TLS: usize = 3;
    const IO: usize = 4;
    const MALFORMED_HTTP_RESPONSE: usize = 5;
    const HTTP_STATUS_BASE: usize = 1 << 16;

    fn encode(self) -> usize {
        match self {
            Self::Timeout => Self::TIMEOUT,
            Self::Transport => Self::TRANSPORT,
            Self::Tls => Self::TLS,
            Self::Io => Self::IO,
            Self::MalformedHttpResponse => Self::MALFORMED_HTTP_RESPONSE,
            Self::HttpStatus(status) => Self::HTTP_STATUS_BASE + usize::from(status),
        }
    }

    fn decode(value: usize) -> Option<Self> {
        match value {
            Self::NONE => None,
            Self::TIMEOUT => Some(Self::Timeout),
            Self::TRANSPORT => Some(Self::Transport),
            Self::TLS => Some(Self::Tls),
            Self::IO => Some(Self::Io),
            Self::MALFORMED_HTTP_RESPONSE => Some(Self::MalformedHttpResponse),
            value if value >= Self::HTTP_STATUS_BASE => {
                u16::try_from(value - Self::HTTP_STATUS_BASE)
                    .ok()
                    .map(Self::HttpStatus)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHealthStatusSnapshot {
    pub outbound_tag: String,
    pub state: OutboundHealthState,
    pub delay_ms: Option<u64>,
    pub last_try_unix_ms: Option<u64>,
    pub last_seen_unix_ms: Option<u64>,
    pub consecutive_failures: u64,
    pub last_failure: Option<OutboundHealthFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHealthSnapshot {
    pub revision: u64,
    pub outbounds: Vec<OutboundHealthStatusSnapshot>,
}

impl OutboundNode {
    pub fn id(&self) -> OutboundNodeId {
        self.id
    }

    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    pub fn kind(&self) -> OutboundNodeKind {
        self.kind
    }
}

/// Immutable topology and tag index for one core configuration.
///
/// Protocol handlers are deliberately absent from this type. They are owned
/// by [`OutboundFactory`], so future selector/group nodes can refer to stable
/// graph nodes without duplicating connection pools or protocol state.
#[derive(Debug)]
pub struct OutboundGraph {
    identity: u64,
    config: Arc<CoreConfig>,
    nodes: Box<[OutboundNode]>,
    leaf_count: usize,
    first_tag_node: HashMap<String, OutboundNodeId>,
    proxy_targets: Box<[Option<OutboundNodeId>]>,
    proxy_validation_error: Option<OutboundProxyGraphError>,
    selector_groups: Box<[OutboundSelectorGroup]>,
    first_group_node: HashMap<String, OutboundNodeId>,
    default_node: Option<OutboundNodeId>,
    unresolved_default_tag: bool,
}

impl OutboundGraph {
    pub fn new(config: Arc<CoreConfig>) -> Self {
        let identity = NEXT_OUTBOUND_GRAPH_RUNTIME_IDENTITY.fetch_add(1, Ordering::Relaxed);
        let mut nodes = config
            .outbounds
            .iter()
            .enumerate()
            .map(|(index, outbound)| OutboundNode {
                id: OutboundNodeId {
                    graph_identity: identity,
                    index,
                },
                tag: outbound.tag.clone(),
                kind: match outbound.settings {
                    OutboundSettings::Freedom => OutboundNodeKind::Freedom,
                    OutboundSettings::Vless(_) => OutboundNodeKind::Vless,
                    OutboundSettings::Dns(_) => OutboundNodeKind::Dns,
                },
            })
            .collect::<Vec<_>>();
        let leaf_count = nodes.len();
        let mut first_tag_node = HashMap::with_capacity(nodes.len());
        for node in &nodes {
            if let Some(tag) = node.tag.as_ref() {
                first_tag_node.entry(tag.clone()).or_insert(node.id);
            }
        }
        let (proxy_targets, proxy_validation_error) =
            build_outbound_proxy_edges(&config.outbounds, &nodes, &first_tag_node);
        let default_node = config
            .default_outbound_tag
            .as_deref()
            .and_then(|tag| first_tag_node.get(tag).copied())
            .or_else(|| {
                if config.default_outbound_tag.is_none() {
                    nodes.first().map(OutboundNode::id)
                } else {
                    None
                }
            });
        let unresolved_default_tag =
            config.default_outbound_tag.is_some() && default_node.is_none();

        let mut selector_groups = Vec::with_capacity(config.routing.balancers.len());
        let mut first_group_node = HashMap::with_capacity(config.routing.balancers.len());
        for balancer in &config.routing.balancers {
            let mut selected_tags = first_tag_node
                .iter()
                .filter(|(tag, _)| {
                    balancer
                        .selectors
                        .iter()
                        .any(|selector| tag.starts_with(selector))
                })
                .map(|(tag, node)| (tag.as_str(), *node))
                .collect::<Vec<_>>();
            selected_tags.sort_unstable_by(|left, right| left.0.cmp(right.0));
            let least_load_costs = match &balancer.strategy {
                RoutingBalancerStrategy::LeastLoad(settings) => selected_tags
                    .iter()
                    .map(|(tag, _)| least_load_cost_millionths(settings, tag))
                    .collect::<Vec<_>>(),
                _ => vec![COST_MILLIONTHS_ONE; selected_tags.len()],
            };
            let group_node = OutboundNodeId {
                graph_identity: identity,
                index: nodes.len(),
            };
            nodes.push(OutboundNode {
                id: group_node,
                tag: Some(balancer.tag.clone()),
                kind: OutboundNodeKind::Selector,
            });
            first_group_node
                .entry(balancer.tag.clone())
                .or_insert(group_node);
            selector_groups.push(OutboundSelectorGroup {
                node: group_node,
                tag: balancer.tag.clone(),
                members: selected_tags
                    .into_iter()
                    .map(|(_, node)| node)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                strategy: balancer.strategy.clone(),
                least_load_costs: least_load_costs.into_boxed_slice(),
                fallback_tag: balancer.fallback_tag.clone(),
            });
        }

        Self {
            identity,
            config,
            nodes: nodes.into_boxed_slice(),
            leaf_count,
            first_tag_node,
            proxy_targets,
            proxy_validation_error,
            selector_groups: selector_groups.into_boxed_slice(),
            first_group_node,
            default_node,
            unresolved_default_tag,
        }
    }

    pub fn nodes(&self) -> &[OutboundNode] {
        &self.nodes
    }

    pub fn node(&self, id: OutboundNodeId) -> Option<&OutboundNode> {
        (id.graph_identity == self.identity)
            .then(|| self.nodes.get(id.index))
            .flatten()
    }

    pub fn node_for_tag(&self, tag: &str) -> Option<OutboundNodeId> {
        self.first_tag_node.get(tag).copied()
    }

    pub fn selector_groups(&self) -> &[OutboundSelectorGroup] {
        &self.selector_groups
    }

    pub fn selector_group(&self, id: OutboundNodeId) -> Option<&OutboundSelectorGroup> {
        if id.graph_identity != self.identity || id.index < self.leaf_count {
            return None;
        }
        self.selector_groups.get(id.index - self.leaf_count)
    }

    pub fn selector_group_for_tag(&self, tag: &str) -> Option<&OutboundSelectorGroup> {
        self.first_group_node
            .get(tag)
            .and_then(|id| self.selector_group(*id))
    }

    pub fn leaf_nodes_matching_prefixes(&self, prefixes: &[String]) -> Vec<OutboundNodeId> {
        let mut nodes = self
            .first_tag_node
            .iter()
            .filter(|(tag, _)| prefixes.iter().any(|prefix| tag.starts_with(prefix)))
            .map(|(tag, node)| (tag.as_str(), *node))
            .collect::<Vec<_>>();
        nodes.sort_unstable_by(|left, right| left.0.cmp(right.0));
        nodes.into_iter().map(|(_, node)| node).collect()
    }

    pub fn default_node(&self) -> Option<OutboundNodeId> {
        self.default_node
    }

    pub fn has_unresolved_default_tag(&self) -> bool {
        self.unresolved_default_tag
    }

    pub fn validate_proxy_chains(&self) -> Result<(), OutboundProxyGraphError> {
        match &self.proxy_validation_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    pub fn proxy_target(&self, id: OutboundNodeId) -> Option<OutboundNodeId> {
        if id.graph_identity != self.identity || id.index >= self.leaf_count {
            return None;
        }
        self.proxy_targets.get(id.index).copied().flatten()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn config(&self) -> &CoreConfig {
        self.config.as_ref()
    }

    fn configured_outbound(&self, id: OutboundNodeId) -> Option<&OutboundConfig> {
        if id.graph_identity != self.identity || id.index >= self.leaf_count {
            return None;
        }
        self.config.outbounds.get(id.index)
    }
}

fn build_outbound_proxy_edges(
    outbounds: &[OutboundConfig],
    nodes: &[OutboundNode],
    first_tag_node: &HashMap<String, OutboundNodeId>,
) -> (
    Box<[Option<OutboundNodeId>]>,
    Option<OutboundProxyGraphError>,
) {
    let mut targets = vec![None; outbounds.len()];
    for (index, outbound) in outbounds.iter().enumerate() {
        let Some(proxy) = &outbound.proxy_settings else {
            continue;
        };
        let outbound_label = outbound_node_label(nodes, index);
        if !proxy.transport_layer {
            return (
                targets.into_boxed_slice(),
                Some(OutboundProxyGraphError::TransportLayerRequired {
                    outbound: outbound_label,
                }),
            );
        }
        let Some(target) = first_tag_node.get(&proxy.tag).copied() else {
            return (
                targets.into_boxed_slice(),
                Some(OutboundProxyGraphError::TargetNotFound {
                    outbound: outbound_label,
                    target: proxy.tag.clone(),
                }),
            );
        };
        targets[index] = Some(target);
    }

    let mut chained_nodes = vec![false; outbounds.len()];
    for (index, target) in targets.iter().enumerate() {
        if let Some(target) = target {
            chained_nodes[index] = true;
            chained_nodes[target.index] = true;
        }
    }
    for (index, outbound) in outbounds.iter().enumerate() {
        if !chained_nodes[index] {
            continue;
        }
        let reason = match (&outbound.settings, &outbound.stream) {
            (OutboundSettings::Dns(_), _) => Some("DNS outbounds are not TCP carriers"),
            (
                _,
                StreamSettings {
                    security: StreamSecurity::Reality(_),
                    ..
                },
            ) => Some("REALITY over a preconnected stream is unsupported"),
            (
                _,
                StreamSettings {
                    transport: StreamTransport::Xhttp(_),
                    security: StreamSecurity::Tls(tls),
                    ..
                },
            ) if matches!(tls.alpn.as_slice(), [only] if only == "h3") => {
                Some("XHTTP HTTP/3 uses QUIC rather than a TCP carrier")
            }
            _ => None,
        };
        if let Some(reason) = reason {
            return (
                targets.into_boxed_slice(),
                Some(OutboundProxyGraphError::UnsupportedNode {
                    outbound: outbound_node_label(nodes, index),
                    reason,
                }),
            );
        }
    }

    let mut state = vec![0_u8; outbounds.len()];
    for start in 0..outbounds.len() {
        if state[start] != 0 {
            continue;
        }
        let mut path = Vec::new();
        let mut current = start;
        loop {
            match state[current] {
                2 => break,
                1 => {
                    let cycle_start = path
                        .iter()
                        .position(|candidate| *candidate == current)
                        .expect("a visiting proxy node belongs to the current path");
                    let mut cycle = path[cycle_start..]
                        .iter()
                        .map(|index| outbound_node_label(nodes, *index))
                        .collect::<Vec<_>>();
                    cycle.push(outbound_node_label(nodes, current));
                    return (
                        targets.into_boxed_slice(),
                        Some(OutboundProxyGraphError::Cycle { path: cycle }),
                    );
                }
                _ => {
                    state[current] = 1;
                    path.push(current);
                }
            }

            let Some(target) = targets[current] else {
                break;
            };
            current = target.index;
        }
        for index in path {
            state[index] = 2;
        }
    }

    (targets.into_boxed_slice(), None)
}

fn outbound_node_label(nodes: &[OutboundNode], index: usize) -> String {
    nodes
        .get(index)
        .and_then(OutboundNode::tag)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("#{index}"))
}

fn least_load_cost_millionths(settings: &RoutingLeastLoadSettings, tag: &str) -> u64 {
    settings
        .costs
        .iter()
        .find(|cost| tag.contains(&cost.tag_substring))
        .map_or(COST_MILLIONTHS_ONE, |cost| cost.value_millionths)
}

#[derive(Debug)]
struct OutboundSelectorGroupState {
    override_member: AtomicUsize,
    round_robin_cursor: AtomicU64,
}

#[derive(Debug)]
struct OutboundHealthAtomicState {
    state: AtomicU8,
    delay_ms: AtomicU64,
    last_try_unix_ms: AtomicU64,
    last_seen_unix_ms: AtomicU64,
    consecutive_failures: AtomicU64,
    last_failure: AtomicUsize,
    least_load_metrics: AtomicU64,
    history: Mutex<OutboundHealthWindow>,
}

#[derive(Debug)]
struct OutboundHealthWindow {
    samples: [Option<u64>; LEAST_LOAD_HEALTH_WINDOW],
    next: usize,
    len: usize,
}

impl Default for OutboundHealthWindow {
    fn default() -> Self {
        Self {
            samples: [None; LEAST_LOAD_HEALTH_WINDOW],
            next: 0,
            len: 0,
        }
    }
}

impl OutboundHealthWindow {
    fn record(&mut self, delay_ms: Option<u64>) -> OutboundHealthWindowMetrics {
        self.samples[self.next] = delay_ms;
        self.next = (self.next + 1) % LEAST_LOAD_HEALTH_WINDOW;
        self.len = (self.len + 1).min(LEAST_LOAD_HEALTH_WINDOW);

        let samples = &self.samples[..self.len];
        let successes = samples
            .iter()
            .filter_map(|sample| *sample)
            .collect::<Vec<_>>();
        let success_count = successes.len() as u64;
        let failure_count = self.len as u64 - success_count;
        if successes.is_empty() {
            return OutboundHealthWindowMetrics {
                sample_count: self.len as u64,
                failure_count,
                average_ms: u64::MAX,
                deviation_ms: u64::MAX,
            };
        }
        let sum = successes
            .iter()
            .fold(0u128, |sum, sample| sum + u128::from(*sample));
        let average = sum / u128::from(success_count);
        let variance = successes.iter().fold(0u128, |sum, sample| {
            let sample = u128::from(*sample);
            let difference = sample.abs_diff(average);
            sum.saturating_add(difference.saturating_mul(difference))
        }) / u128::from(success_count);
        OutboundHealthWindowMetrics {
            sample_count: self.len as u64,
            failure_count,
            average_ms: u64::try_from(average).unwrap_or(u64::MAX),
            deviation_ms: u64::try_from(variance.isqrt()).unwrap_or(u64::MAX),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct OutboundHealthWindowMetrics {
    sample_count: u64,
    failure_count: u64,
    average_ms: u64,
    deviation_ms: u64,
}

impl OutboundHealthWindowMetrics {
    fn encode(self) -> u64 {
        let average = self.average_ms.min(LEAST_LOAD_RTT_MAX);
        let deviation = self.deviation_ms.min(LEAST_LOAD_RTT_MAX);
        self.sample_count.min(31)
            | (self.failure_count.min(31) << 5)
            | (average << 10)
            | (deviation << (10 + LEAST_LOAD_RTT_BITS))
    }

    fn decode(value: u64) -> Self {
        Self {
            sample_count: value & 31,
            failure_count: (value >> 5) & 31,
            average_ms: (value >> 10) & LEAST_LOAD_RTT_MAX,
            deviation_ms: (value >> (10 + LEAST_LOAD_RTT_BITS)) & LEAST_LOAD_RTT_MAX,
        }
    }
}

impl Default for OutboundHealthAtomicState {
    fn default() -> Self {
        Self {
            state: AtomicU8::new(OutboundHealthState::UNKNOWN),
            delay_ms: AtomicU64::new(u64::MAX),
            last_try_unix_ms: AtomicU64::new(0),
            last_seen_unix_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            last_failure: AtomicUsize::new(OutboundHealthFailure::NONE),
            least_load_metrics: AtomicU64::new(0),
            history: Mutex::new(OutboundHealthWindow::default()),
        }
    }
}

impl OutboundHealthAtomicState {
    fn record_sample(&self, delay_ms: Option<u64>) {
        let metrics = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record(delay_ms);
        self.least_load_metrics
            .store(metrics.encode(), Ordering::Release);
    }
}

/// Small mutable layer over an immutable outbound graph.
///
/// Candidate membership never changes. An override is one release-store and
/// every new flow observes it with an acquire-load; existing flows keep their
/// already selected handler and transport resources.
#[derive(Debug)]
pub struct OutboundSelectionOverlay {
    graph: Arc<OutboundGraph>,
    groups: Box<[OutboundSelectorGroupState]>,
    health: Box<[OutboundHealthAtomicState]>,
    revision: AtomicU64,
    update_lock: Mutex<()>,
}

impl OutboundSelectionOverlay {
    fn new(graph: Arc<OutboundGraph>) -> Self {
        let groups = (0..graph.selector_groups().len())
            .map(|_| OutboundSelectorGroupState {
                override_member: AtomicUsize::new(0),
                round_robin_cursor: AtomicU64::new(0),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let health = (0..graph.leaf_count)
            .map(|_| OutboundHealthAtomicState::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            graph,
            groups,
            health,
            revision: AtomicU64::new(0),
            update_lock: Mutex::new(()),
        }
    }

    pub fn set_override(&self, group_tag: &str, outbound_tag: &str) -> Result<u64, CoreError> {
        let _update = self
            .update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (group_index, group) = self.group_for_tag(group_tag)?;
        let member_index = group
            .members()
            .iter()
            .position(|member| {
                self.graph
                    .node(*member)
                    .and_then(OutboundNode::tag)
                    .is_some_and(|tag| tag == outbound_tag)
            })
            .ok_or_else(|| CoreError::OutboundSelectorCandidateNotFound {
                group: group_tag.to_owned(),
                outbound: outbound_tag.to_owned(),
            })?;
        self.groups[group_index]
            .override_member
            .store(member_index + 1, Ordering::Release);
        Ok(self.revision.fetch_add(1, Ordering::AcqRel) + 1)
    }

    pub fn clear_override(&self, group_tag: &str) -> Result<u64, CoreError> {
        let _update = self
            .update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (group_index, _) = self.group_for_tag(group_tag)?;
        self.groups[group_index]
            .override_member
            .store(0, Ordering::Release);
        Ok(self.revision.fetch_add(1, Ordering::AcqRel) + 1)
    }

    pub fn snapshot(&self) -> OutboundSelectionSnapshot {
        let _update = self
            .update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let groups = self
            .graph
            .selector_groups()
            .iter()
            .enumerate()
            .map(|(index, group)| {
                let candidates = group
                    .members()
                    .iter()
                    .filter_map(|member| self.graph.node(*member)?.tag().map(ToOwned::to_owned))
                    .collect();
                let override_member = self.groups[index].override_member.load(Ordering::Acquire);
                let override_tag = override_member
                    .checked_sub(1)
                    .and_then(|member| group.members().get(member))
                    .and_then(|member| self.graph.node(*member))
                    .and_then(OutboundNode::tag)
                    .map(ToOwned::to_owned);
                OutboundSelectorGroupSnapshot {
                    tag: group.tag().to_owned(),
                    candidates,
                    override_tag,
                }
            })
            .collect();
        OutboundSelectionSnapshot {
            revision: self.revision.load(Ordering::Acquire),
            groups,
        }
    }

    pub fn health_snapshot(&self) -> OutboundHealthSnapshot {
        let _update = self
            .update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let outbounds = self
            .health
            .iter()
            .enumerate()
            .filter_map(|(index, health)| {
                let node = self.graph.nodes().get(index)?;
                let outbound_tag = node.tag()?.to_owned();
                let state = OutboundHealthState::from_u8(health.state.load(Ordering::Acquire));
                let delay_ms = health.delay_ms.load(Ordering::Acquire);
                let last_try_unix_ms = health.last_try_unix_ms.load(Ordering::Acquire);
                let last_seen_unix_ms = health.last_seen_unix_ms.load(Ordering::Acquire);
                Some(OutboundHealthStatusSnapshot {
                    outbound_tag,
                    state,
                    delay_ms: (delay_ms != u64::MAX).then_some(delay_ms),
                    last_try_unix_ms: (last_try_unix_ms != 0).then_some(last_try_unix_ms),
                    last_seen_unix_ms: (last_seen_unix_ms != 0).then_some(last_seen_unix_ms),
                    consecutive_failures: health.consecutive_failures.load(Ordering::Acquire),
                    last_failure: OutboundHealthFailure::decode(
                        health.last_failure.load(Ordering::Acquire),
                    ),
                })
            })
            .collect();
        OutboundHealthSnapshot {
            revision: self.revision.load(Ordering::Acquire),
            outbounds,
        }
    }

    pub(crate) fn record_health_success(
        &self,
        node: OutboundNodeId,
        delay: Duration,
        now_unix_ms: u64,
    ) {
        let Some(health) = self.health_state(node) else {
            return;
        };
        let _update = self
            .update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health.delay_ms.store(
            delay.as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Release,
        );
        health.record_sample(Some(delay.as_millis().min(u128::from(u64::MAX)) as u64));
        health
            .last_try_unix_ms
            .store(now_unix_ms, Ordering::Release);
        health
            .last_seen_unix_ms
            .store(now_unix_ms, Ordering::Release);
        health.consecutive_failures.store(0, Ordering::Release);
        health
            .last_failure
            .store(OutboundHealthFailure::NONE, Ordering::Release);
        health
            .state
            .store(OutboundHealthState::HEALTHY, Ordering::Release);
        self.revision.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn record_health_failure(
        &self,
        node: OutboundNodeId,
        failure: OutboundHealthFailure,
        now_unix_ms: u64,
    ) {
        let Some(health) = self.health_state(node) else {
            return;
        };
        let _update = self
            .update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health.record_sample(None);
        health.delay_ms.store(u64::MAX, Ordering::Release);
        health
            .last_try_unix_ms
            .store(now_unix_ms, Ordering::Release);
        health.consecutive_failures.fetch_add(1, Ordering::AcqRel);
        health
            .last_failure
            .store(failure.encode(), Ordering::Release);
        health
            .state
            .store(OutboundHealthState::UNHEALTHY, Ordering::Release);
        self.revision.fetch_add(1, Ordering::AcqRel);
    }

    fn select(&self, group_tag: &str) -> Result<OutboundNodeId, CoreError> {
        let (group_index, group) = self.group_for_tag(group_tag)?;
        let state = &self.groups[group_index];
        if let Some(member_index) = state.override_member.load(Ordering::Acquire).checked_sub(1) {
            return group
                .members()
                .get(member_index)
                .copied()
                .ok_or(CoreError::NoSupportedOutbound);
        }
        let selected = match group.strategy() {
            RoutingBalancerStrategy::Random => self.select_random_eligible(group),
            RoutingBalancerStrategy::RoundRobin => {
                let cursor = state.round_robin_cursor.fetch_add(1, Ordering::Relaxed);
                self.select_round_robin_eligible(group, cursor)
            }
            RoutingBalancerStrategy::LeastPing => self.select_least_ping(group),
            RoutingBalancerStrategy::LeastLoad(settings) => self.select_least_load(group, settings),
        };
        selected
            .or_else(|| {
                group
                    .fallback_tag()
                    .and_then(|tag| self.graph.node_for_tag(tag))
            })
            .ok_or(CoreError::NoSupportedOutbound)
    }

    fn group_for_tag(&self, group_tag: &str) -> Result<(usize, &OutboundSelectorGroup), CoreError> {
        let node = self
            .graph
            .first_group_node
            .get(group_tag)
            .copied()
            .ok_or_else(|| CoreError::OutboundSelectorGroupNotFound(group_tag.to_owned()))?;
        let index = node.index - self.graph.leaf_count;
        Ok((index, &self.graph.selector_groups[index]))
    }

    fn health_state(&self, node: OutboundNodeId) -> Option<&OutboundHealthAtomicState> {
        (node.graph_identity == self.graph.identity)
            .then(|| self.health.get(node.index))
            .flatten()
    }

    fn is_eligible(&self, node: OutboundNodeId) -> bool {
        self.health_state(node).is_some_and(|health| {
            OutboundHealthState::from_u8(health.state.load(Ordering::Acquire))
                != OutboundHealthState::Unhealthy
        })
    }

    fn select_random_eligible(&self, group: &OutboundSelectorGroup) -> Option<OutboundNodeId> {
        let eligible_count = group
            .members()
            .iter()
            .filter(|node| self.is_eligible(**node))
            .count();
        if eligible_count == 0 {
            return None;
        }
        let selected = rand::thread_rng().gen_range(0..eligible_count);
        group
            .members()
            .iter()
            .copied()
            .filter(|node| self.is_eligible(*node))
            .nth(selected)
    }

    fn select_round_robin_eligible(
        &self,
        group: &OutboundSelectorGroup,
        cursor: u64,
    ) -> Option<OutboundNodeId> {
        let eligible_count = group
            .members()
            .iter()
            .filter(|node| self.is_eligible(**node))
            .count();
        if eligible_count == 0 {
            return None;
        }
        let selected = usize::try_from(cursor % eligible_count as u64)
            .expect("round-robin remainder fits usize");
        group
            .members()
            .iter()
            .copied()
            .filter(|node| self.is_eligible(*node))
            .nth(selected)
    }

    fn select_least_ping(&self, group: &OutboundSelectorGroup) -> Option<OutboundNodeId> {
        group
            .members()
            .iter()
            .copied()
            .filter_map(|node| {
                let health = self.health_state(node)?;
                (OutboundHealthState::from_u8(health.state.load(Ordering::Acquire))
                    == OutboundHealthState::Healthy)
                    .then(|| (health.delay_ms.load(Ordering::Acquire), node))
            })
            .min_by_key(|(delay_ms, _)| *delay_ms)
            .map(|(_, node)| node)
    }

    fn select_least_load(
        &self,
        group: &OutboundSelectorGroup,
        settings: &RoutingLeastLoadSettings,
    ) -> Option<OutboundNodeId> {
        let max_rtt_ms = settings
            .max_rtt
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64);
        let mut candidates = group
            .members()
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(member_index, node)| {
                let health = self.health_state(node)?;
                if OutboundHealthState::from_u8(health.state.load(Ordering::Acquire))
                    != OutboundHealthState::Healthy
                {
                    return None;
                }
                let delay_ms = health.delay_ms.load(Ordering::Acquire);
                if max_rtt_ms.is_some_and(|maximum| delay_ms >= maximum) {
                    return None;
                }
                let metrics = OutboundHealthWindowMetrics::decode(
                    health.least_load_metrics.load(Ordering::Acquire),
                );
                if metrics.sample_count == 0 {
                    return None;
                }
                if settings.tolerance_millionths > 0
                    && u128::from(metrics.failure_count) * 1_000_000
                        > u128::from(metrics.sample_count)
                            * u128::from(settings.tolerance_millionths)
                {
                    return None;
                }
                let tag = self.graph.node(node)?.tag()?;
                let cost = group
                    .least_load_costs
                    .get(member_index)
                    .copied()
                    .unwrap_or(COST_MILLIONTHS_ONE);
                let deviation = u128::from(metrics.deviation_ms);
                let weighted_variance = deviation
                    .saturating_mul(deviation)
                    .saturating_mul(u128::from(cost));
                Some((
                    weighted_variance,
                    metrics.average_ms,
                    metrics.failure_count,
                    metrics.sample_count,
                    tag,
                    node,
                ))
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| right.3.cmp(&left.3))
                .then_with(|| left.4.cmp(right.4))
        });
        if candidates.is_empty() {
            return None;
        }

        let expected = usize::from(settings.expected.max(1)).min(candidates.len());
        let selected_count = if settings.baselines.is_empty() {
            expected
        } else {
            let mut count = 0usize;
            for baseline in &settings.baselines {
                let baseline_ms = baseline.as_millis();
                let threshold = baseline_ms
                    .saturating_mul(baseline_ms)
                    .saturating_mul(u128::from(COST_MILLIONTHS_ONE));
                while count < candidates.len() && candidates[count].0 < threshold {
                    count += 1;
                }
                if count >= expected {
                    break;
                }
            }
            if settings.expected > 0 {
                count.max(expected)
            } else {
                count
            }
        };
        if selected_count == 0 {
            return None;
        }
        let selected = rand::thread_rng().gen_range(0..selected_count);
        Some(candidates[selected].5)
    }
}

/// Owns the lazily compiled handlers and transport resources for one graph.
///
/// Sharing one factory across routers or future selector policies guarantees
/// that a configured node has exactly one cache and one set of stateful
/// transport pools for the lifetime of the core.
#[derive(Debug)]
pub struct OutboundFactory {
    graph: Arc<OutboundGraph>,
    entries: Box<[CachedOutboundEntry]>,
    selection: Arc<OutboundSelectionOverlay>,
}

impl OutboundFactory {
    pub fn new(graph: Arc<OutboundGraph>) -> Self {
        let entries = (0..graph.leaf_count)
            .map(|_| CachedOutboundEntry::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let selection = Arc::new(OutboundSelectionOverlay::new(Arc::clone(&graph)));
        Self {
            graph,
            entries,
            selection,
        }
    }

    pub fn graph(&self) -> &OutboundGraph {
        self.graph.as_ref()
    }

    pub fn graph_handle(&self) -> Arc<OutboundGraph> {
        Arc::clone(&self.graph)
    }

    pub fn selection(&self) -> &OutboundSelectionOverlay {
        self.selection.as_ref()
    }

    pub fn selection_handle(&self) -> Arc<OutboundSelectionOverlay> {
        Arc::clone(&self.selection)
    }

    fn entry(&self, node: OutboundNodeId) -> Result<&CachedOutboundEntry, CachedOutboundError> {
        if self.graph.node(node).is_none() {
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        self.entries
            .get(node.index)
            .ok_or(CachedOutboundError::NoSupportedOutbound)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsRoutePortRange {
    start: u16,
    end: u16,
}

impl DnsRoutePortRange {
    const ALL: Self = Self {
        start: 0,
        end: u16::MAX,
    };

    fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

#[derive(Debug, Default)]
struct DnsRouteNetworkIndex {
    tcp: Box<[DnsRoutePortRange]>,
    udp: Box<[DnsRoutePortRange]>,
}

impl DnsRouteNetworkIndex {
    fn contains(&self, network: Network, port: u16) -> bool {
        let ranges = match network {
            Network::Tcp => &self.tcp,
            Network::Udp => &self.udp,
        };
        let insertion = ranges.partition_point(|range| range.start <= port);
        insertion > 0 && ranges[insertion - 1].contains(port)
    }
}

#[derive(Debug, Default)]
struct DnsRouteNetworkIndexBuilder {
    tcp: Vec<DnsRoutePortRange>,
    udp: Vec<DnsRoutePortRange>,
}

impl DnsRouteNetworkIndexBuilder {
    fn add_rule(&mut self, rule: &RoutingRule) {
        if rule.networks.is_empty() {
            self.add_ports(Network::Tcp, rule);
            self.add_ports(Network::Udp, rule);
            return;
        }

        for network in rule.networks.iter().copied() {
            self.add_ports(network, rule);
        }
    }

    fn add_ports(&mut self, network: Network, rule: &RoutingRule) {
        let ranges = match network {
            Network::Tcp => &mut self.tcp,
            Network::Udp => &mut self.udp,
        };
        if rule.port_ranges.is_empty() {
            ranges.push(DnsRoutePortRange::ALL);
        } else {
            ranges.extend(rule.port_ranges.iter().map(|range| DnsRoutePortRange {
                start: range.start(),
                end: range.end(),
            }));
        }
    }

    fn finish(self) -> DnsRouteNetworkIndex {
        DnsRouteNetworkIndex {
            tcp: merge_dns_route_port_ranges(self.tcp),
            udp: merge_dns_route_port_ranges(self.udp),
        }
    }
}

fn merge_dns_route_port_ranges(mut ranges: Vec<DnsRoutePortRange>) -> Box<[DnsRoutePortRange]> {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<DnsRoutePortRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut() {
            if range.start <= previous.end.saturating_add(1) {
                previous.end = previous.end.max(range.end);
                continue;
            }
        }
        merged.push(range);
    }
    merged.into_boxed_slice()
}

#[derive(Debug, Default)]
struct DnsRoutePrefilter {
    network_ports: DnsRouteNetworkIndex,
    wildcard_inbound: bool,
    tagged_inbounds: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingPolicySnapshot {
    pub revision: u64,
    pub rule_count: usize,
    pub domain_strategy: RoutingDomainStrategy,
}

#[derive(Debug)]
struct RoutingPolicyState {
    revision: u64,
    routing: RoutingConfig,
    dns_route_prefilter: DnsRoutePrefilter,
}

impl DnsRoutePrefilter {
    fn new<'a>(rules: impl Iterator<Item = &'a RoutingRule>) -> Self {
        let mut network_ports = DnsRouteNetworkIndexBuilder::default();
        let mut wildcard_inbound = false;
        let mut tagged_inbounds = HashSet::new();
        for rule in rules {
            network_ports.add_rule(rule);
            if rule.inbound_tags.is_empty() {
                wildcard_inbound = true;
                continue;
            }
            tagged_inbounds.extend(rule.inbound_tags.iter().cloned());
        }

        Self {
            network_ports: network_ports.finish(),
            wildcard_inbound,
            tagged_inbounds,
        }
    }

    fn may_match(&self, inbound_tag: Option<&str>, network: Network, port: u16) -> bool {
        self.network_ports.contains(network, port)
            && (self.wildcard_inbound
                || inbound_tag.is_some_and(|tag| self.tagged_inbounds.contains(tag)))
    }
}

/// Persistent routing policy over one immutable outbound graph and factory.
///
/// Routing-rule order remains authoritative, duplicate outbound tags resolve to
/// their first configured entry, and invalid outbounds are compiled only when
/// selected. Routers created from the same factory share stateful transport
/// resources such as gRPC and XHTTP connection pools.
#[derive(Debug)]
pub struct OutboundRouter {
    factory: Arc<OutboundFactory>,
    routing_policy: RwLock<Arc<RoutingPolicyState>>,
    routing_update_lock: Mutex<()>,
    default_is_dns: bool,
    default_requires_selection: bool,
}

impl OutboundRouter {
    pub fn new(config: Arc<CoreConfig>) -> Self {
        let graph = Arc::new(OutboundGraph::new(config));
        Self::from_factory(Arc::new(OutboundFactory::new(graph)))
    }

    pub fn from_factory(factory: Arc<OutboundFactory>) -> Self {
        let graph = factory.graph();
        let routing = graph.config().routing.clone();
        let routing_policy = RoutingPolicyState {
            revision: 0,
            dns_route_prefilter: Self::dns_route_prefilter(graph, &routing),
            routing,
        };
        let default_is_dns = graph
            .default_node()
            .and_then(|id| graph.node(id))
            .is_some_and(|node| node.kind() == OutboundNodeKind::Dns);
        let default_requires_selection = graph.has_unresolved_default_tag();
        Self {
            factory,
            routing_policy: RwLock::new(Arc::new(routing_policy)),
            routing_update_lock: Mutex::new(()),
            default_is_dns,
            default_requires_selection,
        }
    }

    pub fn graph(&self) -> &OutboundGraph {
        self.factory.graph()
    }

    pub fn factory(&self) -> &OutboundFactory {
        self.factory.as_ref()
    }

    pub fn factory_handle(&self) -> Arc<OutboundFactory> {
        Arc::clone(&self.factory)
    }

    pub fn selection(&self) -> &OutboundSelectionOverlay {
        self.factory.selection()
    }

    pub fn selection_handle(&self) -> Arc<OutboundSelectionOverlay> {
        self.factory.selection_handle()
    }

    pub fn replace_routing_policy(&self, routing: RoutingConfig) -> Result<u64, CoreError> {
        self.validate_routing_policy(&routing)?;
        let dns_route_prefilter = Self::dns_route_prefilter(self.graph(), &routing);
        let _update = self
            .routing_update_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let revision = self
            .routing_policy_state()
            .revision
            .checked_add(1)
            .ok_or(CoreError::RoutingPolicyRevisionExhausted)?;
        let next = Arc::new(RoutingPolicyState {
            revision,
            routing,
            dns_route_prefilter,
        });
        *self
            .routing_policy
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
        Ok(revision)
    }

    pub fn routing_policy_snapshot(&self) -> RoutingPolicySnapshot {
        let policy = self.routing_policy_state();
        RoutingPolicySnapshot {
            revision: policy.revision,
            rule_count: policy.routing.rules.len(),
            domain_strategy: policy.routing.domain_strategy,
        }
    }

    fn routing_policy_state(&self) -> Arc<RoutingPolicyState> {
        Arc::clone(
            &self
                .routing_policy
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    fn validate_routing_policy(&self, routing: &RoutingConfig) -> Result<(), CoreError> {
        if !routing.balancers.is_empty()
            && routing.balancers != self.graph().config().routing.balancers
        {
            return Err(CoreError::RoutingPolicyBalancerTopologyChanged);
        }
        for rule in &routing.rules {
            match &rule.target {
                RoutingRuleTarget::Outbound(tag) if self.graph().node_for_tag(tag).is_none() => {
                    return Err(CoreError::RoutingPolicyOutboundNotFound(tag.clone()));
                }
                RoutingRuleTarget::Balancer(tag)
                    if self.graph().selector_group_for_tag(tag).is_none() =>
                {
                    return Err(CoreError::RoutingPolicyBalancerNotFound(tag.clone()));
                }
                RoutingRuleTarget::Outbound(_) | RoutingRuleTarget::Balancer(_) => {}
            }
        }
        Ok(())
    }

    fn dns_route_prefilter(graph: &OutboundGraph, routing: &RoutingConfig) -> DnsRoutePrefilter {
        DnsRoutePrefilter::new(routing.rules.iter().filter(|rule| {
            match &rule.target {
                RoutingRuleTarget::Outbound(tag) => graph
                    .node_for_tag(tag)
                    .and_then(|id| graph.node(id))
                    .is_some_and(|node| node.kind() == OutboundNodeKind::Dns),
                RoutingRuleTarget::Balancer(tag) => {
                    graph.selector_group_for_tag(tag).is_some_and(|group| {
                        group.members().iter().any(|member| {
                            graph
                                .node(*member)
                                .is_some_and(|node| node.kind() == OutboundNodeKind::Dns)
                        }) || group
                            .fallback_tag()
                            .and_then(|tag| graph.node_for_tag(tag))
                            .and_then(|node| graph.node(node))
                            .is_some_and(|node| node.kind() == OutboundNodeKind::Dns)
                    })
                }
            }
        }))
    }

    fn config(&self) -> &CoreConfig {
        self.graph().config()
    }

    pub fn select_tcp_outbound(&self) -> Result<TcpOutbound, CoreError> {
        let node = self.select_configured_node(None, None, None, None, None)?;
        self.factory.cached_tcp_outbound(node)
    }

    pub(crate) fn select_tcp_outbound_direct(
        &self,
        outbound_tag: Option<&str>,
    ) -> Result<TcpOutbound, CoreError> {
        let node = self.select_configured_node_direct(outbound_tag)?;
        self.factory.cached_tcp_outbound(node)
    }

    pub fn select_tcp_outbound_for_session(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
    ) -> Result<TcpOutbound, CoreError> {
        let node = self.select_configured_node(
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        )?;
        self.factory.cached_tcp_outbound(node)
    }

    /// Selects a TCP outbound from the original session metadata and retains
    /// its configured tag for runtime logging.
    ///
    /// Unlike the resolver-backed selector, this deliberately does not run an
    /// `IPIfNonMatch` DNS second pass. Internal DNS clients use this path to
    /// match Xray's `SkipDNSResolve` routing context and avoid recursively
    /// resolving the name server that is needed to perform the lookup.
    pub(crate) fn select_tcp_outbound_for_session_with_tag(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        include_tag: bool,
    ) -> Result<SelectedTcpOutbound, CoreError> {
        let node = self.select_configured_node(
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        )?;
        let tag = include_tag
            .then(|| self.graph().node(node).and_then(|node| node.tag.clone()))
            .flatten();
        let outbound = self.factory.cached_tcp_outbound(node)?;
        Ok(SelectedTcpOutbound { outbound, tag })
    }

    #[cfg(test)]
    pub(crate) fn select_tcp_outbound_for_session_with_tag_and_resolved_ip(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        resolved_ip: Option<&IpAddr>,
        include_tag: bool,
    ) -> Result<SelectedTcpOutbound, CoreError> {
        let node =
            self.select_configured_node_with_resolved_ip(inbound_tag, target, resolved_ip)?;
        let tag = include_tag
            .then(|| self.graph().node(node).and_then(|node| node.tag.clone()))
            .flatten();
        let outbound = self.factory.cached_tcp_outbound(node)?;
        Ok(SelectedTcpOutbound { outbound, tag })
    }

    pub async fn select_tcp_outbound_for_session_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<TcpOutbound, CoreError> {
        let node = self
            .select_configured_node_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        self.factory.cached_tcp_outbound(node)
    }

    pub(crate) async fn select_tcp_session_outbound_with_tag_and_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        include_tag: bool,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<SelectedTcpSessionOutbound, CoreError> {
        let node = self
            .select_configured_node_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        let tag = include_tag
            .then(|| self.graph().node(node).and_then(|node| node.tag.clone()))
            .flatten();
        let outbound = if self
            .graph()
            .node(node)
            .is_some_and(|node| node.kind() == OutboundNodeKind::Dns)
        {
            self.factory
                .cached_dns_outbound(node)
                .map(TcpSessionOutbound::Dns)
        } else {
            self.factory
                .cached_tcp_outbound(node)
                .map(TcpSessionOutbound::Transport)
        }?;
        Ok(SelectedTcpSessionOutbound { outbound, tag })
    }

    pub(crate) async fn select_tcp_outbound_for_session_with_tag_and_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        include_tag: bool,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<SelectedTcpOutbound, CoreError> {
        let node = self
            .select_configured_node_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        let tag = include_tag
            .then(|| self.graph().node(node).and_then(|node| node.tag.clone()))
            .flatten();
        let outbound = self.factory.cached_tcp_outbound(node)?;
        Ok(SelectedTcpOutbound { outbound, tag })
    }

    pub fn select_udp_outbound_for_session(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
    ) -> Result<UdpOutbound, CoreError> {
        let node = self.select_configured_node(
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        )?;
        self.factory.cached_udp_outbound(node)
    }

    /// Returns the selected DNS message handler without treating regular
    /// transport outbounds as errors. Callers can therefore preserve their
    /// existing TCP/UDP path when no DNS outbound was selected.
    pub fn select_dns_outbound_for_session(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
    ) -> Result<Option<DnsOutbound>, CoreError> {
        let policy = self.routing_policy_state();
        if !self.may_select_dns_outbound_in_policy(&policy, inbound_tag, target) {
            return Ok(None);
        }
        let node = self.select_configured_node_in_policy(
            &policy,
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        )?;
        if !self
            .graph()
            .node(node)
            .is_some_and(|node| node.kind() == OutboundNodeKind::Dns)
        {
            return Ok(None);
        }
        self.factory.cached_dns_outbound(node).map(Some)
    }

    pub async fn select_dns_outbound_for_session_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<Option<DnsOutbound>, CoreError> {
        let policy = self.routing_policy_state();
        if !self.may_select_dns_outbound_in_policy(&policy, inbound_tag, target) {
            return Ok(None);
        }
        let node = self
            .select_configured_node_with_resolver_in_policy(
                &policy,
                inbound_tag,
                target,
                dns_resolver,
            )
            .await?;
        if !self
            .graph()
            .node(node)
            .is_some_and(|node| node.kind() == OutboundNodeKind::Dns)
        {
            return Ok(None);
        }
        self.factory.cached_dns_outbound(node).map(Some)
    }

    #[cfg(test)]
    fn may_select_dns_outbound(&self, inbound_tag: Option<&str>, target: &Target) -> bool {
        let policy = self.routing_policy_state();
        self.may_select_dns_outbound_in_policy(&policy, inbound_tag, target)
    }

    fn may_select_dns_outbound_in_policy(
        &self,
        policy: &RoutingPolicyState,
        inbound_tag: Option<&str>,
        target: &Target,
    ) -> bool {
        self.default_is_dns
            || self.default_requires_selection
            || policy.dns_route_prefilter.may_match(
                inbound_tag,
                target_network(target),
                target.port,
            )
    }

    /// Checks the effective tags assigned to managed DNS clients. Runtime DNS
    /// transports combine this compatibility check with their trusted origin
    /// context before bypassing DNS rules.
    pub(crate) fn is_dns_client_tag(&self, inbound_tag: Option<&str>) -> bool {
        let Some(inbound_tag) = inbound_tag else {
            return false;
        };
        self.config()
            .dns
            .servers
            .iter()
            .any(|server| server.effective_tag(&self.config().dns.tag) == inbound_tag)
    }

    pub async fn select_udp_outbound_for_session_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<UdpOutbound, CoreError> {
        let node = self
            .select_configured_node_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        self.factory.cached_udp_outbound(node)
    }

    pub(crate) async fn select_udp_session_outbound_with_tag_and_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        include_tag: bool,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<SelectedUdpSessionOutbound, CoreError> {
        let node = self
            .select_configured_node_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        let tag = include_tag
            .then(|| self.graph().node(node).and_then(|node| node.tag.clone()))
            .flatten();
        let outbound = if self
            .graph()
            .node(node)
            .is_some_and(|node| node.kind() == OutboundNodeKind::Dns)
        {
            self.factory
                .cached_dns_outbound(node)
                .map(UdpSessionOutbound::Dns)
        } else {
            self.factory
                .cached_udp_outbound(node)
                .map(UdpSessionOutbound::Transport)
        }?;
        Ok(SelectedUdpSessionOutbound { outbound, tag })
    }

    fn select_configured_node(
        &self,
        inbound_tag: Option<&str>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
        target_network: Option<Network>,
        target_port: Option<u16>,
    ) -> Result<OutboundNodeId, CoreError> {
        let policy = self.routing_policy_state();
        self.select_configured_node_in_policy(
            &policy,
            inbound_tag,
            target_domain,
            target_ip,
            target_network,
            target_port,
        )
    }

    fn select_configured_node_in_policy(
        &self,
        policy: &RoutingPolicyState,
        inbound_tag: Option<&str>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
        target_network: Option<Network>,
        target_port: Option<u16>,
    ) -> Result<OutboundNodeId, CoreError> {
        let routed_target = select_routed_target(
            &policy.routing,
            inbound_tag,
            target_domain,
            target_ip,
            target_network,
            target_port,
        );
        match routed_target {
            Some(target) => self.node_for_target(target),
            None => self.select_default_configured_node(),
        }
    }

    #[cfg(test)]
    fn select_configured_node_with_resolved_ip(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        resolved_ip: Option<&IpAddr>,
    ) -> Result<OutboundNodeId, CoreError> {
        let policy = self.routing_policy_state();
        if let Some(routed_target) = select_routed_target(
            &policy.routing,
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        ) {
            return self.node_for_target(routed_target);
        }

        if policy.routing.domain_strategy == RoutingDomainStrategy::IpIfNonMatch {
            if let Some(resolved_ip) = resolved_ip {
                if let Some(routed_target) = select_routed_target(
                    &policy.routing,
                    inbound_tag,
                    target_domain(target),
                    Some(resolved_ip),
                    Some(target_network(target)),
                    Some(target.port),
                ) {
                    return self.node_for_target(routed_target);
                }
            }
        }

        self.select_default_configured_node()
    }

    async fn select_configured_node_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<OutboundNodeId, CoreError> {
        // Retain one immutable policy snapshot across any DNS await so a flow
        // never observes rules from two revisions.
        let policy = self.routing_policy_state();
        self.select_configured_node_with_resolver_in_policy(
            &policy,
            inbound_tag,
            target,
            dns_resolver,
        )
        .await
    }

    async fn select_configured_node_with_resolver_in_policy(
        &self,
        policy: &RoutingPolicyState,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<OutboundNodeId, CoreError> {
        if let Some(routed_target) = select_routed_target(
            &policy.routing,
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        ) {
            return self.node_for_target(routed_target);
        }

        if policy.routing.domain_strategy == RoutingDomainStrategy::IpIfNonMatch {
            if let Some(domain) = target_domain(target) {
                if let Ok(resolved) = dns_resolver.resolve_all(domain, target.port).await {
                    if let Some(routed_target) = select_routed_target_with_resolved_ips(
                        &policy.routing,
                        inbound_tag,
                        Some(domain),
                        resolved.socket_addrs(),
                        Some(target_network(target)),
                        Some(target.port),
                    ) {
                        return self.node_for_target(routed_target);
                    }
                }
            }
        }

        self.select_default_configured_node()
    }

    fn select_configured_node_direct(
        &self,
        outbound_tag: Option<&str>,
    ) -> Result<OutboundNodeId, CoreError> {
        match outbound_tag {
            Some(tag) => self.node_for_tag(tag),
            None => self.select_default_configured_node(),
        }
    }

    fn select_default_configured_node(&self) -> Result<OutboundNodeId, CoreError> {
        self.graph()
            .default_node()
            .ok_or(CoreError::NoSupportedOutbound)
    }

    fn node_for_tag(&self, tag: &str) -> Result<OutboundNodeId, CoreError> {
        self.graph()
            .node_for_tag(tag)
            .ok_or(CoreError::NoSupportedOutbound)
    }

    fn node_for_target(&self, target: &RoutingRuleTarget) -> Result<OutboundNodeId, CoreError> {
        match target {
            RoutingRuleTarget::Outbound(tag) => self.node_for_tag(tag),
            RoutingRuleTarget::Balancer(tag) => self.selection().select(tag),
        }
    }
}

impl OutboundFactory {
    pub(crate) fn cached_tcp_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<TcpOutbound, CoreError> {
        self.graph.validate_proxy_chains()?;
        let cached = self
            .entry(node)
            .map_err(CachedOutboundError::into_core_error)?
            .tcp
            .get_or_init(|| self.compile_tcp_outbound(node));
        clone_cached_outbound(cached)
    }

    pub(crate) fn cached_udp_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<UdpOutbound, CoreError> {
        self.graph.validate_proxy_chains()?;
        let cached = self
            .entry(node)
            .map_err(CachedOutboundError::into_core_error)?
            .udp
            .get_or_init(|| self.compile_udp_outbound(node));
        clone_cached_outbound(cached)
    }

    pub(crate) fn cached_dns_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<DnsOutbound, CoreError> {
        self.graph.validate_proxy_chains()?;
        let cached = self
            .entry(node)
            .map_err(CachedOutboundError::into_core_error)?
            .dns
            .get_or_init(|| self.compile_dns_outbound(node));
        clone_cached_outbound(cached)
    }

    fn cached_vless_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<VlessTcpOutbound, CachedOutboundError> {
        let configured = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        let cached = self.entry(node)?.vless.get_or_init(|| {
            build_vless_tcp_outbound(configured).map_err(CachedOutboundError::from_core_error)
        });
        match cached {
            Ok(outbound) => Ok(outbound.clone()),
            Err(error) => Err(error.clone()),
        }
    }

    fn compile_tcp_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<TcpOutbound, CachedOutboundError> {
        let outbound = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        if outbound.stream.network != Network::Tcp {
            return Err(CachedOutboundError::UnsupportedOutboundNetwork);
        }

        let compiled = match &outbound.settings {
            OutboundSettings::Dns(_) => Err(CachedOutboundError::NoSupportedOutbound),
            OutboundSettings::Freedom => {
                if !stream_transport_is_dialable(&outbound.stream) {
                    return Err(CachedOutboundError::UnsupportedOutboundNetwork);
                }
                if outbound.stream.security != StreamSecurity::None {
                    return Err(CachedOutboundError::UnsupportedOutboundSecurity);
                }
                Ok(build_freedom_tcp_outbound(&outbound.stream))
            }
            OutboundSettings::Vless(_) => self
                .cached_vless_outbound(node)
                .map(|outbound| TcpOutbound::Vless(Box::new(outbound))),
        }?;

        match self.graph.proxy_target(node) {
            Some(proxy) => self
                .cached_tcp_outbound(proxy)
                .map(|proxy| TcpOutbound::Chained {
                    outbound: Box::new(compiled),
                    proxy: Box::new(proxy),
                })
                .map_err(CachedOutboundError::from_core_error),
            None => Ok(compiled),
        }
    }

    fn compile_udp_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<UdpOutbound, CachedOutboundError> {
        let outbound = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        if outbound.proxy_settings.is_some() {
            return Err(CachedOutboundError::UnsupportedOutboundProxyNetwork("UDP"));
        }
        match &outbound.settings {
            OutboundSettings::Dns(_) => Err(CachedOutboundError::NoSupportedOutbound),
            OutboundSettings::Freedom => {
                if !stream_transport_is_dialable(&outbound.stream) {
                    return Err(CachedOutboundError::UnsupportedOutboundNetwork);
                }
                if outbound.stream.security != StreamSecurity::None {
                    return Err(CachedOutboundError::UnsupportedOutboundSecurity);
                }
                Ok(UdpOutbound::Freedom)
            }
            OutboundSettings::Vless(_) => {
                if outbound.stream.network != Network::Tcp {
                    return Err(CachedOutboundError::UnsupportedOutboundNetwork);
                }
                self.cached_vless_outbound(node)
                    .map(|outbound| UdpOutbound::Vless(Box::new(outbound)))
            }
        }
    }

    fn compile_dns_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<DnsOutbound, CachedOutboundError> {
        let configured = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        if configured.proxy_settings.is_some() {
            return Err(CachedOutboundError::UnsupportedOutboundProxyNetwork("DNS"));
        }
        match &configured.settings {
            OutboundSettings::Dns(settings) => {
                let conn_idle =
                    effective_policy_for_level(self.graph.config(), Some(settings.user_level))
                        .conn_idle;
                DnsOutbound::new_with_stream(settings.clone(), &configured.stream, conn_idle)
                    .map_err(CachedOutboundError::from_core_error)
            }
            OutboundSettings::Freedom | OutboundSettings::Vless(_) => {
                Err(CachedOutboundError::NoSupportedOutbound)
            }
        }
    }
}

fn clone_cached_outbound<T: Clone>(
    cached: &Result<T, CachedOutboundError>,
) -> Result<T, CoreError> {
    match cached {
        Ok(outbound) => Ok(outbound.clone()),
        Err(error) => Err(error.clone().into_core_error()),
    }
}

/// Whether this stream's transport is one the *freedom* and *DNS* outbounds
/// can dial.
///
/// VLESS carries a `TransportLayer` and dials ws, httpupgrade and gRPC for
/// real. These two do not: they hand the stream straight to a socket, and the
/// stream's `network` is `Tcp` for every transport, so without this a
/// `network: "ws"` freedom outbound would silently dial plain TCP.
fn stream_transport_is_dialable(stream: &StreamSettings) -> bool {
    matches!(stream.transport, StreamTransport::Raw)
}

/// Resolves the config's transport into the dial-ready one.
///
/// WebSocket and HTTPUpgrade's `Host` header follows Xray's precedence -- the
/// transport's own `host`, else the TLS/REALITY server name, else the
/// destination address -- and never carries a port. XHTTP resolves the same
/// sources separately below because its scheme, authority validation, and
/// native-client port rule belong to its request URL.
///
/// gRPC's `:authority` looks like the same question and is not: it has its own
/// chain, its own view of REALITY, and a fallback that does carry the port.
/// [`grpc_authority`] has it, and `host_fallback` below is the wrong answer to
/// it in three separate ways.
fn build_transport_layer(
    outbound: &OutboundConfig,
    connector: &ConnectorConfig,
) -> Result<TransportLayer, CoreError> {
    let OutboundSettings::Vless(settings) = &outbound.settings else {
        return Err(CoreError::NoSupportedOutbound);
    };

    let host_fallback = || match connector {
        ConnectorConfig::Tls(tls) if !tls.server_name.is_empty() => tls.server_name.clone(),
        ConnectorConfig::Reality(reality) if !reality.server_name.is_empty() => {
            reality.server_name.clone()
        }
        _ => match &settings.server {
            TargetAddr::Domain(domain) => domain.clone(),
            TargetAddr::Ip(ip) => ip.to_string(),
        },
    };

    Ok(match &outbound.stream.transport {
        StreamTransport::Raw => TransportLayer::Raw,
        StreamTransport::WebSocket(websocket) => TransportLayer::WebSocket(WebSocketConfig {
            path: websocket.path.clone(),
            host: websocket.host.clone().unwrap_or_else(host_fallback),
            headers: websocket.headers.clone(),
            early_data_bytes: websocket.early_data_bytes,
            heartbeat_period_secs: websocket.heartbeat_period_secs,
        }),
        StreamTransport::HttpUpgrade(upgrade) => TransportLayer::HttpUpgrade(HttpUpgradeConfig {
            path: upgrade.path.clone(),
            host: upgrade.host.clone().unwrap_or_else(host_fallback),
            headers: upgrade.headers.clone(),
        }),
        StreamTransport::Grpc(grpc) => TransportLayer::Grpc(GrpcTransport::new(GrpcConfig {
            service_name: grpc.service_name.clone(),
            multi_mode: grpc.multi_mode,
            authority: grpc_authority(
                grpc.authority.as_deref(),
                &outbound.stream.security,
                &settings.server,
                settings.port,
            )?,
            user_agent: grpc_user_agent(grpc.user_agent.as_deref())?,
            idle_timeout_secs: grpc.idle_timeout_secs,
            health_check_timeout_secs: grpc.health_check_timeout_secs,
            permit_without_stream: grpc.permit_without_stream,
            initial_windows_size: grpc.initial_windows_size,
        })),
        StreamTransport::Xhttp(xhttp) => TransportLayer::Xhttp(build_xhttp_transport(
            xhttp,
            &outbound.stream.security,
            &settings.server,
            outbound.stream.quic_params.as_ref(),
        )?),
    })
}

fn build_xhttp_transport(
    settings: &XhttpSettings,
    security: &StreamSecurity,
    destination: &TargetAddr,
    quic_params: Option<&QuicParamsSettings>,
) -> Result<XhttpTransport, CoreError> {
    let http_version = xhttp_http_version(security)?;
    let endpoint = xhttp_endpoint(settings, security, destination)?;
    let config = xhttp_config(settings, matches!(security, StreamSecurity::Reality(_)))?;
    let xmux = xhttp_xmux_policy(settings);
    let h3_quic = if http_version == XhttpHttpVersion::Http3 {
        xhttp_h3_quic_config(quic_params)?
    } else {
        // Xray retains finalmask.quicParams in every stream config but only
        // consults it after exact `alpn: ["h3"]` selected the UDP path.
        H3QuicConfig::default()
    };

    XhttpTransport::new_with_h3_quic(config, endpoint, http_version, xmux, h3_quic)
        .map_err(invalid_xhttp_configuration)
}

/// Xray's `decideHTTPVersion` decision, before a socket is opened.
///
/// HTTP/3 changes the destination to UDP inside the transport dialer. Every
/// other TLS list follows Xray's HTTP/2 branch, including an empty or
/// multi-value list; REALITY is always HTTP/2.
fn xhttp_http_version(security: &StreamSecurity) -> Result<XhttpHttpVersion, CoreError> {
    match security {
        StreamSecurity::None => Ok(XhttpHttpVersion::Http1),
        StreamSecurity::Reality(_) => Ok(XhttpHttpVersion::Http2),
        StreamSecurity::Tls(tls) => match tls.alpn.as_slice() {
            [only] if only == "http/1.1" => Ok(XhttpHttpVersion::Http1),
            [only] if only == "h3" => Ok(XhttpHttpVersion::Http3),
            _ => Ok(XhttpHttpVersion::Http2),
        },
    }
}

/// Resolves XHTTP's request URL endpoint.
///
/// The native Xray HTTP client fixes the dial destination in its custom
/// dialer and does not append the VLESS destination port to `URL.Host`.
/// Non-default ports are appended only by Xray's optional browser dialer,
/// which this runtime does not use. A port explicitly written in
/// `xhttpSettings.host` remains part of the authority.
fn xhttp_endpoint(
    settings: &XhttpSettings,
    security: &StreamSecurity,
    destination: &TargetAddr,
) -> Result<XhttpEndpoint, CoreError> {
    let scheme = match security {
        StreamSecurity::None => XhttpScheme::Http,
        StreamSecurity::Tls(_) | StreamSecurity::Reality(_) => XhttpScheme::Https,
    };
    let authority = settings
        .host
        .as_deref()
        .filter(|host| !host.is_empty())
        .or_else(|| match security {
            StreamSecurity::Tls(tls) => tls
                .server_name
                .as_deref()
                .filter(|server_name| !server_name.is_empty()),
            StreamSecurity::Reality(reality) => {
                (!reality.server_name.is_empty()).then_some(reality.server_name.as_str())
            }
            StreamSecurity::None => None,
        })
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| xhttp_destination_authority(destination));

    XhttpEndpoint::new(scheme, authority).map_err(invalid_xhttp_configuration)
}

fn xhttp_destination_authority(destination: &TargetAddr) -> String {
    match destination {
        TargetAddr::Domain(domain) => domain.clone(),
        TargetAddr::Ip(ip) => match ip.to_canonical() {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        },
    }
}

fn xhttp_config(settings: &XhttpSettings, is_reality: bool) -> Result<XhttpConfig, CoreError> {
    let mut headers = HeaderMap::new();
    for (name, value) in &settings.headers {
        // Xray feeds the protobuf map through `http.Header.Add`. The JSON map
        // can contain keys which differ only by case; config parsing MIME-
        // canonicalizes both, so appending is what preserves both values.
        headers.add(name, value);
    }

    // `noSSEHeader` and `serverMaxHeaderBytes` are deliberately absent. Both
    // are inbound/server-only in Xray: the former changes hub response
    // headers, while the latter caps listener request heads. The H1/H2 client
    // engines retain their independent defensive 10 MiB response-head cap.
    XhttpConfig::normalize(XhttpConfigInput {
        mode: xhttp_mode_selection(settings.mode),
        is_reality,
        path: settings.path.clone(),
        headers,
        x_padding_bytes: xhttp_range(settings.x_padding_bytes),
        x_padding_obfs_mode: settings.x_padding_obfs_mode,
        x_padding_key: settings.x_padding_key.clone(),
        x_padding_header: settings.x_padding_header.clone(),
        x_padding_placement: xhttp_padding_placement(settings.x_padding_placement),
        x_padding_method: xhttp_padding_method(settings.x_padding_method),
        uplink_http_method: settings.uplink_http_method.clone(),
        session_placement: xhttp_metadata_placement(settings.session_placement),
        session_key: settings.session_key.clone(),
        session_id_table: settings.session_id_table.clone(),
        session_id_length: xhttp_range(settings.session_id_length),
        seq_placement: xhttp_metadata_placement(settings.seq_placement),
        seq_key: settings.seq_key.clone(),
        uplink_data_placement: xhttp_uplink_data_placement(settings.uplink_data_placement),
        uplink_data_key: settings.uplink_data_key.clone(),
        uplink_chunk_size: xhttp_range(settings.uplink_chunk_size),
        no_grpc_header: settings.no_grpc_header,
        sc_max_each_post_bytes: xhttp_range(settings.sc_max_each_post_bytes),
        sc_min_posts_interval_ms: xhttp_range(settings.sc_min_posts_interval_ms),
        sc_max_buffered_posts: settings.sc_max_buffered_posts,
        sc_stream_up_server_secs: xhttp_range(settings.sc_stream_up_server_secs),
    })
    .map_err(invalid_xhttp_configuration)
}

fn invalid_xhttp_configuration(error: impl ToString) -> CoreError {
    CoreError::InvalidXhttpConfiguration(error.to_string())
}

/// Maps Xray's QUIC surface into the phase-one HTTP/3 engine.
///
/// Defaults remain usable and interoperable, with the engine's diagnostics
/// naming its fixed-window and Quinn-BBR performance approximations. Explicit
/// UDP hopping, debug side-effects, adaptive receive-window pairs,
/// non-standard BBR profiles and Brutal are retained by the parser but
/// rejected by `H3QuicConfig` (or here) until their runtime implementation
/// exists.
fn xhttp_h3_quic_config(settings: Option<&QuicParamsSettings>) -> Result<H3QuicConfig, CoreError> {
    let Some(settings) = settings else {
        return Ok(H3QuicConfig::default());
    };
    let mut config = H3QuicConfig::default();
    config.initial_stream_receive_window = quic_u64_or_default(
        "initStreamReceiveWindow",
        settings.init_stream_receive_window,
        config.initial_stream_receive_window,
    )?;
    config.max_stream_receive_window =
        quic_optional_u64("maxStreamReceiveWindow", settings.max_stream_receive_window)?;
    config.initial_connection_receive_window = quic_u64_or_default(
        "initConnectionReceiveWindow",
        settings.init_connection_receive_window,
        config.initial_connection_receive_window,
    )?;
    config.max_connection_receive_window = quic_optional_u64(
        "maxConnectionReceiveWindow",
        settings.max_connection_receive_window,
    )?;
    match settings.max_idle_timeout_secs {
        0 => {}
        value if value > 0 => {
            config.max_idle_timeout = Duration::from_secs(u64::try_from(value).map_err(|_| {
                CoreError::InvalidXhttpConfiguration(
                    "finalmask.quicParams.maxIdleTimeout is negative".to_owned(),
                )
            })?);
        }
        _ => {
            return Err(CoreError::InvalidXhttpConfiguration(
                "finalmask.quicParams.maxIdleTimeout is negative".to_owned(),
            ));
        }
    }
    config.keep_alive_interval = match settings.keep_alive_period_secs {
        0 => None,
        value if value > 0 => Some(Duration::from_secs(u64::try_from(value).map_err(|_| {
            CoreError::InvalidXhttpConfiguration(
                "finalmask.quicParams.keepAlivePeriod is negative".to_owned(),
            )
        })?)),
        _ => {
            return Err(CoreError::InvalidXhttpConfiguration(
                "finalmask.quicParams.keepAlivePeriod is negative".to_owned(),
            ));
        }
    };
    config.max_incoming_bidirectional_streams = quic_incoming_streams_or_default(
        "maxIncomingStreams",
        settings.max_incoming_streams,
        config.max_incoming_bidirectional_streams,
    )?;
    config.disable_path_mtu_discovery = settings.disable_path_mtu_discovery
        || !cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        ));
    config.congestion = match settings.congestion {
        xray_config::QuicCongestion::Reno => H3Congestion::Reno,
        xray_config::QuicCongestion::Brutal => H3Congestion::Brutal,
        xray_config::QuicCongestion::ForceBrutal => H3Congestion::ForceBrutal {
            bytes_per_second: settings.brutal_up_bytes_per_sec,
        },
        xray_config::QuicCongestion::Default | xray_config::QuicCongestion::Bbr => {
            match settings.bbr_profile {
                xray_config::QuicBbrProfile::Conservative => H3Congestion::BbrConservative,
                xray_config::QuicBbrProfile::Standard => H3Congestion::BbrStandard,
                xray_config::QuicBbrProfile::Aggressive => H3Congestion::BbrAggressive,
            }
        }
    };
    config.udp_hop = H3UdpHopConfig {
        ports: settings.udp_hop.ports.clone(),
        interval_min: quic_i32_seconds("udpHop.interval.from", settings.udp_hop.interval.from)?,
        interval_max: quic_i32_seconds("udpHop.interval.to", settings.udp_hop.interval.to)?,
    };
    config.debug = settings.debug;
    Ok(config)
}

const QUIC_VARINT_MAX: u64 = (1_u64 << 62) - 1;
const QUIC_MAX_STREAM_COUNT: u64 = 1_u64 << 60;

fn quic_u64_or_default(name: &'static str, value: u64, default: u64) -> Result<u64, CoreError> {
    if value == 0 {
        Ok(default)
    } else {
        quic_varint(name, value)
    }
}

fn quic_optional_u64(name: &'static str, value: u64) -> Result<Option<u64>, CoreError> {
    if value == 0 {
        Ok(None)
    } else {
        quic_varint(name, value).map(Some)
    }
}

fn quic_varint(name: &'static str, value: u64) -> Result<u64, CoreError> {
    if value <= QUIC_VARINT_MAX {
        Ok(value)
    } else {
        Err(CoreError::InvalidXhttpConfiguration(format!(
            "finalmask.quicParams.{name}={value} exceeds QUIC's 62-bit varint limit"
        )))
    }
}

fn quic_incoming_streams_or_default(
    name: &'static str,
    value: i64,
    default: u64,
) -> Result<u64, CoreError> {
    if value == 0 {
        return Ok(default);
    }
    let value = u64::try_from(value).map_err(|_| {
        CoreError::InvalidXhttpConfiguration(format!(
            "finalmask.quicParams.{name}={value} cannot be negative"
        ))
    })?;
    // quic-go clamps this transport parameter to the QUIC stream-count
    // domain during config validation. Mirror that instead of allowing Quinn
    // to emit a peer-invalid INITIAL_MAX_STREAMS value.
    Ok(value.min(QUIC_MAX_STREAM_COUNT))
}

fn quic_i32_seconds(name: &'static str, value: i32) -> Result<Duration, CoreError> {
    let value = u64::try_from(value).map_err(|_| {
        CoreError::InvalidXhttpConfiguration(format!(
            "finalmask.quicParams.{name}={value} cannot be negative"
        ))
    })?;
    Ok(Duration::from_secs(value))
}

fn xhttp_xmux_policy(settings: &XhttpSettings) -> XhttpXmuxPolicy {
    XhttpXmuxPolicy {
        max_concurrency: xhttp_range(settings.xmux.max_concurrency),
        max_connections: xhttp_range(settings.xmux.max_connections),
        c_max_reuse_times: xhttp_range(settings.xmux.c_max_reuse_times),
        h_max_request_times: xhttp_range(settings.xmux.h_max_request_times),
        h_max_reusable_secs: xhttp_range(settings.xmux.h_max_reusable_secs),
        h_keep_alive_period_secs: settings.xmux.h_keep_alive_period_secs,
    }
}

const fn xhttp_range(range: xray_config::XhttpRange) -> XhttpRange {
    XhttpRange {
        from: range.from,
        to: range.to,
    }
}

const fn xhttp_mode_selection(mode: xray_config::XhttpMode) -> XhttpModeSelection {
    match mode {
        xray_config::XhttpMode::Auto => XhttpModeSelection::Auto,
        xray_config::XhttpMode::PacketUp => XhttpModeSelection::PacketUp,
        xray_config::XhttpMode::StreamUp => XhttpModeSelection::StreamUp,
        xray_config::XhttpMode::StreamOne => XhttpModeSelection::StreamOne,
    }
}

const fn xhttp_padding_placement(
    placement: xray_config::XhttpPaddingPlacement,
) -> XhttpPaddingPlacement {
    match placement {
        xray_config::XhttpPaddingPlacement::Cookie => XhttpPaddingPlacement::Cookie,
        xray_config::XhttpPaddingPlacement::Header => XhttpPaddingPlacement::Header,
        xray_config::XhttpPaddingPlacement::Query => XhttpPaddingPlacement::Query,
        xray_config::XhttpPaddingPlacement::QueryInHeader => XhttpPaddingPlacement::QueryInHeader,
    }
}

const fn xhttp_padding_method(method: xray_config::XhttpPaddingMethod) -> XhttpPaddingMethod {
    match method {
        xray_config::XhttpPaddingMethod::RepeatX => XhttpPaddingMethod::RepeatX,
        xray_config::XhttpPaddingMethod::Tokenish => XhttpPaddingMethod::Tokenish,
    }
}

const fn xhttp_metadata_placement(
    placement: xray_config::XhttpPlacement,
) -> XhttpMetadataPlacement {
    match placement {
        xray_config::XhttpPlacement::Path => XhttpMetadataPlacement::Path,
        xray_config::XhttpPlacement::Cookie => XhttpMetadataPlacement::Cookie,
        xray_config::XhttpPlacement::Header => XhttpMetadataPlacement::Header,
        xray_config::XhttpPlacement::Query => XhttpMetadataPlacement::Query,
    }
}

const fn xhttp_uplink_data_placement(
    placement: xray_config::XhttpUplinkDataPlacement,
) -> XhttpUplinkDataPlacement {
    match placement {
        xray_config::XhttpUplinkDataPlacement::Auto => XhttpUplinkDataPlacement::Auto,
        xray_config::XhttpUplinkDataPlacement::Body => XhttpUplinkDataPlacement::Body,
        xray_config::XhttpUplinkDataPlacement::Cookie => XhttpUplinkDataPlacement::Cookie,
        xray_config::XhttpUplinkDataPlacement::Header => XhttpUplinkDataPlacement::Header,
    }
}

// The config keys the derived half of the `:authority` chain can come from, as
// `CoreError::UnrepresentableGrpcAuthority` names them.
//
// Spelled as the paths the config parser reports its own errors under — the
// address key verbatim (`crates/xray-config/src/parser.rs:2440`), and the TLS
// server name as the object path the parser uses plus the key it accepts
// inside it (`parser.rs:3211,3220`) — minus the `$.outbounds[N]` prefix this
// layer no longer knows, so the message is something to search a profile for
// rather than a description of it. `realitySettings.serverName` is not among
// them on purpose: `dial.go:162` never reads it, for the reason `grpc_authority`
// gives.
//
// `SERVER_ENDPOINT_KEYS` names a pair because the last-resort branch *composes*
// its value out of two keys, and printing one of them next to `例え.jp:443`
// would send the user looking for a `:443` that key does not hold.
const TLS_SERVER_NAME_KEY: &str = "streamSettings.tlsSettings.serverName";
const SERVER_ADDRESS_KEY: &str = "settings.vnext[0].address";
const SERVER_ENDPOINT_KEYS: &str = "settings.vnext[0].address and settings.vnext[0].port";

/// The `:authority` one gRPC outbound dials with.
///
/// Xray's chain is `grpcSettings.authority`, else `tlsSettings.serverName`,
/// else the destination *domain* and only when REALITY is absent, else the
/// empty string (`Xray-core/transport/internet/grpc/dial.go:159-167`).
///
/// **Three ways this differs from `build_transport_layer`'s `host_fallback`**,
/// which resolves the `Host` header for ws and httpupgrade and is the obvious
/// thing to reuse here:
///
/// * REALITY's server name is not in the chain. `dial.go:162` reads
///   `tlsConfig.ServerName`, and `tls.ConfigFromStreamSettings` returns nil for
///   a REALITY stream because the type assertion on `SecuritySettings` fails
///   (`transport/internet/tls/config.go:510-519`), so under REALITY the whole
///   branch is skipped rather than answered with the REALITY SNI.
/// * The destination branch needs the destination to be a domain. An IP one
///   leaves the authority empty even with no REALITY in sight.
/// * **The empty string is not an omitted header.** `initAuthority` walks past
///   the dial option to the transport credentials, and Xray's are
///   `insecure.NewCredentials()` (`dial.go:157`), whose `Info().ServerName` is
///   empty (`grpc@v1.81.0/credentials/insecure/insecure.go:51-53`); the
///   passthrough resolver is no `AuthorityOverrider` either, so the chain ends
///   at `encodeAuthority(endpoint)` (`clientconn.go:1976-1986`) over the target
///   Xray built as `passthrough:///host:port` (`dial.go:181-191`) — port
///   included. Verified on the wire against grpc-go v1.81.0 for a domain, an
///   IPv4 and an IPv6 destination. `encodeAuthority` leaves `:`, `[`, `]` and
///   `@` unescaped (`clientconn.go:1889-1942`), which is why an IPv6 literal
///   keeps its brackets instead of arriving as `%5B`. Under REALITY this
///   fallback is the default path, not an edge case.
///
/// **The parse is split between the configured value and the derived ones**,
/// because refusing an outbound over them is two different acts.
///
/// `grpcSettings.authority` is a string the user typed, and refusing it is the
/// better of two bad options: [`xray_transport::stream::GrpcConfig::authority`]
/// has the reasoning, which is that a `/` in it silently calls a gRPC method
/// nobody configured. They can fix what they typed.
///
/// The other three are values *we* derive on their behalf, and
/// `CoreError::InvalidGrpcAuthority` over one of those would blame a key their
/// config does not contain. They get
/// [`CoreError::UnrepresentableGrpcAuthority`], which names the key that
/// actually produced the value.
///
/// **Both still refuse, because nothing else is reachable.** An IDN
/// destination is the case that provokes the question — `Authority` rejects
/// every byte above `0x7f` (`http-1.5.0/src/uri/authority.rs:493-516`), and
/// grpc-go sends `例え.jp` verbatim, verified on the wire against v1.81.0 — and
/// none of the alternatives survive contact with it:
///
/// * **Falling through the chain does not rescue it, it moves it.** The step
///   after the destination domain is [`host_and_port`], which is that same
///   domain with a `:443` appended, so it fails identically. The step after
///   `tlsSettings.serverName` is the destination, which would answer — with a
///   *different* authority than Xray sends, on a stream whose TLS layer is
///   about to refuse the same name anyway (`TransportError::InvalidTlsServerName`).
///   Sending the wrong authority to buy one extra failed handshake is not a
///   trade worth making.
/// * **Carrying it as a `String` only relocates the refusal.** `h2` reads
///   `:authority` out of `Request::uri()` and nowhere else
///   (`h2-0.4.15/src/frame/headers.rs:561-604`, `src/client.rs:1604-1664`), and
///   an `http::Uri`'s authority *is* an [`Authority`]. A value this rejects is
///   one no request can carry, so the only thing deferring the parse buys is
///   the same failure once per dial, each behind a TCP connect and a TLS or
///   REALITY handshake.
/// * **Reproducing grpc-go's escaping does not help either.** `encodeAuthority`
///   percent-escapes the `host:port` fallback, so upstream really does put
///   `%E4%BE%8B%E3%81%88.jp:443` on the wire for an IDN destination under
///   REALITY — also verified — and that form is *pure ASCII*. It still will not
///   parse: `http` allows `%` only in userinfo or an IPv6 zone id and rejects
///   it in a host (`authority.rs:503-514,564-567`).
/// * **The IDNA A-label is the one form that would parse, and nothing here can
///   build it.** `Authority::try_from("xn--r8jz45g.jp")` is `Ok` where the raw
///   `例え.jp` is `InvalidUriChar` and grpc-go's escaping is
///   `InvalidAuthority`, all three checked against `http` 1.5.0 — so punycode
///   is a real escape hatch and it is still not reachable: no `idna` crate
///   appears anywhere in this workspace's dependency graph. Adding one to
///   convert silently would put an authority on the wire that upstream does
///   not send, and under TLS the same name is refused a layer down regardless,
///   since an IDN is not a rustls `ServerName` either
///   (`crates/xray-transport/src/tls.rs:220`). A profile that wants the
///   A-label can write it, and that already works.
///
/// So an IDN gRPC profile runs on xray-core and does not run here. That is a
/// real parity gap, and it is a property of `http`/`h2`, not of this function;
/// what this function owes the user is a message that names the address they
/// wrote instead of a key they did not.
fn grpc_authority(
    configured: Option<&str>,
    security: &StreamSecurity,
    server: &TargetAddr,
    port: u16,
) -> Result<Authority, CoreError> {
    // The config layer has already collapsed an empty `authority` to `None`,
    // matching Go's inability to tell one from an absent key.
    if let Some(configured) = configured {
        return Authority::try_from(configured)
            .map_err(|_| CoreError::InvalidGrpcAuthority(configured.to_owned()));
    }

    let (key, derived) = match configured_tls_server_name(security) {
        Some(server_name) => (TLS_SERVER_NAME_KEY, server_name.to_owned()),
        None => match server {
            TargetAddr::Domain(domain) if !matches!(security, StreamSecurity::Reality(_)) => {
                (SERVER_ADDRESS_KEY, domain.clone())
            }
            _ => (SERVER_ENDPOINT_KEYS, host_and_port(server, port)),
        },
    };

    Authority::try_from(derived.as_str()).map_err(|_| CoreError::UnrepresentableGrpcAuthority {
        key,
        value: derived,
    })
}

/// The `user-agent` one gRPC outbound sends, through Xray's keyword table.
///
/// A wrapper over [`resolve_user_agent`] and not much else: what it adds is the
/// error, and the error is the reason the resolution happens here rather than
/// at the dial. [`xray_transport::stream::GrpcConfig::user_agent`] has why the
/// value is refused at all — measured against grpc-go rather than reasoned
/// about, and the short version is that every value refused here is a value
/// whose every stream a grpc-go peer resets, so no profile that ran upstream
/// stops running.
///
/// **Only [`CoreError::InvalidGrpcUserAgent`] and no derived-value twin**,
/// which is where this parts company with [`grpc_authority`]. That chain has
/// two error variants because three of its four branches produce a value the
/// user never typed, and blaming `grpcSettings.authority` for the destination
/// address would send them looking for a key their config does not hold. This
/// one has no such branch: the three browser keywords resolve through the
/// masquerade table to printable ASCII and `golang` to the empty string, so
/// the only arm that can fail is the one that hands back the configured string
/// verbatim. Naming the key is therefore always right, and the value in the
/// message is always one they can search their profile for.
fn grpc_user_agent(configured: Option<&str>) -> Result<HeaderValue, CoreError> {
    resolve_user_agent(configured)
        .map_err(|_| CoreError::InvalidGrpcUserAgent(configured.unwrap_or_default().to_owned()))
}

/// `tlsSettings.serverName`, read from the config the way `dial.go:162` reads
/// it and not from the connector this outbound was built with.
///
/// The distinction has no effect on the resolved authority and every effect on
/// which key gets blamed for it. `ConnectorConfig::Tls::server_name` is already
/// the destination domain when the key is absent — `build_vless_tcp_outbound`
/// substitutes it — where Xray's `tls.ConfigFromStreamSettings` hands
/// `dial.go:162` the raw proto field, which is empty; the mutation that copies
/// the domain in happens later, inside the dial closure, on a `*gotls.Config`
/// the authority chain never sees (`dial.go:136-142`). Reading the connector
/// therefore answers branch 2 with a value upstream answers branch 3 with,
/// which is the same string, from a key the user may never have written. The
/// difference is only observable once that key reaches a message, which is the
/// last row of `a_derived_authority_is_not_refused_as_the_configured_one`.
///
/// The distinction becomes visible for a TLS stream over an IP destination:
/// the connector carries that IP for certificate-name verification, while
/// upstream gRPC still sees the raw absent/empty setting and falls through to
/// `host:port`. Reading this function from the config preserves that split.
fn configured_tls_server_name(security: &StreamSecurity) -> Option<&str> {
    match security {
        StreamSecurity::Tls(tls) => tls
            .server_name
            .as_deref()
            .filter(|server_name| !server_name.is_empty()),
        StreamSecurity::None | StreamSecurity::Reality(_) => None,
    }
}

/// grpc-go's resolver-endpoint fallback, i.e. Go's `net.JoinHostPort` over the
/// destination — which brackets an IPv6 literal, as `SocketAddr` does.
///
/// `to_canonical` is what makes the IPv4-mapped case agree: Go builds the host
/// from `dest.Address.IP().String()` (`dial.go:181-186`), and `net.IP.String`
/// writes a 16-byte address whose `To4()` matches as a dotted quad, where
/// Rust's `Display` would keep `::ffff:`. Both fold exactly the v4-mapped
/// prefix and nothing else, so the two agree everywhere once this is applied.
fn host_and_port(server: &TargetAddr, port: u16) -> String {
    match server {
        TargetAddr::Domain(domain) => format!("{domain}:{port}"),
        TargetAddr::Ip(ip) => SocketAddr::new(ip.to_canonical(), port).to_string(),
    }
}

#[cfg(test)]
fn build_tcp_outbound(outbound: &OutboundConfig) -> Result<TcpOutbound, CoreError> {
    if outbound.stream.network != Network::Tcp {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }

    match &outbound.settings {
        OutboundSettings::Dns(_) => Err(CoreError::NoSupportedOutbound),
        OutboundSettings::Freedom => {
            if !stream_transport_is_dialable(&outbound.stream) {
                return Err(CoreError::UnsupportedOutboundNetwork);
            }
            if outbound.stream.security != StreamSecurity::None {
                return Err(CoreError::UnsupportedOutboundSecurity);
            }
            Ok(build_freedom_tcp_outbound(&outbound.stream))
        }
        OutboundSettings::Vless(_) => build_vless_tcp_outbound(outbound)
            .map(|outbound| TcpOutbound::Vless(Box::new(outbound))),
    }
}

#[cfg(test)]
fn build_udp_outbound(outbound: &OutboundConfig) -> Result<UdpOutbound, CoreError> {
    match &outbound.settings {
        OutboundSettings::Dns(_) => Err(CoreError::NoSupportedOutbound),
        OutboundSettings::Freedom => {
            if !stream_transport_is_dialable(&outbound.stream) {
                return Err(CoreError::UnsupportedOutboundNetwork);
            }
            if outbound.stream.security != StreamSecurity::None {
                return Err(CoreError::UnsupportedOutboundSecurity);
            }
            Ok(UdpOutbound::Freedom)
        }
        OutboundSettings::Vless(_) => {
            if outbound.stream.network != Network::Tcp {
                return Err(CoreError::UnsupportedOutboundNetwork);
            }
            build_vless_tcp_outbound(outbound)
                .map(|outbound| UdpOutbound::Vless(Box::new(outbound)))
        }
    }
}

fn select_routed_target<'a>(
    routing: &'a RoutingConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_ip: Option<&IpAddr>,
    target_network: Option<Network>,
    target_port: Option<u16>,
) -> Option<&'a RoutingRuleTarget> {
    routing
        .rules
        .iter()
        .find(|rule| {
            rule.matches_target(
                inbound_tag,
                target_domain,
                target_ip,
                target_network,
                target_port,
            )
        })
        .map(|rule| &rule.target)
}

fn select_routed_target_with_resolved_ips<'a>(
    routing: &'a RoutingConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_addrs: &[SocketAddr],
    target_network: Option<Network>,
    target_port: Option<u16>,
) -> Option<&'a RoutingRuleTarget> {
    routing
        .rules
        .iter()
        .find(|rule| {
            target_addrs.iter().any(|target_addr| {
                rule.matches_target(
                    inbound_tag,
                    target_domain,
                    Some(&target_addr.ip()),
                    target_network,
                    target_port,
                )
            })
        })
        .map(|rule| &rule.target)
}

fn target_domain(target: &Target) -> Option<&str> {
    match &target.addr {
        RoutingTargetAddr::Domain(domain) => Some(domain.as_str()),
        RoutingTargetAddr::Ip(_) => None,
    }
}

fn target_ip(target: &Target) -> Option<&IpAddr> {
    match &target.addr {
        RoutingTargetAddr::Ip(ip) => Some(ip),
        RoutingTargetAddr::Domain(_) => None,
    }
}

fn target_network(target: &Target) -> Network {
    match target.network {
        RoutingNetwork::Tcp => Network::Tcp,
        RoutingNetwork::Udp => Network::Udp,
    }
}

fn build_vless_tcp_outbound(outbound: &OutboundConfig) -> Result<VlessTcpOutbound, CoreError> {
    if outbound.stream.network != Network::Tcp {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }

    let OutboundSettings::Vless(settings) = &outbound.settings else {
        return Err(CoreError::NoSupportedOutbound);
    };
    let user = settings
        .users
        .first()
        .cloned()
        .ok_or(CoreError::NoSupportedOutbound)?;
    validate_stream_flow(user.flow.as_deref(), &outbound.stream.security)?;

    let transport = match &outbound.stream.security {
        StreamSecurity::None => ConnectorConfig::Tcp,
        StreamSecurity::Tls(tls) => {
            let server_name = match tls.server_name.as_deref() {
                Some(name) if !name.is_empty() => name.to_owned(),
                Some(_) | None => match &settings.server {
                    TargetAddr::Domain(domain) => domain.clone(),
                    TargetAddr::Ip(ip) => ip.to_string(),
                },
            };

            ConnectorConfig::Tls(TlsClientConfig {
                server_name,
                allow_insecure: tls.allow_insecure,
                pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                alpn: tls.alpn.clone(),
                fingerprint: tls.fingerprint.clone(),
            })
        }
        StreamSecurity::Reality(reality) => ConnectorConfig::Reality(RealityClientConfig {
            server_name: reality.server_name.clone(),
            fingerprint: reality.fingerprint.clone(),
            public_key: reality.public_key,
            short_id: reality.short_id.as_slice().to_vec(),
            spider_x: reality.spider_x.clone(),
            mldsa65_verify: reality.mldsa65_verify.clone(),
        }),
    };

    let addr = match &settings.server {
        TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
        TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
    };

    Ok(VlessTcpOutbound {
        payload: Arc::new(VlessTcpOutboundPayload {
            server: Target::new(addr, settings.port, RoutingNetwork::Tcp),
            user,
            transport_layer: build_transport_layer(outbound, &transport)?,
            transport,
            happy_eyeballs: happy_eyeballs_config(&outbound.stream),
        }),
    })
}

fn build_freedom_tcp_outbound(stream: &StreamSettings) -> TcpOutbound {
    match happy_eyeballs_config(stream) {
        Some(config) => TcpOutbound::FreedomHappyEyeballs(config),
        None => TcpOutbound::Freedom,
    }
}

fn dns_tcp_connector(stream: &StreamSettings) -> Result<DnsTcpConnector, CoreError> {
    match &stream.security {
        StreamSecurity::None => Ok(DnsTcpConnector::Static(ConnectorConfig::Tcp)),
        StreamSecurity::Tls(tls) => match tls.server_name.as_deref() {
            Some(server_name) if !server_name.is_empty() => Ok(DnsTcpConnector::Static(
                ConnectorConfig::Tls(TlsClientConfig {
                    server_name: server_name.to_owned(),
                    allow_insecure: tls.allow_insecure,
                    pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                    verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                    alpn: tls.alpn.clone(),
                    fingerprint: tls.fingerprint.clone(),
                }),
            )),
            Some(_) | None => Ok(DnsTcpConnector::TlsFromTarget {
                allow_insecure: tls.allow_insecure,
                pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                alpn: tls.alpn.clone(),
                fingerprint: tls.fingerprint.clone(),
            }),
        },
        StreamSecurity::Reality(reality) => Ok(DnsTcpConnector::Static(ConnectorConfig::Reality(
            RealityClientConfig {
                server_name: reality.server_name.clone(),
                fingerprint: reality.fingerprint.clone(),
                public_key: reality.public_key,
                short_id: reality.short_id.as_slice().to_vec(),
                spider_x: reality.spider_x.clone(),
                mldsa65_verify: reality.mldsa65_verify.clone(),
            },
        ))),
    }
}

fn dns_happy_eyeballs_mode(stream: &StreamSettings) -> DnsHappyEyeballsMode {
    let Some(settings) = stream
        .socket_options
        .as_ref()
        .and_then(|socket_options| socket_options.happy_eyeballs.as_ref())
    else {
        return DnsHappyEyeballsMode::DnsDefault;
    };
    if settings.try_delay_ms == 0 || settings.max_concurrent_try == 0 {
        return DnsHappyEyeballsMode::Disabled;
    }
    happy_eyeballs_config(stream).map_or(DnsHappyEyeballsMode::Disabled, |config| {
        DnsHappyEyeballsMode::Configured(config)
    })
}

fn happy_eyeballs_config(stream: &StreamSettings) -> Option<HappyEyeballsConfig> {
    let settings = stream.socket_options.as_ref()?.happy_eyeballs.as_ref()?;
    if settings.try_delay_ms == 0 || settings.max_concurrent_try == 0 {
        return None;
    }

    let interleave = usize::try_from(settings.interleave).ok()?;
    let max_concurrent = usize::try_from(settings.max_concurrent_try).ok()?;
    let max_concurrent = NonZeroUsize::new(max_concurrent)?;

    Some(HappyEyeballsConfig {
        prioritize_ipv6: settings.prioritize_ipv6,
        interleave,
        try_delay: Duration::from_millis(settings.try_delay_ms),
        max_concurrent,
    })
}

fn validate_stream_flow(flow: Option<&str>, security: &StreamSecurity) -> Result<(), CoreError> {
    validate_vision_flow(
        flow,
        matches!(
            security,
            StreamSecurity::Tls(_) | StreamSecurity::Reality(_)
        ),
    )
    .map(|_| ())
}

fn validate_connector_flow(
    flow: Option<&str>,
    transport: &ConnectorConfig,
    stream_transport: &TransportLayer,
) -> Result<VisionFlow, CoreError> {
    // Vision splices itself into the security connection's internals, and every
    // non-raw transport implemented here wraps that connection instead of
    // handing it back, so Vision has nothing to splice into.
    //
    // Keying on the transport is narrower than xray-core's own rule rather than
    // a copy of it. `Process` asks whether the dialer returned the security
    // conn itself as `iConn` (`proxy/vless/outbound/outbound.go:268-285`), which
    // mKCP satisfies and raw with a `tcpSettings.header.type` authenticator does
    // not, and it skips the question entirely when VLESS `encryption` is on.
    // Neither divergence is reachable here — raw is the only dialer that hands
    // the conn back, and `encryption: "none"` is the only value we accept — so
    // the two rules agree on every profile we parse. See
    // `docs/config-compatibility.md` for the full account.
    if !matches!(stream_transport, TransportLayer::Raw) {
        return validate_vision_flow(flow, false);
    }

    validate_vision_flow(
        flow,
        matches!(
            transport,
            ConnectorConfig::Tls(_) | ConnectorConfig::Reality(_)
        ),
    )
}

fn validate_vision_flow(flow: Option<&str>, is_protected: bool) -> Result<VisionFlow, CoreError> {
    match flow {
        None => Ok(VisionFlow::None),
        Some(VISION_FLOW) if is_protected => Ok(VisionFlow::Vision),
        Some(VISION_UDP443_FLOW) if is_protected => Ok(VisionFlow::VisionUdp443),
        Some(_) => Err(CoreError::UnsupportedOutboundFlow),
    }
}

async fn resolve_server_candidates(
    server: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<Vec<SocketAddr>, CoreError> {
    match &server.addr {
        RoutingTargetAddr::Ip(ip) => Ok(vec![SocketAddr::new(*ip, server.port)]),
        RoutingTargetAddr::Domain(domain) => {
            let resolved = dns_resolver.resolve_all(domain, server.port).await?;
            Ok(resolved.socket_addrs().to_vec())
        }
    }
}

pub async fn open_vless_tcp_stream_with_resolver(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<BoxedTransportStream, CoreError> {
    let transport_dialer = TransportDialer::system()?;
    open_vless_tcp_stream_with_resolver_and_dialer(
        outbound,
        target,
        dns_resolver,
        &transport_dialer,
    )
    .await
}

pub async fn open_tcp_stream_with_resolver_and_dialer(
    outbound: &TcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    open_tcp_stream_with_resolvers_and_dialer(
        outbound,
        target,
        dns_resolver,
        dns_resolver,
        transport_dialer,
    )
    .await
}

pub(crate) async fn open_tcp_stream_with_resolvers_and_dialer(
    outbound: &TcpOutbound,
    target: &Target,
    destination_resolver: &dyn DnsResolver,
    bootstrap_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    if let TcpOutbound::Chained { outbound, proxy } = outbound {
        let proxy_dialer =
            prepare_outbound_proxy_dialer(proxy, bootstrap_resolver, transport_dialer).await?;
        return open_plain_tcp_stream_with_resolvers_and_dialer(
            outbound.primary(),
            target,
            destination_resolver,
            bootstrap_resolver,
            &proxy_dialer,
            proxy_chain_requires_local_resolution(proxy),
        )
        .await;
    }

    open_plain_tcp_stream_with_resolvers_and_dialer(
        outbound,
        target,
        destination_resolver,
        bootstrap_resolver,
        transport_dialer,
        true,
    )
    .await
}

async fn open_plain_tcp_stream_with_resolvers_and_dialer(
    outbound: &TcpOutbound,
    target: &Target,
    destination_resolver: &dyn DnsResolver,
    bootstrap_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
    requires_local_resolution: bool,
) -> Result<BoxedTransportStream, CoreError> {
    match outbound {
        TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => {
            let candidates = if requires_local_resolution {
                resolve_server_candidates(target, destination_resolver).await?
            } else {
                Vec::new()
            };
            Ok(transport_dialer
                .connect_resolved(
                    &ConnectorConfig::Tcp,
                    target,
                    &candidates,
                    outbound.freedom_happy_eyeballs(),
                )
                .await?)
        }
        TcpOutbound::Vless(outbound) if requires_local_resolution => {
            open_vless_tcp_stream_with_resolver_and_dialer(
                outbound,
                target,
                bootstrap_resolver,
                transport_dialer,
            )
            .await
        }
        TcpOutbound::Vless(outbound) => {
            open_vless_tcp_stream_with_resolved_server_and_dialer(
                outbound,
                target,
                &[],
                transport_dialer,
            )
            .await
        }
        TcpOutbound::Chained { .. } => {
            unreachable!("a chain wrapper is removed before opening its primary outbound")
        }
    }
}

pub async fn open_vless_tcp_stream_with_resolver_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    // Preserve the validation-before-I/O contract for direct VLESS opens. The
    // resolved-server helper repeats this check because chained opens enter it
    // directly with candidates supplied by the outer proxy dialer.
    validate_connector_flow(
        outbound.user().flow.as_deref(),
        outbound.transport(),
        outbound.transport_layer(),
    )?;
    let resolved_server = resolve_server_candidates(outbound.server(), dns_resolver).await?;
    open_vless_tcp_stream_with_resolved_server_and_dialer(
        outbound,
        target,
        &resolved_server,
        transport_dialer,
    )
    .await
}

async fn open_vless_tcp_stream_with_resolved_server_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    resolved_server: &[SocketAddr],
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    let flow = validate_connector_flow(
        outbound.user().flow.as_deref(),
        outbound.transport(),
        outbound.transport_layer(),
    )?;

    let mut stream = transport_dialer
        .connect_stream(
            outbound.transport(),
            outbound.transport_layer(),
            outbound.server(),
            resolved_server,
            outbound.happy_eyeballs(),
        )
        .await?;
    let request = VlessRequest {
        user_id: outbound.user().id,
        command: VlessCommand::Tcp,
        target: target.clone(),
        flow: flow.request_flow(),
    };
    let header = encode_request_header(&request)?;

    stream.write_all(&header).await?;

    if flow.uses_vision() {
        let stream = VlessResponseStream::new(VisionTransportStream::new(stream));
        let mut stream =
            VisionStream::new(stream, *outbound.user().id.as_bytes(), DEFAULT_VISION_SEED);
        stream.queue_empty_padding_frame()?;
        stream.flush().await?;
        return Ok(Box::new(VisionOutboundStream::new(stream)));
    }

    // Without Vision there is no direct mode, so the transport never needs
    // record-aligned reads.
    stream.release_record_alignment();
    let stream = VlessResponseStream::new(stream);
    Ok(Box::new(VlessOutboundStream::new(stream)))
}

pub async fn open_vless_udp_stream_with_resolver_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<(BoxedTransportStream, VlessUdpFraming), CoreError> {
    open_vless_udp_stream_with_resolver_dialer_and_options(
        outbound,
        target,
        dns_resolver,
        transport_dialer,
        VlessUdpOpenOptions::default(),
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VlessUdpOpenOptions {
    pub(crate) reject_udp443_for_regular_vision: bool,
}

impl Default for VlessUdpOpenOptions {
    fn default() -> Self {
        Self {
            reject_udp443_for_regular_vision: true,
        }
    }
}

pub(crate) async fn open_vless_udp_stream_with_resolver_dialer_and_options(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
    options: VlessUdpOpenOptions,
) -> Result<(BoxedTransportStream, VlessUdpFraming), CoreError> {
    let flow = validate_connector_flow(
        outbound.user().flow.as_deref(),
        outbound.transport(),
        outbound.transport_layer(),
    )?;
    let uses_vision = flow.uses_vision();
    if options.reject_udp443_for_regular_vision
        && uses_vision
        && !flow.allows_udp443()
        && is_udp443_target(target)
    {
        return Err(CoreError::VisionUdp443Rejected);
    }
    let uses_xudp = uses_vision || should_use_xudp_for_udp_target(target);

    let resolved_server = resolve_server_candidates(outbound.server(), dns_resolver).await?;
    let mut stream = transport_dialer
        .connect_stream(
            outbound.transport(),
            outbound.transport_layer(),
            outbound.server(),
            &resolved_server,
            outbound.happy_eyeballs(),
        )
        .await?;
    let request = VlessRequest {
        user_id: outbound.user().id,
        command: if uses_xudp {
            VlessCommand::Mux
        } else {
            VlessCommand::Udp
        },
        target: target.clone(),
        flow: flow.request_flow(),
    };
    let header = encode_request_header(&request)?;

    stream.write_all(&header).await?;

    if uses_vision {
        let stream = VlessResponseStream::new(VisionTransportStream::new(stream));
        return Ok((
            Box::new(VisionOutboundStream::new(VisionStream::new(
                stream,
                *outbound.user().id.as_bytes(),
                DEFAULT_VISION_SEED,
            ))),
            VlessUdpFraming::Xudp,
        ));
    }

    // Without Vision there is no direct mode, so the transport never needs
    // record-aligned reads.
    stream.release_record_alignment();
    let stream = VlessResponseStream::new(stream);
    if uses_xudp {
        return Ok((
            Box::new(VlessOutboundStream::new(stream)),
            VlessUdpFraming::Xudp,
        ));
    }

    Ok((
        Box::new(VlessOutboundStream::new(stream)),
        VlessUdpFraming::LengthPrefixed,
    ))
}

fn should_use_xudp_for_udp_target(target: &Target) -> bool {
    target.network == xray_routing::Network::Udp && target.port != 53 && target.port != 443
}

fn is_udp443_target(target: &Target) -> bool {
    target.network == xray_routing::Network::Udp && target.port == 443
}

pub async fn open_vless_tcp_stream(
    outbound: &VlessTcpOutbound,
    target: &Target,
) -> Result<BoxedTransportStream, CoreError> {
    open_vless_tcp_stream_with_resolver(outbound, target, &SystemDnsResolver).await
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::num::NonZeroUsize;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Notify;
    use uuid::Uuid;
    use xray_config::{
        compile_domain_matchers, DnsConfig, DnsServerConfig, DomainMatcher, DomainMatcherSet,
        GrpcSettings, HappyEyeballsSettings, HttpUpgradeSettings, IpCidr, IpMatcherSet,
        OutboundProxySettings, RealitySettings, RealityShortId, RoutingConfig,
        RoutingDomainStrategy, RoutingPortRange, RoutingRule, SocketOptions, StreamSettings,
        TlsSettings, VlessOutboundSettings, WebSocketSettings,
    };
    use xray_proxy::vless::{unpad_vision_block, VisionCommand};
    use xray_transport::{
        CachingDnsResolver, DnsLookup, RealityTlsEngine, ResolvedTcpConnector, TransportError,
    };

    use super::*;

    async fn read_vision_frame<R>(reader: &mut R, includes_user_id: bool) -> (Vec<u8>, usize, usize)
    where
        R: AsyncRead + Unpin,
    {
        let prefix_len = if includes_user_id { 16 + 5 } else { 5 };
        let header_offset = if includes_user_id { 16 } else { 0 };
        let mut frame = vec![0; prefix_len];
        reader
            .read_exact(&mut frame)
            .await
            .expect("read Vision frame header");

        let content_len =
            u16::from_be_bytes([frame[header_offset + 1], frame[header_offset + 2]]) as usize;
        let padding_len =
            u16::from_be_bytes([frame[header_offset + 3], frame[header_offset + 4]]) as usize;
        let mut body = vec![0; content_len + padding_len];
        reader
            .read_exact(&mut body)
            .await
            .expect("read Vision frame body");
        frame.extend_from_slice(&body);

        (frame, content_len, padding_len)
    }

    #[derive(Default)]
    struct RecordingTcpConnector {
        calls: AtomicUsize,
        peers: Mutex<Vec<tokio::io::DuplexStream>>,
    }

    #[async_trait]
    impl ResolvedTcpConnector for RecordingTcpConnector {
        async fn connect_resolved(
            &self,
            _original_target: &Target,
            _candidates: &[SocketAddr],
            _happy_eyeballs: Option<&HappyEyeballsConfig>,
        ) -> Result<BoxedTransportStream, TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (stream, peer) = tokio::io::duplex(4_096);
            self.peers.lock().unwrap().push(peer);
            Ok(Box::new(stream))
        }
    }

    fn direct_selection_freedom(tag: &str) -> OutboundConfig {
        OutboundConfig {
            tag: Some(tag.to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: None,
            },
            settings: OutboundSettings::Freedom,
        }
    }

    fn direct_selection_vless(tag: &str) -> OutboundConfig {
        OutboundConfig {
            tag: Some(tag.to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: None,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 443,
                users: vec![VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: None,
                    level: 0,
                }],
            }),
        }
    }

    fn dns_selection_outbound(tag: &str, settings: DnsOutboundSettings) -> OutboundConfig {
        OutboundConfig {
            tag: Some(tag.to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: None,
            },
            settings: OutboundSettings::Dns(settings),
        }
    }

    fn direct_selection_config() -> CoreConfig {
        CoreConfig {
            inbounds: Vec::new(),
            outbounds: vec![
                direct_selection_freedom("direct"),
                direct_selection_vless("proxy"),
            ],
            default_outbound_tag: Some("proxy".to_owned()),
            routing: RoutingConfig {
                rules: vec![RoutingRule {
                    inbound_tags: Vec::new(),
                    networks: Vec::new(),
                    port_ranges: Vec::new(),
                    domain_matchers: DomainMatcherSet::default(),
                    ip_matchers: Default::default(),
                    target: RoutingRuleTarget::Outbound("direct".to_owned()),
                }],
                ..Default::default()
            },
            observatory: None,
            dns: Default::default(),
            policy: Default::default(),
        }
    }

    #[derive(Debug)]
    struct FakeDnsResolver {
        result: Result<Vec<SocketAddr>, TransportError>,
        expected: Option<(&'static str, u16)>,
        calls: AtomicUsize,
    }

    impl FakeDnsResolver {
        fn resolving_to(addr: SocketAddr) -> Self {
            Self {
                result: Ok(vec![addr]),
                expected: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn resolving_to_many(addrs: Vec<SocketAddr>) -> Self {
            Self {
                result: Ok(addrs),
                expected: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn failing_with(error: TransportError) -> Self {
            Self {
                result: Err(error),
                expected: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn expect_lookup(mut self, domain: &'static str, port: u16) -> Self {
            self.expected = Some((domain, port));
            self
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn record_lookup(
            &self,
            domain: &str,
            port: u16,
        ) -> Result<Vec<SocketAddr>, TransportError> {
            if let Some((expected_domain, expected_port)) = self.expected {
                assert_eq!(domain, expected_domain);
                assert_eq!(port, expected_port);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.result {
                Ok(addrs) => Ok(addrs.clone()),
                Err(TransportError::NoResolvedAddress(domain, port)) => {
                    Err(TransportError::NoResolvedAddress(domain.clone(), *port))
                }
                Err(error) => panic!("fake resolver cannot clone transport error: {error}"),
            }
        }
    }

    #[async_trait]
    impl DnsResolver for FakeDnsResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            self.record_lookup(domain, port)?
                .into_iter()
                .next()
                .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
        }

        async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
            let addrs = self.record_lookup(domain, port)?;
            if addrs.is_empty() {
                return Err(TransportError::NoResolvedAddress(domain.to_owned(), port));
            }
            Ok(DnsLookup::new(addrs, None))
        }
    }

    struct PausedDnsResolver {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        result: SocketAddr,
    }

    #[async_trait]
    impl DnsResolver for PausedDnsResolver {
        async fn resolve(&self, _domain: &str, _port: u16) -> Result<SocketAddr, TransportError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(self.result)
        }

        async fn resolve_all(
            &self,
            _domain: &str,
            _port: u16,
        ) -> Result<DnsLookup, TransportError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(DnsLookup::new(vec![self.result], None))
        }
    }

    fn domain_tcp_target(domain: &str) -> Target {
        Target::new(
            RoutingTargetAddr::Domain(domain.to_owned()),
            443,
            RoutingNetwork::Tcp,
        )
    }

    fn ip_matcher_set(cidr: IpCidr) -> IpMatcherSet {
        let mut matchers = IpMatcherSet::builder();
        matchers.insert_cidr(cidr.cidr(), false);
        matchers.build()
    }

    fn ip_rule(tag: &str, ip: Ipv4Addr) -> RoutingRule {
        RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: DomainMatcherSet::default(),
            ip_matchers: ip_matcher_set(IpCidr::full(IpAddr::V4(ip))),
            target: RoutingRuleTarget::Outbound(tag.to_owned()),
        }
    }

    fn domain_and_ip_rule(tag: &str, domain: &str, ip: Ipv4Addr) -> RoutingRule {
        RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: compile_domain_matchers(&[DomainMatcher::Full(domain.to_owned())])
                .unwrap(),
            ip_matchers: ip_matcher_set(IpCidr::full(IpAddr::V4(ip))),
            target: RoutingRuleTarget::Outbound(tag.to_owned()),
        }
    }

    fn inbound_rule(inbound_tag: &str, outbound_tag: &str) -> RoutingRule {
        RoutingRule {
            inbound_tags: vec![inbound_tag.to_owned()],
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: DomainMatcherSet::default(),
            ip_matchers: Default::default(),
            target: RoutingRuleTarget::Outbound(outbound_tag.to_owned()),
        }
    }

    fn network_port_rule(
        outbound_tag: &str,
        network: Network,
        port_range: RoutingPortRange,
    ) -> RoutingRule {
        RoutingRule {
            inbound_tags: Vec::new(),
            networks: vec![network],
            port_ranges: vec![port_range],
            domain_matchers: DomainMatcherSet::default(),
            ip_matchers: Default::default(),
            target: RoutingRuleTarget::Outbound(outbound_tag.to_owned()),
        }
    }

    #[test]
    fn outbound_router_tcp_session_selector_matches_target_network_and_port() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Tcp,
            RoutingPortRange::single(443),
        )];
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_tcp_outbound_for_session(None, &domain_tcp_target("example.test"))
            .expect("select target-aware TCP route");

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn outbound_router_udp_session_selector_matches_target_network_and_port() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Udp,
            RoutingPortRange::new(53, 5353).expect("valid test port range"),
        )];
        let router = OutboundRouter::new(Arc::new(config));
        let target = Target::new(
            RoutingTargetAddr::Domain("example.test".to_owned()),
            53,
            RoutingNetwork::Udp,
        );

        let selected = router
            .select_udp_outbound_for_session(None, &target)
            .expect("select target-aware UDP route");

        assert!(matches!(selected, UdpOutbound::Freedom));
    }

    #[test]
    fn outbound_router_selects_and_caches_dns_message_handler() {
        let mut config = direct_selection_config();
        config.outbounds.push(dns_selection_outbound(
            "dns-out",
            DnsOutboundSettings {
                rewrite_network: Some(Network::Tcp),
                rewrite_address: Some(TargetAddr::Domain("resolver.example".to_owned())),
                rewrite_port: 5353,
                ..DnsOutboundSettings::default()
            },
        ));
        config.routing.rules = vec![network_port_rule(
            "dns-out",
            Network::Udp,
            RoutingPortRange::single(53),
        )];
        let router = OutboundRouter::new(Arc::new(config));
        let original = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
            53,
            RoutingNetwork::Udp,
        );

        let first = router
            .select_dns_outbound_for_session(Some("tun-in"), &original)
            .expect("select DNS outbound")
            .expect("DNS handler should be selected");
        let second = router
            .select_dns_outbound_for_session(Some("tun-in"), &original)
            .expect("select cached DNS outbound")
            .expect("DNS handler should remain selected");

        assert!(Arc::ptr_eq(&first.payload, &second.payload));
        assert_eq!(
            first.rewrite_target(&original),
            Target::new(
                RoutingTargetAddr::Domain("resolver.example".to_owned()),
                5353,
                RoutingNetwork::Tcp,
            )
        );
    }

    #[test]
    fn dns_outbound_compiles_tls_and_derives_an_omitted_sni_from_target() {
        let explicit = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Tls(TlsSettings {
                    server_name: Some("resolver.example".to_owned()),
                    fingerprint: None,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: vec![[0x11; 32]],
                    verify_peer_cert_by_name: vec!["resolver-cert.example".to_owned()],
                    alpn: Vec::new(),
                }),
                quic_params: None,
                socket_options: None,
            },
            Duration::from_secs(60),
        )
        .expect("compile explicit DNS TLS transport");
        let target = Target::new(
            RoutingTargetAddr::Domain("rewritten.example".to_owned()),
            853,
            RoutingNetwork::Tcp,
        );
        assert_eq!(
            explicit
                .tcp_connector_for(&target)
                .expect("build explicit DNS connector"),
            ConnectorConfig::Tls(TlsClientConfig {
                server_name: "resolver.example".to_owned(),
                allow_insecure: false,
                pinned_peer_cert_sha256: vec![[0x11; 32]],
                verify_peer_cert_by_name: vec!["resolver-cert.example".to_owned()],
                alpn: Vec::new(),
                fingerprint: None,
            })
        );
        assert!(!explicit.supports_direct_udp());

        for server_name in [None, Some(String::new())] {
            let dynamic = DnsOutbound::new_with_stream(
                DnsOutboundSettings::default(),
                &StreamSettings {
                    network: Network::Tcp,
                    transport: StreamTransport::Raw,
                    security: StreamSecurity::Tls(TlsSettings {
                        server_name,
                        fingerprint: None,
                        allow_insecure: false,
                        pinned_peer_cert_sha256: vec![[0x22; 32]],
                        verify_peer_cert_by_name: vec!["dynamic-cert.example".to_owned()],
                        alpn: Vec::new(),
                    }),
                    quic_params: None,
                    socket_options: None,
                },
                Duration::from_secs(60),
            )
            .expect("compile target-derived DNS TLS transport");
            assert_eq!(
                dynamic
                    .tcp_connector_for(&target)
                    .expect("derive DNS TLS connector"),
                ConnectorConfig::Tls(TlsClientConfig {
                    server_name: "rewritten.example".to_owned(),
                    allow_insecure: false,
                    pinned_peer_cert_sha256: vec![[0x22; 32]],
                    verify_peer_cert_by_name: vec!["dynamic-cert.example".to_owned()],
                    alpn: Vec::new(),
                    fingerprint: None,
                })
            );
        }
    }

    #[test]
    fn tls_outbound_carries_the_tls_shape_into_the_static_dns_connector() {
        let stream = StreamSettings {
            network: Network::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::Tls(TlsSettings {
                server_name: Some("example.com".to_owned()),
                fingerprint: Some("firefox".to_owned()),
                allow_insecure: false,
                pinned_peer_cert_sha256: vec![[0x33; 32]],
                verify_peer_cert_by_name: vec!["cert.example".to_owned()],
                alpn: vec!["http/1.1".to_owned()],
            }),
            quic_params: None,
            socket_options: None,
        };

        let connector = dns_tcp_connector(&stream).expect("a TLS fingerprint must be accepted");

        let DnsTcpConnector::Static(ConnectorConfig::Tls(tls)) = connector else {
            panic!("expected a static TLS connector");
        };
        assert_eq!(tls.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(tls.pinned_peer_cert_sha256, vec![[0x33; 32]]);
        assert_eq!(tls.verify_peer_cert_by_name, ["cert.example"]);
        assert_eq!(tls.alpn, vec!["http/1.1".to_owned()]);
    }

    #[test]
    fn target_derived_dns_tls_connector_carries_the_full_tls_shape() {
        // An omitted server name defers the whole config to dial time, so the
        // shape has to survive the deferral, not just the static branch.
        let outbound = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Tls(TlsSettings {
                    server_name: None,
                    fingerprint: Some("firefox".to_owned()),
                    allow_insecure: false,
                    pinned_peer_cert_sha256: vec![[0x44; 32]],
                    verify_peer_cert_by_name: vec!["cert.example".to_owned()],
                    alpn: vec!["h2".to_owned()],
                }),
                quic_params: None,
                socket_options: None,
            },
            Duration::from_secs(60),
        )
        .expect("a TLS fingerprint must be accepted");

        assert_eq!(
            outbound
                .tcp_connector_for(&domain_tcp_target("rewritten.example"))
                .expect("derive DNS TLS connector"),
            ConnectorConfig::Tls(TlsClientConfig {
                server_name: "rewritten.example".to_owned(),
                allow_insecure: false,
                pinned_peer_cert_sha256: vec![[0x44; 32]],
                verify_peer_cert_by_name: vec!["cert.example".to_owned()],
                alpn: vec!["h2".to_owned()],
                fingerprint: Some("firefox".to_owned()),
            })
        );
    }

    #[test]
    fn vless_tls_carries_pins_and_derives_dns_or_ip_verification_name() {
        for (server, configured_name, expected_name) in [
            (
                TargetAddr::Domain("origin.example".to_owned()),
                None,
                "origin.example",
            ),
            (
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                Some(String::new()),
                "127.0.0.1",
            ),
        ] {
            let mut outbound = direct_selection_vless("proxy");
            let OutboundSettings::Vless(settings) = &mut outbound.settings else {
                panic!("expected VLESS settings");
            };
            settings.server = server;
            outbound.stream.security = StreamSecurity::Tls(TlsSettings {
                server_name: configured_name,
                fingerprint: Some("unsafe".to_owned()),
                pinned_peer_cert_sha256: vec![[0x55; 32]],
                verify_peer_cert_by_name: vec!["cert.example".to_owned()],
                allow_insecure: false,
                alpn: vec!["h2".to_owned()],
            });

            let built = build_vless_tcp_outbound(&outbound).expect("build pinned VLESS TLS");
            assert_eq!(
                built.transport(),
                &ConnectorConfig::Tls(TlsClientConfig {
                    server_name: expected_name.to_owned(),
                    allow_insecure: false,
                    pinned_peer_cert_sha256: vec![[0x55; 32]],
                    verify_peer_cert_by_name: vec!["cert.example".to_owned()],
                    alpn: vec!["h2".to_owned()],
                    fingerprint: Some("unsafe".to_owned()),
                })
            );
        }
    }

    #[test]
    fn dns_outbound_rejects_an_unsupported_stream_network_instead_of_downgrading() {
        let non_tcp = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Udp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: None,
            },
            Duration::from_secs(60),
        )
        .expect("UDP stream settings remain usable for a UDP Direct target");
        assert!(non_tcp.supports_direct_udp());
        let error = non_tcp
            .tcp_connector_for(&domain_tcp_target("resolver.example"))
            .expect_err("unsupported DNS stream network must fail closed for TCP");
        assert!(matches!(error, CoreError::UnsupportedOutboundNetwork));
    }

    #[test]
    fn dns_outbound_preserves_reality_and_happy_eyeballs_modes() {
        let reality = RealitySettings {
            server_name: "reality.example".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [7; 32],
            short_id: RealityShortId::try_from_slice(&[1, 2, 3, 4])
                .expect("valid Reality short id"),
            spider_x: "/dns".to_owned(),
            mldsa65_verify: Some(vec![5, 6]),
        };
        let configured = HappyEyeballsConfig {
            prioritize_ipv6: true,
            interleave: 2,
            try_delay: Duration::from_millis(125),
            max_concurrent: NonZeroUsize::new(3).expect("nonzero test concurrency"),
        };
        let outbound = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Reality(reality.clone()),
                quic_params: None,
                socket_options: Some(SocketOptions {
                    happy_eyeballs: Some(HappyEyeballsSettings {
                        prioritize_ipv6: configured.prioritize_ipv6,
                        interleave: u32::try_from(configured.interleave)
                            .expect("bounded test interleave"),
                        try_delay_ms: u64::try_from(configured.try_delay.as_millis())
                            .expect("bounded test delay"),
                        max_concurrent_try: u32::try_from(configured.max_concurrent.get())
                            .expect("bounded test concurrency"),
                    }),
                }),
            },
            Duration::from_secs(60),
        )
        .expect("compile DNS Reality transport");
        let target = domain_tcp_target("rewritten.example");
        assert_eq!(
            outbound
                .tcp_connector_for(&target)
                .expect("build DNS Reality connector"),
            ConnectorConfig::Reality(RealityClientConfig {
                server_name: reality.server_name,
                fingerprint: reality.fingerprint,
                public_key: reality.public_key,
                short_id: reality.short_id.as_slice().to_vec(),
                spider_x: reality.spider_x,
                mldsa65_verify: reality.mldsa65_verify,
            })
        );
        assert_eq!(
            outbound.happy_eyeballs_mode(),
            DnsHappyEyeballsMode::Configured(configured)
        );

        let absent = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: None,
            },
            Duration::from_secs(60),
        )
        .expect("compile default DNS transport");
        assert_eq!(
            absent.happy_eyeballs_mode(),
            DnsHappyEyeballsMode::DnsDefault
        );

        let disabled = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: Some(SocketOptions {
                    happy_eyeballs: Some(HappyEyeballsSettings::default()),
                }),
            },
            Duration::from_secs(60),
        )
        .expect("compile explicitly disabled DNS Happy Eyeballs");
        assert_eq!(
            disabled.happy_eyeballs_mode(),
            DnsHappyEyeballsMode::Disabled
        );
    }

    #[test]
    fn dns_outbound_runtime_identity_is_shared_only_by_clones() {
        let plain = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: None,
            },
            Duration::from_secs(60),
        )
        .expect("compile plain DNS outbound");
        let plain_clone = plain.clone();
        let tls = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Tls(TlsSettings {
                    server_name: Some("resolver.example".to_owned()),
                    fingerprint: None,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn: Vec::new(),
                }),
                quic_params: None,
                socket_options: None,
            },
            Duration::from_secs(60),
        )
        .expect("compile TLS DNS outbound");

        assert_eq!(plain.runtime_identity(), plain_clone.runtime_identity());
        assert_ne!(plain.runtime_identity(), tls.runtime_identity());
    }

    #[test]
    fn dns_selector_prefilter_rejects_mismatched_network_and_port() {
        let mut config = direct_selection_config();
        config.outbounds.push(dns_selection_outbound(
            "dns-out",
            DnsOutboundSettings::default(),
        ));
        config.routing.rules = vec![network_port_rule(
            "dns-out",
            Network::Udp,
            RoutingPortRange::single(53),
        )];
        let router = OutboundRouter::new(Arc::new(config));
        let tcp_target = domain_tcp_target("example.test");
        let udp_target = Target::new(
            RoutingTargetAddr::Domain("example.test".to_owned()),
            443,
            RoutingNetwork::Udp,
        );

        assert!(!router.may_select_dns_outbound(None, &tcp_target));
        assert!(!router.may_select_dns_outbound(None, &udp_target));
        assert!(router
            .select_dns_outbound_for_session(None, &udp_target)
            .expect("mismatched DNS route should preserve the regular path")
            .is_none());
    }

    #[test]
    fn dns_selector_prefilter_matches_only_the_configured_inbound_tag() {
        let mut config = direct_selection_config();
        config.outbounds.push(dns_selection_outbound(
            "dns-out",
            DnsOutboundSettings::default(),
        ));
        let mut rule = network_port_rule("dns-out", Network::Udp, RoutingPortRange::single(53));
        rule.inbound_tags = vec!["tun-in".to_owned()];
        config.routing.rules = vec![rule];
        let router = OutboundRouter::new(Arc::new(config));
        let target = Target::new(
            RoutingTargetAddr::Domain("example.test".to_owned()),
            53,
            RoutingNetwork::Udp,
        );

        assert!(router.may_select_dns_outbound(Some("tun-in"), &target));
        assert!(!router.may_select_dns_outbound(Some("socks-in"), &target));
        assert!(!router.may_select_dns_outbound(None, &target));
    }

    #[test]
    fn dns_selector_prefilter_merges_large_adjacent_rule_sets() {
        let mut config = direct_selection_config();
        config.outbounds.push(dns_selection_outbound(
            "dns-out",
            DnsOutboundSettings::default(),
        ));
        config.routing.rules = (0..4_096)
            .map(|offset| {
                network_port_rule(
                    "dns-out",
                    Network::Udp,
                    RoutingPortRange::single(10_000 + offset),
                )
            })
            .collect();
        let router = OutboundRouter::new(Arc::new(config));
        let policy = router.routing_policy_state();
        let udp_ranges = &policy.dns_route_prefilter.network_ports.udp;

        assert_eq!(
            udp_ranges.as_ref(),
            &[DnsRoutePortRange {
                start: 10_000,
                end: 14_095,
            }]
        );
    }

    #[test]
    fn dns_selector_prefilter_does_not_multiply_tags_by_port_ranges() {
        const SELECTOR_COUNT: usize = 2_048;

        let mut config = direct_selection_config();
        config.outbounds.push(dns_selection_outbound(
            "dns-out",
            DnsOutboundSettings::default(),
        ));
        let mut inbound_tags = (0..SELECTOR_COUNT)
            .map(|index| format!("dns-in-{index}"))
            .collect::<Vec<_>>();
        inbound_tags.extend(inbound_tags.clone());
        config.routing.rules = vec![RoutingRule {
            inbound_tags,
            networks: vec![Network::Udp],
            port_ranges: (0..SELECTOR_COUNT)
                .map(|index| {
                    RoutingPortRange::single(
                        u16::try_from(index * 2).expect("test port must fit in u16"),
                    )
                })
                .collect(),
            domain_matchers: DomainMatcherSet::default(),
            ip_matchers: Default::default(),
            target: RoutingRuleTarget::Outbound("dns-out".to_owned()),
        }];

        let router = OutboundRouter::new(Arc::new(config));
        let policy = router.routing_policy_state();

        assert!(!policy.dns_route_prefilter.wildcard_inbound);
        assert_eq!(
            policy.dns_route_prefilter.tagged_inbounds.len(),
            SELECTOR_COUNT
        );
        assert_eq!(
            policy.dns_route_prefilter.network_ports.udp.len(),
            SELECTOR_COUNT
        );
        assert!(policy.dns_route_prefilter.network_ports.tcp.is_empty());
    }

    #[test]
    fn dns_selector_prefilter_keeps_domain_matching_conservative() {
        let mut config = direct_selection_config();
        config.outbounds.push(dns_selection_outbound(
            "dns-out",
            DnsOutboundSettings::default(),
        ));
        config.default_outbound_tag = Some("direct".to_owned());
        let mut rule = network_port_rule("dns-out", Network::Udp, RoutingPortRange::single(53));
        rule.domain_matchers =
            compile_domain_matchers(&[DomainMatcher::Full("dns-only.test".to_owned())]).unwrap();
        config.routing.rules = vec![rule];
        let router = OutboundRouter::new(Arc::new(config));
        let target = Target::new(
            RoutingTargetAddr::Domain("other.test".to_owned()),
            53,
            RoutingNetwork::Udp,
        );

        assert!(router.may_select_dns_outbound(None, &target));
        assert!(router
            .select_dns_outbound_for_session(None, &target)
            .expect("conservative prefilter should fall through to the regular outbound")
            .is_none());
    }

    #[tokio::test]
    async fn dns_selector_ip_if_non_match_can_route_away_from_dns_default() {
        let resolved_ip = Ipv4Addr::new(203, 0, 113, 17);
        let mut config = direct_selection_config();
        config.outbounds.push(dns_selection_outbound(
            "dns-out",
            DnsOutboundSettings::default(),
        ));
        config.default_outbound_tag = Some("dns-out".to_owned());
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![ip_rule("direct", resolved_ip)];
        let router = OutboundRouter::new(Arc::new(config));
        let resolver = FakeDnsResolver::resolving_to(SocketAddr::from((resolved_ip, 443)))
            .expect_lookup("example.test", 443);

        let selected = router
            .select_dns_outbound_for_session_with_resolver(
                None,
                &domain_tcp_target("example.test"),
                &resolver,
            )
            .await
            .expect("resolved-IP route should select a regular outbound");

        assert!(selected.is_none());
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn dns_selector_returns_none_for_regular_selected_outbound() {
        let router = OutboundRouter::new(Arc::new(direct_selection_config()));

        let selected = router
            .select_dns_outbound_for_session(None, &domain_tcp_target("example.test"))
            .expect("regular outbound selection should succeed");

        assert!(selected.is_none());
    }

    #[test]
    fn dns_selector_treats_an_empty_outbound_set_as_no_optional_handler() {
        let mut config = direct_selection_config();
        config.outbounds.clear();
        config.default_outbound_tag = None;
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_dns_outbound_for_session(None, &domain_tcp_target("example.test"))
            .expect("empty outbound set should preserve an existing local DNS mode");

        assert!(selected.is_none());
    }

    #[test]
    fn dns_selector_does_not_hide_a_missing_configured_outbound_tag() {
        let mut config = direct_selection_config();
        config.default_outbound_tag = Some("missing".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));

        let error = router
            .select_dns_outbound_for_session(None, &domain_tcp_target("example.test"))
            .expect_err("missing selected tag must fail closed");

        assert!(matches!(error, CoreError::NoSupportedOutbound));
    }

    #[test]
    fn managed_dns_client_tag_uses_effective_global_tag() {
        let mut config = direct_selection_config();
        config.dns = DnsConfig {
            servers: vec![DnsServerConfig::Ip(SocketAddr::from((
                Ipv4Addr::new(192, 0, 2, 53),
                53,
            )))],
            tag: "managed-dns".to_owned(),
            ..DnsConfig::default()
        };
        let router = OutboundRouter::new(Arc::new(config));

        assert!(router.is_dns_client_tag(Some("managed-dns")));
        assert!(!router.is_dns_client_tag(Some("tun-in")));
        assert!(!router.is_dns_client_tag(None));
    }

    #[test]
    fn outbound_router_session_selector_rejects_target_network_mismatch() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Tcp,
            RoutingPortRange::single(53),
        )];
        let router = OutboundRouter::new(Arc::new(config));
        let target = Target::new(
            RoutingTargetAddr::Domain("example.test".to_owned()),
            53,
            RoutingNetwork::Udp,
        );

        let selected = router
            .select_udp_outbound_for_session(None, &target)
            .expect("network mismatch should use the default route");

        assert!(matches!(selected, UdpOutbound::Vless(_)));
    }

    #[test]
    fn outbound_router_session_selector_rejects_target_port_mismatch() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Tcp,
            RoutingPortRange::new(80, 443).expect("valid test port range"),
        )];
        let router = OutboundRouter::new(Arc::new(config));
        let target = Target::new(
            RoutingTargetAddr::Domain("example.test".to_owned()),
            444,
            RoutingNetwork::Tcp,
        );

        let selected = router
            .select_tcp_outbound_for_session(None, &target)
            .expect("port mismatch should use the default route");

        assert!(matches!(selected, TcpOutbound::Vless(_)));
    }

    #[test]
    fn outbound_router_selector_without_target_ignores_network_and_port_rule() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Tcp,
            RoutingPortRange::single(443),
        )];
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_tcp_outbound()
            .expect("targetless router selection should use the configured default route");

        assert!(matches!(selected, TcpOutbound::Vless(_)));
    }

    #[test]
    fn outbound_router_tagged_selector_matches_target_network_and_port() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Tcp,
            RoutingPortRange::single(443),
        )];
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_tcp_outbound_for_session_with_tag(
                None,
                &domain_tcp_target("example.test"),
                true,
            )
            .expect("select tagged target-aware route");

        assert_eq!(selected.tag.as_deref(), Some("direct"));
    }

    #[test]
    fn outbound_router_direct_selector_uses_explicit_tag() {
        let router = OutboundRouter::new(Arc::new(direct_selection_config()));
        let selected = router.select_tcp_outbound_direct(Some("direct")).unwrap();

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn explicit_happy_eyeballs_settings_are_compiled_for_freedom() {
        let mut configured = direct_selection_freedom("direct");
        configured.stream.socket_options = Some(SocketOptions {
            happy_eyeballs: Some(HappyEyeballsSettings {
                prioritize_ipv6: true,
                interleave: 2,
                try_delay_ms: 175,
                max_concurrent_try: 3,
            }),
        });

        let TcpOutbound::FreedomHappyEyeballs(compiled) =
            build_tcp_outbound(&configured).expect("compile freedom outbound")
        else {
            panic!("explicit Happy Eyeballs settings should enable candidate racing");
        };

        assert!(compiled.prioritize_ipv6);
        assert_eq!(compiled.interleave, 2);
        assert_eq!(compiled.try_delay, Duration::from_millis(175));
        assert_eq!(compiled.max_concurrent.get(), 3);
    }

    #[test]
    fn zero_happy_eyeballs_delay_preserves_legacy_freedom_variant() {
        let mut configured = direct_selection_freedom("direct");
        configured.stream.socket_options = Some(SocketOptions {
            happy_eyeballs: Some(HappyEyeballsSettings {
                try_delay_ms: 0,
                ..HappyEyeballsSettings::default()
            }),
        });

        let compiled = build_tcp_outbound(&configured).expect("compile freedom outbound");

        assert!(matches!(compiled, TcpOutbound::Freedom));
    }

    #[test]
    fn explicit_happy_eyeballs_settings_are_compiled_for_vless_carrier() {
        let mut configured = direct_selection_vless("proxy");
        configured.stream.socket_options = Some(SocketOptions {
            happy_eyeballs: Some(HappyEyeballsSettings {
                prioritize_ipv6: false,
                interleave: 3,
                try_delay_ms: 250,
                max_concurrent_try: 5,
            }),
        });

        let TcpOutbound::Vless(outbound) =
            build_tcp_outbound(&configured).expect("compile VLESS outbound")
        else {
            panic!("configured outbound should remain VLESS");
        };
        let compiled = outbound
            .happy_eyeballs()
            .expect("VLESS carrier should retain Happy Eyeballs settings");

        assert_eq!(compiled.interleave, 3);
        assert_eq!(compiled.try_delay, Duration::from_millis(250));
        assert_eq!(compiled.max_concurrent.get(), 5);
    }

    #[tokio::test]
    async fn freedom_happy_eyeballs_falls_back_to_second_resolved_candidate() {
        let refused_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind refused candidate reservation");
        let refused = refused_listener
            .local_addr()
            .expect("read refused candidate address");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind successful candidate");
        let successful = listener.local_addr().expect("read listener address");
        drop(refused_listener);
        let resolver = FakeDnsResolver::resolving_to_many(vec![refused, successful])
            .expect_lookup("multi.example", 443);
        let outbound = TcpOutbound::FreedomHappyEyeballs(HappyEyeballsConfig {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay: Duration::from_secs(30),
            max_concurrent: NonZeroUsize::new(2).expect("non-zero test concurrency"),
        });
        let target = domain_tcp_target("multi.example");
        let dialer = TransportDialer::system().expect("build transport dialer");

        let (opened, accepted) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                open_tcp_stream_with_resolver_and_dialer(&outbound, &target, &resolver, &dialer,),
                listener.accept(),
            )
        })
        .await
        .expect("fast failure should accelerate the next candidate");

        let _stream = opened.expect("connect to second resolved candidate");
        let (_accepted, _peer) = accepted.expect("accept fallback connection");
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test]
    async fn vless_tcp_carrier_falls_back_to_second_resolved_candidate() {
        let refused_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind refused candidate reservation");
        let refused = refused_listener
            .local_addr()
            .expect("read refused candidate address");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind successful candidate");
        let successful = listener.local_addr().expect("read listener address");
        drop(refused_listener);
        let resolver = FakeDnsResolver::resolving_to_many(vec![refused, successful])
            .expect_lookup("proxy.example", 443);
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                server: domain_tcp_target("proxy.example"),
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: None,
                    level: 0,
                },
                transport: ConnectorConfig::Tcp,
                transport_layer: TransportLayer::Raw,
                happy_eyeballs: Some(HappyEyeballsConfig {
                    prioritize_ipv6: false,
                    interleave: 1,
                    try_delay: Duration::from_secs(30),
                    max_concurrent: NonZeroUsize::new(2).expect("non-zero test concurrency"),
                }),
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Domain("destination.example".to_owned()),
            80,
            RoutingNetwork::Tcp,
        );
        let dialer = TransportDialer::system().expect("build transport dialer");

        let (opened, accepted) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                open_vless_tcp_stream_with_resolver_and_dialer(
                    &outbound, &target, &resolver, &dialer,
                ),
                listener.accept(),
            )
        })
        .await
        .expect("fast failure should accelerate the next VLESS carrier candidate");

        let _stream = opened.expect("open VLESS carrier through second candidate");
        let (mut accepted, _peer) = accepted.expect("accept VLESS fallback connection");
        let expected = encode_request_header(&VlessRequest {
            user_id: outbound.user().id,
            command: VlessCommand::Tcp,
            target,
            flow: None,
        })
        .expect("encode expected VLESS request");
        let mut received = vec![0; expected.len()];
        accepted
            .read_exact(&mut received)
            .await
            .expect("read VLESS request from fallback connection");
        assert_eq!(received, expected);
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn outbound_graph_preserves_order_kind_first_tag_and_default_identity() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_freedom("duplicate"),
            direct_selection_vless("duplicate"),
            dns_selection_outbound("dns-out", DnsOutboundSettings::default()),
        ];
        config.default_outbound_tag = Some("duplicate".to_owned());
        let graph = OutboundGraph::new(Arc::new(config));

        assert_eq!(graph.nodes().len(), 3);
        assert_eq!(graph.nodes()[0].tag(), Some("duplicate"));
        assert_eq!(graph.nodes()[0].kind(), OutboundNodeKind::Freedom);
        assert_eq!(graph.nodes()[1].kind(), OutboundNodeKind::Vless);
        assert_eq!(graph.nodes()[2].kind(), OutboundNodeKind::Dns);
        assert_eq!(graph.node_for_tag("duplicate"), Some(graph.nodes()[0].id()));
        assert_eq!(graph.default_node(), Some(graph.nodes()[0].id()));
        assert!(!graph.has_unresolved_default_tag());
    }

    #[test]
    fn outbound_graph_retains_an_unresolved_default_reference() {
        let mut config = direct_selection_config();
        config.default_outbound_tag = Some("missing".to_owned());
        let graph = OutboundGraph::new(Arc::new(config));

        assert_eq!(graph.default_node(), None);
        assert!(graph.has_unresolved_default_tag());
    }

    #[test]
    fn outbound_graph_resolves_transport_layer_proxy_edges() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_freedom("entry"),
            direct_selection_freedom("exit"),
        ];
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "exit".to_owned(),
            transport_layer: true,
        });
        let graph = OutboundGraph::new(Arc::new(config));

        graph.validate_proxy_chains().expect("valid chain");
        assert_eq!(
            graph.proxy_target(graph.nodes()[0].id()),
            Some(graph.nodes()[1].id())
        );
        assert_eq!(graph.proxy_target(graph.nodes()[1].id()), None);
    }

    #[test]
    fn outbound_graph_rejects_a_missing_proxy_target() {
        let mut config = direct_selection_config();
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "missing".to_owned(),
            transport_layer: true,
        });
        let graph = OutboundGraph::new(Arc::new(config));

        assert_eq!(
            graph.validate_proxy_chains(),
            Err(OutboundProxyGraphError::TargetNotFound {
                outbound: "direct".to_owned(),
                target: "missing".to_owned(),
            })
        );
    }

    #[test]
    fn outbound_graph_rejects_programmatic_protocol_layer_proxy_settings() {
        let mut config = direct_selection_config();
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "proxy".to_owned(),
            transport_layer: false,
        });

        assert_eq!(
            OutboundGraph::new(Arc::new(config)).validate_proxy_chains(),
            Err(OutboundProxyGraphError::TransportLayerRequired {
                outbound: "direct".to_owned(),
            })
        );
    }

    #[test]
    fn outbound_graph_rejects_self_and_multi_node_proxy_cycles() {
        let mut self_cycle = direct_selection_config();
        self_cycle.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "direct".to_owned(),
            transport_layer: true,
        });
        assert_eq!(
            OutboundGraph::new(Arc::new(self_cycle)).validate_proxy_chains(),
            Err(OutboundProxyGraphError::Cycle {
                path: vec!["direct".to_owned(), "direct".to_owned()],
            })
        );

        let mut cycle = direct_selection_config();
        cycle.outbounds = vec![
            direct_selection_freedom("a"),
            direct_selection_freedom("b"),
            direct_selection_freedom("c"),
        ];
        for (index, target) in ["b", "c", "a"].into_iter().enumerate() {
            cycle.outbounds[index].proxy_settings = Some(OutboundProxySettings {
                tag: target.to_owned(),
                transport_layer: true,
            });
        }
        assert_eq!(
            OutboundGraph::new(Arc::new(cycle)).validate_proxy_chains(),
            Err(OutboundProxyGraphError::Cycle {
                path: vec![
                    "a".to_owned(),
                    "b".to_owned(),
                    "c".to_owned(),
                    "a".to_owned(),
                ],
            })
        );
    }

    #[test]
    fn outbound_graph_rejects_reality_inside_a_proxy_chain() {
        let mut config = direct_selection_config();
        let mut proxy = direct_selection_vless("proxy");
        proxy.stream.security = StreamSecurity::Reality(RealitySettings {
            server_name: "server.example".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [7; 32],
            short_id: RealityShortId::try_from_slice(&[1, 2, 3, 4]).unwrap(),
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        });
        config.outbounds = vec![direct_selection_freedom("entry"), proxy];
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "proxy".to_owned(),
            transport_layer: true,
        });

        assert!(matches!(
            OutboundGraph::new(Arc::new(config)).validate_proxy_chains(),
            Err(OutboundProxyGraphError::UnsupportedNode { outbound, .. }) if outbound == "proxy"
        ));
    }

    #[tokio::test]
    async fn freedom_proxy_chain_uses_the_nested_tcp_carrier() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_freedom("entry"),
            direct_selection_freedom("exit"),
        ];
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "exit".to_owned(),
            transport_layer: true,
        });
        config.default_outbound_tag = Some("entry".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let outbound = router.select_tcp_outbound().expect("compile chain");
        assert!(matches!(outbound, TcpOutbound::Chained { .. }));

        let connector = Arc::new(RecordingTcpConnector::default());
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(connector.clone());
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80))),
            443,
            RoutingNetwork::Tcp,
        );

        let _stream = open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .expect("open through nested freedom carrier");

        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn vless_proxy_chain_writes_the_outer_request_over_the_nested_carrier() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_vless("entry"),
            direct_selection_freedom("exit"),
        ];
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "exit".to_owned(),
            transport_layer: true,
        });
        config.default_outbound_tag = Some("entry".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let outbound = router.select_tcp_outbound().expect("compile VLESS chain");

        let connector = Arc::new(RecordingTcpConnector::default());
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(connector.clone());
        let target = Target::new(
            RoutingTargetAddr::Domain("destination.example".to_owned()),
            8443,
            RoutingNetwork::Tcp,
        );
        let _stream = open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .expect("open outer VLESS over nested carrier");

        let mut peer = connector.peers.lock().unwrap().pop().expect("nested peer");
        let primary = outbound.primary();
        let TcpOutbound::Vless(vless) = primary else {
            panic!("entry should compile as VLESS");
        };
        let expected = encode_request_header(&VlessRequest {
            user_id: vless.user().id,
            command: VlessCommand::Tcp,
            target,
            flow: None,
        })
        .unwrap();
        let mut received = vec![0; expected.len()];
        peer.read_exact(&mut received).await.unwrap();

        assert_eq!(received, expected);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn freedom_over_vless_chain_does_not_resolve_the_final_domain_locally() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_freedom("entry"),
            direct_selection_vless("proxy"),
        ];
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "proxy".to_owned(),
            transport_layer: true,
        });
        config.default_outbound_tag = Some("entry".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let outbound = router
            .select_tcp_outbound()
            .expect("compile VLESS proxy chain");

        let connector = Arc::new(RecordingTcpConnector::default());
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(connector);
        let resolver = FakeDnsResolver::failing_with(TransportError::NoResolvedAddress(
            "destination.example".to_owned(),
            443,
        ));
        let target = Target::new(
            RoutingTargetAddr::Domain("destination.example".to_owned()),
            443,
            RoutingNetwork::Tcp,
        );

        let _stream =
            open_tcp_stream_with_resolver_and_dialer(&outbound, &target, &resolver, &dialer)
                .await
                .expect("the VLESS proxy should receive the unresolved domain");

        assert_eq!(resolver.calls(), 0);
    }

    #[tokio::test]
    async fn multi_hop_vless_chain_layers_each_request_in_graph_order() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_vless("entry"),
            direct_selection_vless("middle"),
            direct_selection_freedom("exit"),
        ];
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "middle".to_owned(),
            transport_layer: true,
        });
        config.outbounds[1].proxy_settings = Some(OutboundProxySettings {
            tag: "exit".to_owned(),
            transport_layer: true,
        });
        config.default_outbound_tag = Some("entry".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let outbound = router
            .select_tcp_outbound()
            .expect("compile multi-hop chain");

        let connector = Arc::new(RecordingTcpConnector::default());
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(connector.clone());
        let target = Target::new(
            RoutingTargetAddr::Domain("destination.example".to_owned()),
            8443,
            RoutingNetwork::Tcp,
        );
        let _stream = open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .expect("open multi-hop VLESS chain");

        let TcpOutbound::Chained {
            outbound: entry,
            proxy,
        } = &outbound
        else {
            panic!("entry should be wrapped by its proxy edge");
        };
        let TcpOutbound::Vless(entry) = entry.primary() else {
            panic!("entry should be VLESS");
        };
        let TcpOutbound::Vless(middle) = proxy.primary() else {
            panic!("middle should be VLESS");
        };
        let middle_request = encode_request_header(&VlessRequest {
            user_id: middle.user().id,
            command: VlessCommand::Tcp,
            target: entry.server().clone(),
            flow: None,
        })
        .unwrap();
        let entry_request = encode_request_header(&VlessRequest {
            user_id: entry.user().id,
            command: VlessCommand::Tcp,
            target,
            flow: None,
        })
        .unwrap();
        let mut expected = middle_request;
        expected.extend_from_slice(&entry_request);
        let mut peer = connector
            .peers
            .lock()
            .unwrap()
            .pop()
            .expect("terminal peer");
        let mut received = vec![0; expected.len()];
        peer.read_exact(&mut received).await.unwrap();

        assert_eq!(received, expected);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn udp_selection_rejects_a_tcp_only_proxy_chain() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_freedom("entry"),
            direct_selection_freedom("exit"),
        ];
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "exit".to_owned(),
            transport_layer: true,
        });
        config.default_outbound_tag = Some("entry".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let target = Target::new(
            RoutingTargetAddr::Domain("dns.example".to_owned()),
            53,
            RoutingNetwork::Udp,
        );

        assert!(matches!(
            router.select_udp_outbound_for_session(None, &target),
            Err(CoreError::UnsupportedOutboundProxyNetwork("UDP"))
        ));
    }

    fn selector_group_config(strategy: RoutingBalancerStrategy) -> CoreConfig {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_vless("proxy-b"),
            direct_selection_freedom("direct"),
            direct_selection_vless("proxy-a"),
        ];
        config.default_outbound_tag = Some("direct".to_owned());
        config.routing.balancers = vec![RoutingBalancer {
            tag: "automatic".to_owned(),
            selectors: vec!["proxy-".to_owned()],
            strategy,
            fallback_tag: Some("direct".to_owned()),
        }];
        config.routing.rules = vec![RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: DomainMatcherSet::default(),
            ip_matchers: Default::default(),
            target: RoutingRuleTarget::Balancer("automatic".to_owned()),
        }];
        config
    }

    #[test]
    fn routing_policy_replacement_switches_new_flows_and_advances_revision() {
        let router = OutboundRouter::new(Arc::new(direct_selection_config()));
        let target = domain_tcp_target("example.test");

        let initial = router.routing_policy_snapshot();
        assert_eq!(initial.revision, 0);
        assert_eq!(initial.rule_count, 1);
        assert_eq!(
            router
                .select_tcp_outbound_for_session_with_tag(None, &target, true)
                .unwrap()
                .tag
                .as_deref(),
            Some("direct")
        );

        assert_eq!(
            router
                .replace_routing_policy(RoutingConfig::default())
                .unwrap(),
            1
        );
        assert_eq!(
            router
                .select_tcp_outbound_for_session_with_tag(None, &target, true)
                .unwrap()
                .tag
                .as_deref(),
            Some("proxy")
        );
        assert_eq!(router.routing_policy_snapshot().rule_count, 0);
    }

    #[test]
    fn rejected_routing_policy_leaves_the_previous_snapshot_active() {
        let router = OutboundRouter::new(Arc::new(direct_selection_config()));
        let before = router.routing_policy_snapshot();
        let invalid = RoutingConfig {
            rules: vec![network_port_rule(
                "missing",
                Network::Tcp,
                RoutingPortRange::single(443),
            )],
            ..Default::default()
        };

        assert!(matches!(
            router.replace_routing_policy(invalid),
            Err(CoreError::RoutingPolicyOutboundNotFound(tag)) if tag == "missing"
        ));
        assert_eq!(router.routing_policy_snapshot(), before);
    }

    #[test]
    fn routing_policy_cannot_mutate_the_immutable_balancer_topology() {
        let config = selector_group_config(RoutingBalancerStrategy::RoundRobin);
        let router = OutboundRouter::new(Arc::new(config.clone()));
        let mut replacement = config.routing;
        replacement.balancers[0].selectors = vec!["direct".to_owned()];

        assert!(matches!(
            router.replace_routing_policy(replacement),
            Err(CoreError::RoutingPolicyBalancerTopologyChanged)
        ));
        assert_eq!(router.routing_policy_snapshot().revision, 0);
    }

    #[test]
    fn routing_policy_replacement_rebuilds_the_dns_prefilter() {
        let mut config = direct_selection_config();
        config.routing.rules.clear();
        config.outbounds.push(dns_selection_outbound(
            "dns-out",
            DnsOutboundSettings::default(),
        ));
        let router = OutboundRouter::new(Arc::new(config));
        let target = Target::new(
            RoutingTargetAddr::Domain("dns.example".to_owned()),
            53,
            RoutingNetwork::Udp,
        );
        assert!(router
            .select_dns_outbound_for_session(None, &target)
            .unwrap()
            .is_none());

        router
            .replace_routing_policy(RoutingConfig {
                rules: vec![network_port_rule(
                    "dns-out",
                    Network::Udp,
                    RoutingPortRange::single(53),
                )],
                ..Default::default()
            })
            .unwrap();

        assert!(router
            .select_dns_outbound_for_session(None, &target)
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn in_flight_dns_selection_retains_one_routing_policy_revision() {
        let mut config = direct_selection_config();
        config.routing = RoutingConfig {
            rules: vec![ip_rule("direct", Ipv4Addr::new(192, 0, 2, 1))],
            domain_strategy: RoutingDomainStrategy::IpIfNonMatch,
            ..Default::default()
        };
        let router = Arc::new(OutboundRouter::new(Arc::new(config)));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let resolver = Arc::new(PausedDnsResolver {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            result: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
        });
        let selection = {
            let router = Arc::clone(&router);
            let resolver = Arc::clone(&resolver);
            tokio::spawn(async move {
                router
                    .select_tcp_outbound_for_session_with_tag_and_resolver(
                        None,
                        &domain_tcp_target("example.test"),
                        true,
                        resolver.as_ref(),
                    )
                    .await
            })
        };

        entered.notified().await;
        assert_eq!(
            router
                .replace_routing_policy(RoutingConfig::default())
                .unwrap(),
            1
        );
        release.notify_one();
        let selected = selection.await.unwrap().unwrap();
        assert_eq!(selected.tag.as_deref(), Some("direct"));

        let subsequent = router
            .select_tcp_outbound_for_session_with_tag_and_resolver(
                None,
                &domain_tcp_target("example.test"),
                true,
                resolver.as_ref(),
            )
            .await
            .unwrap();
        assert_eq!(subsequent.tag.as_deref(), Some("proxy"));
    }

    #[test]
    fn outbound_graph_expands_selector_prefixes_in_sorted_tag_order() {
        let graph = OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::RoundRobin,
        )));
        let group = graph
            .selector_group_for_tag("automatic")
            .expect("selector group node");
        let tags = group
            .members()
            .iter()
            .map(|member| graph.node(*member).unwrap().tag().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(graph.nodes().len(), 4);
        assert_eq!(group.node(), graph.nodes()[3].id());
        assert_eq!(graph.nodes()[3].kind(), OutboundNodeKind::Selector);
        assert_eq!(tags, vec!["proxy-a", "proxy-b"]);
        assert_eq!(group.fallback_tag(), Some("direct"));
    }

    #[test]
    fn round_robin_selector_uses_one_shared_atomic_cursor() {
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::RoundRobin,
        ))));
        let factory = Arc::new(OutboundFactory::new(graph));
        let first_router = OutboundRouter::from_factory(Arc::clone(&factory));
        let second_router = OutboundRouter::from_factory(factory);
        let target = domain_tcp_target("example.test");

        let first = first_router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        let second = second_router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        let third = first_router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();

        assert_eq!(first.tag.as_deref(), Some("proxy-a"));
        assert_eq!(second.tag.as_deref(), Some("proxy-b"));
        assert_eq!(third.tag.as_deref(), Some("proxy-a"));
    }

    #[test]
    fn round_robin_selector_skips_known_unhealthy_members_and_uses_fallback() {
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::RoundRobin,
        ))));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let proxy_b = graph.node_for_tag("proxy-b").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));
        let target = domain_tcp_target("example.test");

        router
            .selection()
            .record_health_failure(proxy_a, OutboundHealthFailure::Timeout, 1_000);
        let selected = router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("proxy-b"));

        router
            .selection()
            .record_health_failure(proxy_b, OutboundHealthFailure::Transport, 2_000);
        let selected = router
            .select_tcp_outbound_for_session(None, &target)
            .unwrap();
        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn least_ping_selects_lowest_healthy_delay_with_stable_tag_tiebreak() {
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::LeastPing,
        ))));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let proxy_b = graph.node_for_tag("proxy-b").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));
        let target = domain_tcp_target("example.test");

        router
            .selection()
            .record_health_success(proxy_a, Duration::from_millis(40), 1_000);
        router
            .selection()
            .record_health_success(proxy_b, Duration::from_millis(10), 1_000);
        let selected = router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("proxy-b"));

        router
            .selection()
            .record_health_success(proxy_a, Duration::from_millis(10), 2_000);
        let selected = router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("proxy-a"));
    }

    #[test]
    fn least_load_prefers_bounded_window_stability_over_latest_ping() {
        let settings = RoutingLeastLoadSettings::default();
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::LeastLoad(settings),
        ))));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let proxy_b = graph.node_for_tag("proxy-b").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));
        let target = domain_tcp_target("example.test");

        router
            .selection()
            .record_health_success(proxy_a, Duration::from_millis(10), 1_000);
        router
            .selection()
            .record_health_success(proxy_a, Duration::from_millis(50), 2_000);
        router
            .selection()
            .record_health_success(proxy_b, Duration::from_millis(100), 1_000);
        router
            .selection()
            .record_health_success(proxy_b, Duration::from_millis(100), 2_000);

        let selected = router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("proxy-b"));
    }

    #[test]
    fn least_load_distributes_only_across_the_bounded_top_n() {
        let settings = RoutingLeastLoadSettings {
            expected: 2,
            ..Default::default()
        };
        let mut config = selector_group_config(RoutingBalancerStrategy::LeastLoad(settings));
        config.outbounds.push(direct_selection_vless("proxy-c"));
        let graph = Arc::new(OutboundGraph::new(Arc::new(config)));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let proxy_b = graph.node_for_tag("proxy-b").unwrap();
        let proxy_c = graph.node_for_tag("proxy-c").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));
        let target = domain_tcp_target("example.test");

        for (node, first, second) in [(proxy_a, 10, 10), (proxy_b, 20, 22), (proxy_c, 30, 50)] {
            router
                .selection()
                .record_health_success(node, Duration::from_millis(first), 1_000);
            router
                .selection()
                .record_health_success(node, Duration::from_millis(second), 2_000);
        }

        for _ in 0..64 {
            let selected = router
                .select_tcp_outbound_for_session_with_tag(None, &target, true)
                .unwrap();
            assert!(matches!(
                selected.tag.as_deref(),
                Some("proxy-a" | "proxy-b")
            ));
        }
    }

    #[test]
    fn least_load_applies_literal_tag_cost_before_average_tiebreak() {
        let settings = RoutingLeastLoadSettings {
            costs: vec![xray_config::RoutingLeastLoadCost {
                tag_substring: "proxy-a".to_owned(),
                value_millionths: 25_000_000,
            }],
            ..Default::default()
        };
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::LeastLoad(settings),
        ))));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let proxy_b = graph.node_for_tag("proxy-b").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));
        let target = domain_tcp_target("example.test");

        for (node, first, second) in [(proxy_a, 10, 12), (proxy_b, 100, 104)] {
            router
                .selection()
                .record_health_success(node, Duration::from_millis(first), 1_000);
            router
                .selection()
                .record_health_success(node, Duration::from_millis(second), 2_000);
        }

        let selected = router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("proxy-b"));
    }

    #[test]
    fn least_load_baseline_can_fail_closed_to_fallback() {
        let settings = RoutingLeastLoadSettings {
            baselines: vec![Duration::from_millis(1)],
            ..Default::default()
        };
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::LeastLoad(settings),
        ))));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let proxy_b = graph.node_for_tag("proxy-b").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));
        let target = domain_tcp_target("example.test");

        for (node, first, second) in [(proxy_a, 10, 12), (proxy_b, 100, 104)] {
            router
                .selection()
                .record_health_success(node, Duration::from_millis(first), 1_000);
            router
                .selection()
                .record_health_success(node, Duration::from_millis(second), 2_000);
        }

        let selected = router
            .select_tcp_outbound_for_session(None, &target)
            .unwrap();
        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn least_load_filters_max_rtt_and_failure_tolerance_before_ranking() {
        let settings = RoutingLeastLoadSettings {
            max_rtt: Some(Duration::from_millis(80)),
            tolerance_millionths: 250_000,
            ..Default::default()
        };
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::LeastLoad(settings),
        ))));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let proxy_b = graph.node_for_tag("proxy-b").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));
        let target = domain_tcp_target("example.test");

        router
            .selection()
            .record_health_success(proxy_a, Duration::from_millis(40), 1_000);
        router
            .selection()
            .record_health_failure(proxy_a, OutboundHealthFailure::Timeout, 2_000);
        router
            .selection()
            .record_health_success(proxy_a, Duration::from_millis(40), 3_000);
        router
            .selection()
            .record_health_success(proxy_b, Duration::from_millis(100), 3_000);

        let selected = router
            .select_tcp_outbound_for_session(None, &target)
            .unwrap();
        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn health_snapshot_is_coherent_and_uses_structured_failures() {
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::RoundRobin,
        ))));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));

        router.selection().record_health_failure(
            proxy_a,
            OutboundHealthFailure::HttpStatus(503),
            12_345,
        );
        let snapshot = router.selection().health_snapshot();
        let status = snapshot
            .outbounds
            .iter()
            .find(|status| status.outbound_tag == "proxy-a")
            .unwrap();

        assert_eq!(snapshot.revision, 1);
        assert_eq!(status.state, OutboundHealthState::Unhealthy);
        assert_eq!(status.delay_ms, None);
        assert_eq!(status.last_try_unix_ms, Some(12_345));
        assert_eq!(status.last_seen_unix_ms, None);
        assert_eq!(status.consecutive_failures, 1);
        assert_eq!(
            status.last_failure,
            Some(OutboundHealthFailure::HttpStatus(503))
        );
    }

    #[test]
    fn explicit_override_remains_authoritative_when_member_is_unhealthy() {
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::RoundRobin,
        ))));
        let proxy_a = graph.node_for_tag("proxy-a").unwrap();
        let router = OutboundRouter::from_factory(Arc::new(OutboundFactory::new(graph)));

        router
            .selection()
            .record_health_failure(proxy_a, OutboundHealthFailure::Timeout, 1_000);
        router
            .selection()
            .set_override("automatic", "proxy-a")
            .unwrap();
        let selected = router
            .select_tcp_outbound_for_session_with_tag(
                None,
                &domain_tcp_target("example.test"),
                true,
            )
            .unwrap();

        assert_eq!(selected.tag.as_deref(), Some("proxy-a"));
    }

    #[test]
    fn selector_override_switches_atomically_and_reuses_compiled_handlers() {
        let graph = Arc::new(OutboundGraph::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::RoundRobin,
        ))));
        let factory = Arc::new(OutboundFactory::new(graph));
        let first_router = OutboundRouter::from_factory(Arc::clone(&factory));
        let second_router = OutboundRouter::from_factory(factory);
        let target = domain_tcp_target("example.test");

        assert_eq!(
            first_router
                .selection()
                .set_override("automatic", "proxy-a")
                .unwrap(),
            1
        );
        let first = first_router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        assert_eq!(first.tag.as_deref(), Some("proxy-a"));

        assert_eq!(
            second_router
                .selection()
                .set_override("automatic", "proxy-b")
                .unwrap(),
            2
        );
        let second = first_router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        assert_eq!(second.tag.as_deref(), Some("proxy-b"));

        second_router
            .selection()
            .set_override("automatic", "proxy-a")
            .unwrap();
        let first_again = second_router
            .select_tcp_outbound_for_session_with_tag(None, &target, true)
            .unwrap();
        let (TcpOutbound::Vless(first), TcpOutbound::Vless(first_again)) =
            (first.outbound, first_again.outbound)
        else {
            panic!("selector members should be VLESS outbounds");
        };
        assert!(Arc::ptr_eq(&first.payload, &first_again.payload));

        let snapshot = second_router.selection().snapshot();
        assert_eq!(snapshot.revision, 3);
        assert_eq!(snapshot.groups[0].tag, "automatic");
        assert_eq!(snapshot.groups[0].candidates, vec!["proxy-a", "proxy-b"]);
        assert_eq!(snapshot.groups[0].override_tag.as_deref(), Some("proxy-a"));
    }

    #[test]
    fn selector_override_rejects_unknown_groups_and_non_members() {
        let router = OutboundRouter::new(Arc::new(selector_group_config(
            RoutingBalancerStrategy::RoundRobin,
        )));

        assert!(matches!(
            router.selection().set_override("missing", "proxy-a"),
            Err(CoreError::OutboundSelectorGroupNotFound(group)) if group == "missing"
        ));
        assert!(matches!(
            router.selection().set_override("automatic", "direct"),
            Err(CoreError::OutboundSelectorCandidateNotFound { group, outbound })
                if group == "automatic" && outbound == "direct"
        ));
        assert_eq!(router.selection().snapshot().revision, 0);
    }

    #[test]
    fn empty_selector_group_uses_its_fallback_tag() {
        let mut config = selector_group_config(RoutingBalancerStrategy::Random);
        config.routing.balancers[0].selectors = vec!["absent".to_owned()];
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_tcp_outbound_for_session(None, &domain_tcp_target("example.test"))
            .unwrap();

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn dns_prefilter_preserves_balancer_routes_that_can_select_dns() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_freedom("direct"),
            dns_selection_outbound("dns-primary", DnsOutboundSettings::default()),
        ];
        config.default_outbound_tag = Some("direct".to_owned());
        config.routing.balancers = vec![RoutingBalancer {
            tag: "dns-group".to_owned(),
            selectors: vec!["dns-".to_owned()],
            strategy: RoutingBalancerStrategy::Random,
            fallback_tag: None,
        }];
        config.routing.rules[0].target = RoutingRuleTarget::Balancer("dns-group".to_owned());
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_dns_outbound_for_session(None, &domain_tcp_target("example.test"))
            .expect("select DNS group");

        assert!(selected.is_some());
    }

    #[test]
    fn outbound_factory_rejects_a_node_from_another_graph() {
        let first_graph = OutboundGraph::new(Arc::new(direct_selection_config()));
        let foreign_node = first_graph
            .node_for_tag("proxy")
            .expect("foreign graph proxy node");
        let second_graph = Arc::new(OutboundGraph::new(Arc::new(direct_selection_config())));
        let factory = OutboundFactory::new(second_graph);

        assert!(matches!(
            factory.cached_tcp_outbound(foreign_node),
            Err(CoreError::NoSupportedOutbound)
        ));
    }

    #[test]
    fn routers_sharing_a_factory_share_one_compiled_handler() {
        let graph = Arc::new(OutboundGraph::new(Arc::new(direct_selection_config())));
        let factory = Arc::new(OutboundFactory::new(graph));
        let first_router = OutboundRouter::from_factory(Arc::clone(&factory));
        let second_router = OutboundRouter::from_factory(Arc::clone(&factory));

        let first = first_router.select_tcp_outbound_direct(None).unwrap();
        let second = second_router.select_tcp_outbound_direct(None).unwrap();
        let (TcpOutbound::Vless(first), TcpOutbound::Vless(second)) = (first, second) else {
            panic!("expected the configured VLESS default");
        };

        assert!(Arc::ptr_eq(&first.payload, &second.payload));
        assert!(Arc::ptr_eq(
            &first_router.factory_handle(),
            &second_router.factory_handle()
        ));
    }

    #[test]
    fn outbound_router_direct_selector_uses_default_tag_without_routing() {
        let router = OutboundRouter::new(Arc::new(direct_selection_config()));
        let selected = router.select_tcp_outbound_direct(None).unwrap();

        assert!(matches!(selected, TcpOutbound::Vless(_)));
    }

    #[test]
    fn outbound_router_direct_selector_errors_when_explicit_tag_is_missing() {
        let router = OutboundRouter::new(Arc::new(direct_selection_config()));
        let error = router
            .select_tcp_outbound_direct(Some("missing"))
            .unwrap_err();

        assert!(matches!(error, CoreError::NoSupportedOutbound));
    }

    #[test]
    fn outbound_router_direct_selector_uses_first_outbound_without_default() {
        let mut config = direct_selection_config();
        config.default_outbound_tag = None;
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router.select_tcp_outbound_direct(None).unwrap();

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn outbound_router_duplicate_tag_keeps_first_configured_outbound() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_freedom("duplicate"),
            direct_selection_vless("duplicate"),
        ];
        config.default_outbound_tag = Some("duplicate".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router.select_tcp_outbound().unwrap();

        assert!(matches!(selected, TcpOutbound::Freedom));
        let duplicate = router
            .graph()
            .node_for_tag("duplicate")
            .and_then(|id| router.graph().node(id))
            .expect("resolve duplicate tag");
        assert_eq!(duplicate.kind(), OutboundNodeKind::Freedom);
    }

    #[test]
    fn outbound_router_defers_invalid_outbound_error_until_it_is_selected() {
        let mut config = direct_selection_config();
        let mut invalid = direct_selection_freedom("invalid");
        invalid.stream.network = Network::Udp;
        config.outbounds.push(invalid);
        config.default_outbound_tag = Some("direct".to_owned());
        config.routing.rules = vec![inbound_rule("api", "invalid")];
        let router = OutboundRouter::new(Arc::new(config));
        let target = domain_tcp_target("example.test");

        assert!(router.factory.entries[2].tcp.get().is_none());
        assert!(matches!(
            router
                .select_tcp_outbound_for_session(Some("socks-in"), &target)
                .unwrap(),
            TcpOutbound::Freedom
        ));
        assert!(router.factory.entries[2].tcp.get().is_none());

        let error = router
            .select_tcp_outbound_for_session(Some("api"), &target)
            .unwrap_err();
        assert!(matches!(error, CoreError::UnsupportedOutboundNetwork));
        assert!(router.factory.entries[2].tcp.get().is_some());
        let cached_error = router
            .select_tcp_outbound_for_session(Some("api"), &target)
            .unwrap_err();
        assert!(matches!(
            cached_error,
            CoreError::UnsupportedOutboundNetwork
        ));
    }

    /// VLESS dials ws and httpupgrade for real now, but freedom and the DNS
    /// outbound hand the stream straight to a socket and carry no transport
    /// layer. Since `stream.network` is `Tcp` for all three transports, those
    /// two have to refuse rather than quietly dial plain TCP.
    #[test]
    fn a_transport_freedom_cannot_dial_fails_closed_instead_of_dialing_plain_tcp() {
        let websocket = StreamTransport::WebSocket(WebSocketSettings {
            path: "/chat".to_owned(),
            ..WebSocketSettings::default()
        });
        let httpupgrade = StreamTransport::HttpUpgrade(HttpUpgradeSettings {
            path: "/up".to_owned(),
            ..HttpUpgradeSettings::default()
        });
        let grpc = StreamTransport::Grpc(GrpcSettings {
            service_name: "GunService".to_owned(),
            ..GrpcSettings::default()
        });

        for transport in [websocket, httpupgrade, grpc] {
            let mut freedom = direct_selection_freedom("proxy");
            freedom.stream.transport = transport.clone();
            assert!(matches!(
                build_tcp_outbound(&freedom).unwrap_err(),
                CoreError::UnsupportedOutboundNetwork
            ));
            assert!(matches!(
                build_udp_outbound(&freedom).unwrap_err(),
                CoreError::UnsupportedOutboundNetwork
            ));

            // The DNS outbound reads the stream settings separately.
            assert!(matches!(
                DnsOutbound::new_with_stream(
                    DnsOutboundSettings::default(),
                    &freedom.stream,
                    Duration::from_secs(60),
                )
                .unwrap_err(),
                CoreError::UnsupportedOutboundNetwork
            ));
        }
    }

    /// `compile_udp_outbound` is the router's cached twin of
    /// `build_udp_outbound`, and the two are reached from the same config by
    /// different callers. A guard only one of them applies makes the verdict
    /// depend on whether the cache is live, which is not a property a config
    /// should have.
    #[test]
    fn the_cached_and_uncached_udp_freedom_paths_agree_on_an_undialable_transport() {
        let mut freedom = direct_selection_freedom("direct");
        freedom.stream.transport = StreamTransport::WebSocket(WebSocketSettings {
            path: "/chat".to_owned(),
            ..WebSocketSettings::default()
        });

        let mut config = direct_selection_config();
        config.outbounds = vec![freedom.clone()];
        config.default_outbound_tag = Some("direct".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));

        let tcp_target = domain_tcp_target("example.test");
        let target = Target::new(
            tcp_target.addr.clone(),
            tcp_target.port,
            RoutingNetwork::Udp,
        );

        assert!(matches!(
            build_udp_outbound(&freedom).unwrap_err(),
            CoreError::UnsupportedOutboundNetwork
        ));
        assert!(matches!(
            router
                .select_udp_outbound_for_session(None, &target)
                .unwrap_err(),
            CoreError::UnsupportedOutboundNetwork
        ));
    }

    /// The other half: every VLESS builder, including the cached router's own
    /// path, now produces an outbound carrying the dial-ready layer.
    #[test]
    fn every_vless_builder_carries_the_stream_transport() {
        let mut vless = direct_selection_vless("proxy");
        vless.stream.transport = StreamTransport::WebSocket(WebSocketSettings {
            path: "/chat".to_owned(),
            ..WebSocketSettings::default()
        });

        for built in [
            build_vless_tcp_outbound(&vless).expect("the direct VLESS builder"),
            match build_tcp_outbound(&vless).expect("the TCP builder") {
                TcpOutbound::Vless(outbound) => *outbound,
                other => panic!("expected a VLESS outbound, got {other:?}"),
            },
            match build_udp_outbound(&vless).expect("the UDP builder") {
                UdpOutbound::Vless(outbound) => *outbound,
                other => panic!("expected a VLESS outbound, got {other:?}"),
            },
        ] {
            assert!(matches!(
                built.transport_layer(),
                TransportLayer::WebSocket(_)
            ));
        }

        let mut config = direct_selection_config();
        config.outbounds = vec![vless];
        config.default_outbound_tag = Some("proxy".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let TcpOutbound::Vless(selected) = router
            .select_tcp_outbound()
            .expect("the cached router path must build it too")
        else {
            panic!("expected a VLESS outbound");
        };
        assert!(matches!(
            selected.transport_layer(),
            TransportLayer::WebSocket(_)
        ));
    }

    #[test]
    fn outbound_router_reuses_vless_arc_across_tcp_and_udp_selections() {
        let mut config = direct_selection_config();
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let target = domain_tcp_target("example.test");

        let TcpOutbound::Vless(first_tcp) = router
            .select_tcp_outbound_for_session(None, &target)
            .unwrap()
        else {
            panic!("expected cached VLESS TCP outbound");
        };
        let TcpOutbound::Vless(second_tcp) = router
            .select_tcp_outbound_for_session(None, &target)
            .unwrap()
        else {
            panic!("expected cached VLESS TCP outbound");
        };
        let UdpOutbound::Vless(udp) = router
            .select_udp_outbound_for_session(
                None,
                &Target::new(target.addr.clone(), target.port, RoutingNetwork::Udp),
            )
            .unwrap()
        else {
            panic!("expected cached VLESS UDP outbound");
        };

        assert!(Arc::ptr_eq(&first_tcp.payload, &second_tcp.payload));
        assert!(Arc::ptr_eq(&first_tcp.payload, &udp.payload));
    }

    fn reality_settings() -> RealitySettings {
        RealitySettings {
            server_name: "reality.example".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [7; 32],
            short_id: RealityShortId::try_from_slice(&[1, 2, 3, 4])
                .expect("valid Reality short id"),
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        }
    }

    fn grpc_settings(authority: Option<&str>) -> GrpcSettings {
        GrpcSettings {
            service_name: "GunService".to_owned(),
            authority: authority.map(str::to_owned),
            ..GrpcSettings::default()
        }
    }

    fn grpc_vless(
        grpc: GrpcSettings,
        security: StreamSecurity,
        server: TargetAddr,
    ) -> OutboundConfig {
        let mut vless = direct_selection_vless("proxy");
        vless.stream.transport = StreamTransport::Grpc(grpc);
        vless.stream.security = security;
        let OutboundSettings::Vless(settings) = &mut vless.settings else {
            panic!("expected a VLESS outbound");
        };
        settings.server = server;
        vless
    }

    fn grpc_reality_vless(flow: Option<&str>) -> OutboundConfig {
        let mut vless = grpc_vless(
            grpc_settings(None),
            StreamSecurity::Reality(reality_settings()),
            TargetAddr::Domain("dest.example.com".to_owned()),
        );
        let OutboundSettings::Vless(settings) = &mut vless.settings else {
            panic!("expected a VLESS outbound");
        };
        settings.users[0].flow = flow.map(str::to_owned);
        vless
    }

    fn built_grpc_transport(outbound: &OutboundConfig) -> GrpcTransport {
        let built = build_vless_tcp_outbound(outbound).expect("a gRPC VLESS outbound");
        let TransportLayer::Grpc(grpc) = built.transport_layer() else {
            panic!("expected the gRPC transport layer");
        };
        grpc.clone()
    }

    fn tls_security(server_name: Option<&str>, alpn: &[&str]) -> StreamSecurity {
        StreamSecurity::Tls(TlsSettings {
            server_name: server_name.map(str::to_owned),
            fingerprint: Some("chrome".to_owned()),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: alpn.iter().map(|protocol| (*protocol).to_owned()).collect(),
        })
    }

    fn xhttp_vless(
        xhttp: XhttpSettings,
        security: StreamSecurity,
        server: TargetAddr,
        port: u16,
    ) -> OutboundConfig {
        let mut vless = direct_selection_vless("proxy");
        vless.stream.transport = StreamTransport::Xhttp(Box::new(xhttp));
        vless.stream.security = security;
        let OutboundSettings::Vless(settings) = &mut vless.settings else {
            panic!("expected a VLESS outbound");
        };
        settings.server = server;
        settings.port = port;
        vless
    }

    fn built_xhttp_transport(outbound: &OutboundConfig) -> XhttpTransport {
        let built = build_vless_tcp_outbound(outbound).expect("an XHTTP VLESS outbound");
        xhttp_transport(&built).clone()
    }

    fn xhttp_transport(outbound: &VlessTcpOutbound) -> &XhttpTransport {
        let TransportLayer::Xhttp(xhttp) = outbound.transport_layer() else {
            panic!("expected the XHTTP transport layer");
        };
        xhttp
    }

    #[test]
    fn xhttp_http_version_matches_xrays_security_and_exact_alpn_rules() {
        for (security, expected) in [
            (StreamSecurity::None, XhttpHttpVersion::Http1),
            (
                StreamSecurity::Reality(reality_settings()),
                XhttpHttpVersion::Http2,
            ),
            (
                tls_security(Some("sni.example"), &[]),
                XhttpHttpVersion::Http2,
            ),
            (
                tls_security(Some("sni.example"), &["http/1.1"]),
                XhttpHttpVersion::Http1,
            ),
            (
                tls_security(Some("sni.example"), &["h2"]),
                XhttpHttpVersion::Http2,
            ),
            (
                tls_security(Some("sni.example"), &["h2", "http/1.1"]),
                XhttpHttpVersion::Http2,
            ),
            (
                tls_security(Some("sni.example"), &["h3", "h2"]),
                XhttpHttpVersion::Http2,
            ),
            (
                tls_security(Some("sni.example"), &["h3"]),
                XhttpHttpVersion::Http3,
            ),
        ] {
            assert_eq!(xhttp_http_version(&security).unwrap(), expected);
        }

        let h3 = tls_security(Some("sni.example"), &["h3"]);
        let outbound = xhttp_vless(
            XhttpSettings::default(),
            h3,
            TargetAddr::Domain("origin.example".to_owned()),
            443,
        );
        let built = build_vless_tcp_outbound(&outbound).expect("exact h3 builds XHTTP over UDP");
        assert_eq!(
            xhttp_transport(&built).h3_quic_config().keep_alive_interval,
            Some(Duration::from_secs(10)),
            "zero QUIC and xmux keepalive selects Xray's H3 default"
        );
    }

    #[test]
    fn xhttp_endpoint_follows_precedence_scheme_and_native_port_semantics() {
        let destination = TargetAddr::Domain("origin.example".to_owned());
        let tls = tls_security(Some("sni.example"), &[]);
        let mut configured = XhttpSettings {
            host: Some("CDN.example:8443".to_owned()),
            ..XhttpSettings::default()
        };
        assert_eq!(
            xhttp_endpoint(&configured, &tls, &destination).unwrap(),
            XhttpEndpoint {
                scheme: XhttpScheme::Https,
                authority: "cdn.example:8443".to_owned(),
            }
        );

        configured.host = None;
        assert_eq!(
            xhttp_endpoint(&configured, &tls, &destination)
                .unwrap()
                .authority,
            "sni.example"
        );
        assert_eq!(
            xhttp_endpoint(
                &configured,
                &StreamSecurity::Reality(reality_settings()),
                &destination,
            )
            .unwrap()
            .authority,
            "reality.example"
        );

        let outbound = xhttp_vless(configured.clone(), StreamSecurity::None, destination, 8_443);
        let OutboundSettings::Vless(server) = &outbound.settings else {
            panic!("expected VLESS settings");
        };
        let StreamTransport::Xhttp(settings) = &outbound.stream.transport else {
            panic!("expected XHTTP settings");
        };
        let endpoint = xhttp_endpoint(settings, &outbound.stream.security, &server.server).unwrap();
        assert_eq!(server.port, 8_443);
        assert_eq!(endpoint.scheme, XhttpScheme::Http);
        assert_eq!(endpoint.authority, "origin.example");

        assert_eq!(
            xhttp_endpoint(
                &configured,
                &StreamSecurity::None,
                &TargetAddr::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,))),
            )
            .unwrap()
            .authority,
            "[2001:db8::1]"
        );
        assert_eq!(
            xhttp_endpoint(
                &configured,
                &StreamSecurity::None,
                &TargetAddr::Ip(IpAddr::V6(Ipv6Addr::new(
                    0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201,
                ))),
            )
            .unwrap()
            .authority,
            "192.0.2.1"
        );
    }

    #[test]
    fn xhttp_auto_mode_uses_reality_and_preserves_explicit_modes() {
        for (security, configured, expected) in [
            (
                StreamSecurity::None,
                xray_config::XhttpMode::Auto,
                xray_transport::stream::XhttpMode::PacketUp,
            ),
            (
                StreamSecurity::Reality(reality_settings()),
                xray_config::XhttpMode::Auto,
                xray_transport::stream::XhttpMode::StreamOne,
            ),
            (
                StreamSecurity::Reality(reality_settings()),
                xray_config::XhttpMode::StreamUp,
                xray_transport::stream::XhttpMode::StreamUp,
            ),
        ] {
            let outbound = xhttp_vless(
                XhttpSettings {
                    mode: configured,
                    ..XhttpSettings::default()
                },
                security,
                TargetAddr::Domain("origin.example".to_owned()),
                443,
            );
            assert_eq!(built_xhttp_transport(&outbound).config().mode, expected);
        }
    }

    #[test]
    fn every_xhttp_client_setting_reaches_the_dial_ready_policy() {
        let settings = XhttpSettings {
            host: Some("cdn.example".to_owned()),
            path: "wire?existing=1#part".to_owned(),
            mode: xray_config::XhttpMode::StreamUp,
            headers: vec![
                ("X-First".to_owned(), "one".to_owned()),
                ("X-Second".to_owned(), "two".to_owned()),
            ],
            x_padding_bytes: xray_config::XhttpRange { from: 101, to: 102 },
            x_padding_obfs_mode: true,
            x_padding_key: "pad_key".to_owned(),
            x_padding_header: "X-Pad-Key".to_owned(),
            x_padding_placement: xray_config::XhttpPaddingPlacement::Header,
            x_padding_method: xray_config::XhttpPaddingMethod::Tokenish,
            uplink_http_method: "PUT".to_owned(),
            session_placement: xray_config::XhttpPlacement::Cookie,
            session_key: "session_key".to_owned(),
            session_id_table: "Base62".to_owned(),
            session_id_length: xray_config::XhttpRange { from: 6, to: 9 },
            seq_placement: xray_config::XhttpPlacement::Header,
            seq_key: "X-Sequence-Key".to_owned(),
            uplink_data_placement: xray_config::XhttpUplinkDataPlacement::Body,
            uplink_data_key: "unused_body_key".to_owned(),
            uplink_chunk_size: xray_config::XhttpRange { from: 201, to: 202 },
            no_grpc_header: true,
            no_sse_header: true,
            sc_max_each_post_bytes: xray_config::XhttpRange {
                from: 1_001,
                to: 1_002,
            },
            sc_min_posts_interval_ms: xray_config::XhttpRange { from: 31, to: 32 },
            sc_max_buffered_posts: 37,
            sc_stream_up_server_secs: xray_config::XhttpRange { from: 41, to: 42 },
            server_max_header_bytes: 4_096,
            xmux: xray_config::XhttpXmuxSettings {
                max_concurrency: xray_config::XhttpRange { from: -2, to: -1 },
                max_connections: xray_config::XhttpRange { from: 2, to: 3 },
                c_max_reuse_times: xray_config::XhttpRange { from: 4, to: 5 },
                h_max_request_times: xray_config::XhttpRange { from: 6, to: 7 },
                h_max_reusable_secs: xray_config::XhttpRange { from: 8, to: 9 },
                h_keep_alive_period_secs: -10,
            },
        };

        let config = xhttp_config(&settings, false).unwrap();
        assert_eq!(config.mode, xray_transport::stream::XhttpMode::StreamUp);
        assert_eq!(config.path, "/wire");
        assert_eq!(config.raw_query, "existing=1");
        assert_eq!(config.fragment, "part");
        assert_eq!(config.headers.get("X-First"), Some("one"));
        assert_eq!(config.headers.get("X-Second"), Some("two"));
        assert_eq!(config.padding.range.from, 101);
        assert_eq!(config.padding.range.to, 102);
        assert!(config.padding.obfs_mode);
        assert_eq!(config.padding.key, "pad_key");
        assert_eq!(config.padding.header, "X-Pad-Key");
        assert_eq!(config.padding.placement, XhttpPaddingPlacement::Header);
        assert_eq!(config.padding.method, XhttpPaddingMethod::Tokenish);
        assert_eq!(config.uplink_http_method, "PUT");
        assert_eq!(config.session.placement, XhttpMetadataPlacement::Cookie);
        assert_eq!(config.session.key, "session_key");
        assert_eq!(
            config.session_id.table,
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        );
        assert_eq!(config.session_id.length.from, 6);
        assert_eq!(config.session_id.length.to, 9);
        assert_eq!(config.sequence.placement, XhttpMetadataPlacement::Header);
        assert_eq!(config.sequence.key, "X-Sequence-Key");
        assert_eq!(config.uplink_data.placement, XhttpUplinkDataPlacement::Body);
        assert_eq!(config.uplink_data.key, "unused_body_key");
        assert_eq!(config.uplink_data.chunk_size.from, 201);
        assert_eq!(config.uplink_data.chunk_size.to, 202);
        assert!(config.no_grpc_header);
        assert_eq!(config.max_each_post_bytes.from, 1_001);
        assert_eq!(config.max_each_post_bytes.to, 1_002);
        assert_eq!(config.min_posts_interval_ms.from, 31);
        assert_eq!(config.min_posts_interval_ms.to, 32);
        assert_eq!(config.max_buffered_posts, 37);
        assert_eq!(config.stream_up_server_secs.from, 41);
        assert_eq!(config.stream_up_server_secs.to, 42);

        assert_eq!(
            xhttp_xmux_policy(&settings),
            XhttpXmuxPolicy {
                max_concurrency: XhttpRange { from: -2, to: -1 },
                max_connections: XhttpRange { from: 2, to: 3 },
                c_max_reuse_times: XhttpRange { from: 4, to: 5 },
                h_max_request_times: XhttpRange { from: 6, to: 7 },
                h_max_reusable_secs: XhttpRange { from: 8, to: 9 },
                h_keep_alive_period_secs: -10,
            }
        );
    }

    #[test]
    fn xhttp_duplicate_canonical_headers_reach_h1_wire_in_add_order() {
        // The parser has already canonicalized case-variant JSON keys at this
        // layer. Runtime mapping must retain both protobuf-map values rather
        // than treating the second Add as a Set.
        let settings = XhttpSettings {
            headers: vec![
                ("X-Foo".to_owned(), "first".to_owned()),
                ("X-Foo".to_owned(), "second".to_owned()),
            ],
            ..XhttpSettings::default()
        };
        let config = xhttp_config(&settings, false).expect("XHTTP config");
        let wire =
            xray_transport::stream::serialize_request("GET", "/", "example.com", &config.headers);
        let wire = String::from_utf8(wire).expect("ASCII request");

        assert!(
            wire.contains("\r\nX-Foo: first\r\nX-Foo: second\r\n"),
            "{wire}"
        );
    }

    #[test]
    fn every_supported_quic_parameter_reaches_the_h3_engine() {
        let mut outbound = xhttp_vless(
            XhttpSettings::default(),
            tls_security(Some("sni.example"), &["h3"]),
            TargetAddr::Domain("origin.example".to_owned()),
            443,
        );
        outbound.stream.quic_params = Some(QuicParamsSettings {
            congestion: xray_config::QuicCongestion::Reno,
            bbr_profile: xray_config::QuicBbrProfile::Standard,
            brutal_up_bytes_per_sec: 65_536,
            brutal_down_bytes_per_sec: 131_072,
            udp_hop: xray_config::QuicUdpHopSettings::default(),
            init_stream_receive_window: 2_100_000,
            max_stream_receive_window: 2_100_000,
            init_connection_receive_window: 3_100_000,
            max_connection_receive_window: 3_100_000,
            max_idle_timeout_secs: 17,
            keep_alive_period_secs: 11,
            disable_path_mtu_discovery: true,
            max_incoming_streams: 16,
            debug: false,
        });

        let built = built_xhttp_transport(&outbound);
        let quic = built.h3_quic_config();
        assert_eq!(quic.initial_stream_receive_window, 2_100_000);
        assert_eq!(quic.max_stream_receive_window, Some(2_100_000));
        assert_eq!(quic.initial_connection_receive_window, 3_100_000);
        assert_eq!(quic.max_connection_receive_window, Some(3_100_000));
        assert_eq!(quic.max_idle_timeout, Duration::from_secs(17));
        assert_eq!(quic.keep_alive_interval, Some(Duration::from_secs(11)));
        assert_eq!(quic.max_incoming_bidirectional_streams, 16);
        assert!(quic.disable_path_mtu_discovery);
        assert_eq!(quic.congestion, H3Congestion::Reno);
    }

    #[test]
    fn unsupported_explicit_h3_quic_features_fail_closed_but_h2_ignores_them() {
        let invalid = QuicParamsSettings {
            udp_hop: xray_config::QuicUdpHopSettings {
                ports: vec![4_443],
                interval: xray_config::QuicIntervalRange { from: 5, to: 6 },
            },
            ..QuicParamsSettings::default()
        };
        let mut h3 = xhttp_vless(
            XhttpSettings::default(),
            tls_security(Some("sni.example"), &["h3"]),
            TargetAddr::Domain("origin.example".to_owned()),
            443,
        );
        h3.stream.quic_params = Some(invalid.clone());
        assert!(matches!(
            build_vless_tcp_outbound(&h3),
            Err(CoreError::InvalidXhttpConfiguration(message)) if message.contains("UDP hop")
        ));

        let mut h2 = h3;
        h2.stream.security = tls_security(Some("sni.example"), &["h2"]);
        build_vless_tcp_outbound(&h2)
            .expect("Xray does not consult QUIC-only settings on the H2 branch");

        for invalid in [
            QuicParamsSettings {
                debug: true,
                ..QuicParamsSettings::default()
            },
            QuicParamsSettings {
                congestion: xray_config::QuicCongestion::Bbr,
                bbr_profile: xray_config::QuicBbrProfile::Conservative,
                ..QuicParamsSettings::default()
            },
            QuicParamsSettings {
                init_stream_receive_window: 2 * 1024 * 1024,
                max_stream_receive_window: 6 * 1024 * 1024,
                ..QuicParamsSettings::default()
            },
            QuicParamsSettings {
                congestion: xray_config::QuicCongestion::ForceBrutal,
                brutal_up_bytes_per_sec: 65_536,
                ..QuicParamsSettings::default()
            },
        ] {
            let mut outbound = xhttp_vless(
                XhttpSettings::default(),
                tls_security(Some("sni.example"), &["h3"]),
                TargetAddr::Domain("origin.example".to_owned()),
                443,
            );
            outbound.stream.quic_params = Some(invalid);
            assert!(matches!(
                build_vless_tcp_outbound(&outbound),
                Err(CoreError::InvalidXhttpConfiguration(_))
            ));
        }
    }

    #[test]
    fn h3_quic_transport_parameters_respect_the_quic_varint_domain() {
        let clamped = xhttp_h3_quic_config(Some(&QuicParamsSettings {
            max_incoming_streams: i64::MAX,
            ..QuicParamsSettings::default()
        }))
        .expect("quic-go clamps oversized incoming-stream limits");
        assert_eq!(
            clamped.max_incoming_bidirectional_streams,
            QUIC_MAX_STREAM_COUNT
        );

        let mut outbound = xhttp_vless(
            XhttpSettings::default(),
            tls_security(Some("sni.example"), &["h3"]),
            TargetAddr::Domain("origin.example".to_owned()),
            443,
        );
        outbound.stream.quic_params = Some(QuicParamsSettings {
            init_stream_receive_window: QUIC_VARINT_MAX + 1,
            max_stream_receive_window: QUIC_VARINT_MAX + 1,
            ..QuicParamsSettings::default()
        });

        assert!(matches!(
            build_vless_tcp_outbound(&outbound),
            Err(CoreError::InvalidXhttpConfiguration(message))
                if message.contains("62-bit varint limit")
        ));
    }

    #[test]
    fn cached_xhttp_selections_share_one_xmux_manager() {
        let mut config = direct_selection_config();
        config.outbounds = vec![xhttp_vless(
            XhttpSettings::default(),
            StreamSecurity::None,
            TargetAddr::Domain("origin.example".to_owned()),
            443,
        )];
        config.default_outbound_tag = Some("proxy".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let target = domain_tcp_target("example.test");

        let TcpOutbound::Vless(first) = router.select_tcp_outbound().unwrap() else {
            panic!("expected cached VLESS outbound");
        };
        let TcpOutbound::Vless(second) = router.select_tcp_outbound().unwrap() else {
            panic!("expected cached VLESS outbound");
        };
        let UdpOutbound::Vless(udp) = router
            .select_udp_outbound_for_session(
                None,
                &Target::new(target.addr, target.port, RoutingNetwork::Udp),
            )
            .unwrap()
        else {
            panic!("expected cached VLESS UDP outbound");
        };

        assert!(xhttp_transport(&first).shares_xmux_with(xhttp_transport(&second)));
        assert!(xhttp_transport(&first).shares_xmux_with(xhttp_transport(&udp)));
    }

    /// Xray's `:authority` chain, in order:
    /// `grpcSettings.authority`, else `tlsSettings.serverName`, else the
    /// destination domain but *only when REALITY is absent*, else the empty
    /// string (`Xray-core/transport/internet/grpc/dial.go:159-167`).
    ///
    /// The empty string is not an omitted header. grpc-go falls back to the
    /// resolver endpoint, which Xray builds as `passthrough:///host:port`
    /// (`dial.go:188-191`), so what goes out carries the port — confirmed on
    /// the wire against grpc-go v1.81.0. Under REALITY that fallback is the
    /// default path rather than an edge case, which is why the last row is not
    /// a curiosity. [`grpc_authority`] has the rest of the reasoning, including
    /// why the `Host` header's `host_fallback` cannot answer this.
    #[test]
    fn the_grpc_authority_follows_xrays_precedence_chain() {
        for (configured, tls_server_name, reality, expected) in [
            (
                Some("cdn.example.com"),
                Some("sni.example.com"),
                false,
                "cdn.example.com",
            ),
            (Some("cdn.example.com"), None, true, "cdn.example.com"),
            (None, Some("sni.example.com"), false, "sni.example.com"),
            (None, None, false, "dest.example.com"),
            (None, None, true, "dest.example.com:443"),
        ] {
            let security = match (tls_server_name, reality) {
                (Some(name), false) => StreamSecurity::Tls(TlsSettings {
                    server_name: Some(name.to_owned()),
                    fingerprint: None,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn: Vec::new(),
                }),
                (None, true) => StreamSecurity::Reality(reality_settings()),
                (None, false) => StreamSecurity::None,
                (Some(_), true) => panic!("a stream carries one security layer, not two"),
            };
            let outbound = grpc_vless(
                grpc_settings(configured),
                security,
                TargetAddr::Domain("dest.example.com".to_owned()),
            );

            assert_eq!(
                built_grpc_transport(&outbound).config().authority,
                expected,
                "authority={configured:?} serverName={tls_server_name:?} reality={reality}"
            );
        }
    }

    /// A TLS stream with no `tlsSettings.serverName` reaches the destination
    /// branch, not the server-name one.
    ///
    /// The two are indistinguishable by value, which is the point: our
    /// `ConnectorConfig::Tls.server_name` is already filled from the
    /// destination domain when the key is absent
    /// (`build_vless_tcp_outbound`), where Xray's `tls.ConfigFromStreamSettings`
    /// hands `dial.go:162` the raw proto field and it reads empty — the
    /// mutation that copies the domain in happens later, inside the dial
    /// closure, on a `*gotls.Config` the authority chain never sees. So
    /// upstream takes branch 3 where a connector-driven port would take
    /// branch 2, and both land on the destination domain.
    ///
    /// For an IP destination the branches do differ by value: the connector
    /// carries the IP for TLS certificate-name verification, but this authority
    /// path reads the raw absent name and therefore keeps upstream's
    /// `host:port` fallback. The next test pins that reachable case.
    #[test]
    fn a_tls_stream_without_a_server_name_takes_the_destination_branch() {
        let outbound = grpc_vless(
            grpc_settings(None),
            StreamSecurity::Tls(TlsSettings {
                server_name: None,
                fingerprint: None,
                allow_insecure: false,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: Vec::new(),
            }),
            TargetAddr::Domain("dest.example.com".to_owned()),
        );

        assert_eq!(
            built_grpc_transport(&outbound).config().authority,
            "dest.example.com"
        );
    }

    /// The destination branch of the chain is `realityConfig == nil &&
    /// dest.Address.Family().IsDomain()` (`dial.go:164`), so an IP destination
    /// leaves the authority empty with or without REALITY and takes the same
    /// `host:port` fallback. grpc-go's `encodeAuthority` leaves `:`, `[` and
    /// `]` alone (`grpc@v1.81.0/clientconn.go:1889-1942`), which is what keeps
    /// an IPv6 literal bracketed rather than percent-escaped.
    ///
    /// The last row is Go's `net.IP.String()` writing a v4-mapped address as a
    /// dotted quad when `To4()` matches, which is the only shape where Rust's
    /// `Display` and Go's disagree.
    #[test]
    fn an_ip_destination_carries_its_port_into_the_authority() {
        for (server, security, expected) in [
            (
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                StreamSecurity::None,
                "192.0.2.1:443",
            ),
            (
                TargetAddr::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
                StreamSecurity::Reality(reality_settings()),
                "[2001:db8::1]:443",
            ),
            (
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
                tls_security(None, &[]),
                "192.0.2.2:443",
            ),
            (
                TargetAddr::Ip(IpAddr::V6(Ipv6Addr::new(
                    0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201,
                ))),
                StreamSecurity::None,
                "192.0.2.1:443",
            ),
        ] {
            let outbound = grpc_vless(grpc_settings(None), security, server.clone());
            assert_eq!(
                built_grpc_transport(&outbound).config().authority,
                expected,
                "server={server:?}"
            );
        }
    }

    /// Every `grpcSettings` key has to survive the trip into the dial-ready
    /// config; a field silently left at its default is a setting the user
    /// wrote and the wire never sees.
    #[test]
    fn every_grpc_setting_reaches_the_dial_ready_config() {
        let outbound = grpc_vless(
            GrpcSettings {
                service_name: "/my/Service|Multi".to_owned(),
                multi_mode: true,
                authority: Some("cdn.example.com".to_owned()),
                user_agent: Some("golang".to_owned()),
                idle_timeout_secs: 17,
                health_check_timeout_secs: 23,
                permit_without_stream: true,
                initial_windows_size: 65_536,
            },
            StreamSecurity::None,
            TargetAddr::Domain("dest.example.com".to_owned()),
        );

        let transport = built_grpc_transport(&outbound);
        let config = transport.config();
        assert_eq!(config.service_name, "/my/Service|Multi");
        assert!(config.multi_mode);
        assert_eq!(config.authority, "cdn.example.com");
        // `golang` is the one keyword that empties the header rather than
        // naming a browser (`dial.go:202-203`).
        assert_eq!(config.user_agent, "");
        assert_eq!(config.idle_timeout_secs, 17);
        assert_eq!(config.health_check_timeout_secs, 23);
        assert!(config.permit_without_stream);
        assert_eq!(config.initial_windows_size, 65_536);
    }

    /// `GrpcConfig::authority` is an `http::uri::Authority` so that a value no
    /// authority can hold is refused once, here, rather than silently calling
    /// a gRPC method nobody configured on every dial.
    ///
    /// grpc-go validates `WithAuthority` not at all and sends
    /// `example.com/api` verbatim, so this refusal is a deliberate divergence.
    /// It has to reach the cached router intact too: `CachedOutboundError`
    /// memoizes build failures and panics on any `CoreError` it cannot
    /// represent.
    #[test]
    fn a_malformed_authority_refuses_the_outbound_once_instead_of_every_dial() {
        let outbound = grpc_vless(
            grpc_settings(Some("example.com/api")),
            StreamSecurity::None,
            TargetAddr::Domain("dest.example.com".to_owned()),
        );

        let error =
            build_vless_tcp_outbound(&outbound).expect_err("a path cannot live in an authority");
        assert!(matches!(
            &error,
            CoreError::InvalidGrpcAuthority(value) if value == "example.com/api"
        ));
        assert!(error.to_string().contains("example.com/api"));

        let mut config = direct_selection_config();
        config.outbounds = vec![outbound];
        config.default_outbound_tag = Some("proxy".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        assert!(matches!(
            router.select_tcp_outbound().unwrap_err(),
            CoreError::InvalidGrpcAuthority(_)
        ));
    }

    /// The refusal above is defensible only for the value the *user typed*.
    /// Everything else in `dial.go:159-167` is derived on their behalf — the
    /// TLS server name, the destination domain, the `host:port` last resort —
    /// and blaming `grpcSettings.authority` for one of those sends the user
    /// looking for a key their config does not contain.
    ///
    /// An IDN destination is the plain case: `Authority` rejects every byte
    /// above 0x7f, and grpc-go sends the same name happily — verified on the
    /// wire against grpc-go v1.81.0, which delivers `:authority: 例え.jp` when
    /// `WithAuthority` carries it and `:authority: %E4%BE%8B%E3%81%88.jp:443`
    /// when it is empty and `encodeAuthority` escapes the endpoint.
    ///
    /// Each row still refuses the outbound, because
    /// [`super::grpc_authority`] documents why nothing else is reachable, but
    /// it must not refuse it as the configured key. It also has to survive
    /// `CachedOutboundError`, which panics on any `CoreError` it cannot
    /// represent, and which has to carry the key and the value across rather
    /// than rebuild them.
    ///
    /// Row 2 is the last-resort branch, whose value is composed out of an
    /// address and a port, so it names both keys — printing only the address
    /// key beside `例え.jp:443` would send the user hunting for a `:443` that
    /// key does not hold.
    ///
    /// Row 4 is the row that pins
    /// [`super::configured_tls_server_name`] to the *config*: it is the only
    /// input where reading the built connector instead would answer with a
    /// different key. `build_vless_tcp_outbound` fills
    /// `ConnectorConfig::Tls::server_name` from the destination domain when
    /// `tlsSettings.serverName` is absent, so a connector-driven read blames
    /// `streamSettings.tlsSettings.serverName` for a key the profile does not
    /// contain. Every other row agrees between the two.
    #[test]
    fn a_derived_authority_is_not_refused_as_the_configured_one() {
        for (security, server, key, value) in [
            (
                StreamSecurity::None,
                TargetAddr::Domain("例え.jp".to_owned()),
                "settings.vnext[0].address",
                "例え.jp",
            ),
            (
                StreamSecurity::Reality(reality_settings()),
                TargetAddr::Domain("例え.jp".to_owned()),
                "settings.vnext[0].address and settings.vnext[0].port",
                "例え.jp:443",
            ),
            (
                StreamSecurity::Tls(TlsSettings {
                    server_name: Some("例え.jp".to_owned()),
                    fingerprint: None,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn: Vec::new(),
                }),
                TargetAddr::Domain("dest.example.com".to_owned()),
                "streamSettings.tlsSettings.serverName",
                "例え.jp",
            ),
            (
                StreamSecurity::Tls(TlsSettings {
                    server_name: None,
                    fingerprint: None,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn: Vec::new(),
                }),
                TargetAddr::Domain("例え.jp".to_owned()),
                "settings.vnext[0].address",
                "例え.jp",
            ),
        ] {
            let outbound = grpc_vless(grpc_settings(None), security, server.clone());
            let error = build_vless_tcp_outbound(&outbound)
                .expect_err("an IDN authority is not one `http` can hold");
            assert!(
                matches!(
                    &error,
                    CoreError::UnrepresentableGrpcAuthority { key: got_key, value: got_value }
                        if *got_key == key && got_value == value
                ),
                "server={server:?} error={error}"
            );
            let message = error.to_string();
            assert!(message.contains(key), "{message}");
            assert!(message.contains(value), "{message}");
            assert!(
                !message.contains("grpcSettings.authority"),
                "a derived value must not blame the configured key: {message}"
            );

            let mut config = direct_selection_config();
            config.outbounds = vec![outbound];
            config.default_outbound_tag = Some("proxy".to_owned());
            config.routing.rules.clear();
            let router = OutboundRouter::new(Arc::new(config));
            let cached = router.select_tcp_outbound().unwrap_err();
            assert!(
                matches!(
                    &cached,
                    CoreError::UnrepresentableGrpcAuthority { key: got_key, value: got_value }
                        if *got_key == key && got_value == value
                ),
                "server={server:?} cached={cached}"
            );
        }
    }

    /// The same IDN string, this time *typed by the user*, and the message
    /// names the key they typed it in.
    ///
    /// Both halves of the chain refuse it — the wall is `http::Uri`, not a
    /// policy either half can relax — so what has to differ is who gets
    /// blamed. Pinned against the rows above so the two cannot quietly
    /// collapse back into one error.
    #[test]
    fn a_configured_authority_is_refused_under_the_key_the_user_wrote() {
        let outbound = grpc_vless(
            grpc_settings(Some("例え.jp")),
            StreamSecurity::None,
            TargetAddr::Domain("dest.example.com".to_owned()),
        );

        let error = build_vless_tcp_outbound(&outbound)
            .expect_err("an IDN authority is not one `http` can hold");
        assert!(matches!(
            &error,
            CoreError::InvalidGrpcAuthority(value) if value == "例え.jp"
        ));
        let message = error.to_string();
        assert!(message.contains("grpcSettings.authority"), "{message}");
        assert!(message.contains("例え.jp"), "{message}");
    }

    /// Neither `:authority` refusal may print the value it rejected raw.
    ///
    /// Both values are profile strings the config layer passes through: it
    /// rejects `grpcSettings.authority` only for emptiness
    /// (`crates/xray-config/src/parser.rs:2869-2872`) and copies
    /// `tlsSettings.serverName` unchecked (`parser.rs:3157-3160`), so a CR LF in
    /// either arrives here intact. Rendered with `{0}` or `{value}` it would let
    /// a profile forge a line in whatever shows the error — the exposure
    /// [`CoreError::InvalidGrpcUserAgent`] was born Debug-formatted to avoid and
    /// its two older neighbours carried until this test.
    ///
    /// One input covers both because a CR LF is what makes each string
    /// unrepresentable in the first place: the values that reach these two
    /// errors at all are drawn from the same set as the values that can forge.
    #[test]
    fn a_refused_authority_is_escaped_rather_than_printed() {
        let forged = "dest.example.com\r\nx-injected: 1";
        for (key, outbound) in [
            (
                "grpcSettings.authority",
                grpc_vless(
                    grpc_settings(Some(forged)),
                    StreamSecurity::None,
                    TargetAddr::Domain("dest.example.com".to_owned()),
                ),
            ),
            (
                TLS_SERVER_NAME_KEY,
                grpc_vless(
                    grpc_settings(None),
                    StreamSecurity::Tls(TlsSettings {
                        server_name: Some(forged.to_owned()),
                        fingerprint: None,
                        allow_insecure: false,
                        pinned_peer_cert_sha256: Vec::new(),
                        verify_peer_cert_by_name: Vec::new(),
                        alpn: Vec::new(),
                    }),
                    TargetAddr::Domain("dest.example.com".to_owned()),
                ),
            ),
        ] {
            let error = build_vless_tcp_outbound(&outbound)
                .expect_err("a CR LF cannot live in an authority");
            let message = error.to_string();
            assert!(message.contains(key), "{key}: {message}");
            assert!(message.contains(r"\r\n"), "{key}: {message}");
            assert!(!message.contains('\r'), "{key}: {message:?}");
            assert!(!message.contains('\n'), "{key}: {message:?}");
        }
    }

    /// `grpcSettings.user_agent` gets the same treatment as the authority, for
    /// the same reason: it is free-form JSON the config layer only checks for
    /// emptiness, it is settled once when the outbound is built, and it reaches
    /// the HEADERS block verbatim.
    ///
    /// Unlike the authority this costs no parity. grpc-go's client sends an
    /// unvalidated user agent byte for byte and a grpc-go peer then resets
    /// every stream carrying one with a control character in it, which
    /// `tests/fixtures/grpc/user_agent_validity.json` records from sixteen real
    /// dials. So the profiles refused here are the profiles that failed
    /// upstream — every flow, forever, with an error naming neither the key nor
    /// the character.
    ///
    /// Like the authority, it has to survive `CachedOutboundError`, which
    /// memoizes build failures and panics on any `CoreError` it cannot
    /// represent.
    #[test]
    fn an_unsendable_user_agent_refuses_the_outbound_once_instead_of_every_dial() {
        let unsendable = "grpc-go/1.81.0\r\nx-injected: 1";
        let outbound = grpc_vless(
            GrpcSettings {
                user_agent: Some(unsendable.to_owned()),
                ..grpc_settings(None)
            },
            StreamSecurity::None,
            TargetAddr::Domain("dest.example.com".to_owned()),
        );

        let error = build_vless_tcp_outbound(&outbound)
            .expect_err("a control character cannot live in a header value");
        assert!(matches!(
            &error,
            CoreError::InvalidGrpcUserAgent(value) if value == unsendable
        ));

        let message = error.to_string();
        assert!(message.contains("grpcSettings.user_agent"), "{message}");
        // Debug-formatted, so the CR LF the value carries is escaped rather
        // than printed. A `{0}` here would let a profile string forge a line in
        // whatever renders the error, which is the one thing this variant's
        // values are all guaranteed to be able to do.
        assert!(message.contains(r"\r\n"), "{message}");
        assert!(!message.contains('\r'), "{message:?}");

        let mut config = direct_selection_config();
        config.outbounds = vec![outbound];
        config.default_outbound_tag = Some("proxy".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        assert!(matches!(
            router.select_tcp_outbound().unwrap_err(),
            CoreError::InvalidGrpcUserAgent(_)
        ));
    }

    /// The keywords are not caught by the refusal above, and one boundary case
    /// is not either.
    ///
    /// `resolve_user_agent`'s three browser arms resolve through the masquerade
    /// draw rather than through the configured string, so a refusal that fired
    /// on one of them would be refusing a value the user did not write. The
    /// last row is the other half: `http` and `httpguts` both accept a byte
    /// above `0x7f`, so an outbound whose user agent is not ASCII at all still
    /// builds — a divergence would be silently narrowing what runs.
    #[test]
    fn a_sendable_user_agent_still_builds_whatever_it_looks_like() {
        for configured in [
            None,
            Some("chrome"),
            Some("firefox"),
            Some("edge"),
            Some("golang"),
            Some(""),
            Some("Mozilla/5.0 (例え)"),
            Some("grpc-go/1.81.0\tspaced"),
        ] {
            let outbound = grpc_vless(
                GrpcSettings {
                    user_agent: configured.map(str::to_owned),
                    ..grpc_settings(None)
                },
                StreamSecurity::None,
                TargetAddr::Domain("dest.example.com".to_owned()),
            );

            assert!(
                build_vless_tcp_outbound(&outbound).is_ok(),
                "user_agent {configured:?} is one grpc-go sends and a grpc-go peer accepts"
            );
        }
    }

    /// A pool that every selection rebuilt would be a pool of one flow. The
    /// `Arc` inside `GrpcTransport` is what makes it shared, and the cached
    /// router is what makes the same `GrpcTransport` reach every session.
    #[test]
    fn two_selections_of_one_grpc_outbound_share_a_pool() {
        let mut config = direct_selection_config();
        config.outbounds = vec![grpc_vless(
            grpc_settings(None),
            StreamSecurity::None,
            TargetAddr::Domain("dest.example.com".to_owned()),
        )];
        config.default_outbound_tag = Some("proxy".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let target = domain_tcp_target("example.test");

        let TcpOutbound::Vless(first_tcp) = router
            .select_tcp_outbound_for_session(None, &target)
            .unwrap()
        else {
            panic!("expected a cached VLESS TCP outbound");
        };
        let TcpOutbound::Vless(second_tcp) = router
            .select_tcp_outbound_for_session(None, &target)
            .unwrap()
        else {
            panic!("expected a cached VLESS TCP outbound");
        };
        let UdpOutbound::Vless(udp) = router
            .select_udp_outbound_for_session(
                None,
                &Target::new(target.addr.clone(), target.port, RoutingNetwork::Udp),
            )
            .unwrap()
        else {
            panic!("expected a cached VLESS UDP outbound");
        };

        let pools: Vec<_> = [
            first_tcp.transport_layer(),
            second_tcp.transport_layer(),
            udp.transport_layer(),
        ]
        .into_iter()
        .map(|layer| match layer {
            TransportLayer::Grpc(grpc) => grpc,
            other => panic!("expected the gRPC transport layer, got {other:?}"),
        })
        .collect();

        assert!(pools[0].shares_pool_with(pools[1]));
        assert!(pools[0].shares_pool_with(pools[2]));
    }

    #[tokio::test]
    async fn ip_if_non_match_uses_dns_second_pass_for_ip_rules() {
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        let mut rule = ip_rule("direct", Ipv4Addr::new(203, 0, 113, 7));
        rule.networks = vec![Network::Tcp];
        rule.port_ranges = vec![RoutingPortRange::single(443)];
        config.routing.rules = vec![rule];
        let router = OutboundRouter::new(Arc::new(config));
        let resolver =
            FakeDnsResolver::resolving_to(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)))
                .expect_lookup("example.test", 443);

        let selected = router
            .select_tcp_outbound_for_session_with_resolver(
                None,
                &domain_tcp_target("example.test"),
                &resolver,
            )
            .await
            .expect("select route using resolved IP");

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[tokio::test]
    async fn ip_if_non_match_uses_non_first_dns_candidate() {
        let first = Ipv4Addr::new(198, 51, 100, 10);
        let second = Ipv4Addr::new(203, 0, 113, 7);
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![ip_rule("direct", second)];
        let router = OutboundRouter::new(Arc::new(config));
        let resolver = FakeDnsResolver::resolving_to_many(vec![
            SocketAddr::from((first, 443)),
            SocketAddr::from((second, 443)),
        ])
        .expect_lookup("example.test", 443);

        let selected = router
            .select_tcp_outbound_for_session_with_resolver(
                None,
                &domain_tcp_target("example.test"),
                &resolver,
            )
            .await
            .expect("select route using a non-first resolved IP");

        assert!(matches!(selected, TcpOutbound::Freedom));
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test]
    async fn outbound_router_preserves_rule_priority_across_dns_candidates() {
        let first_candidate = Ipv4Addr::new(198, 51, 100, 10);
        let second_candidate = Ipv4Addr::new(203, 0, 113, 7);
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![
            ip_rule("direct", second_candidate),
            ip_rule("proxy", first_candidate),
        ];
        let router = OutboundRouter::new(Arc::new(config));
        let resolver = FakeDnsResolver::resolving_to_many(vec![
            SocketAddr::from((first_candidate, 443)),
            SocketAddr::from((second_candidate, 443)),
        ])
        .expect_lookup("example.test", 443);

        let selected = router
            .select_tcp_outbound_for_session_with_resolver(
                None,
                &domain_tcp_target("example.test"),
                &resolver,
            )
            .await
            .expect("select the first matching rule across all resolved IPs");

        assert!(matches!(selected, TcpOutbound::Freedom));
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test]
    async fn ip_if_non_match_reuses_cached_multi_address_lookup_without_losing_candidates() {
        let first_candidate = Ipv4Addr::new(198, 51, 100, 10);
        let second_candidate = Ipv4Addr::new(203, 0, 113, 7);
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![ip_rule("direct", second_candidate)];
        let router = OutboundRouter::new(Arc::new(config));
        let upstream = Arc::new(
            FakeDnsResolver::resolving_to_many(vec![
                SocketAddr::from((first_candidate, 443)),
                SocketAddr::from((second_candidate, 443)),
            ])
            .expect_lookup("example.test", 443),
        );
        let resolver = CachingDnsResolver::new(upstream.clone());

        for _ in 0..2 {
            let selected = router
                .select_tcp_outbound_for_session_with_resolver(
                    None,
                    &domain_tcp_target("example.test"),
                    &resolver,
                )
                .await
                .expect("select route from a cached multi-address lookup");

            assert!(matches!(selected, TcpOutbound::Freedom));
        }
        assert_eq!(upstream.calls(), 1);
    }

    #[tokio::test]
    async fn ip_if_non_match_second_pass_preserves_domain_for_combined_rule() {
        let resolved_ip = Ipv4Addr::new(203, 0, 113, 7);
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![domain_and_ip_rule("direct", "example.test", resolved_ip)];
        let router = OutboundRouter::new(Arc::new(config));
        let resolver = FakeDnsResolver::resolving_to(SocketAddr::from((resolved_ip, 443)))
            .expect_lookup("example.test", 443);

        let selected = router
            .select_tcp_outbound_for_session_with_resolver(
                None,
                &domain_tcp_target("example.test"),
                &resolver,
            )
            .await
            .expect("select combined domain and resolved-IP route");

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[tokio::test]
    async fn outbound_router_dns_second_pass_preserves_domain_for_combined_rule() {
        let resolved_ip = Ipv4Addr::new(203, 0, 113, 7);
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        let mut rule = domain_and_ip_rule("direct", "example.test", resolved_ip);
        rule.networks = vec![Network::Tcp];
        rule.port_ranges = vec![RoutingPortRange::single(443)];
        config.routing.rules = vec![rule];
        let router = OutboundRouter::new(Arc::new(config));
        let resolver = FakeDnsResolver::resolving_to(SocketAddr::from((resolved_ip, 443)))
            .expect_lookup("example.test", 443);

        let selected = router
            .select_tcp_outbound_for_session_with_resolver(
                None,
                &domain_tcp_target("example.test"),
                &resolver,
            )
            .await
            .expect("select cached combined domain and resolved-IP route");

        assert!(matches!(selected, TcpOutbound::Freedom));
    }

    #[test]
    fn outbound_router_original_metadata_selector_skips_ip_if_non_match_second_pass() {
        let resolved_ip = Ipv4Addr::new(203, 0, 113, 7);
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![ip_rule("direct", resolved_ip)];
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_tcp_outbound_for_session_with_tag(
                None,
                &domain_tcp_target("dns-upstream.example"),
                true,
            )
            .expect("DNS routing should use the default without resolving the upstream");

        assert!(matches!(selected.outbound, TcpOutbound::Vless(_)));
        assert_eq!(selected.tag.as_deref(), Some("proxy"));
    }

    #[test]
    fn outbound_router_supplied_ip_second_pass_preserves_domain_for_combined_rule() {
        let resolved_ipv4 = Ipv4Addr::new(203, 0, 113, 7);
        let resolved_ip = IpAddr::V4(resolved_ipv4);
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        let mut rule = domain_and_ip_rule("direct", "example.test", resolved_ipv4);
        rule.networks = vec![Network::Tcp];
        rule.port_ranges = vec![RoutingPortRange::single(443)];
        config.routing.rules = vec![rule];
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_tcp_outbound_for_session_with_tag_and_resolved_ip(
                None,
                &domain_tcp_target("example.test"),
                Some(&resolved_ip),
                false,
            )
            .expect("select supplied combined domain and resolved-IP route");

        assert!(matches!(selected.outbound, TcpOutbound::Freedom));
    }

    #[tokio::test]
    async fn ip_if_non_match_does_not_resolve_when_rule_matches_first_pass() {
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![
            inbound_rule("socks-in", "proxy"),
            ip_rule("direct", Ipv4Addr::new(203, 0, 113, 7)),
        ];
        let router = OutboundRouter::new(Arc::new(config));
        let resolver =
            FakeDnsResolver::resolving_to(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)));

        let selected = router
            .select_tcp_outbound_for_session_with_resolver(
                Some("socks-in"),
                &domain_tcp_target("example.test"),
                &resolver,
            )
            .await
            .expect("select first-pass route");

        assert!(matches!(selected, TcpOutbound::Vless(_)));
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn missing_outbound_tag_errors_only_when_selected() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![inbound_rule("api", "api")];
        let router = OutboundRouter::new(Arc::new(config));

        let selected = router
            .select_tcp_outbound_for_session(Some("socks-in"), &domain_tcp_target("example.test"))
            .expect("unmatched missing tag rule should fall back to default");
        assert!(matches!(selected, TcpOutbound::Vless(_)));

        let error = router
            .select_tcp_outbound_for_session(Some("api"), &domain_tcp_target("example.test"))
            .unwrap_err();
        assert!(matches!(error, CoreError::NoSupportedOutbound));
    }

    #[tokio::test]
    async fn ip_if_non_match_dns_failure_uses_default_outbound() {
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![ip_rule("direct", Ipv4Addr::new(203, 0, 113, 7))];
        let router = OutboundRouter::new(Arc::new(config));
        let resolver = FakeDnsResolver::failing_with(TransportError::NoResolvedAddress(
            "example.test".to_owned(),
            443,
        ))
        .expect_lookup("example.test", 443);

        let selected = router
            .select_tcp_outbound_for_session_with_resolver(
                None,
                &domain_tcp_target("example.test"),
                &resolver,
            )
            .await
            .expect("DNS failure should fall back to the configured default outbound");

        assert!(matches!(selected, TcpOutbound::Vless(_)));
        assert_eq!(resolver.calls(), 1);
    }

    #[derive(Debug)]
    struct DuplexRealityEngine {
        stream: Mutex<Option<tokio::io::DuplexStream>>,
        seen: Mutex<Option<(RealityClientConfig, Target)>>,
    }

    impl DuplexRealityEngine {
        fn new(stream: tokio::io::DuplexStream) -> Self {
            Self {
                stream: Mutex::new(Some(stream)),
                seen: Mutex::new(None),
            }
        }

        fn seen(&self) -> Option<(RealityClientConfig, Target)> {
            self.seen.lock().expect("seen lock").clone()
        }
    }

    #[async_trait]
    impl RealityTlsEngine for DuplexRealityEngine {
        async fn connect(
            &self,
            config: &RealityClientConfig,
            target: &Target,
        ) -> Result<BoxedTransportStream, TransportError> {
            *self.seen.lock().expect("seen lock") = Some((config.clone(), target.clone()));
            let stream = self
                .stream
                .lock()
                .expect("stream lock")
                .take()
                .expect("fake REALITY stream should be consumed once");

            Ok(Box::new(stream))
        }
    }

    #[tokio::test]
    async fn open_vless_tcp_stream_rejects_outbound_with_flow_before_connecting() {
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                server: Target::new(
                    RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    0,
                    RoutingNetwork::Tcp,
                ),
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: Some("xtls-rprx-vision".to_owned()),
                    level: 0,
                },
                transport: ConnectorConfig::Tcp,
                transport_layer: TransportLayer::Raw,
                happy_eyeballs: None,
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Tcp,
        );

        let result = open_vless_tcp_stream(&outbound, &target).await;

        assert!(matches!(result, Err(CoreError::UnsupportedOutboundFlow)));
    }

    #[tokio::test]
    async fn open_vless_tcp_stream_uses_default_live_reality_transport_for_vision_flow() {
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                server: Target::new(
                    RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    0,
                    RoutingNetwork::Tcp,
                ),
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: Some(VISION_FLOW.to_owned()),
                    level: 0,
                },
                transport: ConnectorConfig::Reality(RealityClientConfig {
                    server_name: "example.com".to_owned(),
                    fingerprint: "chrome".to_owned(),
                    public_key: [7; 32],
                    short_id: vec![1, 2, 3, 4],
                    spider_x: "/".to_owned(),
                    mldsa65_verify: None,
                }),
                transport_layer: TransportLayer::Raw,
                happy_eyeballs: None,
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Tcp,
        );

        let result = open_vless_tcp_stream(&outbound, &target).await;

        assert!(matches!(
            result,
            Err(CoreError::Transport(xray_transport::TransportError::Tcp(_)))
        ));
    }

    #[tokio::test]
    async fn open_vless_tcp_stream_wraps_injected_reality_stream_with_vision() {
        let reality_config = RealityClientConfig {
            server_name: "example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        };
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                server: Target::new(
                    RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    443,
                    RoutingNetwork::Tcp,
                ),
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: Some(VISION_FLOW.to_owned()),
                    level: 0,
                },
                transport: ConnectorConfig::Reality(reality_config.clone()),
                transport_layer: TransportLayer::Raw,
                happy_eyeballs: None,
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Tcp,
        );
        let (client, mut protected_side) = tokio::io::duplex(4096);
        let engine = Arc::new(DuplexRealityEngine::new(client));
        let transport_dialer = TransportDialer::system()
            .unwrap()
            .with_reality_engine(engine.clone());

        let mut stream = open_vless_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &transport_dialer,
        )
        .await
        .expect("open VLESS over injected REALITY stream");

        let expected_header = encode_request_header(&VlessRequest {
            user_id: outbound.user().id,
            command: VlessCommand::Tcp,
            target: target.clone(),
            flow: outbound.user().flow.clone(),
        })
        .unwrap();
        let mut received_header = vec![0; expected_header.len()];
        protected_side
            .read_exact(&mut received_header)
            .await
            .expect("read VLESS header from protected stream");
        assert_eq!(received_header, expected_header);

        let (header_padding, content_len, padding_len) =
            read_vision_frame(&mut protected_side, true).await;
        assert_eq!(content_len, 0);
        assert!((900..=1399).contains(&padding_len));
        let unpadded = unpad_vision_block(&header_padding, outbound.user().id.as_bytes()).unwrap();
        assert_eq!(unpadded.command, VisionCommand::Continue);
        assert!(unpadded.payload.is_empty());

        stream.write_all(b"vision payload").await.unwrap();
        stream.flush().await.unwrap();

        let (padded, content_len, padding_len) =
            read_vision_frame(&mut protected_side, false).await;
        assert_eq!(content_len, "vision payload".len());
        assert!(padding_len <= 255);
        let unpadded = unpad_vision_block(&padded, outbound.user().id.as_bytes()).unwrap();
        assert_eq!(unpadded.command, VisionCommand::Continue);
        assert_eq!(&unpadded.payload[..], b"vision payload");

        let (seen_config, seen_target) = engine.seen().expect("engine saw config and target");
        assert_eq!(seen_config, reality_config);
        assert_eq!(seen_target.addr, outbound.server().addr);
        assert_eq!(seen_target.port, outbound.server().port);
        assert_eq!(seen_target.network, outbound.server().network);
    }

    #[tokio::test]
    async fn open_vless_udp_stream_rejects_udp443_for_regular_vision_flow_before_connecting() {
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                server: Target::new(
                    RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    443,
                    RoutingNetwork::Tcp,
                ),
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: Some(VISION_FLOW.to_owned()),
                    level: 0,
                },
                transport: ConnectorConfig::Reality(RealityClientConfig {
                    server_name: "example.com".to_owned(),
                    fingerprint: "chrome".to_owned(),
                    public_key: [7; 32],
                    short_id: vec![1, 2, 3, 4],
                    spider_x: "/".to_owned(),
                    mldsa65_verify: None,
                }),
                transport_layer: TransportLayer::Raw,
                happy_eyeballs: None,
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Udp,
        );
        let (client, _protected_side) = tokio::io::duplex(4096);
        let engine = Arc::new(DuplexRealityEngine::new(client));
        let transport_dialer = TransportDialer::system()
            .unwrap()
            .with_reality_engine(engine.clone());

        let result = open_vless_udp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &transport_dialer,
        )
        .await;

        match result {
            Err(error) => assert_eq!(error.to_string(), "XTLS rejected UDP/443 traffic"),
            Ok(_) => panic!("expected UDP/443 rejection for regular Vision flow"),
        }
        assert!(
            engine.seen().is_none(),
            "UDP/443 rejection should happen before dialing the VLESS server"
        );
    }

    #[tokio::test]
    async fn open_vless_udp_stream_allows_udp443_flow_and_sends_vision_addons() {
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                server: Target::new(
                    RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    443,
                    RoutingNetwork::Tcp,
                ),
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: Some("xtls-rprx-vision-udp443".to_owned()),
                    level: 0,
                },
                transport: ConnectorConfig::Reality(RealityClientConfig {
                    server_name: "example.com".to_owned(),
                    fingerprint: "chrome".to_owned(),
                    public_key: [7; 32],
                    short_id: vec![1, 2, 3, 4],
                    spider_x: "/".to_owned(),
                    mldsa65_verify: None,
                }),
                transport_layer: TransportLayer::Raw,
                happy_eyeballs: None,
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Udp,
        );
        let (client, mut protected_side) = tokio::io::duplex(4096);
        let engine = Arc::new(DuplexRealityEngine::new(client));
        let transport_dialer = TransportDialer::system()
            .unwrap()
            .with_reality_engine(engine.clone());

        let (_stream, framing) = open_vless_udp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &transport_dialer,
        )
        .await
        .expect("open VLESS UDP/443 stream with explicit udp443 Vision flow");

        assert_eq!(framing, VlessUdpFraming::Xudp);
        let expected_header = encode_request_header(&VlessRequest {
            user_id: outbound.user().id,
            command: VlessCommand::Mux,
            target: target.clone(),
            flow: Some(VISION_FLOW.to_owned()),
        })
        .unwrap();
        let mut received_header = vec![0; expected_header.len()];
        protected_side
            .read_exact(&mut received_header)
            .await
            .expect("read VLESS header from protected stream");
        assert_eq!(received_header, expected_header);
        assert!(engine.seen().is_some());
    }

    #[test]
    fn vision_is_rejected_outside_the_raw_transport() {
        // Xray's VLESS outbound reaches into the private `input`/`rawInput`
        // fields of the security connection the dialer returns, so a dialer
        // that wraps that connection rather than returning it gets "XTLS only
        // supports TLS and REALITY directly for now." — which is every non-raw
        // transport implemented here.
        let error = validate_connector_flow(
            Some(VISION_FLOW),
            &ConnectorConfig::Tls(TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: Vec::new(),
                fingerprint: Some("chrome".to_owned()),
            }),
            &TransportLayer::WebSocket(WebSocketConfig {
                path: "/chat".to_owned(),
                host: "example.com".to_owned(),
                headers: Vec::new(),
                early_data_bytes: 0,
                heartbeat_period_secs: 0,
            }),
        )
        .expect_err("Vision needs a raw transport");

        assert!(matches!(error, CoreError::UnsupportedOutboundFlow));
    }

    #[test]
    fn vision_over_xhttp_is_rejected_as_non_raw_for_tls_and_reality() {
        for security in [
            tls_security(Some("sni.example"), &[]),
            StreamSecurity::Reality(reality_settings()),
        ] {
            let mut outbound = xhttp_vless(
                XhttpSettings::default(),
                security,
                TargetAddr::Domain("origin.example".to_owned()),
                443,
            );
            let OutboundSettings::Vless(settings) = &mut outbound.settings else {
                panic!("expected VLESS settings");
            };
            settings.users[0].flow = Some(VISION_FLOW.to_owned());

            let built = build_vless_tcp_outbound(&outbound)
                .expect("Xray accepts the XHTTP/Vision pairing at config-build time");
            assert!(matches!(built.transport_layer(), TransportLayer::Xhttp(_)));
            assert!(matches!(
                validate_connector_flow(
                    built.user().flow.as_deref(),
                    built.transport(),
                    built.transport_layer(),
                ),
                Err(CoreError::UnsupportedOutboundFlow)
            ));
        }

        let mut raw = direct_selection_vless("proxy");
        raw.stream.security = StreamSecurity::Reality(reality_settings());
        let OutboundSettings::Vless(settings) = &mut raw.settings else {
            panic!("expected VLESS settings");
        };
        settings.server = TargetAddr::Domain("origin.example".to_owned());
        settings.users[0].flow = Some(VISION_FLOW.to_owned());
        let built = build_vless_tcp_outbound(&raw).expect("raw REALITY Vision remains supported");
        assert!(matches!(built.transport_layer(), TransportLayer::Raw));
        assert!(validate_connector_flow(
            built.user().flow.as_deref(),
            built.transport(),
            built.transport_layer(),
        )
        .unwrap()
        .uses_vision());
    }

    /// The rule the retired `the_grpc_placeholder_refuses_every_vless_config_vision_or_not`
    /// asked for, now that `TransportLayer` has a `Grpc` variant to hand
    /// `validate_connector_flow`.
    ///
    /// Xray refuses `xtls-rprx-vision` over gRPC, but at *runtime*, not in the
    /// config layer: `proxy/vless/outbound/outbound.go:207` unwraps the dialled
    /// connection and `:274-283` needs it to be a `*tls.Conn`, `*tls.UConn` or
    /// `*reality.UConn` for Vision to splice itself into, which a gRPC hunk
    /// connection is not, so `:284` errors with "XTLS only supports TLS and
    /// REALITY directly for now.". Its config layer takes the pairing
    /// (`infra/conf/vless.go:326-330` looks at the flow string and nothing
    /// else), so refusing at *our* parse layer would be the divergence.
    ///
    /// Hence the two halves: the build succeeds, and the guard the connect path
    /// runs first refuses. `vision_is_rejected_outside_the_raw_transport` pins
    /// the transport-agnostic half of the same rule.
    #[test]
    fn vision_over_grpc_is_refused_at_the_connect_guard_not_at_the_build() {
        let visioned = build_vless_tcp_outbound(&grpc_reality_vless(Some(VISION_FLOW)))
            .expect("Xray's config layer accepts the pairing, so ours must build it");
        let error = validate_connector_flow(
            visioned.user().flow.as_deref(),
            visioned.transport(),
            visioned.transport_layer(),
        )
        .expect_err("Vision cannot reach into a gRPC hunk connection");
        assert!(matches!(error, CoreError::UnsupportedOutboundFlow));

        let flowless = build_vless_tcp_outbound(&grpc_reality_vless(None))
            .expect("gRPC without a flow is an ordinary outbound");
        assert_eq!(
            validate_connector_flow(
                flowless.user().flow.as_deref(),
                flowless.transport(),
                flowless.transport_layer(),
            )
            .expect("no flow, nothing to refuse"),
            VisionFlow::None
        );
    }

    #[test]
    fn vision_is_accepted_over_raw_tls() {
        let flow = validate_connector_flow(
            Some(VISION_FLOW),
            &ConnectorConfig::Tls(TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: Vec::new(),
                fingerprint: Some("chrome".to_owned()),
            }),
            &TransportLayer::Raw,
        )
        .expect("Vision over raw TLS stays valid");

        assert!(flow.uses_vision());
    }
}
