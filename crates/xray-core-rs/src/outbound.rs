use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_config::{
    CoreConfig, DnsOutboundSettings, Network, OutboundConfig, OutboundSettings,
    RoutingDomainStrategy, RoutingRule, StreamSecurity, StreamSettings, StreamTransport,
    TargetAddr, VlessUser,
};
use xray_proxy::vless::{
    encode_request_header, VisionStream, VisionStreamIo, VlessCommand, VlessRequest,
    VlessResponseStream, DEFAULT_VISION_SEED,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::stream::{
    resolve_user_agent, Authority, GrpcConfig, GrpcTransport, HttpUpgradeConfig, TransportLayer,
    WebSocketConfig,
};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, DnsResolver, HappyEyeballsConfig, RealityClientConfig,
    SystemDnsResolver, TlsClientConfig, TransportDialer, TransportStream,
};

use crate::policy::effective_policy_for_level;
use crate::{CompiledDnsOutboundPolicy, CoreError};

const VISION_FLOW: &str = "xtls-rprx-vision";
const VISION_UDP443_FLOW: &str = "xtls-rprx-vision-udp443";
const DNS_OUTBOUND_HARD_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_DNS_OUTBOUND_RUNTIME_IDENTITY: AtomicU64 = AtomicU64::new(1);

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

/// One configured handler selected for a UDP session. Keeping this combined
/// result avoids performing routing (and an IPIfNonMatch lookup) twice.
#[derive(Debug, Clone)]
pub(crate) enum UdpSessionOutbound {
    Transport(UdpOutbound),
    Dns(DnsOutbound),
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
    pub(crate) fn freedom_happy_eyeballs(&self) -> Option<&HappyEyeballsConfig> {
        match self {
            Self::Freedom => None,
            Self::FreedomHappyEyeballs(config) => Some(config),
            Self::Vless(_) => None,
        }
    }
}

/// Every build failure the router is allowed to memoize.
///
/// **Not `Copy` since `InvalidGrpcAuthority` joined it**, which is the price of
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

/// Persistent outbound selector and lazy compiler for one immutable core config.
///
/// Routing-rule order remains authoritative, duplicate outbound tags resolve to
/// their first configured entry, and invalid outbounds are compiled only when
/// selected.
#[derive(Debug)]
pub struct OutboundRouter {
    config: Arc<CoreConfig>,
    first_tag_index: HashMap<String, usize>,
    dns_route_prefilter: DnsRoutePrefilter,
    default_is_dns: bool,
    default_requires_selection: bool,
    entries: Box<[CachedOutboundEntry]>,
}

impl OutboundRouter {
    pub fn new(config: Arc<CoreConfig>) -> Self {
        let mut first_tag_index = HashMap::with_capacity(config.outbounds.len());
        for (index, outbound) in config.outbounds.iter().enumerate() {
            if let Some(tag) = outbound.tag.as_ref() {
                first_tag_index.entry(tag.clone()).or_insert(index);
            }
        }
        let is_dns_index =
            |index: usize| matches!(config.outbounds[index].settings, OutboundSettings::Dns(_));
        let dns_route_prefilter =
            DnsRoutePrefilter::new(config.routing.rules.iter().filter(|rule| {
                first_tag_index
                    .get(&rule.outbound_tag)
                    .is_some_and(|index| is_dns_index(*index))
            }));
        let default_index = config
            .default_outbound_tag
            .as_deref()
            .and_then(|tag| first_tag_index.get(tag).copied())
            .or_else(|| config.default_outbound_tag.is_none().then_some(0))
            .filter(|index| *index < config.outbounds.len());
        let default_is_dns = default_index.is_some_and(is_dns_index);
        let default_requires_selection =
            config.default_outbound_tag.is_some() && default_index.is_none();
        let entries = (0..config.outbounds.len())
            .map(|_| CachedOutboundEntry::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            config,
            first_tag_index,
            dns_route_prefilter,
            default_is_dns,
            default_requires_selection,
            entries,
        }
    }

    pub fn select_tcp_outbound(&self) -> Result<TcpOutbound, CoreError> {
        let index = self.select_configured_index(None, None, None, None, None)?;
        self.cached_tcp_outbound(index)
    }

    pub(crate) fn select_tcp_outbound_direct(
        &self,
        outbound_tag: Option<&str>,
    ) -> Result<TcpOutbound, CoreError> {
        let index = self.select_configured_index_direct(outbound_tag)?;
        self.cached_tcp_outbound(index)
    }

    pub fn select_tcp_outbound_for_session(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
    ) -> Result<TcpOutbound, CoreError> {
        let index = self.select_configured_index(
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        )?;
        self.cached_tcp_outbound(index)
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
        let index = self.select_configured_index(
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        )?;
        let tag = include_tag
            .then(|| self.config.outbounds[index].tag.clone())
            .flatten();
        let outbound = self.cached_tcp_outbound(index)?;
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
        let index =
            self.select_configured_index_with_resolved_ip(inbound_tag, target, resolved_ip)?;
        let tag = include_tag
            .then(|| self.config.outbounds[index].tag.clone())
            .flatten();
        let outbound = self.cached_tcp_outbound(index)?;
        Ok(SelectedTcpOutbound { outbound, tag })
    }

    pub async fn select_tcp_outbound_for_session_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<TcpOutbound, CoreError> {
        let index = self
            .select_configured_index_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        self.cached_tcp_outbound(index)
    }

    pub(crate) async fn select_tcp_session_outbound_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<TcpSessionOutbound, CoreError> {
        let index = self
            .select_configured_index_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        if matches!(
            self.config.outbounds[index].settings,
            OutboundSettings::Dns(_)
        ) {
            self.cached_dns_outbound(index).map(TcpSessionOutbound::Dns)
        } else {
            self.cached_tcp_outbound(index)
                .map(TcpSessionOutbound::Transport)
        }
    }

    pub(crate) async fn select_tcp_outbound_for_session_with_tag_and_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        include_tag: bool,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<SelectedTcpOutbound, CoreError> {
        let index = self
            .select_configured_index_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        let tag = include_tag
            .then(|| self.config.outbounds[index].tag.clone())
            .flatten();
        let outbound = self.cached_tcp_outbound(index)?;
        Ok(SelectedTcpOutbound { outbound, tag })
    }

    pub fn select_udp_outbound_for_session(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
    ) -> Result<UdpOutbound, CoreError> {
        let index = self.select_configured_index(
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        )?;
        self.cached_udp_outbound(index)
    }

    /// Returns the selected DNS message handler without treating regular
    /// transport outbounds as errors. Callers can therefore preserve their
    /// existing TCP/UDP path when no DNS outbound was selected.
    pub fn select_dns_outbound_for_session(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
    ) -> Result<Option<DnsOutbound>, CoreError> {
        if !self.may_select_dns_outbound(inbound_tag, target) {
            return Ok(None);
        }
        let index = self.select_configured_index(
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        )?;
        if !matches!(
            self.config.outbounds[index].settings,
            OutboundSettings::Dns(_)
        ) {
            return Ok(None);
        }
        self.cached_dns_outbound(index).map(Some)
    }

    pub async fn select_dns_outbound_for_session_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<Option<DnsOutbound>, CoreError> {
        if !self.may_select_dns_outbound(inbound_tag, target) {
            return Ok(None);
        }
        let index = self
            .select_configured_index_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        if !matches!(
            self.config.outbounds[index].settings,
            OutboundSettings::Dns(_)
        ) {
            return Ok(None);
        }
        self.cached_dns_outbound(index).map(Some)
    }

    fn may_select_dns_outbound(&self, inbound_tag: Option<&str>, target: &Target) -> bool {
        self.default_is_dns
            || self.default_requires_selection
            || self
                .dns_route_prefilter
                .may_match(inbound_tag, target_network(target), target.port)
    }

    /// Checks the effective tags assigned to managed DNS clients. Runtime DNS
    /// transports combine this compatibility check with their trusted origin
    /// context before bypassing DNS rules.
    pub(crate) fn is_dns_client_tag(&self, inbound_tag: Option<&str>) -> bool {
        let Some(inbound_tag) = inbound_tag else {
            return false;
        };
        self.config
            .dns
            .servers
            .iter()
            .any(|server| server.effective_tag(&self.config.dns.tag) == inbound_tag)
    }

    pub async fn select_udp_outbound_for_session_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<UdpOutbound, CoreError> {
        let index = self
            .select_configured_index_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        self.cached_udp_outbound(index)
    }

    pub(crate) async fn select_udp_session_outbound_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<UdpSessionOutbound, CoreError> {
        let index = self
            .select_configured_index_with_resolver(inbound_tag, target, dns_resolver)
            .await?;
        if matches!(
            self.config.outbounds[index].settings,
            OutboundSettings::Dns(_)
        ) {
            self.cached_dns_outbound(index).map(UdpSessionOutbound::Dns)
        } else {
            self.cached_udp_outbound(index)
                .map(UdpSessionOutbound::Transport)
        }
    }

    fn select_configured_index(
        &self,
        inbound_tag: Option<&str>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
        target_network: Option<Network>,
        target_port: Option<u16>,
    ) -> Result<usize, CoreError> {
        let routed_tag = select_routed_outbound_tag(
            &self.config,
            inbound_tag,
            target_domain,
            target_ip,
            target_network,
            target_port,
        );
        match routed_tag.or(self.config.default_outbound_tag.as_deref()) {
            Some(tag) => self.index_for_tag(tag),
            None if self.config.outbounds.is_empty() => Err(CoreError::NoSupportedOutbound),
            None => Ok(0),
        }
    }

    #[cfg(test)]
    fn select_configured_index_with_resolved_ip(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        resolved_ip: Option<&IpAddr>,
    ) -> Result<usize, CoreError> {
        if let Some(routed_tag) = select_routed_outbound_tag(
            &self.config,
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        ) {
            return self.index_for_tag(routed_tag);
        }

        if self.config.routing.domain_strategy == RoutingDomainStrategy::IpIfNonMatch {
            if let Some(resolved_ip) = resolved_ip {
                if let Some(routed_tag) = select_routed_outbound_tag(
                    &self.config,
                    inbound_tag,
                    target_domain(target),
                    Some(resolved_ip),
                    Some(target_network(target)),
                    Some(target.port),
                ) {
                    return self.index_for_tag(routed_tag);
                }
            }
        }

        self.select_default_configured_index()
    }

    async fn select_configured_index_with_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<usize, CoreError> {
        if let Some(routed_tag) = select_routed_outbound_tag(
            &self.config,
            inbound_tag,
            target_domain(target),
            target_ip(target),
            Some(target_network(target)),
            Some(target.port),
        ) {
            return self.index_for_tag(routed_tag);
        }

        if self.config.routing.domain_strategy == RoutingDomainStrategy::IpIfNonMatch {
            if let Some(domain) = target_domain(target) {
                if let Ok(resolved) = dns_resolver.resolve_all(domain, target.port).await {
                    if let Some(routed_tag) = select_routed_outbound_tag_with_resolved_ips(
                        &self.config,
                        inbound_tag,
                        Some(domain),
                        resolved.socket_addrs(),
                        Some(target_network(target)),
                        Some(target.port),
                    ) {
                        return self.index_for_tag(routed_tag);
                    }
                }
            }
        }

        self.select_default_configured_index()
    }

    fn select_configured_index_direct(
        &self,
        outbound_tag: Option<&str>,
    ) -> Result<usize, CoreError> {
        match outbound_tag.or(self.config.default_outbound_tag.as_deref()) {
            Some(tag) => self.index_for_tag(tag),
            None if self.config.outbounds.is_empty() => Err(CoreError::NoSupportedOutbound),
            None => Ok(0),
        }
    }

    fn select_default_configured_index(&self) -> Result<usize, CoreError> {
        match self.config.default_outbound_tag.as_deref() {
            Some(tag) => self.index_for_tag(tag),
            None if self.config.outbounds.is_empty() => Err(CoreError::NoSupportedOutbound),
            None => Ok(0),
        }
    }

    fn index_for_tag(&self, tag: &str) -> Result<usize, CoreError> {
        self.first_tag_index
            .get(tag)
            .copied()
            .ok_or(CoreError::NoSupportedOutbound)
    }

    fn cached_tcp_outbound(&self, index: usize) -> Result<TcpOutbound, CoreError> {
        let cached = self.entries[index]
            .tcp
            .get_or_init(|| self.compile_tcp_outbound(index));
        clone_cached_outbound(cached)
    }

    fn cached_udp_outbound(&self, index: usize) -> Result<UdpOutbound, CoreError> {
        let cached = self.entries[index]
            .udp
            .get_or_init(|| self.compile_udp_outbound(index));
        clone_cached_outbound(cached)
    }

    fn cached_dns_outbound(&self, index: usize) -> Result<DnsOutbound, CoreError> {
        let cached = self.entries[index]
            .dns
            .get_or_init(|| self.compile_dns_outbound(index));
        clone_cached_outbound(cached)
    }

    fn cached_vless_outbound(&self, index: usize) -> Result<VlessTcpOutbound, CachedOutboundError> {
        let cached = self.entries[index].vless.get_or_init(|| {
            build_vless_tcp_outbound(&self.config.outbounds[index])
                .map_err(CachedOutboundError::from_core_error)
        });
        match cached {
            Ok(outbound) => Ok(outbound.clone()),
            Err(error) => Err(error.clone()),
        }
    }

    fn compile_tcp_outbound(&self, index: usize) -> Result<TcpOutbound, CachedOutboundError> {
        let outbound = &self.config.outbounds[index];
        if outbound.stream.network != Network::Tcp {
            return Err(CachedOutboundError::UnsupportedOutboundNetwork);
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
                Ok(build_freedom_tcp_outbound(&outbound.stream))
            }
            OutboundSettings::Vless(_) => self
                .cached_vless_outbound(index)
                .map(|outbound| TcpOutbound::Vless(Box::new(outbound))),
        }
    }

    fn compile_udp_outbound(&self, index: usize) -> Result<UdpOutbound, CachedOutboundError> {
        let outbound = &self.config.outbounds[index];
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
                self.cached_vless_outbound(index)
                    .map(|outbound| UdpOutbound::Vless(Box::new(outbound)))
            }
        }
    }

    fn compile_dns_outbound(&self, index: usize) -> Result<DnsOutbound, CachedOutboundError> {
        let configured = &self.config.outbounds[index];
        match &configured.settings {
            OutboundSettings::Dns(settings) => {
                let conn_idle =
                    effective_policy_for_level(&self.config, Some(settings.user_level)).conn_idle;
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

pub fn select_tcp_outbound(config: &CoreConfig) -> Result<TcpOutbound, CoreError> {
    let outbound = select_configured_outbound(config, None, None, None, None, None)?;
    build_tcp_outbound(outbound)
}

#[allow(dead_code)]
pub(crate) fn select_tcp_outbound_direct(
    config: &CoreConfig,
    outbound_tag: Option<&str>,
) -> Result<TcpOutbound, CoreError> {
    let outbound = select_configured_outbound_direct(config, outbound_tag)?;
    build_tcp_outbound(outbound)
}

/// Selects a session outbound using only the original target metadata.
///
/// Runtime paths that need `routing.domainStrategy = IPIfNonMatch` should use
/// `select_tcp_outbound_for_session_with_resolver` so DNS-based second-pass
/// routing can run.
pub fn select_tcp_outbound_for_session(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
) -> Result<TcpOutbound, CoreError> {
    let outbound = select_configured_outbound(
        config,
        inbound_tag,
        target_domain(target),
        target_ip(target),
        Some(target_network(target)),
        Some(target.port),
    )?;
    build_tcp_outbound(outbound)
}

pub async fn select_tcp_outbound_for_session_with_resolver(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<TcpOutbound, CoreError> {
    let outbound =
        select_configured_outbound_with_resolver(config, inbound_tag, target, dns_resolver).await?;
    build_tcp_outbound(outbound)
}

/// Selects a UDP session outbound using only the original target metadata.
///
/// Runtime paths that need `routing.domainStrategy = IPIfNonMatch` should use
/// `select_udp_outbound_for_session_with_resolver` so DNS-based second-pass
/// routing can run.
pub fn select_udp_outbound_for_session(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
) -> Result<UdpOutbound, CoreError> {
    let outbound = select_configured_outbound(
        config,
        inbound_tag,
        target_domain(target),
        target_ip(target),
        Some(target_network(target)),
        Some(target.port),
    )?;
    build_udp_outbound(outbound)
}

pub async fn select_udp_outbound_for_session_with_resolver(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<UdpOutbound, CoreError> {
    let outbound =
        select_configured_outbound_with_resolver(config, inbound_tag, target, dns_resolver).await?;
    build_udp_outbound(outbound)
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
/// The `Host` header follows Xray's precedence -- the transport's own `host`,
/// else the TLS server name, else the destination address -- and never carries
/// a port, because Xray sets the header from those three values directly and
/// only appends a port to the dial URI.
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
            // `ed` on this transport carries no payload; any positive value
            // only means "do not block waiting for the 101".
            wait_for_response: upgrade.early_data_bytes == 0,
        }),
        StreamTransport::Grpc(grpc) => TransportLayer::Grpc(GrpcTransport::new(GrpcConfig {
            service_name: grpc.service_name.clone(),
            multi_mode: grpc.multi_mode,
            authority: grpc_authority(
                grpc.authority.as_deref(),
                connector,
                &settings.server,
                settings.port,
            )?,
            user_agent: resolve_user_agent(grpc.user_agent.as_deref()),
            idle_timeout_secs: grpc.idle_timeout_secs,
            health_check_timeout_secs: grpc.health_check_timeout_secs,
            permit_without_stream: grpc.permit_without_stream,
            initial_windows_size: grpc.initial_windows_size,
        })),
    })
}

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
/// The parse is the one place a malformed `grpcSettings.authority` is caught:
/// see [`xray_transport::stream::GrpcConfig::authority`] for why it is refused
/// rather than sent verbatim the way grpc-go would.
fn grpc_authority(
    configured: Option<&str>,
    connector: &ConnectorConfig,
    server: &TargetAddr,
    port: u16,
) -> Result<Authority, CoreError> {
    // The config layer has already collapsed an empty `authority` to `None`,
    // matching Go's inability to tell one from an absent key.
    let resolved = if let Some(authority) = configured {
        authority.to_owned()
    } else if let Some(server_name) = configured_tls_server_name(connector) {
        server_name.to_owned()
    } else {
        match server {
            TargetAddr::Domain(domain) if !matches!(connector, ConnectorConfig::Reality(_)) => {
                domain.clone()
            }
            _ => host_and_port(server, port),
        }
    };

    match Authority::try_from(resolved.as_str()) {
        Ok(authority) => Ok(authority),
        Err(_) => Err(CoreError::InvalidGrpcAuthority(resolved)),
    }
}

/// `tlsSettings.serverName` as `dial.go:162` reads it, and nothing else.
///
/// The empty-name arm is unreachable from `build_vless_tcp_outbound`, which
/// refuses a TLS stream whose server name resolves to nothing long before this
/// runs. It is kept because `dial.go:162` tests emptiness too: without it the
/// function would encode an invariant of one caller rather than Xray's rule,
/// and a caller that stops holding it would silently send `:authority: ` empty
/// instead of falling through to the destination.
fn configured_tls_server_name(connector: &ConnectorConfig) -> Option<&str> {
    match connector {
        ConnectorConfig::Tls(tls) if !tls.server_name.is_empty() => Some(&tls.server_name),
        ConnectorConfig::Tcp | ConnectorConfig::Tls(_) | ConnectorConfig::Reality(_) => None,
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

pub fn select_vless_tcp_outbound(config: &CoreConfig) -> Result<VlessTcpOutbound, CoreError> {
    let outbound = select_configured_outbound(config, None, None, None, None, None)?;
    build_vless_tcp_outbound(outbound)
}

fn select_configured_outbound<'a>(
    config: &'a CoreConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_ip: Option<&IpAddr>,
    target_network: Option<Network>,
    target_port: Option<u16>,
) -> Result<&'a OutboundConfig, CoreError> {
    let routed_tag = select_routed_outbound_tag(
        config,
        inbound_tag,
        target_domain,
        target_ip,
        target_network,
        target_port,
    );

    let outbound = match routed_tag.or(config.default_outbound_tag.as_deref()) {
        Some(tag) => config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
            .ok_or(CoreError::NoSupportedOutbound)?,
        None => config
            .outbounds
            .first()
            .ok_or(CoreError::NoSupportedOutbound)?,
    };

    Ok(outbound)
}

async fn select_configured_outbound_with_resolver<'a>(
    config: &'a CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<&'a OutboundConfig, CoreError> {
    if let Some(routed_tag) = select_routed_outbound_tag(
        config,
        inbound_tag,
        target_domain(target),
        target_ip(target),
        Some(target_network(target)),
        Some(target.port),
    ) {
        return select_configured_outbound_by_tag(config, routed_tag);
    }

    if config.routing.domain_strategy == RoutingDomainStrategy::IpIfNonMatch {
        if let Some(domain) = target_domain(target) {
            if let Ok(resolved) = dns_resolver.resolve_all(domain, target.port).await {
                if let Some(routed_tag) = select_routed_outbound_tag_with_resolved_ips(
                    config,
                    inbound_tag,
                    Some(domain),
                    resolved.socket_addrs(),
                    Some(target_network(target)),
                    Some(target.port),
                ) {
                    return select_configured_outbound_by_tag(config, routed_tag);
                }
            }
        }
    }

    select_default_configured_outbound(config)
}

fn select_routed_outbound_tag<'a>(
    config: &'a CoreConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_ip: Option<&IpAddr>,
    target_network: Option<Network>,
    target_port: Option<u16>,
) -> Option<&'a str> {
    config
        .routing
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
        .map(|rule| rule.outbound_tag.as_str())
}

fn select_routed_outbound_tag_with_resolved_ips<'a>(
    config: &'a CoreConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_addrs: &[SocketAddr],
    target_network: Option<Network>,
    target_port: Option<u16>,
) -> Option<&'a str> {
    config
        .routing
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
        .map(|rule| rule.outbound_tag.as_str())
}

fn select_configured_outbound_by_tag<'a>(
    config: &'a CoreConfig,
    tag: &str,
) -> Result<&'a OutboundConfig, CoreError> {
    config
        .outbounds
        .iter()
        .find(|outbound| outbound.tag.as_deref() == Some(tag))
        .ok_or(CoreError::NoSupportedOutbound)
}

fn select_default_configured_outbound(config: &CoreConfig) -> Result<&OutboundConfig, CoreError> {
    match config.default_outbound_tag.as_deref() {
        Some(tag) => select_configured_outbound_by_tag(config, tag),
        None => config
            .outbounds
            .first()
            .ok_or(CoreError::NoSupportedOutbound),
    }
}

#[allow(dead_code)]
fn select_configured_outbound_direct<'a>(
    config: &'a CoreConfig,
    outbound_tag: Option<&str>,
) -> Result<&'a OutboundConfig, CoreError> {
    match outbound_tag.or(config.default_outbound_tag.as_deref()) {
        Some(tag) => config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
            .ok_or(CoreError::NoSupportedOutbound),
        None => config
            .outbounds
            .first()
            .ok_or(CoreError::NoSupportedOutbound),
    }
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
                Some(_) => return Err(CoreError::UnsupportedOutboundSecurity),
                None => match &settings.server {
                    TargetAddr::Domain(domain) => domain.clone(),
                    TargetAddr::Ip(_) => return Err(CoreError::UnsupportedOutboundSecurity),
                },
            };

            ConnectorConfig::Tls(TlsClientConfig {
                server_name,
                allow_insecure: tls.allow_insecure,
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
                    alpn: tls.alpn.clone(),
                    fingerprint: tls.fingerprint.clone(),
                }),
            )),
            Some(_) | None => Ok(DnsTcpConnector::TlsFromTarget {
                allow_insecure: tls.allow_insecure,
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
    // Vision splices itself into the TLS connection's internals, so anything
    // layered between the two breaks it. Xray refuses the same pairing with
    // "XTLS only supports TLS and REALITY directly for now."
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
    match outbound {
        TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => {
            let candidates = resolve_server_candidates(target, destination_resolver).await?;
            Ok(transport_dialer
                .connect_resolved(
                    &ConnectorConfig::Tcp,
                    target,
                    &candidates,
                    outbound.freedom_happy_eyeballs(),
                )
                .await?)
        }
        TcpOutbound::Vless(outbound) => {
            open_vless_tcp_stream_with_resolver_and_dialer(
                outbound,
                target,
                bootstrap_resolver,
                transport_dialer,
            )
            .await
        }
    }
}

pub async fn open_vless_tcp_stream_with_resolver_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    let flow = validate_connector_flow(
        outbound.user().flow.as_deref(),
        outbound.transport(),
        outbound.transport_layer(),
    )?;

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
    use uuid::Uuid;
    use xray_config::{
        DnsConfig, DnsServerConfig, DomainMatcher, GrpcSettings, HappyEyeballsSettings,
        HttpUpgradeSettings, IpCidr, IpMatcher, RealitySettings, RealityShortId, RoutingConfig,
        RoutingDomainStrategy, RoutingPortRange, RoutingRule, SocketOptions, StreamSettings,
        TlsSettings, VlessOutboundSettings, WebSocketSettings,
    };
    use xray_proxy::vless::{unpad_vision_block, VisionCommand};
    use xray_transport::{CachingDnsResolver, DnsLookup, RealityTlsEngine, TransportError};

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

    fn direct_selection_freedom(tag: &str) -> OutboundConfig {
        OutboundConfig {
            tag: Some(tag.to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                socket_options: None,
            },
            settings: OutboundSettings::Freedom,
        }
    }

    fn direct_selection_vless(tag: &str) -> OutboundConfig {
        OutboundConfig {
            tag: Some(tag.to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
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
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
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
                    domain_matchers: Vec::new(),
                    ip_matchers: Vec::new(),
                    outbound_tag: "direct".to_owned(),
                }],
                ..Default::default()
            },
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

    fn domain_tcp_target(domain: &str) -> Target {
        Target::new(
            RoutingTargetAddr::Domain(domain.to_owned()),
            443,
            RoutingNetwork::Tcp,
        )
    }

    fn ip_rule(tag: &str, ip: Ipv4Addr) -> RoutingRule {
        RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: vec![IpMatcher::Cidr(IpCidr::full(IpAddr::V4(ip)))],
            outbound_tag: tag.to_owned(),
        }
    }

    fn domain_and_ip_rule(tag: &str, domain: &str, ip: Ipv4Addr) -> RoutingRule {
        RoutingRule {
            inbound_tags: Vec::new(),
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: vec![DomainMatcher::Full(domain.to_owned())],
            ip_matchers: vec![IpMatcher::Cidr(IpCidr::full(IpAddr::V4(ip)))],
            outbound_tag: tag.to_owned(),
        }
    }

    fn inbound_rule(inbound_tag: &str, outbound_tag: &str) -> RoutingRule {
        RoutingRule {
            inbound_tags: vec![inbound_tag.to_owned()],
            networks: Vec::new(),
            port_ranges: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: outbound_tag.to_owned(),
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
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: outbound_tag.to_owned(),
        }
    }

    #[test]
    fn standalone_tcp_session_selector_matches_target_network_and_port() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Tcp,
            RoutingPortRange::single(443),
        )];

        let selected =
            select_tcp_outbound_for_session(&config, None, &domain_tcp_target("example.test"))
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
                    allow_insecure: true,
                    alpn: Vec::new(),
                }),
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
                allow_insecure: true,
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
                        alpn: Vec::new(),
                    }),
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
                    alpn: Vec::new(),
                    fingerprint: None,
                })
            );
        }
    }

    #[test]
    fn tls_outbound_carries_the_fingerprint_into_the_connector() {
        let stream = StreamSettings {
            network: Network::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::Tls(TlsSettings {
                server_name: Some("example.com".to_owned()),
                fingerprint: Some("firefox".to_owned()),
                allow_insecure: false,
                alpn: vec!["http/1.1".to_owned()],
            }),
            socket_options: None,
        };

        let connector = dns_tcp_connector(&stream).expect("a TLS fingerprint must be accepted");

        let DnsTcpConnector::Static(ConnectorConfig::Tls(tls)) = connector else {
            panic!("expected a static TLS connector");
        };
        assert_eq!(tls.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(tls.alpn, vec!["http/1.1".to_owned()]);
    }

    #[test]
    fn target_derived_tls_connector_carries_the_fingerprint() {
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
                    alpn: vec!["h2".to_owned()],
                }),
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
                alpn: vec!["h2".to_owned()],
                fingerprint: Some("firefox".to_owned()),
            })
        );
    }

    #[test]
    fn dns_outbound_rejects_an_unsupported_stream_network_instead_of_downgrading() {
        let non_tcp = DnsOutbound::new_with_stream(
            DnsOutboundSettings::default(),
            &StreamSettings {
                network: Network::Udp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
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
                    alpn: Vec::new(),
                }),
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
        let udp_ranges = &router.dns_route_prefilter.network_ports.udp;

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
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: "dns-out".to_owned(),
        }];

        let router = OutboundRouter::new(Arc::new(config));

        assert!(!router.dns_route_prefilter.wildcard_inbound);
        assert_eq!(
            router.dns_route_prefilter.tagged_inbounds.len(),
            SELECTOR_COUNT
        );
        assert_eq!(
            router.dns_route_prefilter.network_ports.udp.len(),
            SELECTOR_COUNT
        );
        assert!(router.dns_route_prefilter.network_ports.tcp.is_empty());
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
        rule.domain_matchers = vec![DomainMatcher::Full("dns-only.test".to_owned())];
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
    fn standalone_session_selector_rejects_target_network_mismatch() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Tcp,
            RoutingPortRange::single(53),
        )];
        let target = Target::new(
            RoutingTargetAddr::Domain("example.test".to_owned()),
            53,
            RoutingNetwork::Udp,
        );

        let selected = select_udp_outbound_for_session(&config, None, &target)
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
    fn legacy_selector_without_target_ignores_network_and_port_rule() {
        let mut config = direct_selection_config();
        config.routing.rules = vec![network_port_rule(
            "direct",
            Network::Tcp,
            RoutingPortRange::single(443),
        )];

        let selected = select_tcp_outbound(&config)
            .expect("legacy selection should use the configured default route");

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
    fn select_tcp_outbound_direct_uses_explicit_tag() {
        let selected =
            select_tcp_outbound_direct(&direct_selection_config(), Some("direct")).unwrap();

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
    fn select_tcp_outbound_direct_uses_default_tag_without_routing() {
        let selected = select_tcp_outbound_direct(&direct_selection_config(), None).unwrap();

        assert!(matches!(selected, TcpOutbound::Vless(_)));
    }

    #[test]
    fn select_tcp_outbound_direct_errors_when_explicit_tag_is_missing() {
        let error =
            select_tcp_outbound_direct(&direct_selection_config(), Some("missing")).unwrap_err();

        assert!(matches!(error, CoreError::NoSupportedOutbound));
    }

    #[test]
    fn select_tcp_outbound_direct_uses_first_outbound_without_default() {
        let mut config = direct_selection_config();
        config.default_outbound_tag = None;

        let selected = select_tcp_outbound_direct(&config, None).unwrap();

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
        assert_eq!(router.first_tag_index.get("duplicate"), Some(&0));
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

        assert!(router.entries[2].tcp.get().is_none());
        assert!(matches!(
            router
                .select_tcp_outbound_for_session(Some("socks-in"), &target)
                .unwrap(),
            TcpOutbound::Freedom
        ));
        assert!(router.entries[2].tcp.get().is_none());

        let error = router
            .select_tcp_outbound_for_session(Some("api"), &target)
            .unwrap_err();
        assert!(matches!(error, CoreError::UnsupportedOutboundNetwork));
        assert!(router.entries[2].tcp.get().is_some());
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
        let resolver =
            FakeDnsResolver::resolving_to(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)))
                .expect_lookup("example.test", 443);

        let selected = select_tcp_outbound_for_session_with_resolver(
            &config,
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
        let resolver = FakeDnsResolver::resolving_to_many(vec![
            SocketAddr::from((first, 443)),
            SocketAddr::from((second, 443)),
        ])
        .expect_lookup("example.test", 443);

        let selected = select_tcp_outbound_for_session_with_resolver(
            &config,
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
        let resolver = FakeDnsResolver::resolving_to(SocketAddr::from((resolved_ip, 443)))
            .expect_lookup("example.test", 443);

        let selected = select_tcp_outbound_for_session_with_resolver(
            &config,
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
        let resolver =
            FakeDnsResolver::resolving_to(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)));

        let selected = select_tcp_outbound_for_session_with_resolver(
            &config,
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

        let selected = select_tcp_outbound_for_session(
            &config,
            Some("socks-in"),
            &domain_tcp_target("example.test"),
        )
        .expect("unmatched missing tag rule should fall back to default");
        assert!(matches!(selected, TcpOutbound::Vless(_)));

        let error = select_tcp_outbound_for_session(
            &config,
            Some("api"),
            &domain_tcp_target("example.test"),
        )
        .unwrap_err();
        assert!(matches!(error, CoreError::NoSupportedOutbound));
    }

    #[tokio::test]
    async fn ip_if_non_match_dns_failure_uses_default_outbound() {
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        config.routing.rules = vec![ip_rule("direct", Ipv4Addr::new(203, 0, 113, 7))];
        let resolver = FakeDnsResolver::failing_with(TransportError::NoResolvedAddress(
            "example.test".to_owned(),
            443,
        ))
        .expect_lookup("example.test", 443);

        let selected = select_tcp_outbound_for_session_with_resolver(
            &config,
            None,
            &domain_tcp_target("example.test"),
            &resolver,
        )
        .await
        .expect("DNS failure should fall back to the configured default outbound");

        assert!(matches!(selected, TcpOutbound::Vless(_)));
        assert_eq!(resolver.calls(), 1);

        let router = OutboundRouter::new(Arc::new(config));
        let cached_resolver = FakeDnsResolver::failing_with(TransportError::NoResolvedAddress(
            "example.test".to_owned(),
            443,
        ))
        .expect_lookup("example.test", 443);
        let selected = router
            .select_tcp_outbound_for_session_with_resolver(
                None,
                &domain_tcp_target("example.test"),
                &cached_resolver,
            )
            .await
            .expect("cached router should use the configured default outbound");

        assert!(matches!(selected, TcpOutbound::Vless(_)));
        assert_eq!(cached_resolver.calls(), 1);
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
        // Xray's VLESS outbound reaches into the TLS connection's private
        // fields to splice Vision in, so anything layered between the two
        // breaks it: "XTLS only supports TLS and REALITY directly for now."
        let error = validate_connector_flow(
            Some(VISION_FLOW),
            &ConnectorConfig::Tls(TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
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
                alpn: Vec::new(),
                fingerprint: Some("chrome".to_owned()),
            }),
            &TransportLayer::Raw,
        )
        .expect("Vision over raw TLS stays valid");

        assert!(flow.uses_vision());
    }
}
