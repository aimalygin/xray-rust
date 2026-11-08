mod vmess;
pub use vmess::VmessOutbound;
mod first_payload;
mod protocol_stream;
use first_payload::{
    flush_header_alone, FirstPayloadDeadline, HeldHeader, TROJAN_FIRST_PAYLOAD_WAIT,
    VLESS_FIRST_PAYLOAD_WAIT,
};
mod shadowsocks;
pub use shadowsocks::Shadowsocks2022Outbound;
mod blackhole;
pub(crate) use blackhole::{
    absorb_udp_datagrams, absorb_udp_datagrams_until, BlackholeOutbound, BLACKHOLE_RESPONSE_GRACE,
};
mod encryption;
mod trojan;
pub use trojan::TrojanOutbound;
mod socks;
pub use socks::SocksOutbound;
mod http;
pub use http::HttpOutbound;
pub(crate) mod hysteria;
pub use hysteria::HysteriaOutbound;
pub(crate) mod wireguard;
pub use wireguard::WireguardOutbound;
mod address_port;
mod carrier;
pub(crate) mod datagram;
mod domain_strategy;
pub(crate) mod final_rules;
pub(crate) mod proxy_protocol;
pub(crate) use domain_strategy::DomainStrategyResolver;
mod mux;
mod preconnect;
mod routing;
pub(crate) mod socket_options;
mod xhttp;
mod xudp;
use carrier::StreamCarrier;

use xhttp::*;

use routing::{select_routed_target, select_routed_target_with_resolver};

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    CoreConfig, DnsOutboundSettings, DomainStrategy, FreedomFinalRule, FreedomOutboundSettings,
    FreedomRedirect, Network, OutboundConfig, OutboundSettings, ProxyProtocolVersion,
    QuicParamsSettings, RouteContext, RoutingBalancerStrategy, RoutingConfig,
    RoutingDomainStrategy, RoutingLeastLoadSettings, RoutingRule, RoutingRuleTarget,
    StreamSecurity, StreamSettings, StreamTransport, TargetAddr, VlessUser, XhttpSettings,
};
use xray_proxy::vless::{
    encode_request_header, VisionStream, VisionStreamIo, VlessCommand, VlessRequest,
    VlessResponseStream,
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
use zeroize::Zeroizing;

use crate::policy::effective_policy_for_level;
use crate::{CompiledDnsOutboundPolicy, CoreError};
pub(crate) use proxy_protocol::InboundSource;

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
    carrier: StreamCarrier,
    user: VlessUser,
    encryption: Option<xray_vless_encryption::Client>,
    mux: Option<mux::Runtime>,
    /// `testpre`: carrier connections opened ahead of requests.
    pre_connections: Option<preconnect::PreConnections>,
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

/// A freedom outbound, which dials destinations itself. The default dials
/// as Xray-core's freedom does with no settings.
#[derive(Debug, Clone, Default)]
pub struct FreedomOutbound {
    fragment: Option<Arc<xray_transport::TcpFragmentConfig>>,
    happy_eyeballs: Option<HappyEyeballsConfig>,
    /// `sockopt`, for every TCP and UDP socket freedom opens.
    socket_options: Option<Arc<xray_transport::SocketOptions>>,
    domain_strategy: DomainStrategy,
    /// Present only when it changes the destination.
    redirect: Option<Arc<FreedomRedirect>>,
    user_level: u32,
    proxy_protocol: Option<ProxyProtocolVersion>,
    /// Present only when there are rules.
    final_rules: Option<Arc<[FreedomFinalRule]>>,
    /// Present only when there are noises.
    noises: Option<Arc<[xray_config::FreedomNoise]>>,
}

#[derive(Debug, Clone)]
pub enum TcpOutbound {
    Freedom(FreedomOutbound),
    Vless(Box<VlessTcpOutbound>),
    Trojan(TrojanOutbound),
    Socks(SocksOutbound),
    Http(HttpOutbound),
    Vmess(VmessOutbound),
    Shadowsocks2022(Shadowsocks2022Outbound),
    Hysteria(HysteriaOutbound),
    Wireguard(WireguardOutbound),
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
    Freedom(FreedomOutbound),
    Vless(Box<VlessTcpOutbound>),
    Trojan(TrojanOutbound),
    Socks(SocksOutbound),
    Vmess(VmessOutbound),
    Shadowsocks2022(Shadowsocks2022Outbound),
    Hysteria(HysteriaOutbound),
    Wireguard(WireguardOutbound),
}

/// One configured handler selected for a TCP session. DNS remains a message
/// handler rather than pretending to be a byte-stream transport, and a
/// blackhole answers the session itself without dialing.
#[derive(Debug, Clone)]
pub(crate) enum TcpSessionOutbound {
    Transport(TcpOutbound),
    Dns(DnsOutbound),
    Blackhole(BlackholeOutbound),
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
    /// The flow gets the optional response once and its datagrams are then
    /// discarded without opening a socket.
    Blackhole(BlackholeOutbound),
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
        &self.payload.carrier.server
    }
    fn carrier(&self) -> &carrier::StreamCarrier {
        &self.payload.carrier
    }

    pub fn transport(&self) -> &ConnectorConfig {
        &self.payload.carrier.transport
    }

    pub fn transport_layer(&self) -> &TransportLayer {
        &self.payload.carrier.transport_layer
    }

    pub fn user(&self) -> &VlessUser {
        &self.payload.user
    }

    fn encryption(&self) -> Option<&xray_vless_encryption::Client> {
        self.payload.encryption.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn happy_eyeballs(&self) -> Option<&HappyEyeballsConfig> {
        self.payload.carrier.happy_eyeballs.as_ref()
    }

    /// True for the regular `xtls-rprx-vision` flow, which (matching upstream
    /// xray-core) cannot carry UDP/443 and must refuse it so QUIC apps fall back
    /// to TCP. The `xtls-rprx-vision-udp443` variant returns false.
    pub(crate) fn blocks_udp443(&self) -> bool {
        validate_outbound_flow(self)
            .map(|flow| flow.uses_vision() && !flow.allows_udp443())
            .unwrap_or(false)
    }

    pub(crate) fn close(&self) {
        if let Some(mux) = &self.payload.mux {
            mux.close();
        }
        if let Some(pre_connections) = &self.payload.pre_connections {
            pre_connections.close();
        }
    }

    pub(crate) async fn join(&self) {
        if let Some(mux) = &self.payload.mux {
            mux.join().await;
        }
        if let Some(pre_connections) = &self.payload.pre_connections {
            pre_connections.join().await;
        }
    }

    /// The carrier stream a request starts on: one opened ahead under
    /// `testpre`, else a new one. Taking one is boxed, so it adds a pointer
    /// and not its state to every open future.
    fn open_carrier<'a>(
        &'a self,
        server: &'a [SocketAddr],
        download: &'a [SocketAddr],
        dialer: &'a TransportDialer,
    ) -> impl Future<Output = Result<BoxedTransportStream, CoreError>> + 'a {
        match &self.payload.pre_connections {
            None => futures_util::future::Either::Left(
                self.payload.carrier.open(server, download, dialer),
            ),
            Some(pre_connections) => {
                futures_util::future::Either::Right(Box::pin(pre_connections.take(
                    preconnect::DialSpec {
                        server: server.to_vec(),
                        download: download.to_vec(),
                        dialer: dialer.clone(),
                    },
                    || Arc::new(CarrierOpener(Arc::downgrade(&self.payload))),
                )))
            }
        }
    }

    fn mux_pool(&self, target: &Target) -> Result<Option<&mux::Pool>, CoreError> {
        self.payload
            .mux
            .as_ref()
            .map_or(Ok(None), |mux| mux.pool(target))
    }

    /// True when Xray's Mux layer rather than the VLESS UDP command owns this
    /// UDP flow: a pooled XUDP child, or a `xudpProxyUDP443: reject` refusal.
    /// Xray's outbound handler applies both before VLESS sees the flow, so the
    /// Vision UDP/443 rule only covers flows that fall through to native UDP.
    pub(crate) fn udp_uses_mux(&self, target: &Target) -> bool {
        !matches!(self.mux_pool(target), Ok(None))
    }

    pub(crate) async fn open_mux_udp(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
        global_id: [u8; 8],
    ) -> Result<mux::UdpSession, CoreError> {
        if target.network != RoutingNetwork::Udp {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let pool = self
            .mux_pool(target)?
            .ok_or(CoreError::UnsupportedOutboundNetwork)?;
        let server = self
            .payload
            .carrier
            .resolve_server(resolver, dialer)
            .await?;
        let download = self
            .payload
            .carrier
            .resolve_download(resolver, dialer)
            .await?;
        let child = pool
            .open_datagram(
                target,
                global_id,
                open_vless_mux_parent(self, &server, &download, dialer),
            )
            .await?;
        Ok(mux::UdpSession::new(child, target.clone()))
    }
}

/// Xray-core's `crypto.RandBetween`: from the lower bound up to, but not
/// including, the upper, or the bound itself when they are equal.
fn xray_rand_between(first: u32, second: u32) -> u32 {
    let (low, high) = if first > second {
        (second, first)
    } else {
        (first, second)
    };
    if low == high {
        low
    } else {
        rand::thread_rng().gen_range(low..high)
    }
}

/// Whether a noise for `family` goes to `target`. Xray-core reads an
/// IPv4-mapped address as IPv4.
fn noise_applies(family: xray_config::FreedomNoiseFamily, target: IpAddr) -> bool {
    let ipv4 = target.to_canonical().is_ipv4();
    match family {
        xray_config::FreedomNoiseFamily::Ip => true,
        xray_config::FreedomNoiseFamily::Ipv4 => ipv4,
        xray_config::FreedomNoiseFamily::Ipv6 => !ipv4,
    }
}

impl FreedomOutbound {
    fn new(settings: &FreedomOutboundSettings, stream: &StreamSettings) -> Result<Self, CoreError> {
        Ok(Self {
            fragment: carrier::fragment_config(stream)?,
            happy_eyeballs: happy_eyeballs_config(stream),
            ..Self::for_udp(settings, stream)
        })
    }

    /// UDP reads neither the fragment mask nor Happy Eyeballs.
    fn for_udp(settings: &FreedomOutboundSettings, stream: &StreamSettings) -> Self {
        Self {
            fragment: None,
            happy_eyeballs: None,
            socket_options: socket_options::compile(stream),
            domain_strategy: Self::stream_domain_strategy(stream),
            redirect: (!settings.redirect.is_empty()).then(|| Arc::new(settings.redirect.clone())),
            user_level: settings.user_level,
            proxy_protocol: settings.proxy_protocol,
            final_rules: (!settings.final_rules.is_empty())
                .then(|| settings.final_rules.as_slice().into()),
            noises: (!settings.noises.is_empty()).then(|| settings.noises.as_slice().into()),
        }
    }

    /// Sends `noises` before a UDP flow's first datagram, as Xray-core's
    /// `NoisePacketWriter` does: to `target`, the address the flow goes to,
    /// in order, skipping those for the other address family, and waiting
    /// out each one's delay. Nothing is sent when `redirect` sends the flow
    /// to port 53, as there. Returns the bytes sent.
    pub(crate) async fn send_udp_noises(
        &self,
        socket: &tokio::net::UdpSocket,
        target: SocketAddr,
    ) -> io::Result<u64> {
        let Some(noises) = self.noises.as_deref() else {
            return Ok(0);
        };
        if self
            .redirect
            .as_deref()
            .and_then(|redirect| redirect.port)
            .is_some_and(|port| port.get() == 53)
        {
            return Ok(0);
        }
        let mut sent = 0;
        for noise in noises {
            if !noise_applies(noise.apply_to, target.ip()) {
                continue;
            }
            let packet = match &noise.packet {
                xray_config::FreedomNoisePacket::Bytes(bytes) => bytes.clone(),
                xray_config::FreedomNoisePacket::Random(first, second) => {
                    let mut bytes = vec![0; xray_rand_between(*first, *second) as usize];
                    rand::thread_rng().fill(bytes.as_mut_slice());
                    bytes
                }
            };
            sent += socket.send_to(&packet, target).await? as u64;
            let (min, max) = noise.delay_ms;
            if (min, max) != (0, 0) {
                let delay = xray_rand_between(min, max);
                tokio::time::sleep(Duration::from_millis(u64::from(delay))).await;
            }
        }
        Ok(sent)
    }

    /// `finalRules`, in order.
    pub(crate) fn final_rules(&self) -> &[FreedomFinalRule] {
        self.final_rules.as_deref().unwrap_or_default()
    }

    /// `proxyProtocol`, the header freedom writes before the payload.
    pub(crate) fn proxy_protocol(&self) -> Option<ProxyProtocolVersion> {
        self.proxy_protocol
    }

    /// The stand-in for a TCP connection to `candidates` that a final rule
    /// blocks: Xray-core holds it, discarding what the client sends.
    fn blocked_stream(&self, candidates: &[SocketAddr]) -> Option<BoxedTransportStream> {
        let rule = final_rules::blocking_rule(
            self.final_rules(),
            Network::Tcp,
            candidates.iter().copied(),
        )?;
        Some(Box::new(final_rules::BlockedStream::new(
            final_rules::block_delay(rule),
        )))
    }

    /// Connects to `target` at `candidates` through `dialer`, as Xray-core's
    /// freedom does once it has its destination: a connection that a final
    /// rule blocks is held and discarded instead, and the PROXY protocol
    /// header goes first on the raw connection, before any fragment mask.
    async fn connect(
        &self,
        dialer: &TransportDialer,
        target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
        source: Option<InboundSource>,
    ) -> Result<BoxedTransportStream, TransportError> {
        if let Some(blocked) = self.blocked_stream(candidates) {
            return Ok(blocked);
        }
        match self.proxy_protocol {
            None => {
                dialer
                    .connect_resolved(&ConnectorConfig::Tcp, target, candidates, happy_eyeballs)
                    .await
            }
            // Boxed so the rare header path adds no state to every TCP open.
            Some(version) => {
                Box::pin(dialer.connect_tcp_with_preamble(
                    target,
                    candidates,
                    happy_eyeballs,
                    |peer| tcp_proxy_header(version, source, peer),
                ))
                .await
            }
        }
    }

    /// The destination `redirect` sends a connection to instead of
    /// `target`, as Xray-core's freedom rewrites it before dialing.
    pub(crate) fn redirect(&self, target: &Target) -> Option<Target> {
        let redirect = self.redirect.as_deref()?;
        let addr = match &redirect.address {
            Some(TargetAddr::Ip(ip)) => RoutingTargetAddr::Ip(*ip),
            Some(TargetAddr::Domain(domain)) => RoutingTargetAddr::Domain(domain.clone()),
            None => target.addr.clone(),
        };
        let port = redirect.port.map_or(target.port, std::num::NonZeroU16::get);
        Some(Target::new(addr, port, target.network))
    }

    /// Whether `redirect` replaces the destination address, so the original
    /// one never needs resolving.
    fn redirects_address(&self) -> bool {
        self.redirect
            .as_deref()
            .is_some_and(|redirect| redirect.address.is_some())
    }

    /// The address `redirect` sends connections to, with port 0, so a chain
    /// can resolve it once.
    fn redirect_address(&self) -> Option<Target> {
        let addr = match self.redirect.as_deref()?.address.as_ref()? {
            TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
            TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
        };
        Some(Target::new(addr, 0, RoutingNetwork::Tcp))
    }

    /// The policy level of freedom's own idle timer.
    pub(crate) fn level(&self) -> u32 {
        self.user_level
    }

    fn stream_domain_strategy(stream: &StreamSettings) -> DomainStrategy {
        stream
            .socket_options
            .as_ref()
            .map(|options| options.domain_strategy)
            .unwrap_or_default()
    }

    /// The dialer with this outbound's socket options and fragment mask, if
    /// it has them.
    pub(crate) fn dialer<'a>(
        &self,
        dialer: &'a TransportDialer,
    ) -> std::borrow::Cow<'a, TransportDialer> {
        let dialer = socket_options::dialer(dialer, self.socket_options.as_ref());
        match &self.fragment {
            Some(fragment) => {
                std::borrow::Cow::Owned(dialer.into_owned().with_tcp_fragment(fragment.clone()))
            }
            None => dialer,
        }
    }

    pub(crate) fn domain_strategy(&self) -> DomainStrategy {
        self.domain_strategy
    }

    /// The strategy for a UDP flow whose destination was `original` before
    /// sniffing or a fake IP replaced it, as Xray-core's `GetDynamicStrategy`
    /// picks it.
    pub(crate) fn udp_domain_strategy(&self, original: &Target) -> DomainStrategy {
        match original.addr {
            RoutingTargetAddr::Ip(ip) => self.domain_strategy.for_original_ip(ip),
            RoutingTargetAddr::Domain(_) => self.domain_strategy,
        }
    }
}

/// The PROXY protocol header for a TCP connection to `peer`. Through
/// dialerProxy there is no direct peer, and Xray-core's connection reports
/// 0.0.0.0:0 as its remote address.
fn tcp_proxy_header(
    version: ProxyProtocolVersion,
    source: Option<InboundSource>,
    peer: Option<SocketAddr>,
) -> Vec<u8> {
    let destination = peer.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    proxy_protocol::header(version, source, RoutingNetwork::Tcp, destination)
}

impl TcpOutbound {
    pub(crate) fn freedom_dialer<'a>(
        &self,
        dialer: &'a TransportDialer,
    ) -> std::borrow::Cow<'a, TransportDialer> {
        match self.primary() {
            Self::Freedom(freedom) => freedom.dialer(dialer),
            _ => std::borrow::Cow::Borrowed(dialer),
        }
    }
    pub(crate) fn primary(&self) -> &Self {
        match self {
            Self::Chained { outbound, .. } => outbound.primary(),
            outbound => outbound,
        }
    }

    /// Lets connections this outbound keeps for later flows close: an HTTP
    /// outbound's shared HTTP/2 connection.
    pub(crate) fn close_shared_connections(&self) {
        match self {
            Self::Http(http) => http.close(),
            Self::Chained { outbound, proxy } => {
                outbound.close_shared_connections();
                proxy.close_shared_connections();
            }
            _ => {}
        }
    }

    /// Whether this chain names the client: a freedom in it writes a PROXY
    /// protocol header, or an HTTP outbound's custom headers name the
    /// source.
    pub(crate) fn names_the_client(&self) -> bool {
        match self {
            Self::Freedom(freedom) => freedom.proxy_protocol.is_some(),
            Self::Http(http) => http.names_the_client(),
            Self::Chained { outbound, proxy } => {
                outbound.names_the_client() || proxy.names_the_client()
            }
            _ => false,
        }
    }

    pub(crate) fn freedom_happy_eyeballs(&self) -> Option<&HappyEyeballsConfig> {
        match self.primary() {
            Self::Freedom(freedom) => freedom.happy_eyeballs.as_ref(),
            Self::Vless(_)
            | Self::Vmess(_)
            | Self::Trojan(_)
            | Self::Socks(_)
            | Self::Http(_)
            | Self::Shadowsocks2022(_)
            | Self::Hysteria(_)
            | Self::Wireguard(_) => None,
            Self::Chained { .. } => unreachable!("primary outbound is never a chain wrapper"),
        }
    }
}

#[derive(Clone)]
struct OutboundProxyTcpConnector {
    outbound: TcpOutbound,
    server_candidates: Box<[SocketAddr]>,
    transport_dialer: TransportDialer,
    /// The client of the connection the chain carries.
    source: Option<InboundSource>,
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
            TcpOutbound::Freedom(freedom) => {
                // The next hop's server is this hop's destination, so
                // `redirect` rewrites it as it does any other.
                let redirected = freedom.redirect(original_target);
                let (target, candidates) = match &redirected {
                    Some(target) => {
                        let addresses = if freedom.redirects_address() {
                            &self.server_candidates[..]
                        } else {
                            candidates
                        };
                        let candidates = addresses
                            .iter()
                            .map(|address| {
                                let mut address = *address;
                                address.set_port(target.port);
                                address
                            })
                            .collect();
                        (target, candidates)
                    }
                    None => (original_target, candidates.to_vec()),
                };
                freedom
                    .connect(
                        &self.outbound.freedom_dialer(&self.transport_dialer),
                        target,
                        &candidates,
                        self.outbound.freedom_happy_eyeballs().or(happy_eyeballs),
                        self.source,
                    )
                    .await
            }
            TcpOutbound::Wireguard(_) => Err(TransportError::ChainedOutbound(
                "WireGuard chaining is unsupported".into(),
            )),
            TcpOutbound::Hysteria(_) => Err(TransportError::ChainedOutbound(
                "Hysteria chaining is unsupported".into(),
            )),
            TcpOutbound::Trojan(outbound) => outbound
                .open_resolved(
                    original_target,
                    &self.server_candidates,
                    &[],
                    &self.transport_dialer,
                )
                .await
                .map_err(|error| TransportError::ChainedOutbound(error.to_string())),
            TcpOutbound::Socks(outbound) => outbound
                .open_resolved(
                    original_target,
                    &self.server_candidates,
                    &[],
                    &self.transport_dialer,
                )
                .await
                .map_err(|error| TransportError::ChainedOutbound(error.to_string())),
            TcpOutbound::Http(outbound) => outbound
                .open_resolved(
                    original_target,
                    &self.server_candidates,
                    &[],
                    &self.transport_dialer,
                    self.source.map(|source| source.addr),
                )
                .await
                .map_err(|error| TransportError::ChainedOutbound(error.to_string())),
            TcpOutbound::Vmess(outbound) => outbound
                .open_resolved(
                    original_target,
                    &self.server_candidates,
                    &[],
                    &self.transport_dialer,
                )
                .await
                .map_err(|error| TransportError::ChainedOutbound(error.to_string())),
            TcpOutbound::Shadowsocks2022(outbound) => outbound
                .open_resolved(
                    original_target,
                    &self.server_candidates,
                    &[],
                    &self.transport_dialer,
                )
                .await
                .map_err(|error| TransportError::ChainedOutbound(error.to_string())),
            TcpOutbound::Vless(outbound) => open_vless_tcp_stream_with_resolved_server_and_dialer(
                outbound,
                original_target,
                &self.server_candidates,
                &[],
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
    source: Option<InboundSource>,
) -> Pin<Box<dyn Future<Output = Result<TransportDialer, CoreError>> + Send + 'a>> {
    Box::pin(async move {
        let (outbound, nested_proxy) = match proxy {
            TcpOutbound::Chained { outbound, proxy } => (outbound.as_ref(), Some(proxy.as_ref())),
            outbound => (outbound, None),
        };
        let transport_dialer = match nested_proxy {
            Some(proxy) => {
                prepare_outbound_proxy_dialer(proxy, dns_resolver, transport_dialer, source).await?
            }
            None => transport_dialer.clone(),
        };
        let requires_local_resolution = nested_proxy
            .map(proxy_chain_requires_local_resolution)
            .unwrap_or(true);
        let server_candidates = match outbound.primary() {
            TcpOutbound::Vless(vless) if requires_local_resolution => vless
                .carrier()
                .resolve_server(dns_resolver, &transport_dialer)
                .await?
                .into_boxed_slice(),
            TcpOutbound::Vless(_) => Box::default(),
            TcpOutbound::Trojan(outbound) if requires_local_resolution => outbound
                .carrier()
                .resolve_server(dns_resolver, &transport_dialer)
                .await?
                .into_boxed_slice(),
            TcpOutbound::Socks(outbound) if requires_local_resolution => outbound
                .carrier()
                .resolve_server(dns_resolver, &transport_dialer)
                .await?
                .into_boxed_slice(),
            TcpOutbound::Http(outbound) if requires_local_resolution => outbound
                .carrier()
                .resolve_server(dns_resolver, &transport_dialer)
                .await?
                .into_boxed_slice(),
            TcpOutbound::Vmess(outbound) if requires_local_resolution => outbound
                .carrier()
                .resolve_server(dns_resolver, &transport_dialer)
                .await?
                .into_boxed_slice(),
            TcpOutbound::Shadowsocks2022(outbound) if requires_local_resolution => outbound
                .carrier()
                .resolve_server(dns_resolver, &transport_dialer)
                .await?
                .into_boxed_slice(),
            TcpOutbound::Trojan(_) => Box::default(),
            TcpOutbound::Socks(_) => Box::default(),
            TcpOutbound::Http(_) => Box::default(),
            TcpOutbound::Vmess(_) => Box::default(),
            TcpOutbound::Shadowsocks2022(_) => Box::default(),
            TcpOutbound::Wireguard(_) => {
                return Err(CoreError::UnsupportedOutboundProxyNetwork("WireGuard"));
            }
            TcpOutbound::Hysteria(_) => {
                return Err(CoreError::UnsupportedOutboundProxyNetwork("Hysteria"))
            }
            // Ports are filled in per connection, from the next hop's server
            // unless the redirect names one.
            TcpOutbound::Freedom(freedom) => match freedom.redirect_address() {
                Some(address) => {
                    let resolver =
                        DomainStrategyResolver::new(dns_resolver, freedom.domain_strategy());
                    resolve_server_candidates(&address, &resolver)
                        .await?
                        .into_boxed_slice()
                }
                None => Box::default(),
            },
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
                source,
            })),
        )
    })
}

fn proxy_chain_requires_local_resolution(proxy: &TcpOutbound) -> bool {
    match proxy.primary() {
        TcpOutbound::Vless(_)
        | TcpOutbound::Trojan(_)
        | TcpOutbound::Socks(_)
        | TcpOutbound::Http(_)
        | TcpOutbound::Vmess(_)
        | TcpOutbound::Shadowsocks2022(_)
        | TcpOutbound::Hysteria(_)
        | TcpOutbound::Wireguard(_) => false,
        TcpOutbound::Freedom(freedom) => match proxy {
            TcpOutbound::Chained { proxy, .. } => proxy_chain_requires_local_resolution(proxy),
            // The redirect address replaces the next hop's server.
            _ => !freedom.redirects_address(),
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
    Trojan(xray_proxy::trojan::WireError),
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
    BlackholeOutbound,
    LoopbackOutbound,
}

impl CachedOutboundError {
    fn from_core_error(error: CoreError) -> Self {
        match error {
            CoreError::Trojan(error) => Self::Trojan(error),
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
            CoreError::BlackholeOutbound => Self::BlackholeOutbound,
            CoreError::LoopbackOutbound => Self::LoopbackOutbound,
            other => unreachable!("outbound compilation returned non-cacheable error: {other}"),
        }
    }

    fn into_core_error(self) -> CoreError {
        match self {
            Self::Trojan(error) => CoreError::Trojan(error),
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
            Self::BlackholeOutbound => CoreError::BlackholeOutbound,
            Self::LoopbackOutbound => CoreError::LoopbackOutbound,
        }
    }
}

#[derive(Debug, Default)]
struct CachedOutboundEntry {
    tcp: OnceLock<Result<TcpOutbound, CachedOutboundError>>,
    udp: OnceLock<Result<UdpOutbound, CachedOutboundError>>,
    dns: OnceLock<Result<DnsOutbound, CachedOutboundError>>,
    vless: OnceLock<Result<VlessTcpOutbound, CachedOutboundError>>,
    trojan: OnceLock<Result<TrojanOutbound, CachedOutboundError>>,
    vmess: OnceLock<Result<VmessOutbound, CachedOutboundError>>,
    shadowsocks: OnceLock<Result<Shadowsocks2022Outbound, CachedOutboundError>>,
    hysteria: OnceLock<Result<HysteriaOutbound, CachedOutboundError>>,
    wireguard: OnceLock<Result<WireguardOutbound, CachedOutboundError>>,
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
    Hysteria,
    Wireguard,
    Freedom,
    Vless,
    Trojan,
    Vmess,
    Shadowsocks2022,
    Dns,
    Blackhole,
    Loopback,
    Socks,
    Http,
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
                    OutboundSettings::Freedom(_) => OutboundNodeKind::Freedom,
                    OutboundSettings::Vless(_) => OutboundNodeKind::Vless,
                    OutboundSettings::Trojan(_) => OutboundNodeKind::Trojan,
                    OutboundSettings::Vmess(_) => OutboundNodeKind::Vmess,
                    OutboundSettings::Shadowsocks2022(_) => OutboundNodeKind::Shadowsocks2022,
                    OutboundSettings::Hysteria(_) => OutboundNodeKind::Hysteria,
                    OutboundSettings::Wireguard(_) => OutboundNodeKind::Wireguard,
                    OutboundSettings::Dns(_) => OutboundNodeKind::Dns,
                    OutboundSettings::Blackhole(_) => OutboundNodeKind::Blackhole,
                    OutboundSettings::Loopback(_) => OutboundNodeKind::Loopback,
                    OutboundSettings::Socks(_) => OutboundNodeKind::Socks,
                    OutboundSettings::Http(_) => OutboundNodeKind::Http,
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

    /// The `inboundTag` a loopback outbound routes its connections from
    /// again, or `None` for any other node.
    fn loopback_inbound_tag(&self, id: OutboundNodeId) -> Option<&str> {
        match &self.configured_outbound(id)?.settings {
            OutboundSettings::Loopback(settings) => Some(&settings.inbound_tag),
            _ => None,
        }
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
            (
                _,
                StreamSettings {
                    transport: StreamTransport::Xhttp(xhttp),
                    ..
                },
            ) if xhttp.download.is_some() => {
                Some("XHTTP downloadSettings with outbound chaining is unsupported")
            }
            (OutboundSettings::Dns(_), _) => Some("DNS outbounds are not TCP carriers"),
            (OutboundSettings::Blackhole(_), _) => Some("blackhole outbounds are not TCP carriers"),
            (OutboundSettings::Loopback(_), _) => Some("loopback outbounds are not TCP carriers"),
            (OutboundSettings::Hysteria(_), _) => Some("Hysteria chaining is unsupported"),
            (OutboundSettings::Wireguard(_), _) => Some("WireGuard chaining is unsupported"),
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
    hysteria_stream_limits: crate::HysteriaStreamLimits,
    graph: Arc<OutboundGraph>,
    entries: Box<[CachedOutboundEntry]>,
    selection: Arc<OutboundSelectionOverlay>,
    sessions_closed: std::sync::atomic::AtomicBool,
    parallel_vmess_relays: Arc<tokio::sync::Semaphore>,
}

const PARALLEL_VMESS_CONNECTIONS: usize = 2;

impl OutboundFactory {
    pub fn new(graph: Arc<OutboundGraph>) -> Self {
        Self::with_hysteria_stream_limits(graph, crate::HysteriaStreamLimits::default())
    }

    pub fn with_hysteria_stream_limits(
        graph: Arc<OutboundGraph>,
        hysteria_stream_limits: crate::HysteriaStreamLimits,
    ) -> Self {
        let entries = (0..graph.leaf_count)
            .map(|_| CachedOutboundEntry::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let selection = Arc::new(OutboundSelectionOverlay::new(Arc::clone(&graph)));
        Self {
            hysteria_stream_limits,
            graph,
            entries,
            selection,
            sessions_closed: std::sync::atomic::AtomicBool::new(false),
            parallel_vmess_relays: Arc::new(tokio::sync::Semaphore::new(
                PARALLEL_VMESS_CONNECTIONS,
            )),
        }
    }

    /// Shared by every router/inbound using this core. Relay I/O continues
    /// locally while waiting; only active duplex work can occupy admission.
    pub(crate) fn parallel_vmess_budget(&self) -> Arc<tokio::sync::Semaphore> {
        self.parallel_vmess_relays.clone()
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
        let Some(networks) = &rule.networks else {
            self.add_ports(Network::Tcp, rule);
            self.add_ports(Network::Udp, rule);
            return;
        };

        // A network list of only names Xray-core does not know adds nothing.
        for network in networks.iter().copied() {
            self.add_ports(network, rule);
        }
    }

    fn add_ports(&mut self, network: Network, rule: &RoutingRule) {
        let ranges = match network {
            Network::Tcp => &mut self.tcp,
            Network::Udp => &mut self.udp,
        };
        match &rule.port_ranges {
            None => ranges.push(DnsRoutePortRange::ALL),
            // A port condition with no ranges matches no port.
            Some(port_ranges) => ranges.extend(port_ranges.iter().map(|range| DnsRoutePortRange {
                start: range.start(),
                end: range.end(),
            })),
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
    sniffed_routing: SniffedRouting,
}

/// What the rules route by that only sniffing a flow tells.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SniffedRouting {
    /// A rule has `protocol`, so inbounds sniff flows for their protocol
    /// even where `destOverride` would not.
    pub protocol: bool,
    /// A rule has `attrs`, so inbounds sniff TCP flows for what Xray-core's
    /// HTTP sniffer records.
    pub attributes: bool,
}

impl SniffedRouting {
    fn of(routing: &RoutingConfig) -> Self {
        Self {
            protocol: routing.rules.iter().any(|rule| rule.protocols.is_some()),
            attributes: routing.rules.iter().any(|rule| rule.attributes.is_some()),
        }
    }

    /// Whether TCP flows are sniffed for routing, which reads both.
    pub(crate) const fn tcp(self) -> bool {
        self.protocol || self.attributes
    }
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
            sniffed_routing: SniffedRouting::of(&routing),
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
            sniffed_routing: SniffedRouting::of(&routing),
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

    /// What the current rules route by that only sniffing tells.
    pub(crate) fn sniffed_routing(&self) -> SniffedRouting {
        self.routing_policy_state().sniffed_routing
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
        let node = self.select_configured_node(&RouteContext::default(), None, None, None, None)?;
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
            &RouteContext::inbound(inbound_tag),
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
    /// This selector skips resolver-driven `IPIfNonMatch` and `IPOnDemand`
    /// lookups. Internal DNS clients use this path to
    /// match Xray's `SkipDNSResolve` routing context and avoid recursively
    /// resolving the name server that is needed to perform the lookup.
    pub(crate) fn select_tcp_outbound_for_session_with_tag(
        &self,
        route: &RouteContext<'_>,
        target: &Target,
        include_tag: bool,
    ) -> Result<SelectedTcpOutbound, CoreError> {
        let node = self.select_configured_node(
            route,
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
        let node = self.select_configured_node_with_resolved_ip(
            &RouteContext::inbound(inbound_tag),
            target,
            resolved_ip,
        )?;
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
            .select_configured_node_with_resolver(
                &RouteContext::inbound(inbound_tag),
                target,
                dns_resolver,
            )
            .await?;
        self.factory.cached_tcp_outbound(node)
    }

    /// Selects the outbound of a TCP session routed by `target` that goes to
    /// `dial_target`, which loopbacks route again.
    pub(crate) async fn select_tcp_session_outbound_with_tag_and_resolver(
        &self,
        route: &RouteContext<'_>,
        target: &Target,
        dial_target: &Target,
        include_tag: bool,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<SelectedTcpSessionOutbound, CoreError> {
        let node = self
            .select_session_node_with_resolver(route, target, dial_target, dns_resolver)
            .await?;
        let tag = include_tag
            .then(|| self.graph().node(node).and_then(|node| node.tag.clone()))
            .flatten();
        let outbound = match self.graph().node(node).map(OutboundNode::kind) {
            Some(OutboundNodeKind::Dns) => self
                .factory
                .cached_dns_outbound(node)
                .map(TcpSessionOutbound::Dns),
            Some(OutboundNodeKind::Blackhole) => self
                .factory
                .blackhole_outbound(node)
                .map(TcpSessionOutbound::Blackhole),
            _ => self
                .factory
                .cached_tcp_outbound(node)
                .map(TcpSessionOutbound::Transport),
        }?;
        Ok(SelectedTcpSessionOutbound { outbound, tag })
    }

    #[cfg(test)]
    pub(crate) async fn select_tcp_outbound_for_session_with_tag_and_resolver(
        &self,
        inbound_tag: Option<&str>,
        target: &Target,
        include_tag: bool,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<SelectedTcpOutbound, CoreError> {
        let node = self
            .select_configured_node_with_resolver(
                &RouteContext::inbound(inbound_tag),
                target,
                dns_resolver,
            )
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
            &RouteContext::inbound(inbound_tag),
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
        self.select_dns_outbound_for_route(&RouteContext::inbound(inbound_tag), target)
    }

    pub(crate) fn select_dns_outbound_for_route(
        &self,
        route: &RouteContext<'_>,
        target: &Target,
    ) -> Result<Option<DnsOutbound>, CoreError> {
        let policy = self.routing_policy_state();
        if !self.may_select_dns_outbound_in_policy(&policy, route.inbound_tag, target) {
            return Ok(None);
        }
        let node = self.select_configured_node_in_policy(
            &policy,
            route,
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
        self.select_dns_outbound_for_route_with_resolver(
            &RouteContext::inbound(inbound_tag),
            target,
            dns_resolver,
        )
        .await
    }

    pub(crate) async fn select_dns_outbound_for_route_with_resolver(
        &self,
        route: &RouteContext<'_>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<Option<DnsOutbound>, CoreError> {
        let policy = self.routing_policy_state();
        if !self.may_select_dns_outbound_in_policy(&policy, route.inbound_tag, target) {
            return Ok(None);
        }
        let node = self
            .select_configured_node_with_resolver_in_policy(
                &policy,
                route,
                target,
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
            .select_configured_node_with_resolver(
                &RouteContext::inbound(inbound_tag),
                target,
                dns_resolver,
            )
            .await?;
        self.factory.cached_udp_outbound(node)
    }

    /// Selects the outbound of a UDP session routed by `target` that goes to
    /// `dial_target`, which loopbacks route again.
    pub(crate) async fn select_udp_session_outbound_with_tag_and_resolver(
        &self,
        route: &RouteContext<'_>,
        target: &Target,
        dial_target: &Target,
        include_tag: bool,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<SelectedUdpSessionOutbound, CoreError> {
        let node = self
            .select_session_node_with_resolver(route, target, dial_target, dns_resolver)
            .await?;
        let tag = include_tag
            .then(|| self.graph().node(node).and_then(|node| node.tag.clone()))
            .flatten();
        let outbound = match self.graph().node(node).map(OutboundNode::kind) {
            Some(OutboundNodeKind::Dns) => self
                .factory
                .cached_dns_outbound(node)
                .map(UdpSessionOutbound::Dns),
            Some(OutboundNodeKind::Blackhole) => self
                .factory
                .blackhole_outbound(node)
                .map(UdpSessionOutbound::Blackhole),
            _ => self
                .factory
                .cached_udp_outbound(node)
                .map(UdpSessionOutbound::Transport),
        }?;
        Ok(SelectedUdpSessionOutbound { outbound, tag })
    }

    fn select_configured_node(
        &self,
        route: &RouteContext<'_>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
        target_network: Option<Network>,
        target_port: Option<u16>,
    ) -> Result<OutboundNodeId, CoreError> {
        let policy = self.routing_policy_state();
        self.select_configured_node_in_policy(
            &policy,
            route,
            target_domain,
            target_ip,
            target_network,
            target_port,
        )
    }

    fn select_configured_node_in_policy(
        &self,
        policy: &RoutingPolicyState,
        route: &RouteContext<'_>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
        target_network: Option<Network>,
        target_port: Option<u16>,
    ) -> Result<OutboundNodeId, CoreError> {
        let node = self.route_once_in_policy(
            policy,
            route,
            target_domain,
            target_ip,
            target_network,
            target_port,
        )?;
        self.follow_loopbacks(
            policy,
            node,
            route,
            target_domain,
            target_ip,
            target_network,
            target_port,
        )
    }

    fn route_once_in_policy(
        &self,
        policy: &RoutingPolicyState,
        route: &RouteContext<'_>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
        target_network: Option<Network>,
        target_port: Option<u16>,
    ) -> Result<OutboundNodeId, CoreError> {
        let routed_target = select_routed_target(
            &policy.routing,
            route,
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

    /// Follows loopback outbounds from `node`, as Xray-core's loopback
    /// dispatches its connection again. Routing then sees the loopback's
    /// `inboundTag` with the source, local address and user it had, but no
    /// sniffed protocol or attributes, and checks the target given, the
    /// address the connection goes to, without the DNS lookups of
    /// `IPIfNonMatch` and `IPOnDemand`. Xray-core sets no limit to how many
    /// loopbacks follow one another, and recurses until it crashes on a loop;
    /// here more than [`MAX_LOOPBACK_HOPS`] fail the connection.
    #[expect(
        clippy::too_many_arguments,
        reason = "routing takes the target in the parts the synchronous selectors have"
    )]
    fn follow_loopbacks(
        &self,
        policy: &RoutingPolicyState,
        mut node: OutboundNodeId,
        route: &RouteContext<'_>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
        target_network: Option<Network>,
        target_port: Option<u16>,
    ) -> Result<OutboundNodeId, CoreError> {
        for _ in 0..MAX_LOOPBACK_HOPS {
            let Some(inbound_tag) = self.graph().loopback_inbound_tag(node) else {
                return Ok(node);
            };
            let again = RouteContext {
                inbound_tag: Some(inbound_tag),
                protocol: None,
                attributes: None,
                ..*route
            };
            node = self.route_once_in_policy(
                policy,
                &again,
                target_domain,
                target_ip,
                target_network,
                target_port,
            )?;
        }
        match self.graph().loopback_inbound_tag(node) {
            Some(_) => Err(CoreError::LoopbackChainTooLong(MAX_LOOPBACK_HOPS)),
            None => Ok(node),
        }
    }

    #[cfg(test)]
    fn select_configured_node_with_resolved_ip(
        &self,
        route: &RouteContext<'_>,
        target: &Target,
        resolved_ip: Option<&IpAddr>,
    ) -> Result<OutboundNodeId, CoreError> {
        let policy = self.routing_policy_state();
        if let Some(routed_target) = select_routed_target(
            &policy.routing,
            route,
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
                    route,
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
        route: &RouteContext<'_>,
        target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<OutboundNodeId, CoreError> {
        self.select_session_node_with_resolver(route, target, target, dns_resolver)
            .await
    }

    /// Routes a session by `target`, then follows loopbacks by `dial_target`,
    /// the address it goes to, which Xray-core's loopback routes again.
    async fn select_session_node_with_resolver(
        &self,
        route: &RouteContext<'_>,
        target: &Target,
        dial_target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<OutboundNodeId, CoreError> {
        // Retain one immutable policy snapshot across any DNS await so a flow
        // never observes rules from two revisions.
        let policy = self.routing_policy_state();
        self.select_configured_node_with_resolver_in_policy(
            &policy,
            route,
            target,
            dial_target,
            dns_resolver,
        )
        .await
    }

    async fn select_configured_node_with_resolver_in_policy(
        &self,
        policy: &RoutingPolicyState,
        route: &RouteContext<'_>,
        target: &Target,
        dial_target: &Target,
        dns_resolver: &dyn DnsResolver,
    ) -> Result<OutboundNodeId, CoreError> {
        let node =
            match select_routed_target_with_resolver(&policy.routing, route, target, dns_resolver)
                .await?
            {
                Some(target) => self.node_for_target(target)?,
                None => self.select_default_configured_node()?,
            };
        self.follow_loopbacks(
            policy,
            node,
            route,
            target_domain(dial_target),
            target_ip(dial_target),
            Some(target_network(dial_target)),
            Some(dial_target.port),
        )
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

/// How many loopback outbounds one connection may pass in a row.
pub(crate) const MAX_LOOPBACK_HOPS: usize = 8;

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
        // Only a Mux pool owns sessions; other VLESS opens keep their
        // existing behaviour after shutdown begins.
        if configured.mux.is_some() && self.sessions_closed.load(Ordering::Acquire) {
            if let Ok(outbound) = cached {
                outbound.close();
            }
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        match cached {
            Ok(outbound) => Ok(outbound.clone()),
            Err(error) => Err(error.clone()),
        }
    }

    fn cached_trojan_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<TrojanOutbound, CachedOutboundError> {
        if self.sessions_closed.load(Ordering::Acquire) {
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        let configured = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        let result = self
            .entry(node)?
            .trojan
            .get_or_init(|| {
                TrojanOutbound::new(configured).map_err(CachedOutboundError::from_core_error)
            })
            .clone();
        if self.sessions_closed.load(Ordering::Acquire) {
            if let Ok(outbound) = &result {
                outbound.close();
            }
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        result
    }

    fn cached_vmess_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<VmessOutbound, CachedOutboundError> {
        if self.sessions_closed.load(Ordering::Acquire) {
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        let configured = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        let result = self
            .entry(node)?
            .vmess
            .get_or_init(|| {
                VmessOutbound::new(configured).map_err(CachedOutboundError::from_core_error)
            })
            .clone();
        if self.sessions_closed.load(Ordering::Acquire) {
            if let Ok(outbound) = &result {
                outbound.close();
            }
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        result
    }

    fn cached_shadowsocks_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<Shadowsocks2022Outbound, CachedOutboundError> {
        if self.sessions_closed.load(Ordering::Acquire) {
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        let configured = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        let result = self
            .entry(node)?
            .shadowsocks
            .get_or_init(|| {
                Shadowsocks2022Outbound::new(configured)
                    .map_err(CachedOutboundError::from_core_error)
            })
            .clone();
        if self.sessions_closed.load(Ordering::Acquire) {
            if let Ok(outbound) = &result {
                outbound.close();
            }
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        result
    }

    fn cached_hysteria_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<HysteriaOutbound, CachedOutboundError> {
        if self.sessions_closed.load(Ordering::Acquire) {
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        let configured = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        let result = self
            .entry(node)?
            .hysteria
            .get_or_init(|| {
                HysteriaOutbound::with_stream_limits(configured, self.hysteria_stream_limits)
                    .map_err(CachedOutboundError::from_core_error)
            })
            .clone();
        if self.sessions_closed.load(Ordering::Acquire) {
            if let Ok(outbound) = &result {
                outbound.close();
            }
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        result
    }

    fn cached_wireguard_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<WireguardOutbound, CachedOutboundError> {
        if self.sessions_closed.load(Ordering::Acquire) {
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        let configured = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        let result = self
            .entry(node)?
            .wireguard
            .get_or_init(|| {
                WireguardOutbound::new(configured).map_err(CachedOutboundError::from_core_error)
            })
            .clone();
        if self.sessions_closed.load(Ordering::Acquire) {
            if let Ok(outbound) = &result {
                outbound.close();
            }
            return Err(CachedOutboundError::NoSupportedOutbound);
        }
        result
    }

    pub(crate) fn close_sessions(&self) {
        self.sessions_closed.store(true, Ordering::Release);
        for entry in &self.entries {
            if let Some(Ok(outbound)) = entry.tcp.get() {
                outbound.close_shared_connections();
            }
            if let Some(Ok(outbound)) = entry.vless.get() {
                outbound.close();
            }
            if let Some(Ok(outbound)) = entry.trojan.get() {
                outbound.close();
            }
            if let Some(Ok(outbound)) = entry.shadowsocks.get() {
                outbound.close();
            }
            if let Some(Ok(outbound)) = entry.vmess.get() {
                outbound.close();
            }
            if let Some(Ok(outbound)) = entry.wireguard.get() {
                outbound.close();
            }
            if let Some(Ok(outbound)) = entry.hysteria.get() {
                outbound.close();
            }
        }
    }

    pub(crate) async fn join_sessions(&self) {
        for entry in &self.entries {
            if let Some(Ok(outbound)) = entry.vless.get() {
                outbound.join().await;
            }
            if let Some(Ok(outbound)) = entry.trojan.get() {
                outbound.join().await;
            }
            if let Some(Ok(outbound)) = entry.shadowsocks.get() {
                outbound.join().await;
            }
            if let Some(Ok(outbound)) = entry.vmess.get() {
                outbound.join().await;
            }
        }
        // Inbound owners have stopped admitting work. Their cancelled relay
        // children retain their lease until they stop polling owned I/O.
        let _all = self
            .parallel_vmess_relays
            .acquire_many(PARALLEL_VMESS_CONNECTIONS as u32)
            .await;
    }

    pub(crate) fn rebind_hysteria(&self) -> u64 {
        if self.sessions_closed.load(Ordering::Acquire) {
            return 0;
        }
        self.entries
            .iter()
            .filter(|entry| matches!(entry.hysteria.get(), Some(Ok(outbound)) if outbound.rebind()))
            .count() as u64
    }

    pub(crate) fn rebind_wireguard(&self) -> u64 {
        if self.sessions_closed.load(Ordering::Acquire) {
            return 0;
        }
        self.entries
            .iter()
            .filter(
                |entry| matches!(entry.wireguard.get(), Some(Ok(outbound)) if outbound.rebind()),
            )
            .count() as u64
    }

    fn compile_tcp_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<TcpOutbound, CachedOutboundError> {
        let outbound = self
            .graph
            .configured_outbound(node)
            .ok_or(CachedOutboundError::NoSupportedOutbound)?;
        if outbound.mux.is_some()
            && !matches!(
                outbound.settings,
                OutboundSettings::Vless(_)
                    | OutboundSettings::Trojan(_)
                    | OutboundSettings::Shadowsocks2022(_)
                    | OutboundSettings::Vmess(_)
            )
        {
            return Err(CachedOutboundError::UnsupportedOutboundNetwork);
        }

        if outbound.stream.network != Network::Tcp
            && !matches!(outbound.settings, OutboundSettings::Hysteria(_))
        {
            return Err(CachedOutboundError::UnsupportedOutboundNetwork);
        }

        let compiled = match &outbound.settings {
            OutboundSettings::Hysteria(_) => self
                .cached_hysteria_outbound(node)
                .map(TcpOutbound::Hysteria),
            OutboundSettings::Wireguard(_) => self
                .cached_wireguard_outbound(node)
                .map(TcpOutbound::Wireguard),
            OutboundSettings::Trojan(_) => {
                self.cached_trojan_outbound(node).map(TcpOutbound::Trojan)
            }
            OutboundSettings::Vmess(_) => self.cached_vmess_outbound(node).map(TcpOutbound::Vmess),
            OutboundSettings::Shadowsocks2022(_) => self
                .cached_shadowsocks_outbound(node)
                .map(TcpOutbound::Shadowsocks2022),
            OutboundSettings::Dns(_) => Err(CachedOutboundError::NoSupportedOutbound),
            OutboundSettings::Socks(_) => SocksOutbound::new(outbound)
                .map(TcpOutbound::Socks)
                .map_err(CachedOutboundError::from_core_error),
            OutboundSettings::Http(_) => HttpOutbound::new(outbound)
                .map(TcpOutbound::Http)
                .map_err(CachedOutboundError::from_core_error),
            OutboundSettings::Blackhole(_) => Err(CachedOutboundError::BlackholeOutbound),
            OutboundSettings::Loopback(_) => Err(CachedOutboundError::LoopbackOutbound),
            OutboundSettings::Freedom(settings) => {
                if !stream_transport_is_dialable(&outbound.stream) {
                    return Err(CachedOutboundError::UnsupportedOutboundNetwork);
                }
                if outbound.stream.security != StreamSecurity::None {
                    return Err(CachedOutboundError::UnsupportedOutboundSecurity);
                }
                build_freedom_tcp_outbound(settings, &outbound.stream)
                    .map_err(CachedOutboundError::from_core_error)
            }
            OutboundSettings::Vless(_) => self
                .cached_vless_outbound(node)
                .map(|outbound| TcpOutbound::Vless(Box::new(outbound))),
        }?;

        match self.graph.proxy_target(node) {
            // Xray-core hands the address and port it looks up to the proxy;
            // a chain here gives it the configured server.
            Some(_)
                if carrier::address_port_strategy(&outbound.stream)
                    .records()
                    .is_some() =>
            {
                Err(CachedOutboundError::UnsupportedOutboundProxyNetwork(
                    "addressPortStrategy",
                ))
            }
            // mKCP's datagrams would need the chain's UDP.
            Some(_) if matches!(outbound.stream.transport, StreamTransport::Kcp(_)) => {
                Err(CachedOutboundError::UnsupportedOutboundProxyNetwork("mKCP"))
            }
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
        if outbound.mux.is_some()
            && !matches!(
                outbound.settings,
                OutboundSettings::Vless(_)
                    | OutboundSettings::Trojan(_)
                    | OutboundSettings::Shadowsocks2022(_)
                    | OutboundSettings::Vmess(_)
            )
        {
            return Err(CachedOutboundError::UnsupportedOutboundNetwork);
        }

        if outbound.proxy_settings.is_some() {
            return Err(CachedOutboundError::UnsupportedOutboundProxyNetwork("UDP"));
        }
        match &outbound.settings {
            OutboundSettings::Hysteria(_) => self
                .cached_hysteria_outbound(node)
                .map(UdpOutbound::Hysteria),
            OutboundSettings::Wireguard(_) => self
                .cached_wireguard_outbound(node)
                .map(UdpOutbound::Wireguard),
            OutboundSettings::Trojan(_) => {
                self.cached_trojan_outbound(node).map(UdpOutbound::Trojan)
            }
            OutboundSettings::Vmess(_) => self.cached_vmess_outbound(node).map(UdpOutbound::Vmess),
            OutboundSettings::Shadowsocks2022(_) => self
                .cached_shadowsocks_outbound(node)
                .map(UdpOutbound::Shadowsocks2022),
            OutboundSettings::Dns(_) => Err(CachedOutboundError::NoSupportedOutbound),
            OutboundSettings::Socks(_) => SocksOutbound::new(outbound)
                .map(UdpOutbound::Socks)
                .map_err(CachedOutboundError::from_core_error),
            OutboundSettings::Http(_) => Err(CachedOutboundError::UnsupportedOutboundNetwork),
            OutboundSettings::Blackhole(_) => Err(CachedOutboundError::BlackholeOutbound),
            OutboundSettings::Loopback(_) => Err(CachedOutboundError::LoopbackOutbound),
            OutboundSettings::Freedom(settings) => {
                if !stream_transport_is_dialable(&outbound.stream) {
                    return Err(CachedOutboundError::UnsupportedOutboundNetwork);
                }
                if outbound.stream.security != StreamSecurity::None {
                    return Err(CachedOutboundError::UnsupportedOutboundSecurity);
                }
                Ok(UdpOutbound::Freedom(FreedomOutbound::for_udp(
                    settings,
                    &outbound.stream,
                )))
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
        if configured.mux.is_some()
            && !matches!(
                configured.settings,
                OutboundSettings::Vless(_)
                    | OutboundSettings::Trojan(_)
                    | OutboundSettings::Shadowsocks2022(_)
                    | OutboundSettings::Vmess(_)
            )
        {
            return Err(CachedOutboundError::UnsupportedOutboundNetwork);
        }

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
            OutboundSettings::Blackhole(_) => Err(CachedOutboundError::BlackholeOutbound),
            OutboundSettings::Loopback(_) => Err(CachedOutboundError::LoopbackOutbound),
            OutboundSettings::Freedom(_)
            | OutboundSettings::Vless(_)
            | OutboundSettings::Hysteria(_)
            | OutboundSettings::Trojan(_)
            | OutboundSettings::Vmess(_)
            | OutboundSettings::Shadowsocks2022(_)
            | OutboundSettings::Wireguard(_)
            | OutboundSettings::Socks(_)
            | OutboundSettings::Http(_) => Err(CachedOutboundError::NoSupportedOutbound),
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

#[cfg(test)]
fn build_tcp_outbound(outbound: &OutboundConfig) -> Result<TcpOutbound, CoreError> {
    if outbound.stream.network != Network::Tcp
        && !matches!(outbound.settings, OutboundSettings::Hysteria(_))
    {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }

    match &outbound.settings {
        OutboundSettings::Hysteria(_) => HysteriaOutbound::new(outbound).map(TcpOutbound::Hysteria),
        OutboundSettings::Wireguard(_) => {
            WireguardOutbound::new(outbound).map(TcpOutbound::Wireguard)
        }
        OutboundSettings::Trojan(_) => TrojanOutbound::new(outbound).map(TcpOutbound::Trojan),
        OutboundSettings::Vmess(_) => VmessOutbound::new(outbound).map(TcpOutbound::Vmess),
        OutboundSettings::Shadowsocks2022(_) => {
            Shadowsocks2022Outbound::new(outbound).map(TcpOutbound::Shadowsocks2022)
        }
        OutboundSettings::Dns(_) => Err(CoreError::NoSupportedOutbound),
        OutboundSettings::Socks(_) => SocksOutbound::new(outbound).map(TcpOutbound::Socks),
        OutboundSettings::Http(_) => HttpOutbound::new(outbound).map(TcpOutbound::Http),
        OutboundSettings::Blackhole(_) => Err(CoreError::BlackholeOutbound),
        OutboundSettings::Loopback(_) => Err(CoreError::LoopbackOutbound),
        OutboundSettings::Freedom(settings) => {
            if !stream_transport_is_dialable(&outbound.stream) {
                return Err(CoreError::UnsupportedOutboundNetwork);
            }
            if outbound.stream.security != StreamSecurity::None {
                return Err(CoreError::UnsupportedOutboundSecurity);
            }
            build_freedom_tcp_outbound(settings, &outbound.stream)
        }
        OutboundSettings::Vless(_) => build_vless_tcp_outbound(outbound)
            .map(|outbound| TcpOutbound::Vless(Box::new(outbound))),
    }
}

#[cfg(test)]
fn build_udp_outbound(outbound: &OutboundConfig) -> Result<UdpOutbound, CoreError> {
    match &outbound.settings {
        OutboundSettings::Hysteria(_) => HysteriaOutbound::new(outbound).map(UdpOutbound::Hysteria),
        OutboundSettings::Wireguard(_) => {
            WireguardOutbound::new(outbound).map(UdpOutbound::Wireguard)
        }
        OutboundSettings::Trojan(_) => TrojanOutbound::new(outbound).map(UdpOutbound::Trojan),
        OutboundSettings::Vmess(_) => VmessOutbound::new(outbound).map(UdpOutbound::Vmess),
        OutboundSettings::Shadowsocks2022(_) => {
            Shadowsocks2022Outbound::new(outbound).map(UdpOutbound::Shadowsocks2022)
        }
        OutboundSettings::Dns(_) => Err(CoreError::NoSupportedOutbound),
        OutboundSettings::Socks(_) => SocksOutbound::new(outbound).map(UdpOutbound::Socks),
        OutboundSettings::Http(_) => Err(CoreError::UnsupportedOutboundNetwork),
        OutboundSettings::Blackhole(_) => Err(CoreError::BlackholeOutbound),
        OutboundSettings::Loopback(_) => Err(CoreError::LoopbackOutbound),
        OutboundSettings::Freedom(settings) => {
            if !stream_transport_is_dialable(&outbound.stream) {
                return Err(CoreError::UnsupportedOutboundNetwork);
            }
            if outbound.stream.security != StreamSecurity::None {
                return Err(CoreError::UnsupportedOutboundSecurity);
            }
            Ok(UdpOutbound::Freedom(FreedomOutbound::for_udp(
                settings,
                &outbound.stream,
            )))
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
    let encryption = user
        .encryption
        .client()
        .cloned()
        .map(xray_vless_encryption::Client::new);
    if encryption.is_some() {
        validate_vision_flow(user.flow.as_deref(), true)?;
    } else {
        validate_stream_flow(user.flow.as_deref(), &outbound.stream.security)?;
    }

    let carrier = StreamCarrier::new(
        &outbound.stream,
        &settings.server,
        settings.port,
        user.encryption.is_none(),
        carrier::VLESS_PATHS,
    )?;
    // Xray's VLESS inbound restricts a Vision account's Mux.Cool connection to
    // UDP children and breaks the whole connection on a TCP child, so the
    // parser's Vision rule is repeated for configs built without it.
    if user.flow.is_some()
        && outbound
            .mux
            .as_ref()
            .is_some_and(|mux| mux.concurrency >= 0)
    {
        return Err(CoreError::UnsupportedOutboundFlow);
    }
    let mux = mux::Runtime::new(&outbound.mux, &outbound.stream.transport)?;
    let pre_connections = preconnect::PreConnections::new(user.pre_connections);
    Ok(VlessTcpOutbound {
        payload: Arc::new(VlessTcpOutboundPayload {
            carrier,
            user,
            encryption,
            mux,
            pre_connections,
        }),
    })
}

fn build_freedom_tcp_outbound(
    settings: &FreedomOutboundSettings,
    stream: &StreamSettings,
) -> Result<TcpOutbound, CoreError> {
    FreedomOutbound::new(settings, stream).map(TcpOutbound::Freedom)
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

fn validate_outbound_flow(outbound: &VlessTcpOutbound) -> Result<VisionFlow, CoreError> {
    if outbound.encryption().is_some() {
        // Xray uses CommonConn as Vision's protected layer on every carrier.
        return validate_vision_flow(outbound.user().flow.as_deref(), true);
    }
    validate_connector_flow(
        outbound.user().flow.as_deref(),
        outbound.transport(),
        outbound.transport_layer(),
    )
}

fn validate_connector_flow(
    flow: Option<&str>,
    transport: &ConnectorConfig,
    stream_transport: &TransportLayer,
) -> Result<VisionFlow, CoreError> {
    // Without VLESS encryption, only raw TLS/REALITY exposes the security
    // connection Vision needs, and mKCP's TLS, which Xray's `DialKCP` also
    // returns undisguised. Encrypted outbounds are handled separately.
    if !matches!(
        stream_transport,
        TransportLayer::Raw | TransportLayer::Kcp(_)
    ) {
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
        None,
    )
    .await
}

/// Opens a TCP connection to `target` through `outbound`. `source` is the
/// client the connection is for, which a freedom `proxyProtocol` header
/// names; it is borrowed to keep this common future small.
pub(crate) async fn open_tcp_stream_with_resolvers_and_dialer(
    outbound: &TcpOutbound,
    target: &Target,
    destination_resolver: &dyn DnsResolver,
    bootstrap_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
    source: Option<&InboundSource>,
) -> Result<BoxedTransportStream, CoreError> {
    if let TcpOutbound::Chained { outbound, proxy } = outbound {
        let proxy_dialer = prepare_outbound_proxy_dialer(
            proxy,
            bootstrap_resolver,
            transport_dialer,
            source.copied(),
        )
        .await?;
        let requires_local_resolution = proxy_chain_requires_local_resolution(proxy);
        if let (Some(source), TcpOutbound::Freedom(freedom)) = (source, outbound.primary()) {
            if freedom.proxy_protocol.is_some() {
                return Box::pin(open_freedom_tcp_stream(
                    outbound,
                    freedom,
                    target,
                    destination_resolver,
                    &proxy_dialer,
                    requires_local_resolution,
                    Some(*source),
                ))
                .await;
            }
        }
        // A freedom hop is handed the server address as its destination, and
        // Xray-core's freedom resolves that with its own domain strategy.
        let strategy = match proxy.primary() {
            TcpOutbound::Freedom(freedom) => freedom.domain_strategy(),
            _ => DomainStrategy::AsIs,
        };
        let bootstrap = DomainStrategyResolver::new(bootstrap_resolver, strategy);
        if let (Some(source), TcpOutbound::Http(http)) = (source, outbound.primary()) {
            if http.names_the_client() {
                return Box::pin(open_http_tcp_stream(
                    http,
                    target,
                    &bootstrap,
                    &proxy_dialer,
                    requires_local_resolution,
                    source.addr,
                ))
                .await;
            }
        }
        return open_plain_tcp_stream_with_resolvers_and_dialer(
            outbound.primary(),
            target,
            destination_resolver,
            &bootstrap,
            &proxy_dialer,
            requires_local_resolution,
        )
        .await;
    }

    // An outbound that names the client opens apart, so the common open
    // future carries no client.
    match (source, outbound) {
        (Some(source), TcpOutbound::Freedom(freedom)) if freedom.proxy_protocol.is_some() => {
            return Box::pin(open_freedom_tcp_stream(
                outbound,
                freedom,
                target,
                destination_resolver,
                transport_dialer,
                true,
                Some(*source),
            ))
            .await;
        }
        (Some(source), TcpOutbound::Http(http)) if http.names_the_client() => {
            return Box::pin(open_http_tcp_stream(
                http,
                target,
                bootstrap_resolver,
                transport_dialer,
                true,
                source.addr,
            ))
            .await;
        }
        _ => {}
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

/// Opens an HTTP tunnel whose custom headers name the client, `source`.
/// Callers box it, as for a freedom naming the client.
async fn open_http_tcp_stream(
    http: &HttpOutbound,
    target: &Target,
    bootstrap_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
    requires_local_resolution: bool,
    source: SocketAddr,
) -> Result<BoxedTransportStream, CoreError> {
    if requires_local_resolution {
        http.open(target, bootstrap_resolver, transport_dialer, Some(source))
            .await
    } else {
        http.open_resolved(target, &[], &[], transport_dialer, Some(source))
            .await
    }
}

/// Opens a freedom TCP connection that has final rules or writes a PROXY
/// protocol header naming `source`. Callers box it, so these rarer settings
/// add no state to every TCP open.
async fn open_freedom_tcp_stream(
    outbound: &TcpOutbound,
    freedom: &FreedomOutbound,
    target: &Target,
    destination_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
    requires_local_resolution: bool,
    source: Option<InboundSource>,
) -> Result<BoxedTransportStream, CoreError> {
    let redirected = freedom.redirect(target);
    let target = redirected.as_ref().unwrap_or(target);
    let candidates = if requires_local_resolution {
        let resolver = DomainStrategyResolver::new(destination_resolver, freedom.domain_strategy());
        resolve_server_candidates(target, &resolver).await?
    } else {
        Vec::new()
    };
    Ok(freedom
        .connect(
            &outbound.freedom_dialer(transport_dialer),
            target,
            &candidates,
            outbound.freedom_happy_eyeballs(),
            source,
        )
        .await?)
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
        TcpOutbound::Trojan(outbound) => {
            if requires_local_resolution {
                Box::pin(outbound.open(target, bootstrap_resolver, transport_dialer)).await
            } else {
                Box::pin(outbound.open_resolved(target, &[], &[], transport_dialer)).await
            }
        }
        TcpOutbound::Socks(outbound) => {
            if requires_local_resolution {
                Box::pin(outbound.open(target, bootstrap_resolver, transport_dialer)).await
            } else {
                Box::pin(outbound.open_resolved(target, &[], &[], transport_dialer)).await
            }
        }
        TcpOutbound::Http(outbound) => {
            if requires_local_resolution {
                Box::pin(outbound.open(target, bootstrap_resolver, transport_dialer, None)).await
            } else {
                Box::pin(outbound.open_resolved(target, &[], &[], transport_dialer, None)).await
            }
        }
        TcpOutbound::Vmess(outbound) => {
            if requires_local_resolution {
                Box::pin(outbound.open(target, bootstrap_resolver, transport_dialer)).await
            } else {
                Box::pin(outbound.open_resolved(target, &[], &[], transport_dialer)).await
            }
        }
        TcpOutbound::Shadowsocks2022(outbound) => {
            if requires_local_resolution {
                Box::pin(outbound.open(target, bootstrap_resolver, transport_dialer)).await
            } else {
                Box::pin(outbound.open_resolved(target, &[], &[], transport_dialer)).await
            }
        }
        TcpOutbound::Wireguard(outbound) => {
            // Cold protocol setup contains large async state. Keep it out of
            // every TCP task, including long-lived Freedom/VLESS connections.
            Box::pin(outbound.open_tcp(
                target,
                destination_resolver,
                bootstrap_resolver,
                transport_dialer,
            ))
            .await
        }
        TcpOutbound::Hysteria(outbound) => {
            Box::pin(outbound.open_tcp(target, bootstrap_resolver, transport_dialer)).await
        }
        TcpOutbound::Freedom(freedom) => {
            if freedom.final_rules.is_some() || freedom.proxy_protocol.is_some() {
                // Without a known client, a header names none.
                return Box::pin(open_freedom_tcp_stream(
                    outbound,
                    freedom,
                    target,
                    destination_resolver,
                    transport_dialer,
                    requires_local_resolution,
                    None,
                ))
                .await;
            }
            let redirected = freedom.redirect(target);
            let target = redirected.as_ref().unwrap_or(target);
            let candidates = if requires_local_resolution {
                let resolver =
                    DomainStrategyResolver::new(destination_resolver, freedom.domain_strategy());
                resolve_server_candidates(target, &resolver).await?
            } else {
                Vec::new()
            };
            Ok(outbound
                .freedom_dialer(transport_dialer)
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
    validate_outbound_flow(outbound)?;
    let resolved_server = outbound
        .payload
        .carrier
        .resolve_server(dns_resolver, transport_dialer)
        .await?;
    let resolved_download = outbound
        .payload
        .carrier
        .resolve_download(dns_resolver, transport_dialer)
        .await?;
    open_vless_tcp_stream_with_resolved_server_and_dialer(
        outbound,
        target,
        &resolved_server,
        &resolved_download,
        transport_dialer,
    )
    .await
}

async fn open_vless_tcp_stream_with_resolved_server_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    resolved_server: &[SocketAddr],
    resolved_download: &[SocketAddr],
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    let flow = validate_outbound_flow(outbound)?;
    if target.network == RoutingNetwork::Tcp {
        if let Some(pool) = outbound.mux_pool(target)? {
            let parent = open_vless_mux_parent(
                outbound,
                resolved_server,
                resolved_download,
                transport_dialer,
            );
            // Boxed so pooling adds no state to every TCP open future.
            return Ok(Box::new(Box::pin(pool.open(target, parent)).await?));
        }
    }

    let stream = outbound
        .open_carrier(resolved_server, resolved_download, transport_dialer)
        .await?;
    let stream = encryption::wrap(stream, outbound.encryption(), flow.uses_vision()).await?;
    let request = VlessRequest {
        user_id: outbound.user().id,
        command: VlessCommand::Tcp,
        target: target.clone(),
        flow: flow.request_flow(),
    };
    let header = Zeroizing::new(encode_request_header(&request)?);
    // Like Xray-core, hold the header until the first payload so both share
    // one write; the deadline sends it alone when no payload arrives.
    let mut stream: BoxedTransportStream = Box::new(HeldHeader::new(stream, &header));

    if flow.uses_vision() {
        let stream = VlessResponseStream::new(VisionTransportStream::new(stream));
        let stream = VisionStream::new(
            stream,
            *outbound.user().id.as_bytes(),
            outbound.user().vision_seed,
        );
        // On timeout Xray-core pads an empty frame to hide the bare header.
        return Ok(Box::new(FirstPayloadDeadline::new(
            VisionOutboundStream::new(stream),
            VLESS_FIRST_PAYLOAD_WAIT,
            |stream| stream.inner.queue_empty_padding_frame(),
        )));
    }

    // Without Vision there is no direct mode, so the transport never needs
    // record-aligned reads.
    stream.release_record_alignment();
    let stream = VlessResponseStream::new(stream);
    Ok(Box::new(FirstPayloadDeadline::new(
        VlessOutboundStream::new(stream),
        VLESS_FIRST_PAYLOAD_WAIT,
        flush_header_alone,
    )))
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
    let flow = validate_outbound_flow(outbound)?;
    let uses_vision = flow.uses_vision();
    if options.reject_udp443_for_regular_vision
        && uses_vision
        && !flow.allows_udp443()
        && is_udp443_target(target)
    {
        return Err(CoreError::VisionUdp443Rejected);
    }
    let uses_xudp = uses_vision || should_use_xudp_for_udp_target(target);

    let resolved_server = outbound
        .payload
        .carrier
        .resolve_server(dns_resolver, transport_dialer)
        .await?;
    let resolved_download = outbound
        .payload
        .carrier
        .resolve_download(dns_resolver, transport_dialer)
        .await?;
    let command = if uses_xudp {
        VlessCommand::Mux
    } else {
        VlessCommand::Udp
    };
    let stream = open_vless_command_stream(
        outbound,
        flow,
        command,
        target,
        &resolved_server,
        &resolved_download,
        transport_dialer,
    )
    .await?;
    let framing = if uses_xudp {
        VlessUdpFraming::Xudp
    } else {
        VlessUdpFraming::LengthPrefixed
    };
    Ok((stream, framing))
}

/// Opens `testpre` connections on the carrier of a VLESS outbound that is
/// still alive; the dialers hold no strong reference, so dropping the
/// outbound ends them.
struct CarrierOpener(std::sync::Weak<VlessTcpOutboundPayload>);

#[async_trait]
impl preconnect::Opener for CarrierOpener {
    async fn open(
        &self,
        spec: &preconnect::DialSpec,
    ) -> Option<Result<BoxedTransportStream, CoreError>> {
        let payload = self.0.upgrade()?;
        Some(
            payload
                .carrier
                .open(&spec.server, &spec.download, &spec.dialer)
                .await,
        )
    }
}

/// Opens one Mux.Cool parent: the VLESS Mux command to `v1.mux.cool:9527`,
/// as Xray's `DialingWorkerFactory` hands it to the VLESS outbound. Vision
/// keeps its padding layer; the pinned server then admits only UDP children.
async fn open_vless_mux_parent(
    outbound: &VlessTcpOutbound,
    resolved_server: &[SocketAddr],
    resolved_download: &[SocketAddr],
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    let flow = validate_outbound_flow(outbound)?;
    open_vless_command_stream(
        outbound,
        flow,
        VlessCommand::Mux,
        &mux::target(),
        resolved_server,
        resolved_download,
        transport_dialer,
    )
    .await
}

/// Writes the request header for a UDP or Mux command. Unlike a TCP request,
/// Vision queues no empty padding frame: an XUDP or Mux frame always follows.
async fn open_vless_command_stream(
    outbound: &VlessTcpOutbound,
    flow: VisionFlow,
    command: VlessCommand,
    target: &Target,
    resolved_server: &[SocketAddr],
    resolved_download: &[SocketAddr],
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    let stream = outbound
        .open_carrier(resolved_server, resolved_download, transport_dialer)
        .await?;
    let mut stream = encryption::wrap(stream, outbound.encryption(), flow.uses_vision()).await?;
    let request = VlessRequest {
        user_id: outbound.user().id,
        command,
        target: target.clone(),
        flow: flow.request_flow(),
    };
    let header = Zeroizing::new(encode_request_header(&request)?);

    stream.write_all(&header).await?;

    if flow.uses_vision() {
        let stream = VlessResponseStream::new(VisionTransportStream::new(stream));
        return Ok(Box::new(VisionOutboundStream::new(VisionStream::new(
            stream,
            *outbound.user().id.as_bytes(),
            outbound.user().vision_seed,
        ))));
    }

    // Without Vision there is no direct mode, so the transport never needs
    // record-aligned reads.
    stream.release_record_alignment();
    Ok(Box::new(VlessOutboundStream::new(
        VlessResponseStream::new(stream),
    )))
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

/// UDP masks, noise and `header-custom`, need a UDP carrier: Hysteria, mKCP
/// or XHTTP with exact `h3` ALPN.
pub(crate) fn validate_udp_noise(stream: &StreamSettings) -> Result<(), CoreError> {
    let udp_carrier = matches!(
        stream.transport,
        StreamTransport::Hysteria(_) | StreamTransport::Kcp(_)
    ) || matches!(stream.transport, StreamTransport::Xhttp(_))
        && matches!(&stream.security, StreamSecurity::Tls(tls) if tls.alpn == ["h3"]);
    if (stream.udp_noise.is_some() || stream.udp_header_custom.is_some()) && !udp_carrier {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }
    // Sudoku's fourfold datagrams need fragments that QUIC's sockets forbid.
    if stream.udp_sudoku.is_some() && !matches!(stream.transport, StreamTransport::Kcp(_)) {
        return Err(CoreError::UnsupportedOutboundNetwork);
    }
    if let Some(noise) = &stream.udp_noise {
        xhttp::udp_noise_config(noise)?;
    }
    Ok(())
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
        compile_domain_matchers, DnsConfig, DnsServerConfig, DomainMatcher, GrpcSettings,
        HappyEyeballsSettings, HttpUpgradeSettings, IpCidr, IpMatcherSet, OutboundProxySettings,
        RealitySettings, RealityShortId, RoutingConfig, RoutingDomainStrategy, RoutingPortRange,
        RoutingRule, SocketOptions, StreamSettings, TlsSettings, VlessOutboundSettings,
        WebSocketSettings,
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
            mux: None,
            tag: Some(tag.to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
                socket_options: None,
            },
            settings: OutboundSettings::Freedom(Default::default()),
        }
    }

    fn direct_selection_vless(tag: &str) -> OutboundConfig {
        OutboundConfig {
            mux: None,
            tag: Some(tag.to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
                socket_options: None,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 443,
                users: vec![VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: None,
                    level: 0,
                    vision_seed: xray_proxy::vless::DEFAULT_VISION_SEED,
                    pre_connections: 0,
                }],
            }),
        }
    }

    fn dns_selection_outbound(tag: &str, settings: DnsOutboundSettings) -> OutboundConfig {
        OutboundConfig {
            mux: None,
            tag: Some(tag.to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
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
                    attributes: None,
                    protocols: None,
                    origin: Default::default(),
                    inbound_tags: Vec::new(),
                    networks: None,
                    port_ranges: None,
                    domain_matchers: None,
                    ip_matchers: None,
                    target: RoutingRuleTarget::Outbound("direct".to_owned()),
                    local_os: Vec::new(),
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
            attributes: None,
            protocols: None,
            origin: Default::default(),
            inbound_tags: Vec::new(),
            networks: None,
            port_ranges: None,
            domain_matchers: None,
            ip_matchers: Some(ip_matcher_set(IpCidr::full(IpAddr::V4(ip)))),
            target: RoutingRuleTarget::Outbound(tag.to_owned()),
            local_os: Vec::new(),
        }
    }

    fn domain_and_ip_rule(tag: &str, domain: &str, ip: Ipv4Addr) -> RoutingRule {
        RoutingRule {
            attributes: None,
            protocols: None,
            origin: Default::default(),
            inbound_tags: Vec::new(),
            networks: None,
            port_ranges: None,
            domain_matchers: Some(
                compile_domain_matchers(&[DomainMatcher::Full(domain.to_owned())]).unwrap(),
            ),
            ip_matchers: Some(ip_matcher_set(IpCidr::full(IpAddr::V4(ip)))),
            target: RoutingRuleTarget::Outbound(tag.to_owned()),
            local_os: Vec::new(),
        }
    }

    fn inbound_rule(inbound_tag: &str, outbound_tag: &str) -> RoutingRule {
        RoutingRule {
            attributes: None,
            protocols: None,
            origin: Default::default(),
            inbound_tags: vec![inbound_tag.to_owned()],
            networks: None,
            port_ranges: None,
            domain_matchers: None,
            ip_matchers: None,
            target: RoutingRuleTarget::Outbound(outbound_tag.to_owned()),
            local_os: Vec::new(),
        }
    }

    fn network_port_rule(
        outbound_tag: &str,
        network: Network,
        port_range: RoutingPortRange,
    ) -> RoutingRule {
        RoutingRule {
            attributes: None,
            protocols: None,
            origin: Default::default(),
            inbound_tags: Vec::new(),
            networks: Some(vec![network]),
            port_ranges: Some(vec![port_range]),
            domain_matchers: None,
            ip_matchers: None,
            target: RoutingRuleTarget::Outbound(outbound_tag.to_owned()),
            local_os: Vec::new(),
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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

        assert!(matches!(selected, UdpOutbound::Freedom(_)));
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
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
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
                    tcp_fragment: None,
                    tcp_header_custom: None,
                    udp_header_custom: None,
                    tcp_sudoku: None,
                    udp_sudoku: None,
                    udp_noise: None,
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
            tcp_fragment: None,
            tcp_header_custom: None,
            udp_header_custom: None,
            tcp_sudoku: None,
            udp_sudoku: None,
            udp_noise: None,
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
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
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
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
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
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
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
                    ..SocketOptions::default()
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
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
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
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
                socket_options: Some(SocketOptions {
                    happy_eyeballs: Some(HappyEyeballsSettings::default()),
                    ..SocketOptions::default()
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
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
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
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                udp_sudoku: None,
                udp_noise: None,
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
    fn dns_selector_prefilter_skips_conditions_that_match_nothing() {
        // `"port": 0` or `"network": "quic"` keeps a condition that no
        // connection meets, so the rule can never select the DNS outbound.
        let target = Target::new(
            RoutingTargetAddr::Domain("example.test".to_owned()),
            53,
            RoutingNetwork::Udp,
        );
        for nothing in [
            |rule: &mut RoutingRule| rule.port_ranges = Some(Vec::new()),
            |rule: &mut RoutingRule| rule.networks = Some(Vec::new()),
        ] {
            let mut config = direct_selection_config();
            config.outbounds.push(dns_selection_outbound(
                "dns-out",
                DnsOutboundSettings::default(),
            ));
            let mut rule = network_port_rule("dns-out", Network::Udp, RoutingPortRange::single(53));
            nothing(&mut rule);
            config.routing.rules = vec![rule];
            let router = OutboundRouter::new(Arc::new(config));

            assert!(!router.may_select_dns_outbound(None, &target));
            assert!(router
                .select_dns_outbound_for_session(None, &target)
                .expect("a rule that matches nothing keeps the regular path")
                .is_none());
        }
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
            attributes: None,
            protocols: None,
            origin: Default::default(),
            inbound_tags,
            networks: Some(vec![Network::Udp]),
            port_ranges: Some(
                (0..SELECTOR_COUNT)
                    .map(|index| {
                        RoutingPortRange::single(
                            u16::try_from(index * 2).expect("test port must fit in u16"),
                        )
                    })
                    .collect(),
            ),
            domain_matchers: None,
            ip_matchers: None,
            target: RoutingRuleTarget::Outbound("dns-out".to_owned()),
            local_os: Vec::new(),
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
        rule.domain_matchers = Some(
            compile_domain_matchers(&[DomainMatcher::Full("dns-only.test".to_owned())]).unwrap(),
        );
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
                &xray_config::RouteContext::default(),
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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
            ..SocketOptions::default()
        });

        let TcpOutbound::Freedom(freedom) =
            build_tcp_outbound(&configured).expect("compile freedom outbound")
        else {
            panic!("freedom compiles to freedom");
        };
        let compiled = freedom
            .happy_eyeballs
            .expect("explicit Happy Eyeballs settings should enable candidate racing");

        assert!(compiled.prioritize_ipv6);
        assert_eq!(compiled.interleave, 2);
        assert_eq!(compiled.try_delay, Duration::from_millis(175));
        assert_eq!(compiled.max_concurrent.get(), 3);
    }

    #[test]
    fn zero_happy_eyeballs_delay_leaves_freedom_without_racing() {
        let mut configured = direct_selection_freedom("direct");
        configured.stream.socket_options = Some(SocketOptions {
            happy_eyeballs: Some(HappyEyeballsSettings {
                try_delay_ms: 0,
                ..HappyEyeballsSettings::default()
            }),
            ..SocketOptions::default()
        });

        let compiled = build_tcp_outbound(&configured).expect("compile freedom outbound");

        assert!(matches!(
            compiled,
            TcpOutbound::Freedom(FreedomOutbound {
                happy_eyeballs: None,
                ..
            })
        ));
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
            ..SocketOptions::default()
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
        let outbound = TcpOutbound::Freedom(FreedomOutbound {
            happy_eyeballs: Some(HappyEyeballsConfig {
                prioritize_ipv6: false,
                interleave: 1,
                try_delay: Duration::from_secs(30),
                max_concurrent: NonZeroUsize::new(2).expect("non-zero test concurrency"),
            }),
            ..FreedomOutbound::default()
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
                mux: None,
                pre_connections: None,
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: None,
                    level: 0,
                    vision_seed: xray_proxy::vless::DEFAULT_VISION_SEED,
                    pre_connections: 0,
                },
                encryption: None,
                carrier: StreamCarrier {
                    fragment: None,
                    header_custom: None,
                    sudoku: None,
                    socket_options: None,
                    address_port: Default::default(),
                    download: None,
                    server: domain_tcp_target("proxy.example"),
                    transport: ConnectorConfig::Tcp,
                    transport_layer: TransportLayer::Raw,
                    happy_eyeballs: Some(HappyEyeballsConfig {
                        prioritize_ipv6: false,
                        interleave: 1,
                        try_delay: Duration::from_secs(30),
                        max_concurrent: NonZeroUsize::new(2).expect("non-zero test concurrency"),
                    }),
                },
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

        let mut stream = opened.expect("open VLESS carrier through second candidate");
        // No payload follows, so flush the held request header on its own.
        stream.flush().await.unwrap();
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
        let mut stream = open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .expect("open outer VLESS over nested carrier");
        // No payload follows, so flush the held request headers on their own.
        stream.flush().await.unwrap();

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

    /// Records the candidates of every dial and hands back an in-memory peer.
    #[derive(Default)]
    struct CandidateRecordingConnector {
        candidates: Mutex<Vec<Vec<SocketAddr>>>,
        peers: Mutex<Vec<tokio::io::DuplexStream>>,
    }

    #[async_trait]
    impl ResolvedTcpConnector for CandidateRecordingConnector {
        async fn connect_resolved(
            &self,
            _original_target: &Target,
            candidates: &[SocketAddr],
            _happy_eyeballs: Option<&HappyEyeballsConfig>,
        ) -> Result<BoxedTransportStream, TransportError> {
            self.candidates.lock().unwrap().push(candidates.to_vec());
            let (stream, peer) = tokio::io::duplex(4_096);
            self.peers.lock().unwrap().push(peer);
            Ok(Box::new(stream))
        }
    }

    fn strategy_freedom(domain_strategy: DomainStrategy) -> TcpOutbound {
        TcpOutbound::Freedom(FreedomOutbound {
            domain_strategy,
            ..FreedomOutbound::default()
        })
    }

    #[tokio::test]
    async fn freedom_dials_only_the_addresses_its_domain_strategy_permits() {
        let v4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 443));
        let v6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7), 443));
        let target = domain_tcp_target("dual.example");
        for (answer, strategy, expected) in [
            (vec![v6, v4], DomainStrategy::AsIs, Some(vec![v6, v4])),
            (vec![v6, v4], DomainStrategy::UseIp, Some(vec![v6, v4])),
            (vec![v6, v4], DomainStrategy::UseIpv4, Some(vec![v4])),
            (vec![v6, v4], DomainStrategy::ForceIpv6, Some(vec![v6])),
            (vec![v6, v4], DomainStrategy::UseIpv4v6, Some(vec![v4])),
            (vec![v4], DomainStrategy::UseIpv6v4, Some(vec![v4])),
            // A Use strategy falls back to both families; Force fails.
            (vec![v4], DomainStrategy::UseIpv6, Some(vec![v4])),
            (vec![v4], DomainStrategy::ForceIpv6, None),
        ] {
            let connector = Arc::new(CandidateRecordingConnector::default());
            let dialer = TransportDialer::system()
                .unwrap()
                .with_resolved_tcp_connector(connector.clone());
            let resolver = FakeDnsResolver::resolving_to_many(answer);
            let opened = open_tcp_stream_with_resolver_and_dialer(
                &strategy_freedom(strategy),
                &target,
                &resolver,
                &dialer,
            )
            .await;
            let dialed = connector.candidates.lock().unwrap().clone();
            match expected {
                Some(expected) => {
                    opened.unwrap_or_else(|error| panic!("{strategy:?}: {error}"));
                    assert_eq!(dialed, [expected], "{strategy:?}");
                }
                None => {
                    assert!(opened.is_err(), "{strategy:?}");
                    assert!(dialed.is_empty(), "{strategy:?}");
                }
            }
        }
    }

    #[tokio::test]
    async fn a_freedom_hop_resolves_the_next_server_with_its_domain_strategy() {
        let mut config = direct_selection_config();
        config.outbounds = vec![
            direct_selection_vless("entry"),
            direct_selection_freedom("exit"),
        ];
        let OutboundSettings::Vless(vless) = &mut config.outbounds[0].settings else {
            unreachable!()
        };
        vless.server = TargetAddr::Domain("server.example".to_owned());
        config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
            tag: "exit".to_owned(),
            transport_layer: true,
        });
        config.outbounds[1].stream.socket_options = Some(SocketOptions {
            domain_strategy: DomainStrategy::ForceIpv4,
            ..SocketOptions::default()
        });
        config.default_outbound_tag = Some("entry".to_owned());
        config.routing.rules.clear();
        let router = OutboundRouter::new(Arc::new(config));
        let outbound = router.select_tcp_outbound().expect("compile the chain");

        let v4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 9), 443));
        let v6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9), 443));
        let resolver =
            FakeDnsResolver::resolving_to_many(vec![v6, v4]).expect_lookup("server.example", 443);
        let connector = Arc::new(CandidateRecordingConnector::default());
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(connector.clone());
        let _stream = open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &domain_tcp_target("destination.example"),
            &resolver,
            &dialer,
        )
        .await
        .expect("open the chain");

        assert_eq!(*connector.candidates.lock().unwrap(), [vec![v4]]);
    }

    fn redirect_freedom(redirect: FreedomRedirect, domain_strategy: DomainStrategy) -> TcpOutbound {
        TcpOutbound::Freedom(FreedomOutbound {
            redirect: Some(Arc::new(redirect)),
            domain_strategy,
            ..FreedomOutbound::default()
        })
    }

    fn redirect_to(address: Option<TargetAddr>, port: u16) -> FreedomRedirect {
        FreedomRedirect {
            address,
            port: std::num::NonZeroU16::new(port),
        }
    }

    #[tokio::test]
    async fn freedom_dials_the_redirect_destination() {
        let answer = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 20), 443));
        let pinned = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
        for (redirect, expected_lookup, expected) in [
            // An IP address and port replace both.
            (
                redirect_to(Some(TargetAddr::Ip(pinned)), 8443),
                None,
                SocketAddr::new(pinned, 8443),
            ),
            // Port 0 keeps the destination's port.
            (
                redirect_to(Some(TargetAddr::Ip(pinned)), 0),
                None,
                SocketAddr::new(pinned, 443),
            ),
            // A port alone keeps the destination's address. Resolvers answer
            // with the port they are asked for, which is the redirect's.
            (
                redirect_to(None, 8443),
                Some(("dual.example", 8443)),
                answer,
            ),
            // A domain resolves in place of the destination.
            (
                redirect_to(Some(TargetAddr::Domain("redirect.example".to_owned())), 0),
                Some(("redirect.example", 443)),
                answer,
            ),
        ] {
            let connector = Arc::new(CandidateRecordingConnector::default());
            let dialer = TransportDialer::system()
                .unwrap()
                .with_resolved_tcp_connector(connector.clone());
            let mut resolver = FakeDnsResolver::resolving_to_many(vec![answer]);
            if let Some((domain, port)) = expected_lookup {
                resolver = resolver.expect_lookup(domain, port);
            }
            let outbound = redirect_freedom(redirect, DomainStrategy::AsIs);
            open_tcp_stream_with_resolver_and_dialer(
                &outbound,
                &domain_tcp_target("dual.example"),
                &resolver,
                &dialer,
            )
            .await
            .expect("dial the redirect destination");
            let dialed = connector.candidates.lock().unwrap().clone();
            assert_eq!(dialed, [vec![expected]]);
            assert_eq!(resolver.calls(), usize::from(expected_lookup.is_some()));
        }
    }

    #[tokio::test]
    async fn a_freedom_hop_redirects_the_next_server() {
        let pinned = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 40));
        let answer = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 41), 443));
        for (redirect, server_lookups, expected) in [
            // The server is never resolved once its address is replaced.
            (
                redirect_to(Some(TargetAddr::Ip(pinned)), 0),
                0,
                SocketAddr::new(pinned, 443),
            ),
            (
                redirect_to(None, 8443),
                1,
                SocketAddr::new(answer.ip(), 8443),
            ),
        ] {
            let mut config = direct_selection_config();
            config.outbounds = vec![
                direct_selection_vless("entry"),
                direct_selection_freedom("exit"),
            ];
            let OutboundSettings::Vless(vless) = &mut config.outbounds[0].settings else {
                unreachable!()
            };
            vless.server = TargetAddr::Domain("server.example".to_owned());
            config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
                tag: "exit".to_owned(),
                transport_layer: true,
            });
            config.outbounds[1].settings = OutboundSettings::Freedom(FreedomOutboundSettings {
                redirect,
                ..FreedomOutboundSettings::default()
            });
            config.default_outbound_tag = Some("entry".to_owned());
            config.routing.rules.clear();
            let router = OutboundRouter::new(Arc::new(config));
            let outbound = router.select_tcp_outbound().expect("compile the chain");

            let resolver = FakeDnsResolver::resolving_to_many(vec![answer]);
            let connector = Arc::new(CandidateRecordingConnector::default());
            let dialer = TransportDialer::system()
                .unwrap()
                .with_resolved_tcp_connector(connector.clone());
            let _stream = open_tcp_stream_with_resolver_and_dialer(
                &outbound,
                &domain_tcp_target("destination.example"),
                &resolver,
                &dialer,
            )
            .await
            .expect("open the chain");

            assert_eq!(*connector.candidates.lock().unwrap(), [vec![expected]]);
            assert_eq!(resolver.calls(), server_lookups);
        }
    }

    #[test]
    fn rand_between_reads_as_xray_core_draws() {
        // The upper bound is left out, and bounds one apart give the lower.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let drawn = xray_rand_between(16, 20);
            assert!((16..20).contains(&drawn), "{drawn}");
            seen.insert(drawn);
            assert_eq!(xray_rand_between(10, 11), 10);
            assert_eq!(xray_rand_between(11, 10), 10);
            assert_eq!(xray_rand_between(7, 7), 7);
            let reversed = xray_rand_between(20, 16);
            assert!((16..20).contains(&reversed), "{reversed}");
            seen.insert(reversed);
        }
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), [16, 17, 18, 19]);
    }

    #[test]
    fn noises_read_a_mapped_address_as_ipv4() {
        use xray_config::FreedomNoiseFamily::{Ip, Ipv4, Ipv6};
        for (target, ipv4) in [
            ("192.0.2.1", true),
            ("::ffff:192.0.2.1", true),
            ("2001:db8::1", false),
        ] {
            let target: IpAddr = target.parse().unwrap();
            assert!(noise_applies(Ip, target));
            assert_eq!(noise_applies(Ipv4, target), ipv4, "{target}");
            assert_eq!(noise_applies(Ipv6, target), !ipv4, "{target}");
        }
    }

    #[tokio::test]
    async fn freedom_sends_noises_as_xray_core_does() {
        use xray_config::{FreedomNoise, FreedomNoiseFamily, FreedomNoisePacket};
        let noise = |packet: &[u8], apply_to| FreedomNoise {
            packet: FreedomNoisePacket::Bytes(packet.to_vec()),
            delay_ms: (0, 0),
            apply_to,
        };
        let freedom = |redirect| {
            let mut configured = direct_selection_freedom("direct");
            configured.settings = OutboundSettings::Freedom(FreedomOutboundSettings {
                redirect,
                noises: vec![
                    noise(b"any", FreedomNoiseFamily::Ip),
                    noise(b"v6", FreedomNoiseFamily::Ipv6),
                    FreedomNoise {
                        packet: FreedomNoisePacket::Random(3, 4),
                        delay_ms: (1, 1),
                        apply_to: FreedomNoiseFamily::Ipv4,
                    },
                ],
                ..FreedomOutboundSettings::default()
            });
            let UdpOutbound::Freedom(freedom) = build_udp_outbound(&configured).unwrap() else {
                panic!("freedom compiles to freedom");
            };
            freedom
        };
        let sink = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = sink.local_addr().unwrap();

        let sent = freedom(FreedomRedirect::default())
            .send_udp_noises(&socket, target)
            .await
            .unwrap();
        assert_eq!(sent, 6);
        let mut buffer = [0; 64];
        let first = sink.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..first], b"any");
        // The IPv6 noise is skipped for an IPv4 destination.
        assert_eq!(sink.recv(&mut buffer).await.unwrap(), 3);

        // Nothing goes when `redirect` sends the flow to port 53.
        let sent = freedom(redirect_to(None, 53))
            .send_udp_noises(&socket, target)
            .await
            .unwrap();
        assert_eq!(sent, 0);
    }

    #[test]
    fn freedom_settings_reach_tcp_and_udp_outbounds() {
        let mut configured = direct_selection_freedom("direct");
        configured.settings = OutboundSettings::Freedom(FreedomOutboundSettings {
            redirect: redirect_to(None, 53),
            user_level: 3,
            ..FreedomOutboundSettings::default()
        });
        let TcpOutbound::Freedom(tcp) = build_tcp_outbound(&configured).unwrap() else {
            panic!("freedom compiles to freedom");
        };
        let UdpOutbound::Freedom(udp) = build_udp_outbound(&configured).unwrap() else {
            panic!("freedom compiles to freedom");
        };
        let target = Target::new(
            RoutingTargetAddr::Domain("dns.example".to_owned()),
            5353,
            RoutingNetwork::Udp,
        );
        for freedom in [tcp, udp] {
            assert_eq!(freedom.level(), 3);
            let redirected = freedom.redirect(&target).expect("a redirect");
            assert_eq!(redirected.addr, target.addr);
            assert_eq!(redirected.port, 53);
            assert_eq!(redirected.network, RoutingNetwork::Udp);
        }

        // An empty redirect is dropped.
        let compiled = build_tcp_outbound(&direct_selection_freedom("direct")).unwrap();
        let TcpOutbound::Freedom(freedom) = compiled else {
            panic!("freedom compiles to freedom");
        };
        assert!(freedom.redirect(&target).is_none());
    }

    #[test]
    fn freedom_domain_strategy_reaches_tcp_and_udp_outbounds() {
        let mut configured = direct_selection_freedom("direct");
        configured.stream.socket_options = Some(SocketOptions {
            domain_strategy: DomainStrategy::ForceIp,
            ..SocketOptions::default()
        });
        let TcpOutbound::Freedom(tcp) = build_tcp_outbound(&configured).unwrap() else {
            panic!("freedom compiles to freedom");
        };
        assert_eq!(tcp.domain_strategy(), DomainStrategy::ForceIp);
        let UdpOutbound::Freedom(udp) = build_udp_outbound(&configured).unwrap() else {
            panic!("freedom compiles to freedom");
        };
        assert_eq!(udp.domain_strategy(), DomainStrategy::ForceIp);

        // A UDP flow first addressed to an IP prefers that IP's family.
        let original = |addr| Target::new(addr, 443, RoutingNetwork::Udp);
        assert_eq!(
            udp.udp_domain_strategy(&original(RoutingTargetAddr::Ip(IpAddr::V6(
                Ipv6Addr::LOCALHOST
            )))),
            DomainStrategy::ForceIpv6v4
        );
        assert_eq!(
            udp.udp_domain_strategy(&original(RoutingTargetAddr::Domain(
                "quic.example".to_owned()
            ))),
            DomainStrategy::ForceIp
        );
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
        let mut stream = open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .expect("open multi-hop VLESS chain");
        // No payload follows, so flush the held request headers on their own.
        stream.flush().await.unwrap();

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
            attributes: None,
            protocols: None,
            origin: Default::default(),
            inbound_tags: Vec::new(),
            networks: None,
            port_ranges: None,
            domain_matchers: None,
            ip_matchers: None,
            target: RoutingRuleTarget::Balancer("automatic".to_owned()),
            local_os: Vec::new(),
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
                .select_tcp_outbound_for_session_with_tag(
                    &xray_config::RouteContext::default(),
                    &target,
                    true
                )
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
                .select_tcp_outbound_for_session_with_tag(
                    &xray_config::RouteContext::default(),
                    &target,
                    true
                )
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
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
            .unwrap();
        let second = second_router
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
            .unwrap();
        let third = first_router
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
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
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("proxy-b"));

        router
            .selection()
            .record_health_failure(proxy_b, OutboundHealthFailure::Transport, 2_000);
        let selected = router
            .select_tcp_outbound_for_session(None, &target)
            .unwrap();
        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("proxy-b"));

        router
            .selection()
            .record_health_success(proxy_a, Duration::from_millis(10), 2_000);
        let selected = router
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
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
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
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
                .select_tcp_outbound_for_session_with_tag(
                    &xray_config::RouteContext::default(),
                    &target,
                    true,
                )
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
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
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
        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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
        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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
                &xray_config::RouteContext::default(),
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
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
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
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
            .unwrap();
        assert_eq!(second.tag.as_deref(), Some("proxy-b"));

        second_router
            .selection()
            .set_override("automatic", "proxy-a")
            .unwrap();
        let first_again = second_router
            .select_tcp_outbound_for_session_with_tag(
                &xray_config::RouteContext::default(),
                &target,
                true,
            )
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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
            TcpOutbound::Freedom(_)
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
            h2_stream_receive_window: Some(1024 * 1024),
            download: None,
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
        assert_eq!(config.h2_stream_receive_window, 1024 * 1024);
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
            udp_hop: xray_config::QuicUdpHopSettings {
                ports: vec![4_443, 4_444],
                interval: xray_config::QuicIntervalRange { from: 7, to: 9 },
                local: true,
                remote: false,
                remote_once: true,
                remote_ips: vec![xray_config::IpCidr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 0)),
                    24,
                )
                .unwrap()],
            },
            init_stream_receive_window: 2_100_000,
            max_stream_receive_window: 2_100_000,
            init_connection_receive_window: 3_100_000,
            max_connection_receive_window: 3_100_000,
            max_idle_timeout_secs: 17,
            keep_alive_period_secs: 11,
            disable_path_mtu_discovery: true,
            max_incoming_streams: 16,
            disable_gso: true,
            disable_stateless_reset: true,
            brutal_disable_loss_compensation: true,
            debug: false,
        });

        let built = built_xhttp_transport(&outbound);
        let quic = built.h3_quic_config();
        assert!(quic.disable_gso);
        assert!(quic.brutal_disable_loss_compensation);
        assert_eq!(quic.initial_stream_receive_window, 2_100_000);
        assert_eq!(quic.max_stream_receive_window, Some(2_100_000));
        assert_eq!(quic.initial_connection_receive_window, 3_100_000);
        assert_eq!(quic.max_connection_receive_window, Some(3_100_000));
        assert_eq!(quic.max_idle_timeout, Duration::from_secs(17));
        assert_eq!(quic.keep_alive_interval, Some(Duration::from_secs(11)));
        assert_eq!(quic.max_incoming_bidirectional_streams, 16);
        assert!(quic.disable_path_mtu_discovery);
        assert_eq!(quic.congestion, H3Congestion::Reno);
        assert_eq!(
            quic.udp_hop,
            xray_transport::stream::H3UdpHopConfig {
                ports: vec![4_443, 4_444],
                interval_min: Duration::from_secs(7),
                interval_max: Duration::from_secs(9),
                local: true,
                remote: false,
                remote_once: true,
                remote_ips: vec![(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 0)),
                    24
                )],
            }
        );
    }

    #[test]
    fn unsupported_explicit_h3_quic_features_fail_closed_but_h2_ignores_them() {
        let hop = |from| QuicParamsSettings {
            udp_hop: xray_config::QuicUdpHopSettings {
                ports: vec![4_443],
                interval: xray_config::QuicIntervalRange { from, to: 6 },
                local: true,
                remote: true,
                ..xray_config::QuicUdpHopSettings::default()
            },
            ..QuicParamsSettings::default()
        };
        let mut h3 = xhttp_vless(
            XhttpSettings::default(),
            tls_security(Some("sni.example"), &["h3"]),
            TargetAddr::Domain("origin.example".to_owned()),
            443,
        );
        h3.stream.quic_params = Some(hop(5));
        build_vless_tcp_outbound(&h3).expect("H3 hops its UDP carrier");
        h3.stream.quic_params = Some(hop(4));
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
            // A maximum below its initial window; distinct maxima above it
            // now auto-tune.
            QuicParamsSettings {
                init_stream_receive_window: 2 * 1024 * 1024,
                max_stream_receive_window: 1024 * 1024,
                ..QuicParamsSettings::default()
            },
            // Only Hysteria announces the peer rate plain `brutal` follows.
            QuicParamsSettings {
                congestion: xray_config::QuicCongestion::Brutal,
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

        let mut adaptive = xhttp_vless(
            XhttpSettings::default(),
            tls_security(Some("sni.example"), &["h3"]),
            TargetAddr::Domain("origin.example".to_owned()),
            443,
        );
        adaptive.stream.quic_params = Some(QuicParamsSettings {
            init_stream_receive_window: 2 * 1024 * 1024,
            max_stream_receive_window: 6 * 1024 * 1024,
            ..QuicParamsSettings::default()
        });
        build_vless_tcp_outbound(&adaptive).expect("receive windows auto-tune up to their maxima");

        let mut fixed_rate = adaptive;
        fixed_rate.stream.quic_params = Some(QuicParamsSettings {
            congestion: xray_config::QuicCongestion::ForceBrutal,
            brutal_up_bytes_per_sec: 65_536,
            ..QuicParamsSettings::default()
        });
        let built = built_xhttp_transport(&fixed_rate);
        assert_eq!(
            built.h3_quic_config().congestion,
            H3Congestion::ForceBrutal {
                bytes_per_second: 65_536
            }
        );
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
    /// a curiosity. [`carrier::grpc_authority`] has the rest of the reasoning, including
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
    /// [`super::carrier::grpc_authority`] documents why nothing else is reachable, but
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
    /// [`super::carrier::configured_tls_server_name`] to the *config*: it is the only
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
                "streamSettings.tlsSettings.serverName",
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
        rule.networks = Some(vec![Network::Tcp]);
        rule.port_ranges = Some(vec![RoutingPortRange::single(443)]);
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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

            assert!(matches!(selected, TcpOutbound::Freedom(_)));
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
    }

    #[tokio::test]
    async fn outbound_router_dns_second_pass_preserves_domain_for_combined_rule() {
        let resolved_ip = Ipv4Addr::new(203, 0, 113, 7);
        let mut config = direct_selection_config();
        config.routing.domain_strategy = RoutingDomainStrategy::IpIfNonMatch;
        let mut rule = domain_and_ip_rule("direct", "example.test", resolved_ip);
        rule.networks = Some(vec![Network::Tcp]);
        rule.port_ranges = Some(vec![RoutingPortRange::single(443)]);
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

        assert!(matches!(selected, TcpOutbound::Freedom(_)));
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
                &xray_config::RouteContext::default(),
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
        rule.networks = Some(vec![Network::Tcp]);
        rule.port_ranges = Some(vec![RoutingPortRange::single(443)]);
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

        assert!(matches!(selected.outbound, TcpOutbound::Freedom(_)));
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
                mux: None,
                pre_connections: None,
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: Some("xtls-rprx-vision".to_owned()),
                    level: 0,
                    vision_seed: xray_proxy::vless::DEFAULT_VISION_SEED,
                    pre_connections: 0,
                },
                encryption: None,
                carrier: StreamCarrier {
                    fragment: None,
                    header_custom: None,
                    sudoku: None,
                    socket_options: None,
                    address_port: Default::default(),
                    download: None,
                    server: Target::new(
                        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        0,
                        RoutingNetwork::Tcp,
                    ),
                    transport: ConnectorConfig::Tcp,
                    transport_layer: TransportLayer::Raw,
                    happy_eyeballs: None,
                },
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
                mux: None,
                pre_connections: None,
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: Some(VISION_FLOW.to_owned()),
                    level: 0,
                    vision_seed: xray_proxy::vless::DEFAULT_VISION_SEED,
                    pre_connections: 0,
                },
                encryption: None,
                carrier: StreamCarrier {
                    fragment: None,
                    header_custom: None,
                    sudoku: None,
                    socket_options: None,
                    address_port: Default::default(),
                    download: None,
                    server: Target::new(
                        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        0,
                        RoutingNetwork::Tcp,
                    ),
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
                },
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
                mux: None,
                pre_connections: None,
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: Some(VISION_FLOW.to_owned()),
                    level: 0,
                    vision_seed: xray_proxy::vless::DEFAULT_VISION_SEED,
                    pre_connections: 0,
                },
                encryption: None,
                carrier: StreamCarrier {
                    fragment: None,
                    header_custom: None,
                    sudoku: None,
                    socket_options: None,
                    address_port: Default::default(),
                    download: None,
                    server: Target::new(
                        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        443,
                        RoutingNetwork::Tcp,
                    ),
                    transport: ConnectorConfig::Reality(reality_config.clone()),
                    transport_layer: TransportLayer::Raw,
                    happy_eyeballs: None,
                },
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
        // The header waits for the first payload and leaves in front of it.
        stream.write_all(b"vision payload").await.unwrap();
        stream.flush().await.unwrap();

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

        // No empty padding frame: the first frame carries the UUID and payload.
        let (padded, content_len, padding_len) = read_vision_frame(&mut protected_side, true).await;
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

    /// `testseed` sets Vision's padding: a zero range pads no frame, where
    /// Xray-core's default pads each short frame with up to 255 bytes.
    #[tokio::test]
    async fn vision_pads_with_the_users_testseed() {
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                mux: None,
                pre_connections: None,
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: Some(VISION_FLOW.to_owned()),
                    level: 0,
                    vision_seed: [0, 0, 0, 0],
                    pre_connections: 0,
                },
                encryption: None,
                carrier: StreamCarrier {
                    fragment: None,
                    header_custom: None,
                    sudoku: None,
                    socket_options: None,
                    address_port: Default::default(),
                    download: None,
                    server: Target::new(
                        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        443,
                        RoutingNetwork::Tcp,
                    ),
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
                },
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Tcp,
        );
        let (client, mut protected_side) = tokio::io::duplex(1 << 16);
        let transport_dialer = TransportDialer::system()
            .unwrap()
            .with_reality_engine(Arc::new(DuplexRealityEngine::new(client)));
        let mut stream = open_vless_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &transport_dialer,
        )
        .await
        .unwrap();
        let header_len = encode_request_header(&VlessRequest {
            user_id: outbound.user().id,
            command: VlessCommand::Tcp,
            target: target.clone(),
            flow: outbound.user().flow.clone(),
        })
        .unwrap()
        .len();
        let mut header = vec![0; header_len];
        for (index, payload) in [b"first".as_slice(), b"second", b"third"]
            .into_iter()
            .enumerate()
        {
            stream.write_all(payload).await.unwrap();
            stream.flush().await.unwrap();
            if index == 0 {
                protected_side.read_exact(&mut header).await.unwrap();
            }
            let (_, content_len, padding_len) =
                read_vision_frame(&mut protected_side, index == 0).await;
            assert_eq!(content_len, payload.len());
            assert_eq!(padding_len, 0, "frame {index}");
        }
    }

    #[tokio::test]
    async fn open_vless_udp_stream_rejects_udp443_for_regular_vision_flow_before_connecting() {
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                mux: None,
                pre_connections: None,
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: Some(VISION_FLOW.to_owned()),
                    level: 0,
                    vision_seed: xray_proxy::vless::DEFAULT_VISION_SEED,
                    pre_connections: 0,
                },
                encryption: None,
                carrier: StreamCarrier {
                    fragment: None,
                    header_custom: None,
                    sudoku: None,
                    socket_options: None,
                    address_port: Default::default(),
                    download: None,
                    server: Target::new(
                        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        443,
                        RoutingNetwork::Tcp,
                    ),
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
                },
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
                mux: None,
                pre_connections: None,
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: Some("xtls-rprx-vision-udp443".to_owned()),
                    level: 0,
                    vision_seed: xray_proxy::vless::DEFAULT_VISION_SEED,
                    pre_connections: 0,
                },
                encryption: None,
                carrier: StreamCarrier {
                    fragment: None,
                    header_custom: None,
                    sudoku: None,
                    socket_options: None,
                    address_port: Default::default(),
                    download: None,
                    server: Target::new(
                        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        443,
                        RoutingNetwork::Tcp,
                    ),
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
                },
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

    /// The command stream UDP and Mux ride pads with the user's `testseed`
    /// too.
    #[tokio::test]
    async fn vision_udp_pads_with_the_users_testseed() {
        let outbound = VlessTcpOutbound {
            payload: Arc::new(VlessTcpOutboundPayload {
                mux: None,
                pre_connections: None,
                user: VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: Some("xtls-rprx-vision-udp443".to_owned()),
                    level: 0,
                    vision_seed: [0, 0, 0, 0],
                    pre_connections: 0,
                },
                encryption: None,
                carrier: StreamCarrier {
                    fragment: None,
                    header_custom: None,
                    sudoku: None,
                    socket_options: None,
                    address_port: Default::default(),
                    download: None,
                    server: Target::new(
                        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        443,
                        RoutingNetwork::Tcp,
                    ),
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
                },
            }),
        };
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            443,
            RoutingNetwork::Udp,
        );
        let (client, mut protected_side) = tokio::io::duplex(1 << 16);
        let transport_dialer = TransportDialer::system()
            .unwrap()
            .with_reality_engine(Arc::new(DuplexRealityEngine::new(client)));
        let (mut stream, _) = open_vless_udp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &transport_dialer,
        )
        .await
        .unwrap();
        let header_len = encode_request_header(&VlessRequest {
            user_id: outbound.user().id,
            command: VlessCommand::Mux,
            target: target.clone(),
            flow: Some(VISION_FLOW.to_owned()),
        })
        .unwrap()
        .len();
        let mut header = vec![0; header_len];
        protected_side.read_exact(&mut header).await.unwrap();
        for (index, payload) in [b"first".as_slice(), b"second", b"third"]
            .into_iter()
            .enumerate()
        {
            stream.write_all(payload).await.unwrap();
            stream.flush().await.unwrap();
            let (_, content_len, padding_len) =
                read_vision_frame(&mut protected_side, index == 0).await;
            assert_eq!(content_len, payload.len());
            assert_eq!(padding_len, 0, "frame {index}");
        }
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
    #[tokio::test]
    async fn encrypted_vision_udp443_is_rejected_before_dns_on_every_carrier() {
        for network in ["tcp", "ws", "httpupgrade", "grpc", "xhttp"] {
            let raw = serde_json::json!({"outbounds": [{"protocol": "vless", "settings": {"vnext": [{
                "address": "must-not-resolve.invalid", "port": 443,
                "users": [{"id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "flow": VISION_FLOW,
                    "encryption": "mlkem768x25519plus.random.0rtt.CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]
            }]}, "streamSettings": {"network": network, "security": "none"}}]});
            let config = xray_config::parse_xray_json(&raw.to_string())
                .unwrap()
                .config;
            let outbound = build_vless_tcp_outbound(&config.outbounds[0]).unwrap();
            assert!(outbound.blocks_udp443());
            let target = Target::new(
                RoutingTargetAddr::Domain("quic.example.test".to_owned()),
                443,
                RoutingNetwork::Udp,
            );
            let error = open_vless_udp_stream_with_resolver_and_dialer(
                &outbound,
                &target,
                &SystemDnsResolver,
                &TransportDialer::system().unwrap(),
            )
            .await;
            assert!(
                matches!(error, Err(CoreError::VisionUdp443Rejected)),
                "{network}"
            );
        }
    }

    fn vless_mux(
        concurrency: i16,
        xudp_concurrency: i16,
        udp443: xray_config::MuxUdp443,
    ) -> Option<xray_config::MuxSettings> {
        Some(xray_config::MuxSettings {
            concurrency,
            xudp_concurrency,
            udp443,
        })
    }

    async fn read_mux_frames(peer: &mut tokio::io::DuplexStream, count: usize) -> Vec<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut frames = Vec::new();
        while frames.len() < count {
            if let Some((_, n)) = xray_proxy::mux::decode(&bytes).unwrap() {
                frames.push(bytes.drain(..n).collect());
                continue;
            }
            let mut chunk = [0; 512];
            let n = peer.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "Mux parent closed early");
            bytes.extend_from_slice(&chunk[..n]);
        }
        frames
    }

    #[tokio::test]
    async fn vless_mux_shares_one_mux_command_parent_for_tcp_and_xudp_children() {
        let mut config = direct_selection_vless("proxy");
        config.mux = vless_mux(4, 0, xray_config::MuxUdp443::Reject);
        let outbound = build_vless_tcp_outbound(&config).unwrap();
        let connector = Arc::new(RecordingTcpConnector::default());
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(connector.clone());
        let tcp = |port| {
            Target::new(
                RoutingTargetAddr::Domain("destination.example".to_owned()),
                port,
                RoutingNetwork::Tcp,
            )
        };
        let udp = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
            5353,
            RoutingNetwork::Udp,
        );
        let mut children = Vec::new();
        for port in [8443, 8444] {
            children.push(
                open_vless_tcp_stream_with_resolver_and_dialer(
                    &outbound,
                    &tcp(port),
                    &SystemDnsResolver,
                    &dialer,
                )
                .await
                .unwrap(),
            );
        }
        assert!(outbound.udp_uses_mux(&udp));
        let datagrams = outbound
            .open_mux_udp(&udp, &SystemDnsResolver, &dialer, [9; 8])
            .await
            .unwrap();
        datagrams.send(&udp, b"query").await.unwrap();
        // Xray's xudpConcurrency 0 shares the TCP pool: one carrier dial.
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);

        let mut peer = connector.peers.lock().unwrap().pop().unwrap();
        let header = encode_request_header(&VlessRequest {
            user_id: outbound.user().id,
            command: VlessCommand::Mux,
            target: mux::target(),
            flow: None,
        })
        .unwrap();
        let mut received = vec![0; header.len()];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, header);
        let frames = read_mux_frames(&mut peer, 3).await;
        let frames = frames
            .iter()
            .map(|bytes| xray_proxy::mux::decode(bytes).unwrap().unwrap().0)
            .collect::<Vec<_>>();
        assert_eq!(
            frames.iter().map(|f| f.session_id).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(frames
            .iter()
            .all(|f| f.status == xray_proxy::mux::Status::New));
        assert_eq!(frames[0].target.as_ref(), Some(&tcp(8443)));
        assert_eq!(frames[1].target.as_ref(), Some(&tcp(8444)));
        assert_eq!(frames[2].target.as_ref(), Some(&udp));
        assert_eq!(frames[2].payload, Some(&b"query"[..]));
        assert!(frames[2].global_id.is_some_and(|id| id != [0; 8]));

        outbound.close();
        outbound.join().await;
        assert!(children[0].write_all(b"closed").await.is_err());
    }

    #[test]
    fn vless_mux_udp_dispatch_follows_xray_outbound_handler_order() {
        use xray_config::MuxUdp443::{Allow, Reject, Skip};
        let quic = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            443,
            RoutingNetwork::Udp,
        );
        let dns = Target::new(quic.addr.clone(), 53, RoutingNetwork::Udp);
        for (tcp, xudp, policy, quic_mux, dns_mux) in [
            // xudpProxyUDP443 is checked before either pool, as in
            // app/proxyman/outbound/handler.go; reject is a Mux-layer refusal.
            (4, 0, Reject, true, true),
            (4, 0, Skip, false, true),
            (4, 0, Allow, true, true),
            // Negative xudpConcurrency, or no pool at all, uses native UDP.
            (4, -1, Allow, false, false),
            (-1, 0, Allow, false, false),
            (-1, 4, Allow, true, true),
        ] {
            let mut config = direct_selection_vless("proxy");
            config.mux = vless_mux(tcp, xudp, policy);
            let outbound = build_vless_tcp_outbound(&config).unwrap();
            assert_eq!(
                outbound.udp_uses_mux(&quic),
                quic_mux,
                "{tcp} {xudp} {policy:?}"
            );
            assert_eq!(
                outbound.udp_uses_mux(&dns),
                dns_mux,
                "{tcp} {xudp} {policy:?}"
            );
        }
    }

    #[test]
    fn vless_vision_mux_admits_only_the_udp_pool() {
        let mut config = direct_selection_vless("proxy");
        config.stream.security = StreamSecurity::Reality(RealitySettings {
            server_name: "server.example".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [7; 32],
            short_id: RealityShortId::try_from_slice(&[1, 2, 3, 4]).unwrap(),
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        });
        let OutboundSettings::Vless(settings) = &mut config.settings else {
            unreachable!()
        };
        settings.users[0].flow = Some(VISION_UDP443_FLOW.to_owned());
        for tcp in [8, 1] {
            config.mux = vless_mux(tcp, 4, xray_config::MuxUdp443::Allow);
            assert!(matches!(
                build_vless_tcp_outbound(&config),
                Err(CoreError::UnsupportedOutboundFlow)
            ));
        }
        config.mux = vless_mux(-1, 4, xray_config::MuxUdp443::Allow);
        let outbound = build_vless_tcp_outbound(&config).unwrap();
        // Vision still refuses native UDP/443 only when the flow forbids it;
        // a pooled XUDP child is outside VLESS's UDP command entirely.
        let quic = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            443,
            RoutingNetwork::Udp,
        );
        assert!(outbound.udp_uses_mux(&quic));
        assert!(outbound
            .mux_pool(&Target::new(quic.addr.clone(), 443, RoutingNetwork::Tcp))
            .unwrap()
            .is_none());
    }

    #[test]
    fn vless_mux_over_xhttp_reports_a_cacheable_error() {
        let mut config = direct_selection_vless("proxy");
        config.mux = vless_mux(8, 0, xray_config::MuxUdp443::Reject);
        let error = mux::Runtime::new(&config.mux, &StreamTransport::Xhttp(Default::default()))
            .unwrap_err();
        assert!(matches!(error, CoreError::InvalidXhttpConfiguration(_)));
        let _ = CachedOutboundError::from_core_error(error);
    }
}

#[cfg(all(test, target_pointer_width = "64"))]
mod future_layout_tests {
    use super::*;
    #[test]
    fn common_tcp_open_future_stays_within_legacy_task_budget() {
        let target = Target::new(
            RoutingTargetAddr::Ip("127.0.0.1".parse().unwrap()),
            80,
            RoutingNetwork::Tcp,
        );
        let dialer = TransportDialer::system().unwrap();
        let outbound = TcpOutbound::Freedom(FreedomOutbound::default());
        let plain = open_plain_tcp_stream_with_resolvers_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &SystemDnsResolver,
            &dialer,
            true,
        );
        let routed = open_tcp_stream_with_resolvers_and_dialer(
            &outbound,
            &target,
            &SystemDnsResolver,
            &SystemDnsResolver,
            &dialer,
            None,
        );
        // Without isolating new protocol setup, even idle Freedom tasks keep
        // a 9.8 KiB future and exceed the 100/1000-flow RSS release budgets.
        assert!(std::mem::size_of_val(&plain) <= 4096);
        assert!(std::mem::size_of_val(&routed) <= 4352);
    }
}

#[cfg(test)]
mod parallel_relay_budget_tests {
    use super::*;

    #[tokio::test]
    async fn join_sessions_waits_for_admitted_relay_owners() {
        let config = Arc::new(
            xray_config::parse_xray_json(r#"{"outbounds":[{"protocol":"freedom"}]}"#)
                .unwrap()
                .config,
        );
        let router = OutboundRouter::new(config);
        let factory = router.factory_handle();
        let lease = factory.parallel_vmess_budget().try_acquire_owned().unwrap();
        factory.close_sessions();
        let drain = tokio::spawn(async move {
            factory.join_sessions().await;
        });
        tokio::task::yield_now().await;
        assert!(!drain.is_finished());
        drop(lease);
        tokio::time::timeout(Duration::from_secs(1), drain)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn admission_is_shared_across_routers_but_isolated_across_cores() {
        let config = Arc::new(
            xray_config::parse_xray_json(
                r#"{"outbounds":[{"protocol":"freedom","tag":"direct"}]}"#,
            )
            .unwrap()
            .config,
        );
        let first = OutboundRouter::new(config.clone());
        let second = OutboundRouter::from_factory(first.factory_handle());
        let other_core = OutboundRouter::new(config);
        let mut leases = (0..PARALLEL_VMESS_CONNECTIONS)
            .map(|_| {
                first
                    .factory()
                    .parallel_vmess_budget()
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(first
            .factory()
            .parallel_vmess_budget()
            .try_acquire_owned()
            .is_err());
        assert!(second
            .factory()
            .parallel_vmess_budget()
            .try_acquire_owned()
            .is_err());
        assert!(other_core
            .factory()
            .parallel_vmess_budget()
            .try_acquire_owned()
            .is_ok());
        drop(leases.pop());
        let replacement = second
            .factory()
            .parallel_vmess_budget()
            .try_acquire_owned()
            .unwrap();
        assert!(first
            .factory()
            .parallel_vmess_budget()
            .try_acquire_owned()
            .is_err());
        drop(replacement);
        drop(leases);
        assert_eq!(
            first.factory.parallel_vmess_relays.available_permits(),
            PARALLEL_VMESS_CONNECTIONS
        );
    }
}

#[cfg(test)]
mod socket_option_tests {
    use super::*;
    use serde_json::json;
    use tokio::net::TcpListener;

    const MISSING: &str = "xray-missing0";

    fn outbound(value: serde_json::Value) -> OutboundConfig {
        let parsed = xray_config::parse_xray_json(&json!({ "outbounds": [value] }).to_string())
            .unwrap_or_else(|error| panic!("{error:?}"));
        parsed.config.outbounds[0].clone()
    }

    fn missing_interface_error(error: impl std::fmt::Display) -> bool {
        error.to_string().contains("failed to bind to interface")
    }

    /// An outbound whose `sockopt` names an interface that does not exist
    /// fails before its first byte, whatever its protocol and transport, so
    /// every one of them dials with its own options.
    #[tokio::test]
    async fn every_outbound_tcp_dial_takes_its_socket_options() {
        // A server that accepts and holds: a dial that skipped its options
        // would get this far and then wait.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let sockopt = json!({ "interface": MISSING });
        let id = "27848739-7e62-4138-9fd3-098a63964b6b";
        let vless = |stream: serde_json::Value| {
            json!({
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": port,
                                        "users": [{"id": id, "encryption": "none"}]}]},
                "streamSettings": stream,
            })
        };
        let cases = [
            (
                "freedom",
                json!({"protocol": "freedom", "streamSettings": {"sockopt": sockopt}}),
            ),
            ("vless", vless(json!({"sockopt": sockopt}))),
            (
                "vless-tls",
                vless(
                    json!({"security": "tls", "tlsSettings": {"serverName": "localhost"}, "sockopt": sockopt}),
                ),
            ),
            (
                "vless-ws",
                vless(json!({"network": "ws", "sockopt": sockopt})),
            ),
            (
                "vless-httpupgrade",
                vless(json!({"network": "httpupgrade", "sockopt": sockopt})),
            ),
            (
                "vless-grpc",
                vless(
                    json!({"network": "grpc", "grpcSettings": {"serviceName": "x"}, "sockopt": sockopt}),
                ),
            ),
            (
                "vless-xhttp",
                vless(
                    json!({"network": "xhttp", "xhttpSettings": {"path": "/x"}, "sockopt": sockopt}),
                ),
            ),
            (
                "vless-xhttp-download",
                vless(json!({"network": "xhttp", "xhttpSettings": {
                "mode": "packet-up", "path": "/x",
                "downloadSettings": {"address": "127.0.0.1", "port": port, "network": "xhttp",
                                     "xhttpSettings": {"path": "/x"}, "sockopt": sockopt}}})),
            ),
            (
                "vless-xhttp-penetrate",
                vless(
                    json!({"network": "xhttp", "sockopt": {"penetrate": true, "interface": MISSING},
                "xhttpSettings": {"mode": "stream-up", "path": "/x",
                "downloadSettings": {"address": "127.0.0.1", "port": port, "network": "xhttp",
                                     "xhttpSettings": {"path": "/x"}}}}),
                ),
            ),
            (
                "trojan",
                json!({"protocol": "trojan", "settings": {"servers": [{"address": "127.0.0.1", "port": port, "password": "pw"}]},
                              "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "socks",
                json!({"protocol": "socks", "settings": {"address": "127.0.0.1", "port": port},
                             "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "http",
                json!({"protocol": "http", "settings": {"address": "127.0.0.1", "port": port},
                            "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "vmess",
                json!({"protocol": "vmess", "settings": {"vnext": [{"address": "127.0.0.1", "port": port,
                                                                          "users": [{"id": id}]}]},
                             "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "shadowsocks",
                json!({"protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": port,
                                   "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}]},
                                   "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "hysteria",
                json!({"protocol": "hysteria", "settings": {"version": 2, "address": "127.0.0.1", "port": port},
                                "streamSettings": {"network": "hysteria", "security": "tls",
                                                   "tlsSettings": {"serverName": "localhost", "alpn": ["h3"]},
                                                   "hysteriaSettings": {"version": 2, "auth": "a"},
                                                   "sockopt": sockopt}}),
            ),
            (
                "wireguard",
                json!({"protocol": "wireguard", "settings": {
                    "secretKey": "4242424242424242424242424242424242424242424242424242424242424242",
                    "address": ["10.44.0.2/32"],
                    "peers": [{"publicKey": "5353535353535353535353535353535353535353535353535353535353535353",
                               "endpoint": format!("127.0.0.1:{port}"), "allowedIPs": ["0.0.0.0/0"]}]},
                    "streamSettings": {"sockopt": sockopt}}),
            ),
        ];
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port,
            RoutingNetwork::Tcp,
        );
        for (name, value) in cases {
            let tcp = build_tcp_outbound(&outbound(value))
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let dialer = TransportDialer::system().unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                open_tcp_stream_with_resolver_and_dialer(
                    &tcp,
                    &target,
                    &SystemDnsResolver,
                    &dialer,
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("{name}: the dial went past its socket options"));
            let Err(error) = result else {
                panic!("{name}: dialed without its interface");
            };
            // Hysteria and WireGuard name the failure without its cause.
            assert!(
                missing_interface_error(&error)
                    || matches!(name, "hysteria" | "wireguard")
                        && error.to_string().contains("socket protection failed"),
                "{name}: {error}"
            );
        }
        held.abort();
    }

    /// Hysteria matches a cached session by its dialer's protector, so the
    /// dialer with its socket options stays the same while the one given
    /// does.
    #[test]
    fn hysteria_keeps_one_dialer_with_its_socket_options() {
        let value = json!({"protocol": "hysteria", "settings": {"version": 2, "address": "127.0.0.1", "port": 443},
                           "streamSettings": {"network": "hysteria", "security": "tls",
                                              "tlsSettings": {"serverName": "localhost", "alpn": ["h3"]},
                                              "hysteriaSettings": {"version": 2, "auth": "a"},
                                              "sockopt": {"mark": 4}}});
        let TcpOutbound::Hysteria(hysteria) = build_tcp_outbound(&outbound(value)).unwrap() else {
            panic!("hysteria");
        };
        let base = TransportDialer::system().unwrap();
        let first = hysteria.socket_dialer(&base);
        let second = hysteria.socket_dialer(&base);
        assert_eq!(first.socket_options().map(|options| options.mark), Some(4));
        assert!(first
            .tls_connector()
            .shares_session_context(second.tls_connector()));
        let other = TransportDialer::system().unwrap();
        let third = hysteria.socket_dialer(&other);
        assert!(!first
            .tls_connector()
            .shares_session_context(third.tls_connector()));
    }

    /// Records the type of each socket the platform protector is handed.
    #[derive(Default)]
    struct SocketTypes(std::sync::Mutex<Vec<socket2::Type>>);

    impl xray_transport::SocketProtector for SocketTypes {
        fn protect(&self, socket: xray_transport::SocketHandle) -> io::Result<()> {
            use std::os::fd::BorrowedFd;
            // SAFETY: the socket stays open for this call.
            let fd = unsafe { BorrowedFd::borrow_raw(socket.raw() as std::os::fd::RawFd) };
            let kind = socket2::SockRef::from(&fd).r#type()?;
            self.0.lock().unwrap().push(kind);
            Ok(())
        }
    }

    /// The UDP sockets SOCKS and Shadowsocks open for datagrams take the
    /// outbound's options too. Each is bound before any control connection
    /// opens, so with its options in force no TCP socket is ever handed out.
    #[tokio::test]
    async fn outbound_udp_sockets_take_their_socket_options() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let sockopt = json!({ "interface": MISSING });
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53_053,
            RoutingNetwork::Udp,
        );
        for (name, value) in [
            (
                "socks",
                json!({"protocol": "socks", "settings": {"address": "127.0.0.1", "port": port},
                             "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "shadowsocks",
                json!({"protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": port,
                                   "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}]},
                                   "streamSettings": {"sockopt": sockopt}}),
            ),
        ] {
            let udp = build_udp_outbound(&outbound(value))
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let types = Arc::new(SocketTypes::default());
            let dialer = TransportDialer::system()
                .unwrap()
                .with_socket_protector(types.clone());
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                datagram::open(
                    &udp,
                    &target,
                    &SystemDnsResolver,
                    &SystemDnsResolver,
                    &dialer,
                    [0; 8],
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("{name}: the open went past its socket options"));
            let Err(error) = result else {
                panic!("{name}: opened without its interface");
            };
            assert!(missing_interface_error(&error), "{name}: {error}");
            assert_eq!(*types.0.lock().unwrap(), [socket2::Type::DGRAM], "{name}");
        }
        held.abort();
    }

    #[test]
    fn freedom_udp_takes_its_socket_options() {
        let value = json!({"protocol": "freedom", "streamSettings": {"sockopt": {"mark": 9}}});
        let UdpOutbound::Freedom(freedom) = build_udp_outbound(&outbound(value)).unwrap() else {
            panic!("freedom");
        };
        let base = TransportDialer::system().unwrap();
        let dialer = freedom.dialer(&base);
        assert_eq!(dialer.socket_options().map(|options| options.mark), Some(9));
        let plain = json!({"protocol": "freedom"});
        let UdpOutbound::Freedom(freedom) = build_udp_outbound(&outbound(plain)).unwrap() else {
            panic!("freedom");
        };
        assert!(matches!(
            freedom.dialer(&base),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    /// The download leg dials with its own options and without the
    /// outbound's chain, unless `penetrate` hands it the outbound's dialer.
    #[test]
    fn the_download_leg_picks_its_dialer_as_xray_core_does() {
        struct NoTcp;
        #[async_trait]
        impl ResolvedTcpConnector for NoTcp {
            async fn connect_resolved(
                &self,
                _: &Target,
                _: &[SocketAddr],
                _: Option<&HappyEyeballsConfig>,
            ) -> Result<BoxedTransportStream, TransportError> {
                Err(TransportError::UnsupportedConnectorConfig("test"))
            }
        }
        let chained = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(Arc::new(NoTcp));
        let upload = chained
            .clone()
            .with_socket_options(Arc::new(xray_transport::SocketOptions {
                mark: 1,
                ..Default::default()
            }));
        let compiled = |upload_sockopt: serde_json::Value, download_sockopt: serde_json::Value| {
            let value = json!({
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": 443,
                    "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]},
                "streamSettings": {"network": "xhttp", "sockopt": upload_sockopt, "xhttpSettings": {
                    "mode": "packet-up", "path": "/x",
                    "downloadSettings": {"address": "127.0.0.1", "port": 443, "network": "xhttp",
                                         "xhttpSettings": {"path": "/x"}, "sockopt": download_sockopt}}},
            });
            let TcpOutbound::Vless(vless) = build_tcp_outbound(&outbound(value)).unwrap() else {
                panic!("vless");
            };
            vless
        };
        let own = compiled(json!({"mark": 1}), json!({}));
        let download = own.payload.carrier.download.as_ref().unwrap();
        let dialer = download.dialer(&chained, &upload);
        assert!(!dialer.carries_tcp_through_outbound());
        assert!(dialer.socket_options().is_none());

        let own = compiled(json!({"mark": 1}), json!({"mark": 2}));
        let download = own.payload.carrier.download.as_ref().unwrap();
        let dialer = download.dialer(&chained, &upload);
        assert!(!dialer.carries_tcp_through_outbound());
        assert_eq!(dialer.socket_options().map(|options| options.mark), Some(2));

        let penetrate = compiled(json!({"mark": 1, "penetrate": true}), json!({"mark": 2}));
        let download = penetrate.payload.carrier.download.as_ref().unwrap();
        let dialer = download.dialer(&chained, &upload);
        assert!(dialer.carries_tcp_through_outbound());
        assert_eq!(dialer.socket_options().map(|options| options.mark), Some(1));
    }
}

#[cfg(test)]
mod address_port_tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::{TcpListener, UdpSocket};
    use xray_transport::{RecordResolver, SrvRecord};

    fn outbound(value: serde_json::Value) -> OutboundConfig {
        let parsed = xray_config::parse_xray_json(&json!({ "outbounds": [value] }).to_string())
            .unwrap_or_else(|error| panic!("{error:?}"));
        parsed.config.outbounds[0].clone()
    }

    /// Every name has the one TXT record given and no SRV record.
    struct Txt(String);

    #[async_trait]
    impl RecordResolver for Txt {
        async fn lookup_srv(&self, _: &str, _: &str, _: &str) -> io::Result<Vec<SrvRecord>> {
            Err(io::ErrorKind::NotFound.into())
        }
        async fn lookup_txt(&self, _: &str) -> io::Result<Vec<String>> {
            Ok(vec![self.0.clone()])
        }
    }

    /// Resolves no name, so a dial reaches only an address a record names.
    struct NoNames;

    #[async_trait]
    impl DnsResolver for NoNames {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            Err(TransportError::DnsNoData(domain.to_owned(), port))
        }
    }

    const SERVER: &str = "txt.example";
    const ID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";

    fn dialer(record: String) -> TransportDialer {
        TransportDialer::system()
            .unwrap()
            .with_record_resolver(Arc::new(Txt(record)))
    }

    /// Each proxy outbound over each transport dials the address and port a
    /// TXT record of its server's name gives, as Xray-core's `DialSystem`
    /// does for every dial.
    #[tokio::test]
    async fn every_proxy_outbound_dials_what_its_lookup_gives() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        let held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });
        let dialer = dialer(format!("127.0.0.1:{port}"));
        let sockopt = json!({"addressPortStrategy": "TxtPortAndAddress"});
        let vless = |stream: serde_json::Value| {
            json!({"protocol": "vless", "settings": {"vnext": [{"address": SERVER, "port": 1,
                    "users": [{"id": ID, "encryption": "none"}]}]}, "streamSettings": stream})
        };
        let cases = [
            ("vless", vless(json!({"sockopt": sockopt}))),
            (
                "vless-ws",
                vless(json!({"network": "ws", "sockopt": sockopt})),
            ),
            (
                "vless-grpc",
                vless(
                    json!({"network": "grpc", "grpcSettings": {"serviceName": "x"}, "sockopt": sockopt}),
                ),
            ),
            (
                "vless-xhttp",
                vless(
                    json!({"network": "xhttp", "xhttpSettings": {"path": "/x"}, "sockopt": sockopt}),
                ),
            ),
            (
                "trojan",
                json!({"protocol": "trojan", "settings": {"servers": [{"address": SERVER, "port": 1, "password": "pw"}]},
                       "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "socks",
                json!({"protocol": "socks", "settings": {"address": SERVER, "port": 1},
                       "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "http",
                json!({"protocol": "http", "settings": {"address": SERVER, "port": 1},
                       "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "vmess",
                json!({"protocol": "vmess", "settings": {"vnext": [{"address": SERVER, "port": 1, "users": [{"id": ID}]}]},
                       "streamSettings": {"sockopt": sockopt}}),
            ),
            (
                "shadowsocks",
                json!({"protocol": "shadowsocks", "settings": {"servers": [{"address": SERVER, "port": 1,
                       "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}]},
                       "streamSettings": {"sockopt": sockopt}}),
            ),
        ];
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            9,
            RoutingNetwork::Tcp,
        );
        for (name, value) in cases {
            let tcp = build_tcp_outbound(&outbound(value))
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let before = accepted.load(Ordering::SeqCst);
            // What the protocol does after the dial is not this test's.
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                open_tcp_stream_with_resolver_and_dialer(&tcp, &target, &NoNames, &dialer),
            )
            .await;
            tokio::time::timeout(Duration::from_secs(2), async {
                while accepted.load(Ordering::SeqCst) == before {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{name}: the dial missed the record's address"));
        }
        held.abort();
    }

    /// Hysteria's QUIC socket and Shadowsocks' UDP datagrams go where the
    /// lookup says too.
    #[tokio::test]
    async fn udp_carriers_send_to_what_their_lookup_gives() {
        let sockopt = json!({"addressPortStrategy": "TxtPortAndAddress"});
        let hysteria = json!({"protocol": "hysteria", "settings": {"version": 2, "address": SERVER, "port": 1},
            "streamSettings": {"network": "hysteria", "security": "tls",
                               "tlsSettings": {"serverName": "localhost", "alpn": ["h3"]},
                               "hysteriaSettings": {"version": 2, "auth": "a"}, "sockopt": sockopt}});
        let shadowsocks = json!({"protocol": "shadowsocks", "settings": {"servers": [{"address": SERVER, "port": 1,
            "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="}]},
            "streamSettings": {"sockopt": sockopt}});
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            9,
            RoutingNetwork::Udp,
        );
        for (name, value) in [("hysteria", hysteria), ("shadowsocks", shadowsocks)] {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let dialer = dialer(format!("127.0.0.1:{}", socket.local_addr().unwrap().port()));
            let udp = build_udp_outbound(&outbound(value))
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let send = async {
                if let Ok(session) =
                    datagram::open(&udp, &target, &NoNames, &NoNames, &dialer, [0; 8]).await
                {
                    let _ = session.send(&target, b"payload").await;
                }
                std::future::pending::<()>().await;
            };
            let mut buffer = [0; 2048];
            tokio::select! {
                () = send => unreachable!(),
                received = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer)) => {
                    received
                        .unwrap_or_else(|_| panic!("{name}: nothing reached the record's address"))
                        .unwrap();
                }
            }
        }
    }

    /// The XHTTP download leg looks up with the `sockopt` it dials with: the
    /// outbound's under `penetrate`, else its own.
    #[tokio::test]
    async fn the_download_leg_looks_up_with_its_own_sockopt() {
        struct Named;
        #[async_trait]
        impl DnsResolver for Named {
            async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
                match domain {
                    "down.example" => Ok(SocketAddr::from(([127, 0, 0, 7], port))),
                    _ => Err(TransportError::DnsNoData(domain.to_owned(), port)),
                }
            }
        }
        let txt = json!({"addressPortStrategy": "TxtPortAndAddress"});
        let vless = |upload: serde_json::Value, download: serde_json::Value| {
            json!({"protocol": "vless", "settings": {"vnext": [{"address": SERVER, "port": 1,
                "users": [{"id": ID, "encryption": "none"}]}]},
                "streamSettings": {"network": "xhttp", "sockopt": upload, "xhttpSettings": {
                    "mode": "packet-up", "path": "/x",
                    "downloadSettings": {"address": "down.example", "port": 2, "network": "xhttp",
                                         "xhttpSettings": {"path": "/x"}, "sockopt": download}}}})
        };
        let looked_up = vec![SocketAddr::from(([127, 0, 0, 9], 9))];
        let configured = vec![SocketAddr::from(([127, 0, 0, 7], 2))];
        let dialer = dialer("127.0.0.9:9".into());
        for (upload, download, expected) in [
            (txt.clone(), json!({}), &configured),
            (json!({}), txt.clone(), &looked_up),
            (
                json!({"penetrate": true, "addressPortStrategy": "TxtPortAndAddress"}),
                json!({}),
                &looked_up,
            ),
            (json!({"penetrate": true}), txt.clone(), &configured),
        ] {
            let TcpOutbound::Vless(outbound) =
                build_tcp_outbound(&outbound(vless(upload.clone(), download.clone()))).unwrap()
            else {
                panic!("vless");
            };
            assert_eq!(
                outbound
                    .carrier()
                    .resolve_download(&Named, &dialer)
                    .await
                    .unwrap(),
                *expected,
                "{upload} {download}"
            );
        }
    }

    /// The outbound a chain dials through looks its own server up.
    #[tokio::test]
    async fn a_dialer_proxy_outbound_dials_what_its_lookup_gives() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = xray_config::parse_xray_json(
            &json!({"outbounds": [
                {"tag": "front", "protocol": "socks", "settings": {"address": "127.0.0.1", "port": 1080},
                 "streamSettings": {"sockopt": {"dialerProxy": "back"}}},
                {"tag": "back", "protocol": "vless", "settings": {"vnext": [{"address": SERVER, "port": 1,
                    "users": [{"id": ID, "encryption": "none"}]}]},
                 "streamSettings": {"sockopt": {"addressPortStrategy": "TxtPortAndAddress"}}}
            ]})
            .to_string(),
        )
        .unwrap()
        .config;
        let router = OutboundRouter::new(Arc::new(config));
        let front = router.select_tcp_outbound_direct(Some("front")).unwrap();
        let dialer = dialer(format!("127.0.0.1:{port}"));
        let target = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            9,
            RoutingNetwork::Tcp,
        );
        let opened = tokio::spawn(async move {
            let _ =
                open_tcp_stream_with_resolver_and_dialer(&front, &target, &NoNames, &dialer).await;
        });
        tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("the proxy missed the record's address")
            .unwrap();
        opened.abort();
    }

    /// A chain hands its proxy the configured server, which Xray-core
    /// replaces with what it looks up, so the two are not combined.
    #[test]
    fn a_chained_outbound_takes_no_address_port_strategy() {
        let mut config = xray_config::parse_xray_json(
            &json!({"outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": SERVER, "port": 1,
                    "users": [{"id": ID, "encryption": "none"}]}]},
                 "streamSettings": {"sockopt": {"dialerProxy": "next"}}},
                {"tag": "next", "protocol": "socks", "settings": {"address": "127.0.0.1", "port": 1080}}
            ]})
            .to_string(),
        )
        .unwrap()
        .config;
        config.outbounds[0]
            .stream
            .socket_options
            .as_mut()
            .unwrap()
            .address_port_strategy = xray_config::AddressPortStrategy::TxtPortOnly;
        let router = OutboundRouter::new(Arc::new(config));
        assert!(matches!(
            router.select_tcp_outbound_direct(Some("proxy")),
            Err(CoreError::UnsupportedOutboundProxyNetwork(
                "addressPortStrategy"
            ))
        ));
    }
}

#[cfg(test)]
mod testpre_tests {
    use super::*;
    use serde_json::json;
    use tokio::{io::AsyncReadExt, net::TcpListener, sync::mpsc};

    const ID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";

    fn vless(port: u16, testpre: u32) -> VlessTcpOutbound {
        let config = xray_config::parse_xray_json(
            &json!({"outbounds": [{"protocol": "vless", "settings": {"address": "127.0.0.1",
                "port": port, "id": ID, "encryption": "none", "testpre": testpre}}]})
            .to_string(),
        )
        .unwrap_or_else(|error| panic!("{error:?}"))
        .config;
        let TcpOutbound::Vless(outbound) = build_tcp_outbound(&config.outbounds[0]).unwrap() else {
            panic!("vless");
        };
        *outbound
    }

    /// A listener that hands over every connection it accepts.
    async fn server() -> (u16, mpsc::UnboundedReceiver<tokio::net::TcpStream>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted, connections) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                if accepted.send(stream).is_err() {
                    return;
                }
            }
        });
        (port, connections)
    }

    fn drain(
        connections: &mut mpsc::UnboundedReceiver<tokio::net::TcpStream>,
    ) -> Vec<tokio::net::TcpStream> {
        std::iter::from_fn(|| connections.try_recv().ok()).collect()
    }

    fn target() -> Target {
        Target::new(
            RoutingTargetAddr::Domain("example.com".into()),
            443,
            RoutingNetwork::Tcp,
        )
    }

    /// Nothing opens before the first request. Then each of the `testpre`
    /// dialers opens a connection, the request takes one, and its dialer
    /// opens another 200 ms later; the next request takes a held one.
    #[tokio::test]
    async fn vless_opens_testpre_connections_ahead_of_requests() {
        let (port, mut connections) = server().await;
        let outbound = vless(port, 2);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(drain(&mut connections).is_empty());

        let dialer = TransportDialer::system().unwrap();
        let mut stream = open_vless_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target(),
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .unwrap();
        stream.write_all(b"payload").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut first = drain(&mut connections);
        assert_eq!(first.len(), 2);
        // One of them carries the request: VLESS version 0, then the ID.
        let mut carried = 0;
        for connection in &mut first {
            let mut header = [0; 17];
            if tokio::time::timeout(
                Duration::from_millis(200),
                connection.read_exact(&mut header),
            )
            .await
            .is_ok()
            {
                assert_eq!(header[0], 0);
                assert_eq!(&header[1..], uuid::Uuid::parse_str(ID).unwrap().as_bytes());
                carried += 1;
            }
        }
        assert_eq!(carried, 1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(drain(&mut connections).len(), 1);

        // A held connection serves the next request without a new dial.
        let _second = open_vless_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target(),
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .unwrap();
        assert!(drain(&mut connections).is_empty());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(drain(&mut connections).len(), 1);
        outbound.close();
        outbound.join().await;
    }

    /// UDP requests, which open a command stream, take them too, and
    /// closing the outbound closes the held ones.
    #[tokio::test]
    async fn vless_udp_takes_testpre_connections_and_close_closes_them() {
        let (port, mut connections) = server().await;
        let outbound = vless(port, 1);
        let dialer = TransportDialer::system().unwrap();
        let udp = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
            53,
            RoutingNetwork::Udp,
        );
        let _udp = open_vless_udp_stream_with_resolver_and_dialer(
            &outbound,
            &udp,
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut accepted = drain(&mut connections);
        // The one that carried the request, and its refill.
        assert_eq!(accepted.len(), 2);
        outbound.close();
        outbound.join().await;
        let mut byte = [0; 1];
        let held = accepted.pop().unwrap();
        let mut held = held;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), held.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let error = open_vless_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target(),
            &SystemDnsResolver,
            &dialer,
        )
        .await
        .err()
        .expect("a closed outbound has no testpre connections");
        assert!(error.to_string().contains("closed"), "{error}");
    }
}

#[cfg(test)]
mod kcp_tests {
    use super::*;
    use serde_json::{json, Value};

    const ID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";

    fn vless(stream: Value) -> OutboundConfig {
        xray_config::parse_xray_json(
            &json!({"outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{
                "address": "10.0.0.1", "port": 443, "users": [{"id": ID, "encryption": "none",
                "flow": stream.get("flow").cloned().unwrap_or(Value::Null)}]}]},
                "streamSettings": stream.get("stream").cloned().unwrap_or(stream)}]})
            .to_string(),
        )
        .unwrap()
        .config
        .outbounds
        .remove(0)
    }

    #[test]
    fn the_carrier_takes_mkcps_settings_masks_and_noise() {
        let outbound = vless(json!({"network": "kcp",
        "kcpSettings": {"mtu": 1200, "tti": 20, "uplinkCapacity": 9, "downlinkCapacity": 30,
            "cwndMultiplier": 2, "maxSendingWindow": 65536},
        "finalmask": {"udp": [
            {"type": "mkcp-legacy", "settings": {"value": "seed"}},
            {"type": "noise", "settings": {"noise": [{"type": "str", "packet": "hi"}]}},
            {"type": "mkcp-legacy", "settings": {"header": "dns", "value": "kcp.example"}},
        ]}}));
        let built = build_vless_tcp_outbound(&outbound).unwrap();
        let TransportLayer::Kcp(kcp) = built.transport_layer() else {
            panic!("not mKCP");
        };
        assert_eq!(
            (
                kcp.mtu,
                kcp.tti,
                kcp.uplink_capacity,
                kcp.downlink_capacity,
                kcp.cwnd_multiplier,
                kcp.max_sending_window
            ),
            (1200, 20, 9, 30, 2, 65536)
        );
        use xray_transport::kcp::{KcpHeader, KcpMask};
        assert_eq!(
            kcp.masks,
            [
                KcpMask::Aes128Gcm("seed".to_owned().into()),
                KcpMask::Noise,
                KcpMask::Header(KcpHeader::Dns("kcp.example".to_owned())),
            ]
        );
        assert_eq!(kcp.noise.as_ref().unwrap().items[0].packet, b"hi");
        assert!(matches!(built.transport(), ConnectorConfig::Tcp));
    }

    #[test]
    fn vision_rides_mkcps_tls_and_not_plain_mkcp() {
        let tls = vless(
            json!({"flow": "xtls-rprx-vision", "stream": {"network": "kcp",
            "security": "tls", "tlsSettings": {"serverName": "kcp.example"}}}),
        );
        let built = build_vless_tcp_outbound(&tls).unwrap();
        assert!(validate_connector_flow(
            built.user().flow.as_deref(),
            built.transport(),
            built.transport_layer(),
        )
        .unwrap()
        .uses_vision());
        // Without TLS the build refuses it, as it refuses raw without TLS.
        let plain = vless(json!({"flow": "xtls-rprx-vision", "stream": {"network": "kcp"}}));
        assert!(matches!(
            build_vless_tcp_outbound(&plain),
            Err(CoreError::UnsupportedOutboundFlow)
        ));
    }

    /// Xray-core ignores TCP masks on mKCP's UDP dial; here they are refused,
    /// as on XHTTP's HTTP/3.
    #[test]
    fn tcp_masks_are_refused_on_mkcp() {
        let outbound = vless(json!({"network": "kcp", "security": "tls",
            "tlsSettings": {"serverName": "kcp.example"},
            "finalmask": {"tcp": [{"type": "fragment", "settings": {"packets": "tlshello",
                "length": "100-200", "delay": "10-20"}}]}}));
        assert!(matches!(
            build_vless_tcp_outbound(&outbound),
            Err(CoreError::UnsupportedOutboundNetwork)
        ));
    }

    /// A chain would have to carry mKCP's datagrams.
    #[test]
    fn a_chained_outbound_takes_no_mkcp() {
        let config = xray_config::parse_xray_json(
            &json!({"outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "10.0.0.1",
                    "port": 443, "users": [{"id": ID, "encryption": "none"}]}]},
                 "streamSettings": {"network": "kcp", "sockopt": {"dialerProxy": "next"}}},
                {"tag": "next", "protocol": "socks", "settings": {"address": "127.0.0.1", "port": 1080}}
            ]})
            .to_string(),
        )
        .unwrap()
        .config;
        let router = OutboundRouter::new(Arc::new(config));
        assert!(matches!(
            router.select_tcp_outbound_direct(Some("proxy")),
            Err(CoreError::UnsupportedOutboundProxyNetwork("mKCP"))
        ));
    }
}
