use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use uuid::Uuid;
use xray_routing::{
    domain_matcher::domain_matches_suffix, Cidr, DomainMatcherSetBuilder, DomainMatcherSetError,
    DomainRegexError,
};
pub use xray_routing::{
    DnsHostTarget, DnsIpFilter, DomainHostIndex, DomainMatcher, DomainMatcherSet, DomainNameMode,
    IpMatcherSet, RegexMatcher,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigModelError {
    #[error("reality short id cannot exceed 8 bytes")]
    RealityShortIdTooLong,
    #[error("CIDR prefix length {prefix} exceeds max {max}")]
    InvalidCidrPrefix { prefix: u8, max: u8 },
    #[error("invalid domain regex `{pattern}`: {message}")]
    InvalidDomainRegex { pattern: String, message: String },
    #[error("invalid domain matcher set: {message}")]
    InvalidDomainMatcherSet { message: String },
    #[error("DNS qtype range start {start} exceeds end {end}")]
    InvalidDnsQTypeRange { start: u16, end: u16 },
    #[error("routing port range start {start} exceeds end {end}")]
    InvalidRoutingPortRange { start: u16, end: u16 },
}

impl From<DomainRegexError> for ConfigModelError {
    fn from(error: DomainRegexError) -> Self {
        Self::InvalidDomainRegex {
            pattern: error.pattern,
            message: error.message,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub default_outbound_tag: Option<String>,
    pub routing: RoutingConfig,
    pub observatory: Option<ObservatoryConfig>,
    pub dns: DnsConfig,
    pub policy: PolicyConfig,
}

pub const DEFAULT_OBSERVATORY_PROBE_URL: &str = "https://www.google.com/generate_204";
pub const DEFAULT_OBSERVATORY_PROBE_INTERVAL: Duration = Duration::from_secs(10);
pub const OBSERVATORY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Xray-compatible periodic URL probe configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryConfig {
    pub subject_selectors: Vec<String>,
    pub probe_url: String,
    pub probe_interval: Duration,
    pub enable_concurrency: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingConfig {
    pub rules: Vec<RoutingRule>,
    pub balancers: Vec<RoutingBalancer>,
    pub domain_strategy: RoutingDomainStrategy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RoutingDomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
}

/// Xray-compatible outbound selector group from `routing.balancers`.
///
/// Each selector is a tag prefix. The runtime expands the prefixes against
/// configured tagged outbounds once when it builds the immutable graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingBalancer {
    pub tag: String,
    pub selectors: Vec<String>,
    pub strategy: RoutingBalancerStrategy,
    pub fallback_tag: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RoutingBalancerStrategy {
    #[default]
    Random,
    RoundRobin,
    LeastPing,
    LeastLoad(RoutingLeastLoadSettings),
}

/// Bounded subset of Xray's `leastLoad` strategy settings.
///
/// Floating-point JSON values are normalized to millionths so the parsed
/// model remains deterministic and equality-safe across the FFI build matrix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingLeastLoadSettings {
    /// Number of best candidates to distribute new flows across. Zero uses
    /// Xray's effective default of one.
    pub expected: u8,
    pub max_rtt: Option<Duration>,
    pub tolerance_millionths: u32,
    pub baselines: Vec<Duration>,
    pub costs: Vec<RoutingLeastLoadCost>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingLeastLoadCost {
    /// Literal substring matched against an outbound tag.
    pub tag_substring: String,
    /// Positive cost multiplier normalized to millionths.
    pub value_millionths: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfig {
    pub fake_ip: Option<DnsFakeIpConfig>,
    pub servers: Vec<DnsServerConfig>,
    /// `dns.hosts` entries, keyed by DNS-normalized `full:` names with the
    /// remaining matchers scanned in config order.
    pub hosts: DomainHostIndex<DnsHostTarget>,
    /// Default synthetic inbound tag used by configured DNS clients.
    ///
    /// An empty value asks the runtime to supply Xray's generated internal
    /// tag. UUID generation intentionally stays outside the config model.
    pub tag: String,
    pub query_strategy: DnsQueryStrategy,
    pub disable_fallback: bool,
    pub disable_fallback_if_match: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DnsQueryStrategy {
    #[default]
    UseIp,
    UseIpv4,
    UseIpv6,
}

/// Transport used by one configured DNS server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DnsServerTransport {
    /// Classic DNS over UDP with the existing TCP retry on truncation.
    #[default]
    Classic,
    /// DNS over TCP dispatched through Xray routing.
    TcpRouted,
    /// DNS over TCP dialed directly through the local network stack.
    TcpLocal,
}

pub const DEFAULT_DNS_SERVER_TIMEOUT_MS: u64 = 4_000;
/// Largest millisecond value safe across Xray-core's duration conversions.
///
/// Xray accepts larger `uint64` values, but its cached parallel-query context
/// doubles the signed nanosecond duration. Rejecting values above this boundary
/// avoids an overflow into an unintended deadline.
pub const MAX_DNS_SERVER_TIMEOUT_MS: u64 = i64::MAX as u64 / 2 / 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServerConfig {
    Ip(SocketAddr),
    Domain { domain: String, port: u16 },
    Policy(Box<DnsNameServerConfig>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNameServerConfig {
    pub endpoint: DnsServerEndpoint,
    pub transport: DnsServerTransport,
    /// Compiled with [`compile_dns_domain_matchers`] semantics.
    pub domains: DomainMatcherSet,
    pub expected_ips: DnsIpFilter,
    pub unexpected_ips: DnsIpFilter,
    /// Per-client synthetic inbound tag; empty inherits `dns.tag`.
    pub tag: String,
    /// Raw Xray `timeoutMs`; zero selects [`DEFAULT_DNS_SERVER_TIMEOUT_MS`].
    pub timeout_ms: u64,
    pub skip_fallback: bool,
    pub query_strategy: DnsQueryStrategy,
    pub final_query: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServerEndpoint {
    Ip(SocketAddr),
    Domain { domain: String, port: u16 },
}

impl DnsServerConfig {
    pub fn endpoint(&self) -> DnsServerEndpoint {
        match self {
            Self::Ip(addr) => DnsServerEndpoint::Ip(*addr),
            Self::Domain { domain, port } => DnsServerEndpoint::Domain {
                domain: domain.clone(),
                port: *port,
            },
            Self::Policy(server) => server.endpoint.clone(),
        }
    }

    /// Returns the effective transport, including classic shorthand servers.
    pub fn transport(&self) -> DnsServerTransport {
        match self {
            Self::Policy(server) => server.transport,
            Self::Ip(_) | Self::Domain { .. } => DnsServerTransport::Classic,
        }
    }

    pub fn skip_fallback(&self) -> bool {
        matches!(self, Self::Policy(server) if server.skip_fallback)
    }

    pub fn query_strategy(&self) -> DnsQueryStrategy {
        match self {
            Self::Policy(server) => server.query_strategy,
            Self::Ip(_) | Self::Domain { .. } => DnsQueryStrategy::UseIp,
        }
    }

    pub fn final_query(&self) -> bool {
        matches!(self, Self::Policy(server) if server.final_query)
    }

    pub fn timeout_ms(&self) -> u64 {
        match self {
            Self::Policy(server) if server.timeout_ms != 0 => server.timeout_ms,
            Self::Policy(_) | Self::Ip(_) | Self::Domain { .. } => DEFAULT_DNS_SERVER_TIMEOUT_MS,
        }
    }

    /// Returns this client's configured tag after applying Xray inheritance.
    ///
    /// String shorthand servers and object servers with an omitted, `null`,
    /// or empty tag inherit the effective global DNS tag supplied by the
    /// caller. Runtime generation of an internal tag remains a core concern.
    pub fn effective_tag<'a>(&'a self, global_tag: &'a str) -> &'a str {
        match self {
            Self::Policy(server) if !server.tag.is_empty() => &server.tag,
            Self::Policy(_) | Self::Ip(_) | Self::Domain { .. } => global_tag,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFakeIpConfig {
    pub enabled: bool,
    pub ipv4_pool: IpCidr,
    pub pool_size: u32,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    pub inbound_tags: Vec<String>,
    pub networks: Vec<Network>,
    pub port_ranges: Vec<RoutingPortRange>,
    pub domain_matchers: DomainMatcherSet,
    pub ip_matchers: IpMatcherSet,
    pub target: RoutingRuleTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingRuleTarget {
    Outbound(String),
    Balancer(String),
}

impl RoutingRuleTarget {
    pub fn tag(&self) -> &str {
        match self {
            Self::Outbound(tag) | Self::Balancer(tag) => tag,
        }
    }
}

impl RoutingRule {
    pub fn matches(
        &self,
        inbound_tag: Option<&str>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
    ) -> bool {
        self.matches_target(inbound_tag, target_domain, target_ip, None, None)
    }

    pub fn matches_target(
        &self,
        inbound_tag: Option<&str>,
        target_domain: Option<&str>,
        target_ip: Option<&IpAddr>,
        target_network: Option<Network>,
        target_port: Option<u16>,
    ) -> bool {
        self.matches_inbound(inbound_tag)
            && self.matches_network(target_network)
            && self.matches_port(target_port)
            && self.matches_domain(target_domain)
            && self.matches_ip(target_ip)
    }

    pub fn matches_inbound(&self, inbound_tag: Option<&str>) -> bool {
        if self.inbound_tags.is_empty() {
            return true;
        }

        let Some(inbound_tag) = inbound_tag else {
            return false;
        };

        self.inbound_tags
            .iter()
            .any(|candidate| candidate == inbound_tag)
    }

    pub fn matches_network(&self, target_network: Option<Network>) -> bool {
        if self.networks.is_empty() {
            return true;
        }

        target_network.is_some_and(|target| self.networks.contains(&target))
    }

    pub fn matches_port(&self, target_port: Option<u16>) -> bool {
        if self.port_ranges.is_empty() {
            return true;
        }

        target_port
            .is_some_and(|target| self.port_ranges.iter().any(|range| range.contains(target)))
    }

    pub fn matches_domain(&self, target_domain: Option<&str>) -> bool {
        if self.domain_matchers.is_empty() {
            return true;
        }

        let Some(target_domain) = target_domain else {
            return false;
        };

        self.domain_matchers.matches(target_domain)
    }

    pub fn matches_ip(&self, target_ip: Option<&IpAddr>) -> bool {
        if self.ip_matchers.is_empty() {
            return true;
        }

        let Some(target_ip) = target_ip else {
            return false;
        };

        self.ip_matchers.matches(*target_ip)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingPortRange {
    start: u16,
    end: u16,
}

impl RoutingPortRange {
    pub fn new(start: u16, end: u16) -> Result<Self, ConfigModelError> {
        if start > end {
            return Err(ConfigModelError::InvalidRoutingPortRange { start, end });
        }
        Ok(Self { start, end })
    }

    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub const fn start(self) -> u16 {
        self.start
    }

    pub const fn end(self) -> u16 {
        self.end
    }

    pub fn contains(self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

/// Compiles routing matchers ([`DomainNameMode::Routing`]).
pub fn compile_domain_matchers(
    matchers: &[DomainMatcher],
) -> Result<DomainMatcherSet, ConfigModelError> {
    DomainMatcherSet::compile(matchers, DomainNameMode::Routing).map_err(domain_matcher_set_error)
}

/// Compiles DNS matchers ([`DomainNameMode::Dns`]).
pub fn compile_dns_domain_matchers(
    matchers: &[DomainMatcher],
) -> Result<DomainMatcherSet, ConfigModelError> {
    DomainMatcherSet::compile(matchers, DomainNameMode::Dns).map_err(domain_matcher_set_error)
}

pub(crate) fn build_domain_matcher_set(
    builder: DomainMatcherSetBuilder,
) -> Result<DomainMatcherSet, ConfigModelError> {
    builder.build().map_err(domain_matcher_set_error)
}

fn domain_matcher_set_error(error: DomainMatcherSetError) -> ConfigModelError {
    ConfigModelError::InvalidDomainMatcherSet {
        message: error.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr(Cidr);

impl IpCidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, ConfigModelError> {
        Cidr::new(network, prefix)
            .map(Self)
            .map_err(|error| ConfigModelError::InvalidCidrPrefix {
                prefix,
                max: error.max_prefix,
            })
    }

    pub const fn full(ip: IpAddr) -> Self {
        Self(Cidr::host(ip))
    }

    pub const fn cidr(self) -> Cidr {
        self.0
    }

    pub fn network(&self) -> IpAddr {
        self.0.network()
    }

    pub fn prefix(&self) -> u8 {
        self.0.prefix_len()
    }

    pub fn matches(&self, ip: &IpAddr) -> bool {
        self.0.contains(*ip)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConfig {
    pub tag: Option<String>,
    pub protocol: InboundProtocol,
    pub listen: String,
    pub port: u16,
    /// Explicit consent to expose an unauthenticated SOCKS/HTTP listener
    /// beyond loopback. Runtime code enforces this even for programmatically
    /// constructed configurations.
    pub allow_unauthenticated_lan: bool,
    pub sniffing: Option<InboundSniffingConfig>,
    pub user_level: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSniffingConfig {
    pub enabled: bool,
    pub dest_override: Vec<SniffingDestination>,
    pub metadata_only: bool,
    pub route_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffingDestination {
    Http,
    Tls,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundProtocol {
    Socks,
    Http,
    Tun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundConfig {
    pub tag: Option<String>,
    pub proxy_settings: Option<OutboundProxySettings>,
    pub stream: StreamSettings,
    pub settings: OutboundSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundProxySettings {
    pub tag: String,
    pub transport_layer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundProtocol {
    Freedom,
    Dns,
    Vless,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundSettings {
    Freedom,
    Dns(DnsOutboundSettings),
    Vless(VlessOutboundSettings),
}

impl OutboundSettings {
    pub fn protocol(&self) -> OutboundProtocol {
        match self {
            Self::Freedom => OutboundProtocol::Freedom,
            Self::Dns(_) => OutboundProtocol::Dns,
            Self::Vless(_) => OutboundProtocol::Vless,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsOutboundSettings {
    /// Optional transport override; `None` preserves the original DNS flow.
    pub rewrite_network: Option<Network>,
    /// Optional address override; `None` preserves the original DNS target.
    pub rewrite_address: Option<TargetAddr>,
    /// Optional port override; zero preserves the original DNS target port.
    pub rewrite_port: u16,
    pub user_level: u32,
    pub rules: Vec<DnsOutboundRule>,
}

impl DnsOutboundSettings {
    /// Applies ordered Xray DNS outbound rules and then Xray's implicit policy.
    pub fn action_for(&self, qtype: u16, domain: &str) -> DnsOutboundRuleAction {
        let normalized_domain = normalize_dns_qname(domain);
        self.rules
            .iter()
            .find(|rule| rule.matches_normalized(qtype, &normalized_domain))
            .map_or_else(
                || {
                    if matches!(qtype, 1 | 28) {
                        DnsOutboundRuleAction::Hijack
                    } else {
                        DnsOutboundRuleAction::Return
                    }
                },
                |rule| rule.action,
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOutboundRule {
    pub action: DnsOutboundRuleAction,
    /// DNS response code used by `Return` and by non-address `Hijack` rules.
    pub r_code: u16,
    pub qtype_ranges: Vec<DnsQTypeRange>,
    /// Compiled with [`compile_dns_domain_matchers`] semantics.
    pub domain_matchers: DomainMatcherSet,
}

impl DnsOutboundRule {
    pub fn matches(&self, qtype: u16, domain: &str) -> bool {
        let normalized_domain = normalize_dns_qname(domain);
        self.matches_normalized(qtype, &normalized_domain)
    }

    fn matches_normalized(&self, qtype: u16, normalized_domain: &str) -> bool {
        (self.qtype_ranges.is_empty()
            || self.qtype_ranges.iter().any(|range| range.contains(qtype)))
            && (self.domain_matchers.is_empty() || self.domain_matchers.matches(normalized_domain))
    }
}

fn normalize_dns_qname(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsOutboundRuleAction {
    Direct,
    Drop,
    Return,
    Hijack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsQTypeRange {
    start: u16,
    end: u16,
}

impl DnsQTypeRange {
    pub fn new(start: u16, end: u16) -> Result<Self, ConfigModelError> {
        if start > end {
            return Err(ConfigModelError::InvalidDnsQTypeRange { start, end });
        }
        Ok(Self { start, end })
    }

    pub const fn single(qtype: u16) -> Self {
        Self {
            start: qtype,
            end: qtype,
        }
    }

    pub const fn start(self) -> u16 {
        self.start
    }

    pub const fn end(self) -> u16 {
        self.end
    }

    pub fn contains(self, qtype: u16) -> bool {
        (self.start..=self.end).contains(&qtype)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessOutboundSettings {
    pub server: TargetAddr,
    pub port: u16,
    pub users: Vec<VlessUser>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessUser {
    pub id: Uuid,
    pub encryption: String,
    pub flow: Option<String>,
    pub level: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyConfig {
    pub levels: BTreeMap<u32, PolicyLevelConfig>,
    pub system: PolicySystemConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyLevelConfig {
    pub handshake: Option<u32>,
    pub conn_idle: Option<u32>,
    pub uplink_only: Option<u32>,
    pub downlink_only: Option<u32>,
    pub stats_user_uplink: bool,
    pub stats_user_downlink: bool,
    pub buffer_size: Option<i32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySystemConfig {
    pub stats_inbound_uplink: bool,
    pub stats_inbound_downlink: bool,
    pub stats_outbound_uplink: bool,
    pub stats_outbound_downlink: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSettings {
    pub network: Network,
    pub transport: StreamTransport,
    pub security: StreamSecurity,
    /// Normalized `streamSettings.finalmask.quicParams` values. `None`
    /// preserves the distinction between an absent/null Go pointer and an
    /// explicitly present (possibly default-valued) configuration.
    pub quic_params: Option<QuicParamsSettings>,
    pub socket_options: Option<SocketOptions>,
}

/// Xray's final QUIC parameters after config-build normalization.
///
/// Bandwidths are stored in bytes per second, matching the protobuf/runtime
/// representation rather than the bits-per-second JSON spelling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicParamsSettings {
    pub congestion: QuicCongestion,
    pub bbr_profile: QuicBbrProfile,
    pub brutal_up_bytes_per_sec: u64,
    pub brutal_down_bytes_per_sec: u64,
    pub udp_hop: QuicUdpHopSettings,
    pub init_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub init_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout_secs: i64,
    pub keep_alive_period_secs: i64,
    pub disable_path_mtu_discovery: bool,
    pub max_incoming_streams: i64,
    /// Retained for fail-closed runtime handling. Unlike Xray's config build,
    /// parsing this flag does not mutate process-global environment variables.
    pub debug: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum QuicCongestion {
    /// Xray leaves an empty congestion name for the QUIC runtime to resolve.
    #[default]
    Default,
    Brutal,
    Reno,
    Bbr,
    ForceBrutal,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum QuicBbrProfile {
    Conservative,
    /// Xray normalizes an absent/empty profile to `standard`.
    #[default]
    Standard,
    Aggressive,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicUdpHopSettings {
    /// Expanded in configured order; duplicates are intentionally preserved.
    pub ports: Vec<u16>,
    pub interval: QuicIntervalRange,
}

/// An ordered Xray `Int32Range` used for the UDP-hop interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicIntervalRange {
    pub from: i32,
    pub to: i32,
}

/// The stream transport `streamSettings.network` selected, with its own
/// settings block already parsed.
///
/// `network` above stays `Network::Tcp` for all of these: every transport we
/// support runs over a TCP connection, and the variant only says what gets
/// layered on top of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamTransport {
    /// `tcp` / `raw`: nothing layered on top.
    Raw,
    WebSocket(WebSocketSettings),
    HttpUpgrade(HttpUpgradeSettings),
    Grpc(GrpcSettings),
    /// `xhttp` / the legacy `splithttp` spelling.
    Xhttp(Box<XhttpSettings>),
}

/// An ordered XHTTP integer range. Xray accepts either a JSON integer or a
/// string such as `"100-1000"`; a single value has identical bounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XhttpRange {
    pub from: i32,
    pub to: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpMode {
    #[default]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpPaddingPlacement {
    Cookie,
    Header,
    Query,
    #[default]
    QueryInHeader,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpPaddingMethod {
    #[default]
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpPlacement {
    #[default]
    Path,
    Cookie,
    Header,
    Query,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XhttpUplinkDataPlacement {
    #[default]
    Auto,
    Body,
    Cookie,
    Header,
}

/// The client-side XHTTP connection-reuse policy. The runtime may initially
/// use direct per-connection reuse, but retaining and validating this surface
/// prevents real Xray profiles from being silently reinterpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhttpXmuxSettings {
    pub max_concurrency: XhttpRange,
    pub max_connections: XhttpRange,
    pub c_max_reuse_times: XhttpRange,
    pub h_max_request_times: XhttpRange,
    pub h_max_reusable_secs: XhttpRange,
    pub h_keep_alive_period_secs: i64,
}

impl Default for XhttpXmuxSettings {
    fn default() -> Self {
        Self {
            max_concurrency: XhttpRange::default(),
            max_connections: XhttpRange { from: 3, to: 3 },
            c_max_reuse_times: XhttpRange::default(),
            h_max_request_times: XhttpRange { from: 600, to: 900 },
            h_max_reusable_secs: XhttpRange {
                from: 1_800,
                to: 3_000,
            },
            h_keep_alive_period_secs: 0,
        }
    }
}

/// Config-build-normalized `xhttpSettings` / `splithttpSettings` from Xray
/// v26.7.28. Zero ranges remain zero here where Xray's `Build` leaves them;
/// the transport must apply its mode/placement-dependent `GetNormalized*`
/// defaults when it creates a connection.
///
/// [`Default`] represents an explicit empty settings object after
/// `SplitHTTPConfig.Build`. The parser separately preserves the zero XMUX
/// produced when both settings pointers are absent or null.
///
/// `extra` is intentionally absent from the normalized model: the parser
/// applies Xray's one-level replacement rule and stores only the effective
/// settings here. `downloadSettings` remains absent because it adds a second
/// independent transport stack and is rejected until the runtime can honor it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpSettings {
    pub host: Option<String>,
    /// The configured path, before XHTTP adds a leading/trailing slash and
    /// separates its query string for individual requests.
    pub path: String,
    pub mode: XhttpMode,
    pub headers: Vec<(String, String)>,
    pub x_padding_bytes: XhttpRange,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: XhttpPaddingPlacement,
    pub x_padding_method: XhttpPaddingMethod,
    pub uplink_http_method: String,
    pub session_placement: XhttpPlacement,
    pub session_key: String,
    /// Empty selects Xray's UUID v4 fallback. Non-empty values retain the
    /// configured alias/custom table for transport-side expansion.
    pub session_id_table: String,
    pub session_id_length: XhttpRange,
    pub seq_placement: XhttpPlacement,
    pub seq_key: String,
    pub uplink_data_placement: XhttpUplinkDataPlacement,
    pub uplink_data_key: String,
    pub uplink_chunk_size: XhttpRange,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub sc_max_each_post_bytes: XhttpRange,
    pub sc_min_posts_interval_ms: XhttpRange,
    pub sc_max_buffered_posts: i64,
    pub sc_stream_up_server_secs: XhttpRange,
    pub server_max_header_bytes: i32,
    pub xmux: XhttpXmuxSettings,
}

impl Default for XhttpSettings {
    fn default() -> Self {
        Self {
            host: None,
            path: String::new(),
            mode: XhttpMode::Auto,
            headers: Vec::new(),
            x_padding_bytes: XhttpRange::default(),
            x_padding_obfs_mode: false,
            x_padding_key: "x_padding".to_owned(),
            x_padding_header: "X-Padding".to_owned(),
            x_padding_placement: XhttpPaddingPlacement::QueryInHeader,
            x_padding_method: XhttpPaddingMethod::RepeatX,
            uplink_http_method: "POST".to_owned(),
            session_placement: XhttpPlacement::Path,
            session_key: String::new(),
            session_id_table: String::new(),
            session_id_length: XhttpRange::default(),
            seq_placement: XhttpPlacement::Path,
            seq_key: String::new(),
            uplink_data_placement: XhttpUplinkDataPlacement::Auto,
            uplink_data_key: "X-Data".to_owned(),
            uplink_chunk_size: XhttpRange::default(),
            no_grpc_header: false,
            no_sse_header: false,
            sc_max_each_post_bytes: XhttpRange::default(),
            sc_min_posts_interval_ms: XhttpRange::default(),
            sc_max_buffered_posts: 0,
            sc_stream_up_server_secs: XhttpRange::default(),
            server_max_header_bytes: 0,
            xmux: XhttpXmuxSettings::default(),
        }
    }
}

/// `grpcSettings`. Key spellings are Xray's, inconsistencies included: five of
/// the eight are snake_case upstream (`idle_timeout`, `health_check_timeout`,
/// `permit_without_stream`, `initial_windows_size`, `user_agent`) while
/// `serviceName` and `multiMode` are not, and regularising either group here
/// would accept a config xray-core ignores (`Xray-core/infra/conf/
/// grpc.go:8-17`).
///
/// The three numbers are `int32` there and clamp a negative to zero rather
/// than failing, so an unsigned field holds every value that survives
/// `GRPCConfig.Build`. `authority` and `user_agent` are `Option` because Xray
/// cannot tell an absent key from an empty string either: both leave the Go
/// field `""`, which is what selects the authority fallback chain and the
/// Chrome user agent (`transport/internet/grpc/dial.go:159-166,193-205`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrpcSettings {
    pub service_name: String,
    pub multi_mode: bool,
    pub authority: Option<String>,
    pub user_agent: Option<String>,
    pub idle_timeout_secs: u32,
    pub health_check_timeout_secs: u32,
    pub permit_without_stream: bool,
    pub initial_windows_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebSocketSettings {
    /// Normalized: always begins with `/`, and `?ed=N` has been stripped with
    /// the remaining query re-encoded the way Go's `url.Values.Encode` does.
    pub path: String,
    /// `Host` header. Falls back to the TLS server name, then the destination
    /// address. Never carries a port.
    pub host: Option<String>,
    /// Extra headers, MIME-canonicalized. Xray feeds them to Go's `header.Add`,
    /// which title-cases the key, so `accept` reaches the wire as `Accept` —
    /// unlike `HttpUpgradeSettings::headers`, which keeps the literal casing.
    /// Order here is not meaningful; the serializer sorts them.
    pub headers: Vec<(String, String)>,
    /// From `?ed=N`. Zero means early data is off.
    pub early_data_bytes: u32,
    /// Seconds between client pings. Zero means no keepalive.
    pub heartbeat_period_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpUpgradeSettings {
    pub path: String,
    pub host: Option<String>,
    /// Extra headers with their literal casing preserved: Xray assigns these
    /// into the header map directly rather than through `header.Add`, on
    /// purpose, so that a config can send names like `Sec-WebSocket-Key`
    /// exactly as written.
    pub headers: Vec<(String, String)>,
    /// From `?ed=N`. For HTTPUpgrade this carries no payload — any positive
    /// value is retained only for config compatibility; the client still
    /// waits for the 101 to avoid stranding coalesced bytes in Xray's inbound
    /// buffered reader.
    pub early_data_bytes: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketOptions {
    pub happy_eyeballs: Option<HappyEyeballsSettings>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HappyEyeballsSettings {
    pub prioritize_ipv6: bool,
    pub interleave: u32,
    pub try_delay_ms: u64,
    pub max_concurrent_try: u32,
}

impl Default for HappyEyeballsSettings {
    fn default() -> Self {
        Self {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay_ms: 0,
            max_concurrent_try: 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSecurity {
    None,
    Tls(TlsSettings),
    Reality(RealitySettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    pub server_name: Option<String>,
    /// Normalized uTLS fingerprint. A parsed config always populates it: an
    /// absent `tlsSettings.fingerprint` means `chrome`, and `unsafe` means no
    /// shaping. `None` reaches here only from call sites that build the model
    /// directly, where it also means no shaping.
    pub fingerprint: Option<String>,
    /// SHA-256 fingerprints of complete DER-encoded peer certificates from
    /// Xray's comma-separated `pinnedPeerCertSha256` setting.
    pub pinned_peer_cert_sha256: Vec<[u8; 32]>,
    /// Alternative certificate verification names parsed from Xray's
    /// comma-separated `verifyPeerCertByName` setting. Any one matching DNS
    /// or IP SAN is sufficient; this list is independent of the TLS SNI.
    pub verify_peer_cert_by_name: Vec<String>,
    /// Programmatic-only escape hatch retained for local test fixtures. The
    /// canonical Xray JSON parser rejects `allowInsecure: true`.
    pub allow_insecure: bool,
    /// `tlsSettings.alpn`, verbatim.
    pub alpn: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySettings {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: RealityShortId,
    pub spider_x: String,
    pub mldsa65_verify: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityShortId {
    bytes: [u8; 8],
    len: u8,
}

impl RealityShortId {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConfigModelError> {
        if bytes.len() > 8 {
            return Err(ConfigModelError::RealityShortIdTooLong);
        }

        let mut short_id = Self {
            bytes: [0; 8],
            len: bytes.len() as u8,
        };
        short_id.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(short_id)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(std::net::IpAddr),
    Domain(String),
}

impl TargetAddr {
    /// Whether Xray-core exempts this server address from its outbound
    /// transport-security requirement.
    ///
    /// This intentionally uses Xray's broader private/reserved/test set, not
    /// the routing-oriented `geoip:private` set ([`xray_routing::PRIVATE_NETWORKS`]). Xray normalizes one
    /// trailing domain dot and domain case before applying these rules.
    pub fn is_xray_plaintext_server_exempt(&self) -> bool {
        match self {
            Self::Ip(ip) => XRAY_PLAINTEXT_SERVER_CIDRS
                .iter()
                .any(|cidr| cidr.matches(ip)),
            Self::Domain(domain) => xray_plaintext_server_domain_matches(domain),
        }
    }
}

fn xray_plaintext_server_domain_matches(domain: &str) -> bool {
    let normalized = domain.to_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    const PRIVATE_SUFFIXES: [&str; 9] = [
        "lan",
        "localdomain",
        "example",
        "invalid",
        "localhost",
        "test",
        "local",
        "home.arpa",
        "internal",
    ];

    PRIVATE_SUFFIXES
        .iter()
        .any(|suffix| domain_matches_suffix(normalized, suffix))
        || xray_dotless_domain_matches(normalized)
}

fn xray_dotless_domain_matches(domain: &str) -> bool {
    let bytes = domain.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }

    bytes[1..bytes.len() - 1]
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
}

const XRAY_PLAINTEXT_SERVER_CIDRS: [IpCidr; 18] = [
    IpCidr(Cidr::new_const(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8)),
    IpCidr(Cidr::new_const(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)),
    IpCidr(Cidr::new_const(
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
        10,
    )),
    IpCidr(Cidr::new_const(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)),
    IpCidr(Cidr::new_const(
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        16,
    )),
    IpCidr(Cidr::new_const(
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
        12,
    )),
    IpCidr(Cidr::new_const(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)), 24)),
    IpCidr(Cidr::new_const(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)),
    IpCidr(Cidr::new_const(
        IpAddr::V4(Ipv4Addr::new(192, 88, 99, 0)),
        24,
    )),
    IpCidr(Cidr::new_const(
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        16,
    )),
    IpCidr(Cidr::new_const(
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)),
        15,
    )),
    IpCidr(Cidr::new_const(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
        24,
    )),
    IpCidr(Cidr::new_const(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
        24,
    )),
    IpCidr(Cidr::new_const(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 3)),
    IpCidr(Cidr::new_const(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 127)),
    IpCidr(Cidr::new_const(
        IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
        7,
    )),
    IpCidr(Cidr::new_const(
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
        10,
    )),
    IpCidr(Cidr::new_const(
        IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
        8,
    )),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum Matcher {
        Cidr(Cidr, bool),
        Private(bool),
    }

    fn cidr(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Matcher {
        Matcher::Cidr(
            Cidr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), prefix).unwrap(),
            false,
        )
    }

    fn private() -> Matcher {
        Matcher::Private(false)
    }

    fn not(matcher: Matcher) -> Matcher {
        match matcher {
            Matcher::Cidr(cidr, inverted) => Matcher::Cidr(cidr, !inverted),
            Matcher::Private(inverted) => Matcher::Private(!inverted),
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(segments))
    }

    fn mapped(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V6(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped())
    }

    fn set(matchers: Vec<Matcher>) -> IpMatcherSet {
        let mut builder = IpMatcherSet::builder();
        for matcher in matchers {
            match matcher {
                Matcher::Cidr(cidr, inverted) => builder.insert_cidr(cidr, inverted),
                Matcher::Private(inverted) => builder.insert_private_networks(inverted),
            }
        }
        builder.build()
    }

    #[test]
    fn ip_matcher_set_positive_match_wins_over_failing_inverse() {
        // Positive matches even though the inverse clause fails (10.0.0.1 is inside the
        // negated 10.0.0.0/8) — and regardless of matcher ordering.
        let matchers = set(vec![not(cidr(10, 0, 0, 0, 8)), cidr(10, 0, 0, 0, 16)]);
        assert!(matchers.matches(v4(10, 0, 0, 1)));

        let matchers = set(vec![cidr(10, 0, 0, 0, 16), not(cidr(10, 0, 0, 0, 8))]);
        assert!(matchers.matches(v4(10, 0, 0, 1)));
    }

    #[test]
    fn ip_matcher_set_only_inverses_with_one_failing_is_false() {
        let matchers = set(vec![
            not(cidr(10, 0, 0, 0, 8)),
            not(cidr(192, 168, 0, 0, 16)),
            not(cidr(172, 16, 0, 0, 12)),
        ]);
        assert!(!matchers.matches(v4(192, 168, 1, 1)));
        assert!(!matchers.matches(v4(10, 1, 2, 3)));
        assert!(!matchers.matches(v4(172, 20, 0, 1)));
    }

    #[test]
    fn ip_matcher_set_only_inverses_all_passing_is_true() {
        let matchers = set(vec![
            not(cidr(10, 0, 0, 0, 8)),
            not(cidr(192, 168, 0, 0, 16)),
        ]);
        assert!(matchers.matches(v4(8, 8, 8, 8)));
    }

    #[test]
    fn ip_matcher_set_with_no_matchers_is_empty_and_matches_nothing() {
        let matchers = set(Vec::new());
        assert!(matchers.is_empty());
        assert_eq!(matchers.range_count(), 0);
        assert!(!matchers.matches(v4(8, 8, 8, 8)));
        assert_eq!(matchers, IpMatcherSet::default());
        assert!(!set(vec![cidr(10, 0, 0, 0, 8)]).is_empty());
        assert!(!set(vec![not(cidr(10, 0, 0, 0, 8))]).is_empty());
    }

    #[test]
    fn ip_matcher_set_positive_miss_and_failing_inverse_is_false() {
        let matchers = set(vec![cidr(203, 0, 113, 0, 24), not(cidr(10, 0, 0, 0, 8))]);
        assert!(!matchers.matches(v4(10, 42, 0, 1)));
        // Positive miss but inverse clause holds.
        assert!(matchers.matches(v4(8, 8, 8, 8)));
    }

    #[test]
    fn ip_matcher_set_flattens_nested_not() {
        let matchers = set(vec![not(not(cidr(10, 0, 0, 0, 8)))]);
        assert!(matchers.matches(v4(10, 1, 1, 1)));
        assert!(!matchers.matches(v4(8, 8, 8, 8)));
        assert_eq!(matchers, set(vec![cidr(10, 0, 0, 0, 8)]));

        let matchers = set(vec![
            not(not(cidr(10, 0, 0, 0, 8))),
            not(cidr(192, 168, 0, 0, 16)),
        ]);
        assert!(matchers.matches(v4(8, 8, 8, 8)));
        assert!(matchers.matches(v4(10, 1, 1, 1)));
        assert!(!matchers.matches(v4(192, 168, 1, 1)));
        assert!(set(vec![not(not(cidr(10, 0, 0, 0, 8)))]).matches(v4(10, 1, 1, 1)));
        assert!(!set(vec![not(not(cidr(10, 0, 0, 0, 8)))]).matches(v4(8, 8, 8, 8)));
    }

    #[test]
    fn ip_matcher_set_canonicalizes_v4_mapped_targets_and_networks() {
        let matchers = set(vec![cidr(203, 0, 113, 0, 24)]);
        assert!(matchers.matches(mapped(203, 0, 113, 7)));
        assert!(!matchers.matches(mapped(203, 0, 114, 7)));
        assert!(set(vec![cidr(203, 0, 113, 0, 24)]).matches(mapped(203, 0, 113, 7)));

        let mapped_network = Matcher::Cidr(
            IpCidr::new(mapped(203, 0, 113, 0), 24)
                .expect("v4 prefix")
                .cidr(),
            false,
        );
        assert_eq!(
            set(vec![mapped_network]),
            set(vec![cidr(203, 0, 113, 0, 24)])
        );
        assert!(set(vec![mapped_network]).matches(v4(203, 0, 113, 7)));
        assert!(IpCidr::new(mapped(203, 0, 113, 0), 33).is_err());

        let inverse = set(vec![not(cidr(10, 0, 0, 0, 8))]);
        assert!(!inverse.matches(mapped(10, 1, 1, 1)));
        assert!(inverse.matches(mapped(8, 8, 8, 8)));
    }

    #[test]
    fn ip_matcher_set_inverse_of_foreign_family_matches_nothing() {
        let matchers = set(vec![not(cidr(10, 0, 0, 0, 8))]);
        assert!(matchers.matches(v4(8, 8, 8, 8)));
        assert!(!matchers.matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
        assert!(!matchers.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(
            !set(vec![not(cidr(10, 0, 0, 0, 8))]).matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]))
        );

        let fc00 = Matcher::Cidr(
            Cidr::new(v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7).expect("v6 prefix"),
            false,
        );
        let matchers = set(vec![not(cidr(10, 0, 0, 0, 8)), not(fc00)]);
        assert!(matchers.matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
        assert!(!matchers.matches(v6([0xfd00, 0, 0, 0, 0, 0, 0, 1])));
        assert!(matchers.matches(v4(8, 8, 8, 8)));
        assert!(!matchers.matches(v4(10, 0, 0, 1)));

        let matchers = set(vec![not(fc00), cidr(203, 0, 113, 0, 24)]);
        assert!(matchers.matches(v4(203, 0, 113, 7)));
        assert!(!matchers.matches(v4(8, 8, 8, 8)));
    }

    #[test]
    fn ip_matcher_set_prefix_zero_covers_the_whole_family() {
        let matchers = set(vec![cidr(0, 0, 0, 0, 0)]);
        assert_eq!(matchers.range_count(), 1);
        assert!(matchers.matches(v4(0, 0, 0, 0)));
        assert!(matchers.matches(v4(255, 255, 255, 255)));
        assert!(matchers.matches(mapped(8, 8, 8, 8)));
        assert!(!matchers.matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));

        let matchers = set(vec![not(cidr(0, 0, 0, 0, 0))]);
        assert!(!matchers.matches(v4(8, 8, 8, 8)));
        assert!(!matchers.matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
    }

    #[test]
    fn ip_matcher_set_merges_adjacent_and_overlapping_ranges() {
        let matchers = set(vec![
            cidr(10, 0, 0, 128, 25),
            cidr(10, 0, 0, 0, 25),
            cidr(10, 0, 1, 0, 24),
            cidr(10, 0, 0, 0, 26),
        ]);
        assert_eq!(matchers.range_count(), 1);
        assert!(matchers.matches(v4(10, 0, 0, 0)));
        assert!(matchers.matches(v4(10, 0, 1, 255)));
        assert!(!matchers.matches(v4(10, 0, 2, 0)));
        assert_eq!(matchers, set(vec![cidr(10, 0, 0, 0, 23)]));

        let inverse = set(vec![not(cidr(10, 0, 0, 0, 24)), not(cidr(10, 0, 1, 0, 24))]);
        assert_eq!(inverse.range_count(), 1);
        assert!(!inverse.matches(v4(10, 0, 0, 255)));
        assert!(!inverse.matches(v4(10, 0, 1, 0)));
        assert!(inverse.matches(v4(10, 0, 2, 0)));

        let both = set(vec![cidr(10, 0, 0, 0, 24), not(cidr(10, 0, 1, 0, 24))]);
        assert_eq!(both.range_count(), 2);
    }

    #[test]
    fn ip_matcher_set_private_and_its_inverse() {
        let private_set = set(vec![private()]);
        assert_eq!(private_set.range_count(), 9);
        assert!(private_set.matches(v4(10, 1, 2, 3)));
        assert!(private_set.matches(mapped(192, 168, 1, 1)));
        assert!(private_set.matches(v6([0xfe80, 0, 0, 0, 0, 0, 0, 1])));
        assert!(!private_set.matches(v4(8, 8, 8, 8)));

        let public = set(vec![not(private())]);
        assert_eq!(public.range_count(), 9);
        assert!(public.matches(v4(8, 8, 8, 8)));
        assert!(public.matches(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
        assert!(!public.matches(v4(10, 0, 0, 1)));
        assert!(!public.matches(mapped(192, 168, 1, 1)));
        assert!(!public.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!public.matches(v6([0xfe80, 0, 0, 0, 0, 0, 0, 1])));
        assert!(set(vec![not(private())]).matches(v4(8, 8, 8, 8)));
        assert!(!set(vec![not(private())]).matches(v4(10, 0, 0, 1)));
    }

    #[test]
    fn private_matcher_uses_shared_private_networks() {
        assert!(set(vec![private()]).matches(v4(10, 1, 2, 3)));
        assert!(set(vec![private()]).matches(v4(100, 64, 0, 1)));
        assert!(set(vec![private()]).matches(v4(127, 0, 0, 1)));
        assert!(set(vec![private()]).matches(v4(169, 254, 1, 1)));
        assert!(set(vec![private()]).matches(v4(172, 31, 255, 255)));
        assert!(set(vec![private()]).matches(v4(192, 168, 0, 1)));
        assert!(set(vec![private()]).matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(
            set(vec![private()]).matches(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)))
        );
        assert!(
            set(vec![private()]).matches(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
        );
        assert!(!set(vec![private()]).matches(v4(8, 8, 8, 8)));
        assert!(!set(vec![private()]).matches(v4(172, 32, 0, 1)));
        assert!(!set(vec![private()])
            .matches(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn invalid_domain_regex_maps_to_the_config_error() {
        let error = ConfigModelError::from(RegexMatcher::new("(").unwrap_err());
        assert!(matches!(
            &error,
            ConfigModelError::InvalidDomainRegex { pattern, message }
                if pattern == "(" && !message.is_empty()
        ));
        assert!(error.to_string().starts_with("invalid domain regex `(`: "));
    }

    fn parity_matchers() -> Vec<DomainMatcher> {
        let regex = |pattern: &str| DomainMatcher::Regex(RegexMatcher::new(pattern).unwrap());
        vec![
            DomainMatcher::Full("example.com".to_owned()),
            DomainMatcher::Full("Exact.TEST".to_owned()),
            DomainMatcher::Full("dotted.test.".to_owned()),
            DomainMatcher::Full("bücher.example".to_owned()),
            DomainMatcher::Full("single".to_owned()),
            DomainMatcher::Full("".to_owned()),
            DomainMatcher::Suffix("suffix.example".to_owned()),
            DomainMatcher::Suffix("Mixed.Case.Example".to_owned()),
            DomainMatcher::Suffix("trailing.example.".to_owned()),
            DomainMatcher::Suffix(".leading.example".to_owned()),
            DomainMatcher::Suffix("tld".to_owned()),
            DomainMatcher::Suffix("".to_owned()),
            DomainMatcher::Suffix("münchen.example".to_owned()),
            DomainMatcher::Suffix("a..b.example".to_owned()),
            DomainMatcher::Keyword("track".to_owned()),
            DomainMatcher::Keyword("ADS".to_owned()),
            DomainMatcher::Keyword(".metrics.".to_owned()),
            DomainMatcher::Keyword("straße".to_owned()),
            DomainMatcher::Keyword("zz-only-tail".to_owned()),
            DomainMatcher::Keyword("k".to_owned()),
            regex("^[^.]*intranet[^.]*$"),
            regex("^[^.]*[^.]*$"),
            regex(r"^api\.[a-z0-9-]+\.svc$"),
            regex(r"(^|\.)regex\.example\.?$"),
            regex(r"^cdn[0-9]+\.static\.example$"),
            regex(r"^[a-z]{2}\.[a-z]{2}$"),
            regex(r"\.onion$"),
            regex(r"^(www\.)?shop\.example$"),
            regex(r"caf\u{e9}"),
            regex(r"^x{3,}$"),
        ]
    }

    fn parity_probes() -> Vec<String> {
        let mut probes = vec![
            "",
            ".",
            "..",
            "example.com",
            "EXAMPLE.COM",
            "example.com.",
            "www.example.com",
            "notexample.com",
            "exact.test",
            "EXACT.TEST",
            "exact.test.",
            "notexact.test",
            "dotted.test",
            "dotted.test.",
            "sub.dotted.test.",
            "bücher.example",
            "BÜCHER.example",
            "single",
            "single.",
            "a.single",
            "suffix.example",
            "SUB.SUFFIX.EXAMPLE",
            "notsuffix.example",
            "suffix.example.evil",
            "suffix.example.",
            "mixed.case.example",
            "deep.MIXED.CASE.EXAMPLE",
            "trailing.example",
            "trailing.example.",
            "a.trailing.example.",
            "leading.example",
            ".leading.example",
            "x..leading.example",
            "www.leading.example",
            "tld",
            "a.tld",
            "tld.example",
            "atld",
            "münchen.example",
            "MÜNCHEN.example",
            "www.münchen.example",
            "a..b.example",
            "x.a..b.example",
            "a.b.example",
            "tracker.test",
            "TRACKING.test",
            "ads.example",
            "ADS",
            "roads.example",
            "roadside.example",
            "a.metrics.b",
            "metrics.b",
            "a.metrics",
            "straße.example",
            "STRASSE.example",
            "strasse.example",
            "zz-only-tail",
            "zz-only-tai",
            "k",
            "K",
            "no-such-letter",
            "intranet",
            "MyIntranetBox",
            "intranet.corp",
            "nodots",
            "api.svc-1.svc",
            "API.SVC-1.SVC",
            "api.svc-1.svc.",
            "regex.example",
            "regex.example.",
            "a.regex.example",
            "aregex.example",
            "cdn12.static.example",
            "cdn.static.example",
            "ab.cd",
            "ab.cde",
            "hidden.onion",
            "onion",
            "shop.example",
            "www.shop.example",
            "m.shop.example",
            "café.example",
            "CAFÉ.example",
            "xxx",
            "xx",
            "xxxx.",
            "XXX",
            "🙂.example",
            "😀",
            "a.b.c.d.e.f.g.h",
            "trailing.dots...",
            "...",
            "mix.Of.EVERYTHING.example.com.",
            "com",
            "example",
            "-",
            "_dmarc.example.com",
            "xn--bcher-kva.example",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        probes.push("y".repeat(300));
        probes.push("very-long-label-".repeat(4));
        probes
    }

    fn dns_reference_matches(matcher: &DomainMatcher, domain: &str) -> bool {
        let trimmed = |pattern: &str| pattern.trim_end_matches('.').to_owned();
        match matcher {
            DomainMatcher::Full(expected) => DomainMatcher::Full(trimmed(expected)),
            DomainMatcher::Suffix(suffix) => DomainMatcher::Suffix(trimmed(suffix)),
            other => other.clone(),
        }
        .matches(domain.trim_end_matches('.'))
    }

    #[test]
    fn compiled_routing_set_matches_the_linear_reference_on_every_probe() {
        let matchers = parity_matchers();
        let set = compile_domain_matchers(&matchers).unwrap();
        assert_eq!(set.matcher_count(), matchers.len());
        let probes = parity_probes();
        assert!(probes.len() >= 100);
        let mut hits = 0;
        for domain in &probes {
            let expected = matchers.iter().any(|matcher| matcher.matches(domain));
            assert_eq!(set.matches(domain), expected, "domain={domain:?}");
            hits += usize::from(expected);
        }
        assert!(hits > 30 && hits < probes.len() - 20, "hits={hits}");
    }

    #[test]
    fn compiled_dns_set_matches_the_transport_reference_on_normalized_names() {
        let matchers = parity_matchers();
        let set = compile_dns_domain_matchers(&matchers).unwrap();
        for domain in parity_probes() {
            let domain = domain.trim_end_matches('.');
            let expected = matchers
                .iter()
                .any(|matcher| dns_reference_matches(matcher, domain));
            assert_eq!(set.matches(domain), expected, "domain={domain:?}");
        }
    }

    #[test]
    fn routing_and_dns_compilation_differ_only_in_trailing_dot_patterns() {
        let matchers = [
            DomainMatcher::Full("dotted.test.".to_owned()),
            DomainMatcher::Suffix("trailing.example.".to_owned()),
        ];
        let routing = compile_domain_matchers(&matchers).unwrap();
        let dns = compile_dns_domain_matchers(&matchers).unwrap();

        assert!(routing.matches("dotted.test."));
        assert!(!routing.matches("dotted.test"));
        assert!(routing.matches("a.trailing.example."));
        assert!(!routing.matches("a.trailing.example"));

        assert!(dns.matches("dotted.test"));
        assert!(!dns.matches("dotted.test."));
        assert!(dns.matches("a.trailing.example"));
        assert!(!dns.matches("a.trailing.example."));
    }
}
