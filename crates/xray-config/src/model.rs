use std::{
    borrow::Cow,
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use regex::Regex;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigModelError {
    #[error("reality short id cannot exceed 8 bytes")]
    RealityShortIdTooLong,
    #[error("CIDR prefix length {prefix} exceeds max {max}")]
    InvalidCidrPrefix { prefix: u8, max: u8 },
    #[error("invalid domain regex `{pattern}`: {message}")]
    InvalidDomainRegex { pattern: String, message: String },
    #[error("DNS qtype range start {start} exceeds end {end}")]
    InvalidDnsQTypeRange { start: u16, end: u16 },
    #[error("routing port range start {start} exceeds end {end}")]
    InvalidRoutingPortRange { start: u16, end: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub default_outbound_tag: Option<String>,
    pub routing: RoutingConfig,
    pub dns: DnsConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingConfig {
    pub rules: Vec<RoutingRule>,
    pub domain_strategy: RoutingDomainStrategy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RoutingDomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfig {
    pub fake_ip: Option<DnsFakeIpConfig>,
    pub servers: Vec<DnsServerConfig>,
    pub hosts: Vec<DnsHostMapping>,
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
    Policy(DnsNameServerConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNameServerConfig {
    pub endpoint: DnsServerEndpoint,
    pub transport: DnsServerTransport,
    pub domains: Vec<DomainMatcher>,
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsIpFilter {
    pub custom_matchers: Vec<IpMatcher>,
    pub geoip_matchers: Vec<IpMatcher>,
    pub soft: bool,
}

impl DnsIpFilter {
    pub fn matches(&self, ip: &IpAddr) -> bool {
        dns_ip_matcher_group_matches(&self.custom_matchers, ip)
            || dns_ip_matcher_group_matches(&self.geoip_matchers, ip)
    }

    pub fn is_empty(&self) -> bool {
        self.custom_matchers.is_empty() && self.geoip_matchers.is_empty()
    }
}

fn dns_ip_matcher_group_matches(matchers: &[IpMatcher], target_ip: &IpAddr) -> bool {
    let target_ip = canonicalize_ip_matcher_address(*target_ip);
    let mut positive_matched = false;
    let mut inverse_supports_family = false;
    let mut inverse_contains = false;

    for matcher in matchers {
        let (matcher, inverse) = dns_ip_matcher_base(matcher);
        if inverse {
            if dns_ip_matcher_supports_family(matcher, target_ip) {
                inverse_supports_family = true;
                inverse_contains |= dns_ip_matcher_matches(matcher, target_ip);
            }
        } else {
            positive_matched |= dns_ip_matcher_matches(matcher, target_ip);
        }
    }

    positive_matched || inverse_supports_family && !inverse_contains
}

fn dns_ip_matcher_base(mut matcher: &IpMatcher) -> (&IpMatcher, bool) {
    let mut inverse = false;
    while let IpMatcher::Not(inner) = matcher {
        inverse = !inverse;
        matcher = inner;
    }
    (matcher, inverse)
}

fn dns_ip_matcher_supports_family(matcher: &IpMatcher, target_ip: IpAddr) -> bool {
    match matcher {
        IpMatcher::Cidr(cidr) => {
            matches!(
                (canonicalize_ip_matcher_address(cidr.network()), target_ip),
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
            )
        }
        IpMatcher::Private => true,
        IpMatcher::Not(_) => unreachable!("DNS IP matcher negation should be flattened"),
    }
}

fn dns_ip_matcher_matches(matcher: &IpMatcher, target_ip: IpAddr) -> bool {
    match matcher {
        IpMatcher::Cidr(cidr) => {
            let network = canonicalize_ip_matcher_address(cidr.network());
            let width = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            cidr.prefix() <= width
                && match (network, target_ip) {
                    (IpAddr::V4(network), IpAddr::V4(ip)) => prefix_matches(
                        u128::from(u32::from(network)),
                        u128::from(u32::from(ip)),
                        cidr.prefix(),
                        32,
                    ),
                    (IpAddr::V6(network), IpAddr::V6(ip)) => {
                        prefix_matches(u128::from(network), u128::from(ip), cidr.prefix(), 128)
                    }
                    (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
                }
        }
        IpMatcher::Private => PRIVATE_CIDRS
            .iter()
            .any(|private_cidr| private_cidr.matches(&target_ip)),
        IpMatcher::Not(_) => unreachable!("DNS IP matcher negation should be flattened"),
    }
}

fn canonicalize_ip_matcher_address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
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

    pub fn domains(&self) -> &[DomainMatcher] {
        match self {
            Self::Policy(server) => &server.domains,
            Self::Ip(_) | Self::Domain { .. } => &[],
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
pub struct DnsHostMapping {
    pub matcher: DomainMatcher,
    pub target: DnsHostTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsHostTarget {
    Ip(IpAddr),
    Ips(Vec<IpAddr>),
    Domain(String),
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
    pub domain_matchers: Vec<DomainMatcher>,
    pub ip_matchers: Vec<IpMatcher>,
    pub outbound_tag: String,
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

        self.domain_matchers
            .iter()
            .any(|matcher| matcher.matches(target_domain))
    }

    pub fn matches_ip(&self, target_ip: Option<&IpAddr>) -> bool {
        if self.ip_matchers.is_empty() {
            return true;
        }

        let Some(target_ip) = target_ip else {
            return false;
        };

        ip_matcher_group_matches(&self.ip_matchers, target_ip)
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

/// Positive matchers form a disjunction, inverse (`Not`) matchers form a conjunction,
/// and the rule matches when either clause holds:
/// `(any positive matched) || (has inverse && all inverse matched)`.
///
/// The loop short-circuits: the first positive hit decides the result, and once an
/// inverse matcher fails the inverse clause is dead, so remaining inverse matchers are
/// skipped and only positives are still evaluated.
fn ip_matcher_group_matches(matchers: &[IpMatcher], target_ip: &IpAddr) -> bool {
    let mut has_inverse = false;
    let mut all_inverse_matched = true;

    for matcher in matchers {
        if matcher.is_inverse() {
            has_inverse = true;
            if all_inverse_matched && !matcher.matches(target_ip) {
                all_inverse_matched = false;
            }
        } else if matcher.matches(target_ip) {
            return true;
        }
    }

    has_inverse && all_inverse_matched
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMatcher {
    Keyword(String),
    Full(String),
    Suffix(String),
    Regex(RegexMatcher),
}

impl DomainMatcher {
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Keyword(keyword) => contains_ignore_ascii_case(domain, keyword),
            Self::Full(expected) => domain.eq_ignore_ascii_case(expected),
            Self::Suffix(suffix) => domain_matches_suffix(domain, suffix),
            Self::Regex(matcher) => matcher.matches(domain),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegexMatcher {
    pattern: String,
    regex: Regex,
}

impl RegexMatcher {
    pub fn new(pattern: impl Into<String>) -> Result<Self, ConfigModelError> {
        let pattern = pattern.into();
        let regex = Regex::new(&pattern).map_err(|error| ConfigModelError::InvalidDomainRegex {
            pattern: pattern.clone(),
            message: error.to_string(),
        })?;

        Ok(Self { pattern, regex })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn matches(&self, domain: &str) -> bool {
        // Patterns are matched against the ASCII-lowercased domain. Only pay for the
        // allocation when the input actually contains uppercase ASCII.
        let domain: Cow<'_, str> = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(domain.to_ascii_lowercase())
        } else {
            Cow::Borrowed(domain)
        };
        self.regex.is_match(&domain)
    }
}

impl PartialEq for RegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for RegexMatcher {}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }

    if domain.len() <= suffix.len() {
        return false;
    }

    let boundary_index = domain.len() - suffix.len() - 1;
    let domain_bytes = domain.as_bytes();
    domain_bytes[boundary_index] == b'.'
        && domain_bytes[boundary_index + 1..].eq_ignore_ascii_case(suffix.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpMatcher {
    Cidr(IpCidr),
    Private,
    Not(Box<IpMatcher>),
}

impl IpMatcher {
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Cidr(cidr) => cidr.matches(ip),
            Self::Private => PRIVATE_CIDRS
                .iter()
                .any(|private_cidr| private_cidr.matches(ip)),
            Self::Not(matcher) => !matcher.matches(ip),
        }
    }

    fn is_inverse(&self) -> bool {
        matches!(self, Self::Not(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, ConfigModelError> {
        let network = canonicalize_ip_matcher_address(network);
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(ConfigModelError::InvalidCidrPrefix { prefix, max });
        }

        Ok(Self { network, prefix })
    }

    pub fn full(ip: IpAddr) -> Self {
        let ip = canonicalize_ip_matcher_address(ip);
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self {
            network: ip,
            prefix,
        }
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn matches(&self, ip: &IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => prefix_matches(
                u128::from(u32::from(network)),
                u128::from(u32::from(*ip)),
                self.prefix,
                32,
            ),
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                prefix_matches(u128::from(network), u128::from(*ip), self.prefix, 128)
            }
            _ => false,
        }
    }
}

fn prefix_matches(network: u128, ip: u128, prefix: u8, width: u8) -> bool {
    if prefix == 0 {
        return true;
    }

    let shift = u32::from(width - prefix);
    (network >> shift) == (ip >> shift)
}

const PRIVATE_CIDRS: [IpCidr; 9] = [
    IpCidr {
        network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix: 8,
    },
    IpCidr {
        network: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
        prefix: 10,
    },
    IpCidr {
        network: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        prefix: 8,
    },
    IpCidr {
        network: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        prefix: 16,
    },
    IpCidr {
        network: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
        prefix: 12,
    },
    IpCidr {
        network: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        prefix: 16,
    },
    IpCidr {
        network: IpAddr::V6(Ipv6Addr::LOCALHOST),
        prefix: 128,
    },
    IpCidr {
        network: IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
        prefix: 7,
    },
    IpCidr {
        network: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
        prefix: 10,
    },
];

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
    pub stream: StreamSettings,
    pub settings: OutboundSettings,
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
    pub domain_matchers: Vec<DomainMatcher>,
}

impl DnsOutboundRule {
    pub fn matches(&self, qtype: u16, domain: &str) -> bool {
        let normalized_domain = normalize_dns_qname(domain);
        self.matches_normalized(qtype, &normalized_domain)
    }

    fn matches_normalized(&self, qtype: u16, normalized_domain: &str) -> bool {
        (self.qtype_ranges.is_empty()
            || self.qtype_ranges.iter().any(|range| range.contains(qtype)))
            && (self.domain_matchers.is_empty()
                || self
                    .domain_matchers
                    .iter()
                    .any(|matcher| matcher.matches(normalized_domain)))
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
    /// the routing-oriented [`IpMatcher::Private`] set. Xray normalizes one
    /// trailing domain dot and domain case before applying these rules.
    pub fn is_xray_plaintext_server_exempt(&self) -> bool {
        match self {
            Self::Ip(ip) => {
                let ip = canonicalize_ip_matcher_address(*ip);
                xray_plaintext_server_cidrs()
                    .iter()
                    .any(|cidr| cidr.matches(&ip))
            }
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

fn xray_plaintext_server_cidrs() -> [IpCidr; 18] {
    [
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix: 8,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix: 8,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
            prefix: 10,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            prefix: 8,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
            prefix: 16,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
            prefix: 12,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)),
            prefix: 24,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            prefix: 24,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(192, 88, 99, 0)),
            prefix: 24,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix: 16,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)),
            prefix: 15,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
            prefix: 24,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
            prefix: 24,
        },
        IpCidr {
            network: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
            prefix: 3,
        },
        IpCidr {
            network: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix: 127,
        },
        IpCidr {
            network: IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
            prefix: 7,
        },
        IpCidr {
            network: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
            prefix: 10,
        },
        IpCidr {
            network: IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
            prefix: 8,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> IpMatcher {
        IpMatcher::Cidr(IpCidr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), prefix).unwrap())
    }

    fn not(matcher: IpMatcher) -> IpMatcher {
        IpMatcher::Not(Box::new(matcher))
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn ip_matcher_group_positive_match_wins_over_failing_inverse() {
        // Positive matches even though the inverse clause fails (10.0.0.1 is inside the
        // negated 10.0.0.0/8) — and regardless of matcher ordering.
        let matchers = [not(cidr(10, 0, 0, 0, 8)), cidr(10, 0, 0, 0, 16)];
        assert!(ip_matcher_group_matches(&matchers, &v4(10, 0, 0, 1)));

        let matchers = [cidr(10, 0, 0, 0, 16), not(cidr(10, 0, 0, 0, 8))];
        assert!(ip_matcher_group_matches(&matchers, &v4(10, 0, 0, 1)));
    }

    #[test]
    fn ip_matcher_group_only_inverses_with_one_failing_is_false() {
        let matchers = [
            not(cidr(10, 0, 0, 0, 8)),
            not(cidr(192, 168, 0, 0, 16)),
            not(cidr(172, 16, 0, 0, 12)),
        ];
        assert!(!ip_matcher_group_matches(&matchers, &v4(192, 168, 1, 1)));
        // Failing inverse first, then passing ones: skipped inverses must not flip the result.
        assert!(!ip_matcher_group_matches(&matchers, &v4(10, 1, 2, 3)));
        // Failing inverse last.
        assert!(!ip_matcher_group_matches(&matchers, &v4(172, 20, 0, 1)));
    }

    #[test]
    fn ip_matcher_group_only_inverses_all_passing_is_true() {
        let matchers = [not(cidr(10, 0, 0, 0, 8)), not(cidr(192, 168, 0, 0, 16))];
        assert!(ip_matcher_group_matches(&matchers, &v4(8, 8, 8, 8)));
    }

    #[test]
    fn ip_matcher_group_with_no_matchers_is_false() {
        // `RoutingRule::matches_ip` handles the empty case (as "no constraint") before
        // reaching this function; the group itself has nothing to match.
        assert!(!ip_matcher_group_matches(&[], &v4(8, 8, 8, 8)));
    }

    #[test]
    fn ip_matcher_group_positive_miss_and_failing_inverse_is_false() {
        let matchers = [cidr(203, 0, 113, 0, 24), not(cidr(10, 0, 0, 0, 8))];
        assert!(!ip_matcher_group_matches(&matchers, &v4(10, 42, 0, 1)));
        // Positive miss but inverse clause holds.
        assert!(ip_matcher_group_matches(&matchers, &v4(8, 8, 8, 8)));
    }

    #[test]
    fn ip_matcher_group_treats_nested_not_by_outer_layer_only() {
        // Not(Not(x)) counts as an inverse matcher (outer layer) whose value equals x.
        let matchers = [not(not(cidr(10, 0, 0, 0, 8)))];
        assert!(ip_matcher_group_matches(&matchers, &v4(10, 1, 1, 1)));
        assert!(!ip_matcher_group_matches(&matchers, &v4(8, 8, 8, 8)));
    }

    #[test]
    fn private_matcher_uses_const_private_ranges() {
        assert!(IpMatcher::Private.matches(&v4(10, 1, 2, 3)));
        assert!(IpMatcher::Private.matches(&v4(100, 64, 0, 1)));
        assert!(IpMatcher::Private.matches(&v4(127, 0, 0, 1)));
        assert!(IpMatcher::Private.matches(&v4(169, 254, 1, 1)));
        assert!(IpMatcher::Private.matches(&v4(172, 31, 255, 255)));
        assert!(IpMatcher::Private.matches(&v4(192, 168, 0, 1)));
        assert!(IpMatcher::Private.matches(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(IpMatcher::Private.matches(&IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
        assert!(IpMatcher::Private.matches(&IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!IpMatcher::Private.matches(&v4(8, 8, 8, 8)));
        assert!(!IpMatcher::Private.matches(&v4(172, 32, 0, 1)));
        assert!(!IpMatcher::Private
            .matches(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert_eq!(PRIVATE_CIDRS.len(), 9);
    }

    #[test]
    fn regex_matcher_lowercases_input_but_not_pattern() {
        let matcher = RegexMatcher::new(r"^api\.example\.com$").unwrap();
        assert!(matcher.matches("api.example.com"));
        assert!(matcher.matches("API.Example.COM"));
        assert!(!matcher.matches("api.example.org"));

        // An uppercase literal in the pattern never matches: input is lowercased, the
        // pattern is not (no case-insensitive flag).
        let upper = RegexMatcher::new(r"^API\.example\.com$").unwrap();
        assert!(!upper.matches("api.example.com"));
        assert!(!upper.matches("API.example.com"));

        // Non-ASCII input takes the borrowed path and is matched as-is.
        let unicode = RegexMatcher::new("^пример\\.рф$").unwrap();
        assert!(unicode.matches("пример.рф"));
    }
}
