use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time;

use crate::{
    canonicalize_socket_addr, connect_tcp_stream, SocketHandle, SocketProtector, TransportError,
};

/// A DNS lookup result containing every usable address and its remaining TTL.
///
/// `ttl = None` means the resolver cannot expose an authoritative TTL (for
/// example, the platform system resolver). Cache layers may replace it with a
/// bounded policy TTL.
#[derive(Debug, Clone)]
pub struct DnsLookup {
    socket_addrs: Arc<[SocketAddr]>,
    ttl: Option<Duration>,
    observed_at: Instant,
}

impl DnsLookup {
    /// Builds a lookup while preserving the first occurrence of each address.
    /// IPv4-mapped IPv6 candidates are canonicalized to IPv4 so routing and
    /// the eventual socket family observe the same endpoint.
    pub fn new(addresses: impl IntoIterator<Item = SocketAddr>, ttl: Option<Duration>) -> Self {
        let mut unique = Vec::new();
        let mut seen = HashSet::new();
        for address in addresses {
            let address = canonicalize_socket_addr(address);
            if seen.insert(address) {
                unique.push(address);
            }
        }
        Self {
            socket_addrs: unique.into(),
            ttl,
            observed_at: Instant::now(),
        }
    }

    /// Builds socket addresses for one destination port from resolved IPs.
    pub fn from_ips(
        addresses: impl IntoIterator<Item = IpAddr>,
        port: u16,
        ttl: Option<Duration>,
    ) -> Self {
        Self::new(
            addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, port)),
            ttl,
        )
    }

    /// Builds a lookup containing one address.
    pub fn single(address: SocketAddr, ttl: Option<Duration>) -> Self {
        Self::new([address], ttl)
    }

    /// Returns candidates in resolver order.
    pub fn socket_addrs(&self) -> &[SocketAddr] {
        &self.socket_addrs
    }

    /// Iterates over candidate IPs in resolver order.
    pub fn ips(&self) -> impl ExactSizeIterator<Item = IpAddr> + '_ {
        self.socket_addrs.iter().map(|address| address.ip())
    }

    /// Returns the authoritative or remaining cache TTL when known.
    pub fn ttl(&self) -> Option<Duration> {
        self.remaining_ttl_at(Instant::now())
    }

    fn first_socket_addr(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.socket_addrs
            .first()
            .copied()
            .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
    }

    fn ensure_non_empty(self, domain: &str, port: u16) -> Result<Self, TransportError> {
        if self.socket_addrs.is_empty() {
            Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
        } else {
            Ok(self)
        }
    }

    fn with_ttl_cap(mut self, cap: Duration) -> Self {
        let now = Instant::now();
        self.ttl = Some(self.remaining_ttl_at(now).map_or(cap, |ttl| ttl.min(cap)));
        self.observed_at = now;
        self
    }

    fn with_remaining_ttl(&self, ttl: Duration) -> Self {
        Self {
            socket_addrs: Arc::clone(&self.socket_addrs),
            ttl: Some(ttl),
            observed_at: Instant::now(),
        }
    }

    fn remaining_ttl_at(&self, now: Instant) -> Option<Duration> {
        self.ttl
            .map(|ttl| ttl.saturating_sub(now.saturating_duration_since(self.observed_at)))
    }
}

/// Resolves a domain into addresses suitable for the configured port.
///
/// Callers pass the configured port and must dial returned `SocketAddr`
/// candidates as-is. A resolver may intentionally replace the port or attach
/// IPv6 flow/scope metadata.
///
/// Existing implementations only need to implement [`DnsResolver::resolve`].
/// Rich resolvers should override [`DnsResolver::resolve_all`] so routing and
/// dialing can consume every answer and the DNS TTL.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError>;

    async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        let address = self.resolve(domain, port).await?;
        Ok(DnsLookup::single(address, None))
    }
}

#[derive(Debug, Clone, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.resolve_all(domain, port)
            .await?
            .first_socket_addr(domain, port)
    }

    async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        let addrs = tokio::net::lookup_host((domain, port))
            .await
            .map_err(|source| TransportError::Dns {
                domain: domain.to_owned(),
                port,
                source,
            })?;

        DnsLookup::new(addrs, None).ensure_non_empty(domain, port)
    }
}

const DNS_DEFAULT_TTL: Duration = Duration::from_secs(300);
const DNS_STATIC_HOST_TTL: Duration = Duration::from_secs(10);
const DNS_CACHE_MAX_ENTRIES: usize = 256;
const MAX_DNS_UDP_RESPONSE_SIZE: usize = 4096;
const DNS_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_ALIAS_DEPTH: usize = 8;

/// TTL cache over another resolver. Proxy clients open a new outbound
/// connection per session; resolving the (usually single) server domain on
/// every connect adds tens of milliseconds on mobile networks.
pub struct CachingDnsResolver {
    inner: Arc<dyn DnsResolver>,
    ttl: Duration,
    state: Mutex<DnsCacheState>,
}

#[derive(Default)]
struct DnsCacheState {
    resolved: HashMap<(String, u16), CachedDnsLookup>,
    in_flight: HashMap<(String, u16), Arc<InFlightDnsLookup>>,
    access_sequence: u64,
}

struct CachedDnsLookup {
    lookup: DnsLookup,
    expires_at: Instant,
    last_used: u64,
}

impl DnsCacheState {
    fn next_access_sequence(&mut self) -> u64 {
        self.access_sequence = self.access_sequence.wrapping_add(1);
        if self.access_sequence == 0 {
            for entry in self.resolved.values_mut() {
                entry.last_used = 0;
            }
            self.access_sequence = 1;
        }
        self.access_sequence
    }
}

struct InFlightDnsLookup {
    notify: Arc<Notify>,
    outcome: Mutex<Option<InFlightDnsOutcome>>,
}

#[derive(Clone)]
enum InFlightDnsOutcome {
    Resolved(DnsLookup),
    NeedsDns(String),
    Dns {
        domain: String,
        port: u16,
        kind: io::ErrorKind,
        message: String,
    },
    NameError(String, u16),
    NoData(String, u16),
    NoResolvedAddress(String, u16),
    Other(String),
}

impl InFlightDnsOutcome {
    fn from_result(result: &Result<DnsLookup, TransportError>) -> Self {
        match result {
            Ok(lookup) => Self::Resolved(lookup.clone()),
            Err(TransportError::NeedsDns(domain)) => Self::NeedsDns(domain.clone()),
            Err(TransportError::Dns {
                domain,
                port,
                source,
            }) => Self::Dns {
                domain: domain.clone(),
                port: *port,
                kind: source.kind(),
                message: source.to_string(),
            },
            Err(TransportError::DnsNameError(domain, port)) => {
                Self::NameError(domain.clone(), *port)
            }
            Err(TransportError::DnsNoData(domain, port)) => Self::NoData(domain.clone(), *port),
            Err(TransportError::NoResolvedAddress(domain, port)) => {
                Self::NoResolvedAddress(domain.clone(), *port)
            }
            Err(error) => Self::Other(error.to_string()),
        }
    }

    fn into_result(
        self,
        requested_domain: &str,
        requested_port: u16,
    ) -> Result<DnsLookup, TransportError> {
        match self {
            Self::Resolved(lookup) => Ok(lookup),
            Self::NeedsDns(domain) => Err(TransportError::NeedsDns(domain)),
            Self::Dns {
                domain,
                port,
                kind,
                message,
            } => Err(TransportError::Dns {
                domain,
                port,
                source: io::Error::new(kind, message),
            }),
            Self::NameError(domain, port) => Err(TransportError::DnsNameError(domain, port)),
            Self::NoData(domain, port) => Err(TransportError::DnsNoData(domain, port)),
            Self::NoResolvedAddress(domain, port) => {
                Err(TransportError::NoResolvedAddress(domain, port))
            }
            Self::Other(message) => Err(TransportError::Dns {
                domain: requested_domain.to_owned(),
                port: requested_port,
                source: io::Error::other(message),
            }),
        }
    }
}

impl InFlightDnsLookup {
    fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            outcome: Mutex::new(None),
        }
    }
}

struct InFlightDnsLeader<'a> {
    state: &'a Mutex<DnsCacheState>,
    key: (String, u16),
    lookup: Arc<InFlightDnsLookup>,
    active: bool,
}

impl InFlightDnsLeader<'_> {
    fn finish(&mut self, outcome: InFlightDnsOutcome) {
        {
            let mut stored_outcome = self
                .lookup
                .outcome
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *stored_outcome = Some(outcome.clone());
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let still_leader = state
            .in_flight
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.lookup));
        if still_leader {
            state.in_flight.remove(&self.key);
            if let InFlightDnsOutcome::Resolved(lookup) = outcome {
                let now = Instant::now();
                if let Some(ttl) = lookup.ttl().filter(|ttl| !ttl.is_zero()) {
                    if let Some(expires_at) = now.checked_add(ttl) {
                        if state.resolved.len() >= DNS_CACHE_MAX_ENTRIES {
                            state.resolved.retain(|_, entry| entry.expires_at > now);
                        }
                        if state.resolved.len() >= DNS_CACHE_MAX_ENTRIES {
                            let lru_key = state
                                .resolved
                                .iter()
                                .min_by_key(|(_, entry)| entry.last_used)
                                .map(|(key, _)| key.clone());
                            if let Some(lru_key) = lru_key {
                                state.resolved.remove(&lru_key);
                            }
                        }
                        let access_sequence = state.next_access_sequence();
                        state.resolved.insert(
                            self.key.clone(),
                            CachedDnsLookup {
                                lookup,
                                expires_at,
                                last_used: access_sequence,
                            },
                        );
                    }
                }
            }
        }
        self.active = false;
        drop(state);
        self.lookup.notify.notify_waiters();
    }
}

impl Drop for InFlightDnsLeader<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let still_leader = state
            .in_flight
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.lookup));
        if still_leader {
            state.in_flight.remove(&self.key);
        }
        drop(state);
        self.lookup.notify.notify_waiters();
    }
}

impl CachingDnsResolver {
    pub fn new(inner: Arc<dyn DnsResolver>) -> Self {
        Self::with_ttl(inner, DNS_DEFAULT_TTL)
    }

    pub fn with_ttl(inner: Arc<dyn DnsResolver>, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            state: Mutex::new(DnsCacheState::default()),
        }
    }
}

#[async_trait]
impl DnsResolver for CachingDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.resolve_all(domain, port)
            .await?
            .first_socket_addr(domain, port)
    }

    async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        let key = (
            normalize_dns_name(domain).unwrap_or_else(|| domain.to_ascii_lowercase()),
            port,
        );
        let lookup = loop {
            let now = Instant::now();
            let (waiter, leader) = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let access_sequence = state.next_access_sequence();
                if let Some(entry) = state.resolved.get_mut(&key) {
                    if entry.expires_at > now {
                        entry.last_used = access_sequence;
                        return Ok(entry
                            .lookup
                            .with_remaining_ttl(entry.expires_at.duration_since(now)));
                    }
                }
                state.resolved.remove(&key);

                match state.in_flight.get(&key) {
                    Some(lookup) => {
                        let lookup = Arc::clone(lookup);
                        let waiter = Arc::clone(&lookup.notify).notified_owned();
                        (Some((lookup, waiter)), None)
                    }
                    None => {
                        let lookup = Arc::new(InFlightDnsLookup::new());
                        state.in_flight.insert(key.clone(), Arc::clone(&lookup));
                        (None, Some(lookup))
                    }
                }
            };

            if let Some((lookup, waiter)) = waiter {
                waiter.await;
                let outcome = lookup
                    .outcome
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                match outcome {
                    Some(outcome) => return outcome.into_result(domain, port),
                    None => continue,
                }
            }

            break leader.expect("a DNS lookup without a waiter must have a leader");
        };

        let mut leader = InFlightDnsLeader {
            state: &self.state,
            key,
            lookup,
            active: true,
        };
        let resolved = self
            .inner
            .resolve_all(domain, port)
            .await
            .and_then(|lookup| lookup.ensure_non_empty(domain, port))
            .map(|lookup| lookup.with_ttl_cap(self.ttl));
        leader.finish(InFlightDnsOutcome::from_result(&resolved));
        resolved
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticHostRule {
    pub matcher: TransportDomainMatcher,
    pub target: StaticHostTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportDomainMatcher {
    Keyword(String),
    Full(String),
    Suffix(String),
    Regex(TransportRegexMatcher),
}

impl TransportDomainMatcher {
    pub fn regex(pattern: impl Into<String>) -> Result<Self, regex::Error> {
        TransportRegexMatcher::new(pattern).map(Self::Regex)
    }

    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Keyword(keyword) => contains_ignore_ascii_case(domain, keyword),
            Self::Full(expected) => domain
                .trim_end_matches('.')
                .eq_ignore_ascii_case(expected.trim_end_matches('.')),
            Self::Suffix(suffix) => {
                domain_matches_suffix(domain.trim_end_matches('.'), suffix.trim_end_matches('.'))
            }
            Self::Regex(matcher) => matcher.matches(domain),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransportRegexMatcher {
    pattern: String,
    regex: regex::Regex,
}

impl TransportRegexMatcher {
    pub fn new(pattern: impl Into<String>) -> Result<Self, regex::Error> {
        let pattern = pattern.into();
        let regex = regex::Regex::new(&pattern)?;
        Ok(Self { pattern, regex })
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    fn matches(&self, domain: &str) -> bool {
        self.regex.is_match(&domain.to_ascii_lowercase())
    }

    fn matches_lowercase(&self, domain: &str) -> bool {
        self.regex.is_match(domain)
    }
}

impl PartialEq for TransportRegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for TransportRegexMatcher {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticHostTarget {
    Ip(IpAddr),
    Ips(Vec<IpAddr>),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameServer {
    Socket(SocketAddr),
    Domain { domain: String, port: u16 },
}

/// A normalized IP network used by managed-DNS response filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsIpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl DnsIpCidr {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, DnsIpCidrError> {
        let network = canonicalize_dns_filter_ip(network);
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(DnsIpCidrError::PrefixTooLong {
                address: network,
                prefix_len,
                max_prefix,
            });
        }

        Ok(Self {
            network: normalize_ip_network(network, prefix_len),
            prefix_len,
        })
    }

    pub fn host(address: IpAddr) -> Self {
        let address = canonicalize_dns_filter_ip(address);
        Self {
            network: address,
            prefix_len: match address {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        }
    }

    pub fn network(self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, canonicalize_dns_filter_ip(address)) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = ipv4_prefix_mask(self.prefix_len);
                u32::from(address) & mask == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = ipv6_prefix_mask(self.prefix_len);
                u128::from(address) & mask == u128::from(network)
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DnsIpCidrError {
    #[error("DNS IP CIDR prefix length {prefix_len} exceeds {max_prefix} for address {address}")]
    PrefixTooLong {
        address: IpAddr,
        prefix_len: u8,
        max_prefix: u8,
    },
}

/// One portable rule in an Xray-compatible managed-DNS IP filter.
///
/// Positive rules within one category are ORed. Inverse rules within the same
/// category mean "outside every inverse network", matching Xray's optimized
/// IP-set behavior rather than ORing individual negations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsIpMatcher {
    Cidr(DnsIpCidr),
    Private,
    Not(Box<DnsIpMatcher>),
}

impl DnsIpMatcher {
    pub fn cidr(network: IpAddr, prefix_len: u8) -> Result<Self, DnsIpCidrError> {
        DnsIpCidr::new(network, prefix_len).map(Self::Cidr)
    }

    pub fn host(address: IpAddr) -> Self {
        Self::Cidr(DnsIpCidr::host(address))
    }

    pub fn inverted(self) -> Self {
        Self::Not(Box::new(self))
    }
}

/// Source form of one `expectedIPs` or `unexpectedIPs` filter.
///
/// `custom_matchers` and `geoip_matchers` are independent Xray matcher
/// categories and are ORed together. `soft` corresponds to the `*` marker:
/// the preferred subset is used only when it is non-empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsIpFilter {
    pub custom_matchers: Vec<DnsIpMatcher>,
    pub geoip_matchers: Vec<DnsIpMatcher>,
    pub soft: bool,
}

impl DnsIpFilter {
    pub fn new(
        custom_matchers: Vec<DnsIpMatcher>,
        geoip_matchers: Vec<DnsIpMatcher>,
        soft: bool,
    ) -> Self {
        Self {
            custom_matchers,
            geoip_matchers,
            soft,
        }
    }

    pub fn hard(custom_matchers: Vec<DnsIpMatcher>, geoip_matchers: Vec<DnsIpMatcher>) -> Self {
        Self::new(custom_matchers, geoip_matchers, false)
    }

    pub fn soft(custom_matchers: Vec<DnsIpMatcher>, geoip_matchers: Vec<DnsIpMatcher>) -> Self {
        Self::new(custom_matchers, geoip_matchers, true)
    }

    pub fn is_empty(&self) -> bool {
        self.custom_matchers.is_empty() && self.geoip_matchers.is_empty()
    }
}

/// Query-ready managed-DNS IP filter compiled into merged address ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDnsIpFilter {
    custom: CompiledDnsIpMatcherCategory,
    geoip: CompiledDnsIpMatcherCategory,
    soft: bool,
    matcher_count: usize,
}

impl CompiledDnsIpFilter {
    pub fn new(filter: DnsIpFilter) -> Self {
        let matcher_count = filter.custom_matchers.len() + filter.geoip_matchers.len();
        Self {
            custom: CompiledDnsIpMatcherCategory::new(filter.custom_matchers),
            geoip: CompiledDnsIpMatcherCategory::new(filter.geoip_matchers),
            soft: filter.soft,
            matcher_count,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.custom.is_empty() && self.geoip.is_empty()
    }

    pub fn is_soft(&self) -> bool {
        self.soft
    }

    /// Returns the number of source matcher entries supplied to the filter.
    ///
    /// `Private` counts as one source entry even though compilation expands it
    /// into the nine Xray private-address networks. A wrapping `Not` also does
    /// not change the source count.
    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    /// Returns the deterministic number of merged ranges retained by the
    /// query-time index across custom/GeoIP, positive/inverse, and IP-family
    /// partitions.
    pub fn compiled_range_count(&self) -> usize {
        self.custom.range_count() + self.geoip.range_count()
    }

    pub fn matches(&self, address: IpAddr) -> bool {
        self.custom.matches(address) || self.geoip.matches(address)
    }

    /// Applies this filter as `expectedIPs` and returns false when a hard
    /// filter rejects every candidate.
    pub fn apply_expected(&self, addresses: &mut Vec<IpAddr>) -> bool {
        self.retain_preferred(addresses, true)
    }

    /// Applies this filter as `unexpectedIPs` and returns false when a hard
    /// filter rejects every candidate.
    pub fn apply_unexpected(&self, addresses: &mut Vec<IpAddr>) -> bool {
        self.retain_preferred(addresses, false)
    }

    fn retain_preferred(&self, addresses: &mut Vec<IpAddr>, keep_matches: bool) -> bool {
        if self.is_empty() {
            return true;
        }
        let preferred = |address: &IpAddr| self.matches(*address) == keep_matches;
        if self.soft && !addresses.iter().any(&preferred) {
            return true;
        }
        addresses.retain(preferred);
        !addresses.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CompiledDnsIpMatcherCategory {
    positive: DnsIpRangeSet,
    inverse: DnsIpRangeSet,
}

impl CompiledDnsIpMatcherCategory {
    fn new(matchers: Vec<DnsIpMatcher>) -> Self {
        let mut positive = DnsIpRangeSetBuilder::default();
        let mut inverse = DnsIpRangeSetBuilder::default();
        for matcher in matchers {
            add_dns_ip_matcher(matcher, false, &mut positive, &mut inverse);
        }
        Self {
            positive: positive.build(),
            inverse: inverse.build(),
        }
    }

    fn is_empty(&self) -> bool {
        self.positive.is_empty() && self.inverse.is_empty()
    }

    fn range_count(&self) -> usize {
        self.positive.range_count() + self.inverse.range_count()
    }

    fn matches(&self, address: IpAddr) -> bool {
        self.positive.contains(address)
            || self.inverse.supports_family(address) && !self.inverse.contains(address)
    }
}

fn add_dns_ip_matcher(
    matcher: DnsIpMatcher,
    inverted: bool,
    positive: &mut DnsIpRangeSetBuilder,
    inverse: &mut DnsIpRangeSetBuilder,
) {
    match matcher {
        DnsIpMatcher::Cidr(cidr) => {
            if inverted {
                inverse.insert(cidr);
            } else {
                positive.insert(cidr);
            }
        }
        DnsIpMatcher::Private => {
            for cidr in private_dns_ip_cidrs() {
                if inverted {
                    inverse.insert(cidr);
                } else {
                    positive.insert(cidr);
                }
            }
        }
        DnsIpMatcher::Not(matcher) => {
            add_dns_ip_matcher(*matcher, !inverted, positive, inverse);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Range {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv6Range {
    start: u128,
    end: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DnsIpRangeSet {
    ipv4: Box<[Ipv4Range]>,
    ipv6: Box<[Ipv6Range]>,
}

impl DnsIpRangeSet {
    fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    fn range_count(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }

    fn supports_family(&self, address: IpAddr) -> bool {
        match canonicalize_dns_filter_ip(address) {
            IpAddr::V4(_) => !self.ipv4.is_empty(),
            IpAddr::V6(_) => !self.ipv6.is_empty(),
        }
    }

    fn contains(&self, address: IpAddr) -> bool {
        match canonicalize_dns_filter_ip(address) {
            IpAddr::V4(address) => {
                let address = u32::from(address);
                let insertion = self.ipv4.partition_point(|range| range.start <= address);
                insertion > 0 && address <= self.ipv4[insertion - 1].end
            }
            IpAddr::V6(address) => {
                let address = u128::from(address);
                let insertion = self.ipv6.partition_point(|range| range.start <= address);
                insertion > 0 && address <= self.ipv6[insertion - 1].end
            }
        }
    }
}

#[derive(Default)]
struct DnsIpRangeSetBuilder {
    ipv4: Vec<Ipv4Range>,
    ipv6: Vec<Ipv6Range>,
}

impl DnsIpRangeSetBuilder {
    fn insert(&mut self, cidr: DnsIpCidr) {
        match cidr.network {
            IpAddr::V4(network) => {
                let mask = ipv4_prefix_mask(cidr.prefix_len);
                let start = u32::from(network) & mask;
                self.ipv4.push(Ipv4Range {
                    start,
                    end: start | !mask,
                });
            }
            IpAddr::V6(network) => {
                let mask = ipv6_prefix_mask(cidr.prefix_len);
                let start = u128::from(network) & mask;
                self.ipv6.push(Ipv6Range {
                    start,
                    end: start | !mask,
                });
            }
        }
    }

    fn build(mut self) -> DnsIpRangeSet {
        merge_ipv4_ranges(&mut self.ipv4);
        merge_ipv6_ranges(&mut self.ipv6);
        DnsIpRangeSet {
            ipv4: self.ipv4.into_boxed_slice(),
            ipv6: self.ipv6.into_boxed_slice(),
        }
    }
}

fn merge_ipv4_ranges(ranges: &mut Vec<Ipv4Range>) {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut write = 0;
    for read in 0..ranges.len() {
        let current = ranges[read];
        if write > 0 && current.start <= ranges[write - 1].end.saturating_add(1) {
            ranges[write - 1].end = ranges[write - 1].end.max(current.end);
        } else {
            ranges[write] = current;
            write += 1;
        }
    }
    ranges.truncate(write);
}

fn merge_ipv6_ranges(ranges: &mut Vec<Ipv6Range>) {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut write = 0;
    for read in 0..ranges.len() {
        let current = ranges[read];
        if write > 0 && current.start <= ranges[write - 1].end.saturating_add(1) {
            ranges[write - 1].end = ranges[write - 1].end.max(current.end);
        } else {
            ranges[write] = current;
            write += 1;
        }
    }
    ranges.truncate(write);
}

fn normalize_ip_network(network: IpAddr, prefix_len: u8) -> IpAddr {
    match network {
        IpAddr::V4(network) => IpAddr::V4(Ipv4Addr::from(
            u32::from(network) & ipv4_prefix_mask(prefix_len),
        )),
        IpAddr::V6(network) => IpAddr::V6(Ipv6Addr::from(
            u128::from(network) & ipv6_prefix_mask(prefix_len),
        )),
    }
}

fn ipv4_prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn ipv6_prefix_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

fn canonicalize_dns_filter_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn private_dns_ip_cidrs() -> [DnsIpCidr; 9] {
    [
        DnsIpCidr {
            network: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 8,
        },
        DnsIpCidr {
            network: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
            prefix_len: 10,
        },
        DnsIpCidr {
            network: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            prefix_len: 8,
        },
        DnsIpCidr {
            network: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
            prefix_len: 16,
        },
        DnsIpCidr {
            network: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
            prefix_len: 12,
        },
        DnsIpCidr {
            network: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix_len: 16,
        },
        DnsIpCidr {
            network: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix_len: 128,
        },
        DnsIpCidr {
            network: IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
            prefix_len: 7,
        },
        DnsIpCidr {
            network: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
            prefix_len: 10,
        },
    ]
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DnsQueryStrategy {
    #[default]
    UseIp,
    UseIpv4,
    UseIpv6,
}

impl DnsQueryStrategy {
    fn accepts(self, ip: IpAddr) -> bool {
        match self {
            Self::UseIp => true,
            Self::UseIpv4 => match ip {
                IpAddr::V4(_) => true,
                IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().is_some(),
            },
            Self::UseIpv6 => match ip {
                IpAddr::V4(_) => false,
                IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().is_none(),
            },
        }
    }

    fn intersect(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::UseIp, strategy) | (strategy, Self::UseIp) => Some(strategy),
            (Self::UseIpv4, Self::UseIpv4) => Some(Self::UseIpv4),
            (Self::UseIpv6, Self::UseIpv6) => Some(Self::UseIpv6),
            (Self::UseIpv4, Self::UseIpv6) | (Self::UseIpv6, Self::UseIpv4) => None,
        }
    }
}

/// Wire transport used for a DNS query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryTransportKind {
    Udp,
    Tcp,
}

/// Exchanges already encoded DNS messages with a configured name server.
///
/// `ConfiguredDnsResolver` remains responsible for query construction,
/// response validation, A/AAAA/CNAME handling, failover, and TCP retry. This
/// boundary lets an embedding runtime route the exchange through a proxy
/// without duplicating the DNS wire codec. UDP implementations must discard
/// unrelated datagrams and return only a response whose envelope matches the
/// supplied query; [`dns_response_matches_query`] implements that check.
#[async_trait]
pub trait DnsQueryTransport: Send + Sync {
    async fn exchange(
        &self,
        server: &NameServer,
        transport: DnsQueryTransportKind,
        query: &[u8],
    ) -> io::Result<Vec<u8>>;
}

struct DirectDnsQueryTransport {
    bootstrap_resolver: Arc<dyn DnsResolver>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
}

impl DirectDnsQueryTransport {
    fn new(
        bootstrap_resolver: Arc<dyn DnsResolver>,
        socket_protector: Option<Arc<dyn SocketProtector>>,
    ) -> Self {
        Self {
            bootstrap_resolver,
            socket_protector,
        }
    }

    async fn server_addr(&self, server: &NameServer) -> io::Result<SocketAddr> {
        match server {
            NameServer::Socket(addr) => Ok(*addr),
            NameServer::Domain { domain, port } => self
                .bootstrap_resolver
                .resolve(domain, *port)
                .await
                .map_err(io::Error::other),
        }
    }
}

#[async_trait]
impl DnsQueryTransport for DirectDnsQueryTransport {
    async fn exchange(
        &self,
        server: &NameServer,
        transport: DnsQueryTransportKind,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let server_addr = self.server_addr(server).await?;
        match transport {
            DnsQueryTransportKind::Udp => {
                exchange_direct_udp(server_addr, query, self.socket_protector.as_deref()).await
            }
            DnsQueryTransportKind::Tcp => {
                exchange_direct_tcp(server_addr, query, self.socket_protector.as_deref()).await
            }
        }
    }
}

/// One configured DNS client together with its Xray selection policy.
///
/// Multiple entries may intentionally point at the same endpoint: selection
/// and failover operate on entries, not on deduplicated socket addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameServerPolicy {
    pub server: NameServer,
    pub domains: Vec<TransportDomainMatcher>,
    pub expected_ips: DnsIpFilter,
    pub unexpected_ips: DnsIpFilter,
    pub skip_fallback: bool,
    pub query_strategy: DnsQueryStrategy,
    pub final_query: bool,
    /// Overrides the resolver's default wall-clock budget for this client.
    pub timeout: Option<Duration>,
}

impl NameServerPolicy {
    pub fn new(server: NameServer) -> Self {
        Self {
            server,
            domains: Vec::new(),
            expected_ips: DnsIpFilter::default(),
            unexpected_ips: DnsIpFilter::default(),
            skip_fallback: false,
            query_strategy: DnsQueryStrategy::UseIp,
            final_query: false,
            timeout: None,
        }
    }
}

/// A compact, query-ready set of configured DNS server policies.
///
/// Construction consumes the source policies and compiles their domain rules
/// once. Full-name rules use a hash set, suffix rules use a label trie, while
/// uncommon keyword and regular-expression rules retain their Xray-compatible
/// linear semantics. The compiled set preserves configured server indices and
/// therefore remains suitable for duplicate endpoints and `finalQuery`.
#[derive(Debug, Default)]
pub struct CompiledNameServerPolicies {
    policies: Vec<CompiledNameServerPolicy>,
    matcher_count: usize,
    pattern_bytes: usize,
}

impl CompiledNameServerPolicies {
    pub fn new(policies: Vec<NameServerPolicy>) -> Self {
        let mut matcher_count = 0;
        let mut pattern_bytes = 0;
        let policies = policies
            .into_iter()
            .map(|policy| {
                let NameServerPolicy {
                    server,
                    domains,
                    expected_ips,
                    unexpected_ips,
                    skip_fallback,
                    query_strategy,
                    final_query,
                    timeout,
                } = policy;
                matcher_count += domains.len();
                let domains = CompiledDomainMatcherSet::new(domains);
                pattern_bytes += domains.pattern_bytes();
                CompiledNameServerPolicy {
                    server,
                    domains,
                    expected_ips: compile_dns_ip_filter(expected_ips),
                    unexpected_ips: compile_dns_ip_filter(unexpected_ips),
                    skip_fallback,
                    query_strategy,
                    final_query,
                    timeout,
                }
            })
            .collect();
        Self {
            policies,
            matcher_count,
            pattern_bytes,
        }
    }

    pub fn len(&self) -> usize {
        self.policies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Returns the configured endpoint at a selected policy index.
    pub fn name_server(&self, index: usize) -> Option<&NameServer> {
        self.policies.get(index).map(|policy| &policy.server)
    }

    /// Returns the configured timeout override at a selected policy index.
    pub fn timeout(&self, index: usize) -> Option<Duration> {
        self.policies.get(index).and_then(|policy| policy.timeout)
    }

    /// Returns the number of source domain-matcher entries compiled into this set.
    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    /// Returns the matcher-pattern payload retained by the compact set.
    ///
    /// This intentionally excludes allocator and regex-engine overhead, so it
    /// is a deterministic payload metric rather than a process-RSS estimate.
    pub fn pattern_bytes(&self) -> usize {
        self.pattern_bytes
    }

    /// Builds the serial candidate plan with Xray's match/fallback ordering.
    pub fn select_indices(
        &self,
        domain: &str,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
    ) -> Vec<usize> {
        let domain = lowercase_ascii(domain);
        let mut selected = Vec::with_capacity(self.policies.len());
        let mut selected_policies = SelectedPolicyTracker::new(self.policies.len());
        let mut matched = false;

        for (index, policy) in self.policies.iter().enumerate() {
            if !policy.domains.matches(&domain) {
                continue;
            }
            matched = true;
            selected_policies.insert(index);
            selected.push(index);
            if policy.final_query {
                return selected;
            }
        }

        if !(disable_fallback || disable_fallback_if_match && matched) {
            for (index, policy) in self.policies.iter().enumerate() {
                if selected_policies.contains(index) || policy.skip_fallback {
                    continue;
                }
                selected_policies.insert(index);
                selected.push(index);
                if policy.final_query {
                    break;
                }
            }
        }

        if selected.is_empty() && !self.policies.is_empty() {
            selected.push(0);
        }
        selected
    }

    fn get(&self, index: usize) -> Option<&CompiledNameServerPolicy> {
        self.policies.get(index)
    }
}

#[derive(Debug)]
struct CompiledNameServerPolicy {
    server: NameServer,
    domains: CompiledDomainMatcherSet,
    expected_ips: Option<CompiledDnsIpFilter>,
    unexpected_ips: Option<CompiledDnsIpFilter>,
    skip_fallback: bool,
    query_strategy: DnsQueryStrategy,
    final_query: bool,
    timeout: Option<Duration>,
}

impl CompiledNameServerPolicy {
    fn apply_ip_filters(&self, addresses: &mut Vec<IpAddr>) -> bool {
        // Xray applies both mandatory filters before either preference filter.
        // The mixed-mode ordering is observable when one filter removes the
        // only subset preferred by the other.
        if self
            .expected_ips
            .as_ref()
            .filter(|filter| !filter.is_soft())
            .is_some_and(|filter| !filter.apply_expected(addresses))
        {
            return false;
        }
        if self
            .unexpected_ips
            .as_ref()
            .filter(|filter| !filter.is_soft())
            .is_some_and(|filter| !filter.apply_unexpected(addresses))
        {
            return false;
        }
        if self
            .expected_ips
            .as_ref()
            .filter(|filter| filter.is_soft())
            .is_some_and(|filter| !filter.apply_expected(addresses))
        {
            return false;
        }
        if self
            .unexpected_ips
            .as_ref()
            .filter(|filter| filter.is_soft())
            .is_some_and(|filter| !filter.apply_unexpected(addresses))
        {
            return false;
        }
        true
    }
}

fn compile_dns_ip_filter(filter: DnsIpFilter) -> Option<CompiledDnsIpFilter> {
    let compiled = CompiledDnsIpFilter::new(filter);
    (!compiled.is_empty()).then_some(compiled)
}

#[derive(Debug, Default)]
struct CompiledDomainMatcherSet {
    full: HashSet<Box<str>>,
    suffix: DomainSuffixTrie,
    matches_empty_suffix: bool,
    keywords: Vec<Box<str>>,
    regex: Vec<TransportRegexMatcher>,
}

impl CompiledDomainMatcherSet {
    fn new(matchers: Vec<TransportDomainMatcher>) -> Self {
        let mut compiled = Self::default();
        for matcher in matchers {
            match matcher {
                TransportDomainMatcher::Keyword(mut keyword) => {
                    keyword.make_ascii_lowercase();
                    compiled.keywords.push(keyword.into_boxed_str());
                }
                TransportDomainMatcher::Full(mut domain) => {
                    domain.truncate(domain.trim_end_matches('.').len());
                    domain.make_ascii_lowercase();
                    compiled.full.insert(domain.into_boxed_str());
                }
                TransportDomainMatcher::Suffix(mut suffix) => {
                    suffix.truncate(suffix.trim_end_matches('.').len());
                    suffix.make_ascii_lowercase();
                    if suffix.is_empty() {
                        compiled.matches_empty_suffix = true;
                    } else {
                        compiled.suffix.insert(&suffix);
                    }
                }
                TransportDomainMatcher::Regex(regex) => compiled.regex.push(regex),
            }
        }
        compiled
    }

    fn matches(&self, lowercase_domain: &str) -> bool {
        let normalized = lowercase_domain.trim_end_matches('.');
        self.full.contains(normalized)
            || self.matches_empty_suffix && normalized.is_empty()
            || self.suffix.matches(normalized)
            || self
                .keywords
                .iter()
                .any(|keyword| lowercase_domain.contains(keyword.as_ref()))
            || self
                .regex
                .iter()
                .any(|regex| regex.matches_lowercase(lowercase_domain))
    }

    fn pattern_bytes(&self) -> usize {
        self.full.iter().map(|pattern| pattern.len()).sum::<usize>()
            + self.suffix.pattern_bytes
            + self
                .keywords
                .iter()
                .map(|pattern| pattern.len())
                .sum::<usize>()
            + self
                .regex
                .iter()
                .map(|matcher| matcher.pattern().len())
                .sum::<usize>()
    }
}

#[derive(Debug, Default)]
struct DomainSuffixTrie {
    nodes: Vec<DomainSuffixTrieNode>,
    pattern_bytes: usize,
}

impl DomainSuffixTrie {
    fn insert(&mut self, suffix: &str) {
        if suffix.is_empty() {
            return;
        }
        if self.nodes.is_empty() {
            self.nodes.push(DomainSuffixTrieNode::default());
        }
        let mut node_index = 0;
        for label in suffix.rsplit('.') {
            let next = self.nodes[node_index].children.get(label).copied();
            node_index = match next {
                Some(next) => next,
                None => {
                    let next = self.nodes.len();
                    self.nodes.push(DomainSuffixTrieNode::default());
                    self.nodes[node_index]
                        .children
                        .insert(label.to_owned().into_boxed_str(), next);
                    self.pattern_bytes += label.len();
                    next
                }
            };
        }
        self.nodes[node_index].matched = true;
    }

    fn matches(&self, domain: &str) -> bool {
        if self.nodes.is_empty() {
            return false;
        }
        let mut node_index = 0;
        for label in domain.rsplit('.') {
            let Some(next) = self.nodes[node_index].children.get(label).copied() else {
                return false;
            };
            node_index = next;
            if self.nodes[node_index].matched {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Default)]
struct DomainSuffixTrieNode {
    matched: bool,
    children: HashMap<Box<str>, usize>,
}

fn lowercase_ascii(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

enum SelectedPolicyTracker {
    Small(u64),
    Large(Vec<u64>),
}

impl SelectedPolicyTracker {
    fn new(policy_count: usize) -> Self {
        if policy_count <= u64::BITS as usize {
            Self::Small(0)
        } else {
            Self::Large(vec![0; policy_count.div_ceil(u64::BITS as usize)])
        }
    }

    fn insert(&mut self, index: usize) {
        let word_index = index / u64::BITS as usize;
        let bit = 1_u64 << (index % u64::BITS as usize);
        match self {
            Self::Small(bits) => *bits |= bit,
            Self::Large(words) => words[word_index] |= bit,
        }
    }

    fn contains(&self, index: usize) -> bool {
        let word_index = index / u64::BITS as usize;
        let bit = 1_u64 << (index % u64::BITS as usize);
        match self {
            Self::Small(bits) => *bits & bit != 0,
            Self::Large(words) => words[word_index] & bit != 0,
        }
    }
}

pub struct ConfiguredDnsResolver {
    host_rules: Vec<StaticHostRule>,
    name_servers: Arc<CompiledNameServerPolicies>,
    fallback: Arc<dyn DnsResolver>,
    server_timeout: Duration,
    system_fallback_timeout: Option<Duration>,
    resolution_timeout: Option<Duration>,
    query_transport: Arc<dyn DnsQueryTransport>,
    uses_direct_query_transport: bool,
    query_strategy: DnsQueryStrategy,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
}

impl ConfiguredDnsResolver {
    pub fn new(
        host_rules: Vec<StaticHostRule>,
        name_servers: Vec<NameServer>,
        fallback: Arc<dyn DnsResolver>,
    ) -> Self {
        let query_transport = Arc::new(DirectDnsQueryTransport::new(Arc::clone(&fallback), None));
        Self {
            host_rules,
            name_servers: Arc::new(CompiledNameServerPolicies::new(
                name_servers
                    .into_iter()
                    .map(NameServerPolicy::new)
                    .collect(),
            )),
            fallback,
            server_timeout: Duration::from_secs(4),
            system_fallback_timeout: Some(DNS_RESOLUTION_TIMEOUT),
            resolution_timeout: None,
            query_transport,
            uses_direct_query_transport: true,
            query_strategy: DnsQueryStrategy::default(),
            disable_fallback: false,
            disable_fallback_if_match: false,
        }
    }

    pub fn with_name_server_policies(mut self, name_servers: Vec<NameServerPolicy>) -> Self {
        self.name_servers = Arc::new(CompiledNameServerPolicies::new(name_servers));
        self
    }

    /// Reuses an already compiled policy set across resolvers with different
    /// DNS query transports (for example, multiple inbound routing contexts).
    pub fn with_name_server_policy_set(
        mut self,
        name_servers: Arc<CompiledNameServerPolicies>,
    ) -> Self {
        self.name_servers = name_servers;
        self
    }

    pub fn with_name_server_fallback_policy(
        mut self,
        disable_fallback: bool,
        disable_fallback_if_match: bool,
    ) -> Self {
        self.disable_fallback = disable_fallback;
        self.disable_fallback_if_match = disable_fallback_if_match;
        self
    }

    pub fn with_query_strategy(mut self, query_strategy: DnsQueryStrategy) -> Self {
        self.query_strategy = query_strategy;
        self
    }

    pub fn with_server_timeout(mut self, timeout: Duration) -> Self {
        self.server_timeout = timeout;
        self
    }

    /// Leaves system fallback timing to the surrounding operation.
    ///
    /// This is intended for non-recursive endpoint bootstrap performed inside
    /// an already bounded configured-server attempt.
    pub fn without_system_fallback_timeout(mut self) -> Self {
        self.system_fallback_timeout = None;
        self
    }

    pub fn with_resolution_timeout(mut self, timeout: Duration) -> Self {
        self.resolution_timeout = Some(timeout);
        self
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        if self.uses_direct_query_transport {
            self.query_transport = Arc::new(DirectDnsQueryTransport::new(
                Arc::clone(&self.fallback),
                Some(protector),
            ));
        }
        self
    }

    pub fn with_query_transport(mut self, transport: Arc<dyn DnsQueryTransport>) -> Self {
        self.query_transport = transport;
        self.uses_direct_query_transport = false;
        self
    }

    fn matching_host_rule(&self, domain: &str) -> Option<&StaticHostRule> {
        self.host_rules
            .iter()
            .find(|rule| {
                matches!(&rule.matcher, TransportDomainMatcher::Full(_))
                    && rule.matcher.matches(domain)
            })
            .or_else(|| {
                self.host_rules
                    .iter()
                    .find(|rule| rule.matcher.matches(domain))
            })
    }

    async fn query_configured_servers(
        &self,
        domain: &str,
        selected_servers: &[usize],
    ) -> ConfiguredServersResult {
        let mut last_negative = None;
        for &index in selected_servers {
            let Some(name_server) = self.name_servers.get(index) else {
                continue;
            };
            let deadline =
                time::sleep(name_server.timeout.unwrap_or(self.server_timeout)).deadline();
            let mut current_domain = domain.to_owned();
            let mut cname_ttl_cap = None;
            for depth in 0..MAX_DNS_ALIAS_DEPTH {
                let started_at = Instant::now();
                let result = self
                    .query_configured_server(name_server, &current_domain, deadline)
                    .await;
                cname_ttl_cap = age_ttl_cap(cname_ttl_cap, started_at.elapsed());
                match result {
                    Ok(ConfiguredServerResult::Answer(ConfiguredDnsAnswer::Addresses(
                        mut answer,
                    ))) => {
                        if let Some(ttl_cap) = cname_ttl_cap {
                            answer.ttl = answer.ttl.min(ttl_cap);
                        }
                        return ConfiguredServersResult::Answer(answer);
                    }
                    Ok(ConfiguredServerResult::Answer(ConfiguredDnsAnswer::Cname {
                        alias,
                        ttl,
                    })) => {
                        cname_ttl_cap =
                            Some(cname_ttl_cap.map_or(ttl, |current: Duration| current.min(ttl)));
                        let alias = normalize_dns_name(&alias).unwrap_or(alias);
                        if alias == current_domain || depth + 1 == MAX_DNS_ALIAS_DEPTH {
                            last_negative = Some(ConfiguredDnsNegative::NoData);
                            break;
                        }
                        current_domain = alias;
                    }
                    Ok(ConfiguredServerResult::Negative(negative)) => {
                        last_negative = Some(negative);
                        break;
                    }
                    Err(_) => {
                        if cname_ttl_cap.is_some() {
                            last_negative = Some(ConfiguredDnsNegative::NoData);
                        }
                        break;
                    }
                }
            }
        }

        last_negative.map_or(
            ConfiguredServersResult::Unavailable,
            ConfiguredServersResult::Negative,
        )
    }

    async fn query_configured_server(
        &self,
        name_server: &CompiledNameServerPolicy,
        domain: &str,
        deadline: time::Instant,
    ) -> io::Result<ConfiguredServerResult> {
        let Some(query_strategy) = self.query_strategy.intersect(name_server.query_strategy) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dns server query strategy has no address family in common with the global strategy",
            ));
        };
        let result = match query_strategy {
            DnsQueryStrategy::UseIp => {
                let (ipv4, ipv6) = tokio::join!(
                    self.query_server_until(
                        &name_server.server,
                        domain,
                        DnsRecordType::A,
                        deadline,
                    ),
                    self.query_server_until(
                        &name_server.server,
                        domain,
                        DnsRecordType::Aaaa,
                        deadline,
                    ),
                );
                merge_configured_family_results([ipv4, ipv6])
            }
            DnsQueryStrategy::UseIpv4 => merge_configured_family_results([self
                .query_server_until(&name_server.server, domain, DnsRecordType::A, deadline)
                .await]),
            DnsQueryStrategy::UseIpv6 => merge_configured_family_results([self
                .query_server_until(&name_server.server, domain, DnsRecordType::Aaaa, deadline)
                .await]),
        }?;

        match result {
            ConfiguredServerResult::Answer(ConfiguredDnsAnswer::Addresses(mut answer)) => {
                if name_server.apply_ip_filters(&mut answer.addresses) {
                    Ok(ConfiguredServerResult::Answer(
                        ConfiguredDnsAnswer::Addresses(answer),
                    ))
                } else {
                    Ok(ConfiguredServerResult::Negative(
                        ConfiguredDnsNegative::NoData,
                    ))
                }
            }
            result => Ok(result),
        }
    }

    async fn query_server_until(
        &self,
        name_server: &NameServer,
        domain: &str,
        record_type: DnsRecordType,
        deadline: time::Instant,
    ) -> io::Result<(ParsedDnsResponse, Instant)> {
        let query = build_dns_query(domain, record_type)?;
        let response = time::timeout_at(
            deadline,
            self.query_transport
                .exchange(name_server, DnsQueryTransportKind::Udp, &query),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns query timed out"))??;
        let observed_at = Instant::now();

        match parse_dns_response(&query, &response, record_type)? {
            response @ (ParsedDnsResponse::Answer(_)
            | ParsedDnsResponse::NoData
            | ParsedDnsResponse::NameError
            | ParsedDnsResponse::ServerFailure(_)) => Ok((response, observed_at)),
            ParsedDnsResponse::Truncated => {
                let response = time::timeout_at(
                    deadline,
                    self.query_transport
                        .exchange(name_server, DnsQueryTransportKind::Tcp, &query),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "dns tcp retry timed out")
                })??;
                let observed_at = Instant::now();
                match parse_dns_response(&query, &response, record_type)? {
                    ParsedDnsResponse::Truncated => Err(invalid_dns_response(
                        "DNS TCP response must not remain truncated",
                    )),
                    response => Ok((response, observed_at)),
                }
            }
        }
    }

    async fn resolve_configured(&self, domain: &str, port: u16) -> ConfiguredLookupResult {
        let mut current_domain = normalize_dns_name(domain).unwrap_or_else(|| domain.to_owned());
        let mut ttl_cap = None;
        for depth in 0..MAX_DNS_ALIAS_DEPTH {
            if let Some(rule) = self.matching_host_rule(&current_domain) {
                match &rule.target {
                    StaticHostTarget::Ip(ip) => {
                        if !self.query_strategy.accepts(*ip) {
                            return ConfiguredLookupResult::Negative {
                                domain: current_domain,
                                negative: ConfiguredDnsNegative::NoData,
                            };
                        }
                        return ConfiguredLookupResult::Resolved(cap_lookup_ttl(
                            DnsLookup::single(
                                SocketAddr::new(*ip, port),
                                Some(DNS_STATIC_HOST_TTL),
                            ),
                            ttl_cap,
                        ));
                    }
                    StaticHostTarget::Ips(ips) => {
                        if !ips
                            .iter()
                            .copied()
                            .any(|ip| self.query_strategy.accepts(ip))
                        {
                            return ConfiguredLookupResult::Negative {
                                domain: current_domain,
                                negative: ConfiguredDnsNegative::NoData,
                            };
                        }
                        return ConfiguredLookupResult::Resolved(cap_lookup_ttl(
                            DnsLookup::from_ips(
                                ips.iter()
                                    .copied()
                                    .filter(|ip| self.query_strategy.accepts(*ip)),
                                port,
                                Some(DNS_STATIC_HOST_TTL),
                            ),
                            ttl_cap,
                        ));
                    }
                    StaticHostTarget::Domain(alias) => {
                        let alias = normalize_dns_name(alias).unwrap_or_else(|| alias.clone());
                        if alias == current_domain {
                            break;
                        }
                        if depth + 1 == MAX_DNS_ALIAS_DEPTH {
                            return ConfiguredLookupResult::Fallback {
                                domain: domain.to_owned(),
                                ttl_cap,
                            };
                        }
                        current_domain = alias;
                        continue;
                    }
                }
            }

            let started_at = Instant::now();
            let server_plan = self.name_servers.select_indices(
                &current_domain,
                self.disable_fallback,
                self.disable_fallback_if_match,
            );
            let result = self
                .query_configured_servers(&current_domain, &server_plan)
                .await;
            ttl_cap = age_ttl_cap(ttl_cap, started_at.elapsed());
            match result {
                ConfiguredServersResult::Answer(answer) => {
                    let lookup = DnsLookup::from_ips(
                        answer
                            .addresses
                            .into_iter()
                            .filter(|ip| self.query_strategy.accepts(*ip)),
                        port,
                        Some(answer.ttl),
                    );
                    if lookup.socket_addrs().is_empty() {
                        return ConfiguredLookupResult::Negative {
                            domain: current_domain,
                            negative: ConfiguredDnsNegative::NoData,
                        };
                    }
                    return ConfiguredLookupResult::Resolved(cap_lookup_ttl(lookup, ttl_cap));
                }
                ConfiguredServersResult::Negative(negative) => {
                    return ConfiguredLookupResult::Negative {
                        domain: current_domain,
                        negative,
                    };
                }
                ConfiguredServersResult::Unavailable => {
                    if self.name_servers.is_empty() {
                        break;
                    }
                    return ConfiguredLookupResult::Unavailable {
                        domain: current_domain,
                    };
                }
            }
        }

        if self.name_servers.is_empty() {
            ConfiguredLookupResult::Fallback {
                domain: current_domain,
                ttl_cap,
            }
        } else {
            ConfiguredLookupResult::Unavailable {
                domain: current_domain,
            }
        }
    }
}

/// Builds the serial managed-DNS candidate plan using Xray's match/fallback
/// ordering. Returned indices refer to `name_servers` and preserve policy
/// entries even when multiple entries share one endpoint.
pub fn select_name_server_indices(
    name_servers: &[NameServerPolicy],
    domain: &str,
    disable_fallback: bool,
    disable_fallback_if_match: bool,
) -> Vec<usize> {
    let mut selected = Vec::with_capacity(name_servers.len());
    let mut selected_policies = SelectedPolicyTracker::new(name_servers.len());
    let mut matched = false;

    for (index, name_server) in name_servers.iter().enumerate() {
        if !name_server
            .domains
            .iter()
            .any(|matcher| matcher.matches(domain))
        {
            continue;
        }
        matched = true;
        selected_policies.insert(index);
        selected.push(index);
        if name_server.final_query {
            return selected;
        }
    }

    if !(disable_fallback || disable_fallback_if_match && matched) {
        for (index, name_server) in name_servers.iter().enumerate() {
            if selected_policies.contains(index) || name_server.skip_fallback {
                continue;
            }
            selected_policies.insert(index);
            selected.push(index);
            if name_server.final_query {
                break;
            }
        }
    }

    if selected.is_empty() && !name_servers.is_empty() {
        selected.push(0);
    }
    selected
}

fn cap_lookup_ttl(lookup: DnsLookup, ttl_cap: Option<Duration>) -> DnsLookup {
    match ttl_cap {
        Some(ttl_cap) => lookup.with_ttl_cap(ttl_cap),
        None => lookup,
    }
}

fn age_ttl_cap(ttl_cap: Option<Duration>, elapsed: Duration) -> Option<Duration> {
    ttl_cap.map(|ttl| ttl.saturating_sub(elapsed))
}

fn merge_configured_family_results<const N: usize>(
    results: [io::Result<(ParsedDnsResponse, Instant)>; N],
) -> io::Result<ConfiguredServerResult> {
    let mut addresses = Vec::new();
    let mut answer_ttl = None;
    let mut cname: Option<(String, Duration)> = None;
    let mut cname_conflict = false;
    let mut saw_name_error = false;
    let mut saw_no_data = false;
    let mut last_error = None;

    for result in results {
        match result {
            Ok((
                ParsedDnsResponse::Answer(ConfiguredDnsAnswer::Addresses(mut answer)),
                observed_at,
            )) => {
                answer.ttl = answer.ttl.saturating_sub(observed_at.elapsed());
                addresses.extend_from_slice(&answer.addresses);
                answer_ttl = Some(
                    answer_ttl.map_or(answer.ttl, |current: Duration| current.min(answer.ttl)),
                );
            }
            Ok((
                ParsedDnsResponse::Answer(ConfiguredDnsAnswer::Cname { alias, ttl }),
                observed_at,
            )) => {
                let ttl = ttl.saturating_sub(observed_at.elapsed());
                answer_ttl = Some(answer_ttl.map_or(ttl, |current: Duration| current.min(ttl)));
                match &cname {
                    Some((current, _)) if !alias.eq_ignore_ascii_case(current) => {
                        cname_conflict = true;
                    }
                    Some(_) => {}
                    None => cname = Some((alias, ttl)),
                }
            }
            Ok((ParsedDnsResponse::NoData, _)) => saw_no_data = true,
            Ok((ParsedDnsResponse::NameError, _)) => saw_name_error = true,
            Ok((ParsedDnsResponse::ServerFailure(code), _)) => {
                last_error = Some(dns_response_code_error(code));
            }
            Ok((ParsedDnsResponse::Truncated, _)) => {
                last_error = Some(invalid_dns_response(
                    "truncated DNS response after TCP retry",
                ));
            }
            Err(error) => last_error = Some(error),
        }
    }

    if !addresses.is_empty() {
        return Ok(ConfiguredServerResult::Answer(
            ConfiguredDnsAnswer::Addresses(ConfiguredDnsAddresses {
                addresses,
                ttl: answer_ttl.unwrap_or(DNS_DEFAULT_TTL),
            }),
        ));
    }
    if cname_conflict {
        return Err(invalid_dns_response(
            "DNS A and AAAA responses contain conflicting CNAME targets",
        ));
    }
    if let Some((alias, ttl)) = cname {
        return Ok(ConfiguredServerResult::Answer(ConfiguredDnsAnswer::Cname {
            alias,
            ttl: answer_ttl.unwrap_or(ttl),
        }));
    }
    if saw_name_error {
        return Ok(ConfiguredServerResult::Negative(
            ConfiguredDnsNegative::NameError,
        ));
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    if saw_no_data {
        return Ok(ConfiguredServerResult::Negative(
            ConfiguredDnsNegative::NoData,
        ));
    }

    Err(invalid_dns_response("DNS server returned no family result"))
}

#[async_trait]
impl DnsResolver for ConfiguredDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.resolve_all(domain, port)
            .await?
            .first_socket_addr(domain, port)
    }

    async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        let resolution = async {
            match self.resolve_configured(domain, port).await {
                ConfiguredLookupResult::Resolved(lookup) => Ok(lookup),
                ConfiguredLookupResult::Fallback { domain, ttl_cap } => {
                    let started_at = Instant::now();
                    let fallback = self.fallback.resolve_all(&domain, port);
                    let result = match (self.resolution_timeout, self.system_fallback_timeout) {
                        (None, Some(fallback_timeout)) => time::timeout(fallback_timeout, fallback)
                            .await
                            .unwrap_or_else(|_| {
                                Err(TransportError::Dns {
                                    domain: domain.clone(),
                                    port,
                                    source: io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        "DNS system fallback timed out",
                                    ),
                                })
                            }),
                        (Some(_), _) | (None, None) => fallback.await,
                    };
                    result
                        .map(|lookup| {
                            cap_lookup_ttl(lookup, age_ttl_cap(ttl_cap, started_at.elapsed()))
                        })
                        .and_then(|lookup| match self.query_strategy {
                            DnsQueryStrategy::UseIp => lookup.ensure_non_empty(&domain, port),
                            DnsQueryStrategy::UseIpv4 | DnsQueryStrategy::UseIpv6 => {
                                let ttl = lookup.ttl();
                                DnsLookup::new(
                                    lookup.socket_addrs().iter().copied().filter(|address| {
                                        self.query_strategy.accepts(address.ip())
                                    }),
                                    ttl,
                                )
                                .ensure_non_empty(&domain, port)
                                .map_err(|_| TransportError::DnsNoData(domain, port))
                            }
                        })
                }
                ConfiguredLookupResult::Negative {
                    domain,
                    negative: ConfiguredDnsNegative::NameError,
                } => Err(TransportError::DnsNameError(domain, port)),
                ConfiguredLookupResult::Negative {
                    domain,
                    negative: ConfiguredDnsNegative::NoData,
                } => Err(TransportError::DnsNoData(domain, port)),
                ConfiguredLookupResult::Unavailable { domain } => Err(TransportError::Dns {
                    domain,
                    port,
                    source: io::Error::new(
                        io::ErrorKind::NotConnected,
                        "all configured DNS servers are unavailable",
                    ),
                }),
            }
        };
        let Some(resolution_timeout) = self.resolution_timeout else {
            return resolution.await;
        };
        match time::timeout(resolution_timeout, resolution).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Dns {
                domain: domain.to_owned(),
                port,
                source: io::Error::new(io::ErrorKind::TimedOut, "DNS resolution timed out"),
            }),
        }
    }
}

enum ConfiguredLookupResult {
    Resolved(DnsLookup),
    Fallback {
        domain: String,
        ttl_cap: Option<Duration>,
    },
    Negative {
        domain: String,
        negative: ConfiguredDnsNegative,
    },
    Unavailable {
        domain: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfiguredDnsNegative {
    NameError,
    NoData,
}

enum ConfiguredServerResult {
    Answer(ConfiguredDnsAnswer),
    Negative(ConfiguredDnsNegative),
}

enum ConfiguredServersResult {
    Answer(ConfiguredDnsAddresses),
    Negative(ConfiguredDnsNegative),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfiguredDnsAnswer {
    Addresses(ConfiguredDnsAddresses),
    Cname { alias: String, ttl: Duration },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfiguredDnsAddresses {
    addresses: Vec<IpAddr>,
    ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsRecordType {
    A,
    Aaaa,
}

impl DnsRecordType {
    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

async fn exchange_direct_udp(
    server_addr: SocketAddr,
    query: &[u8],
    socket_protector: Option<&dyn SocketProtector>,
) -> io::Result<Vec<u8>> {
    let bind_addr = if server_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = StdUdpSocket::bind(bind_addr)?;
    if let Some(protector) = socket_protector {
        protector.protect(SocketHandle::from_std_udp_socket(&socket))?;
    }
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket)?;
    socket.connect(server_addr).await?;
    let written = socket.send(query).await?;
    if written != query.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short dns udp write",
        ));
    }

    let mut buffer = vec![0_u8; MAX_DNS_UDP_RESPONSE_SIZE + 1];
    loop {
        let len = socket.recv(&mut buffer).await?;
        if !dns_response_matches_query(query, &buffer[..len]) {
            continue;
        }
        if len > MAX_DNS_UDP_RESPONSE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns udp response is too large",
            ));
        }
        buffer.truncate(len);
        return Ok(buffer);
    }
}

async fn exchange_direct_tcp(
    server_addr: SocketAddr,
    query: &[u8],
    socket_protector: Option<&dyn SocketProtector>,
) -> io::Result<Vec<u8>> {
    let query_len = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns tcp query is too large"))?;
    let mut stream = connect_tcp_stream(server_addr, socket_protector)
        .await
        .map_err(io::Error::other)?;
    stream.write_u16(query_len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    let response_len = usize::from(stream.read_u16().await?);
    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

#[cfg(test)]
async fn query_udp_dns_server(
    server_addr: SocketAddr,
    domain: &str,
    record_type: DnsRecordType,
    timeout: Duration,
    socket_protector: Option<&dyn SocketProtector>,
) -> io::Result<Option<ConfiguredDnsAnswer>> {
    let query = build_dns_query(domain, record_type)?;
    let response = time::timeout(
        timeout,
        exchange_direct_udp(server_addr, &query, socket_protector),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns query timed out"))??;
    match parse_dns_response(&query, &response, record_type)? {
        ParsedDnsResponse::Answer(answer) => Ok(Some(answer)),
        ParsedDnsResponse::NoData
        | ParsedDnsResponse::NameError
        | ParsedDnsResponse::ServerFailure(_)
        | ParsedDnsResponse::Truncated => Ok(None),
    }
}

fn build_dns_query(domain: &str, record_type: DnsRecordType) -> io::Result<Vec<u8>> {
    build_dns_query_with_id(domain, record_type, rand::random())
}

fn normalize_dns_name(domain: &str) -> Option<String> {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn build_dns_query_with_id(
    domain: &str,
    record_type: DnsRecordType,
    id: u16,
) -> io::Result<Vec<u8>> {
    let normalized_domain = domain.trim_end_matches('.');
    if normalized_domain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dns query domain cannot be empty",
        ));
    }

    let mut query = Vec::with_capacity(12 + normalized_domain.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());

    for label in normalized_domain.split('.') {
        let label_bytes = label.as_bytes();
        if label_bytes.is_empty() || label_bytes.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dns query domain has invalid label",
            ));
        }
        query.push(label_bytes.len() as u8);
        query.extend_from_slice(label_bytes);
    }
    query.push(0);
    query.extend_from_slice(&record_type.code().to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

/// Returns whether a DNS response belongs to the supplied query.
///
/// UDP transports use this envelope check to discard stale or unrelated
/// datagrams from the selected upstream without turning them into resolver
/// fallback. Full answer and RCODE validation remains the resolver's job.
pub fn dns_response_matches_query(query: &[u8], response: &[u8]) -> bool {
    if query.len() < 12 || response.len() < 12 || query[0..2] != response[0..2] {
        return false;
    }
    let Ok(query_flags) = read_u16(query, 2) else {
        return false;
    };
    let Ok(response_flags) = read_u16(response, 2) else {
        return false;
    };
    if query_flags & 0x8000 != 0
        || response_flags & 0x8000 == 0
        || query_flags & 0x7800 != response_flags & 0x7800
    {
        return false;
    }

    let Ok(expected_question) = parse_dns_question(query) else {
        return false;
    };
    if read_u16(response, 4).ok() != Some(1) {
        return false;
    }
    let mut offset = 12;
    read_dns_question(response, &mut offset).is_ok_and(|question| question == expected_question)
}

fn parse_dns_response(
    query: &[u8],
    packet: &[u8],
    requested_type: DnsRecordType,
) -> io::Result<ParsedDnsResponse> {
    if packet.len() < 12 || query.len() < 2 || packet[0..2] != query[0..2] {
        return Err(invalid_dns_response(
            "DNS response header or transaction ID does not match",
        ));
    }

    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 {
        return Err(invalid_dns_response("DNS packet is not a response"));
    }

    let (expected_question, expected_type, expected_class) = parse_dns_question(query)?;
    if expected_type != requested_type.code() || expected_class != 1 {
        return Err(invalid_dns_response("DNS query type or class is invalid"));
    }

    let question_count = read_u16(packet, 4)?;
    if question_count != 1 {
        return Err(invalid_dns_response(
            "DNS response must repeat exactly one question",
        ));
    }
    let answer_count = read_u16(packet, 6)?;
    let mut offset = 12;

    let (response_question, response_type, response_class) =
        read_dns_question(packet, &mut offset)?;
    if response_question != expected_question
        || response_type != expected_type
        || response_class != expected_class
    {
        return Err(invalid_dns_response("DNS response question does not match"));
    }

    match flags & 0x000F {
        0 => {}
        3 => return Ok(ParsedDnsResponse::NameError),
        code => return Ok(ParsedDnsResponse::ServerFailure(code)),
    }

    if flags & 0x0200 != 0 {
        return Ok(ParsedDnsResponse::Truncated);
    }

    let mut response_ttl = DNS_DEFAULT_TTL;
    let mut addresses = Vec::new();
    let mut cnames = Vec::new();
    for _ in 0..answer_count {
        let owner_name = read_dns_name(packet, &mut offset)?;
        let record_type = read_u16(packet, offset)?;
        let record_class = read_u16(packet, offset + 2)?;
        let ttl = Duration::from_secs(u64::from(
            read_u32(packet, offset + 4)?.clamp(1, DNS_DEFAULT_TTL.as_secs() as u32),
        ));
        response_ttl = response_ttl.min(ttl);
        let data_len = usize::from(read_u16(packet, offset + 8)?);
        offset = offset
            .checked_add(10)
            .ok_or_else(|| invalid_dns_response("dns answer overflow"))?;
        let data_end = offset
            .checked_add(data_len)
            .ok_or_else(|| invalid_dns_response("dns rdata overflow"))?;
        if data_end > packet.len() {
            return Err(invalid_dns_response("truncated dns rdata"));
        }

        if record_class == 1 && record_type == requested_type.code() {
            match requested_type {
                DnsRecordType::A if data_len == 4 => {
                    addresses.push(ParsedDnsAddress {
                        owner: owner_name,
                        address: IpAddr::V4(Ipv4Addr::new(
                            packet[offset],
                            packet[offset + 1],
                            packet[offset + 2],
                            packet[offset + 3],
                        )),
                    });
                }
                DnsRecordType::Aaaa if data_len == 16 => {
                    let segments = [
                        read_u16(packet, offset)?,
                        read_u16(packet, offset + 2)?,
                        read_u16(packet, offset + 4)?,
                        read_u16(packet, offset + 6)?,
                        read_u16(packet, offset + 8)?,
                        read_u16(packet, offset + 10)?,
                        read_u16(packet, offset + 12)?,
                        read_u16(packet, offset + 14)?,
                    ];
                    let address = Ipv6Addr::new(
                        segments[0],
                        segments[1],
                        segments[2],
                        segments[3],
                        segments[4],
                        segments[5],
                        segments[6],
                        segments[7],
                    );
                    // Match Xray's address parser: IPv4-mapped data is not a
                    // usable AAAA result and must remain eligible for
                    // configured-server failover instead of becoming an IPv4
                    // dial candidate.
                    if address.to_ipv4_mapped().is_none() {
                        addresses.push(ParsedDnsAddress {
                            owner: owner_name,
                            address: IpAddr::V6(address),
                        });
                    }
                }
                _ => {
                    return Err(invalid_dns_response(
                        "DNS address record has an invalid RDATA length",
                    ));
                }
            }
        } else if record_class == 1 && record_type == 5 {
            let mut cname_offset = offset;
            let alias = read_dns_name_limited(packet, &mut cname_offset, data_end)?;
            if cname_offset != data_end {
                return Err(invalid_dns_response("dns cname rdata length mismatch"));
            }
            cnames.push(ParsedDnsCname {
                owner: owner_name,
                alias,
            });
        }

        offset = data_end;
    }

    resolve_parsed_dns_answers(&expected_question, addresses, cnames, response_ttl)
}

struct ParsedDnsAddress {
    owner: String,
    address: IpAddr,
}

struct ParsedDnsCname {
    owner: String,
    alias: String,
}

fn resolve_parsed_dns_answers(
    expected_name: &str,
    addresses: Vec<ParsedDnsAddress>,
    cnames: Vec<ParsedDnsCname>,
    ttl: Duration,
) -> io::Result<ParsedDnsResponse> {
    let mut current_name = expected_name.to_owned();
    let mut visited = vec![current_name.clone()];
    let mut followed_cname = false;

    for depth in 0..=MAX_DNS_ALIAS_DEPTH {
        let matched_addresses = addresses
            .iter()
            .filter(|record| record.owner.eq_ignore_ascii_case(&current_name))
            .map(|record| record.address)
            .collect::<Vec<_>>();
        if !matched_addresses.is_empty() {
            return Ok(ParsedDnsResponse::Answer(ConfiguredDnsAnswer::Addresses(
                ConfiguredDnsAddresses {
                    addresses: matched_addresses,
                    ttl,
                },
            )));
        }

        let mut matching_aliases = cnames
            .iter()
            .filter(|record| record.owner.eq_ignore_ascii_case(&current_name));
        let Some(first_alias) = matching_aliases.next() else {
            return if followed_cname {
                Ok(ParsedDnsResponse::Answer(ConfiguredDnsAnswer::Cname {
                    alias: current_name,
                    ttl,
                }))
            } else if addresses.is_empty() && cnames.is_empty() {
                Ok(ParsedDnsResponse::NoData)
            } else {
                Err(invalid_dns_response(
                    "DNS response contains no answer for the requested name",
                ))
            };
        };
        if matching_aliases.any(|record| !record.alias.eq_ignore_ascii_case(&first_alias.alias)) {
            return Err(invalid_dns_response(
                "DNS response contains conflicting CNAME targets",
            ));
        }
        if depth == MAX_DNS_ALIAS_DEPTH {
            return Err(invalid_dns_response(
                "DNS CNAME chain exceeds the depth limit",
            ));
        }
        if visited
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&first_alias.alias))
        {
            return Err(invalid_dns_response("DNS CNAME chain contains a cycle"));
        }

        followed_cname = true;
        current_name.clone_from(&first_alias.alias);
        visited.push(current_name.clone());
    }

    Err(invalid_dns_response(
        "DNS CNAME chain exceeds the depth limit",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedDnsResponse {
    Answer(ConfiguredDnsAnswer),
    NoData,
    NameError,
    ServerFailure(u16),
    Truncated,
}

fn dns_response_code_error(code: u16) -> io::Error {
    io::Error::other(format!("DNS server returned response code {code}"))
}

fn parse_dns_question(packet: &[u8]) -> io::Result<(String, u16, u16)> {
    let question_count = read_u16(packet, 4)?;
    if question_count != 1 {
        return Err(invalid_dns_response("dns query must have one question"));
    }
    let mut offset = 12;
    read_dns_question(packet, &mut offset)
}

fn read_dns_question(packet: &[u8], offset: &mut usize) -> io::Result<(String, u16, u16)> {
    let name = read_dns_name(packet, offset)?;
    let record_type = read_u16(packet, *offset)?;
    let record_class = read_u16(packet, *offset + 2)?;
    *offset = (*offset)
        .checked_add(4)
        .ok_or_else(|| invalid_dns_response("dns question overflow"))?;
    if *offset > packet.len() {
        return Err(invalid_dns_response("truncated dns question"));
    }
    Ok((name, record_type, record_class))
}

fn read_dns_name(packet: &[u8], offset: &mut usize) -> io::Result<String> {
    read_dns_name_limited(packet, offset, packet.len())
}

fn read_dns_name_limited(packet: &[u8], offset: &mut usize, limit: usize) -> io::Result<String> {
    if limit > packet.len() || *offset > limit {
        return Err(invalid_dns_response("invalid dns name limit"));
    }

    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut jumped = false;

    for _ in 0..32 {
        if !jumped && cursor >= limit {
            return Err(invalid_dns_response("truncated dns name"));
        }
        let Some(&length) = packet.get(cursor) else {
            return Err(invalid_dns_response("truncated dns name"));
        };

        if length & 0xC0 == 0xC0 {
            if !jumped && cursor + 2 > limit {
                return Err(invalid_dns_response("truncated dns name pointer"));
            }
            let Some(&next) = packet.get(cursor + 1) else {
                return Err(invalid_dns_response("truncated dns name pointer"));
            };
            if !jumped {
                *offset = cursor + 2;
            }
            cursor = ((usize::from(length & 0x3F)) << 8) | usize::from(next);
            jumped = true;
            continue;
        }

        if length == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            return Ok(labels.join("."));
        }

        if length & 0xC0 != 0 {
            return Err(invalid_dns_response("unsupported dns label encoding"));
        }

        cursor += 1;
        let label_len = usize::from(length);
        let label_end = cursor
            .checked_add(label_len)
            .ok_or_else(|| invalid_dns_response("dns label overflow"))?;
        if !jumped && label_end > limit {
            return Err(invalid_dns_response("truncated dns label"));
        }
        if label_end > packet.len() {
            return Err(invalid_dns_response("truncated dns label"));
        }
        let label = std::str::from_utf8(&packet[cursor..label_end])
            .map_err(|_| invalid_dns_response("dns label is not utf-8"))?;
        labels.push(label.to_ascii_lowercase());
        cursor = label_end;
    }

    Err(invalid_dns_response("dns name pointer loop"))
}

fn read_u16(packet: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_dns_response("truncated u16"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> io::Result<u32> {
    let bytes = packet
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_dns_response("truncated u32"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn invalid_dns_response(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

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

    let Some(prefix_len) = domain.len().checked_sub(suffix.len()) else {
        return false;
    };

    domain.as_bytes().get(prefix_len.wrapping_sub(1)) == Some(&b'.')
        && domain[prefix_len..].eq_ignore_ascii_case(suffix)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::net::UdpSocket;
    use tokio::sync::{oneshot, Barrier, Notify};

    use super::{
        build_dns_query_with_id, parse_dns_response, query_udp_dns_server,
        select_name_server_indices, CachingDnsResolver, CompiledDnsIpFilter,
        CompiledNameServerPolicies, ConfiguredDnsAddresses, ConfiguredDnsAnswer,
        ConfiguredDnsResolver, DnsIpCidr, DnsIpCidrError, DnsIpFilter, DnsIpMatcher, DnsLookup,
        DnsQueryStrategy, DnsQueryTransport, DnsQueryTransportKind, DnsRecordType, DnsResolver,
        NameServer, NameServerPolicy, StaticHostRule, StaticHostTarget, TransportDomainMatcher,
        DNS_CACHE_MAX_ENTRIES,
    };
    use crate::{SocketHandle, SocketProtector, TransportError};

    #[test]
    fn build_dns_query_uses_injected_transaction_id() {
        let query = build_dns_query_with_id("example.com", DnsRecordType::A, 0xA17E)
            .expect("valid query should encode");

        assert_eq!(&query[..2], &0xA17E_u16.to_be_bytes());
    }

    fn dns_ip_cidr(network: &str, prefix_len: u8) -> DnsIpMatcher {
        DnsIpMatcher::cidr(network.parse().expect("valid test IP address"), prefix_len)
            .expect("valid test prefix")
    }

    fn hard_dns_ip_filter(matchers: Vec<DnsIpMatcher>) -> CompiledDnsIpFilter {
        CompiledDnsIpFilter::new(DnsIpFilter::hard(matchers, Vec::new()))
    }

    fn soft_dns_ip_filter(matchers: Vec<DnsIpMatcher>) -> CompiledDnsIpFilter {
        CompiledDnsIpFilter::new(DnsIpFilter::soft(matchers, Vec::new()))
    }

    #[test]
    fn dns_ip_cidr_normalizes_network_and_validates_prefix() {
        let cidr = DnsIpCidr::new(Ipv4Addr::new(192, 0, 2, 129).into(), 24).unwrap();

        assert_eq!(cidr.network(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)));
        assert_eq!(cidr.prefix_len(), 24);
        assert!(cidr.contains(Ipv4Addr::new(192, 0, 2, 255).into()));
        assert!(!cidr.contains(Ipv4Addr::new(192, 0, 3, 1).into()));
        assert_eq!(
            DnsIpCidr::new(Ipv4Addr::LOCALHOST.into(), 33),
            Err(DnsIpCidrError::PrefixTooLong {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                prefix_len: 33,
                max_prefix: 32,
            })
        );

        let mapped = Ipv4Addr::new(192, 0, 2, 129).to_ipv6_mapped();
        let mapped_cidr = DnsIpCidr::new(IpAddr::V6(mapped), 24).unwrap();
        assert_eq!(
            (mapped_cidr.network(), mapped_cidr.prefix_len()),
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)
        );
        assert_eq!(
            DnsIpCidr::new(IpAddr::V6(mapped), 120),
            Err(DnsIpCidrError::PrefixTooLong {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 129)),
                prefix_len: 120,
                max_prefix: 32,
            })
        );
        assert_eq!(
            DnsIpCidr::host(IpAddr::V6(mapped)),
            DnsIpCidr::host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 129)))
        );
    }

    #[test]
    fn compiled_dns_ip_filter_matches_private_and_reports_deterministic_stats() {
        let filter = hard_dns_ip_filter(vec![DnsIpMatcher::Private]);

        assert_eq!(filter.matcher_count(), 1);
        assert_eq!(filter.compiled_range_count(), 9);
        assert!(filter.matches(Ipv4Addr::new(10, 1, 2, 3).into()));
        assert!(filter.matches(Ipv4Addr::new(100, 64, 1, 2).into()));
        assert!(filter.matches(Ipv6Addr::LOCALHOST.into()));
        assert!(filter.matches(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into()));
        assert!(!filter.matches(Ipv4Addr::new(8, 8, 8, 8).into()));
        assert!(!filter.matches(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).into()));
    }

    #[test]
    fn compiled_dns_ip_filter_merges_ranges_without_losing_source_count() {
        let filter = hard_dns_ip_filter(vec![
            dns_ip_cidr("192.0.2.0", 25),
            dns_ip_cidr("192.0.2.128", 25),
        ]);

        assert_eq!(filter.matcher_count(), 2);
        assert_eq!(filter.compiled_range_count(), 1);
        assert!(filter.matches(Ipv4Addr::new(192, 0, 2, 255).into()));
    }

    #[test]
    fn inverse_dns_ip_matchers_complement_the_union_for_their_address_family() {
        let filter = hard_dns_ip_filter(vec![
            dns_ip_cidr("10.0.0.0", 8).inverted(),
            dns_ip_cidr("192.168.0.0", 16).inverted(),
        ]);

        assert!(filter.matches(Ipv4Addr::new(203, 0, 113, 7).into()));
        assert!(!filter.matches(Ipv4Addr::new(10, 2, 3, 4).into()));
        assert!(!filter.matches(Ipv4Addr::new(192, 168, 5, 6).into()));
        assert!(!filter.matches(Ipv6Addr::LOCALHOST.into()));
    }

    #[test]
    fn custom_and_geoip_dns_matcher_categories_are_ored() {
        let filter = CompiledDnsIpFilter::new(DnsIpFilter::hard(
            vec![dns_ip_cidr("192.0.2.0", 24)],
            vec![dns_ip_cidr("2001:db8::", 32)],
        ));

        assert!(filter.matches(Ipv4Addr::new(192, 0, 2, 10).into()));
        assert!(filter.matches(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10).into()));
        assert!(!filter.matches(Ipv4Addr::new(198, 51, 100, 10).into()));
    }

    #[test]
    fn inverse_custom_and_geoip_dns_matcher_categories_remain_independent() {
        let filter = CompiledDnsIpFilter::new(DnsIpFilter::hard(
            vec![dns_ip_cidr("10.0.0.0", 8).inverted()],
            vec![dns_ip_cidr("192.168.0.0", 16).inverted()],
        ));

        // Each inverse category is its own Xray submatcher; the category not
        // containing the address still makes the multi-matcher succeed.
        assert!(filter.matches(Ipv4Addr::new(10, 1, 2, 3).into()));
        assert!(filter.matches(Ipv4Addr::new(192, 168, 1, 2).into()));
    }

    #[test]
    fn dns_ip_filter_unmaps_ipv4_mapped_match_inputs_like_xray() {
        let filter = hard_dns_ip_filter(vec![dns_ip_cidr("192.0.2.0", 24)]);

        assert!(filter.matches(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped())));
    }

    #[test]
    fn expected_dns_ip_filters_keep_matching_candidates_with_hard_and_soft_semantics() {
        let matching_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let matching_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10));
        let rejected = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let matchers = vec![dns_ip_cidr("192.0.2.0", 24), dns_ip_cidr("2001:db8::", 32)];
        let hard = hard_dns_ip_filter(matchers.clone());
        let soft = soft_dns_ip_filter(matchers);

        let mut hard_candidates = vec![matching_v6, rejected, matching_v4, matching_v6];
        assert!(hard.apply_expected(&mut hard_candidates));
        assert_eq!(hard_candidates, [matching_v6, matching_v4, matching_v6]);

        let mut hard_rejected = vec![rejected];
        assert!(!hard.apply_expected(&mut hard_rejected));
        assert!(hard_rejected.is_empty());

        let mut soft_preferred = vec![rejected, matching_v4];
        assert!(soft.apply_expected(&mut soft_preferred));
        assert_eq!(soft_preferred, [matching_v4]);

        let mut soft_fallback = vec![rejected, rejected];
        assert!(soft.apply_expected(&mut soft_fallback));
        assert_eq!(soft_fallback, [rejected, rejected]);
    }

    #[test]
    fn unexpected_dns_ip_filters_keep_nonmatching_candidates_with_hard_and_soft_semantics() {
        let unexpected = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let preferred_v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let preferred_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10));
        let matcher = vec![dns_ip_cidr("192.0.2.0", 24)];
        let hard = hard_dns_ip_filter(matcher.clone());
        let soft = soft_dns_ip_filter(matcher);

        let mut hard_candidates = vec![unexpected, preferred_v4, preferred_v6, preferred_v4];
        assert!(hard.apply_unexpected(&mut hard_candidates));
        assert_eq!(hard_candidates, [preferred_v4, preferred_v6, preferred_v4]);

        let mut hard_rejected = vec![unexpected, unexpected];
        assert!(!hard.apply_unexpected(&mut hard_rejected));
        assert!(hard_rejected.is_empty());

        let mut soft_preferred = vec![unexpected, preferred_v4];
        assert!(soft.apply_unexpected(&mut soft_preferred));
        assert_eq!(soft_preferred, [preferred_v4]);

        let mut soft_fallback = vec![unexpected, unexpected];
        assert!(soft.apply_unexpected(&mut soft_fallback));
        assert_eq!(soft_fallback, [unexpected, unexpected]);
    }

    #[test]
    fn empty_dns_ip_filter_is_a_noop_even_when_hard() {
        let filter = CompiledDnsIpFilter::new(DnsIpFilter::default());
        let original = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))];
        let mut expected = original.clone();
        let mut unexpected = original.clone();

        assert!(filter.is_empty());
        assert!(filter.apply_expected(&mut expected));
        assert!(filter.apply_unexpected(&mut unexpected));
        assert_eq!(expected, original);
        assert_eq!(unexpected, original);
    }

    #[test]
    fn compiled_name_server_policy_applies_expected_before_soft_unexpected() {
        let server = NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)));
        let mut policy = NameServerPolicy::new(server);
        policy.expected_ips = DnsIpFilter::hard(vec![dns_ip_cidr("192.0.2.0", 24)], Vec::new());
        policy.unexpected_ips = DnsIpFilter::soft(vec![dns_ip_cidr("192.0.2.0", 24)], Vec::new());
        let policies = CompiledNameServerPolicies::new(vec![policy]);
        let mut addresses = vec![
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        ];

        assert!(policies.get(0).unwrap().apply_ip_filters(&mut addresses));
        assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
    }

    #[test]
    fn compiled_name_server_policy_applies_hard_unexpected_before_soft_expected() {
        let server = NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)));
        let mut policy = NameServerPolicy::new(server);
        policy.expected_ips = DnsIpFilter::soft(vec![dns_ip_cidr("192.0.2.0", 24)], Vec::new());
        policy.unexpected_ips = DnsIpFilter::hard(vec![dns_ip_cidr("192.0.2.0", 24)], Vec::new());
        let policies = CompiledNameServerPolicies::new(vec![policy]);
        let mut addresses = vec![
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        ];

        assert!(policies.get(0).unwrap().apply_ip_filters(&mut addresses));
        assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))]);
    }

    fn policy(server_octet: u8) -> NameServerPolicy {
        NameServerPolicy::new(NameServer::Socket(SocketAddr::from((
            [192, 0, 2, server_octet],
            53,
        ))))
    }

    #[test]
    fn compiled_name_server_policy_preserves_timeout_override() {
        let mut policy = policy(1);
        policy.timeout = Some(Duration::from_millis(37));
        let compiled = CompiledNameServerPolicies::new(vec![policy]);

        assert_eq!(compiled.timeout(0), Some(Duration::from_millis(37)));
        assert_eq!(compiled.timeout(1), None);
    }

    #[test]
    fn name_server_selector_matches_before_ordered_fallback() {
        let fallback = policy(1);
        let mut matched_suffix = policy(2);
        matched_suffix.domains = vec![TransportDomainMatcher::Suffix("internal.test".to_owned())];
        let mut matched_full = policy(3);
        matched_full.domains = vec![TransportDomainMatcher::Full(
            "service.internal.test".to_owned(),
        )];
        let mut skipped = policy(4);
        skipped.skip_fallback = true;
        skipped.domains = vec![TransportDomainMatcher::Full(
            "service.internal.test".to_owned(),
        )];
        let servers = [fallback, matched_suffix, matched_full, skipped];

        assert_eq!(
            select_name_server_indices(&servers, "service.internal.test", false, false),
            vec![1, 2, 3, 0]
        );
        assert_eq!(
            select_name_server_indices(&servers, "unmatched.test", false, false),
            vec![0, 1, 2]
        );
        assert_eq!(
            select_name_server_indices(&servers, "service.internal.test", true, false),
            vec![1, 2, 3]
        );
        assert_eq!(
            select_name_server_indices(&servers, "service.internal.test", false, true),
            vec![1, 2, 3]
        );
        assert_eq!(
            select_name_server_indices(&servers, "unmatched.test", false, true),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn name_server_selector_honors_final_query_and_forced_first() {
        let mut first = policy(1);
        first.skip_fallback = true;
        let mut final_match = policy(2);
        final_match.domains = vec![TransportDomainMatcher::Suffix("internal.test".to_owned())];
        final_match.final_query = true;
        let mut later_match = policy(3);
        later_match.domains = vec![TransportDomainMatcher::Full(
            "service.internal.test".to_owned(),
        )];
        let servers = [first, final_match, later_match];

        assert_eq!(
            select_name_server_indices(&servers, "service.internal.test", false, false),
            vec![1]
        );
        assert_eq!(
            select_name_server_indices(&servers, "unmatched.test", true, false),
            vec![0]
        );

        let mut fallback_final = policy(1);
        fallback_final.final_query = true;
        assert_eq!(
            select_name_server_indices(
                &[fallback_final, policy(2)],
                "unmatched.test",
                false,
                false,
            ),
            vec![0]
        );
    }

    #[test]
    fn compiled_name_server_selector_matches_reference_semantics() {
        let fallback = policy(1);
        let mut exact = policy(2);
        exact.domains = vec![TransportDomainMatcher::Full(
            "SERVICE.INTERNAL.TEST.".to_owned(),
        )];
        let mut mixed = policy(3);
        mixed.domains = vec![
            TransportDomainMatcher::Suffix("Internal.Test.".to_owned()),
            TransportDomainMatcher::Keyword("CORP".to_owned()),
            TransportDomainMatcher::regex(r"(^|\.)regex\.test\.?$").unwrap(),
        ];
        let mut skipped = policy(4);
        skipped.skip_fallback = true;
        skipped.domains = vec![TransportDomainMatcher::Full("forced.test".to_owned())];
        let mut final_query = policy(5);
        final_query.final_query = true;
        final_query.domains = vec![TransportDomainMatcher::Suffix("final.test".to_owned())];
        let policies = vec![fallback, exact, mixed, skipped, final_query];
        let compiled = CompiledNameServerPolicies::new(policies.clone());

        assert_eq!(compiled.matcher_count(), 6);
        assert!(compiled.pattern_bytes() > 0);
        assert_eq!(compiled.name_server(0), Some(&policies[0].server));
        assert_eq!(compiled.name_server(policies.len()), None);
        for domain in [
            "service.internal.test",
            "SERVICE.INTERNAL.TEST.",
            "host.internal.test",
            "my-corp-zone.test",
            "www.regex.test",
            "forced.test",
            "www.final.test",
            "unmatched.test",
        ] {
            for (disable_fallback, disable_fallback_if_match) in
                [(false, false), (true, false), (false, true)]
            {
                assert_eq!(
                    compiled.select_indices(
                        domain,
                        disable_fallback,
                        disable_fallback_if_match,
                    ),
                    select_name_server_indices(
                        &policies,
                        domain,
                        disable_fallback,
                        disable_fallback_if_match,
                    ),
                    "domain={domain} disableFallback={disable_fallback} disableFallbackIfMatch={disable_fallback_if_match}",
                );
            }
        }
    }

    #[test]
    fn compiled_name_server_selector_indexes_large_exact_rule_set() {
        let mut indexed = policy(2);
        indexed.domains.extend(
            (0..9_999)
                .map(|index| TransportDomainMatcher::Full(format!("miss-{index}.policy.invalid"))),
        );
        indexed.domains.push(TransportDomainMatcher::Full(
            "target.policy.test".to_owned(),
        ));
        let policies = vec![policy(1), indexed];
        let compiled = CompiledNameServerPolicies::new(policies.clone());

        assert_eq!(compiled.matcher_count(), 10_000);
        assert_eq!(
            compiled.select_indices("target.policy.test", false, false),
            select_name_server_indices(&policies, "target.policy.test", false, false),
        );
    }

    #[test]
    fn compiled_name_server_selector_preserves_low_level_empty_suffix_semantics() {
        let mut empty_suffix = policy(1);
        empty_suffix.domains = vec![TransportDomainMatcher::Suffix("...".to_owned())];
        let policies = vec![empty_suffix, policy(2)];
        let compiled = CompiledNameServerPolicies::new(policies.clone());

        for domain in ["", ".", "...", "example.test"] {
            assert_eq!(
                compiled.select_indices(domain, false, true),
                select_name_server_indices(&policies, domain, false, true),
            );
        }
    }

    #[test]
    fn name_server_selectors_scale_past_inline_policy_bitset() {
        let mut policies = (0..130)
            .map(|index| policy((index % 254 + 1) as u8))
            .collect::<Vec<_>>();
        policies[65].skip_fallback = true;
        policies[100].domains = vec![TransportDomainMatcher::Full("matched.test".to_owned())];
        let compiled = CompiledNameServerPolicies::new(policies.clone());

        assert_eq!(
            compiled.select_indices("matched.test", false, false),
            select_name_server_indices(&policies, "matched.test", false, false),
        );
        assert_eq!(
            compiled.select_indices("unmatched.test", false, false),
            select_name_server_indices(&policies, "unmatched.test", false, false),
        );
    }

    #[test]
    fn dns_parser_flattens_out_of_order_cname_chain_and_uses_minimum_ttl() {
        let query = build_dns_query_with_id("origin.example", DnsRecordType::A, 0xA17F).unwrap();
        let response =
            build_test_cname_and_a_response(&query, "alias.example", Ipv4Addr::new(192, 0, 2, 84));

        let parsed = parse_dns_response(&query, &response, DnsRecordType::A).unwrap();

        assert_eq!(
            parsed,
            super::ParsedDnsResponse::Answer(ConfiguredDnsAnswer::Addresses(
                ConfiguredDnsAddresses {
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 84))],
                    ttl: Duration::from_secs(20),
                },
            ))
        );
    }

    #[test]
    fn dns_lookup_preserves_order_and_removes_exact_duplicates() {
        let first = SocketAddr::from(([192, 0, 2, 10], 443));
        let second = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 7, 9));
        let mapped_first = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped(),
            443,
            7,
            9,
        ));

        let lookup = DnsLookup::new(
            [mapped_first, second, first, second],
            Some(Duration::from_secs(30)),
        );

        assert_eq!(lookup.socket_addrs(), &[first, second]);
        assert!(lookup.ttl().is_some_and(|ttl| {
            ttl <= Duration::from_secs(30) && ttl > Duration::from_secs(29)
        }));
    }

    struct LegacySocketDnsResolver(SocketAddr);

    #[async_trait::async_trait]
    impl DnsResolver for LegacySocketDnsResolver {
        async fn resolve(&self, _domain: &str, _port: u16) -> Result<SocketAddr, TransportError> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn default_resolve_all_preserves_legacy_socket_address_as_is() {
        let expected = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 17, 9));
        let resolver = LegacySocketDnsResolver(expected);

        let lookup = resolver.resolve_all("legacy.example", 443).await.unwrap();

        assert_eq!(lookup.socket_addrs(), &[expected]);
    }

    #[derive(Default)]
    struct CountingProtector {
        calls: AtomicUsize,
    }

    impl SocketProtector for CountingProtector {
        fn protect(&self, _socket: SocketHandle) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn configured_dns_protects_udp_socket_before_query() {
        let server = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("test DNS socket should bind");
        let protector = CountingProtector::default();

        let result = query_udp_dns_server(
            server.local_addr().expect("test DNS address should exist"),
            "example.com",
            DnsRecordType::A,
            Duration::from_millis(1),
            Some(&protector),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(protector.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn connected_dns_socket_ignores_response_from_different_peer() {
        let server = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("test DNS socket should bind");
        let server_addr = server.local_addr().expect("server address should exist");
        let attacker = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("attacker socket should bind");
        let (observed_tx, observed_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut packet = [0_u8; 512];
            let (len, client_addr) = server
                .recv_from(&mut packet)
                .await
                .expect("server should receive query");
            let query = packet[..len].to_vec();
            observed_tx
                .send((client_addr, query.clone()))
                .expect("test should observe query");
            tokio::time::sleep(Duration::from_millis(10)).await;
            server
                .send_to(
                    &build_test_a_response(&query, Ipv4Addr::new(192, 0, 2, 20)),
                    client_addr,
                )
                .await
                .expect("server should send legitimate response");
        });
        let query_task = tokio::spawn(query_udp_dns_server(
            server_addr,
            "example.com",
            DnsRecordType::A,
            Duration::from_secs(1),
            None,
        ));
        let (client_addr, query) = observed_rx.await.expect("query should be observable");
        attacker
            .send_to(
                &build_test_a_response(&query, Ipv4Addr::new(198, 51, 100, 99)),
                client_addr,
            )
            .await
            .expect("attacker should send forged response");

        let answer = query_task
            .await
            .expect("query task should not panic")
            .expect("query should complete")
            .expect("query should return an answer");
        server_task.await.expect("server task should not panic");

        assert_eq!(
            answer,
            ConfiguredDnsAnswer::Addresses(ConfiguredDnsAddresses {
                addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))],
                ttl: Duration::from_secs(60),
            })
        );
    }

    #[tokio::test]
    async fn connected_dns_socket_ignores_unrelated_response_from_selected_peer() {
        let server = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("test DNS socket should bind");
        let server_addr = server.local_addr().expect("server address should exist");
        let server_task = tokio::spawn(async move {
            let mut packet = [0_u8; 512];
            let (len, client_addr) = server
                .recv_from(&mut packet)
                .await
                .expect("server should receive query");
            let query = packet[..len].to_vec();
            let transaction_id = u16::from_be_bytes([query[0], query[1]]);
            let unrelated_query =
                build_dns_query_with_id("unrelated.example", DnsRecordType::A, transaction_id)
                    .unwrap();
            server
                .send_to(
                    &build_test_a_response(&unrelated_query, Ipv4Addr::new(198, 51, 100, 99)),
                    client_addr,
                )
                .await
                .expect("server should send unrelated response");
            server
                .send_to(
                    &build_test_a_response(&query, Ipv4Addr::new(192, 0, 2, 21)),
                    client_addr,
                )
                .await
                .expect("server should send matching response");
        });

        let answer = query_udp_dns_server(
            server_addr,
            "example.com",
            DnsRecordType::A,
            Duration::from_secs(1),
            None,
        )
        .await
        .expect("query should complete")
        .expect("query should return an answer");
        server_task.await.expect("server task should not panic");

        assert_eq!(
            answer,
            ConfiguredDnsAnswer::Addresses(ConfiguredDnsAddresses {
                addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21))],
                ttl: Duration::from_secs(60),
            })
        );
    }

    struct RejectingResolver;

    #[async_trait::async_trait]
    impl DnsResolver for RejectingResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
        }
    }

    #[derive(Default)]
    struct FamilyRecordingQueryTransport {
        record_types: Mutex<Vec<u16>>,
        ipv6_address: Option<Ipv6Addr>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for FamilyRecordingQueryTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let record_type = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
            self.record_types.lock().unwrap().push(record_type);
            match record_type {
                1 => Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 90))),
                28 => Ok(build_test_address_response(
                    query,
                    &[(
                        28,
                        60,
                        self.ipv6_address
                            .unwrap_or(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 90))
                            .octets()
                            .to_vec(),
                    )],
                )),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected DNS record type",
                )),
            }
        }
    }

    struct MappedFirstServerQueryTransport {
        first: NameServer,
        calls: Mutex<Vec<NameServer>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for MappedFirstServerQueryTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(server.clone());
            let address = if server == &self.first {
                Ipv4Addr::new(192, 0, 2, 96).to_ipv6_mapped()
            } else {
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 96)
            };
            Ok(build_test_address_response(
                query,
                &[(28, 60, address.octets().to_vec())],
            ))
        }
    }

    #[tokio::test]
    async fn configured_dns_use_ipv6_rejects_mapped_ipv4_wire_answer() {
        let fallback = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: Some(SocketAddr::from(([192, 0, 2, 94], 0))),
        });
        let transport = Arc::new(FamilyRecordingQueryTransport {
            record_types: Mutex::new(Vec::new()),
            ipv6_address: Some(Ipv4Addr::new(192, 0, 2, 95).to_ipv6_mapped()),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
            fallback.clone(),
        )
        .with_query_strategy(DnsQueryStrategy::UseIpv6)
        .with_query_transport(transport.clone());

        let error = resolver
            .resolve("mapped-wire.example", 443)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            TransportError::DnsNoData(domain, 443) if domain == "mapped-wire.example"
        ));
        assert_eq!(*transport.record_types.lock().unwrap(), [28]);
        assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn configured_dns_mapped_aaaa_keeps_server_failover_available() {
        let first = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let second = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let transport = Arc::new(MappedFirstServerQueryTransport {
            first: first.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![first.clone(), second.clone()],
            Arc::new(RejectingResolver),
        )
        .with_query_strategy(DnsQueryStrategy::UseIpv6)
        .with_query_transport(transport.clone());

        let resolved = resolver
            .resolve("mapped-failover.example", 443)
            .await
            .unwrap();

        assert_eq!(
            resolved,
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 96), 443))
        );
        assert_eq!(*transport.calls.lock().unwrap(), [first, second]);
    }

    #[tokio::test]
    async fn configured_dns_query_strategy_sends_only_selected_family() {
        for (strategy, record_type, expected) in [
            (
                DnsQueryStrategy::UseIpv4,
                1,
                SocketAddr::from(([192, 0, 2, 90], 443)),
            ),
            (
                DnsQueryStrategy::UseIpv6,
                28,
                SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 90), 443)),
            ),
        ] {
            let transport = Arc::new(FamilyRecordingQueryTransport::default());
            let resolver = ConfiguredDnsResolver::new(
                Vec::new(),
                vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
                Arc::new(RejectingResolver),
            )
            .with_query_strategy(strategy)
            .with_query_transport(transport.clone());

            let resolved = resolver.resolve("family.example", 443).await.unwrap();

            assert_eq!(resolved, expected);
            assert_eq!(*transport.record_types.lock().unwrap(), [record_type]);
        }
    }

    #[tokio::test]
    async fn configured_dns_query_strategy_filters_static_hosts_and_mapped_ipv4() {
        let native_ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 91);
        let mapped_ipv4 = Ipv4Addr::new(192, 0, 2, 91).to_ipv6_mapped();
        let native_ipv4 = Ipv4Addr::new(192, 0, 2, 92);
        let host_rule = StaticHostRule {
            matcher: TransportDomainMatcher::Full("mixed.example".to_owned()),
            target: StaticHostTarget::Ips(vec![
                IpAddr::V6(native_ipv6),
                IpAddr::V6(mapped_ipv4),
                IpAddr::V4(native_ipv4),
            ]),
        };

        let ipv4 = ConfiguredDnsResolver::new(
            vec![host_rule.clone()],
            Vec::new(),
            Arc::new(RejectingResolver),
        )
        .with_query_strategy(DnsQueryStrategy::UseIpv4)
        .resolve_all("mixed.example", 443)
        .await
        .unwrap();
        let ipv6 =
            ConfiguredDnsResolver::new(vec![host_rule], Vec::new(), Arc::new(RejectingResolver))
                .with_query_strategy(DnsQueryStrategy::UseIpv6)
                .resolve_all("mixed.example", 443)
                .await
                .unwrap();

        assert_eq!(
            ipv4.socket_addrs(),
            [
                SocketAddr::new(
                    IpAddr::V4(mapped_ipv4.to_ipv4_mapped().expect("mapped IPv4")),
                    443,
                ),
                SocketAddr::new(IpAddr::V4(native_ipv4), 443),
            ]
        );
        assert_eq!(
            ipv6.socket_addrs(),
            [SocketAddr::new(IpAddr::V6(native_ipv6), 443)]
        );
    }

    #[tokio::test]
    async fn configured_dns_wrong_family_static_host_is_terminal_nodata() {
        let fallback = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: Some(SocketAddr::from(([192, 0, 2, 93], 0))),
        });
        let resolver = ConfiguredDnsResolver::new(
            vec![StaticHostRule {
                matcher: TransportDomainMatcher::Full("ipv6-only.example".to_owned()),
                target: StaticHostTarget::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            }],
            Vec::new(),
            fallback.clone(),
        )
        .with_query_strategy(DnsQueryStrategy::UseIpv4);

        let error = resolver
            .resolve("ipv6-only.example", 443)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            TransportError::DnsNoData(domain, 443) if domain == "ipv6-only.example"
        ));
        assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn configured_dns_exact_host_mapping_wins_over_broader_mapping() {
        let resolver = ConfiguredDnsResolver::new(
            vec![
                StaticHostRule {
                    matcher: TransportDomainMatcher::Keyword("example".to_owned()),
                    target: StaticHostTarget::Ip(Ipv4Addr::new(192, 0, 2, 1).into()),
                },
                StaticHostRule {
                    matcher: TransportDomainMatcher::Full("PROXY.EXAMPLE.".to_owned()),
                    target: StaticHostTarget::Ip(Ipv4Addr::new(192, 0, 2, 2).into()),
                },
            ],
            Vec::new(),
            Arc::new(RejectingResolver),
        );

        let lookup = resolver.resolve_all("PROXY.EXAMPLE.", 443).await.unwrap();

        assert_eq!(
            lookup.socket_addrs(),
            &[SocketAddr::from(([192, 0, 2, 2], 443))]
        );
        assert!(lookup
            .ttl()
            .is_some_and(|ttl| { ttl <= Duration::from_secs(10) && ttl > Duration::from_secs(9) }));
    }

    #[tokio::test]
    async fn configured_dns_static_host_mapping_preserves_all_ip_candidates() {
        let resolver = ConfiguredDnsResolver::new(
            vec![StaticHostRule {
                matcher: TransportDomainMatcher::Full("proxy.example".to_owned()),
                target: StaticHostTarget::Ips(vec![
                    Ipv6Addr::LOCALHOST.into(),
                    Ipv4Addr::new(192, 0, 2, 44).into(),
                    Ipv6Addr::LOCALHOST.into(),
                ]),
            }],
            Vec::new(),
            Arc::new(RejectingResolver),
        );

        let lookup = resolver.resolve_all("proxy.example", 8443).await.unwrap();

        assert_eq!(
            lookup.socket_addrs(),
            &[
                SocketAddr::from((Ipv6Addr::LOCALHOST, 8443)),
                SocketAddr::from((Ipv4Addr::new(192, 0, 2, 44), 8443)),
            ]
        );
    }

    struct MultiAddressQueryTransport;

    #[async_trait::async_trait]
    impl DnsQueryTransport for MultiAddressQueryTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let record_type = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
            match record_type {
                1 => Ok(build_test_address_response(
                    query,
                    &[
                        (1, 120, Ipv4Addr::new(192, 0, 2, 80).octets().to_vec()),
                        (1, 30, Ipv4Addr::new(192, 0, 2, 81).octets().to_vec()),
                    ],
                )),
                28 => Ok(build_test_address_response(
                    query,
                    &[
                        (
                            28,
                            90,
                            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 80)
                                .octets()
                                .to_vec(),
                        ),
                        (
                            28,
                            45,
                            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 81)
                                .octets()
                                .to_vec(),
                        ),
                    ],
                )),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected DNS query type",
                )),
            }
        }
    }

    #[tokio::test]
    async fn configured_dns_returns_all_families_with_minimum_answer_ttl() {
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
            Arc::new(RejectingResolver),
        )
        .with_query_transport(Arc::new(MultiAddressQueryTransport));

        let lookup = resolver.resolve_all("multi.example", 443).await.unwrap();

        assert_eq!(
            lookup.ips().collect::<Vec<_>>(),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 81)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 80)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 81)),
            ]
        );
        assert!(lookup.ttl().is_some_and(|ttl| {
            ttl <= Duration::from_secs(30) && ttl > Duration::from_secs(29)
        }));
    }

    #[tokio::test]
    async fn configured_dns_filters_merged_families_without_reordering_or_recomputing_ttl() {
        let server = NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)));
        let mut policy = NameServerPolicy::new(server);
        policy.expected_ips = DnsIpFilter::hard(
            vec![
                DnsIpMatcher::host(Ipv4Addr::new(192, 0, 2, 80).into()),
                DnsIpMatcher::host(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 80).into()),
            ],
            Vec::new(),
        );
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![policy])
                .with_query_transport(Arc::new(MultiAddressQueryTransport));

        let lookup = resolver
            .resolve_all("filtered-multi.example", 443)
            .await
            .unwrap();

        assert_eq!(
            lookup.ips().collect::<Vec<_>>(),
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 80)),
            ]
        );
        assert!(lookup.ttl().is_some_and(|ttl| {
            ttl <= Duration::from_secs(30) && ttl > Duration::from_secs(29)
        }));
    }

    struct TtlCountingResolver {
        calls: AtomicUsize,
        ttl: Duration,
    }

    #[async_trait::async_trait]
    impl DnsResolver for TtlCountingResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            self.resolve_all(domain, port)
                .await?
                .first_socket_addr(domain, port)
        }

        async fn resolve_all(
            &self,
            _domain: &str,
            _port: u16,
        ) -> Result<DnsLookup, TransportError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(DnsLookup::from_ips(
                [
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 82)),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 83)),
                ],
                _port,
                Some(self.ttl),
            ))
        }
    }

    #[tokio::test]
    async fn caching_dns_expires_multi_address_result_using_upstream_ttl() {
        let inner = Arc::new(TtlCountingResolver {
            calls: AtomicUsize::new(0),
            ttl: Duration::from_secs(1),
        });
        let resolver = CachingDnsResolver::new(inner.clone());

        let first = resolver.resolve_all("ttl.example", 443).await.unwrap();
        let first_ttl = first.ttl().unwrap();
        let cached = resolver.resolve_all("ttl.example", 443).await.unwrap();
        let cached_ttl = cached.ttl().unwrap();
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let refreshed = resolver.resolve_all("ttl.example", 443).await.unwrap();

        assert_eq!(first.socket_addrs(), cached.socket_addrs());
        assert_eq!(cached.socket_addrs(), refreshed.socket_addrs());
        assert!(!cached_ttl.is_zero());
        assert!(cached_ttl <= first_ttl);
        assert!(refreshed.ttl().is_some_and(|ttl| {
            ttl <= Duration::from_secs(1) && ttl > Duration::from_millis(900)
        }));
        assert_eq!(inner.calls.load(Ordering::Relaxed), 2);
    }

    struct DelayedCountingResolver {
        calls: AtomicUsize,
        result: Option<SocketAddr>,
    }

    struct ImmediateCountingResolver {
        calls: AtomicUsize,
        result: SocketAddr,
    }

    #[async_trait::async_trait]
    impl DnsResolver for ImmediateCountingResolver {
        async fn resolve(&self, _domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(SocketAddr::new(self.result.ip(), port))
        }
    }

    #[async_trait::async_trait]
    impl DnsResolver for DelayedCountingResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(50)).await;
            self.result
                .map(|addr| SocketAddr::new(addr.ip(), port))
                .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn caching_dns_single_flights_concurrent_successes() {
        let inner = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: Some(SocketAddr::from(([192, 0, 2, 60], 0))),
        });
        let resolver = Arc::new(CachingDnsResolver::new(inner.clone()));
        let barrier = Arc::new(Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let resolver = Arc::clone(&resolver);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                resolver.resolve("burst.example", 443).await
            }));
        }
        barrier.wait().await;

        for task in tasks {
            assert_eq!(
                task.await.unwrap().unwrap(),
                SocketAddr::from(([192, 0, 2, 60], 443))
            );
        }
        assert_eq!(inner.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn caching_dns_reuses_canonical_names() {
        let inner = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: Some(SocketAddr::from(([192, 0, 2, 61], 0))),
        });
        let resolver = CachingDnsResolver::new(inner.clone());

        resolver.resolve("Cache.Example", 443).await.unwrap();
        resolver.resolve("cache.example", 443).await.unwrap();
        resolver.resolve("CACHE.EXAMPLE.", 443).await.unwrap();

        assert_eq!(inner.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn caching_dns_evicts_only_the_least_recently_used_live_entry() {
        let inner = Arc::new(ImmediateCountingResolver {
            calls: AtomicUsize::new(0),
            result: SocketAddr::from(([192, 0, 2, 62], 0)),
        });
        let resolver = CachingDnsResolver::new(inner.clone());
        for index in 0..DNS_CACHE_MAX_ENTRIES {
            resolver
                .resolve(&format!("entry-{index}.example"), 443)
                .await
                .unwrap();
        }
        resolver.resolve("entry-0.example", 443).await.unwrap();
        resolver.resolve("overflow.example", 443).await.unwrap();
        resolver.resolve("entry-0.example", 443).await.unwrap();
        resolver.resolve("entry-1.example", 443).await.unwrap();

        assert_eq!(
            inner.calls.load(Ordering::Relaxed),
            DNS_CACHE_MAX_ENTRIES + 2
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn caching_dns_single_flights_concurrent_failures() {
        let inner = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: None,
        });
        let resolver = Arc::new(CachingDnsResolver::new(inner.clone()));
        let barrier = Arc::new(Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let resolver = Arc::clone(&resolver);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                resolver.resolve("missing.example", 443).await
            }));
        }
        barrier.wait().await;

        for task in tasks {
            assert!(task.await.unwrap().is_err());
        }
        assert_eq!(inner.calls.load(Ordering::Relaxed), 1);
    }

    struct DelayedNameErrorResolver {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl DnsResolver for DelayedNameErrorResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(50)).await;
            Err(TransportError::DnsNameError(domain.to_owned(), port))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn caching_dns_preserves_negative_outcome_for_all_singleflight_waiters() {
        let inner = Arc::new(DelayedNameErrorResolver {
            calls: AtomicUsize::new(0),
        });
        let resolver = Arc::new(CachingDnsResolver::new(inner.clone()));
        let barrier = Arc::new(Barrier::new(17));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let resolver = Arc::clone(&resolver);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                resolver.resolve("missing.example", 443).await
            }));
        }
        barrier.wait().await;

        for task in tasks {
            assert!(matches!(
                task.await.unwrap(),
                Err(TransportError::DnsNameError(domain, 443)) if domain == "missing.example"
            ));
        }
        assert_eq!(inner.calls.load(Ordering::Relaxed), 1);
    }

    struct CancelOnceResolver {
        calls: AtomicUsize,
        first_started: Notify,
    }

    #[async_trait::async_trait]
    impl DnsResolver for CancelOnceResolver {
        async fn resolve(&self, _domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                self.first_started.notify_one();
                std::future::pending().await
            } else {
                Ok(SocketAddr::from(([192, 0, 2, 61], port)))
            }
        }
    }

    #[tokio::test]
    async fn caching_dns_wakes_waiters_when_lookup_leader_is_cancelled() {
        let inner = Arc::new(CancelOnceResolver {
            calls: AtomicUsize::new(0),
            first_started: Notify::new(),
        });
        let resolver = Arc::new(CachingDnsResolver::new(inner.clone()));
        let leader_resolver = Arc::clone(&resolver);
        let leader =
            tokio::spawn(async move { leader_resolver.resolve("cancelled.example", 443).await });
        inner.first_started.notified().await;
        let waiter_resolver = Arc::clone(&resolver);
        let waiter =
            tokio::spawn(async move { waiter_resolver.resolve("cancelled.example", 443).await });
        tokio::task::yield_now().await;

        leader.abort();
        let resolved = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should be released after leader cancellation")
            .unwrap()
            .unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 61], 443)));
        assert_eq!(inner.calls.load(Ordering::Relaxed), 2);
    }

    #[derive(Default)]
    struct TruncatingQueryTransport {
        calls: Mutex<Vec<DnsQueryTransportKind>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for TruncatingQueryTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(transport);
            match transport {
                DnsQueryTransportKind::Udp => {
                    let mut response = Vec::with_capacity(query.len());
                    response.extend_from_slice(&query[..2]);
                    response.extend_from_slice(&0x8380_u16.to_be_bytes());
                    response.extend_from_slice(&1_u16.to_be_bytes());
                    response.extend_from_slice(&0_u16.to_be_bytes());
                    response.extend_from_slice(&0_u16.to_be_bytes());
                    response.extend_from_slice(&0_u16.to_be_bytes());
                    response.extend_from_slice(&query[12..]);
                    Ok(response)
                }
                DnsQueryTransportKind::Tcp => {
                    Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 25)))
                }
            }
        }
    }

    #[tokio::test]
    async fn configured_dns_retries_valid_truncated_udp_response_over_tcp() {
        let transport = Arc::new(TruncatingQueryTransport::default());
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
            Arc::new(RejectingResolver),
        )
        .with_query_transport(transport.clone());

        let resolved = resolver.resolve("example.com", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 25], 443)));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            vec![
                DnsQueryTransportKind::Udp,
                DnsQueryTransportKind::Tcp,
                DnsQueryTransportKind::Udp,
                DnsQueryTransportKind::Tcp,
            ]
        );
    }

    struct FixedResolver(SocketAddr);

    #[async_trait::async_trait]
    impl DnsResolver for FixedResolver {
        async fn resolve(&self, _domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            Ok(SocketAddr::new(self.0.ip(), port))
        }
    }

    struct PendingQueryTransport;

    #[async_trait::async_trait]
    impl DnsQueryTransport for PendingQueryTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            _transport: DnsQueryTransportKind,
            _query: &[u8],
        ) -> io::Result<Vec<u8>> {
            std::future::pending().await
        }
    }

    struct ResponseCodeQueryTransport {
        response_code: u16,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for ResponseCodeQueryTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(build_test_empty_response(query, self.response_code))
        }
    }

    #[tokio::test]
    async fn configured_dns_nxdomain_is_terminal_and_does_not_use_fallback() {
        let fallback = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: Some(SocketAddr::from(([192, 0, 2, 70], 0))),
        });
        let transport = Arc::new(ResponseCodeQueryTransport {
            response_code: 3,
            calls: AtomicUsize::new(0),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
            fallback.clone(),
        )
        .with_query_transport(transport.clone());

        let error = resolver.resolve("missing.example", 443).await.unwrap_err();

        assert!(matches!(
            error,
            TransportError::DnsNameError(domain, 443) if domain == "missing.example"
        ));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 2);
        assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn configured_dns_nodata_is_terminal_after_a_and_aaaa() {
        let fallback = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: Some(SocketAddr::from(([192, 0, 2, 71], 0))),
        });
        let transport = Arc::new(ResponseCodeQueryTransport {
            response_code: 0,
            calls: AtomicUsize::new(0),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
            fallback.clone(),
        )
        .with_query_transport(transport.clone());

        let error = resolver.resolve("nodata.example", 443).await.unwrap_err();

        assert!(matches!(
            error,
            TransportError::DnsNoData(domain, 443) if domain == "nodata.example"
        ));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 2);
        assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn configured_dns_single_family_negative_is_terminal() {
        let fallback = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: Some(SocketAddr::from(([192, 0, 2, 71], 0))),
        });
        let transport = Arc::new(ResponseCodeQueryTransport {
            response_code: 3,
            calls: AtomicUsize::new(0),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
            fallback.clone(),
        )
        .with_query_strategy(DnsQueryStrategy::UseIpv6)
        .with_query_transport(transport.clone());

        let error = resolver
            .resolve("missing-v6.example", 443)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            TransportError::DnsNameError(domain, 443) if domain == "missing-v6.example"
        ));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
        assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
    }

    struct FirstServerResponseCodeTransport {
        first: NameServer,
        response_code: u16,
        calls: Mutex<Vec<NameServer>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for FirstServerResponseCodeTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(server.clone());
            if server == &self.first {
                Ok(build_test_empty_response(query, self.response_code))
            } else {
                Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 72)))
            }
        }
    }

    #[tokio::test]
    async fn configured_dns_servfail_moves_to_the_next_server() {
        let first = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let second = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let transport = Arc::new(FirstServerResponseCodeTransport {
            first: first.clone(),
            response_code: 2,
            calls: Mutex::new(Vec::new()),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![first.clone(), second.clone()],
            Arc::new(RejectingResolver),
        )
        .with_query_transport(transport.clone());

        let resolved = resolver.resolve("servfail.example", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 72], 443)));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            vec![first.clone(), first, second.clone(), second]
        );
    }

    #[tokio::test]
    async fn configured_dns_single_family_failover_queries_each_server_once() {
        let first = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let second = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let transport = Arc::new(FirstServerResponseCodeTransport {
            first: first.clone(),
            response_code: 2,
            calls: Mutex::new(Vec::new()),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![first.clone(), second.clone()],
            Arc::new(RejectingResolver),
        )
        .with_query_strategy(DnsQueryStrategy::UseIpv4)
        .with_query_transport(transport.clone());

        let resolved = resolver.resolve("servfail-v4.example", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 72], 443)));
        assert_eq!(*transport.calls.lock().unwrap(), [first, second]);
    }

    #[derive(Default)]
    struct RecordingAddressQueryTransport {
        calls: Mutex<Vec<(NameServer, u16)>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for RecordingAddressQueryTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let (_, record_type, _) = super::parse_dns_question(query)?;
            self.calls
                .lock()
                .unwrap()
                .push((server.clone(), record_type));
            Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 73)))
        }
    }

    #[tokio::test]
    async fn configured_dns_intersects_global_and_per_server_query_strategy() {
        let server = NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)));
        let transport = Arc::new(RecordingAddressQueryTransport::default());
        let mut policy = NameServerPolicy::new(server.clone());
        policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![policy])
                .with_query_strategy(DnsQueryStrategy::UseIp)
                .with_query_transport(transport.clone());

        let resolved = resolver.resolve("strategy.example", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 73], 443)));
        assert_eq!(*transport.calls.lock().unwrap(), [(server, 1)]);
    }

    struct StickyCnameQueryTransport {
        cname_server: NameServer,
        calls: Mutex<Vec<(NameServer, String)>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for StickyCnameQueryTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let (domain, record_type, _) = super::parse_dns_question(query)?;
            if record_type != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sticky CNAME test expects only A queries",
                ));
            }
            self.calls
                .lock()
                .unwrap()
                .push((server.clone(), domain.clone()));
            if server != &self.cname_server {
                if domain == "origin.internal.test" {
                    return Ok(build_test_empty_response(query, 2));
                }
                return Ok(build_test_a_response(
                    query,
                    Ipv4Addr::new(198, 51, 100, 99),
                ));
            }
            if domain == "origin.internal.test" {
                Ok(build_test_cname_response(query, "alias.public.test"))
            } else {
                Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 74)))
            }
        }
    }

    #[tokio::test]
    async fn configured_dns_keeps_cname_follow_on_the_answering_server() {
        let failing_internal = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let cname_internal = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let public = NameServer::Socket(SocketAddr::from(([192, 0, 2, 3], 53)));
        let mut failing_policy = NameServerPolicy::new(failing_internal.clone());
        failing_policy.domains = vec![TransportDomainMatcher::Suffix("internal.test".to_owned())];
        let mut cname_policy = NameServerPolicy::new(cname_internal.clone());
        cname_policy.domains = vec![TransportDomainMatcher::Suffix("internal.test".to_owned())];
        let mut public_policy = NameServerPolicy::new(public);
        public_policy.domains = vec![TransportDomainMatcher::Suffix("public.test".to_owned())];
        let transport = Arc::new(StickyCnameQueryTransport {
            cname_server: cname_internal.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![failing_policy, cname_policy, public_policy])
                .with_name_server_fallback_policy(false, true)
                .with_query_strategy(DnsQueryStrategy::UseIpv4)
                .with_query_transport(transport.clone());

        let resolved = resolver.resolve("origin.internal.test", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 74], 443)));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            [
                (failing_internal, "origin.internal.test".to_owned(),),
                (cname_internal.clone(), "origin.internal.test".to_owned()),
                (cname_internal, "alias.public.test".to_owned()),
            ]
        );
    }

    struct FilteredCnameFailoverQueryTransport {
        filtered_server: NameServer,
        calls: Mutex<Vec<(NameServer, String)>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for FilteredCnameFailoverQueryTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let (domain, record_type, _) = super::parse_dns_question(query)?;
            if record_type != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "filtered CNAME test expects only A queries",
                ));
            }
            self.calls
                .lock()
                .unwrap()
                .push((server.clone(), domain.clone()));

            if server == &self.filtered_server {
                return if domain == "origin.filtered.test" {
                    Ok(build_test_cname_response(query, "alias.filtered.test"))
                } else {
                    Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 75)))
                };
            }

            if domain != "origin.filtered.test" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "server failover must restart from the original query name",
                ));
            }
            Ok(build_test_a_response(
                query,
                Ipv4Addr::new(198, 51, 100, 75),
            ))
        }
    }

    #[tokio::test]
    async fn configured_dns_filtered_cname_answer_fails_over_with_original_query_name() {
        let filtered = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let fallback = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let mut filtered_policy = NameServerPolicy::new(filtered.clone());
        filtered_policy.expected_ips =
            DnsIpFilter::hard(vec![dns_ip_cidr("203.0.113.0", 24)], Vec::new());
        let transport = Arc::new(FilteredCnameFailoverQueryTransport {
            filtered_server: filtered.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![
                    filtered_policy,
                    NameServerPolicy::new(fallback.clone()),
                ])
                .with_query_strategy(DnsQueryStrategy::UseIpv4)
                .with_query_transport(transport.clone());

        let resolved = resolver.resolve("origin.filtered.test", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([198, 51, 100, 75], 443)));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            [
                (filtered.clone(), "origin.filtered.test".to_owned()),
                (filtered, "alias.filtered.test".to_owned()),
                (fallback, "origin.filtered.test".to_owned()),
            ]
        );
    }

    struct CnameThenUnavailableQueryTransport;

    #[async_trait::async_trait]
    impl DnsQueryTransport for CnameThenUnavailableQueryTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let (domain, _, _) = super::parse_dns_question(query)?;
            if domain == "origin.internal.test" {
                Ok(build_test_cname_response(query, "alias.public.test"))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "CNAME continuation unavailable",
                ))
            }
        }
    }

    #[tokio::test]
    async fn configured_dns_cname_continuation_does_not_leak_to_outer_fallback() {
        let fallback = Arc::new(DelayedCountingResolver {
            calls: AtomicUsize::new(0),
            result: Some(SocketAddr::from(([198, 51, 100, 99], 0))),
        });
        let mut policy = policy(1);
        policy.domains = vec![TransportDomainMatcher::Suffix("internal.test".to_owned())];
        let resolver = ConfiguredDnsResolver::new(Vec::new(), Vec::new(), fallback.clone())
            .with_name_server_policies(vec![policy])
            .with_name_server_fallback_policy(false, true)
            .with_query_strategy(DnsQueryStrategy::UseIpv4)
            .with_query_transport(Arc::new(CnameThenUnavailableQueryTransport));

        let error = resolver
            .resolve("origin.internal.test", 443)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            TransportError::DnsNoData(domain, 443) if domain == "origin.internal.test"
        ));
        assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn configured_dns_nxdomain_moves_to_the_next_server() {
        let first = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let second = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let transport = Arc::new(FirstServerResponseCodeTransport {
            first: first.clone(),
            response_code: 3,
            calls: Mutex::new(Vec::new()),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![first.clone(), second.clone()],
            Arc::new(RejectingResolver),
        )
        .with_query_transport(transport.clone());

        let resolved = resolver.resolve("nxdomain.example", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 72], 443)));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            vec![first.clone(), first, second.clone(), second]
        );
    }

    struct PendingResolver;

    #[async_trait::async_trait]
    impl DnsResolver for PendingResolver {
        async fn resolve(&self, _domain: &str, _port: u16) -> Result<SocketAddr, TransportError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn configured_dns_resolution_timeout_includes_system_fallback() {
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(PendingResolver))
                .with_resolution_timeout(Duration::from_millis(10));

        let error = resolver
            .resolve("bounded-fallback.example", 443)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            TransportError::Dns { source, .. }
                if source.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_bounds_system_fallback_by_default() {
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(PendingResolver));
        let started_at = tokio::time::Instant::now();

        let error = resolver
            .resolve("default-bounded-fallback.example", 443)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            TransportError::Dns { source, .. }
                if source.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(started_at.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_bounds_alias_depth_system_fallback_with_policies() {
        let host_rules = (0..8)
            .map(|index| StaticHostRule {
                matcher: TransportDomainMatcher::Full(format!("alias{index}.example")),
                target: StaticHostTarget::Domain(format!("alias{}.example", index + 1)),
            })
            .collect();
        let policy =
            NameServerPolicy::new(NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53))));
        let resolver =
            ConfiguredDnsResolver::new(host_rules, Vec::new(), Arc::new(PendingResolver))
                .with_name_server_policies(vec![policy]);
        let started_at = tokio::time::Instant::now();

        let error = resolver.resolve("alias0.example", 443).await.unwrap_err();

        assert!(matches!(
            error,
            TransportError::Dns { source, .. }
                if source.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(started_at.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_can_leave_bootstrap_fallback_to_an_outer_deadline() {
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(PendingResolver))
                .without_system_fallback_timeout();
        let started_at = tokio::time::Instant::now();

        let result = tokio::time::timeout(
            Duration::from_secs(6),
            resolver.resolve("outer-bounded.example", 443),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(started_at.elapsed(), Duration::from_secs(6));
    }

    struct FirstServerPendingTransport {
        first: NameServer,
        calls: Mutex<Vec<(NameServer, u16)>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for FirstServerPendingTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let record_type = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
            self.calls
                .lock()
                .unwrap()
                .push((server.clone(), record_type));
            if server == &self.first {
                std::future::pending().await
            } else {
                Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 62)))
            }
        }
    }

    struct FreshServerDeadlineTransport {
        first: NameServer,
        calls: Mutex<Vec<NameServer>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for FreshServerDeadlineTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(server.clone());
            if server == &self.first {
                std::future::pending().await
            } else {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 64)))
            }
        }
    }

    struct PendingAaaaQueryTransport;

    #[async_trait::async_trait]
    impl DnsQueryTransport for PendingAaaaQueryTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let record_type = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
            if record_type == 1 {
                Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 63)))
            } else {
                std::future::pending().await
            }
        }
    }

    struct ExchangeDropGuard(Arc<AtomicBool>);

    impl Drop for ExchangeDropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct DropObservedPendingTransport {
        dropped: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for DropObservedPendingTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            _transport: DnsQueryTransportKind,
            _query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let _guard = ExchangeDropGuard(Arc::clone(&self.dropped));
            std::future::pending().await
        }
    }

    struct NxdomainPendingAaaaQueryTransport;

    #[async_trait::async_trait]
    impl DnsQueryTransport for NxdomainPendingAaaaQueryTransport {
        async fn exchange(
            &self,
            _server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let record_type = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
            if record_type == 1 {
                Ok(build_test_empty_response(query, 3))
            } else {
                std::future::pending().await
            }
        }
    }

    struct TcpRetryRemainderTransport {
        first: NameServer,
        calls: Mutex<Vec<(NameServer, DnsQueryTransportKind)>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for TcpRetryRemainderTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            self.calls.lock().unwrap().push((server.clone(), transport));
            if server != &self.first {
                return Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 65)));
            }

            tokio::time::sleep(Duration::from_millis(7)).await;
            match transport {
                DnsQueryTransportKind::Udp => Ok(build_test_truncated_response(query)),
                DnsQueryTransportKind::Tcp => {
                    Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 66)))
                }
            }
        }
    }

    struct CnameDeadlineTransport {
        first: NameServer,
        calls: Mutex<Vec<(NameServer, String)>>,
    }

    #[async_trait::async_trait]
    impl DnsQueryTransport for CnameDeadlineTransport {
        async fn exchange(
            &self,
            server: &NameServer,
            _transport: DnsQueryTransportKind,
            query: &[u8],
        ) -> io::Result<Vec<u8>> {
            let (domain, record_type, _) = super::parse_dns_question(query)?;
            if record_type != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CNAME deadline test expects only A queries",
                ));
            }
            self.calls
                .lock()
                .unwrap()
                .push((server.clone(), domain.clone()));
            if server != &self.first {
                if domain != "origin.deadline.test" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "server failover must restart from the original query name",
                    ));
                }
                return Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 67)));
            }

            tokio::time::sleep(Duration::from_millis(7)).await;
            if domain == "origin.deadline.test" {
                Ok(build_test_cname_response(query, "alias.deadline.test"))
            } else {
                Ok(build_test_a_response(query, Ipv4Addr::new(192, 0, 2, 68)))
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_default_server_timeout_matches_xray_four_seconds() {
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)))],
            Arc::new(RejectingResolver),
        )
        .with_query_strategy(DnsQueryStrategy::UseIpv4)
        .with_query_transport(Arc::new(PendingQueryTransport));
        let started_at = tokio::time::Instant::now();

        let error = resolver
            .resolve("default-timeout.example", 443)
            .await
            .unwrap_err();

        assert!(matches!(error, TransportError::Dns { source, .. }
            if source.kind() == io::ErrorKind::NotConnected));
        assert_eq!(started_at.elapsed(), Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_policy_timeout_overrides_resolver_default() {
        let mut policy =
            NameServerPolicy::new(NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53))));
        policy.timeout = Some(Duration::from_millis(10));
        policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![policy])
                .with_query_strategy(DnsQueryStrategy::UseIpv4)
                .with_query_transport(Arc::new(PendingQueryTransport))
                .with_server_timeout(Duration::from_millis(1));
        let started_at = tokio::time::Instant::now();

        let error = resolver
            .resolve("policy-timeout.example", 443)
            .await
            .unwrap_err();

        assert!(matches!(error, TransportError::Dns { source, .. }
            if source.kind() == io::ErrorKind::NotConnected));
        assert_eq!(started_at.elapsed(), Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_domain_bootstrap_consumes_the_candidate_deadline() {
        let mut policy = NameServerPolicy::new(NameServer::Domain {
            domain: "resolver.example".to_owned(),
            port: 53,
        });
        policy.timeout = Some(Duration::from_secs(6));
        policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(PendingResolver))
                .with_name_server_policies(vec![policy])
                .with_query_strategy(DnsQueryStrategy::UseIpv4);
        let started_at = tokio::time::Instant::now();

        let error = resolver
            .resolve("domain-bootstrap.example", 443)
            .await
            .unwrap_err();

        assert!(matches!(error, TransportError::Dns { source, .. }
            if source.kind() == io::ErrorKind::NotConnected));
        assert_eq!(started_at.elapsed(), Duration::from_secs(6));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_timeout_drops_the_in_flight_exchange_future() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut policy =
            NameServerPolicy::new(NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53))));
        policy.timeout = Some(Duration::from_millis(10));
        policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![policy])
                .with_query_strategy(DnsQueryStrategy::UseIpv4)
                .with_query_transport(Arc::new(DropObservedPendingTransport {
                    dropped: Arc::clone(&dropped),
                }));

        let _ = resolver.resolve("cancel.example", 443).await;

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_tcp_retry_uses_only_the_remaining_policy_budget() {
        let first = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let second = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let mut first_policy = NameServerPolicy::new(first.clone());
        first_policy.timeout = Some(Duration::from_millis(10));
        first_policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let mut second_policy = NameServerPolicy::new(second.clone());
        second_policy.timeout = Some(Duration::from_millis(20));
        second_policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let transport = Arc::new(TcpRetryRemainderTransport {
            first: first.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![first_policy, second_policy])
                .with_query_strategy(DnsQueryStrategy::UseIpv4)
                .with_query_transport(transport.clone());
        let started_at = tokio::time::Instant::now();

        let resolved = resolver
            .resolve("tcp-remainder.example", 443)
            .await
            .unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 65], 443)));
        assert_eq!(started_at.elapsed(), Duration::from_millis(10));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            [
                (first.clone(), DnsQueryTransportKind::Udp),
                (first, DnsQueryTransportKind::Tcp),
                (second, DnsQueryTransportKind::Udp),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_cname_chain_shares_policy_deadline_and_failover_restarts_qname() {
        let first = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let second = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let mut first_policy = NameServerPolicy::new(first.clone());
        first_policy.timeout = Some(Duration::from_millis(10));
        first_policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let mut second_policy = NameServerPolicy::new(second.clone());
        second_policy.timeout = Some(Duration::from_millis(20));
        second_policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let transport = Arc::new(CnameDeadlineTransport {
            first: first.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![first_policy, second_policy])
                .with_query_strategy(DnsQueryStrategy::UseIpv4)
                .with_query_transport(transport.clone());
        let started_at = tokio::time::Instant::now();

        let resolved = resolver.resolve("origin.deadline.test", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 67], 443)));
        assert_eq!(started_at.elapsed(), Duration::from_millis(10));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            [
                (first.clone(), "origin.deadline.test".to_owned()),
                (first, "alias.deadline.test".to_owned()),
                (second, "origin.deadline.test".to_owned()),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_keeps_positive_family_at_the_shared_policy_deadline() {
        let mut policy =
            NameServerPolicy::new(NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53))));
        policy.timeout = Some(Duration::from_millis(10));
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![policy])
                .with_query_transport(Arc::new(PendingAaaaQueryTransport));
        let started_at = tokio::time::Instant::now();

        let lookup = resolver.resolve_all("partial.example", 443).await.unwrap();

        assert_eq!(
            lookup.socket_addrs(),
            &[SocketAddr::from(([192, 0, 2, 63], 443))]
        );
        assert!(lookup
            .ttl()
            .is_some_and(|ttl| { ttl < Duration::from_secs(60) && ttl > Duration::from_secs(59) }));
        assert_eq!(started_at.elapsed(), Duration::from_millis(10));
    }

    #[tokio::test]
    async fn configured_dns_nxdomain_wins_when_other_family_times_out() {
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)))],
            Arc::new(RejectingResolver),
        )
        .with_query_transport(Arc::new(NxdomainPendingAaaaQueryTransport))
        .with_server_timeout(Duration::from_millis(10));

        let error = resolver.resolve("missing.example", 443).await.unwrap_err();

        assert!(matches!(
            error,
            TransportError::DnsNameError(domain, 443) if domain == "missing.example"
        ));
    }

    #[tokio::test]
    async fn configured_dns_gives_each_server_one_a_and_aaaa_budget() {
        let first = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let second = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let transport = Arc::new(FirstServerPendingTransport {
            first: first.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![first.clone(), second.clone()],
            Arc::new(RejectingResolver),
        )
        .with_query_transport(transport.clone())
        .with_server_timeout(Duration::from_millis(20))
        .with_resolution_timeout(Duration::from_millis(200));

        let resolved = resolver.resolve("failover.example", 443).await.unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 62], 443)));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            vec![
                (first.clone(), 1),
                (first, 28),
                (second.clone(), 1),
                (second, 28)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_gives_each_policy_a_fresh_deadline_without_hidden_overall_cap() {
        let first = NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)));
        let second = NameServer::Socket(SocketAddr::from(([192, 0, 2, 2], 53)));
        let mut first_policy = NameServerPolicy::new(first.clone());
        first_policy.timeout = Some(Duration::from_secs(4));
        first_policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let mut second_policy = NameServerPolicy::new(second.clone());
        second_policy.timeout = Some(Duration::from_secs(3));
        second_policy.query_strategy = DnsQueryStrategy::UseIpv4;
        let transport = Arc::new(FreshServerDeadlineTransport {
            first: first.clone(),
            calls: Mutex::new(Vec::new()),
        });
        let resolver =
            ConfiguredDnsResolver::new(Vec::new(), Vec::new(), Arc::new(RejectingResolver))
                .with_name_server_policies(vec![first_policy, second_policy])
                .with_query_strategy(DnsQueryStrategy::UseIpv4)
                .with_query_transport(transport.clone());
        let started_at = tokio::time::Instant::now();

        let resolved = resolver
            .resolve("fresh-deadline.example", 443)
            .await
            .unwrap();

        assert_eq!(resolved, SocketAddr::from(([192, 0, 2, 64], 443)));
        assert_eq!(started_at.elapsed(), Duration::from_secs(6));
        assert_eq!(*transport.calls.lock().unwrap(), [first, second]);
    }

    #[tokio::test(start_paused = true)]
    async fn configured_dns_bounds_the_whole_server_alias_and_fallback_sequence() {
        let fallback = SocketAddr::from(([192, 0, 2, 40], 0));
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
            Arc::new(FixedResolver(fallback)),
        )
        .with_query_transport(Arc::new(PendingQueryTransport))
        .with_resolution_timeout(Duration::from_millis(10));

        let started_at = tokio::time::Instant::now();

        let error = resolver.resolve("bounded.example", 8443).await.unwrap_err();

        assert!(matches!(
            error,
            TransportError::Dns { source, .. }
                if source.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(started_at.elapsed(), Duration::from_millis(10));
    }

    fn build_test_truncated_response(query: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(query.len());
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8380_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response
    }

    fn build_test_a_response(query: &[u8], answer: Ipv4Addr) -> Vec<u8> {
        build_test_address_response(query, &[(1, 60, answer.octets().to_vec())])
    }

    fn build_test_address_response(query: &[u8], answers: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut response = Vec::with_capacity(query.len() + answers.len() * 28);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        for (record_type, ttl, answer) in answers {
            response.extend_from_slice(&0xC00C_u16.to_be_bytes());
            response.extend_from_slice(&record_type.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&ttl.to_be_bytes());
            response.extend_from_slice(&(answer.len() as u16).to_be_bytes());
            response.extend_from_slice(answer);
        }
        response
    }

    fn build_test_cname_and_a_response(query: &[u8], alias: &str, answer: Ipv4Addr) -> Vec<u8> {
        let encoded_alias = encode_test_dns_name(alias);
        let mut response = Vec::with_capacity(query.len() + encoded_alias.len() * 2 + 42);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&2_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);

        response.extend_from_slice(&encoded_alias);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&90_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&answer.octets());

        response.extend_from_slice(&0xC00C_u16.to_be_bytes());
        response.extend_from_slice(&5_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&20_u32.to_be_bytes());
        response.extend_from_slice(&(encoded_alias.len() as u16).to_be_bytes());
        response.extend_from_slice(&encoded_alias);
        response
    }

    fn build_test_cname_response(query: &[u8], alias: &str) -> Vec<u8> {
        let encoded_alias = encode_test_dns_name(alias);
        let mut response = Vec::with_capacity(query.len() + encoded_alias.len() + 18);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&0xC00C_u16.to_be_bytes());
        response.extend_from_slice(&5_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&20_u32.to_be_bytes());
        response.extend_from_slice(&(encoded_alias.len() as u16).to_be_bytes());
        response.extend_from_slice(&encoded_alias);
        response
    }

    fn encode_test_dns_name(domain: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in domain.split('.') {
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0);
        encoded
    }

    fn build_test_empty_response(query: &[u8], response_code: u16) -> Vec<u8> {
        let mut response = Vec::with_capacity(query.len());
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&(0x8180_u16 | response_code).to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response
    }
}
