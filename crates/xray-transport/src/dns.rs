use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
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

pub struct ConfiguredDnsResolver {
    host_rules: Vec<StaticHostRule>,
    name_servers: Vec<NameServer>,
    fallback: Arc<dyn DnsResolver>,
    server_timeout: Duration,
    resolution_timeout: Duration,
    query_transport: Arc<dyn DnsQueryTransport>,
    uses_direct_query_transport: bool,
    query_strategy: DnsQueryStrategy,
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
            name_servers,
            fallback,
            server_timeout: Duration::from_secs(2),
            resolution_timeout: DNS_RESOLUTION_TIMEOUT,
            query_transport,
            uses_direct_query_transport: true,
            query_strategy: DnsQueryStrategy::default(),
        }
    }

    pub fn with_query_strategy(mut self, query_strategy: DnsQueryStrategy) -> Self {
        self.query_strategy = query_strategy;
        self
    }

    pub fn with_server_timeout(mut self, timeout: Duration) -> Self {
        self.server_timeout = timeout;
        self
    }

    pub fn with_resolution_timeout(mut self, timeout: Duration) -> Self {
        self.resolution_timeout = timeout;
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

    async fn query_configured_servers(&self, domain: &str) -> ConfiguredServersResult {
        let mut last_negative = None;
        for name_server in &self.name_servers {
            match self.query_configured_server(name_server, domain).await {
                Ok(ConfiguredServerResult::Answer(answer)) => {
                    return ConfiguredServersResult::Answer(answer);
                }
                Ok(ConfiguredServerResult::Negative(negative)) => {
                    last_negative = Some(negative);
                }
                Err(_) => {}
            }
        }

        last_negative.map_or(
            ConfiguredServersResult::Unavailable,
            ConfiguredServersResult::Negative,
        )
    }

    async fn query_configured_server(
        &self,
        name_server: &NameServer,
        domain: &str,
    ) -> io::Result<ConfiguredServerResult> {
        match self.query_strategy {
            DnsQueryStrategy::UseIp => {
                let (ipv4, ipv6) = tokio::join!(
                    self.query_server_with_budget(name_server, domain, DnsRecordType::A),
                    self.query_server_with_budget(name_server, domain, DnsRecordType::Aaaa),
                );
                merge_configured_family_results([ipv4, ipv6])
            }
            DnsQueryStrategy::UseIpv4 => merge_configured_family_results([self
                .query_server_with_budget(name_server, domain, DnsRecordType::A)
                .await]),
            DnsQueryStrategy::UseIpv6 => merge_configured_family_results([self
                .query_server_with_budget(name_server, domain, DnsRecordType::Aaaa)
                .await]),
        }
    }

    async fn query_server_with_budget(
        &self,
        name_server: &NameServer,
        domain: &str,
        record_type: DnsRecordType,
    ) -> io::Result<(ParsedDnsResponse, Instant)> {
        time::timeout(
            self.server_timeout,
            self.query_server(name_server, domain, record_type),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns server budget expired"))?
    }

    async fn query_server(
        &self,
        name_server: &NameServer,
        domain: &str,
        record_type: DnsRecordType,
    ) -> io::Result<(ParsedDnsResponse, Instant)> {
        let query = build_dns_query(domain, record_type)?;
        let response = time::timeout(
            self.server_timeout,
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
                let response = time::timeout(
                    self.server_timeout,
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
            let result = self.query_configured_servers(&current_domain).await;
            ttl_cap = age_ttl_cap(ttl_cap, started_at.elapsed());
            match result {
                ConfiguredServersResult::Answer(ConfiguredDnsAnswer::Addresses(answer)) => {
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
                ConfiguredServersResult::Answer(ConfiguredDnsAnswer::Cname { alias, ttl }) => {
                    ttl_cap = Some(ttl_cap.map_or(ttl, |current: Duration| current.min(ttl)));
                    let alias = normalize_dns_name(&alias).unwrap_or(alias);
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
                }
                ConfiguredServersResult::Negative(negative) => {
                    return ConfiguredLookupResult::Negative {
                        domain: current_domain,
                        negative,
                    };
                }
                ConfiguredServersResult::Unavailable => break,
            }
        }

        ConfiguredLookupResult::Fallback {
            domain: current_domain,
            ttl_cap,
        }
    }
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
                    self.fallback
                        .resolve_all(&domain, port)
                        .await
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
            }
        };
        match time::timeout(self.resolution_timeout, resolution).await {
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
    Answer(ConfiguredDnsAnswer),
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::net::UdpSocket;
    use tokio::sync::{oneshot, Barrier, Notify};

    use super::{
        build_dns_query_with_id, parse_dns_response, query_udp_dns_server, CachingDnsResolver,
        ConfiguredDnsAddresses, ConfiguredDnsAnswer, ConfiguredDnsResolver, DnsLookup,
        DnsQueryStrategy, DnsQueryTransport, DnsQueryTransportKind, DnsRecordType, DnsResolver,
        NameServer, StaticHostRule, StaticHostTarget, TransportDomainMatcher,
        DNS_CACHE_MAX_ENTRIES,
    };
    use crate::{SocketHandle, SocketProtector, TransportError};

    #[test]
    fn build_dns_query_uses_injected_transaction_id() {
        let query = build_dns_query_with_id("example.com", DnsRecordType::A, 0xA17E)
            .expect("valid query should encode");

        assert_eq!(&query[..2], &0xA17E_u16.to_be_bytes());
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

    #[tokio::test]
    async fn configured_dns_keeps_positive_family_when_other_family_times_out() {
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 1], 53)))],
            Arc::new(RejectingResolver),
        )
        .with_query_transport(Arc::new(PendingAaaaQueryTransport))
        .with_server_timeout(Duration::from_millis(10));

        let lookup = resolver.resolve_all("partial.example", 443).await.unwrap();

        assert_eq!(
            lookup.socket_addrs(),
            &[SocketAddr::from(([192, 0, 2, 63], 443))]
        );
        assert!(lookup
            .ttl()
            .is_some_and(|ttl| { ttl < Duration::from_secs(60) && ttl > Duration::from_secs(59) }));
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

    #[tokio::test]
    async fn configured_dns_bounds_the_whole_server_alias_and_fallback_sequence() {
        let fallback = SocketAddr::from(([192, 0, 2, 40], 0));
        let resolver = ConfiguredDnsResolver::new(
            Vec::new(),
            vec![NameServer::Socket(SocketAddr::from(([192, 0, 2, 53], 53)))],
            Arc::new(FixedResolver(fallback)),
        )
        .with_query_transport(Arc::new(PendingQueryTransport))
        .with_resolution_timeout(Duration::from_millis(10));

        let error = resolver.resolve("bounded.example", 8443).await.unwrap_err();

        assert!(matches!(
            error,
            TransportError::Dns { source, .. }
                if source.kind() == io::ErrorKind::TimedOut
        ));
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
