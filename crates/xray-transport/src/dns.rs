use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time;

use crate::{SocketHandle, SocketProtector, TransportError};

/// Resolves a domain and configured port into the concrete socket address to dial.
///
/// Callers pass the configured port and dial the returned `SocketAddr` as-is.
/// This keeps platform-specific DNS and deterministic test resolvers explicit.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        let mut addrs = tokio::net::lookup_host((domain, port))
            .await
            .map_err(|source| TransportError::Dns {
                domain: domain.to_owned(),
                port,
                source,
            })?;

        addrs
            .next()
            .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
    }
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_CACHE_MAX_ENTRIES: usize = 256;

/// TTL cache over another resolver. Proxy clients open a new outbound
/// connection per session; resolving the (usually single) server domain on
/// every connect adds tens of milliseconds on mobile networks.
pub struct CachingDnsResolver {
    inner: Arc<dyn DnsResolver>,
    ttl: Duration,
    cache: Mutex<HashMap<(String, u16), (SocketAddr, Instant)>>,
}

impl CachingDnsResolver {
    pub fn new(inner: Arc<dyn DnsResolver>) -> Self {
        Self::with_ttl(inner, DNS_CACHE_TTL)
    }

    pub fn with_ttl(inner: Arc<dyn DnsResolver>, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl DnsResolver for CachingDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        let key = (domain.to_owned(), port);
        let now = Instant::now();
        {
            let cache = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some((addr, stored_at)) = cache.get(&key) {
                if now.duration_since(*stored_at) < self.ttl {
                    return Ok(*addr);
                }
            }
        }

        let addr = self.inner.resolve(domain, port).await?;

        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.retain(|_, (_, stored_at)| now.duration_since(*stored_at) < self.ttl);
        }
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.clear();
        }
        cache.insert(key, (addr, now));
        Ok(addr)
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
            Self::Full(expected) => domain.eq_ignore_ascii_case(expected),
            Self::Suffix(suffix) => domain_matches_suffix(domain, suffix),
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
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameServer {
    Socket(SocketAddr),
    Domain { domain: String, port: u16 },
}

pub struct ConfiguredDnsResolver {
    host_rules: Vec<StaticHostRule>,
    name_servers: Vec<NameServer>,
    fallback: Arc<dyn DnsResolver>,
    server_timeout: Duration,
    socket_protector: Option<Arc<dyn SocketProtector>>,
}

impl ConfiguredDnsResolver {
    pub fn new(
        host_rules: Vec<StaticHostRule>,
        name_servers: Vec<NameServer>,
        fallback: Arc<dyn DnsResolver>,
    ) -> Self {
        Self {
            host_rules,
            name_servers,
            fallback,
            server_timeout: Duration::from_secs(2),
            socket_protector: None,
        }
    }

    pub fn with_server_timeout(mut self, timeout: Duration) -> Self {
        self.server_timeout = timeout;
        self
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.socket_protector = Some(protector);
        self
    }

    fn matching_host_rule(&self, domain: &str) -> Option<&StaticHostRule> {
        self.host_rules
            .iter()
            .find(|rule| rule.matcher.matches(domain))
    }

    async fn query_configured_servers(&self, domain: &str) -> Option<ConfiguredDnsAnswer> {
        for name_server in &self.name_servers {
            let server_addr = match name_server {
                NameServer::Socket(addr) => *addr,
                NameServer::Domain {
                    domain: server_domain,
                    port,
                } => {
                    let Ok(addr) = self.fallback.resolve(server_domain, *port).await else {
                        continue;
                    };
                    addr
                }
            };

            if let Ok(Some(answer)) = query_udp_dns_server(
                server_addr,
                domain,
                DnsRecordType::A,
                self.server_timeout,
                self.socket_protector.as_deref(),
            )
            .await
            {
                return Some(answer);
            }

            if let Ok(Some(answer)) = query_udp_dns_server(
                server_addr,
                domain,
                DnsRecordType::Aaaa,
                self.server_timeout,
                self.socket_protector.as_deref(),
            )
            .await
            {
                return Some(answer);
            }
        }

        None
    }
}

#[async_trait]
impl DnsResolver for ConfiguredDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        const MAX_ALIAS_DEPTH: usize = 8;

        let mut current_domain = domain.to_owned();
        for depth in 0..MAX_ALIAS_DEPTH {
            if let Some(rule) = self.matching_host_rule(&current_domain) {
                match &rule.target {
                    StaticHostTarget::Ip(ip) => return Ok(SocketAddr::new(*ip, port)),
                    StaticHostTarget::Domain(alias) => {
                        if alias.eq_ignore_ascii_case(&current_domain) {
                            break;
                        }
                        if depth + 1 == MAX_ALIAS_DEPTH {
                            return self.fallback.resolve(domain, port).await;
                        }
                        current_domain = alias.clone();
                        continue;
                    }
                }
            }

            match self.query_configured_servers(&current_domain).await {
                Some(ConfiguredDnsAnswer::Ip(ip)) => return Ok(SocketAddr::new(ip, port)),
                Some(ConfiguredDnsAnswer::Cname(alias)) => {
                    if alias.eq_ignore_ascii_case(&current_domain) {
                        break;
                    }
                    if depth + 1 == MAX_ALIAS_DEPTH {
                        return self.fallback.resolve(domain, port).await;
                    }
                    current_domain = alias;
                }
                None => break,
            }
        }

        self.fallback.resolve(&current_domain, port).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfiguredDnsAnswer {
    Ip(IpAddr),
    Cname(String),
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

async fn query_udp_dns_server(
    server_addr: SocketAddr,
    domain: &str,
    record_type: DnsRecordType,
    timeout: Duration,
    socket_protector: Option<&dyn SocketProtector>,
) -> io::Result<Option<ConfiguredDnsAnswer>> {
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
    let query = build_dns_query(domain, record_type)?;

    time::timeout(timeout, socket.send(&query))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns query send timed out"))??;

    let mut buffer = [0_u8; 1232];
    let len = time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns query timed out"))??;

    parse_dns_response(&query, &buffer[..len], record_type)
}

fn build_dns_query(domain: &str, record_type: DnsRecordType) -> io::Result<Vec<u8>> {
    build_dns_query_with_id(domain, record_type, rand::random())
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

fn parse_dns_response(
    query: &[u8],
    packet: &[u8],
    requested_type: DnsRecordType,
) -> io::Result<Option<ConfiguredDnsAnswer>> {
    if packet.len() < 12 || query.len() < 2 || packet[0..2] != query[0..2] {
        return Ok(None);
    }

    let flags = read_u16(packet, 2)?;
    let rcode = flags & 0x000F;
    if flags & 0x8000 == 0 || rcode != 0 {
        return Ok(None);
    }

    let (expected_question, expected_type, expected_class) = parse_dns_question(query)?;
    if expected_type != requested_type.code() || expected_class != 1 {
        return Ok(None);
    }

    let question_count = read_u16(packet, 4)?;
    if question_count != 1 {
        return Ok(None);
    }
    let answer_count = read_u16(packet, 6)?;
    let mut offset = 12;

    let (response_question, response_type, response_class) =
        read_dns_question(packet, &mut offset)?;
    if response_question != expected_question
        || response_type != expected_type
        || response_class != expected_class
    {
        return Ok(None);
    }

    let mut accepted_answer_names = vec![expected_question];
    let mut cname = None;
    for _ in 0..answer_count {
        let owner_name = read_dns_name(packet, &mut offset)?;
        let record_type = read_u16(packet, offset)?;
        let record_class = read_u16(packet, offset + 2)?;
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

        if record_class == 1
            && record_type == requested_type.code()
            && accepted_answer_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&owner_name))
        {
            match requested_type {
                DnsRecordType::A if data_len == 4 => {
                    return Ok(Some(ConfiguredDnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(
                        packet[offset],
                        packet[offset + 1],
                        packet[offset + 2],
                        packet[offset + 3],
                    )))));
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
                    return Ok(Some(ConfiguredDnsAnswer::Ip(IpAddr::V6(Ipv6Addr::new(
                        segments[0],
                        segments[1],
                        segments[2],
                        segments[3],
                        segments[4],
                        segments[5],
                        segments[6],
                        segments[7],
                    )))));
                }
                _ => {}
            }
        } else if record_class == 1
            && record_type == 5
            && accepted_answer_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&owner_name))
        {
            let mut cname_offset = offset;
            let alias = read_dns_name_limited(packet, &mut cname_offset, data_end)?;
            if cname_offset != data_end {
                return Err(invalid_dns_response("dns cname rdata length mismatch"));
            }
            accepted_answer_names.push(alias.clone());
            cname = Some(alias);
        }

        offset = data_end;
    }

    Ok(cname.map(ConfiguredDnsAnswer::Cname))
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;

    use super::{
        build_dns_query_with_id, query_udp_dns_server, ConfiguredDnsAnswer, DnsRecordType,
    };
    use crate::{SocketHandle, SocketProtector};

    #[test]
    fn build_dns_query_uses_injected_transaction_id() {
        let query = build_dns_query_with_id("example.com", DnsRecordType::A, 0xA17E)
            .expect("valid query should encode");

        assert_eq!(&query[..2], &0xA17E_u16.to_be_bytes());
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
            ConfiguredDnsAnswer::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)))
        );
    }

    fn build_test_a_response(query: &[u8], answer: Ipv4Addr) -> Vec<u8> {
        let mut response = Vec::with_capacity(query.len() + 16);
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&0xC00C_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&answer.octets());
        response
    }
}
