use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use xray_routing::{
    DnsHostTarget, DomainHostIndex, DomainMatcher, Network, RegexMatcher, Target, TargetAddr,
};
use xray_transport::{
    CachingDnsResolver, ConfiguredDnsResolver, DnsResolver, NameServer, SystemDnsResolver,
    TcpConnector, TransportConnector, TransportError,
};

fn hosts<const N: usize>(
    rules: [(DomainMatcher, DnsHostTarget); N],
) -> DomainHostIndex<DnsHostTarget> {
    rules.into_iter().collect()
}

#[derive(Default)]
struct CountingResolver {
    calls: AtomicUsize,
}

#[async_trait]
impl DnsResolver for CountingResolver {
    async fn resolve(&self, _domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SocketAddr::from(([192, 0, 2, 1], port)))
    }
}

#[derive(Default)]
struct MapResolver {
    calls: AtomicUsize,
    answers: Mutex<HashMap<String, IpAddr>>,
}

impl MapResolver {
    fn with_answer(self, domain: &str, ip: IpAddr) -> Self {
        self.answers.lock().unwrap().insert(domain.to_owned(), ip);
        self
    }
}

#[async_trait]
impl DnsResolver for MapResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let ip = self
            .answers
            .lock()
            .unwrap()
            .get(domain)
            .copied()
            .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))?;
        Ok(SocketAddr::new(ip, port))
    }
}

#[tokio::test]
async fn caching_resolver_reuses_fresh_entries() {
    let inner = Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::from_secs(60));

    let first = resolver.resolve("example.com", 443).await.unwrap();
    let second = resolver.resolve("example.com", 443).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn caching_resolver_expires_entries() {
    let inner = Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::ZERO);

    resolver.resolve("example.com", 443).await.unwrap();
    resolver.resolve("example.com", 443).await.unwrap();

    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn caching_resolver_keys_by_domain_and_port() {
    let inner = Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::from_secs(60));

    resolver.resolve("example.com", 443).await.unwrap();
    resolver.resolve("example.com", 80).await.unwrap();

    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn system_dns_resolver_resolves_localhost_without_tcp_io() {
    let resolver = SystemDnsResolver;

    let addr = resolver.resolve("localhost", 443).await.unwrap();

    assert_eq!(addr.port(), 443);
}

#[tokio::test]
async fn tcp_connector_still_rejects_domain_targets_without_dns() {
    let connector = TcpConnector::new(xray_transport::ConnectorConfig::Tcp);
    let target = Target::new(
        TargetAddr::Domain("localhost".to_owned()),
        443,
        Network::Tcp,
    );

    let result = connector.connect(&target).await;

    assert!(matches!(result, Err(TransportError::NeedsDns(domain)) if domain == "localhost"));
}

#[tokio::test]
async fn configured_dns_hosts_ip_mapping_wins() {
    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        hosts([(
            DomainMatcher::Suffix("example.com".to_owned()),
            DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        )]),
        Vec::new(),
        fallback.clone(),
    );

    let addr = resolver.resolve("www.example.com", 443).await.unwrap();

    assert_eq!(addr, SocketAddr::from(([203, 0, 113, 7], 443)));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn configured_dns_hosts_domain_alias_uses_inner_resolution() {
    let fallback = Arc::new(
        MapResolver::default()
            .with_answer("alias.example", IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
    );
    let resolver = ConfiguredDnsResolver::new(
        hosts([(
            DomainMatcher::Suffix("service.example".to_owned()),
            DnsHostTarget::Domain("alias.example".to_owned()),
        )]),
        Vec::new(),
        fallback,
    );

    let addr = resolver
        .resolve("storage.service.example", 8443)
        .await
        .unwrap();

    assert_eq!(addr, SocketAddr::from(([198, 51, 100, 9], 8443)));
}

#[tokio::test]
async fn configured_dns_hosts_regex_matcher_uses_compiled_pattern() {
    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        hosts([(
            DomainMatcher::Regex(RegexMatcher::new(r"(^|\.)service\.example$").unwrap()),
            DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))),
        )]),
        Vec::new(),
        fallback.clone(),
    );

    let addr = resolver
        .resolve("storage.service.example", 443)
        .await
        .unwrap();

    assert_eq!(addr, SocketAddr::from(([203, 0, 113, 8], 443)));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn configured_dns_alias_depth_exhaustion_falls_back_to_terminal_alias_without_servers() {
    let fallback = Arc::new(MapResolver::default().with_answer(
        "alias8.example",
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
    ));
    let host_rules = (0..8)
        .map(|index| {
            (
                DomainMatcher::Full(if index == 0 {
                    "start.example".to_owned()
                } else {
                    format!("alias{index}.example")
                }),
                DnsHostTarget::Domain(format!("alias{}.example", index + 1)),
            )
        })
        .collect::<DomainHostIndex<_>>();
    let resolver = ConfiguredDnsResolver::new(host_rules, Vec::new(), fallback);

    let addr = resolver.resolve("start.example", 443).await.unwrap();

    assert_eq!(addr, SocketAddr::from(([198, 51, 100, 10], 443)));
}

#[tokio::test]
async fn configured_dns_socket_nameserver_answer_is_used() {
    let dns_server = FakeUdpDnsServer::start(FakeDnsResponseMode::Answer {
        owner: None,
        answer: Ipv4Addr::new(192, 0, 2, 55),
    })
    .await;
    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        DomainHostIndex::default(),
        vec![NameServer::Socket(dns_server.addr)],
        fallback.clone(),
    );

    let addr = resolver.resolve("example.net", 443).await.unwrap();

    assert_eq!(addr, SocketAddr::from(([192, 0, 2, 55], 443)));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn configured_dns_ignores_response_for_different_question() {
    let dns_server = FakeUdpDnsServer::start(FakeDnsResponseMode::WrongQuestion {
        answer: Ipv4Addr::new(192, 0, 2, 55),
    })
    .await;
    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        DomainHostIndex::default(),
        vec![NameServer::Socket(dns_server.addr)],
        fallback.clone(),
    );

    let error = resolver.resolve("example.net", 443).await.unwrap_err();

    assert!(matches!(
        error,
        TransportError::Dns { source, .. }
            if source.kind() == std::io::ErrorKind::NotConnected
    ));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn configured_dns_ignores_answer_for_different_owner_name() {
    let dns_server = FakeUdpDnsServer::start(FakeDnsResponseMode::Answer {
        owner: Some("other.example"),
        answer: Ipv4Addr::new(192, 0, 2, 55),
    })
    .await;
    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        DomainHostIndex::default(),
        vec![NameServer::Socket(dns_server.addr)],
        fallback.clone(),
    );

    let error = resolver.resolve("example.net", 443).await.unwrap_err();

    assert!(matches!(
        error,
        TransportError::Dns { source, .. }
            if source.kind() == std::io::ErrorKind::NotConnected
    ));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn configured_dns_rejects_cname_that_overruns_rdata() {
    let dns_server = FakeUdpDnsServer::start(FakeDnsResponseMode::ShortCnameRdata).await;
    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        DomainHostIndex::default(),
        vec![NameServer::Socket(dns_server.addr)],
        fallback.clone(),
    );

    let error = resolver.resolve("example.net", 443).await.unwrap_err();

    assert!(matches!(
        error,
        TransportError::Dns { source, .. }
            if source.kind() == std::io::ErrorKind::NotConnected
    ));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn configured_dns_server_exhaustion_does_not_leak_to_system_fallback() {
    let unused_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let dead_server_addr = unused_socket.local_addr().unwrap();
    drop(unused_socket);

    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        DomainHostIndex::default(),
        vec![NameServer::Socket(dead_server_addr)],
        fallback.clone(),
    )
    .with_server_timeout(Duration::from_millis(25));

    let error = resolver
        .resolve("fallback.example", 9443)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        TransportError::Dns { source, .. }
            if source.kind() == std::io::ErrorKind::NotConnected
    ));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

struct FakeUdpDnsServer {
    addr: SocketAddr,
}

#[derive(Clone, Copy)]
enum FakeDnsResponseMode {
    Answer {
        owner: Option<&'static str>,
        answer: Ipv4Addr,
    },
    WrongQuestion {
        answer: Ipv4Addr,
    },
    ShortCnameRdata,
}

impl FakeUdpDnsServer {
    async fn start(mode: FakeDnsResponseMode) -> Self {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            for _ in 0..2 {
                let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let query = &buffer[..len];
                let response = if dns_query_type(query) == 1 {
                    build_dns_response(query, mode)
                } else {
                    build_dns_empty_response(query)
                };
                let _ = socket.send_to(&response, peer).await;
            }
        });
        Self { addr }
    }
}

fn build_dns_response(query: &[u8], mode: FakeDnsResponseMode) -> Vec<u8> {
    match mode {
        FakeDnsResponseMode::Answer { owner, answer } => build_dns_a_response(query, owner, answer),
        FakeDnsResponseMode::WrongQuestion { answer } => {
            let mut response = build_dns_a_response(query, None, answer);
            let question_end = dns_question_end(query);
            let mut wrong_question = encode_dns_name("different.example");
            wrong_question.extend_from_slice(&1_u16.to_be_bytes());
            wrong_question.extend_from_slice(&1_u16.to_be_bytes());
            response.splice(12..question_end, wrong_question);
            response
        }
        FakeDnsResponseMode::ShortCnameRdata => build_short_cname_response(query),
    }
}

fn build_dns_empty_response(query: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..dns_question_end(query)]);
    response
}

fn build_dns_a_response(query: &[u8], owner: Option<&str>, answer: Ipv4Addr) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());

    let question_end = dns_question_end(query);
    response.extend_from_slice(&query[12..question_end]);
    match owner {
        Some(owner) => response.extend_from_slice(&encode_dns_name(owner)),
        None => response.extend_from_slice(&0xC00C_u16.to_be_bytes()),
    }
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&answer.octets());
    response
}

fn build_short_cname_response(query: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());

    let question_end = dns_question_end(query);
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&0xC00C_u16.to_be_bytes());
    response.extend_from_slice(&5_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.push(3);
    response.extend_from_slice(&encode_dns_name("alias.example"));
    response
}

fn encode_dns_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in domain.split('.') {
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

fn dns_question_end(query: &[u8]) -> usize {
    let mut index = 12;
    while query[index] != 0 {
        index += usize::from(query[index]) + 1;
    }
    index + 5
}

fn dns_query_type(query: &[u8]) -> u16 {
    let question_end = dns_question_end(query);
    u16::from_be_bytes([query[question_end - 4], query[question_end - 3]])
}

/// The platform resolver as `localhost` sees it: both families, no TTL, as
/// `getaddrinfo` reports.
struct PlatformResolver;

#[async_trait]
impl DnsResolver for PlatformResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
    }

    async fn resolve_all(
        &self,
        domain: &str,
        port: u16,
    ) -> Result<xray_transport::DnsLookup, TransportError> {
        match domain {
            "printer.lan" | "printer.lan.example" => Ok(xray_transport::DnsLookup::from_ips(
                [
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                    IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)),
                ],
                port,
                None,
            )),
            "gone.lan" => Err(TransportError::DnsNameError(domain.to_owned(), port)),
            _ => Err(TransportError::NoResolvedAddress(domain.to_owned(), port)),
        }
    }
}

fn dns_query(id: u16, domain: &str, record_type: u16, flags: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&flags.to_be_bytes());
    query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(&encode_dns_name(domain));
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}

#[tokio::test]
async fn system_dns_query_answers_each_family_from_the_platform_resolver() {
    let query = dns_query(0x5151, "printer.lan", 1, 0x0100);
    let response = xray_transport::exchange_system_dns_query(&PlatformResolver, &query)
        .await
        .unwrap();
    assert!(xray_transport::dns_response_matches_query(
        &query, &response
    ));
    assert_eq!(&response[2..4], &0x8180_u16.to_be_bytes());
    assert_eq!(&response[6..8], &1_u16.to_be_bytes(), "one A record");
    let answer = &response[query.len()..];
    assert_eq!(&answer[0..2], &[0xc0, 0x0c]);
    assert_eq!(&answer[2..4], &1_u16.to_be_bytes());
    assert_eq!(&answer[6..10], &300_u32.to_be_bytes(), "Xray's default TTL");
    assert_eq!(&answer[10..12], &4_u16.to_be_bytes());
    assert_eq!(&answer[12..16], &[192, 0, 2, 7]);

    let query = dns_query(0x5252, "printer.lan", 28, 0);
    let response = xray_transport::exchange_system_dns_query(&PlatformResolver, &query)
        .await
        .unwrap();
    assert_eq!(&response[2..4], &0x8080_u16.to_be_bytes(), "RD stays clear");
    assert_eq!(&response[6..8], &1_u16.to_be_bytes(), "one AAAA record");
    let answer = &response[query.len()..];
    assert_eq!(&answer[10..12], &16_u16.to_be_bytes());
    assert_eq!(
        &answer[12..28],
        &std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7).octets()
    );
}

#[tokio::test]
async fn system_dns_query_reports_negative_answers_and_fails_failed_lookups() {
    // Other types get an empty answer without a lookup.
    let query = dns_query(0x5353, "printer.lan", 16, 0x0100);
    let response = xray_transport::exchange_system_dns_query(&PlatformResolver, &query)
        .await
        .unwrap();
    assert_eq!(&response[2..4], &0x8180_u16.to_be_bytes());
    assert_eq!(&response[6..8], &0_u16.to_be_bytes());

    let query = dns_query(0x5454, "gone.lan", 1, 0x0100);
    let response = xray_transport::exchange_system_dns_query(&PlatformResolver, &query)
        .await
        .unwrap();
    assert_eq!(&response[2..4], &0x8183_u16.to_be_bytes(), "NXDOMAIN");

    // A lookup that finds nothing, as a static-only bootstrap answers every
    // name, fails, so the resolver moves on to its next server.
    let query = dns_query(0x5555, "unknown.example", 1, 0x0100);
    assert!(
        xray_transport::exchange_system_dns_query(&PlatformResolver, &query)
            .await
            .is_err()
    );

    // A response is no query.
    let mut response = dns_query(0x5656, "printer.lan", 1, 0x8100);
    assert!(
        xray_transport::exchange_system_dns_query(&PlatformResolver, &response)
            .await
            .is_err()
    );
    response.truncate(8);
    assert!(
        xray_transport::exchange_system_dns_query(&PlatformResolver, &response)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn configured_dns_system_server_answers_from_its_fallback_resolver() {
    let policy = xray_transport::NameServerPolicy {
        transport: xray_transport::NameServerTransport::System,
        ..xray_transport::NameServerPolicy::new(NameServer::Domain {
            domain: "localhost".to_owned(),
            port: 53,
        })
    };
    let resolver = ConfiguredDnsResolver::new(
        DomainHostIndex::new(),
        Vec::new(),
        Arc::new(PlatformResolver),
    )
    .with_name_server_policies(vec![policy]);

    let lookup = resolver.resolve_all("printer.lan", 443).await.unwrap();
    assert_eq!(
        lookup.socket_addrs(),
        [
            SocketAddr::from(([192, 0, 2, 7], 443)),
            SocketAddr::from((
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7),
                443
            )),
        ]
    );
    let ttl = lookup.ttl().unwrap();
    assert!(ttl <= Duration::from_secs(300) && ttl > Duration::from_secs(290));

    // The one server failing leaves no fallback to the platform resolver for
    // the name itself: configured servers own the destination lookup.
    assert!(resolver.resolve_all("unknown.example", 443).await.is_err());
}
