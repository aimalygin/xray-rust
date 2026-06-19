use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    CachingDnsResolver, ConfiguredDnsResolver, DnsResolver, NameServer, StaticHostRule,
    StaticHostTarget, SystemDnsResolver, TcpConnector, TransportConnector, TransportDomainMatcher,
    TransportError,
};

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
        vec![StaticHostRule {
            matcher: TransportDomainMatcher::Suffix("example.com".to_owned()),
            target: StaticHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        }],
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
            .with_answer("googleapis.com", IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
    );
    let resolver = ConfiguredDnsResolver::new(
        vec![StaticHostRule {
            matcher: TransportDomainMatcher::Suffix("googleapis.cn".to_owned()),
            target: StaticHostTarget::Domain("googleapis.com".to_owned()),
        }],
        Vec::new(),
        fallback,
    );

    let addr = resolver
        .resolve("storage.googleapis.cn", 8443)
        .await
        .unwrap();

    assert_eq!(addr, SocketAddr::from(([198, 51, 100, 9], 8443)));
}

#[tokio::test]
async fn configured_dns_hosts_regex_matcher_uses_compiled_pattern() {
    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        vec![StaticHostRule {
            matcher: TransportDomainMatcher::regex(r"(^|\.)googleapis\.cn$").unwrap(),
            target: StaticHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))),
        }],
        Vec::new(),
        fallback.clone(),
    );

    let addr = resolver
        .resolve("storage.googleapis.cn", 443)
        .await
        .unwrap();

    assert_eq!(addr, SocketAddr::from(([203, 0, 113, 8], 443)));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn configured_dns_alias_depth_exhaustion_falls_back_to_original_domain() {
    let fallback = Arc::new(
        MapResolver::default()
            .with_answer("start.example", IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
    );
    let host_rules = (0..8)
        .map(|index| StaticHostRule {
            matcher: TransportDomainMatcher::Full(if index == 0 {
                "start.example".to_owned()
            } else {
                format!("alias{index}.example")
            }),
            target: StaticHostTarget::Domain(format!("alias{}.example", index + 1)),
        })
        .collect();
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
        Vec::new(),
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
        Vec::new(),
        vec![NameServer::Socket(dns_server.addr)],
        fallback.clone(),
    );

    let addr = resolver.resolve("example.net", 443).await.unwrap();

    assert_eq!(addr, SocketAddr::from(([192, 0, 2, 1], 443)));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
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
        Vec::new(),
        vec![NameServer::Socket(dns_server.addr)],
        fallback.clone(),
    );

    let addr = resolver.resolve("example.net", 443).await.unwrap();

    assert_eq!(addr, SocketAddr::from(([192, 0, 2, 1], 443)));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn configured_dns_rejects_cname_that_overruns_rdata() {
    let dns_server = FakeUdpDnsServer::start(FakeDnsResponseMode::ShortCnameRdata).await;
    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        Vec::new(),
        vec![NameServer::Socket(dns_server.addr)],
        fallback.clone(),
    );

    let addr = resolver.resolve("example.net", 443).await.unwrap();

    assert_eq!(addr, SocketAddr::from(([192, 0, 2, 1], 443)));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn configured_dns_server_failure_falls_back() {
    let unused_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let dead_server_addr = unused_socket.local_addr().unwrap();
    drop(unused_socket);

    let fallback = Arc::new(CountingResolver::default());
    let resolver = ConfiguredDnsResolver::new(
        Vec::new(),
        vec![NameServer::Socket(dead_server_addr)],
        fallback.clone(),
    )
    .with_server_timeout(Duration::from_millis(25));

    let addr = resolver.resolve("fallback.example", 9443).await.unwrap();

    assert_eq!(addr, SocketAddr::from(([192, 0, 2, 1], 9443)));
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
}

struct FakeUdpDnsServer {
    addr: SocketAddr,
}

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
            let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let response = build_dns_response(&buffer[..len], mode);
            let _ = socket.send_to(&response, peer).await;
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
