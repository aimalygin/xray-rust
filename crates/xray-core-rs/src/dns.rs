use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use xray_config::{CoreConfig, DnsHostTarget, DomainMatcher};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_new_packet, read_udp_packet, read_xudp_packet,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr};
use xray_transport::{
    dns_response_matches_query, protect_udp_socket, BoxedTransportStream, ConnectorConfig,
    DnsQueryDispatch, DnsQueryMetadata, DnsQueryTransport, DnsQueryTransportKind, DnsResolver,
    HappyEyeballsConfig, NameServer, TransportDialer,
};

use crate::outbound::{
    open_tcp_stream_with_resolver_and_dialer, open_vless_udp_stream_with_resolver_and_dialer,
    TcpOutbound, UdpOutbound, VlessUdpFraming,
};
use crate::OutboundRouter;

const MAX_STATIC_ALIAS_DEPTH: usize = 8;
const MAX_DNS_UDP_RESPONSE_SIZE: usize = 4096;
const DNS_LOCAL_TCP_FALLBACK_DELAY: Duration = Duration::from_millis(300);

/// DNS roles used by one runtime ingress context.
///
/// Destination lookups may use routed or explicitly local `dns.servers`;
/// bootstrap lookups must
/// never recurse through that same transport because they resolve the DNS
/// upstream or proxy server needed to open it.
#[derive(Clone)]
pub(crate) struct RuntimeDnsResolvers {
    pub(crate) destination: Arc<dyn DnsResolver>,
    pub(crate) bootstrap: Arc<dyn DnsResolver>,
}

/// DNS wire transport routed through the same outbound policy as application
/// traffic. It is independent of the TUN packet adapter so the resolver can be
/// reused by future listener and server runtimes.
pub(crate) struct RoutedDnsQueryTransport {
    outbound_router: Arc<OutboundRouter>,
    bootstrap_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    forbidden_servers: Arc<[SocketAddr]>,
}

impl RoutedDnsQueryTransport {
    pub(crate) fn new(
        outbound_router: Arc<OutboundRouter>,
        bootstrap_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
        forbidden_servers: impl Into<Arc<[SocketAddr]>>,
    ) -> Self {
        Self {
            outbound_router,
            bootstrap_resolver,
            transport_dialer,
            forbidden_servers: forbidden_servers.into(),
        }
    }

    fn target(&self, server: &NameServer, network: RoutingNetwork) -> Target {
        match server {
            NameServer::Socket(addr) => {
                Target::new(TargetAddr::Ip(addr.ip()), addr.port(), network)
            }
            NameServer::Domain { domain, port } => {
                Target::new(TargetAddr::Domain(domain.clone()), *port, network)
            }
        }
    }

    async fn resolved_server(&self, server: &NameServer) -> io::Result<SocketAddr> {
        self.resolved_servers(server)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS server has no address"))
    }

    async fn resolved_servers(&self, server: &NameServer) -> io::Result<Vec<SocketAddr>> {
        let resolved = match server {
            NameServer::Socket(addr) => vec![*addr],
            NameServer::Domain { domain, port } => self
                .bootstrap_resolver
                .resolve_all(domain, *port)
                .await
                .map_err(io::Error::other)?
                .socket_addrs()
                .to_vec(),
        };
        resolved
            .into_iter()
            .map(|candidate| self.validate_server(candidate))
            .collect()
    }

    fn validate_server(&self, server: SocketAddr) -> io::Result<SocketAddr> {
        let server_ip = canonical_ip(server.ip());
        let forbidden = self.forbidden_servers.iter().any(|forbidden| {
            forbidden.port() == server.port() && canonical_ip(forbidden.ip()) == server_ip
        });
        if forbidden {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dns server resolves to a runtime-local address",
            ));
        }
        Ok(server)
    }

    async fn exchange_udp(
        &self,
        server: &NameServer,
        metadata: DnsQueryMetadata<'_>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let target = self.target(server, RoutingNetwork::Udp);
        let outbound = self
            .outbound_router
            .select_udp_outbound_for_session(metadata.inbound_tag, &target)
            .map_err(io::Error::other)?;

        match outbound {
            UdpOutbound::Freedom => {
                let server = self.resolved_server(server).await?;
                exchange_freedom_udp(server, query, self.transport_dialer.socket_protector()).await
            }
            UdpOutbound::Vless(outbound) => {
                if server_socket_has_nonzero_scope(server) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "scoped ipv6 dns server cannot be encoded in a vless target",
                    ));
                }
                let (mut stream, framing) = open_vless_udp_stream_with_resolver_and_dialer(
                    &outbound,
                    &target,
                    self.bootstrap_resolver.as_ref(),
                    self.transport_dialer.as_ref(),
                )
                .await
                .map_err(io::Error::other)?;
                let frame = match framing {
                    VlessUdpFraming::LengthPrefixed => {
                        encode_udp_packet(query).map_err(io::Error::other)?
                    }
                    VlessUdpFraming::Xudp => {
                        encode_xudp_new_packet(&target, query, [0; 8]).map_err(io::Error::other)?
                    }
                };
                stream.write_all(&frame).await?;
                stream.flush().await?;
                loop {
                    let response = match framing {
                        VlessUdpFraming::LengthPrefixed => read_udp_packet(&mut stream).await?,
                        VlessUdpFraming::Xudp => read_xudp_packet(&mut stream).await?.payload,
                    };
                    if dns_response_matches_query(query, response.as_ref()) {
                        return Ok(response.to_vec());
                    }
                }
            }
        }
    }

    async fn exchange_tcp(
        &self,
        server: &NameServer,
        metadata: DnsQueryMetadata<'_>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let target = self.target(server, RoutingNetwork::Tcp);
        if metadata.dispatch == DnsQueryDispatch::Local {
            let candidates = self.resolved_servers(server).await?;
            let mut stream =
                open_local_dns_tcp_stream(self.transport_dialer.as_ref(), &target, &candidates)
                    .await?;
            return exchange_dns_tcp_message(&mut stream, query).await;
        }
        let selected = self
            .outbound_router
            .select_tcp_outbound_for_session_with_tag(metadata.inbound_tag, &target, false)
            .map_err(io::Error::other)?;

        let mut stream = match selected.outbound {
            outbound @ (TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_)) => {
                let candidates = self.resolved_servers(server).await?;
                open_routed_freedom_dns_tcp_stream(
                    self.transport_dialer.as_ref(),
                    &target,
                    &candidates,
                    outbound.freedom_happy_eyeballs(),
                )
                .await?
            }
            outbound @ TcpOutbound::Vless(_) => {
                if server_socket_has_nonzero_scope(server) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "scoped ipv6 dns server cannot be encoded in a vless target",
                    ));
                }
                open_tcp_stream_with_resolver_and_dialer(
                    &outbound,
                    &target,
                    self.bootstrap_resolver.as_ref(),
                    self.transport_dialer.as_ref(),
                )
                .await
                .map_err(io::Error::other)?
            }
        };

        exchange_dns_tcp_message(&mut stream, query).await
    }
}

/// Opens a protected, directly dialled DNS TCP stream without consulting the
/// outbound router.
///
/// The 300 ms family fallback mirrors Go's system dialer closely enough for
/// `tcp+local://` to retain dual-stack behavior on mobile networks. Candidate
/// resolution remains the caller's responsibility so it can use the dedicated
/// non-recursive bootstrap resolver.
pub(crate) async fn open_local_dns_tcp_stream(
    transport_dialer: &TransportDialer,
    target: &Target,
    candidates: &[SocketAddr],
) -> io::Result<BoxedTransportStream> {
    open_routed_freedom_dns_tcp_stream(transport_dialer, target, candidates, None).await
}

/// Opens a protected Freedom DNS TCP stream after routing has selected the
/// outbound. Explicit outbound Happy Eyeballs settings take precedence; plain
/// Freedom still receives the DNS-specific fallback so every bootstrap address
/// remains usable.
pub(crate) async fn open_routed_freedom_dns_tcp_stream(
    transport_dialer: &TransportDialer,
    target: &Target,
    candidates: &[SocketAddr],
    configured_happy_eyeballs: Option<&HappyEyeballsConfig>,
) -> io::Result<BoxedTransportStream> {
    let default_happy_eyeballs = dns_tcp_happy_eyeballs(candidates);
    let happy_eyeballs = configured_happy_eyeballs.unwrap_or(&default_happy_eyeballs);
    transport_dialer
        .connect_resolved(
            &ConnectorConfig::Tcp,
            target,
            candidates,
            Some(happy_eyeballs),
        )
        .await
        .map_err(io::Error::other)
}

fn dns_tcp_happy_eyeballs(candidates: &[SocketAddr]) -> HappyEyeballsConfig {
    HappyEyeballsConfig {
        prioritize_ipv6: candidates
            .first()
            .is_some_and(|candidate| canonical_ip(candidate.ip()).is_ipv6()),
        interleave: 1,
        try_delay: DNS_LOCAL_TCP_FALLBACK_DELAY,
        max_concurrent: NonZeroUsize::new(4).unwrap_or(NonZeroUsize::MIN),
    }
}

async fn exchange_dns_tcp_message<S>(stream: &mut S, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let query_len = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns tcp query is too large"))?;
    stream.write_u16(query_len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    let response_len = usize::from(stream.read_u16().await?);
    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

#[async_trait]
impl DnsQueryTransport for RoutedDnsQueryTransport {
    async fn exchange(
        &self,
        server: &NameServer,
        transport: DnsQueryTransportKind,
        metadata: DnsQueryMetadata<'_>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        match transport {
            DnsQueryTransportKind::Udp if metadata.dispatch == DnsQueryDispatch::Local => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "local DNS UDP is not supported",
                ))
            }
            DnsQueryTransportKind::Udp => self.exchange_udp(server, metadata, query).await,
            DnsQueryTransportKind::Tcp => self.exchange_tcp(server, metadata, query).await,
        }
    }
}

async fn exchange_freedom_udp(
    server: SocketAddr,
    query: &[u8],
    socket_protector: Option<&dyn xray_transport::SocketProtector>,
) -> io::Result<Vec<u8>> {
    let bind_addr = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    protect_udp_socket(&socket, socket_protector).map_err(io::Error::other)?;
    socket.connect(server).await?;
    let written = socket.send(query).await?;
    if written != query.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short dns udp write",
        ));
    }
    let mut response = vec![0_u8; MAX_DNS_UDP_RESPONSE_SIZE + 1];
    loop {
        let len = socket.recv(&mut response).await?;
        if !dns_response_matches_query(query, &response[..len]) {
            continue;
        }
        if len > MAX_DNS_UDP_RESPONSE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dns udp response is too large",
            ));
        }
        response.truncate(len);
        return Ok(response);
    }
}

pub(crate) fn static_dns_host_target(config: &CoreConfig, domain: &str) -> Option<DnsHostTarget> {
    let mut current = normalize_dns_name(domain)?;
    let mut matched_alias = false;
    for _ in 0..MAX_STATIC_ALIAS_DEPTH {
        let Some(mapping) = config
            .dns
            .hosts
            .iter()
            .find(|mapping| {
                matches!(&mapping.matcher, DomainMatcher::Full(_))
                    && dns_host_matcher_matches(&mapping.matcher, &current)
            })
            .or_else(|| {
                config
                    .dns
                    .hosts
                    .iter()
                    .find(|mapping| dns_host_matcher_matches(&mapping.matcher, &current))
            })
        else {
            return matched_alias.then_some(DnsHostTarget::Domain(current));
        };
        match &mapping.target {
            DnsHostTarget::Ip(ip) => return Some(DnsHostTarget::Ip(*ip)),
            DnsHostTarget::Ips(ips) => return Some(DnsHostTarget::Ips(ips.clone())),
            DnsHostTarget::Domain(alias) => {
                let alias = normalize_dns_name(alias)?;
                if alias == current {
                    return None;
                }
                matched_alias = true;
                current = alias;
            }
        }
    }
    None
}

fn dns_host_matcher_matches(matcher: &DomainMatcher, domain: &str) -> bool {
    match matcher {
        DomainMatcher::Full(expected) => normalize_dns_name(expected)
            .is_some_and(|expected| domain.eq_ignore_ascii_case(&expected)),
        DomainMatcher::Suffix(suffix) => normalize_dns_name(suffix).is_some_and(|suffix| {
            domain.eq_ignore_ascii_case(&suffix)
                || domain
                    .strip_suffix(&suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }),
        DomainMatcher::Keyword(_) | DomainMatcher::Regex(_) => matcher.matches(domain),
    }
}

pub(crate) fn normalize_dns_name(domain: &str) -> Option<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

fn server_socket_has_nonzero_scope(server: &NameServer) -> bool {
    matches!(server, NameServer::Socket(SocketAddr::V6(addr)) if addr.scope_id() != 0)
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_config::{
        CoreConfig, DnsConfig, DnsHostMapping, DnsHostTarget, DomainMatcher, Network,
        OutboundConfig, OutboundSettings, PolicyConfig, RoutingConfig, StreamSecurity,
        StreamSettings,
    };
    use xray_transport::{
        DnsQueryMetadata, DnsQueryTransportKind, SocketHandle, SocketProtector, TransportError,
    };

    use super::*;
    use crate::OutboundRouter;

    #[derive(Debug, Default)]
    struct CountingSocketProtector {
        calls: AtomicUsize,
    }

    impl SocketProtector for CountingSocketProtector {
        fn protect(&self, _socket: SocketHandle) -> std::io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct CandidateBootstrapResolver {
        expected_domain: &'static str,
        expected_port: u16,
        candidates: Vec<SocketAddr>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsResolver for CandidateBootstrapResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            assert_eq!(domain, self.expected_domain);
            assert_eq!(port, self.expected_port);
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.candidates
                .first()
                .copied()
                .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
        }

        async fn resolve_all(
            &self,
            domain: &str,
            port: u16,
        ) -> Result<xray_transport::DnsLookup, TransportError> {
            assert_eq!(domain, self.expected_domain);
            assert_eq!(port, self.expected_port);
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(xray_transport::DnsLookup::new(
                self.candidates.iter().copied(),
                None,
            ))
        }
    }

    #[test]
    fn static_dns_exact_mapping_wins_over_broader_mapping() {
        let config = CoreConfig {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            default_outbound_tag: None,
            routing: RoutingConfig::default(),
            dns: DnsConfig {
                hosts: vec![
                    DnsHostMapping {
                        matcher: DomainMatcher::Keyword("example".to_owned()),
                        target: DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                    },
                    DnsHostMapping {
                        matcher: DomainMatcher::Full("PROXY.EXAMPLE.".to_owned()),
                        target: DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
                    },
                ],
                ..DnsConfig::default()
            },
            policy: PolicyConfig::default(),
        };

        assert_eq!(
            static_dns_host_target(&config, "PROXY.EXAMPLE."),
            Some(DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))))
        );
    }

    #[test]
    fn dns_tcp_fallback_preserves_first_canonical_candidate_family() {
        let ipv6_first = [
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 53)),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53)),
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), 53)),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53)),
        ];
        let config = dns_tcp_happy_eyeballs(&ipv6_first);

        assert!(config.prioritize_ipv6);
        assert_eq!(config.order_candidates(&ipv6_first), ipv6_first);

        let mapped_v4 =
            SocketAddr::new(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 3).to_ipv6_mapped()), 53);
        let ipv6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3), 53));
        let config = dns_tcp_happy_eyeballs(&[mapped_v4, ipv6]);

        assert!(!config.prioritize_ipv6);
        assert_eq!(
            config.order_candidates(&[mapped_v4, ipv6]),
            [SocketAddr::from((Ipv4Addr::new(192, 0, 2, 3), 53)), ipv6,]
        );
    }

    #[tokio::test]
    async fn local_tcp_dns_bypasses_router_and_protects_the_socket() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local DNS TCP listener");
        let server_addr = listener.local_addr().expect("read DNS TCP address");
        let response = b"local-dns-response".to_vec();
        let expected_response = response.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept local DNS TCP");
            let query_len = usize::from(stream.read_u16().await.expect("read DNS query length"));
            let mut query = vec![0; query_len];
            stream.read_exact(&mut query).await.expect("read DNS query");
            assert_eq!(query, b"local-dns-query");
            stream
                .write_u16(u16::try_from(response.len()).expect("bounded response"))
                .await
                .expect("write DNS response length");
            stream
                .write_all(&response)
                .await
                .expect("write DNS response");
        });

        let config = Arc::new(CoreConfig {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            default_outbound_tag: None,
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            policy: PolicyConfig::default(),
        });
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                .expect("build protected transport dialer"),
        );
        let bootstrap: Arc<dyn DnsResolver> = Arc::new(xray_transport::SystemDnsResolver);
        let transport = RoutedDnsQueryTransport::new(
            Arc::new(OutboundRouter::new(config)),
            bootstrap,
            dialer,
            Vec::new(),
        );
        let name_server = NameServer::Socket(server_addr);

        let routed_error = transport
            .exchange(
                &name_server,
                DnsQueryTransportKind::Tcp,
                DnsQueryMetadata::new(Some("dns-route")),
                b"must-not-connect",
            )
            .await
            .expect_err("routed DNS requires a configured outbound");
        assert_eq!(routed_error.kind(), io::ErrorKind::Other);

        let actual = transport
            .exchange(
                &name_server,
                DnsQueryTransportKind::Tcp,
                DnsQueryMetadata::local(Some("ignored-local-tag")),
                b"local-dns-query",
            )
            .await
            .expect("local DNS must bypass the empty router");

        assert_eq!(actual, expected_response);
        assert_eq!(protector.calls.load(Ordering::Relaxed), 1);
        server.await.expect("join DNS TCP server");
    }

    #[tokio::test]
    async fn local_tcp_dns_uses_bootstrap_candidates_and_falls_forward() {
        let refused_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("reserve refused DNS candidate");
        let refused = refused_listener
            .local_addr()
            .expect("read refused DNS candidate");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind successful DNS candidate");
        let successful = listener.local_addr().expect("read DNS listener address");
        drop(refused_listener);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fallback DNS TCP");
            let query_len = usize::from(stream.read_u16().await.expect("read DNS query length"));
            let mut query = vec![0; query_len];
            stream.read_exact(&mut query).await.expect("read DNS query");
            stream
                .write_u16(u16::try_from(query.len()).expect("bounded response"))
                .await
                .expect("write DNS response length");
            stream.write_all(&query).await.expect("write DNS response");
        });

        let config = Arc::new(CoreConfig {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            default_outbound_tag: None,
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            policy: PolicyConfig::default(),
        });
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                .expect("build protected transport dialer"),
        );
        let bootstrap = Arc::new(CandidateBootstrapResolver {
            expected_domain: "resolver.bootstrap.test",
            expected_port: 5353,
            candidates: vec![refused, successful],
            calls: AtomicUsize::new(0),
        });
        let transport = RoutedDnsQueryTransport::new(
            Arc::new(OutboundRouter::new(config)),
            bootstrap.clone(),
            dialer,
            Vec::new(),
        );

        let response = transport
            .exchange(
                &NameServer::Domain {
                    domain: "resolver.bootstrap.test".to_owned(),
                    port: 5353,
                },
                DnsQueryTransportKind::Tcp,
                DnsQueryMetadata::local(None),
                b"candidate-query",
            )
            .await
            .expect("local DNS should fall forward to the second bootstrap candidate");

        assert_eq!(response, b"candidate-query");
        assert_eq!(bootstrap.calls.load(Ordering::Relaxed), 1);
        assert!(protector.calls.load(Ordering::Relaxed) >= 2);
        server.await.expect("join fallback DNS server");
    }

    #[tokio::test]
    async fn routed_freedom_tcp_dns_falls_forward_without_outbound_happy_eyeballs() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind successful routed DNS candidate");
        let successful = listener.local_addr().expect("read DNS listener address");
        let refused = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), successful.port()));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept routed fallback DNS TCP");
            let query_len = usize::from(stream.read_u16().await.expect("read DNS query length"));
            let mut query = vec![0; query_len];
            stream.read_exact(&mut query).await.expect("read DNS query");
            stream
                .write_u16(u16::try_from(query.len()).expect("bounded response"))
                .await
                .expect("write DNS response length");
            stream.write_all(&query).await.expect("write DNS response");
        });

        let config = Arc::new(CoreConfig {
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig {
                tag: Some("direct".to_owned()),
                stream: StreamSettings {
                    network: Network::Tcp,
                    security: StreamSecurity::None,
                    socket_options: None,
                },
                settings: OutboundSettings::Freedom,
            }],
            default_outbound_tag: Some("direct".to_owned()),
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            policy: PolicyConfig::default(),
        });
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                .expect("build protected transport dialer"),
        );
        let bootstrap = Arc::new(CandidateBootstrapResolver {
            expected_domain: "routed.resolver.bootstrap.test",
            expected_port: successful.port(),
            candidates: vec![refused, successful],
            calls: AtomicUsize::new(0),
        });
        let transport = RoutedDnsQueryTransport::new(
            Arc::new(OutboundRouter::new(config)),
            bootstrap.clone(),
            dialer,
            Vec::new(),
        );

        let response = transport
            .exchange(
                &NameServer::Domain {
                    domain: "routed.resolver.bootstrap.test".to_owned(),
                    port: successful.port(),
                },
                DnsQueryTransportKind::Tcp,
                DnsQueryMetadata::new(None),
                b"routed-candidate-query",
            )
            .await
            .expect("plain Freedom DNS should use the second bootstrap candidate");

        assert_eq!(response, b"routed-candidate-query");
        assert_eq!(bootstrap.calls.load(Ordering::Relaxed), 1);
        assert!(protector.calls.load(Ordering::Relaxed) >= 2);
        server.await.expect("join routed fallback DNS server");
    }
}
