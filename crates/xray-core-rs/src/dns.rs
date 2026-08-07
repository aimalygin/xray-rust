use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};
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

use crate::dns_outbound_runtime::DnsDirectExecutor;
use crate::outbound::{
    open_tcp_stream_with_resolver_and_dialer, open_vless_udp_stream_with_resolver_and_dialer,
    DnsHappyEyeballsMode, DnsOutbound, TcpOutbound, UdpOutbound, VlessUdpFraming,
};
use crate::OutboundRouter;

const MAX_STATIC_ALIAS_DEPTH: usize = 8;
const MAX_DNS_WIRE_MESSAGE_SIZE: usize = u16::MAX as usize;
const MAX_DIRECT_DNS_CANDIDATES: usize = 8;
const MAX_DNS_UNRELATED_UDP_RESPONSES: usize = 8;
const MAX_DIRECT_DNS_UNRELATED_TCP_RESPONSES: usize = 8;
const DNS_LOCAL_TCP_FALLBACK_DELAY: Duration = Duration::from_millis(300);
const DNS_DIRECT_UDP_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(750);
const DNS_DIRECT_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

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
    pub(crate) outbound: Arc<crate::dns_outbound_runtime::DnsOutboundRuntime>,
}

/// DNS wire transport routed through the same outbound policy as application
/// traffic. It is independent of the TUN packet adapter so the resolver can be
/// reused by future listener and server runtimes.
pub(crate) struct RoutedDnsQueryTransport {
    outbound_router: Arc<OutboundRouter>,
    bootstrap_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    forbidden_servers: Arc<[SocketAddr]>,
    direct_executor: Arc<DnsDirectExecutor>,
    operation_permits: Arc<Semaphore>,
}

impl RoutedDnsQueryTransport {
    #[cfg(test)]
    pub(crate) fn new(
        outbound_router: Arc<OutboundRouter>,
        bootstrap_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
        forbidden_servers: impl Into<Arc<[SocketAddr]>>,
    ) -> Self {
        let forbidden_servers = forbidden_servers.into();
        let direct_executor = Arc::new(DnsDirectExecutor::new(
            Arc::clone(&bootstrap_resolver),
            Arc::clone(&transport_dialer),
            Arc::clone(&forbidden_servers),
        ));
        Self::with_direct_executor(
            outbound_router,
            bootstrap_resolver,
            transport_dialer,
            forbidden_servers,
            direct_executor,
            16,
        )
    }

    pub(crate) fn with_direct_executor(
        outbound_router: Arc<OutboundRouter>,
        bootstrap_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
        forbidden_servers: impl Into<Arc<[SocketAddr]>>,
        direct_executor: Arc<DnsDirectExecutor>,
        max_concurrent_operations: usize,
    ) -> Self {
        Self {
            outbound_router,
            bootstrap_resolver,
            transport_dialer,
            forbidden_servers: forbidden_servers.into(),
            direct_executor,
            operation_permits: Arc::new(Semaphore::new(max_concurrent_operations.max(1))),
        }
    }

    fn try_reserve_operation(&self) -> io::Result<OwnedSemaphorePermit> {
        match Arc::clone(&self.operation_permits).try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(tokio::sync::TryAcquireError::NoPermits) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "managed DNS operation limit reached",
            )),
            Err(error @ tokio::sync::TryAcquireError::Closed) => Err(io::Error::other(error)),
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
        if is_forbidden_dns_server(server, self.forbidden_servers.as_ref()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dns server resolves to a runtime-local address",
            ));
        }
        Ok(server)
    }

    async fn exchange_selected_dns_outbound(
        &self,
        target: &Target,
        outbound: &DnsOutbound,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        timeout(
            outbound.operation_timeout(),
            self.direct_executor
                .exchange_stateless(outbound, target, query),
        )
        .await
        .map_err(|_| direct_dns_timeout_error("DNS outbound policy timeout elapsed"))?
    }

    async fn exchange_udp(
        &self,
        server: &NameServer,
        metadata: DnsQueryMetadata<'_>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let target = self.target(server, RoutingNetwork::Udp);
        // Xray marks internal DNS-upstream sessions SkipDNSResolve. The
        // bootstrap resolver is used only after first-pass routing has chosen
        // an outbound, never to run IPIfNonMatch against the server needed to
        // answer that very lookup.
        if let Some(outbound) = self
            .outbound_router
            .select_dns_outbound_for_session(metadata.inbound_tag, &target)
            .map_err(io::Error::other)?
        {
            if metadata.dispatch != DnsQueryDispatch::Routed
                || !self.outbound_router.is_dns_client_tag(metadata.inbound_tag)
            {
                return Err(untrusted_dns_outbound_error());
            }
            return self
                .exchange_selected_dns_outbound(&target, &outbound, query)
                .await;
        }
        let outbound = self
            .outbound_router
            .select_udp_outbound_for_session(metadata.inbound_tag, &target)
            .map_err(io::Error::other)?;

        match outbound {
            UdpOutbound::Freedom => {
                let server = self.resolved_server(server).await?;
                let _udp_exchange_permit = self.direct_executor.try_reserve_udp_exchange()?;
                exchange_freedom_udp(
                    server,
                    query,
                    self.transport_dialer.socket_protector(),
                    true,
                )
                .await
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
        // Keep routed TCP name-server selection non-recursive for the same
        // SkipDNSResolve reason as the UDP path above.
        if let Some(outbound) = self
            .outbound_router
            .select_dns_outbound_for_session(metadata.inbound_tag, &target)
            .map_err(io::Error::other)?
        {
            if !self.outbound_router.is_dns_client_tag(metadata.inbound_tag) {
                return Err(untrusted_dns_outbound_error());
            }
            return self
                .exchange_selected_dns_outbound(&target, &outbound, query)
                .await;
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

fn untrusted_dns_outbound_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "DNS outbound recursion bypass requires a managed DNS client tag",
    )
}

/// Exchanges one DNS wire message directly after applying the selected DNS
/// outbound's component-wise rewrite.
///
/// This is the recursion escape hatch used by managed DNS clients when their
/// own synthetic inbound tag routes back to the DNS outbound. It deliberately
/// bypasses outbound selection while retaining socket protection, bootstrap
/// isolation, response correlation, and bounded network work.
#[cfg(test)]
pub(crate) async fn exchange_direct_dns_query(
    original: &Target,
    outbound: &DnsOutbound,
    query: &[u8],
    bootstrap: &dyn DnsResolver,
    dialer: &TransportDialer,
    forbidden: &[SocketAddr],
) -> io::Result<Vec<u8>> {
    exchange_direct_dns_query_with_udp_admission(
        original,
        outbound,
        query,
        bootstrap,
        dialer,
        forbidden,
        || Ok(()),
    )
    .await
}

pub(crate) async fn exchange_direct_dns_query_with_udp_admission<G, F>(
    original: &Target,
    outbound: &DnsOutbound,
    query: &[u8],
    bootstrap: &dyn DnsResolver,
    dialer: &TransportDialer,
    forbidden: &[SocketAddr],
    acquire_udp_guard: F,
) -> io::Result<Vec<u8>>
where
    G: Send,
    F: FnOnce() -> io::Result<G> + Send,
{
    let target = outbound.rewrite_target(original);
    if target.port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "direct DNS target port cannot be zero",
        ));
    }
    if query.len() > usize::from(u16::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "direct DNS query is too large",
        ));
    }

    let exchange = async {
        if target.network == RoutingNetwork::Udp && !outbound.supports_direct_udp() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS outbound stream security requires a TCP rewrite target",
            ));
        }
        let candidates = resolve_direct_dns_candidates(&target, bootstrap, forbidden).await?;
        match target.network {
            RoutingNetwork::Udp => {
                let _udp_guard = acquire_udp_guard()?;
                exchange_direct_dns_udp_candidates(&candidates, query, dialer.socket_protector())
                    .await
            }
            RoutingNetwork::Tcp => {
                let mut session =
                    DirectDnsTcpSession::open_resolved(dialer, outbound, &target, &candidates)
                        .await?;
                session.exchange(query).await
            }
        }
    };
    timeout(DNS_DIRECT_TOTAL_TIMEOUT, exchange)
        .await
        .map_err(|_| direct_dns_timeout_error("direct DNS exchange timed out"))?
}

pub(crate) struct DirectDnsTcpSession {
    stream: BoxedTransportStream,
}

impl DirectDnsTcpSession {
    pub(crate) async fn open(
        original: &Target,
        outbound: &DnsOutbound,
        bootstrap: &dyn DnsResolver,
        dialer: &TransportDialer,
        forbidden: &[SocketAddr],
    ) -> io::Result<Self> {
        let target = outbound.rewrite_target(original);
        if target.network != RoutingNetwork::Tcp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reusable direct DNS session requires a TCP target",
            ));
        }
        if target.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct DNS target port cannot be zero",
            ));
        }
        let candidates = resolve_direct_dns_candidates(&target, bootstrap, forbidden).await?;
        Self::open_resolved(dialer, outbound, &target, &candidates).await
    }

    async fn open_resolved(
        dialer: &TransportDialer,
        outbound: &DnsOutbound,
        target: &Target,
        candidates: &[SocketAddr],
    ) -> io::Result<Self> {
        let stream = open_dns_outbound_tcp_stream(dialer, outbound, target, candidates).await?;
        Ok(Self { stream })
    }

    pub(crate) async fn exchange(&mut self, query: &[u8]) -> io::Result<Vec<u8>> {
        exchange_correlated_dns_tcp_message(&mut self.stream, query).await
    }

    pub(crate) async fn send(&mut self, query: &[u8]) -> io::Result<()> {
        send_dns_tcp_message(&mut self.stream, query).await
    }

    pub(crate) fn into_stream(self) -> BoxedTransportStream {
        self.stream
    }
}

pub(crate) async fn resolve_direct_dns_candidates(
    target: &Target,
    bootstrap: &dyn DnsResolver,
    forbidden: &[SocketAddr],
) -> io::Result<Vec<SocketAddr>> {
    let mut candidates = Vec::with_capacity(MAX_DIRECT_DNS_CANDIDATES);
    match &target.addr {
        TargetAddr::Ip(ip) => push_direct_dns_candidate(
            &mut candidates,
            SocketAddr::new(*ip, target.port),
            target.port,
            forbidden,
        )?,
        TargetAddr::Domain(domain) => {
            if domain.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "direct DNS target domain cannot be empty",
                ));
            }
            let lookup = bootstrap
                .resolve_all(domain, target.port)
                .await
                .map_err(io::Error::other)?;
            for candidate in lookup
                .socket_addrs()
                .iter()
                .copied()
                .take(MAX_DIRECT_DNS_CANDIDATES)
            {
                push_direct_dns_candidate(&mut candidates, candidate, target.port, forbidden)?;
            }
        }
    }
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "direct DNS target has no resolved address",
        ));
    }
    Ok(candidates)
}

fn push_direct_dns_candidate(
    candidates: &mut Vec<SocketAddr>,
    mut candidate: SocketAddr,
    port: u16,
    forbidden: &[SocketAddr],
) -> io::Result<()> {
    candidate.set_port(port);
    candidate = canonical_socket_addr(candidate);
    if is_forbidden_dns_server(candidate, forbidden) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "direct DNS target resolves to a runtime-local address",
        ));
    }
    if !candidates.contains(&candidate) {
        candidates.push(candidate);
    }
    Ok(())
}

fn canonical_socket_addr(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => address
            .ip()
            .to_ipv4_mapped()
            .map_or(SocketAddr::V6(address), |ip| {
                SocketAddr::new(IpAddr::V4(ip), address.port())
            }),
        SocketAddr::V4(_) => address,
    }
}

fn is_forbidden_dns_server(server: SocketAddr, forbidden: &[SocketAddr]) -> bool {
    let server_ip = canonical_ip(server.ip());
    forbidden.iter().any(|candidate| {
        (candidate.port() == 0 || candidate.port() == server.port())
            && canonical_ip(candidate.ip()) == server_ip
    })
}

async fn exchange_direct_dns_udp_candidates(
    candidates: &[SocketAddr],
    query: &[u8],
    socket_protector: Option<&dyn xray_transport::SocketProtector>,
) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + DNS_DIRECT_TOTAL_TIMEOUT;
    let mut last_error = None;
    for (index, candidate) in candidates.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let candidate_share =
            direct_dns_udp_attempt_timeout(remaining, candidates.len().saturating_sub(index));
        match timeout(
            candidate_share.min(DNS_DIRECT_UDP_ATTEMPT_TIMEOUT),
            exchange_freedom_udp(*candidate, query, socket_protector, false),
        )
        .await
        {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(direct_dns_timeout_error("DNS UDP exchange timed out"));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| direct_dns_timeout_error("DNS UDP exchange timed out")))
}

fn direct_dns_udp_attempt_timeout(remaining: Duration, remaining_candidates: usize) -> Duration {
    let candidate_share = u32::try_from(remaining_candidates)
        .ok()
        .filter(|count| *count != 0)
        .map_or(remaining, |count| remaining / count);
    candidate_share.min(DNS_DIRECT_UDP_ATTEMPT_TIMEOUT)
}

async fn exchange_correlated_dns_tcp_message<S>(stream: &mut S, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    send_dns_tcp_message(stream, query).await?;

    for _ in 0..=MAX_DIRECT_DNS_UNRELATED_TCP_RESPONSES {
        let response_len = usize::from(stream.read_u16().await?);
        let mut response = vec![0_u8; response_len];
        stream.read_exact(&mut response).await?;
        if direct_dns_response_matches_query(query, &response) {
            return Ok(response);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "too many unrelated DNS TCP responses",
    ))
}

async fn send_dns_tcp_message<S>(stream: &mut S, query: &[u8]) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let query_len = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns tcp query is too large"))?;
    stream.write_u16(query_len).await?;
    stream.write_all(query).await?;
    stream.flush().await
}

fn direct_dns_timeout_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
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

/// Opens a Direct DNS TCP stream with the DNS outbound's own stream security
/// and Happy Eyeballs policy. This is deliberately separate from
/// `tcp+local://`, whose transport is always plain protected TCP.
pub(crate) async fn open_dns_outbound_tcp_stream(
    transport_dialer: &TransportDialer,
    outbound: &DnsOutbound,
    target: &Target,
    candidates: &[SocketAddr],
) -> io::Result<BoxedTransportStream> {
    let connector = outbound
        .tcp_connector_for(target)
        .map_err(io::Error::other)?;
    match outbound.happy_eyeballs_mode() {
        DnsHappyEyeballsMode::DnsDefault => {
            let default_happy_eyeballs = dns_tcp_happy_eyeballs(candidates);
            transport_dialer
                .connect_resolved(
                    &connector,
                    target,
                    candidates,
                    Some(&default_happy_eyeballs),
                )
                .await
                .map_err(io::Error::other)
        }
        DnsHappyEyeballsMode::Disabled => transport_dialer
            .connect_resolved(&connector, target, candidates, None)
            .await
            .map_err(io::Error::other),
        DnsHappyEyeballsMode::Configured(config) => transport_dialer
            .connect_resolved(&connector, target, candidates, Some(&config))
            .await
            .map_err(io::Error::other),
    }
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
        let _operation_permit = self.try_reserve_operation()?;
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
    match_question: bool,
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
    let mut response = vec![0_u8; MAX_DNS_WIRE_MESSAGE_SIZE];
    let mut unrelated_responses = 0_usize;
    loop {
        let len = socket.recv(&mut response).await?;
        let matches = if match_question {
            dns_response_matches_query(query, &response[..len])
        } else {
            direct_dns_response_matches_query(query, &response[..len])
        };
        if !matches {
            if unrelated_responses >= MAX_DNS_UNRELATED_UDP_RESPONSES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many unrelated DNS UDP responses",
                ));
            }
            unrelated_responses = unrelated_responses.saturating_add(1);
            tokio::task::yield_now().await;
            continue;
        }
        response.truncate(len);
        return Ok(response);
    }
}

fn direct_dns_response_matches_query(query: &[u8], response: &[u8]) -> bool {
    let (Some(query_header), Some(response_header)) = (query.get(..12), response.get(..12)) else {
        return false;
    };
    let query_flags = u16::from_be_bytes([query_header[2], query_header[3]]);
    let response_flags = u16::from_be_bytes([response_header[2], response_header[3]]);
    query_header[..2] == response_header[..2]
        && query_flags & 0x8000 == 0
        && response_flags & 0x8000 != 0
        && query_flags & 0x7800 == response_flags & 0x7800
}

pub(crate) fn static_dns_host_target(config: &CoreConfig, domain: &str) -> Option<DnsHostTarget> {
    static_dns_host_target_from_mappings(&config.dns.hosts, domain)
}

pub(crate) fn static_dns_host_target_from_mappings(
    hosts: &[xray_config::DnsHostMapping],
    domain: &str,
) -> Option<DnsHostTarget> {
    let mut current = normalize_dns_name(domain)?;
    let mut matched_alias = false;
    for _ in 0..MAX_STATIC_ALIAS_DEPTH {
        let Some(mapping) = hosts
            .iter()
            .find(|mapping| {
                matches!(&mapping.matcher, DomainMatcher::Full(_))
                    && dns_host_matcher_matches(&mapping.matcher, &current)
            })
            .or_else(|| {
                hosts
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
    matched_alias.then_some(DnsHostTarget::Domain(current))
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

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;
    use xray_config::{
        CoreConfig, DnsConfig, DnsHostMapping, DnsHostTarget, DnsOutboundRule,
        DnsOutboundRuleAction, DnsOutboundSettings, DnsQTypeRange, DnsServerConfig, DomainMatcher,
        IpCidr, IpMatcher, Network, OutboundConfig, OutboundSettings, PolicyConfig, RoutingConfig,
        RoutingDomainStrategy, RoutingRule, StreamSecurity, StreamSettings, StreamTransport,
        TargetAddr as ConfigTargetAddr, TlsSettings,
    };
    use xray_transport::{
        DnsQueryMetadata, DnsQueryTransportKind, SocketHandle, SocketProtector, TlsConnector,
        TransportError,
    };

    use super::*;
    use crate::dns_outbound_runtime::{
        DnsClientTransport, DnsDirectPoolConfig, DnsMessageOutcome, DnsOutboundRuntime,
    };
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

    fn dns_query(id: u16, domain: &str) -> Vec<u8> {
        let mut query = Vec::with_capacity(12 + domain.len() + 6);
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.split('.') {
            query.push(u8::try_from(label.len()).expect("bounded test label"));
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    fn dns_response(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response
    }

    fn dns_outbound_config(settings: DnsOutboundSettings, dns: DnsConfig) -> Arc<CoreConfig> {
        dns_outbound_config_with_stream(
            settings,
            dns,
            StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                socket_options: None,
            },
        )
    }

    fn dns_outbound_config_with_stream(
        settings: DnsOutboundSettings,
        dns: DnsConfig,
        stream: StreamSettings,
    ) -> Arc<CoreConfig> {
        Arc::new(CoreConfig {
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig {
                tag: Some("dns-out".to_owned()),
                stream,
                settings: OutboundSettings::Dns(settings),
            }],
            default_outbound_tag: Some("dns-out".to_owned()),
            routing: RoutingConfig::default(),
            dns,
            policy: PolicyConfig::default(),
        })
    }

    fn skip_dns_resolve_routing_config(
        server_domain: &str,
        server: SocketAddr,
        trap_ip: IpAddr,
        network: Network,
    ) -> Arc<CoreConfig> {
        let direct = OutboundConfig {
            tag: Some("direct".to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                socket_options: None,
            },
            settings: OutboundSettings::Freedom,
        };
        let dns_outbound = OutboundConfig {
            tag: Some("dns-out".to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                socket_options: None,
            },
            settings: OutboundSettings::Dns(DnsOutboundSettings {
                rewrite_network: Some(network),
                rewrite_address: Some(ConfigTargetAddr::Ip(trap_ip)),
                rewrite_port: server.port(),
                ..DnsOutboundSettings::default()
            }),
        };
        Arc::new(CoreConfig {
            inbounds: Vec::new(),
            outbounds: vec![direct, dns_outbound],
            default_outbound_tag: Some("direct".to_owned()),
            routing: RoutingConfig {
                rules: vec![RoutingRule {
                    inbound_tags: Vec::new(),
                    networks: vec![network],
                    port_ranges: Vec::new(),
                    domain_matchers: Vec::new(),
                    ip_matchers: vec![IpMatcher::Cidr(
                        IpCidr::new(server.ip(), if server.is_ipv4() { 32 } else { 128 }).unwrap(),
                    )],
                    outbound_tag: "dns-out".to_owned(),
                }],
                domain_strategy: RoutingDomainStrategy::IpIfNonMatch,
            },
            dns: DnsConfig {
                servers: vec![DnsServerConfig::Domain {
                    domain: server_domain.to_owned(),
                    port: server.port(),
                }],
                tag: "managed-dns".to_owned(),
                ..DnsConfig::default()
            },
            policy: PolicyConfig::default(),
        })
    }

    fn selected_dns_outbound(settings: DnsOutboundSettings) -> DnsOutbound {
        selected_dns_outbound_with_stream(
            settings,
            StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                socket_options: None,
            },
        )
    }

    fn selected_dns_outbound_with_stream(
        settings: DnsOutboundSettings,
        stream: StreamSettings,
    ) -> DnsOutbound {
        let router = OutboundRouter::new(dns_outbound_config_with_stream(
            settings,
            DnsConfig::default(),
            stream,
        ));
        router
            .select_dns_outbound_for_session(
                None,
                &Target::new(
                    TargetAddr::Domain("original.resolver.test".to_owned()),
                    53,
                    RoutingNetwork::Udp,
                ),
            )
            .expect("select DNS outbound")
            .expect("default outbound should be DNS")
    }

    fn dns_tls_configs(
        server_name: &str,
    ) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![server_name.to_owned()])
                .expect("generate DNS TLS test certificate");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add DNS TLS test root");
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports DNS TLS test versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports DNS TLS test versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build DNS TLS test server");
        (Arc::new(client_config), Arc::new(server_config))
    }

    async fn spawn_dns_tls_server(
        server_config: Arc<rustls::ServerConfig>,
        expected_query: Vec<u8>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind DNS TLS test server");
        let address = listener.local_addr().expect("read DNS TLS test address");
        let acceptor = TlsAcceptor::from(server_config);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept DNS TLS client");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("accept DNS TLS stream");
            let query_len =
                usize::from(stream.read_u16().await.expect("read DNS TLS query length"));
            let mut query = vec![0_u8; query_len];
            stream
                .read_exact(&mut query)
                .await
                .expect("read DNS TLS query");
            assert_eq!(query, expected_query);
            let response = dns_response(&query);
            stream
                .write_u16(u16::try_from(response.len()).expect("bounded DNS TLS response"))
                .await
                .expect("write DNS TLS response length");
            stream
                .write_all(&response)
                .await
                .expect("write DNS TLS response");
        });
        (address, task)
    }

    #[test]
    fn selected_dns_outbound_applies_component_rewrite_and_own_link_bypass() {
        let settings = DnsOutboundSettings {
            rewrite_network: Some(Network::Tcp),
            rewrite_address: Some(ConfigTargetAddr::Domain(
                "rewritten.resolver.test".to_owned(),
            )),
            rewrite_port: 5353,
            user_level: 0,
            rules: vec![DnsOutboundRule {
                action: DnsOutboundRuleAction::Drop,
                qtype_ranges: vec![DnsQTypeRange::single(1)],
                domain_matchers: vec![DomainMatcher::Full("policy.test".to_owned())],
            }],
        };
        let outbound = selected_dns_outbound(settings);
        let original = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
            53,
            RoutingNetwork::Udp,
        );

        assert_eq!(
            outbound.rewrite_target(&original),
            Target::new(
                TargetAddr::Domain("rewritten.resolver.test".to_owned()),
                5353,
                RoutingNetwork::Tcp,
            )
        );
        let query = dns_query(0x1234, "policy.test");
        assert_eq!(
            outbound.policy().decide_message(&query, false),
            Ok(crate::DnsOutboundDecision::Drop)
        );
        assert_eq!(
            outbound.policy().decide_message(&query, true),
            Ok(crate::DnsOutboundDecision::Direct)
        );
    }

    #[tokio::test]
    async fn routed_dns_own_link_uses_protected_direct_udp_and_correlates_response() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind direct DNS UDP server");
        let server_addr = socket.local_addr().expect("read DNS UDP server address");
        let query = dns_query(0x2345, "own-link.test");
        let expected_response = dns_response(&query);
        let server_response = expected_response.clone();
        let mut server = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (read, peer) = socket.recv_from(&mut buffer).await.expect("read DNS query");
            let mut unrelated = dns_response(&buffer[..read]);
            unrelated[1] ^= 1;
            socket
                .send_to(&unrelated, peer)
                .await
                .expect("send unrelated DNS response");
            socket
                .send_to(&server_response, peer)
                .await
                .expect("send matching DNS response");
        });

        let original_server = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
        let settings = DnsOutboundSettings {
            rewrite_network: Some(Network::Udp),
            rewrite_address: Some(ConfigTargetAddr::Ip(server_addr.ip())),
            rewrite_port: server_addr.port(),
            user_level: 0,
            rules: vec![DnsOutboundRule {
                action: DnsOutboundRuleAction::Drop,
                qtype_ranges: Vec::new(),
                domain_matchers: Vec::new(),
            }],
        };
        let config = dns_outbound_config(
            settings,
            DnsConfig {
                servers: vec![DnsServerConfig::Ip(original_server)],
                tag: "managed-dns".to_owned(),
                ..DnsConfig::default()
            },
        );
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                .expect("build protected transport dialer"),
        );
        let transport = RoutedDnsQueryTransport::new(
            Arc::new(OutboundRouter::new(config)),
            Arc::new(xray_transport::SystemDnsResolver),
            dialer,
            Vec::new(),
        );

        let response = transport
            .exchange(
                &NameServer::Socket(original_server),
                DnsQueryTransportKind::Udp,
                DnsQueryMetadata::new(Some("managed-dns")),
                &query,
            )
            .await
            .expect("managed own-link DNS should bypass Drop and use direct rewrite");

        assert_eq!(response, expected_response);
        assert_eq!(protector.calls.load(Ordering::Relaxed), 1);
        let joined = tokio::time::timeout(Duration::from_secs(1), &mut server).await;
        if joined.is_err() {
            server.abort();
            let _ = server.await;
        }
        joined
            .expect("direct DNS UDP server should finish")
            .expect("join direct DNS UDP server");
    }

    #[tokio::test]
    async fn managed_own_link_and_ingress_direct_udp_share_the_socket_budget() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind shared-budget DNS UDP server");
        let server_addr = socket.local_addr().expect("read DNS UDP server address");
        let (observed_tx, observed_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .await
                .expect("read admitted DNS query");
            let response = dns_response(&buffer[..read]);
            observed_tx.send(()).expect("signal admitted DNS query");
            release_rx.await.expect("release admitted DNS query");
            socket
                .send_to(&response, peer)
                .await
                .expect("send admitted DNS response");
            timeout(Duration::from_millis(100), socket.recv_from(&mut buffer))
                .await
                .is_ok()
        });

        let original_server = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
        let settings = DnsOutboundSettings {
            rewrite_network: Some(Network::Udp),
            rewrite_address: Some(ConfigTargetAddr::Ip(server_addr.ip())),
            rewrite_port: server_addr.port(),
            rules: vec![DnsOutboundRule {
                action: DnsOutboundRuleAction::Direct,
                qtype_ranges: Vec::new(),
                domain_matchers: Vec::new(),
            }],
            ..DnsOutboundSettings::default()
        };
        let config = dns_outbound_config(
            settings,
            DnsConfig {
                servers: vec![DnsServerConfig::Ip(original_server)],
                tag: "managed-dns".to_owned(),
                ..DnsConfig::default()
            },
        );
        let router = Arc::new(OutboundRouter::new(config));
        let bootstrap: Arc<dyn DnsResolver> = Arc::new(xray_transport::SystemDnsResolver);
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                .expect("build protected shared-budget dialer"),
        );
        let direct_executor = Arc::new(DnsDirectExecutor::with_pool_config(
            Arc::clone(&bootstrap),
            Arc::clone(&dialer),
            Vec::new(),
            DnsDirectPoolConfig::from_runtime_limit(1, Duration::from_secs(30)),
        ));
        let transport = Arc::new(RoutedDnsQueryTransport::with_direct_executor(
            Arc::clone(&router),
            Arc::clone(&bootstrap),
            dialer,
            Vec::new(),
            Arc::clone(&direct_executor),
            1,
        ));
        let target = Target::new(
            TargetAddr::Ip(original_server.ip()),
            original_server.port(),
            RoutingNetwork::Udp,
        );
        let selected = router
            .select_dns_outbound_for_session(Some("managed-dns"), &target)
            .expect("select managed DNS outbound")
            .expect("managed DNS outbound should be selected");
        let runtime = DnsOutboundRuntime::with_direct_executor(
            Arc::new(xray_transport::SystemDnsResolver),
            Arc::clone(&direct_executor),
            1,
        );
        let managed_query = dns_query(0x2351, "managed-budget.test");
        let managed_transport = Arc::clone(&transport);
        let managed_task = tokio::spawn(async move {
            managed_transport
                .exchange(
                    &NameServer::Socket(original_server),
                    DnsQueryTransportKind::Udp,
                    DnsQueryMetadata::new(Some("managed-dns")),
                    &managed_query,
                )
                .await
        });
        observed_rx
            .await
            .expect("managed own-link query should occupy the UDP budget");

        let ingress_query = dns_query(0x2352, "ingress-budget.test");
        let outcome = timeout(
            Duration::from_millis(200),
            runtime.execute_message(
                &selected,
                &target,
                ingress_query.into(),
                DnsClientTransport::Udp {
                    path_payload_cap: 1_232,
                },
            ),
        )
        .await
        .expect("saturated ingress Direct must fail closed without waiting");
        let DnsMessageOutcome::Reply(response) = outcome else {
            panic!("valid saturated ingress query should return SERVFAIL");
        };
        assert_eq!(response[3] & 0x0f, 2);
        assert_eq!(protector.calls.load(Ordering::Relaxed), 1);

        release_tx.send(()).expect("release managed DNS query");
        managed_task
            .await
            .expect("join managed DNS query")
            .expect("managed DNS query should complete");
        assert!(
            !server.await.expect("join shared-budget DNS server"),
            "saturated ingress Direct opened a second UDP socket"
        );
    }

    #[tokio::test]
    async fn routed_freedom_dns_has_a_global_operation_cap_and_shares_the_udp_budget() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind Freedom budget DNS UDP server");
        let server_addr = socket.local_addr().expect("read Freedom DNS address");
        let (observed_tx, observed_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .await
                .expect("read admitted Freedom DNS query");
            let response = dns_response(&buffer[..read]);
            observed_tx.send(()).expect("signal Freedom DNS query");
            release_rx.await.expect("release Freedom DNS query");
            socket
                .send_to(&response, peer)
                .await
                .expect("send Freedom DNS response");
            timeout(Duration::from_millis(100), socket.recv_from(&mut buffer))
                .await
                .is_ok()
        });

        let config = Arc::new(CoreConfig {
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig {
                tag: Some("direct".to_owned()),
                stream: StreamSettings {
                    network: Network::Tcp,
                    transport: StreamTransport::Raw,
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
        let bootstrap: Arc<dyn DnsResolver> = Arc::new(xray_transport::SystemDnsResolver);
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                .expect("build protected Freedom DNS dialer"),
        );
        let direct_executor = Arc::new(DnsDirectExecutor::with_pool_config(
            Arc::clone(&bootstrap),
            Arc::clone(&dialer),
            Vec::new(),
            DnsDirectPoolConfig::from_runtime_limit(1, Duration::from_secs(30)),
        ));
        let transport = Arc::new(RoutedDnsQueryTransport::with_direct_executor(
            Arc::new(OutboundRouter::new(config)),
            Arc::clone(&bootstrap),
            dialer,
            Vec::new(),
            Arc::clone(&direct_executor),
            1,
        ));
        let first_query = dns_query(0x2361, "freedom-budget.test");
        let first_transport = Arc::clone(&transport);
        let first_task = tokio::spawn(async move {
            first_transport
                .exchange(
                    &NameServer::Socket(server_addr),
                    DnsQueryTransportKind::Udp,
                    DnsQueryMetadata::new(None),
                    &first_query,
                )
                .await
        });
        observed_rx
            .await
            .expect("Freedom query should occupy both managed and UDP budgets");

        let second_query = dns_query(0x2362, "second-freedom-budget.test");
        let error = transport
            .exchange(
                &NameServer::Socket(server_addr),
                DnsQueryTransportKind::Udp,
                DnsQueryMetadata::new(None),
                &second_query,
            )
            .await
            .expect_err("second managed DNS operation must fail closed at the global cap");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        let ingress_outbound = selected_dns_outbound(DnsOutboundSettings {
            rewrite_network: Some(Network::Udp),
            rewrite_address: Some(ConfigTargetAddr::Ip(server_addr.ip())),
            rewrite_port: server_addr.port(),
            rules: vec![DnsOutboundRule {
                action: DnsOutboundRuleAction::Direct,
                qtype_ranges: Vec::new(),
                domain_matchers: Vec::new(),
            }],
            ..DnsOutboundSettings::default()
        });
        let runtime = DnsOutboundRuntime::with_direct_executor(
            Arc::new(xray_transport::SystemDnsResolver),
            Arc::clone(&direct_executor),
            1,
        );
        let outcome = timeout(
            Duration::from_millis(200),
            runtime.execute_message(
                &ingress_outbound,
                &Target::new(
                    TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
                    53,
                    RoutingNetwork::Udp,
                ),
                dns_query(0x2363, "ingress-behind-freedom.test").into(),
                DnsClientTransport::Udp {
                    path_payload_cap: 1_232,
                },
            ),
        )
        .await
        .expect("saturated ingress UDP must fail closed without waiting");
        let DnsMessageOutcome::Reply(response) = outcome else {
            panic!("valid saturated ingress query should return SERVFAIL");
        };
        assert_eq!(response[3] & 0x0f, 2);
        assert_eq!(protector.calls.load(Ordering::Relaxed), 1);

        release_tx.send(()).expect("release Freedom DNS query");
        first_task
            .await
            .expect("join Freedom DNS query")
            .expect("Freedom DNS query should complete");
        assert!(
            !server.await.expect("join Freedom budget DNS server"),
            "a saturated managed or ingress query opened a second UDP socket"
        );
    }

    #[tokio::test]
    async fn routed_dns_own_link_uses_the_injected_direct_tcp_pool() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind shared Direct DNS TCP server");
        let server_addr = listener
            .local_addr()
            .expect("read shared Direct DNS TCP address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept shared Direct DNS TCP client");
            let mut accepted = 1_usize;
            for index in 0..2 {
                let query_len = if index == 0 {
                    stream.read_u16().await.expect("read DNS query length")
                } else if let Ok(Ok(query_len)) =
                    timeout(Duration::from_millis(250), stream.read_u16()).await
                {
                    query_len
                } else {
                    let (next_stream, _) = listener
                        .accept()
                        .await
                        .expect("accept unexpected second Direct DNS TCP client");
                    stream = next_stream;
                    accepted = accepted.saturating_add(1);
                    stream
                        .read_u16()
                        .await
                        .expect("read query from second connection")
                };
                let query_len = usize::from(query_len);
                let mut query = vec![0_u8; query_len];
                stream
                    .read_exact(&mut query)
                    .await
                    .expect("read shared-pool DNS query");
                let response = dns_response(&query);
                stream
                    .write_u16(u16::try_from(response.len()).expect("bounded DNS response"))
                    .await
                    .expect("write DNS response length");
                stream
                    .write_all(&response)
                    .await
                    .expect("write shared-pool DNS response");
                stream.flush().await.expect("flush shared-pool response");
            }
            accepted
        });

        let original_server = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
        let settings = DnsOutboundSettings {
            rewrite_network: Some(Network::Tcp),
            rewrite_address: Some(ConfigTargetAddr::Ip(server_addr.ip())),
            rewrite_port: server_addr.port(),
            user_level: 0,
            rules: vec![DnsOutboundRule {
                action: DnsOutboundRuleAction::Direct,
                qtype_ranges: Vec::new(),
                domain_matchers: Vec::new(),
            }],
        };
        let config = dns_outbound_config(
            settings,
            DnsConfig {
                servers: vec![DnsServerConfig::Ip(original_server)],
                tag: "managed-dns".to_owned(),
                ..DnsConfig::default()
            },
        );
        let router = Arc::new(OutboundRouter::new(config));
        let bootstrap: Arc<dyn DnsResolver> = Arc::new(xray_transport::SystemDnsResolver);
        let dialer =
            Arc::new(TransportDialer::system().expect("build shared Direct DNS transport dialer"));
        let direct_executor = Arc::new(DnsDirectExecutor::new(
            Arc::clone(&bootstrap),
            Arc::clone(&dialer),
            Vec::new(),
        ));
        let transport = RoutedDnsQueryTransport::with_direct_executor(
            Arc::clone(&router),
            Arc::clone(&bootstrap),
            dialer,
            Vec::new(),
            Arc::clone(&direct_executor),
            16,
        );
        let target = Target::new(
            TargetAddr::Ip(original_server.ip()),
            original_server.port(),
            RoutingNetwork::Udp,
        );
        let selected = router
            .select_dns_outbound_for_session(Some("managed-dns"), &target)
            .expect("select managed DNS outbound")
            .expect("managed DNS outbound should be selected");
        let first = dns_query(0x2441, "managed-pool-one.test");
        let second = dns_query(0x2442, "managed-pool-two.test");

        let first_response = transport
            .exchange(
                &NameServer::Socket(original_server),
                DnsQueryTransportKind::Udp,
                DnsQueryMetadata::new(Some("managed-dns")),
                &first,
            )
            .await
            .expect("managed own-link query should succeed");
        let second_response = direct_executor
            .exchange_stateless(&selected, &target, &second)
            .await
            .expect("core Direct executor query should succeed");

        assert_eq!(first_response, dns_response(&first));
        assert_eq!(second_response, dns_response(&second));
        assert_eq!(
            timeout(Duration::from_secs(1), server)
                .await
                .expect("shared Direct DNS server should finish")
                .expect("join shared Direct DNS server"),
            1,
            "managed own-link created a second TCP pool"
        );
    }

    #[tokio::test]
    async fn routed_dns_selected_outbound_rejects_unmanaged_tag_before_dial() {
        let original_server = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
        let config = dns_outbound_config(
            DnsOutboundSettings::default(),
            DnsConfig {
                servers: vec![DnsServerConfig::Ip(original_server)],
                tag: "managed-dns".to_owned(),
                ..DnsConfig::default()
            },
        );
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                .expect("build protected transport dialer"),
        );
        let transport = RoutedDnsQueryTransport::new(
            Arc::new(OutboundRouter::new(config)),
            Arc::new(xray_transport::SystemDnsResolver),
            dialer,
            Vec::new(),
        );

        let error = transport
            .exchange(
                &NameServer::Socket(original_server),
                DnsQueryTransportKind::Udp,
                DnsQueryMetadata::new(Some("unmanaged")),
                &dns_query(0x2a2a, "unmanaged.test"),
            )
            .await
            .expect_err("selected DNS outbound must not recurse for an unmanaged tag");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(protector.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn direct_dns_tcp_rewrite_is_protected_and_correlates_response() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind direct DNS TCP server");
        let server_addr = listener.local_addr().expect("read DNS TCP server address");
        let query = dns_query(0x3456, "direct-tcp.test");
        let expected_response = dns_response(&query);
        let server_response = expected_response.clone();
        let mut server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept direct DNS TCP");
            let query_len = usize::from(stream.read_u16().await.expect("read DNS query length"));
            let mut received = vec![0_u8; query_len];
            stream
                .read_exact(&mut received)
                .await
                .expect("read DNS query");
            for offset in 0..MAX_DIRECT_DNS_UNRELATED_TCP_RESPONSES {
                let mut unrelated = dns_response(&received);
                unrelated[0..2].copy_from_slice(
                    &u16::try_from(offset.saturating_add(1))
                        .expect("bounded unrelated response id")
                        .to_be_bytes(),
                );
                stream
                    .write_u16(u16::try_from(unrelated.len()).expect("bounded response"))
                    .await
                    .expect("write unrelated response length");
                stream
                    .write_all(&unrelated)
                    .await
                    .expect("write unrelated response");
            }
            stream
                .write_u16(u16::try_from(server_response.len()).expect("bounded response"))
                .await
                .expect("write response length");
            stream
                .write_all(&server_response)
                .await
                .expect("write response");
        });

        let outbound = selected_dns_outbound(DnsOutboundSettings {
            rewrite_network: Some(Network::Tcp),
            rewrite_address: Some(ConfigTargetAddr::Domain("rewritten.direct.test".to_owned())),
            rewrite_port: server_addr.port(),
            ..DnsOutboundSettings::default()
        });
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = TransportDialer::system_with_socket_protector(Some(protector.clone()))
            .expect("build protected transport dialer");
        let bootstrap = CandidateBootstrapResolver {
            expected_domain: "rewritten.direct.test",
            expected_port: server_addr.port(),
            candidates: vec![server_addr],
            calls: AtomicUsize::new(0),
        };
        let original = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))),
            53,
            RoutingNetwork::Udp,
        );

        let response =
            exchange_direct_dns_query(&original, &outbound, &query, &bootstrap, &dialer, &[])
                .await
                .expect("direct DNS TCP rewrite should succeed");

        assert_eq!(response, expected_response);
        assert_eq!(bootstrap.calls.load(Ordering::Relaxed), 1);
        assert!(protector.calls.load(Ordering::Relaxed) >= 1);
        let joined = tokio::time::timeout(Duration::from_secs(1), &mut server).await;
        if joined.is_err() {
            server.abort();
            let _ = server.await;
        }
        joined
            .expect("direct DNS TCP server should finish")
            .expect("join direct DNS TCP server");
    }

    #[tokio::test]
    async fn direct_dns_tcp_applies_explicit_tls_and_allow_insecure() {
        let query = dns_query(0x6655, "explicit-tls.test");
        let expected_response = dns_response(&query);
        let (_, server_config) = dns_tls_configs("explicit-sni.test");
        let (server_addr, mut server) = spawn_dns_tls_server(server_config, query.clone()).await;
        let outbound = selected_dns_outbound_with_stream(
            DnsOutboundSettings {
                rewrite_network: Some(Network::Tcp),
                rewrite_address: Some(ConfigTargetAddr::Domain(
                    "explicit-upstream.test".to_owned(),
                )),
                rewrite_port: server_addr.port(),
                ..DnsOutboundSettings::default()
            },
            StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Tls(TlsSettings {
                    server_name: Some("explicit-sni.test".to_owned()),
                    fingerprint: None,
                    allow_insecure: true,
                    alpn: Vec::new(),
                }),
                socket_options: None,
            },
        );
        let bootstrap = CandidateBootstrapResolver {
            expected_domain: "explicit-upstream.test",
            expected_port: server_addr.port(),
            candidates: vec![server_addr],
            calls: AtomicUsize::new(0),
        };
        let original = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))),
            53,
            RoutingNetwork::Udp,
        );
        let dialer = TransportDialer::system().expect("build system DNS TLS dialer");

        let response = tokio::time::timeout(
            Duration::from_secs(2),
            exchange_direct_dns_query(&original, &outbound, &query, &bootstrap, &dialer, &[]),
        )
        .await
        .expect("DNS TLS exchange should not stall")
        .expect("explicit DNS TLS exchange should succeed");

        assert_eq!(response, expected_response);
        assert_eq!(bootstrap.calls.load(Ordering::Relaxed), 1);
        tokio::time::timeout(Duration::from_secs(1), &mut server)
            .await
            .expect("DNS TLS server should finish")
            .expect("join DNS TLS server");
    }

    #[tokio::test]
    async fn direct_dns_tcp_derives_tls_sni_from_rewritten_domain() {
        let rewritten_domain = "derived-sni.test";
        let query = dns_query(0x7766, "derived-tls.test");
        let expected_response = dns_response(&query);
        let (client_config, server_config) = dns_tls_configs(rewritten_domain);
        let (server_addr, mut server) = spawn_dns_tls_server(server_config, query.clone()).await;
        let outbound = selected_dns_outbound_with_stream(
            DnsOutboundSettings {
                rewrite_network: Some(Network::Tcp),
                rewrite_address: Some(ConfigTargetAddr::Domain(rewritten_domain.to_owned())),
                rewrite_port: server_addr.port(),
                ..DnsOutboundSettings::default()
            },
            StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Tls(TlsSettings {
                    server_name: None,
                    fingerprint: None,
                    allow_insecure: false,
                    alpn: Vec::new(),
                }),
                socket_options: None,
            },
        );
        let bootstrap = CandidateBootstrapResolver {
            expected_domain: rewritten_domain,
            expected_port: server_addr.port(),
            candidates: vec![server_addr],
            calls: AtomicUsize::new(0),
        };
        let original = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))),
            53,
            RoutingNetwork::Udp,
        );
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ))
        .with_socket_protector(protector.clone());

        let response = tokio::time::timeout(
            Duration::from_secs(2),
            exchange_direct_dns_query(&original, &outbound, &query, &bootstrap, &dialer, &[]),
        )
        .await
        .expect("derived-SNI DNS TLS exchange should not stall")
        .expect("derived-SNI DNS TLS exchange should succeed");

        assert_eq!(response, expected_response);
        assert_eq!(bootstrap.calls.load(Ordering::Relaxed), 1);
        assert!(protector.calls.load(Ordering::Relaxed) >= 1);
        tokio::time::timeout(Duration::from_secs(1), &mut server)
            .await
            .expect("derived-SNI DNS TLS server should finish")
            .expect("join derived-SNI DNS TLS server");
    }

    #[tokio::test]
    async fn direct_dns_tcp_transfer_keeps_tls_and_preserves_multiple_messages() {
        let rewritten_domain = "transfer-sni.test";
        let mut query = dns_query(0x8877, "transfer-tls.test");
        let qtype_offset = query.len().saturating_sub(4);
        query[qtype_offset..qtype_offset + 2].copy_from_slice(&252_u16.to_be_bytes());
        let expected_response = dns_response(&query);
        let (client_config, server_config) = dns_tls_configs(rewritten_domain);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind transfer DNS TLS server");
        let server_addr = listener
            .local_addr()
            .expect("read transfer DNS TLS server address");
        let acceptor = TlsAcceptor::from(server_config);
        let server_query = query.clone();
        let server_response = expected_response.clone();
        let mut server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept transfer DNS TLS client");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("accept transfer DNS TLS stream");
            let query_len = usize::from(
                stream
                    .read_u16()
                    .await
                    .expect("read transfer DNS query length"),
            );
            let mut received = vec![0_u8; query_len];
            stream
                .read_exact(&mut received)
                .await
                .expect("read transfer DNS query");
            assert_eq!(received, server_query);
            for _ in 0..2 {
                stream
                    .write_u16(
                        u16::try_from(server_response.len())
                            .expect("bounded transfer DNS response"),
                    )
                    .await
                    .expect("write transfer DNS response length");
                stream
                    .write_all(&server_response)
                    .await
                    .expect("write transfer DNS response");
            }
            stream.flush().await.expect("flush transfer DNS responses");
        });
        let outbound = selected_dns_outbound_with_stream(
            DnsOutboundSettings {
                rewrite_network: Some(Network::Tcp),
                rewrite_address: Some(ConfigTargetAddr::Domain(rewritten_domain.to_owned())),
                rewrite_port: server_addr.port(),
                ..DnsOutboundSettings::default()
            },
            StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Tls(TlsSettings {
                    server_name: None,
                    fingerprint: None,
                    allow_insecure: false,
                    alpn: Vec::new(),
                }),
                socket_options: None,
            },
        );
        let bootstrap = CandidateBootstrapResolver {
            expected_domain: rewritten_domain,
            expected_port: server_addr.port(),
            candidates: vec![server_addr],
            calls: AtomicUsize::new(0),
        };
        let original = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))),
            53,
            RoutingNetwork::Tcp,
        );
        let dialer = TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
            client_config,
        ));

        let mut session = DirectDnsTcpSession::open(&original, &outbound, &bootstrap, &dialer, &[])
            .await
            .expect("open transfer DNS TLS session");
        session
            .send(&query)
            .await
            .expect("send transfer DNS query through TLS");
        let mut stream = session.into_stream();
        for _ in 0..2 {
            let response_len = usize::from(
                stream
                    .read_u16()
                    .await
                    .expect("read transfer DNS response length"),
            );
            let mut response = vec![0_u8; response_len];
            stream
                .read_exact(&mut response)
                .await
                .expect("read transfer DNS response");
            assert_eq!(response, expected_response);
        }
        tokio::time::timeout(Duration::from_secs(1), &mut server)
            .await
            .expect("transfer DNS TLS server should finish")
            .expect("join transfer DNS TLS server");
    }

    #[tokio::test]
    async fn direct_dns_udp_with_stream_security_fails_before_dial() {
        let outbound = selected_dns_outbound_with_stream(
            DnsOutboundSettings {
                rewrite_network: Some(Network::Udp),
                rewrite_address: Some(ConfigTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))),
                rewrite_port: 5353,
                ..DnsOutboundSettings::default()
            },
            StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::Tls(TlsSettings {
                    server_name: Some("resolver.test".to_owned()),
                    fingerprint: None,
                    allow_insecure: true,
                    alpn: Vec::new(),
                }),
                socket_options: None,
            },
        );
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = TransportDialer::system_with_socket_protector(Some(protector.clone()))
            .expect("build protected DNS dialer");
        let original = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))),
            53,
            RoutingNetwork::Udp,
        );

        let error = exchange_direct_dns_query(
            &original,
            &outbound,
            &dns_query(0x5544, "udp-tls.test"),
            &xray_transport::SystemDnsResolver,
            &dialer,
            &[],
        )
        .await
        .expect_err("DNS TLS cannot be silently downgraded to UDP");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(protector.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn direct_dns_correlation_accepts_opaque_questions_but_checks_envelope() {
        let mut query = vec![0_u8; 12];
        query[0..2].copy_from_slice(&0x4a4a_u16.to_be_bytes());
        query[2..4].copy_from_slice(&0x1100_u16.to_be_bytes());
        query[4..6].copy_from_slice(&2_u16.to_be_bytes());
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x9100_u16.to_be_bytes());

        assert!(direct_dns_response_matches_query(&query, &response));

        response[1] ^= 1;
        assert!(!direct_dns_response_matches_query(&query, &response));
        response[1] ^= 1;
        response[2..4].copy_from_slice(&0x8900_u16.to_be_bytes());
        assert!(!direct_dns_response_matches_query(&query, &response));
    }

    #[tokio::test]
    async fn direct_dns_udp_preserves_response_larger_than_four_kibibytes() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind direct DNS UDP server");
        let server_addr = server.local_addr().expect("read DNS UDP server address");
        let query = dns_query(0x4b4b, "large-direct.test");
        let server_query = query.clone();
        let mut server_task = tokio::spawn(async move {
            let mut received = vec![0_u8; 512];
            let (len, peer) = server
                .recv_from(&mut received)
                .await
                .expect("receive direct DNS query");
            assert_eq!(&received[..len], server_query.as_slice());
            let mut response = vec![0_u8; 5_000];
            response[0..2].copy_from_slice(&server_query[0..2]);
            response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            server
                .send_to(&response, peer)
                .await
                .expect("send large direct DNS response");
        });
        let outbound = selected_dns_outbound(DnsOutboundSettings {
            rewrite_network: Some(Network::Udp),
            rewrite_address: Some(ConfigTargetAddr::Ip(server_addr.ip())),
            rewrite_port: server_addr.port(),
            ..DnsOutboundSettings::default()
        });
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = TransportDialer::system_with_socket_protector(Some(protector.clone()))
            .expect("build protected transport dialer");
        let original = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))),
            53,
            RoutingNetwork::Udp,
        );

        let response = exchange_direct_dns_query(
            &original,
            &outbound,
            &query,
            &xray_transport::SystemDnsResolver,
            &dialer,
            &[],
        )
        .await
        .expect("large direct DNS UDP response should succeed");

        assert_eq!(response.len(), 5_000);
        assert_eq!(&response[0..2], &query[0..2]);
        assert!(protector.calls.load(Ordering::Relaxed) >= 1);
        let joined = tokio::time::timeout(Duration::from_secs(1), &mut server_task).await;
        if joined.is_err() {
            server_task.abort();
            let _ = server_task.await;
        }
        joined
            .expect("direct DNS UDP server should finish")
            .expect("join direct DNS UDP server");
    }

    #[tokio::test]
    async fn direct_dns_udp_bounds_unrelated_responses() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind unrelated-response DNS UDP server");
        let server_addr = server.local_addr().expect("read DNS UDP server address");
        let query = dns_query(0x4c4c, "unrelated-direct.test");
        let server_query = query.clone();
        let server_task = tokio::spawn(async move {
            let mut received = vec![0_u8; 512];
            let (len, peer) = server
                .recv_from(&mut received)
                .await
                .expect("receive direct DNS query");
            assert_eq!(&received[..len], server_query.as_slice());
            for offset in 0..=MAX_DNS_UNRELATED_UDP_RESPONSES {
                let mut unrelated = dns_response(&server_query);
                unrelated[0..2].copy_from_slice(
                    &u16::try_from(offset.saturating_add(1))
                        .expect("bounded unrelated UDP id")
                        .to_be_bytes(),
                );
                server
                    .send_to(&unrelated, peer)
                    .await
                    .expect("send unrelated direct DNS response");
            }
        });
        let outbound = selected_dns_outbound(DnsOutboundSettings {
            rewrite_network: Some(Network::Udp),
            rewrite_address: Some(ConfigTargetAddr::Ip(server_addr.ip())),
            rewrite_port: server_addr.port(),
            ..DnsOutboundSettings::default()
        });
        let dialer = TransportDialer::system().expect("build DNS UDP dialer");
        let original = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))),
            53,
            RoutingNetwork::Udp,
        );

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            exchange_direct_dns_query(
                &original,
                &outbound,
                &query,
                &xray_transport::SystemDnsResolver,
                &dialer,
                &[],
            ),
        )
        .await
        .expect("unrelated DNS responses must be bounded")
        .expect_err("unrelated DNS responses must not be accepted");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        server_task.await.expect("join unrelated DNS UDP server");
    }

    #[test]
    fn direct_dns_udp_timeout_reserves_a_share_for_every_candidate() {
        let total = Duration::from_secs(5);
        let first = direct_dns_udp_attempt_timeout(total, MAX_DIRECT_DNS_CANDIDATES);
        assert_eq!(first, total / MAX_DIRECT_DNS_CANDIDATES as u32);
        assert!(first < DNS_DIRECT_UDP_ATTEMPT_TIMEOUT);
        assert_eq!(
            direct_dns_udp_attempt_timeout(Duration::from_secs(2), 1),
            DNS_DIRECT_UDP_ATTEMPT_TIMEOUT
        );
    }

    #[tokio::test]
    async fn direct_dns_rewrite_rejects_forbidden_runtime_local_endpoint() {
        let port = 5353;
        let outbound = selected_dns_outbound(DnsOutboundSettings {
            rewrite_network: Some(Network::Udp),
            rewrite_address: Some(ConfigTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            rewrite_port: port,
            ..DnsOutboundSettings::default()
        });
        let protector = Arc::new(CountingSocketProtector::default());
        let dialer = TransportDialer::system_with_socket_protector(Some(protector.clone()))
            .expect("build protected transport dialer");
        let forbidden = SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 0);
        let original = Target::new(
            TargetAddr::Domain("unused.original.test".to_owned()),
            53,
            RoutingNetwork::Udp,
        );

        let error = exchange_direct_dns_query(
            &original,
            &outbound,
            &dns_query(0x4567, "forbidden.test"),
            &xray_transport::SystemDnsResolver,
            &dialer,
            &[forbidden],
        )
        .await
        .expect_err("runtime-local rewritten DNS target must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(protector.calls.load(Ordering::Relaxed), 0);
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
                    transport: StreamTransport::Raw,
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

    #[tokio::test]
    async fn managed_udp_upstream_skips_ip_if_non_match_resolution_during_routing() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind managed DNS UDP server");
        let server_addr = socket.local_addr().expect("read managed DNS UDP address");
        let query = dns_query(0x4310, "skip-dns-resolve-udp.test");
        let expected_response = dns_response(&query);
        let server_response = expected_response.clone();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            let (read, peer) = socket.recv_from(&mut buffer).await.expect("read DNS query");
            socket
                .send_to(&server_response, peer)
                .await
                .expect("send DNS response");
            assert_eq!(&buffer[..read], query);
        });
        let server_domain = "managed-udp.resolver.test";
        let bootstrap = Arc::new(CandidateBootstrapResolver {
            expected_domain: server_domain,
            expected_port: server_addr.port(),
            candidates: vec![server_addr],
            calls: AtomicUsize::new(0),
        });
        let config = skip_dns_resolve_routing_config(
            server_domain,
            server_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            Network::Udp,
        );
        let transport = RoutedDnsQueryTransport::new(
            Arc::new(OutboundRouter::new(config)),
            bootstrap.clone(),
            Arc::new(TransportDialer::system().expect("build DNS dialer")),
            Vec::new(),
        );

        let response = timeout(
            Duration::from_secs(1),
            transport.exchange(
                &NameServer::Domain {
                    domain: server_domain.to_owned(),
                    port: server_addr.port(),
                },
                DnsQueryTransportKind::Udp,
                DnsQueryMetadata::new(Some("managed-dns")),
                &dns_query(0x4310, "skip-dns-resolve-udp.test"),
            ),
        )
        .await
        .expect("managed UDP routing must not recurse through IPIfNonMatch")
        .expect("managed UDP query should use the first-pass Freedom route");

        assert_eq!(response, expected_response);
        assert_eq!(bootstrap.calls.load(Ordering::Relaxed), 1);
        server.await.expect("join managed DNS UDP server");
    }

    #[tokio::test]
    async fn managed_tcp_upstream_skips_ip_if_non_match_resolution_during_routing() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind managed DNS TCP server");
        let server_addr = listener.local_addr().expect("read managed DNS TCP address");
        let query = dns_query(0x4311, "skip-dns-resolve-tcp.test");
        let expected_response = dns_response(&query);
        let server_response = expected_response.clone();
        let server_query = query.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept managed DNS TCP");
            let query_len = usize::from(stream.read_u16().await.expect("read query length"));
            let mut received = vec![0_u8; query_len];
            stream
                .read_exact(&mut received)
                .await
                .expect("read managed DNS query");
            assert_eq!(received, server_query);
            stream
                .write_u16(u16::try_from(server_response.len()).unwrap())
                .await
                .expect("write response length");
            stream
                .write_all(&server_response)
                .await
                .expect("write managed DNS response");
        });
        let server_domain = "managed-tcp.resolver.test";
        let bootstrap = Arc::new(CandidateBootstrapResolver {
            expected_domain: server_domain,
            expected_port: server_addr.port(),
            candidates: vec![server_addr],
            calls: AtomicUsize::new(0),
        });
        let config = skip_dns_resolve_routing_config(
            server_domain,
            server_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            Network::Tcp,
        );
        let transport = RoutedDnsQueryTransport::new(
            Arc::new(OutboundRouter::new(config)),
            bootstrap.clone(),
            Arc::new(TransportDialer::system().expect("build DNS dialer")),
            Vec::new(),
        );

        let response = timeout(
            Duration::from_secs(1),
            transport.exchange(
                &NameServer::Domain {
                    domain: server_domain.to_owned(),
                    port: server_addr.port(),
                },
                DnsQueryTransportKind::Tcp,
                DnsQueryMetadata::new(Some("managed-dns")),
                &query,
            ),
        )
        .await
        .expect("managed TCP routing must not recurse through IPIfNonMatch")
        .expect("managed TCP query should use the first-pass Freedom route");

        assert_eq!(response, expected_response);
        assert_eq!(bootstrap.calls.load(Ordering::Relaxed), 1);
        server.await.expect("join managed DNS TCP server");
    }
}
