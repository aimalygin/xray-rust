use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use xray_config::{CoreConfig, DnsHostTarget, DomainMatcher};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_new_packet, read_udp_packet, read_xudp_packet,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr};
use xray_transport::{
    dns_response_matches_query, protect_udp_socket, ConnectorConfig, DnsQueryMetadata,
    DnsQueryTransport, DnsQueryTransportKind, DnsResolver, NameServer, TransportDialer,
};

use crate::outbound::{
    open_tcp_stream_with_resolver_and_dialer, open_vless_udp_stream_with_resolver_and_dialer,
    TcpOutbound, UdpOutbound, VlessUdpFraming,
};
use crate::OutboundRouter;

const MAX_STATIC_ALIAS_DEPTH: usize = 8;
const MAX_DNS_UDP_RESPONSE_SIZE: usize = 4096;

/// DNS roles used by one runtime ingress context.
///
/// Destination lookups may use routed `dns.servers`; bootstrap lookups must
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
            .select_udp_outbound_for_session_with_resolver(
                metadata.inbound_tag,
                &target,
                self.bootstrap_resolver.as_ref(),
            )
            .await
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
        let selected = self
            .outbound_router
            .select_tcp_outbound_for_session_with_tag_and_resolver(
                metadata.inbound_tag,
                &target,
                false,
                self.bootstrap_resolver.as_ref(),
            )
            .await
            .map_err(io::Error::other)?;

        let mut stream = match selected.outbound {
            outbound @ (TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_)) => {
                let candidates = self.resolved_servers(server).await?;
                self.transport_dialer
                    .connect_resolved(
                        &ConnectorConfig::Tcp,
                        &target,
                        &candidates,
                        outbound.freedom_happy_eyeballs(),
                    )
                    .await
                    .map_err(io::Error::other)?
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

        let query_len = u16::try_from(query.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "dns tcp query is too large")
        })?;
        stream.write_u16(query_len).await?;
        stream.write_all(query).await?;
        stream.flush().await?;
        let response_len = usize::from(stream.read_u16().await?);
        let mut response = vec![0_u8; response_len];
        stream.read_exact(&mut response).await?;
        Ok(response)
    }
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
    use std::net::{IpAddr, Ipv4Addr};

    use xray_config::{
        CoreConfig, DnsConfig, DnsHostMapping, DnsHostTarget, DomainMatcher, PolicyConfig,
        RoutingConfig,
    };

    use super::static_dns_host_target;

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
}
