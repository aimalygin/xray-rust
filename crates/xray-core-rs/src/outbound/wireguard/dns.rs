//! Destination DNS stays inside the WireGuard device, including TCP fallback.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_routing::DomainHostIndex;
use xray_transport::{
    dns_response_matches_query, CachingDnsResolver, ConfiguredDnsResolver, DnsQueryMetadata,
    DnsQueryTransport, DnsQueryTransportKind, NameServer,
};

struct NoLocalFallback;

#[async_trait]
impl DnsResolver for NoLocalFallback {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        Err(TransportError::DnsNoData(domain.to_owned(), port))
    }
}

struct TunnelDns(Client);

#[async_trait]
impl DnsQueryTransport for TunnelDns {
    async fn exchange(
        &self,
        server: &NameServer,
        transport: DnsQueryTransportKind,
        _metadata: DnsQueryMetadata<'_>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let NameServer::Socket(server) = server else {
            return Err(io::Error::other(
                "WireGuard remoteDNS must be an IP literal",
            ));
        };
        match transport {
            DnsQueryTransportKind::Udp => {
                let session = self.0.open_udp(*server).await.map_err(io::Error::other)?;
                session.send(query).await.map_err(io::Error::other)?;
                // The resolver supplies the deadline; also cap unrelated replies.
                for _ in 0..32 {
                    let reply = session.recv().await.map_err(io::Error::other)?;
                    if dns_response_matches_query(query, &reply) {
                        return Ok(reply.to_vec());
                    }
                }
                Err(io::Error::other("too many unrelated WireGuard DNS replies"))
            }
            DnsQueryTransportKind::Tcp => {
                let length = u16::try_from(query.len())
                    .map_err(|_| io::Error::other("DNS query exceeds TCP framing limit"))?;
                let mut stream = self.0.connect(*server).await.map_err(io::Error::other)?;
                stream.write_u16(length).await?;
                stream.write_all(query).await?;
                stream.flush().await?;
                let length = usize::from(stream.read_u16().await?);
                let mut reply = vec![0; length];
                stream.read_exact(&mut reply).await?;
                Ok(reply)
            }
            _ => Err(io::Error::other("unsupported WireGuard DNS transport")),
        }
    }
}

pub(super) fn resolver(client: Client, servers: &[IpAddr]) -> Arc<dyn DnsResolver> {
    let resolver = ConfiguredDnsResolver::new(
        DomainHostIndex::default(),
        servers
            .iter()
            .map(|ip| NameServer::Socket(SocketAddr::new(*ip, 53)))
            .collect(),
        Arc::new(NoLocalFallback),
    )
    .with_query_transport(Arc::new(TunnelDns(client)))
    .with_resolution_timeout(Duration::from_secs(8));
    // Shared bounded cache: 256 entries, single-flight, authoritative TTL capped
    // at 300 seconds, no stale answers. It belongs to this device, not the host.
    Arc::new(CachingDnsResolver::with_ttl(
        Arc::new(resolver),
        Duration::from_secs(300),
    ))
}
