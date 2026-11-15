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

/// The stack a tunnel's resolver opens its queries on.
pub(crate) enum TunnelFlows {
    Wireguard(Client),
    /// MASQUE's stack over a CONNECT-IP tunnel.
    Netstack(xray_wireguard::Netstack),
}

impl TunnelFlows {
    async fn open_udp(&self, server: SocketAddr) -> Result<xray_wireguard::UdpSession, Error> {
        match self {
            Self::Wireguard(client) => client.open_udp(server).await,
            Self::Netstack(stack) => stack.open_udp(server).await,
        }
    }

    async fn connect(&self, server: SocketAddr) -> Result<xray_wireguard::TcpStream, Error> {
        match self {
            Self::Wireguard(client) => client.connect(server).await,
            Self::Netstack(stack) => stack.connect(server).await,
        }
    }
}

struct TunnelDns(TunnelFlows);

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
            return Err(io::Error::other("remoteDNS must be an IP literal"));
        };
        match transport {
            DnsQueryTransportKind::Udp => {
                let session = self.0.open_udp(*server).await.map_err(io::Error::other)?;
                session.send(query).await.map_err(io::Error::other)?;
                // The resolver supplies the deadline; also cap unrelated replies.
                // A tunnel loses a datagram as its carrier does, so the query
                // goes out again until its answer comes.
                let mut resend = crate::dns::dns_datagram_resend();
                let mut unrelated = 0;
                while unrelated < 32 {
                    tokio::select! {
                        reply = session.recv() => {
                            let reply = reply.map_err(io::Error::other)?;
                            if dns_response_matches_query(query, &reply) {
                                return Ok(reply.to_vec());
                            }
                            unrelated += 1;
                        }
                        _ = resend.tick() => {
                            session.send(query).await.map_err(io::Error::other)?;
                        }
                    }
                }
                Err(io::Error::other("too many unrelated tunnel DNS replies"))
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
            _ => Err(io::Error::other("unsupported tunnel DNS transport")),
        }
    }
}

pub(crate) fn resolver(flows: TunnelFlows, servers: &[IpAddr]) -> Arc<dyn DnsResolver> {
    let resolver = ConfiguredDnsResolver::new(
        DomainHostIndex::default(),
        servers
            .iter()
            .map(|ip| NameServer::Socket(SocketAddr::new(*ip, 53)))
            .collect(),
        Arc::new(NoLocalFallback),
    )
    .with_query_transport(Arc::new(TunnelDns(flows)))
    .with_resolution_timeout(Duration::from_secs(8));
    // Shared bounded cache: 256 entries, single-flight, authoritative TTL capped
    // at 300 seconds, no stale answers. It belongs to this device, not the host.
    Arc::new(CachingDnsResolver::with_ttl(
        Arc::new(resolver),
        Duration::from_secs(300),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use xray_transport::DnsQueryStrategy;

    fn udp_v4(src: (Ipv4Address, u16), dst: (Ipv4Address, u16), payload: &[u8]) -> bytes::Bytes {
        let udp = UdpRepr {
            src_port: src.1,
            dst_port: dst.1,
        };
        let ip = Ipv4Repr {
            src_addr: src.0,
            dst_addr: dst.0,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut bytes = bytes::BytesMut::zeroed(ip.buffer_len() + udp.header_len() + payload.len());
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
        ip.emit(&mut packet, &ChecksumCapabilities::default());
        udp.emit(
            &mut UdpPacket::new_unchecked(packet.payload_mut()),
            &src.0.into(),
            &dst.0.into(),
            payload.len(),
            |buf| buf.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        bytes.freeze()
    }

    /// The answer to an A query: its question and 198.51.100.7.
    fn answer(query: &[u8]) -> Vec<u8> {
        let mut end = 12;
        while query[end] != 0 {
            end += 1 + usize::from(query[end]);
        }
        end += 5;
        let mut reply = query[..2].to_vec();
        reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        reply.extend_from_slice(&query[12..end]);
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7]);
        reply
    }

    /// A destination's lookup inside a tunnel survives the loss of its
    /// query: the query goes out again, where the lookup used to wait out
    /// the server's four seconds and fail. The tunnel here loses the first
    /// datagram of every flow.
    #[tokio::test(start_paused = true)]
    async fn a_query_lost_in_the_tunnel_goes_out_again() {
        let server: IpAddr = "192.0.2.53".parse().unwrap();
        let (stack, mut packets) =
            xray_wireguard::Netstack::start(vec!["10.66.0.2".parse().unwrap()], 1280).unwrap();
        let resolver = resolver(TunnelFlows::Netstack(stack.clone()), &[server]);
        let datagrams = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&datagrams);
        let tunnel = tokio::spawn(async move {
            let mut flows = std::collections::HashSet::new();
            while let Some(packet) = packets.outgoing.recv().await {
                let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
                let udp = UdpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(IpAddr::from(ip.dst_addr()), server);
                seen.fetch_add(1, Ordering::SeqCst);
                if flows.insert(udp.src_port()) {
                    continue;
                }
                let reply = udp_v4(
                    (ip.dst_addr(), udp.dst_port()),
                    (ip.src_addr(), udp.src_port()),
                    &answer(udp.payload()),
                );
                if packets.incoming.send(reply).await.is_err() {
                    return;
                }
            }
        });

        let lookup = tokio::time::timeout(
            Duration::from_secs(3),
            resolver.resolve_all_with_strategy("lost-once.test", 443, DnsQueryStrategy::UseIpv4),
        )
        .await
        .expect("the lost query is sent again within the server's four seconds")
        .expect("the second query is answered");
        assert_eq!(
            lookup.socket_addrs(),
            ["198.51.100.7:443".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(datagrams.load(Ordering::SeqCst), 2, "one resend");
        stack.shutdown().await;
        tunnel.abort();
    }
}
