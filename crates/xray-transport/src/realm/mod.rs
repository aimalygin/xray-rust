//! The `realm` UDP mask as Xray-core v26.10.31's client runs it. The
//! carrier's socket learns its public addresses from STUN servers, a
//! rendezvous introduces it to the server registered under a realm name,
//! both sides punch a hole towards the other's addresses, and the carrier's
//! datagrams go to the address whose punch packet arrived first.
//!
//! The rendezvous only introduces; it never carries traffic. Everything
//! happens on the carrier's own socket before the carrier starts, as
//! `realm.NewConnClient` does it inside the dial.
mod candidates;
mod punch;
pub(crate) mod quic;
mod rendezvous;
mod stun;

use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use rand::RngCore;
use tokio::{net::UdpSocket, time::Instant};

use crate::{DnsQueryStrategy, DnsResolver, SocketProtector, TlsClientConfig, TlsConnector};

/// `defaultSTUNTimeout`: how long the client waits for the STUN answers.
const STUN_TIMEOUT: Duration = Duration::from_secs(4);
/// `defaultPunchTimeout`.
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
/// `defaultPunchInterval`: hello packets go out to every candidate this
/// often.
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
/// Xray-core reads STUN answers into a buffer of this size.
const STUN_BUFFER: usize = 1500;

/// The longest a realm introduction takes before the carrier's own
/// handshake: every STUN answer awaited, the rendezvous's longest wait and
/// the punch. Carriers add it to their dial deadlines.
pub const ESTABLISH_BUDGET: Duration = Duration::from_secs(36);

/// The client's settings, as `Realm.Build` reads them.
#[derive(Clone, PartialEq, Eq)]
pub struct RealmConfig {
    pub scheme: RealmScheme,
    /// The rendezvous host, a name or an IP address without brackets.
    pub host: String,
    /// The port as the URL spells it, for the `Host` header.
    pub port_text: String,
    pub port: u16,
    pub token: Arc<zeroize::Zeroizing<String>>,
    /// The realm name.
    pub id: String,
    pub stun_servers: Vec<RealmStunServer>,
    /// The rendezvous's TLS: required for HTTPS, its server name the host
    /// unless `tlsConfig` names another.
    pub tls: Option<TlsClientConfig>,
    pub family: RealmFamily,
}

impl fmt::Debug for RealmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealmConfig")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("id", &self.id)
            .field("stun_servers", &self.stun_servers)
            .field("family", &self.family)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealmScheme {
    Https,
    Http,
}

/// One STUN server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmStunServer {
    pub host: String,
    /// The port as written: Xray-core keys servers by it.
    pub port_text: String,
    pub port: u16,
}

/// `ipMode`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RealmFamily {
    #[default]
    Dual,
    V4,
    V6,
}

/// What a dial lends the introduction: the resolver for the STUN servers'
/// and rendezvous's names, the TLS connector and the platform's socket
/// protection.
#[derive(Clone)]
pub struct RealmEnv {
    pub resolver: Arc<dyn DnsResolver>,
    pub tls: TlsConnector,
    pub protector: Option<Arc<dyn SocketProtector>>,
}

impl fmt::Debug for RealmEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealmEnv")
            .field("protected", &self.protector.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RealmError {
    #[error("realm socket: {0}")]
    Io(#[from] io::Error),
    #[error("realm: no STUN server answered")]
    NoLocals,
    #[error("realm rendezvous: {0}")]
    Rendezvous(String),
    #[error("realm rendezvous returned {status}{detail}")]
    Status { status: u16, detail: String },
    #[error("realm: the server reported no address to punch")]
    NoPeers,
    #[error("realm: no punch packet arrived in time")]
    PunchTimeout,
}

/// The carrier's socket under realm, unconnected. For `dual` it listens on
/// the IPv6 wildcard for both families, as Go's wildcard listener does,
/// and reaches IPv4 addresses through their IPv4-mapped form.
pub(crate) struct RealmUdp {
    socket: UdpSocket,
    dual_stack: bool,
}

impl RealmUdp {
    /// A protected socket of the family `family` allows. A protection
    /// failure is the platform's, never retried unprotected.
    pub(crate) fn open(
        family: RealmFamily,
        protector: Option<&dyn SocketProtector>,
    ) -> Result<Self, crate::TransportError> {
        let (socket, dual_stack) = open_std(family).map_err(crate::TransportError::RealmSocket)?;
        crate::protect_std_udp_socket(&socket, protector)?;
        socket
            .set_nonblocking(true)
            .map_err(crate::TransportError::RealmSocket)?;
        Ok(Self {
            socket: UdpSocket::from_std(socket).map_err(crate::TransportError::RealmSocket)?,
            dual_stack,
        })
    }

    fn wire(&self, peer: SocketAddr) -> SocketAddr {
        match peer {
            SocketAddr::V4(v4) if self.dual_stack => {
                SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            peer => peer,
        }
    }

    pub(crate) async fn send_to(&self, datagram: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(datagram, self.wire(peer)).await
    }

    /// A datagram and its source, an IPv4-mapped one read as IPv4.
    pub(crate) async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (length, from) = self.socket.recv_from(buf).await?;
        Ok((length, crate::canonicalize_socket_addr(from)))
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Whether the socket reaches IPv4 addresses through IPv6.
    fn reaches_ipv4(&self) -> bool {
        self.dual_stack || self.local_addr().is_ok_and(|local| local.is_ipv4())
    }

    fn reaches_ipv6(&self) -> bool {
        self.local_addr().is_ok_and(|local| local.is_ipv6())
    }

    /// The socket back for a carrier that drives it itself.
    pub(crate) fn into_std(self) -> io::Result<StdUdpSocket> {
        self.socket.into_std()
    }
}

/// `dual` asks for a dual-stack socket and falls back to IPv4 where the
/// system has no IPv6, as Go's listener does.
fn open_std(family: RealmFamily) -> io::Result<(StdUdpSocket, bool)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let ipv6 = |only_v6: bool| -> io::Result<StdUdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(only_v6)?;
        socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into())?;
        Ok(socket.into())
    };
    let ipv4 = || StdUdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0));
    match family {
        RealmFamily::Dual => match ipv6(false) {
            Ok(socket) => Ok((socket, true)),
            Err(_) => Ok((ipv4()?, false)),
        },
        RealmFamily::V4 => Ok((ipv4()?, false)),
        RealmFamily::V6 => Ok((ipv6(true)?, false)),
    }
}

/// `getpeer`: the STUN servers, their answers, the rendezvous, the
/// candidates and the punch. Returns the peer the carrier sends to.
pub(crate) async fn establish(
    udp: &RealmUdp,
    config: &RealmConfig,
    env: &RealmEnv,
) -> Result<SocketAddr, RealmError> {
    let servers = resolve_stun_servers(udp, config, env).await;
    if servers.is_empty() {
        return Err(RealmError::NoLocals);
    }
    let locals = discover(udp, &servers).await;
    if locals.is_empty() {
        return Err(RealmError::NoLocals);
    }
    let meta = punch::PunchMetadata::random();
    let addresses: Vec<String> = locals.iter().map(ToString::to_string).collect();
    let answer = rendezvous::connect(config, env, &addresses, &meta).await?;
    let peers = candidates::parse_addr_ports(&answer);
    let peers = candidates::punch_candidates(&locals, &peers, config.family);
    if peers.is_empty() {
        return Err(RealmError::NoPeers);
    }
    punch(udp, &meta, &peers).await
}

/// `resolveSTUNServers`: one address per server, the first of the family
/// the socket and `ipMode` allow that no earlier server took with the same
/// port text. A server that does not resolve is skipped.
async fn resolve_stun_servers(
    udp: &RealmUdp,
    config: &RealmConfig,
    env: &RealmEnv,
) -> Vec<SocketAddr> {
    let strategy = match config.family {
        RealmFamily::V4 => DnsQueryStrategy::UseIpv4,
        RealmFamily::V6 => DnsQueryStrategy::UseIpv6,
        RealmFamily::Dual if udp.reaches_ipv4() && udp.reaches_ipv6() => DnsQueryStrategy::UseIp,
        RealmFamily::Dual => DnsQueryStrategy::UseIpv4,
    };
    let mut seen = HashSet::new();
    let mut servers = Vec::with_capacity(config.stun_servers.len());
    for server in &config.stun_servers {
        let ips: Vec<IpAddr> = match server.host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => match env
                .resolver
                .resolve_all_with_strategy(&server.host, server.port, strategy)
                .await
            {
                Ok(lookup) => lookup.ips().collect(),
                Err(_) => continue,
            },
        };
        let accepted = |ip: &IpAddr| match strategy {
            DnsQueryStrategy::UseIp => true,
            DnsQueryStrategy::UseIpv4 => ip.to_canonical().is_ipv4(),
            DnsQueryStrategy::UseIpv6 => !ip.to_canonical().is_ipv4(),
        };
        for ip in ips.into_iter().filter(accepted) {
            let ip = ip.to_canonical();
            if seen.insert((ip, server.port_text.clone())) {
                servers.push(SocketAddr::new(ip, server.port));
                break;
            }
        }
    }
    servers
}

/// `discover`: a Binding request to every server, then the answers to them
/// until all have come or the STUN timeout passes, sorted as their strings
/// sort.
async fn discover(udp: &RealmUdp, servers: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut pending = HashSet::with_capacity(servers.len());
    for server in servers {
        let mut transaction_id = [0u8; stun::TRANSACTION_ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut transaction_id);
        pending.insert(transaction_id);
        let _ = udp
            .send_to(&stun::binding_request(transaction_id), *server)
            .await;
    }
    let deadline = Instant::now() + STUN_TIMEOUT;
    let mut buf = vec![0u8; STUN_BUFFER];
    let mut locals = Vec::with_capacity(servers.len());
    while !pending.is_empty() {
        let Ok(Ok((length, _))) = tokio::time::timeout_at(deadline, udp.recv_from(&mut buf)).await
        else {
            break;
        };
        let Some(response) = stun::parse_binding_response(&buf[..length]) else {
            continue;
        };
        if pending.remove(&response.transaction_id) {
            locals.push(response.mapped);
        }
    }
    candidates::sort_by_string(&mut locals);
    locals
}

/// `punch`: hello packets to every candidate every interval until a punch
/// packet of this attempt arrives, from whichever address; a hello is
/// acknowledged. That address is the peer.
async fn punch(
    udp: &RealmUdp,
    meta: &punch::PunchMetadata,
    peers: &[SocketAddr],
) -> Result<SocketAddr, RealmError> {
    let start = Instant::now();
    let deadline = start + PUNCH_TIMEOUT;
    let mut next_send = start;
    let mut buf = vec![0u8; punch::MAX_WIRE_LEN];
    loop {
        let now = Instant::now();
        if now > deadline {
            return Err(RealmError::PunchTimeout);
        }
        if now >= next_send {
            for peer in peers {
                let _ = udp
                    .send_to(&punch::encode(punch::PacketType::Hello, meta), *peer)
                    .await;
            }
            next_send = now + PUNCH_INTERVAL;
        }
        let wake = next_send.min(deadline);
        let (length, from) = match tokio::time::timeout_at(wake, udp.recv_from(&mut buf)).await {
            Err(_) => continue,
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(received)) => received,
        };
        let Some((kind, _)) = punch::decode(&buf[..length], meta) else {
            continue;
        };
        if kind == punch::PacketType::Hello {
            let _ = udp
                .send_to(&punch::encode(punch::PacketType::Ack, meta), from)
                .await;
        }
        return Ok(from);
    }
}

#[cfg(test)]
mod tests;
