//! Optional Hysteria UDP carrier transforms. The ordinary carrier never enters
//! this wrapper. Port changes use Quinn's bounded current/previous socket pair.
use std::{
    collections::VecDeque,
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use blake2::{digest::consts::U32, Blake2b, Digest};
#[cfg(not(target_os = "macos"))]
use quinn::Runtime;
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use rand::{Rng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use super::{
    gecko::{self, GeckoPacketSize, Reassembly},
    HysteriaError,
};
use crate::{
    header_custom::{quic::HeaderCustomState, udp::UdpHeader, HeaderCustomUdpConfig},
    stream::H3UdpHopConfig,
    udp_noise::UdpNoiseState,
};

pub(crate) const SALT_LEN: usize = 8;

/// Xray Salamander and UDP-hop options. Empty options preserve the native path.
#[derive(Clone, Default)]
pub struct HysteriaCarrierConfig {
    pub salamander_password: Option<Arc<Zeroizing<String>>>,
    /// Gecko's fragment sizes, Salamander's `packetSize` in Xray. Requires a
    /// Salamander password.
    pub gecko: Option<GeckoPacketSize>,
    pub udp_hop: H3UdpHopConfig,
    pub noise: Option<crate::udp_noise::UdpNoiseConfig>,
    pub header_custom: Option<HeaderCustomCarrier>,
    pub sudoku: Option<SudokuCarrier>,
    /// The `xdns` mask, the outermost: the datagrams go to its resolvers,
    /// never to the server's address.
    pub xdns: Option<Arc<crate::xdns::XdnsConfig>>,
    /// The `realm` mask, the outermost: the socket is introduced to the
    /// server through a rendezvous, and the datagrams go to the address that
    /// answered its punch.
    pub realm: Option<Arc<crate::realm::RealmConfig>>,
    /// The `xicmp` mask, the outermost: the datagrams go out in ICMP echo
    /// requests, never in UDP.
    pub xicmp: Option<Arc<crate::xicmp::XicmpConfig>>,
}

/// A `salamander` UDP mask outside Hysteria, which keeps its own in
/// [`HysteriaCarrierConfig`]: its place among the other masks is theirs to
/// record, as they are listed before or after it.
#[derive(Clone, PartialEq, Eq)]
pub struct SalamanderCarrier {
    pub password: Arc<Zeroizing<String>>,
    /// Gecko's fragment sizes, Salamander's `packetSize` in Xray.
    pub gecko: Option<GeckoPacketSize>,
}

impl fmt::Debug for SalamanderCarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderCarrier")
            .field("password", &"<redacted>")
            .field("gecko", &self.gecko)
            .finish()
    }
}

/// A `sudoku` UDP mask and its place among the carrier's masks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SudokuCarrier {
    pub config: Arc<crate::sudoku::SudokuConfig>,
    /// Listed before Salamander, which then obfuscates it.
    pub before_salamander: bool,
    /// Listed before noise, whose packets then pass through it.
    pub before_noise: bool,
    /// Listed before `header-custom`, whose prefixes it then encodes.
    pub before_header_custom: bool,
}

/// A `header-custom` UDP mask and its place among the carrier's masks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderCustomCarrier {
    pub config: Arc<HeaderCustomUdpConfig>,
    /// Listed before Salamander, which then obfuscates it.
    pub before_salamander: bool,
    /// Listed before noise, whose packets then pass through it.
    pub before_noise: bool,
}

impl fmt::Debug for HysteriaCarrierConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaCarrierConfig")
            .field("salamander", &self.salamander_password.is_some())
            .field("gecko", &self.gecko)
            .field("udp_hop", &self.udp_hop)
            .field("header_custom", &self.header_custom.is_some())
            .field("sudoku", &self.sudoku.is_some())
            .field("xdns", &self.xdns.is_some())
            .field("realm", &self.realm.is_some())
            .field("xicmp", &self.xicmp.is_some())
            .finish()
    }
}

/// A carrier's masks, from the innermost as `finalmask.udp` lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mask {
    Noise,
    Salamander,
    Header,
    Sudoku,
}

/// One QUIC connection's mask state, which its rebound sockets keep:
/// Xray-core's masks sit above the socket that is replaced.
#[derive(Clone, Default)]
pub(crate) struct CarrierSession {
    pub(crate) noise: Option<Arc<UdpNoiseState>>,
    pub(crate) header: Option<Arc<HeaderCustomState>>,
    /// The xdns client, whose id the server knows the connection by, so
    /// every rebound socket goes through it.
    pub(crate) xdns: Option<Arc<crate::xdns::XdnsClient>>,
    /// The xicmp client, whose id the server knows the connection by, as
    /// the xdns client's.
    pub(crate) xicmp: Option<Arc<crate::xicmp::XicmpClient>>,
}

impl fmt::Debug for CarrierSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CarrierSession")
            .field("noise", &self.noise.is_some())
            .field("header", &self.header.is_some())
            .field("xdns", &self.xdns.is_some())
            .field("xicmp", &self.xicmp.is_some())
            .finish()
    }
}

impl CarrierSession {
    /// The state a new connection with `config` starts from.
    pub(crate) fn new(config: &HysteriaCarrierConfig) -> io::Result<Self> {
        Ok(Self {
            noise: config
                .noise
                .as_ref()
                .filter(|noise| !noise.items.is_empty())
                .map(|_| Arc::default()),
            header: config
                .header_custom
                .as_ref()
                .map(|header| HeaderCustomState::new(header.config.clone()))
                .transpose()?,
            xdns: None,
            xicmp: None,
        })
    }

    /// Opens the xdns client `config` asks for, unless there is one. A
    /// resolver that does not open fails the dial, as in Xray-core.
    pub(crate) async fn open_xdns(
        &mut self,
        config: &HysteriaCarrierConfig,
        protector: Option<Arc<dyn crate::SocketProtector>>,
    ) -> io::Result<()> {
        if let (Some(xdns), None) = (&config.xdns, &self.xdns) {
            let client = crate::xdns::XdnsClient::connect(xdns, protector)
                .await
                .map_err(io::Error::other)?;
            self.xdns = Some(Arc::new(client));
        }
        Ok(())
    }

    /// Opens the xicmp client `config` asks for, to `server` when its
    /// addresses are empty, unless there is one.
    pub(crate) async fn open_xicmp(
        &mut self,
        config: &HysteriaCarrierConfig,
        server: IpAddr,
        protector: Option<Arc<dyn crate::SocketProtector>>,
    ) -> io::Result<()> {
        if let (Some(xicmp), None) = (&config.xicmp, &self.xicmp) {
            let client = crate::xicmp::XicmpClient::connect(xicmp, server, protector)
                .await
                .map_err(io::Error::other)?;
            self.xicmp = Some(Arc::new(client));
        }
        Ok(())
    }
}

impl HysteriaCarrierConfig {
    pub(crate) fn validate(&self) -> Result<(), HysteriaError> {
        if let Some(noise) = &self.noise {
            noise.validate().map_err(|_| HysteriaError::Configuration)?;
        }
        if let Some(header) = &self.header_custom {
            // Xray-core writes to 0.0.0.0:0 under udphop but reads from the
            // hop's address, so its state never matches; refused here.
            if self.udp_hop.is_active() {
                return Err(HysteriaError::Configuration);
            }
            UdpHeader::new(header.config.clone()).map_err(|_| HysteriaError::Configuration)?;
        }
        if let Some(sudoku) = &self.sudoku {
            sudoku
                .config
                .tables()
                .map_err(|_| HysteriaError::Configuration)?;
        }
        if let Some(xdns) = &self.xdns {
            // Neither hops: xdns has no socket to the server, and Xray-core
            // ignores the udphop socket under it. Sudoku's datagrams are
            // four times a QUIC packet, past what one xdns packet takes.
            xdns.validate().map_err(|_| HysteriaError::Configuration)?;
            if self.udp_hop.is_active() || self.sudoku.is_some() {
                return Err(HysteriaError::Configuration);
            }
        }
        if self.xicmp.is_some()
            && (self.udp_hop.is_active()
                || self.xdns.is_some()
                || self.header_custom.is_some()
                || self.sudoku.is_some())
        {
            // Each of udphop and xdns sends elsewhere, as realm does, which
            // refuses xicmp below; header-custom would key the server's port
            // while replies come without one; sudoku's datagrams exceed what
            // an echo carries.
            return Err(HysteriaError::Configuration);
        }
        if let Some(realm) = &self.realm {
            // Its socket goes to the punched peer, never hops, and is no
            // resolver's; header-custom's state would key the server's
            // address while replies come from the peer's.
            if self.udp_hop.is_active()
                || self.xdns.is_some()
                || self.xicmp.is_some()
                || self.header_custom.is_some()
                || realm.stun_servers.is_empty()
                || (realm.scheme == crate::realm::RealmScheme::Https && realm.tls.is_none())
            {
                return Err(HysteriaError::Configuration);
            }
        }
        if self
            .salamander_password
            .as_ref()
            .is_some_and(|p| !(4..=4096).contains(&p.len()))
            || self.udp_hop.ports.len() > 65_535
            || self.udp_hop.ports.contains(&0)
            || self
                .udp_hop
                .remote_ips
                .iter()
                .any(|&(ip, prefix)| prefix > if ip.is_ipv4() { 32 } else { 128 })
            || self
                .gecko
                .is_some_and(|size| self.salamander_password.is_none() || !size.is_valid())
        {
            return Err(HysteriaError::Configuration);
        }
        if self.udp_hop.hops_on_interval() {
            let (min, max) = self.intervals();
            if min < Duration::from_secs(5)
                || max < min
                || max > Duration::from_secs(i32::MAX as u64)
            {
                return Err(HysteriaError::Configuration);
            }
        }
        Ok(())
    }

    fn intervals(&self) -> (Duration, Duration) {
        let default = |v: Duration| {
            if v.is_zero() {
                Duration::from_secs(30)
            } else {
                v
            }
        };
        (
            default(self.udp_hop.interval_min),
            default(self.udp_hop.interval_max),
        )
    }

    pub(crate) fn enabled(&self) -> bool {
        self.salamander_password.is_some()
            || self.udp_hop.is_active()
            || self.noise.is_some()
            || self.header_custom.is_some()
            || self.sudoku.is_some()
            || self.xdns.is_some()
            || self.realm.is_some()
            || self.xicmp.is_some()
    }

    /// What the masks add to every QUIC datagram: Salamander's salt and a
    /// custom prefix.
    pub(crate) fn wire_overhead(&self) -> usize {
        let salt = if self.salamander_password.is_some() {
            SALT_LEN
        } else {
            0
        };
        let prefix = self
            .header_custom
            .as_ref()
            .and_then(|header| UdpHeader::new(header.config.clone()).ok())
            .map_or(0, |header| header.prefix_len());
        salt + prefix
    }

    /// The masks from the innermost, as `finalmask.udp` lists them: each
    /// after as many of the others as are listed before it.
    fn mask_order(&self) -> Vec<Mask> {
        let mut masks = Vec::new();
        if self.salamander_password.is_some() {
            masks.push(Mask::Salamander);
        }
        if self.noise.is_some() {
            masks.push(Mask::Noise);
        }
        if self.header_custom.is_some() {
            masks.push(Mask::Header);
        }
        if self.sudoku.is_some() {
            masks.push(Mask::Sudoku);
        }
        let rank = |mask: Mask| {
            masks
                .iter()
                .filter(|&&other| other != mask && self.listed_before(other, mask))
                .count()
        };
        let mut ranked: Vec<(usize, Mask)> = masks.iter().map(|&mask| (rank(mask), mask)).collect();
        ranked.sort_by_key(|(rank, _)| *rank);
        ranked.into_iter().map(|(_, mask)| mask).collect()
    }

    /// Whether `first` is listed before `second`.
    fn listed_before(&self, first: Mask, second: Mask) -> bool {
        let noise = self.noise.as_ref();
        let header = self.header_custom.as_ref();
        let sudoku = self.sudoku.as_ref();
        let before = |first: Mask, second: Mask| match (first, second) {
            (Mask::Noise, Mask::Salamander) => noise.map(|noise| noise.before_salamander),
            (Mask::Header, Mask::Salamander) => header.map(|header| header.before_salamander),
            (Mask::Header, Mask::Noise) => header.map(|header| header.before_noise),
            (Mask::Sudoku, Mask::Salamander) => sudoku.map(|sudoku| sudoku.before_salamander),
            (Mask::Sudoku, Mask::Noise) => sudoku.map(|sudoku| sudoku.before_noise),
            (Mask::Sudoku, Mask::Header) => sudoku.map(|sudoku| sudoku.before_header_custom),
            _ => None,
        };
        before(first, second)
            .or_else(|| before(second, first).map(|after| !after))
            .unwrap_or(false)
    }

    /// The first remote address: with `remote` or `remote_once`, a random
    /// one, as Xray draws it at dial; otherwise the server's.
    pub(crate) fn next_peer(&self, mut peer: SocketAddr) -> SocketAddr {
        let hop = &self.udp_hop;
        if !(hop.remote || hop.remote_once) {
            return peer;
        }
        if let Some(ip) = self.draw_remote_ip(peer.ip()) {
            peer.set_ip(ip);
        }
        if !hop.ports.is_empty() {
            peer.set_port(hop.ports[rand::thread_rng().gen_range(0..hop.ports.len())]);
        }
        peer
    }

    /// The remote address for a scheduled hop from `current`. Without
    /// `remote` it stays. With it the IP is drawn again from `remote_ips`, and
    /// the port among the configured ports other than the current one, so
    /// every hop changes the path. Xray draws the port with replacement, so
    /// with two ports half of its hops leave it as is. A single distinct
    /// port keeps it.
    pub(crate) fn next_hop_peer(&self, logical: SocketAddr, mut current: SocketAddr) -> SocketAddr {
        if !self.udp_hop.remote {
            return current;
        }
        if let Some(ip) = self.draw_remote_ip(logical.ip()) {
            current.set_ip(ip);
        }
        let current_port = current.port();
        let mut others = self
            .udp_hop
            .ports
            .iter()
            .filter(|&&port| port != current_port);
        let count = others.clone().count();
        if count > 0 {
            current.set_port(
                *others
                    .nth(rand::thread_rng().gen_range(0..count))
                    .expect("index below count"),
            );
        }
        current
    }

    /// A random IP in a random one of the `remote_ips` of `server`'s family,
    /// with the host bits drawn as Xray's `randPrefix` draws them. `None`
    /// when there is none: a hop never leaves the server's family, since the
    /// QUIC endpoint keeps its socket family.
    fn draw_remote_ip(&self, server: IpAddr) -> Option<IpAddr> {
        let candidates: Vec<(IpAddr, u8)> = self
            .udp_hop
            .remote_ips
            .iter()
            .copied()
            .filter(|(ip, _)| ip.is_ipv4() == server.is_ipv4())
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let (network, prefix) = candidates[rand::thread_rng().gen_range(0..candidates.len())];
        Some(random_ip_in(network, prefix))
    }

    pub(crate) fn next_interval(&self) -> Option<Duration> {
        if !self.udp_hop.hops_on_interval() {
            return None;
        }
        let (min, max) = self.intervals();
        Some(Duration::from_nanos(
            rand::thread_rng().gen_range(min.as_nanos() as u64..=max.as_nanos() as u64),
        ))
    }
}

/// Xray's `randPrefix`: `network` with every bit past `prefix` random.
fn random_ip_in(network: IpAddr, prefix: u8) -> IpAddr {
    let mut rng = rand::thread_rng();
    match network {
        IpAddr::V4(ip) => {
            let host = u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(
                (u32::from(ip) & !host) | (rng.gen::<u32>() & host),
            ))
        }
        IpAddr::V6(ip) => {
            let host = u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(
                (u128::from(ip) & !host) | (rng.gen::<u128>() & host),
            ))
        }
    }
}

pub(crate) fn wrap(
    socket: UdpSocket,
    logical_peer: SocketAddr,
    wire_peer: SocketAddr,
    config: &HysteriaCarrierConfig,
    session: &CarrierSession,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    if let Some(tunnel) = tunnel(config, session, wire_peer)? {
        drop(socket);
        return wrap_masks(tunnel, logical_peer, wire_peer, config, session);
    }
    // Quinn sets the don't-fragment bit as it wraps the socket; sudoku's
    // datagrams need it clear again, through a clone of the socket.
    let fragmenting = config
        .sudoku
        .as_ref()
        .map(|_| socket.try_clone())
        .transpose()?;
    // A realm socket is unconnected and may be dual-stack, its peer of
    // another family than the server's address.
    let socket = if config.realm.is_some() {
        use quinn::Runtime as _;
        crate::realm::quic::wrap(quinn::TokioRuntime.wrap_udp_socket(socket)?, logical_peer)?
    } else {
        // Socket protection has already happened, before connect or any send.
        #[cfg(target_os = "macos")]
        let socket = crate::connected_quic::wrap(socket, wire_peer)?;
        #[cfg(not(target_os = "macos"))]
        let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
        socket
    };
    if let Some(clone) = fragmenting {
        crate::sudoku::quic::allow_fragmentation(&clone)?;
    }
    wrap_masks(socket, logical_peer, wire_peer, config, session)
}

/// The client that carries every datagram when the masks name xicmp or
/// xdns. The UDP socket then goes unused: Xray-core dials none under
/// xicmp, and the one it dials under xdns stays idle.
pub(crate) fn tunnel(
    config: &HysteriaCarrierConfig,
    session: &CarrierSession,
    wire_peer: SocketAddr,
) -> io::Result<Option<Arc<dyn AsyncUdpSocket>>> {
    if config.xicmp.is_some() {
        let client = session.xicmp.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "the xicmp client is not open")
        })?;
        return Ok(Some(crate::xicmp::quic::socket(client, wire_peer)));
    }
    if config.xdns.is_some() {
        let client = session.xdns.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "the xdns client is not open")
        })?;
        return Ok(Some(crate::xdns::quic::socket(client, wire_peer)));
    }
    Ok(None)
}

/// The masks over the carrier's socket, built from the wire inwards.
pub(crate) fn wrap_masks(
    mut socket: Arc<dyn AsyncUdpSocket>,
    logical_peer: SocketAddr,
    wire_peer: SocketAddr,
    config: &HysteriaCarrierConfig,
    session: &CarrierSession,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    // Built from the wire inwards. Masks outside the carrier socket see the
    // wire peer and those inside it the logical one; it sits at Salamander's
    // place, or innermost without Salamander.
    let mut inside = false;
    for mask in config.mask_order().into_iter().rev() {
        let peer = if inside { logical_peer } else { wire_peer };
        socket = match (mask, &config.noise, &config.header_custom) {
            (Mask::Noise, Some(noise), _) => {
                crate::udp_noise::wrap(socket, peer, noise.clone(), session.noise.clone())?
            }
            (Mask::Sudoku, ..) => match &config.sudoku {
                Some(sudoku) => crate::sudoku::quic::wrap(socket, &sudoku.config)?,
                None => socket,
            },
            (Mask::Header, _, Some(header)) => {
                let state = match &session.header {
                    Some(state) => state.clone(),
                    None => HeaderCustomState::new(header.config.clone())?,
                };
                crate::header_custom::quic::wrap(socket, peer, logical_peer, state)
            }
            (Mask::Salamander, ..) => {
                inside = true;
                carrier_socket(socket, logical_peer, wire_peer, config)
            }
            _ => socket,
        };
    }
    if !inside {
        socket = carrier_socket(socket, logical_peer, wire_peer, config);
    }
    Ok(socket)
}

fn carrier_socket(
    inner: Arc<dyn AsyncUdpSocket>,
    logical_peer: SocketAddr,
    wire_peer: SocketAddr,
    config: &HysteriaCarrierConfig,
) -> Arc<dyn AsyncUdpSocket> {
    Arc::new(CarrierSocket {
        inner,
        logical_peer,
        wire_peer,
        password: config.salamander_password.clone(),
        send_buffer: Mutex::new(Vec::with_capacity(1500)),
        receive_buffer: config
            .salamander_password
            .as_ref()
            .map(|_| Mutex::new(vec![0; 65_536].into_boxed_slice())),
        gecko: config
            .gecko
            .filter(|_| config.salamander_password.is_some())
            .map(GeckoState::new),
    })
}

struct CarrierSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    logical_peer: SocketAddr,
    wire_peer: SocketAddr,
    password: Option<Arc<Zeroizing<String>>>,
    send_buffer: Mutex<Vec<u8>>,
    receive_buffer: Option<Mutex<Box<[u8]>>>,
    gecko: Option<GeckoState>,
}

/// Per-socket Gecko state. Hops and rebinds get a fresh socket and state;
/// the server keys its reassembly by source address, so nothing carries over.
struct GeckoState {
    size: GeckoPacketSize,
    last_message: AtomicU32,
    receive: Mutex<GeckoReceive>,
}

#[derive(Default)]
struct GeckoReceive {
    reassembly: Reassembly,
    /// Reassembled messages and the short-header datagrams read with them,
    /// delivered before the socket is read again.
    ready: VecDeque<Vec<u8>>,
    /// The metadata of the read that filled `ready`.
    meta: udp::RecvMeta,
}

impl GeckoState {
    fn new(size: GeckoPacketSize) -> Self {
        Self {
            size,
            last_message: AtomicU32::new(0),
            receive: Mutex::default(),
        }
    }

    /// Gecko's message IDs: a wrapping counter whose first value is one.
    fn next_message(&self) -> u8 {
        self.last_message
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1) as u8
    }

    /// Feeds one read's decoded datagrams, split at its stride, through
    /// reassembly. Returns false, consuming nothing, when none is a frame.
    fn absorb(&self, decoded: &[u8], meta: &udp::RecvMeta) -> bool {
        let datagrams = || decoded.chunks(meta.stride.max(1));
        if !datagrams().any(gecko::is_fragmented) {
            return false;
        }
        let now = Instant::now();
        let mut receive = self.receive.lock().unwrap_or_else(|e| e.into_inner());
        for datagram in datagrams() {
            if !gecko::is_fragmented(datagram) {
                receive.ready.push_back(datagram.to_vec());
            } else if let Some(frame) = gecko::parse_frame(datagram) {
                if let Some(message) = receive.reassembly.accept(now, frame) {
                    receive.ready.push_back(message);
                }
            }
        }
        // ECN marks belong to individual fragments, not to messages.
        receive.meta = udp::RecvMeta { ecn: None, ..*meta };
        true
    }

    /// Moves ready datagrams into Quinn's buffers, one per buffer. Returns
    /// how many buffers were used, or none when nothing was ready.
    fn deliver(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [udp::RecvMeta]) -> Option<usize> {
        let mut receive = self.receive.lock().unwrap_or_else(|e| e.into_inner());
        let mut count = 0;
        for (buffer, meta) in bufs.iter_mut().zip(meta.iter_mut()) {
            let Some(datagram) = receive.ready.pop_front() else {
                break;
            };
            *meta = udp::RecvMeta {
                len: datagram.len(),
                stride: datagram.len(),
                ..receive.meta
            };
            if datagram.len() <= buffer.len() {
                buffer[..datagram.len()].copy_from_slice(&datagram);
            } else {
                meta.len = 0;
                meta.stride = 1;
            }
            count += 1;
        }
        (count > 0).then_some(count)
    }
}

impl fmt::Debug for CarrierSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaCarrierSocket")
            .field("logical_peer", &self.logical_peer)
            .field("wire_peer", &self.wire_peer)
            .field("salamander", &self.password.is_some())
            .finish_non_exhaustive()
    }
}

pub(crate) fn key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

fn encode(password: &str, salt: [u8; SALT_LEN], input: &[u8], output: &mut [u8]) {
    let mut mask = key(password, &salt);
    output[..SALT_LEN].copy_from_slice(&salt);
    for (i, byte) in input.iter().enumerate() {
        output[SALT_LEN + i] = byte ^ mask[i % mask.len()];
    }
    mask.zeroize();
}

// Compact each GRO segment separately. Removing only the first salt would
// corrupt coalesced datagrams on Linux/Android.
fn decode(password: &str, buffer: &mut [u8], meta: &mut udp::RecvMeta) {
    if meta.stride <= SALT_LEN
        || meta.len > buffer.len()
        || !meta.len.is_multiple_of(meta.stride) && meta.len % meta.stride <= SALT_LEN
    {
        meta.len = 0;
        meta.stride = 1;
        return;
    }
    let mut written = 0;
    for offset in (0..meta.len).step_by(meta.stride) {
        let end = (offset + meta.stride).min(meta.len);
        let mut mask = key(password, &buffer[offset..offset + SALT_LEN]);
        for i in 0..end - offset - SALT_LEN {
            buffer[written + i] = buffer[offset + SALT_LEN + i] ^ mask[i % mask.len()];
        }
        written += end - offset - SALT_LEN;
        mask.zeroize();
    }
    meta.len = written;
    meta.stride -= SALT_LEN;
}

impl AsyncUdpSocket for CarrierSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.logical_peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected Hysteria peer",
            ));
        }
        let mut rewritten = udp::Transmit {
            destination: self.wire_peer,
            ..*transmit
        };
        let Some(password) = &self.password else {
            return self.inner.try_send(&rewritten);
        };
        if transmit.contents.len() > 65_507 - SALT_LEN
            || transmit
                .segment_size
                .is_some_and(|size| size == 0 || transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salamander requires one bounded datagram",
            ));
        }
        let mut buffer = self.send_buffer.lock().unwrap_or_else(|e| e.into_inner());
        rewritten.segment_size = None;
        if let Some(gecko) = self
            .gecko
            .as_ref()
            .filter(|_| gecko::is_fragmented(transmit.contents))
        {
            let message = gecko.next_message();
            let frames = gecko::fragment(
                transmit.contents,
                message,
                gecko.size,
                &mut rand::thread_rng(),
            );
            for (index, frame) in frames.iter().enumerate() {
                buffer.resize(frame.len() + SALT_LEN, 0);
                let mut salt = [0; SALT_LEN];
                rand::thread_rng().fill_bytes(&mut salt);
                encode(password, salt, frame, &mut buffer);
                let fragment = udp::Transmit {
                    contents: &buffer,
                    ..rewritten
                };
                match self.inner.try_send(&fragment) {
                    Ok(()) => {}
                    // Fragments already sent cannot be recalled. Losing the
                    // rest loses the datagram, which QUIC recovers; resending
                    // would leave the peer another incomplete message.
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && index > 0 => {
                        return Ok(())
                    }
                    Err(error) => return Err(error),
                }
            }
            return Ok(());
        }
        buffer.resize(transmit.contents.len() + SALT_LEN, 0);
        let mut salt = [0; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        encode(password, salt, transmit.contents, &mut buffer);
        rewritten.contents = &buffer;
        self.inner.try_send(&rewritten)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let (Some(password), Some(scratch)) = (&self.password, &self.receive_buffer) {
            if let Some(count) = self.gecko.as_ref().and_then(|g| g.deliver(bufs, meta)) {
                return Poll::Ready(Ok(count));
            }
            // Quinn allocates receive buffers from its advertised QUIC payload
            // limit, which excludes the salt. Reserve wire overhead separately,
            // including for GRO aggregates, before copying decoded bytes back.
            let mut scratch = scratch.lock().unwrap_or_else(|e| e.into_inner());
            let mut wire = [IoSliceMut::new(&mut scratch)];
            let count = std::task::ready!(self.inner.poll_recv(cx, &mut wire, &mut meta[..1]))?;
            if count == 0 {
                return Poll::Ready(Ok(0));
            }
            if meta[0].addr == self.wire_peer {
                decode(password, &mut scratch, &mut meta[0]);
                meta[0].addr = self.logical_peer;
                if let Some(gecko) = &self.gecko {
                    // Frames travel only during the handshake; afterwards
                    // every datagram takes the copy below.
                    if meta[0].len > 0 && gecko.absorb(&scratch[..meta[0].len], &meta[0]) {
                        if let Some(count) = gecko.deliver(bufs, meta) {
                            return Poll::Ready(Ok(count));
                        }
                        meta[0].len = 0;
                        meta[0].stride = 1;
                        return Poll::Ready(Ok(1));
                    }
                }
                if meta[0].len <= bufs[0].len() {
                    bufs[0][..meta[0].len].copy_from_slice(&scratch[..meta[0].len]);
                } else {
                    meta[0].len = 0;
                    meta[0].stride = 1;
                }
            } else {
                meta[0].len = 0;
                meta[0].stride = 1;
            }
            return Poll::Ready(Ok(1));
        }
        let count = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (buffer, meta) in bufs.iter_mut().zip(meta).take(count) {
            if meta.addr != self.wire_peer {
                meta.len = 0;
                meta.stride = 1;
                continue;
            }
            meta.addr = self.logical_peer;
            if let Some(password) = &self.password {
                decode(password, buffer, meta);
            }
        }
        Poll::Ready(Ok(count))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
    fn max_transmit_segments(&self) -> usize {
        if self.password.is_some() {
            1
        } else {
            self.inner.max_transmit_segments()
        }
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_noise_mask_order_is_visible_on_the_wire() {
        use crate::udp_noise::{NoiseRange, UdpNoiseConfig, UdpNoiseItem};
        use std::future::poll_fn;
        for before in [false, true] {
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = peer.local_addr().unwrap();
            let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
            raw.set_nonblocking(true).unwrap();
            let zero = || NoiseRange { from: 0, to: 0 };
            let config = HysteriaCarrierConfig {
                salamander_password: Some(Arc::new(Zeroizing::new("synthetic".into()))),
                noise: Some(UdpNoiseConfig {
                    items: vec![UdpNoiseItem {
                        packet: b"prelude".to_vec(),
                        random_length: zero(),
                        random_bytes: zero(),
                        delay_ms: zero(),
                        segments: Vec::new(),
                    }],
                    reset_secs: zero(),
                    before_salamander: before,
                }),
                ..Default::default()
            };
            let client = wrap(raw, addr, addr, &config, &CarrierSession::default()).unwrap();
            let mut poller = client.clone().create_io_poller();
            for contents in [b"first".as_slice(), b"later"] {
                let transmit = udp::Transmit {
                    destination: addr,
                    ecn: None,
                    contents,
                    segment_size: None,
                    src_ip: None,
                };
                loop {
                    match client.try_send(&transmit) {
                        Ok(()) => break,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            poll_fn(|cx| poller.as_mut().poll_writable(cx))
                                .await
                                .unwrap()
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
            }
            for (index, expected) in [b"prelude".as_slice(), b"first", b"later"]
                .into_iter()
                .enumerate()
            {
                let mut bytes = [0; 128];
                let (n, _) =
                    tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                        .await
                        .unwrap()
                        .unwrap();
                if index == 0 && !before {
                    assert_eq!(&bytes[..n], expected);
                } else {
                    let mut meta = udp::RecvMeta {
                        len: n,
                        stride: n,
                        ..Default::default()
                    };
                    decode("synthetic", &mut bytes, &mut meta);
                    assert_eq!(&bytes[..meta.len], expected);
                }
            }
        }
    }

    #[test]
    fn independent_blake2b_256_vector_and_gro_boundaries() {
        // Independently generated with Python hashlib.blake2b(digest_size=32).
        // BLAKE2b-512 truncated to 256 bits would NOT match this vector.
        let input = b"Salamander independent wire vector";
        let expected =
            "000102030405060777443fb63daf49e241c27041583d9a8f9c675ee1f82d2a91937784a0f67f81414b57";
        let mut wire = vec![0; input.len() + SALT_LEN];
        encode(
            "synthetic-password",
            [0, 1, 2, 3, 4, 5, 6, 7],
            input,
            &mut wire,
        );
        assert_eq!(
            wire.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            expected
        );
        let stride = wire.len();
        let mut aggregate = wire.clone();
        aggregate.extend_from_slice(&wire);
        let mut short = vec![0; 11];
        encode("synthetic-password", [0xff; 8], b"end", &mut short);
        aggregate.extend_from_slice(&short);
        let mut meta = udp::RecvMeta {
            len: aggregate.len(),
            stride,
            ..Default::default()
        };
        decode("synthetic-password", &mut aggregate, &mut meta);
        assert_eq!(meta.stride, input.len());
        assert_eq!(
            &aggregate[..meta.len],
            [input.as_slice(), input.as_slice(), b"end"].concat()
        );
        for length in 0..=8 {
            let mut invalid = vec![0; stride + length];
            let mut meta = udp::RecvMeta {
                len: invalid.len(),
                stride: if length == 0 { 0 } else { stride },
                ..Default::default()
            };
            decode("synthetic-password", &mut invalid, &mut meta);
            assert_eq!(meta.len, 0);
            assert_eq!(meta.stride, 1);
        }
    }

    #[tokio::test]
    async fn header_custom_order_around_salamander_is_visible_on_the_wire() {
        use crate::header_custom::{CustomItem, HeaderCustomUdpConfig};
        let item = |packet: &[u8]| CustomItem {
            delay: (0, 0),
            rand: 0,
            rand_range: (0, 255),
            packet: packet.to_vec(),
            capture: String::new(),
            reuse: String::new(),
            transform: None,
        };
        for before in [false, true] {
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = peer.local_addr().unwrap();
            let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
            raw.set_nonblocking(true).unwrap();
            let config = HysteriaCarrierConfig {
                salamander_password: Some(Arc::new(Zeroizing::new("synthetic".into()))),
                header_custom: Some(HeaderCustomCarrier {
                    config: Arc::new(HeaderCustomUdpConfig {
                        standalone: false,
                        client: vec![item(b"HC")],
                        server: vec![item(b"SV")],
                    }),
                    before_salamander: before,
                    before_noise: false,
                }),
                ..Default::default()
            };
            config.validate().unwrap();
            assert_eq!(config.wire_overhead(), SALT_LEN + 2);
            let client = wrap(
                raw,
                addr,
                addr,
                &config,
                &CarrierSession::new(&config).unwrap(),
            )
            .unwrap();
            let mut poller = client.clone().create_io_poller();
            let transmit = udp::Transmit {
                destination: addr,
                ecn: None,
                contents: b"quic",
                segment_size: None,
                src_ip: None,
            };
            loop {
                match client.try_send(&transmit) {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                            .await
                            .unwrap()
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            let mut bytes = [0; 128];
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            let mut meta = udp::RecvMeta {
                len: n,
                stride: n,
                ..Default::default()
            };
            if before {
                // Salamander obfuscates the prefix with the datagram.
                decode("synthetic", &mut bytes, &mut meta);
                assert_eq!(&bytes[..meta.len], b"HCquic");
            } else {
                // The prefix stays outside Salamander's datagram.
                assert_eq!(&bytes[..2], b"HC");
                let mut inner = bytes[2..n].to_vec();
                let mut meta = udp::RecvMeta {
                    len: n - 2,
                    stride: n - 2,
                    ..Default::default()
                };
                decode("synthetic", &mut inner, &mut meta);
                assert_eq!(&inner[..meta.len], b"quic");
            }
        }
    }

    #[tokio::test]
    async fn a_rebound_carrier_keeps_its_standalone_handshake() {
        use crate::header_custom::{CustomItem, HeaderCustomUdpConfig};
        use std::future::poll_fn;
        let item = |packet: &[u8]| CustomItem {
            delay: (0, 0),
            rand: 0,
            rand_range: (0, 255),
            packet: packet.to_vec(),
            capture: String::new(),
            reuse: String::new(),
            transform: None,
        };
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap();
        let config = HysteriaCarrierConfig {
            header_custom: Some(HeaderCustomCarrier {
                config: Arc::new(HeaderCustomUdpConfig {
                    standalone: true,
                    client: vec![item(b"REQ")],
                    server: vec![item(b"ACK")],
                }),
                before_salamander: false,
                before_noise: false,
            }),
            ..Default::default()
        };
        let session = CarrierSession::new(&config).unwrap();
        let open = || {
            let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
            raw.set_nonblocking(true).unwrap();
            wrap(raw, addr, addr, &config, &session).unwrap()
        };
        let send = |socket: &Arc<dyn AsyncUdpSocket>, contents: &[u8]| {
            socket.try_send(&udp::Transmit {
                destination: addr,
                ecn: None,
                contents,
                segment_size: None,
                src_ip: None,
            })
        };
        let mut bytes = [0; 64];
        let first = open();
        let mut poller = first.clone().create_io_poller();
        poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        assert!(send(&first, b"one").is_err());
        let (n, from) = peer.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], b"REQ");
        peer.send_to(b"ACK", from).await.unwrap();
        let mut buffer = vec![0; 2048];
        let mut meta = [udp::RecvMeta::default()];
        poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buffer)];
            first.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await
        .unwrap();
        assert_eq!(meta[0].len, 0);
        // A new socket of the same connection sends at once.
        let rebound = open();
        let mut poller = rebound.clone().create_io_poller();
        poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        send(&rebound, b"two").unwrap();
        let (n, _) = peer.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], b"two");
    }

    #[test]
    fn header_custom_ranks_against_noise_and_salamander() {
        use crate::header_custom::HeaderCustomUdpConfig;
        use crate::udp_noise::{NoiseRange, UdpNoiseConfig};
        let noise = |before_salamander| UdpNoiseConfig {
            items: vec![],
            reset_secs: NoiseRange { from: 0, to: 0 },
            before_salamander,
        };
        let header = |before_salamander, before_noise| HeaderCustomCarrier {
            config: Arc::new(HeaderCustomUdpConfig::default()),
            before_salamander,
            before_noise,
        };
        let order = |salamander: bool, noise: Option<UdpNoiseConfig>, header| {
            HysteriaCarrierConfig {
                salamander_password: salamander
                    .then(|| Arc::new(Zeroizing::new("synthetic".into()))),
                noise,
                header_custom: Some(header),
                ..Default::default()
            }
            .mask_order()
        };
        use Mask::{Header as H, Noise as N, Salamander as S};
        assert_eq!(
            order(false, Some(noise(false)), header(false, true)),
            [H, N]
        );
        assert_eq!(
            order(false, Some(noise(false)), header(false, false)),
            [N, H]
        );
        assert_eq!(
            order(true, Some(noise(true)), header(false, false)),
            [N, S, H]
        );
        assert_eq!(
            order(true, Some(noise(false)), header(true, true)),
            [H, S, N]
        );
        assert_eq!(
            order(true, Some(noise(true)), header(true, true)),
            [H, N, S]
        );
        assert_eq!(
            order(true, Some(noise(true)), header(true, false)),
            [N, H, S]
        );
        assert_eq!(order(true, None, header(true, false)), [H, S]);
        // A custom header under udphop is refused.
        let mut config = HysteriaCarrierConfig {
            header_custom: Some(header(false, false)),
            ..Default::default()
        };
        config.validate().unwrap();
        config.udp_hop.ports = vec![443, 8443];
        config.udp_hop.local = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn xdns_runs_without_udphop_and_sudoku_and_needs_its_client() {
        let xdns = Arc::new(crate::xdns::XdnsConfig {
            domains: vec![crate::xdns::XdnsDomain {
                name: "t.example.com".into(),
                len_limit: 255,
                label_limit: 63,
                types: vec![],
                edns0: 0,
            }],
            resolvers: vec![crate::xdns::XdnsResolver::Udp(vec!["127.0.0.1:53"
                .parse()
                .unwrap()])],
            extra_poll: 0,
        });
        let mut config = HysteriaCarrierConfig {
            xdns: Some(xdns.clone()),
            ..Default::default()
        };
        assert!(config.enabled());
        config.validate().unwrap();
        config.udp_hop.ports = vec![443, 8443];
        config.udp_hop.local = true;
        assert!(config.validate().is_err(), "udphop");
        config.udp_hop = Default::default();
        config.sudoku = Some(SudokuCarrier {
            config: Arc::new(crate::sudoku::SudokuConfig {
                password: "synthetic".into(),
                ..Default::default()
            }),
            before_salamander: false,
            before_noise: false,
            before_header_custom: false,
        });
        assert!(config.validate().is_err(), "sudoku");
        config.sudoku = None;
        config.xdns = Some(Arc::new(crate::xdns::XdnsConfig {
            resolvers: vec![],
            ..(*xdns).clone()
        }));
        assert!(config.validate().is_err(), "no resolver");
        // The session opens the client; without it the socket is refused.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        config.xdns = Some(xdns);
        let session = CarrierSession::new(&config).unwrap();
        assert!(wrap(socket, peer, peer, &config, &session).is_err());
    }

    #[test]
    fn xicmp_runs_without_udphop_xdns_realm_header_custom_and_sudoku() {
        let xicmp = Arc::new(crate::xicmp::XicmpConfig {
            dgram: true,
            ips: vec![],
        });
        let mut config = HysteriaCarrierConfig {
            xicmp: Some(xicmp),
            ..Default::default()
        };
        assert!(config.enabled());
        config.validate().unwrap();
        config.udp_hop.ports = vec![443, 8443];
        config.udp_hop.local = true;
        assert!(config.validate().is_err(), "udphop");
        config.udp_hop = Default::default();
        config.xdns = Some(Arc::new(crate::xdns::XdnsConfig::default()));
        assert!(config.validate().is_err(), "xdns");
        config.xdns = None;
        config.realm = Some(Arc::new(crate::realm::RealmConfig {
            scheme: crate::realm::RealmScheme::Http,
            host: "127.0.0.1".into(),
            port_text: "80".into(),
            port: 80,
            token: Arc::new(Zeroizing::new("t".into())),
            id: "x".into(),
            stun_servers: vec![crate::realm::RealmStunServer {
                host: "127.0.0.1".into(),
                port_text: "3478".into(),
                port: 3478,
            }],
            tls: None,
            family: crate::realm::RealmFamily::Dual,
        }));
        assert!(config.validate().is_err(), "realm");
        config.realm = None;
        config.header_custom = Some(HeaderCustomCarrier {
            config: Arc::new(HeaderCustomUdpConfig::default()),
            before_salamander: false,
            before_noise: false,
        });
        assert!(config.validate().is_err(), "header-custom");
        config.header_custom = None;
        config.sudoku = Some(SudokuCarrier {
            config: Arc::new(crate::sudoku::SudokuConfig {
                password: "synthetic".into(),
                ..Default::default()
            }),
            before_salamander: false,
            before_noise: false,
            before_header_custom: false,
        });
        assert!(config.validate().is_err(), "sudoku");
        config.sudoku = None;
        config.salamander_password = Some(Arc::new(Zeroizing::new("synthetic".into())));
        config.validate().unwrap();
        // The session opens the client; without it the socket is refused.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let session = CarrierSession::new(&config).unwrap();
        assert!(wrap(socket, peer, peer, &config, &session).is_err());
    }

    #[test]
    fn realm_runs_without_udphop_xdns_and_header_custom() {
        let realm = Arc::new(crate::realm::RealmConfig {
            scheme: crate::realm::RealmScheme::Http,
            host: "127.0.0.1".into(),
            port_text: "80".into(),
            port: 80,
            token: Arc::new(Zeroizing::new("t".into())),
            id: "x".into(),
            stun_servers: vec![crate::realm::RealmStunServer {
                host: "127.0.0.1".into(),
                port_text: "3478".into(),
                port: 3478,
            }],
            tls: None,
            family: crate::realm::RealmFamily::Dual,
        });
        let mut config = HysteriaCarrierConfig {
            realm: Some(realm.clone()),
            ..Default::default()
        };
        assert!(config.enabled());
        config.validate().unwrap();
        config.udp_hop.ports = vec![443, 8443];
        config.udp_hop.local = true;
        assert!(config.validate().is_err(), "udphop");
        config.udp_hop = Default::default();
        config.header_custom = Some(HeaderCustomCarrier {
            config: Arc::new(HeaderCustomUdpConfig::default()),
            before_salamander: false,
            before_noise: false,
        });
        assert!(config.validate().is_err(), "header-custom");
        config.header_custom = None;
        config.xdns = Some(Arc::new(crate::xdns::XdnsConfig::default()));
        assert!(config.validate().is_err(), "xdns");
        config.xdns = None;
        // HTTPS needs its TLS settings.
        config.realm = Some(Arc::new(crate::realm::RealmConfig {
            scheme: crate::realm::RealmScheme::Https,
            ..(*realm).clone()
        }));
        assert!(config.validate().is_err(), "HTTPS without TLS");
        config.salamander_password = Some(Arc::new(Zeroizing::new("synthetic".into())));
        config.realm = Some(realm);
        config.validate().unwrap();
    }

    #[test]
    fn sudoku_ranks_against_every_other_mask() {
        use crate::header_custom::HeaderCustomUdpConfig;
        use crate::udp_noise::{NoiseRange, UdpNoiseConfig};
        use Mask::{Header as H, Noise as N, Salamander as S, Sudoku as K};
        // Each position of a list as Xray-core reads it, from the innermost.
        let lists: [&[Mask]; 6] = [
            &[K, S],
            &[S, K],
            &[K, N, H, S],
            &[N, S, K, H],
            &[H, K, S, N],
            &[S, H, N, K],
        ];
        for list in lists {
            let at = |mask| list.iter().position(|&m| m == mask);
            let before = |first, second| at(first).zip(at(second)).is_some_and(|(a, b)| a < b);
            let config = HysteriaCarrierConfig {
                salamander_password: at(S).map(|_| Arc::new(Zeroizing::new("synthetic".into()))),
                noise: at(N).map(|_| UdpNoiseConfig {
                    items: vec![],
                    reset_secs: NoiseRange { from: 0, to: 0 },
                    before_salamander: before(N, S),
                }),
                header_custom: at(H).map(|_| HeaderCustomCarrier {
                    config: Arc::new(HeaderCustomUdpConfig::default()),
                    before_salamander: before(H, S),
                    before_noise: before(H, N),
                }),
                sudoku: at(K).map(|_| SudokuCarrier {
                    config: Arc::new(crate::sudoku::SudokuConfig::default()),
                    before_salamander: before(K, S),
                    before_noise: before(K, N),
                    before_header_custom: before(K, H),
                }),
                ..Default::default()
            };
            assert_eq!(config.mask_order(), list, "{list:?}");
        }
        // An unbuildable table is refused.
        let config = HysteriaCarrierConfig {
            sudoku: Some(SudokuCarrier {
                config: Arc::new(crate::sudoku::SudokuConfig {
                    ascii: "text".into(),
                    ..Default::default()
                }),
                before_salamander: false,
                before_noise: false,
                before_header_custom: false,
            }),
            ..Default::default()
        };
        assert!(config.enabled());
        assert!(config.validate().is_err());
    }

    /// Sudoku outside Salamander: the wire carries sudoku, Salamander
    /// inside it, and the reply comes back through both.
    #[tokio::test]
    async fn the_carrier_puts_sudoku_at_its_place_and_lets_it_fragment() {
        use crate::sudoku::{datagram::DatagramMask, SudokuConfig};
        use std::future::poll_fn;
        const PASSWORD: &str = "synthetic-password";
        let sudoku = SudokuConfig {
            password: "synthetic-sudoku".into(),
            ..Default::default()
        };
        let mask = DatagramMask::new(&sudoku).unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire_peer = peer.local_addr().unwrap();
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        local.set_nonblocking(true).unwrap();
        // A clone shows the socket's options after the carrier took it.
        let probe = local.try_clone().unwrap();
        let config = HysteriaCarrierConfig {
            salamander_password: Some(Arc::new(Zeroizing::new(PASSWORD.into()))),
            sudoku: Some(SudokuCarrier {
                config: Arc::new(sudoku),
                before_salamander: false,
                before_noise: false,
                before_header_custom: false,
            }),
            ..Default::default()
        };
        config.validate().unwrap();
        let client = wrap(
            local,
            wire_peer,
            wire_peer,
            &config,
            &CarrierSession::default(),
        )
        .unwrap();
        assert!(client.may_fragment());
        assert_eq!(client.max_transmit_segments(), 1);
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        ))]
        {
            use std::os::fd::AsRawFd;
            let [(level, name, allowed), _] = crate::sudoku::quic::FRAGMENTATION;
            let value = crate::socket_options::sys::get_int(probe.as_raw_fd(), level, name);
            assert_eq!(value.unwrap(), allowed, "the system may fragment");
        }
        drop(probe);
        let packet = vec![0x5a; 1200];
        let transmit = udp::Transmit {
            destination: wire_peer,
            ecn: None,
            contents: &packet,
            segment_size: None,
            src_ip: None,
        };
        let mut poller = client.clone().create_io_poller();
        loop {
            match client.try_send(&transmit) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    poll_fn(|cx| poller.as_mut().poll_writable(cx))
                        .await
                        .unwrap()
                }
                Err(e) => panic!("{e}"),
            }
        }
        let mut wire = vec![0; 65_536];
        let (n, from) = peer.recv_from(&mut wire).await.unwrap();
        assert!(n >= (packet.len() + SALT_LEN) * 4, "{n}");
        let inner = mask.decode(&mut wire, 0..n).unwrap();
        assert_eq!(salamander_plaintext(PASSWORD, &wire[inner]), packet);

        let reply = mask.encode(&salamander_datagram(PASSWORD, b"reply"));
        peer.send_to(&reply, from).await.unwrap();
        let mut output = vec![0; 1472];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [udp::RecvMeta::default()];
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| client.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&output[..meta[0].len], b"reply");
    }

    #[test]
    fn hop_bounds_defaults_and_secret_redaction() {
        let mut config = HysteriaCarrierConfig::default();
        assert!(!config.enabled());
        assert_eq!(config.next_interval(), None);
        config.salamander_password = Some(Arc::new(Zeroizing::new("secret-synthetic".into())));
        assert!(!format!("{config:?}").contains("secret-synthetic"));
        config.udp_hop.ports = vec![443, 8443];
        config.udp_hop.local = true;
        config.udp_hop.remote = true;
        config.validate().unwrap();
        assert_eq!(config.next_interval(), Some(Duration::from_secs(30)));
        config.udp_hop.interval_min = Duration::from_secs(4);
        assert!(config.validate().is_err());
        config.udp_hop.interval_min = Duration::from_secs(31);
        assert!(config.validate().is_err());
        config.udp_hop.interval_max = Duration::from_secs(60);
        config.validate().unwrap();
        for _ in 0..100 {
            assert!((Duration::from_secs(31)..=Duration::from_secs(60))
                .contains(&config.next_interval().unwrap()));
            assert!(config
                .udp_hop
                .ports
                .contains(&config.next_peer("127.0.0.1:1000".parse().unwrap()).port()));
        }
        config.udp_hop.ports.push(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn gecko_requires_salamander_and_bounded_sizes() {
        let mut config = HysteriaCarrierConfig {
            gecko: GeckoPacketSize::new(512, 1200),
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.salamander_password = Some(Arc::new(Zeroizing::new("synthetic".into())));
        config.validate().unwrap();
        assert!(format!("{config:?}").contains("min: 512, max: 1200"));
        for (min, max) in [(0, 10), (20, 10), (1, 2049)] {
            config.gecko = Some(GeckoPacketSize { min, max });
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn scheduled_hops_always_leave_the_current_port() {
        let logical: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let at = |port: u16| SocketAddr::new(logical.ip(), port);
        let mut config = HysteriaCarrierConfig::default();
        config.udp_hop.remote = true;
        config.udp_hop.ports = vec![443, 8443];
        // With two ports Xray's draw with replacement stays put half the time.
        let mut current = at(443);
        for _ in 0..100 {
            let next = config.next_hop_peer(logical, current);
            assert_eq!(next.ip(), logical.ip());
            assert_ne!(next.port(), current.port());
            current = next;
        }
        // Duplicates do not count as a different port.
        config.udp_hop.ports = vec![443, 443, 8443];
        assert_eq!(config.next_hop_peer(logical, at(443)).port(), 8443);
        // Every other port is reachable.
        config.udp_hop.ports = (1000..1010).collect();
        let seen: std::collections::HashSet<u16> = (0..1000)
            .map(|_| config.next_hop_peer(logical, at(1000)).port())
            .collect();
        assert_eq!(seen, (1001..1010).collect());
        // A single distinct port has nowhere else to go.
        config.udp_hop.ports = vec![443, 443];
        assert_eq!(config.next_hop_peer(logical, at(443)).port(), 443);
    }

    /// Each mode changes only what Xray's changes: `intervalLocal` alone keeps
    /// the server's address and hops on a timer, `perConnRemote` draws the
    /// first address and never hops, `intervalRemote` does both.
    #[test]
    fn modes_choose_the_first_address_and_the_timer() {
        let logical: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let mut config = HysteriaCarrierConfig::default();
        config.udp_hop.ports = vec![8443, 8444];
        assert!(!config.udp_hop.is_active());
        assert!(!config.enabled());

        config.udp_hop.local = true;
        assert!(config.enabled());
        assert_eq!(config.next_peer(logical), logical);
        assert!(config.next_interval().is_some());
        let current = config.next_peer(logical);
        assert_eq!(config.next_hop_peer(logical, current), logical);

        config.udp_hop.local = false;
        config.udp_hop.remote_once = true;
        assert!(config.enabled());
        assert_eq!(config.next_interval(), None);
        let first = config.next_peer(logical);
        assert!([8443, 8444].contains(&first.port()));
        assert_eq!(config.next_hop_peer(logical, first), first);

        config.udp_hop.remote_once = false;
        config.udp_hop.remote = true;
        assert!(config.next_interval().is_some());
        assert!([8443, 8444].contains(&config.next_peer(logical).port()));
        assert_eq!(
            config.next_hop_peer(logical, first).port(),
            8443 + 8444 - first.port()
        );
    }

    /// `remoteIPs` gives the IP of a random address within a prefix of the
    /// server's family; one of the other family is never drawn.
    #[test]
    fn remote_ips_draw_within_prefixes_of_the_servers_family() {
        let logical: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let mut config = HysteriaCarrierConfig::default();
        config.udp_hop.remote = true;
        config.udp_hop.remote_ips = vec![
            ("198.51.100.0".parse().unwrap(), 30),
            ("203.0.113.9".parse().unwrap(), 32),
            ("2001:db8::".parse().unwrap(), 64),
        ];
        config.validate().unwrap();
        let seen: std::collections::HashSet<IpAddr> =
            (0..2000).map(|_| config.next_peer(logical).ip()).collect();
        let expected: std::collections::HashSet<IpAddr> = [
            "198.51.100.0",
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
            "203.0.113.9",
        ]
        .iter()
        .map(|ip| ip.parse().unwrap())
        .collect();
        assert_eq!(seen, expected);
        // The port stays without ports to draw from.
        assert!((0..100).all(|_| config.next_hop_peer(logical, logical).port() == 443));
        // A server of the other family keeps its own IP.
        let v6: SocketAddr = "[2001:db8:1::1]:443".parse().unwrap();
        config.udp_hop.remote_ips.retain(|(ip, _)| ip.is_ipv4());
        assert_eq!(config.next_peer(v6), v6);
        // An impossible prefix length is refused.
        config.udp_hop.remote_ips = vec![("192.0.2.0".parse().unwrap(), 33)];
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn wire_overhead_receive_capacity_and_wrong_peer() {
        use std::future::poll_fn;
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire_peer = peer.local_addr().unwrap();
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        local.set_nonblocking(true).unwrap();
        let logical = "127.0.0.1:1".parse().unwrap();
        let config = HysteriaCarrierConfig {
            salamander_password: Some(Arc::new(Zeroizing::new("synthetic-password".into()))),
            ..Default::default()
        };
        let client = wrap(
            local,
            logical,
            wire_peer,
            &config,
            &CarrierSession::default(),
        )
        .unwrap();
        assert_eq!(client.max_transmit_segments(), 1);
        let input = vec![0xa5; 1472];
        let mut wire = vec![0; input.len() + SALT_LEN];
        encode("synthetic-password", [7; 8], &input, &mut wire);
        let mut destination = client.local_addr().unwrap();
        destination.set_ip(wire_peer.ip());
        peer.send_to(&wire, destination).await.unwrap();
        let mut output = vec![0; input.len()];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [udp::RecvMeta::default()];
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| client.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(meta[0].addr, logical);
        assert_eq!(meta[0].len, input.len());
        assert_eq!(output, input);
    }

    fn salamander_datagram(password: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut wire = vec![0; plaintext.len() + SALT_LEN];
        let mut salt = [0; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        encode(password, salt, plaintext, &mut wire);
        wire
    }

    fn salamander_plaintext(password: &str, wire: &[u8]) -> Vec<u8> {
        let mut bytes = wire.to_vec();
        let mut meta = udp::RecvMeta {
            len: bytes.len(),
            stride: bytes.len(),
            ..Default::default()
        };
        decode(password, &mut bytes, &mut meta);
        bytes.truncate(meta.len);
        bytes
    }

    #[tokio::test]
    async fn gecko_fragments_long_headers_and_reassembles_replies() {
        use std::future::poll_fn;
        const PASSWORD: &str = "synthetic-password";
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire_peer = peer.local_addr().unwrap();
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        local.set_nonblocking(true).unwrap();
        let logical: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let size = GeckoPacketSize::new(200, 400).unwrap();
        let config = HysteriaCarrierConfig {
            salamander_password: Some(Arc::new(Zeroizing::new(PASSWORD.into()))),
            gecko: Some(size),
            ..Default::default()
        };
        config.validate().unwrap();
        let client = wrap(
            local,
            logical,
            wire_peer,
            &config,
            &CarrierSession::default(),
        )
        .unwrap();
        assert_eq!(client.max_transmit_segments(), 1);
        let mut poller = client.clone().create_io_poller();
        let mut long = vec![0xc3; 1200];
        rand::thread_rng().fill_bytes(&mut long[1..]);
        let short: Vec<u8> = std::iter::once(0x43).chain(1..=99).collect();
        for contents in [long.as_slice(), &short] {
            let transmit = udp::Transmit {
                destination: logical,
                ecn: None,
                contents,
                segment_size: None,
                src_ip: None,
            };
            loop {
                match client.try_send(&transmit) {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        poll_fn(|cx| poller.as_mut().poll_writable(cx))
                            .await
                            .unwrap()
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        }
        let receive = || async {
            let mut bytes = [0; 2048];
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            (bytes[..n].to_vec(), from)
        };
        // The long header leaves as two to eight Salamander datagrams, each
        // with its own salt, padded into packetSize when its chunk allows.
        let (first, client_address) = receive().await;
        let chunks = usize::from(salamander_plaintext(PASSWORD, &first)[2] & 0x0f);
        assert!((2..=8).contains(&chunks));
        let mut wires = vec![first];
        for _ in 1..chunks {
            wires.push(receive().await.0);
        }
        let mut reassembly = Reassembly::default();
        let mut message = None;
        for (index, wire) in wires.iter().enumerate() {
            let plaintext = salamander_plaintext(PASSWORD, wire);
            let frame = gecko::parse_frame(&plaintext).unwrap();
            let chunk = if index + 1 < chunks {
                1200 / chunks
            } else {
                1200 - (chunks - 1) * (1200 / chunks)
            };
            let unpadded = SALT_LEN + 5 + chunk;
            if unpadded > 400 {
                assert_eq!(wire.len(), unpadded);
            } else {
                assert!((200..=400).contains(&wire.len()), "{}", wire.len());
            }
            message = reassembly.accept(Instant::now(), frame).or(message);
        }
        assert_eq!(message.unwrap(), long);
        assert_ne!(wires[0][..SALT_LEN], wires[1][..SALT_LEN]);
        // A short header travels as one ordinary Salamander datagram.
        let (wire, _) = receive().await;
        assert_eq!(wire.len(), short.len() + SALT_LEN);
        assert_eq!(salamander_plaintext(PASSWORD, &wire), short);

        // Replies: fragments out of order around a short header, plus a
        // malformed frame, come back as the two datagrams.
        let mut reply = vec![0xe0; 300];
        rand::thread_rng().fill_bytes(&mut reply[1..]);
        let mut frames = gecko::fragment(&reply, 77, size, &mut rand::thread_rng());
        frames.rotate_right(1);
        let mut sequence = vec![salamander_datagram(PASSWORD, &frames[0])];
        sequence.push(salamander_datagram(PASSWORD, &short));
        sequence.push(salamander_datagram(PASSWORD, &[0x80, 1, 0x09, 0, 0]));
        sequence.extend(frames[1..].iter().map(|f| salamander_datagram(PASSWORD, f)));
        for datagram in &sequence {
            peer.send_to(datagram, client_address).await.unwrap();
        }
        let mut storage = [[0u8; 1500]; 4];
        let mut delivered = Vec::new();
        let mut reads = 0;
        while delivered.len() < 2 {
            let [a, b, c, d] = &mut storage;
            let mut bufs = [a, b, c, d].map(|b| IoSliceMut::new(b));
            let mut meta = [udp::RecvMeta::default(); 4];
            let count = tokio::time::timeout(
                Duration::from_secs(2),
                poll_fn(|cx| client.poll_recv(cx, &mut bufs, &mut meta)),
            )
            .await
            .unwrap()
            .unwrap();
            reads += 1;
            for (buffer, meta) in bufs.iter().zip(&meta).take(count) {
                if meta.len > 0 {
                    assert_eq!(meta.addr, logical);
                    assert_eq!(meta.stride, meta.len);
                    delivered.push(buffer[..meta.len].to_vec());
                }
            }
        }
        assert_eq!(delivered, [short.clone(), reply]);
        assert_eq!(reads, sequence.len());
    }

    #[test]
    fn gecko_delivery_splits_gro_reads_and_spans_polls() {
        let state = GeckoState::new(GeckoPacketSize::new(100, 200).unwrap());
        let source: SocketAddr = "192.0.2.7:443".parse().unwrap();
        let read = |len| udp::RecvMeta {
            addr: source,
            len,
            stride: 40,
            ecn: Some(udp::EcnCodepoint::Ce),
            dst_ip: None,
        };
        // A read of short headers alone stays on the ordinary path.
        assert!(!state.absorb(&[0x41; 70], &read(70)));
        // A GRO read with frames: short header, both halves of message 5
        // (the second with one padding byte), and a shorter last datagram.
        let mut decoded = vec![0x41; 40];
        decoded.extend_from_slice(&[0x80, 5, 0x02, 0, 0]);
        decoded.extend_from_slice(&[b'a'; 35]);
        decoded.extend_from_slice(&[0x80, 5, 0x12, 0, 1, 0xff]);
        decoded.extend_from_slice(&[b'b'; 34]);
        decoded.extend_from_slice(&[0x42; 10]);
        assert!(state.absorb(&decoded, &read(decoded.len())));
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let mut meta = [udp::RecvMeta::default(); 2];
        assert_eq!(state.deliver(&mut bufs, &mut meta), Some(2));
        assert_eq!(
            (meta[0].addr, meta[0].len, meta[0].stride),
            (source, 40, 40)
        );
        assert_eq!(meta[0].ecn, None);
        assert_eq!(&bufs[0][..40], &[0x41; 40]);
        // The 69-byte message does not fit a 64-byte buffer and is dropped.
        assert_eq!(meta[1].len, 0);
        // The rest waits for the next poll, ahead of any new read.
        assert_eq!(state.deliver(&mut bufs, &mut meta), Some(1));
        assert_eq!((meta[0].len, meta[0].stride), (10, 10));
        assert_eq!(&bufs[0][..10], &[0x42; 10]);
        assert_eq!(state.deliver(&mut bufs, &mut meta), None);
        // A message that fits is delivered whole.
        let mut message = vec![0x80, 6, 0x02, 0, 0];
        message.extend_from_slice(&[b'c'; 35]);
        message.extend_from_slice(&[0x80, 6, 0x12, 0, 0, b'd']);
        assert!(state.absorb(&message, &read(message.len())));
        assert_eq!(state.deliver(&mut bufs, &mut meta), Some(1));
        assert_eq!(
            &bufs[0][..meta[0].len],
            [[b'c'; 35].as_slice(), b"d"].concat()
        );
    }
}
