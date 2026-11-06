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
use crate::stream::H3UdpHopConfig;

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
}

impl fmt::Debug for HysteriaCarrierConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaCarrierConfig")
            .field("salamander", &self.salamander_password.is_some())
            .field("gecko", &self.gecko)
            .field("udp_hop", &self.udp_hop)
            .finish()
    }
}

impl HysteriaCarrierConfig {
    pub(crate) fn validate(&self) -> Result<(), HysteriaError> {
        if let Some(noise) = &self.noise {
            noise.validate().map_err(|_| HysteriaError::Configuration)?;
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
        self.salamander_password.is_some() || self.udp_hop.is_active() || self.noise.is_some()
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
    noise_state: Option<Arc<crate::udp_noise::UdpNoiseState>>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    // Socket protection has already happened, before connect or any send.
    #[cfg(target_os = "macos")]
    let inner = crate::connected_quic::wrap(socket, wire_peer)?;
    #[cfg(not(target_os = "macos"))]
    let inner = quinn::TokioRuntime.wrap_udp_socket(socket)?;
    let inner = if let Some(noise) = config.noise.as_ref().filter(|n| !n.before_salamander) {
        crate::udp_noise::wrap(inner, wire_peer, noise.clone(), noise_state.clone())?
    } else {
        inner
    };
    let wrapped: Arc<dyn AsyncUdpSocket> = Arc::new(CarrierSocket {
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
    });
    if let Some(noise) = config.noise.as_ref().filter(|n| n.before_salamander) {
        crate::udp_noise::wrap(wrapped, logical_peer, noise.clone(), noise_state)
    } else {
        Ok(wrapped)
    }
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

fn key(password: &str, salt: &[u8]) -> [u8; 32] {
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
                    }],
                    reset_secs: zero(),
                    before_salamander: before,
                }),
                ..Default::default()
            };
            let client = wrap(raw, addr, addr, &config, None).unwrap();
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
        let client = wrap(local, logical, wire_peer, &config, None).unwrap();
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
        let client = wrap(local, logical, wire_peer, &config, None).unwrap();
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
