use crate::Error;
use std::net::{IpAddr, SocketAddr};
use xray_proxy::wireguard::{AllowedIp, KeyMaterial};

/// One device with 1..8 peers and at most one local address per IP family.
/// PSK is optional; reserved-byte extensions are unsupported.
#[derive(Clone, Debug)]
pub struct Config {
    pub secret_key: KeyMaterial,
    pub peers: Vec<PeerConfig>,
    pub addresses: Vec<IpAddr>,
    pub mtu: u16,
}
#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub public_key: KeyMaterial,
    pub preshared_key: Option<KeyMaterial>,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<AllowedIp>,
    pub keepalive: u16,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if !(1280..=1420).contains(&self.mtu)
            || self.addresses.is_empty()
            || self.addresses.len() > 2
            || self.addresses.iter().any(|ip| !usable_ip(*ip))
            || self.addresses.iter().filter(|ip| ip.is_ipv4()).count() > 1
            || self.addresses.iter().filter(|ip| ip.is_ipv6()).count() > 1
            || self.peers.is_empty()
            || self.peers.len() > 8
            || self
                .peers
                .iter()
                .map(|p| p.allowed_ips.len())
                .sum::<usize>()
                > 256
        {
            return Err(Error::Configuration);
        }
        let secret = x25519_dalek::StaticSecret::from(*self.secret_key.expose_bytes());
        for (index, peer) in self.peers.iter().enumerate() {
            let public = x25519_dalek::PublicKey::from(*peer.public_key.expose_bytes());
            if peer.endpoint.port() == 0
                || !usable_ip(peer.endpoint.ip())
                || scoped(peer.endpoint)
                || peer.allowed_ips.is_empty()
                || self.peers[..index]
                    .iter()
                    .any(|p| p.public_key == peer.public_key)
                || !secret.diffie_hellman(&public).was_contributory()
                || public == x25519_dalek::PublicKey::from(&secret)
            {
                return Err(Error::Configuration);
            }
        }
        Ok(())
    }
}

/// How many TCP flows one stack carries at once, how many more may wait for a
/// place, and how much each one buffers.
///
/// Each admitted TCP flow owns a receive and a send buffer of
/// [`Self::tcp_buffer`] bytes for as long as it is open, idle or not, and a
/// long transfer touches all of it, so the admitted flows' buffers are bounded
/// by `2 × tcp × tcp_buffer`. A flow past [`Self::tcp`] waits, in arrival
/// order, for an earlier one to close, for at most the ten-second open
/// deadline; giving up its wait leaves the queue at once. One that would make
/// more than [`Self::tcp_waiting`] waiters is refused at once with
/// [`Error::Busy`], and so is one whose wait runs out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowLimits {
    tcp: usize,
    tcp_waiting: usize,
    tcp_buffer: usize,
}
impl FlowLimits {
    /// The most TCP flows a stack takes at once.
    pub const MAX_TCP: usize = 1024;
    /// The most TCP flows that may wait for a place.
    pub const MAX_TCP_WAITING: usize = 4096;
    /// The smallest TCP buffer: a flow advertises a 64 KiB window when it
    /// opens and needs room for more.
    pub const MIN_TCP_BUFFER: usize = 128 * 1024;
    /// The largest TCP buffer: the stack shares 1 MiB of receive and of send
    /// credit among its flows, so a larger buffer would never fill.
    pub const MAX_TCP_BUFFER: usize = 1024 * 1024;

    /// 32 TCP flows of 256 KiB each way, 16 MiB in all; 64 may wait.
    pub const LOW_MEMORY: Self = Self {
        tcp: 32,
        tcp_waiting: 64,
        tcp_buffer: 256 * 1024,
    };
    /// 64 TCP flows of 256 KiB each way: 32 MiB in all, what 16 flows of
    /// 1 MiB took before; 128 may wait. A phone browser opens more than 16
    /// connections for one page and keeps them open while idle.
    pub const MOBILE: Self = Self {
        tcp: 64,
        tcp_waiting: 128,
        tcp_buffer: 256 * 1024,
    };
    /// 128 TCP flows of 1 MiB each way, 256 MiB in all; 256 may wait.
    pub const DESKTOP: Self = Self {
        tcp: 128,
        tcp_waiting: 256,
        tcp_buffer: 1024 * 1024,
    };

    /// Limits of a host's choosing, within [`Self::MAX_TCP`],
    /// [`Self::MAX_TCP_WAITING`] and [`Self::MIN_TCP_BUFFER`]..=[`Self::MAX_TCP_BUFFER`].
    pub fn new(tcp: usize, tcp_waiting: usize, tcp_buffer: usize) -> Result<Self, Error> {
        if !(1..=Self::MAX_TCP).contains(&tcp)
            || tcp_waiting > Self::MAX_TCP_WAITING
            || !(Self::MIN_TCP_BUFFER..=Self::MAX_TCP_BUFFER).contains(&tcp_buffer)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            tcp,
            tcp_waiting,
            tcp_buffer,
        })
    }
    pub fn tcp(self) -> usize {
        self.tcp
    }
    pub fn tcp_waiting(self) -> usize {
        self.tcp_waiting
    }
    pub fn tcp_buffer(self) -> usize {
        self.tcp_buffer
    }
}
/// [`FlowLimits::MOBILE`] on Android and Apple's mobile systems,
/// [`FlowLimits::DESKTOP`] elsewhere.
impl Default for FlowLimits {
    fn default() -> Self {
        if cfg!(any(
            target_os = "android",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos"
        )) {
            Self::MOBILE
        } else {
            Self::DESKTOP
        }
    }
}

pub(crate) fn scoped(addr: SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
}
pub(crate) fn usable_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(v4) => v4 != std::net::Ipv4Addr::BROADCAST,
            IpAddr::V6(v6) => !v6.is_unicast_link_local() && v6.to_ipv4_mapped().is_none(),
        }
}
