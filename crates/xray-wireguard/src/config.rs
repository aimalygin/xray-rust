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
    pub(crate) fn local_for(&self, remote: SocketAddr) -> Result<IpAddr, Error> {
        if remote.port() == 0
            || !usable_ip(remote.ip())
            || scoped(remote)
            || !self
                .peers
                .iter()
                .flat_map(|p| &p.allowed_ips)
                .any(|p| p.contains(remote.ip()))
        {
            return Err(Error::NoRoute);
        }
        self.addresses
            .iter()
            .copied()
            .find(|ip| ip.is_ipv4() == remote.is_ipv4())
            .ok_or(Error::NoRoute)
    }
}
fn scoped(addr: SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
}
fn usable_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(v4) => v4 != std::net::Ipv4Addr::BROADCAST,
            IpAddr::V6(v6) => !v6.is_unicast_link_local() && v6.to_ipv4_mapped().is_none(),
        }
}
