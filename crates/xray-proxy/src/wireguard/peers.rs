use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

/// Initial configuration budgets; no packet-driven peer or route insertion.
pub const MAX_PEERS: usize = 128;
pub const MAX_ALLOWED_IPS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    #[error("invalid WireGuard allowed IP prefix")]
    Prefix,
    #[error("WireGuard peer or allowed IP budget exceeded")]
    Budget,
    #[error("WireGuard route references an unknown peer")]
    Peer,
}

/// WireGuard prefixes keep IPv4 and IPv6 separate, including IPv4-mapped IPv6.
/// The general routing Cidr unmaps IPv6, so it is unsuitable for this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllowedIp {
    network: IpAddr,
    prefix_length: u8,
}

impl AllowedIp {
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, RouteError> {
        let network = match address {
            IpAddr::V4(ip) if prefix_length <= 32 => {
                IpAddr::V4((u32::from(ip) & mask32(prefix_length)).into())
            }
            IpAddr::V6(ip) if prefix_length <= 128 => {
                IpAddr::V6((u128::from(ip) & mask128(prefix_length)).into())
            }
            _ => return Err(RouteError::Prefix),
        };
        Ok(Self {
            network,
            prefix_length,
        })
    }

    pub fn network(self) -> IpAddr {
        self.network
    }
    pub fn prefix_length(self) -> u8 {
        self.prefix_length
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                u32::from(address) & mask32(self.prefix_length) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                u128::from(address) & mask128(self.prefix_length) == u128::from(network)
            }
            _ => false,
        }
    }
}

impl FromStr for AllowedIp {
    type Err = RouteError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = input.split_once('/').ok_or(RouteError::Prefix)?;
        // Avoid accepting whitespace or signs that Xray's netip parser rejects.
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RouteError::Prefix);
        }
        Self::new(
            address.parse().map_err(|_| RouteError::Prefix)?,
            prefix.parse().map_err(|_| RouteError::Prefix)?,
        )
    }
}

fn mask32(length: u8) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX << (32 - length)
    }
}
fn mask128(length: u8) -> u128 {
    if length == 0 {
        0
    } else {
        u128::MAX << (128 - length)
    }
}

/// Immutable longest-prefix lookup using the WireGuard engine's insertion rule:
/// for identical normalized prefixes, the last inserted peer owns the prefix.
/// Use the same lookup for outbound destination and authenticated inbound source.
#[derive(Debug)]
pub struct PeerRoutes {
    peer_count: usize,
    routes: Vec<(AllowedIp, usize)>,
}

impl PeerRoutes {
    pub fn new(peer_count: usize, routes: &[(AllowedIp, usize)]) -> Result<Self, RouteError> {
        if peer_count == 0 || peer_count > MAX_PEERS || routes.len() > MAX_ALLOWED_IPS {
            return Err(RouteError::Budget);
        }
        let mut unique = BTreeMap::new();
        for &(prefix, peer) in routes {
            if peer >= peer_count {
                return Err(RouteError::Peer);
            }
            unique.insert(prefix, peer);
        }
        let mut routes: Vec<_> = unique.into_iter().collect();
        routes.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.prefix_length));
        Ok(Self { peer_count, routes })
    }

    pub fn lookup(&self, destination: IpAddr) -> Option<usize> {
        self.routes
            .iter()
            .find(|(prefix, _)| prefix.contains(destination))
            .map(|(_, peer)| *peer)
    }

    /// Call only after authenticating the packet and obtaining its peer identity
    /// from the engine. An endpoint address is not an authenticated identity.
    pub fn accepts_source(&self, authenticated_peer: usize, source: IpAddr) -> bool {
        authenticated_peer < self.peer_count && self.lookup(source) == Some(authenticated_peer)
    }
}
