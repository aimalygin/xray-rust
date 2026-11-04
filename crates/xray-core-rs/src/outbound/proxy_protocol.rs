//! Freedom's `proxyProtocol` header, as go-proxyproto v0.16.0's
//! `HeaderProxyFromAddrs` builds it for Xray-core v26.10.31.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use xray_config::ProxyProtocolVersion;
use xray_routing::Network;

/// Who a freedom connection is for, as Xray-core's `inbound.Source` records
/// it: the client's address and the network it reached the inbound over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InboundSource {
    pub(crate) addr: SocketAddr,
    pub(crate) network: Network,
}

impl InboundSource {
    pub(crate) fn tcp(addr: SocketAddr) -> Self {
        Self {
            addr,
            network: Network::Tcp,
        }
    }

    pub(crate) fn udp(addr: SocketAddr) -> Self {
        Self {
            addr,
            network: Network::Udp,
        }
    }
}

const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// The header for a `network` connection from `source` to `destination`.
///
/// A source of another network, or none, makes go-proxyproto's unspecified
/// header: `PROXY UNKNOWN` in version 1, `LOCAL` in version 2. The family is
/// IPv4 only when both ends are, IPv4-mapped addresses included; otherwise an
/// IPv4 end is written mapped into IPv6.
pub(crate) fn header(
    version: ProxyProtocolVersion,
    source: Option<InboundSource>,
    network: Network,
    destination: SocketAddr,
) -> Vec<u8> {
    let source = source
        .filter(|source| source.network == network)
        .map(|source| source.addr);
    match version {
        ProxyProtocolVersion::V1 => version_1(source, network, destination),
        ProxyProtocolVersion::V2 => version_2(source, network, destination),
    }
}

fn version_1(source: Option<SocketAddr>, network: Network, destination: SocketAddr) -> Vec<u8> {
    // Version 1 names only TCP over IPv4 and IPv6.
    let Some(source) = source.filter(|_| network == Network::Tcp) else {
        return b"PROXY UNKNOWN\r\n".to_vec();
    };
    let (protocol, source_ip, destination_ip) = match (ipv4(source.ip()), ipv4(destination.ip())) {
        (Some(source_ip), Some(destination_ip)) => {
            ("TCP4", source_ip.to_string(), destination_ip.to_string())
        }
        _ => (
            "TCP6",
            ipv6(source.ip()).to_string(),
            ipv6(destination.ip()).to_string(),
        ),
    };
    format!(
        "PROXY {protocol} {source_ip} {destination_ip} {} {}\r\n",
        source.port(),
        destination.port()
    )
    .into_bytes()
}

fn version_2(source: Option<SocketAddr>, network: Network, destination: SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(V2_SIGNATURE.len() + 4 + 36);
    header.extend_from_slice(&V2_SIGNATURE);
    let Some(source) = source else {
        // LOCAL, unspecified family, no addresses.
        header.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        return header;
    };
    let transport = match network {
        Network::Tcp => 0x1,
        Network::Udp => 0x2,
    };
    header.push(0x21);
    match (ipv4(source.ip()), ipv4(destination.ip())) {
        (Some(source_ip), Some(destination_ip)) => {
            header.push(0x10 | transport);
            header.extend_from_slice(&12_u16.to_be_bytes());
            header.extend_from_slice(&source_ip.octets());
            header.extend_from_slice(&destination_ip.octets());
        }
        _ => {
            header.push(0x20 | transport);
            header.extend_from_slice(&36_u16.to_be_bytes());
            header.extend_from_slice(&ipv6(source.ip()).octets());
            header.extend_from_slice(&ipv6(destination.ip()).octets());
        }
    }
    header.extend_from_slice(&source.port().to_be_bytes());
    header.extend_from_slice(&destination.port().to_be_bytes());
    header
}

/// Go's `IP.To4`: IPv4, or IPv6 that maps one.
fn ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    }
}

/// Go's `IP.To16`, IPv4 mapped into IPv6.
fn ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    }
}

#[cfg(test)]
mod tests;
