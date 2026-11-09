//! IP packets in CONNECT-IP datagrams, as Xray-core v26.10.31's
//! `connectip/conn.go` and `connectip/icmp.go` treat them.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::capsule::{IpPrefix, IpRoute};

const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
/// The smallest link MTU of each family; a tunnel below it is unusable.
const IPV4_MIN_MTU: usize = 68;
const IPV6_MIN_MTU: usize = 1280;

/// Why a packet cannot be sent: Xray drops it and logs at debug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unsendable(pub(crate) String);

/// Readies an outgoing packet for the tunnel, as Xray's `composeDatagram`
/// does before adding the context ID: the TTL or hop limit goes down by one
/// and an IPv4 header checksum is recomputed.
pub(crate) fn prepare_outgoing(packet: &mut [u8]) -> Result<(), Unsendable> {
    let Some(&first) = packet.first() else {
        return Err(Unsendable("connect-ip: empty packet".into()));
    };
    match first >> 4 {
        4 => {
            if packet.len() < IPV4_HEADER {
                return Err(Unsendable("connect-ip: IPv4 packet too short".into()));
            }
            let header = usize::from(first & 0x0f) << 2;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header < IPV4_HEADER || header > total || total > packet.len() {
                return Err(Unsendable(format!(
                    "connect-ip: malformed IPv4 header: header length {header}, total length {total}, packet length {}",
                    packet.len()
                )));
            }
            let ttl = packet[8];
            if ttl <= 1 {
                return Err(Unsendable(format!(
                    "connect-ip: datagram TTL too small: {ttl}"
                )));
            }
            packet[8] -= 1;
            let checksum = ipv4_header_checksum(&packet[..header]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        6 => {
            if packet.len() < IPV6_HEADER {
                return Err(Unsendable("connect-ip: IPv6 packet too short".into()));
            }
            let hop_limit = packet[7];
            if hop_limit <= 1 {
                return Err(Unsendable(format!(
                    "connect-ip: datagram Hop Limit too small: {hop_limit}"
                )));
            }
            packet[7] -= 1;
        }
        version => {
            return Err(Unsendable(format!(
                "connect-ip: unknown IP versions: {version}"
            )))
        }
    }
    Ok(())
}

/// Xray's `calculateIPv4Checksum`: the header's 16-bit words but the
/// checksum's own, folded and complemented.
pub(crate) fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for (index, word) in header.chunks(2).enumerate() {
        if index == 5 {
            continue;
        }
        let high = u32::from(word[0]);
        let low = u32::from(word.get(1).copied().unwrap_or(0));
        sum += high << 8 | low;
    }
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Where an incoming packet may go: the prefixes the proxy assigned, or a
/// route this endpoint advertised, which a client never does.
#[derive(Debug, Clone, Default)]
pub(crate) struct Destinations {
    pub(crate) assigned: Vec<IpPrefix>,
    pub(crate) local_routes: Vec<IpRoute>,
    /// The addresses the peer may send from, once this endpoint assigned
    /// any; a client never does.
    pub(crate) peer: Option<Vec<IpPrefix>>,
}

/// Xray's `handleIncomingProxiedPacket`: whether a packet from the proxy may
/// be delivered.
pub(crate) fn check_incoming(packet: &[u8], allowed: &Destinations) -> Result<(), Unsendable> {
    let Some(&first) = packet.first() else {
        return Err(Unsendable("connect-ip: empty packet".into()));
    };
    let version = first >> 4;
    let (src, dst, protocol) = match version {
        4 => {
            if packet.len() < IPV4_HEADER {
                return Err(Unsendable(
                    "connect-ip: malformed datagram: too short".into(),
                ));
            }
            let src: [u8; 4] = packet[12..16].try_into().expect("length checked");
            let dst: [u8; 4] = packet[16..20].try_into().expect("length checked");
            (
                IpAddr::V4(Ipv4Addr::from(src)),
                IpAddr::V4(Ipv4Addr::from(dst)),
                packet[9],
            )
        }
        6 => {
            if packet.len() < IPV6_HEADER {
                return Err(Unsendable(
                    "connect-ip: malformed datagram: too short".into(),
                ));
            }
            let src: [u8; 16] = packet[8..24].try_into().expect("length checked");
            let dst: [u8; 16] = packet[24..40].try_into().expect("length checked");
            (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                packet[6],
            )
        }
        version => {
            return Err(Unsendable(format!(
                "connect-ip: unknown IP versions: {version}"
            )))
        }
    };
    if let Some(peer) = &allowed.peer {
        if !peer.iter().any(|prefix| prefix.contains(src)) {
            return Err(Unsendable(format!(
                "connect-ip: datagram source address not allowed: {src}"
            )));
        }
    }
    let icmp = version == 4 && protocol == PROTO_ICMP || version == 6 && protocol == PROTO_ICMPV6;
    let allowed_dst = allowed.assigned.iter().any(|prefix| prefix.contains(dst))
        || allowed.local_routes.iter().any(|route| {
            route.start.is_ipv4() == dst.is_ipv4()
                && route.start <= dst
                && dst <= route.end
                && (icmp || route.protocol == 0 || route.protocol == protocol)
        });
    if !allowed_dst {
        return Err(Unsendable(format!(
            "connect-ip: datagram destination address / protocol not allowed: {dst} (protocol: {protocol})"
        )));
    }
    Ok(())
}

/// The tunnel cannot carry the smallest packet a link of the family must.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MtuTooSmall(pub(crate) usize);

/// Xray's `composeICMPTooLargePacket`: an ICMP Fragmentation Needed or
/// ICMPv6 Packet Too Big, from the packet's destination back to its source,
/// announcing `mtu`.
pub(crate) fn icmp_too_large(packet: &[u8], mtu: usize) -> Result<Vec<u8>, IcmpError> {
    let Some(&first) = packet.first() else {
        return Err(IcmpError::Malformed("connect-ip: empty packet".into()));
    };
    match first >> 4 {
        4 => {
            if packet.len() < IPV4_HEADER {
                return Err(IcmpError::Malformed(
                    "connect-ip: IPv4 packet too short".into(),
                ));
            }
            if mtu < IPV4_MIN_MTU {
                return Err(IcmpError::MtuTooSmall(MtuTooSmall(mtu)));
            }
            let quoted = &packet[..packet
                .len()
                .min(IPV4_HEADER.max(usize::from(first & 0x0f) << 2) + 8)];
            // Type 3 (destination unreachable), code 4, then the MTU as Go's
            // icmp.PacketTooBig writes it: a 32-bit big-endian word.
            let mut icmp = vec![3, 4, 0, 0];
            icmp.extend_from_slice(&(mtu as u32).to_be_bytes());
            icmp.extend_from_slice(quoted);
            let checksum = internet_checksum(&[&icmp]);
            icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
            let mut header = [0u8; IPV4_HEADER];
            header[0] = 0x45;
            header[2..4].copy_from_slice(&((IPV4_HEADER + icmp.len()) as u16).to_be_bytes());
            header[8] = 64;
            header[9] = PROTO_ICMP;
            header[12..16].copy_from_slice(&packet[16..20]);
            header[16..20].copy_from_slice(&packet[12..16]);
            let checksum = ipv4_header_checksum(&header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            let mut out = header.to_vec();
            out.extend_from_slice(&icmp);
            Ok(out)
        }
        6 => {
            if packet.len() < IPV6_HEADER {
                return Err(IcmpError::Malformed(
                    "connect-ip: IPv6 packet too short".into(),
                ));
            }
            if mtu < IPV6_MIN_MTU {
                return Err(IcmpError::MtuTooSmall(MtuTooSmall(mtu)));
            }
            let quoted = &packet[..packet.len().min(1232)];
            let mut icmp = vec![2, 0, 0, 0];
            icmp.extend_from_slice(&(mtu as u32).to_be_bytes());
            icmp.extend_from_slice(quoted);
            // The pseudo header: the new source (the packet's destination),
            // the new destination, the upper-layer length and next header.
            let mut pseudo = Vec::with_capacity(40);
            pseudo.extend_from_slice(&packet[24..40]);
            pseudo.extend_from_slice(&packet[8..24]);
            pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, PROTO_ICMPV6]);
            let checksum = internet_checksum(&[&pseudo, &icmp]);
            icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
            let mut header = [0u8; IPV6_HEADER];
            header[0] = 6 << 4;
            header[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
            header[6] = PROTO_ICMPV6;
            header[7] = 64;
            header[8..24].copy_from_slice(&packet[24..40]);
            header[24..40].copy_from_slice(&packet[8..24]);
            let mut out = header.to_vec();
            out.extend_from_slice(&icmp);
            Ok(out)
        }
        version => Err(IcmpError::Malformed(format!(
            "connect-ip: unknown IP version: {version}"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IcmpError {
    MtuTooSmall(MtuTooSmall),
    Malformed(String),
}

/// The Internet checksum over the concatenated parts, each part's length
/// but the last's even.
fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut words = part.chunks_exact(2);
        for word in &mut words {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        if let [last] = words.remainder() {
            sum += u32::from(*last) << 8;
        }
    }
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(src: [u8; 4], dst: [u8; 4], ttl: u8, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 20 + payload.len()];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        b[8] = ttl;
        b[9] = 17;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&dst);
        b[20..].copy_from_slice(payload);
        let checksum = ipv4_header_checksum(&b[..20]);
        b[10..12].copy_from_slice(&checksum.to_be_bytes());
        b
    }

    #[test]
    fn outgoing_packets_lose_one_ttl_and_keep_a_valid_checksum() {
        let mut packet = ipv4_udp([10, 0, 0, 2], [192, 0, 2, 1], 64, b"ping");
        prepare_outgoing(&mut packet).unwrap();
        assert_eq!(packet[8], 63);
        // A valid header sums to 0xffff with its checksum included.
        let mut sum = 0u32;
        for word in packet[..20].chunks(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff);
        let mut expiring = ipv4_udp([10, 0, 0, 2], [192, 0, 2, 1], 1, b"");
        assert!(prepare_outgoing(&mut expiring).is_err());
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[7] = 2;
        prepare_outgoing(&mut v6).unwrap();
        assert_eq!(v6[7], 1);
        assert!(prepare_outgoing(&mut v6).is_err());
        assert!(prepare_outgoing(&mut []).is_err());
        let mut truncated = ipv4_udp([10, 0, 0, 2], [192, 0, 2, 1], 64, b"ping");
        truncated[3] = 200;
        assert!(prepare_outgoing(&mut truncated).is_err());
    }

    #[test]
    fn incoming_packets_must_go_to_an_assigned_address() {
        let allowed = Destinations {
            assigned: vec![IpPrefix::new("10.0.0.2".parse().unwrap(), 32)],
            ..Default::default()
        };
        assert!(check_incoming(&ipv4_udp([1, 1, 1, 1], [10, 0, 0, 2], 64, b""), &allowed).is_ok());
        assert!(check_incoming(&ipv4_udp([1, 1, 1, 1], [10, 0, 0, 3], 64, b""), &allowed).is_err());
        assert!(check_incoming(&[0x45, 0, 0], &allowed).is_err());
        assert!(check_incoming(&[0x50; 40], &allowed).is_err());
    }

    #[test]
    fn local_routes_admit_icmp_and_their_protocol() {
        let allowed = Destinations {
            local_routes: vec![IpRoute {
                start: "192.0.2.0".parse().unwrap(),
                end: "192.0.2.255".parse().unwrap(),
                protocol: 6,
            }],
            ..Default::default()
        };
        let mut udp = ipv4_udp([1, 1, 1, 1], [192, 0, 2, 9], 64, b"");
        assert!(check_incoming(&udp, &allowed).is_err());
        udp[9] = 6;
        assert!(check_incoming(&udp, &allowed).is_ok());
        udp[9] = PROTO_ICMP;
        assert!(check_incoming(&udp, &allowed).is_ok());
    }

    #[test]
    fn icmp_too_large_quotes_the_packet_and_swaps_the_addresses() {
        let packet = ipv4_udp([10, 0, 0, 2], [192, 0, 2, 1], 64, &[9; 100]);
        let icmp = icmp_too_large(&packet, 1200).unwrap();
        assert_eq!(icmp.len(), 20 + 8 + 28);
        assert_eq!(&icmp[12..16], &[192, 0, 2, 1]);
        assert_eq!(&icmp[16..20], &[10, 0, 0, 2]);
        assert_eq!(&icmp[20..22], &[3, 4]);
        assert_eq!(&icmp[24..28], &1200u32.to_be_bytes());
        assert_eq!(internet_checksum(&[&icmp[20..]]), 0);
        assert_eq!(
            icmp_too_large(&packet, 67),
            Err(IcmpError::MtuTooSmall(MtuTooSmall(67)))
        );
        let mut v6 = vec![0u8; 1300];
        v6[0] = 0x60;
        v6[8] = 0xfd;
        v6[24] = 0x20;
        let icmp = icmp_too_large(&v6, 1280).unwrap();
        assert_eq!(icmp.len(), 40 + 8 + 1232);
        assert_eq!(icmp[8], 0x20);
        assert_eq!(icmp[24], 0xfd);
        assert!(matches!(
            icmp_too_large(&v6, 1279),
            Err(IcmpError::MtuTooSmall(_))
        ));
    }
}
