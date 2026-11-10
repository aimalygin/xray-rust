//! Which addresses Xray-core's realm client punches: the server's, in the
//! families its own addresses have, with the ports of a predictable
//! symmetric NAT filled in, sorted as their strings sort.
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};

const SYMMETRIC_NAT_PORT_GAP: u16 = 4;
const SYMMETRIC_NAT_EXTRA_PORTS: u32 = 4;
const SYMMETRIC_NAT_MAX_PORTS_PER_HOST: usize = 32;
/// The most addresses one attempt punches. Xray punches every address the
/// rendezvous lists; the list is the rendezvous's to write, and a hello goes
/// to each address ten times a second, so an unbounded one turns the client
/// into a source of UDP towards whatever it names.
pub(super) const MAX_PUNCH_CANDIDATES: usize = 64;

/// `netip.Addr.Is4`: an IPv4-mapped IPv6 address is not IPv4.
fn is4(addr: &SocketAddr) -> bool {
    addr.is_ipv4()
}

/// `parseAddrPorts`: every entry, or none when one does not parse.
pub(super) fn parse_addr_ports(addresses: &[String]) -> Vec<SocketAddr> {
    addresses
        .iter()
        .map(|address| address.parse::<SocketAddr>())
        .collect::<Result<_, _>>()
        .unwrap_or_default()
}

/// `candidatePunchAddrs` then `expandSymmetricNATCandidates`, the first
/// [`MAX_PUNCH_CANDIDATES`] of them.
pub(super) fn punch_candidates(
    locals: &[SocketAddr],
    peers: &[SocketAddr],
    family: super::RealmFamily,
) -> Vec<SocketAddr> {
    let mut allow4 = locals.iter().any(is4);
    let mut allow6 = locals.iter().any(|local| !is4(local));
    match family {
        super::RealmFamily::V4 => allow6 = false,
        super::RealmFamily::V6 => allow4 = false,
        super::RealmFamily::Dual => {}
    }
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for peer in peers {
        if seen.contains(peer) {
            continue;
        }
        if (is4(peer) && allow4) || (!is4(peer) && allow6) {
            seen.insert(*peer);
            candidates.push(*peer);
        }
    }
    let mut candidates = expand_symmetric_nat(candidates, seen);
    candidates.truncate(MAX_PUNCH_CANDIDATES);
    candidates
}

/// `expandSymmetricNATCandidates`: for each IPv4 host whose ports lie at
/// most four apart, every port from the lowest to four past the highest,
/// at most 32 more per host.
fn expand_symmetric_nat(
    mut candidates: Vec<SocketAddr>,
    mut seen: HashSet<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut ports_by_ip: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
    for addr in candidates.iter().filter(|addr| is4(addr)) {
        ports_by_ip.entry(addr.ip()).or_default().push(addr.port());
    }
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        let predictable = ports.len() >= 2
            && ports
                .windows(2)
                .all(|pair| pair[1] - pair[0] <= SYMMETRIC_NAT_PORT_GAP);
        if !predictable {
            continue;
        }
        let start = u32::from(ports[0]);
        let end = (u32::from(ports[ports.len() - 1]) + SYMMETRIC_NAT_EXTRA_PORTS).min(65_535);
        let mut added = 0;
        let mut port = start;
        while port <= end && added < SYMMETRIC_NAT_MAX_PORTS_PER_HOST {
            let addr = SocketAddr::new(ip, port as u16);
            if seen.insert(addr) {
                candidates.push(addr);
                added += 1;
            }
            port += 1;
        }
    }
    sort_by_string(&mut candidates);
    candidates
}

/// Sorted as `strings.Compare` orders `AddrPort.String`.
pub(super) fn sort_by_string(addresses: &mut [SocketAddr]) {
    addresses.sort_by_cached_key(|addr| addr.to_string());
}

#[cfg(test)]
mod tests;
