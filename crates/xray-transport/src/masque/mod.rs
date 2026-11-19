//! MASQUE CONNECT-IP client tunnels (RFC 9484), as Xray-core v26.10.31's
//! `transport/internet/masque` dials them: over HTTP/3 by default, with
//! IP packets in HTTP datagrams, or over HTTP/2 with the packets in
//! capsules. Its `proxy/masque` client runs a userspace TCP/IP stack over
//! each tunnel, which `xray-core-rs` supplies.
mod capsule;
pub(crate) mod h2;
mod h3;
mod packet;
mod request;
mod session;
mod warp;

#[cfg(test)]
mod oracle_tests;

pub use capsule::{AssignedAddress, IpPrefix, IpRoute};
pub use h2::{dial_h2, MasqueH2Config, H2_KEEP_ALIVE};
pub use h3::{dial_h3, MasqueH3Config};
pub use request::{authority, MasqueRequest, DEFAULT_PATH};
pub use session::{MasqueError, MasqueTunnel, WriteOutcome, MAX_TUNNEL_PACKET};
pub use warp::MasqueWarp;

use std::time::Duration;

/// Xray's `MinPacketSize`: the packets a tunnel must carry, and the MTU of
/// the stack over it.
pub const MIN_PACKET_SIZE: usize = 1280;
/// Xray's `initialPacketSize` for the QUIC connection.
pub const INITIAL_PACKET_SIZE: u16 = 1350;
/// Xray's `establishTimeout` for a tunnel.
pub const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);
/// quic-go's `QuicgoH3KeepAlivePeriod`, MASQUE's default keepalive.
pub const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(10);
/// MASQUE's default QUIC idle timeout.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// quic-go's default connection ID length, which Xray's dial keeps.
pub const QUIC_CONNECTION_ID_LEN: u8 = 4;

/// A proxy's capsule stream, pushed in pieces of the size the first byte
/// picks, as the tunnel reads it: assignments become the destinations the
/// DATAGRAM capsules' packets are checked against, as `read_packet` checks
/// them, and each packet is also readied and answered as an outgoing one.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_capsules(data: &[u8]) {
    use capsule::{Capsule, CapsuleParser, Parsed};

    let Some((&selector, stream)) = data.split_first() else {
        return;
    };
    let bare = selector & 0x80 != 0;
    let mut parser = CapsuleParser::default();
    let mut destinations = packet::Destinations::default();
    for piece in stream.chunks(usize::from(selector & 0x7f) + 1) {
        parser.push(piece);
        loop {
            match parser.next() {
                Ok(Some(Parsed::Capsule(Capsule::AddressAssign(entries)))) => {
                    destinations.assigned = entries
                        .iter()
                        .filter(|entry| !entry.prefix.is_rejection())
                        .map(|entry| entry.prefix)
                        .collect();
                }
                Ok(Some(Parsed::Capsule(Capsule::AddressRequest(entries)))) => {
                    let refusals: Vec<_> = entries
                        .iter()
                        .map(|entry| AssignedAddress {
                            request_id: entry.request_id,
                            prefix: IpPrefix::rejection(entry.prefix.addr.is_ipv4()),
                        })
                        .collect();
                    let _ = capsule::address_assign(&refusals);
                }
                // A client keeps no routes; matching against the proxy's
                // still runs the range checks a server's routes take.
                Ok(Some(Parsed::Capsule(Capsule::RouteAdvertisement(routes)))) => {
                    destinations.local_routes = routes;
                }
                Ok(Some(Parsed::Capsule(Capsule::Datagram(value)))) => {
                    let Some(packet) = session::datagram_packet(value, bare) else {
                        continue;
                    };
                    let _ = packet::check_incoming(&packet, &destinations);
                    let mut outgoing = packet.to_vec();
                    let _ = packet::prepare_outgoing(&mut outgoing);
                    let _ = packet::icmp_too_large(&packet, MIN_PACKET_SIZE);
                    let _ = session::datagram_capsule(&packet, bare);
                }
                Ok(Some(Parsed::OversizedDatagram(_))) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
    let _ = parser.is_mid_capsule();
}
