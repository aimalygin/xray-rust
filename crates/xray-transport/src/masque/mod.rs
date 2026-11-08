//! MASQUE CONNECT-IP client tunnels (RFC 9484), as Xray-core v26.10.31's
//! `transport/internet/masque` dials them: over HTTP/3 by default, with
//! IP packets in HTTP datagrams. Its `proxy/masque` client runs a userspace
//! TCP/IP stack over each tunnel, which `xray-core-rs` supplies.
mod capsule;
mod h3;
mod packet;
mod request;
mod session;

#[cfg(test)]
mod oracle_tests;

pub use capsule::{AssignedAddress, IpPrefix, IpRoute};
pub use h3::{dial_h3, MasqueH3Config};
pub use request::{authority, MasqueRequest, DEFAULT_PATH};
pub use session::{MasqueError, MasqueTunnel, WriteOutcome, MAX_TUNNEL_PACKET};

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

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    //! Capsule parsing for the fuzz targets.
    pub fn parse_capsules(data: &[u8]) {
        let mut parser = super::capsule::CapsuleParser::default();
        parser.push(data);
        while let Ok(Some(_)) = parser.next() {}
    }
}
