//! The `xicmp` UDP mask as Xray-core v26.10.31's client runs it. Every
//! datagram rides in an ICMP echo request to the server, after the client's
//! 8-byte id, and the server's datagrams come back in its echo replies.
//!
//! The mask replaces the socket: the carrier's packets never go out as UDP.
//! Its ICMP sockets are datagram sockets, which need no privilege where the
//! system allows them, or raw ones, which need root or `CAP_NET_RAW`.
mod client;
mod message;
pub(crate) mod quic;

pub use client::XicmpClient;

use std::net::IpAddr;

/// The client's settings, as `Xicmp.Build` reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XicmpConfig {
    /// Datagram ICMP sockets rather than raw ones.
    pub dgram: bool,
    /// The server addresses, one drawn for each packet; empty sends to the
    /// carrier's server address.
    pub ips: Vec<IpAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum XicmpError {
    #[error("xicmp socket: {0}")]
    Socket(#[source] std::io::Error),
    #[error("xicmp socket protection: {0}")]
    Protection(#[source] crate::TransportError),
}

#[cfg(test)]
mod tests;
