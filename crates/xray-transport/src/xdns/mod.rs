//! The `xdns` UDP mask as Xray-core v26.10.31's client runs it. Every packet
//! rides in the names of DNS queries to recursive resolvers, which carry
//! them to the server's domain, and comes back in their answers; polls keep
//! queries waiting at the server for what it has to send.
//!
//! The mask replaces the socket: the carrier's packets never go to the
//! server's address, only to the resolvers.
mod client;
mod domain;
mod message;
pub(crate) mod quic;
mod resolver;

pub use client::XdnsClient;

use std::net::SocketAddr;

/// The client's settings, as `XDNS.Build` reads them: one entry per domain
/// name, defaults filled in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XdnsConfig {
    pub domains: Vec<XdnsDomain>,
    pub resolvers: Vec<XdnsResolver>,
    /// Polls sent after each packet and each poll, 0 to 3.
    pub extra_poll: u8,
}

/// One domain the client tunnels under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdnsDomain {
    pub name: String,
    /// The longest query name, at most 255.
    pub len_limit: i32,
    /// The longest label carrying data, at most 63.
    pub label_limit: i32,
    /// The record types the client asks for, picked at random for each
    /// packet; empty asks for TXT.
    pub types: Vec<u16>,
    /// The UDP size an OPT record advertises, or 0 for none.
    pub edns0: u16,
}

/// A resolver and the addresses it was resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XdnsResolver {
    /// DNS over UDP to the first address a socket opens for.
    Udp(Vec<SocketAddr>),
    /// DNS over TCP to the first address that connects, as Go's dialer
    /// tries them.
    Tcp(Vec<SocketAddr>),
}

#[derive(Debug, thiserror::Error)]
pub enum XdnsError {
    #[error("xdns domain: {0}")]
    Domain(&'static str),
    #[error("xdns: {0}")]
    Config(&'static str),
    #[error("xdns resolver: {0}")]
    Resolver(#[source] std::io::Error),
}

impl XdnsConfig {
    /// The domains as the client reads them.
    fn domains(&self) -> Result<Vec<domain::Domain>, XdnsError> {
        if self.domains.is_empty() {
            return Err(XdnsError::Config("xdns needs a domain"));
        }
        self.domains
            .iter()
            .map(|domain| {
                let types = if domain.types.is_empty() {
                    &[domain::TYPE_TXT][..]
                } else {
                    &domain.types
                };
                domain::Domain::new(
                    &domain.name,
                    domain.len_limit,
                    domain.label_limit,
                    types,
                    domain.edns0,
                )
            })
            .collect()
    }

    /// Checks what can be checked before connecting.
    pub fn validate(&self) -> Result<(), XdnsError> {
        self.domains()?;
        if self.resolvers.is_empty() {
            return Err(XdnsError::Config("xdns needs a resolver"));
        }
        if self.extra_poll > 3 {
            return Err(XdnsError::Config("extraPoll must be 0 to 3"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
