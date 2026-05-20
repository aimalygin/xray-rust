use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub addr: TargetAddr,
    pub port: u16,
    pub network: Network,
}

impl Target {
    pub fn new(addr: TargetAddr, port: u16, network: Network) -> Self {
        Self {
            addr,
            port,
            network,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub inbound_tag: String,
    pub target: Target,
}

impl Session {
    pub fn new(inbound_tag: impl Into<String>, target: Target) -> Self {
        Self {
            inbound_tag: inbound_tag.into(),
            target,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("no outbound available")]
    NoOutbound,
}

pub trait Router: Send + Sync {
    fn pick_outbound<'a>(&'a self, session: &Session) -> Result<&'a str, RoutingError>;
}

#[derive(Debug, Clone)]
pub struct StaticRouter {
    default_outbound: String,
}

impl StaticRouter {
    pub fn new(default_outbound: impl Into<String>) -> Self {
        Self {
            default_outbound: default_outbound.into(),
        }
    }

    pub fn pick_outbound<'a>(&'a self, session: &Session) -> Result<&'a str, RoutingError> {
        <Self as Router>::pick_outbound(self, session)
    }
}

impl Router for StaticRouter {
    fn pick_outbound<'a>(&'a self, _session: &Session) -> Result<&'a str, RoutingError> {
        if self.default_outbound.is_empty() {
            Err(RoutingError::NoOutbound)
        } else {
            Ok(&self.default_outbound)
        }
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
