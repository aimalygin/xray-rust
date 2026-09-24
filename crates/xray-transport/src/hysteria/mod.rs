//! Authenticated Hysteria 2 client sessions over protected QUIC sockets.
//! The core parser/SDK do not advertise this outbound until runtime integration.

mod client;
mod tcp;
mod udp;

pub use client::{HysteriaClient, HysteriaConfig, HysteriaError, HysteriaLimits};
pub use tcp::HysteriaTcpStream;
pub use udp::{HysteriaDatagram, HysteriaUdpSession};

use xray_routing::{Network, Target, TargetAddr};

fn address(target: &Target, network: Network) -> Result<String, HysteriaError> {
    if target.network != network || target.port == 0 {
        return Err(HysteriaError::Target);
    }
    let host = match &target.addr {
        TargetAddr::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        TargetAddr::Ip(ip) => ip.to_string(),
        TargetAddr::Domain(domain) => {
            let ascii = idna::domain_to_ascii_strict(domain).map_err(|_| HysteriaError::Target)?;
            let normalized = ascii.strip_suffix('.').unwrap_or(&ascii);
            if normalized.is_empty()
                || normalized.len() > 253
                || normalized
                    .split('.')
                    .any(|label| label.is_empty() || label.len() > 63)
            {
                return Err(HysteriaError::Target);
            }
            ascii
        }
    };
    Ok(format!("{host}:{}", target.port))
}

fn parse_udp_source(input: &str) -> Result<Target, HysteriaError> {
    if let Ok(socket) = input.parse::<std::net::SocketAddr>() {
        if socket.port() == 0 {
            return Err(HysteriaError::Target);
        }
        return Ok(Target::new(
            TargetAddr::Ip(socket.ip()),
            socket.port(),
            Network::Udp,
        ));
    }
    let (host, port) = input.rsplit_once(':').ok_or(HysteriaError::Target)?;
    let target = Target::new(
        TargetAddr::Domain(host.to_owned()),
        port.parse().map_err(|_| HysteriaError::Target)?,
        Network::Udp,
    );
    address(&target, Network::Udp)?;
    Ok(target)
}
