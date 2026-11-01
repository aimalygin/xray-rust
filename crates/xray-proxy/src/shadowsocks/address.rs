//! SOCKS-style target addresses shared by both Shadowsocks families.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use xray_routing::{Network, Target, TargetAddr};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn encode(target: &Target) -> io::Result<Vec<u8>> {
    if target.port == 0 {
        return Err(invalid("Shadowsocks target port is zero"));
    }
    let mut bytes = Vec::with_capacity(259);
    match &target.addr {
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 255
                || domain.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(invalid("invalid Shadowsocks target domain"));
            }
            bytes.extend_from_slice(&[3, domain.len() as u8]);
            bytes.extend_from_slice(domain.as_bytes());
        }
    }
    bytes.extend_from_slice(&target.port.to_be_bytes());
    Ok(bytes)
}

/// Parse a UDP source address and return it with its encoded length. The
/// caller decides how to treat the type byte's high bits before this call.
pub(crate) fn decode(bytes: &[u8]) -> io::Result<(Target, usize)> {
    let truncated = || invalid("truncated Shadowsocks address");
    let (addr, end) = match bytes.first().ok_or_else(truncated)? {
        1 => {
            let ip: [u8; 4] = bytes.get(1..5).ok_or_else(truncated)?.try_into().unwrap();
            (TargetAddr::Ip(Ipv4Addr::from(ip).into()), 5)
        }
        4 => {
            let ip: [u8; 16] = bytes.get(1..17).ok_or_else(truncated)?.try_into().unwrap();
            (TargetAddr::Ip(Ipv6Addr::from(ip).into()), 17)
        }
        3 => {
            let len = *bytes.get(1).ok_or_else(truncated)? as usize;
            let domain = bytes.get(2..2 + len).ok_or_else(truncated)?;
            let domain = std::str::from_utf8(domain)
                .map_err(|_| invalid("invalid Shadowsocks domain"))?
                .to_owned();
            (TargetAddr::Domain(domain), 2 + len)
        }
        _ => return Err(invalid("invalid Shadowsocks address type")),
    };
    let port = bytes.get(end..end + 2).ok_or_else(truncated)?;
    let target = Target::new(addr, u16::from_be_bytes([port[0], port[1]]), Network::Udp);
    encode(&target)?;
    Ok((target, end + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip_and_reject_truncation_and_invalid_values() {
        for addr in [
            TargetAddr::Ip("192.0.2.8".parse().unwrap()),
            TargetAddr::Ip("2001:db8::8".parse().unwrap()),
            TargetAddr::Domain("example.test".into()),
        ] {
            let target = Target::new(addr, 53, Network::Udp);
            let mut wire = encode(&target).unwrap();
            let len = wire.len();
            wire.extend_from_slice(b"payload");
            assert_eq!(decode(&wire).unwrap(), (target, len));
            for cut in 0..len {
                assert!(decode(&wire[..cut]).is_err());
            }
        }
        for bad in [
            &[2, 0, 0, 0, 0, 0, 53][..],
            &[1, 192, 0, 2, 8, 0, 0],
            &[3, 0, 0, 53],
            &[3, 1, 0xff, 0, 53],
            &[3, 1, b' ', 0, 53],
        ] {
            assert!(decode(bad).is_err());
        }
        let long = Target::new(TargetAddr::Domain("a".repeat(256)), 53, Network::Tcp);
        assert!(encode(&long).is_err());
    }
}
