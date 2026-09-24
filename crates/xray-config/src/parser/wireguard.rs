use super::*;
use crate::{WireguardDomainStrategy, WireguardOutboundSettings, WireguardPeerSettings};
use xray_proxy::wireguard::{AllowedIp, KeyMaterial};

impl Parser<'_> {
    pub(super) fn parse_wireguard_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<WireguardOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let parsed = (|| {
            let settings = outbound.get("settings").filter(|v| v.is_object())?;
            self.reject_unknown_fields(settings, &path, &surface::WIREGUARD);
            if outbound.get("streamSettings").is_some() || outbound.get("proxySettings").is_some() {
                self.error(
                    format!("$.outbounds[{index}]"),
                    "WireGuard custom stream settings and chaining are unsupported",
                );
            }
            if let Some(value) = settings.get("noKernelTun") {
                value.as_bool()?;
            }
            if let Some(value) = settings.get("reserved") {
                let bytes = value.as_array()?;
                if !(bytes.is_empty()
                    || bytes.len() == 3 && bytes.iter().all(|b| b.as_u64() == Some(0)))
                {
                    return None;
                }
            }
            let secret_key = KeyMaterial::parse(settings.get("secretKey")?.as_str()?).ok()?;
            let values = settings.get("peers")?.as_array()?;
            if values.is_empty() || values.len() > 8 {
                return None;
            }
            let mut peers: Vec<WireguardPeerSettings> = Vec::with_capacity(values.len());
            let mut prefix_count = 0;
            for (peer_index, value) in values.iter().enumerate() {
                let peer = value.as_object()?;
                self.reject_unknown_fields(
                    value,
                    &format!("{path}.peers[{peer_index}]"),
                    &surface::WIREGUARD_PEER,
                );
                let public_key = KeyMaterial::parse(peer.get("publicKey")?.as_str()?).ok()?;
                let preshared_key = match peer.get("preSharedKey") {
                    None => None,
                    Some(value) => match value.as_str()? {
                        "" => None,
                        text => {
                            let key = KeyMaterial::parse(text).ok()?;
                            // The WireGuard UAPI treats an all-zero PSK as unset.
                            (!key.expose_bytes().iter().all(|b| *b == 0)).then_some(key)
                        }
                    },
                };
                // Reject obviously unusable identities here; the runtime also verifies
                // X25519 contribution before constructing the device or opening sockets.
                if public_key.expose_bytes().iter().all(|b| *b == 0) {
                    return None;
                }
                let (endpoint, port) = parse_endpoint(peer.get("endpoint")?.as_str()?)?;
                let keepalive = optional_u16(peer.get("keepAlive"), 0)?;
                let allowed_ips = match peer.get("allowedIPs") {
                    None => vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                    Some(value) => {
                        let values = value.as_array()?;
                        if values.is_empty() || values.len() > 256 {
                            return None;
                        }
                        values
                            .iter()
                            .map(|v| v.as_str()?.parse::<AllowedIp>().ok())
                            .collect::<Option<Vec<_>>>()?
                    }
                };
                prefix_count += allowed_ips.len();
                if prefix_count > 256 || peers.iter().any(|p| p.public_key == public_key) {
                    return None;
                }
                peers.push(WireguardPeerSettings {
                    public_key,
                    preshared_key,
                    endpoint,
                    port,
                    allowed_ips,
                    keepalive,
                });
            }
            let mtu = optional_u16(settings.get("mtu"), 1420)?;
            let mtu = if mtu == 0 { 1420 } else { mtu };
            if !(1280..=1420).contains(&mtu) {
                return None;
            }
            let addresses = match settings.get("address") {
                None => vec![
                    "10.0.0.1".parse().unwrap(),
                    "fd59:7153:2388:b5fd::1".parse().unwrap(),
                ],
                Some(value) => {
                    let values = value.as_array()?;
                    if values.is_empty() || values.len() > 2 {
                        return None;
                    }
                    values
                        .iter()
                        .map(|v| parse_address(v.as_str()?))
                        .collect::<Option<Vec<_>>>()?
                }
            };
            if addresses.iter().filter(|ip| ip.is_ipv4()).count() > 1
                || addresses.iter().filter(|ip| ip.is_ipv6()).count() > 1
            {
                return None;
            }
            let domain_strategy = match settings
                .get("domainStrategy")
                .map(Value::as_str)
                .unwrap_or(Some(""))
                .map(str::to_ascii_lowercase)?
                .as_str()
            {
                "" | "forceip" => WireguardDomainStrategy::ForceIp,
                "forceipv4" => WireguardDomainStrategy::ForceIpv4,
                "forceipv6" => WireguardDomainStrategy::ForceIpv6,
                "forceipv4v6" => WireguardDomainStrategy::ForceIpv4v6,
                "forceipv6v4" => WireguardDomainStrategy::ForceIpv6v4,
                _ => return None,
            };
            Some(WireguardOutboundSettings {
                secret_key,
                peers,
                addresses,
                mtu,
                domain_strategy,
            })
        })();
        if parsed.is_none() {
            self.error(path, "invalid or unsupported WireGuard configuration (1..8 distinct peers, at most 256 total allowed IPs, valid keys/endpoints/addresses, MTU 1280..1420)");
        }
        parsed
    }
}
fn optional_u16(value: Option<&Value>, fallback: u16) -> Option<u16> {
    value.map_or(Some(fallback), |v| u16::try_from(v.as_u64()?).ok())
}
fn parse_address(input: &str) -> Option<IpAddr> {
    let (text, prefix) = input
        .split_once('/')
        .map_or((input, None), |(ip, p)| (ip, Some(p)));
    let ip = text.parse::<IpAddr>().ok()?;
    if let Some(prefix) = prefix {
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        AllowedIp::new(ip, prefix.parse().ok()?).ok()?;
    }
    if !usable_ip(ip) {
        return None;
    }
    Some(ip)
}
fn usable_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(v4) => v4 != std::net::Ipv4Addr::BROADCAST,
            IpAddr::V6(v6) => !v6.is_unicast_link_local() && v6.to_ipv4_mapped().is_none(),
        }
}
fn parse_endpoint(input: &str) -> Option<(TargetAddr, u16)> {
    if input.len() > 260 {
        return None;
    }
    if let Ok(addr) = input.parse::<SocketAddr>() {
        if addr.port() == 0
            || !usable_ip(addr.ip())
            || matches!(addr, SocketAddr::V6(v6) if v6.scope_id() != 0)
        {
            return None;
        }
        return Some((TargetAddr::Ip(addr.ip()), addr.port()));
    }
    let (host, port) = input.rsplit_once(':')?;
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
        || port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some((TargetAddr::Domain(host.to_string()), port))
}
