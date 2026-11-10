//! The `xicmp` UDP mask, as Xray-core v26.10.31's `Xicmp.Build` reads it.
use super::*;
use crate::{go_lowercase, XicmpMask};

impl Parser<'_> {
    /// The `xicmp` entry of `finalmask.udp`. The stream checks its carrier
    /// and the masks it cannot run with.
    pub(super) fn parse_udp_xicmp(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<XicmpMask> {
        let masks = stream?.pointer("/finalmask/udp")?.as_array()?;
        let i = masks.iter().position(|mask| {
            mask.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| go_lowercase(kind) == "xicmp")
        })?;
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp[{i}]");
        // It opens its own sockets, so Xray-core dials it only outermost,
        // and fails every dial with "incorrect index" elsewhere, a filter
        // after it included.
        if i + 1 != masks.len() {
            self.error(
                &path,
                "xicmp must be the last UDP mask: Xray-core fails every dial with it anywhere else",
            );
        }
        let path = format!("{path}.settings");
        // Absent settings read as `{}`, as for every mask.
        let settings = match masks[i].get("settings") {
            None | Some(Value::Null) => return Some(XicmpMask::default()),
            Some(settings) if settings.is_object() => settings,
            Some(_) => {
                self.error(path, "xicmp settings must be an object");
                return None;
            }
        };
        self.reject_unknown_fields(settings, &path, &surface::XICMP_MASK);
        let dgram = self.go_bool_at(settings, "dgram", format!("{path}.dgram"));
        let ips = self.go_string_list_at(settings, "ips", format!("{path}.ips"));
        let (dgram, ips) = (dgram?, ips?);
        let mut addresses = Vec::with_capacity(ips.len());
        for (j, ip) in ips.iter().enumerate() {
            match netip_addr(ip) {
                Some(address) => addresses.push(address),
                None => self.error(
                    format!("{path}.ips[{j}]"),
                    format!("xicmp ips are IP addresses, not {ip:?}"),
                ),
            }
        }
        (addresses.len() == ips.len()).then_some(XicmpMask {
            dgram,
            ips: addresses,
        })
    }
}

/// `netip.ParseAddr`, keeping what `Addr.AsSlice` keeps: a zone, which Go
/// reads on an IPv6 address, is dropped, and an IPv4-mapped address is the
/// IPv4 address it sends to.
fn netip_addr(text: &str) -> Option<std::net::IpAddr> {
    if let Ok(ip) = text.parse::<std::net::Ipv4Addr>() {
        return Some(ip.into());
    }
    let (address, zone) = match text.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (text, None),
    };
    if zone.is_some_and(str::is_empty) {
        return None;
    }
    let ip = address.parse::<std::net::Ipv6Addr>().ok()?;
    Some(std::net::IpAddr::V6(ip).to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ips_read_as_netip_reads_them() {
        assert_eq!(netip_addr("192.0.2.1"), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(
            netip_addr("2001:db8::1%eth0"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            netip_addr("::ffff:192.0.2.1"),
            Some("192.0.2.1".parse().unwrap())
        );
        for refused in [
            "",
            "192.0.2.1%eth0",
            "2001:db8::1%",
            "01.0.2.1",
            "[::1]",
            "host",
        ] {
            assert_eq!(netip_addr(refused), None, "{refused}");
        }
    }
}
