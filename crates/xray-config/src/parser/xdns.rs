//! The `xdns` UDP mask, as Xray-core v26.10.31's `XDNS.Build` reads it.
use super::*;
use crate::{go_lowercase, XdnsDomain, XdnsMask, XdnsProtocol, XdnsResolver};

impl Parser<'_> {
    /// The `xdns` entry of `finalmask.udp`. The stream checks its carrier
    /// and the masks it cannot run with.
    pub(super) fn parse_udp_xdns(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<XdnsMask> {
        let masks = stream?.pointer("/finalmask/udp")?.as_array()?;
        let i = masks.iter().position(|mask| {
            mask.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| go_lowercase(kind) == "xdns")
        })?;
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp[{i}]");
        // The client opens its own resolver sockets and never uses the one
        // under it, so Xray-core dials the masks listed after it for
        // nothing. A filter there wraps nothing anyway.
        if masks[i + 1..].iter().any(|mask| !filter::is_filter(mask)) {
            self.error(
                &path,
                "xdns must be the last UDP mask: Xray-core dials the masks listed after it and never uses them",
            );
        }
        let path = format!("{path}.settings");
        let Some(settings) = masks[i].get("settings").filter(|s| s.is_object()) else {
            self.error(path, "xdns settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::XDNS_MASK);
        let domains = self.xdns_domains(settings, &path);
        let resolvers = self.xdns_resolvers(settings, &path);
        let extra_poll = self.go_int32_at(settings, "extraPoll", format!("{path}.extraPoll"));
        let extra_poll = match extra_poll {
            Some(value @ 0..=3) => Some(value as u8),
            Some(_) => {
                self.error(format!("{path}.extraPoll"), "extraPoll must be 0 to 3");
                None
            }
            None => None,
        };
        let (domains, resolvers, extra_poll) = (domains?, resolvers?, extra_poll?);
        // Xray-core builds these empty and fails every dial.
        if domains.is_empty() {
            self.error(format!("{path}.domains"), "xdns needs a domain name");
            return None;
        }
        if resolvers.is_empty() {
            self.error(format!("{path}.resolvers"), "xdns needs a resolver address");
            return None;
        }
        Some(XdnsMask {
            domains,
            resolvers,
            extra_poll,
        })
    }

    /// `domains`: one entry per name, each name read as `NewDomain` reads
    /// it.
    fn xdns_domains(&mut self, settings: &Value, path: &str) -> Option<Vec<XdnsDomain>> {
        let entries = match settings.get("domains") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(entries)) => entries,
            Some(_) => {
                self.error(format!("{path}.domains"), "xdns domains must be an array");
                return None;
            }
        };
        let mut domains = Vec::new();
        let mut valid = true;
        for (i, entry) in entries.iter().enumerate() {
            let path = format!("{path}.domains[{i}]");
            if !entry.is_object() {
                self.error(path, "an xdns domain must be an object");
                valid = false;
                continue;
            }
            self.reject_unknown_fields(entry, &path, &surface::XDNS_DOMAIN);
            let names = self.go_string_list_at(entry, "names", format!("{path}.names"));
            let len_limit = self.go_int32_at(entry, "lenLimit", format!("{path}.lenLimit"));
            let label_limit = self.go_int32_at(entry, "labelLimit", format!("{path}.labelLimit"));
            let types = self.xdns_types(entry, &format!("{path}.types"));
            let edns0 = self.go_int32_at(entry, "edns0", format!("{path}.edns0"));
            let (Some(names), Some(len_limit), Some(label_limit), Some(types), Some(edns0)) =
                (names, len_limit, label_limit, types, edns0)
            else {
                valid = false;
                continue;
            };
            let len_limit = if len_limit == 0 { 255 } else { len_limit };
            let label_limit = if label_limit == 0 { 63 } else { label_limit };
            // Go keeps the low 16 bits of a size.
            let edns0 = edns0 as u16;
            for (j, name) in names.into_iter().enumerate() {
                if let Err(message) = check_domain(&name, len_limit, label_limit, edns0) {
                    self.error(format!("{path}.names[{j}]"), message);
                    valid = false;
                    continue;
                }
                domains.push(XdnsDomain {
                    name,
                    len_limit,
                    label_limit,
                    types: types.clone(),
                    edns0,
                });
            }
        }
        valid.then_some(domains)
    }

    /// `types`: record types, each kept to 16 bits as Go converts it. Xray
    /// reads them only at dial, where one it does not know fails every
    /// dial; here it is refused.
    fn xdns_types(&mut self, entry: &Value, path: &str) -> Option<Vec<u16>> {
        let items = match entry.get("types") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(items)) => items,
            Some(_) => {
                self.error(path, "xdns types must be an array of numbers");
                return None;
            }
        };
        let mut types = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let value = match item {
                Value::Null => Some(0),
                _ => item.as_i64().and_then(|value| i32::try_from(value).ok()),
            };
            match value.map(|value| value as u16) {
                Some(qtype @ (1 | 5 | 16 | 28)) => types.push(qtype),
                Some(_) => {
                    self.error(
                        format!("{path}[{i}]"),
                        "xdns record types are A (1), CNAME (5), TXT (16) and AAAA (28)",
                    );
                    return None;
                }
                None => {
                    self.error(format!("{path}[{i}]"), "must be a 32-bit integer");
                    return None;
                }
            }
        }
        Some(types)
    }

    /// `resolvers`: every address of every entry. `worker` is read and, as
    /// Xray reads it, only DNS over HTTPS would use it.
    fn xdns_resolvers(&mut self, settings: &Value, path: &str) -> Option<Vec<XdnsResolver>> {
        let entries = match settings.get("resolvers") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(entries)) => entries,
            Some(_) => {
                self.error(
                    format!("{path}.resolvers"),
                    "xdns resolvers must be an array",
                );
                return None;
            }
        };
        let mut resolvers = Vec::new();
        let mut valid = true;
        for (i, entry) in entries.iter().enumerate() {
            let path = format!("{path}.resolvers[{i}]");
            if !entry.is_object() {
                self.error(path, "an xdns resolver must be an object");
                valid = false;
                continue;
            }
            self.reject_unknown_fields(entry, &path, &surface::XDNS_RESOLVER);
            for key in ["tlsConfig", "quicConfig"] {
                if entry.get(key).is_some_and(|value| !value.is_null()) {
                    self.error(
                        format!("{path}.{key}"),
                        "tlsConfig and quicConfig are for DNS over HTTPS resolvers, which xray-rust does not support yet",
                    );
                    valid = false;
                }
            }
            if self
                .go_int32_at(entry, "worker", format!("{path}.worker"))
                .is_none()
            {
                valid = false;
            }
            let Some(addrs) = self.go_string_list_at(entry, "addrs", format!("{path}.addrs"))
            else {
                valid = false;
                continue;
            };
            for (j, addr) in addrs.iter().enumerate() {
                match resolver_address(addr) {
                    Ok(resolver) => resolvers.push(resolver),
                    Err(message) => {
                        self.error(format!("{path}.addrs[{j}]"), message);
                        valid = false;
                    }
                }
            }
        }
        valid.then_some(resolvers)
    }
}

/// `NewDomain`'s checks, in its order, with Go's IDNA conversion. A name Go
/// accepts and then cannot pack, which panics Xray's client at its first
/// query, is refused: an empty label or one longer than 63 bytes.
fn check_domain(name: &str, len_limit: i32, label_limit: i32, edns0: u16) -> Result<(), String> {
    if name.contains("..") {
        return Err("an xdns domain cannot have an empty label".into());
    }
    if !(0..=255).contains(&len_limit) {
        return Err("lenLimit must be 0 to 255".into());
    }
    if !(0..=63).contains(&label_limit) {
        return Err("labelLimit must be 0 to 63".into());
    }
    if edns0 != 0 && !(512..=4096).contains(&edns0) {
        return Err("edns0 must be 0 or 512 to 4096".into());
    }
    if let Err(label) = idna_to_ascii(name) {
        return Err(format!("the label {label:?} is not valid IDNA"));
    }
    if name
        .split('.')
        .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(
            "every label of an xdns domain must be 1 to 63 bytes: Xray-core accepts this one and its client panics at the first query"
                .into(),
        );
    }
    // The name on the wire, with its trailing dot.
    let length = name.len() + 1;
    if length > 255 {
        return Err("the xdns domain is longer than 254 bytes".into());
    }
    let len_limit = len_limit as usize;
    let label_limit = label_limit as usize;
    if len_limit < length + 1 {
        return Err("lenLimit is shorter than the domain".into());
    }
    let room = len_limit - length - 1;
    let mut total = room / (label_limit + 1) * label_limit;
    let left = room % (label_limit + 1);
    if left > 1 {
        total += left - 1;
    }
    if total * 5 / 8 < 17 {
        return Err("lenLimit and labelLimit leave a query under 17 bytes".into());
    }
    Ok(())
}

/// `idna.ToASCII` as the Punycode profile runs it, for whether it fails:
/// an `xn--` label that does not decode, or decodes to ASCII alone, and a
/// label holding U+FFFD, which it will not encode. The failing label is
/// returned.
fn idna_to_ascii(name: &str) -> Result<(), String> {
    for label in name.split('.') {
        let unicode = match label.strip_prefix("xn--") {
            Some(encoded) => {
                let decoded = punycode_decode(encoded).ok_or_else(|| encoded.to_owned())?;
                if !decoded.is_empty() && decoded.is_ascii() {
                    return Err(encoded.to_owned());
                }
                decoded
            }
            None => label.to_owned(),
        };
        if unicode.contains('\u{FFFD}') {
            return Err(unicode);
        }
    }
    Ok(())
}

/// Go's `idna` punycode decoder.
fn punycode_decode(encoded: &str) -> Option<String> {
    const BASE: i32 = 36;
    const TMIN: i32 = 1;
    const TMAX: i32 = 26;
    if encoded.is_empty() {
        return Some(String::new());
    }
    let start = encoded.rfind('-').map_or(0, |i| i + 1);
    if start == 1 {
        return None;
    }
    if start == encoded.len() {
        return Some(encoded[..encoded.len() - 1].to_owned());
    }
    let mut output: Vec<char> = if start == 0 {
        Vec::new()
    } else {
        encoded[..start - 1].chars().collect()
    };
    let madd = |a: i32, b: i32, c: i32| -> Option<i32> {
        let product = i64::from(b) * i64::from(c);
        (product <= i64::from(i32::MAX) - i64::from(a)).then(|| a + product as i32)
    };
    let adapt = |mut delta: i32, points: i32, first: bool| {
        delta /= if first { 700 } else { 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + 38)
    };
    let bytes = encoded.as_bytes();
    let mut pos = start;
    let (mut i, mut n, mut bias) = (0i32, 128i32, 72i32);
    while pos < bytes.len() {
        let old = i;
        let mut w = 1;
        let mut k = BASE;
        loop {
            let byte = *bytes.get(pos)?;
            let digit = match byte {
                b'0'..=b'9' => i32::from(byte - b'0') + 26,
                b'A'..=b'Z' => i32::from(byte - b'A'),
                b'a'..=b'z' => i32::from(byte - b'a'),
                _ => return None,
            };
            pos += 1;
            i = madd(i, digit, w)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = madd(0, w, BASE - t)?;
            k += BASE;
        }
        if output.len() >= 1024 {
            return None;
        }
        let x = output.len() as i32 + 1;
        bias = adapt(i - old, x, old == 0);
        n = n.wrapping_add(i / x);
        i %= x;
        // A surrogate is no rune Go keeps: its string holds U+FFFD there,
        // which encoding refuses.
        let c = char::from_u32(u32::try_from(n).ok()?)?;
        output.insert(i as usize, c);
        i += 1;
    }
    Some(output.into_iter().collect())
}

/// One `addrs` entry, as `XDNS.Build` parses it with `url.Parse`: `udp://`
/// when it names no scheme, port 53 when it names none. The host must be
/// an IP address here; Xray-core also resolves a name.
fn resolver_address(addr: &str) -> Result<XdnsResolver, String> {
    let url = if addr.contains("://") {
        addr.to_owned()
    } else {
        format!("udp://{addr}")
    };
    let (scheme, rest) = url.split_once("://").expect("a scheme");
    let protocol = match scheme.to_ascii_lowercase().as_str() {
        "udp" => XdnsProtocol::Udp,
        "tcp" => XdnsProtocol::Tcp,
        "https" => {
            return Err("DNS over HTTPS resolvers are not supported by xray-rust yet".into());
        }
        _ => {
            return Err(format!(
                "xdns resolvers are udp:// or tcp://, not {scheme}://"
            ))
        }
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let (host, after) = bracketed
            .split_once(']')
            .ok_or("an xdns resolver's IPv6 address is missing its ]")?;
        let port = match after {
            "" => "",
            _ => after
                .strip_prefix(':')
                .ok_or("an xdns resolver's port follows a colon")?,
        };
        let ip = host
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| format!("{host:?} is not an IPv6 address"))?;
        (std::net::IpAddr::V6(ip), port)
    } else {
        let (host, port) = host_port.rsplit_once(':').unwrap_or((host_port, ""));
        let ip = host.parse::<std::net::Ipv4Addr>().map_err(|_| {
            format!("an xdns resolver must be an IP address, not {host:?}: xray-rust does not resolve resolver names yet")
        })?;
        (std::net::IpAddr::V4(ip), port)
    };
    // Go's URL port is digits; Xray reads it as a 16-bit number.
    let port = if port.is_empty() {
        53
    } else {
        port.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| port.parse::<u16>().ok())
            .flatten()
            .filter(|&port| port != 0)
            .ok_or_else(|| format!("{port:?} is not a port from 1 to 65535"))?
    };
    Ok(XdnsResolver {
        protocol,
        address: std::net::SocketAddr::new(host, port),
    })
}

#[cfg(test)]
mod tests;
