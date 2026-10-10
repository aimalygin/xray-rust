use super::*;

pub(super) fn import(text: &str, dns: &[String]) -> Result<ImportedProfile, ImportError> {
    let text = text.trim();
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ImportError::Syntax);
    }
    let (scheme, body) = text.split_once("://").ok_or(ImportError::Syntax)?;
    if !scheme.eq_ignore_ascii_case("hy2") && !scheme.eq_ignore_ascii_case("hysteria2") {
        return Err(ImportError::Unsupported);
    }
    let (body, fragment) = body
        .split_once('#')
        .map_or((body, None), |(a, b)| (a, Some(b)));
    if fragment.is_some_and(|s| s.contains('#')) {
        return Err(ImportError::Syntax);
    }
    let name = fragment
        .map(decode)
        .transpose()?
        .filter(|s| !s.is_empty())
        .map_or_else(|| "Hysteria 2".into(), |s| s.to_string());
    let (authority_path, query) = body.split_once('?').map_or((body, ""), |p| p);
    let authority = authority_path.strip_suffix('/').unwrap_or(authority_path);
    if authority.contains('/') {
        return Err(ImportError::Syntax);
    }
    let (auth, address) = authority.split_once('@').ok_or(ImportError::Syntax)?;
    if address.contains('@') {
        return Err(ImportError::Syntax);
    }
    let auth = decode(auth)?;
    if auth.is_empty() || auth.len() > 4096 || auth.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ImportError::Configuration);
    }
    let (host, port, mut hopping_ports) = hysteria_address(address)?;
    let mut obfs = None;
    let mut obfs_password = None;
    let mut mport_seen = false;
    let mut sni = None;
    let mut insecure_seen = false;
    if !query.is_empty() {
        if query.split('&').count() > 16 {
            return Err(ImportError::TooLarge);
        }
        for item in query.split('&') {
            let (key, value) = item.split_once('=').ok_or(ImportError::Syntax)?;
            let (key, value) = (decode(key)?, decode(value)?);
            match key.as_str() {
                "sni" => {
                    if sni.is_some() {
                        return Err(ImportError::Duplicate);
                    }
                    if !valid_host(&value) {
                        return Err(ImportError::Syntax);
                    }
                    sni = Some(value);
                }
                "insecure" => {
                    if insecure_seen {
                        return Err(ImportError::Duplicate);
                    }
                    insecure_seen = true;
                    if value.as_str() != "0" {
                        return Err(ImportError::Unsupported);
                    }
                }
                "obfs" => {
                    if obfs.replace(value).is_some() {
                        return Err(ImportError::Duplicate);
                    }
                }
                "obfs-password" => {
                    if obfs_password.replace(value).is_some() {
                        return Err(ImportError::Duplicate);
                    }
                }
                "mport" => {
                    if mport_seen || hopping_ports.is_some() {
                        return Err(ImportError::Duplicate);
                    }
                    mport_seen = true;
                    let ports = crate::parser::parse_quic_udp_hop_ports(&value)
                        .map_err(|_| ImportError::Configuration)?;
                    if ports.is_empty() {
                        return Err(ImportError::Configuration);
                    }
                    hopping_ports = Some(value.to_string());
                }
                _ => return Err(ImportError::Unsupported),
            }
        }
    }
    let salamander = match (obfs.as_deref(), obfs_password.as_deref()) {
        (None, None) => None,
        (Some(kind), Some(password))
            if kind.eq_ignore_ascii_case("salamander") && (4..=4096).contains(&password.len()) =>
        {
            Some(password)
        }
        _ => return Err(ImportError::Unsupported),
    };
    let mut root = SecretJson(json!({
        "inbounds":[inbound()],
        "outbounds":[{"tag":"proxy","protocol":"hysteria",
            "settings":{"version":2,"address":host,"port":port},
            "streamSettings":{"network":"hysteria","security":"tls",
                "tlsSettings":{"serverName":sni.as_deref().map(String::as_str).unwrap_or(&host),"alpn":["h3"]},
                "hysteriaSettings":{"version":2,"auth":auth.as_str()}}}],
        "routing":{"domainStrategy":"AsIs","rules":[]}
    }));
    if let Some(password) = salamander {
        root.0["outbounds"][0]["streamSettings"]["finalmask"]["udp"] = json!([
            {"type":"salamander", "settings":{"password":password.as_str()}}
        ]);
    }
    if let Some(ports) = hopping_ports {
        root.0["outbounds"][0]["streamSettings"]["finalmask"]["quicParams"]["udpHop"] =
            json!({"ports":ports});
    }
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        json!({"servers":dns_ips(dns)?})
    };
    finish(ProfileFormat::Hysteria2, name, host, &root.0)
}

pub(super) fn decode(value: &str) -> Result<Zeroizing<String>, ImportError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let high = input.next().and_then(hex).ok_or(ImportError::Syntax)?;
            let low = input.next().and_then(hex).ok_or(ImportError::Syntax)?;
            bytes.push(high * 16 + low);
        } else {
            bytes.push(byte);
        }
    }
    // '+' is a literal plus in URI components, not HTML form encoding.
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| ImportError::Syntax)?
            .into(),
    ))
}
fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hysteria_address(address: &str) -> Result<(String, u16, Option<String>), ImportError> {
    let separator = if address.starts_with('[') {
        address
            .find(']')
            .and_then(|end| address[end + 1..].starts_with(':').then_some(end + 1))
    } else {
        address.find(':')
    };
    let Some(index) = separator else {
        return host_port(address, Some(443)).map(|(host, port)| (host, port, None));
    };
    let ports = &address[index + 1..];
    if !ports.contains(['-', ',']) {
        return host_port(address, Some(443)).map(|(host, port)| (host, port, None));
    }
    let parsed =
        crate::parser::parse_quic_udp_hop_ports(ports).map_err(|_| ImportError::Configuration)?;
    let port = *parsed.first().ok_or(ImportError::Configuration)?;
    let (host, port) = host_port(&format!("{}:{port}", &address[..index]), None)?;
    Ok((host, port, Some(ports.into())))
}
