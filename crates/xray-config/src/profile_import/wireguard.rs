use super::*;
use std::collections::BTreeMap;
use xray_proxy::wireguard::AllowedIp;

type Fields<'a> = BTreeMap<String, Vec<&'a str>>;

pub(super) fn import(text: &str, dns: &[String]) -> Result<ImportedProfile, ImportError> {
    let mut interface = Fields::new();
    let mut peers = Vec::<Fields<'_>>::new();
    let mut interface_seen = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            if interface_seen || !peers.is_empty() {
                return Err(ImportError::Duplicate);
            }
            interface_seen = true;
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            if !interface_seen {
                return Err(ImportError::Syntax);
            }
            if peers.len() == 8 {
                return Err(ImportError::TooLarge);
            }
            peers.push(Fields::new());
            continue;
        }
        if !interface_seen {
            return Err(ImportError::Syntax);
        }
        let (key, value) = line.split_once('=').ok_or(ImportError::Syntax)?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        let in_interface = peers.is_empty();
        let fields = peers.last_mut().unwrap_or(&mut interface);
        let is_peer = key_matches_peer(&key);
        let allowed = if in_interface {
            matches!(
                key.as_str(),
                "privatekey"
                    | "address"
                    | "dns"
                    | "mtu"
                    | "listenport"
                    | "fwmark"
                    | "table"
                    | "saveconfig"
            )
        } else {
            is_peer
        };
        if !allowed {
            return Err(ImportError::Unsupported);
        }
        let entry = fields.entry(key.clone()).or_default();
        if !entry.is_empty() && !matches!(key.as_str(), "address" | "dns" | "allowedips") {
            return Err(ImportError::Duplicate);
        }
        entry.push(value);
    }
    if peers.is_empty() {
        return Err(ImportError::Syntax);
    }
    for (key, accepted) in [
        ("listenport", &["0"][..]),
        ("fwmark", &["0", "off"][..]),
        ("table", &["auto"][..]),
        ("saveconfig", &["false"][..]),
    ] {
        if let Some(value) = optional(&interface, key) {
            if !accepted.iter().any(|s| value.eq_ignore_ascii_case(s)) {
                return Err(ImportError::Unsupported);
            }
        }
    }
    let addresses = list(&interface, "address", 2)?;
    if addresses.is_empty() {
        return Err(ImportError::Configuration);
    }
    let file_dns = list(&interface, "dns", 8)?;
    if !file_dns.is_empty() && !dns.is_empty() {
        return Err(ImportError::Duplicate);
    }
    let dns = dns_ips(if file_dns.is_empty() { dns } else { &file_dns })?;
    let secret = key(&interface, "privatekey")?;
    let mtu = optional(&interface, "mtu")
        .map(number)
        .transpose()?
        .unwrap_or(1420);
    let mut root = SecretJson(json!({"inbounds":[inbound()],
        "outbounds":[{"tag":"direct","protocol":"freedom","settings":{}},
            {"tag":"proxy","protocol":"wireguard","settings":{"secretKey":secret,"address":addresses,"mtu":mtu,"peers":[]}}],
        "dns":{"servers":dns},
        "routing":{"domainStrategy":"IPOnDemand","rules":[]}}));
    let mut all_prefixes = Vec::new();
    let mut server_address = String::new();
    for peer in peers {
        let endpoint = required(&peer, "endpoint")?;
        let (host, _) = host_port(endpoint, None)?;
        if server_address.is_empty() {
            server_address = host;
        }
        let allowed = list(&peer, "allowedips", 256)?;
        if allowed.is_empty() {
            return Err(ImportError::Configuration);
        }
        if all_prefixes.len() + allowed.len() > 256 {
            return Err(ImportError::TooLarge);
        }
        for prefix in &allowed {
            let _: AllowedIp = prefix.parse().map_err(|_| ImportError::Configuration)?;
            // Generic routing unmapped IPv4-mapped IPv6 differs from WG routing.
            let address = prefix.split('/').next().ok_or(ImportError::Syntax)?;
            if matches!(address.parse::<IpAddr>(), Ok(IpAddr::V6(ip)) if ip.to_ipv4_mapped().is_some())
            {
                return Err(ImportError::Unsupported);
            }
        }
        all_prefixes.extend(allowed.iter().cloned());
        let keepalive = optional(&peer, "persistentkeepalive")
            .map(|v| {
                if v.eq_ignore_ascii_case("off") {
                    Ok(0)
                } else {
                    number(v)
                }
            })
            .transpose()?
            .unwrap_or(0);
        let mut settings = json!({"publicKey":key(&peer,"publickey")?,"endpoint":endpoint,"allowedIPs":allowed,"keepAlive":keepalive});
        if peer.contains_key("presharedkey") {
            let psk = key(&peer, "presharedkey")?;
            settings["preSharedKey"] = psk.into();
        }
        root.0["outbounds"][1]["settings"]["peers"]
            .as_array_mut()
            .unwrap()
            .push(settings);
    }
    root.0["routing"]["rules"] = json!([{"type":"field","ip":all_prefixes,"outboundTag":"proxy"}]);
    finish(
        ProfileFormat::Wireguard,
        "WireGuard".into(),
        server_address,
        &root.0,
    )
}
fn key_matches_peer(key: &str) -> bool {
    matches!(
        key,
        "publickey" | "presharedkey" | "allowedips" | "endpoint" | "persistentkeepalive"
    )
}
fn key<'a>(fields: &Fields<'a>, field: &str) -> Result<&'a str, ImportError> {
    let value = required(fields, field)?;
    // wg(8) files use padded standard base64; the core JSON additionally
    // accepts hex/URL-base64, which are deliberately not file syntax here.
    if value.len() != 44
        || !value.ends_with('=')
        || !value.as_bytes()[..43]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
    {
        return Err(ImportError::Configuration);
    }
    xray_proxy::wireguard::KeyMaterial::parse(value).map_err(|_| ImportError::Configuration)?;
    Ok(value)
}
fn optional<'a>(fields: &Fields<'a>, key: &str) -> Option<&'a str> {
    fields.get(key).and_then(|v| v.first().copied())
}
fn required<'a>(fields: &Fields<'a>, key: &str) -> Result<&'a str, ImportError> {
    optional(fields, key)
        .filter(|s| !s.is_empty())
        .ok_or(ImportError::Configuration)
}
fn number(value: &str) -> Result<u16, ImportError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ImportError::Syntax);
    }
    value.parse().map_err(|_| ImportError::Configuration)
}
fn list(fields: &Fields<'_>, key: &str, max: usize) -> Result<Vec<String>, ImportError> {
    let mut output = Vec::new();
    for value in fields
        .get(key)
        .into_iter()
        .flatten()
        .flat_map(|v| v.split(','))
    {
        let value = value.trim();
        if value.is_empty() {
            return Err(ImportError::Syntax);
        }
        if output.len() == max {
            return Err(ImportError::TooLarge);
        }
        output.push(value.into());
    }
    Ok(output)
}
