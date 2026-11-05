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
    let mut insecure = None;
    let mut pin = None;
    let mut fm = None;
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
                    // Go's strconv.ParseBool spellings, as Hysteria's client
                    // reads them; it ignores anything else, which is refused here.
                    let value = match value.as_str() {
                        "0" | "f" | "F" | "false" | "FALSE" | "False" => false,
                        "1" | "t" | "T" | "true" | "TRUE" | "True" => true,
                        _ => return Err(ImportError::Syntax),
                    };
                    if insecure.replace(value).is_some() {
                        return Err(ImportError::Duplicate);
                    }
                }
                "pinSHA256" => {
                    if pin.replace(value).is_some() {
                        return Err(ImportError::Duplicate);
                    }
                }
                "fm" => {
                    if fm.replace(value).is_some() {
                        return Err(ImportError::Duplicate);
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
    // Hysteria's client lowercases the pin and strips `:` and `-`; Xray reads
    // a comma-separated list and strips `:`. Accept both, and let the parser
    // check each digest as it checks canonical JSON.
    let pin = pin
        .map(|pin| Zeroizing::new(pin.replace('-', "")))
        .filter(|pin| pin.split(',').any(|v| !v.trim().is_empty()));
    // A matching leaf pin replaces the CA check, as Xray's pinnedPeerCertSha256
    // does, so `insecure=1` adds nothing to it. Without a pin it would skip
    // verification, which the core refuses.
    if insecure == Some(true) && pin.is_none() {
        return Err(ImportError::Unsupported);
    }
    // Hysteria's URIs carry no Gecko sizes, so its client pads Gecko to its
    // defaults, 512..=1200 bytes.
    let salamander = match (obfs.as_deref(), obfs_password.as_deref()) {
        (None, None) => None,
        (Some(kind), Some(password)) if (4..=4096).contains(&password.len()) => {
            if kind.eq_ignore_ascii_case("salamander") {
                Some((password, None))
            } else if kind.eq_ignore_ascii_case("gecko") {
                Some((password, Some("512-1200")))
            } else {
                return Err(ImportError::Unsupported);
            }
        }
        _ => return Err(ImportError::Unsupported),
    };
    let mut mask = fm
        .filter(|v| !v.is_empty())
        .map(|text| final_mask(&text).map(SecretJson))
        .transpose()?;
    if let Some(mask) = &mut mask {
        // The import acknowledges the missing ChromeParrot shaping, as it does
        // without `fm`; any other value is left for the parser to refuse.
        match mask.0.get_mut("quicParams") {
            None | Some(Value::Null) => mask.0["quicParams"] = json!({"disableChromeParrot":true}),
            Some(Value::Object(quic)) => {
                quic.entry("disableChromeParrot").or_insert(json!(true));
            }
            Some(_) => {}
        }
        match mask.0.get("udp") {
            None | Some(Value::Null) => mask.0["udp"] = json!([]),
            Some(Value::Array(_)) => {}
            Some(_) => return Err(ImportError::UnsupportedParameter("fm")),
        }
    }
    // Remnawave derives `obfs` from the mask's Salamander entry for Hysteria's
    // own client, which ignores `fm`. Both must describe the same mask, which
    // then appears once.
    let salamander = match (&mask, salamander) {
        (Some(mask), Some((password, gecko))) => {
            let found = mask.0["udp"].as_array().is_some_and(|masks| {
                masks.iter().any(|m| {
                    m.get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|t| t.eq_ignore_ascii_case("salamander"))
                        && m.pointer("/settings/password").and_then(Value::as_str)
                            == Some(password.as_str())
                        && m.pointer("/settings/packetSize")
                            .is_some_and(|v| !v.is_null())
                            == gecko.is_some()
                })
            });
            if !found {
                return Err(ImportError::UnsupportedParameter("obfs"));
            }
            None
        }
        (_, salamander) => salamander,
    };
    let mut root = SecretJson(json!({
        "inbounds":[inbound()],
        "outbounds":[{"tag":"proxy","protocol":"hysteria",
            "settings":{"version":2,"address":host,"port":port},
            "streamSettings":{"network":"hysteria","security":"tls",
                "tlsSettings":{"serverName":sni.as_deref().map(String::as_str).unwrap_or(&host),"alpn":["h3"]},
                "hysteriaSettings":{"version":2,"auth":auth.as_str()},
                "finalmask":{"quicParams":{"disableChromeParrot":true},"udp":[]}}}],
        "routing":{"domainStrategy":"AsIs","rules":[]}
    }));
    let has_mask = mask.is_some();
    if let Some(mask) = &mut mask {
        root.0["outbounds"][0]["streamSettings"]["finalmask"] = mask.0.take();
    }
    let masks = root.0["outbounds"][0]["streamSettings"]["finalmask"]["udp"]
        .as_array_mut()
        .unwrap();
    if let Some(ports) = hopping_ports {
        masks.insert(
            0,
            json!({"type":"udphop","settings":{
            "mode":"intervalLocal,intervalRemote","remotePorts":ports}}),
        );
    }
    if let Some((password, gecko)) = salamander {
        let mut mask = json!({"type":"salamander", "settings":{"password":password.as_str()}});
        if let Some(size) = gecko {
            mask["settings"]["packetSize"] = json!(size);
        }
        masks.push(mask);
    }
    if let Some(pin) = &pin {
        root.0["outbounds"][0]["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] =
            json!(pin.as_str());
    }
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        json!({"servers":dns_ips(dns)?})
    };
    finish_masked(ProfileFormat::Hysteria2, name, host, &root.0, has_mask)
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
