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
    let (host, port) = host_port(address, Some(443))?;
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
                _ => return Err(ImportError::Unsupported),
            }
        }
    }
    let mut root = SecretJson(json!({
        "inbounds":[inbound()],
        "outbounds":[{"tag":"proxy","protocol":"hysteria",
            "settings":{"version":2,"address":host,"port":port},
            "streamSettings":{"network":"hysteria","security":"tls",
                "tlsSettings":{"serverName":sni.as_deref().map(String::as_str).unwrap_or(&host),"alpn":["h3"]},
                "hysteriaSettings":{"version":2,"auth":auth.as_str()}}}],
        "routing":{"domainStrategy":"AsIs","rules":[]}
    }));
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        json!({"servers":dns_ips(dns)?})
    };
    finish(ProfileFormat::Hysteria2, name, host, &root.0)
}

fn decode(value: &str) -> Result<Zeroizing<String>, ImportError> {
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
