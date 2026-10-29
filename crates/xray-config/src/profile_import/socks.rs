//! SOCKS5 URI authorities with optional plain or Base64 userinfo.
use super::*;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};

pub(super) fn import(text: &str, dns: &[String]) -> Result<ImportedProfile, ImportError> {
    let text = text.trim();
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ImportError::Syntax);
    }
    let (scheme, body) = text.split_once("://").ok_or(ImportError::Syntax)?;
    if !scheme.eq_ignore_ascii_case("socks") && !scheme.eq_ignore_ascii_case("socks5") {
        return Err(ImportError::Unsupported);
    }
    let (body, fragment) = body
        .split_once('#')
        .map_or((body, None), |(a, b)| (a, Some(b)));
    if fragment.is_some_and(|f| f.contains('#')) {
        return Err(ImportError::Syntax);
    }
    let name = fragment
        .map(hysteria::decode)
        .transpose()?
        .filter(|v| !v.is_empty())
        .map_or_else(|| "SOCKS5".into(), |v| v.to_string());
    let (authority, query) = body.split_once('?').map_or((body, ""), |v| v);
    // A share link must not silently lose TLS, transport or DNS policy.
    if !query.is_empty() {
        return Err(ImportError::Unsupported);
    }
    let (userinfo, endpoint) = authority
        .split_once('@')
        .map_or((None, authority), |(a, b)| (Some(a), b));
    if endpoint.contains('@') {
        return Err(ImportError::Syntax);
    }
    let endpoint = endpoint.strip_suffix('/').unwrap_or(endpoint);
    let (host, port) = host_port(endpoint, None)?;
    let account = userinfo.map(credentials).transpose()?;
    let mut root = SecretJson(json!({
        "inbounds": [inbound()],
        "outbounds": [{"tag": "proxy", "protocol": "socks", "settings": {
            "address": host, "port": port
        }}],
        "routing": {"domainStrategy": "AsIs", "rules": []}
    }));
    if let Some((user, pass)) = account {
        // v2rayN/v2rayNG export an empty account as Base64(":"). Treat only
        // that complete empty pair as noauth; never drop partial credentials.
        if !user.is_empty() || !pass.is_empty() {
            for value in [&user, &pass] {
                if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
                    return Err(ImportError::Syntax);
                }
            }
            let settings = &mut root.0["outbounds"][0]["settings"];
            settings["user"] = json!(user.as_str());
            settings["pass"] = json!(pass.as_str());
        }
    }
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        json!({"servers":dns_ips(dns)?})
    };
    finish(ProfileFormat::Socks, name, host, &root.0)
}

fn credentials(userinfo: &str) -> Result<(Zeroizing<String>, Zeroizing<String>), ImportError> {
    // Split before decoding so an escaped colon can belong to the username.
    if let Some((user, pass)) = userinfo.split_once(':') {
        return Ok((hysteria::decode(user)?, hysteria::decode(pass)?));
    }
    let decoded = hysteria::decode(userinfo)?;
    let plain = if decoded.contains(':') {
        decoded
    } else {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(decoded.as_bytes())
                .or_else(|_| URL_SAFE.decode(decoded.as_bytes()))
                .or_else(|_| STANDARD_NO_PAD.decode(decoded.as_bytes()))
                .or_else(|_| STANDARD.decode(decoded.as_bytes()))
                .map_err(|_| ImportError::Syntax)?,
        );
        Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| ImportError::Syntax)?
                .to_owned(),
        )
    };
    // Base64 content is literal; decoding its percent signs again would
    // silently change passwords such as "synthetic%40password".
    let (user, pass) = plain.split_once(':').ok_or(ImportError::Syntax)?;
    Ok((Zeroizing::new(user.into()), Zeroizing::new(pass.into())))
}
