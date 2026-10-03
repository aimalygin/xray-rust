//! SIP002 userinfo and percent-encoded SS2022 credentials; plugins fail closed.
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
    if !scheme.eq_ignore_ascii_case("ss") {
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
        .map_or_else(|| "Shadowsocks 2022".into(), |v| v.to_string());
    let (authority, query) = body.split_once('?').map_or((body, ""), |v| v);
    if !query.is_empty() {
        return Err(ImportError::Unsupported);
    }
    let (user, endpoint) = authority.split_once('@').ok_or(ImportError::Syntax)?;
    if endpoint.contains('@') {
        return Err(ImportError::Syntax);
    }
    let endpoint = endpoint.strip_suffix('/').unwrap_or(endpoint);
    let (host, port) = host_port(endpoint, None)?;
    let decoded = hysteria::decode(user)?;
    let credentials = if decoded.contains(':') {
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
    let (method, password) = credentials.split_once(':').ok_or(ImportError::Syntax)?;
    xray_proxy::shadowsocks2022::Method::new(method, password)
        .map_err(|_| ImportError::Configuration)?;
    let mut root = SecretJson(
        json!({"inbounds":[inbound()],"outbounds":[{"tag":"proxy","protocol":"shadowsocks","settings":{"address":host,"port":port,"method":method,"password":password}}],"routing":{"domainStrategy":"AsIs","rules":[]}}),
    );
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        json!({"servers":dns_ips(dns)?})
    };
    finish(ProfileFormat::Shadowsocks2022, name, host, &root.0)
}
