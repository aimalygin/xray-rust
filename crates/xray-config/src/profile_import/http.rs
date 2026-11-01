//! HTTP CONNECT proxy URIs, with optional TLS and percent-encoded userinfo.
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
    let tls = if scheme.eq_ignore_ascii_case("https") {
        true
    } else if scheme.eq_ignore_ascii_case("http") {
        false
    } else {
        return Err(ImportError::Unsupported);
    };
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
        .map_or_else(
            || if tls { "HTTPS" } else { "HTTP" }.into(),
            |v| v.to_string(),
        );
    let (authority, query) = body.split_once('?').map_or((body, ""), |v| v);
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
    if userinfo.is_none() && encoded_authority(endpoint) {
        return Err(ImportError::Unsupported);
    }
    let (host, port) = host_port(endpoint, Some(if tls { 443 } else { 80 }))?;
    let mut root = SecretJson(json!({
        "inbounds": [inbound()],
        "outbounds": [{"tag": "proxy", "protocol": "http", "settings": {
            "address": host, "port": port
        }, "streamSettings": {"network": "raw", "security": if tls { "tls" } else { "none" }}}],
        "routing": {"domainStrategy": "AsIs", "rules": []}
    }));
    if let Some(userinfo) = userinfo {
        if userinfo.contains(['/', '\\']) {
            return Err(ImportError::Syntax);
        }
        // Split before percent decoding. Never guess Base64: a token-shaped
        // username with an empty password is a valid HTTP Basic account.
        let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        let user = hysteria::decode(user)?;
        let pass = hysteria::decode(pass)?;
        xray_proxy::outbound::HttpAccount::new(user.as_str(), pass.as_str())
            .ok_or(ImportError::Syntax)?;
        let settings = &mut root.0["outbounds"][0]["settings"];
        settings["user"] = json!(user.as_str());
        settings["pass"] = json!(pass.as_str());
    }
    if tls {
        root.0["outbounds"][0]["streamSettings"]["tlsSettings"] =
            json!({"serverName":host,"alpn":["http/1.1"]});
    }
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        // HTTP CONNECT has no UDP relay. Route explicit DNS over TCP through
        // the proxy, retaining the caller's resolver IPs and normal port 53.
        let servers: Vec<_> = dns_ips(dns)?
            .iter()
            .map(|ip| {
                if ip.contains(':') {
                    format!("tcp://[{ip}]:53")
                } else {
                    format!("tcp://{ip}:53")
                }
            })
            .collect();
        json!({"servers":servers})
    };
    finish(ProfileFormat::Http, name, host, &root.0)
}

/// Legacy exporters put Base64 of the whole `user:pass@host:port` in the
/// authority. With the default port it would parse as a one-label host: the
/// profile would point at no server and DNS bootstrap would send the encoded
/// credentials to the carrier resolver. Base64 is still not guessed; such a
/// link is refused like other legacy forms.
fn encoded_authority(endpoint: &str) -> bool {
    !endpoint.contains([':', '.', '['])
        && [URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD, STANDARD]
            .iter()
            .any(|engine| {
                engine.decode(endpoint).is_ok_and(|bytes| {
                    let bytes = Zeroizing::new(bytes);
                    std::str::from_utf8(&bytes).is_ok_and(|text| {
                        text.rsplit_once('@')
                            .is_some_and(|(_, server)| server.contains(':'))
                    })
                })
            })
}
