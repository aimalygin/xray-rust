use super::*;
use std::collections::BTreeMap;

pub(super) fn import(text: &str, dns: &[String]) -> Result<ImportedProfile, ImportError> {
    let text = text.trim();
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ImportError::Syntax);
    }
    let (scheme, body) = text.split_once("://").ok_or(ImportError::Syntax)?;
    if !scheme.eq_ignore_ascii_case("trojan") {
        return Err(ImportError::Unsupported);
    }
    let (body, fragment) = body
        .split_once('#')
        .map_or((body, None), |(a, b)| (a, Some(b)));
    if fragment.is_some_and(|v| v.contains('#')) {
        return Err(ImportError::Syntax);
    }
    let name = fragment
        .map(hysteria::decode)
        .transpose()?
        .filter(|v| !v.is_empty())
        .map_or_else(|| "Trojan".into(), |v| v.to_string());
    let (authority, query) = body.split_once('?').map_or((body, ""), |v| v);
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.contains('/') {
        return Err(ImportError::Syntax);
    }
    let (password, address) = authority.split_once('@').ok_or(ImportError::Syntax)?;
    if address.contains('@') {
        return Err(ImportError::Syntax);
    }
    let password = hysteria::decode(password)?;
    if password.is_empty() || password.len() > xray_proxy::trojan::MAX_PASSWORD_LENGTH {
        return Err(ImportError::Configuration);
    }
    let (host, port) = host_port(address, Some(443))?;
    let mut params = BTreeMap::new();
    if !query.is_empty() {
        if query.split('&').count() > 32 {
            return Err(ImportError::TooLarge);
        }
        for item in query.split('&') {
            let (key, value) = item.split_once('=').ok_or(ImportError::Syntax)?;
            let key = hysteria::decode(key)?;
            let value = hysteria::decode(value)?;
            let key = match key.as_str() {
                "peer" => "sni",
                "insecure" => "allowInsecure",
                key => key,
            }
            .to_owned();
            if params.insert(key, value).is_some() {
                return Err(ImportError::Duplicate);
            }
        }
    }
    if params.remove("flow").is_some_and(|v| !v.is_empty()) {
        return Err(ImportError::Unsupported);
    }
    if params
        .remove("allowInsecure")
        .is_some_and(|v| !matches!(v.as_str(), "0" | "false"))
    {
        return Err(ImportError::Unsupported);
    }
    let mut stream = stream_settings(&mut params, &host)?;
    if !params.is_empty() {
        return Err(ImportError::Unsupported);
    }
    let mut root = SecretJson(
        json!({"inbounds":[inbound()],"outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"address":host,"port":port,"password":password.as_str()},"streamSettings":stream.0.take()}],"routing":{"domainStrategy":"AsIs","rules":[]}}),
    );
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        json!({"servers":dns_ips(dns)?})
    };
    finish(ProfileFormat::Trojan, name, host, &root.0)
}

pub(super) fn stream_settings(
    params: &mut BTreeMap<String, Zeroizing<String>>,
    host: &str,
) -> Result<SecretJson, ImportError> {
    let network = params
        .remove("type")
        .unwrap_or_else(|| Zeroizing::new("tcp".into()));
    let security = params
        .remove("security")
        .unwrap_or_else(|| Zeroizing::new("tls".into()));
    let mut stream = SecretJson(json!({"network":network.as_str(),"security":security.as_str()}));
    match security.as_str() {
        "tls" => {
            let sni = params
                .remove("sni")
                .unwrap_or_else(|| Zeroizing::new(host.into()));
            if !valid_host(&sni) {
                return Err(ImportError::Syntax);
            }
            stream.0["tlsSettings"] = json!({"serverName":sni.as_str()});
            if let Some(fp) = params.remove("fp") {
                stream.0["tlsSettings"]["fingerprint"] = json!(fp.as_str());
            }
            if let Some(alpn) = params.remove("alpn") {
                if alpn.len() > 256 {
                    return Err(ImportError::TooLarge);
                }
                stream.0["tlsSettings"]["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
            }
        }
        "reality" => {
            let sni = params.remove("sni").ok_or(ImportError::Configuration)?;
            let key = params.remove("pbk").ok_or(ImportError::Configuration)?;
            if !valid_host(&sni) {
                return Err(ImportError::Syntax);
            }
            stream.0["realitySettings"] =
                json!({"serverName":sni.as_str(),"publicKey":key.as_str()});
            for (uri, field) in [
                ("sid", "shortId"),
                ("spx", "spiderX"),
                ("fp", "fingerprint"),
                ("pqv", "mldsa65Verify"),
            ] {
                if let Some(value) = params.remove(uri) {
                    stream.0["realitySettings"][field] = json!(value.as_str());
                }
            }
        }
        "none" => {}
        _ => return Err(ImportError::Unsupported),
    }
    let (block, fields): (&str, &[(&str, &str)]) = match network.as_str() {
        "raw" | "tcp" => ("", &[]),
        "ws" | "websocket" => ("wsSettings", &[("host", "host"), ("path", "path")]),
        "httpupgrade" => ("httpupgradeSettings", &[("host", "host"), ("path", "path")]),
        "grpc" => (
            "grpcSettings",
            &[("serviceName", "serviceName"), ("authority", "authority")],
        ),
        "xhttp" | "splithttp" => (
            "xhttpSettings",
            &[("host", "host"), ("path", "path"), ("mode", "mode")],
        ),
        _ => return Err(ImportError::Unsupported),
    };
    if !block.is_empty() {
        stream.0[block] = json!({});
        for (uri, field) in fields {
            if let Some(value) = params.remove(*uri) {
                stream.0[block][*field] = json!(value.as_str());
            }
        }
    }
    Ok(stream)
}
