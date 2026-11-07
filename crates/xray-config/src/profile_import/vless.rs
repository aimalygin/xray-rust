use super::*;
use std::collections::BTreeMap;

type Params = BTreeMap<String, Zeroizing<String>>;

const VISION: &str = "xtls-rprx-vision";
const VISION_UDP_443: &str = "xtls-rprx-vision-udp443";

/// Query names the importer understands, in their canonical spelling. Names
/// match case-insensitively, as the platform importers read them. A known
/// name the selected transport and security leave unused is refused, an
/// unknown one is ignored.
const KNOWN: [&str; 26] = [
    "type",
    "encryption",
    "security",
    "flow",
    "host",
    "path",
    "mode",
    "serviceName",
    "authority",
    "sni",
    "fp",
    "alpn",
    "allowInsecure",
    "pbk",
    "sid",
    "spx",
    "pqv",
    "extra",
    "pcs",
    "vcn",
    "ech",
    "echQuery",
    "fm",
    "headerType",
    "heartbeatPeriod",
    "cs",
];

/// Carrier fields that an empty value leaves meaningless on any transport.
const EMPTY_IGNORED: [&str; 10] = [
    "host",
    "path",
    "mode",
    "serviceName",
    "authority",
    "pcs",
    "vcn",
    "ech",
    "echQuery",
    "cs",
];

pub(super) fn import(text: &str, dns: &[String]) -> Result<ImportedProfile, ImportError> {
    let text = text.trim();
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ImportError::Syntax);
    }
    let (scheme, body) = text.split_once("://").ok_or(ImportError::Syntax)?;
    if !scheme.eq_ignore_ascii_case("vless") {
        return Err(ImportError::Unsupported);
    }
    let (body, fragment) = body
        .split_once('#')
        .map_or((body, None), |(a, b)| (a, Some(b)));
    if fragment.is_some_and(|v| v.contains('#')) {
        return Err(ImportError::Syntax);
    }
    let fragment = fragment
        .map(hysteria::decode)
        .transpose()?
        .filter(|v| !v.is_empty());
    let (authority, query) = body.split_once('?').map_or((body, ""), |v| v);
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.contains('/') {
        return Err(ImportError::Syntax);
    }
    let (id, address) = authority.split_once('@').ok_or(ImportError::Syntax)?;
    if address.contains('@') {
        return Err(ImportError::Syntax);
    }
    let id = hysteria::decode(id)?;
    // Read as Xray-core's `uuid.ParseString` reads it, as VMess links are: a
    // UUID with or without its hyphens, or 1 to 30 bytes of text.
    if crate::xray_uuid::parse(&id).is_none() {
        return Err(ImportError::Configuration);
    }
    // Share links carry no default port.
    let (host, port) = host_port(address, None)?;
    let name = fragment.map_or_else(
        || {
            if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        },
        |v| v.to_string(),
    );
    let mut params = query_params(query)?;

    let encryption = params
        .remove("encryption")
        .unwrap_or_else(|| Zeroizing::new("none".into()));
    if encryption.is_empty() {
        return Err(ImportError::UnsupportedParameter("encryption"));
    }
    let encrypted = encryption.as_str() != "none";
    let network = params.get("type").map_or("tcp", |v| v.as_str()).to_owned();
    let security = params
        .entry("security".into())
        .or_insert_with(|| Zeroizing::new("none".into()))
        .to_string();
    let raw = matches!(network.as_str(), "tcp" | "raw");

    let flow = params.remove("flow").filter(|v| !v.is_empty());
    if let Some(flow) = &flow {
        // Xray-core runs Vision on a raw TLS or REALITY connection, or on any
        // carrier inside VLESS encryption.
        if !matches!(flow.as_str(), VISION | VISION_UDP_443)
            || !(encrypted || raw && matches!(security.as_str(), "tls" | "reality"))
        {
            return Err(ImportError::UnsupportedParameter("flow"));
        }
    }
    if security == "reality" && matches!(network.as_str(), "ws" | "websocket" | "httpupgrade") {
        return Err(ImportError::UnsupportedParameter("security"));
    }
    if params
        .remove("allowInsecure")
        .is_some_and(|v| !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false"))
    {
        return Err(ImportError::UnsupportedParameter("allowInsecure"));
    }
    if security == "reality" {
        // REALITY negotiates h2 itself; other ALPN values cannot be honoured.
        if params.remove("alpn").is_some_and(|v| v.as_str() != "h2") {
            return Err(ImportError::UnsupportedParameter("alpn"));
        }
        if !params.contains_key("sni") {
            params.insert("sni".into(), Zeroizing::new(host.clone()));
        }
        // Xray-core reads a missing shortId as the empty one.
        params
            .entry("sid".into())
            .or_insert_with(|| Zeroizing::new(String::new()));
    }
    // Some links percent-encode the XHTTP `extra` JSON twice.
    if let Some(extra) = params.get_mut("extra") {
        if serde_json::from_str::<serde::de::IgnoredAny>(extra).is_err() {
            *extra = hysteria::decode(extra)?;
        }
    }
    if !raw
        && params
            .get("headerType")
            .is_some_and(|v| matches!(v.as_str(), "" | "none"))
    {
        params.remove("headerType");
    }
    if security == "none" && matches!(network.as_str(), "xhttp" | "splithttp") {
        // The platform importers drop TLS fields on a cleartext XHTTP link.
        for key in ["sni", "fp", "alpn"] {
            params.remove(key);
        }
    }
    for key in EMPTY_IGNORED.into_iter().chain(["pqv"]) {
        if params.get(key).is_some_and(|v| v.is_empty()) {
            params.remove(key);
        }
    }

    let mut stream = trojan::stream_settings(&mut params, &host)?;
    if let Some(key) = KNOWN.into_iter().find(|key| params.contains_key(*key)) {
        return Err(ImportError::UnsupportedParameter(key));
    }
    let fm = stream.0.get("finalmask").is_some();
    // The user ID goes straight into the guarded tree: `json!` serializes a
    // copy of any `Value` it embeds, which nothing would wipe.
    let mut root = SecretJson(
        json!({"inbounds":[inbound()],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":host,"port":port,"users":[{"id":id.as_str(),"encryption":encryption.as_str()}]}]},"streamSettings":stream.0.take()}],"routing":{"domainStrategy":"AsIs","rules":[]}}),
    );
    if let Some(flow) = &flow {
        root.0["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] = json!(flow.as_str());
    }
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        json!({"servers":dns_ips(dns)?})
    };
    finish_masked(ProfileFormat::Vless, name, host, &root.0, fm)
}

/// Known names are canonicalised and must not repeat; unknown names, which
/// share-link generators add freely, are dropped.
fn query_params(query: &str) -> Result<Params, ImportError> {
    let mut params = Params::new();
    if query.is_empty() {
        return Ok(params);
    }
    if query.split('&').count() > 32 {
        return Err(ImportError::TooLarge);
    }
    for item in query.split('&') {
        let (key, value) = item.split_once('=').unwrap_or((item, ""));
        let key = hysteria::decode(key)?;
        let value = hysteria::decode(value)?;
        let Some(key) = KNOWN
            .into_iter()
            .find(|known| known.eq_ignore_ascii_case(&key))
        else {
            continue;
        };
        if params.insert(key.into(), value).is_some() {
            return Err(ImportError::Duplicate);
        }
    }
    Ok(params)
}
