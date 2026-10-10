use super::*;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use std::collections::BTreeMap;
type Fields = BTreeMap<String, Zeroizing<String>>;
// The common base64-JSON dialect is flat. A custom visitor rejects duplicate
// fields instead of silently replacing credentials, and retains no Value tree.
struct LinkFields(Fields);
impl<'de> Deserialize<'de> for LinkFields {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = LinkFields;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("flat VMess profile")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut fields = Fields::new();
                while let Some(key) = map.next_key::<String>()? {
                    if fields.len() >= 32 || fields.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate or excessive fields"));
                    }
                    let mut value = SecretJson(map.next_value::<Value>()?);
                    let text = match &mut value.0 {
                        Value::String(s) => Zeroizing::new(std::mem::take(s)),
                        Value::Number(n) if n.is_u64() => Zeroizing::new(n.to_string()),
                        _ => return Err(serde::de::Error::custom("non-scalar profile field")),
                    };
                    fields.insert(key, text);
                }
                Ok(LinkFields(fields))
            }
        }
        de.deserialize_map(Visitor)
    }
}
fn take(fields: &mut Fields, key: &str, default: &str) -> Zeroizing<String> {
    fields
        .remove(key)
        .unwrap_or_else(|| Zeroizing::new(default.into()))
}
fn insert(fields: &mut Fields, key: &str, value: Zeroizing<String>) -> Result<(), ImportError> {
    if fields.insert(key.into(), value).is_some() {
        Err(ImportError::Duplicate)
    } else {
        Ok(())
    }
}
fn integer(text: &str) -> Result<u32, ImportError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ImportError::Syntax);
    }
    text.parse().map_err(|_| ImportError::Syntax)
}
pub(super) fn import(text: &str, dns: &[String]) -> Result<ImportedProfile, ImportError> {
    let text = text.trim();
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ImportError::Syntax);
    }
    let (scheme, body) = text.split_once("://").ok_or(ImportError::Syntax)?;
    if !scheme.eq_ignore_ascii_case("vmess") {
        return Err(ImportError::Unsupported);
    }
    let (body, fragment) = body
        .split_once('#')
        .map_or((body, None), |(a, b)| (a, Some(b)));
    if fragment.is_some_and(|f| f.contains('#')) {
        return Err(ImportError::Syntax);
    }
    let fragment = fragment
        .map(hysteria::decode)
        .transpose()?
        .filter(|f| !f.is_empty());
    let (host, port, id, name, mut params) = if body.contains('@') {
        let (authority, query) = body.split_once('?').map_or((body, ""), |v| v);
        let (user, endpoint) = authority.split_once('@').ok_or(ImportError::Syntax)?;
        if endpoint.contains('@') {
            return Err(ImportError::Syntax);
        }
        let (host, port) = host_port(endpoint.strip_suffix('/').unwrap_or(endpoint), Some(443))?;
        let mut params = Fields::new();
        if !query.is_empty() {
            if query.split('&').count() > 32 {
                return Err(ImportError::TooLarge);
            }
            for part in query.split('&') {
                let (key, value) = part.split_once('=').ok_or(ImportError::Syntax)?;
                let key = hysteria::decode(key)?;
                let key = match key.as_str() {
                    "scy" => "encryption",
                    "aid" => "alterId",
                    "peer" => "sni",
                    "insecure" => "allowInsecure",
                    k => k,
                };
                insert(&mut params, key, hysteria::decode(value)?)?;
            }
        }
        (host, port, hysteria::decode(user)?, "VMess".into(), params)
    } else {
        let decoded = Zeroizing::new(
            STANDARD
                .decode(body)
                .or_else(|_| STANDARD_NO_PAD.decode(body))
                .or_else(|_| URL_SAFE.decode(body))
                .or_else(|_| URL_SAFE_NO_PAD.decode(body))
                .map_err(|_| ImportError::Syntax)?,
        );
        let LinkFields(mut fields) =
            serde_json::from_slice(&decoded).map_err(|_| ImportError::Syntax)?;
        let version = take(&mut fields, "v", "2");
        if version.as_str() != "2" {
            return Err(ImportError::Unsupported);
        }
        let host = take(&mut fields, "add", "").to_string();
        if !valid_host(&host) {
            return Err(ImportError::Syntax);
        }
        let port = integer(&take(&mut fields, "port", ""))?;
        let port = u16::try_from(port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or(ImportError::Syntax)?;
        let id = take(&mut fields, "id", "");
        let name = take(&mut fields, "ps", "VMess").to_string();
        let network = take(&mut fields, "net", "tcp");
        let header_type = take(&mut fields, "type", "none");
        if !(matches!(header_type.as_str(), "" | "none")
            || network.as_str() == "grpc" && header_type.as_str() == "gun")
        {
            return Err(ImportError::Unsupported);
        }
        let mut params = Fields::new();
        insert(&mut params, "type", network.clone())?;
        let security = take(&mut fields, "tls", "none");
        insert(
            &mut params,
            "security",
            if security.is_empty() {
                Zeroizing::new("none".into())
            } else {
                security
            },
        )?;
        insert(&mut params, "encryption", take(&mut fields, "scy", "auto"))?;
        insert(&mut params, "alterId", take(&mut fields, "aid", "0"))?;
        for key in [
            "sni",
            "alpn",
            "fp",
            "pbk",
            "sid",
            "spx",
            "pqv",
            "experiments",
        ] {
            let value = take(&mut fields, key, "");
            if !value.is_empty() {
                insert(&mut params, key, value)?;
            }
        }
        for (key, field) in [
            (
                "host",
                if network.as_str() == "grpc" {
                    "authority"
                } else {
                    "host"
                },
            ),
            (
                "path",
                if network.as_str() == "grpc" {
                    "serviceName"
                } else {
                    "path"
                },
            ),
        ] {
            let value = take(&mut fields, key, "");
            if !value.is_empty() {
                insert(&mut params, field, value)?;
            }
        }
        if !fields.is_empty() {
            return Err(ImportError::Unsupported);
        }
        (host, port, id, name, params)
    };
    let name = fragment.map_or(name, |f| f.to_string());
    if uuid::Uuid::parse_str(&id).is_err() {
        return Err(ImportError::Configuration);
    }
    if integer(&take(&mut params, "alterId", "0"))? != 0 {
        return Err(ImportError::Unsupported);
    }
    let cipher = take(&mut params, "encryption", "auto");
    let experiments = take(&mut params, "experiments", "");
    if params
        .remove("allowInsecure")
        .is_some_and(|v| !matches!(v.as_str(), "0" | "false"))
    {
        return Err(ImportError::Unsupported);
    }
    params
        .entry("security".into())
        .or_insert_with(|| Zeroizing::new("none".into()));
    let mut stream = trojan::stream_settings(&mut params, &host)?;
    if !params.is_empty() {
        return Err(ImportError::Unsupported);
    }
    let mut root = SecretJson(
        json!({"inbounds":[inbound()],"outbounds":[{"tag":"proxy","protocol":"vmess","settings":{"address":host,"port":port,"id":id.as_str(),"security":cipher.as_str(),"experiments":experiments.as_str()},"streamSettings":stream.0.take()}],"routing":{"domainStrategy":"AsIs","rules":[]}}),
    );
    root.0["dns"] = if dns.is_empty() {
        json!({"queryStrategy":"UseIPv4","fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768,"ttl":60}})
    } else {
        json!({"servers":dns_ips(dns)?})
    };
    finish(ProfileFormat::Vmess, name, host, &root.0)
}
