//! Bounded, offline mobile profile import shared by the native SDKs.
mod hysteria;
mod wireguard;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_RESULT_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileFormat {
    Hysteria2,
    Wireguard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("profile import exceeds its size limit")]
    TooLarge,
    #[error("invalid profile import request")]
    Request,
    #[error("invalid profile syntax")]
    Syntax,
    #[error("profile contains an unsupported setting")]
    Unsupported,
    #[error("profile contains a duplicate setting")]
    Duplicate,
    #[error("invalid profile name (1..128 UTF-8 bytes, no control characters)")]
    Name,
    #[error("profile requires 1..8 IP DNS servers; set DNS or dnsServers for WireGuard (no search domains)")]
    Dns,
    #[error("profile is outside the supported protocol configuration")]
    Configuration,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct SecretText(String);
impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    format: ProfileFormat,
    text: SecretText,
    name: Option<SecretText>,
    #[serde(default)]
    dns_servers: Vec<String>,
}

/// Contains credentials. Debug is redacted; the JSON owner is wiped on drop.
/// Caller input, serialized copies and platform strings remain caller-owned.
pub struct ImportedProfile {
    pub format: ProfileFormat,
    pub name: String,
    pub server_address: String,
    pub config_json: Zeroizing<String>,
}
impl std::fmt::Debug for ImportedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedProfile")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}
impl ImportedProfile {
    pub fn to_json(&self) -> Result<Zeroizing<String>, ImportError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Response<'a> {
            schema_version: u8,
            name: &'a str,
            server_address: &'a str,
            #[serde(rename = "configJSON")]
            config_json: &'a str,
        }
        let text = Zeroizing::new(
            serde_json::to_string(&Response {
                schema_version: 1,
                name: &self.name,
                server_address: &self.server_address,
                config_json: &self.config_json,
            })
            .map_err(|_| ImportError::Configuration)?,
        );
        if text.len() > MAX_RESULT_BYTES {
            return Err(ImportError::TooLarge);
        }
        Ok(text)
    }
}

pub fn import_request(request_json: &str) -> Result<ImportedProfile, ImportError> {
    if request_json.len() > MAX_REQUEST_BYTES {
        return Err(ImportError::TooLarge);
    }
    let request: Request = serde_json::from_str(request_json).map_err(|_| ImportError::Request)?;
    import_profile(
        request.format,
        &request.text.0,
        request.name.as_ref().map(|s| s.0.as_str()),
        &request.dns_servers,
    )
}

pub fn import_profile(
    format: ProfileFormat,
    text: &str,
    name: Option<&str>,
    dns_servers: &[String],
) -> Result<ImportedProfile, ImportError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(ImportError::TooLarge);
    }
    if text.contains('\0') {
        return Err(ImportError::Syntax);
    }
    if let Some(name) = name {
        validate_name(name)?;
    }
    let mut profile = match format {
        ProfileFormat::Hysteria2 => hysteria::import(text, dns_servers)?,
        ProfileFormat::Wireguard => wireguard::import(text, dns_servers)?,
    };
    if let Some(name) = name {
        profile.name = name.into();
    }
    Ok(profile)
}

// Guard JSON credential strings on both success and early-return paths. This
// does not promise erasure of every serde/parser or compiler temporary.
struct SecretJson(Value);
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(wipe),
                Value::Object(o) => o.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
fn finish(
    format: ProfileFormat,
    name: String,
    server_address: String,
    root: &Value,
) -> Result<ImportedProfile, ImportError> {
    validate_name(&name)?;
    let config_json =
        Zeroizing::new(serde_json::to_string(root).map_err(|_| ImportError::Configuration)?);
    let parsed = crate::parse_xray_json(&config_json).map_err(|_| ImportError::Configuration)?;
    if !parsed.diagnostics.is_empty() {
        return Err(ImportError::Configuration);
    }
    Ok(ImportedProfile {
        format,
        name,
        server_address,
        config_json,
    })
}
fn validate_name(name: &str) -> Result<(), ImportError> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(ImportError::Name);
    }
    Ok(())
}
fn inbound() -> Value {
    // No sniffing rewrite: explicit WireGuard IP policy must remain IP policy.
    json!({"tag":"tun-in", "protocol":"tun", "settings":{}})
}
fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return usable_ip(ip);
    }
    host.strip_suffix('.')
        .unwrap_or(host)
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        })
}
fn usable_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(ip) => ip != std::net::Ipv4Addr::BROADCAST,
            IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.to_ipv4_mapped().is_none(),
        }
}
fn dns_ips(values: &[String]) -> Result<Vec<String>, ImportError> {
    if values.is_empty() || values.len() > 8 {
        return Err(ImportError::Dns);
    }
    values
        .iter()
        .map(|value| {
            let ip = value.parse::<IpAddr>().map_err(|_| ImportError::Dns)?;
            if !usable_ip(ip)
                || [
                    "198.18.0.1",
                    "198.18.0.2",
                    "10.7.0.1",
                    "fd00:7872::1",
                    "fd00:7872::2",
                ]
                .iter()
                .any(|s| s.parse::<IpAddr>() == Ok(ip))
            {
                return Err(ImportError::Dns);
            }
            Ok(ip.to_string())
        })
        .collect()
}
fn port(value: &str) -> Result<u16, ImportError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ImportError::Syntax);
    }
    let number: u16 = value.parse().map_err(|_| ImportError::Syntax)?;
    if number == 0 {
        return Err(ImportError::Syntax);
    }
    Ok(number)
}
fn host_port(value: &str, default_port: Option<u16>) -> Result<(String, u16), ImportError> {
    let (host, suffix) = if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']').ok_or(ImportError::Syntax)?;
        if !matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            return Err(ImportError::Syntax);
        }
        (host, suffix)
    } else {
        let end = value.find(':').unwrap_or(value.len());
        (&value[..end], &value[end..])
    };
    if !valid_host(host) {
        return Err(ImportError::Syntax);
    }
    let port = if suffix.is_empty() {
        default_port.ok_or(ImportError::Syntax)?
    } else {
        port(suffix.strip_prefix(':').ok_or(ImportError::Syntax)?)?
    };
    Ok((host.into(), port))
}
