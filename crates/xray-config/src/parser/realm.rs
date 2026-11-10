//! The `realm` UDP mask, as Xray-core v26.10.31's `Realm.Build` reads it.
use super::go_url::{self, Encoding};
use super::*;
use crate::{go_lowercase, RealmIpMode, RealmMask, RealmPortMapping, RealmScheme, RealmStunServer};

impl Parser<'_> {
    /// The `realm` entry of `finalmask.udp`. The stream checks its carrier
    /// and the masks it cannot run with.
    pub(super) fn parse_udp_realm(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<RealmMask> {
        let masks = stream?.pointer("/finalmask/udp")?.as_array()?;
        let i = masks.iter().position(|mask| {
            mask.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| go_lowercase(kind) == "realm")
        })?;
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp[{i}]");
        // Xray-core sends the STUN requests and punch packets through the
        // masks listed after realm. Every one of them but noise mangles
        // them, and Xray-core fails each dial; noise there would announce
        // the STUN and punch packets, which the carrier's masks never see
        // here. A filter there passes them on untouched.
        if masks[i + 1..].iter().any(|mask| !filter::is_filter(mask)) {
            self.error(
                &path,
                "realm must be the last UDP mask: the masks listed after it would wrap its STUN and punch packets; list noise before realm",
            );
        }
        let path = format!("{path}.settings");
        let Some(settings) = masks[i].get("settings").filter(|s| s.is_object()) else {
            self.error(path, "realm settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::REALM_MASK);
        let url = self
            .nullable_string_at(settings, "url", format!("{path}.url"))
            .map(ToOwned::to_owned);
        let stun_servers =
            self.go_string_list_at(settings, "stunServers", format!("{path}.stunServers"));
        let tls_path = format!("{path}.tlsConfig");
        let tls = match settings.get("tlsConfig") {
            None | Some(Value::Null) => Some(None),
            Some(value) if value.is_object() => {
                Some(Some(self.parse_tls_object(Some(value), &tls_path)))
            }
            Some(_) => {
                self.error(&tls_path, "realm tlsConfig must be an object or null");
                None
            }
        };
        let ip_mode = self
            .nullable_string_at(settings, "ipMode", format!("{path}.ipMode"))
            .map(|mode| match go_lowercase(mode).as_ref() {
                "v4" => RealmIpMode::V4,
                "v6" => RealmIpMode::V6,
                // Xray-core reads anything else as dual.
                _ => RealmIpMode::Dual,
            });
        let port_mapping = self.realm_port_mapping(settings, &format!("{path}.portMapping"));
        let (url, stun_servers, tls, ip_mode, port_mapping) =
            (url?, stun_servers?, tls?, ip_mode?, port_mapping?);
        let url_path = format!("{path}.url");
        let endpoint = match realm_url(&url) {
            Ok(endpoint) => endpoint,
            Err(message) => {
                self.error(url_path, message);
                return None;
            }
        };
        let stun_path = format!("{path}.stunServers");
        if stun_servers.is_empty() {
            self.error(&stun_path, "realm needs stunServers");
            return None;
        }
        let mut servers = Vec::with_capacity(stun_servers.len());
        for (j, server) in stun_servers.iter().enumerate() {
            match stun_server(server) {
                Ok(server) => servers.push(server),
                Err(message) => self.error(format!("{stun_path}[{j}]"), message),
            }
        }
        if servers.len() != stun_servers.len() {
            return None;
        }
        Some(RealmMask {
            scheme: endpoint.scheme,
            host: endpoint.host,
            port_text: endpoint.port_text,
            port: endpoint.port,
            token: zeroize::Zeroizing::new(endpoint.token),
            id: endpoint.id,
            stun_servers: servers,
            tls,
            ip_mode,
            port_mapping,
        })
    }

    /// `portMapping`, decoded into Xray-core's `realm.PortMapping`.
    fn realm_port_mapping(
        &mut self,
        settings: &Value,
        path: &str,
    ) -> Option<Option<RealmPortMapping>> {
        let mapping = match settings.get("portMapping") {
            None | Some(Value::Null) => return Some(None),
            Some(mapping) if mapping.is_object() => mapping,
            Some(_) => {
                self.error(path, "realm portMapping must be an object or null");
                return None;
            }
        };
        self.reject_unknown_fields(mapping, path, &surface::REALM_PORT_MAPPING);
        let enabled = self.go_bool_at(mapping, "enabled", format!("{path}.enabled"));
        let timeout = self.go_int64_at(mapping, "timeout", format!("{path}.timeout"));
        let lifetime = self.go_int64_at(mapping, "lifetime", format!("{path}.lifetime"));
        Some(Some(RealmPortMapping {
            enabled: enabled?,
            timeout: timeout?,
            lifetime: lifetime?,
        }))
    }

    /// A Go `int64` field: absent and null are zero, and only an integer
    /// literal within range decodes, as `encoding/json` decodes one.
    fn go_int64_at(&mut self, value: &Value, key: &str, path: String) -> Option<i64> {
        match value.get(key) {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_i64() {
                Some(value) => Some(value),
                None => {
                    self.error(
                        path,
                        format!("field `{key}` must be a 64-bit integer or null"),
                    );
                    None
                }
            },
        }
    }
}

/// What `Realm.Build` takes from the URL.
#[derive(Debug, PartialEq, Eq)]
struct RealmEndpoint {
    scheme: RealmScheme,
    host: String,
    port_text: String,
    port: u16,
    token: String,
    id: String,
}

/// `Realm.Build`'s reading of `url`, then what makes every dial fail.
fn realm_url(raw: &str) -> Result<RealmEndpoint, String> {
    let url = go_url::parse(raw)?;
    let scheme = match url.scheme.as_str() {
        "realm" => RealmScheme::Https,
        "realm+http" => RealmScheme::Http,
        other => {
            return Err(format!(
                "realm url scheme is realm or realm+http, not {other:?}"
            ))
        }
    };
    let host = url.hostname().to_owned();
    if host.is_empty() {
        return Err("realm url needs a host".to_owned());
    }
    let port_text = match url.port() {
        "" if scheme == RealmScheme::Http => "80".to_owned(),
        "" => "443".to_owned(),
        port => port.to_owned(),
    };
    let token = go_url::unescape_bytes(url.user_string().as_bytes(), Encoding::PathSegment)?;
    if token.is_empty() {
        return Err("realm url needs a token before the host".to_owned());
    }
    let escaped_path = url.escaped_path();
    let id = go_url::unescape_bytes(
        escaped_path
            .strip_prefix('/')
            .unwrap_or(&escaped_path)
            .as_bytes(),
        Encoding::PathSegment,
    )?;
    if id.is_empty() {
        return Err("realm url needs a realm name as its path".to_owned());
    }
    // Xray-core accepts the rest and fails every dial.
    let port = port_text
        .parse::<u32>()
        .ok()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|&port| port != 0)
        .ok_or_else(|| format!("realm url port {port_text:?} is not a port from 1 to 65535"))?;
    if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(format!(
            "realm url host {host:?} is neither a name nor an IP address"
        ));
    }
    let token = String::from_utf8(token)
        .map_err(|_| "realm url token must be UTF-8 once unescaped".to_owned())?;
    // Go's HTTP client refuses a header value with a control byte.
    if token.bytes().any(|b| (b < b' ' && b != b'\t') || b == 0x7f) {
        return Err("realm url token must not hold control characters".to_owned());
    }
    let id = String::from_utf8(id)
        .map_err(|_| "realm url name must be UTF-8 once unescaped".to_owned())?;
    Ok(RealmEndpoint {
        scheme,
        host,
        port_text,
        port,
        token,
        id,
    })
}

/// A `stunServers` entry: `net.SplitHostPort`, as `Realm.Build` checks it,
/// then the port Xray-core's client reads with `strconv.Atoi`. It skips an
/// entry whose port does not read and sends nothing to one out of range,
/// waiting out its STUN timeout; both are refused here.
fn stun_server(server: &str) -> Result<RealmStunServer, String> {
    let (host, port_text) = go_split_host_port(server)?;
    let digits = port_text.strip_prefix('+').unwrap_or(port_text);
    let port = (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse::<u64>().ok())
        .flatten()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|&port| port != 0)
        .ok_or_else(|| format!("STUN server port {port_text:?} is not a port from 1 to 65535"))?;
    Ok(RealmStunServer {
        host: host.to_owned(),
        port_text: port_text.to_owned(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_url_as_realm_build_does() {
        let endpoint = realm_url("realm://public@realm.hy2.io/my-server").unwrap();
        assert_eq!(
            endpoint,
            RealmEndpoint {
                scheme: RealmScheme::Https,
                host: "realm.hy2.io".into(),
                port_text: "443".into(),
                port: 443,
                token: "public".into(),
                id: "my-server".into(),
            }
        );
        let endpoint = realm_url("REALM+HTTP://a%2Fb:p%40ss@[2001:db8::1]:08080/x%2Fy").unwrap();
        assert_eq!(endpoint.scheme, RealmScheme::Http);
        assert_eq!(endpoint.host, "2001:db8::1");
        assert_eq!(
            (endpoint.port_text.as_str(), endpoint.port),
            ("08080", 8080)
        );
        assert_eq!(endpoint.token, "a/b:p@ss");
        assert_eq!(endpoint.id, "x/y");
        assert_eq!(realm_url("realm+http://t@h/i").unwrap().port, 80);
        for refused in [
            "",
            "https://t@h/i",
            "realm://h/i",
            "realm://@h/i",
            "realm://t@h",
            "realm://t@h/",
            "realm://t@:443/i",
            "realm://t@h:0/i",
            "realm://t@h:65536/i",
            "realm://t@a:b:1/i",
            "realm://t%0A@h/i",
            "realm://t%FF@h/i",
        ] {
            assert!(realm_url(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn reads_stun_servers_as_atoi_does() {
        let server = stun_server("stun.example.com:+3478").unwrap();
        assert_eq!(
            (server.host.as_str(), server.port),
            ("stun.example.com", 3478)
        );
        assert_eq!(server.port_text, "+3478");
        assert_eq!(
            stun_server("[2001:db8::1]:3478").unwrap().host,
            "2001:db8::1"
        );
        for refused in [
            "stun.example.com",
            "h:",
            "h:0",
            "h:-1",
            "h:x",
            "h:70000",
            "a:b:1",
        ] {
            assert!(stun_server(refused).is_err(), "{refused}");
        }
    }
}
