//! The `masque` outbound and `masqueSettings`, read as Xray-core v26.10.31's
//! `MasqueClientConfig.Build` and `MasqueConfig.Build` read them, and the
//! checks its client makes when it starts.
use super::*;
use crate::{
    MasqueOutboundSettings, MasqueSettings, MasqueWarpSettings, XhttpXmuxSettings,
    MASQUE_DEFAULT_XMUX,
};

mod warp;

/// Xray's `masque.WarpHost` and `masque.WarpPath`, warp's defaults.
pub(crate) const MASQUE_WARP_HOST: &str = "cloudflareaccess.com";
const MASQUE_WARP_PATH: &str = "/";
use base64::Engine as _;
use zeroize::Zeroizing;

/// Xray's `masque.DefaultPath`.
pub(crate) const MASQUE_DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";
/// `remoteDNS` servers the tunnel's resolver asks; Xray-core sets no limit.
const MAX_MASQUE_REMOTE_DNS: usize = 8;
/// Bounds a profile's custom headers; Xray-core sets no limit.
const MAX_MASQUE_HEADERS: usize = 64;
const MAX_MASQUE_HEADER_VALUE: usize = 8 * 1024;

impl Parser<'_> {
    pub(super) fn parse_masque_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<MasqueOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        // Xray-core decodes absent or null settings as `{}`, which has no
        // address.
        let empty = Value::Object(Default::default());
        let settings = match outbound.get("settings") {
            None | Some(Value::Null) => &empty,
            Some(settings @ Value::Object(_)) => settings,
            Some(_) => {
                self.error(path, "MASQUE settings must be an object");
                return None;
            }
        };
        self.reject_unknown_fields(settings, &path, &surface::MASQUE);
        let server = match settings.get("address") {
            None | Some(Value::Null) => {
                self.error(format!("{path}.address"), r#"MASQUE: "address" is not set"#);
                None
            }
            Some(Value::String(address)) => {
                let address = normalize_xray_address_text(address);
                // Xray-core takes an empty or blank address as a domain and
                // fails every dial to it.
                if address.is_empty()
                    || address.len() > 253
                    || address.chars().any(char::is_whitespace)
                {
                    self.error(format!("{path}.address"), "invalid MASQUE server address");
                    None
                } else {
                    Some(
                        address
                            .parse::<IpAddr>()
                            .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip),
                    )
                }
            }
            Some(_) => {
                self.error(
                    format!("{path}.address"),
                    "invalid address: MASQUE address must be a string",
                );
                None
            }
        };
        let port = match settings.get("port") {
            None | Some(Value::Null) => 0,
            Some(raw) => match raw.as_u64().and_then(|port| u16::try_from(port).ok()) {
                Some(port) => port,
                None => {
                    self.error(
                        format!("{path}.port"),
                        "MASQUE port must be an integer from 0 to 65535",
                    );
                    return None;
                }
            },
        };
        if port == 0 {
            self.error(format!("{path}.port"), r#"MASQUE: "port" is not set"#);
        }
        let remote_dns = self.masque_remote_dns(settings, &path)?;
        if port == 0 {
            return None;
        }
        Some(MasqueOutboundSettings {
            server: server?,
            port,
            remote_dns,
        })
    }

    /// `remoteDNS`, Go's `netip.ParseAddr` of each string.
    fn masque_remote_dns(&mut self, settings: &Value, path: &str) -> Option<Vec<IpAddr>> {
        let path = format!("{path}.remoteDNS");
        let values = match settings.get("remoteDNS") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(values)) => values,
            Some(_) => {
                self.error(path, "remoteDNS must be an array of IP addresses");
                return None;
            }
        };
        if values.len() > MAX_MASQUE_REMOTE_DNS {
            self.error(
                &path,
                format!("MASQUE takes at most {MAX_MASQUE_REMOTE_DNS} remoteDNS servers"),
            );
            return None;
        }
        let mut servers = Vec::with_capacity(values.len());
        let mut valid = true;
        for (index, value) in values.iter().enumerate() {
            // Go decodes null as an empty string, which is not an address.
            let text = match value {
                Value::String(text) => text.as_str(),
                Value::Null => "",
                _ => {
                    self.error(
                        format!("{path}[{index}]"),
                        "remoteDNS entries must be strings",
                    );
                    valid = false;
                    continue;
                }
            };
            if text.contains('%') {
                self.error(
                    format!("{path}[{index}]"),
                    format!(
                        r#"MASQUE: invalid "remoteDNS" {text}: a scoped IPv6 address is unsupported"#
                    ),
                );
                valid = false;
                continue;
            }
            match text.parse::<IpAddr>() {
                Ok(ip) => servers.push(ip),
                Err(_) => {
                    self.error(
                        format!("{path}[{index}]"),
                        format!(r#"MASQUE: invalid "remoteDNS" {text}"#),
                    );
                    valid = false;
                }
            }
        }
        valid.then_some(servers)
    }

    pub(super) fn parse_masque_transport(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<MasqueSettings> {
        let path = format!("$.outbounds[{index}].streamSettings.masqueSettings");
        let settings = match stream.and_then(|s| s.get("masqueSettings")) {
            // Xray-core's transport then keeps its registered default: the
            // default path and no xmux at all, so the one tunnel is never
            // retired.
            None | Some(Value::Null) => {
                return Some(MasqueSettings {
                    host: String::new(),
                    path: MASQUE_DEFAULT_PATH.to_owned(),
                    headers: Vec::new(),
                    warp: None,
                    xmux: zero_xhttp_xmux_settings(),
                })
            }
            Some(settings @ Value::Object(_)) => settings,
            Some(_) => {
                self.error(path, "masqueSettings must be an object or null");
                return None;
            }
        };
        self.reject_unknown_fields(settings, &path, &surface::MASQUE_TRANSPORT);
        let host = self.nullable_string_at(settings, "host", format!("{path}.host"));
        let request_path = self.nullable_string_at(settings, "path", format!("{path}.path"));
        let user = self.nullable_string_at(settings, "user", format!("{path}.user"));
        let pass = self.nullable_string_at(settings, "pass", format!("{path}.pass"));
        let headers = self.masque_headers(settings, &path);
        let warp = match settings.get("warp") {
            None | Some(Value::Null) => None,
            Some(warp @ Value::Object(_)) => Some(warp),
            Some(_) => {
                self.error(format!("{path}.warp"), "warp must be an object or null");
                return None;
            }
        };
        let xmux = self.parse_masque_xmux(settings, &path);
        let (host, request_path, user, pass, headers, xmux) =
            (host?, request_path?, user?, pass?, headers?, xmux?);

        let mut valid = true;
        let mut host = host.to_owned();
        let mut request_path = request_path.to_owned();
        let warp = match warp {
            Some(warp) => match self.parse_masque_warp(warp, &format!("{path}.warp"), user, pass) {
                Some(warp) => {
                    if host.is_empty() {
                        host = MASQUE_WARP_HOST.to_owned();
                    }
                    if request_path.is_empty() {
                        request_path = MASQUE_WARP_PATH.to_owned();
                    }
                    Some(warp)
                }
                None => {
                    valid = false;
                    None
                }
            },
            None => None,
        };
        if request_path.is_empty() {
            request_path = MASQUE_DEFAULT_PATH.to_owned();
        }
        let request_path = replace_masque_path_variables(&request_path);
        if !request_path.starts_with('/') || request_path.contains(['{', '}']) {
            self.error(
                format!("{path}.path"),
                format!(
                    r#"invalid "path": {request_path}, only the variables {{target}} and {{ipproto}} are supported"#
                ),
            );
            valid = false;
        }
        if !host.is_empty() && !go_url_host_round_trips(&host) {
            self.error(format!("{path}.host"), format!(r#"invalid "host": {host}"#));
            valid = false;
        }
        let credentials = !user.is_empty() || !pass.is_empty();
        let mut fields: Vec<(String, Zeroizing<String>)> = Vec::with_capacity(headers.len() + 1);
        for (name, value) in headers {
            if !is_http_token(name) || !valid_header_field_value(value) {
                self.error(
                    format!("{path}.headers"),
                    format!(r#"invalid header in "headers": {name:?}"#),
                );
                valid = false;
                continue;
            }
            let lower = name.to_ascii_lowercase();
            if matches!(lower.as_str(), "host" | "capsule-protocol")
                || lower == "authorization" && credentials
            {
                let reason = if lower == "authorization" {
                    r#" when "user" or "pass" is set"#
                } else {
                    ""
                };
                self.error(
                    format!("{path}.headers.{name}"),
                    format!(r#""headers" can't contain "{name}"{reason}"#),
                );
                valid = false;
                continue;
            }
            fields.push((
                canonical_header_name(name),
                Zeroizing::new(value.to_owned()),
            ));
        }
        if credentials {
            if user.contains(':') {
                // Not the value: with a colon in it, it is most likely `name:password`.
                self.error(format!("{path}.user"), r#""user" must not contain ':'"#);
                valid = false;
            }
            // Built in place, so no copy of the credential outlives it.
            let pair = Zeroizing::new(format!("{user}:{pass}"));
            let mut value = Zeroizing::new(String::from("Basic "));
            base64::engine::general_purpose::STANDARD.encode_string(pair.as_bytes(), &mut value);
            fields.push(("Authorization".to_owned(), value));
        }
        // `http.Header.Set` keeps the last value of a name: sort, then let a
        // later duplicate replace an earlier one.
        fields.sort_by(|a, b| a.0.cmp(&b.0));
        let mut deduped: Vec<(String, Zeroizing<String>)> = Vec::with_capacity(fields.len());
        for (name, value) in fields {
            match deduped.last_mut() {
                Some((last, last_value)) if *last == name => *last_value = value,
                _ => deduped.push((name, value)),
            }
        }
        if !valid {
            return None;
        }
        host.shrink_to_fit();
        Some(MasqueSettings {
            host,
            path: request_path,
            headers: deduped,
            warp,
            xmux,
        })
    }

    /// `warp`, as Xray's `MasqueConfig.Build` reads it: no `user` or `pass`
    /// beside it, then the private key, the public key and the addresses,
    /// stopping at the first that fails.
    fn parse_masque_warp(
        &mut self,
        warp: &Value,
        path: &str,
        user: &str,
        pass: &str,
    ) -> Option<MasqueWarpSettings> {
        self.reject_unknown_fields(warp, path, &surface::MASQUE_WARP);
        let private_key = self.nullable_string_at(warp, "privateKey", format!("{path}.privateKey"));
        let public_key = self.nullable_string_at(warp, "publicKey", format!("{path}.publicKey"));
        let address = match warp.get("address") {
            None | Some(Value::Null) => Some(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Value::String(text) => Some(text.clone()),
                    Value::Null => Some(String::new()),
                    _ => None,
                })
                .collect::<Option<Vec<String>>>(),
            Some(_) => None,
        };
        let Some(address) = address else {
            self.error(
                format!("{path}.address"),
                "field `address` must be an array of strings",
            );
            return None;
        };
        let (private_key, public_key) = (private_key?, public_key?);
        if !user.is_empty() || !pass.is_empty() {
            self.error(path, r#""user" and "pass" can't be used with "warp""#);
            return None;
        }
        let private_key = match warp::private_key(private_key) {
            Ok(key) => key,
            Err(error) => {
                self.error(
                    format!("{path}.privateKey"),
                    format!(r#"invalid "privateKey" in "warp": {error}"#),
                );
                return None;
            }
        };
        let public_key = match warp::public_key(public_key) {
            Ok(key) => key,
            Err(error) => {
                self.error(
                    format!("{path}.publicKey"),
                    format!(r#"invalid "publicKey" in "warp": {error}"#),
                );
                return None;
            }
        };
        let addresses = match warp::addresses(&address) {
            Ok(addresses) => addresses,
            Err(error) => {
                self.error(format!("{path}.address"), error);
                return None;
            }
        };
        Some(MasqueWarpSettings {
            private_key,
            public_key,
            addresses,
        })
    }

    /// `headers`, a Go `map[string]string`: null values read as empty.
    fn masque_headers<'a>(
        &mut self,
        settings: &'a Value,
        path: &str,
    ) -> Option<Vec<(&'a str, &'a str)>> {
        let path = format!("{path}.headers");
        let entries = match settings.get("headers") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Object(entries)) => entries,
            Some(_) => {
                self.error(path, "field `headers` must be an object");
                return None;
            }
        };
        if entries.len() > MAX_MASQUE_HEADERS {
            self.error(
                &path,
                format!("MASQUE takes at most {MAX_MASQUE_HEADERS} headers"),
            );
            return None;
        }
        let mut headers = Vec::with_capacity(entries.len());
        let mut valid = true;
        for (name, value) in entries {
            let value = match value {
                Value::String(value) => value.as_str(),
                Value::Null => "",
                _ => {
                    self.error(format!("{path}.{name}"), "header values must be strings");
                    valid = false;
                    continue;
                }
            };
            if value.len() > MAX_MASQUE_HEADER_VALUE {
                self.error(
                    format!("{path}.{name}"),
                    format!("a MASQUE header value takes at most {MAX_MASQUE_HEADER_VALUE} bytes"),
                );
                valid = false;
                continue;
            }
            headers.push((name.as_str(), value));
        }
        valid.then_some(headers)
    }

    /// `xmux`, a non-pointer Go struct: null keeps it zero. An all-zero
    /// value takes MASQUE's defaults.
    fn parse_masque_xmux(&mut self, settings: &Value, path: &str) -> Option<XhttpXmuxSettings> {
        let parsed = self.parse_zeroable_xmux(settings, path)?;
        if parsed.max_connections.to > 0 && parsed.max_concurrency.to > 0 {
            self.error(
                format!("{path}.xmux"),
                "maxConnections cannot be specified together with maxConcurrency",
            );
            return None;
        }
        Some(if parsed == zero_xhttp_xmux_settings() {
            MASQUE_DEFAULT_XMUX
        } else {
            parsed
        })
    }

    /// What Xray-core requires of a `masque` outbound and its stream when
    /// the configuration builds and when its client starts.
    pub(super) fn validate_masque_pair(
        &mut self,
        settings: &OutboundSettings,
        stream: &StreamSettings,
        chained: bool,
        index: usize,
    ) {
        let masque = matches!(settings, OutboundSettings::Masque(_));
        let transport = matches!(stream.transport, StreamTransport::Masque(_));
        if transport && !masque {
            self.error(
                format!("$.outbounds[{index}].streamSettings.network"),
                "the masque transport can only be used by the masque outbound",
            );
            return;
        }
        if !masque {
            return;
        }
        if !transport {
            self.error(
                format!("$.outbounds[{index}].streamSettings.network"),
                "proxy/masque: not masque transport",
            );
            return;
        }
        let StreamSecurity::Tls(tls) = &stream.security else {
            self.error(
                format!("$.outbounds[{index}].streamSettings.security"),
                r#"proxy/masque: MASQUE requires "security": "tls""#,
            );
            return;
        };
        // Xray's HTTP/2 client sends any TE value; this one refuses the
        // request with one other than "trailers", so the config does.
        if masque_uses_http2(&tls.alpn) {
            if let StreamTransport::Masque(masque) = &stream.transport {
                if let Some((name, _)) = masque.headers.iter().find(|(name, value)| {
                    name.eq_ignore_ascii_case("te") && !value.eq_ignore_ascii_case("trailers")
                }) {
                    self.error(
                        format!(
                            "$.outbounds[{index}].streamSettings.masqueSettings.headers.{name}"
                        ),
                        r#"MASQUE over HTTP/2 can't send a "TE" header other than "trailers""#,
                    );
                }
            }
        }
        if chained {
            self.error(
                format!("$.outbounds[{index}].proxySettings"),
                "MASQUE outbound chaining is unsupported",
            );
        }
    }
}

/// Xray's `usesHTTP2`: HTTP/2 when the TLS ALPN list names `h2` and not
/// `h3`; HTTP/3 otherwise, an empty list included.
pub(crate) fn masque_uses_http2(alpn: &[String]) -> bool {
    alpn.iter().any(|p| p == "h2") && !alpn.iter().any(|p| p == "h3")
}

/// The `strings.Replacer` Xray applies to the path. No replacement contains
/// a brace, so replacing in turn gives the replacer's result.
fn replace_masque_path_variables(path: &str) -> String {
    [
        ("{target}", "*"),
        ("{ipproto}", "*"),
        ("{?target,ipproto}", "?target=*&ipproto=*"),
        ("{?ipproto,target}", "?ipproto=*&target=*"),
        ("{&target,ipproto}", "&target=*&ipproto=*"),
        ("{&ipproto,target}", "&ipproto=*&target=*"),
    ]
    .into_iter()
    .fold(path.to_owned(), |path, (from, to)| path.replace(from, to))
}

/// Whether Go 1.27's `url.Parse("https://" + host)` succeeds with `Host`
/// equal to `host`, as Xray's check of `masqueSettings.host` requires.
fn go_url_host_round_trips(host: &str) -> bool {
    // Parse refuses control bytes; '/', '?' and '#' end the authority and
    // '@' starts the host after user information, so the host differs.
    if host
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || matches!(b, b'/' | b'?' | b'#' | b'@'))
    {
        return false;
    }
    // '%' is not allowed either: a host may %-encode only non-ASCII bytes,
    // which unescaping changes, and an IPv6 zone's %25 unescapes to '%', so
    // Host differs either way.
    let allowed =
        |b: u8| b >= 0x80 || b.is_ascii_alphanumeric() || b"!\"$&'()*+,-.:;<=>[]_~".contains(&b);
    if !host.bytes().all(allowed) {
        return false;
    }
    let valid_port = |port: &str| {
        port.is_empty()
            || port
                .strip_prefix(':')
                .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
    };
    match host.rfind('[') {
        Some(0) => {
            let Some(close) = host.rfind(']') else {
                return false;
            };
            if !valid_port(&host[close + 1..]) {
                return false;
            }
            // Only an IPv6 address may be bracketed.
            host[1..close].parse::<std::net::Ipv6Addr>().is_ok()
        }
        Some(_) => false,
        None => match host.find(':') {
            // Go 1.27 refuses a second colon in an http or https host.
            Some(first) => host.rfind(':') == Some(first) && valid_port(&host[first..]),
            None => true,
        },
    }
}

/// `httpguts.ValidHeaderFieldValue`: no control byte but horizontal tab.
fn valid_header_field_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::XhttpRange;

    #[test]
    fn path_variables_are_replaced_as_xrays_replacer_does() {
        assert_eq!(
            replace_masque_path_variables("/masque/{target}/{ipproto}/"),
            "/masque/*/*/"
        );
        assert_eq!(
            replace_masque_path_variables("/m{?target,ipproto}"),
            "/m?target=*&ipproto=*"
        );
        assert_eq!(
            replace_masque_path_variables("/m?a=1{&ipproto,target}"),
            "/m?a=1&ipproto=*&target=*"
        );
        assert_eq!(replace_masque_path_variables("/m/{x}"), "/m/{x}");
    }

    #[test]
    fn hosts_round_trip_as_gos_url_parse_requires() {
        for host in [
            "example.com",
            "example.com:8443",
            "example.com:",
            "[2001:db8::1]",
            "[2001:db8::1]:443",
            "[::ffff:1.2.3.4]",
            "exa_mple.com",
            "a!$&'()*+,;=b",
            "例え.テスト",
            "192.0.2.1",
            "a]b",
        ] {
            assert!(go_url_host_round_trips(host), "{host}");
        }
        for host in [
            "example.com/path",
            "example.com?x",
            "example.com#x",
            "user@example.com",
            "exa mple.com",
            "example.com:port",
            "a:1:2",
            "[1.2.3.4]",
            "[2001:db8::1",
            "x[::1]",
            "[fe80::1%25en0]",
            "ex%41mple.com",
            "a{b",
            "a\tb",
        ] {
            assert!(!go_url_host_round_trips(host), "{host}");
        }
    }

    #[test]
    fn http2_is_chosen_only_for_h2_without_h3() {
        let alpn = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(!masque_uses_http2(&alpn(&[])));
        assert!(!masque_uses_http2(&alpn(&["h3"])));
        assert!(masque_uses_http2(&alpn(&["h2"])));
        assert!(masque_uses_http2(&alpn(&["h2", "http/1.1"])));
        assert!(!masque_uses_http2(&alpn(&["h3", "h2"])));
        assert!(!masque_uses_http2(&alpn(&["http/1.1"])));
    }

    #[test]
    fn default_xmux_is_one_tunnel_reused_for_half_an_hour_or_more() {
        assert_eq!(
            MASQUE_DEFAULT_XMUX.max_connections,
            XhttpRange { from: 1, to: 1 }
        );
        assert_eq!(
            MASQUE_DEFAULT_XMUX.h_max_reusable_secs,
            XhttpRange {
                from: 1_800,
                to: 3_000
            }
        );
    }
}
