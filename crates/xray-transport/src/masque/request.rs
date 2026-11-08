//! The CONNECT-IP request: its authority, path and header fields, as
//! Xray-core v26.10.31's `establish`, `authority` and `setUserAgent` build
//! them.
use std::net::Ipv6Addr;

use crate::stream::masquerade::{
    anchored_chrome_user_agent, anchored_curl_user_agent, anchored_edge_user_agent,
    anchored_firefox_user_agent, anchored_safari_user_agent,
};

/// Xray's `masque.DefaultPath`.
pub const DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";
/// quic-go's `http3.defaultUserAgent`, which Xray's `golang` preset leaves.
pub(crate) const QUIC_GO_USER_AGENT: &str = "quic-go HTTP/3";

/// What `masqueSettings` asks of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueRequest {
    /// `masqueSettings.host`; empty takes the TLS server name.
    pub host: String,
    /// The path, its template variables already replaced.
    pub path: String,
    /// Header fields with canonical names, Authorization included.
    pub headers: Vec<(String, String)>,
}

impl Default for MasqueRequest {
    fn default() -> Self {
        Self {
            host: String::new(),
            path: DEFAULT_PATH.to_owned(),
            headers: Vec::new(),
        }
    }
}

/// Xray's `authority`: `masqueSettings.host`, else the TLS server name
/// without brackets, with the port unless it is 443.
pub fn authority(host: &str, server_name: &str, port: u16) -> String {
    if !host.is_empty() {
        return host.to_owned();
    }
    let name = server_name.strip_prefix('[').unwrap_or(server_name);
    let name = name.strip_suffix(']').unwrap_or(name);
    if port == 443 {
        if name.parse::<Ipv6Addr>().is_ok() {
            return format!("[{name}]");
        }
        return name.to_owned();
    }
    // Go's net.JoinHostPort brackets any host with a colon.
    if name.contains(':') {
        format!("[{name}]:{port}")
    } else {
        format!("{name}:{port}")
    }
}

/// The User-Agent a request carries after Xray's `setUserAgent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UserAgent {
    /// The HTTP library's own default: `golang`.
    LibraryDefault,
    /// No User-Agent at all: an empty value.
    Omitted,
    Value(String),
}

/// Xray's `setUserAgent`: absent means `chrome`; `chrome`, `firefox`,
/// `safari`, `edge` and `curl` are presets; `golang` leaves the library's
/// default and empty sends none.
pub(crate) fn user_agent(headers: &[(String, String)]) -> UserAgent {
    let configured = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        .map(|(_, value)| value.as_str());
    match configured.unwrap_or("chrome") {
        "" => UserAgent::Omitted,
        "chrome" => UserAgent::Value(anchored_chrome_user_agent()),
        "firefox" => UserAgent::Value(anchored_firefox_user_agent()),
        "safari" => UserAgent::Value(anchored_safari_user_agent()),
        "edge" => UserAgent::Value(anchored_edge_user_agent()),
        "curl" => UserAgent::Value(anchored_curl_user_agent()),
        "golang" => UserAgent::LibraryDefault,
        other => UserAgent::Value(other.to_owned()),
    }
}

/// The request's header fields, lowercased and sorted by name, without
/// pseudo-fields: the configured ones, Capsule-Protocol unless WARP over
/// HTTP/2 replaces it, and the User-Agent with `library_default` standing in
/// for the library's own.
pub(crate) fn request_fields(
    request: &MasqueRequest,
    capsule_protocol: bool,
    library_default: Option<&str>,
) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = request
        .headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("user-agent"))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    if capsule_protocol {
        fields.push(("capsule-protocol".to_owned(), "?1".to_owned()));
    }
    match user_agent(&request.headers) {
        UserAgent::Value(value) => fields.push(("user-agent".to_owned(), value)),
        UserAgent::LibraryDefault => {
            if let Some(value) = library_default {
                fields.push(("user-agent".to_owned(), value.to_owned()));
            }
        }
        UserAgent::Omitted => {}
    }
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    fields
}

/// The authority as quic-go's `PunycodeHostPort` sends it: a non-ASCII host
/// in its ASCII form.
pub(crate) fn ascii_authority(authority: &str) -> Option<String> {
    if authority.is_ascii() {
        return Some(authority.to_owned());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(']') && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, Some(port))
        }
        _ => (authority, None),
    };
    let host = idna::domain_to_ascii(host).ok()?;
    Some(match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_is_xrays() {
        for (host, server_name, port, want) in [
            ("", "example.com", 443, "example.com"),
            ("", "example.com", 8443, "example.com:8443"),
            ("", "127.0.0.1", 443, "127.0.0.1"),
            ("", "[2001:db8::1]", 443, "[2001:db8::1]"),
            ("", "[2001:db8::1]", 8443, "[2001:db8::1]:8443"),
            ("", "2001:db8::1", 8443, "[2001:db8::1]:8443"),
            ("proxy.example", "example.com", 8443, "proxy.example"),
        ] {
            assert_eq!(authority(host, server_name, port), want, "{server_name}");
        }
    }

    #[test]
    fn user_agent_presets_are_xrays() {
        let with = |value: &str| vec![("User-Agent".to_owned(), value.to_owned())];
        assert!(matches!(user_agent(&[]), UserAgent::Value(ua) if ua.contains("Chrome/")));
        assert_eq!(user_agent(&with("")), UserAgent::Omitted);
        assert!(
            matches!(user_agent(&with("firefox")), UserAgent::Value(ua) if ua.contains("Firefox/"))
        );
        assert!(
            matches!(user_agent(&with("safari")), UserAgent::Value(ua) if ua.contains("Safari/605"))
        );
        assert!(matches!(user_agent(&with("edge")), UserAgent::Value(ua) if ua.contains("Edg/")));
        assert!(
            matches!(user_agent(&with("curl")), UserAgent::Value(ua) if ua.starts_with("curl/8."))
        );
        assert_eq!(user_agent(&with("golang")), UserAgent::LibraryDefault);
        assert_eq!(
            user_agent(&with("custom/1.0")),
            UserAgent::Value("custom/1.0".to_owned())
        );
    }

    #[test]
    fn fields_are_lowercase_sorted_and_carry_the_capsule_protocol() {
        let request = MasqueRequest {
            headers: vec![
                ("X-Custom".to_owned(), "1".to_owned()),
                ("Authorization".to_owned(), "Basic dTpw".to_owned()),
                ("User-Agent".to_owned(), "golang".to_owned()),
            ],
            ..MasqueRequest::default()
        };
        assert_eq!(
            request_fields(&request, true, Some(QUIC_GO_USER_AGENT)),
            [
                ("authorization".to_owned(), "Basic dTpw".to_owned()),
                ("capsule-protocol".to_owned(), "?1".to_owned()),
                ("user-agent".to_owned(), QUIC_GO_USER_AGENT.to_owned()),
                ("x-custom".to_owned(), "1".to_owned()),
            ]
        );
    }

    #[test]
    fn non_ascii_hosts_go_out_in_punycode() {
        assert_eq!(
            ascii_authority("пример.испытание:8443").as_deref(),
            Some("xn--e1afmkfd.xn--80akhbyknj4f:8443")
        );
        assert_eq!(
            ascii_authority("[2001:db8::1]:443").as_deref(),
            Some("[2001:db8::1]:443")
        );
    }
}
