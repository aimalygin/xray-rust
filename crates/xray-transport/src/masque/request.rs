//! The CONNECT-IP request: its authority, path and header fields, as
//! Xray-core v26.10.31's `establish`, `authority` and `setUserAgent` build
//! them.
use std::net::Ipv6Addr;

use zeroize::Zeroizing;

use crate::stream::masquerade::{
    anchored_chrome_user_agent, anchored_curl_user_agent, anchored_edge_user_agent,
    anchored_firefox_user_agent, anchored_safari_user_agent,
};

/// Xray's `masque.DefaultPath`.
pub const DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";
/// quic-go's `http3.defaultUserAgent`, which Xray's `golang` preset leaves.
pub(crate) const QUIC_GO_USER_AGENT: &str = "quic-go HTTP/3";
/// Xray's `http2DefaultUserAgent`, its HTTP/2 client's `golang` default.
pub(crate) const GO_HTTP2_USER_AGENT: &str = "Go-http-client/2.0";

/// What `masqueSettings` asks of the request. Its `Debug` leaves the header
/// values out, Authorization among them.
#[derive(Clone, PartialEq, Eq)]
pub struct MasqueRequest {
    /// `masqueSettings.host`; empty takes the TLS server name.
    pub host: String,
    /// The path, its template variables already replaced.
    pub path: String,
    /// Header fields with canonical names, Authorization included; the
    /// values are wiped when dropped.
    pub headers: Vec<(String, Zeroizing<String>)>,
}

impl std::fmt::Debug for MasqueRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueRequest")
            .field("host", &self.host)
            .field("path", &self.path)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
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
pub(crate) fn user_agent(headers: &[(String, Zeroizing<String>)]) -> UserAgent {
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

/// Whether a configured field goes out: quic-go and Xray's HTTP/2 client
/// both leave out the authority's and the connection's own fields.
fn is_sent(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// The request's header fields, lowercased and sorted by name, without
/// pseudo-fields: the configured ones, Capsule-Protocol unless WARP over
/// HTTP/2 replaces it, and the User-Agent with `library_default` standing in
/// for the library's own. quic-go sends them in map order, which no order
/// reproduces.
pub(crate) fn request_fields(
    request: &MasqueRequest,
    capsule_protocol: bool,
    library_default: Option<&str>,
) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = request
        .headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("user-agent") && is_sent(name))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
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

/// The request's header fields as Xray's HTTP/2 client writes them: its
/// default User-Agent first when the `golang` preset leaves none, then
/// every field of the request's `http.Header` in the order of its canonical
/// names, lowercased. `extra` holds fields the dial adds, canonical names
/// first: Capsule-Protocol, or WARP's own.
pub(crate) fn h2_request_fields(
    request: &MasqueRequest,
    extra: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut header: Vec<(String, String)> = request
        .headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("user-agent"))
        .map(|(name, value)| (name.clone(), value.to_string()))
        .chain(
            extra
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        )
        .collect();
    let mut fields = Vec::with_capacity(header.len() + 1);
    match user_agent(&request.headers) {
        UserAgent::LibraryDefault => {
            fields.push(("user-agent".to_owned(), GO_HTTP2_USER_AGENT.to_owned()))
        }
        UserAgent::Value(value) => header.push(("User-Agent".to_owned(), value)),
        UserAgent::Omitted => {}
    }
    header.sort_by(|a, b| a.0.cmp(&b.0));
    fields.extend(
        header
            .into_iter()
            .filter(|(name, _)| is_sent(name))
            .map(|(name, value)| (name.to_ascii_lowercase(), value)),
    );
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

    fn field(name: &str, value: &str) -> (String, Zeroizing<String>) {
        (name.to_owned(), Zeroizing::new(value.to_owned()))
    }

    #[test]
    fn user_agent_presets_are_xrays() {
        let with = |value: &str| vec![field("User-Agent", value)];
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
                field("X-Custom", "1"),
                field("Authorization", "Basic dTpw"),
                field("User-Agent", "golang"),
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
    fn connection_fields_stay_out_as_quic_go_and_xray_leave_them() {
        let request = MasqueRequest {
            headers: vec![
                field("Connection", "close"),
                field("Content-Length", "0"),
                field("Keep-Alive", "1"),
                field("Proxy-Connection", "1"),
                field("Transfer-Encoding", "chunked"),
                field("Upgrade", "h2c"),
                field("User-Agent", ""),
                field("X-Kept", "1"),
            ],
            ..MasqueRequest::default()
        };
        let kept = vec![("x-kept".to_owned(), "1".to_owned())];
        assert_eq!(request_fields(&request, false, None), kept);
        assert_eq!(h2_request_fields(&request, &[]), kept);
    }

    #[test]
    fn http2_fields_follow_xrays_client() {
        let mut request = MasqueRequest {
            headers: vec![
                field("Authorization", "Basic dTpw"),
                field("User-Agent", "golang"),
                field("X-A", "1"),
            ],
            ..MasqueRequest::default()
        };
        // The default User-Agent leads; Go sorts the canonical names, and
        // `X-A` sorts before `X-_`, which lowercase names would reverse.
        request.headers.push(field("X-_", "2"));
        assert_eq!(
            h2_request_fields(&request, &[("Capsule-Protocol", "?1")]),
            [
                ("user-agent", GO_HTTP2_USER_AGENT),
                ("authorization", "Basic dTpw"),
                ("capsule-protocol", "?1"),
                ("x-a", "1"),
                ("x-_", "2"),
            ]
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
        );
        request.headers[1].1 = Zeroizing::new("custom/1.0".to_owned());
        assert_eq!(
            h2_request_fields(&request, &[("Capsule-Protocol", "?1")])
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            [
                "authorization",
                "capsule-protocol",
                "user-agent",
                "x-a",
                "x-_"
            ]
        );
    }

    #[test]
    fn debug_leaves_header_values_out() {
        let request = MasqueRequest {
            headers: vec![
                field("Authorization", "Basic c2VjcmV0"),
                field("X-Token", "t0k3n"),
            ],
            ..MasqueRequest::default()
        };
        let debug = format!("{request:?}");
        assert!(
            debug.contains("Authorization") && debug.contains("X-Token"),
            "{debug}"
        );
        assert!(
            !debug.contains("c2VjcmV0") && !debug.contains("t0k3n"),
            "{debug}"
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
