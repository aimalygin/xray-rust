use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct StartupProbeOptions {
    pub url: String,
    pub timeout: Duration,
    pub outbound_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct ParsedProbeUrl {
    pub(crate) scheme: ProbeScheme,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path_and_query: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ProbeScheme {
    Http,
    Https,
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum StartupProbeError {
    #[error("unsupported startup probe URL `{0}`")]
    UnsupportedUrl(String),
}

#[allow(dead_code)]
pub(crate) fn parse_probe_url(raw: &str) -> Result<ParsedProbeUrl, StartupProbeError> {
    if raw.contains('#') {
        return Err(StartupProbeError::UnsupportedUrl(raw.to_owned()));
    }

    let (scheme, rest, default_port) = if let Some(rest) = raw.strip_prefix("https://") {
        (ProbeScheme::Https, rest, 443)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (ProbeScheme::Http, rest, 80)
    } else {
        return Err(StartupProbeError::UnsupportedUrl(raw.to_owned()));
    };

    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty()
        || authority.contains('@')
        || authority.starts_with(':')
        || contains_ascii_whitespace_or_control(authority)
    {
        return Err(StartupProbeError::UnsupportedUrl(raw.to_owned()));
    }

    let (host, port) = parse_authority(authority, default_port)
        .ok_or_else(|| StartupProbeError::UnsupportedUrl(raw.to_owned()))?;
    let path_and_query = match &rest[authority_end..] {
        "" => "/".to_owned(),
        suffix if suffix.starts_with('/') => suffix.to_owned(),
        suffix if suffix.starts_with('?') => format!("/{suffix}"),
        _ => return Err(StartupProbeError::UnsupportedUrl(raw.to_owned())),
    };
    if !is_valid_request_target(&path_and_query) {
        return Err(StartupProbeError::UnsupportedUrl(raw.to_owned()));
    }

    Ok(ParsedProbeUrl {
        scheme,
        host,
        port,
        path_and_query,
    })
}

fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.starts_with('[') {
        // IPv6 literals need host-kind modeling so Host headers can preserve brackets.
        return None;
    }

    let mut parts = authority.rsplitn(2, ':');
    let last = parts.next()?;
    let maybe_host = parts.next();
    match maybe_host {
        Some(host) => {
            if host.is_empty() || last.is_empty() || host.contains(':') {
                return None;
            }
            Some((host.to_owned(), parse_port(last)?))
        }
        None => Some((authority.to_owned(), default_port)),
    }
}

fn parse_port(raw: &str) -> Option<u16> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    raw.parse::<u16>().ok()
}

fn is_valid_request_target(target: &str) -> bool {
    target.starts_with('/') && !contains_ascii_whitespace_or_control(target)
}

fn contains_ascii_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || ch.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_probe_url_accepts_https_with_default_port() {
        let parsed = parse_probe_url("https://example.com/generate_204").unwrap();

        assert_eq!(
            parsed,
            ParsedProbeUrl {
                scheme: ProbeScheme::Https,
                host: "example.com".to_owned(),
                port: 443,
                path_and_query: "/generate_204".to_owned(),
            }
        );
    }

    #[test]
    fn parse_probe_url_accepts_http_with_custom_port_and_query() {
        let parsed = parse_probe_url("http://probe.test:8080/health?check=1").unwrap();

        assert_eq!(
            parsed,
            ParsedProbeUrl {
                scheme: ProbeScheme::Http,
                host: "probe.test".to_owned(),
                port: 8080,
                path_and_query: "/health?check=1".to_owned(),
            }
        );
    }

    #[test]
    fn parse_probe_url_defaults_empty_path_to_slash() {
        let parsed = parse_probe_url("https://example.com").unwrap();

        assert_eq!(parsed.path_and_query, "/");
    }

    #[test]
    fn parse_probe_url_prefixes_query_only_target_with_slash() {
        let parsed = parse_probe_url("https://example.com?check=1").unwrap();

        assert_eq!(parsed.path_and_query, "/?check=1");
    }

    #[test]
    fn parse_probe_url_rejects_unsupported_scheme() {
        let error = parse_probe_url("ftp://example.com/file").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "ftp://example.com/file")
        );
    }

    #[test]
    fn parse_probe_url_rejects_missing_host() {
        let error = parse_probe_url("https:///generate_204").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https:///generate_204")
        );
    }

    #[test]
    fn parse_probe_url_rejects_authority_whitespace() {
        let error = parse_probe_url("https://exa mple.com/").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://exa mple.com/")
        );
    }

    #[test]
    fn parse_probe_url_rejects_request_target_whitespace() {
        let error = parse_probe_url("https://example.com/a b").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://example.com/a b")
        );
    }

    #[test]
    fn parse_probe_url_rejects_request_target_raw_crlf() {
        let error = parse_probe_url("https://example.com/a\r\nHost:evil").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://example.com/a\r\nHost:evil")
        );
    }

    #[test]
    fn parse_probe_url_rejects_userinfo_authority() {
        let error = parse_probe_url("https://user@example.com/").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://user@example.com/")
        );
    }

    #[test]
    fn parse_probe_url_rejects_userinfo_with_password_authority() {
        let error = parse_probe_url("https://user:pass@example.com/").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://user:pass@example.com/")
        );
    }

    #[test]
    fn parse_probe_url_rejects_invalid_port() {
        let error = parse_probe_url("https://example.com:70000/").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://example.com:70000/")
        );
    }

    #[test]
    fn parse_probe_url_rejects_signed_port() {
        let error = parse_probe_url("https://example.com:+443/").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://example.com:+443/")
        );
    }

    #[test]
    fn parse_probe_url_rejects_non_digit_port() {
        let error = parse_probe_url("https://example.com:443x/").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://example.com:443x/")
        );
    }

    #[test]
    fn parse_probe_url_rejects_ipv6_literal() {
        let error = parse_probe_url("https://[2001:db8::1]/").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://[2001:db8::1]/")
        );
    }

    #[test]
    fn parse_probe_url_rejects_authority_fragment() {
        let error = parse_probe_url("https://example.com#frag").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://example.com#frag")
        );
    }

    #[test]
    fn parse_probe_url_rejects_path_fragment() {
        let error = parse_probe_url("https://example.com/path#frag").unwrap_err();

        assert!(
            matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://example.com/path#frag")
        );
    }
}
