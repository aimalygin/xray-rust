//! Go 1.27's `net/url` as `url.Parse` reads a URL, for settings Xray-core
//! reads with it. The functions follow `net/url/url.go` line by line: the
//! escaping table of `gen_encoding_table.go`, `parse`, `parseAuthority`,
//! `parseHost` and the accessors `Hostname`, `Port`, `EscapedPath` and
//! `Userinfo.String`. Go strings are bytes; an unescaped value that is not
//! UTF-8 is replaced lossily, and callers that need its bytes refuse it.

/// One of `net/url`'s encoding modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Path,
    PathSegment,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

/// Go's `shouldEscape`, the reference implementation its table encodes.
pub(crate) fn should_escape(c: u8, mode: Encoding) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, Encoding::Host | Encoding::Zone)
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Encoding::Path => return c == b'?',
            Encoding::PathSegment => return matches!(c, b'/' | b';' | b',' | b'?'),
            Encoding::UserPassword => return matches!(c, b'@' | b'/' | b'?' | b':'),
            Encoding::QueryComponent => return true,
            Encoding::Fragment => return false,
            Encoding::Host | Encoding::Zone => {}
        },
        _ => {}
    }
    if mode == Encoding::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
}

fn unhex(c: u8) -> u8 {
    9 * (c >> 6) + (c & 15)
}

/// Go's `EscapeError` text.
fn escape_error(s: &[u8]) -> String {
    format!(
        "invalid URL escape {}",
        go_quote(&String::from_utf8_lossy(s))
    )
}

/// What `strconv.Quote` prints for the short strings errors quote.
fn go_quote(s: &str) -> String {
    format!("{s:?}")
}

/// Go's `unescape`, on bytes.
pub(crate) fn unescape_bytes(s: &[u8], mode: Encoding) -> Result<Vec<u8>, String> {
    let mut n = 0;
    let mut has_plus = false;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                n += 1;
                if i + 2 >= s.len()
                    || !s[i + 1].is_ascii_hexdigit()
                    || !s[i + 2].is_ascii_hexdigit()
                {
                    let rest = &s[i..];
                    return Err(escape_error(&rest[..rest.len().min(3)]));
                }
                // Hosts %-encode only non-ASCII bytes, apart from %25.
                if mode == Encoding::Host && unhex(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                    return Err(escape_error(&s[i..i + 3]));
                }
                if mode == Encoding::Zone {
                    let v = (unhex(s[i + 1]) << 4) | unhex(s[i + 2]);
                    if &s[i..i + 3] != b"%25" && v != b' ' && should_escape(v, Encoding::Host) {
                        return Err(escape_error(&s[i..i + 3]));
                    }
                }
                i += 3;
            }
            b'+' => {
                has_plus = mode == Encoding::QueryComponent;
                i += 1;
            }
            c => {
                if matches!(mode, Encoding::Host | Encoding::Zone)
                    && c < 0x80
                    && should_escape(c, mode)
                {
                    return Err(format!(
                        "invalid character {} in host name",
                        go_quote(&String::from_utf8_lossy(&s[i..i + 1]))
                    ));
                }
                i += 1;
            }
        }
    }
    if n == 0 && !has_plus {
        return Ok(s.to_vec());
    }
    let plus = if mode == Encoding::QueryComponent {
        b' '
    } else {
        b'+'
    };
    let mut out = Vec::with_capacity(s.len() - 2 * n);
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                out.push((unhex(s[i + 1]) << 4) | unhex(s[i + 2]));
                i += 2;
            }
            b'+' => out.push(plus),
            c => out.push(c),
        }
        i += 1;
    }
    Ok(out)
}

/// Go's `escape`.
pub(crate) fn escape(s: &[u8], mode: Encoding) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s {
        if c == b' ' && mode == Encoding::QueryComponent {
            out.push('+');
        } else if should_escape(c, mode) {
            out.push_str(&format!("%{c:02X}"));
        } else {
            out.push(char::from(c));
        }
    }
    out
}

/// A URL's user information, unescaped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Userinfo {
    pub username: Vec<u8>,
    pub password: Option<Vec<u8>>,
}

impl Userinfo {
    /// `Userinfo.String`: both parts escaped again, joined by a colon.
    pub(crate) fn to_go_string(&self) -> String {
        let mut s = escape(&self.username, Encoding::UserPassword);
        if let Some(password) = &self.password {
            s.push(':');
            s.push_str(&escape(password, Encoding::UserPassword));
        }
        s
    }
}

/// The fields of Go's `url.URL` that `url.Parse` fills.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Url {
    pub scheme: String,
    pub opaque: String,
    pub user: Option<Userinfo>,
    pub host: String,
    pub path: Vec<u8>,
    pub raw_path: String,
    /// A `?` with nothing after it ends the URL.
    pub force_query: bool,
    pub raw_query: String,
    pub fragment: Vec<u8>,
}

impl Url {
    /// `URL.Hostname`: the host without its port and brackets.
    pub(crate) fn hostname(&self) -> &str {
        split_host_port(&self.host).0
    }

    /// `URL.Port`: the port's digits, empty when there are none.
    pub(crate) fn port(&self) -> &str {
        split_host_port(&self.host).1
    }

    /// `URL.EscapedPath`.
    pub(crate) fn escaped_path(&self) -> String {
        if !self.raw_path.is_empty() && valid_encoded(self.raw_path.as_bytes(), Encoding::Path) {
            if let Ok(path) = unescape_bytes(self.raw_path.as_bytes(), Encoding::Path) {
                if path == self.path {
                    return self.raw_path.clone();
                }
            }
        }
        if self.path == b"*" {
            return "*".to_owned();
        }
        escape(&self.path, Encoding::Path)
    }

    /// `URL.User.String()`, empty without user information.
    pub(crate) fn user_string(&self) -> String {
        self.user
            .as_ref()
            .map(Userinfo::to_go_string)
            .unwrap_or_default()
    }
}

/// Go's unexported `splitHostPort`: a numeric port after the last colon,
/// and brackets stripped.
fn split_host_port(host_port: &str) -> (&str, &str) {
    let mut host = host_port;
    let mut port = "";
    if let Some(colon) = host.rfind(':') {
        if valid_optional_port(&host[colon..]) {
            port = &host[colon + 1..];
            host = &host[..colon];
        }
    }
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

fn valid_optional_port(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    let Some(digits) = port.strip_prefix(':') else {
        return false;
    };
    digits.bytes().all(|b| b.is_ascii_digit())
}

fn valid_encoded(s: &[u8], mode: Encoding) -> bool {
    s.iter().all(|&c| {
        matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'['
                | b']'
                | b'%'
        ) || !should_escape(c, mode)
    })
}

fn valid_userinfo(s: &str) -> bool {
    s.chars().all(|r| {
        r.is_ascii_alphanumeric()
            || matches!(
                r,
                '-' | '.'
                    | '_'
                    | ':'
                    | '~'
                    | '!'
                    | '$'
                    | '&'
                    | '\''
                    | '('
                    | ')'
                    | '*'
                    | '+'
                    | ','
                    | ';'
                    | '='
                    | '%'
                    | '@'
            )
    })
}

fn get_scheme(raw: &str) -> Result<(&str, &str), String> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok(("", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err("missing protocol scheme".to_owned());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

/// Go's `url.Parse`.
pub(crate) fn parse(raw: &str) -> Result<Url, String> {
    let (u, fragment) = match raw.split_once('#') {
        Some((u, fragment)) => (u, Some(fragment)),
        None => (raw, None),
    };
    let mut url = parse_without_fragment(u).map_err(|e| format!("parse {}: {e}", go_quote(u)))?;
    if let Some(fragment) = fragment.filter(|f| !f.is_empty()) {
        url.fragment = unescape_bytes(fragment.as_bytes(), Encoding::Fragment)
            .map_err(|e| format!("parse {}: {e}", go_quote(raw)))?;
    }
    Ok(url)
}

fn parse_without_fragment(raw: &str) -> Result<Url, String> {
    if raw.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err("net/url: invalid control character in URL".to_owned());
    }
    let mut url = Url::default();
    if raw == "*" {
        url.path = b"*".to_vec();
        return Ok(url);
    }
    let (scheme, mut rest) = get_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();
    let mut rest_owned;
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        url.force_query = true;
        rest = &rest[..rest.len() - 1];
    } else if let Some((before, query)) = rest.split_once('?') {
        url.raw_query = query.to_owned();
        rest = before;
    }
    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_owned();
            return Ok(url);
        }
        let segment = rest.split('/').next().unwrap_or_default();
        if segment.contains(':') {
            return Err("first path segment in URL cannot contain colon".to_owned());
        }
    }
    if (!url.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let authority_and_path = &rest[2..];
        let (authority, path) = match authority_and_path.find('/') {
            Some(i) => (&authority_and_path[..i], &authority_and_path[i..]),
            None => (authority_and_path, ""),
        };
        let (user, host) = parse_authority(&url.scheme, authority)?;
        url.user = user;
        url.host = host;
        rest_owned = path.to_owned();
    } else {
        rest_owned = rest.to_owned();
    }
    let path = unescape_bytes(rest_owned.as_bytes(), Encoding::Path)?;
    if escape(&path, Encoding::Path) != rest_owned {
        url.raw_path = std::mem::take(&mut rest_owned);
    }
    url.path = path;
    Ok(url)
}

fn parse_authority(scheme: &str, authority: &str) -> Result<(Option<Userinfo>, String), String> {
    let at = authority.rfind('@');
    let host = parse_host(scheme, at.map_or(authority, |i| &authority[i + 1..]))?;
    let Some(i) = at else {
        return Ok((None, host));
    };
    let userinfo = &authority[..i];
    if !valid_userinfo(userinfo) {
        return Err("net/url: invalid userinfo".to_owned());
    }
    let user = match userinfo.split_once(':') {
        None => Userinfo {
            username: unescape_bytes(userinfo.as_bytes(), Encoding::UserPassword)?,
            password: None,
        },
        Some((username, password)) => Userinfo {
            username: unescape_bytes(username.as_bytes(), Encoding::UserPassword)?,
            password: Some(unescape_bytes(password.as_bytes(), Encoding::UserPassword)?),
        },
    };
    Ok((Some(user), host))
}

fn parse_host(scheme: &str, host: &str) -> Result<String, String> {
    let lossy = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
    match host.rfind('[') {
        Some(open) if open > 0 => Err("invalid IP-literal".to_owned()),
        Some(_) => {
            let Some(close) = host.rfind(']') else {
                return Err("missing ']' in host".to_owned());
            };
            let colon_port = &host[close + 1..];
            if !valid_optional_port(colon_port) {
                return Err(format!("invalid port {} after host", go_quote(colon_port)));
            }
            let colon_port = lossy(unescape_bytes(colon_port.as_bytes(), Encoding::Host)?);
            let hostname = &host[1..close];
            let unescaped = match hostname.find("%25") {
                Some(zone) => {
                    let mut part = unescape_bytes(&hostname.as_bytes()[..zone], Encoding::Host)?;
                    part.extend(unescape_bytes(
                        &hostname.as_bytes()[zone..],
                        Encoding::Zone,
                    )?);
                    lossy(part)
                }
                None => lossy(unescape_bytes(hostname.as_bytes(), Encoding::Host)?),
            };
            // Only an IPv6 address goes in brackets.
            match parse_netip_addr(&unescaped) {
                Some(true) => Err("invalid IP-literal".to_owned()),
                Some(false) => Ok(format!("[{unescaped}]{colon_port}")),
                None => Err(format!(
                    "invalid host: ParseAddr({}): unable to parse IP",
                    go_quote(&unescaped)
                )),
            }
        }
        None => {
            if let Some(first) = host.find(':') {
                let last = host.rfind(':').expect("a colon");
                // Go keeps the first colon for http and https unless
                // GODEBUG urlstrictcolons=0; Xray-core's other schemes take
                // the last.
                let i = if last != first && !matches!(scheme, "http" | "https") {
                    last
                } else {
                    first
                };
                let colon_port = &host[i..];
                if !valid_optional_port(colon_port) {
                    return Err(format!("invalid port {} after host", go_quote(colon_port)));
                }
            }
            Ok(lossy(unescape_bytes(host.as_bytes(), Encoding::Host)?))
        }
    }
}

/// `netip.ParseAddr`'s verdict: `Some(true)` for IPv4, `Some(false)` for
/// IPv6 with an optional nonempty zone, `None` when it does not parse.
fn parse_netip_addr(s: &str) -> Option<bool> {
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(true);
    }
    let (address, zone) = match s.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (s, None),
    };
    if zone.is_some_and(str::is_empty) {
        return None;
    }
    address.parse::<std::net::Ipv6Addr>().ok().map(|_| false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_as_go_does() {
        assert_eq!(escape(b"a/b c?", Encoding::PathSegment), "a%2Fb%20c%3F");
        assert_eq!(escape(b"a/b%c", Encoding::Path), "a/b%25c");
        assert_eq!(escape(b"u:p@!", Encoding::UserPassword), "u%3Ap%40%21");
        assert_eq!(
            unescape_bytes(b"a%2fb+c", Encoding::PathSegment).unwrap(),
            b"a/b+c"
        );
        assert!(unescape_bytes(b"%zz", Encoding::Path).is_err());
        assert!(unescape_bytes(b"%41", Encoding::Host).is_err());
        assert_eq!(
            unescape_bytes(b"%C3%A9", Encoding::Host).unwrap(),
            "é".as_bytes()
        );
    }

    #[test]
    fn parses_authority_path_and_port() {
        let url = parse("REALM://t%40k:p@host.example:0443/my%2Frealm?x#y").unwrap();
        assert_eq!(url.scheme, "realm");
        assert_eq!(url.user_string(), "t%40k:p");
        assert_eq!(url.hostname(), "host.example");
        assert_eq!(url.port(), "0443");
        assert_eq!(url.escaped_path(), "/my%2Frealm");
        let url = parse("realm://t@[fe80::1%25en0]:8443/id").unwrap();
        assert_eq!(url.hostname(), "fe80::1%en0");
        assert!(parse("realm://t@[1.2.3.4]/id").is_err());
        assert!(parse("realm://t@ho st/id").is_err());
        assert!(parse("realm://t@host:x/id").is_err());
        assert!(parse("realm://t\u{1}@host/id").is_err());
        let url = parse("realm://t@::1:443/id").unwrap();
        assert_eq!((url.hostname(), url.port()), ("::1", "443"));
    }
}
