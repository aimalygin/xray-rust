//! Go 1.27's `net/url` as `url.Parse` reads a URL, for the settings
//! Xray-core reads with it and the requests its transports build. The
//! functions follow `net/url/url.go` line by line: the escaping table of
//! `gen_encoding_table.go`, `parse`, `parseAuthority`, `parseHost`, the
//! accessors `Hostname`, `Port`, `EscapedPath`, `RequestURI` and
//! `Userinfo.String`, and `Values.Encode`. Go strings are bytes; an
//! unescaped value that is not UTF-8 is replaced lossily, and callers that
//! need its bytes refuse it.

/// One of `net/url`'s encoding modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Path,
    PathSegment,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

/// Go's `shouldEscape`, the reference implementation its table encodes.
pub fn should_escape(c: u8, mode: Encoding) -> bool {
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
    format!("invalid URL escape {}", go_quote(s))
}

/// `strconv.Quote`: Go's escapes for control bytes, quotes and backslashes,
/// `\xHH` for a byte that is not UTF-8, and `\u` or `\U` for a character
/// that is not printable. Printable here is what is neither a control nor
/// a space other than U+0020, nearly Go's `IsPrint`.
fn go_quote(s: impl AsRef<[u8]>) -> String {
    let mut out = String::from("\"");
    for chunk in s.as_ref().utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{7}' => out.push_str("\\a"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{b}' => out.push_str("\\v"),
                ' ' => out.push(' '),
                c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                    out.push_str(&format!("\\x{:02x}", c as u32));
                }
                c if !c.is_control() && !c.is_whitespace() => out.push(c),
                c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push_str(&format!("\\U{:08x}", c as u32)),
            }
        }
        for byte in chunk.invalid() {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out.push('"');
    out
}

/// Go's `unescape`, on bytes.
pub fn unescape_bytes(s: &[u8], mode: Encoding) -> Result<Vec<u8>, String> {
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
                        go_quote(&s[i..i + 1])
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
pub fn escape(s: &[u8], mode: Encoding) -> String {
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

/// `url.Values.Encode`: every pair as `key=value`, both query-escaped,
/// sorted by key and joined by `&`, the values of one key in their order.
pub fn encode_values(values: &[(&str, &str)]) -> String {
    let mut sorted: Vec<&(&str, &str)> = values.iter().collect();
    // A stable sort keeps the values of one key in the order given.
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                escape(key.as_bytes(), Encoding::QueryComponent),
                escape(value.as_bytes(), Encoding::QueryComponent)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// A URL's user information, unescaped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Userinfo {
    pub username: Vec<u8>,
    pub password: Option<Vec<u8>>,
}

impl Userinfo {
    /// `Userinfo.String`: both parts escaped again, joined by a colon.
    pub fn to_go_string(&self) -> String {
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
pub struct Url {
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
    /// The fragment as written, when escaping `fragment` again would not
    /// give it back.
    pub raw_fragment: String,
    /// `scheme:/path`: a scheme and a path with no authority at all, which
    /// `String` writes back without `//`.
    pub omit_host: bool,
}

impl Url {
    /// `URL.Hostname`: the host without its port and brackets.
    pub fn hostname(&self) -> &str {
        split_host_port(&self.host).0
    }

    /// `URL.Port`: the port's digits, empty when there are none.
    pub fn port(&self) -> &str {
        split_host_port(&self.host).1
    }

    /// `URL.EscapedPath`.
    pub fn escaped_path(&self) -> String {
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

    /// `URL.RequestURI`: the escaped path, `/` when empty, with the query.
    pub fn request_uri(&self) -> String {
        let mut result = self.opaque.clone();
        if result.is_empty() {
            result = self.escaped_path();
            if result.is_empty() {
                result = "/".to_owned();
            }
        } else if result.starts_with("//") {
            result = format!("{}:{result}", self.scheme);
        }
        if self.force_query || !self.raw_query.is_empty() {
            result.push('?');
            result.push_str(&self.raw_query);
        }
        result
    }

    /// `URL.EscapedFragment`.
    pub fn escaped_fragment(&self) -> String {
        if !self.raw_fragment.is_empty()
            && valid_encoded(self.raw_fragment.as_bytes(), Encoding::Fragment)
        {
            if let Ok(fragment) = unescape_bytes(self.raw_fragment.as_bytes(), Encoding::Fragment) {
                if fragment == self.fragment {
                    return self.raw_fragment.clone();
                }
            }
        }
        escape(&self.fragment, Encoding::Fragment)
    }

    /// `URL.String`.
    pub fn to_go_string(&self) -> String {
        let mut buf = String::new();
        if !self.scheme.is_empty() {
            buf.push_str(&self.scheme);
            buf.push(':');
        }
        if !self.opaque.is_empty() {
            buf.push_str(&self.opaque);
        } else {
            let no_authority = self.omit_host && self.host.is_empty() && self.user.is_none();
            if (!self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some())
                && !no_authority
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    buf.push_str("//");
                }
                if let Some(user) = &self.user {
                    buf.push_str(&user.to_go_string());
                    buf.push('@');
                }
                if !self.host.is_empty() {
                    buf.push_str(&escape(self.host.as_bytes(), Encoding::Host));
                }
            }
            let mut path = self.escaped_path();
            if no_authority && path.starts_with("//") {
                // Read again, the path would turn into an authority.
                buf.push_str("%2F");
                path.remove(0);
            }
            if !path.is_empty() && !path.starts_with('/') && !self.host.is_empty() {
                buf.push('/');
            }
            if buf.is_empty() && path.split('/').next().unwrap_or_default().contains(':') {
                buf.push_str("./");
            }
            buf.push_str(&path);
        }
        if self.force_query || !self.raw_query.is_empty() {
            buf.push('?');
            buf.push_str(&self.raw_query);
        }
        if !self.fragment.is_empty() {
            buf.push('#');
            buf.push_str(&self.escaped_fragment());
        }
        buf
    }

    /// `URL.setPath`: the path from its escaped form, kept as written when
    /// escaping it again would not give it back.
    fn set_path(&mut self, escaped: &str) -> Result<(), String> {
        let path = unescape_bytes(escaped.as_bytes(), Encoding::Path)?;
        self.raw_path = if escape(&path, Encoding::Path) == escaped {
            String::new()
        } else {
            escaped.to_owned()
        };
        self.path = path;
        Ok(())
    }

    /// `URL.ResolveReference`: `reference` read against this URL, as RFC
    /// 3986 section 5.2 says.
    pub fn resolve_reference(&self, reference: &Url) -> Url {
        let mut url = reference.clone();
        if reference.scheme.is_empty() {
            url.scheme = self.scheme.clone();
        }
        if !reference.scheme.is_empty() || !reference.host.is_empty() || reference.user.is_some() {
            // Go ignores the error: the path was validly escaped.
            let _ = url.set_path(&resolve_path(&reference.escaped_path(), ""));
            return url;
        }
        if !reference.opaque.is_empty() {
            url.user = None;
            url.host.clear();
            url.path.clear();
            return url;
        }
        if reference.path.is_empty() && !reference.force_query && reference.raw_query.is_empty() {
            url.raw_query = self.raw_query.clone();
            if reference.fragment.is_empty() {
                url.fragment = self.fragment.clone();
                url.raw_fragment = self.raw_fragment.clone();
            }
        }
        if reference.path.is_empty() && !self.opaque.is_empty() {
            url.opaque = self.opaque.clone();
            url.user = None;
            url.host.clear();
            url.path.clear();
            return url;
        }
        url.host = self.host.clone();
        url.user = self.user.clone();
        let _ = url.set_path(&resolve_path(
            &self.escaped_path(),
            &reference.escaped_path(),
        ));
        url
    }

    /// `URL.Parse`: `reference` parsed, then resolved against this URL.
    pub fn parse_reference(&self, reference: &str) -> Result<Url, String> {
        Ok(self.resolve_reference(&parse(reference)?))
    }

    /// `URL.User.String()`, empty without user information.
    pub fn user_string(&self) -> String {
        self.user
            .as_ref()
            .map(Userinfo::to_go_string)
            .unwrap_or_default()
    }
}

/// Go's unexported `resolvePath`: `reference` against `base`, both escaped,
/// with dot segments removed.
fn resolve_path(base: &str, reference: &str) -> String {
    let full = if reference.is_empty() {
        base.to_owned()
    } else if !reference.starts_with('/') {
        let cut = base.rfind('/').map_or(0, |i| i + 1);
        format!("{}{reference}", &base[..cut])
    } else {
        reference.to_owned()
    };
    if full.is_empty() {
        return String::new();
    }
    let mut dst = String::from("/");
    let mut first = true;
    let mut elem = "";
    let mut remaining = full.as_str();
    let mut found = true;
    while found {
        (elem, remaining, found) = match remaining.split_once('/') {
            Some((elem, rest)) => (elem, rest, true),
            None => (remaining, "", false),
        };
        if elem == "." {
            first = false;
            continue;
        }
        if elem == ".." {
            let written = dst[1..].to_owned();
            dst.clear();
            dst.push('/');
            match written.rfind('/') {
                None => first = true,
                Some(index) => dst.push_str(&written[..index]),
            }
        } else {
            if !first {
                dst.push('/');
            }
            dst.push_str(elem);
            first = false;
        }
    }
    if elem == "." || elem == ".." {
        dst.push('/');
    }
    if dst.len() > 1 && dst.as_bytes()[1] == b'/' {
        dst.remove(0);
    }
    dst
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
pub fn parse(raw: &str) -> Result<Url, String> {
    let (u, fragment) = match raw.split_once('#') {
        Some((u, fragment)) => (u, Some(fragment)),
        None => (raw, None),
    };
    let mut url = parse_without_fragment(u).map_err(|e| format!("parse {}: {e}", go_quote(u)))?;
    if let Some(fragment) = fragment.filter(|f| !f.is_empty()) {
        url.fragment = unescape_bytes(fragment.as_bytes(), Encoding::Fragment)
            .map_err(|e| format!("parse {}: {e}", go_quote(raw)))?;
        if escape(&url.fragment, Encoding::Fragment) != fragment {
            url.raw_fragment = fragment.to_owned();
        }
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
        url.omit_host = !url.scheme.is_empty() && rest.starts_with('/');
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
    fn request_uris_and_values_encode_as_go_does() {
        let url = parse("https://s3.example:9000/bucket/a%20b?list-type=2&prefix=x").unwrap();
        assert_eq!(url.request_uri(), "/bucket/a%20b?list-type=2&prefix=x");
        assert_eq!(parse("https://host").unwrap().request_uri(), "/");
        assert_eq!(parse("https://host/?").unwrap().request_uri(), "/?");
        assert_eq!(parse("https://host/a%2Fb").unwrap().request_uri(), "/a%2Fb");
        assert_eq!(
            encode_values(&[
                ("prefix", "a b+c/"),
                ("list-type", "2"),
                ("max-keys", "1000")
            ]),
            "list-type=2&max-keys=1000&prefix=a+b%2Bc%2F"
        );
        assert_eq!(
            encode_values(&[("b", "2"), ("a", "1"), ("b", "1")]),
            "a=1&b=2&b=1"
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
