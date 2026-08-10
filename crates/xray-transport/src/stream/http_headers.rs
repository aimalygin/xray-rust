//! Go-compatible HTTP/1.1 request serialization.
//!
//! Xray writes its requests with Go's `net/http`, whose header order is
//! observable and therefore part of the fingerprint: request line, `Host`,
//! `User-Agent`, then every other header sorted **case-sensitively by the
//! literal map key**. Header names keep whatever casing the caller used —
//! Xray deliberately emits non-canonical names like `Sec-CH-UA` and `DNT`.
//! A Rust HTTP stack would lowercase or reorder these, which is why this is
//! written by hand.

/// Insertion-order-independent header storage that keeps literal key casing.
///
/// Go's `http.Header` is a map, so two keys differing only in case are two
/// distinct headers, and both are emitted. This mirrors that.
#[derive(Debug, Clone, Default)]
pub struct HeaderMap {
    entries: Vec<(String, String)>,
}

const DEFAULT_USER_AGENT: &str = "Go-http-client/1.1";

/// Request-body framing fields written by Go's `Request.Write` before the
/// caller-provided header map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum H1BodyFraming {
    None,
    ContentLength(u64),
    Chunked,
}

impl HeaderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces every existing value for this exact key with one value.
    /// Comparison is case-sensitive, matching Go's map semantics.
    pub fn set(&mut self, key: &str, value: &str) {
        let replacement = value.to_owned();
        let mut found = false;
        self.entries.retain_mut(|(name, existing)| {
            if name != key {
                return true;
            }
            if found {
                return false;
            }
            *existing = replacement.clone();
            found = true;
            true
        });
        if !found {
            self.entries.push((key.to_owned(), replacement));
        }
    }

    /// Appends another value for this exact key without replacing earlier
    /// values, matching Go's `http.Header.Add` value ordering.
    pub fn add(&mut self, key: &str, value: &str) {
        self.entries.push((key.to_owned(), value.to_owned()));
    }

    /// Returns the first value for this exact key, like Go's `Header.Get`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// Iterates literal key/value pairs without exposing the backing storage.
    ///
    /// XHTTP's HTTP/2 composer needs to validate and lowercase these fields;
    /// HTTP/1.1 still uses the original casing and its own Go-compatible sort.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|(name, _)| name != key);
    }
}

/// Serializes a request the way Go's `Request.Write` does.
///
/// `host` becomes the `Host` header; Go carries it in `Request.Host` rather
/// than the header map, which is why it is a separate argument and why it is
/// never subject to the sort. `Host` and `User-Agent` are both excluded from
/// the sorted remainder for the same reason: Go writes each from its own
/// `Request` field (`Request.Host`, and the `User-Agent` line emitted above),
/// so a map entry under either name would duplicate a line this function
/// already wrote. Go's own writer excludes both via `reqWriteExcludeHeader`;
/// an unfiltered `Host` entry would produce two `Host:` lines, an RFC 7230
/// §5.4 violation most servers reject outright.
pub fn serialize_request(method: &str, path: &str, host: &str, headers: &HeaderMap) -> Vec<u8> {
    serialize_request_with_framing(method, path, host, headers, H1BodyFraming::None)
}

/// Serializes a request with Go's body-framing header placement.
///
/// `Content-Length` and `Transfer-Encoding` are derived from request body
/// state in `net/http`, not emitted as ordinary map entries. They therefore
/// appear immediately after `User-Agent`, before the sorted header map.
pub(crate) fn serialize_request_with_framing(
    method: &str,
    path: &str,
    host: &str,
    headers: &HeaderMap,
    framing: H1BodyFraming,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    let host = go_host_header(host);
    out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());

    let user_agent = headers.get("User-Agent").unwrap_or(DEFAULT_USER_AGENT);
    let user_agent = sanitize_header_value(user_agent);
    if !user_agent.is_empty() {
        out.extend_from_slice(format!("User-Agent: {user_agent}\r\n").as_bytes());
    }

    match framing {
        H1BodyFraming::None => {}
        H1BodyFraming::ContentLength(length) => {
            out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
        H1BodyFraming::Chunked => {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
    }

    let mut rest: Vec<&(String, String)> = headers
        .entries
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "User-Agent" | "Host" | "Content-Length" | "Transfer-Encoding" | "Trailer"
            )
        })
        .collect();
    rest.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));

    for (name, value) in rest {
        if !valid_header_name(name) {
            continue;
        }
        let value = sanitize_header_value(value);
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    out.extend_from_slice(b"\r\n");
    out
}

/// Converts an IDN to the form Go's `httpguts.PunycodeHostPort` writes and
/// applies its deliberately lenient Host-header byte allowlist. Invalid input
/// becomes an empty Host value, matching `Request.Write` for direct requests
/// and, crucially, preventing config text from creating a second header line.
fn go_host_header(host: &str) -> String {
    let ascii = if host.is_ascii() {
        host.to_owned()
    } else {
        let (name, port) = split_non_ascii_host_port(host);
        let Ok(name) = idna::domain_to_ascii(name) else {
            return String::new();
        };
        match port {
            Some("") | None => name,
            Some(port) => format!("{name}:{port}"),
        }
    };

    if ascii.bytes().all(valid_host_byte) {
        ascii
    } else {
        String::new()
    }
}

/// `net.SplitHostPort` is only relevant on the non-ASCII branch in Go. The
/// stream transport normally supplies a bare host, but preserving this case
/// keeps the serializer correct for its public test surface too.
fn split_non_ascii_host_port(host: &str) -> (&str, Option<&str>) {
    let Some((name, port)) = host.rsplit_once(':') else {
        return (host, None);
    };
    if name.contains(':') {
        (host, None)
    } else {
        (name, Some(port))
    }
}

fn valid_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b':'
                | b';'
                | b'='
                | b'['
                | b']'
                | b'_'
                | b'~'
        )
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn sanitize_header_value(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .trim_matches([' ', '\t'])
        .to_owned()
}

/// Escapes a decoded `url.URL.Path` exactly as Go's `EscapedPath` does.
/// Existing percent signs are data here and are therefore escaped too.
pub(crate) fn escape_decoded_path(path: &str) -> String {
    escape_url_component(
        if path.is_empty() { "/" } else { path },
        Component::Path,
        false,
    )
}

/// Reproduces the request target obtained when gorilla parses a WebSocket URI.
/// Valid existing path escapes retain their spelling, the query remains raw,
/// and a fragment is parsed but never sent in an HTTP request target.
pub(crate) fn websocket_request_target(raw: &str) -> Result<String, &'static str> {
    if raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err("URL contains a control character");
    }

    let without_fragment = raw.split_once('#').map_or(raw, |(before, _)| before);
    let (path, query) = match without_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (without_fragment, None),
    };
    if !valid_percent_escapes(path) {
        return Err("URL path contains an invalid percent escape");
    }

    let path = if path.is_empty() { "/" } else { path };
    let mut target = escape_url_component(path, Component::Path, true);
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    Ok(target)
}

#[derive(Clone, Copy)]
enum Component {
    Path,
}

fn escape_url_component(value: &str, component: Component, preserve_percent: bool) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if preserve_percent
            && byte == b'%'
            && bytes
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        {
            out.push('%');
            out.push(bytes[index + 1] as char);
            out.push(bytes[index + 2] as char);
            index += 3;
            continue;
        }

        let safe = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || matches!(component, Component::Path)
                && matches!(
                    byte,
                    b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'@'
                );
        if safe {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
        index += 1;
    }
    out
}

fn valid_percent_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(hex) = bytes.get(index + 1..index + 3) else {
            return false;
        };
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return false;
        }
        index += 3;
    }
    true
}
