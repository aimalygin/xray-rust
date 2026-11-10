//! HTTP/1 messages as Go's `net/http` reads and writes them in Xray-core's
//! HTTP inbound: a request head as `http.ReadRequest` reads it, a plain
//! request forwarded as `Request.Write` writes it, and a response read as
//! `http.ReadResponse` reads it and written back as `Response.Write` does.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use xray_routing::Target;
use zeroize::Zeroizing;

use super::http::{parse_authority_target, HttpParseError};

/// The longest line read in a message head.
const MAX_LINE_LEN: usize = 8192;
/// The most a header block holds, line ends included: Go's
/// `http.DefaultMaxHeaderBytes`. Xray-core reads a block of any size, so a
/// peer that never ends its headers grows the process until it dies.
const MAX_HEADER_BLOCK: usize = 1 << 20;
/// Xray-core forwards at most this much of a `1xx` response head.
const MAX_INFORMATIONAL_HEAD: usize = 1024;

/// Header fields as Go's `http.Header` keeps them: each name's values in the
/// order they came, under the name's canonical form, and written in the
/// order of the names. `Debug` shows only the names.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HttpHeaders {
    fields: BTreeMap<String, Vec<Vec<u8>>>,
}

impl HttpHeaders {
    pub fn add(&mut self, name: &str, value: Vec<u8>) {
        self.fields
            .entry(canonical_header_key(name).into_owned())
            .or_default()
            .push(value);
    }

    pub fn set(&mut self, name: &str, value: &[u8]) {
        self.fields.insert(
            canonical_header_key(name).into_owned(),
            vec![value.to_vec()],
        );
    }

    /// The first value of `name`, as Go's `Header.Get` returns it.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.values(name).first().map(Vec::as_slice)
    }

    pub fn values(&self, name: &str) -> &[Vec<u8>] {
        self.fields
            .get(canonical_header_key(name).as_ref())
            .map_or(&[], Vec::as_slice)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.fields
            .contains_key(canonical_header_key(name).as_ref())
    }

    pub fn remove(&mut self, name: &str) {
        self.fields.remove(canonical_header_key(name).as_ref());
    }

    /// Names, in the order Go writes them, with their values.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[Vec<u8>])> {
        self.fields
            .iter()
            .map(|(name, values)| (name.as_str(), values.as_slice()))
    }

    fn last_value_mut(&mut self, name: &str) -> Option<&mut Vec<u8>> {
        self.fields
            .get_mut(name)
            .and_then(|values| values.last_mut())
    }

    /// Go's `Header.writeSubset`: every field but `exclude`, by name, each
    /// value with line breaks turned to spaces and trimmed. A name that is
    /// not a token is left out, as Go leaves it out: reading keeps a name
    /// with a space in it, and `Transfer-Encoding : chunked` must not reach
    /// a peer that reads it as the framing this side did not apply.
    fn write_subset(&self, exclude: &[&str], output: &mut Vec<u8>) {
        for (name, values) in self.iter() {
            if exclude.contains(&name) || !name.bytes().all(is_token_byte) {
                continue;
            }
            for value in values {
                let value: Vec<u8> = value
                    .iter()
                    .map(|&byte| {
                        if byte == b'\r' || byte == b'\n' {
                            b' '
                        } else {
                            byte
                        }
                    })
                    .collect();
                output.extend_from_slice(name.as_bytes());
                output.extend_from_slice(b": ");
                output.extend_from_slice(trim_ascii_space(&value));
                output.extend_from_slice(b"\r\n");
            }
        }
    }
}

impl fmt::Debug for HttpHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_set().entries(self.fields.keys()).finish()
    }
}

/// Go's `textproto.CanonicalMIMEHeaderKey`: the first letter and each one
/// after a hyphen uppercase, the rest lowercase. A name with a byte that is
/// not a token character, such as a space, stays as it is.
pub fn canonical_header_key(name: &str) -> Cow<'_, str> {
    let bytes = name.as_bytes();
    if !bytes.iter().all(|&byte| is_token_byte(byte)) {
        return Cow::Borrowed(name);
    }
    let mut upper = true;
    let canonical = bytes.iter().all(|&byte| {
        let fits = !(upper && byte.is_ascii_lowercase() || !upper && byte.is_ascii_uppercase());
        upper = byte == b'-';
        fits
    });
    if canonical {
        return Cow::Borrowed(name);
    }
    let mut upper = true;
    Cow::Owned(
        bytes
            .iter()
            .map(|&byte| {
                let byte = if upper {
                    byte.to_ascii_uppercase()
                } else {
                    byte.to_ascii_lowercase()
                };
                upper = byte == b'-';
                char::from(byte)
            })
            .collect(),
    )
}

/// RFC 9110 token characters, as Go's `httpguts` checks a method or a header
/// name.
pub(crate) fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Go's `textproto.TrimString`.
fn trim_ascii_space(value: &[u8]) -> &[u8] {
    let is_space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\r' | b'\n');
    let start = value
        .iter()
        .position(|byte| !is_space(byte))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !is_space(byte))
        .map_or(start, |end| end + 1);
    &value[start..end]
}

/// Space and tab, which Go trims from a header line.
fn trim_blank(value: &[u8]) -> &[u8] {
    let is_blank = |byte: &u8| matches!(byte, b' ' | b'\t');
    let start = value
        .iter()
        .position(|byte| !is_blank(byte))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !is_blank(byte))
        .map_or(start, |end| end + 1);
    &value[start..end]
}

/// A request head as Go's `http.ReadRequest` reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestHead {
    pub method: String,
    pub target: String,
    pub version: (u8, u8),
    /// Every header but `Proxy-Authorization`.
    pub headers: HttpHeaders,
    /// The first `Proxy-Authorization` value, which is the one Go's
    /// `Header.Get` returns, wiped on drop.
    pub proxy_authorization: Option<Zeroizing<Vec<u8>>>,
    /// How the body is delimited, as Go's `readTransfer` reads a request's.
    pub body: HttpBody,
}

/// Reads a request head as Go's `http.ReadRequest` does. Its request line is
/// three parts split at single spaces: a token, a target without control
/// characters, and an HTTP version Go reads. Header lines are read as Go's
/// `textproto` reads them, with at most one `Host`. As there, `Pragma:
/// no-cache` adds `Cache-Control: no-cache`, and a body Go cannot delimit
/// refuses the request.
pub async fn read_http_request_head<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<HttpRequestHead, HttpParseError> {
    let line = read_line(reader).await?;
    let line = std::str::from_utf8(&line).map_err(|_| HttpParseError::Malformed)?;
    let (method, rest) = line.split_once(' ').ok_or(HttpParseError::Malformed)?;
    let (target, version) = rest.split_once(' ').ok_or(HttpParseError::Malformed)?;
    let version = http_version(version).ok_or(HttpParseError::Malformed)?;
    if method.is_empty()
        || !method.bytes().all(is_token_byte)
        || target.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(HttpParseError::Malformed);
    }
    let block = read_header_block(reader, true).await?;
    let mut headers = block.headers;
    if headers.values("Host").len() > 1 {
        return Err(HttpParseError::Malformed);
    }
    fix_pragma_cache_control(&mut headers);
    let chunked =
        transfer_is_chunked(&mut headers, version).map_err(|()| HttpParseError::Malformed)?;
    // Go reads a request's body as a response's to a GET with status 200.
    let body = match fix_length(&mut headers, false, 200, method, chunked)
        .map_err(|()| HttpParseError::Malformed)?
    {
        _ if chunked => HttpBody::Chunked,
        0 => HttpBody::None,
        length => HttpBody::Length(length.unsigned_abs()),
    };
    // `http.ReadRequest` takes `Host` out of the headers.
    headers.remove("Host");
    Ok(HttpRequestHead {
        method: method.to_owned(),
        target: target.to_owned(),
        version,
        headers,
        proxy_authorization: block.proxy_authorization,
        body,
    })
}

impl HttpRequestHead {
    /// Where a `CONNECT` request goes, or `None` for another method.
    pub fn connect_target(&self) -> Option<Result<Target, HttpParseError>> {
        connect_target(self)
    }
}

/// Go's `ParseHTTPVersion`: `HTTP/` and one digit, a dot and one digit.
pub(crate) fn http_version(version: &str) -> Option<(u8, u8)> {
    match version.as_bytes() {
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit() =>
        {
            Some((major - b'0', minor - b'0'))
        }
        _ => None,
    }
}

struct HeaderBlock {
    headers: HttpHeaders,
    proxy_authorization: Option<Zeroizing<Vec<u8>>>,
}

/// What a continuation line extends.
enum Last {
    Nothing,
    Field(String),
    ProxyAuthorization,
    Ignored,
}

/// Reads header lines up to the blank one, as Go's `textproto` does. Every
/// line holds a colon after a name of token characters, or spaces, which Go
/// keeps uncanonicalized. A line that starts with a space or tab continues
/// the previous one, joined by a space, but cannot open the block. Values
/// are trimmed of spaces and tabs. With `keep_authorization`, the first
/// `Proxy-Authorization` is kept apart, to be wiped.
async fn read_header_block<R: AsyncRead + Unpin>(
    reader: &mut R,
    keep_authorization: bool,
) -> Result<HeaderBlock, HttpParseError> {
    let mut headers = HttpHeaders::default();
    let mut proxy_authorization: Option<Zeroizing<Vec<u8>>> = None;
    let mut last = Last::Nothing;
    let mut read = 0usize;
    loop {
        let line = read_line(reader).await?;
        read += line.len() + 2;
        if read > MAX_HEADER_BLOCK {
            return Err(HttpParseError::HeadTooLarge);
        }
        if line.is_empty() {
            return Ok(HeaderBlock {
                headers,
                proxy_authorization,
            });
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            let rest = trim_blank(&line);
            let value = match &last {
                Last::Nothing => return Err(HttpParseError::Malformed),
                Last::Field(name) => headers.last_value_mut(name),
                Last::ProxyAuthorization => proxy_authorization.as_deref_mut(),
                Last::Ignored => None,
            };
            if let Some(value) = value {
                value.push(b' ');
                value.extend_from_slice(rest);
            }
            continue;
        }
        let line = trim_blank(&line);
        let colon = line
            .iter()
            .position(|&byte| byte == b':')
            .ok_or(HttpParseError::Malformed)?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&byte| is_token_byte(byte) || byte == b' ') {
            return Err(HttpParseError::Malformed);
        }
        let name = std::str::from_utf8(name).map_err(|_| HttpParseError::Malformed)?;
        let value = trim_blank(&line[colon + 1..]);
        let canonical = canonical_header_key(name);
        if keep_authorization && canonical == "Proxy-Authorization" {
            if proxy_authorization.is_none() {
                proxy_authorization = Some(Zeroizing::new(value.to_vec()));
                last = Last::ProxyAuthorization;
            } else {
                last = Last::Ignored;
            }
            continue;
        }
        headers.add(&canonical, value.to_vec());
        last = Last::Field(canonical.into_owned());
    }
}

/// One line without its `\n` or `\r\n`, wiped on drop.
async fn read_line<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Zeroizing<Vec<u8>>, HttpParseError> {
    let mut line = Zeroizing::new(Vec::new());
    loop {
        if line.len() >= MAX_LINE_LEN {
            return Err(HttpParseError::LineTooLong);
        }
        let byte = reader.read_u8().await.map_err(|_| HttpParseError::Io)?;
        if byte == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        line.push(byte);
    }
}

/// How a message's body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBody {
    None,
    Length(u64),
    Chunked,
    /// Until the connection closes; only a response's.
    UntilClose,
}

/// Why a plain request is not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainHttpError {
    /// The target names no host. Xray-core answers it with a 400 unless
    /// `allowTransparent` is on.
    NoHost,
    /// Go's `http.ReadRequest` refuses it, so the connection is closed.
    Malformed,
}

/// A request Xray-core's HTTP inbound forwards: not `CONNECT`, with an
/// absolute target, its hop-by-hop headers removed, and no
/// `Proxy-Authorization`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainHttpRequest {
    pub method: String,
    /// Where the request goes: the target's host and port, port 443 for
    /// `https` and 80 otherwise when it names none.
    pub destination: Target,
    /// The path, decoded, which routing's `attrs` sees as `:path`.
    pub path: Vec<u8>,
    request_uri: String,
    host: String,
    headers: HttpHeaders,
    pub body: HttpBody,
    /// `Proxy-Connection: keep-alive`, which keeps the client connection for
    /// another request after a response of known length.
    pub keep_alive: bool,
}

impl PlainHttpRequest {
    /// Reads a request as Xray-core's `handlePlainHTTP` does after Go's
    /// `http.ReadRequest`: the target parsed as Go's `url.ParseRequestURI`
    /// parses it, and the hop-by-hop headers removed, with an absent
    /// `User-Agent` kept empty so that none is sent.
    pub fn new(head: &HttpRequestHead) -> Result<Self, PlainHttpError> {
        let url = RequestUrl::parse(&head.target)?;
        let mut headers = head.headers.clone();
        let body = head.body;
        let keep_alive = headers
            .get("Proxy-Connection")
            .is_some_and(|value| trim_ascii_space(value).eq_ignore_ascii_case(b"keep-alive"));
        let host = url.host.ok_or(PlainHttpError::NoHost)?;
        let default_port = if url.scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        };
        let destination =
            parse_authority_target(&host, default_port).map_err(|_| PlainHttpError::Malformed)?;
        remove_hop_by_hop_headers(&mut headers);
        if headers.get("User-Agent").is_none_or(<[u8]>::is_empty) {
            headers.set("User-Agent", b"");
        }
        Ok(Self {
            method: head.method.clone(),
            destination,
            path: url.path,
            request_uri: url.request_uri,
            host,
            headers,
            body,
            keep_alive,
        })
    }

    /// What routing's `attrs` sees, as Xray-core's HTTP inbound records it:
    /// `:method` uppercased, `:path` decoded, and each header's first value
    /// under its lowercased name. Names are given as Go keeps them.
    pub fn attributes(&self) -> impl Iterator<Item = (&str, Cow<'_, [u8]>)> {
        let method = Cow::Owned(self.method.to_ascii_uppercase().into_bytes());
        [
            (":method", method),
            (":path", Cow::Borrowed(self.path.as_slice())),
        ]
        .into_iter()
        .chain(self.headers.iter().map(|(name, values)| {
            (
                name,
                Cow::Borrowed(values.first().map_or(&[][..], Vec::as_slice)),
            )
        }))
    }

    /// The request as Go's `Request.Write` sends it on, after Xray-core sets
    /// `Connection: close`: the request line with the target's path and
    /// query, `Host` from the target in Punycode, any `User-Agent`, the
    /// body's length or chunking, then the other headers by name.
    pub fn forwarded_head(&self) -> Vec<u8> {
        let mut head = Vec::with_capacity(256);
        head.extend_from_slice(self.method.as_bytes());
        head.push(b' ');
        head.extend_from_slice(self.request_uri.as_bytes());
        head.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        head.extend_from_slice(host_header(&self.host).as_bytes());
        head.extend_from_slice(b"\r\n");
        if let Some(agent) = self.headers.get("User-Agent") {
            let agent: Vec<u8> = agent
                .iter()
                .map(|&byte| {
                    if byte == b'\r' || byte == b'\n' {
                        b' '
                    } else {
                        byte
                    }
                })
                .collect();
            let agent = trim_ascii_space(&agent);
            if !agent.is_empty() {
                head.extend_from_slice(b"User-Agent: ");
                head.extend_from_slice(agent);
                head.extend_from_slice(b"\r\n");
            }
        }
        let sends_length = match self.body {
            HttpBody::Length(length) => {
                length > 0 || matches!(self.method.as_str(), "POST" | "PUT" | "PATCH")
            }
            HttpBody::None => matches!(self.method.as_str(), "POST" | "PUT" | "PATCH"),
            HttpBody::Chunked | HttpBody::UntilClose => false,
        };
        if sends_length {
            let length = match self.body {
                HttpBody::Length(length) => length,
                _ => 0,
            };
            head.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        } else if self.body == HttpBody::Chunked {
            head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        let mut headers = self.headers.clone();
        headers.set("Connection", b"close");
        headers.write_subset(
            &[
                "Host",
                "User-Agent",
                "Content-Length",
                "Transfer-Encoding",
                "Trailer",
            ],
            &mut head,
        );
        head.extend_from_slice(b"\r\n");
        head
    }
}

/// Go's `fixPragmaCacheControl`.
fn fix_pragma_cache_control(headers: &mut HttpHeaders) {
    if headers.get("Pragma") == Some(b"no-cache") && !headers.contains("Cache-Control") {
        headers.set("Cache-Control", b"no-cache");
    }
}

/// Xray-core's `RemoveHopByHopHeaders`, with the headers `Connection` names.
fn remove_hop_by_hop_headers(headers: &mut HttpHeaders) {
    for name in [
        "Proxy-Connection",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailers",
        "Transfer-Encoding",
        "Upgrade",
    ] {
        headers.remove(name);
    }
    let connection = headers.get("Connection").map(<[u8]>::to_vec);
    headers.remove("Connection");
    for name in connection
        .iter()
        .flat_map(|value| value.split(|&byte| byte == b','))
    {
        if let Ok(name) = std::str::from_utf8(trim_ascii_space(name)) {
            headers.remove(name);
        }
    }
}

/// Go's `parseTransferEncoding`: removes `Transfer-Encoding`, which only
/// HTTP/1.1 and later read, and refuses anything but a single `chunked`.
fn transfer_is_chunked(headers: &mut HttpHeaders, version: (u8, u8)) -> Result<bool, ()> {
    let values = headers.values("Transfer-Encoding").to_vec();
    if values.is_empty() {
        return Ok(false);
    }
    headers.remove("Transfer-Encoding");
    if version < (1, 1) {
        return Ok(false);
    }
    match values.as_slice() {
        [value] if value.eq_ignore_ascii_case(b"chunked") => Ok(true),
        _ => Err(()),
    }
}

/// Go 1.27's `fixLength`: repeated `Content-Length` headers must agree and
/// collapse into one, which must parse whatever follows. A response to
/// `HEAD`, or with a `1xx`, 204 or 304 status, has no body; a chunked one
/// drops `Content-Length`; then the declared length counts. Without one, a
/// request has no body and a response runs until the connection closes, -1.
fn fix_length(
    headers: &mut HttpHeaders,
    response: bool,
    status: u16,
    request_method: &str,
    chunked: bool,
) -> Result<i64, ()> {
    let declared = agreed_content_length(headers)?
        .map(|value| parse_content_length(&value))
        .transpose()?;
    if response && request_method == "HEAD" || !body_allowed(status) {
        return Ok(0);
    }
    if chunked {
        headers.remove("Content-Length");
        return Ok(-1);
    }
    match declared {
        Some(length) => Ok(i64::try_from(length).map_err(|_| ())?),
        None => {
            headers.remove("Content-Length");
            Ok(if response { -1 } else { 0 })
        }
    }
}

/// Go's `fixLength` on repeated `Content-Length` headers: they must agree
/// after trimming, and collapse into one. Returns the value, if any.
fn agreed_content_length(headers: &mut HttpHeaders) -> Result<Option<Vec<u8>>, ()> {
    let values = headers.values("Content-Length").to_vec();
    let Some(first) = values.first() else {
        return Ok(None);
    };
    let first = trim_ascii_space(first).to_vec();
    if values.iter().any(|value| trim_ascii_space(value) != first) {
        return Err(());
    }
    if values.len() > 1 {
        headers.set("Content-Length", &first);
    }
    Ok(Some(first))
}

/// Go's `parseContentLength`: decimal digits that fit 63 bits.
fn parse_content_length(value: &[u8]) -> Result<u64, ()> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(());
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|digits| digits.parse::<u64>().ok())
        .filter(|&length| i64::try_from(length).is_ok())
        .ok_or(())
}

/// A request target as Go's `url.ParseRequestURI` reads it.
struct RequestUrl {
    scheme: String,
    /// The authority's host and port, without user information.
    host: Option<String>,
    path: Vec<u8>,
    /// The escaped path and query, as Go's `URL.RequestURI` gives them.
    request_uri: String,
}

impl RequestUrl {
    fn parse(target: &str) -> Result<Self, PlainHttpError> {
        if target.is_empty() {
            return Err(PlainHttpError::Malformed);
        }
        if target == "*" {
            return Err(PlainHttpError::NoHost);
        }
        let (scheme, rest) = url_scheme(target)?;
        let (rest, query) = if rest.ends_with('?') && rest.matches('?').count() == 1 {
            (&rest[..rest.len() - 1], Some(""))
        } else {
            match rest.split_once('?') {
                Some((rest, query)) => (rest, Some(query)),
                None => (rest, None),
            }
        };
        if !rest.starts_with('/') {
            // Go reads a rootless path after a scheme as opaque, with no host.
            return if scheme.is_empty() {
                Err(PlainHttpError::Malformed)
            } else {
                Err(PlainHttpError::NoHost)
            };
        }
        let (host, path) = match rest.strip_prefix("//").filter(|_| !scheme.is_empty()) {
            Some(rest) => {
                let (authority, path) = rest
                    .find('/')
                    .map_or((rest, ""), |slash| rest.split_at(slash));
                // User information goes, as Go keeps it apart from the host.
                let host = authority
                    .rsplit_once('@')
                    .map_or(authority, |(_, host)| host);
                (Some(host.to_owned()).filter(|host| !host.is_empty()), path)
            }
            None => (None, rest),
        };
        let decoded = percent_decode(path).ok_or(PlainHttpError::Malformed)?;
        let mut request_uri = escaped_path(path, &decoded);
        if request_uri.is_empty() {
            request_uri.push('/');
        }
        if let Some(query) = query {
            request_uri.push('?');
            request_uri.push_str(query);
        }
        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            host,
            path: decoded,
            request_uri,
        })
    }
}

/// Go's `getScheme`: letters, then letters, digits, `+`, `-` or `.` up to a
/// colon. A target without one has no scheme.
fn url_scheme(target: &str) -> Result<(&str, &str), PlainHttpError> {
    for (index, byte) in target.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if index > 0 => {}
            b':' if index == 0 => return Err(PlainHttpError::Malformed),
            b':' => return Ok((&target[..index], &target[index + 1..])),
            _ => return Ok(("", target)),
        }
    }
    Ok(("", target))
}

/// Go's `unescape` in path mode: each `%` begins two hex digits.
fn percent_decode(path: &str) -> Option<Vec<u8>> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = (*bytes.get(index + 1)? as char).to_digit(16)?;
            let low = (*bytes.get(index + 2)? as char).to_digit(16)?;
            decoded.push(u8::try_from(high * 16 + low).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Some(decoded)
}

/// Go's `URL.EscapedPath`: the path as sent when it is a valid encoding of
/// the decoded path, otherwise the decoded path escaped again.
fn escaped_path(raw: &str, decoded: &[u8]) -> String {
    let escaped = escape_path(decoded);
    if escaped == raw || !raw.bytes().all(valid_encoded_path_byte) {
        escaped
    } else {
        raw.to_owned()
    }
}

/// Go's `escape` in path mode: everything but letters, digits, `-_.~` and
/// `$&+,/:;=@` is percent-encoded with uppercase hex.
fn escape_path(path: &[u8]) -> String {
    let mut escaped = String::with_capacity(path.len());
    for &byte in path {
        if byte.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

/// Go's `validEncoded` in path mode.
fn valid_encoded_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@!'()*[]%".contains(&byte)
}

/// The `Host` Go's `Request.Write` sends: the target's host and port, a
/// non-ASCII host in Punycode, empty when it is not a valid host field.
fn host_header(host: &str) -> Cow<'_, str> {
    let host = if host.is_ascii() {
        Cow::Borrowed(host)
    } else {
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => {
                (name, Some(port))
            }
            _ => (host, None),
        };
        match idna::domain_to_ascii(name) {
            Ok(name) => Cow::Owned(match port {
                Some(port) => format!("{name}:{port}"),
                None => name,
            }),
            Err(_) => Cow::Borrowed(""),
        }
    };
    if host.bytes().all(valid_host_byte) {
        host
    } else {
        Cow::Borrowed("")
    }
}

/// Go's `httpguts.ValidHostHeader`.
fn valid_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!$&'()*+,-.:;=[]_~%".contains(&byte)
}

/// A response head as Go's `http.ReadResponse` reads it, delimited for the
/// request that asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseHead {
    version: (u8, u8),
    status_code: u16,
    /// The line after the version, as Go keeps it in `Response.Status`.
    status: String,
    headers: HttpHeaders,
    pub body: HttpBody,
    /// Go's `Response.ContentLength`: the body's length, or for a `HEAD`
    /// request the one `Content-Length` declares, -1 when unknown.
    content_length: i64,
}

impl HttpResponseHead {
    /// Whether the client connection can take another request after this
    /// response, as Xray-core decides by a known length.
    pub fn keeps_alive(&self) -> bool {
        self.content_length >= 0
    }

    /// The head Xray-core writes back with Go's `Response.Write`, after
    /// removing hop-by-hop headers and, for a response of known length,
    /// setting `Connection`, `Proxy-Connection` and `Keep-Alive` to keep the
    /// client connection, or otherwise closing it.
    pub fn client_head(&self, request_method: &str) -> Vec<u8> {
        let mut headers = self.headers.clone();
        remove_hop_by_hop_headers(&mut headers);
        let keeps_alive = self.keeps_alive();
        if keeps_alive {
            headers.set("Proxy-Connection", b"keep-alive");
            headers.set("Connection", b"keep-alive");
            headers.set("Keep-Alive", b"timeout=60");
        }
        let code = self.status_code.to_string();
        let text = self
            .status
            .strip_prefix(&format!("{code} "))
            .unwrap_or(&self.status);
        let mut head = format!(
            "HTTP/{}.{} {:03} {}\r\n",
            self.version.0, self.version.1, self.status_code, text
        )
        .into_bytes();
        let chunked = self.body == HttpBody::Chunked;
        if !keeps_alive && !has_close_token(headers.values("Connection")) {
            head.extend_from_slice(b"Connection: close\r\n");
        }
        let sends_length = !chunked
            && (self.content_length > 0
                || self.content_length == 0 && matches!(request_method, "POST" | "PUT" | "PATCH"));
        if sends_length {
            head.extend_from_slice(
                format!("Content-Length: {}\r\n", self.content_length).as_bytes(),
            );
        } else if chunked {
            head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        headers.write_subset(
            &["Content-Length", "Transfer-Encoding", "Trailer"],
            &mut head,
        );
        if self.content_length == 0 && !chunked && !sends_length && body_allowed(self.status_code) {
            head.extend_from_slice(b"Content-Length: 0\r\n");
        }
        head.extend_from_slice(b"\r\n");
        head
    }
}

fn has_close_token(values: &[Vec<u8>]) -> bool {
    values
        .iter()
        .flat_map(|value| value.split(|&byte| byte == b','))
        .any(|token| trim_blank(token).eq_ignore_ascii_case(b"close"))
}

fn body_allowed(status: u16) -> bool {
    !matches!(status, 100..=199 | 204 | 304)
}

/// A response as Xray-core reads it: an informational (`1xx`) head it
/// forwards as it came, when one comes first, then the response itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub informational: Option<Vec<u8>>,
    pub head: HttpResponseHead,
}

/// Reads a response as Xray-core's `readResponseAndHandle100Continue` does
/// for a request with `request_method`. When the status after the first
/// line's first space starts with `1`, that head is read up to a blank line
/// ending in `\r\n\r\n`, at most 1024 bytes, and kept to be forwarded as it
/// is; the next head is then read as Go's `http.ReadResponse` reads one.
pub async fn read_http_response<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    request_method: &str,
) -> Result<HttpResponse, HttpParseError> {
    let mut first = Vec::new();
    read_raw_line(reader, &mut first).await?;
    let informational = first
        .iter()
        .position(|&byte| byte == b' ')
        .is_some_and(|space| first.get(space + 1) == Some(&b'1'));
    if !informational {
        let head = read_http_response_head(reader, &first, request_method).await?;
        return Ok(HttpResponse {
            informational: None,
            head,
        });
    }
    let mut raw = first;
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() > MAX_INFORMATIONAL_HEAD {
            return Err(HttpParseError::LineTooLong);
        }
        read_raw_line(reader, &mut raw).await?;
    }
    let mut first = Vec::new();
    read_raw_line(reader, &mut first).await?;
    let head = read_http_response_head(reader, &first, request_method).await?;
    Ok(HttpResponse {
        informational: Some(raw),
        head,
    })
}

/// Appends one line, with its `\n`, to `line`.
async fn read_raw_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> Result<(), HttpParseError> {
    let mut limited = reader.take(MAX_LINE_LEN as u64);
    let read = limited
        .read_until(b'\n', line)
        .await
        .map_err(|_| HttpParseError::Io)?;
    if read == 0 {
        return Err(HttpParseError::Io);
    }
    if !line.ends_with(b"\n") {
        return Err(HttpParseError::LineTooLong);
    }
    Ok(())
}

/// Reads the rest of a response head, after its status line `first`, as Go's
/// `http.ReadResponse` does. The status line is a version Go reads, a
/// space, and a status whose first part is three characters `strconv.Atoi`
/// reads. The body is delimited as Go's `readTransfer` delimits a response
/// to `request_method`.
async fn read_http_response_head<R: AsyncRead + Unpin>(
    reader: &mut R,
    first: &[u8],
    request_method: &str,
) -> Result<HttpResponseHead, HttpParseError> {
    let line = first.strip_suffix(b"\n").unwrap_or(first);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let line = std::str::from_utf8(line).map_err(|_| HttpParseError::Malformed)?;
    let (version, status) = line.split_once(' ').ok_or(HttpParseError::Malformed)?;
    let status = status.trim_start_matches(' ');
    let code = status.split(' ').next().unwrap_or_default();
    let status_code = (code.len() == 3)
        .then(|| code.parse::<i64>().ok())
        .flatten()
        .and_then(|code| u16::try_from(code).ok())
        .ok_or(HttpParseError::Malformed)?;
    let version = http_version(version).ok_or(HttpParseError::Malformed)?;
    let mut headers = read_header_block(reader, false).await?.headers;
    fix_pragma_cache_control(&mut headers);
    let malformed = |()| HttpParseError::Malformed;
    let chunked = transfer_is_chunked(&mut headers, version).map_err(malformed)?;
    let length =
        fix_length(&mut headers, true, status_code, request_method, chunked).map_err(malformed)?;
    let content_length = if request_method == "HEAD" {
        // Go takes a `HEAD` response's length from what it declares.
        match headers.get("Content-Length") {
            Some(value) => {
                let length = parse_content_length(trim_ascii_space(value)).map_err(malformed)?;
                i64::try_from(length).map_err(|_| HttpParseError::Malformed)?
            }
            None => -1,
        }
    } else {
        length
    };
    let body = match length {
        _ if chunked && request_method != "HEAD" && body_allowed(status_code) => HttpBody::Chunked,
        0 => HttpBody::None,
        -1 => HttpBody::UntilClose,
        length => HttpBody::Length(length.unsigned_abs()),
    };
    Ok(HttpResponseHead {
        version,
        status_code,
        status: status.to_owned(),
        headers,
        body,
        content_length,
    })
}

/// Copies exactly `length` body bytes.
pub async fn copy_body_length<R, W>(
    reader: &mut R,
    writer: &mut W,
    length: u64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut reader.take(length), writer).await?;
    if copied != length {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(copied)
}

/// Copies a chunked body as Go relays it: each chunk's data is written as a
/// chunk of its own, the size lines and extensions read as Go's chunked
/// reader reads them, and the trailer dropped for a closing `0` chunk.
pub async fn copy_body_chunked<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let mut copied = 0;
    loop {
        let line = read_line(reader).await.map_err(|_| invalid())?;
        let size = line.split(|&byte| byte == b';').next().unwrap_or_default();
        let size = trim_blank(size);
        if size.is_empty() || size.len() > 16 || !size.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid());
        }
        let size = std::str::from_utf8(size)
            .ok()
            .and_then(|size| u64::from_str_radix(size, 16).ok())
            .ok_or_else(invalid)?;
        if size == 0 {
            // The trailer, up to its blank line.
            while !read_line(reader).await.map_err(|_| invalid())?.is_empty() {}
            writer.write_all(b"0\r\n\r\n").await?;
            return Ok(copied);
        }
        writer.write_all(format!("{size:x}\r\n").as_bytes()).await?;
        copy_body_length(reader, writer, size).await?;
        writer.write_all(b"\r\n").await?;
        if !read_line(reader).await.map_err(|_| invalid())?.is_empty() {
            return Err(invalid());
        }
        copied += size;
    }
}

/// Where a request head's `CONNECT` target goes, or `None` for another
/// method. Go reads a target as an authority only for `CONNECT` exactly.
pub(crate) fn connect_target(head: &HttpRequestHead) -> Option<Result<Target, HttpParseError>> {
    (head.method == "CONNECT").then(|| parse_authority_target(&head.target, 80))
}
