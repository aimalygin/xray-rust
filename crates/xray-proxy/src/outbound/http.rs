//! HTTP/1.1 CONNECT client (RFC 9110 section 9.3.6) with optional Basic
//! authentication (RFC 7617).
//!
//! The request follows the HTTP/1.1 path of Xray-core v26.7.28
//! `proxy/http/client.go`: Go's `Request.Write` puts `Host` and `User-Agent`
//! first and every other header after them, sorted by its literal name, and
//! the tunnel opens only on status 200, not on any 2xx.
//!
//! Two details deliberately differ from Xray. The response head is bounded to
//! [`MAX_HTTP_CONNECT_RESPONSE_HEAD`] bytes, where Go reads it without a
//! limit. And bytes that arrive in the same read as the head are returned to
//! the caller: Xray reads the head through a `bufio.Reader` it then drops, so
//! a proxy or target that speaks first loses its first bytes there.
//!
//! This module does not dial or time out, so a proxy that accepts the
//! connection and then stays silent stalls it forever: callers must bound the
//! whole handshake.

use std::fmt;
use std::io;
use std::net::IpAddr;

use base64::Engine as _;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_routing::{Target, TargetAddr};
use zeroize::Zeroizing;

/// The largest response head, plus any tunnel bytes read with it, that the
/// client buffers before giving up.
pub const MAX_HTTP_CONNECT_RESPONSE_HEAD: usize = 16 * 1024;

/// The largest `user` or `pass`, in bytes. Xray has no limit; this one keeps
/// the request bounded while leaving room for long proxy tokens.
pub const MAX_HTTP_CREDENTIAL_LENGTH: usize = 1024;

const MAX_DOMAIN_LENGTH: usize = u8::MAX as usize;
const READ_CHUNK: usize = 2048;
/// Go's `Request.Write` default when the header map has no `User-Agent`.
const DEFAULT_USER_AGENT: &str = "Go-http-client/1.1";

/// A failed HTTP CONNECT handshake. No variant carries a credential or text
/// from the proxy's response.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HttpClientError {
    #[error("HTTP CONNECT target port must be nonzero")]
    InvalidTargetPort,
    #[error("HTTP CONNECT target domain must contain 1..=255 URI host characters")]
    InvalidTargetDomain,
    #[error("HTTP CONNECT header name or value is not valid")]
    InvalidHeader,
    #[error("HTTP proxy io error: {0}")]
    Io(io::ErrorKind),
    #[error("HTTP proxy closed the connection before the end of its response head")]
    ConnectionClosed,
    #[error("HTTP proxy response head exceeds {MAX_HTTP_CONNECT_RESPONSE_HEAD} bytes")]
    ResponseTooLarge,
    #[error("malformed HTTP proxy response")]
    MalformedResponse,
    #[error("HTTP proxy requires authentication (status 407)")]
    ProxyAuthenticationRequired,
    #[error("HTTP proxy answered CONNECT with status {0}, not 200")]
    Rejected(u16),
}

impl From<io::Error> for HttpClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// One Basic authentication pair for an HTTP proxy.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpAccount {
    user: Zeroizing<String>,
    pass: Zeroizing<String>,
}

impl HttpAccount {
    /// Returns `None` unless `user` has 1..=1024 bytes without `:`, `pass` has
    /// at most 1024 bytes, and neither contains a control character, which
    /// RFC 7617 excludes from both.
    pub fn new(user: &str, pass: &str) -> Option<Self> {
        let printable = |value: &str| !value.chars().any(char::is_control);
        let valid = (1..=MAX_HTTP_CREDENTIAL_LENGTH).contains(&user.len())
            && pass.len() <= MAX_HTTP_CREDENTIAL_LENGTH
            && !user.contains(':')
            && printable(user)
            && printable(pass);
        valid.then(|| Self {
            user: Zeroizing::new(user.to_owned()),
            pass: Zeroizing::new(pass.to_owned()),
        })
    }

    /// `Basic base64(user ":" pass)`, built without reallocating so that no
    /// unzeroed copy is left behind.
    fn proxy_authorization(&self) -> Zeroizing<String> {
        let mut plain = Zeroizing::new(Vec::with_capacity(self.user.len() + 1 + self.pass.len()));
        plain.extend_from_slice(self.user.as_bytes());
        plain.push(b':');
        plain.extend_from_slice(self.pass.as_bytes());
        let mut value = Zeroizing::new(String::with_capacity(6 + plain.len().div_ceil(3) * 4));
        value.push_str("Basic ");
        base64::engine::general_purpose::STANDARD.encode_string(plain.as_slice(), &mut value);
        value
    }
}

impl fmt::Debug for HttpAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpAccount")
            .field("user", &"<redacted>")
            .field("pass", &"<redacted>")
            .finish()
    }
}

/// Builds the CONNECT request for `target`.
///
/// `headers` are extra fields, such as Xray's browser masquerade block; a
/// `User-Agent` among them replaces Go's default. `Host`,
/// `Proxy-Authorization` and `Proxy-Connection` are always this function's
/// own and are skipped in `headers`. The target is validated before anything
/// is built, so callers can fail before resolving or dialing the proxy.
pub fn encode_connect_request(
    target: &Target,
    account: Option<&HttpAccount>,
    headers: &[(&str, &str)],
) -> Result<Zeroizing<Vec<u8>>, HttpClientError> {
    let authority = connect_authority(target)?;
    let authorization = account.map(HttpAccount::proxy_authorization);
    let mut fields: Vec<(&str, &str)> = headers
        .iter()
        .copied()
        .filter(|(name, _)| {
            !matches!(
                *name,
                "Host" | "User-Agent" | "Proxy-Authorization" | "Proxy-Connection"
            )
        })
        .chain(
            authorization
                .as_deref()
                .map(|value| ("Proxy-Authorization", value.as_str())),
        )
        .chain([("Proxy-Connection", "Keep-Alive")])
        .collect();
    let user_agent = headers
        .iter()
        .find_map(|&(name, value)| (name == "User-Agent").then_some(value))
        .unwrap_or(DEFAULT_USER_AGENT);
    if fields
        .iter()
        .copied()
        .chain([("User-Agent", user_agent)])
        .any(|(name, value)| !valid_header_name(name) || !valid_header_value(value))
    {
        return Err(HttpClientError::InvalidHeader);
    }
    fields.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));

    // Go omits `User-Agent` when it is set to the empty string.
    let lines: Vec<(&str, &str)> = [("Host", authority.as_str()), ("User-Agent", user_agent)]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .chain(fields)
        .collect();
    let capacity = "CONNECT  HTTP/1.1\r\n\r\n".len()
        + authority.len()
        + lines
            .iter()
            .map(|(name, value)| name.len() + value.len() + 4)
            .sum::<usize>();
    // Sized up front so the buffer holding the credentials never reallocates.
    let mut request = Zeroizing::new(Vec::with_capacity(capacity));
    for part in ["CONNECT ", &authority, " HTTP/1.1\r\n"] {
        request.extend_from_slice(part.as_bytes());
    }
    for (name, value) in &lines {
        for part in [name, ": ", value, "\r\n"] {
            request.extend_from_slice(part.as_bytes());
        }
    }
    request.extend_from_slice(b"\r\n");
    debug_assert_eq!(request.len(), capacity);
    Ok(request)
}

/// Sends `request` over an established `stream` and reads the response head.
///
/// On status 200 the stream is positioned after the head, and the returned
/// bytes are tunnel bytes that arrived with it; the caller must deliver them
/// before reading the stream again. `Content-Length` and `Transfer-Encoding`
/// in the 200 response are ignored, as RFC 9110 section 9.3.6 requires.
pub async fn http_connect<S>(stream: &mut S, request: &[u8]) -> Result<Vec<u8>, HttpClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    stream.flush().await?;
    read_connect_response(stream).await
}

/// `host:port` for the request line and `Host`, as Go's `net.JoinHostPort`
/// writes it. An IPv4-mapped IPv6 target is sent as IPv4, as Xray does.
fn connect_authority(target: &Target) -> Result<String, HttpClientError> {
    if target.port == 0 {
        return Err(HttpClientError::InvalidTargetPort);
    }
    Ok(match &target.addr {
        TargetAddr::Ip(ip) => match ip.to_canonical() {
            IpAddr::V4(ip) => format!("{ip}:{}", target.port),
            IpAddr::V6(ip) => format!("[{ip}]:{}", target.port),
        },
        TargetAddr::Domain(domain) if valid_domain(domain) => format!("{domain}:{}", target.port),
        TargetAddr::Domain(_) => return Err(HttpClientError::InvalidTargetDomain),
    })
}

/// An RFC 3986 `reg-name` (unreserved, percent and sub-delimiter characters),
/// so the authority can neither break the request line nor smuggle a port,
/// user info or path. Non-ASCII names are refused rather than converted.
fn valid_domain(domain: &str) -> bool {
    (1..=MAX_DOMAIN_LENGTH).contains(&domain.len())
        && domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~%!$&'()*+,;=".contains(&byte))
}

/// RFC 9110 `token`.
fn valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_byte)
}

/// No line break or other control byte except horizontal tab.
fn valid_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || !byte.is_ascii_control())
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Reads up to the empty line that ends the head and returns what follows it.
async fn read_connect_response<S>(stream: &mut S) -> Result<Vec<u8>, HttpClientError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(READ_CHUNK);
    let mut scanned = 0;
    loop {
        if let Some((head_len, end)) = find_head_end(&buffer, scanned) {
            validate_response_head(&buffer[..head_len])?;
            return Ok(buffer.split_off(end));
        }
        // A terminator can straddle reads, so rescan the last two bytes.
        scanned = buffer.len().saturating_sub(2);
        let room = MAX_HTTP_CONNECT_RESPONSE_HEAD - buffer.len();
        if room == 0 {
            return Err(HttpClientError::ResponseTooLarge);
        }
        let start = buffer.len();
        buffer.resize(start + room.min(READ_CHUNK), 0);
        let read = stream.read(&mut buffer[start..]).await?;
        buffer.truncate(start + read);
        if read == 0 {
            return Err(HttpClientError::ConnectionClosed);
        }
    }
}

/// Finds the empty line, accepting bare `LF` line ends as Go does. Returns the
/// head length up to and including the last header line's `LF`, and the
/// offset of the first byte after the empty line.
fn find_head_end(buffer: &[u8], from: usize) -> Option<(usize, usize)> {
    (from..buffer.len())
        .filter(|&index| buffer[index] == b'\n')
        .find_map(|index| match &buffer[index + 1..] {
            [b'\n', ..] => Some((index + 1, index + 2)),
            [b'\r', b'\n', ..] => Some((index + 1, index + 3)),
            _ => None,
        })
}

/// Checks the status line and the header syntax, then requires status 200.
///
/// As in Go's `ReadResponse`, a malformed header fails even when the status
/// would be refused anyway. Header values are not interpreted.
fn validate_response_head(head: &[u8]) -> Result<(), HttpClientError> {
    let mut lines = head
        .split(|&byte| byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let status = parse_status_line(lines.next().unwrap_or_default())?;
    let mut previous_field = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let valid = match line {
            // obs-fold continues the previous field (RFC 9112 section 5.2).
            [b' ' | b'\t', ..] => previous_field && valid_field_bytes(line),
            _ => line
                .iter()
                .position(|&byte| byte == b':')
                .is_some_and(|colon| {
                    colon > 0
                        && line[..colon].iter().copied().all(is_token_byte)
                        && valid_field_bytes(&line[colon + 1..])
                }),
        };
        if !valid {
            return Err(HttpClientError::MalformedResponse);
        }
        previous_field = true;
    }
    match status {
        200 => Ok(()),
        407 => Err(HttpClientError::ProxyAuthenticationRequired),
        status => Err(HttpClientError::Rejected(status)),
    }
}

/// `HTTP/1.x SP 3DIGIT [SP reason]`. Like Go, the code must be exactly three
/// digits followed by a space or the end of the line.
fn parse_status_line(line: &[u8]) -> Result<u16, HttpClientError> {
    let rest = line
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.0 "))
        .ok_or(HttpClientError::MalformedResponse)?;
    let (code, reason) = rest
        .split_at_checked(3)
        .ok_or(HttpClientError::MalformedResponse)?;
    if !code.iter().all(u8::is_ascii_digit)
        || !matches!(reason, [] | [b' ', ..])
        || !valid_field_bytes(reason)
    {
        return Err(HttpClientError::MalformedResponse);
    }
    Ok(code
        .iter()
        .fold(0, |status, digit| status * 10 + u16::from(digit - b'0')))
}

/// Field values and reason phrases: no control byte except horizontal tab.
fn valid_field_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&byte| byte == b'\t' || !byte.is_ascii_control())
}
