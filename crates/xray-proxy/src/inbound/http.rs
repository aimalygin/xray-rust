use std::fmt;
use std::net::IpAddr;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use xray_routing::{Network, Target, TargetAddr};
use zeroize::Zeroizing;

use super::{InboundUser, SocksInboundAuth};

const MAX_REQUEST_LINE_LEN: usize = 8192;
/// Xray-core reads a `CONNECT` target with Go's `ParseHost`, which takes
/// port 80 when the target names none.
const DEFAULT_CONNECT_PORT: u16 = 80;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("request is not http connect")]
    NotConnect,
    #[error("request line is too long")]
    LineTooLong,
    #[error("request is malformed")]
    Malformed,
    #[error("invalid authority")]
    InvalidAuthority,
    #[error("invalid port")]
    InvalidPort,
    #[error("io error")]
    Io,
}

/// An HTTP proxy request's head and the credentials it offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectRequest {
    /// Where a `CONNECT` request goes, or `None` for any other method.
    pub target: Option<Target>,
    /// The first `Proxy-Authorization` value, trimmed of whitespace, which
    /// is the one Go's `Header.Get` returns.
    pub proxy_authorization: Option<Zeroizing<Vec<u8>>>,
}

/// The target of an HTTP `CONNECT` request, or [`HttpParseError::NotConnect`]
/// for another method.
pub async fn parse_http_connect<R: AsyncRead + Unpin>(reader: R) -> Result<Target, HttpParseError> {
    parse_http_connect_request(reader)
        .await?
        .target
        .ok_or(HttpParseError::NotConnect)
}

/// Reads an HTTP proxy request's head as Go's `http.ReadRequest` does in
/// Xray-core's HTTP inbound. Its request line is three parts split at single
/// spaces, ending in an HTTP version Go reads; every header line holds a
/// colon after a name of token characters, or spaces, which Go keeps
/// uncanonicalized; and at most one `Host` is given. Anything else is
/// malformed, which Xray-core answers by closing the connection.
pub async fn parse_http_connect_request<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<HttpConnectRequest, HttpParseError> {
    let request_line = read_line_limited(&mut reader).await?;
    let request_line =
        std::str::from_utf8(trim_line_end(&request_line)).map_err(|_| HttpParseError::Malformed)?;
    let (method, rest) = request_line
        .split_once(' ')
        .ok_or(HttpParseError::Malformed)?;
    let (request_target, version) = rest.split_once(' ').ok_or(HttpParseError::Malformed)?;
    if !is_token(method.as_bytes()) || !is_http_version(version) {
        return Err(HttpParseError::Malformed);
    }
    // Go reads a target as an authority only for `CONNECT` exactly.
    let target = (method == "CONNECT")
        .then(|| parse_connect_target(request_target))
        .transpose()?;
    let proxy_authorization = read_headers(&mut reader).await?;
    Ok(HttpConnectRequest {
        target,
        proxy_authorization,
    })
}

/// Reads header lines up to the blank one, keeping the first
/// `Proxy-Authorization` value.
async fn read_headers<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Zeroizing<Vec<u8>>>, HttpParseError> {
    let mut proxy_authorization = None;
    let mut hosts = 0;
    let mut first = true;
    loop {
        let line = Zeroizing::new(read_line_limited(reader).await?);
        let line = trim_line_end(&line);
        if line.is_empty() {
            return Ok(proxy_authorization);
        }
        // A line that starts with whitespace continues the previous header,
        // which Go folds into it, but cannot open the header block.
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if first {
                return Err(HttpParseError::Malformed);
            }
            continue;
        }
        first = false;
        let colon = line
            .iter()
            .position(|&byte| byte == b':')
            .ok_or(HttpParseError::Malformed)?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&byte| is_token_byte(byte) || byte == b' ') {
            return Err(HttpParseError::Malformed);
        }
        // Go leaves a name with a space as it is, so it is neither header.
        if name.eq_ignore_ascii_case(b"host") {
            hosts += 1;
            if hosts > 1 {
                return Err(HttpParseError::Malformed);
            }
        } else if name.eq_ignore_ascii_case(b"proxy-authorization") && proxy_authorization.is_none()
        {
            proxy_authorization = Some(Zeroizing::new(line[colon + 1..].trim_ascii().to_vec()));
        }
    }
}

fn trim_line_end(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// RFC 9110 token characters, as Go's `httpguts` checks a method or a header
/// name.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_token(text: &[u8]) -> bool {
    !text.is_empty() && text.iter().all(|&byte| is_token_byte(byte))
}

/// Go's `ParseHTTPVersion`: `HTTP/` and one digit, a dot and one digit.
fn is_http_version(version: &str) -> bool {
    matches!(
        version.as_bytes(),
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit()
    )
}

/// The target of a `CONNECT` request, as Go's URL parser and Xray-core's
/// `ParseHost` read an authority. A missing or empty port is port 80; a port
/// is digits read as Go's `strconv.Atoi` reads them and cut to 16 bits, so
/// `70000` is port 4464, as in Xray-core. A host with a colon needs brackets.
fn parse_connect_target(authority: &str) -> Result<Target, HttpParseError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or(HttpParseError::InvalidAuthority)?;
        match rest {
            "" => (host, None),
            _ => (
                host,
                Some(
                    rest.strip_prefix(':')
                        .ok_or(HttpParseError::InvalidAuthority)?,
                ),
            ),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, _)) if host.contains(':') => return Err(HttpParseError::InvalidAuthority),
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        None | Some("") => DEFAULT_CONNECT_PORT,
        Some(port) => parse_port(port)?,
    };
    let bracketed = authority.starts_with('[');
    Ok(Target::new(
        parse_host(host, bracketed)?,
        port,
        Network::Tcp,
    ))
}

fn parse_port(port: &str) -> Result<u16, HttpParseError> {
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpParseError::InvalidPort);
    }
    let value = port
        .parse::<i64>()
        .map_err(|_| HttpParseError::InvalidPort)?;
    // Go converts the int to a 16-bit port, keeping its low bits.
    let port = value.to_le_bytes();
    match u16::from_le_bytes([port[0], port[1]]) {
        // Port 0 cannot be dialed; Xray-core answers it before failing to.
        0 => Err(HttpParseError::InvalidPort),
        port => Ok(port),
    }
}

/// A host Go's URL parser accepts: letters, digits, `-._~`, the sub-delims,
/// anything outside ASCII, and inside brackets colons. Go refuses `%` for an
/// ASCII byte, which is refused here for any byte.
fn parse_host(host: &str, bracketed: bool) -> Result<TargetAddr, HttpParseError> {
    let allowed = |byte: u8| {
        !byte.is_ascii()
            || byte.is_ascii_alphanumeric()
            || b"-._~!$&'()*+,;=<>\"".contains(&byte)
            || (bracketed && byte == b':')
    };
    if host.is_empty() || !host.bytes().all(allowed) {
        return Err(HttpParseError::InvalidAuthority);
    }

    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(TargetAddr::Ip(ip)),
        Err(_) => Ok(TargetAddr::Domain(host.to_owned())),
    }
}

/// A user name and password from `Proxy-Authorization`, wiped on drop.
pub type HttpBasicCredentials = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// Go's `parseBasicAuth` in Xray's HTTP server: a case-sensitive `Basic `
/// prefix, padded standard base64, and a split at the first colon.
pub fn decode_http_basic_credentials(value: &[u8]) -> Option<HttpBasicCredentials> {
    use base64::Engine as _;
    let encoded = value.strip_prefix(b"Basic ")?;
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?,
    );
    let colon = decoded.iter().position(|&byte| byte == b':')?;
    Some((
        Zeroizing::new(decoded[..colon].to_vec()),
        Zeroizing::new(decoded[colon + 1..].to_vec()),
    ))
}

/// The accounts an HTTP server requires as `Proxy-Authorization: Basic`
/// credentials: an HTTP inbound's, or a SOCKS inbound's for HTTP on its port.
/// As Xray-core keeps them, a name has one password, a later account
/// replacing an earlier one, and names and passwords may be any strings.
/// They are credentials: never log them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HttpInboundAccounts {
    accounts: Vec<HttpBasicCredentials>,
}

impl HttpInboundAccounts {
    pub fn insert(&mut self, user: &[u8], pass: &[u8]) {
        let pass = Zeroizing::new(pass.to_vec());
        match self
            .accounts
            .iter_mut()
            .find(|(known, _)| known.as_slice() == user)
        {
            Some((_, known)) => *known = pass,
            None => self.accounts.push((Zeroizing::new(user.to_vec()), pass)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Who a request proceeds as: `None` when it is refused, `Some(None)`
    /// when there are no accounts. As Xray-core's `HasAccount`, the name
    /// picks the account and the password must be its own. Every account is
    /// compared in constant time, so timing does not reveal which matched.
    pub fn basic_user(&self, proxy_authorization: Option<&[u8]>) -> Option<Option<InboundUser>> {
        use aws_lc_rs::constant_time::verify_slices_are_equal;
        if self.accounts.is_empty() {
            return Some(None);
        }
        let (user, pass) = proxy_authorization.and_then(decode_http_basic_credentials)?;
        let admitted = self
            .accounts
            .iter()
            .fold(false, |admitted, (known_user, known_pass)| {
                let user_matches = verify_slices_are_equal(known_user, &user).is_ok();
                let pass_matches = verify_slices_are_equal(known_pass, &pass).is_ok();
                admitted | (user_matches & pass_matches)
            });
        admitted.then(|| Some(InboundUser::new(&user)))
    }
}

/// The accounts Xray-core's SOCKS inbound hands its HTTP server: those of
/// `password` authentication.
impl From<&SocksInboundAuth> for HttpInboundAccounts {
    fn from(auth: &SocksInboundAuth) -> Self {
        let mut accounts = Self::default();
        if let SocksInboundAuth::Password(socks) = auth {
            for account in socks {
                accounts.insert(account.user(), account.pass());
            }
        }
        accounts
    }
}

impl fmt::Debug for HttpInboundAccounts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpInboundAccounts")
            .field("accounts", &self.accounts.len())
            .finish()
    }
}

async fn read_line_limited<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, HttpParseError> {
    let mut line = Vec::new();

    loop {
        if line.len() >= MAX_REQUEST_LINE_LEN {
            return Err(HttpParseError::LineTooLong);
        }

        let byte = reader.read_u8().await.map_err(|_| HttpParseError::Io)?;
        line.push(byte);
        if byte == b'\n' {
            return Ok(line);
        }
    }
}
