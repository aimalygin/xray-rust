use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_routing::{Network, Target, TargetAddr};
use zeroize::Zeroizing;

/// RFC 1929 caps both the username and the password at 255 bytes.
pub const MAX_SOCKS_CREDENTIAL_LENGTH: usize = u8::MAX as usize;

pub(crate) const METHOD_NO_AUTH: u8 = 0x00;
pub(crate) const METHOD_PASSWORD: u8 = 0x02;
pub(crate) const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
pub(crate) const PASSWORD_AUTH_VERSION: u8 = 0x01;
pub(crate) const PASSWORD_AUTH_SUCCESS: u8 = 0x00;
/// Xray-core refuses a login with `0xFF`; RFC 1929 asks only for nonzero.
const PASSWORD_AUTH_FAILURE: u8 = 0xff;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_CONNECT: u8 = 0x01;
const SOCKS5_UDP_ASSOCIATE: u8 = 0x03;
/// Tor's `RESOLVE` and `RESOLVE_PTR`, which Xray-core takes for `CONNECT`.
const SOCKS5_TOR_RESOLVE: u8 = 0xf0;
const SOCKS5_TOR_RESOLVE_PTR: u8 = 0xf1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SocksParseError {
    #[error("unsupported socks version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported socks command {0}")]
    UnsupportedCommand(u8),
    #[error("unsupported socks address type {0}")]
    UnsupportedAddressType(u8),
    #[error("invalid socks domain")]
    InvalidDomain,
    #[error("socks udp fragmentation is unsupported")]
    UnsupportedUdpFragment,
    #[error("socks udp datagram is truncated")]
    TruncatedUdpDatagram,
    #[error("socks udp payload is too large")]
    PayloadTooLarge,
    #[error("no acceptable socks authentication methods")]
    NoAcceptableMethods,
    #[error("socks username/password authentication failed")]
    AuthenticationFailed,
    #[error("io error")]
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksCommand {
    Connect,
    UdpAssociate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    pub command: SocksCommand,
    pub target: Target,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksUdpDatagram {
    pub target: Target,
    pub payload: Bytes,
}

/// One RFC 1929 username/password pair accepted by a SOCKS inbound.
#[derive(Clone, PartialEq, Eq)]
pub struct SocksAccount {
    user: Zeroizing<Vec<u8>>,
    pass: Zeroizing<Vec<u8>>,
}

impl SocksAccount {
    /// Returns `None` when either value is longer than the 255 bytes RFC 1929
    /// can carry. Empty values are kept, as Xray-core keeps them.
    pub fn new(user: &[u8], pass: &[u8]) -> Option<Self> {
        let valid = |value: &[u8]| value.len() <= MAX_SOCKS_CREDENTIAL_LENGTH;
        (valid(user) && valid(pass)).then(|| Self {
            user: Zeroizing::new(user.to_vec()),
            pass: Zeroizing::new(pass.to_vec()),
        })
    }

    /// The username, at most 255 bytes. It is a credential: never log it.
    pub fn user(&self) -> &[u8] {
        &self.user
    }

    /// The password, at most 255 bytes. It is a credential: never log it.
    pub fn pass(&self) -> &[u8] {
        &self.pass
    }

    /// Compares both halves in constant time and always checks both.
    fn matches(&self, user: &[u8], pass: &[u8]) -> bool {
        use aws_lc_rs::constant_time::verify_slices_are_equal;
        let user_matches = verify_slices_are_equal(&self.user, user).is_ok();
        let pass_matches = verify_slices_are_equal(&self.pass, pass).is_ok();
        user_matches & pass_matches
    }
}

impl fmt::Debug for SocksAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocksAccount")
            .field("user", &"<redacted>")
            .field("pass", &"<redacted>")
            .finish()
    }
}

/// The account name a client authenticated with, which Xray-core gives
/// routing as the user's email. It is a credential: never log it.
#[derive(Clone, PartialEq, Eq)]
pub struct InboundUser(Zeroizing<String>);

impl InboundUser {
    pub(crate) fn new(user: &[u8]) -> Self {
        Self(Zeroizing::new(String::from_utf8_lossy(user).into_owned()))
    }

    /// The name, its invalid UTF-8 replaced.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InboundUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InboundUser(<redacted>)")
    }
}

/// Authentication required by a SOCKS inbound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SocksInboundAuth {
    #[default]
    NoAuth,
    /// RFC 1929 username/password. The parser never builds an empty list,
    /// and keeps one account per name, the last given, as Xray-core does.
    Password(Vec<SocksAccount>),
}

/// `fold` with a non-short-circuit `|` checks every account, so the timing
/// does not reveal which one matched; `any` would stop at the first.
fn accounts_admit(accounts: &[SocksAccount], user: &[u8], pass: &[u8]) -> bool {
    accounts.iter().fold(false, |accepted, account| {
        accepted | account.matches(user, pass)
    })
}

impl SocksInboundAuth {
    pub const fn requires_password(&self) -> bool {
        matches!(self, Self::Password(_))
    }

    /// The RFC 1928 method code this inbound selects.
    const fn method(&self) -> u8 {
        match self {
            Self::NoAuth => METHOD_NO_AUTH,
            Self::Password(_) => METHOD_PASSWORD,
        }
    }
}

pub async fn negotiate_socks5_no_auth<S>(stream: S) -> Result<(), SocksParseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_socks5(stream, &SocksInboundAuth::NoAuth)
        .await
        .map(|_| ())
}

/// Runs SOCKS5 method selection and, for [`SocksInboundAuth::Password`], the
/// RFC 1929 sub-negotiation. Only the method matching `auth` is ever selected.
/// Returns the user the client authenticated as, if `auth` has accounts.
pub async fn negotiate_socks5<S>(
    mut stream: S,
    auth: &SocksInboundAuth,
) -> Result<Option<InboundUser>, SocksParseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0; 2];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| SocksParseError::Io)?;

    let version = head[0];
    if version != 5 {
        return Err(SocksParseError::UnsupportedVersion(version));
    }

    let method_count = head[1];
    let mut methods = [0; u8::MAX as usize];
    let methods = &mut methods[..usize::from(method_count)];
    stream
        .read_exact(methods)
        .await
        .map_err(|_| SocksParseError::Io)?;

    let wanted = auth.method();
    if !methods.contains(&wanted) {
        stream
            .write_all(&[5, METHOD_NONE_ACCEPTABLE])
            .await
            .map_err(|_| SocksParseError::Io)?;
        return Err(SocksParseError::NoAcceptableMethods);
    }
    stream
        .write_all(&[5, wanted])
        .await
        .map_err(|_| SocksParseError::Io)?;

    match auth {
        SocksInboundAuth::NoAuth => Ok(None),
        SocksInboundAuth::Password(accounts) => {
            verify_password(&mut stream, accounts).await.map(Some)
        }
    }
}

/// RFC 1929: `VER=1 | ULEN | UNAME | PLEN | PASSWD`, answered with `VER=1 | STATUS`.
/// As in Xray-core, `VER` is not checked.
async fn verify_password<S>(
    stream: &mut S,
    accounts: &[SocksAccount],
) -> Result<InboundUser, SocksParseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let user = read_credential(stream).await?;
    let pass = read_credential(stream).await?;
    let accepted = accounts_admit(accounts, &user, &pass);
    let status = if accepted {
        PASSWORD_AUTH_SUCCESS
    } else {
        PASSWORD_AUTH_FAILURE
    };
    stream
        .write_all(&[PASSWORD_AUTH_VERSION, status])
        .await
        .map_err(|_| SocksParseError::Io)?;
    if accepted {
        Ok(InboundUser::new(&user))
    } else {
        Err(SocksParseError::AuthenticationFailed)
    }
}

async fn read_credential<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Zeroizing<Vec<u8>>, SocksParseError> {
    let length = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let mut value = Zeroizing::new(vec![0; usize::from(length)]);
    reader
        .read_exact(&mut value)
        .await
        .map_err(|_| SocksParseError::Io)?;
    Ok(value)
}

/// Reads a SOCKS5 request: [`read_socks5_command`], then
/// [`read_socks5_target`].
pub async fn parse_socks5_request_message<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<SocksRequest, SocksParseError> {
    let command = read_socks5_command(&mut reader).await?;
    let target = read_socks5_target(&mut reader, command).await?;
    Ok(SocksRequest { command, target })
}

/// Reads the `VER | CMD | RSV` that opens a SOCKS5 request, as Xray-core
/// v26.10.31 reads it: only the command is checked, and Tor's `RESOLVE` and
/// `RESOLVE_PTR` are taken for `CONNECT`. Any other command is
/// [`SocksParseError::UnsupportedCommand`], which Xray-core refuses before
/// reading the address.
pub async fn read_socks5_command<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<SocksCommand, SocksParseError> {
    let mut head = [0; 3];
    reader
        .read_exact(&mut head)
        .await
        .map_err(|_| SocksParseError::Io)?;
    match head[1] {
        SOCKS5_CONNECT | SOCKS5_TOR_RESOLVE | SOCKS5_TOR_RESOLVE_PTR => Ok(SocksCommand::Connect),
        SOCKS5_UDP_ASSOCIATE => Ok(SocksCommand::UdpAssociate),
        other => Err(SocksParseError::UnsupportedCommand(other)),
    }
}

/// Reads the `ATYP | DST.ADDR | DST.PORT` that follows a request's command.
pub async fn read_socks5_target<R: AsyncRead + Unpin>(
    mut reader: R,
    command: SocksCommand,
) -> Result<Target, SocksParseError> {
    let address_type = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let (addr, port) = read_socks5_address(&mut reader, address_type).await?;
    let network = match command {
        SocksCommand::Connect => Network::Tcp,
        SocksCommand::UdpAssociate => Network::Udp,
    };
    Ok(Target::new(addr, port, network))
}

pub async fn parse_socks5_request<R: AsyncRead + Unpin>(
    reader: R,
) -> Result<Target, SocksParseError> {
    let request = parse_socks5_request_message(reader).await?;
    if request.command != SocksCommand::Connect {
        return Err(SocksParseError::UnsupportedCommand(3));
    }
    Ok(request.target)
}

pub async fn parse_socks5_connect<S>(mut stream: S) -> Result<Target, SocksParseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_socks5_no_auth(&mut stream).await?;
    parse_socks5_request(stream).await
}

pub async fn write_socks5_success<W: AsyncWrite + Unpin>(
    mut writer: W,
) -> Result<(), SocksParseError> {
    writer
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|_| SocksParseError::Io)
}

pub async fn write_socks5_success_with_bind<W: AsyncWrite + Unpin>(
    mut writer: W,
    bind: SocketAddr,
) -> Result<(), SocksParseError> {
    let mut response = vec![5, 0, 0];
    match bind {
        SocketAddr::V4(addr) => {
            response.push(1);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            response.push(4);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    writer
        .write_all(&response)
        .await
        .map_err(|_| SocksParseError::Io)
}

pub async fn write_socks5_failure<W: AsyncWrite + Unpin>(writer: W) -> Result<(), SocksParseError> {
    write_socks5_error(writer, REPLY_GENERAL_FAILURE).await
}

/// Refuses a request with `REP = 0x07` (command not supported) and a
/// `0.0.0.0:0` bind address, the reply Xray-core sends for `UDP ASSOCIATE`
/// on an inbound with `"udp": false`.
pub async fn write_socks5_command_not_supported<W: AsyncWrite + Unpin>(
    writer: W,
) -> Result<(), SocksParseError> {
    write_socks5_error(writer, REPLY_COMMAND_NOT_SUPPORTED).await
}

async fn write_socks5_error<W: AsyncWrite + Unpin>(
    mut writer: W,
    reply: u8,
) -> Result<(), SocksParseError> {
    writer
        .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|_| SocksParseError::Io)
}

pub fn encode_socks5_udp_datagram(
    target: &Target,
    payload: &[u8],
) -> Result<Vec<u8>, SocksParseError> {
    if target.network != Network::Udp {
        return Err(SocksParseError::UnsupportedCommand(1));
    }
    let mut datagram = vec![0, 0, 0];
    encode_target_addr(&mut datagram, &target.addr)?;
    datagram.extend_from_slice(&target.port.to_be_bytes());
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

/// Reads a SOCKS5 UDP datagram as Xray-core does: its two reserved bytes are
/// not checked, and a fragment is refused.
pub fn parse_socks5_udp_datagram(raw: &[u8]) -> Result<SocksUdpDatagram, SocksParseError> {
    if raw.len() < 4 {
        return Err(SocksParseError::TruncatedUdpDatagram);
    }
    if raw[2] != 0 {
        return Err(SocksParseError::UnsupportedUdpFragment);
    }

    let (addr, offset) = parse_target_addr(raw, 3)?;
    if raw.len() < offset + 2 {
        return Err(SocksParseError::TruncatedUdpDatagram);
    }
    let port = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
    Ok(SocksUdpDatagram {
        target: Target::new(addr, port, Network::Udp),
        payload: Bytes::copy_from_slice(&raw[offset + 2..]),
    })
}

/// Why a SOCKS5 `ADDR | PORT` field could not be read.
pub(crate) enum AddressReadError {
    Io(std::io::Error),
    /// A domain that [`socks_domain_address`] refuses.
    InvalidDomain,
    UnsupportedType(u8),
}

/// A SOCKS5 domain address as Xray-core's address parser reads it. A name
/// that starts with `[` or a digit and is an IP literal to Go's
/// `net.ParseAddress` is that IP. Any other name may hold only ASCII letters,
/// digits, `-`, `.` and `_`.
fn socks_domain_address(raw: &[u8]) -> Option<TargetAddr> {
    let first = *raw.first()?;
    if first == b'[' || first.is_ascii_digit() {
        let ip = std::str::from_utf8(raw)
            .ok()
            .and_then(|text| go_address_text(text).parse::<IpAddr>().ok());
        if let Some(ip) = ip {
            return Some(TargetAddr::Ip(ip.to_canonical()));
        }
    }
    raw.iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
        .then(|| TargetAddr::Domain(raw.iter().map(|&byte| char::from(byte)).collect()))
}

/// Go's `net.ParseAddress`: an IP literal, an IPv4-mapped one as IPv4, or
/// else a domain of the text that [`go_address_text`] leaves.
pub(crate) fn go_parse_address(text: &str) -> TargetAddr {
    let text = go_address_text(text);
    match text.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(ip.to_canonical()),
        Err(_) => TargetAddr::Domain(text.to_owned()),
    }
}

/// The text Go's `net.ParseAddress` reads: without enclosing brackets, and
/// trimmed of white space. Go trims only a text that starts or ends with
/// neither a letter nor a digit, which is the only kind with any to trim.
fn go_address_text(text: &str) -> &str {
    text.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(text)
        .trim()
}

/// An IPv6 address field, which Xray-core reads as IPv4 when it is
/// IPv4-mapped.
fn socks_ipv6_address(octets: [u8; 16]) -> TargetAddr {
    TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical())
}

impl From<AddressReadError> for SocksParseError {
    fn from(error: AddressReadError) -> Self {
        match error {
            AddressReadError::Io(_) => Self::Io,
            AddressReadError::InvalidDomain => Self::InvalidDomain,
            AddressReadError::UnsupportedType(other) => Self::UnsupportedAddressType(other),
        }
    }
}

/// Reads the `ADDR | PORT` that follows an already-read `ATYP`. Only exact
/// reads are used, so nothing past the port is consumed. Shared by the request
/// parser and the client-side reply reader.
pub(crate) async fn read_socks5_address<R: AsyncRead + Unpin>(
    reader: &mut R,
    address_type: u8,
) -> Result<(TargetAddr, u16), AddressReadError> {
    match address_type {
        1 => {
            let mut raw = [0; 6];
            reader
                .read_exact(&mut raw)
                .await
                .map_err(AddressReadError::Io)?;
            let [a, b, c, d, high, low] = raw;
            Ok((
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
                u16::from_be_bytes([high, low]),
            ))
        }
        3 => {
            let len = usize::from(reader.read_u8().await.map_err(AddressReadError::Io)?);
            if len == 0 {
                return Err(AddressReadError::InvalidDomain);
            }
            let mut domain_and_port = vec![0; len + 2];
            reader
                .read_exact(&mut domain_and_port)
                .await
                .map_err(AddressReadError::Io)?;
            let port = u16::from_be_bytes([domain_and_port[len], domain_and_port[len + 1]]);
            let addr = socks_domain_address(&domain_and_port[..len])
                .ok_or(AddressReadError::InvalidDomain)?;
            Ok((addr, port))
        }
        4 => {
            let mut raw = [0; 18];
            reader
                .read_exact(&mut raw)
                .await
                .map_err(AddressReadError::Io)?;
            let mut octets = [0; 16];
            octets.copy_from_slice(&raw[..16]);
            Ok((
                socks_ipv6_address(octets),
                u16::from_be_bytes([raw[16], raw[17]]),
            ))
        }
        other => Err(AddressReadError::UnsupportedType(other)),
    }
}

pub(crate) fn encode_target_addr(
    output: &mut Vec<u8>,
    addr: &TargetAddr,
) -> Result<(), SocksParseError> {
    match addr {
        TargetAddr::Ip(IpAddr::V4(addr)) => {
            output.push(1);
            output.extend_from_slice(&addr.octets());
        }
        TargetAddr::Ip(IpAddr::V6(addr)) => {
            output.push(4);
            output.extend_from_slice(&addr.octets());
        }
        TargetAddr::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| SocksParseError::InvalidDomain)?;
            if len == 0 {
                return Err(SocksParseError::InvalidDomain);
            }
            output.push(3);
            output.push(len);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

fn parse_target_addr(raw: &[u8], offset: usize) -> Result<(TargetAddr, usize), SocksParseError> {
    let address_type = *raw
        .get(offset)
        .ok_or(SocksParseError::TruncatedUdpDatagram)?;
    match address_type {
        1 => {
            let start = offset + 1;
            let end = start + 4;
            let octets = raw
                .get(start..end)
                .ok_or(SocksParseError::TruncatedUdpDatagram)?;
            Ok((
                TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(
                    octets[0], octets[1], octets[2], octets[3],
                ))),
                end,
            ))
        }
        3 => {
            let len = *raw
                .get(offset + 1)
                .ok_or(SocksParseError::TruncatedUdpDatagram)?;
            if len == 0 {
                return Err(SocksParseError::InvalidDomain);
            }
            let start = offset + 2;
            let end = start + usize::from(len);
            let domain = raw
                .get(start..end)
                .ok_or(SocksParseError::TruncatedUdpDatagram)?;
            let addr = socks_domain_address(domain).ok_or(SocksParseError::InvalidDomain)?;
            Ok((addr, end))
        }
        4 => {
            let start = offset + 1;
            let end = start + 16;
            let octets = raw
                .get(start..end)
                .ok_or(SocksParseError::TruncatedUdpDatagram)?;
            let mut addr = [0; 16];
            addr.copy_from_slice(octets);
            Ok((socks_ipv6_address(addr), end))
        }
        other => Err(SocksParseError::UnsupportedAddressType(other)),
    }
}

/// The first byte of a SOCKS 4 or 4a request.
pub const SOCKS4_VERSION: u8 = 0x04;
const SOCKS4_CONNECT: u8 = 0x01;
/// A SOCKS 4 reply: version 0, status, then port and address, which Xray
/// leaves zero.
pub const SOCKS4_GRANTED: [u8; 8] = [0x00, 90, 0, 0, 0, 0, 0, 0];
pub const SOCKS4_REJECTED: [u8; 8] = [0x00, 91, 0, 0, 0, 0, 0, 0];
/// A user ID or SOCKS 4a domain longer than this is refused. Xray allows up to
/// its 8 KiB buffer; a DNS name has at most 253 bytes.
const MAX_SOCKS4_STRING: usize = 255;

/// Reads a SOCKS 4 or 4a `CONNECT` after its version byte, as Xray-core
/// accepts it: the user ID is ignored, and an address whose first byte is zero
/// is followed by a domain (4a), read with Go's `net.ParseAddress`. Other
/// commands are refused, as are a 4a domain that is empty or not UTF-8,
/// which Xray-core grants and then fails to dial.
pub async fn parse_socks4_connect<R>(mut reader: R) -> Result<Target, SocksParseError>
where
    R: AsyncRead + Unpin,
{
    let command = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let port = reader.read_u16().await.map_err(|_| SocksParseError::Io)?;
    let mut ip = [0; 4];
    reader
        .read_exact(&mut ip)
        .await
        .map_err(|_| SocksParseError::Io)?;
    read_socks4_string(&mut reader).await?;
    let addr = if ip[0] == 0 {
        let domain = read_socks4_string(&mut reader).await?;
        let domain = String::from_utf8(domain).map_err(|_| SocksParseError::InvalidDomain)?;
        match go_parse_address(&domain) {
            TargetAddr::Domain(name) if name.is_empty() => {
                return Err(SocksParseError::InvalidDomain)
            }
            addr => addr,
        }
    } else {
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(ip)))
    };
    if command != SOCKS4_CONNECT {
        return Err(SocksParseError::UnsupportedCommand(command));
    }
    Ok(Target::new(addr, port, Network::Tcp))
}

async fn read_socks4_string<R>(reader: &mut R) -> Result<Vec<u8>, SocksParseError>
where
    R: AsyncRead + Unpin,
{
    let mut value = Vec::new();
    loop {
        match reader.read_u8().await.map_err(|_| SocksParseError::Io)? {
            0 => return Ok(value),
            _ if value.len() == MAX_SOCKS4_STRING => return Err(SocksParseError::InvalidDomain),
            byte => value.push(byte),
        }
    }
}
