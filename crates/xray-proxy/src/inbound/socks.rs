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
const PASSWORD_AUTH_FAILURE: u8 = 0x01;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SocksParseError {
    #[error("unsupported socks version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported socks command {0}")]
    UnsupportedCommand(u8),
    #[error("invalid socks reserved byte {0}")]
    InvalidReserved(u8),
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
    #[error("unsupported socks username/password version {0}")]
    UnsupportedAuthVersion(u8),
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
    /// Returns `None` unless both values contain 1..=255 bytes.
    pub fn new(user: &[u8], pass: &[u8]) -> Option<Self> {
        let valid = |value: &[u8]| (1..=MAX_SOCKS_CREDENTIAL_LENGTH).contains(&value.len());
        (valid(user) && valid(pass)).then(|| Self {
            user: Zeroizing::new(user.to_vec()),
            pass: Zeroizing::new(pass.to_vec()),
        })
    }

    /// The username, 1..=255 bytes. It is a credential: never log it.
    pub fn user(&self) -> &[u8] {
        &self.user
    }

    /// The password, 1..=255 bytes. It is a credential: never log it.
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

/// Authentication required by a SOCKS inbound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SocksInboundAuth {
    #[default]
    NoAuth,
    /// RFC 1929 username/password; the list is never empty when built by the parser.
    Password(Vec<SocksAccount>),
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
    negotiate_socks5(stream, &SocksInboundAuth::NoAuth).await
}

/// Runs SOCKS5 method selection and, for [`SocksInboundAuth::Password`], the
/// RFC 1929 sub-negotiation. Only the method matching `auth` is ever selected.
pub async fn negotiate_socks5<S>(
    mut stream: S,
    auth: &SocksInboundAuth,
) -> Result<(), SocksParseError>
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
        SocksInboundAuth::NoAuth => Ok(()),
        SocksInboundAuth::Password(accounts) => verify_password(&mut stream, accounts).await,
    }
}

/// RFC 1929: `VER=1 | ULEN | UNAME | PLEN | PASSWD`, answered with `VER=1 | STATUS`.
async fn verify_password<S>(
    stream: &mut S,
    accounts: &[SocksAccount],
) -> Result<(), SocksParseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if version != PASSWORD_AUTH_VERSION {
        let _ = stream
            .write_all(&[PASSWORD_AUTH_VERSION, PASSWORD_AUTH_FAILURE])
            .await;
        return Err(SocksParseError::UnsupportedAuthVersion(version));
    }
    let user = read_credential(stream).await?;
    let pass = read_credential(stream).await?;
    // `fold` with a non-short-circuit `|` checks every account, so the timing
    // does not reveal which one matched; `any` would stop at the first.
    let accepted = accounts.iter().fold(false, |accepted, account| {
        accepted | account.matches(&user, &pass)
    });
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
        Ok(())
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

pub async fn parse_socks5_request_message<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<SocksRequest, SocksParseError> {
    let mut head = [0; 4];
    reader
        .read_exact(&mut head)
        .await
        .map_err(|_| SocksParseError::Io)?;

    let request_version = head[0];
    if request_version != 5 {
        return Err(SocksParseError::UnsupportedVersion(request_version));
    }

    let command = match head[1] {
        1 => SocksCommand::Connect,
        3 => SocksCommand::UdpAssociate,
        other => return Err(SocksParseError::UnsupportedCommand(other)),
    };

    let reserved = head[2];
    if reserved != 0 {
        return Err(SocksParseError::InvalidReserved(reserved));
    }

    let network = match command {
        SocksCommand::Connect => Network::Tcp,
        SocksCommand::UdpAssociate => Network::Udp,
    };
    let (addr, port) = read_socks5_address(&mut reader, head[3]).await?;

    Ok(SocksRequest {
        command,
        target: Target::new(addr, port, network),
    })
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

pub async fn write_socks5_failure<W: AsyncWrite + Unpin>(
    mut writer: W,
) -> Result<(), SocksParseError> {
    writer
        .write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
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

pub fn parse_socks5_udp_datagram(raw: &[u8]) -> Result<SocksUdpDatagram, SocksParseError> {
    if raw.len() < 4 {
        return Err(SocksParseError::TruncatedUdpDatagram);
    }
    if raw[0] != 0 || raw[1] != 0 {
        return Err(SocksParseError::InvalidReserved(raw[1]));
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
    /// A zero-length or non-UTF-8 domain.
    InvalidDomain,
    UnsupportedType(u8),
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
            domain_and_port.truncate(len);
            let domain =
                String::from_utf8(domain_and_port).map_err(|_| AddressReadError::InvalidDomain)?;
            Ok((TargetAddr::Domain(domain), port))
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
                TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(octets))),
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
            Ok((
                TargetAddr::Domain(
                    String::from_utf8(domain.to_vec())
                        .map_err(|_| SocksParseError::InvalidDomain)?,
                ),
                end,
            ))
        }
        4 => {
            let start = offset + 1;
            let end = start + 16;
            let octets = raw
                .get(start..end)
                .ok_or(SocksParseError::TruncatedUdpDatagram)?;
            let mut addr = [0; 16];
            addr.copy_from_slice(octets);
            Ok((TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(addr))), end))
        }
        other => Err(SocksParseError::UnsupportedAddressType(other)),
    }
}
