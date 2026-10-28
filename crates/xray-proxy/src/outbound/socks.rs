//! SOCKS5 client (RFC 1928 CONNECT and UDP ASSOCIATE with optional RFC 1929
//! auth).
//!
//! The wire behaviour follows Xray-core v26.7.28 `proxy/socks/protocol.go`:
//! exactly one method is offered and each step is a separate write that waits
//! for its reply. Unlike Xray, every length and version byte is checked, and a
//! zero-length bound domain is an error rather than a crash.
//!
//! UDP ASSOCIATE deliberately differs from Xray, which always declares
//! `0.0.0.0:0`: the client declares its relay socket's real address so that
//! servers which pin the association to the declared endpoint (RFC 1928
//! section 7) accept it. Received datagrams that are malformed, fragmented or
//! not from the relay are dropped one by one instead of ending the session,
//! and an oversized payload is an error instead of an empty datagram.
//!
//! This module does not dial or time out; callers bound the whole handshake.

use std::io;
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_routing::{Target, TargetAddr};
use zeroize::Zeroizing;

use crate::inbound::{
    encode_target_addr, parse_socks5_udp_datagram, read_socks5_address, AddressReadError,
    SocksAccount, SocksParseError, SocksUdpDatagram, METHOD_NONE_ACCEPTABLE, METHOD_NO_AUTH,
    METHOD_PASSWORD, PASSWORD_AUTH_SUCCESS, PASSWORD_AUTH_VERSION,
};

const VERSION: u8 = 5;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const REPLY_SUCCEEDED: u8 = 0x00;
const MAX_DOMAIN_LENGTH: usize = u8::MAX as usize;

/// The largest UDP request datagram, header included, that the client sends.
///
/// Xray-core reads each relay datagram into one 8 KiB buffer and silently
/// truncates anything longer, so a larger payload is refused before sending.
pub const MAX_SOCKS_UDP_DATAGRAM_LENGTH: usize = 8192;

/// A failed SOCKS5 client handshake. No variant carries a credential.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SocksClientError {
    #[error("SOCKS target port must be nonzero")]
    InvalidTargetPort,
    #[error("SOCKS target domain must contain 1..=255 bytes without whitespace or controls")]
    InvalidTargetDomain,
    #[error("SOCKS io error: {0}")]
    Io(io::ErrorKind),
    #[error("unexpected SOCKS server version {0}")]
    UnexpectedVersion(u8),
    #[error("SOCKS server accepts none of the offered authentication methods")]
    NoAcceptableMethod,
    #[error("SOCKS server selected unoffered authentication method {0}")]
    UnexpectedMethod(u8),
    #[error("unexpected SOCKS username/password version {0}")]
    UnexpectedAuthVersion(u8),
    #[error("SOCKS server rejected the username/password with status {0}")]
    AuthRejected(u8),
    #[error("SOCKS server rejected the request: {text} ({0})", text = reply_text(*.0))]
    RequestRejected(u8),
    #[error("unsupported SOCKS reply address type {0}")]
    UnsupportedAddressType(u8),
    #[error("malformed SOCKS reply address")]
    MalformedReply,
    #[error("SOCKS server returned an unusable UDP relay address")]
    InvalidRelayAddress,
    #[error("SOCKS UDP datagram exceeds {MAX_SOCKS_UDP_DATAGRAM_LENGTH} bytes")]
    UdpPayloadTooLarge,
}

/// Why a datagram received on the client's UDP relay socket was dropped.
///
/// A drop never ends the association: only that datagram is discarded.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SocksUdpDrop {
    #[error("SOCKS UDP datagram did not come from the relay")]
    ForeignSource,
    #[error("fragmented SOCKS UDP datagram")]
    Fragmented,
    #[error("malformed SOCKS UDP datagram")]
    Malformed,
}

impl From<io::Error> for SocksClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<AddressReadError> for SocksClientError {
    fn from(error: AddressReadError) -> Self {
        match error {
            AddressReadError::Io(error) => error.into(),
            AddressReadError::InvalidDomain => Self::MalformedReply,
            AddressReadError::UnsupportedType(other) => Self::UnsupportedAddressType(other),
        }
    }
}

/// RFC 1928 section 6 reply codes.
const fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "general SOCKS server failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unassigned reply code",
    }
}

/// Opens a CONNECT tunnel to `target` over an established `stream`.
///
/// `target.network` is ignored: the request is always CONNECT. An
/// IPv4-mapped IPv6 target is sent as IPv4, as Xray does. On success the
/// stream is positioned at the first tunnel byte; the reply's bound address
/// is read exactly and discarded.
pub async fn socks5_connect<S>(
    stream: &mut S,
    account: Option<&SocksAccount>,
    target: &Target,
) -> Result<(), SocksClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = encode_connect_request(target)?;
    negotiate(stream, account).await?;
    write_flushed(stream, &request).await?;
    read_reply(stream).await.map(drop)
}

/// Opens a UDP association over an established control `stream` and returns
/// the relay address that datagrams go to.
///
/// `client_endpoint` is the local address of the socket that will send the
/// datagrams; it is declared in the request as RFC 1928 section 7 asks, so a
/// server may admit only that endpoint. An unspecified bound address in the
/// reply (`0.0.0.0` or `::`) means "the server itself": `server` is returned
/// with the bound port, as Xray does. A bound domain is accepted only when it
/// is an IP literal, and a zero bound port is an error. IPv4-mapped IPv6
/// addresses are returned as IPv4.
///
/// The control stream carries nothing afterwards; the association lasts until
/// either side closes it.
pub async fn socks5_udp_associate<S>(
    stream: &mut S,
    account: Option<&SocksAccount>,
    client_endpoint: SocketAddr,
    server: IpAddr,
) -> Result<SocketAddr, SocksClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = Vec::with_capacity(3 + 1 + 16 + 2);
    request.extend_from_slice(&[VERSION, COMMAND_UDP_ASSOCIATE, 0]);
    encode_target_addr(
        &mut request,
        &TargetAddr::Ip(client_endpoint.ip().to_canonical()),
    )
    .map_err(|_| SocksClientError::InvalidTargetDomain)?;
    request.extend_from_slice(&client_endpoint.port().to_be_bytes());

    negotiate(stream, account).await?;
    write_flushed(stream, &request).await?;
    let (bound, port) = read_reply(stream).await?;
    let ip = match bound {
        TargetAddr::Ip(ip) => ip,
        TargetAddr::Domain(domain) => domain
            .parse()
            .map_err(|_| SocksClientError::InvalidRelayAddress)?,
    };
    if port == 0 {
        return Err(SocksClientError::InvalidRelayAddress);
    }
    let ip = if ip.is_unspecified() { server } else { ip };
    Ok(SocketAddr::new(ip.to_canonical(), port))
}

/// Builds one `RSV RSV FRAG=0 | ATYP | DST.ADDR | DST.PORT | DATA` request
/// datagram. The target is validated like a CONNECT target, and a datagram
/// longer than [`MAX_SOCKS_UDP_DATAGRAM_LENGTH`] is refused rather than sent
/// truncated or empty.
pub fn encode_socks5_udp_request(
    target: &Target,
    payload: &[u8],
) -> Result<Vec<u8>, SocksClientError> {
    let addr = canonical_target_addr(target)?;
    let mut datagram = Vec::with_capacity(3 + 2 + MAX_DOMAIN_LENGTH + 2 + payload.len());
    datagram.extend_from_slice(&[0, 0, 0]);
    encode_target_addr(&mut datagram, &addr).map_err(|_| SocksClientError::InvalidTargetDomain)?;
    datagram.extend_from_slice(&target.port.to_be_bytes());
    if datagram.len() + payload.len() > MAX_SOCKS_UDP_DATAGRAM_LENGTH {
        return Err(SocksClientError::UdpPayloadTooLarge);
    }
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

/// Parses one datagram received from `source`. Anything that is not a whole,
/// unfragmented datagram from `relay` is reported as a [`SocksUdpDrop`] so the
/// caller can discard it and keep the association.
pub fn decode_socks5_udp_reply(
    relay: SocketAddr,
    source: SocketAddr,
    raw: &[u8],
) -> Result<SocksUdpDatagram, SocksUdpDrop> {
    if SocketAddr::new(source.ip().to_canonical(), source.port()) != relay {
        return Err(SocksUdpDrop::ForeignSource);
    }
    parse_socks5_udp_datagram(raw).map_err(|error| match error {
        SocksParseError::UnsupportedUdpFragment => SocksUdpDrop::Fragmented,
        _ => SocksUdpDrop::Malformed,
    })
}

/// Offers exactly one method (password when an account is set) and runs the
/// RFC 1929 sub-negotiation when it is selected.
async fn negotiate<S>(
    stream: &mut S,
    account: Option<&SocksAccount>,
) -> Result<(), SocksClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let method = match account {
        Some(_) => METHOD_PASSWORD,
        None => METHOD_NO_AUTH,
    };
    write_flushed(stream, &[VERSION, 1, method]).await?;
    let mut selection = [0; 2];
    stream.read_exact(&mut selection).await?;
    match selection {
        [VERSION, selected] if selected == method => {}
        [VERSION, METHOD_NONE_ACCEPTABLE] => return Err(SocksClientError::NoAcceptableMethod),
        [VERSION, selected] => return Err(SocksClientError::UnexpectedMethod(selected)),
        [version, _] => return Err(SocksClientError::UnexpectedVersion(version)),
    }

    match account {
        Some(account) => authenticate(stream, account).await,
        None => Ok(()),
    }
}

/// Checks that `target` can be sent in a CONNECT request, so callers can fail
/// before resolving or dialing the proxy server.
pub fn validate_connect_target(target: &Target) -> Result<(), SocksClientError> {
    encode_connect_request(target).map(drop)
}

/// `VER=5 | CMD=CONNECT | RSV | ATYP | DST.ADDR | DST.PORT`, built only after
/// the target is validated so that an invalid target performs no I/O.
fn encode_connect_request(target: &Target) -> Result<Vec<u8>, SocksClientError> {
    let addr = canonical_target_addr(target)?;
    let mut request = Vec::with_capacity(3 + 2 + MAX_DOMAIN_LENGTH + 2);
    request.extend_from_slice(&[VERSION, COMMAND_CONNECT, 0]);
    encode_target_addr(&mut request, &addr).map_err(|_| SocksClientError::InvalidTargetDomain)?;
    request.extend_from_slice(&target.port.to_be_bytes());
    Ok(request)
}

/// Validates a CONNECT or UDP destination and sends an IPv4-mapped IPv6
/// address as IPv4, as Xray does.
fn canonical_target_addr(target: &Target) -> Result<TargetAddr, SocksClientError> {
    if target.port == 0 {
        return Err(SocksClientError::InvalidTargetPort);
    }
    match &target.addr {
        TargetAddr::Ip(ip) => Ok(TargetAddr::Ip(ip.to_canonical())),
        TargetAddr::Domain(domain) if valid_domain(domain) => Ok(target.addr.clone()),
        TargetAddr::Domain(_) => Err(SocksClientError::InvalidTargetDomain),
    }
}

/// Mirrors the Trojan client's domain rule.
fn valid_domain(domain: &str) -> bool {
    (1..=MAX_DOMAIN_LENGTH).contains(&domain.len())
        && !domain.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// RFC 1929: one write of `VER=1 | ULEN | UNAME | PLEN | PASSWD`, answered with
/// `VER=1 | STATUS`. The buffer is sized up front so it never reallocates and
/// leaves an unzeroed copy behind.
async fn authenticate<S>(stream: &mut S, account: &SocksAccount) -> Result<(), SocksClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (user, pass) = (account.user(), account.pass());
    let mut message = Zeroizing::new(Vec::with_capacity(3 + user.len() + pass.len()));
    message.push(PASSWORD_AUTH_VERSION);
    for value in [user, pass] {
        // `SocksAccount::new` bounds both values to 1..=255 bytes, so the
        // length byte never truncates (Xray's would at 256).
        message.push(value.len() as u8);
        message.extend_from_slice(value);
    }
    write_flushed(stream, &message).await?;

    let mut status = [0; 2];
    stream.read_exact(&mut status).await?;
    match status {
        [PASSWORD_AUTH_VERSION, PASSWORD_AUTH_SUCCESS] => Ok(()),
        [PASSWORD_AUTH_VERSION, status] => Err(SocksClientError::AuthRejected(status)),
        [version, _] => Err(SocksClientError::UnexpectedAuthVersion(version)),
    }
}

/// `VER=5 | REP | RSV | ATYP | BND.ADDR | BND.PORT`. The reserved byte is not
/// checked, as in Xray. A rejection is reported before reading the address.
async fn read_reply<S>(stream: &mut S) -> Result<(TargetAddr, u16), SocksClientError>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0; 3];
    stream.read_exact(&mut head).await?;
    match head {
        [VERSION, REPLY_SUCCEEDED, _] => {}
        [VERSION, code, _] => return Err(SocksClientError::RequestRejected(code)),
        [version, ..] => return Err(SocksClientError::UnexpectedVersion(version)),
    }
    let address_type = stream.read_u8().await?;
    Ok(read_socks5_address(stream, address_type).await?)
}

async fn write_flushed<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(bytes).await?;
    stream.flush().await
}
