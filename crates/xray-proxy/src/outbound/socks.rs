//! SOCKS5 client handshake (RFC 1928 CONNECT with optional RFC 1929 auth).
//!
//! The wire behaviour follows Xray-core v26.7.28 `proxy/socks/protocol.go`:
//! exactly one method is offered and each step is a separate write that waits
//! for its reply. Unlike Xray, every length and version byte is checked, and a
//! zero-length bound domain is an error rather than a crash.
//!
//! This module does not dial or time out; callers bound the whole handshake.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_routing::{Target, TargetAddr};
use zeroize::Zeroizing;

use crate::inbound::{
    encode_target_addr, read_socks5_address, AddressReadError, SocksAccount,
    METHOD_NONE_ACCEPTABLE, METHOD_NO_AUTH, METHOD_PASSWORD, PASSWORD_AUTH_SUCCESS,
    PASSWORD_AUTH_VERSION,
};

const VERSION: u8 = 5;
const COMMAND_CONNECT: u8 = 0x01;
const REPLY_SUCCEEDED: u8 = 0x00;
const MAX_DOMAIN_LENGTH: usize = u8::MAX as usize;

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

    if let Some(account) = account {
        authenticate(stream, account).await?;
    }

    write_flushed(stream, &request).await?;
    read_reply(stream).await
}

/// Checks that `target` can be sent in a CONNECT request, so callers can fail
/// before resolving or dialing the proxy server.
pub fn validate_connect_target(target: &Target) -> Result<(), SocksClientError> {
    encode_connect_request(target).map(drop)
}

/// `VER=5 | CMD=CONNECT | RSV | ATYP | DST.ADDR | DST.PORT`, built only after
/// the target is validated so that an invalid target performs no I/O.
fn encode_connect_request(target: &Target) -> Result<Vec<u8>, SocksClientError> {
    if target.port == 0 {
        return Err(SocksClientError::InvalidTargetPort);
    }
    let addr = match &target.addr {
        TargetAddr::Ip(ip) => TargetAddr::Ip(ip.to_canonical()),
        TargetAddr::Domain(domain) if valid_domain(domain) => target.addr.clone(),
        TargetAddr::Domain(_) => return Err(SocksClientError::InvalidTargetDomain),
    };
    let mut request = Vec::with_capacity(3 + 2 + MAX_DOMAIN_LENGTH + 2);
    request.extend_from_slice(&[VERSION, COMMAND_CONNECT, 0]);
    encode_target_addr(&mut request, &addr).map_err(|_| SocksClientError::InvalidTargetDomain)?;
    request.extend_from_slice(&target.port.to_be_bytes());
    Ok(request)
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
async fn read_reply<S>(stream: &mut S) -> Result<(), SocksClientError>
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
    read_socks5_address(stream, address_type).await?;
    Ok(())
}

async fn write_flushed<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(bytes).await?;
    stream.flush().await
}
