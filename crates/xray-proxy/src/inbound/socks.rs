use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_routing::{Network, Target, TargetAddr};

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
    #[error("no acceptable socks authentication methods")]
    NoAcceptableMethods,
    #[error("io error")]
    Io,
}

pub async fn negotiate_socks5_no_auth<S>(mut stream: S) -> Result<(), SocksParseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if version != 5 {
        return Err(SocksParseError::UnsupportedVersion(version));
    }

    let method_count = stream.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let mut methods = vec![0; usize::from(method_count)];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| SocksParseError::Io)?;

    if methods.contains(&0) {
        stream
            .write_all(&[5, 0])
            .await
            .map_err(|_| SocksParseError::Io)?;
        Ok(())
    } else {
        stream
            .write_all(&[5, 0xff])
            .await
            .map_err(|_| SocksParseError::Io)?;
        Err(SocksParseError::NoAcceptableMethods)
    }
}

pub async fn parse_socks5_request<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<Target, SocksParseError> {
    let request_version = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if request_version != 5 {
        return Err(SocksParseError::UnsupportedVersion(request_version));
    }

    let command = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if command != 1 {
        return Err(SocksParseError::UnsupportedCommand(command));
    }

    let reserved = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if reserved != 0 {
        return Err(SocksParseError::InvalidReserved(reserved));
    }

    let address_type = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let addr = match address_type {
        1 => {
            let mut octets = [0; 4];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(|_| SocksParseError::Io)?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        3 => {
            let len = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
            if len == 0 {
                return Err(SocksParseError::InvalidDomain);
            }

            let mut domain = vec![0; usize::from(len)];
            reader
                .read_exact(&mut domain)
                .await
                .map_err(|_| SocksParseError::Io)?;
            TargetAddr::Domain(
                String::from_utf8(domain).map_err(|_| SocksParseError::InvalidDomain)?,
            )
        }
        4 => {
            let mut octets = [0; 16];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(|_| SocksParseError::Io)?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => return Err(SocksParseError::UnsupportedAddressType(other)),
    };
    let port = reader.read_u16().await.map_err(|_| SocksParseError::Io)?;

    Ok(Target::new(addr, port, Network::Tcp))
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

pub async fn write_socks5_failure<W: AsyncWrite + Unpin>(
    mut writer: W,
) -> Result<(), SocksParseError> {
    writer
        .write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|_| SocksParseError::Io)
}
