use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
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
    #[error("socks udp fragmentation is unsupported")]
    UnsupportedUdpFragment,
    #[error("socks udp datagram is truncated")]
    TruncatedUdpDatagram,
    #[error("socks udp payload is too large")]
    PayloadTooLarge,
    #[error("no acceptable socks authentication methods")]
    NoAcceptableMethods,
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

pub async fn parse_socks5_request_message<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<SocksRequest, SocksParseError> {
    let request_version = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if request_version != 5 {
        return Err(SocksParseError::UnsupportedVersion(request_version));
    }

    let command = match reader.read_u8().await.map_err(|_| SocksParseError::Io)? {
        1 => SocksCommand::Connect,
        3 => SocksCommand::UdpAssociate,
        other => return Err(SocksParseError::UnsupportedCommand(other)),
    };

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
    let network = match command {
        SocksCommand::Connect => Network::Tcp,
        SocksCommand::UdpAssociate => Network::Udp,
    };

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

fn encode_target_addr(output: &mut Vec<u8>, addr: &TargetAddr) -> Result<(), SocksParseError> {
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
