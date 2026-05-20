use std::net::IpAddr;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use xray_routing::{Network, Target, TargetAddr};

const MAX_REQUEST_LINE_LEN: usize = 8192;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("request is not http connect")]
    NotConnect,
    #[error("request line is too long")]
    LineTooLong,
    #[error("target is missing port")]
    MissingPort,
    #[error("invalid authority")]
    InvalidAuthority,
    #[error("invalid port")]
    InvalidPort,
    #[error("io error")]
    Io,
}

pub async fn parse_http_connect<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<Target, HttpParseError> {
    let mut request_line = Vec::new();

    loop {
        if request_line.len() >= MAX_REQUEST_LINE_LEN {
            return Err(HttpParseError::LineTooLong);
        }

        let byte = reader.read_u8().await.map_err(|_| HttpParseError::Io)?;
        request_line.push(byte);
        if byte == b'\n' {
            break;
        }
    }

    let request_line =
        std::str::from_utf8(&request_line).map_err(|_| HttpParseError::NotConnect)?;
    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpParseError::NotConnect)?;
    if method != "CONNECT" {
        return Err(HttpParseError::NotConnect);
    }

    let authority = parts.next().ok_or(HttpParseError::MissingPort)?;
    let (host, port) = parse_authority(authority)?;
    let port = parse_port(port)?;
    let addr = parse_host(host)?;

    Ok(Target::new(addr, port, Network::Tcp))
}

fn parse_authority(authority: &str) -> Result<(&str, &str), HttpParseError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or(HttpParseError::MissingPort)?;
        return Ok((host, port));
    }

    authority
        .rsplit_once(':')
        .ok_or(HttpParseError::MissingPort)
}

fn parse_port(port: &str) -> Result<u16, HttpParseError> {
    let port = port.parse().map_err(|_| HttpParseError::InvalidPort)?;
    if port == 0 {
        return Err(HttpParseError::InvalidPort);
    }

    Ok(port)
}

fn parse_host(host: &str) -> Result<TargetAddr, HttpParseError> {
    if host.is_empty() {
        return Err(HttpParseError::InvalidAuthority);
    }

    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(TargetAddr::Ip(ip)),
        Err(_) => Ok(TargetAddr::Domain(host.to_owned())),
    }
}
