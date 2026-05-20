use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use xray_routing::{Network, Target, TargetAddr};

const MAX_REQUEST_LINE_LEN: usize = 8192;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("request is not http connect")]
    NotConnect,
    #[error("target is missing port")]
    MissingPort,
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
            return Err(HttpParseError::Io);
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
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or(HttpParseError::MissingPort)?;
    let port = port.parse().map_err(|_| HttpParseError::InvalidPort)?;

    Ok(Target::new(
        TargetAddr::Domain(host.to_owned()),
        port,
        Network::Tcp,
    ))
}
