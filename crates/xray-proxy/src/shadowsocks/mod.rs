//! Shadowsocks client codecs behind one `method` string, as in Xray-core's
//! `shadowsocks` outbound: Shadowsocks 2022 (`2022-blake3-*`) and the classic
//! AEAD methods. Both families share the SOCKS-style target address codec.
pub(crate) mod address;
pub mod aead2017;

use crate::shadowsocks2022;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_routing::Target;

/// Largest datagram either codec emits or accepts.
pub const MAX_UDP_WIRE_LENGTH: usize = shadowsocks2022::MAX_UDP_WIRE_LENGTH;

#[derive(Debug, Clone)]
pub enum Method {
    Aead2017(Arc<aead2017::Method>),
    Shadowsocks2022(Arc<shadowsocks2022::Method>),
}

impl Method {
    /// Method names are case-insensitive, as Xray-core lowercases them for
    /// both families (`infra/conf/shadowsocks.go`, `shadowsocks_2022.GetCipherMethod`).
    pub fn new(name: &str, password: &str) -> io::Result<Self> {
        let name = name.to_lowercase();
        if let Some(cipher) = aead2017::Cipher::parse(&name) {
            return aead2017::Method::with_cipher(cipher, password)
                .map(|method| Self::Aead2017(Arc::new(method)));
        }
        if name.starts_with("2022-") {
            return shadowsocks2022::Method::new(&name, password)
                .map(|method| Self::Shadowsocks2022(Arc::new(method)));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported Shadowsocks method",
        ))
    }

    pub fn is_2022(&self) -> bool {
        matches!(self, Self::Shadowsocks2022(_))
    }

    /// Both families encode targets identically.
    pub fn validate_target(target: &Target) -> io::Result<()> {
        address::encode(target).map(|_| ())
    }
}

/// A TCP request stream for either family. No background tasks.
pub enum ClientStream<S> {
    Aead2017(aead2017::ClientStream<S>),
    Shadowsocks2022(shadowsocks2022::ClientStream<S>),
}

impl<S> ClientStream<S> {
    pub fn new(inner: S, method: &Method, target: &Target) -> io::Result<Self> {
        Ok(match method {
            Method::Aead2017(m) => {
                Self::Aead2017(aead2017::ClientStream::new(inner, m.clone(), target)?)
            }
            Method::Shadowsocks2022(m) => Self::Shadowsocks2022(
                shadowsocks2022::ClientStream::new(inner, m.clone(), target)?,
            ),
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Aead2017(s) => Pin::new(s).poll_read(cx, out),
            Self::Shadowsocks2022(s) => Pin::new(s).poll_read(cx, out),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Aead2017(s) => Pin::new(s).poll_write(cx, input),
            Self::Shadowsocks2022(s) => Pin::new(s).poll_write(cx, input),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Aead2017(s) => Pin::new(s).poll_flush(cx),
            Self::Shadowsocks2022(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Aead2017(s) => Pin::new(s).poll_shutdown(cx),
            Self::Shadowsocks2022(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// A native UDP association for either family. The SS2022 session carries
/// two replay windows, so it is boxed rather than sizing every variant.
pub enum UdpSession {
    Aead2017(aead2017::UdpSession),
    Shadowsocks2022(Box<shadowsocks2022::UdpSession>),
}

impl UdpSession {
    pub fn new(method: &Method) -> io::Result<Self> {
        Ok(match method {
            Method::Aead2017(m) => Self::Aead2017(aead2017::UdpSession::new(m.clone())),
            Method::Shadowsocks2022(m) => {
                Self::Shadowsocks2022(Box::new(shadowsocks2022::UdpSession::new(m.clone())?))
            }
        })
    }
    pub fn encode(&mut self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Aead2017(s) => s.encode(target, payload),
            Self::Shadowsocks2022(s) => s.encode(target, payload),
        }
    }
    pub fn decode(&mut self, wire: &[u8]) -> io::Result<(Target, Vec<u8>)> {
        match self {
            Self::Aead2017(s) => s.decode(wire),
            Self::Shadowsocks2022(s) => s.decode(wire),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names_dispatch_case_insensitively_and_reject_other_ciphers() {
        let key = "AQEBAQEBAQEBAQEBAQEBAQ==";
        for name in ["2022-blake3-aes-128-gcm", "2022-BLAKE3-AES-128-GCM"] {
            assert!(Method::new(name, key).unwrap().is_2022());
        }
        for name in ["aes-128-gcm", "AES-256-GCM", "chacha20-ietf-poly1305"] {
            assert!(!Method::new(name, "synthetic").unwrap().is_2022());
        }
        for name in [
            "none",
            "plain",
            "",
            "rc4-md5",
            "aes-128-cfb",
            "2022-unknown",
        ] {
            let error = Method::new(name, "synthetic-secret").unwrap_err();
            assert!(!error.to_string().contains("synthetic-secret"));
        }
    }
}
