//! Xray's HTTPUpgrade transport: an upgrade handshake with no RFC 6455
//! machinery behind it. After the 101 the connection is raw bytes in both
//! directions — no framing, no keepalive, no close handshake.
//!
//! Three details diverge from what a careful implementer would guess, and all
//! three are load-bearing against a real Xray server:
//!
//! 1. Response validation is **stricter** than WebSocket's. The status line is
//!    compared as the exact string `101 Switching Protocols`, and `Connection`
//!    must equal `upgrade` exactly after lowercasing — no token-list parsing.
//! 2. The configured path is assigned to Go's `URL.Path`, which escapes `?`, so
//!    `/ws?foo=bar` goes out as `/ws%3Ffoo=bar` where WebSocket would send a
//!    real query string.
//! 3. `ed` carries no payload here. Any positive value only means "do not block
//!    waiting for the 101" — the server still sends one, and it is stripped on
//!    the first read instead of during the dial.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{apply_masquerade, serialize_request, HeaderMap};
use crate::{BoxedTransportStream, TransportError, TransportStream};

/// Everything the dial needs, already resolved from config plus the security
/// layer's server name.
#[derive(Debug, Clone)]
pub struct HttpUpgradeConfig {
    /// Normalized path. May contain a `?`, which is percent-escaped on the wire
    /// because Go assigns it to `URL.Path`.
    pub path: String,
    /// `Host` header value: config `host`, else the TLS server name, else the
    /// destination address. Never carries a port.
    pub host: String,
    pub headers: Vec<(String, String)>,
    /// False when `ed` is non-zero: the dial returns without waiting for the
    /// 101, so the first payload write goes out right behind the request.
    pub wait_for_response: bool,
}

const EXPECTED_STATUS: &str = "HTTP/1.1 101 Switching Protocols";
const MAX_RESPONSE_HEAD: usize = 64 * 1024;

/// Escapes a path the way Go's `URL.RequestURI()` does for `URL.Path`.
///
/// Go's path escaper leaves almost everything alone and escapes exactly one
/// reserved character here: `?`. The Xray server unescapes it back, so the
/// round trip works — but only if we escape it too.
fn escape_path(path: &str) -> String {
    path.replace('?', "%3F")
}

pub async fn connect_httpupgrade(
    mut stream: BoxedTransportStream,
    config: &HttpUpgradeConfig,
) -> Result<BoxedTransportStream, TransportError> {
    let mut headers = HeaderMap::new();
    for (key, value) in &config.headers {
        headers.set(key, value);
    }
    apply_masquerade(&mut headers, "ws");
    headers.set("Connection", "Upgrade");
    headers.set("Upgrade", "websocket");

    let request = serialize_request("GET", &escape_path(&config.path), &config.host, &headers);
    stream
        .write_all(&request)
        .await
        .map_err(TransportError::Tcp)?;

    if !config.wait_for_response {
        // The 101 is still coming; it is stripped on the first read instead.
        return Ok(Box::new(DeferredUpgradeStream::new(stream)));
    }

    let leftover = read_and_validate_response(&mut stream).await?;
    Ok(Box::new(PrefixedStream::new(stream, leftover)))
}

/// Reads the response headers and returns any payload bytes that arrived in the
/// same read.
///
/// Xray drops those bytes; we keep them, because losing them is a silent
/// data-corruption bug waiting for a server that speaks first.
async fn read_and_validate_response(
    stream: &mut BoxedTransportStream,
) -> Result<Vec<u8>, TransportError> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.map_err(TransportError::Tcp)?;
        if read == 0 {
            return Err(TransportError::HttpUpgradeRejected(
                "connection closed before the response headers".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_header_end(&buffer) {
            break position;
        }
        if buffer.len() > MAX_RESPONSE_HEAD {
            return Err(TransportError::HttpUpgradeRejected(
                "response headers exceeded 64 KiB".to_owned(),
            ));
        }
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    validate_response_head(&head)?;

    Ok(buffer[header_end + 4..].to_vec())
}

/// Checks the status line and the two upgrade headers.
///
/// Shared by both dial modes: whether the response is read during the dial or
/// on the first read afterwards, it is held to the same rules.
fn validate_response_head(head: &str) -> Result<(), TransportError> {
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status != EXPECTED_STATUS {
        return Err(TransportError::HttpUpgradeRejected(format!(
            "unexpected status line `{status}`"
        )));
    }

    let mut connection = None;
    let mut upgrade = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_ascii_lowercase();
        if name.eq_ignore_ascii_case("connection") && connection.is_none() {
            connection = Some(value);
        } else if name.eq_ignore_ascii_case("upgrade") && upgrade.is_none() {
            upgrade = Some(value);
        }
    }

    // Exact equality, not token-list membership: Xray compares these with `==`
    // after lowercasing, so `Connection: Upgrade, keep-alive` is a failure.
    if connection.as_deref() != Some("upgrade") {
        return Err(TransportError::HttpUpgradeRejected(
            "Connection header must be exactly `upgrade`".to_owned(),
        ));
    }
    if upgrade.as_deref() != Some("websocket") {
        return Err(TransportError::HttpUpgradeRejected(
            "Upgrade header must be exactly `websocket`".to_owned(),
        ));
    }

    Ok(())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn rejected(reason: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        TransportError::HttpUpgradeRejected(reason),
    )
}

/// A stream that consumes the upgrade response on its first read.
///
/// `ed` does not take the 101 off the wire — the server sends it either way. It
/// only means the dial must not block waiting for it, so the first payload
/// write can follow the request immediately. Xray defers the response the same
/// way and then strips it in `ConnRF.Read`, which reads and validates it on the
/// first read whatever `ed` was set to.
///
/// Returning the bare socket instead would hand the status line to the caller
/// as payload, and for VLESS that means parsing `HTTP/1.1 101 ...` as a
/// protocol response: a silent corruption of every early-data connection.
pub(crate) struct DeferredUpgradeStream {
    inner: BoxedTransportStream,
    /// Bytes read while looking for the end of the response head. Once the head
    /// is validated this holds only what followed it.
    buffer: Vec<u8>,
    consumed: usize,
    validated: bool,
}

impl DeferredUpgradeStream {
    pub(crate) fn new(inner: BoxedTransportStream) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            consumed: 0,
            validated: false,
        }
    }

    /// Reads until the response head is complete, then validates it and keeps
    /// whatever followed for the caller.
    fn poll_consume_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(position) = find_header_end(&self.buffer) {
                let head = String::from_utf8_lossy(&self.buffer[..position]).into_owned();
                validate_response_head(&head).map_err(|error| match error {
                    TransportError::HttpUpgradeRejected(reason) => rejected(reason),
                    other => io::Error::other(other),
                })?;
                self.buffer.drain(..position + 4);
                self.validated = true;
                return Poll::Ready(Ok(()));
            }

            if self.buffer.len() > MAX_RESPONSE_HEAD {
                return Poll::Ready(Err(rejected("response headers exceeded 64 KiB".to_owned())));
            }

            let mut chunk = [0u8; 512];
            let mut staging = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut staging))?;
            let filled = staging.filled();
            if filled.is_empty() {
                return Poll::Ready(Err(rejected(
                    "connection closed before the response headers".to_owned(),
                )));
            }
            self.buffer.extend_from_slice(filled);
        }
    }

    /// Serves the next read from what followed the response, if any is left.
    fn drain_buffered(&mut self, output: &mut ReadBuf<'_>) -> bool {
        let remaining = &self.buffer[self.consumed..];
        if remaining.is_empty() {
            return false;
        }

        let take = remaining.len().min(output.remaining());
        output.put_slice(&remaining[..take]);
        self.consumed += take;
        if self.consumed == self.buffer.len() {
            self.buffer = Vec::new();
            self.consumed = 0;
        }
        true
    }
}

impl AsyncRead for DeferredUpgradeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.validated {
            ready!(this.poll_consume_response(cx))?;
        }
        if this.drain_buffered(output) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

/// Writes never wait on the response: sending without waiting is the whole
/// point of early data.
impl AsyncWrite for DeferredUpgradeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The direct-mode methods forward to the plain ones, as they do for
/// `PrefixedStream`: record alignment exists only for Vision, which the
/// compatibility matrix keeps off this transport.
impl TransportStream for DeferredUpgradeStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

/// A stream that drains a leading buffer before delegating to the socket.
///
/// The buffer holds whatever arrived in the same read as the response headers.
pub(crate) struct PrefixedStream {
    inner: BoxedTransportStream,
    prefix: Vec<u8>,
    consumed: usize,
}

impl PrefixedStream {
    pub(crate) fn new(inner: BoxedTransportStream, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            consumed: 0,
        }
    }

    /// Serves the next read from the prefix, if any is left.
    fn drain_prefix(&mut self, output: &mut ReadBuf<'_>) -> bool {
        let remaining = &self.prefix[self.consumed..];
        if remaining.is_empty() {
            return false;
        }

        let take = remaining.len().min(output.remaining());
        output.put_slice(&remaining[..take]);
        self.consumed += take;
        if self.consumed == self.prefix.len() {
            // The buffer is spent; give the memory back rather than carry it
            // for the life of the connection.
            self.prefix = Vec::new();
            self.consumed = 0;
        }
        true
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.drain_prefix(output) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The direct-mode methods forward to the plain ones. Record alignment exists
/// only for Vision, which the compatibility matrix keeps off this transport.
impl TransportStream for PrefixedStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}
