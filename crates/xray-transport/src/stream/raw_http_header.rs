//! RAW's `http` header obfuscation, the client side of Xray-core's
//! `transport/internet/headers/http`.
//!
//! The stream looks like one HTTP/1.1 exchange from the outside: the first
//! write goes out after a request head, and the first read drops the
//! response head the server sends before its first bytes. Nothing else is
//! framed. As in Xray-core the layer sits above TLS or REALITY, so with
//! either it is encrypted with the rest.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::masquerade::{anchored_chrome_ch_ua, anchored_chrome_user_agent};
use crate::{BoxedTransportStream, TransportStream};

/// Xray-core's `maxHeaderLength`: a response head may take this many bytes.
const MAX_RESPONSE_HEAD: usize = 8192;
const HEAD_END: &[u8] = b"\r\n\r\n";

/// The request a connection opens with. Every connection draws one path, and
/// one value for each header, as Xray-core's `pickString` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHttpHeaderConfig {
    /// `GET` unless the config names another.
    pub method: String,
    /// The request line ends in `HTTP/` and this, `1.1` by default.
    pub version: String,
    /// One is drawn per connection; `/` by default.
    pub paths: Vec<String>,
    /// Header names in the order they are sent, each with the values one is
    /// drawn from; an empty list sends an empty value.
    pub headers: Vec<(String, Vec<String>)>,
}

impl RawHttpHeaderConfig {
    /// The headers Xray-core's `AuthenticatorRequest.Build` sends when the
    /// config names none: a Chrome on Windows, its version the one every
    /// other masqueraded request from this process claims.
    pub fn default_headers() -> Vec<(String, Vec<String>)> {
        let header = |name: &str, values: &[&str]| {
            (
                name.to_owned(),
                values.iter().map(|value| (*value).to_owned()).collect(),
            )
        };
        vec![
            header("Host", &["www.baidu.com", "www.bing.com"]),
            ("User-Agent".to_owned(), vec![anchored_chrome_user_agent()]),
            ("Sec-CH-UA".to_owned(), vec![anchored_chrome_ch_ua()]),
            header("Sec-CH-UA-Mobile", &["?0"]),
            header("Sec-CH-UA-Platform", &["Windows"]),
            header("Sec-Fetch-Mode", &["no-cors", "cors", "same-origin"]),
            header("Sec-Fetch-Dest", &["empty"]),
            header("Sec-Fetch-Site", &["none"]),
            header("Sec-Fetch-User", &["?1"]),
            header("Accept-Encoding", &["gzip, deflate"]),
            header("Connection", &["keep-alive"]),
            header("Pragma", &["no-cache"]),
        ]
    }

    /// One request head, with a path and header values drawn for it.
    pub fn request_head(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut pick = |values: &[String]| -> String {
            match values.len() {
                0 => String::new(),
                1 => values[0].clone(),
                count => values[rng.gen_range(0..count)].clone(),
            }
        };
        let mut head = format!(
            "{} {} HTTP/{}\r\n",
            self.method,
            pick(&self.paths),
            self.version
        );
        for (name, values) in &self.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(&pick(values));
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        head.into_bytes()
    }
}

/// A client stream inside Xray-core's HTTP header obfuscation.
pub struct RawHttpHeaderStream {
    inner: BoxedTransportStream,
    /// The request head, until all of it is written.
    request: Vec<u8>,
    written: usize,
    response: Response,
}

enum Response {
    /// The head read so far.
    Head(Vec<u8>),
    /// What came after the head in its last read, still to be returned.
    Body { leftover: Vec<u8>, offset: usize },
}

impl RawHttpHeaderStream {
    pub fn client(inner: BoxedTransportStream, config: &Arc<RawHttpHeaderConfig>) -> Self {
        Self {
            inner,
            request: config.request_head(),
            written: 0,
            response: Response::Head(Vec::new()),
        }
    }

    /// Writes what is left of the request head. Ready once it is all out.
    fn poll_request(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.request.len() {
            let written =
                match Pin::new(&mut self.inner).poll_write(cx, &self.request[self.written..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "the HTTP request head was not written",
                        )))
                    }
                    Poll::Ready(Ok(written)) => written,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                };
            self.written += written;
        }
        if !self.request.is_empty() {
            self.request = Vec::new();
            self.written = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for RawHttpHeaderStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.response {
                Response::Head(head) => {
                    let mut chunk = [0_u8; 2048];
                    let mut chunk = ReadBuf::new(&mut chunk);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut chunk) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if chunk.filled().is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the connection closed inside the HTTP response head",
                        )));
                    }
                    let searched_from = head.len().saturating_sub(HEAD_END.len() - 1);
                    head.extend_from_slice(chunk.filled());
                    if let Some(end) = head[searched_from..]
                        .windows(HEAD_END.len())
                        .position(|window| window == HEAD_END)
                    {
                        let body_start = searched_from + end + HEAD_END.len();
                        let leftover = head.split_off(body_start);
                        this.response = Response::Body {
                            leftover,
                            offset: 0,
                        };
                        continue;
                    }
                    if head.len() > MAX_RESPONSE_HEAD {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the HTTP response head is longer than 8192 bytes",
                        )));
                    }
                }
                Response::Body { leftover, offset } if *offset < leftover.len() => {
                    let count = output.remaining().min(leftover.len() - *offset);
                    output.put_slice(&leftover[*offset..*offset + count]);
                    *offset += count;
                    if *offset == leftover.len() {
                        *leftover = Vec::new();
                        *offset = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                Response::Body { .. } => return Pin::new(&mut this.inner).poll_read(cx, output),
            }
        }
    }
}

impl AsyncWrite for RawHttpHeaderStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_request(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_write(cx, input),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl TransportStream for RawHttpHeaderStream {
    fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.inner.negotiated_alpn()
    }

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
