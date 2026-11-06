//! HTTP/2 CONNECT tunnels for the HTTP outbound.
//!
//! Xray-core's HTTP outbound (`proxy/http/client.go`) opens its tunnel as an
//! HTTP/2 stream when the proxy's TLS negotiated `h2`, with Go's
//! `http2.Transport{}`, and keeps that connection for the tunnels that follow
//! while it can take new requests. This is that client, on the XHTTP HTTP/2
//! engine: its opening SETTINGS are Go's (`ENABLE_PUSH=0`, a 4 MiB stream
//! window, a 1 MiB frame and a 10 MiB header list), and the connection's
//! receive credit stays at the engine's 16 MiB, where Go grants 1 GiB.
//!
//! The caller builds the request fields; this module only sends them.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use h2::Reason;
use http::header::{HeaderName, HeaderValue, PROXY_AUTHORIZATION};
use http::{Method, Request, Uri};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::xhttp::{
    connect_h2_with_window, H2Client, H2Error, H2ReceiveWindow, H2ResponseBody, H2Upload,
};
use crate::{memory_class, BoxedTransportStream, ParallelRead, ParallelWrite, TransportStream};

/// A failed HTTP/2 CONNECT. No variant carries a field value, so no
/// credential reaches a log.
#[derive(Debug, Error)]
pub enum Http2ConnectError {
    /// The connection cannot take this tunnel: it is closed, or the proxy
    /// sent GOAWAY before the request went out. A new connection may succeed.
    #[error("HTTP/2 proxy connection cannot take a new tunnel: {0}")]
    Unusable(String),
    /// A field name or value HTTP/2 cannot carry.
    #[error("HTTP/2 CONNECT field is not valid")]
    InvalidField,
    /// The proxy answered with another status than 200.
    #[error("HTTP/2 proxy answered CONNECT with status {0}, not 200")]
    Rejected(u16),
    /// The handshake or the exchange failed.
    #[error("HTTP/2 CONNECT failed: {0}")]
    Protocol(String),
}

impl Http2ConnectError {
    /// Classifies an engine failure. The tunnel can go on a new connection
    /// when this one died, or when the proxy never processed the request: a
    /// GOAWAY that excluded the stream, or `REFUSED_STREAM`.
    fn from_engine(error: H2Error, live: bool) -> Self {
        match error {
            H2Error::UnexpectedStatus { status } => Self::Rejected(status.as_u16()),
            H2Error::Protocol { ref source, .. }
                if !live
                    || source.is_io()
                    || (source.is_go_away() && source.is_remote())
                    || source.reason() == Some(Reason::REFUSED_STREAM) =>
            {
                Self::Unusable(error.to_string())
            }
            error => Self::Protocol(error.to_string()),
        }
    }

    /// Whether a new connection may succeed where this one failed.
    pub fn connection_unusable(&self) -> bool {
        matches!(self, Self::Unusable(_))
    }
}

/// One HTTP/2 connection to an HTTP proxy, which every tunnel opened on it
/// shares. Clones share the connection.
#[derive(Debug, Clone)]
pub struct Http2ConnectClient {
    client: H2Client,
    /// Tunnels opening or open on the connection, each counted until both
    /// of its halves are gone.
    tunnels: Arc<AtomicUsize>,
}

impl Http2ConnectClient {
    /// Starts HTTP/2 on a TLS session to the proxy that negotiated `h2`.
    pub async fn handshake(io: BoxedTransportStream) -> Result<Self, Http2ConnectError> {
        let client = connect_h2_with_window(io, None, H2ReceiveWindow::for_host(memory_class()))
            .await
            .map_err(|error| Http2ConnectError::Protocol(error.to_string()))?;
        Ok(Self {
            client,
            tunnels: Arc::default(),
        })
    }

    /// Whether a tunnel may open here now, as Go's
    /// `ClientConn.CanTakeNewRequest` decides it: the connection is up and
    /// its tunnels are below the proxy's concurrent stream limit.
    pub fn can_take_new_tunnel(&self) -> bool {
        self.client.is_live()
            && self.tunnels.load(Ordering::Acquire) < self.client.current_max_send_streams()
    }

    /// Sends `CONNECT` for `authority` with `fields`, lowercase names in
    /// the order given, and opens the tunnel once the proxy answers 200.
    ///
    /// A `proxy-authorization` value is sent never indexed, so HPACK keeps no
    /// copy of the credentials.
    pub async fn open(
        &self,
        authority: &str,
        fields: &[(&str, &str)],
    ) -> Result<BoxedTransportStream, Http2ConnectError> {
        let request = connect_request(authority, fields)?;
        let slot = Arc::new(TunnelSlot::new(Arc::clone(&self.tunnels)));
        let fail = |error| Http2ConnectError::from_engine(error, self.client.is_live());
        let (upload, pending) = self.client.start_streaming(request).await.map_err(fail)?;
        let body = pending.open().await.map_err(fail)?;
        Ok(Box::new(Http2Tunnel { body, upload, slot }))
    }
}

/// An authority-form `CONNECT` request: `:method` and `:authority` only, as
/// RFC 9113 section 8.5 and Go send it.
fn connect_request(
    authority: &str,
    fields: &[(&str, &str)],
) -> Result<Request<()>, Http2ConnectError> {
    let uri = Uri::builder()
        .authority(authority)
        .build()
        .map_err(|_| Http2ConnectError::InvalidField)?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .map_err(|_| Http2ConnectError::InvalidField)?;
    let headers = request.headers_mut();
    for &(name, value) in fields {
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| Http2ConnectError::InvalidField)?;
        let mut value =
            HeaderValue::from_str(value).map_err(|_| Http2ConnectError::InvalidField)?;
        if name == PROXY_AUTHORIZATION {
            value.set_sensitive(true);
        }
        headers.append(name, value);
    }
    Ok(request)
}

/// Counts one tunnel toward [`Http2ConnectClient::can_take_new_tunnel`].
#[derive(Debug)]
struct TunnelSlot(Arc<AtomicUsize>);

impl TunnelSlot {
    fn new(tunnels: Arc<AtomicUsize>) -> Self {
        tunnels.fetch_add(1, Ordering::AcqRel);
        Self(tunnels)
    }
}

impl Drop for TunnelSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One tunnel: the request body uplink and the response body downlink of a
/// CONNECT stream. Shutting the write side down sends END_STREAM; dropping
/// either half before its clean end resets the stream with CANCEL, as Go's
/// tunnel `Close` does.
struct Http2Tunnel {
    body: H2ResponseBody,
    upload: H2Upload,
    slot: Arc<TunnelSlot>,
}

/// A half of a split tunnel, which keeps the tunnel counted while it lives.
struct Half<T> {
    inner: T,
    _slot: Arc<TunnelSlot>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Half<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Half<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for Http2Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.body).poll_read(cx, output)
    }
}

impl AsyncWrite for Http2Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.upload).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.upload).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.upload).poll_shutdown(cx)
    }
}

impl TransportStream for Http2Tunnel {
    fn into_io_halves(self: Box<Self>) -> (ParallelRead, ParallelWrite) {
        let Self { body, upload, slot } = *self;
        (
            Box::new(Half {
                inner: body,
                _slot: Arc::clone(&slot),
            }),
            Box::new(Half {
                inner: upload,
                _slot: slot,
            }),
        )
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

impl std::fmt::Debug for Http2Tunnel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Http2Tunnel")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connect_request_carries_only_method_and_authority_pseudo_fields() {
        let request = connect_request(
            "example.com:443",
            &[
                ("user-agent", "agent"),
                ("cookie", "a=1"),
                ("cookie", "b=2"),
            ],
        )
        .unwrap();
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(
            request.uri().authority().unwrap().as_str(),
            "example.com:443"
        );
        assert!(request.uri().scheme().is_none());
        assert!(request.uri().path_and_query().is_none());
        let cookies: Vec<_> = request.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies, ["a=1", "b=2"]);
    }

    #[test]
    fn credentials_are_never_indexed() {
        let request = connect_request(
            "[2001:db8::1]:443",
            &[
                ("proxy-authorization", "Basic dTpw"),
                ("user-agent", "agent"),
            ],
        )
        .unwrap();
        assert!(request.headers()["proxy-authorization"].is_sensitive());
        assert!(!request.headers()["user-agent"].is_sensitive());
    }

    #[test]
    fn a_field_http2_cannot_carry_is_refused() {
        for fields in [
            &[("x-line", "a\r\nb")][..],
            &[("bad name", "v")][..],
            &[("x-nul", "a\0b")][..],
        ] {
            assert!(matches!(
                connect_request("example.com:443", fields),
                Err(Http2ConnectError::InvalidField)
            ));
        }
    }

    #[test]
    fn statuses_map_to_rejections() {
        let error = Http2ConnectError::from_engine(
            H2Error::UnexpectedStatus {
                status: http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            },
            true,
        );
        assert!(matches!(error, Http2ConnectError::Rejected(407)));
        assert!(!error.connection_unusable());
    }

    #[test]
    fn a_new_connection_is_worth_it_when_this_one_died_or_refused_the_stream() {
        let engine = |reason| H2Error::Protocol {
            context: "response HEADERS failed",
            source: h2::Error::from(reason),
        };
        // REFUSED_STREAM guarantees the proxy did not process the request.
        let refused = Http2ConnectError::from_engine(engine(Reason::REFUSED_STREAM), true);
        assert!(refused.connection_unusable(), "{refused}");
        // Another failure on a live connection is this tunnel's own.
        let failed = Http2ConnectError::from_engine(engine(Reason::PROTOCOL_ERROR), true);
        assert!(!failed.connection_unusable(), "{failed}");
        // Any failure once the connection is gone.
        let gone = Http2ConnectError::from_engine(engine(Reason::PROTOCOL_ERROR), false);
        assert!(gone.connection_unusable(), "{gone}");
    }
}
