//! One HTTP/2 connection of a storage, opened as Go's `net/http` transport
//! opens one: its SETTINGS (no push, a 4 MiB stream window, 1 MiB frames, a
//! 10 MiB header list), the connection window raised by 1 GiB, a PING after
//! `keep_alive` without a frame from the server, and Go's request rules for
//! `content-length` and the user agent.

use std::io;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request};
use tokio::task::{AbortHandle, JoinHandle};

use super::client::{read_body, ChunkedBody, Prepared, Progress, ServiceError, ServiceResponse};
use crate::masque::h2::{keep_alive, LastFrame, Watched};
use crate::BoxedTransportStream;

/// Go's `transportDefaultStreamFlow`.
const STREAM_WINDOW: u32 = 4 << 20;
/// Go's `defaultMaxReadFrameSize`.
const MAX_FRAME_SIZE: u32 = 1 << 20;
/// Go's default `MAX_HEADER_LIST_SIZE`, 10 MiB.
const MAX_HEADER_LIST_SIZE: u32 = 10 << 20;
/// Go's `transportDefaultConnFlow`, the WINDOW_UPDATE that follows its
/// SETTINGS.
const CONNECTION_WINDOW_INCREMENT: u32 = 1 << 30;
/// HTTP/2's initial window, which the increment adds to.
const DEFAULT_WINDOW: u32 = 65_535;
/// Go reads a request body at most this much at a time.
const PROGRESS_CHUNK: usize = 16 << 10;

/// A live HTTP/2 connection; clones share it.
#[derive(Clone)]
pub(crate) struct H2Connection {
    inner: Arc<Inner>,
}

struct Inner {
    send: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
    tasks: Vec<AbortHandle>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.driver.abort();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl H2Connection {
    /// The client preface, SETTINGS and window on `io`, a TLS stream that
    /// negotiated `h2`.
    pub(crate) async fn handshake(
        io: BoxedTransportStream,
        keep_alive_period: Option<Duration>,
    ) -> Result<Self, ServiceError> {
        let last_frame = Arc::new(LastFrame::new());
        let io = Watched {
            io,
            last_frame: Arc::clone(&last_frame),
        };
        let (send, mut connection) = h2::client::Builder::new()
            .enable_push(false)
            .initial_window_size(STREAM_WINDOW)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .initial_connection_window_size(DEFAULT_WINDOW + CONNECTION_WINDOW_INCREMENT)
            .go_hpack_choices(true)
            .go_request_pseudo_order(true)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(|error| ServiceError::Network(format!("http2: {error}")))?;
        let ping_pong = connection.ping_pong();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut tasks = Vec::new();
        if let (Some(period), Some(ping_pong)) = (keep_alive_period, ping_pong) {
            tasks.push(
                tokio::spawn(keep_alive(
                    ping_pong,
                    last_frame,
                    period,
                    driver.abort_handle(),
                ))
                .abort_handle(),
            );
        }
        Ok(Self {
            inner: Arc::new(Inner {
                send,
                driver,
                tasks,
            }),
        })
    }

    /// Whether the connection still takes requests: a GOAWAY or a failure
    /// ends its driver.
    pub(crate) fn is_live(&self) -> bool {
        !self.inner.driver.is_finished()
    }

    /// One exchange: the request's HEADERS, its body in 16 KiB steps, and
    /// the answer read up to the request's limit.
    pub(crate) async fn send(
        &self,
        prepared: &Prepared<'_>,
        progress: &Progress,
    ) -> Result<ServiceResponse, ServiceError> {
        let failed = |error: h2::Error| ServiceError::Network(format!("http2: {error}"));
        let request = build_request(prepared)?;
        let mut send = self.inner.send.clone().ready().await.map_err(failed)?;
        let body = &prepared.request.body;
        let (response, mut stream) = send
            .send_request(request, body.is_empty())
            .map_err(failed)?;
        let mut rest = body.clone();
        while !rest.is_empty() {
            stream.reserve_capacity(rest.len().min(PROGRESS_CHUNK));
            let granted = match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
                Some(capacity) => capacity.map_err(failed)?,
                None => return Err(ServiceError::Network("http2: stream closed".to_owned())),
            };
            if granted == 0 {
                continue;
            }
            let chunk = rest.split_to(granted.min(rest.len()).min(PROGRESS_CHUNK));
            stream.send_data(chunk, rest.is_empty()).map_err(failed)?;
            progress.alive();
        }
        let response = response.await.map_err(failed)?;
        progress.alive();
        let (parts, mut received) = response.into_parts();
        let header = |name| {
            parts.headers.get(name).map(|value: &http::HeaderValue| {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            })
        };
        let retry_after = header(http::header::RETRY_AFTER);
        let location = header(http::header::LOCATION);
        let gzip = prepared.gzip
            && parts
                .headers
                .get(http::header::CONTENT_ENCODING)
                .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"));
        let limit = prepared.request.max_body.saturating_add(1);
        let chunks = ChunkedBody::new(|cx: &mut Context<'_>| {
            let polled = ready!(received.poll_data(cx));
            Poll::Ready(polled.map(|chunk| {
                let chunk = chunk.map_err(|error| io::Error::other(format!("http2: {error}")))?;
                let _ = received.flow_control().release_capacity(chunk.len());
                progress.alive();
                Ok(chunk)
            }))
        });
        // Dropped before its end, the stream is reset, as Go's transport
        // resets one whose body was closed early.
        let body = read_body(chunks, gzip, limit).await?;
        Ok(ServiceResponse {
            status: parts.status.as_u16(),
            retry_after,
            location,
            body: Bytes::from(body),
        })
    }
}

/// The request as Go's HTTP/2 transport writes it: the fields lowercased,
/// without those HTTP/2 refuses, `content-length` for a body or a POST,
/// PUT or PATCH, `accept-encoding` when the transport asked for gzip, and
/// the user agent last.
pub(super) fn build_request(prepared: &Prepared<'_>) -> Result<Request<()>, ServiceError> {
    let request = prepared.request;
    let uri = format!("https://{}{}", request.url.authority, request.url.target);
    let mut builder = Request::builder().method(request.method.clone()).uri(uri);
    let mut user_agent = None;
    for (name, value) in prepared.headers.iter() {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "host" | "content-length" | "connection" | "proxy-connection" | "transfer-encoding"
            | "upgrade" | "keep-alive" => continue,
            "user-agent" => {
                user_agent = Some(value.to_owned());
                continue;
            }
            _ => {}
        }
        let name = HeaderName::from_bytes(lower.as_bytes())
            .map_err(|_| ServiceError::Request(format!("invalid HTTP header name {name:?}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| ServiceError::Request(format!("invalid HTTP header value for {name}")))?;
        builder = builder.header(name, value);
    }
    let length = request.body.len();
    if length > 0 || matches!(request.method.as_str(), "POST" | "PUT" | "PATCH") {
        builder = builder.header(http::header::CONTENT_LENGTH, length);
    }
    if prepared.gzip {
        builder = builder.header(http::header::ACCEPT_ENCODING, "gzip");
    }
    match user_agent {
        // An empty one sends none.
        Some(agent) if agent.is_empty() => {}
        Some(agent) => {
            let value = HeaderValue::from_str(&agent)
                .map_err(|_| ServiceError::Request("invalid HTTP user agent".to_owned()))?;
            builder = builder.header(http::header::USER_AGENT, value);
        }
        None => builder = builder.header(http::header::USER_AGENT, "Go-http-client/2.0"),
    }
    builder
        .body(())
        .map_err(|error| ServiceError::Request(format!("failed to build request > {error}")))
}
