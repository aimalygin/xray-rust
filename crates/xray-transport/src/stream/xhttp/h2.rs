//! HTTP/2 wire engine for outbound XHTTP.
//!
//! The XHTTP mode layer composes request URIs and headers. This module owns
//! one reusable HTTP/2 connection plus the flow-controlled request and
//! response bodies opened on it. A streaming exchange is deliberately split
//! into independently pollable halves. Dropping either half before its clean
//! end cancels that exchange, while a shared reset handle keeps the reset
//! scoped to that stream and returns reserved capacity to the connection.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use h2::client::{self, ResponseFuture, SendRequest};
use h2::{Ping, PingPong, Reason, RecvStream, SendStream};
use http::{HeaderMap, Method, Request, StatusCode};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};

use crate::BoxedTransportStream;

/// Keeps one slow response from consuming the receive window shared by every
/// XHTTP stream on the connection. Per-stream flow control remains at the
/// HTTP/2 default, so an individual unread body is still tightly bounded.
const CONNECTION_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

/// Bounds the copy made by one [`AsyncWrite::poll_write`] call.
const MAX_UPLOAD_DATA_BYTES: usize = 16 * 1024;

/// x/net/http2's default `Transport.PingTimeout`.
const PING_TIMEOUT: Duration = Duration::from_secs(15);

/// HTTP/2 connection, request, and response failures.
#[derive(Debug, Error)]
pub enum H2Error {
    #[error("HTTP/2 {context}: {source}")]
    Protocol {
        context: &'static str,
        #[source]
        source: h2::Error,
    },
    #[error("XHTTP HTTP/2 server returned status {status}")]
    UnexpectedStatus { status: StatusCode },
    #[error("HTTP/2 stream state lock is poisoned")]
    StatePoisoned,
    #[error("HTTP/2 response was already consumed")]
    ResponseConsumed,
    #[error("HTTP/2 request body is already closed")]
    RequestBodyClosed,
    #[error("HTTP/2 request stream is reset")]
    RequestBodyReset,
    #[error("HTTP/2 granted zero bytes of upload capacity")]
    ZeroCapacityGrant,
}

/// A reusable HTTP/2 client connection.
///
/// Clones share the underlying connection. Each request clones the h2
/// `SendRequest` handle again before waiting for readiness, which gives every
/// concurrent request its own pending slot.
#[derive(Clone, Debug)]
pub struct H2Client {
    send_request: SendRequest<Bytes>,
    driver: Arc<H2ConnectionDriver>,
}

#[derive(Debug)]
struct H2ConnectionDriver {
    task: JoinHandle<Result<(), h2::Error>>,
}

impl H2Client {
    /// Whether the connection driver is still running.
    ///
    /// A graceful GOAWAY completes the driver successfully but still makes
    /// the connection unusable, so completion rather than failure is the
    /// retirement signal.
    pub fn is_live(&self) -> bool {
        !self.driver.task.is_finished()
    }

    /// The peer's currently advertised concurrent request-stream limit.
    ///
    /// Before the peer SETTINGS frame is processed this returns the
    /// conservative value installed by [`connect_h2_with_keepalive`]. Pool
    /// checkout uses it together with an atomic activity reservation so a
    /// request never waits behind a persistent stream on a saturated
    /// connection.
    pub fn current_max_send_streams(&self) -> usize {
        self.send_request.current_max_send_streams()
    }

    /// Sends one fixed request body and opens its status-200 response.
    ///
    /// An empty body sets END_STREAM on the request HEADERS. A non-empty body
    /// ends on its final DATA frame; no empty DATA frame is appended.
    pub async fn send_fixed(
        &self,
        request: Request<()>,
        body: Bytes,
    ) -> Result<H2ResponseBody, H2Error> {
        if body.is_empty() {
            return self.start_fixed(request, body).await?.open().await;
        }

        let (mut upload, response) = self.open_request(request, false).await?;

        // Poll the response while the fixed body is flowing. Servers may
        // reject a request before consuming it; observing that status here
        // prevents a large upload from waiting forever for a window the peer
        // deliberately stopped opening.
        let (_, response) = tokio::try_join!(upload.send_owned(body), response.open())?;
        Ok(response)
    }

    /// Sends one complete fixed request body without waiting for response
    /// HEADERS.
    ///
    /// Empty bodies set END_STREAM on the request HEADERS. Non-empty bodies
    /// return only after their final DATA frame carries END_STREAM. The caller
    /// can then wait for and validate the response through
    /// [`H2PendingResponse::open`]. Cancelling this future while a
    /// flow-controlled upload is pending resets only this request stream.
    pub async fn start_fixed(
        &self,
        request: Request<()>,
        body: Bytes,
    ) -> Result<H2PendingResponse, H2Error> {
        let end_on_headers = body.is_empty();
        let (mut upload, response) = self.open_request(request, end_on_headers).await?;
        if !end_on_headers {
            upload.send_owned(body).await?;
        }
        Ok(response)
    }

    /// Starts a streaming request and returns its independently pollable
    /// upload and response halves.
    ///
    /// Both halves must end cleanly. Dropping the upload before
    /// [`AsyncWrite::poll_shutdown`] or dropping the response before EOF
    /// sends `RST_STREAM(CANCEL)` and causes the sibling half to fail.
    pub async fn start_streaming(
        &self,
        request: Request<()>,
    ) -> Result<(H2Upload, H2PendingResponse), H2Error> {
        self.open_request(request, false).await
    }

    async fn open_request(
        &self,
        request: Request<()>,
        end_on_headers: bool,
    ) -> Result<(H2Upload, H2PendingResponse), H2Error> {
        let response_is_bodyless = request.method() == Method::HEAD;
        let mut send_request = self
            .send_request
            .clone()
            .ready()
            .await
            .map_err(|source| protocol_error("connection is not ready", source))?;
        let (response, send) = send_request
            .send_request(request, end_on_headers)
            .map_err(|source| protocol_error("request HEADERS could not be sent", source))?;

        let shared = Arc::new(SharedSend::new(send, end_on_headers));
        Ok((
            H2Upload {
                shared: Arc::clone(&shared),
            },
            H2PendingResponse {
                response: Some(response),
                shared,
                response_is_bodyless,
                cancel_on_drop: true,
            },
        ))
    }
}

/// Completes the HTTP/2 handshake on an already secured stream and starts its
/// connection driver.
pub async fn connect_h2(io: BoxedTransportStream) -> Result<H2Client, H2Error> {
    connect_h2_with_keepalive(io, None).await
}

/// Completes the HTTP/2 handshake and optionally probes a read-idle peer.
///
/// The interval is measured from the last bytes read from the secured stream,
/// not from the previous timer wake. A zero interval disables keepalive, just
/// like x/net/http2's zero `ReadIdleTimeout`. An unanswered PING retires the
/// entire connection after x/net/http2's 15-second `PingTimeout`.
pub async fn connect_h2_with_keepalive(
    mut io: BoxedTransportStream,
    read_idle: Option<Duration>,
) -> Result<H2Client, H2Error> {
    // XHTTP cannot use Vision direct mode, so retaining TLS record boundaries
    // after the stream has moved into h2 is pure overhead.
    io.release_record_alignment();

    let read_idle = read_idle.filter(|duration| !duration.is_zero());
    let (io, last_read) = WatchedIo::new(io, read_idle.is_some());
    let mut builder = client::Builder::new();
    builder
        .initial_connection_window_size(CONNECTION_WINDOW_SIZE)
        .initial_max_send_streams(1);
    let (send_request, mut connection) = builder
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|source| protocol_error("handshake failed", source))?;

    // `PingPong` is a single-take handle owned by `Connection`, so it must be
    // extracted before the connection moves into its driver task.
    let keepalive = read_idle.zip(last_read).and_then(|(read_idle, last_read)| {
        connection.ping_pong().map(|ping_pong| H2Keepalive {
            ping_pong,
            read_idle,
            last_read,
        })
    });

    let driver = Arc::new(H2ConnectionDriver {
        task: tokio::spawn(drive_connection(connection, keepalive)),
    });
    Ok(H2Client {
        send_request,
        driver,
    })
}

async fn drive_connection(
    connection: client::Connection<WatchedIo, Bytes>,
    keepalive: Option<H2Keepalive>,
) -> Result<(), h2::Error> {
    let Some(keepalive) = keepalive else {
        return connection.await;
    };

    tokio::select! {
        outcome = connection => outcome,
        () = keepalive.run() => Ok(()),
    }
}

#[derive(Debug)]
struct LastRead {
    opened: Instant,
    nanos_since_opened: AtomicU64,
}

impl LastRead {
    fn new() -> Self {
        Self {
            opened: Instant::now(),
            nanos_since_opened: AtomicU64::new(0),
        }
    }

    fn mark(&self) {
        let elapsed = self.opened.elapsed().as_nanos();
        self.nanos_since_opened.store(
            u64::try_from(elapsed).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn at(&self) -> Instant {
        self.opened + Duration::from_nanos(self.nanos_since_opened.load(Ordering::Relaxed))
    }
}

struct WatchedIo {
    io: BoxedTransportStream,
    last_read: Option<Arc<LastRead>>,
}

impl WatchedIo {
    fn new(io: BoxedTransportStream, enabled: bool) -> (Self, Option<Arc<LastRead>>) {
        let last_read = enabled.then(|| Arc::new(LastRead::new()));
        (
            Self {
                io,
                last_read: last_read.clone(),
            },
            last_read,
        )
    }
}

impl AsyncRead for WatchedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = output.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, output);
        if matches!(polled, Poll::Ready(Ok(()))) && output.filled().len() > before {
            if let Some(last_read) = &self.last_read {
                last_read.mark();
            }
        }
        polled
    }
}

impl AsyncWrite for WatchedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

struct H2Keepalive {
    ping_pong: PingPong,
    read_idle: Duration,
    last_read: Arc<LastRead>,
}

impl H2Keepalive {
    async fn run(mut self) {
        let mut previous_read = self.last_read.at();
        loop {
            tokio::time::sleep_until(previous_read + self.read_idle).await;

            let last_read = self.last_read.at();
            if last_read > previous_read {
                previous_read = last_read;
                continue;
            }

            let pong = tokio::time::timeout(PING_TIMEOUT, self.ping_pong.ping(Ping::opaque()));
            if !matches!(pong.await, Ok(Ok(_))) {
                return;
            }
            previous_read = self.last_read.at();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendPhase {
    Open,
    Ended,
    Reset,
}

#[derive(Debug)]
struct SendState {
    stream: SendStream<Bytes>,
    phase: SendPhase,
}

#[derive(Debug)]
struct SharedSend {
    state: Mutex<SendState>,
}

impl SharedSend {
    fn new(stream: SendStream<Bytes>, ended: bool) -> Self {
        Self {
            state: Mutex::new(SendState {
                stream,
                phase: if ended {
                    SendPhase::Ended
                } else {
                    SendPhase::Open
                },
            }),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, SendState>, H2Error> {
        self.state.lock().map_err(|_| H2Error::StatePoisoned)
    }

    fn cancel(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.phase == SendPhase::Reset {
            return;
        }

        state.stream.reserve_capacity(0);
        state.stream.send_reset(Reason::CANCEL);
        state.phase = SendPhase::Reset;
    }

    fn cancel_if_open(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.phase == SendPhase::Open {
            state.stream.reserve_capacity(0);
            state.stream.send_reset(Reason::CANCEL);
            state.phase = SendPhase::Reset;
        }
    }
}

/// Flow-controlled request body for one streaming HTTP/2 request.
///
/// No borrowed caller buffer is retained across `Poll::Pending`. Capacity is
/// reserved first and bytes are copied only after h2 grants a non-zero slice,
/// so a cancelled write has not silently consumed input.
///
/// Dropping this handle before a successful shutdown resets the exchange.
#[derive(Debug)]
pub struct H2Upload {
    shared: Arc<SharedSend>,
}

impl H2Upload {
    async fn send_owned(&mut self, mut body: Bytes) -> Result<(), H2Error> {
        while !body.is_empty() {
            poll_fn(|cx| {
                let mut state = match self.shared.lock() {
                    Ok(state) => state,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                match state.phase {
                    SendPhase::Open => {}
                    SendPhase::Ended => {
                        return Poll::Ready(Err(H2Error::RequestBodyClosed));
                    }
                    SendPhase::Reset => {
                        return Poll::Ready(Err(H2Error::RequestBodyReset));
                    }
                }

                let wanted = body.len().min(MAX_UPLOAD_DATA_BYTES);
                state.stream.reserve_capacity(wanted);
                let granted = match ready!(state.stream.poll_capacity(cx)) {
                    Some(Ok(granted)) => granted.min(wanted),
                    Some(Err(source)) => {
                        state.stream.reserve_capacity(0);
                        state.phase = SendPhase::Reset;
                        return Poll::Ready(Err(protocol_error(
                            "request body flow control failed",
                            source,
                        )));
                    }
                    None => {
                        state.stream.reserve_capacity(0);
                        state.phase = SendPhase::Reset;
                        return Poll::Ready(Err(H2Error::RequestBodyClosed));
                    }
                };
                if granted == 0 {
                    state.stream.reserve_capacity(0);
                    state.stream.send_reset(Reason::CANCEL);
                    state.phase = SendPhase::Reset;
                    return Poll::Ready(Err(H2Error::ZeroCapacityGrant));
                }

                let chunk = body.split_to(granted);
                let end_of_stream = body.is_empty();
                if let Err(source) = state.stream.send_data(chunk, end_of_stream) {
                    state.stream.reserve_capacity(0);
                    state.phase = SendPhase::Reset;
                    return Poll::Ready(Err(protocol_error(
                        "request DATA could not be sent",
                        source,
                    )));
                }
                if end_of_stream {
                    state.stream.reserve_capacity(0);
                    state.phase = SendPhase::Ended;
                }
                Poll::Ready(Ok(()))
            })
            .await?;
        }
        Ok(())
    }
}

impl Drop for H2Upload {
    fn drop(&mut self) {
        self.shared.cancel_if_open();
    }
}

impl AsyncWrite for H2Upload {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(state_io_error())),
        };
        match state.phase {
            SendPhase::Open => {}
            SendPhase::Ended => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/2 request body is already closed",
                )));
            }
            SendPhase::Reset => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "HTTP/2 request stream is reset",
                )));
            }
        }

        let wanted = input.len().min(MAX_UPLOAD_DATA_BYTES);
        state.stream.reserve_capacity(wanted);
        let granted = match ready!(state.stream.poll_capacity(cx)) {
            Some(Ok(granted)) => granted.min(wanted),
            Some(Err(source)) => {
                state.stream.reserve_capacity(0);
                state.phase = SendPhase::Reset;
                return Poll::Ready(Err(h2_io_error("request body flow control failed", source)));
            }
            None => {
                state.stream.reserve_capacity(0);
                state.phase = SendPhase::Reset;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/2 request body closed before the write",
                )));
            }
        };
        if granted == 0 {
            state.stream.reserve_capacity(0);
            state.stream.send_reset(Reason::CANCEL);
            state.phase = SendPhase::Reset;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                H2Error::ZeroCapacityGrant,
            )));
        }

        if let Err(source) = state
            .stream
            .send_data(Bytes::copy_from_slice(&input[..granted]), false)
        {
            state.stream.reserve_capacity(0);
            state.phase = SendPhase::Reset;
            return Poll::Ready(Err(h2_io_error("request DATA could not be sent", source)));
        }
        Poll::Ready(Ok(granted))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(state_io_error())),
        };
        if state.phase == SendPhase::Reset {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "HTTP/2 request stream is reset",
            )))
        } else {
            // A cancelled `write` may have left a bounded capacity request
            // behind after returning Pending. There is no buffered DATA in
            // this adapter, so flush can and should give that reservation
            // back rather than waiting for it.
            state.stream.reserve_capacity(0);
            // DATA is owned by h2 once `poll_write` returns. The connection
            // driver, rather than this adapter, owns socket flushing.
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(state_io_error())),
        };
        match state.phase {
            SendPhase::Ended => Poll::Ready(Ok(())),
            SendPhase::Reset => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "HTTP/2 request stream is reset",
            ))),
            SendPhase::Open => {
                state.stream.reserve_capacity(0);
                if let Err(source) = state.stream.send_data(Bytes::new(), true) {
                    state.phase = SendPhase::Reset;
                    return Poll::Ready(Err(h2_io_error(
                        "request END_STREAM could not be sent",
                        source,
                    )));
                }
                state.phase = SendPhase::Ended;
                Poll::Ready(Ok(()))
            }
        }
    }
}

/// Response HEADERS that have not arrived yet.
///
/// Dropping this value cancels the request, including a live upload half.
#[derive(Debug)]
pub struct H2PendingResponse {
    response: Option<ResponseFuture>,
    shared: Arc<SharedSend>,
    response_is_bodyless: bool,
    cancel_on_drop: bool,
}

impl H2PendingResponse {
    /// Waits for and validates the final response HEADERS.
    pub async fn open(mut self) -> Result<H2ResponseBody, H2Error> {
        let Some(response) = self.response.take() else {
            self.cancel_on_drop = false;
            return Err(H2Error::ResponseConsumed);
        };
        let response = match response.await {
            Ok(response) => response,
            Err(source) => {
                self.shared.cancel();
                self.cancel_on_drop = false;
                return Err(protocol_error("response HEADERS failed", source));
            }
        };

        let (parts, recv) = response.into_parts();
        if parts.status != StatusCode::OK {
            self.shared.cancel();
            self.cancel_on_drop = false;
            return Err(H2Error::UnexpectedStatus {
                status: parts.status,
            });
        }

        self.cancel_on_drop = false;
        if self.response_is_bodyless || recv.is_end_stream() {
            // Dropping RecvStream clears any illegal DATA already queued for a
            // HEAD response and returns its receive capacity to h2. For an
            // ordinary END_STREAM-on-HEADERS response it also records clean
            // EOF before a caller can drop the body without polling it.
            drop(recv);
            return Ok(H2ResponseBody {
                headers: parts.headers,
                recv: None,
                pending: Bytes::new(),
                reading_trailers: false,
                trailers: None,
                eof: true,
                failure: None,
                shared: self.shared.clone(),
            });
        }

        Ok(H2ResponseBody {
            headers: parts.headers,
            recv: Some(recv),
            pending: Bytes::new(),
            reading_trailers: false,
            trailers: None,
            eof: false,
            failure: None,
            shared: self.shared.clone(),
        })
    }
}

impl Drop for H2PendingResponse {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.shared.cancel();
        }
    }
}

/// Flow-controlled response body for one HTTP/2 request.
///
/// Dropping the body before EOF cancels the request, including a live upload
/// half. Successful completion consumes optional response trailers before it
/// reports EOF.
#[derive(Debug)]
pub struct H2ResponseBody {
    headers: HeaderMap,
    recv: Option<RecvStream>,
    pending: Bytes,
    reading_trailers: bool,
    trailers: Option<HeaderMap>,
    eof: bool,
    failure: Option<String>,
    shared: Arc<SharedSend>,
}

impl H2ResponseBody {
    /// Response headers excluding the HTTP/2 pseudo-headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Trailers received after the response body reached EOF.
    pub fn trailers(&self) -> Option<&HeaderMap> {
        self.trailers.as_ref()
    }

    fn fail(&mut self, message: String) -> io::Error {
        self.failure = Some(message.clone());
        self.shared.cancel();
        io::Error::new(io::ErrorKind::ConnectionReset, message)
    }
}

impl Drop for H2ResponseBody {
    fn drop(&mut self) {
        if !self.eof {
            self.shared.cancel();
        }
    }
}

impl AsyncRead for H2ResponseBody {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        if let Some(failure) = &this.failure {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                failure.clone(),
            )));
        }

        loop {
            if !this.pending.is_empty() {
                let take = this.pending.len().min(output.remaining());
                let release = match this.recv.as_mut() {
                    Some(recv) => recv.flow_control().release_capacity(take),
                    None => {
                        return Poll::Ready(Err(
                            this.fail("HTTP/2 response body lost its receive stream".to_owned())
                        ));
                    }
                };
                if let Err(source) = release {
                    return Poll::Ready(Err(
                        this.fail(format!("HTTP/2 response flow control failed: {source}"))
                    ));
                }

                output.put_slice(&this.pending[..take]);
                this.pending = this.pending.slice(take..);
                return Poll::Ready(Ok(()));
            }

            if this.reading_trailers {
                let trailers = {
                    let Some(recv) = this.recv.as_mut() else {
                        return Poll::Ready(Err(
                            this.fail("HTTP/2 response body lost its trailer stream".to_owned())
                        ));
                    };
                    ready!(recv.poll_trailers(cx))
                };
                match trailers {
                    Ok(trailers) => {
                        this.trailers = trailers;
                        this.recv = None;
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Err(source) => {
                        return Poll::Ready(Err(
                            this.fail(format!("HTTP/2 response trailers failed: {source}"))
                        ));
                    }
                }
            }

            let data = {
                let Some(recv) = this.recv.as_mut() else {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                };
                ready!(recv.poll_data(cx))
            };
            match data {
                Some(Ok(chunk)) if chunk.is_empty() => continue,
                Some(Ok(chunk)) => this.pending = chunk,
                Some(Err(source)) => {
                    return Poll::Ready(Err(
                        this.fail(format!("HTTP/2 response DATA failed: {source}"))
                    ));
                }
                None => {
                    this.reading_trailers = true;
                }
            }
        }
    }
}

fn protocol_error(context: &'static str, source: h2::Error) -> H2Error {
    H2Error::Protocol { context, source }
}

fn h2_io_error(context: &'static str, source: h2::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        protocol_error(context, source),
    )
}

fn state_io_error() -> io::Error {
    io::Error::other(H2Error::StatePoisoned)
}
