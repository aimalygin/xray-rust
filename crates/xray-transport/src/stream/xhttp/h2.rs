//! HTTP/2 wire engine for outbound XHTTP.
//!
//! The XHTTP mode layer composes request URIs and headers. This module owns
//! one reusable HTTP/2 connection plus the flow-controlled request and
//! response bodies opened on it. A streaming exchange is deliberately split
//! into independently pollable halves. Dropping either half before its clean
//! end cancels that exchange, while a shared reset handle keeps the reset
//! scoped to that stream and returns reserved capacity to the connection.

use std::collections::VecDeque;
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{ready, Context, Poll, Waker};

use bytes::Bytes;
use futures_util::FutureExt;
use h2::client::{self, ResponseFuture, SendRequest};
use h2::{FlowControl, Ping, PingPong, Reason, RecvStream, SendStream};
use http::{HeaderMap, Method, Request, StatusCode};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};

use crate::stream::h2_bdp::{BdpEstimator, BdpPings, BdpSampler};
use crate::{BoxedTransportStream, MemoryClass};

use super::config::{
    h2_stream_receive_window, XhttpConfig, XhttpConfigError, DEFAULT_H2_STREAM_RECEIVE_WINDOW,
    H2_CONNECTION_RECEIVE_WINDOW,
};

/// Matches x/net/http2's default stream receive credit. The HTTP/2 default
/// (65,535 bytes) limits a download to about 4.6 Mbit/s at RTT 113 ms even
/// when the connection window is larger (issue #28). Credit is replenished
/// only as the caller reads; this does not eagerly allocate a 4 MiB buffer.
const STREAM_WINDOW_SIZE: u32 = DEFAULT_H2_STREAM_RECEIVE_WINDOW;

/// Aggregate unread DATA credit remains bounded at 16 MiB per connection.
/// At the 4 MiB default, three full unread responses leave a complete stream
/// window for other traffic. Four can exhaust it until a consumer reads or cancels;
/// this is not an RSS bound (TLS, framing and application buffers add to it).
const CONNECTION_WINDOW_SIZE: u32 = H2_CONNECTION_RECEIVE_WINDOW;

/// Stream credit goes back once a sixteenth of the opening window has been
/// read, so the sender keeps at least 15/16 of it. h2 alone waits for half the
/// remaining window, about 1.4 MB of a 4 MiB one, and at 113 ms that left our
/// downloads 28% behind Go's (`docs/issue28-client-comparison.md`). Go's
/// client returns credit every 4 KiB, x/net/http2's `inflowMinRefresh` and the
/// floor here, but a WINDOW_UPDATE for every read cost a fast download 16% of
/// its throughput.
const STREAM_WINDOW_UPDATE_FRACTION: u32 = 16;
const MIN_STREAM_WINDOW_UPDATE: u32 = 4 * 1024;

/// The stream window a constrained host opens with: a quarter of Go's, so
/// that eight stalled downloads pin 8 MiB rather than 32. A reader that keeps
/// up grows it back to [`STREAM_WINDOW_SIZE`] within two round trips.
const CONSTRAINED_STREAM_WINDOW_SIZE: u32 = 1024 * 1024;

/// Go's client never pings to grow a window, and a CDN sees every PING, so
/// sampling also stops once three samples in a row leave the window alone.
const BDP_IDLE_SAMPLES: u32 = 3;

/// The stream receive window an XHTTP H2 connection opens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2ReceiveWindow {
    /// Fixed credit per stream: Go's 4 MiB, or the configured value.
    Fixed(u32),
    /// Opens at `initial` and grows for a reader that keeps up, up to `max`.
    Adaptive { initial: u32, max: u32 },
}

impl H2ReceiveWindow {
    /// A configured window stays as configured. Otherwise a constrained host
    /// opens at [`CONSTRAINED_STREAM_WINDOW_SIZE`] and grows to the default.
    pub(crate) fn for_config(config: &XhttpConfig, class: MemoryClass) -> Self {
        match class {
            MemoryClass::Constrained if !config.h2_stream_receive_window_configured => {
                Self::Adaptive {
                    initial: CONSTRAINED_STREAM_WINDOW_SIZE.min(config.h2_stream_receive_window),
                    max: config.h2_stream_receive_window,
                }
            }
            _ => Self::Fixed(config.h2_stream_receive_window),
        }
    }

    fn initial(self) -> u32 {
        match self {
            Self::Fixed(window)
            | Self::Adaptive {
                initial: window, ..
            } => window,
        }
    }

    /// The read credit a stream gathers before it goes back to the peer.
    fn update_threshold(self) -> u32 {
        (self.initial() / STREAM_WINDOW_UPDATE_FRACTION).max(MIN_STREAM_WINDOW_UPDATE)
    }
}

/// x/net/http2's `initialMaxConcurrentStreams`: the streams Go's client assumes
/// it may open before the server's SETTINGS arrive. Assuming one made the
/// first upload of a packet-up flow dial a second connection, a whole TLS
/// round trip, while the download held the only stream of a fresh one.
const INITIAL_MAX_SEND_STREAMS: usize = 100;

/// Bounds the copy made by one [`AsyncWrite::poll_write`] call.
const MAX_UPLOAD_DATA_BYTES: usize = 16 * 1024;

/// x/net/http2's default `Transport.PingTimeout`.
const PING_TIMEOUT: Duration = Duration::from_secs(15);

/// HTTP/2 connection, request, and response failures.
#[derive(Debug, Error)]
pub enum H2Error {
    #[error(transparent)]
    Configuration(#[from] XhttpConfigError),
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

impl H2Error {
    pub(crate) fn is_remote_goaway_before_request_commit(&self) -> bool {
        matches!(
            self,
            Self::Protocol { context, source }
                if matches!(
                    *context,
                    "connection is not ready" | "request HEADERS could not be sent"
                ) && source.is_go_away()
                    && source.is_remote()
        )
    }
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
    /// Where responses count the DATA they read, for an adaptive window.
    bdp: Option<Arc<BdpSampler>>,
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
                bdp: self.bdp.clone(),
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
    io: BoxedTransportStream,
    read_idle: Option<Duration>,
) -> Result<H2Client, H2Error> {
    connect_h2_with_receive_window(io, read_idle, STREAM_WINDOW_SIZE).await
}

/// Opens H2 with fixed per-stream receive credit and optional keepalive.
/// Invalid windows fail before any handshake; connection credit stays 16 MiB.
pub async fn connect_h2_with_receive_window(
    io: BoxedTransportStream,
    read_idle: Option<Duration>,
    stream_receive_window: u32,
) -> Result<H2Client, H2Error> {
    let stream_receive_window = h2_stream_receive_window(Some(stream_receive_window))?;
    connect_h2_with_window(io, read_idle, H2ReceiveWindow::Fixed(stream_receive_window)).await
}

/// Opens H2 with `window` and optional keepalive; connection credit stays
/// 16 MiB. An adaptive window grows as grpc-go's BDP estimator grows one
/// (see [`crate::stream::h2_bdp`]).
pub async fn connect_h2_with_window(
    mut io: BoxedTransportStream,
    read_idle: Option<Duration>,
    window: H2ReceiveWindow,
) -> Result<H2Client, H2Error> {
    // XHTTP cannot use Vision direct mode, so retaining TLS record boundaries
    // after the stream has moved into h2 is pure overhead.
    io.release_record_alignment();

    let read_idle = read_idle.filter(|duration| !duration.is_zero());
    let (io, last_read) = WatchedIo::new(io, read_idle.is_some());
    let mut builder = client::Builder::new();
    builder
        .initial_window_size(window.initial())
        .initial_connection_window_size(CONNECTION_WINDOW_SIZE)
        .stream_window_update_threshold(window.update_threshold())
        .initial_max_send_streams(INITIAL_MAX_SEND_STREAMS);
    let (send_request, mut connection) = builder
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|source| protocol_error("handshake failed", source))?;

    // `PingPong` is a single-take handle owned by `Connection`, so it must be
    // extracted before the connection moves into its driver task. The
    // keepalive and the BDP loop share it: h2 allows one user PING in flight.
    let ping_pong = connection
        .ping_pong()
        .map(|ping_pong| Arc::new(tokio::sync::Mutex::new(ping_pong)));
    let keepalive = read_idle.zip(last_read).zip(ping_pong.clone()).map(
        |((read_idle, last_read), ping_pong)| H2Keepalive {
            ping_pong,
            read_idle,
            last_read,
        },
    );
    let bdp = match window {
        H2ReceiveWindow::Fixed(_) => None,
        H2ReceiveWindow::Adaptive { initial, max } => ping_pong.map(|ping_pong| BdpPings {
            sampler: Arc::default(),
            ping_pong,
            estimator: BdpEstimator::new(initial, max),
            idle_limit: Some(BDP_IDLE_SAMPLES),
        }),
    };
    let sampler = bdp.as_ref().map(|bdp| Arc::clone(&bdp.sampler));

    let driver = Arc::new(H2ConnectionDriver {
        task: tokio::spawn(drive_connection(connection, keepalive, bdp)),
    });
    Ok(H2Client {
        send_request,
        driver,
        bdp: sampler,
    })
}

async fn drive_connection(
    mut connection: client::Connection<WatchedIo, Bytes>,
    keepalive: Option<H2Keepalive>,
    bdp: Option<BdpPings>,
) -> Result<(), h2::Error> {
    let sampler = bdp.as_ref().map(|bdp| Arc::clone(&bdp.sampler));
    let connection = poll_fn(move |cx| {
        if let Some(sampler) = &sampler {
            if let Some(window) = sampler.take_window(cx.waker()) {
                // h2 refuses a SETTINGS while our previous one is
                // unacknowledged. Reading its ACK polls this again.
                if connection.set_initial_window_size(window).is_err() {
                    sampler.defer_window(window);
                }
            }
        }
        Pin::new(&mut connection).poll(cx)
    });
    let keepalive = async move {
        match keepalive {
            Some(keepalive) => keepalive.run().await,
            None => std::future::pending().await,
        }
    };
    let bdp = async move {
        match bdp {
            Some(bdp) => bdp.run().await,
            None => std::future::pending().await,
        }
    };

    tokio::select! {
        outcome = connection => outcome,
        () = keepalive => Ok(()),
        () = bdp => Ok(()),
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
    ping_pong: Arc<tokio::sync::Mutex<PingPong>>,
    read_idle: Duration,
    last_read: Arc<LastRead>,
}

impl H2Keepalive {
    async fn run(self) {
        let mut previous_read = self.last_read.at();
        loop {
            tokio::time::sleep_until(previous_read + self.read_idle).await;

            let last_read = self.last_read.at();
            if last_read > previous_read {
                previous_read = last_read;
                continue;
            }

            let pong = tokio::time::timeout(PING_TIMEOUT, async {
                self.ping_pong.lock().await.ping(Ping::opaque()).await
            });
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
    pub(crate) async fn send_owned(&mut self, mut body: Bytes) -> Result<(), H2Error> {
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
        let state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(state_io_error())),
        };
        if state.phase == SendPhase::Reset {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "HTTP/2 request stream is reset",
            )))
        } else {
            // DATA is owned by h2 once `poll_write` returns. The connection
            // driver, rather than this adapter, owns socket flushing. Keep a
            // bounded outstanding capacity request intact: the read half of a
            // split XHTTP stream may flush while its write half is waiting for
            // flow control, and cancelling that reservation would strand the
            // pending writer without a wakeup.
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
    bdp: Option<Arc<BdpSampler>>,
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
            return Ok(H2ResponseBody::new(
                parts.headers,
                None,
                self.shared.clone(),
                None,
            ));
        }

        Ok(H2ResponseBody::new(
            parts.headers,
            Some(recv),
            self.shared.clone(),
            self.bdp.take(),
        ))
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
    /// Absent for a response that ended with its HEADERS.
    received: Option<Arc<Mutex<ReceivedBody>>>,
    flow: Option<FlowControl>,
    drain: Option<JoinHandle<()>>,
    pending: Bytes,
    trailers: Option<HeaderMap>,
    eof: bool,
    failure: Option<String>,
    shared: Arc<SharedSend>,
    bdp: Option<Arc<BdpSampler>>,
}

/// DATA received for one response and not yet read, filled by
/// [`drain_response`].
#[derive(Debug, Default)]
struct ReceivedBody {
    chunks: VecDeque<Bytes>,
    end: Option<ReceivedEnd>,
    reader: Option<Waker>,
}

#[derive(Debug)]
enum ReceivedEnd {
    Trailers(Option<HeaderMap>),
    Failed(String),
}

fn lock_received(received: &Mutex<ReceivedBody>) -> MutexGuard<'_, ReceivedBody> {
    received
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Moves response DATA out of h2 as it arrives.
///
/// h2 keeps every received frame as a slice of its shared read buffer, so
/// frames queued behind a slow or paused reader pin roughly twice their size:
/// eight stalled streams held about 60 MiB for 32 MiB of window. A frame that
/// has to wait is therefore copied to an exact-size buffer; a frame the reader
/// takes at once is passed through. Flow control is unchanged: credit returns
/// to the peer only as the reader consumes bytes.
async fn drain_response(mut recv: RecvStream, received: Arc<Mutex<ReceivedBody>>) {
    let end = loop {
        let Some(first) = recv.data().await else {
            break match recv.trailers().await {
                Ok(trailers) => ReceivedEnd::Trailers(trailers),
                Err(source) => {
                    ReceivedEnd::Failed(format!("HTTP/2 response trailers failed: {source}"))
                }
            };
        };
        let mut next = Some(first);
        let mut failure = None;
        let mut guard = lock_received(&received);
        while let Some(data) = next.take() {
            match data {
                Ok(chunk) if chunk.is_empty() => {}
                Ok(chunk) => {
                    let chunk = if guard.chunks.is_empty() {
                        chunk
                    } else {
                        Bytes::copy_from_slice(&chunk)
                    };
                    guard.chunks.push_back(chunk);
                }
                Err(source) => {
                    failure = Some(format!("HTTP/2 response DATA failed: {source}"));
                    break;
                }
            }
            // Take frames that are already buffered without yielding, so the
            // reader is woken once per burst. A Pending result here leaves a
            // no-op waker that the next real poll replaces before it waits.
            next = recv.data().now_or_never().flatten();
        }
        if let Some(reader) = guard.reader.take() {
            reader.wake();
        }
        drop(guard);
        if let Some(failure) = failure {
            break ReceivedEnd::Failed(failure);
        }
    };
    let mut guard = lock_received(&received);
    guard.end = Some(end);
    if let Some(reader) = guard.reader.take() {
        reader.wake();
    }
}

impl H2ResponseBody {
    fn new(
        headers: HeaderMap,
        recv: Option<RecvStream>,
        shared: Arc<SharedSend>,
        bdp: Option<Arc<BdpSampler>>,
    ) -> Self {
        let Some(mut recv) = recv else {
            return Self {
                headers,
                received: None,
                flow: None,
                drain: None,
                pending: Bytes::new(),
                trailers: None,
                eof: true,
                failure: None,
                shared,
                bdp,
            };
        };
        let flow = recv.flow_control().clone();
        let received = Arc::new(Mutex::new(ReceivedBody::default()));
        let drain = tokio::spawn(drain_response(recv, Arc::clone(&received)));
        Self {
            headers,
            received: Some(received),
            flow: Some(flow),
            drain: Some(drain),
            pending: Bytes::new(),
            trailers: None,
            eof: false,
            failure: None,
            shared,
            bdp,
        }
    }

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
        // Dropping the receive stream with the flow-control handle returns
        // any unread credit to the connection.
        if let Some(drain) = self.drain.take() {
            drain.abort();
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

        let mut copied = 0;
        loop {
            if !this.pending.is_empty() {
                let take = this.pending.len().min(output.remaining());
                output.put_slice(&this.pending[..take]);
                this.pending = this.pending.slice(take..);
                copied += take;
                if output.remaining() == 0 {
                    break;
                }
                continue;
            }
            let Some(received) = this.received.as_ref() else {
                this.eof = true;
                break;
            };
            let mut guard = lock_received(received);
            if let Some(chunk) = guard.chunks.pop_front() {
                drop(guard);
                this.pending = chunk;
                continue;
            }
            if copied > 0 {
                break;
            }
            match guard.end.take() {
                Some(ReceivedEnd::Trailers(trailers)) => {
                    drop(guard);
                    this.trailers = trailers;
                    this.received = None;
                    this.flow = None;
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(ReceivedEnd::Failed(message)) => {
                    drop(guard);
                    return Poll::Ready(Err(this.fail(message)));
                }
                None => {
                    guard.reader = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }

        if copied > 0 {
            let release = match this.flow.as_mut() {
                Some(flow) => flow.release_capacity(copied),
                None => Ok(()),
            };
            if let Err(source) = release {
                return Poll::Ready(Err(
                    this.fail(format!("HTTP/2 response flow control failed: {source}"))
                ));
            }
            if let Some(bdp) = &this.bdp {
                bdp.record_data(copied);
            }
        }
        Poll::Ready(Ok(()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::XhttpConfigInput;

    fn config(window: Option<u32>) -> XhttpConfig {
        XhttpConfig::normalize(XhttpConfigInput {
            h2_stream_receive_window: window,
            ..XhttpConfigInput::default()
        })
        .unwrap()
    }

    #[test]
    fn a_standard_host_keeps_gos_fixed_window() {
        assert_eq!(
            H2ReceiveWindow::for_config(&config(None), MemoryClass::Standard),
            H2ReceiveWindow::Fixed(4 << 20)
        );
    }

    #[test]
    fn a_constrained_host_opens_smaller_and_grows_to_the_default() {
        assert_eq!(
            H2ReceiveWindow::for_config(&config(None), MemoryClass::Constrained),
            H2ReceiveWindow::Adaptive {
                initial: 1 << 20,
                max: 4 << 20
            }
        );
    }

    #[test]
    fn a_configured_window_stays_fixed_on_every_host() {
        for class in [MemoryClass::Standard, MemoryClass::Constrained] {
            assert_eq!(
                H2ReceiveWindow::for_config(&config(Some(8 << 20)), class),
                H2ReceiveWindow::Fixed(8 << 20)
            );
        }
    }
}
