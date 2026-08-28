//! XHTTP mode orchestration over the HTTP/1.1, HTTP/2, and HTTP/3 wire engines.
//!
//! Every network stream comes from [`XhttpDial`]. The closure is supplied by
//! the outer transport dialer so Android socket protection, Happy Eyeballs,
//! TLS, and REALITY stay on their existing path instead of being bypassed by
//! an eager `TcpStream::connect` hidden in this module.
//!
//! Xmux is a client-slot manager, not one transport-wide connection pool.
//! Every slot owns its HTTP/2 connection and safe HTTP/1.1 packet pool; the
//! logical stream owns an open-usage lease. That distinction is load-bearing
//! because Xray's default `maxConnections = 3` bounds the shared HTTP-client
//! pool while still allowing simultaneous logical flows to reuse connections.

use std::fmt;
use std::future::{poll_fn, Future};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use async_compression::tokio::bufread::GzipDecoder;
use bytes::Bytes;
use futures_util::task::AtomicWaker;
use http::{header, HeaderName, HeaderValue, Method, Request, Version};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::sync::{oneshot, watch, Mutex as AsyncMutex};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use xray_routing::Target;

use super::super::http_headers::HeaderMap as XhttpHeaderMap;
use super::config::{XhttpConfig, XhttpEndpoint, XhttpMode, XhttpRange};
use super::h1::{start_chunked_request, start_fixed_request, H1Error, H1Request, H1ResponseBody};
use super::h2::{connect_h2_with_keepalive, H2Client, H2Error, H2ResponseBody};
use super::h3::{
    connect_h3_candidates, H3Client, H3ConnectConfig, H3Error, H3QuicConfig, H3ResponseBody,
};
use super::padding::draw_range;
use super::request::{
    compose_packet_request, compose_stream_request, XhttpRequest, XhttpRequestBody,
    XhttpRequestError, XhttpStreamBody,
};
use super::session::{generate_session_id, XhttpSessionIdError};
use crate::{
    utls_tls::TlsAlpnPolicy, BoxedTransportStream, ConnectorConfig, HappyEyeballsConfig,
    TransportDialer, TransportError, TransportStream,
};

const PACKET_RESPONSE_CAP_FALLBACK: usize = 1;
// Xray's packet-up pipe is made from pooled 8 KiB buffers. Grow the H1 body
// only while bytes are actually available instead of materializing the
// configured (potentially multi-megabyte) POST ceiling for every flow.
const H1_PACKET_READ_CHUNK_BYTES: usize = 8 * 1024;
const MAX_PACKET_RESPONSE_TASKS: usize = 256;
const MAX_H1_IDLE_UPLOAD_STREAMS: usize = 256;
const HTTP_MULTIPLEXED_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
// Quinn 0.11 exposes a blocking `open_bi` future but no public getter or
// non-consuming probe for the peer's remaining outbound stream budget. Until
// that capacity can be reserved without consuming an HTTP request stream, one
// active request per pooled H3 connection is the only fail-safe policy: a
// peer advertising MAX_STREAMS_BIDI=1 must not deadlock stream-up's persistent
// downlink against its upload. The H3 engine itself remains concurrent; this
// conservative transport-pool bound trades extra QUIC connections for
// progress against low-limit peers.
const H3_REQUESTS_PER_CONNECTION: usize = 1;

pub type XhttpDialFuture =
    Pin<Box<dyn Future<Output = Result<BoxedTransportStream, TransportError>> + Send + 'static>>;
pub type XhttpDial = Arc<dyn Fn() -> XhttpDialFuture + Send + Sync + 'static>;
pub type XhttpH3DialFuture =
    Pin<Box<dyn Future<Output = Result<H3Client, H3Error>> + Send + 'static>>;
pub type XhttpH3Dial = Arc<dyn Fn() -> XhttpH3DialFuture + Send + Sync + 'static>;
#[doc(hidden)]
pub type XhttpClock = Arc<dyn Fn() -> Instant + Send + Sync + 'static>;

type BoxedRead = Box<dyn AsyncRead + Send + Unpin + 'static>;
type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin + 'static>;
type OpenReadFuture =
    Pin<Box<dyn Future<Output = Result<BoxedRead, XhttpTransportError>> + Send + 'static>>;

#[derive(Debug)]
struct PreparedRequest {
    request: XhttpRequest,
    /// True only when this transport inserted `Accept-Encoding: gzip`.
    /// Keeping this separate from the headers is security- and parity-
    /// relevant: an explicit non-empty caller header must never trigger
    /// transparent response decoding.
    auto_gzip: bool,
}

struct PacketWorkerContext {
    input: tokio::io::DuplexStream,
    first_uplink: Option<oneshot::Receiver<FirstUplink>>,
    session: String,
    max_packet: u32,
    response_cap: usize,
    upload_client: Arc<XmuxClient>,
    dial: XhttpModeDial,
    failure: Arc<SharedFailure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FirstUplink {
    Data,
    Closed,
}

/// Keeps an idle H1 packet-up stream allocation-free on its worker side.
///
/// Tokio's in-memory duplex buffer grows lazily, but the packet worker used to
/// reserve and zero `scMaxEachPostBytes` as soon as the logical stream opened.
/// Notify the worker only after this side has actually accepted a byte. A
/// clean shutdown before any write is distinct so the worker can exit without
/// constructing its packet buffer at all.
struct FirstUplinkWriter {
    inner: tokio::io::DuplexStream,
    first_uplink: Option<oneshot::Sender<FirstUplink>>,
}

impl FirstUplinkWriter {
    fn new(inner: tokio::io::DuplexStream, first_uplink: oneshot::Sender<FirstUplink>) -> Self {
        Self {
            inner,
            first_uplink: Some(first_uplink),
        }
    }

    fn notify(&mut self, event: FirstUplink) {
        if let Some(first_uplink) = self.first_uplink.take() {
            let _ = first_uplink.send(event);
        }
    }
}

impl AsyncWrite for FirstUplinkWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, input);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            this.notify(FirstUplink::Data);
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, input);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            this.notify(FirstUplink::Data);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        if result.is_ready() {
            this.notify(FirstUplink::Closed);
        }
        result
    }
}

#[derive(Clone)]
enum XhttpModeDial {
    Stream(XhttpDial),
    Http3(XhttpH3Dial),
}

impl XhttpModeDial {
    fn stream(&self) -> Result<XhttpDial, XhttpTransportError> {
        match self {
            Self::Stream(dial) => Ok(Arc::clone(dial)),
            Self::Http3(_) => Err(XhttpTransportError::MissingProtocolDial("TCP")),
        }
    }

    fn http3(&self) -> Result<XhttpH3Dial, XhttpTransportError> {
        match self {
            Self::Http3(dial) => Ok(Arc::clone(dial)),
            Self::Stream(_) => Err(XhttpTransportError::MissingProtocolDial("UDP")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpHttpVersion {
    Http1,
    Http2,
    Http3,
}

/// Xray's signed, config-build-normalized xmux policy.
///
/// The ranges deliberately remain signed: a value selected as zero or less
/// disables that bound upstream. An entirely omitted/all-zero JSON object is
/// converted by the config parser to [`Self::default`], matching Xray's
/// `SplitHTTPConfig.Build`; explicit non-default negative values must not be
/// silently reinterpreted as defaults here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhttpXmuxPolicy {
    pub max_concurrency: XhttpRange,
    pub max_connections: XhttpRange,
    pub c_max_reuse_times: XhttpRange,
    pub h_max_request_times: XhttpRange,
    pub h_max_reusable_secs: XhttpRange,
    pub h_keep_alive_period_secs: i64,
}

impl Default for XhttpXmuxPolicy {
    fn default() -> Self {
        Self {
            max_concurrency: XhttpRange::default(),
            max_connections: XhttpRange::exact(3),
            c_max_reuse_times: XhttpRange::default(),
            h_max_request_times: XhttpRange { from: 600, to: 900 },
            h_max_reusable_secs: XhttpRange {
                from: 1_800,
                to: 3_000,
            },
            h_keep_alive_period_secs: 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum XhttpTransportError {
    #[error("XHTTP dial failed: {0}")]
    Dial(#[source] TransportError),
    #[error(transparent)]
    Compose(#[from] XhttpRequestError),
    #[error(transparent)]
    Http1(#[from] H1Error),
    #[error(transparent)]
    Http2(#[from] H2Error),
    #[error(transparent)]
    Http3(#[from] H3Error),
    #[error("XHTTP request could not be represented as HTTP/2: {0}")]
    InvalidHttp2Request(String),
    #[error("XHTTP request could not be represented as HTTP/3: {0}")]
    InvalidHttp3Request(String),
    #[error("XHTTP random source failed: {0}")]
    Random(#[source] rand::Error),
    #[error("XHTTP random source lock is poisoned")]
    RandomStatePoisoned,
    #[error(transparent)]
    SessionId(#[from] XhttpSessionIdError),
    #[error("XHTTP xmux range has descending bounds")]
    DescendingXmuxRange,
    #[error("XHTTP xmux maxConnections cannot be enabled with maxConcurrency")]
    ConflictingXmuxConnectionLimits,
    #[error("XHTTP xmux candidate count does not fit the random selector")]
    XmuxCandidateCountTooLarge,
    #[error("XHTTP xmux reusable deadline is outside the platform clock range")]
    XmuxReusableDeadlineOverflow,
    #[error("XHTTP packet size does not fit this platform")]
    PacketSizeTooLarge,
    #[error("XHTTP packet worker limit does not fit this platform")]
    WorkerLimitTooLarge,
    #[error("XHTTP shared HTTP/2 dial failed: {0}")]
    SharedHttp2Dial(Arc<str>),
    #[error("XHTTP shared HTTP/3 dial failed: {0}")]
    SharedHttp3Dial(Arc<str>),
    #[error("XHTTP {0} connection source is unavailable for the selected HTTP version")]
    MissingProtocolDial(&'static str),
    #[error("XHTTP packet worker stopped before reporting upload completion")]
    UploadCompletionLost,
    #[error("XHTTP background task failed: {0}")]
    BackgroundTask(String),
    #[error("XHTTP I/O failed: {0}")]
    Io(#[source] io::Error),
}

impl XhttpTransportError {
    fn retires_client(&self) -> bool {
        !matches!(self, Self::Io(error) if is_gzip_decode_error(error))
    }
}

/// A dial-ready XHTTP transport shared by every logical stream of one
/// outbound.
#[derive(Clone)]
pub struct XhttpTransport {
    config: Arc<XhttpConfig>,
    endpoint: XhttpEndpoint,
    http_version: XhttpHttpVersion,
    h3_quic: H3QuicConfig,
    rng: Arc<StdMutex<Box<dyn RngCore + Send>>>,
    xmux: Arc<XmuxManager>,
}

impl fmt::Debug for XhttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XhttpTransport")
            .field("config", &self.config)
            .field("endpoint", &self.endpoint)
            .field("http_version", &self.http_version)
            .field("h3_quic", &self.h3_quic)
            .finish_non_exhaustive()
    }
}

impl XhttpTransport {
    pub fn new(
        config: XhttpConfig,
        endpoint: XhttpEndpoint,
        http_version: XhttpHttpVersion,
        xmux_policy: XhttpXmuxPolicy,
    ) -> Result<Self, XhttpTransportError> {
        Self::new_with_h3_quic(
            config,
            endpoint,
            http_version,
            xmux_policy,
            H3QuicConfig::default(),
        )
    }

    pub fn new_with_h3_quic(
        config: XhttpConfig,
        endpoint: XhttpEndpoint,
        http_version: XhttpHttpVersion,
        xmux_policy: XhttpXmuxPolicy,
        mut h3_quic: H3QuicConfig,
    ) -> Result<Self, XhttpTransportError> {
        if http_version == XhttpHttpVersion::Http3
            && h3_quic.keep_alive_interval.is_none()
            && xmux_policy.h_keep_alive_period_secs == 0
        {
            h3_quic.keep_alive_interval = Some(Duration::from_secs(10));
        }
        if http_version == XhttpHttpVersion::Http3 {
            h3_quic.diagnostics()?;
        }
        let rng: Arc<StdMutex<Box<dyn RngCore + Send>>> = Arc::new(StdMutex::new(Box::new(OsRng)));
        let clock: XhttpClock = Arc::new(Instant::now);
        let idle_limit = usize::try_from(config.max_buffered_posts)
            .unwrap_or(PACKET_RESPONSE_CAP_FALLBACK)
            .clamp(PACKET_RESPONSE_CAP_FALLBACK, MAX_H1_IDLE_UPLOAD_STREAMS);
        let xmux = Arc::new(XmuxManager::new(
            xmux_policy,
            idle_limit,
            Arc::clone(&rng),
            clock,
            HTTP_MULTIPLEXED_IDLE_TIMEOUT,
        )?);
        Ok(Self {
            config: Arc::new(config),
            endpoint,
            http_version,
            h3_quic,
            rng,
            xmux,
        })
    }

    #[doc(hidden)]
    pub fn with_rng(mut self, rng: Box<dyn RngCore + Send>) -> Result<Self, XhttpTransportError> {
        let rng = Arc::new(StdMutex::new(rng));
        self.xmux = Arc::new(XmuxManager::new(
            self.xmux.policy,
            self.xmux.h1_idle_limit,
            Arc::clone(&rng),
            Arc::clone(&self.xmux.clock),
            self.xmux.h2_idle_timeout,
        )?);
        self.rng = rng;
        Ok(self)
    }

    #[doc(hidden)]
    pub fn with_clock(mut self, clock: XhttpClock) -> Result<Self, XhttpTransportError> {
        self.xmux = Arc::new(XmuxManager::new(
            self.xmux.policy,
            self.xmux.h1_idle_limit,
            Arc::clone(&self.rng),
            clock,
            self.xmux.h2_idle_timeout,
        )?);
        Ok(self)
    }

    #[doc(hidden)]
    pub fn with_h2_idle_timeout(mut self, timeout: Duration) -> Result<Self, XhttpTransportError> {
        self.xmux = Arc::new(XmuxManager::new(
            self.xmux.policy,
            self.xmux.h1_idle_limit,
            Arc::clone(&self.rng),
            Arc::clone(&self.xmux.clock),
            timeout,
        )?);
        Ok(self)
    }

    #[doc(hidden)]
    pub fn with_h3_idle_timeout(self, timeout: Duration) -> Result<Self, XhttpTransportError> {
        self.with_h2_idle_timeout(timeout)
    }

    #[doc(hidden)]
    pub fn config(&self) -> &XhttpConfig {
        &self.config
    }

    /// Read-only seam for parser-to-runtime compatibility tests. The HTTP
    /// engine is selected while the outbound is compiled, before any socket
    /// exists, so exposing that decision avoids inferring it from network I/O.
    #[doc(hidden)]
    pub fn http_version(&self) -> XhttpHttpVersion {
        self.http_version
    }

    /// Read-only seam for verifying the effective scheme and authority after
    /// XHTTP host, TLS/REALITY SNI, and destination fallbacks are resolved.
    #[doc(hidden)]
    pub fn endpoint(&self) -> &XhttpEndpoint {
        &self.endpoint
    }

    #[doc(hidden)]
    pub fn shares_xmux_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.xmux, &other.xmux)
    }

    #[doc(hidden)]
    pub async fn xmux_client_count(&self) -> usize {
        self.xmux.clients.lock().await.len()
    }

    #[doc(hidden)]
    pub async fn xmux_open_usages(&self) -> Vec<i32> {
        self.xmux
            .clients
            .lock()
            .await
            .iter()
            .map(|client| client.open_usage.load(Ordering::Acquire))
            .collect()
    }

    /// Active request reservations on every pooled HTTP/2 connection.
    ///
    /// This is a deterministic lifecycle seam for integration tests: aborting
    /// a Tokio response monitor is asynchronous, so tests which assert later
    /// connection reuse must first observe its reservation being released.
    #[doc(hidden)]
    pub async fn h2_connection_activity_counts(&self) -> Vec<usize> {
        let clients = self.xmux.clients.lock().await.clone();
        let mut counts = Vec::new();
        for client in clients {
            counts.extend(client.h2_pool.connection_activity_counts().await);
        }
        counts
    }

    /// Effective HTTP/2 read-idle/PING cadence retained for the H2 lifecycle
    /// layer. `None` is the explicit negative-value disable sentinel; zero in
    /// config becomes Xray's Chrome-like 45-second default.
    #[doc(hidden)]
    pub fn h2_keep_alive_period(&self) -> Option<Duration> {
        self.xmux.h2_keep_alive_period
    }

    #[doc(hidden)]
    pub fn h3_quic_config(&self) -> &H3QuicConfig {
        &self.h3_quic
    }

    /// Opens a logical flow through the existing protected/resolved dial path.
    ///
    /// Arguments are cloned only when a client slot actually needs a new
    /// socket. Keeping them out of [`Self::new`] lets the outbound retain this
    /// transport (and its xmux state) before DNS candidates and a per-attempt
    /// connector are available.
    pub(crate) async fn open_stream(
        &self,
        dialer: &TransportDialer,
        connector: &ConnectorConfig,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, XhttpTransportError> {
        if self.http_version == XhttpHttpVersion::Http3 {
            let material = dialer
                .h3_dial_material(connector)
                .map_err(XhttpTransportError::Dial)?;
            let candidates = candidates.to_vec();
            let happy_eyeballs = happy_eyeballs.copied();
            let quic = self.h3_quic.clone();
            let dial: XhttpH3Dial = Arc::new(move || {
                let candidates = candidates.clone();
                let material = material.clone();
                let quic = quic.clone();
                Box::pin(async move {
                    let remote_addr = candidates
                        .first()
                        .copied()
                        .ok_or(H3Error::NoResolvedCandidate)?;
                    connect_h3_candidates(
                        H3ConnectConfig {
                            remote_addr,
                            server_name: material.server_name,
                            tls_config: material.tls_config,
                            socket_protector: material.socket_protector,
                            quic,
                        },
                        &candidates,
                        happy_eyeballs.as_ref(),
                    )
                    .await
                })
            });
            return self
                .open_stream_with_mode_dial(XhttpModeDial::Http3(dial))
                .await;
        }

        let dialer = dialer.clone();
        let connector = connector.clone();
        let original_target = original_target.clone();
        let candidates = candidates.to_vec();
        let happy_eyeballs = happy_eyeballs.copied();
        let alpn_policy = match self.http_version {
            XhttpHttpVersion::Http1 => TlsAlpnPolicy::Http1Upgrade,
            XhttpHttpVersion::Http2 => TlsAlpnPolicy::HttpClient,
            XhttpHttpVersion::Http3 => return Err(XhttpTransportError::MissingProtocolDial("UDP")),
        };
        let dial: XhttpDial = Arc::new(move || {
            let dialer = dialer.clone();
            let connector = connector.clone();
            let original_target = original_target.clone();
            let candidates = candidates.clone();
            Box::pin(async move {
                dialer
                    .connect_resolved_with_alpn_policy(
                        &connector,
                        &original_target,
                        &candidates,
                        happy_eyeballs.as_ref(),
                        alpn_policy,
                    )
                    .await
            })
        });
        self.open_stream_with_mode_dial(XhttpModeDial::Stream(dial))
            .await
    }

    #[doc(hidden)]
    pub async fn open_stream_with_dial(
        &self,
        dial: XhttpDial,
    ) -> Result<BoxedTransportStream, XhttpTransportError> {
        self.open_stream_with_mode_dial(XhttpModeDial::Stream(dial))
            .await
    }

    #[doc(hidden)]
    pub async fn open_stream_with_h3_dial(
        &self,
        dial: XhttpH3Dial,
    ) -> Result<BoxedTransportStream, XhttpTransportError> {
        self.open_stream_with_mode_dial(XhttpModeDial::Http3(dial))
            .await
    }

    async fn open_stream_with_mode_dial(
        &self,
        dial: XhttpModeDial,
    ) -> Result<BoxedTransportStream, XhttpTransportError> {
        let (client, usage) = self.xmux.select_client().await?;
        let selected = Arc::clone(&client);
        let result = match self.config.mode {
            XhttpMode::StreamOne => self.open_stream_one(client, usage, dial).await,
            XhttpMode::StreamUp => self.open_stream_up(client, usage, dial).await,
            XhttpMode::PacketUp => self.open_packet_up(client, usage, dial).await,
        };
        if result.is_err() {
            selected.mark_closed();
        }
        result
    }

    async fn open_stream_one(
        &self,
        client: Arc<XmuxClient>,
        usage: XmuxUsageLease,
        dial: XhttpModeDial,
    ) -> Result<BoxedTransportStream, XhttpTransportError> {
        client.consume_request();
        let prepared = self.compose_stream("", XhttpStreamBody::Streaming)?;
        let auto_gzip = prepared.auto_gzip;
        let failure = Arc::new(SharedFailure::new());
        let (uplink, opening, connection_activity) = match self.http_version {
            XhttpHttpVersion::Http1 => {
                let stream = dial_one(&dial.stream()?).await?;
                let head = h1_request(&prepared.request, &self.endpoint);
                let (upload, pending) = start_chunked_request(stream, &head).await?;
                let opening: OpenReadFuture = Box::pin(async move {
                    let response = pending.open().await?;
                    Ok(h1_response_reader(response, auto_gzip))
                });
                (Box::new(upload) as BoxedWrite, opening, Vec::new())
            }
            XhttpHttpVersion::Http2 => {
                let checkout = client.h2_client(dial.stream()?).await?;
                let request = h2_request(&prepared.request, &self.endpoint, None)?;
                let (upload, pending) = checkout.client.start_streaming(request).await?;
                let opening: OpenReadFuture = Box::pin(async move {
                    let response = pending.open().await?;
                    Ok(h2_response_reader(response, auto_gzip))
                });
                (
                    Box::new(upload) as BoxedWrite,
                    opening,
                    vec![checkout.activity],
                )
            }
            XhttpHttpVersion::Http3 => {
                let checkout = client.h3_client(dial.http3()?).await?;
                let request = h3_request(&prepared.request, &self.endpoint, None)?;
                let (upload, pending) = checkout.client.start_streaming(request).await?;
                let opening: OpenReadFuture = Box::pin(async move {
                    let response = pending.open().await?;
                    Ok(h3_response_reader(response, auto_gzip))
                });
                (
                    Box::new(upload) as BoxedWrite,
                    opening,
                    vec![checkout.activity],
                )
            }
        };
        let (downlink, opener) =
            spawn_deferred_reader(opening, Arc::clone(&failure), Arc::clone(&client));

        Ok(Box::new(XhttpLogicalStream::new(
            downlink,
            uplink,
            failure,
            vec![opener],
            connection_activity,
            usage,
        )))
    }

    async fn open_stream_up(
        &self,
        client: Arc<XmuxClient>,
        usage: XmuxUsageLease,
        dial: XhttpModeDial,
    ) -> Result<BoxedTransportStream, XhttpTransportError> {
        let session = self.new_session_id()?;
        let failure = Arc::new(SharedFailure::new());
        let (downlink, connection_activity, downlink_opener) = self
            .open_download(&client, &session, dial.clone(), Arc::clone(&failure))
            .await?;
        client.consume_request();
        let prepared = self.compose_stream(&session, XhttpStreamBody::Streaming)?;
        let auto_gzip = prepared.auto_gzip;

        let (uplink, monitor): (BoxedWrite, JoinHandle<()>) = match self.http_version {
            XhttpHttpVersion::Http1 => {
                let stream = dial_one(&dial.stream()?).await?;
                let head = h1_request(&prepared.request, &self.endpoint);
                let (upload, pending) = start_chunked_request(stream, &head).await?;
                let monitor_failure = Arc::clone(&failure);
                let monitor_client = Arc::clone(&client);
                let monitor = tokio::spawn(async move {
                    let result = async {
                        let response = pending.open().await?;
                        drain_h1_response(response, auto_gzip).await?;
                        Ok::<(), XhttpTransportError>(())
                    }
                    .await;
                    if let Err(error) = result {
                        if error.retires_client() {
                            monitor_client.mark_closed();
                        }
                        monitor_failure.record_error(&error);
                    }
                });
                (Box::new(upload), monitor)
            }
            XhttpHttpVersion::Http2 => {
                let monitor_client = Arc::clone(&client);
                let checkout = client.h2_client(dial.stream()?).await?;
                let request = h2_request(&prepared.request, &self.endpoint, None)?;
                let (upload, pending) = checkout.client.start_streaming(request).await?;
                let monitor_failure = Arc::clone(&failure);
                let monitor = tokio::spawn(async move {
                    let _activity = checkout.activity;
                    let result = async {
                        let response = pending.open().await?;
                        drain_h2_response(response, auto_gzip).await?;
                        Ok::<(), XhttpTransportError>(())
                    }
                    .await;
                    if let Err(error) = result {
                        if error.retires_client() {
                            monitor_client.mark_closed();
                        }
                        monitor_failure.record_error(&error);
                    }
                });
                (Box::new(upload), monitor)
            }
            XhttpHttpVersion::Http3 => {
                let monitor_client = Arc::clone(&client);
                let checkout = client.h3_client(dial.http3()?).await?;
                let request = h3_request(&prepared.request, &self.endpoint, None)?;
                let (upload, pending) = checkout.client.start_streaming(request).await?;
                let monitor_failure = Arc::clone(&failure);
                let monitor = tokio::spawn(async move {
                    let _activity = checkout.activity;
                    let result = async {
                        let response = pending.open().await?;
                        drain_h3_response(response, auto_gzip).await?;
                        Ok::<(), XhttpTransportError>(())
                    }
                    .await;
                    if let Err(error) = result {
                        if error.retires_client() {
                            monitor_client.mark_closed();
                        }
                        monitor_failure.record_error(&error);
                    }
                });
                (Box::new(upload), monitor)
            }
        };

        Ok(Box::new(XhttpLogicalStream::new(
            downlink,
            uplink,
            failure,
            vec![downlink_opener.into_handle(), monitor],
            connection_activity,
            usage,
        )))
    }

    async fn open_packet_up(
        &self,
        client: Arc<XmuxClient>,
        usage: XmuxUsageLease,
        dial: XhttpModeDial,
    ) -> Result<BoxedTransportStream, XhttpTransportError> {
        let session = self.new_session_id()?;
        let failure = Arc::new(SharedFailure::new());
        let (downlink, connection_activity, downlink_opener) = self
            .open_download(&client, &session, dial.clone(), Arc::clone(&failure))
            .await?;
        let max_packet = self.draw(self.config.max_each_post_bytes)?;
        let pipe_capacity = usize::try_from(max_packet)
            .map_err(|_| XhttpTransportError::PacketSizeTooLarge)?
            .max(1);
        let response_cap = usize::try_from(self.config.max_buffered_posts)
            .map_err(|_| XhttpTransportError::WorkerLimitTooLarge)?
            .clamp(PACKET_RESPONSE_CAP_FALLBACK, MAX_PACKET_RESPONSE_TASKS);
        let (uplink, worker_input) = tokio::io::duplex(pipe_capacity);
        let (uplink, first_uplink): (BoxedWrite, _) = match self.http_version {
            XhttpHttpVersion::Http1 => {
                let (first_uplink_tx, first_uplink_rx) = oneshot::channel();
                (
                    Box::new(FirstUplinkWriter::new(uplink, first_uplink_tx)),
                    Some(first_uplink_rx),
                )
            }
            XhttpHttpVersion::Http2 | XhttpHttpVersion::Http3 => (Box::new(uplink), None),
        };
        let worker_failure = Arc::clone(&failure);
        let response_failure = Arc::clone(&failure);
        let transport = self.clone();
        let worker = tokio::spawn(async move {
            if let Err(error) = transport
                .run_packet_worker(PacketWorkerContext {
                    input: worker_input,
                    first_uplink,
                    session,
                    max_packet,
                    response_cap,
                    upload_client: client,
                    dial,
                    failure: response_failure,
                })
                .await
            {
                worker_failure.record_error(&error);
            }
        });

        Ok(Box::new(XhttpLogicalStream::new(
            downlink,
            uplink,
            failure,
            vec![downlink_opener.into_handle(), worker],
            connection_activity,
            usage,
        )))
    }

    async fn open_download(
        &self,
        client: &Arc<XmuxClient>,
        session: &str,
        dial: XhttpModeDial,
        failure: Arc<SharedFailure>,
    ) -> Result<(BoxedRead, Vec<ConnectionActivityLease>, AbortTaskGuard), XhttpTransportError>
    {
        client.consume_request();
        let prepared = self.compose_stream(session, XhttpStreamBody::None)?;
        let auto_gzip = prepared.auto_gzip;
        let (opening, activity) = match self.http_version {
            XhttpHttpVersion::Http1 => {
                let stream = dial_one(&dial.stream()?).await?;
                let head = h1_request(&prepared.request, &self.endpoint);
                let pending = start_fixed_request(stream, &head, &[]).await?;
                let opening: OpenReadFuture = Box::pin(async move {
                    let response = pending.open().await?;
                    Ok(h1_response_reader(response, auto_gzip))
                });
                (opening, Vec::new())
            }
            XhttpHttpVersion::Http2 => {
                let checkout = client.h2_client(dial.stream()?).await?;
                let request = h2_request(&prepared.request, &self.endpoint, None)?;
                let pending = checkout.client.start_fixed(request, Bytes::new()).await?;
                let opening: OpenReadFuture = Box::pin(async move {
                    let response = pending.open().await?;
                    Ok(h2_response_reader(response, auto_gzip))
                });
                (opening, vec![checkout.activity])
            }
            XhttpHttpVersion::Http3 => {
                let checkout = client.h3_client(dial.http3()?).await?;
                let request = h3_request(&prepared.request, &self.endpoint, None)?;
                let pending = checkout.client.start_fixed(request, Bytes::new()).await?;
                let opening: OpenReadFuture = Box::pin(async move {
                    let response = pending.open().await?;
                    Ok(h3_response_reader(response, auto_gzip))
                });
                (opening, vec![checkout.activity])
            }
        };
        let (reader, opener) = spawn_deferred_reader(opening, failure, Arc::clone(client));
        Ok((reader, activity, AbortTaskGuard::new(opener)))
    }

    async fn run_packet_worker(
        &self,
        context: PacketWorkerContext,
    ) -> Result<(), XhttpTransportError> {
        let PacketWorkerContext {
            mut input,
            first_uplink,
            session,
            max_packet,
            response_cap,
            mut upload_client,
            dial,
            failure,
        } = context;
        if let Some(first_uplink) = first_uplink {
            match first_uplink.await {
                Ok(FirstUplink::Data) => {}
                Ok(FirstUplink::Closed) | Err(_) => return Ok(()),
            }
        }
        let max_packet =
            usize::try_from(max_packet).map_err(|_| XhttpTransportError::PacketSizeTooLarge)?;
        let mut buffer = match self.http_version {
            XhttpHttpVersion::Http1 => h1_packet_buffer(max_packet)?,
            XhttpHttpVersion::Http2 | XhttpHttpVersion::Http3 => fixed_packet_buffer(max_packet)?,
        };

        let mut sequence = 0_i64;
        let mut last_request = None;
        // The logical stream's main lease continues to cover its original
        // downlink client. Packet rotation can move the uplink to another
        // client, which needs an independent reservation until that uploader
        // rotates again or all of its response tasks have completed.
        let mut rotated_upload_usage = None;
        match self.http_version {
            XhttpHttpVersion::Http1 => loop {
                let read = read_h1_packet_input(&mut input, &mut buffer, max_packet).await?;
                if read == 0 {
                    return Ok(());
                }
                self.wait_packet_interval(&mut last_request).await?;
                self.rotate_packet_client_if_needed(&mut upload_client, &mut rotated_upload_usage)
                    .await?;
                let request = self.compose_packet(&session, &sequence.to_string(), buffer)?;
                sequence = sequence.wrapping_add(1);
                // The upstream H1 raw pool writes one request, then consumes
                // its response before that same connection can be checked out
                // again. Waiting here preserves that ordering and is what
                // makes returning a socket to our safe pool possible.
                let request = self
                    .send_h1_packet(&upload_client, dial.stream()?, request)
                    .await?;
                buffer = reclaim_packet_buffer(request, max_packet)?;
            },
            XhttpHttpVersion::Http2 | XhttpHttpVersion::Http3 => {
                // `scMaxBufferedPosts` is an inbound reassembly bound in Xray,
                // not an explicit client concurrency setting. Using it here
                // is a defensive cap on response monitors until normalized
                // xmux policy supplies the real client-side limit. Crucially,
                // the next request is released after its upload completes,
                // not after its response body drains.
                let mut responses = JoinSet::new();
                loop {
                    while responses.len() >= response_cap {
                        join_packet_response(&mut responses).await?;
                    }
                    while let Some(completed) = responses.try_join_next() {
                        packet_response_result(completed)?;
                    }

                    let read = read_packet_input(&mut input, &mut buffer, &mut responses).await?;
                    if read == 0 {
                        while !responses.is_empty() {
                            join_packet_response(&mut responses).await?;
                        }
                        return Ok(());
                    }

                    self.wait_packet_interval(&mut last_request).await?;
                    self.rotate_packet_client_if_needed(
                        &mut upload_client,
                        &mut rotated_upload_usage,
                    )
                    .await?;
                    let request = self.compose_packet(
                        &session,
                        &sequence.to_string(),
                        buffer[..read].to_vec(),
                    )?;
                    sequence = sequence.wrapping_add(1);
                    let (uploaded, uploaded_rx) = oneshot::channel();
                    let transport = self.clone();
                    let packet_client = Arc::clone(&upload_client);
                    let packet_dial = dial.clone();
                    let response_failure = Arc::clone(&failure);
                    responses.spawn(async move {
                        let result = transport
                            .send_multiplexed_packet(packet_client, packet_dial, request, uploaded)
                            .await;
                        // A completed POST can fail while the packet worker is
                        // blocked waiting for more uplink bytes. Publish that
                        // failure from the response task itself so a pending
                        // downlink read is woken immediately; the worker still
                        // joins the task to own cancellation and cleanup.
                        if let Err(error) = &result {
                            response_failure.record(error.clone());
                        }
                        result
                    });

                    match uploaded_rx.await {
                        Ok(Ok(())) => {}
                        Ok(Err(failure)) => {
                            responses.abort_all();
                            return Err(failure.into_transport_error());
                        }
                        Err(_) => {
                            let result = responses
                                .join_next()
                                .await
                                .ok_or(XhttpTransportError::UploadCompletionLost)?;
                            packet_response_result(result)?;
                            return Err(XhttpTransportError::UploadCompletionLost);
                        }
                    }
                }
            }
        }
    }

    async fn rotate_packet_client_if_needed(
        &self,
        client: &mut Arc<XmuxClient>,
        rotated_usage: &mut Option<XmuxUsageLease>,
    ) -> Result<(), XhttpTransportError> {
        let remaining = client.consume_request();
        if remaining <= 0 || client.is_expired((self.xmux.clock)()) {
            // Xray decrements the retiring client's budget before selecting a
            // replacement, and the request which triggers rotation does not
            // decrement the replacement. Preserve that slightly surprising
            // accounting so hMaxRequestTimes has the same observable cadence.
            let (replacement, usage) = self.xmux.select_client().await?;
            *client = replacement;
            *rotated_usage = Some(usage);
        }
        Ok(())
    }

    async fn wait_packet_interval(
        &self,
        last_request: &mut Option<Instant>,
    ) -> Result<(), XhttpTransportError> {
        // Upstream gates on the lower bound before drawing. A mixed `0-N`
        // range therefore disables pacing entirely; drawing and sleeping for
        // its positive outcomes would be a wire-timing divergence.
        if self.config.min_posts_interval_ms.from > 0 {
            let delay_ms = self.draw(self.config.min_posts_interval_ms)?;
            if let Some(last) = *last_request {
                let deadline = last + Duration::from_millis(u64::from(delay_ms));
                tokio::time::sleep_until(deadline).await;
            }
        }
        *last_request = Some(Instant::now());
        Ok(())
    }

    async fn send_h1_packet(
        &self,
        client: &Arc<XmuxClient>,
        dial: XhttpDial,
        prepared: PreparedRequest,
    ) -> Result<PreparedRequest, XhttpTransportError> {
        debug_assert!(!prepared.auto_gzip);
        let body = fixed_packet_body(&prepared.request)?;
        let mut retry_stale_pool_entry = true;
        loop {
            let pooled = client.h1_pool.take().await;
            let was_pooled = pooled.is_some();
            let stream = match pooled {
                Some(stream) => stream,
                None => dial_one(&dial).await?,
            };
            let head = h1_request(&prepared.request, &self.endpoint);
            let pending = match start_fixed_request(stream, &head, body).await {
                Ok(pending) => pending,
                Err(error)
                    if was_pooled
                        && retry_stale_pool_entry
                        && matches!(
                            &error,
                            H1Error::RequestWrite {
                                bytes_written: 0,
                                ..
                            }
                        ) =>
                {
                    retry_stale_pool_entry = false;
                    continue;
                }
                Err(error) => {
                    client.mark_closed();
                    return Err(error.into());
                }
            };
            // Once the complete request is on the wire, a response/status
            // failure is authoritative. Retrying here would duplicate a POST
            // which the server may already have accepted; only a stale pooled
            // socket rejected during request delivery gets the one retry
            // above.
            let response = pending.open().await.map_err(|error| {
                client.mark_closed();
                XhttpTransportError::Http1(error)
            })?;
            let reusable = reusable_h1_stream(response)
                .await
                .inspect_err(|_| client.mark_closed())?;
            if let Some(stream) = reusable {
                client.h1_pool.put(stream).await;
            }
            return Ok(prepared);
        }
    }

    async fn send_multiplexed_packet(
        &self,
        client: Arc<XmuxClient>,
        dial: XhttpModeDial,
        request: PreparedRequest,
        uploaded: oneshot::Sender<Result<(), StoredFailure>>,
    ) -> Result<(), StoredFailure> {
        match self.http_version {
            XhttpHttpVersion::Http2 => {
                let dial = dial
                    .stream()
                    .map_err(|error| StoredFailure::from_error(&error))?;
                self.send_h2_packet(client, dial, request, uploaded).await
            }
            XhttpHttpVersion::Http3 => {
                let dial = dial
                    .http3()
                    .map_err(|error| StoredFailure::from_error(&error))?;
                self.send_h3_packet(client, dial, request, uploaded).await
            }
            XhttpHttpVersion::Http1 => Err(StoredFailure::from_error(
                &XhttpTransportError::MissingProtocolDial("multiplexed HTTP"),
            )),
        }
    }

    async fn send_h2_packet(
        &self,
        client: Arc<XmuxClient>,
        dial: XhttpDial,
        request: PreparedRequest,
        uploaded: oneshot::Sender<Result<(), StoredFailure>>,
    ) -> Result<(), StoredFailure> {
        let result = self
            .send_h2_packet_inner(Arc::clone(&client), dial, request, uploaded)
            .await;
        if result
            .as_ref()
            .is_err_and(XhttpTransportError::retires_client)
        {
            client.mark_closed();
        }
        result.map_err(|error| StoredFailure::from_error(&error))
    }

    async fn send_h2_packet_inner(
        &self,
        client: Arc<XmuxClient>,
        dial: XhttpDial,
        prepared: PreparedRequest,
        uploaded: oneshot::Sender<Result<(), StoredFailure>>,
    ) -> Result<(), XhttpTransportError> {
        let body = Bytes::copy_from_slice(fixed_packet_body(&prepared.request)?);
        let auto_gzip = prepared.auto_gzip;
        let checkout = match client.h2_client(dial).await {
            Ok(checkout) => checkout,
            Err(error) => {
                let _ = uploaded.send(Err(StoredFailure::from_error(&error)));
                return Err(error);
            }
        };
        let request = match h2_request(&prepared.request, &self.endpoint, Some(body.len())) {
            Ok(request) => request,
            Err(error) => {
                let _ = uploaded.send(Err(StoredFailure::from_error(&error)));
                return Err(error);
            }
        };
        let (mut upload, pending) = match checkout.client.start_streaming(request).await {
            Ok(exchange) => exchange,
            Err(error) => {
                let error = XhttpTransportError::Http2(error);
                let _ = uploaded.send(Err(StoredFailure::from_error(&error)));
                return Err(error);
            }
        };

        let mut uploaded = Some(uploaded);
        let mut upload_future = Box::pin(async move {
            upload
                .write_all(&body)
                .await
                .map_err(XhttpTransportError::Io)?;
            upload.shutdown().await.map_err(XhttpTransportError::Io)
        });
        let mut response_future = Box::pin(pending.open());
        let mut response = None;

        loop {
            tokio::select! {
                upload_result = &mut upload_future => {
                    match upload_result {
                        Ok(()) => {
                            if let Some(sender) = uploaded.take() {
                                let _ = sender.send(Ok(()));
                            }
                            break;
                        }
                        Err(error) => {
                            if let Some(sender) = uploaded.take() {
                                let _ = sender.send(Err(StoredFailure::from_error(&error)));
                            }
                            return Err(error);
                        }
                    }
                }
                response_result = &mut response_future, if response.is_none() => {
                    match response_result {
                        Ok(body) => response = Some(body),
                        Err(error) => {
                            let error = XhttpTransportError::Http2(error);
                            if let Some(sender) = uploaded.take() {
                                let _ = sender.send(Err(StoredFailure::from_error(&error)));
                            }
                            return Err(error);
                        }
                    }
                }
            }
        }

        let response = match response {
            Some(response) => response,
            None => response_future.await?,
        };
        drain_h2_response(response, auto_gzip).await
    }

    async fn send_h3_packet(
        &self,
        client: Arc<XmuxClient>,
        dial: XhttpH3Dial,
        request: PreparedRequest,
        uploaded: oneshot::Sender<Result<(), StoredFailure>>,
    ) -> Result<(), StoredFailure> {
        let result = self
            .send_h3_packet_inner(Arc::clone(&client), dial, request, uploaded)
            .await;
        if result
            .as_ref()
            .is_err_and(XhttpTransportError::retires_client)
        {
            client.mark_closed();
        }
        result.map_err(|error| StoredFailure::from_error(&error))
    }

    async fn send_h3_packet_inner(
        &self,
        client: Arc<XmuxClient>,
        dial: XhttpH3Dial,
        prepared: PreparedRequest,
        uploaded: oneshot::Sender<Result<(), StoredFailure>>,
    ) -> Result<(), XhttpTransportError> {
        let body = Bytes::copy_from_slice(fixed_packet_body(&prepared.request)?);
        let auto_gzip = prepared.auto_gzip;
        let checkout = match client.h3_client(dial).await {
            Ok(checkout) => checkout,
            Err(error) => {
                let _ = uploaded.send(Err(StoredFailure::from_error(&error)));
                return Err(error);
            }
        };
        let request = match h3_request(&prepared.request, &self.endpoint, Some(body.len())) {
            Ok(request) => request,
            Err(error) => {
                let _ = uploaded.send(Err(StoredFailure::from_error(&error)));
                return Err(error);
            }
        };
        let (mut upload, pending) = match checkout.client.start_streaming(request).await {
            Ok(exchange) => exchange,
            Err(error) => {
                let error = XhttpTransportError::Http3(error);
                let _ = uploaded.send(Err(StoredFailure::from_error(&error)));
                return Err(error);
            }
        };

        let mut uploaded = Some(uploaded);
        let mut upload_future = Box::pin(async move {
            upload
                .write_all(&body)
                .await
                .map_err(XhttpTransportError::Io)?;
            upload.shutdown().await.map_err(XhttpTransportError::Io)
        });
        let mut response_future = Box::pin(pending.open());
        let mut response = None;

        loop {
            tokio::select! {
                upload_result = &mut upload_future => {
                    match upload_result {
                        Ok(()) => {
                            if let Some(sender) = uploaded.take() {
                                let _ = sender.send(Ok(()));
                            }
                            break;
                        }
                        Err(error) => {
                            if let Some(sender) = uploaded.take() {
                                let _ = sender.send(Err(StoredFailure::from_error(&error)));
                            }
                            return Err(error);
                        }
                    }
                }
                response_result = &mut response_future, if response.is_none() => {
                    match response_result {
                        Ok(body) => response = Some(body),
                        Err(error) => {
                            let error = XhttpTransportError::Http3(error);
                            if let Some(sender) = uploaded.take() {
                                let _ = sender.send(Err(StoredFailure::from_error(&error)));
                            }
                            return Err(error);
                        }
                    }
                }
            }
        }

        let response = match response {
            Some(response) => response,
            None => response_future.await?,
        };
        drain_h3_response(response, auto_gzip).await
    }

    fn compose_stream(
        &self,
        session: &str,
        body: XhttpStreamBody,
    ) -> Result<PreparedRequest, XhttpTransportError> {
        let mut rng = self.rng_guard()?;
        let mut request =
            compose_stream_request(&self.config, &self.endpoint, session, body, &mut **rng)?;
        if self.http_version == XhttpHttpVersion::Http1 {
            request.headers.set("Connection", "close");
        }
        let auto_gzip = prepare_auto_gzip(&mut request, true);
        Ok(PreparedRequest { request, auto_gzip })
    }

    fn compose_packet(
        &self,
        session: &str,
        sequence: &str,
        payload: Vec<u8>,
    ) -> Result<PreparedRequest, XhttpTransportError> {
        let mut rng = self.rng_guard()?;
        let mut request = compose_packet_request(
            &self.config,
            &self.endpoint,
            session,
            sequence,
            payload,
            &mut **rng,
        )?;
        // Xray's H1 packet uploader calls Request.Write directly, bypassing
        // net/http.Transport's compression policy. H2/H3 packet requests do
        // pass through their transports and therefore receive auto-gzip.
        let auto_gzip =
            prepare_auto_gzip(&mut request, self.http_version != XhttpHttpVersion::Http1);
        Ok(PreparedRequest { request, auto_gzip })
    }

    fn draw(&self, range: super::config::NormalizedRange) -> Result<u32, XhttpTransportError> {
        let mut rng = self.rng_guard()?;
        draw_range(range, &mut **rng)
            .map_err(XhttpRequestError::from)
            .map_err(XhttpTransportError::from)
    }

    fn new_session_id(&self) -> Result<String, XhttpTransportError> {
        generate_session_id(&self.config.session_id, &mut **self.rng_guard()?)
            .map_err(XhttpTransportError::from)
    }

    fn rng_guard(&self) -> Result<StdMutexGuard<'_, Box<dyn RngCore + Send>>, XhttpTransportError> {
        self.rng
            .lock()
            .map_err(|_| XhttpTransportError::RandomStatePoisoned)
    }
}

async fn dial_one(dial: &XhttpDial) -> Result<BoxedTransportStream, XhttpTransportError> {
    dial().await.map_err(XhttpTransportError::Dial)
}

fn prepare_auto_gzip(request: &mut XhttpRequest, enabled: bool) -> bool {
    if !enabled
        || request.method == "HEAD"
        || header_value_ci(&request.headers, "Accept-Encoding")
            .is_some_and(|value| !value.is_empty())
        || header_value_ci(&request.headers, "Range").is_some_and(|value| !value.is_empty())
    {
        return false;
    }

    // An explicit empty Accept-Encoding has the same `Header.Get == ""`
    // result as an absent field in Go, so Transport replaces it with gzip.
    set_header_ci(&mut request.headers, "Accept-Encoding", "gzip");
    true
}

fn header_value_ci<'a>(headers: &'a XhttpHeaderMap, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn set_header_ci(headers: &mut XhttpHeaderMap, name: &str, value: &str) {
    let mut rebuilt = XhttpHeaderMap::new();
    let mut replaced = false;
    for (candidate, candidate_value) in headers.iter() {
        if candidate.eq_ignore_ascii_case(name) {
            if !replaced {
                rebuilt.set(name, value);
                replaced = true;
            }
        } else {
            rebuilt.add(candidate, candidate_value);
        }
    }
    if !replaced {
        rebuilt.set(name, value);
    }
    *headers = rebuilt;
}

fn spawn_deferred_reader(
    opening: OpenReadFuture,
    failure: Arc<SharedFailure>,
    client: Arc<XmuxClient>,
) -> (BoxedRead, JoinHandle<()>) {
    let (opened, receiver) = oneshot::channel::<Result<BoxedRead, StoredFailure>>();
    let opener = tokio::spawn(async move {
        let result = match opening.await {
            Ok(reader) => Ok(reader),
            Err(error) => {
                let stored = StoredFailure::from_error(&error);
                client.mark_closed();
                failure.record(stored.clone());
                Err(stored)
            }
        };
        let _ = opened.send(result);
    });
    let receiving: OpenReadFuture = Box::pin(async move {
        match receiver.await {
            Ok(Ok(reader)) => Ok(reader),
            Ok(Err(failure)) => Err(failure.into_transport_error()),
            Err(_) => Err(XhttpTransportError::BackgroundTask(
                "deferred XHTTP response opener stopped".to_owned(),
            )),
        }
    });
    (Box::new(DeferredReader::new(receiving)), opener)
}

fn fixed_packet_body(request: &XhttpRequest) -> Result<&[u8], XhttpTransportError> {
    match &request.body {
        XhttpRequestBody::None => Ok(&[]),
        XhttpRequestBody::Bytes(body) => Ok(body),
        XhttpRequestBody::Streaming => Err(XhttpTransportError::BackgroundTask(
            "packet composer returned a streaming body".to_owned(),
        )),
    }
}

fn h1_packet_buffer(max_packet: usize) -> Result<Vec<u8>, XhttpTransportError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(max_packet.min(H1_PACKET_READ_CHUNK_BYTES))
        .map_err(|error| XhttpTransportError::BackgroundTask(error.to_string()))?;
    Ok(buffer)
}

fn fixed_packet_buffer(max_packet: usize) -> Result<Vec<u8>, XhttpTransportError> {
    resize_fixed_packet_buffer(Vec::new(), max_packet)
}

fn reclaim_packet_buffer(
    prepared: PreparedRequest,
    max_packet: usize,
) -> Result<Vec<u8>, XhttpTransportError> {
    let buffer = match prepared.request.body {
        XhttpRequestBody::Bytes(body) => body,
        XhttpRequestBody::None | XhttpRequestBody::Streaming => Vec::new(),
    };
    if buffer.capacity() > max_packet {
        return h1_packet_buffer(max_packet);
    }
    let mut buffer = buffer;
    buffer.clear();
    Ok(buffer)
}

fn resize_fixed_packet_buffer(
    mut buffer: Vec<u8>,
    max_packet: usize,
) -> Result<Vec<u8>, XhttpTransportError> {
    if buffer.capacity() < max_packet {
        buffer
            .try_reserve_exact(max_packet.saturating_sub(buffer.len()))
            .map_err(|error| XhttpTransportError::BackgroundTask(error.to_string()))?;
    }
    buffer.resize(max_packet, 0);
    Ok(buffer)
}

/// Drains the bytes currently available from the packet pipe into one H1
/// request, up to the configured ceiling. The vector grows in the same 8 KiB
/// units used by Xray's pooled MultiBuffer implementation, so an idle flow
/// that has sent only its small VLESS header does not pin 500 KiB merely
/// because `scMaxEachPostBytes` allows a future request that large.
async fn read_h1_packet_input(
    input: &mut tokio::io::DuplexStream,
    buffer: &mut Vec<u8>,
    max_packet: usize,
) -> Result<usize, XhttpTransportError> {
    buffer.clear();
    poll_fn(|cx| loop {
        if buffer.len() == max_packet {
            return Poll::Ready(Ok(buffer.len()));
        }

        let filled = buffer.len();
        let next = filled
            .saturating_add(H1_PACKET_READ_CHUNK_BYTES)
            .min(max_packet);
        if buffer.capacity() < next {
            if let Err(error) = buffer.try_reserve_exact(next - buffer.len()) {
                return Poll::Ready(Err(XhttpTransportError::BackgroundTask(error.to_string())));
            }
        }
        buffer.resize(next, 0);

        let mut read_buf = ReadBuf::new(&mut buffer[filled..next]);
        match Pin::new(&mut *input).poll_read(cx, &mut read_buf) {
            Poll::Pending => {
                buffer.truncate(filled);
                if filled == 0 {
                    return Poll::Pending;
                }
                return Poll::Ready(Ok(filled));
            }
            Poll::Ready(Err(error)) => {
                buffer.truncate(filled);
                return Poll::Ready(Err(XhttpTransportError::Io(error)));
            }
            Poll::Ready(Ok(())) => {
                let read = read_buf.filled().len();
                buffer.truncate(filled + read);
                if read == 0 {
                    return Poll::Ready(Ok(buffer.len()));
                }
            }
        }
    })
    .await
}

fn gzip_response_reader<R>(reader: R) -> BoxedRead
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let mut decoder = GzipDecoder::new(BufReader::new(ResponseBodyReader(reader)));
    // Go's compress/gzip reader transparently concatenates gzip members.
    decoder.multiple_members(true);
    Box::new(GzipResponseReader { decoder })
}

/// Marks transport-body errors before they enter the gzip decoder, allowing
/// the outer adapter to distinguish a connection/stream failure from a gzip
/// format failure. Only the latter is request-local and must not retire the
/// multiplexed xmux client.
struct ResponseBodyReader<R>(R);

impl<R> AsyncRead for ResponseBodyReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.0).poll_read(cx, output) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::new(
                error.kind(),
                ResponseBodyIoError(error),
            ))),
            result => result,
        }
    }
}

struct GzipResponseReader<R> {
    decoder: GzipDecoder<BufReader<ResponseBodyReader<R>>>,
}

impl<R> AsyncRead for GzipResponseReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.decoder).poll_read(cx, output) {
            Poll::Ready(Err(error))
                if error
                    .get_ref()
                    .is_some_and(|source| source.is::<ResponseBodyIoError>()) =>
            {
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(error)) => {
                Poll::Ready(Err(io::Error::new(error.kind(), GzipDecodeError(error))))
            }
            result => result,
        }
    }
}

#[derive(Debug)]
struct ResponseBodyIoError(io::Error);

impl fmt::Display for ResponseBodyIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ResponseBodyIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0)
    }
}

#[derive(Debug)]
struct GzipDecodeError(io::Error);

impl fmt::Display for GzipDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gzip response decode failed: {}", self.0)
    }
}

impl std::error::Error for GzipDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn is_gzip_decode_error(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|source| {
        source.is::<GzipDecodeError>() || source.is::<StoredGzipDecodeError>()
    })
}

#[derive(Debug)]
struct StoredGzipDecodeError(Arc<str>);

impl fmt::Display for StoredGzipDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for StoredGzipDecodeError {}

fn h1_response_reader<R>(response: H1ResponseBody<R>, auto_gzip: bool) -> BoxedRead
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let decode = auto_gzip
        && response
            .content_encoding()
            .is_some_and(|value| value.eq_ignore_ascii_case(b"gzip"));
    if decode {
        gzip_response_reader(response)
    } else {
        Box::new(response)
    }
}

fn h2_response_reader(response: H2ResponseBody, auto_gzip: bool) -> BoxedRead {
    let decode = auto_gzip
        && response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"));
    if decode {
        gzip_response_reader(response)
    } else {
        Box::new(response)
    }
}

fn h3_response_reader(response: H3ResponseBody, auto_gzip: bool) -> BoxedRead {
    let decode = auto_gzip
        && response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes() == b"gzip");
    if decode {
        gzip_response_reader(response)
    } else {
        Box::new(response)
    }
}

fn h1_request<'a>(request: &'a XhttpRequest, endpoint: &'a XhttpEndpoint) -> H1Request<'a> {
    H1Request {
        method: &request.method,
        target: &request.target,
        host: &endpoint.authority,
        headers: &request.headers,
    }
}

fn h2_request(
    request: &XhttpRequest,
    endpoint: &XhttpEndpoint,
    content_length: Option<usize>,
) -> Result<Request<()>, XhttpTransportError> {
    multiplexed_request(
        request,
        endpoint,
        content_length,
        Version::HTTP_2,
        "Go-http-client/2.0",
    )
    .map_err(XhttpTransportError::InvalidHttp2Request)
}

fn h3_request(
    request: &XhttpRequest,
    endpoint: &XhttpEndpoint,
    content_length: Option<usize>,
) -> Result<Request<()>, XhttpTransportError> {
    multiplexed_request(
        request,
        endpoint,
        content_length,
        Version::HTTP_3,
        "quic-go HTTP/3",
    )
    .map_err(XhttpTransportError::InvalidHttp3Request)
}

fn multiplexed_request(
    request: &XhttpRequest,
    endpoint: &XhttpEndpoint,
    content_length: Option<usize>,
    version: Version,
    default_user_agent: &'static str,
) -> Result<Request<()>, String> {
    let method =
        Method::from_bytes(request.method.as_bytes()).map_err(|error| error.to_string())?;
    let uri = format!(
        "{}://{}{}",
        endpoint.scheme.as_str(),
        endpoint.authority,
        request.target
    );
    let mut output = Request::builder()
        .version(version)
        .method(method.clone())
        .uri(uri)
        .body(())
        .map_err(|error| error.to_string())?;

    let mut saw_user_agent = false;
    for (name, value) in request.headers.iter() {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("upgrade")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("user-agent") {
            if saw_user_agent {
                continue;
            }
            saw_user_agent = true;
            if value.is_empty() {
                continue;
            }
        }
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| error.to_string())?;
        if name == header::COOKIE {
            for cookie in split_cookie_header(value) {
                let value = HeaderValue::from_bytes(cookie.as_bytes())
                    .map_err(|error| error.to_string())?;
                output.headers_mut().append(header::COOKIE, value);
            }
        } else {
            let value =
                HeaderValue::from_bytes(value.as_bytes()).map_err(|error| error.to_string())?;
            output.headers_mut().append(name, value);
        }
    }
    if !saw_user_agent {
        output.headers_mut().insert(
            header::USER_AGENT,
            HeaderValue::from_static(default_user_agent),
        );
    }
    if let Some(content_length) =
        content_length.filter(|length| should_send_content_length(&method, *length))
    {
        let value = HeaderValue::from_bytes(content_length.to_string().as_bytes())
            .map_err(|error| error.to_string())?;
        output.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
    Ok(output)
}

fn should_send_content_length(method: &Method, content_length: usize) -> bool {
    content_length > 0 || matches!(method.as_str(), "POST" | "PUT" | "PATCH")
}

fn split_cookie_header(mut value: &str) -> Vec<&str> {
    let mut cookies = Vec::new();
    while let Some(index) = value.find(';') {
        cookies.push(&value[..index]);
        value = value[index + 1..].trim_start_matches(' ');
    }
    if !value.is_empty() {
        cookies.push(value);
    }
    cookies
}

async fn drain_h1_response<R>(
    response: H1ResponseBody<R>,
    auto_gzip: bool,
) -> Result<(), XhttpTransportError>
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let mut response = h1_response_reader(response, auto_gzip);
    tokio::io::copy(&mut response, &mut tokio::io::sink())
        .await
        .map_err(XhttpTransportError::Io)?;
    Ok(())
}

async fn reusable_h1_stream(
    mut response: H1ResponseBody<BoxedTransportStream>,
) -> Result<Option<BoxedTransportStream>, XhttpTransportError> {
    tokio::io::copy(&mut response, &mut tokio::io::sink())
        .await
        .map_err(XhttpTransportError::Io)?;
    match response.into_reusable() {
        Ok((stream, overread)) if overread.is_empty() => Ok(Some(stream)),
        Ok(_) | Err(_) => Ok(None),
    }
}

async fn drain_h2_response(
    response: H2ResponseBody,
    auto_gzip: bool,
) -> Result<(), XhttpTransportError> {
    let mut response = h2_response_reader(response, auto_gzip);
    tokio::io::copy(&mut response, &mut tokio::io::sink())
        .await
        .map_err(XhttpTransportError::Io)?;
    Ok(())
}

async fn drain_h3_response(
    response: H3ResponseBody,
    auto_gzip: bool,
) -> Result<(), XhttpTransportError> {
    let mut response = h3_response_reader(response, auto_gzip);
    tokio::io::copy(&mut response, &mut tokio::io::sink())
        .await
        .map_err(XhttpTransportError::Io)?;
    Ok(())
}

async fn join_packet_response(
    responses: &mut JoinSet<Result<(), StoredFailure>>,
) -> Result<(), XhttpTransportError> {
    let result = responses.join_next().await.ok_or_else(|| {
        XhttpTransportError::BackgroundTask("packet response set is empty".into())
    })?;
    packet_response_result(result)
}

async fn read_packet_input(
    input: &mut tokio::io::DuplexStream,
    buffer: &mut [u8],
    responses: &mut JoinSet<Result<(), StoredFailure>>,
) -> Result<usize, XhttpTransportError> {
    loop {
        if responses.is_empty() {
            return input.read(buffer).await.map_err(XhttpTransportError::Io);
        }
        tokio::select! {
            response = responses.join_next() => {
                let response = response.ok_or_else(|| {
                    XhttpTransportError::BackgroundTask(
                        "packet response set became empty while awaiting completion".to_owned(),
                    )
                })?;
                packet_response_result(response)?;
            }
            read = input.read(buffer) => {
                return read.map_err(XhttpTransportError::Io);
            }
        }
    }
}

fn packet_response_result(
    result: Result<Result<(), StoredFailure>, tokio::task::JoinError>,
) -> Result<(), XhttpTransportError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(failure)) => Err(failure.into_transport_error()),
        Err(error) => Err(XhttpTransportError::BackgroundTask(error.to_string())),
    }
}

#[derive(Clone, Debug)]
struct StoredFailure {
    kind: io::ErrorKind,
    message: Arc<str>,
    retires_client: bool,
}

impl StoredFailure {
    fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        let retires_client = if let Some(error) = error.downcast_ref::<XhttpTransportError>() {
            error.retires_client()
        } else if let Some(error) = error.downcast_ref::<io::Error>() {
            !is_gzip_decode_error(error)
        } else {
            true
        };
        Self {
            kind: io::ErrorKind::ConnectionReset,
            message: Arc::from(error.to_string()),
            retires_client,
        }
    }

    fn from_io(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: Arc::from(error.to_string()),
            retires_client: !is_gzip_decode_error(error),
        }
    }

    fn to_io_error(&self) -> io::Error {
        if self.retires_client {
            io::Error::new(self.kind, self.message.to_string())
        } else {
            io::Error::new(self.kind, StoredGzipDecodeError(Arc::clone(&self.message)))
        }
    }

    fn into_transport_error(self) -> XhttpTransportError {
        XhttpTransportError::Io(self.to_io_error())
    }
}

struct SharedFailure {
    failure: StdMutex<Option<StoredFailure>>,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl SharedFailure {
    fn new() -> Self {
        Self {
            failure: StdMutex::new(None),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        }
    }

    fn record_error(&self, error: &(dyn std::error::Error + 'static)) {
        self.record(StoredFailure::from_error(error));
    }

    fn record_io(&self, error: &io::Error) {
        self.record(StoredFailure::from_io(error));
    }

    fn record(&self, failure: StoredFailure) {
        let mut stored = lock_unpoisoned(&self.failure);
        if stored.is_none() {
            *stored = Some(failure);
        }
        drop(stored);
        self.read_waker.wake();
        self.write_waker.wake();
    }

    fn read_error(&self, cx: &mut Context<'_>) -> Option<(io::Error, bool)> {
        self.error_after_register(cx, &self.read_waker)
    }

    fn write_error(&self, cx: &mut Context<'_>) -> Option<(io::Error, bool)> {
        self.error_after_register(cx, &self.write_waker)
    }

    fn error_after_register(
        &self,
        cx: &mut Context<'_>,
        waker: &AtomicWaker,
    ) -> Option<(io::Error, bool)> {
        if let Some(error) = lock_unpoisoned(&self.failure).as_ref() {
            return Some((error.to_io_error(), error.retires_client));
        }
        waker.register(cx.waker());
        lock_unpoisoned(&self.failure)
            .as_ref()
            .map(|error| (error.to_io_error(), error.retires_client))
    }
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> StdMutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct XhttpLogicalStream {
    downlink: BoxedRead,
    uplink: BoxedWrite,
    failure: Arc<SharedFailure>,
    background: Vec<JoinHandle<()>>,
    _connection_activity: Vec<ConnectionActivityLease>,
    _usage: XmuxUsageLease,
}

struct AbortTaskGuard {
    task: Option<JoinHandle<()>>,
}

impl AbortTaskGuard {
    fn new(task: JoinHandle<()>) -> Self {
        Self { task: Some(task) }
    }

    fn into_handle(mut self) -> JoinHandle<()> {
        self.task
            .take()
            .expect("an XHTTP task guard is consumed only once")
    }
}

impl Drop for AbortTaskGuard {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl XhttpLogicalStream {
    fn new(
        downlink: BoxedRead,
        uplink: BoxedWrite,
        failure: Arc<SharedFailure>,
        background: Vec<JoinHandle<()>>,
        connection_activity: Vec<ConnectionActivityLease>,
        usage: XmuxUsageLease,
    ) -> Self {
        Self {
            downlink,
            uplink,
            failure,
            background,
            _connection_activity: connection_activity,
            _usage: usage,
        }
    }
}

impl Drop for XhttpLogicalStream {
    fn drop(&mut self) {
        for task in &self.background {
            task.abort();
        }
    }
}

impl AsyncRead for XhttpLogicalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some((error, retires_client)) = this.failure.read_error(cx) {
            if retires_client {
                this._usage.client.mark_closed();
            }
            return Poll::Ready(Err(error));
        }
        // A chunk encoder can fail after `poll_write` accepted bytes. Polling
        // flush with the downlink's waker links that asynchronous uploader
        // failure to a reader which may otherwise sleep forever waiting for
        // the server. Pending does not gate the response read; it only
        // registers this same task to be woken when delivery or failure moves.
        if let Poll::Ready(Err(error)) = Pin::new(&mut this.uplink).poll_flush(cx) {
            this._usage.client.mark_closed();
            this.failure.record_io(&error);
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.downlink).poll_read(cx, output) {
            Poll::Ready(Err(error)) => {
                if !is_gzip_decode_error(&error) {
                    this._usage.client.mark_closed();
                }
                this.failure.record_io(&error);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }
}

impl AsyncWrite for XhttpLogicalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some((error, retires_client)) = this.failure.write_error(cx) {
            if retires_client {
                this._usage.client.mark_closed();
            }
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.uplink).poll_write(cx, input) {
            Poll::Ready(Err(error)) => {
                this._usage.client.mark_closed();
                this.failure.record_io(&error);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some((error, retires_client)) = this.failure.write_error(cx) {
            if retires_client {
                this._usage.client.mark_closed();
            }
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.uplink).poll_flush(cx) {
            Poll::Ready(Err(error)) => {
                this._usage.client.mark_closed();
                this.failure.record_io(&error);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some((error, retires_client)) = this.failure.write_error(cx) {
            if retires_client {
                this._usage.client.mark_closed();
            }
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.uplink).poll_shutdown(cx) {
            Poll::Ready(Err(error)) => {
                this._usage.client.mark_closed();
                this.failure.record_io(&error);
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }
}

impl TransportStream for XhttpLogicalStream {
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

enum DeferredReaderState {
    Opening(OpenReadFuture),
    Reading(BoxedRead),
    Failed(StoredFailure),
}

struct DeferredReader {
    state: DeferredReaderState,
}

impl DeferredReader {
    fn new(opening: OpenReadFuture) -> Self {
        Self {
            state: DeferredReaderState::Opening(opening),
        }
    }
}

impl AsyncRead for DeferredReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                DeferredReaderState::Opening(opening) => match opening.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(reader)) => {
                        this.state = DeferredReaderState::Reading(reader);
                    }
                    Poll::Ready(Err(error)) => {
                        let failure = StoredFailure::from_error(&error);
                        let io_error = failure.to_io_error();
                        this.state = DeferredReaderState::Failed(failure);
                        return Poll::Ready(Err(io_error));
                    }
                },
                DeferredReaderState::Reading(reader) => {
                    return Pin::new(reader).poll_read(cx, output);
                }
                DeferredReaderState::Failed(failure) => {
                    return Poll::Ready(Err(failure.to_io_error()));
                }
            }
        }
    }
}

/// One selection domain matching Xray's `XmuxManager`.
///
/// Manager-level max concurrency/connections are sampled exactly once. The
/// other three ranges are sampled for every new client slot. A slot owns its
/// HTTP/2 connection pool and HTTP/1.1 raw upload pool; moving either pool to
/// the transport would collapse distinct XMUX client slots into one shared
/// pool, bypassing limits such as the v26.7.28 default `maxConnections == 3`.
struct XmuxManager {
    policy: XhttpXmuxPolicy,
    concurrency: i32,
    connections: i32,
    h1_idle_limit: usize,
    h2_keep_alive_period: Option<Duration>,
    h2_idle_timeout: Duration,
    rng: Arc<StdMutex<Box<dyn RngCore + Send>>>,
    clock: XhttpClock,
    clients: AsyncMutex<Vec<Arc<XmuxClient>>>,
}

impl XmuxManager {
    fn new(
        policy: XhttpXmuxPolicy,
        h1_idle_limit: usize,
        rng: Arc<StdMutex<Box<dyn RngCore + Send>>>,
        clock: XhttpClock,
        h2_idle_timeout: Duration,
    ) -> Result<Self, XhttpTransportError> {
        for range in [
            policy.max_concurrency,
            policy.max_connections,
            policy.c_max_reuse_times,
            policy.h_max_request_times,
            policy.h_max_reusable_secs,
        ] {
            if range.from > range.to {
                return Err(XhttpTransportError::DescendingXmuxRange);
            }
        }
        if policy.max_connections.to > 0 && policy.max_concurrency.to > 0 {
            return Err(XhttpTransportError::ConflictingXmuxConnectionLimits);
        }
        let (concurrency, connections) = {
            let mut rng = rng
                .lock()
                .map_err(|_| XhttpTransportError::RandomStatePoisoned)?;
            (
                draw_xmux_range(policy.max_concurrency, &mut **rng)?,
                draw_xmux_range(policy.max_connections, &mut **rng)?,
            )
        };
        let h2_keep_alive_period = match policy.h_keep_alive_period_secs {
            value if value < 0 => None,
            0 => Some(Duration::from_secs(45)),
            value => Some(Duration::from_secs(value as u64)),
        };
        Ok(Self {
            policy,
            concurrency,
            connections,
            h1_idle_limit,
            h2_keep_alive_period,
            h2_idle_timeout,
            rng,
            clock,
            clients: AsyncMutex::new(Vec::new()),
        })
    }

    async fn select_client(
        &self,
    ) -> Result<(Arc<XmuxClient>, XmuxUsageLease), XhttpTransportError> {
        let now = (self.clock)();
        let mut clients = self.clients.lock().await;
        clients.retain(|client| client.is_reusable(now));

        if clients.is_empty() || (self.connections > 0 && clients.len() < self.connections as usize)
        {
            let client = self.new_client(&mut clients, now)?;
            let usage = XmuxUsageLease::new(Arc::clone(&client));
            drop(clients);
            return Ok((client, usage));
        }

        let eligible: Vec<usize> = if self.concurrency > 0 {
            clients
                .iter()
                .enumerate()
                .filter_map(|(index, client)| {
                    (client.open_usage.load(Ordering::Acquire) < self.concurrency).then_some(index)
                })
                .collect()
        } else {
            (0..clients.len()).collect()
        };
        if eligible.is_empty() {
            let client = self.new_client(&mut clients, now)?;
            let usage = XmuxUsageLease::new(Arc::clone(&client));
            drop(clients);
            return Ok((client, usage));
        }

        let selected = if eligible.len() == 1 {
            eligible[0]
        } else {
            let mut rng = self
                .rng
                .lock()
                .map_err(|_| XhttpTransportError::RandomStatePoisoned)?;
            let offset = draw_index(eligible.len(), &mut **rng)?;
            eligible[offset]
        };
        let client = Arc::clone(&clients[selected]);
        let left_usage = client.left_usage.load(Ordering::Acquire);
        if left_usage > 0 {
            client.left_usage.fetch_sub(1, Ordering::AcqRel);
        }
        let usage = XmuxUsageLease::new(Arc::clone(&client));
        drop(clients);
        Ok((client, usage))
    }

    fn new_client(
        &self,
        clients: &mut Vec<Arc<XmuxClient>>,
        now: Instant,
    ) -> Result<Arc<XmuxClient>, XhttpTransportError> {
        let (reuse_times, request_times, reusable_secs) = {
            let mut rng = self
                .rng
                .lock()
                .map_err(|_| XhttpTransportError::RandomStatePoisoned)?;
            (
                draw_xmux_range(self.policy.c_max_reuse_times, &mut **rng)?,
                draw_xmux_range(self.policy.h_max_request_times, &mut **rng)?,
                draw_xmux_range(self.policy.h_max_reusable_secs, &mut **rng)?,
            )
        };
        let left_usage = if reuse_times > 0 { reuse_times - 1 } else { -1 };
        let left_requests = if request_times > 0 {
            request_times
        } else {
            i32::MAX
        };
        let unreusable_at = if reusable_secs > 0 {
            Some(
                now.checked_add(Duration::from_secs(reusable_secs as u64))
                    .ok_or(XhttpTransportError::XmuxReusableDeadlineOverflow)?,
            )
        } else {
            None
        };
        let client = Arc::new(XmuxClient {
            h1_pool: H1Pool::new(self.h1_idle_limit),
            h2_pool: H2Pool::new(
                self.h2_keep_alive_period,
                Arc::clone(&self.clock),
                self.h2_idle_timeout,
            ),
            h3_pool: H3Pool::new(Arc::clone(&self.clock), self.h2_idle_timeout),
            open_usage: AtomicI32::new(0),
            left_usage: AtomicI32::new(left_usage),
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
            closed: AtomicBool::new(false),
        });
        clients.push(Arc::clone(&client));
        Ok(client)
    }
}

struct XmuxClient {
    h1_pool: H1Pool,
    h2_pool: H2Pool,
    h3_pool: H3Pool,
    open_usage: AtomicI32,
    left_usage: AtomicI32,
    left_requests: AtomicI32,
    unreusable_at: Option<Instant>,
    closed: AtomicBool,
}

impl XmuxClient {
    fn is_expired(&self, now: Instant) -> bool {
        self.unreusable_at.is_some_and(|deadline| now > deadline)
    }

    fn is_reusable(&self, now: Instant) -> bool {
        !self.closed.load(Ordering::Acquire)
            && self.left_usage.load(Ordering::Acquire) != 0
            && self.left_requests.load(Ordering::Acquire) > 0
            && !self.is_expired(now)
    }

    fn consume_request(&self) -> i32 {
        self.left_requests
            .fetch_sub(1, Ordering::AcqRel)
            .wrapping_sub(1)
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }

    async fn h2_client(&self, dial: XhttpDial) -> Result<H2Checkout, XhttpTransportError> {
        self.h2_pool.client(dial).await
    }

    async fn h3_client(&self, dial: XhttpH3Dial) -> Result<H3Checkout, XhttpTransportError> {
        self.h3_pool.client(dial).await
    }
}

struct XmuxUsageLease {
    client: Arc<XmuxClient>,
}

impl XmuxUsageLease {
    fn new(client: Arc<XmuxClient>) -> Self {
        client.open_usage.fetch_add(1, Ordering::AcqRel);
        Self { client }
    }
}

impl Drop for XmuxUsageLease {
    fn drop(&mut self) {
        self.client.open_usage.fetch_sub(1, Ordering::AcqRel);
    }
}

fn draw_xmux_range<R: RngCore + ?Sized>(
    range: XhttpRange,
    rng: &mut R,
) -> Result<i32, XhttpTransportError> {
    if range.from > range.to {
        return Err(XhttpTransportError::DescendingXmuxRange);
    }
    if range.from == range.to {
        return Ok(range.from);
    }
    let span = (i64::from(range.to) - i64::from(range.from)) as u64;
    let offset = draw_below(span, rng)?;
    Ok((i64::from(range.from) + offset as i64) as i32)
}

fn draw_index<R: RngCore + ?Sized>(
    candidates: usize,
    rng: &mut R,
) -> Result<usize, XhttpTransportError> {
    let candidates =
        u64::try_from(candidates).map_err(|_| XhttpTransportError::XmuxCandidateCountTooLarge)?;
    let selected = draw_below(candidates, rng)?;
    usize::try_from(selected).map_err(|_| XhttpTransportError::XmuxCandidateCountTooLarge)
}

fn draw_below<R: RngCore + ?Sized>(upper: u64, rng: &mut R) -> Result<u64, XhttpTransportError> {
    debug_assert!(upper > 0);
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let mut bytes = [0_u8; 8];
        rng.try_fill_bytes(&mut bytes)
            .map_err(XhttpTransportError::Random)?;
        let sample = u64::from_le_bytes(bytes);
        if sample >= threshold {
            return Ok(sample % upper);
        }
    }
}

struct H1Pool {
    idle: AsyncMutex<Vec<BoxedTransportStream>>,
    max_idle: usize,
}

impl H1Pool {
    fn new(max_idle: usize) -> Self {
        Self {
            idle: AsyncMutex::new(Vec::new()),
            max_idle,
        }
    }

    async fn take(&self) -> Option<BoxedTransportStream> {
        self.idle.lock().await.pop()
    }

    async fn put(&self, stream: BoxedTransportStream) {
        let mut idle = self.idle.lock().await;
        if idle.len() < self.max_idle {
            idle.push(stream);
        }
    }
}

struct H2Pool {
    state: Arc<AsyncMutex<H2PoolState>>,
    /// Propagated xmux read-idle/PING policy for every connection opened by
    /// this client slot.
    keep_alive_period: Option<Duration>,
    clock: XhttpClock,
    idle_timeout: Duration,
}

#[derive(Default)]
struct H2PoolState {
    connections: Vec<H2PoolConnection>,
    dialing: Option<Arc<H2DialAttempt>>,
}

struct H2PoolConnection {
    client: H2Client,
    lifecycle: Arc<ConnectionLifecycle>,
    fresh: bool,
}

struct H2Checkout {
    client: H2Client,
    activity: ConnectionActivityLease,
}

struct ConnectionLifecycle {
    active: AtomicUsize,
    last_idle: StdMutex<Instant>,
    clock: XhttpClock,
}

impl ConnectionLifecycle {
    fn new(clock: XhttpClock) -> Self {
        let now = clock();
        Self {
            active: AtomicUsize::new(0),
            last_idle: StdMutex::new(now),
            clock,
        }
    }

    fn checkout(self: &Arc<Self>) -> ConnectionActivityLease {
        self.active.fetch_add(1, Ordering::AcqRel);
        ConnectionActivityLease {
            lifecycle: Arc::clone(self),
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire) > 0
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(*lock_unpoisoned(&self.last_idle))
    }
}

struct ConnectionActivityLease {
    lifecycle: Arc<ConnectionLifecycle>,
}

impl Drop for ConnectionActivityLease {
    fn drop(&mut self) {
        if self.lifecycle.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            *lock_unpoisoned(&self.lifecycle.last_idle) = (self.lifecycle.clock)();
        }
    }
}

impl H2Pool {
    fn new(keep_alive_period: Option<Duration>, clock: XhttpClock, idle_timeout: Duration) -> Self {
        Self {
            state: Arc::new(AsyncMutex::new(H2PoolState::default())),
            keep_alive_period,
            clock,
            idle_timeout,
        }
    }

    async fn client(&self, dial: XhttpDial) -> Result<H2Checkout, XhttpTransportError> {
        loop {
            let mut state = self.state.lock().await;
            let now = (self.clock)();
            state.connections.retain(|connection| {
                connection.client.is_live()
                    && (connection.fresh
                        || connection.lifecycle.is_active()
                        || connection.lifecycle.idle_for(now) < self.idle_timeout)
            });

            if let Some(connection) = state.connections.iter_mut().find(|connection| {
                connection.lifecycle.active() < connection.client.current_max_send_streams()
            }) {
                connection.fresh = false;
                return Ok(H2Checkout {
                    client: connection.client.clone(),
                    activity: connection.lifecycle.checkout(),
                });
            }

            let attempt = match &state.dialing {
                Some(attempt) => Arc::clone(attempt),
                None => {
                    let attempt = Arc::new(H2DialAttempt::new());
                    state.dialing = Some(Arc::clone(&attempt));
                    self.spawn_dial(Arc::clone(&dial), Arc::clone(&attempt));
                    attempt
                }
            };
            drop(state);
            attempt.wait().await?;
        }
    }

    fn spawn_dial(&self, dial: XhttpDial, attempt: Arc<H2DialAttempt>) {
        let state = Arc::clone(&self.state);
        let clock = Arc::clone(&self.clock);
        let keep_alive_period = self.keep_alive_period;
        tokio::spawn(async move {
            let result = async {
                let io = dial().await.map_err(XhttpTransportError::Dial)?;
                connect_h2_with_keepalive(io, keep_alive_period)
                    .await
                    .map_err(XhttpTransportError::Http2)
            }
            .await;

            let mut pool_state = state.lock().await;
            let still_current = pool_state
                .dialing
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &attempt));
            if !still_current {
                return;
            }
            pool_state.dialing = None;
            match result {
                Ok(client) => {
                    pool_state.connections.push(H2PoolConnection {
                        client,
                        lifecycle: Arc::new(ConnectionLifecycle::new(clock)),
                        fresh: true,
                    });
                    attempt.complete(H2DialOutcome::Ready);
                }
                Err(error) => {
                    attempt.complete(H2DialOutcome::Failed(Arc::from(error.to_string())));
                }
            }
        });
    }

    async fn connection_activity_counts(&self) -> Vec<usize> {
        self.state
            .lock()
            .await
            .connections
            .iter()
            .map(|connection| connection.lifecycle.active())
            .collect()
    }
}

#[derive(Clone)]
enum H2DialOutcome {
    Pending,
    Ready,
    Failed(Arc<str>),
}

struct H2DialAttempt {
    outcome: watch::Sender<H2DialOutcome>,
}

impl H2DialAttempt {
    fn new() -> Self {
        let (outcome, _) = watch::channel(H2DialOutcome::Pending);
        Self { outcome }
    }

    fn complete(&self, outcome: H2DialOutcome) {
        self.outcome.send_replace(outcome);
    }

    async fn wait(&self) -> Result<(), XhttpTransportError> {
        let mut outcome = self.outcome.subscribe();
        loop {
            let current = outcome.borrow().clone();
            match current {
                H2DialOutcome::Pending => {}
                H2DialOutcome::Ready => return Ok(()),
                H2DialOutcome::Failed(reason) => {
                    return Err(XhttpTransportError::SharedHttp2Dial(reason));
                }
            }
            if outcome.changed().await.is_err() {
                return Err(XhttpTransportError::BackgroundTask(
                    "shared HTTP/2 dial disappeared".to_owned(),
                ));
            }
        }
    }
}

struct H3Pool {
    state: Arc<AsyncMutex<H3PoolState>>,
    clock: XhttpClock,
    idle_timeout: Duration,
}

#[derive(Default)]
struct H3PoolState {
    connections: Vec<H3PoolConnection>,
    dialing: Option<Arc<H3DialAttempt>>,
}

struct H3PoolConnection {
    client: H3Client,
    lifecycle: Arc<ConnectionLifecycle>,
    fresh: bool,
}

struct H3Checkout {
    client: H3Client,
    activity: ConnectionActivityLease,
}

impl H3Pool {
    fn new(clock: XhttpClock, idle_timeout: Duration) -> Self {
        Self {
            state: Arc::new(AsyncMutex::new(H3PoolState::default())),
            clock,
            idle_timeout,
        }
    }

    async fn client(&self, dial: XhttpH3Dial) -> Result<H3Checkout, XhttpTransportError> {
        loop {
            let mut state = self.state.lock().await;
            let now = (self.clock)();
            state.connections.retain(|connection| {
                connection.client.is_live()
                    && (connection.fresh
                        || connection.lifecycle.is_active()
                        || connection.lifecycle.idle_for(now) < self.idle_timeout)
            });

            if let Some(connection) = state
                .connections
                .iter_mut()
                .find(|connection| connection.lifecycle.active() < H3_REQUESTS_PER_CONNECTION)
            {
                connection.fresh = false;
                return Ok(H3Checkout {
                    client: connection.client.clone(),
                    activity: connection.lifecycle.checkout(),
                });
            }

            let attempt = match &state.dialing {
                Some(attempt) => Arc::clone(attempt),
                None => {
                    let attempt = Arc::new(H3DialAttempt::new());
                    state.dialing = Some(Arc::clone(&attempt));
                    self.spawn_dial(Arc::clone(&dial), Arc::clone(&attempt));
                    attempt
                }
            };
            drop(state);
            attempt.wait().await?;
        }
    }

    fn spawn_dial(&self, dial: XhttpH3Dial, attempt: Arc<H3DialAttempt>) {
        let state = Arc::clone(&self.state);
        let clock = Arc::clone(&self.clock);
        tokio::spawn(async move {
            let result = dial().await.map_err(XhttpTransportError::Http3);
            let mut pool_state = state.lock().await;
            let still_current = pool_state
                .dialing
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &attempt));
            if !still_current {
                return;
            }
            pool_state.dialing = None;
            match result {
                Ok(client) => {
                    pool_state.connections.push(H3PoolConnection {
                        client,
                        lifecycle: Arc::new(ConnectionLifecycle::new(clock)),
                        fresh: true,
                    });
                    attempt.complete(H3DialOutcome::Ready);
                }
                Err(error) => {
                    attempt.complete(H3DialOutcome::Failed(Arc::from(error.to_string())));
                }
            }
        });
    }
}

#[derive(Clone)]
enum H3DialOutcome {
    Pending,
    Ready,
    Failed(Arc<str>),
}

struct H3DialAttempt {
    outcome: watch::Sender<H3DialOutcome>,
}

impl H3DialAttempt {
    fn new() -> Self {
        let (outcome, _) = watch::channel(H3DialOutcome::Pending);
        Self { outcome }
    }

    fn complete(&self, outcome: H3DialOutcome) {
        self.outcome.send_replace(outcome);
    }

    async fn wait(&self) -> Result<(), XhttpTransportError> {
        let mut outcome = self.outcome.subscribe();
        loop {
            match outcome.borrow().clone() {
                H3DialOutcome::Pending => {}
                H3DialOutcome::Ready => return Ok(()),
                H3DialOutcome::Failed(reason) => {
                    return Err(XhttpTransportError::SharedHttp3Dial(reason));
                }
            }
            if outcome.changed().await.is_err() {
                return Err(XhttpTransportError::BackgroundTask(
                    "shared HTTP/3 dial disappeared".to_owned(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod packet_buffer_tests {
    use tokio::io::AsyncWriteExt;
    use tokio::sync::oneshot::error::TryRecvError;

    use super::*;

    #[tokio::test]
    async fn first_uplink_writer_waits_for_data_and_distinguishes_clean_shutdown() {
        let (inner, mut peer) = tokio::io::duplex(16);
        let (first_uplink_tx, mut first_uplink_rx) = oneshot::channel();
        let mut writer = FirstUplinkWriter::new(inner, first_uplink_tx);

        writer.flush().await.unwrap();
        assert_eq!(first_uplink_rx.try_recv(), Err(TryRecvError::Empty));

        writer.write_all(b"x").await.unwrap();
        assert_eq!(first_uplink_rx.await.unwrap(), FirstUplink::Data);
        let mut byte = [0_u8; 1];
        peer.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"x");

        let (inner, _peer) = tokio::io::duplex(16);
        let (first_uplink_tx, first_uplink_rx) = oneshot::channel();
        let mut writer = FirstUplinkWriter::new(inner, first_uplink_tx);
        writer.shutdown().await.unwrap();
        assert_eq!(first_uplink_rx.await.unwrap(), FirstUplink::Closed);
    }

    #[tokio::test]
    async fn dropping_an_idle_first_uplink_writer_releases_the_worker_gate() {
        let (inner, _peer) = tokio::io::duplex(16);
        let (first_uplink_tx, first_uplink_rx) = oneshot::channel();
        let writer = FirstUplinkWriter::new(inner, first_uplink_tx);

        drop(writer);
        assert!(first_uplink_rx.await.is_err());
    }

    #[tokio::test]
    async fn h1_packet_buffer_grows_with_available_bytes_not_the_ceiling() {
        const MAX_PACKET: usize = 500_000;
        let (mut writer, mut input) = tokio::io::duplex(MAX_PACKET);
        writer.write_all(b"vless-header").await.unwrap();

        let mut buffer = h1_packet_buffer(MAX_PACKET).unwrap();
        let read = read_h1_packet_input(&mut input, &mut buffer, MAX_PACKET)
            .await
            .unwrap();

        assert_eq!(read, b"vless-header".len());
        assert_eq!(buffer, b"vless-header");
        assert!(buffer.capacity() < MAX_PACKET);
    }

    #[test]
    fn h1_body_packet_reclaims_the_actual_allocation_without_expanding_it() {
        const MAX_PACKET: usize = 500_000;

        let mut body = h1_packet_buffer(MAX_PACKET).unwrap();
        let allocation = body.as_ptr();
        body.extend_from_slice(b"data");
        let request = PreparedRequest {
            request: XhttpRequest {
                method: "POST".to_owned(),
                target: "/upload".to_owned(),
                headers: XhttpHeaderMap::new(),
                body: XhttpRequestBody::Bytes(body),
            },
            auto_gzip: false,
        };

        let reclaimed = reclaim_packet_buffer(request, MAX_PACKET).unwrap();
        assert_eq!(reclaimed.as_ptr(), allocation);
        assert!(reclaimed.is_empty());
        assert_eq!(reclaimed.capacity(), H1_PACKET_READ_CHUNK_BYTES);
    }
}

#[cfg(test)]
mod request_sanitizer_tests {
    use super::*;
    use crate::stream::http_headers::HeaderMap as XhttpHeaderMap;

    fn request(method: &str, headers: XhttpHeaderMap) -> XhttpRequest {
        XhttpRequest {
            method: method.to_owned(),
            target: "/resource".to_owned(),
            headers,
            body: XhttpRequestBody::None,
        }
    }

    fn endpoint() -> XhttpEndpoint {
        XhttpEndpoint::new(super::super::config::XhttpScheme::Https, "example.com")
            .expect("test endpoint")
    }

    #[test]
    fn zero_content_length_is_emitted_only_for_post_put_and_patch() {
        for (method, expected) in [
            ("POST", true),
            ("PUT", true),
            ("PATCH", true),
            ("DELETE", false),
            ("OPTIONS", false),
            ("GET", false),
            ("HEAD", false),
            ("PURGE", false),
        ] {
            let request = request(method, XhttpHeaderMap::new());
            for output in [
                h2_request(&request, &endpoint(), Some(0)).expect("H2 request"),
                h3_request(&request, &endpoint(), Some(0)).expect("H3 request"),
            ] {
                assert_eq!(
                    output.headers().contains_key(header::CONTENT_LENGTH),
                    expected,
                    "method={method} version={:?}",
                    output.version()
                );
            }
        }
    }

    #[test]
    fn positive_content_length_is_emitted_for_arbitrary_methods() {
        let request = request("PURGE", XhttpHeaderMap::new());
        for output in [
            h2_request(&request, &endpoint(), Some(7)).expect("H2 request"),
            h3_request(&request, &endpoint(), Some(7)).expect("H3 request"),
        ] {
            assert_eq!(output.headers()[header::CONTENT_LENGTH], "7");
        }
    }

    #[test]
    fn user_agent_absent_empty_and_custom_are_distinct() {
        let absent = request("GET", XhttpHeaderMap::new());
        assert_eq!(
            h2_request(&absent, &endpoint(), None).unwrap().headers()[header::USER_AGENT],
            "Go-http-client/2.0"
        );
        assert_eq!(
            h3_request(&absent, &endpoint(), None).unwrap().headers()[header::USER_AGENT],
            "quic-go HTTP/3"
        );

        let mut empty_headers = XhttpHeaderMap::new();
        empty_headers.set("User-Agent", "");
        let empty = request("GET", empty_headers);
        assert!(!h2_request(&empty, &endpoint(), None)
            .unwrap()
            .headers()
            .contains_key(header::USER_AGENT));
        assert!(!h3_request(&empty, &endpoint(), None)
            .unwrap()
            .headers()
            .contains_key(header::USER_AGENT));

        let mut custom_headers = XhttpHeaderMap::new();
        custom_headers.set("User-Agent", "custom-agent");
        let custom = request("GET", custom_headers);
        assert_eq!(
            h2_request(&custom, &endpoint(), None).unwrap().headers()[header::USER_AGENT],
            "custom-agent"
        );
        assert_eq!(
            h3_request(&custom, &endpoint(), None).unwrap().headers()[header::USER_AGENT],
            "custom-agent"
        );
    }

    #[test]
    fn multiplexed_cookie_is_split_and_connection_headers_are_removed() {
        let mut headers = XhttpHeaderMap::new();
        headers.set("Cookie", "a=1; b=2; c=3");
        headers.set("Connection", "close");
        headers.set("Keep-Alive", "timeout=5");
        let request = request("GET", headers);
        for output in [
            h2_request(&request, &endpoint(), None).expect("H2 request"),
            h3_request(&request, &endpoint(), None).expect("H3 request"),
        ] {
            let cookies: Vec<_> = output
                .headers()
                .get_all(header::COOKIE)
                .iter()
                .map(|value| value.to_str().expect("ASCII cookie"))
                .collect();
            assert_eq!(cookies, ["a=1", "b=2", "c=3"]);
            assert!(!output.headers().contains_key(header::CONNECTION));
            assert!(!output.headers().contains_key("keep-alive"));
        }
    }

    #[test]
    fn duplicate_canonical_headers_keep_add_order_on_multiplexed_requests() {
        let mut headers = XhttpHeaderMap::new();
        headers.add("X-Foo", "first");
        headers.add("X-Foo", "second");
        let mut request = request("GET", headers);

        // Auto-gzip rebuilds the header map before every downlink request; it
        // must replace only Accept-Encoding and preserve unrelated Add values.
        assert!(prepare_auto_gzip(&mut request, true));
        for output in [
            h2_request(&request, &endpoint(), None).expect("H2 request"),
            h3_request(&request, &endpoint(), None).expect("H3 request"),
        ] {
            let values: Vec<_> = output
                .headers()
                .get_all("x-foo")
                .iter()
                .map(|value| value.to_str().expect("ASCII test header"))
                .collect();
            assert_eq!(values, ["first", "second"]);
        }
    }

    #[test]
    fn auto_gzip_matches_go_transport_request_conditions() {
        let mut absent = request("GET", XhttpHeaderMap::new());
        assert!(prepare_auto_gzip(&mut absent, true));
        assert_eq!(absent.headers.get("Accept-Encoding"), Some("gzip"));

        let mut empty_headers = XhttpHeaderMap::new();
        empty_headers.set("accept-encoding", "");
        let mut explicit_empty = request("GET", empty_headers);
        assert!(prepare_auto_gzip(&mut explicit_empty, true));
        assert_eq!(explicit_empty.headers.get("Accept-Encoding"), Some("gzip"));
        assert_eq!(
            explicit_empty
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("Accept-Encoding"))
                .count(),
            1
        );

        let mut custom_headers = XhttpHeaderMap::new();
        custom_headers.set("Accept-Encoding", "br");
        let mut custom = request("GET", custom_headers);
        assert!(!prepare_auto_gzip(&mut custom, true));
        assert_eq!(custom.headers.get("Accept-Encoding"), Some("br"));

        let mut range_headers = XhttpHeaderMap::new();
        range_headers.set("Range", "bytes=0-9");
        let mut ranged = request("GET", range_headers);
        assert!(!prepare_auto_gzip(&mut ranged, true));
        assert!(ranged.headers.get("Accept-Encoding").is_none());

        let mut empty_range_headers = XhttpHeaderMap::new();
        empty_range_headers.set("Range", "");
        let mut empty_range = request("GET", empty_range_headers);
        assert!(prepare_auto_gzip(&mut empty_range, true));

        let mut head = request("HEAD", XhttpHeaderMap::new());
        assert!(!prepare_auto_gzip(&mut head, true));
        assert!(head.headers.get("Accept-Encoding").is_none());
    }

    #[test]
    fn raw_h1_packet_path_bypasses_auto_gzip() {
        let mut packet = request("POST", XhttpHeaderMap::new());
        assert!(!prepare_auto_gzip(&mut packet, false));
        assert!(packet.headers.get("Accept-Encoding").is_none());
    }

    #[test]
    fn stored_gzip_failure_remains_request_local_across_packet_worker_round_trips() {
        let decode = io::Error::new(
            io::ErrorKind::InvalidData,
            GzipDecodeError(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed member",
            )),
        );
        let first = StoredFailure::from_io(&decode);
        assert!(!first.retires_client);

        let transport_error = first.into_transport_error();
        assert!(!transport_error.retires_client());
        let second = StoredFailure::from_error(&transport_error);
        assert!(!second.retires_client);
    }
}

#[cfg(test)]
mod xmux_reservation_tests {
    use rand::rngs::mock::StepRng;

    use super::*;

    #[tokio::test]
    async fn simultaneous_selections_reserve_max_concurrency_before_unlocking() {
        let rng: Arc<StdMutex<Box<dyn RngCore + Send>>> =
            Arc::new(StdMutex::new(Box::new(StepRng::new(0, 0))));
        // Keep every range exact so this locking test cannot enter random
        // rejection sampling. Only maxConcurrency is relevant here.
        let policy = XhttpXmuxPolicy {
            max_concurrency: XhttpRange::exact(1),
            max_connections: XhttpRange::exact(0),
            c_max_reuse_times: XhttpRange::exact(0),
            h_max_request_times: XhttpRange::exact(1),
            h_max_reusable_secs: XhttpRange::exact(0),
            h_keep_alive_period_secs: 0,
        };
        let manager = XmuxManager::new(
            policy,
            MAX_H1_IDLE_UPLOAD_STREAMS,
            rng,
            Arc::new(Instant::now),
            HTTP_MULTIPLEXED_IDLE_TIMEOUT,
        )
        .expect("xmux manager");

        // `join!` polls both selections before this test can construct any
        // follow-up state. If reservation happened after selection, both
        // futures would deterministically observe usage zero and return the
        // same explicitly selected maxConcurrency=1 client.
        let (first, second) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(manager.select_client(), manager.select_client())
        })
        .await
        .expect("simultaneous xmux selections deadlocked");
        let (first_client, first_usage) = first.expect("first selection");
        let (second_client, second_usage) = second.expect("second selection");

        assert!(!Arc::ptr_eq(&first_client, &second_client));
        assert_eq!(first_client.open_usage.load(Ordering::Acquire), 1);
        assert_eq!(second_client.open_usage.load(Ordering::Acquire), 1);

        drop((first_usage, second_usage));
        assert_eq!(first_client.open_usage.load(Ordering::Acquire), 0);
        assert_eq!(second_client.open_usage.load(Ordering::Acquire), 0);
    }
}
