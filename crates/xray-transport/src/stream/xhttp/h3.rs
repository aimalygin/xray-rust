//! HTTP/3 wire engine for outbound XHTTP.
//!
//! This first implementation owns one protected, single-destination QUIC v1
//! endpoint. UDP hopping and connection-pool policy belong above this layer.

use std::fmt;
use std::future::{poll_fn, Future};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::task::AtomicWaker;
use h3::client;
use h3::error::Code;
use http::{HeaderMap, Method, Request, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};

use crate::{
    canonicalize_socket_addr, HappyEyeballsConfig, SocketHandle, SocketProtector, TransportError,
};

const QUIC_V1: u32 = 0x0000_0001;
const MAX_UPLOAD_DATA_BYTES: usize = 16 * 1024;
const RESPONSE_QUEUE_DEPTH: usize = 1;
const XRAY_INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;
const XRAY_INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = 3 * 1024 * 1024;
const XRAY_BBR_INITIAL_WINDOW: u64 = 32 * 1280;

type H3SendRequest = client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3SendHalf = client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvHalf = client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// QUIC versions understood by XHTTP configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3QuicVersion {
    V1,
    V2,
}

/// Congestion-control choices understood by XHTTP configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3Congestion {
    /// Quinn's BBR implementation with Xray's standard initial window.
    BbrStandard,
    Reno,
    BbrConservative,
    BbrAggressive,
    Brutal,
    ForceBrutal {
        bytes_per_second: u64,
    },
}

/// Parsed UDP-hop policy retained so phase one can reject it explicitly.
///
/// An empty port list is disabled, matching Xray even when an interval was
/// configured. A non-empty list requires packet-socket rebinding support and
/// therefore fails closed before any UDP socket is opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H3UdpHopConfig {
    pub ports: Vec<u16>,
    pub interval_min: Duration,
    pub interval_max: Duration,
}

/// QUIC transport settings supported by the phase-one engine.
///
/// Xray/quic-go normally auto-tunes its receive windows from the configured
/// initial values (2 MiB per stream and 3 MiB per connection) up to larger
/// maxima. Quinn does not expose equivalent receive-window auto-tuning. A
/// `None` maximum therefore means the deliberate phase-one approximation of a
/// static window at the corresponding initial value; it does not claim
/// adaptive-window parity. Supplying a distinct maximum fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3QuicConfig {
    pub version: H3QuicVersion,
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: Option<u64>,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: Option<u64>,
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Option<Duration>,
    pub max_incoming_bidirectional_streams: u64,
    pub disable_path_mtu_discovery: bool,
    pub congestion: H3Congestion,
    pub udp_hop: H3UdpHopConfig,
    pub debug: bool,
}

impl Default for H3QuicConfig {
    fn default() -> Self {
        Self {
            version: H3QuicVersion::V1,
            initial_stream_receive_window: XRAY_INITIAL_STREAM_RECEIVE_WINDOW,
            max_stream_receive_window: None,
            initial_connection_receive_window: XRAY_INITIAL_CONNECTION_RECEIVE_WINDOW,
            max_connection_receive_window: None,
            max_idle_timeout: Duration::from_secs(300),
            keep_alive_interval: None,
            max_incoming_bidirectional_streams: 0,
            disable_path_mtu_discovery: !cfg!(any(
                target_os = "linux",
                target_os = "windows",
                target_os = "macos"
            )),
            congestion: H3Congestion::BbrStandard,
            udp_hop: H3UdpHopConfig::default(),
            debug: false,
        }
    }
}

/// Stable facts callers can log when selecting the phase-one H3 path.
///
/// `adaptive_receive_windows == false` is an explicit compatibility
/// diagnostic: the reported window sizes are fixed Quinn limits, not
/// quic-go's auto-tuned maxima.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Diagnostics {
    pub quic_version: u32,
    pub congestion: &'static str,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
    pub adaptive_receive_windows: bool,
    pub udp_hop: bool,
}

impl H3QuicConfig {
    /// Validates phase-one parity limits without opening a socket.
    ///
    /// The default reports static 2 MiB/3 MiB receive windows and
    /// `adaptive_receive_windows == false`. Explicit adaptive maxima are
    /// rejected instead of being silently reduced to those static limits.
    pub fn diagnostics(&self) -> Result<H3Diagnostics, H3Error> {
        if self.version != H3QuicVersion::V1 {
            return Err(H3Error::UnsupportedQuicVersion {
                requested: self.version,
            });
        }
        if self
            .max_stream_receive_window
            .is_some_and(|maximum| maximum != self.initial_stream_receive_window)
            || self
                .max_connection_receive_window
                .is_some_and(|maximum| maximum != self.initial_connection_receive_window)
        {
            return Err(H3Error::UnsupportedAdaptiveReceiveWindows {
                initial_stream: self.initial_stream_receive_window,
                max_stream: self.max_stream_receive_window,
                initial_connection: self.initial_connection_receive_window,
                max_connection: self.max_connection_receive_window,
            });
        }
        if !self.udp_hop.ports.is_empty() {
            return Err(H3Error::UnsupportedUdpHop {
                port_count: self.udp_hop.ports.len(),
                interval_min: self.udp_hop.interval_min,
                interval_max: self.udp_hop.interval_max,
            });
        }
        if self.debug {
            return Err(H3Error::UnsupportedDebugLogging);
        }

        let congestion = match self.congestion {
            H3Congestion::BbrStandard => "quinn-bbr-standard-approximation",
            H3Congestion::Reno => "new-reno",
            requested => return Err(H3Error::UnsupportedCongestion { requested }),
        };
        quinn_varint(
            "initialStreamReceiveWindow",
            self.initial_stream_receive_window,
        )?;
        quinn_varint(
            "initialConnectionReceiveWindow",
            self.initial_connection_receive_window,
        )?;
        quinn_varint(
            "maxIncomingStreams",
            self.max_incoming_bidirectional_streams,
        )?;

        Ok(H3Diagnostics {
            quic_version: QUIC_V1,
            congestion,
            stream_receive_window: self.initial_stream_receive_window,
            connection_receive_window: self.initial_connection_receive_window,
            adaptive_receive_windows: false,
            udp_hop: false,
        })
    }
}

/// Everything required to connect one protected HTTP/3 destination.
#[derive(Clone)]
pub struct H3ConnectConfig {
    pub remote_addr: SocketAddr,
    pub server_name: String,
    pub tls_config: Arc<rustls::ClientConfig>,
    pub socket_protector: Option<Arc<dyn SocketProtector>>,
    pub quic: H3QuicConfig,
}

impl fmt::Debug for H3ConnectConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("H3ConnectConfig")
            .field("remote_addr", &self.remote_addr)
            .field("server_name", &self.server_name)
            .field("alpn_protocols", &self.tls_config.alpn_protocols)
            .field("socket_protector", &self.socket_protector.is_some())
            .field("quic", &self.quic)
            .finish()
    }
}

/// HTTP/3 connection, stream, and parity failures.
#[derive(Debug, Error)]
pub enum H3Error {
    #[error("HTTP/3 requires at least one resolved UDP candidate")]
    NoResolvedCandidate,
    #[error("QUIC requires TLS ALPN to be exactly `{expected}`")]
    InvalidAlpn { expected: &'static str },
    #[error("QUIC version {requested:?} is not implemented; phase one is fail-closed on v1")]
    UnsupportedQuicVersion { requested: H3QuicVersion },
    #[error(
        "adaptive QUIC receive windows are unsupported (stream {initial_stream}/{max_stream:?}, connection {initial_connection}/{max_connection:?})"
    )]
    UnsupportedAdaptiveReceiveWindows {
        initial_stream: u64,
        max_stream: Option<u64>,
        initial_connection: u64,
        max_connection: Option<u64>,
    },
    #[error("QUIC congestion mode {requested:?} is not implemented without silent fallback")]
    UnsupportedCongestion { requested: H3Congestion },
    #[error(
        "QUIC UDP hop is not implemented ({port_count} ports, interval {interval_min:?}-{interval_max:?})"
    )]
    UnsupportedUdpHop {
        port_count: usize,
        interval_min: Duration,
        interval_max: Duration,
    },
    #[error("QUIC debug logging requires process-global quic-go hooks and is not implemented")]
    UnsupportedDebugLogging,
    #[error("invalid QUIC transport parameter `{name}`: {value}")]
    InvalidTransportParameter { name: &'static str, value: u128 },
    #[error("could not build QUIC TLS configuration: {0}")]
    TlsConfig(String),
    #[error("could not bind HTTP/3 UDP socket {addr}: {source}")]
    UdpBind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("could not configure HTTP/3 UDP socket: {0}")]
    UdpSocket(#[source] io::Error),
    #[error("could not create QUIC endpoint: {0}")]
    Endpoint(#[source] io::Error),
    #[error("could not start QUIC connection: {0}")]
    ConnectStart(#[source] quinn::ConnectError),
    #[error("QUIC connection failed: {0}")]
    Connect(#[source] quinn::ConnectionError),
    #[error("HTTP/3 connection setup failed: {0}")]
    Http3Connection(#[source] h3::error::ConnectionError),
    #[error("HTTP/3 {context}: {source}")]
    Http3Stream {
        context: &'static str,
        #[source]
        source: h3::error::StreamError,
    },
    #[error("XHTTP HTTP/3 server returned status {status}")]
    UnexpectedStatus { status: StatusCode },
    #[error("HTTP/3 response was already consumed")]
    ResponseConsumed,
    #[error("HTTP/3 response task ended before delivering headers")]
    ResponseTaskClosed,
    #[error("HTTP/3 response consumer was dropped")]
    ResponseConsumerDropped,
    #[error("HTTP/3 request was cancelled")]
    Cancelled,
    #[error("HTTP/3 upload I/O failed: {0}")]
    UploadIo(#[source] io::Error),
}

/// A reusable HTTP/3 client backed by one QUIC connection.
#[derive(Clone)]
pub struct H3Client {
    send_request: H3SendRequest,
    driver: Arc<H3ConnectionDriver>,
    diagnostics: H3Diagnostics,
}

impl fmt::Debug for H3Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("H3Client")
            .field("live", &self.is_live())
            .field("local_addr", &self.local_addr())
            .field("diagnostics", &self.diagnostics)
            .finish_non_exhaustive()
    }
}

struct H3ConnectionDriver {
    endpoint: Endpoint,
    connection: quinn::Connection,
    task: JoinHandle<h3::error::ConnectionError>,
}

impl Drop for H3ConnectionDriver {
    fn drop(&mut self) {
        let code = VarInt::from_u32(Code::H3_NO_ERROR.value() as u32);
        self.connection.close(code, b"XHTTP H3 client dropped");
        self.endpoint.close(code, b"XHTTP H3 client dropped");
        self.task.abort();
    }
}

impl H3Client {
    /// Whether the HTTP/3 driver and underlying QUIC connection are live.
    pub fn is_live(&self) -> bool {
        !self.driver.task.is_finished() && self.driver.connection.close_reason().is_none()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.driver.endpoint.local_addr()
    }

    pub fn diagnostics(&self) -> &H3Diagnostics {
        &self.diagnostics
    }

    /// Sends a fixed body and validates its response while upload can progress.
    pub async fn send_fixed(
        &self,
        request: Request<()>,
        body: Bytes,
    ) -> Result<H3ResponseBody, H3Error> {
        if body.is_empty() {
            return self.start_fixed(request, body).await?.open().await;
        }

        let (mut upload, response) = self.start_streaming(request).await?;
        let (_, response) = tokio::try_join!(upload.send_owned(body), response.open())?;
        Ok(response)
    }

    /// Completes a fixed upload and returns without waiting for response headers.
    pub async fn start_fixed(
        &self,
        request: Request<()>,
        body: Bytes,
    ) -> Result<H3PendingResponse, H3Error> {
        let (mut upload, response) = self.start_streaming(request).await?;
        upload.send_owned(body).await?;
        Ok(response)
    }

    /// Opens an independently backpressured upload and download pair.
    pub async fn start_streaming(
        &self,
        request: Request<()>,
    ) -> Result<(H3Upload, H3PendingResponse), H3Error> {
        let response_is_bodyless = request.method() == Method::HEAD;
        let expected_content_length = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let mut send_request = self.send_request.clone();
        let request_stream =
            send_request
                .send_request(request)
                .await
                .map_err(|source| H3Error::Http3Stream {
                    context: "request headers could not be sent",
                    source,
                })?;
        let (send, recv) = request_stream.split();

        let (cancel, _) = watch::channel(false);
        let shared = Arc::new(ExchangeShared {
            cancel,
            _connection_guard: send_request,
            _driver: Arc::clone(&self.driver),
        });
        let upload_status = Arc::new(UploadWorkerStatus::new());
        let (upload, upload_reader) = tokio::io::duplex(MAX_UPLOAD_DATA_BYTES);
        let (upload_finished, upload_completion) = oneshot::channel();
        let (response_headers, response_waiter) = oneshot::channel();
        let (response_body, body_waiter) = mpsc::channel(RESPONSE_QUEUE_DEPTH);

        tokio::spawn(drive_upload(
            send,
            upload_reader,
            expected_content_length,
            Arc::clone(&shared),
            Arc::clone(&upload_status),
            upload_finished,
        ));
        tokio::spawn(drive_response(
            recv,
            response_is_bodyless,
            Arc::clone(&shared),
            response_headers,
            response_body,
        ));

        Ok((
            H3Upload {
                io: upload,
                completion: Some(upload_completion),
                finished: false,
                accepted: 0,
                status: upload_status,
                shared: Arc::clone(&shared),
            },
            H3PendingResponse {
                headers: Some(response_waiter),
                body: Some(body_waiter),
                response_is_bodyless,
                cancel_on_drop: true,
                shared,
            },
        ))
    }
}

/// Connects one protected UDP destination and starts its HTTP/3 driver.
pub async fn connect_h3(config: H3ConnectConfig) -> Result<H3Client, H3Error> {
    let (endpoint, connection, diagnostics) = connect_quic_transport(config, b"h3").await?;
    let (mut h3_connection, send_request) =
        client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(H3Error::Http3Connection)?;
    let task = tokio::spawn(async move { poll_fn(|cx| h3_connection.poll_close(cx)).await });
    let driver = Arc::new(H3ConnectionDriver {
        endpoint,
        connection,
        task,
    });

    Ok(H3Client {
        send_request,
        driver,
        diagnostics,
    })
}

pub(crate) async fn connect_quic_transport(
    config: H3ConnectConfig,
    expected_alpn: &'static [u8],
) -> Result<(Endpoint, quinn::Connection, H3Diagnostics), H3Error> {
    drop(crate::tls::parse_tls_server_name(&config.server_name)?);
    let diagnostics = config.quic.diagnostics()?;
    if config.tls_config.alpn_protocols.len() != 1
        || config.tls_config.alpn_protocols[0].as_slice() != expected_alpn
    {
        let expected = std::str::from_utf8(expected_alpn).unwrap_or("<binary>");
        return Err(H3Error::InvalidAlpn { expected });
    }

    let (endpoint_config, client_config) = build_quinn_config(&config)?;
    let remote_addr = canonicalize_socket_addr(config.remote_addr);
    let bind_addr = match remote_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    let socket = StdUdpSocket::bind(bind_addr).map_err(|source| H3Error::UdpBind {
        addr: bind_addr,
        source,
    })?;
    protect_quic_socket(&socket, config.socket_protector.as_deref())?;
    socket.set_nonblocking(true).map_err(H3Error::UdpSocket)?;

    let endpoint = Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))
        .map_err(H3Error::Endpoint)?;
    let connecting = endpoint
        .connect_with(client_config, remote_addr, &config.server_name)
        .map_err(H3Error::ConnectStart)?;
    let connection = connecting.await.map_err(H3Error::Connect)?;
    Ok((endpoint, connection, diagnostics))
}

/// Connects the first successful protected UDP candidate.
///
/// A missing or zero-delay Happy Eyeballs policy preserves the legacy first
/// candidate behavior. When enabled, candidates use the shared stable family
/// ordering plus the configured delay and concurrency bound. Socket
/// protection failure is fatal because trying an unprotected fallback would
/// leak QUIC outside the caller's VPN routing boundary.
pub async fn connect_h3_candidates(
    config: H3ConnectConfig,
    candidates: &[SocketAddr],
    happy_eyeballs: Option<&HappyEyeballsConfig>,
) -> Result<H3Client, H3Error> {
    let first = candidates
        .first()
        .copied()
        .ok_or(H3Error::NoResolvedCandidate)?;
    let Some(happy_eyeballs) =
        happy_eyeballs.filter(|policy| !policy.try_delay.is_zero() && candidates.len() >= 2)
    else {
        let mut config = config;
        config.remote_addr = first;
        return connect_h3(config).await;
    };

    race_h3_candidates(candidates, happy_eyeballs, move |candidate| {
        let mut config = config.clone();
        config.remote_addr = candidate;
        async move { connect_h3(config).await }
    })
    .await
}

async fn race_h3_candidates<T, Connect, ConnectFuture>(
    candidates: &[SocketAddr],
    policy: &HappyEyeballsConfig,
    connect: Connect,
) -> Result<T, H3Error>
where
    Connect: Fn(SocketAddr) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<T, H3Error>>,
{
    let ordered = policy.order_candidates(candidates);
    let first = ordered
        .first()
        .copied()
        .ok_or(H3Error::NoResolvedCandidate)?;
    let mut attempts = FuturesUnordered::new();
    attempts.push(connect(first));

    let mut next_index = 1;
    let mut next_launch_at = Instant::now().checked_add(policy.try_delay);
    let mut last_error = None;
    loop {
        if attempts.is_empty() {
            return Err(last_error.unwrap_or(H3Error::NoResolvedCandidate));
        }

        let result = if next_index < ordered.len() && attempts.len() < policy.max_concurrent.get() {
            match next_launch_at {
                Some(deadline) => {
                    tokio::select! {
                        result = attempts.next() => result,
                        () = sleep_until(deadline) => {
                            attempts.push(connect(ordered[next_index]));
                            next_index += 1;
                            next_launch_at = Instant::now().checked_add(policy.try_delay);
                            continue;
                        }
                    }
                }
                None => attempts.next().await,
            }
        } else {
            attempts.next().await
        };

        let Some(result) = result else {
            return Err(last_error.unwrap_or(H3Error::NoResolvedCandidate));
        };
        match result {
            Ok(client) => return Ok(client),
            Err(error) if is_socket_protection_error(&error) => return Err(error),
            Err(error) => last_error = Some(error),
        }

        if next_index < ordered.len() {
            attempts.push(connect(ordered[next_index]));
            next_index += 1;
            next_launch_at = Instant::now().checked_add(policy.try_delay);
        }
    }
}

fn is_socket_protection_error(error: &H3Error) -> bool {
    matches!(
        error,
        H3Error::Transport(TransportError::SocketProtection(_))
    )
}

fn build_quinn_config(config: &H3ConnectConfig) -> Result<(EndpointConfig, ClientConfig), H3Error> {
    let mut endpoint = EndpointConfig::default();
    endpoint.supported_versions(vec![QUIC_V1]);

    let stream_window = quinn_varint(
        "initialStreamReceiveWindow",
        config.quic.initial_stream_receive_window,
    )?;
    let connection_window = quinn_varint(
        "initialConnectionReceiveWindow",
        config.quic.initial_connection_receive_window,
    )?;
    let max_incoming = quinn_varint(
        "maxIncomingStreams",
        config.quic.max_incoming_bidirectional_streams,
    )?;
    let idle_timeout = config.quic.max_idle_timeout.try_into().map_err(|_| {
        H3Error::InvalidTransportParameter {
            name: "maxIdleTimeout",
            value: config.quic.max_idle_timeout.as_millis(),
        }
    })?;

    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(config.quic.keep_alive_interval)
        .stream_receive_window(stream_window)
        .receive_window(connection_window)
        .max_concurrent_bidi_streams(max_incoming);
    if config.quic.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    match config.quic.congestion {
        H3Congestion::BbrStandard => {
            let mut bbr = quinn::congestion::BbrConfig::default();
            bbr.initial_window(XRAY_BBR_INITIAL_WINDOW);
            transport.congestion_controller_factory(Arc::new(bbr));
        }
        H3Congestion::Reno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        requested => return Err(H3Error::UnsupportedCongestion { requested }),
    }

    let crypto = QuicClientConfig::try_from(Arc::clone(&config.tls_config))
        .map_err(|error| H3Error::TlsConfig(error.to_string()))?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    client
        .version(QUIC_V1)
        .transport_config(Arc::new(transport));
    Ok((endpoint, client))
}

fn quinn_varint(name: &'static str, value: u64) -> Result<VarInt, H3Error> {
    VarInt::from_u64(value).map_err(|_| H3Error::InvalidTransportParameter {
        name,
        value: u128::from(value),
    })
}

fn protect_quic_socket(
    socket: &StdUdpSocket,
    protector: Option<&dyn SocketProtector>,
) -> Result<(), H3Error> {
    if let Some(protector) = protector {
        protector
            .protect(SocketHandle::from_std_udp_socket(socket))
            .map_err(TransportError::SocketProtection)?;
    }
    Ok(())
}

struct ExchangeShared {
    cancel: watch::Sender<bool>,
    _connection_guard: H3SendRequest,
    _driver: Arc<H3ConnectionDriver>,
}

impl ExchangeShared {
    fn cancel(&self) {
        self.cancel.send_replace(true);
    }

    fn cancellation(&self) -> watch::Receiver<bool> {
        self.cancel.subscribe()
    }
}

async fn cancelled(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn drive_upload(
    mut send: H3SendHalf,
    mut input: DuplexStream,
    expected_content_length: Option<u64>,
    shared: Arc<ExchangeShared>,
    status: Arc<UploadWorkerStatus>,
    completion: oneshot::Sender<Result<(), H3Error>>,
) {
    let mut cancellation = shared.cancellation();
    let mut buffer = [0_u8; MAX_UPLOAD_DATA_BYTES];
    let result = loop {
        let read = tokio::select! {
            biased;
            () = cancelled(&mut cancellation) => break Err(H3Error::Cancelled),
            read = input.read(&mut buffer) => read,
        };
        let read = match read {
            Ok(read) => read,
            Err(source) => break Err(H3Error::UploadIo(source)),
        };
        if read == 0 {
            break tokio::select! {
                biased;
                () = cancelled(&mut cancellation) => Err(H3Error::Cancelled),
                result = send.finish() => match result {
                    Ok(()) => Ok(()),
                    // Xray-core stops reading a fixed-length H3 request with
                    // H3_NO_ERROR as soon as it has consumed Content-Length.
                    // That STOP_SENDING can race with our separate QUIC FIN.
                    // Accept it only when every declared body byte has already
                    // passed send_data. Unknown-length and partial uploads,
                    // other codes, and send_data failures remain authoritative.
                    Err(h3::error::StreamError::RemoteTerminate { code, .. })
                        if code == Code::H3_NO_ERROR
                            && expected_content_length
                                == Some(status.delivered.load(Ordering::Acquire)) => Ok(()),
                    Err(source) => Err(H3Error::Http3Stream {
                        context: "request body could not be finished",
                        source,
                    }),
                },
            };
        }

        let data = Bytes::copy_from_slice(&buffer[..read]);
        let sent = tokio::select! {
            biased;
            () = cancelled(&mut cancellation) => Err(H3Error::Cancelled),
            result = send.send_data(data) => result.map_err(|source| H3Error::Http3Stream {
                context: "request DATA could not be sent",
                source,
            }),
        };
        if let Err(error) = sent {
            break Err(error);
        }
        status.delivered.fetch_add(read as u64, Ordering::Release);
        status.waker.wake();
    };

    if result.is_err() {
        send.stop_stream(Code::H3_REQUEST_CANCELLED);
        shared.cancel();
    }
    if let Err(error) = &result {
        status.fail(error);
    }
    status.done.store(true, Ordering::Release);
    status.waker.wake();
    let _ = completion.send(result);
}

enum BodyEvent {
    Data(Bytes),
    End(Option<HeaderMap>),
    Error(H3Error),
}

async fn drive_response(
    mut recv: H3RecvHalf,
    response_is_bodyless: bool,
    shared: Arc<ExchangeShared>,
    headers: oneshot::Sender<Result<HeaderMap, H3Error>>,
    body: mpsc::Sender<BodyEvent>,
) {
    let mut cancellation = shared.cancellation();
    let mut headers = Some(headers);
    let result = drive_response_inner(
        &mut recv,
        response_is_bodyless,
        &mut cancellation,
        &mut headers,
        &body,
    )
    .await;

    if let Err(error) = result {
        recv.stop_sending(Code::H3_REQUEST_CANCELLED);
        shared.cancel();
        if let Some(headers) = headers.take() {
            let _ = headers.send(Err(error));
        } else {
            let _ = body.try_send(BodyEvent::Error(error));
        }
    }
}

async fn drive_response_inner(
    recv: &mut H3RecvHalf,
    response_is_bodyless: bool,
    cancellation: &mut watch::Receiver<bool>,
    headers: &mut Option<oneshot::Sender<Result<HeaderMap, H3Error>>>,
    body: &mpsc::Sender<BodyEvent>,
) -> Result<(), H3Error> {
    let response = tokio::select! {
        biased;
        () = cancelled(cancellation) => return Err(H3Error::Cancelled),
        result = recv.recv_response() => result.map_err(|source| H3Error::Http3Stream {
            context: "response headers could not be received",
            source,
        })?,
    };
    let (parts, ()) = response.into_parts();
    if parts.status != StatusCode::OK {
        return Err(H3Error::UnexpectedStatus {
            status: parts.status,
        });
    }
    headers
        .take()
        .ok_or(H3Error::ResponseTaskClosed)?
        .send(Ok(parts.headers))
        .map_err(|_| H3Error::ResponseConsumerDropped)?;

    if response_is_bodyless {
        recv.stop_sending(Code::H3_REQUEST_CANCELLED);
        return Ok(());
    }

    loop {
        let data = tokio::select! {
            biased;
            () = cancelled(cancellation) => return Err(H3Error::Cancelled),
            result = recv.recv_data() => result.map_err(|source| H3Error::Http3Stream {
                context: "response DATA could not be received",
                source,
            })?,
        };
        let Some(mut data) = data else {
            break;
        };
        let data = data.copy_to_bytes(data.remaining());
        tokio::select! {
            biased;
            () = cancelled(cancellation) => return Err(H3Error::Cancelled),
            result = body.send(BodyEvent::Data(data)) => {
                result.map_err(|_| H3Error::ResponseConsumerDropped)?;
            }
        }
    }

    let trailers = tokio::select! {
        biased;
        () = cancelled(cancellation) => return Err(H3Error::Cancelled),
        result = recv.recv_trailers() => result.map_err(|source| H3Error::Http3Stream {
            context: "response trailers could not be received",
            source,
        })?,
    };
    tokio::select! {
        biased;
        () = cancelled(cancellation) => Err(H3Error::Cancelled),
        result = body.send(BodyEvent::End(trailers)) => {
            result.map_err(|_| H3Error::ResponseConsumerDropped)
        }
    }
}

/// Flow-controlled request body for a streaming HTTP/3 exchange.
pub struct H3Upload {
    io: DuplexStream,
    completion: Option<oneshot::Receiver<Result<(), H3Error>>>,
    finished: bool,
    accepted: u64,
    status: Arc<UploadWorkerStatus>,
    shared: Arc<ExchangeShared>,
}

struct UploadWorkerStatus {
    delivered: AtomicU64,
    done: AtomicBool,
    failure: Mutex<Option<UploadWorkerFailure>>,
    waker: AtomicWaker,
}

impl UploadWorkerStatus {
    fn new() -> Self {
        Self {
            delivered: AtomicU64::new(0),
            done: AtomicBool::new(false),
            failure: Mutex::new(None),
            waker: AtomicWaker::new(),
        }
    }

    fn fail(&self, error: &H3Error) {
        *lock_unpoisoned(&self.failure) = Some(UploadWorkerFailure {
            kind: h3_io_error_kind(error),
            message: error.to_string(),
        });
    }
}

struct UploadWorkerFailure {
    kind: io::ErrorKind,
    message: String,
}

impl UploadWorkerFailure {
    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

impl fmt::Debug for H3Upload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("H3Upload")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl H3Upload {
    async fn send_owned(&mut self, body: Bytes) -> Result<(), H3Error> {
        self.write_all(&body).await.map_err(H3Error::UploadIo)?;
        self.shutdown().await.map_err(H3Error::UploadIo)
    }

    fn worker_error(&self) -> Option<io::Error> {
        lock_unpoisoned(&self.status.failure)
            .as_ref()
            .map(UploadWorkerFailure::to_io_error)
    }

    fn poll_delivery(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.worker_error() {
            return Poll::Ready(Err(error));
        }
        if self.status.delivered.load(Ordering::Acquire) >= self.accepted {
            return Poll::Ready(Ok(()));
        }
        if self.status.done.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/3 upload worker stopped before delivering accepted bytes",
            )));
        }

        self.status.waker.register(cx.waker());
        if let Some(error) = self.worker_error() {
            return Poll::Ready(Err(error));
        }
        if self.status.delivered.load(Ordering::Acquire) >= self.accepted {
            Poll::Ready(Ok(()))
        } else if self.status.done.load(Ordering::Acquire) {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/3 upload worker stopped before delivering accepted bytes",
            )))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for H3Upload {
    fn drop(&mut self) {
        if !self.finished {
            self.shared.cancel();
        }
    }
}

impl AsyncWrite for H3Upload {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/3 request body is already closed",
            )));
        }
        if let Some(error) = this.worker_error() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.io).poll_write(cx, input);
        match result {
            Poll::Ready(Ok(written)) => {
                this.accepted = this.accepted.saturating_add(written as u64);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                this.shared.cancel();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = this.worker_error() {
            this.shared.cancel();
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.io).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.shared.cancel();
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(())) => this.poll_delivery(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(result) = Pin::new(&mut this.io).poll_shutdown(cx) {
            if let Err(error) = result {
                this.shared.cancel();
                return Poll::Ready(Err(error));
            }
        } else {
            return Poll::Pending;
        }

        let Some(completion) = &mut this.completion else {
            this.shared.cancel();
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/3 upload task ended without completion",
            )));
        };
        match ready!(Pin::new(completion).poll(cx)) {
            Ok(Ok(())) => {
                this.finished = true;
                this.completion = None;
                Poll::Ready(Ok(()))
            }
            Ok(Err(error)) => {
                this.shared.cancel();
                Poll::Ready(Err(h3_io_error(error)))
            }
            Err(_) => {
                this.shared.cancel();
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/3 upload task stopped",
                )))
            }
        }
    }
}

/// Response headers that have not arrived yet.
pub struct H3PendingResponse {
    headers: Option<oneshot::Receiver<Result<HeaderMap, H3Error>>>,
    body: Option<mpsc::Receiver<BodyEvent>>,
    response_is_bodyless: bool,
    cancel_on_drop: bool,
    shared: Arc<ExchangeShared>,
}

impl fmt::Debug for H3PendingResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("H3PendingResponse")
            .field("response_is_bodyless", &self.response_is_bodyless)
            .field("consumed", &self.headers.is_none())
            .finish_non_exhaustive()
    }
}

impl H3PendingResponse {
    pub async fn open(mut self) -> Result<H3ResponseBody, H3Error> {
        let Some(headers) = self.headers.take() else {
            self.cancel_on_drop = false;
            return Err(H3Error::ResponseConsumed);
        };
        let headers = match headers.await {
            Ok(Ok(headers)) => headers,
            Ok(Err(error)) => {
                self.cancel_on_drop = false;
                return Err(error);
            }
            Err(_) => {
                self.shared.cancel();
                self.cancel_on_drop = false;
                return Err(H3Error::ResponseTaskClosed);
            }
        };

        self.cancel_on_drop = false;
        let body = if self.response_is_bodyless {
            None
        } else {
            self.body.take()
        };
        Ok(H3ResponseBody {
            headers,
            trailers: None,
            body,
            pending: Bytes::new(),
            eof: self.response_is_bodyless,
            failure: None,
            shared: Arc::clone(&self.shared),
        })
    }
}

impl Drop for H3PendingResponse {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.shared.cancel();
        }
    }
}

/// Backpressured response body for one HTTP/3 request.
pub struct H3ResponseBody {
    headers: HeaderMap,
    trailers: Option<HeaderMap>,
    body: Option<mpsc::Receiver<BodyEvent>>,
    pending: Bytes,
    eof: bool,
    failure: Option<String>,
    shared: Arc<ExchangeShared>,
}

impl fmt::Debug for H3ResponseBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("H3ResponseBody")
            .field("headers", &self.headers)
            .field("trailers", &self.trailers)
            .field("eof", &self.eof)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl H3ResponseBody {
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn trailers(&self) -> Option<&HeaderMap> {
        self.trailers.as_ref()
    }

    fn fail(&mut self, message: String) -> io::Error {
        self.failure = Some(message.clone());
        self.shared.cancel();
        io::Error::new(io::ErrorKind::ConnectionReset, message)
    }
}

impl Drop for H3ResponseBody {
    fn drop(&mut self) {
        if !self.eof {
            self.shared.cancel();
        }
    }
}

impl AsyncRead for H3ResponseBody {
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
                let copied = this.pending.len().min(output.remaining());
                output.put_slice(&this.pending.split_to(copied));
                return Poll::Ready(Ok(()));
            }

            let Some(body) = &mut this.body else {
                return Poll::Ready(Err(
                    this.fail("HTTP/3 response task ended before EOF".to_owned())
                ));
            };
            match ready!(body.poll_recv(cx)) {
                Some(BodyEvent::Data(data)) => {
                    this.pending = data;
                }
                Some(BodyEvent::End(trailers)) => {
                    this.trailers = trailers;
                    this.body = None;
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(BodyEvent::Error(error)) => {
                    this.body = None;
                    return Poll::Ready(Err(this.fail(error.to_string())));
                }
                None => {
                    this.body = None;
                    return Poll::Ready(Err(
                        this.fail("HTTP/3 response task ended before EOF".to_owned())
                    ));
                }
            }
        }
    }
}

fn h3_io_error(error: H3Error) -> io::Error {
    io::Error::new(h3_io_error_kind(&error), error)
}

fn h3_io_error_kind(error: &H3Error) -> io::ErrorKind {
    match error {
        H3Error::Cancelled => io::ErrorKind::ConnectionReset,
        H3Error::UploadIo(source) => source.kind(),
        _ => io::ErrorKind::BrokenPipe,
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod candidate_scheduler_tests {
    use std::future::pending;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::num::NonZeroUsize;

    use super::*;

    fn addresses() -> [SocketAddr; 4] {
        [
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 443),
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443),
        ]
    }

    #[tokio::test(start_paused = true)]
    async fn candidate_order_and_delay_are_applied_before_a_winner() {
        let candidates = addresses();
        let winner = candidates[0];
        let starts = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let starts = Arc::clone(&starts);
            async move {
                let policy = HappyEyeballsConfig {
                    prioritize_ipv6: true,
                    interleave: 1,
                    try_delay: Duration::from_millis(10),
                    max_concurrent: NonZeroUsize::new(2).expect("nonzero concurrency"),
                };
                race_h3_candidates(&candidates, &policy, move |candidate| {
                    let starts = Arc::clone(&starts);
                    async move {
                        lock_unpoisoned(&starts).push(candidate);
                        if candidate == winner {
                            Ok(candidate)
                        } else {
                            pending::<Result<SocketAddr, H3Error>>().await
                        }
                    }
                })
                .await
            }
        });
        tokio::task::yield_now().await;
        assert_eq!(
            *lock_unpoisoned(&starts),
            vec![candidates[1]],
            "IPv6 preference must select the first attempt"
        );

        tokio::time::advance(Duration::from_millis(9)).await;
        tokio::task::yield_now().await;
        assert_eq!(*lock_unpoisoned(&starts), vec![candidates[1]]);

        tokio::time::advance(Duration::from_millis(1)).await;
        let selected = task
            .await
            .expect("candidate task")
            .expect("second candidate");
        assert_eq!(selected, winner);
        assert_eq!(*lock_unpoisoned(&starts), vec![candidates[1], winner]);
    }

    #[tokio::test(start_paused = true)]
    async fn max_concurrent_one_defers_the_next_candidate_until_failure() {
        let candidates = addresses();
        let first = candidates[0];
        let second = candidates[1];
        let starts = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let starts = Arc::clone(&starts);
            async move {
                let policy = HappyEyeballsConfig {
                    prioritize_ipv6: false,
                    interleave: 1,
                    try_delay: Duration::from_millis(10),
                    max_concurrent: NonZeroUsize::MIN,
                };
                race_h3_candidates(&candidates, &policy, move |candidate| {
                    let starts = Arc::clone(&starts);
                    async move {
                        lock_unpoisoned(&starts).push(candidate);
                        if candidate == first {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            Err(H3Error::NoResolvedCandidate)
                        } else {
                            Ok(candidate)
                        }
                    }
                })
                .await
            }
        });
        tokio::task::yield_now().await;
        assert_eq!(*lock_unpoisoned(&starts), vec![first]);

        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            *lock_unpoisoned(&starts),
            vec![first],
            "the delay must not exceed the concurrency bound"
        );

        tokio::time::advance(Duration::from_millis(10)).await;
        let selected = task
            .await
            .expect("candidate task")
            .expect("fallback candidate");
        assert_eq!(selected, second);
        assert_eq!(*lock_unpoisoned(&starts), vec![first, second]);
    }
}
