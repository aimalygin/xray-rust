//! The HTTP client of XDRIVE's storages, as Xray-core v26.10.31's
//! `newServiceClient` builds one: HTTP/1.1 or HTTP/2 over the stream's TLS
//! (Chrome's hello unless a fingerprint says otherwise) as the server picks
//! by ALPN, plain HTTP/1.1 for `http` URLs, every connection dialed to the
//! stream's `address` and `port` when set, through its masks, sockopt and
//! chain, Chrome's "fetch" headers on every request, Go's transparent gzip,
//! and a request that makes no progress for a minute ends.
//!
//! One [`ServiceClient`] holds the connections of one XMUX connection: one
//! HTTP/2 connection per host, as Go's transport with `MaxConnsPerHost` 1
//! keeps, or up to `max_conns` HTTP/1.1 connections per host once a host
//! answered over HTTP/1.1, which every client of a storage then knows.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_compression::tokio::bufread::GzipDecoder;
use bytes::Bytes;
use http::Method;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use xray_proxy::go_url;
use xray_routing::{Network, Target, TargetAddr};

use super::h2::H2Connection;
use crate::stream::http_headers::{serialize_request_with_framing, H1BodyFraming, HeaderMap};
use crate::stream::masquerade::apply_masquerade;
use crate::stream::xhttp::h1::PendingResponse;
use crate::{BoxedTransportStream, TlsClientConfig, TransportDialer, TransportError};

/// Xray-core's `driveTimeout`: a request that makes no progress for this
/// long ends, however long it runs while its bytes move.
pub(crate) const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// `net.ConnIdleTimeout`: an idle HTTP/1.1 connection closes after this.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Go's `ChromeH2KeepAlivePeriod`: an HTTP/2 connection silent this long is
/// pinged, unless `xmux.hKeepAlivePeriod` says otherwise.
pub(crate) const H2_KEEP_ALIVE: Duration = Duration::from_secs(45);
/// Go reads a request body at most this much at a time, each read counting
/// as progress.
const PROGRESS_CHUNK: usize = 16 << 10;

/// An `http` or `https` URL a request goes to, as Go's `url.Parse` reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceUrl {
    pub secure: bool,
    /// `URL.Hostname()`: without brackets or port.
    pub hostname: String,
    pub port: u16,
    /// `URL.Host`: what `Host` and `:authority` carry.
    pub authority: String,
    /// `URL.RequestURI()`.
    pub target: String,
}

impl ServiceUrl {
    /// `http.NewRequest`'s parse, and its transport's refusal of a scheme
    /// other than `http` and `https` or of a URL without a host.
    #[cfg(test)]
    pub(crate) fn parse(raw: &str) -> Result<Self, ServiceError> {
        let url = go_url::parse(raw)
            .map_err(|error| ServiceError::Request(format!("failed to build request > {error}")))?;
        Self::from_go(&url)
    }

    /// What Go's transport takes of a parsed URL, refusing one it cannot
    /// send.
    pub(crate) fn from_go(url: &go_url::Url) -> Result<Self, ServiceError> {
        let secure = match url.scheme.as_str() {
            "https" => true,
            "http" => false,
            other => {
                return Err(ServiceError::Request(format!(
                    "unsupported protocol scheme \"{other}\""
                )))
            }
        };
        if url.host.is_empty() {
            return Err(ServiceError::Request(
                "http: no Host in request URL".to_owned(),
            ));
        }
        let port = match url.port() {
            "" => {
                if secure {
                    443
                } else {
                    80
                }
            }
            digits => digits
                .parse::<u16>()
                .map_err(|_| ServiceError::Request(format!("invalid port {digits:?}")))?,
        };
        Ok(Self {
            secure,
            hostname: url.hostname().to_owned(),
            port,
            authority: url.host.clone(),
            target: url.request_uri(),
        })
    }

    fn scheme(&self) -> &'static str {
        if self.secure {
            "https"
        } else {
            "http"
        }
    }

    /// Go's connection pool key: the scheme and the host with its port.
    fn pool_key(&self) -> String {
        format!("{}://{}:{}", self.scheme(), self.hostname, self.port)
    }
}

/// One request: its method, URL, the headers Go's `Header.Set` would hold,
/// a body, and the most bytes of its answer to read before giving up.
#[derive(Clone, Debug)]
pub(crate) struct ServiceRequest {
    pub method: Method,
    pub url: ServiceUrl,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub max_body: usize,
}

/// An answer: its status, its first `Retry-After` and `Location` values and
/// the body read up to the request's limit and one byte past it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServiceResponse {
    pub status: u16,
    pub retry_after: Option<String>,
    pub location: Option<String>,
    pub body: Bytes,
}

/// Why a request failed before an answer came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServiceError {
    /// The request could not be built; it is never retried.
    Request(String),
    /// `errStalled`: no progress for [`STALL_TIMEOUT`].
    Stalled,
    /// The network failed: Go's `*net.OpError`, `io.EOF` and the like.
    Network(String),
    /// TLS or HTTP refused the exchange: not a network failure to Go.
    Protocol(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(message) | Self::Network(message) | Self::Protocol(message) => {
                f.write_str(message)
            }
            Self::Stalled => f.write_str("the request made no progress"),
        }
    }
}

impl ServiceError {
    /// Whether Xray-core's S3 client tries again after it: a stall, an
    /// ended or reset connection, a failed dial or lookup.
    pub(crate) fn retryable(&self) -> bool {
        matches!(self, Self::Stalled | Self::Network(_))
    }
}

fn transport_error(error: TransportError) -> ServiceError {
    match error {
        TransportError::Tls(io) => ServiceError::Protocol(format!("tls: {io}")),
        TransportError::TlsConfig(message) => ServiceError::Protocol(message),
        TransportError::InvalidTlsServerName(name) => {
            ServiceError::Protocol(format!("invalid TLS server name {name}"))
        }
        TransportError::UnsupportedTlsFingerprint(name)
        | TransportError::UnnegotiableTlsFingerprint(name) => {
            ServiceError::Protocol(format!("unusable TLS fingerprint {name}"))
        }
        other => ServiceError::Network(other.to_string()),
    }
}

/// How the connections of one storage are dialed.
#[derive(Clone)]
pub(crate) struct ServiceDialer {
    pub dialer: TransportDialer,
    /// The stream's TLS, its server name empty to take each host's.
    pub tls: TlsClientConfig,
    /// The stream's `address` and `port`: where every connection goes, the
    /// port only when nonzero.
    pub fronting: Option<(TargetAddr, u16)>,
    /// The HTTP/2 keepalive; `None` sends no PING.
    pub keep_alive: Option<Duration>,
    /// With `alpn` exactly `["h3"]`, `https` goes over HTTP/3 with these.
    pub h3: Option<crate::stream::H3QuicConfig>,
}

impl std::fmt::Debug for ServiceDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceDialer")
            .field("fronting", &self.fronting)
            .field("keep_alive", &self.keep_alive)
            .finish_non_exhaustive()
    }
}

impl ServiceDialer {
    /// Dials `url`'s host: TCP to the fronting address or the host, then
    /// TLS for `https`, the server name the host's unless the stream names
    /// one. True when the server picked HTTP/2.
    async fn connect(
        &self,
        url: &ServiceUrl,
    ) -> Result<(BoxedTransportStream, bool), ServiceError> {
        let (addr, port) = self.destination(url);
        let target = Target::new(addr, port, Network::Tcp);
        let candidates = self.candidates(&target).await?;
        let tls = url.secure.then(|| {
            let mut tls = self.tls.clone();
            if tls.server_name.is_empty() {
                tls.server_name = url.hostname.clone();
            }
            tls
        });
        let dial = self
            .dialer
            .connect_http_service(tls.as_ref(), &target, &candidates);
        // The dial outlives the request that started it, and a handshake that
        // hangs would keep the host's one connection to itself.
        let (stream, alpn) = tokio::time::timeout(STALL_TIMEOUT, dial)
            .await
            .map_err(|_| ServiceError::Stalled)?
            .map_err(transport_error)?;
        Ok((stream, alpn.as_deref() == Some(b"h2")))
    }

    /// Where a connection for `url` goes: the fronting address, with its
    /// port unless that is zero, or the URL's host and port.
    fn destination(&self, url: &ServiceUrl) -> (TargetAddr, u16) {
        match &self.fronting {
            Some((addr, port)) => (addr.clone(), if *port != 0 { *port } else { url.port }),
            None => match url.hostname.parse::<std::net::IpAddr>() {
                Ok(ip) => (TargetAddr::Ip(ip), url.port),
                Err(_) => (TargetAddr::Domain(url.hostname.clone()), url.port),
            },
        }
    }

    /// A QUIC connection for `url`'s host, as XHTTP's HTTP/3 dial makes
    /// one: to the fronting address or the host, the server name the host's
    /// unless the stream names one, through the stream's UDP masks.
    async fn connect_h3(
        &self,
        url: &ServiceUrl,
        quic: &crate::stream::H3QuicConfig,
    ) -> Result<crate::stream::xhttp::H3Client, ServiceError> {
        let (addr, port) = self.destination(url);
        let target = Target::new(addr, port, Network::Udp);
        if self.dialer.is_chained() {
            return Err(ServiceError::Request(
                "a storage over HTTP/3 cannot go through another outbound".to_owned(),
            ));
        }
        let candidates = self.candidates(&target).await?;
        let mut tls = self.tls.clone();
        if tls.server_name.is_empty() {
            tls.server_name = url.hostname.clone();
        }
        let material = self
            .dialer
            .h3_dial_material(&crate::ConnectorConfig::Tls(tls))
            .map_err(transport_error)?;
        let remote_addr = *candidates
            .first()
            .ok_or_else(|| ServiceError::Network(format!("no address for {}", url.hostname)))?;
        let realm = quic.udp_realm.as_ref().map(|_| self.dialer.realm_env());
        let config = crate::stream::H3ConnectConfig {
            remote_addr,
            server_name: material.server_name,
            tls_config: material.tls_config,
            socket_protector: material.socket_protector,
            quic: quic.clone(),
            realm,
        };
        let dial = crate::stream::xhttp::connect_h3_candidates(config, &candidates, None);
        tokio::time::timeout(STALL_TIMEOUT, dial)
            .await
            .map_err(|_| ServiceError::Stalled)?
            .map_err(|error| ServiceError::Network(format!("http3: {error}")))
    }

    async fn candidates(&self, target: &Target) -> Result<Vec<SocketAddr>, ServiceError> {
        match &target.addr {
            TargetAddr::Ip(ip) => Ok(vec![SocketAddr::new(*ip, target.port)]),
            // A chain resolves the name at its far end.
            TargetAddr::Domain(_) if self.dialer.is_chained() => Ok(Vec::new()),
            TargetAddr::Domain(domain) => self
                .dialer
                .service_resolver()
                .resolve(domain, target.port)
                .await
                .map(|address| vec![address])
                .map_err(|error| ServiceError::Network(error.to_string())),
        }
    }
}

/// The hosts of one storage that answered over HTTP/1.1, which every client
/// of the storage then reaches with more than one connection.
pub(crate) type Http1Hosts = Arc<Mutex<HashSet<String>>>;

/// The connections of one XMUX connection.
pub(crate) struct ServiceClient {
    dialer: Arc<ServiceDialer>,
    http1_hosts: Http1Hosts,
    max_conns: usize,
    hosts: Mutex<HashMap<String, Arc<HostConnections>>>,
}

impl std::fmt::Debug for ServiceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceClient")
            .field("max_conns", &self.max_conns)
            .finish_non_exhaustive()
    }
}

/// One host's connections.
struct HostConnections {
    /// The host's HTTP/3 connection, over `alpn` `["h3"]`.
    h3: tokio::sync::Mutex<Option<Arc<crate::stream::xhttp::H3Client>>>,
    /// Held while the host's one HTTP/2 connection is dialed, so the
    /// requests after the first wait for it instead of dialing their own.
    h2: tokio::sync::Mutex<Option<H2Connection>>,
    idle: Mutex<Vec<IdleConnection>>,
    /// One permit for each HTTP/1.1 request in flight.
    h1_slots: Arc<Semaphore>,
}

struct IdleConnection {
    stream: ProgressStream,
    since: Instant,
}

impl ServiceClient {
    pub(crate) fn new(
        dialer: Arc<ServiceDialer>,
        http1_hosts: Http1Hosts,
        max_conns: usize,
    ) -> Self {
        Self {
            dialer,
            http1_hosts,
            max_conns: max_conns.max(1),
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// Closes every connection: what a request still runs on closes with
    /// it, as when Xray-core cancels the connections' context.
    pub(crate) fn close(&self) {
        self.hosts.lock().unwrap().clear();
    }

    fn host(&self, url: &ServiceUrl) -> Arc<HostConnections> {
        let mut hosts = self.hosts.lock().unwrap();
        Arc::clone(hosts.entry(url.pool_key()).or_insert_with(|| {
            Arc::new(HostConnections {
                h3: tokio::sync::Mutex::new(None),
                h2: tokio::sync::Mutex::new(None),
                idle: Mutex::new(Vec::new()),
                h1_slots: Arc::new(Semaphore::new(self.max_conns)),
            })
        }))
    }

    /// Sends `request` and reads its answer, ending it once it makes no
    /// progress for [`STALL_TIMEOUT`].
    pub(crate) async fn send(
        &self,
        request: &ServiceRequest,
    ) -> Result<ServiceResponse, ServiceError> {
        let progress = Progress::new();
        tokio::select! {
            result = self.exchange(request, &progress) => result,
            () = progress.stalled(STALL_TIMEOUT) => Err(ServiceError::Stalled),
        }
    }

    async fn exchange(
        &self,
        request: &ServiceRequest,
        progress: &Progress,
    ) -> Result<ServiceResponse, ServiceError> {
        let prepared = Prepared::new(request);
        let host = self.host(&request.url);
        let http1 = !request.url.secure
            || self
                .http1_hosts
                .lock()
                .unwrap()
                .contains(&request.url.authority);
        if let Some(quic) = self.dialer.h3.as_ref().filter(|_| request.url.secure) {
            let mut slot = host.h3.lock().await;
            let client = match slot.as_ref().filter(|client| client.is_live()) {
                Some(client) => Arc::clone(client),
                None => {
                    let client = Arc::new(self.dialer.connect_h3(&request.url, quic).await?);
                    *slot = Some(Arc::clone(&client));
                    client
                }
            };
            drop(slot);
            return super::h3::send(&client, &prepared, progress).await;
        }
        if http1 {
            return self.http1(&host, &prepared, None, progress).await;
        }
        let mut slot = host.h2.lock().await;
        if let Some(connection) = slot.as_ref().filter(|connection| connection.is_live()) {
            let connection = connection.clone();
            drop(slot);
            return connection.send(&prepared, progress).await;
        }
        let (stream, h2) = self.dialer.connect(&request.url).await?;
        if h2 {
            let connection = H2Connection::handshake(stream, self.dialer.keep_alive).await?;
            *slot = Some(connection.clone());
            drop(slot);
            return connection.send(&prepared, progress).await;
        }
        drop(slot);
        // A host that answers over HTTP/1.1 moves to more connections.
        self.http1_hosts
            .lock()
            .unwrap()
            .insert(request.url.authority.clone());
        self.http1(&host, &prepared, Some(stream), progress).await
    }

    async fn http1(
        &self,
        host: &HostConnections,
        prepared: &Prepared<'_>,
        fresh: Option<BoxedTransportStream>,
        progress: &Progress,
    ) -> Result<ServiceResponse, ServiceError> {
        let _slot = Arc::clone(&host.h1_slots)
            .acquire_owned()
            .await
            .map_err(|_| ServiceError::Network("the client is closed".to_owned()))?;
        let stream = match fresh {
            Some(stream) => ProgressStream::new(stream),
            None => match take_idle(host) {
                Some(stream) => stream,
                None => {
                    let (stream, _) = self.dialer.connect(&prepared.request.url).await?;
                    ProgressStream::new(stream)
                }
            },
        };
        let (response, reusable) = send_http1(stream, prepared, progress).await?;
        if let Some(stream) = reusable {
            host.idle.lock().unwrap().push(IdleConnection {
                stream,
                since: Instant::now(),
            });
        }
        Ok(response)
    }
}

fn take_idle(host: &HostConnections) -> Option<ProgressStream> {
    let mut idle = host.idle.lock().unwrap();
    while let Some(connection) = idle.pop() {
        if connection.since.elapsed() < IDLE_TIMEOUT {
            return Some(connection.stream);
        }
    }
    None
}

/// A request with the headers Go's transport sends: Chrome's "fetch" block
/// unless the request names another browser or a user agent of its own, and
/// `Accept-Encoding: gzip` when it asks for no encoding and no range.
pub(crate) struct Prepared<'a> {
    pub request: &'a ServiceRequest,
    pub headers: HeaderMap,
    /// Whether the transport asked for gzip, and so decodes it.
    pub gzip: bool,
}

impl<'a> Prepared<'a> {
    pub(crate) fn new(request: &'a ServiceRequest) -> Self {
        let mut headers = HeaderMap::new();
        for (name, value) in &request.headers {
            headers.set(&canonical_header_key(name), value);
        }
        // net/http and http2 would send their own user agent after a hello
        // of Chrome.
        apply_masquerade(&mut headers, "fetch");
        let gzip = headers.get("Accept-Encoding").unwrap_or("").is_empty()
            && headers.get("Range").unwrap_or("").is_empty()
            && request.method != Method::HEAD;
        if gzip {
            headers.remove("Accept-Encoding");
        }
        Self {
            request,
            headers,
            gzip,
        }
    }
}

/// Go's `textproto.CanonicalMIMEHeaderKey`, which `Header.Set` applies.
pub(crate) fn canonical_header_key(name: &str) -> String {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return name.to_owned();
    }
    let mut upper = true;
    name.bytes()
        .map(|byte| {
            let byte = if upper {
                byte.to_ascii_uppercase()
            } else {
                byte.to_ascii_lowercase()
            };
            upper = byte == b'-';
            char::from(byte)
        })
        .collect()
}

/// One HTTP/1.1 exchange on `stream`, as Go's `Request.Write` writes it:
/// `Host`, `User-Agent`, the body's framing, the headers sorted, then the
/// transport's own `Accept-Encoding`.
async fn send_http1(
    mut stream: ProgressStream,
    prepared: &Prepared<'_>,
    progress: &Progress,
) -> Result<(ServiceResponse, Option<ProgressStream>), ServiceError> {
    stream.progress = Some(progress.clone());
    let request = prepared.request;
    let method = request.method.as_str();
    let body = &request.body;
    // Go's transferWriter: an explicit zero length for every empty identity
    // request but GET and HEAD.
    let framing = if body.is_empty() && matches!(method, "GET" | "HEAD") {
        H1BodyFraming::None
    } else {
        H1BodyFraming::ContentLength(body.len() as u64)
    };
    let mut head = serialize_request_with_framing(
        method,
        &request.url.target,
        &request.url.authority,
        &prepared.headers,
        framing,
    );
    if prepared.gzip {
        head.truncate(head.len() - 2);
        head.extend_from_slice(b"Accept-Encoding: gzip\r\n\r\n");
    }
    let network = |error: io::Error| ServiceError::Network(error.to_string());
    stream.write_all(&head).await.map_err(network)?;
    for chunk in body.chunks(PROGRESS_CHUNK) {
        stream.write_all(chunk).await.map_err(network)?;
    }
    stream.flush().await.map_err(network)?;
    let (status, mut response) = PendingResponse::new(stream)
        .for_request_method(method)
        .open_with_status()
        .await
        .map_err(|error| match error {
            crate::stream::xhttp::h1::H1Error::Io(error) => network(error),
            other => ServiceError::Network(other.to_string()),
        })?;
    let retry_after = response
        .retry_after()
        .map(|value| String::from_utf8_lossy(value).into_owned());
    let location = response
        .location()
        .map(|value| String::from_utf8_lossy(value).into_owned());
    let gzip = prepared.gzip
        && response
            .content_encoding()
            .is_some_and(|encoding| encoding.eq_ignore_ascii_case(b"gzip"));
    let mut raw = Vec::new();
    let limit = request.max_body.saturating_add(1);
    if gzip {
        let mut encoded = Vec::new();
        response.read_to_end(&mut encoded).await.map_err(network)?;
        raw = gunzip(&encoded, limit).await?;
    } else {
        (&mut response)
            .take(limit as u64)
            .read_to_end(&mut raw)
            .await
            .map_err(network)?;
    }
    let reusable = response.is_complete();
    let stream = if reusable {
        match response.into_reusable() {
            Ok((stream, leftover)) if leftover.is_empty() => Some(stream),
            _ => None,
        }
    } else {
        None
    };
    let mut stream = stream;
    if let Some(stream) = stream.as_mut() {
        stream.progress = None;
    }
    Ok((
        ServiceResponse {
            status,
            retry_after,
            location,
            body: Bytes::from(raw),
        },
        stream,
    ))
}

/// Decodes a gzip body, up to `limit` bytes of it.
pub(crate) async fn gunzip(encoded: &[u8], limit: usize) -> Result<Vec<u8>, ServiceError> {
    let mut decoded = Vec::new();
    GzipDecoder::new(encoded)
        .take(limit as u64)
        .read_to_end(&mut decoded)
        .await
        .map_err(|error| ServiceError::Network(format!("gzip: {error}")))?;
    Ok(decoded)
}

/// When a request last moved a byte of either body.
#[derive(Clone)]
pub(crate) struct Progress {
    started: Instant,
    /// Milliseconds after `started`.
    last: Arc<AtomicU64>,
}

impl Progress {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            last: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Notes that bytes moved.
    pub(crate) fn alive(&self) {
        let elapsed = self.started.elapsed().as_millis() as u64;
        self.last.fetch_max(elapsed, Ordering::Relaxed);
    }

    /// Resolves once nothing moved for `stall`.
    async fn stalled(&self, stall: Duration) {
        loop {
            let last = self.started + Duration::from_millis(self.last.load(Ordering::Relaxed));
            let deadline = last + stall;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// A connection whose reads and writes count as the progress of the request
/// on it.
pub(crate) struct ProgressStream {
    inner: BoxedTransportStream,
    progress: Option<Progress>,
}

impl ProgressStream {
    fn new(inner: BoxedTransportStream) -> Self {
        Self {
            inner,
            progress: None,
        }
    }
}

impl AsyncRead for ProgressStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            if let Some(progress) = &self.progress {
                progress.alive();
            }
        }
        result
    }
}

impl AsyncWrite for ProgressStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(written)) = &result {
            if *written > 0 {
                if let Some(progress) = &self.progress {
                    progress.alive();
                }
            }
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_read_as_go_reads_them() {
        let url = ServiceUrl::parse("https://bucket.s3.example/key%20one?x=1").unwrap();
        assert_eq!(
            url,
            ServiceUrl {
                secure: true,
                hostname: "bucket.s3.example".to_owned(),
                port: 443,
                authority: "bucket.s3.example".to_owned(),
                target: "/key%20one?x=1".to_owned(),
            }
        );
        let url = ServiceUrl::parse("http://[::1]:9000").unwrap();
        assert_eq!(
            (
                url.hostname.as_str(),
                url.port,
                url.authority.as_str(),
                url.target.as_str()
            ),
            ("::1", 9000, "[::1]:9000", "/")
        );
        assert!(matches!(
            ServiceUrl::parse("ftp://host/x"),
            Err(ServiceError::Request(_))
        ));
        assert!(ServiceUrl::parse("https:///x").is_err());
        assert!(ServiceUrl::parse("https://host:99999/").is_err());
        assert!(ServiceUrl::parse("https://host/%zz").is_err());
    }

    #[test]
    fn header_keys_canonicalize_as_go_does() {
        assert_eq!(canonical_header_key("content-type"), "Content-Type");
        assert_eq!(canonical_header_key("X-AMZ-DATE"), "X-Amz-Date");
        assert_eq!(canonical_header_key("dnt"), "Dnt");
        assert_eq!(canonical_header_key("bad key"), "bad key");
    }

    #[test]
    fn the_transport_asks_for_gzip_unless_the_request_says_otherwise() {
        let request = |headers: &[(&str, &str)], method: Method| ServiceRequest {
            method,
            url: ServiceUrl::parse("https://host/").unwrap(),
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: Bytes::new(),
            max_body: 1,
        };
        let gzip = |headers: &[(&str, &str)], method| Prepared::new(&request(headers, method)).gzip;
        assert!(gzip(&[], Method::GET));
        assert!(gzip(&[("accept-encoding", "")], Method::GET));
        assert!(!gzip(&[("Accept-Encoding", "br")], Method::GET));
        assert!(!gzip(&[("range", "bytes=0-1")], Method::GET));
        assert!(!gzip(&[], Method::HEAD));
        let put = request(&[("x-custom", "1")], Method::PUT);
        let prepared = Prepared::new(&put);
        assert_eq!(prepared.headers.get("X-Custom"), Some("1"));
        assert!(prepared
            .headers
            .get("User-Agent")
            .is_some_and(|ua| ua.contains("Chrome/")));
        assert_eq!(prepared.headers.get("Sec-Fetch-Mode"), Some("cors"));
        let custom = request(&[("user-agent", "custom/1.0")], Method::GET);
        let custom = Prepared::new(&custom);
        assert_eq!(custom.headers.get("User-Agent"), Some("custom/1.0"));
        assert_eq!(custom.headers.get("Sec-Fetch-Mode"), None);
    }
    #[test]
    fn connections_go_to_the_fronting_address_or_the_urls_host() {
        let dialer = |fronting| ServiceDialer {
            dialer: TransportDialer::system().unwrap(),
            tls: TlsClientConfig {
                server_name: String::new(),
                allow_insecure: false,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: Vec::new(),
                fingerprint: None,
            },
            fronting,
            keep_alive: None,
            h3: None,
        };
        let url = ServiceUrl::parse("https://bucket.s3.example:8443/key").unwrap();
        let front = TargetAddr::Domain("front.example".to_owned());
        assert_eq!(
            dialer(None).destination(&url),
            (TargetAddr::Domain("bucket.s3.example".to_owned()), 8443)
        );
        assert_eq!(
            dialer(Some((front.clone(), 443))).destination(&url),
            (front.clone(), 443)
        );
        // Port zero keeps the URL's.
        assert_eq!(
            dialer(Some((front.clone(), 0))).destination(&url),
            (front, 8443)
        );
        let ip = ServiceUrl::parse("http://[::1]:9000/").unwrap();
        assert_eq!(
            dialer(None).destination(&ip),
            (TargetAddr::Ip("::1".parse().unwrap()), 9000)
        );
    }
}
