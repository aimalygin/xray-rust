//! CONNECT-IP over HTTP/2, as Xray-core v26.10.31's `dialHTTP2` opens it
//! with its own HTTP/2 client: one connection per tunnel, that client's
//! SETTINGS and windows, extended CONNECT (RFC 8441) and the packets in
//! DATAGRAM capsules on the request stream.
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::AbortHandle;
use tokio::time::Instant;

use super::capsule::IpPrefix;
use super::request::{ascii_authority, h2_request_fields, MasqueRequest};
use super::session::{
    self, Addressing, Datagrams, HttpConnection, MasqueError, MasqueTunnel, RequestRecv,
    RequestSend,
};

/// Xray's HTTP/2 client SETTINGS and windows: `http2HeaderTableSize`,
/// `http2StreamWindow`, `http2MaxHeaderListSize`, `http2ConnectionWindow`.
const HEADER_TABLE_SIZE: u32 = 64 << 10;
const STREAM_WINDOW: u32 = 6 << 20;
const MAX_HEADER_LIST_SIZE: u32 = 256 << 10;
const CONNECTION_WINDOW: u32 = 15 << 20;
/// Xray's `http2WindowUpdateSize`: the stream's window opens again in
/// steps of this many bytes read.
const WINDOW_UPDATE_SIZE: u32 = 1 << 20;
/// Xray's `http2PingTimeout`: an unanswered PING closes the connection
/// after this long without a frame.
const PING_TIMEOUT: Duration = Duration::from_secs(15);
/// Go's `ChromeH2KeepAlivePeriod`, MASQUE's HTTP/2 keepalive unless
/// `xmux.hKeepAlivePeriod` sets one.
pub const H2_KEEP_ALIVE: Duration = Duration::from_secs(45);
/// Xray's `requestProtocol`.
const CONNECT_IP: &str = "connect-ip";

/// One CONNECT-IP dial over an HTTP/2 connection the caller opened.
#[derive(Debug, Clone)]
pub struct MasqueH2Config {
    /// The request authority, from [`super::authority`].
    pub authority: String,
    pub request: MasqueRequest,
    /// How long the connection may stay silent before a PING; `None` sends
    /// none, as a negative `hKeepAlivePeriod` asks.
    pub keep_alive: Option<Duration>,
    /// Cloudflare WARP's addresses: its plain CONNECT and bare capsules
    /// instead of extended CONNECT. The caller authenticated the TLS.
    pub warp: Option<Vec<IpPrefix>>,
}

/// Opens a tunnel over `io`, a TLS stream that negotiated `h2`. The caller
/// bounds the whole establishment with Xray's ten-second deadline; dropping
/// the future closes the connection.
pub async fn dial_h2<S>(io: S, config: MasqueH2Config) -> Result<MasqueTunnel, MasqueError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let last_frame = Arc::new(LastFrame::new());
    let io = Watched {
        io,
        last_frame: Arc::clone(&last_frame),
    };
    let (send_request, mut connection) = h2::client::Builder::new()
        .header_table_size(HEADER_TABLE_SIZE)
        .enable_push(false)
        .initial_window_size(STREAM_WINDOW)
        .max_header_list_size(MAX_HEADER_LIST_SIZE)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .stream_window_update_threshold(WINDOW_UPDATE_SIZE)
        // Xray's header block: no dynamic table, `:authority` second, and
        // Go's choice of each field's representation.
        .send_header_table_size_limit(0)
        .authority_after_method(true)
        .go_hpack_choices(true)
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|error| MasqueError::Dial(error.to_string()))?;
    let ping_pong = connection.ping_pong();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let connection = driver.abort_handle();
    let mut tasks = vec![driver];
    if let (Some(period), Some(ping_pong)) = (config.keep_alive, ping_pong) {
        tasks.push(tokio::spawn(keep_alive(
            ping_pong, last_frame, period, connection,
        )));
    }
    match open(send_request.clone(), &config).await {
        Ok((send, recv)) => {
            session::start(
                RequestSend::H2(send),
                RequestRecv::H2(recv),
                Datagrams::Capsules {
                    bare: config.warp.is_some(),
                },
                HttpConnection::Http2 {
                    _send_request: send_request,
                    tasks,
                },
                match &config.warp {
                    Some(addresses) => Addressing::Fixed(addresses.clone()),
                    None => Addressing::Request,
                },
            )
            .await
        }
        Err(error) => {
            for task in &tasks {
                task.abort();
            }
            Err(error)
        }
    }
}

/// Xray's `HTTP2ClientConn.Dial` on its client: after the server's first
/// SETTINGS, which must enable extended CONNECT, the request and a 2xx
/// response.
async fn open(
    mut send_request: h2::client::SendRequest<Bytes>,
    config: &MasqueH2Config,
) -> Result<(h2::SendStream<Bytes>, h2::RecvStream), MasqueError> {
    let failed = |error: &dyn std::fmt::Display| {
        MasqueError::Request(format!("connect-ip: failed to send request: {error}"))
    };
    poll_fn(|cx| send_request.poll_remote_settings(cx))
        .await
        .map_err(|error| failed(&error))?;
    let warp = config.warp.is_some();
    if !warp && !send_request.is_extended_connect_protocol_enabled() {
        return Err(failed(&"http2: the server did not enable extended CONNECT"));
    }
    // A non-ASCII host goes out in punycode, as over HTTP/3.
    let authority = ascii_authority(&config.authority)
        .ok_or_else(|| MasqueError::Request("connect-ip: invalid request authority".to_owned()))?;
    let mut builder = Request::builder().method(Method::CONNECT);
    // Cloudflare's tunnel is a plain CONNECT to the authority with a port,
    // named by its header instead of `:protocol`, without Capsule-Protocol.
    let fields = if warp {
        builder = builder.uri(warp_authority(&authority));
        h2_request_fields(
            &config.request,
            &[
                ("Cf-Connect-Proto", "cf-connect-ip"),
                ("Pq-Enabled", "false"),
            ],
        )
    } else {
        builder = builder
            .uri(format!("https://{authority}{}", config.request.path))
            .extension(h2::ext::Protocol::from_static(CONNECT_IP));
        h2_request_fields(&config.request, &[("Capsule-Protocol", "?1")])
    };
    for (name, value) in fields {
        builder = builder.header(name, value);
    }
    let request = builder.body(()).map_err(|error| {
        MasqueError::Request(format!("connect-ip: failed to create request: {error}"))
    })?;
    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|error| failed(&error))?;
    let response = response.await.map_err(|error| failed(&error))?;
    let status = response.status().as_u16();
    if !(200..=299).contains(&status) {
        return Err(MasqueError::Status(status));
    }
    Ok((send, response.into_body()))
}

/// Xray's Cloudflare `Host`: the authority, with port 443 when Go's
/// `net.SplitHostPort` finds none.
fn warp_authority(authority: &str) -> String {
    let has_port = match authority.strip_prefix('[') {
        Some(rest) => rest
            .split_once(']')
            .is_some_and(|(_, after)| after.starts_with(':')),
        None => authority.matches(':').count() == 1,
    };
    if has_port {
        return authority.to_owned();
    }
    let host = authority.trim_matches(|c| c == '[' || c == ']');
    if host.contains(':') {
        format!("[{host}]:443")
    } else {
        format!("{host}:443")
    }
}

/// Xray's `keepAlive`: a PING once the connection has been silent for
/// `period`, and the connection closed when nothing arrives within
/// [`PING_TIMEOUT`] of it.
pub(crate) async fn keep_alive(
    mut ping_pong: h2::PingPong,
    last_frame: Arc<LastFrame>,
    period: Duration,
    connection: AbortHandle,
) {
    let tick = (period.min(PING_TIMEOUT) / 3).max(Duration::from_secs(1));
    let mut ticker = tokio::time::interval_at(Instant::now() + tick, tick);
    let mut ping_at = None;
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            pong = poll_fn(|cx| ping_pong.poll_pong(cx)), if awaiting_pong => {
                awaiting_pong = false;
                if pong.is_err() {
                    return;
                }
                continue;
            }
        }
        if let Some(at) = ping_at {
            if last_frame.at() < at {
                // Xray's `errHTTP2IdleTimeout`: stopping the driver closes
                // the connection, and the tunnel with the reader's error.
                if last_frame.since(at) >= PING_TIMEOUT {
                    connection.abort();
                    return;
                }
                continue;
            }
            ping_at = None;
        }
        if last_frame.elapsed() >= period {
            ping_at = Some(last_frame.now());
            // h2 keeps one PING outstanding; frames since the last one keep
            // the connection alive meanwhile.
            if !awaiting_pong {
                if ping_pong.send_ping(h2::Ping::opaque()).is_err() {
                    return;
                }
                awaiting_pong = true;
            }
        }
    }
}

/// When the connection last received anything, in nanoseconds since it
/// opened, as Xray's `lastFrame`.
#[derive(Debug)]
pub(crate) struct LastFrame {
    epoch: Instant,
    nanos: AtomicU64,
}

impl LastFrame {
    pub(crate) fn new() -> Self {
        Self {
            epoch: Instant::now(),
            nanos: AtomicU64::new(0),
        }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.nanos.fetch_max(self.now(), Ordering::AcqRel);
    }

    fn at(&self) -> u64 {
        self.nanos.load(Ordering::Acquire)
    }

    /// How long ago `at` was.
    fn since(&self, at: u64) -> Duration {
        Duration::from_nanos(self.now().saturating_sub(at))
    }

    fn elapsed(&self) -> Duration {
        self.since(self.at())
    }
}

/// The connection's stream, noting each read as a frame received.
pub(crate) struct Watched<S> {
    pub(crate) io: S,
    pub(crate) last_frame: Arc<LastFrame>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.last_frame.touch();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
