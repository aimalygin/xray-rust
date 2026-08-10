//! Xray's WebSocket transport: an RFC 6455 client over the secured stream.
//!
//! Xray dials through gorilla/websocket, which builds the handshake as an
//! ordinary `http.Request` and writes it with `req.Write` — the same Go
//! serialization the rest of this module reproduces. Four headers come from
//! gorilla itself (`Upgrade`, `Connection`, `Sec-WebSocket-Key`,
//! `Sec-WebSocket-Version`), the browser-masquerade block and the config's own
//! headers come from `wsSettings.GetRequestHeader()`.
//!
//! # Early data
//!
//! With `?ed=N` in the path, nothing touches the network until the layer above
//! makes its first write. If that write fits in `N` bytes it travels inside
//! `Sec-WebSocket-Protocol` as unpadded base64url and no frame is sent for it;
//! if it does not fit, early data is dropped for the whole connection rather
//! than truncated. The boundary is inclusive. Note that two base64 variants
//! appear in one handshake: `Sec-WebSocket-Key` is standard base64 *with*
//! padding, early data is base64url *without* — easy to get backwards.
//!
//! # Response validation
//!
//! Looser than HTTPUpgrade's, because gorilla is looser: the status *code* is
//! compared but not the reason phrase, `Upgrade` and `Connection` are matched
//! as token lists rather than exact strings, and `Sec-WebSocket-Accept` must
//! equal the RFC's digest of the key we sent.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use rand::{rngs::OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{interval_at, Instant, Interval, MissedTickBehavior};

use super::http_headers::websocket_request_target;
use super::websocket_frame::{
    encode_client_frames, encode_frame, FrameDecoder, FrameEvent, OPCODE_CLOSE, OPCODE_PING,
    OPCODE_PONG,
};
use super::{apply_masquerade, serialize_request, HeaderMap};
use crate::{BoxedTransportStream, TransportError, TransportStream};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_RESPONSE_HEAD: usize = 64 * 1024;
const READ_CHUNK: usize = 16 * 1024;

/// `websocket.CloseNormalClosure` with no reason text.
const CLOSE_NORMAL: u16 = 1000;

/// The headers gorilla writes itself. A config that also sets one makes
/// gorilla fail the dial with "duplicate header not allowed", so it fails here
/// too rather than silently sending something Xray never would.
const GORILLA_OWNED_HEADERS: &[&str] = &[
    "Upgrade",
    "Connection",
    "Sec-Websocket-Key",
    "Sec-Websocket-Version",
    "Sec-Websocket-Extensions",
];

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (chunk.get(1).copied().map_or(0, u32::from) << 8)
            | chunk.get(2).copied().map_or(0, u32::from);
        let symbols = chunk.len() + 1;
        for index in 0..symbols {
            let shift = 18 - index * 6;
            out.push(alphabet[((bits >> shift) & 0x3f) as usize] as char);
        }
        if pad {
            for _ in symbols..4 {
                out.push('=');
            }
        }
    }
    out
}

/// `base64(SHA1(key + GUID))`, the RFC 6455 accept-key derivation.
///
/// Standard base64 with padding here — unlike early data, which is base64url
/// without.
pub fn accept_key_for(client_key: &str) -> String {
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64_encode(&hasher.finalize(), STANDARD_ALPHABET, true)
}

/// Base64url without padding, matching Xray's `base64.RawURLEncoding`.
pub fn encode_early_data(payload: &[u8]) -> String {
    base64_encode(payload, URL_ALPHABET, false)
}

/// Everything the WebSocket dial needs, resolved from config plus the security
/// layer's server name.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Normalized path, possibly carrying a real query string. Unlike
    /// HTTPUpgrade, `?` is **not** escaped here.
    pub path: String,
    /// `Host` header: config `host`, else the TLS server name, else the
    /// destination address. Never carries a port.
    pub host: String,
    pub headers: Vec<(String, String)>,
    /// From `?ed=N`. Zero disables early data entirely.
    pub early_data_bytes: u32,
    /// Seconds between client pings; zero means no keepalive.
    pub heartbeat_period_secs: u32,
}

pub async fn connect_websocket(
    stream: BoxedTransportStream,
    config: &WebSocketConfig,
) -> Result<BoxedTransportStream, TransportError> {
    if config.early_data_bytes == 0 {
        let ready = handshake(stream, config.clone(), None).await?;
        return Ok(Box::new(ready));
    }

    Ok(Box::new(DeferredWebSocketStream::new(
        stream,
        config.clone(),
    )))
}

async fn handshake(
    mut stream: BoxedTransportStream,
    config: WebSocketConfig,
    early_data: Option<Vec<u8>>,
) -> Result<WebSocketStream, TransportError> {
    let leftover = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        exchange(&mut stream, &config, early_data.as_deref()),
    )
    .await
    .map_err(|_| {
        TransportError::WebSocketProtocol("handshake timed out after 8 seconds".to_owned())
    })??;

    Ok(WebSocketStream::new(
        stream,
        leftover,
        config.heartbeat_period_secs,
    ))
}

/// Writes the handshake and validates the response, returning any bytes that
/// arrived behind it.
async fn exchange(
    stream: &mut BoxedTransportStream,
    config: &WebSocketConfig,
    early_data: Option<&[u8]>,
) -> Result<Vec<u8>, TransportError> {
    let mut headers = HeaderMap::new();
    for (key, value) in &config.headers {
        if GORILLA_OWNED_HEADERS
            .iter()
            .any(|owned| owned.eq_ignore_ascii_case(key))
        {
            return Err(TransportError::WebSocketProtocol(format!(
                "duplicate header not allowed: {key}"
            )));
        }
        headers.set(key, value);
    }
    apply_masquerade(&mut headers, "ws");

    let key = client_key();
    headers.set("Upgrade", "websocket");
    headers.set("Connection", "Upgrade");
    headers.set("Sec-WebSocket-Key", &key);
    headers.set("Sec-WebSocket-Version", "13");
    if let Some(early_data) = early_data {
        headers.set("Sec-WebSocket-Protocol", &encode_early_data(early_data));
    }

    let target = websocket_request_target(&config.path)
        .map_err(|error| TransportError::WebSocketProtocol(error.to_owned()))?;
    let request = serialize_request("GET", &target, &config.host, &headers);
    stream
        .write_all(&request)
        .await
        .map_err(TransportError::Tcp)?;

    read_and_validate_response(stream, &key).await
}

/// 16 random bytes in standard base64, as RFC 6455 §4.1 requires.
fn client_key() -> String {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    base64_encode(&nonce, STANDARD_ALPHABET, true)
}

async fn read_and_validate_response(
    stream: &mut BoxedTransportStream,
    sent_key: &str,
) -> Result<Vec<u8>, TransportError> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.map_err(TransportError::Tcp)?;
        if read == 0 {
            return Err(TransportError::WebSocketProtocol(
                "connection closed before the handshake response".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        if buffer.len() > MAX_RESPONSE_HEAD {
            return Err(TransportError::WebSocketProtocol(
                "handshake response headers exceeded 64 KiB".to_owned(),
            ));
        }
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");

    // gorilla compares `resp.StatusCode != 101` and never looks at the reason
    // phrase, so neither do we.
    let status = lines.next().unwrap_or_default();
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    if code != Some(101) {
        return Err(TransportError::WebSocketProtocol(format!(
            "handshake was answered with `{status}`"
        )));
    }

    let mut upgrade_ok = false;
    let mut connection_ok = false;
    let mut accept = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade_ok |= token_list_contains(value, "websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection_ok |= token_list_contains(value, "upgrade");
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") && accept.is_none() {
            accept = Some(value.to_owned());
        }
    }

    if !upgrade_ok {
        return Err(TransportError::WebSocketProtocol(
            "response Upgrade does not list `websocket`".to_owned(),
        ));
    }
    if !connection_ok {
        return Err(TransportError::WebSocketProtocol(
            "response Connection does not list `upgrade`".to_owned(),
        ));
    }
    if accept.as_deref() != Some(accept_key_for(sent_key).as_str()) {
        return Err(TransportError::WebSocketProtocol(
            "Sec-WebSocket-Accept does not match the key we sent".to_owned(),
        ));
    }

    Ok(buffer[header_end + 4..].to_vec())
}

/// gorilla's `tokenListContainsValue`: a comma-separated list, compared
/// case-insensitively. This is where WebSocket is laxer than HTTPUpgrade,
/// which demands the whole header equal one token.
fn token_list_contains(header: &str, wanted: &str) -> bool {
    header
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case(wanted))
}

// ---- The framed stream ------------------------------------------------------

pub(crate) struct WebSocketStream {
    inner: BoxedTransportStream,
    decoder: FrameDecoder,
    /// Decoded payload not yet handed to the caller.
    pending: Vec<u8>,
    pending_pos: usize,
    /// Encoded frames not yet written to the socket.
    out: Vec<u8>,
    out_pos: usize,
    scratch: Vec<u8>,
    heartbeat: Option<Interval>,
    peer_closed: bool,
    close_queued: bool,
}

impl WebSocketStream {
    fn new(inner: BoxedTransportStream, leftover: Vec<u8>, heartbeat_period_secs: u32) -> Self {
        let mut decoder = FrameDecoder::new();
        decoder.extend(&leftover);

        // Xray sleeps one period *before* its first ping, so the interval must
        // not fire immediately the way `tokio::time::interval` would. Tying it
        // to the stream instead of a spawned task also means it cannot outlive
        // the connection, which Xray's goroutine does by up to one period.
        let heartbeat = (heartbeat_period_secs > 0).then(|| {
            let period = Duration::from_secs(u64::from(heartbeat_period_secs));
            let mut interval = interval_at(Instant::now() + period, period);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            interval
        });

        Self {
            inner,
            decoder,
            pending: Vec::new(),
            pending_pos: 0,
            out: Vec::new(),
            out_pos: 0,
            scratch: vec![0u8; READ_CHUNK],
            heartbeat,
            peer_closed: false,
            close_queued: false,
        }
    }

    fn deliver(&mut self, output: &mut ReadBuf<'_>) -> bool {
        let remaining = &self.pending[self.pending_pos..];
        let take = remaining.len().min(output.remaining());
        if take == 0 {
            return false;
        }

        output.put_slice(&remaining[..take]);
        self.pending_pos += take;
        if self.pending_pos == self.pending.len() {
            self.pending = Vec::new();
            self.pending_pos = 0;
        }
        true
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let written = match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..])
            {
                Poll::Ready(Ok(written)) => written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += written;
        }

        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Queues a ping for every period that has elapsed. Empty payload, as
    /// Xray's `WriteControl(PingMessage, []byte{}, ...)` sends.
    fn queue_due_pings(&mut self, cx: &mut Context<'_>) {
        let Some(interval) = self.heartbeat.as_mut() else {
            return;
        };
        while interval.poll_tick(cx).is_ready() {
            encode_frame(&mut self.out, OPCODE_PING, true, &[]);
        }
    }
}

impl AsyncRead for WebSocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Control frames the read path itself produced -- pongs, and pings the
        // keepalive is due to send -- ride out on whichever poll notices them.
        this.queue_due_pings(cx);
        if let Poll::Ready(Err(error)) = this.poll_flush_out(cx) {
            return Poll::Ready(Err(error));
        }

        loop {
            if this.deliver(output) {
                return Poll::Ready(Ok(()));
            }
            if this.peer_closed {
                return Poll::Ready(Ok(()));
            }

            match this.decoder.next_event().map_err(protocol_io_error)? {
                Some(FrameEvent::Payload(payload)) => {
                    this.pending = payload;
                    this.pending_pos = 0;
                    continue;
                }
                Some(FrameEvent::Pong(payload)) => {
                    encode_frame(&mut this.out, OPCODE_PONG, true, &payload);
                    if let Poll::Ready(Err(error)) = this.poll_flush_out(cx) {
                        return Poll::Ready(Err(error));
                    }
                    continue;
                }
                Some(FrameEvent::Close) => {
                    this.peer_closed = true;
                    return Poll::Ready(Ok(()));
                }
                None => {}
            }

            let filled = {
                let mut buffer = ReadBuf::new(&mut this.scratch);
                match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                    Poll::Ready(Ok(())) => buffer.filled().len(),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            };
            if filled == 0 {
                // The socket ended without a close frame. Report EOF rather
                // than an error: a half-closed relay is ordinary.
                this.peer_closed = true;
                return Poll::Ready(Ok(()));
            }
            let (chunk, decoder) = (&this.scratch[..filled], &mut this.decoder);
            decoder.extend(chunk);
        }
    }
}

impl AsyncWrite for WebSocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Anything already queued goes first, so a frame is never interleaved
        // with a half-written one.
        match this.poll_flush_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        this.out = encode_client_frames(input);
        this.out_pos = 0;
        if let Poll::Ready(Err(error)) = this.poll_flush_out(cx) {
            return Poll::Ready(Err(error));
        }

        // The frames are ours now; whatever is left drains on the next poll.
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_out(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Xray writes a close frame before closing the socket, so a peer sees
        // 1000 rather than a bare FIN.
        if !this.close_queued {
            encode_frame(
                &mut this.out,
                OPCODE_CLOSE,
                true,
                &CLOSE_NORMAL.to_be_bytes(),
            );
            this.close_queued = true;
        }

        match this.poll_flush_out(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl TransportStream for WebSocketStream {
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

// ---- The deferred dial, for `ed > 0` ----------------------------------------

enum DeferredState {
    /// Nothing has touched the network yet.
    Waiting(Box<(BoxedTransportStream, WebSocketConfig)>),
    /// The first write was copied into owned state and accepted; the task now
    /// completes the handshake and, when it exceeded the ED budget, sends it
    /// as the first frame before handing the stream back.
    Dialing(tokio::task::JoinHandle<Result<WebSocketStream, TransportError>>),
    Ready(Box<WebSocketStream>),
    Failed,
}

/// Holds the connection unopened until the layer above writes.
///
/// Xray's `delayDialConn` does the same, and blocks reads until that write
/// happens. VLESS always writes its request header first, so the block is
/// theoretical — but it is reproduced rather than papered over, because
/// dialing early would put a handshake on the wire that carries no early data
/// and defeat the setting.
pub(crate) struct DeferredWebSocketStream {
    state: DeferredState,
    parked_reader: Option<Waker>,
}

impl DeferredWebSocketStream {
    fn new(stream: BoxedTransportStream, config: WebSocketConfig) -> Self {
        Self {
            state: DeferredState::Waiting(Box::new((stream, config))),
            parked_reader: None,
        }
    }

    fn start_handshake(&mut self, input: &[u8]) -> usize {
        let DeferredState::Waiting(held) =
            std::mem::replace(&mut self.state, DeferredState::Failed)
        else {
            unreachable!("start_handshake requires the Waiting state")
        };
        let (stream, config) = *held;

        // Xray truncates nothing: a first write past the budget disables early
        // data for the whole connection. Either way, take ownership before
        // reporting the bytes as accepted, which is what makes cancellation
        // safe under AsyncWrite's contract.
        let budget = config.early_data_bytes as usize;
        let early = (input.len() <= budget).then(|| input.to_vec());
        let framed = early.is_none().then(|| input.to_vec());
        let accepted = input.len();

        self.state = DeferredState::Dialing(tokio::spawn(async move {
            let mut ready = handshake(stream, config, early).await?;
            if let Some(payload) = framed {
                ready
                    .write_all(&payload)
                    .await
                    .map_err(TransportError::Tcp)?;
                ready.flush().await.map_err(TransportError::Tcp)?;
            }
            Ok(ready)
        }));

        // A reader may have parked before the first write. Wake it so it can
        // poll the JoinHandle and register for the handshake completion.
        if let Some(waker) = self.parked_reader.take() {
            waker.wake();
        }

        accepted
    }

    fn poll_finish_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let outcome = match &mut self.state {
            DeferredState::Dialing(task) => match Pin::new(task).poll(cx) {
                Poll::Ready(outcome) => outcome,
                Poll::Pending => return Poll::Pending,
            },
            DeferredState::Ready(_) => return Poll::Ready(Ok(())),
            DeferredState::Failed => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            DeferredState::Waiting(_) => return Poll::Pending,
        };

        match outcome {
            Ok(Ok(stream)) => {
                self.state = DeferredState::Ready(Box::new(stream));
                Poll::Ready(Ok(()))
            }
            Ok(Err(error)) => {
                self.state = DeferredState::Failed;
                Poll::Ready(Err(protocol_io_error(error)))
            }
            Err(error) => {
                self.state = DeferredState::Failed;
                Poll::Ready(Err(io::Error::other(format!(
                    "websocket handshake task failed: {error}"
                ))))
            }
        }
    }
}

impl Drop for DeferredWebSocketStream {
    fn drop(&mut self) {
        if let DeferredState::Dialing(task) = &self.state {
            task.abort();
        }
    }
}

impl AsyncRead for DeferredWebSocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            DeferredState::Ready(stream) => Pin::new(stream.as_mut()).poll_read(cx, output),
            DeferredState::Failed => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            // No connection exists yet, and reading must not create one: park
            // until the first write dials.
            DeferredState::Waiting(_) => {
                this.parked_reader = Some(cx.waker().clone());
                Poll::Pending
            }
            DeferredState::Dialing(_) => match this.poll_finish_handshake(cx) {
                Poll::Ready(Ok(())) => {
                    let DeferredState::Ready(stream) = &mut this.state else {
                        unreachable!("a completed handshake must install its stream")
                    };
                    Pin::new(stream.as_mut()).poll_read(cx, output)
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for DeferredWebSocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match &mut this.state {
                DeferredState::Waiting(_) => {
                    return Poll::Ready(Ok(this.start_handshake(input)));
                }
                DeferredState::Dialing(_) => match this.poll_finish_handshake(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                },
                DeferredState::Ready(stream) => {
                    return Pin::new(stream.as_mut()).poll_write(cx, input)
                }
                DeferredState::Failed => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, DeferredState::Dialing(_)) {
            match this.poll_finish_handshake(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        match &mut this.state {
            DeferredState::Ready(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            // Nothing has been written, so there is nothing to flush.
            DeferredState::Waiting(_) => Poll::Ready(Ok(())),
            DeferredState::Failed => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            DeferredState::Dialing(_) => unreachable!("the handshake was resolved above"),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.state, DeferredState::Dialing(_)) {
            match this.poll_finish_handshake(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        match &mut this.state {
            DeferredState::Ready(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            DeferredState::Waiting(held) => Pin::new(&mut held.0).poll_shutdown(cx),
            DeferredState::Failed => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            DeferredState::Dialing(_) => unreachable!("the handshake was resolved above"),
        }
    }
}

impl TransportStream for DeferredWebSocketStream {
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

fn protocol_io_error(error: TransportError) -> io::Error {
    io::Error::other(error.to_string())
}
