//! mKCP, the reliable stream over UDP of Xray-core v26.10.31, client side.
//!
//! A connection owns one unconnected UDP socket, as Xray's system dialer
//! opens one for UDP, and accepts datagrams from any address on it. A task
//! drives it the way Xray's two updaters do: every `tti` milliseconds while
//! data or acks are pending, every five seconds regardless, and at once when
//! a write, a read or an arriving segment wakes it.
mod engine;
mod mask;
mod segment;

use std::{
    io,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, MutexGuard, OnceLock, PoisonError,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::Notify,
    time::Instant,
};

use crate::{udp_noise::UdpNoiseConfig, SocketProtector, TransportError, TransportStream};
use engine::{Engine, State, WriteBlocked};
use mask::{Action, Masks};

/// `kcpSettings` with the stream's UDP masks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcpConfig {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub cwnd_multiplier: u32,
    pub max_sending_window: u32,
    /// The `finalmask.udp` masks in array order.
    pub masks: Vec<KcpMask>,
    /// The settings of the noise mask in `masks`, if there is one.
    pub noise: Option<UdpNoiseConfig>,
}

/// A `finalmask.udp` mask on an mKCP stream.
#[derive(Clone, PartialEq, Eq)]
pub enum KcpMask {
    /// `mkcp-legacy` without header or value.
    Original,
    /// `mkcp-legacy` with a value and no header.
    Aes128Gcm(zeroize::Zeroizing<String>),
    /// `mkcp-legacy` with a header.
    Header(KcpHeader),
    /// The noise mask, whose settings are `KcpConfig::noise`.
    Noise,
    /// A custom UDP prefix or standalone handshake.
    HeaderCustom(Arc<crate::header_custom::HeaderCustomUdpConfig>),
    /// The sudoku transform of every datagram.
    Sudoku(Arc<crate::sudoku::SudokuConfig>),
}

impl std::fmt::Debug for KcpMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Original => f.write_str("Original"),
            Self::Aes128Gcm(_) => f.write_str("Aes128Gcm(<redacted>)"),
            Self::Header(header) => f.debug_tuple("Header").field(header).finish(),
            Self::Noise => f.write_str("Noise"),
            Self::HeaderCustom(config) => f.debug_tuple("HeaderCustom").field(config).finish(),
            Self::Sudoku(config) => f.debug_tuple("Sudoku").field(config).finish(),
        }
    }
}

/// An `mkcp-legacy` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KcpHeader {
    /// A DNS query for this domain.
    Dns(String),
    Dtls,
    Srtp,
    Utp,
    Wechat,
    Wireguard,
}

impl KcpConfig {
    fn engine_config(&self) -> io::Result<engine::Config> {
        let invalid = |message: &str| io::Error::new(io::ErrorKind::InvalidInput, message);
        if !(21..=8192).contains(&self.mtu) {
            return Err(invalid("mKCP mtu must be between 21 and 8192"));
        }
        if !(10..=1000).contains(&self.tti) {
            return Err(invalid("mKCP tti must be between 10 and 1000"));
        }
        if self.cwnd_multiplier == 0 {
            return Err(invalid("mKCP cwndMultiplier must be at least 1"));
        }
        if self.max_sending_window < self.mtu {
            return Err(invalid("mKCP maxSendingWindow must be at least mtu"));
        }
        Ok(engine::Config {
            mtu: self.mtu,
            tti: self.tti,
            uplink_capacity: self.uplink_capacity,
            downlink_capacity: self.downlink_capacity,
            cwnd_multiplier: self.cwnd_multiplier,
            max_sending_window: self.max_sending_window,
        })
    }
}

/// The conversation of the next connection. Xray counts up from a random
/// number drawn when the process starts.
fn next_conversation() -> u16 {
    static NEXT: OnceLock<AtomicU32> = OnceLock::new();
    count_up(NEXT.get_or_init(|| AtomicU32::new(u32::from(rand::random::<u16>()))))
}

fn count_up(counter: &AtomicU32) -> u16 {
    counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as u16
}

/// Opens an mKCP connection to the first of `candidates` a socket opens
/// for. Nothing is sent until the stream is written to.
pub async fn connect(
    candidates: &[SocketAddr],
    protector: Option<&dyn SocketProtector>,
    config: &KcpConfig,
) -> Result<KcpStream, TransportError> {
    let engine_config = config.engine_config().map_err(TransportError::Kcp)?;
    let masks = Masks::new(&config.masks, config.noise.as_ref()).map_err(TransportError::Kcp)?;
    let mut last = None;
    for &candidate in candidates {
        let peer = crate::canonicalize_socket_addr(candidate);
        match open_socket(peer, protector) {
            Ok(socket) => {
                return Ok(KcpStream::start(
                    socket,
                    peer,
                    masks,
                    next_conversation(),
                    engine_config,
                ))
            }
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        TransportError::Kcp(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no mKCP server address",
        ))
    }))
}

/// A wildcard socket of `peer`'s family, protected before it is used.
fn open_socket(
    peer: SocketAddr,
    protector: Option<&dyn SocketProtector>,
) -> Result<UdpSocket, TransportError> {
    let bind: SocketAddr = if peer.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = StdUdpSocket::bind(bind).map_err(TransportError::Kcp)?;
    crate::protect_std_udp_socket(&socket, protector)?;
    socket.set_nonblocking(true).map_err(TransportError::Kcp)?;
    UdpSocket::from_std(socket).map_err(TransportError::Kcp)
}

/// Milliseconds since `since`, as Xray's `Elapsed` counts them.
fn elapsed(since: Instant) -> u32 {
    Instant::now().saturating_duration_since(since).as_millis() as u32
}

struct Inner {
    engine: Engine,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl Inner {
    /// The wakers Xray's signals release.
    fn take_wakers(&mut self) -> [Option<Waker>; 2] {
        let reader = std::mem::take(&mut self.engine.input_ready)
            .then(|| self.reader.take())
            .flatten();
        let writer = std::mem::take(&mut self.engine.output_ready)
            .then(|| self.writer.take())
            .flatten();
        [reader, writer]
    }
}

struct Shared {
    since: Instant,
    inner: Mutex<Inner>,
    /// Wakes the driver's data updater.
    wake: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes whom the engine signalled, and the driver if the engine asked.
    fn signal(&self, mut inner: MutexGuard<'_, Inner>) {
        let wakers = inner.take_wakers();
        let wake = std::mem::take(&mut inner.engine.wake_data);
        drop(inner);
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
        if wake {
            self.wake.notify_one();
        }
    }
}

/// One mKCP connection. Dropping it closes the connection, which then
/// terminates as Xray's does, in the background.
pub struct KcpStream {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for KcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpStream").finish_non_exhaustive()
    }
}

impl KcpStream {
    fn start(
        socket: UdpSocket,
        peer: SocketAddr,
        masks: Masks,
        conv: u16,
        config: engine::Config,
    ) -> Self {
        let shared = Arc::new(Shared {
            since: Instant::now(),
            inner: Mutex::new(Inner {
                engine: Engine::new(conv, config),
                reader: None,
                writer: None,
            }),
            wake: Notify::new(),
        });
        tokio::spawn(Driver::new(Arc::clone(&shared), socket, peer, masks).run());
        Self { shared }
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        let mut inner = self.shared.lock();
        let current = elapsed(self.shared.since);
        inner.engine.close(current);
        self.shared.signal(inner);
        // The driver may be waiting inside a standalone UDP handshake.
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut inner = self.shared.lock();
        match inner.engine.read(buf.initialize_unfilled()) {
            None => Poll::Ready(Ok(())),
            Some(0) => {
                inner.reader = Some(cx.waker().clone());
                Poll::Pending
            }
            Some(count) => {
                buf.advance(count);
                self.shared.signal(inner);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut inner = self.shared.lock();
        match inner.engine.write(data) {
            Ok(count) => {
                self.shared.signal(inner);
                Poll::Ready(Ok(count))
            }
            Err(WriteBlocked::Full) => {
                inner.writer = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(WriteBlocked::Closed) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// mKCP has no half close: Xray's connection closes both ways at once,
    /// and the peer stops sending when it sees that. Shutting the write side
    /// down leaves the connection open until the stream is dropped.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TransportStream for KcpStream {
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

/// The ping updater's period.
const PING_INTERVAL: Duration = Duration::from_secs(5);
/// Xray reads a datagram into an 8192-byte buffer.
const RECEIVE_BUFFER: usize = 8192;

/// Xray's data updater: running while data or acks are pending.
struct DataUpdater {
    running: bool,
    next: Instant,
    interval: Duration,
}

/// A standalone request unanswered this long goes out again. Xray-core's data
/// updater waits for its reply for good.
const STANDALONE_RESEND: Duration = Duration::from_secs(1);

/// How the wait for a standalone reply ended.
enum Awaited {
    /// A datagram arrived; the reply may be among them.
    Received,
    /// The request is due to go out again.
    Resend,
    /// The stream is closing.
    Closed,
}

struct Driver {
    shared: Arc<Shared>,
    socket: UdpSocket,
    peer: SocketAddr,
    masks: Masks,
    /// The local address a `header-custom` mask writes with. Go listens on
    /// the IPv6 wildcard for either family, so Xray-core's has a port and
    /// no IPv4 address.
    local: Option<SocketAddr>,
    data: DataUpdater,
    ping_next: Instant,
    /// Xray stops reading for good after a receive error.
    receiving: bool,
}

impl Driver {
    fn new(shared: Arc<Shared>, socket: UdpSocket, peer: SocketAddr, masks: Masks) -> Self {
        let since = shared.since;
        let interval = Duration::from_millis(shared.lock().engine.tti().into());
        let local = socket
            .local_addr()
            .ok()
            .map(|local| SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), local.port()));
        Self {
            shared,
            socket,
            peer,
            masks,
            local,
            data: DataUpdater {
                running: false,
                next: since,
                interval,
            },
            ping_next: since,
            receiving: true,
        }
    }

    async fn run(mut self) {
        let mut buf = vec![0; RECEIVE_BUFFER];
        loop {
            let deadline = if self.data.running {
                self.data.next.min(self.ping_next)
            } else {
                self.ping_next
            };
            tokio::select! {
                biased;
                () = self.shared.wake.notified() => self.wake_data(),
                received = self.socket.recv_from(&mut buf), if self.receiving => {
                    match received {
                        Ok((length, from)) => self.receive(&mut buf[..length], from),
                        Err(_) => self.receiving = false,
                    }
                }
                () = tokio::time::sleep_until(deadline) => {}
            }
            // The timers run whichever branch woke the loop, so datagrams
            // that keep arriving cannot hold them off.
            self.tick();
            if !self.send().await {
                return;
            }
        }
    }

    /// `dataUpdater.WakeUp()`: starts the data updater unless it runs.
    fn wake_data(&mut self) {
        if self.data.running {
            return;
        }
        let mut inner = self.shared.lock();
        if inner.engine.data_update_terminated() {
            return;
        }
        let now = Instant::now();
        self.data.running = inner.engine.data_update_necessary();
        if self.data.running {
            inner.engine.flush(elapsed(self.shared.since));
            self.data.next = now + self.data.interval;
        }
        self.shared.signal_from_driver(inner);
    }

    fn tick(&mut self) {
        let now = Instant::now();
        let mut inner = self.shared.lock();
        let current = elapsed(self.shared.since);
        if self.data.running && now >= self.data.next {
            if inner.engine.data_update_necessary() {
                inner.engine.flush(current);
                self.data.next += self.data.interval;
                if self.data.next <= now {
                    self.data.next = now;
                }
            } else {
                self.data.running = false;
            }
        }
        if now >= self.ping_next {
            if inner.engine.state() != State::Terminated {
                inner.engine.flush(current);
            }
            self.ping_next += PING_INTERVAL;
            if self.ping_next <= now {
                self.ping_next = now + PING_INTERVAL;
            }
        }
        self.shared.signal_from_driver(inner);
    }

    fn receive(&mut self, datagram: &mut [u8], from: SocketAddr) {
        let Some(range) = self.masks.open(datagram, from, Instant::now()) else {
            return;
        };
        let segments = segment::read_segments(&datagram[range]);
        if segments.is_empty() {
            return;
        }
        let mut inner = self.shared.lock();
        inner.engine.input(segments, elapsed(self.shared.since));
        let wake = std::mem::take(&mut inner.engine.wake_data);
        self.shared.signal_from_driver(inner);
        if wake {
            self.wake_data();
        }
    }

    /// Sends what the engine queued. False once the connection terminated.
    async fn send(&mut self) -> bool {
        let (datagrams, terminated) = {
            let mut inner = self.shared.lock();
            (
                std::mem::take(&mut inner.engine.out),
                inner.engine.state() == State::Terminated,
            )
        };
        // When the standalone request being awaited went out.
        let mut requested = None;
        for datagram in datagrams {
            self.masks.start(datagram);
            while let Some(action) = self.masks.next(Instant::now(), self.local, self.peer) {
                match action {
                    Action::Send(datagram) => {
                        requested = None;
                        // A datagram the system refuses is lost, and resent as lost.
                        let _ = self.socket.send_to(&datagram, self.peer).await;
                    }
                    Action::Pause(pause) => {
                        requested = None;
                        if !pause.is_zero() {
                            tokio::time::sleep(pause).await;
                        }
                    }
                    Action::Wait => {
                        let since = *requested.get_or_insert_with(Instant::now);
                        match self.receive_handshake(since + STANDALONE_RESEND).await {
                            Awaited::Received => {}
                            Awaited::Resend => {
                                requested = None;
                                self.masks.resend();
                            }
                            Awaited::Closed => return false,
                        }
                    }
                }
            }
        }
        !terminated
    }

    /// A standalone write waits for the matching reply, receiving ordinary
    /// packets meanwhile and honoring the stream's cancellation.
    async fn receive_handshake(&mut self, resend: Instant) -> Awaited {
        let mut buf = vec![0; RECEIVE_BUFFER];
        loop {
            let closing = matches!(
                self.shared.lock().engine.state(),
                State::ReadyToClose | State::Terminating | State::Terminated
            );
            if !self.receiving || closing {
                self.abort();
                return Awaited::Closed;
            }
            tokio::select! {
                () = self.shared.wake.notified() => {}
                () = tokio::time::sleep_until(resend) => return Awaited::Resend,
                received = self.socket.recv_from(&mut buf) => {
                    match received {
                        Ok((length, from)) => {
                            self.receive(&mut buf[..length], from);
                            return Awaited::Received;
                        }
                        Err(_) => self.receiving = false,
                    }
                }
            }
        }
    }

    fn abort(&self) {
        let mut inner = self.shared.lock();
        inner.engine.abort(elapsed(self.shared.since));
        self.shared.signal_from_driver(inner);
    }
}

impl Shared {
    /// Wakes the stream's reader and writer as the engine signalled. The
    /// driver handles its own data updater.
    fn signal_from_driver(&self, mut inner: MutexGuard<'_, Inner>) {
        let wakers = inner.take_wakers();
        inner.engine.wake_data = false;
        drop(inner);
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests;
