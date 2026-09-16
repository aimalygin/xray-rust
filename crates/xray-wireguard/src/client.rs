use crate::Config;
use crate::{io as transport, stack};
use bytes::Bytes;
use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{mpsc, oneshot, watch, Mutex, Notify, OwnedSemaphorePermit, Semaphore},
};
use xray_transport::{SocketProtector, TransportStream};

pub(crate) const TCP_LIMIT: usize = 16;
pub(crate) const UDP_LIMIT: usize = 16;
pub(crate) const PACKET_QUEUE: usize = 8;
pub(crate) const COMMAND_QUEUE: usize = 32;
pub(crate) const STREAM_BUFFER: usize = 8192;
pub(crate) const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid or unsupported WireGuard configuration")]
    Configuration,
    #[error("WireGuard client is closed")]
    Closed,
    #[error("WireGuard flow budget exhausted")]
    Busy,
    #[error("WireGuard destination is outside allowed IPs or has no local address")]
    NoRoute,
    #[error("WireGuard operation timed out")]
    Timeout,
    #[error("WireGuard TCP connection failed")]
    Connect,
    #[error("WireGuard UDP payload exceeds the configured MTU")]
    PacketTooLarge,
    #[error("WireGuard socket protection failed")]
    SocketProtection,
    #[error("WireGuard I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone)]
pub(crate) struct Stop(watch::Sender<bool>);
impl Stop {
    pub(crate) fn new() -> Self {
        Self(watch::channel(false).0)
    }
    pub(crate) fn close(&self) {
        self.0.send_replace(true);
    }
    pub(crate) fn is_closed(&self) -> bool {
        *self.0.borrow()
    }
    pub(crate) async fn cancelled(&self) {
        let mut rx = self.0.subscribe();
        if *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }
}

struct Owner {
    config: Config,
    commands: mpsc::Sender<Command>,
    stop: Stop,
    finished: watch::Receiver<bool>,
    wake: Arc<Notify>,
    rebind: Arc<RebindRequest>,
    tcp: Arc<Semaphore>,
    udp: Arc<Semaphore>,
    next: AtomicU64,
}

#[derive(Default)]
struct RebindRequest {
    pending: AtomicBool,
    wake: Notify,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.stop.close();
    }
}

#[derive(Clone)]
pub struct Client(Arc<Owner>);
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardClient")
            .field("closed", &self.0.stop.is_closed())
            .finish_non_exhaustive()
    }
}
impl Client {
    pub async fn start(
        config: Config,
        protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let stop = Stop::new();
        // If creation is cancelled or fails, every injected I/O boundary is cancelled.
        let mut guard = StartGuard(Some(stop.clone()));
        let wake = Arc::new(Notify::new());
        let (to_engine, ip_rx) = mpsc::channel(PACKET_QUEUE);
        let (ip_tx, from_engine) = mpsc::channel(PACKET_QUEUE);
        let (commands, requests) = mpsc::channel(COMMAND_QUEUE);
        let stack = stack::Stack::new(&config, to_engine, from_engine, requests, wake.clone());
        let protection_failed = Arc::new(AtomicBool::new(false));
        let peers = config.peers.iter().map(|settings| {
            let mut peer = gotatun::device::Peer::new(x25519_dalek::PublicKey::from(
                *settings.public_key.expose_bytes(),
            ))
            .with_endpoint(settings.endpoint)
            .with_allowed_ips(settings.allowed_ips.iter().map(|p| {
                format!("{}/{}", p.network(), p.prefix_length())
                    .parse()
                    .expect("validated prefix")
            }));
            peer.preshared_key = settings
                .preshared_key
                .as_ref()
                .map(|key| gotatun::PresharedKey::new(key.expose_bytes()));
            peer.keepalive = (settings.keepalive != 0).then_some(settings.keepalive);
            peer
        });
        let carrier = transport::Factory {
            ipv4: config.peers.iter().any(|p| p.endpoint.is_ipv4()),
            ipv6: config.peers.iter().any(|p| p.endpoint.is_ipv6()),
            protector,
            stop: stop.clone(),
            protection_failed: protection_failed.clone(),
            carrier: watch::channel(None).0,
        };
        let mut device = gotatun::device::DeviceBuilder::new()
            .with_limits(gotatun::device::DeviceLimits::mobile())
            .with_private_key(x25519_dalek::StaticSecret::from(
                *config.secret_key.expose_bytes(),
            ))
            .with_peers(peers)
            .with_udp(carrier.clone())
            .with_ip_pair(
                transport::IpTx {
                    tx: ip_tx,
                    stop: stop.clone(),
                },
                transport::IpRx {
                    rx: ip_rx,
                    mtu: config.mtu,
                    stop: stop.clone(),
                    wake: wake.clone(),
                },
            )
            .build()
            .await
            .map_err(|_| {
                if protection_failed.load(Ordering::Acquire) {
                    Error::SocketProtection
                } else {
                    Error::Connect
                }
            })?;
        let (finished, done) = watch::channel(false);
        let task_stop = stop.clone();
        let rebind = Arc::new(RebindRequest::default());
        let rebind_request = rebind.clone();
        tokio::spawn(async move {
            // Keep both the inner stack and engine alive while replacing sockets.
            // Notify coalesces repeated path updates instead of queueing work.
            let mut stack_task = Box::pin(stack.run(task_stop.clone()));
            loop {
                tokio::select! { biased;
                    _ = task_stop.cancelled() => break,
                    _ = &mut stack_task => break,
                    _ = device.wait() => break,
                    _ = rebind_request.wake.notified() => {
                        rebind_request.pending.store(false, Ordering::Release);
                        if task_stop.is_closed() || carrier.rebind().is_err() {
                            break;
                        }
                    },
                }
            }
            task_stop.close();
            drop(stack_task);
            device.stop().await;
            finished.send_replace(true);
        });
        // Drop must no longer cancel after the owner has taken responsibility.
        guard.0 = None;
        Ok(Self(Arc::new(Owner {
            config,
            commands,
            stop,
            finished: done,
            wake,
            rebind,
            tcp: Arc::new(Semaphore::new(TCP_LIMIT)),
            udp: Arc::new(Semaphore::new(UDP_LIMIT)),
            next: AtomicU64::new(1),
        })))
    }
    pub fn is_live(&self) -> bool {
        !self.0.stop.is_closed()
    }
    /// Requests fresh protected carrier sockets while retaining WireGuard
    /// sessions, pending packets, the inner stack and its flows. This does not resolve endpoints.
    /// A bind/protection failure closes the client; no old socket is reused.
    /// Returns whether the live client accepted the coalesced request.
    pub fn rebind(&self) -> bool {
        if !self.is_live() {
            return false;
        }
        if !self.0.rebind.pending.swap(true, Ordering::AcqRel) {
            self.0.rebind.wake.notify_one();
        }
        true
    }
    pub fn close(&self) {
        self.0.stop.close();
    }
    pub async fn shutdown(&self) {
        self.close();
        let mut done = self.0.finished.clone();
        if !*done.borrow() {
            let _ = done.changed().await;
        }
    }
    pub fn available_tcp_slots(&self) -> usize {
        self.0.tcp.available_permits()
    }
    pub fn available_udp_slots(&self) -> usize {
        self.0.udp.available_permits()
    }
    fn lease(&self, tcp: bool) -> Result<(Arc<Flow>, OwnedSemaphorePermit), Error> {
        if !self.is_live() {
            return Err(Error::Closed);
        }
        let semaphore = if tcp { &self.0.tcp } else { &self.0.udp };
        let permit = semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        let flow = Arc::new(Flow {
            id: self.0.next.fetch_add(1, Ordering::Relaxed),
            closed: AtomicBool::new(false),
            reset: AtomicBool::new(false),
            wake: self.0.wake.clone(),
        });
        Ok((flow, permit))
    }
    pub async fn connect(&self, remote: SocketAddr) -> Result<TcpStream, Error> {
        let local = self.0.config.local_for(remote)?;
        let (flow, permit) = self.lease(true)?;
        let guard = FlowGuard(flow.clone());
        let (reply, ready) = oneshot::channel();
        let (stream, bridge) = tokio::io::duplex(STREAM_BUFFER);
        self.0
            .commands
            .try_send(Command::Tcp {
                local,
                remote,
                bridge,
                reply,
                flow: flow.clone(),
                permit,
            })
            .map_err(|_| Error::Busy)?;
        tokio::select! { biased;
            _ = self.0.stop.cancelled() => return Err(Error::Closed),
            result = tokio::time::timeout(OPEN_TIMEOUT, ready) => result.map_err(|_| Error::Timeout)?.map_err(|_| Error::Closed)??,
        }
        Ok(TcpStream {
            stream,
            _guard: guard,
        })
    }
    pub async fn open_udp(&self, remote: SocketAddr) -> Result<UdpSession, Error> {
        let local = self.0.config.local_for(remote)?;
        let (flow, permit) = self.lease(false)?;
        let guard = FlowGuard(flow.clone());
        let (reply, ready) = oneshot::channel();
        let (incoming, packets) = mpsc::channel(PACKET_QUEUE);
        self.0
            .commands
            .try_send(Command::Udp {
                local,
                remote,
                incoming,
                reply,
                flow: flow.clone(),
                permit,
            })
            .map_err(|_| Error::Busy)?;
        tokio::select! { biased;
            _ = self.0.stop.cancelled() => return Err(Error::Closed),
            result = tokio::time::timeout(OPEN_TIMEOUT, ready) => result.map_err(|_| Error::Timeout)?.map_err(|_| Error::Closed)??,
        }
        Ok(UdpSession {
            remote,
            flow,
            _guard: guard,
            commands: self.0.commands.clone(),
            incoming: Mutex::new(packets),
            stop: self.0.stop.clone(),
            max_payload: usize::from(self.0.config.mtu) - if remote.is_ipv4() { 28 } else { 48 },
        })
    }
}
struct StartGuard(Option<Stop>);
impl Drop for StartGuard {
    fn drop(&mut self) {
        if let Some(stop) = &self.0 {
            stop.close();
        }
    }
}

pub(crate) struct Flow {
    pub(crate) id: u64,
    pub(crate) closed: AtomicBool,
    pub(crate) reset: AtomicBool,
    pub(crate) wake: Arc<Notify>,
}
pub(crate) struct FlowGuard(Arc<Flow>);
impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
        self.0.wake.notify_one();
    }
}
pub(crate) enum Command {
    Tcp {
        local: IpAddr,
        remote: SocketAddr,
        bridge: DuplexStream,
        reply: oneshot::Sender<Result<(), Error>>,
        flow: Arc<Flow>,
        permit: OwnedSemaphorePermit,
    },
    Udp {
        local: IpAddr,
        remote: SocketAddr,
        incoming: mpsc::Sender<Bytes>,
        reply: oneshot::Sender<Result<(), Error>>,
        flow: Arc<Flow>,
        permit: OwnedSemaphorePermit,
    },
    Send {
        id: u64,
        payload: Bytes,
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

pub struct TcpStream {
    stream: DuplexStream,
    _guard: FlowGuard,
}
impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let remaining = buf.remaining();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && remaining != 0
            && buf.filled().len() == before
            && self._guard.0.reset.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
        }
        result
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self._guard.0.reset.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
impl TransportStream for TcpStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, buf)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }
}

pub struct UdpSession {
    remote: SocketAddr,
    flow: Arc<Flow>,
    _guard: FlowGuard,
    commands: mpsc::Sender<Command>,
    incoming: Mutex<mpsc::Receiver<Bytes>>,
    stop: Stop,
    max_payload: usize,
}
impl UdpSession {
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }
    pub async fn send(&self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > self.max_payload {
            return Err(Error::PacketTooLarge);
        }
        if self.stop.is_closed() {
            return Err(Error::Closed);
        }
        tokio::select! { biased;
            _ = self.stop.cancelled() => Err(Error::Closed),
            result = tokio::time::timeout(OPEN_TIMEOUT, async {
                let permit = self.commands.reserve().await.map_err(|_| Error::Closed)?;
                let (reply, ready) = oneshot::channel();
                permit.send(Command::Send { id: self.flow.id, payload: Bytes::copy_from_slice(payload), reply });
                ready.await.map_err(|_| Error::Closed)?
            }) => result.map_err(|_| Error::Timeout)?,
        }
    }
    pub async fn recv(&self) -> Result<Bytes, Error> {
        tokio::select! { biased;
            _ = self.stop.cancelled() => Err(Error::Closed),
            packet = async { self.incoming.lock().await.recv().await } => packet.ok_or(Error::Closed),
        }
    }
}

#[cfg(test)]
mod tests;
