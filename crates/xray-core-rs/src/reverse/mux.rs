//! The bridge's end of a reverse Mux.Cool connection: Xray-core's
//! `mux.ServerWorker` over a VLESS reverse tunnel, with
//! `session.IsReverseMux` set. The portal opens the sessions and the bridge
//! answers on them; the portal's control session is read here.
//!
//! As in Xray-core's worker, a session whose queue is full pauses the
//! tunnel's reader until it drains or goes away, so a stalled session delays
//! its siblings (head-of-line blocking), and the tunnel closes when it held
//! no session for a whole idle check.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};
use tokio::time::Instant;
use xray_proxy::mux::{self as wire, Frame, Status};
use xray_proxy::reverse::{decode_control, CONTROL_DOMAIN};
use xray_routing::{Network, Target, TargetAddr};

use super::TunnelState;

/// Frames queued per session and direction, at most 64 KiB of payload, as
/// the client's Mux children queue them.
const SESSION_QUEUE: usize = 8;

/// The sessions one tunnel holds at once. Xray-core's portal retires a
/// tunnel once more than 256 sessions, its control session included, were opened on it, so its own never come
/// near this; Xray-core's bridge has no bound.
pub(super) const MAX_SESSIONS: usize = 512;
/// The most Ends that wait for the writer. The reader queues one for each
/// refused session and each frame of an unknown one, whether or not the
/// portal reads them, so a portal that reads nothing fails the tunnel here.
const MAX_QUEUED_ENDS: usize = 4 * MAX_SESSIONS;

/// How often Xray-core's worker checks for idleness: it closes when it held
/// no session at one check and opened none by the next.
const IDLE_CHECK: Duration = Duration::from_secs(60);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn wake(slot: &mut Option<Waker>) {
    if let Some(waker) = slot.take() {
        waker.wake();
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "reverse Mux session closed")
}

fn queue_end(state: &mut State, id: u16, error: bool) -> io::Result<()> {
    if state.ends.len() >= MAX_QUEUED_ENDS {
        return Err(protocol_error());
    }
    state.ends.push_back((id, error));
    Ok(())
}

fn protocol_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid reverse Mux frame")
}

#[derive(Debug)]
struct Packet {
    /// For a datagram: where it goes (uplink) or comes from (downlink),
    /// when the frame names it.
    address: Option<Target>,
    bytes: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Stream,
    Datagram,
    /// The portal's control session, read here; nothing is written to it.
    Control {
        broken: bool,
    },
}

#[derive(Debug)]
struct Entry {
    kind: Kind,
    rx: VecDeque<Packet>,
    tx: VecDeque<Packet>,
    /// The portal ended the session.
    remote_ended: bool,
    /// The bridge is done: End goes out once `tx` drains.
    closing: bool,
    /// The End carries Xray-core's error flag.
    failed: bool,
    /// End went out.
    ended: bool,
    /// No handle holds the session any more.
    dropped: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl Entry {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            remote_ended: false,
            closing: false,
            failed: false,
            ended: false,
            dropped: false,
            read_waker: None,
            write_waker: None,
        }
    }

    /// Whether nothing will use the entry again.
    fn finished(&self) -> bool {
        (self.ended || self.remote_ended)
            && (self.dropped || matches!(self.kind, Kind::Control { .. }))
    }
}

#[derive(Debug, Default)]
struct State {
    sessions: BTreeMap<u16, Entry>,
    /// Sessions the portal opened on this tunnel, for the idle check.
    opened: u64,
    /// Ends for sessions the bridge does not hold, with their error flags.
    ends: VecDeque<(u16, bool)>,
    cursor: u16,
    closed: bool,
}

#[derive(Debug)]
pub(super) struct Shared {
    state: Mutex<State>,
    /// Wakes the writer: frames to send, or closing.
    changed: Notify,
    /// Wakes a reader paused on a full session: it drained, ended or went
    /// away. The reader is the only waiter, so `notify_one` keeps a permit
    /// for a wake that precedes its wait.
    drained: Notify,
    tunnel: Arc<TunnelState>,
    activity: Mutex<Instant>,
}

impl Shared {
    pub(super) fn new(tunnel: Arc<TunnelState>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            changed: Notify::new(),
            drained: Notify::new(),
            tunnel,
            activity: Mutex::new(Instant::now()),
        })
    }

    fn touch(&self) {
        *lock(&self.activity) = Instant::now();
    }

    fn count(&self, state: &State) {
        self.tunnel
            .sessions
            .store(state.sessions.len(), Ordering::Release);
    }

    /// Fails every session and stops the loops.
    pub(super) fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        for entry in state.sessions.values_mut() {
            entry.rx.clear();
            entry.tx.clear();
            wake(&mut entry.read_waker);
            wake(&mut entry.write_waker);
        }
        drop(state);
        self.changed.notify_waiters();
        // A permit, too, for a writer that has not started waiting yet.
        self.changed.notify_one();
        self.drained.notify_one();
    }
}

/// A session the portal opened, for the tunnel to dispatch.
#[derive(Debug)]
pub(super) struct NewSession {
    pub(super) target: Target,
    pub(super) source: Option<SocketAddr>,
    pub(super) local: Option<SocketAddr>,
    pub(super) session: Session,
}

#[derive(Debug)]
struct Token {
    shared: Arc<Shared>,
    id: u16,
}

impl Drop for Token {
    fn drop(&mut self) {
        let shared = &self.shared;
        let mut state = lock(&shared.state);
        if let Some(entry) = state.sessions.get_mut(&self.id) {
            entry.dropped = true;
            entry.rx.clear();
            if !entry.ended && !entry.remote_ended && !entry.closing {
                // Dropped without finishing: whatever is queued is lost.
                entry.tx.clear();
                entry.failed = true;
                entry.closing = true;
            }
            if entry.finished() {
                state.sessions.remove(&self.id);
                shared.count(&state);
            }
        }
        drop(state);
        shared.changed.notify_one();
        shared.drained.notify_one();
    }
}

/// The bridge's handle on a session: a byte stream for TCP, datagrams with
/// their addresses for UDP. Dropping the last handle ends the session.
#[derive(Debug, Clone)]
pub(crate) struct Session {
    token: Arc<Token>,
    /// Serializes datagram senders, which share one waker slot.
    sender: Arc<AsyncMutex<()>>,
}

impl Session {
    fn new(shared: Arc<Shared>, id: u16) -> Self {
        Self {
            token: Arc::new(Token { shared, id }),
            sender: Arc::new(AsyncMutex::new(())),
        }
    }

    /// Ends the session once what was written is sent; `failed` sets the
    /// End's error flag, as Xray-core does when the copy back failed.
    pub(crate) fn finish(&self, failed: bool) {
        let shared = &self.token.shared;
        let mut state = lock(&shared.state);
        if let Some(entry) = state.sessions.get_mut(&self.token.id) {
            if !entry.ended && !entry.remote_ended {
                entry.failed |= failed;
                entry.closing = true;
                if failed {
                    entry.tx.clear();
                }
            }
            wake(&mut entry.read_waker);
        }
        drop(state);
        shared.changed.notify_one();
    }

    /// The next datagram the portal sent, with the address it goes to when
    /// the frame names one; `None` once the session is over.
    pub(crate) async fn recv_datagram(&self) -> Option<(Option<Target>, Bytes)> {
        std::future::poll_fn(|cx| {
            let shared = &self.token.shared;
            let mut state = lock(&shared.state);
            let tunnel_closed = state.closed;
            let Some(entry) = state.sessions.get_mut(&self.token.id) else {
                return Poll::Ready(None);
            };
            if let Some(packet) = entry.rx.pop_front() {
                drop(state);
                shared.drained.notify_one();
                return Poll::Ready(Some((packet.address, packet.bytes)));
            }
            if tunnel_closed || entry.remote_ended || entry.closing || entry.ended {
                return Poll::Ready(None);
            }
            entry.read_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Sends a datagram back to the portal, naming where it came from.
    pub(crate) async fn send_datagram(&self, source: &Target, payload: &[u8]) -> io::Result<()> {
        if payload.len() > wire::MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reverse Mux datagram too large",
            ));
        }
        let _sender = self.sender.lock().await;
        std::future::poll_fn(|cx| {
            let shared = &self.token.shared;
            let mut state = lock(&shared.state);
            let tunnel_closed = state.closed;
            let entry = state.sessions.get_mut(&self.token.id).ok_or_else(closed)?;
            if tunnel_closed || entry.remote_ended || entry.closing || entry.ended {
                return Poll::Ready(Err(closed()));
            }
            if entry.tx.len() >= SESSION_QUEUE {
                entry.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            entry.tx.push_back(Packet {
                address: Some(source.clone()),
                bytes: Bytes::copy_from_slice(payload),
            });
            drop(state);
            shared.changed.notify_one();
            Poll::Ready(Ok(()))
        })
        .await
    }
}

impl AsyncRead for Session {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let shared = &self.token.shared;
        let mut state = lock(&shared.state);
        let tunnel_closed = state.closed;
        let Some(entry) = state.sessions.get_mut(&self.token.id) else {
            return Poll::Ready(Ok(()));
        };
        if let Some(packet) = entry.rx.front_mut() {
            let n = out.remaining().min(packet.bytes.len());
            out.put_slice(&packet.bytes.split_to(n));
            if packet.bytes.is_empty() {
                entry.rx.pop_front();
                drop(state);
                shared.drained.notify_one();
            }
            return Poll::Ready(Ok(()));
        }
        if tunnel_closed {
            return Poll::Ready(Err(closed()));
        }
        // The portal's End, or the bridge's own, ends the uplink too:
        // Mux.Cool sessions do not half-close.
        if entry.remote_ended || entry.closing || entry.ended {
            return Poll::Ready(Ok(()));
        }
        entry.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for Session {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.token.shared;
        let mut state = lock(&shared.state);
        let tunnel_closed = state.closed;
        let Some(entry) = state.sessions.get_mut(&self.token.id) else {
            return Poll::Ready(Err(closed()));
        };
        if tunnel_closed || entry.remote_ended || entry.closing || entry.ended {
            return Poll::Ready(Err(closed()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if entry.tx.len() >= SESSION_QUEUE {
            entry.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // Xray-core splits a stream into frames of at most 8 KiB.
        let n = input.len().min(wire::MAX_PAYLOAD);
        entry.tx.push_back(Packet {
            address: None,
            bytes: Bytes::copy_from_slice(&input[..n]),
        });
        drop(state);
        shared.changed.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_sent(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_sent(cx))?;
        this.finish(false);
        Poll::Ready(Ok(()))
    }
}

impl Session {
    /// Ready once the writer took every queued frame, which it then sends
    /// before any End of this session.
    fn poll_sent(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let shared = &self.token.shared;
        let mut state = lock(&shared.state);
        let tunnel_closed = state.closed;
        let Some(entry) = state.sessions.get_mut(&self.token.id) else {
            return Poll::Ready(Err(closed()));
        };
        if tunnel_closed || entry.remote_ended {
            return Poll::Ready(Err(closed()));
        }
        if entry.tx.is_empty() || entry.closing || entry.ended {
            return Poll::Ready(Ok(()));
        }
        entry.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Applies one frame from the portal. `Ok(false)` leaves it unconsumed: its
/// session's queue is full. New sessions go to `opened`.
fn deliver(
    shared: &Arc<Shared>,
    frame: wire::ReverseFrame<'_>,
    opened: &mut Vec<NewSession>,
) -> io::Result<bool> {
    let wire::ReverseFrame {
        frame,
        source,
        local,
    } = frame;
    let id = frame.session_id;
    let mut state = lock(&shared.state);
    match frame.status {
        Status::New => {
            if state.sessions.contains_key(&id) {
                // Xray-core's portal never reuses an ID on a connection.
                return Err(protocol_error());
            }
            let target = frame.target.ok_or_else(protocol_error)?;
            state.opened += 1;
            if matches!(&target.addr, TargetAddr::Domain(domain) if domain == CONTROL_DOMAIN) {
                let mut entry = Entry::new(Kind::Control { broken: false });
                if let Some(payload) = frame.payload {
                    control(shared, &mut entry, payload);
                }
                state.sessions.insert(id, entry);
                shared.count(&state);
                return Ok(true);
            }
            if state.sessions.len() >= MAX_SESSIONS {
                queue_end(&mut state, id, true)?;
                drop(state);
                shared.changed.notify_one();
                return Ok(true);
            }
            let kind = match target.network {
                Network::Tcp => Kind::Stream,
                Network::Udp => Kind::Datagram,
            };
            let mut entry = Entry::new(kind);
            if let Some(payload) = frame.payload.filter(|payload| !payload.is_empty()) {
                entry.rx.push_back(Packet {
                    address: None,
                    bytes: Bytes::copy_from_slice(payload),
                });
            }
            state.sessions.insert(id, entry);
            shared.count(&state);
            drop(state);
            opened.push(NewSession {
                target,
                source: source.and_then(|source| endpoint_addr(&source)),
                local: local.and_then(|local| endpoint_addr(&local)),
                session: Session::new(Arc::clone(shared), id),
            });
            Ok(true)
        }
        Status::Keep => {
            let Some(entry) = state.sessions.get_mut(&id) else {
                // As Xray-core does, tell the portal the session is gone.
                if frame.payload.is_some() {
                    queue_end(&mut state, id, false)?;
                    drop(state);
                    shared.changed.notify_one();
                }
                return Ok(true);
            };
            if let Kind::Control { .. } = entry.kind {
                if let Some(payload) = frame.payload {
                    control(shared, entry, payload);
                }
                return Ok(true);
            }
            if entry.remote_ended || entry.closing || entry.ended || entry.dropped {
                return Ok(true);
            }
            if let Some(payload) = frame.payload.filter(|payload| !payload.is_empty()) {
                if entry.rx.len() >= SESSION_QUEUE {
                    return Ok(false);
                }
                entry.rx.push_back(Packet {
                    address: frame.target,
                    bytes: Bytes::copy_from_slice(payload),
                });
                wake(&mut entry.read_waker);
            }
            Ok(true)
        }
        Status::End => {
            if let Some(entry) = state.sessions.get_mut(&id) {
                entry.remote_ended = true;
                entry.tx.clear();
                wake(&mut entry.read_waker);
                wake(&mut entry.write_waker);
                if entry.finished() {
                    state.sessions.remove(&id);
                    shared.count(&state);
                }
            }
            drop(state);
            shared.drained.notify_one();
            Ok(true)
        }
        Status::KeepAlive => Ok(true),
    }
}

/// Reads one of the portal's control messages: any state but `ACTIVE`
/// retires the tunnel. A message that does not parse stops the reading, as
/// Xray-core's bridge stops reading the session then.
fn control(shared: &Shared, entry: &mut Entry, payload: &[u8]) {
    let Kind::Control { broken } = &mut entry.kind else {
        return;
    };
    if *broken {
        return;
    }
    match decode_control(payload) {
        Ok(state) if !state.is_active() => {
            shared.tunnel.draining.store(true, Ordering::Release);
        }
        Ok(_) => {}
        Err(_) => *broken = true,
    }
}

/// The socket address a frame names, when it is an IP address.
fn endpoint_addr(endpoint: &Target) -> Option<SocketAddr> {
    match endpoint.addr {
        TargetAddr::Ip(ip) => Some(SocketAddr::new(ip, endpoint.port)),
        TargetAddr::Domain(_) => None,
    }
}

/// Reads the portal's frames until the tunnel fails or closes.
pub(super) async fn read_loop<R>(
    shared: Arc<Shared>,
    mut stream: R,
    sessions: mpsc::Sender<NewSession>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut opened = Vec::new();
    loop {
        if let Some((frame, n)) = wire::decode_reverse(&bytes)? {
            if !deliver(&shared, frame, &mut opened)? {
                // Xray-core blocks its Mux reader on the session's pipe.
                // Keep the frame and stop reading the tunnel until the
                // session drains, ends or goes away, then decode it again.
                shared.drained.notified().await;
                if lock(&shared.state).closed {
                    return Err(closed());
                }
                continue;
            }
            bytes.drain(..n);
            for session in opened.drain(..) {
                if sessions.send(session).await.is_err() {
                    return Err(closed());
                }
            }
        } else {
            let capacity = wire::MAX_FRAME - bytes.len();
            if capacity == 0 {
                return Err(protocol_error());
            }
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk[..capacity.min(4096)]).await?;
            if n == 0 {
                return Err(closed());
            }
            shared.touch();
            bytes.extend_from_slice(&chunk[..n]);
        }
    }
}

/// The next frame to send: an End for a session the bridge does not hold,
/// else one frame of the next session with something to send.
fn next_frame(shared: &Shared) -> io::Result<Option<Vec<u8>>> {
    let mut state = lock(&shared.state);
    if state.closed {
        return Err(closed());
    }
    if let Some((id, error)) = state.ends.pop_front() {
        return wire::encode(&Frame {
            session_id: id,
            status: Status::End,
            error,
            target: None,
            global_id: None,
            payload: None,
        })
        .map(Some);
    }
    let ready = |entry: &Entry| {
        !entry.ended && !entry.remote_ended && (!entry.tx.is_empty() || entry.closing)
    };
    let cursor = state.cursor;
    let Some(id) = state
        .sessions
        .range((
            std::ops::Bound::Excluded(cursor),
            std::ops::Bound::Unbounded,
        ))
        .chain(state.sessions.range(..=cursor))
        .find(|(_, entry)| ready(entry))
        .map(|(&id, _)| id)
    else {
        return Ok(None);
    };
    state.cursor = id;
    let entry = state.sessions.get_mut(&id).expect("selected session");
    let frame = if let Some(packet) = entry.tx.pop_front() {
        wake(&mut entry.write_waker);
        let target = match (entry.kind, packet.address) {
            (Kind::Datagram, Some(address)) if address.port != 0 => {
                Some(Target::new(address.addr, address.port, Network::Udp))
            }
            _ => None,
        };
        wire::encode(&Frame {
            session_id: id,
            status: Status::Keep,
            error: false,
            target,
            global_id: None,
            payload: Some(&packet.bytes),
        })?
    } else {
        entry.ended = true;
        wake(&mut entry.read_waker);
        wake(&mut entry.write_waker);
        let frame = wire::encode(&Frame {
            session_id: id,
            status: Status::End,
            error: entry.failed,
            target: None,
            global_id: None,
            payload: None,
        })?;
        if entry.finished() {
            state.sessions.remove(&id);
            shared.count(&state);
        }
        frame
    };
    Ok(Some(frame))
}

/// Sends what the sessions queue, one frame per session in turn.
pub(super) async fn write_loop<W>(shared: Arc<Shared>, mut stream: W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        let notified = shared.changed.notified();
        match next_frame(&shared)? {
            Some(frame) => {
                stream.write_all(&frame).await?;
                stream.flush().await?;
                shared.touch();
            }
            None => notified.await,
        }
    }
}

/// Returns once the tunnel held no session at one check and opened none by
/// the next, as Xray-core's worker closes.
pub(super) async fn idle_loop(shared: Arc<Shared>) {
    loop {
        let (held, opened) = {
            let state = lock(&shared.state);
            (state.sessions.len(), state.opened)
        };
        tokio::time::sleep(IDLE_CHECK).await;
        let state = lock(&shared.state);
        if held == 0 && state.sessions.is_empty() && state.opened == opened {
            return;
        }
    }
}

/// Returns once nothing went either way for `idle`, the tunnel's `connIdle`,
/// as Xray-core's activity timer cancels the VLESS connection.
pub(super) async fn inactivity_loop(shared: Arc<Shared>, idle: Duration) {
    loop {
        let last = *lock(&shared.activity);
        let deadline = last.checked_add(idle);
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
        if *lock(&shared.activity) == last {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
