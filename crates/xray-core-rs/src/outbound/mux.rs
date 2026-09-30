//! Shared bounded Mux.Cool session ownership. A slow child is reset rather
//! than blocking the parent's reader or siblings. No application-data replay.
use super::*;
use bytes::Bytes;
use std::{
    collections::{BTreeMap, VecDeque},
    task::Waker,
};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex as AsyncMutex, Notify},
    task::JoinHandle,
};
use xray_proxy::mux::{self as wire, Frame, Status};

const MAX_PARENTS: usize = 4;
const MAX_CHILDREN_EVER: u16 = 128;
const CHILD_QUEUE: usize = 8;
const IDLE: Duration = Duration::from_secs(30);

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Mux session closed")
}
fn full() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "Mux session capacity exhausted")
}
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
fn wake(slot: &mut Option<Waker>) {
    if let Some(w) = slot.take() {
        w.wake();
    }
}

#[derive(Debug)]
pub(super) struct Runtime {
    options: xray_config::MuxSettings,
    tcp: Option<Pool>,
    udp: Option<Pool>,
}
impl Runtime {
    pub(super) fn new(
        options: &Option<xray_config::MuxSettings>,
        transport: &StreamTransport,
    ) -> Result<Option<Self>, CoreError> {
        let Some(options) = options else {
            return Ok(None);
        };
        if options.concurrency > 64 || options.xudp_concurrency > 64 {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let mut options = options.clone();
        if options.concurrency == 0 {
            options.concurrency = 8;
        }
        // The pinned Xray XHTTP inbound only permits UDP Mux children.
        // TCP already shares the carrier's HTTP/2 or HTTP/3 connection.
        if options.concurrency > 0 && matches!(transport, StreamTransport::Xhttp(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XHTTP requires mux.concurrency < 0; use xudpConcurrency for UDP pooling",
            )
            .into());
        }
        Ok(Some(Self {
            tcp: (options.concurrency > 0).then(|| Pool::new(options.concurrency as u16)),
            udp: (options.xudp_concurrency > 0).then(|| Pool::new(options.xudp_concurrency as u16)),
            options,
        }))
    }
    pub(super) fn pool(&self, target: &Target) -> Result<Option<&Pool>, CoreError> {
        if target.network == RoutingNetwork::Tcp {
            return Ok(self.tcp.as_ref());
        }
        if target.port == 443 {
            match self.options.udp443 {
                xray_config::MuxUdp443::Reject => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Mux policy rejects UDP/443",
                    )
                    .into())
                }
                xray_config::MuxUdp443::Skip => return Ok(None),
                xray_config::MuxUdp443::Allow => {}
            }
        }
        Ok(if self.options.xudp_concurrency < 0 {
            None
        } else {
            self.udp.as_ref().or(self.tcp.as_ref())
        })
    }
    pub(super) fn close(&self) {
        if let Some(p) = &self.tcp {
            p.close();
        }
        if let Some(p) = &self.udp {
            p.close();
        }
    }
    pub(super) async fn join(&self) {
        if let Some(p) = &self.tcp {
            p.join().await;
        }
        if let Some(p) = &self.udp {
            p.join().await;
        }
    }
}
pub(super) fn target() -> Target {
    Target::new(
        RoutingTargetAddr::Domain("v1.mux.cool".into()),
        9527,
        RoutingNetwork::Tcp,
    )
}

#[derive(Debug)]
pub(super) struct Pool {
    concurrency: u16,
    flow_ids: wire::FlowIds,
    parents: Mutex<Vec<Arc<Parent>>>,
    connecting: AsyncMutex<()>,
    closed: std::sync::atomic::AtomicBool,
    shutdown: tokio::sync::watch::Sender<bool>,
}
impl Pool {
    pub(super) fn new(concurrency: u16) -> Self {
        Self {
            concurrency,
            flow_ids: wire::FlowIds::default(),
            parents: Mutex::new(Vec::new()),
            connecting: AsyncMutex::new(()),
            closed: std::sync::atomic::AtomicBool::new(false),
            shutdown: tokio::sync::watch::channel(false).0,
        }
    }
    pub(super) async fn open<F>(&self, target: &Target, connect: F) -> Result<Child, CoreError>
    where
        F: Future<Output = Result<BoxedTransportStream, CoreError>>,
    {
        self.open_datagram(target, [0; 8], connect).await
    }
    pub(super) async fn open_datagram<F>(
        &self,
        target: &Target,
        flow: [u8; 8],
        connect: F,
    ) -> Result<Child, CoreError>
    where
        F: Future<Output = Result<BoxedTransportStream, CoreError>>,
    {
        let global_id = self.flow_ids.derive(flow);
        wire::encode(&Frame {
            session_id: 1,
            status: Status::New,
            error: false,
            target: Some(target.clone()),
            global_id: None,
            payload: None,
        })?;
        // Serialize admission with cold connects, but cancellation never keeps
        // the lock or inserts an incompletely constructed parent.
        let mut shutdown = self.shutdown.subscribe();
        if self.closed.load(Ordering::Acquire) {
            return Err(closed().into());
        }
        let _guard = tokio::select! {_ = shutdown.changed()=>return Err(closed().into()),g=self.connecting.lock()=>g};
        if self.closed.load(Ordering::Acquire) {
            return Err(closed().into());
        }
        let retired = {
            let mut parents = lock(&self.parents);
            for parent in parents.iter() {
                if let Some(child) = parent.allocate(target, self.concurrency, global_id) {
                    return Ok(child);
                }
            }
            let mut retired = Vec::new();
            parents.retain(|p| {
                let retire = {
                    let state = lock(&p.shared.state);
                    state.closed || state.next >= MAX_CHILDREN_EVER && state.children.is_empty()
                };
                if retire {
                    p.close();
                    retired.push(p.clone());
                    false
                } else {
                    true
                }
            });
            if parents.len() >= MAX_PARENTS {
                return Err(full().into());
            }
            retired
        };
        for parent in retired {
            parent.join().await;
        }
        let stream =
            tokio::select! {_ = shutdown.changed()=>return Err(closed().into()),r=connect=>r?};
        let parent = Parent::new(stream);
        let child = parent.allocate(target, self.concurrency, global_id);
        let admitted = {
            let mut parents = lock(&self.parents);
            if child.is_some() && !self.closed.load(Ordering::Acquire) {
                parents.push(parent.clone());
                true
            } else {
                false
            }
        };
        if !admitted {
            parent.close();
            parent.join().await;
            return Err(closed().into());
        }
        Ok(child.expect("admission requires an allocated child"))
    }
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.shutdown.send_replace(true);
        for parent in lock(&self.parents).iter() {
            parent.close();
        }
    }
    pub(super) async fn join(&self) {
        let parents = std::mem::take(&mut *lock(&self.parents));
        for parent in parents {
            parent.join().await;
        }
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.close();
    }
}

struct Parent {
    shared: Arc<Shared>,
    task: Mutex<Option<JoinHandle<()>>>,
}
impl std::fmt::Debug for Parent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = lock(&self.shared.state);
        f.debug_struct("MuxParent")
            .field("children", &state.children.len())
            .field("closed", &state.closed)
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    changed: Notify,
}
#[derive(Debug, Default)]
struct State {
    children: BTreeMap<u16, Entry>,
    next: u16,
    cursor: u16,
    closed: bool,
}
#[derive(Debug)]
struct Packet {
    source: Option<Target>,
    bytes: Bytes,
}
#[derive(Debug)]
struct Entry {
    target: Target,
    global_id: [u8; 8],
    rx: VecDeque<Packet>,
    tx: VecDeque<(u64, Bytes)>,
    started: bool,
    inflight: bool,
    closing: bool,
    ended: bool,
    dropped: bool,
    failed: bool,
    read_eof: bool,
    accepted: u64,
    sent: u64,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}
impl Parent {
    fn new(stream: BoxedTransportStream) -> Arc<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            changed: Notify::new(),
        });
        let driver = shared.clone();
        let task = tokio::spawn(async move {
            struct Guard(Arc<Shared>);
            impl Drop for Guard {
                fn drop(&mut self) {
                    self.0.close();
                }
            }
            let _guard = Guard(driver.clone());
            let (read, write) = tokio::io::split(stream);
            // These futures are owned by one joinable task. Cancelling any
            // branch closes both directions and all child waiters.
            tokio::select! {
                _ = read_loop(driver.clone(),read) => {},
                _ = write_loop(driver.clone(),write) => {},
                _ = idle_loop(driver.clone()) => {},
            }
        });
        Arc::new(Self {
            shared,
            task: Mutex::new(Some(task)),
        })
    }
    fn allocate(
        self: &Arc<Self>,
        target: &Target,
        concurrency: u16,
        global_id: [u8; 8],
    ) -> Option<Child> {
        let mut state = lock(&self.shared.state);
        if state.closed
            || state.children.len() >= usize::from(concurrency)
            || state.next >= MAX_CHILDREN_EVER
        {
            return None;
        }
        state.next += 1;
        let id = state.next;
        state.children.insert(
            id,
            Entry {
                target: target.clone(),
                global_id,
                rx: VecDeque::new(),
                tx: VecDeque::new(),
                started: false,
                inflight: false,
                closing: false,
                ended: false,
                dropped: false,
                failed: false,
                read_eof: false,
                accepted: 0,
                sent: 0,
                read_waker: None,
                write_waker: None,
            },
        );
        drop(state);
        self.shared.changed.notify_one();
        Some(Child {
            token: Arc::new(Token {
                parent: self.clone(),
                id,
            }),
            source: None,
        })
    }
    fn close(&self) {
        self.shared.close();
        if let Some(task) = lock(&self.task).as_ref() {
            task.abort();
        }
    }
    async fn join(&self) {
        let task = lock(&self.task).take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}
impl Drop for Parent {
    fn drop(&mut self) {
        self.close();
    }
}
impl Shared {
    fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        for entry in state.children.values_mut() {
            entry.failed = true;
            entry.rx.clear();
            entry.tx.clear();
            wake(&mut entry.read_waker);
            wake(&mut entry.write_waker);
        }
        self.changed.notify_waiters();
    }
}
#[derive(Debug)]
struct Token {
    parent: Arc<Parent>,
    id: u16,
}
impl Drop for Token {
    fn drop(&mut self) {
        let shared = &self.parent.shared;
        let mut state = lock(&shared.state);
        if let Some(entry) = state.children.get_mut(&self.id) {
            if entry.ended || !entry.started && !entry.inflight {
                state.children.remove(&self.id);
            } else {
                entry.dropped = true;
                entry.closing = true;
                entry.rx.clear();
                entry.tx.clear();
            }
        }
        drop(state);
        shared.changed.notify_one();
    }
}
#[derive(Debug)]
pub(super) struct Child {
    token: Arc<Token>,
    source: Option<Target>,
}
impl Child {
    fn writer(&self) -> Self {
        Self {
            token: self.token.clone(),
            source: None,
        }
    }
}
impl AsyncRead for Child {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = lock(&this.token.parent.shared.state);
        let entry = state.children.get_mut(&this.token.id).ok_or_else(closed)?;
        if entry.failed {
            return Poll::Ready(Err(closed()));
        }
        if let Some(packet) = entry.rx.front_mut() {
            if entry.target.network == RoutingNetwork::Udp && out.remaining() < packet.bytes.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Mux datagram receive buffer too small",
                )));
            }
            let n = out.remaining().min(packet.bytes.len());
            out.put_slice(&packet.bytes.split_to(n));
            this.source = packet.source.clone();
            if packet.bytes.is_empty() {
                entry.rx.pop_front();
            }
            return Poll::Ready(Ok(()));
        }
        if entry.read_eof {
            return Poll::Ready(Ok(()));
        }
        entry.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
impl AsyncWrite for Child {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.token.parent.shared;
        let mut state = lock(&shared.state);
        let entry = state.children.get_mut(&self.token.id).ok_or_else(closed)?;
        if entry.failed || entry.closing || entry.ended {
            return Poll::Ready(Err(closed()));
        }
        if entry.target.network == RoutingNetwork::Udp && input.len() > wire::MAX_PAYLOAD {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mux datagram too large",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if entry.tx.len() >= CHILD_QUEUE {
            entry.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = input.len().min(wire::MAX_PAYLOAD);
        entry.accepted = entry.accepted.checked_add(1).ok_or_else(closed)?;
        let seq = entry.accepted;
        entry
            .tx
            .push_back((seq, Bytes::copy_from_slice(&input[..n])));
        drop(state);
        shared.changed.notify_one();
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = lock(&self.token.parent.shared.state);
        let entry = state.children.get_mut(&self.token.id).ok_or_else(closed)?;
        if entry.failed || entry.ended && entry.sent != entry.accepted {
            return Poll::Ready(Err(closed()));
        }
        if !entry.inflight
            && entry.sent == entry.accepted
            && (entry.started || entry.target.network == RoutingNetwork::Udp)
        {
            return Poll::Ready(Ok(()));
        }
        entry.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        let shared = &self.token.parent.shared;
        let mut state = lock(&shared.state);
        let entry = state.children.get_mut(&self.token.id).ok_or_else(closed)?;
        if entry.ended {
            return Poll::Ready(Ok(()));
        }
        entry.closing = true;
        entry.write_waker = Some(cx.waker().clone());
        drop(state);
        shared.changed.notify_one();
        Poll::Pending
    }
}
impl TransportStream for Child {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read(cx, out)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write(cx, data)
    }
}

async fn write_loop(
    shared: Arc<Shared>,
    mut stream: tokio::io::WriteHalf<BoxedTransportStream>,
) -> io::Result<()> {
    loop {
        let notified = shared.changed.notified();
        let next = {
            let mut state = lock(&shared.state);
            if state.closed {
                return Err(closed());
            }
            // Dropped/overloaded children get control priority. Remaining
            // children get one frame per round-robin visit.
            let priority = state
                .children
                .iter()
                .find(|(_, e)| e.dropped && !e.ended)
                .map(|(&id, _)| id);
            let ready = |e: &Entry| {
                !e.ended
                    && (e.closing
                        || !e.tx.is_empty()
                        || !e.started && e.target.network == RoutingNetwork::Tcp)
            };
            let id = priority.or_else(|| {
                state
                    .children
                    .range((
                        std::ops::Bound::Excluded(state.cursor),
                        std::ops::Bound::Unbounded,
                    ))
                    .chain(state.children.range(..=state.cursor))
                    .find(|(_, e)| ready(e))
                    .map(|(&id, _)| id)
            });
            id.map(|id| {
                state.cursor = id;
                let e = state.children.get_mut(&id).unwrap();
                let end = e.closing && e.tx.is_empty();
                let status = if end {
                    Status::End
                } else if e.started {
                    Status::Keep
                } else {
                    Status::New
                };
                let data = if end { None } else { e.tx.pop_front() };
                let target = (!end
                    && (status == Status::New || e.target.network == RoutingNetwork::Udp))
                    .then(|| e.target.clone());
                let global = (status == Status::New && e.target.network == RoutingNetwork::Udp)
                    .then_some(e.global_id);
                e.started = true;
                e.inflight = true;
                wake(&mut e.write_waker);
                (id, status, e.failed, target, global, data)
            })
        };
        let Some((id, status, error, target, global, data)) = next else {
            notified.await;
            continue;
        };
        let bytes = wire::encode(&Frame {
            session_id: id,
            status,
            error: error && status == Status::End,
            target,
            global_id: global,
            payload: data.as_ref().map(|(_, b)| b.as_ref()),
        })?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        let mut state = lock(&shared.state);
        if let Some(e) = state.children.get_mut(&id) {
            e.inflight = false;
            if let Some((seq, _)) = data {
                e.sent = seq;
            }
            if status == Status::End {
                e.ended = true;
                e.read_eof = true;
            }
            wake(&mut e.write_waker);
            wake(&mut e.read_waker);
            if e.dropped && e.ended {
                state.children.remove(&id);
            }
        }
    }
}
async fn read_loop(
    shared: Arc<Shared>,
    mut stream: tokio::io::ReadHalf<BoxedTransportStream>,
) -> io::Result<()> {
    let mut bytes = Vec::new();
    loop {
        if let Some((frame, n)) = wire::decode(&bytes)? {
            let mut state = lock(&shared.state);
            if frame.session_id > state.next && frame.status != Status::KeepAlive {
                return Err(closed());
            }
            if let Some(e) = state.children.get_mut(&frame.session_id) {
                match frame.status {
                    Status::Keep if !e.dropped && !e.failed && !e.read_eof => {
                        if let Some(payload) = frame.payload.filter(|p| !p.is_empty()) {
                            if e.rx.len() >= CHILD_QUEUE {
                                e.failed = true;
                                e.closing = true;
                                e.tx.clear();
                                e.rx.clear();
                                shared.changed.notify_one();
                            } else {
                                e.rx.push_back(Packet {
                                    source: frame.target,
                                    bytes: Bytes::copy_from_slice(payload),
                                });
                            }
                        }
                    }
                    Status::End => {
                        e.read_eof = true;
                        e.ended = true;
                        e.tx.clear();
                        if frame.error || e.sent != e.accepted {
                            e.failed = true;
                        }
                    }
                    _ => {}
                }
                wake(&mut e.read_waker);
                wake(&mut e.write_waker);
                if e.dropped && e.ended {
                    state.children.remove(&frame.session_id);
                }
            }
            drop(state);
            bytes.drain(..n);
        } else {
            let capacity = wire::MAX_FRAME - bytes.len();
            if capacity == 0 {
                return Err(closed());
            }
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk[..capacity.min(4096)]).await?;
            if n == 0 {
                return Err(closed());
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
        tokio::task::yield_now().await;
    }
}

async fn idle_loop(shared: Arc<Shared>) {
    loop {
        tokio::time::sleep(IDLE).await;
        let idle = {
            let mut state = lock(&shared.state);
            let idle = state.children.is_empty();
            if idle {
                state.closed = true;
            }
            idle
        };
        if idle {
            break;
        }
    }
}

pub(crate) struct UdpSession {
    target: Target,
    reader: AsyncMutex<Child>,
    writer: AsyncMutex<Child>,
}
impl UdpSession {
    pub(super) fn new(child: Child, target: Target) -> Self {
        Self {
            target,
            writer: AsyncMutex::new(child.writer()),
            reader: AsyncMutex::new(child),
        }
    }
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        if target != &self.target || payload.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid Mux datagram").into());
        }
        let mut writer = self.writer.lock().await;
        writer.write_all(payload).await?;
        writer.flush().await?;
        Ok(())
    }
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        let mut reader = self.reader.lock().await;
        let mut bytes = vec![0; wire::MAX_PAYLOAD];
        let n = reader.read(&mut bytes).await?;
        if n == 0 {
            return Err(closed().into());
        }
        bytes.truncate(n);
        Ok(datagram::Datagram {
            source: reader.source.clone().unwrap_or_else(|| self.target.clone()),
            payload: bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::DuplexStream, time::timeout};
    fn destination(network: RoutingNetwork) -> Target {
        Target::new(
            RoutingTargetAddr::Domain("example.test".into()),
            8443,
            network,
        )
    }
    fn pair() -> (BoxedTransportStream, DuplexStream) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        (Box::new(protocol_stream::ProtocolStream(a)), b)
    }
    async fn unused() -> Result<BoxedTransportStream, CoreError> {
        panic!("pool should reuse the parent");
    }

    #[test]
    fn mux_udp443_and_native_fallback_match_pinned_dispatch() {
        use xray_config::{MuxSettings, MuxUdp443};
        for tcp in [-1, 0, 4] {
            for udp in [-1, 0, 4] {
                for policy in [MuxUdp443::Reject, MuxUdp443::Allow, MuxUdp443::Skip] {
                    let runtime = Runtime::new(
                        &Some(MuxSettings {
                            concurrency: tcp,
                            xudp_concurrency: udp,
                            udp443: policy,
                        }),
                        &StreamTransport::Raw,
                    )
                    .unwrap()
                    .unwrap();
                    let tcp_target = destination(RoutingNetwork::Tcp);
                    let udp_target = destination(RoutingNetwork::Udp);
                    let mut quic = udp_target.clone();
                    quic.port = 443;
                    assert_eq!(runtime.pool(&tcp_target).unwrap().is_some(), tcp >= 0);
                    let pooled = udp > 0 || udp == 0 && tcp >= 0;
                    assert_eq!(runtime.pool(&udp_target).unwrap().is_some(), pooled);
                    match policy {
                        MuxUdp443::Reject => assert!(runtime.pool(&quic).is_err()),
                        MuxUdp443::Skip => assert!(runtime.pool(&quic).unwrap().is_none()),
                        MuxUdp443::Allow => {
                            assert_eq!(runtime.pool(&quic).unwrap().is_some(), pooled)
                        }
                    }
                }
            }
        }
        let invalid = Some(MuxSettings {
            concurrency: 65,
            xudp_concurrency: 0,
            udp443: MuxUdp443::Reject,
        });
        assert!(Runtime::new(&invalid, &StreamTransport::Raw).is_err());
    }

    #[tokio::test]
    async fn mux_pool_capacity_close_join_and_cancelled_cold_connect_are_bounded() {
        let pool = Pool::new(2);
        let target = destination(RoutingNetwork::Tcp);
        let mut peers = Vec::new();
        let mut children = Vec::new();
        for _ in 0..MAX_PARENTS {
            let (stream, peer) = pair();
            peers.push(peer);
            children.push(pool.open(&target, async { Ok(stream) }).await.unwrap());
            children.push(pool.open(&target, unused()).await.unwrap());
        }
        assert!(
            matches!(pool.open(&target,unused()).await,Err(CoreError::Io(e)) if e.kind()==io::ErrorKind::WouldBlock)
        );
        pool.close();
        pool.join().await;
        for child in &mut children {
            assert!(child.write_all(b"closed").await.is_err());
            assert!(child.read_u8().await.is_err());
        }
        assert!(lock(&pool.parents).is_empty());
        assert!(pool.open(&target, unused()).await.is_err());
        let pool = Pool::new(2);
        let pending = pool.open(&target, std::future::pending());
        tokio::pin!(pending);
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        pool.close();
        assert!(pending.await.is_err());
        pool.join().await;
        assert!(lock(&pool.parents).is_empty());
    }

    #[tokio::test]
    async fn mux_blocked_child_is_reset_without_blocking_siblings_or_control_frames() {
        timeout(Duration::from_secs(2), async {
            let pool = Pool::new(2);
            let target = destination(RoutingNetwork::Tcp);
            let (stream, mut peer) = pair();
            let mut slow = pool.open(&target, async { Ok(stream) }).await.unwrap();
            let mut fast = pool.open(&target, unused()).await.unwrap();
            slow.flush().await.unwrap();
            fast.flush().await.unwrap();
            for _ in 0..=CHILD_QUEUE {
                peer.write_all(
                    &wire::encode(&Frame {
                        session_id: slow.token.id,
                        status: Status::Keep,
                        error: false,
                        target: None,
                        global_id: None,
                        payload: Some(&[0x55; 8192]),
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            }
            peer.write_all(
                &wire::encode(&Frame {
                    session_id: fast.token.id,
                    status: Status::Keep,
                    error: false,
                    target: None,
                    global_id: None,
                    payload: Some(b"alive"),
                })
                .unwrap(),
            )
            .await
            .unwrap();
            let mut response = [0; 5];
            fast.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"alive");
            assert!(slow.read_u8().await.is_err());
            let mut received = Vec::new();
            loop {
                let mut chunk = [0; 512];
                let n = peer.read(&mut chunk).await.unwrap();
                received.extend_from_slice(&chunk[..n]);
                let mut ended = false;
                while let Some((frame, n)) = wire::decode(&received).unwrap() {
                    ended |= frame.status == Status::End
                        && frame.session_id == slow.token.id
                        && frame.error;
                    received.drain(..n);
                }
                if ended {
                    break;
                }
            }
            assert!(!format!("{pool:?}").contains("example.test"));
            pool.close();
            pool.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn mux_peer_failure_reconnects_for_new_children_without_replaying_old_data() {
        let pool = Pool::new(4);
        let target = destination(RoutingNetwork::Tcp);
        let (stream, peer) = pair();
        let mut old = pool.open(&target, async { Ok(stream) }).await.unwrap();
        old.write_all(b"must not replay").await.unwrap();
        old.flush().await.unwrap();
        drop(peer);
        assert!(old.read_u8().await.is_err());
        let (stream, mut peer) = pair();
        let mut new = pool.open(&target, async { Ok(stream) }).await.unwrap();
        new.write_all(b"new").await.unwrap();
        new.flush().await.unwrap();
        let mut bytes = [0; 512];
        let n = peer.read(&mut bytes).await.unwrap();
        assert!(!bytes[..n].windows(15).any(|w| w == b"must not replay"));
        assert!(bytes[..n].windows(3).any(|w| w == b"new"));
        pool.close();
        pool.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn mux_idle_parent_expires_and_session_ids_do_not_recycle() {
        let pool = Pool::new(1);
        let target = destination(RoutingNetwork::Tcp);
        let (stream, _peer) = pair();
        let first = pool.open(&target, async { Ok(stream) }).await.unwrap();
        let parent = first.token.parent.clone();
        let old_id = first.token.id;
        drop(first);
        let second = pool.open(&target, unused()).await.unwrap();
        assert!(second.token.id > old_id);
        drop(second);
        // Let the driver send any pending END before observing idleness.
        tokio::task::yield_now().await;
        tokio::time::advance(IDLE * 2).await;
        tokio::task::yield_now().await;
        assert!(lock(&parent.shared.state).closed);
        pool.close();
        pool.join().await;
    }
}
