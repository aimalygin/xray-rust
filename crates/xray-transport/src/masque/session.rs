//! One CONNECT-IP tunnel after its request was accepted, as Xray-core
//! v26.10.31's `connectip.Conn` and `masque.Conn` run it on a client: the
//! capsule stream, address assignment and the packets in datagrams.
use std::future::poll_fn;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::{Buf, Bytes, BytesMut};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinHandle;

use super::capsule::{
    self, varint_len, AssignedAddress, Capsule, CapsuleParser, IpPrefix, Parsed, CAPSULE_DATAGRAM,
    MAX_CAPSULE_PACKET,
};
use super::packet::{self, Destinations, IcmpError};
use super::MIN_PACKET_SIZE;

/// Xray's `maxQueuedCapsules`: control capsules waiting to be written, and
/// address updates waiting to be read.
const MAX_QUEUED_CAPSULES: usize = 128;
/// The bytes those control capsules may hold. Xray bounds only their number,
/// and the answer to an ADDRESS_REQUEST is as large as the request: a proxy
/// that grants the request stream no credit and keeps asking would have the
/// client hold a full queue of answers of about 200 KiB each.
const MAX_QUEUED_CAPSULE_BYTES: usize = 256 * 1024;
/// Xray's `maxQueuedDatagrams`: DATAGRAM capsules read and not yet taken.
const MAX_QUEUED_DATAGRAMS: usize = 128;
/// Xray's `maxStreamBuffer`: DATAGRAM capsule bytes an HTTP/2 tunnel holds
/// for the request body; a packet waits while that much is queued.
const MAX_STREAM_BUFFER: usize = 32 << 10;
/// Xray's client reads into a `buf.Size` buffer and skips longer packets.
pub const MAX_TUNNEL_PACKET: usize = 8192;
/// HTTP/3 error codes the tunnel closes with.
const H3_NO_ERROR: u32 = 0x100;
const H3_EXCESSIVE_LOAD: u32 = 0x107;
const H3_MESSAGE_ERROR: u32 = 0x10e;

/// A tunnel failure. Messages carry no header value or credential.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MasqueError {
    #[error("MASQUE dial failed: {0}")]
    Dial(String),
    #[error("MASQUE socket protection failed: {0}")]
    SocketProtection(String),
    #[error("connect-ip: server didn't enable Extended CONNECT")]
    NoExtendedConnect,
    #[error("connect-ip: server didn't enable datagrams")]
    NoDatagrams,
    #[error("connect-ip: server responded with {0}")]
    Status(u16),
    #[error("CONNECT-IP request failed: {0}")]
    Request(String),
    #[error("the tunnel can only carry {0}-byte packets, less than {MIN_PACKET_SIZE}")]
    PacketSize(usize),
    #[error("no address assigned: {0}")]
    NoAddress(String),
    #[error("MASQUE tunnel establishment timed out")]
    Timeout,
    #[error("MASQUE: closing the tunnel as it cannot carry {MIN_PACKET_SIZE}-byte packets")]
    MtuTooSmall,
    #[error("MASQUE tunnel closed: {0}")]
    Closed(String),
}

/// What became of a packet handed to [`MasqueTunnel::write_packet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    Sent,
    /// Dropped as Xray drops it: malformed, or its TTL ran out.
    Dropped,
    /// Too big for the path: the ICMP Packet Too Big for the sender.
    TooBig(Vec<u8>),
}

/// The request stream's sending half.
pub(crate) enum RequestSend {
    H3(Box<h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>>),
    H2(h2::SendStream<Bytes>),
}

impl RequestSend {
    async fn send(&mut self, data: Bytes) -> Result<(), String> {
        match self {
            Self::H3(stream) => stream.send_data(data).await.map_err(|e| e.to_string()),
            Self::H2(stream) => send_h2(stream, data).await,
        }
    }

    async fn finish(&mut self) {
        match self {
            Self::H3(stream) => {
                let _ = stream.finish().await;
            }
            Self::H2(stream) => {
                let _ = stream.send_data(Bytes::new(), true);
            }
        }
    }
}

/// Hands `data` to HTTP/2 within the server's flow-control windows, so a
/// spent window holds the writer back, as Xray's `awaitSendWindow` does.
async fn send_h2(stream: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<(), String> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let capacity = match poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(Ok(capacity)) => capacity,
            Some(Err(error)) => return Err(error.to_string()),
            None => return Err("the request stream is closed".to_owned()),
        };
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        stream
            .send_data(chunk, false)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// The request stream's receiving half.
pub(crate) enum RequestRecv {
    H3(h3::client::RequestStream<h3_quinn::RecvStream, Bytes>),
    H2(h2::RecvStream),
}

impl RequestRecv {
    async fn recv(&mut self) -> Result<Option<Bytes>, String> {
        match self {
            Self::H3(stream) => match stream.recv_data().await {
                Ok(Some(mut data)) => Ok(Some(data.copy_to_bytes(data.remaining()))),
                Ok(None) => Ok(None),
                Err(error) => Err(error.to_string()),
            },
            // The window opens as the reader takes the data, as Xray's
            // response body does.
            Self::H2(stream) => match stream.data().await {
                Some(Ok(data)) => {
                    let _ = stream.flow_control().release_capacity(data.len());
                    Ok(Some(data))
                }
                Some(Err(error)) => Err(error.to_string()),
                None => Ok(None),
            },
        }
    }
}

/// How the tunnel's packets travel, as [`start`] is told.
pub(crate) enum Datagrams {
    /// QUIC DATAGRAM frames after the request stream's quarter ID.
    Quic {
        connection: quinn::Connection,
        quarter_stream_id: u64,
    },
    /// DATAGRAM capsules on the request stream, as over HTTP/2. `bare`
    /// leaves the context ID out, as Cloudflare's HTTP/2 tunnel does.
    Capsules { bare: bool },
}

/// How packets travel once the tunnel runs.
enum DatagramPath {
    Quic {
        connection: quinn::Connection,
        quarter_stream_id: u64,
    },
    Capsules {
        outgoing: mpsc::UnboundedSender<Bytes>,
        /// Room left of [`MAX_STREAM_BUFFER`] for outgoing capsules.
        room: Arc<Semaphore>,
        incoming: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
        bare: bool,
    },
}

/// What keeps the HTTP connection up, closed with the tunnel.
pub(crate) enum HttpConnection {
    Quic {
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        /// h3 closes the connection once its last request handle is gone.
        _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        tasks: Vec<JoinHandle<()>>,
    },
    /// One HTTP/2 connection for the tunnel alone; its tasks drive it, and
    /// stopping them closes it.
    Http2 {
        _send_request: h2::client::SendRequest<Bytes>,
        tasks: Vec<JoinHandle<()>>,
    },
}

impl HttpConnection {
    fn close(&self, code: u32) {
        match self {
            Self::Quic {
                endpoint,
                connection,
                tasks,
                ..
            } => {
                connection.close(quinn::VarInt::from_u32(code), b"");
                for task in tasks {
                    task.abort();
                }
                let _ = endpoint;
            }
            Self::Http2 { tasks, .. } => {
                for task in tasks {
                    task.abort();
                }
            }
        }
    }
}

struct Shared {
    local: OnceLock<Vec<IpAddr>>,
    destinations: Mutex<Destinations>,
    path: DatagramPath,
    control: mpsc::Sender<Bytes>,
    control_bytes: Arc<AtomicUsize>,
    http: HttpConnection,
    closed: watch::Sender<Option<String>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Shared {
    /// Closes the tunnel once, keeping the first reason.
    fn close(&self, reason: impl Into<String>, code: u32) {
        let reason = reason.into();
        let first = self.closed.send_if_modified(|closed| {
            if closed.is_none() {
                *closed = Some(reason);
                true
            } else {
                false
            }
        });
        if first {
            if let DatagramPath::Capsules { room, .. } = &self.path {
                room.close();
            }
            self.http.close(code);
            for task in self
                .tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .drain(..)
            {
                task.abort();
            }
        }
    }

    fn closed_error(&self) -> MasqueError {
        MasqueError::Closed(
            self.closed
                .borrow()
                .clone()
                .unwrap_or_else(|| "closed".to_owned()),
        )
    }

    /// Queues a control capsule; a full queue closes the tunnel, as Xray's
    /// `queueWrite` does.
    fn queue(&self, capsule: Bytes) -> Result<(), MasqueError> {
        match queue_control(&self.control, &self.control_bytes, capsule) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.close("connect-ip: capsule queue full", H3_EXCESSIVE_LOAD);
                Err(self.closed_error())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(self.closed_error()),
        }
    }
}

/// Puts `capsule` in the control queue unless it holds [`MAX_QUEUED_CAPSULES`]
/// capsules or [`MAX_QUEUED_CAPSULE_BYTES`] already; the writer takes the
/// bytes off `queued` as it takes each capsule.
fn queue_control(
    control: &mpsc::Sender<Bytes>,
    queued: &AtomicUsize,
    capsule: Bytes,
) -> Result<(), mpsc::error::TrySendError<Bytes>> {
    let len = capsule.len();
    if queued.load(Ordering::Relaxed) > MAX_QUEUED_CAPSULE_BYTES {
        return Err(mpsc::error::TrySendError::Full(capsule));
    }
    queued.fetch_add(len, Ordering::Relaxed);
    control.try_send(capsule).inspect_err(|_| {
        queued.fetch_sub(len, Ordering::Relaxed);
    })
}

/// A CONNECT-IP tunnel: IP packets in and out, from the local addresses the
/// proxy assigned. Dropping it closes the tunnel.
pub struct MasqueTunnel {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for MasqueTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueTunnel")
            .field("local", &self.shared.local.get())
            .field("closed", &self.shared.closed.borrow().is_some())
            .finish()
    }
}

impl Drop for MasqueTunnel {
    fn drop(&mut self) {
        self.shared.close("tunnel dropped", H3_NO_ERROR);
    }
}

/// How the tunnel gets its addresses.
pub(crate) enum Addressing {
    /// Ask for one address of each family, as Xray's client does.
    Request,
    /// WARP's addresses, which the proxy assigns without being asked:
    /// Xray's `SetAssignedAddresses`.
    Fixed(Vec<IpPrefix>),
}

/// The writer's share of the DATAGRAM capsules, over HTTP/2.
struct OutgoingCapsules {
    capsules: mpsc::UnboundedReceiver<Bytes>,
    room: Arc<Semaphore>,
}

/// Runs the tunnel on an accepted request and waits for its addresses.
pub(crate) async fn start(
    send: RequestSend,
    recv: RequestRecv,
    datagrams: Datagrams,
    http: HttpConnection,
    addressing: Addressing,
) -> Result<MasqueTunnel, MasqueError> {
    let (control, control_rx) = mpsc::channel(MAX_QUEUED_CAPSULES);
    let control_bytes = Arc::new(AtomicUsize::new(0));
    let (assignments, mut assignments_rx) = mpsc::channel(MAX_QUEUED_CAPSULES);
    let (path, outgoing, incoming) = match datagrams {
        Datagrams::Quic {
            connection,
            quarter_stream_id,
        } => (
            DatagramPath::Quic {
                connection,
                quarter_stream_id,
            },
            None,
            None,
        ),
        Datagrams::Capsules { bare } => {
            let (outgoing, capsules) = mpsc::unbounded_channel();
            let (incoming_tx, incoming) = mpsc::channel(MAX_QUEUED_DATAGRAMS);
            let room = Arc::new(Semaphore::new(MAX_STREAM_BUFFER));
            (
                DatagramPath::Capsules {
                    outgoing,
                    room: Arc::clone(&room),
                    incoming: tokio::sync::Mutex::new(incoming),
                    bare,
                },
                Some(OutgoingCapsules { capsules, room }),
                Some(incoming_tx),
            )
        }
    };
    let shared = Arc::new(Shared {
        local: OnceLock::new(),
        destinations: Mutex::new(Destinations::default()),
        path,
        control,
        control_bytes,
        http,
        closed: watch::channel(None).0,
        tasks: Mutex::new(Vec::new()),
    });
    let tunnel = MasqueTunnel {
        shared: Arc::clone(&shared),
    };
    {
        let writer = tokio::spawn(write_capsules(
            send,
            control_rx,
            Arc::clone(&shared.control_bytes),
            outgoing,
            Arc::downgrade(&shared),
        ));
        let reader = tokio::spawn(read_capsules(
            recv,
            assignments,
            incoming,
            Arc::downgrade(&shared),
        ));
        shared
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend([writer, reader]);
    }
    let local = match addressing {
        Addressing::Request => {
            shared.queue(capsule::address_request(&[
                AssignedAddress {
                    request_id: 1,
                    prefix: IpPrefix::rejection(true),
                },
                AssignedAddress {
                    request_id: 2,
                    prefix: IpPrefix::rejection(false),
                },
            ]))?;
            let mut closed = shared.closed.subscribe();
            loop {
                let assigned = tokio::select! {
                    assigned = assignments_rx.recv() => assigned,
                    _ = closed.wait_for(Option::is_some) => None,
                };
                let Some(assigned) = assigned else {
                    return Err(MasqueError::NoAddress(match shared.closed_error() {
                        MasqueError::Closed(reason) => reason,
                        other => other.to_string(),
                    }));
                };
                let local = local_addrs(&assigned);
                if !local.is_empty() {
                    break local;
                }
            }
        }
        // The addresses as written, not their prefixes' first hosts.
        Addressing::Fixed(prefixes) => {
            shared
                .destinations
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .assigned = prefixes.clone();
            prefixes.iter().map(|prefix| prefix.addr).collect()
        }
    };
    let _ = shared.local.set(local.clone());
    let watcher = tokio::spawn(serve_assignments(
        assignments_rx,
        local,
        Arc::downgrade(&shared),
    ));
    shared
        .tasks
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(watcher);
    if shared.closed.borrow().is_some() {
        return Err(shared.closed_error());
    }
    Ok(tunnel)
}

/// Xray's `localAddrs`: the first usable address of each family; a whole
/// prefix contributes its first host address.
pub(crate) fn local_addrs(assigned: &[AssignedAddress]) -> Vec<IpAddr> {
    let mut local = Vec::new();
    let (mut has4, mut has6) = (false, false);
    for entry in assigned {
        if entry.prefix.is_rejection() {
            continue;
        }
        let mut addr = entry.prefix.addr;
        if entry.prefix.len != entry.prefix.bits() {
            addr = next_addr(entry.prefix.masked().addr);
        }
        if addr.is_ipv4() && !has4 {
            has4 = true;
            local.push(addr);
        } else if addr.is_ipv6() && !has6 {
            has6 = true;
            local.push(addr);
        }
    }
    local
}

/// Go's `netip.Addr.Next`; the last address stays itself, which a masked
/// prefix shorter than the address never is.
fn next_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => IpAddr::V4(u32::from(v4).saturating_add(1).into()),
        IpAddr::V6(v6) => IpAddr::V6(u128::from(v6).saturating_add(1).into()),
    }
}

/// The permits an outgoing capsule takes of [`MAX_STREAM_BUFFER`].
fn room_for(len: usize) -> u32 {
    len.min(MAX_STREAM_BUFFER) as u32
}

/// Writes control capsules and, over HTTP/2, DATAGRAM capsules, each whole,
/// as Xray's `writeMu` keeps them.
async fn write_capsules(
    mut send: RequestSend,
    mut control: mpsc::Receiver<Bytes>,
    control_bytes: Arc<AtomicUsize>,
    mut datagrams: Option<OutgoingCapsules>,
    shared: std::sync::Weak<Shared>,
) {
    loop {
        let (capsule, counted) = match &mut datagrams {
            Some(datagrams) => tokio::select! { biased;
                capsule = control.recv() => (capsule, false),
                capsule = datagrams.capsules.recv() => (capsule, true),
            },
            None => (control.recv().await, false),
        };
        let Some(capsule) = capsule else {
            break;
        };
        let len = capsule.len();
        if !counted {
            control_bytes.fetch_sub(len, Ordering::Relaxed);
        }
        if let Err(error) = send.send(capsule).await {
            if let Some(shared) = shared.upgrade() {
                shared.close(
                    format!("writing capsules failed: {error}"),
                    H3_EXCESSIVE_LOAD,
                );
            }
            return;
        }
        if counted {
            if let Some(datagrams) = &datagrams {
                datagrams.room.add_permits(room_for(len) as usize);
            }
        }
    }
    send.finish().await;
}

async fn read_capsules(
    mut recv: RequestRecv,
    assignments: mpsc::Sender<Vec<AssignedAddress>>,
    datagrams: Option<mpsc::Sender<Bytes>>,
    shared: std::sync::Weak<Shared>,
) {
    let mut parser = CapsuleParser::default();
    let failure = loop {
        let data = match recv.recv().await {
            Ok(Some(data)) => data,
            Ok(None) if parser.is_mid_capsule() => {
                break Some(("reading capsules failed: unexpected EOF".to_owned(), false));
            }
            Ok(None) => break None,
            Err(error) => break Some((format!("reading capsules failed: {error}"), false)),
        };
        parser.push(data);
        let mut failed = None;
        loop {
            match parser.next() {
                // Over HTTP/2 a packet waits for the reader, holding the
                // stream back, as Xray's `queueDatagram` does. Over HTTP/3
                // packets ride QUIC DATAGRAM frames only; Xray drops those
                // sent in capsules.
                Ok(Some(Parsed::Capsule(Capsule::Datagram(value)))) => {
                    if let Some(datagrams) = &datagrams {
                        if datagrams.send(value).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(Some(Parsed::Capsule(capsule))) => {
                    let Some(shared) = shared.upgrade() else {
                        return;
                    };
                    if let Err(error) = handle_capsule(&shared, capsule, &assignments) {
                        failed = Some(error);
                        break;
                    }
                }
                Ok(Some(Parsed::OversizedDatagram(_))) => {}
                Ok(None) => break,
                Err(error) => {
                    failed = Some((format!("reading capsules failed: {error}"), error.limit));
                    break;
                }
            }
        }
        if failed.is_some() {
            break failed;
        }
    };
    if let Some(shared) = shared.upgrade() {
        match failure {
            Some((reason, limit)) => shared.close(
                reason,
                if limit {
                    H3_EXCESSIVE_LOAD
                } else {
                    H3_MESSAGE_ERROR
                },
            ),
            None => shared.close("the proxy closed the tunnel", H3_NO_ERROR),
        }
    }
}

/// One control capsule from the proxy; an error is the reason and whether
/// it was a limit.
fn handle_capsule(
    shared: &Shared,
    capsule: Capsule,
    assignments: &mpsc::Sender<Vec<AssignedAddress>>,
) -> Result<(), (String, bool)> {
    match capsule {
        Capsule::AddressAssign(entries) => {
            shared
                .destinations
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .assigned = entries
                .iter()
                .filter(|entry| !entry.prefix.is_rejection())
                .map(|entry| entry.prefix)
                .collect();
            if assignments.try_send(entries).is_err() {
                return Err((
                    "connect-ip: capsule limit exceeded: address assignment queue full".to_owned(),
                    true,
                ));
            }
        }
        // The client assigns nothing: every request is refused, as Xray's
        // `serveAddressRequests` refuses it.
        Capsule::AddressRequest(entries) => {
            let refusals: Vec<AssignedAddress> = entries
                .iter()
                .map(|entry| AssignedAddress {
                    request_id: entry.request_id,
                    prefix: IpPrefix::rejection(entry.prefix.addr.is_ipv4()),
                })
                .collect();
            shared
                .queue(capsule::address_assign(&refusals))
                .map_err(|error| (error.to_string(), true))?;
        }
        // Routes only restrict a proxy's own sending; a client keeps none.
        Capsule::RouteAdvertisement(_) => {}
        // The reader takes DATAGRAM capsules before they get here.
        Capsule::Datagram(_) => {}
    }
    Ok(())
}

/// Xray's `serveAddressAssignments`: the tunnel closes once the proxy
/// withdraws a local address.
async fn serve_assignments(
    mut assignments: mpsc::Receiver<Vec<AssignedAddress>>,
    local: Vec<IpAddr>,
    shared: std::sync::Weak<Shared>,
) {
    while let Some(assigned) = assignments.recv().await {
        for addr in &local {
            if !assigned
                .iter()
                .any(|entry| !entry.prefix.is_rejection() && entry.prefix.contains(*addr))
            {
                if let Some(shared) = shared.upgrade() {
                    shared.close(
                        format!("MASQUE: closing the tunnel as the proxy withdrew {addr}"),
                        H3_NO_ERROR,
                    );
                }
                return;
            }
        }
    }
}

impl MasqueTunnel {
    /// The addresses the tunnel's packets come from: at most one per family.
    pub fn local_addrs(&self) -> &[IpAddr] {
        self.shared.local.get().map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.borrow().is_some()
    }

    /// Why the tunnel closed, once it has.
    pub fn close_reason(&self) -> Option<String> {
        self.shared.closed.borrow().clone()
    }

    /// Resolves once the tunnel is closed.
    pub async fn closed(&self) {
        let mut closed = self.shared.closed.subscribe();
        let _ = closed.wait_for(Option::is_some).await;
    }

    pub fn close(&self) {
        self.shared.close("closed locally", H3_NO_ERROR);
    }

    /// The largest packet the tunnel carries now, as Xray's `MaxPacketSize`.
    pub fn max_packet_size(&self) -> usize {
        if self.is_closed() {
            return 0;
        }
        match &self.shared.path {
            DatagramPath::Quic {
                connection,
                quarter_stream_id,
            } => quic_max_packet(connection, *quarter_stream_id),
            DatagramPath::Capsules { .. } => MAX_CAPSULE_PACKET,
        }
    }

    /// The next packet from the proxy for a local address, at most
    /// [`MAX_TUNNEL_PACKET`] bytes; others are dropped as Xray drops them.
    pub async fn read_packet(&self) -> Result<Bytes, MasqueError> {
        let mut closed = self.shared.closed.subscribe();
        loop {
            if closed.borrow().is_some() {
                return Err(self.shared.closed_error());
            }
            let (datagram, bare) = match &self.shared.path {
                DatagramPath::Quic {
                    connection,
                    quarter_stream_id,
                } => {
                    let datagram = tokio::select! {
                        datagram = connection.read_datagram() => datagram,
                        _ = closed.wait_for(Option::is_some) => return Err(self.shared.closed_error()),
                    };
                    let datagram = match datagram {
                        Ok(datagram) => datagram,
                        Err(error) => {
                            self.shared
                                .close(format!("MASQUE tunnel closed: {error}"), H3_NO_ERROR);
                            return Err(self.shared.closed_error());
                        }
                    };
                    match capsule::parse_varint(&datagram) {
                        Some((quarter, n)) if quarter == *quarter_stream_id => {
                            (datagram.slice(n..), false)
                        }
                        _ => continue,
                    }
                }
                DatagramPath::Capsules { incoming, bare, .. } => {
                    let mut incoming = incoming.lock().await;
                    let value = tokio::select! {
                        value = incoming.recv() => value,
                        _ = closed.wait_for(Option::is_some) => return Err(self.shared.closed_error()),
                    };
                    match value {
                        Some(value) => (value, *bare),
                        None => return Err(self.shared.closed_error()),
                    }
                }
            };
            let Some(packet) = datagram_packet(datagram, bare) else {
                continue;
            };
            let allowed = packet::check_incoming(
                &packet,
                &self
                    .shared
                    .destinations
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            );
            if allowed.is_err() || packet.len() > MAX_TUNNEL_PACKET {
                continue;
            }
            return Ok(packet);
        }
    }

    /// Sends a packet from the local stack to the proxy, as Xray's
    /// `masque.Conn.Write` does: a failure closes the tunnel, a packet too
    /// big for the path comes back as an ICMP message for the sender.
    pub async fn write_packet(&self, packet: &[u8]) -> Result<WriteOutcome, MasqueError> {
        if self.is_closed() {
            return Err(self.shared.closed_error());
        }
        match &self.shared.path {
            DatagramPath::Quic {
                connection,
                quarter_stream_id,
            } => {
                let prefix = varint_len(*quarter_stream_id) + 1;
                let mut datagram = BytesMut::with_capacity(prefix + packet.len());
                capsule::put_varint(&mut datagram, *quarter_stream_id);
                capsule::put_varint(&mut datagram, 0);
                datagram.extend_from_slice(packet);
                if packet::prepare_outgoing(&mut datagram[prefix..]).is_err() {
                    return Ok(WriteOutcome::Dropped);
                }
                let datagram = datagram.freeze();
                match connection.send_datagram_wait(datagram.clone()).await {
                    Ok(()) => Ok(WriteOutcome::Sent),
                    Err(quinn::SendDatagramError::TooLarge) => {
                        let mtu = quic_max_packet(connection, *quarter_stream_id);
                        match packet::icmp_too_large(&datagram[prefix..], mtu) {
                            Ok(icmp) => Ok(WriteOutcome::TooBig(icmp)),
                            Err(IcmpError::MtuTooSmall(_)) => {
                                self.shared
                                    .close(MasqueError::MtuTooSmall.to_string(), H3_NO_ERROR);
                                Err(MasqueError::MtuTooSmall)
                            }
                            Err(IcmpError::Malformed(_)) => Ok(WriteOutcome::Dropped),
                        }
                    }
                    Err(error) => {
                        self.shared.close(
                            format!("MASQUE: closing the tunnel as sending failed: {error}"),
                            H3_NO_ERROR,
                        );
                        Err(self.shared.closed_error())
                    }
                }
            }
            DatagramPath::Capsules {
                outgoing,
                room,
                bare,
                ..
            } => {
                let Some(capsule) = datagram_capsule(packet, *bare) else {
                    return Ok(WriteOutcome::Dropped);
                };
                let mut closed = self.shared.closed.subscribe();
                let permit = tokio::select! {
                    permit = room.acquire_many(room_for(capsule.len())) => permit,
                    _ = closed.wait_for(Option::is_some) => return Err(self.shared.closed_error()),
                };
                match permit {
                    Ok(permit) => permit.forget(),
                    Err(_) => return Err(self.shared.closed_error()),
                }
                if outgoing.send(capsule).is_err() {
                    return Err(self.shared.closed_error());
                }
                Ok(WriteOutcome::Sent)
            }
        }
    }
}

/// The packet in a datagram after its quarter stream ID, as Xray's
/// `ReadPacket` takes it: after context ID 0, or the datagram itself when
/// `bare` and it does not start with a zero byte, which reads as context
/// ID 0. `None` for another context or a malformed one.
pub(crate) fn datagram_packet(datagram: Bytes, bare: bool) -> Option<Bytes> {
    if bare && datagram.first().is_some_and(|&first| first != 0) {
        return Some(datagram);
    }
    match capsule::parse_varint(&datagram) {
        Some((0, n)) => Some(datagram.slice(n..)),
        _ => None,
    }
}

/// Xray's `composeDatagram` for a capsule stream: the DATAGRAM capsule of
/// `packet` after its TTL step, or `None` for a packet Xray drops.
pub(crate) fn datagram_capsule(packet: &[u8], bare: bool) -> Option<Bytes> {
    let size = usize::from(!bare) + packet.len();
    let mut capsule =
        BytesMut::with_capacity(varint_len(CAPSULE_DATAGRAM) + varint_len(size as u64) + size);
    capsule::put_varint(&mut capsule, CAPSULE_DATAGRAM);
    capsule::put_varint(&mut capsule, size as u64);
    if !bare {
        capsule::put_varint(&mut capsule, 0);
    }
    let start = capsule.len();
    capsule.extend_from_slice(packet);
    packet::prepare_outgoing(&mut capsule[start..]).ok()?;
    Some(capsule.freeze())
}

/// The largest packet a QUIC DATAGRAM frame carries after the quarter stream
/// ID and the context ID.
pub(crate) fn quic_max_packet(connection: &quinn::Connection, quarter_stream_id: u64) -> usize {
    connection
        .max_datagram_size()
        .unwrap_or(0)
        .saturating_sub(varint_len(quarter_stream_id) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assigned(prefixes: &[&str]) -> Vec<AssignedAddress> {
        prefixes
            .iter()
            .map(|text| {
                let (addr, len) = text.split_once('/').unwrap();
                AssignedAddress {
                    request_id: 0,
                    prefix: IpPrefix::new(addr.parse().unwrap(), len.parse().unwrap()),
                }
            })
            .collect()
    }

    fn addrs(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn local_addresses_are_xrays() {
        assert_eq!(
            local_addrs(&assigned(&["192.0.2.2/32", "2001:db8::2/128"])),
            addrs(&["192.0.2.2", "2001:db8::2"])
        );
        assert_eq!(
            local_addrs(&assigned(&[
                "2001:db8::/64",
                "192.0.2.0/24",
                "198.51.100.7/32"
            ])),
            addrs(&["2001:db8::1", "192.0.2.1"])
        );
        assert_eq!(
            local_addrs(&assigned(&["0.0.0.0/32", "2001:db8::2/128"])),
            addrs(&["2001:db8::2"])
        );
        assert!(local_addrs(&assigned(&["0.0.0.0/32", "::/128"])).is_empty());
    }

    #[test]
    fn control_capsules_are_bounded_in_bytes_as_well_as_in_number() {
        let (control, mut taken) = mpsc::channel(MAX_QUEUED_CAPSULES);
        let queued = AtomicUsize::new(0);
        let large = Bytes::from(vec![0u8; 200 * 1024]);
        assert!(queue_control(&control, &queued, large.clone()).is_ok());
        assert!(queue_control(&control, &queued, large.clone()).is_ok());
        assert!(matches!(
            queue_control(&control, &queued, large.clone()),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(queued.load(Ordering::Relaxed), 2 * large.len());
        // The writer took one: there is room again.
        queued.fetch_sub(taken.try_recv().unwrap().len(), Ordering::Relaxed);
        assert!(queue_control(&control, &queued, large.clone()).is_ok());

        // Small capsules still stop at their number, and one the queue
        // refused does not count.
        let (control, _taken) = mpsc::channel(MAX_QUEUED_CAPSULES);
        let queued = AtomicUsize::new(0);
        for _ in 0..MAX_QUEUED_CAPSULES {
            assert!(queue_control(&control, &queued, Bytes::from_static(b"x")).is_ok());
        }
        assert!(queue_control(&control, &queued, Bytes::from_static(b"x")).is_err());
        assert_eq!(queued.load(Ordering::Relaxed), MAX_QUEUED_CAPSULES);
    }

    #[test]
    fn outgoing_capsules_wait_for_room_as_xrays_stream_buffer() {
        assert_eq!(room_for(1300), 1300);
        assert_eq!(room_for(MAX_STREAM_BUFFER + 1), MAX_STREAM_BUFFER as u32);
    }
}
