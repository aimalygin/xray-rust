//! The resolvers a client queries: DNS over UDP, as Xray-core's
//! `UDPResolver` sends it, and over TCP with the two-byte length RFC 1035
//! puts before each message, which Xray's `TCPResolver` means to write.
use super::{client::MAX_PACKET, XdnsError, XdnsResolver};
use crate::SocketProtector;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedWriteHalf, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
};

/// Responses read and not yet decoded. Xray's readers hand each over
/// unbuffered; these wait once this many are queued.
const RESPONSE_QUEUE: usize = 64;
/// Queries waiting for a TCP resolver's connection. Xray writes them under
/// a lock instead, so its sender waits; these are dropped once this many
/// wait, as a datagram would be.
const TCP_QUEUE: usize = 256;

pub(crate) trait Resolver: Send + Sync {
    /// Sends one query. A resolver that cannot send drops it.
    fn send(&self, query: Vec<u8>);
    /// The address its responses come from, which the packets read report.
    fn addr(&self) -> SocketAddr;
    fn close(&self);
}

/// Opens a resolver, its responses arriving on the receiver.
pub(crate) async fn open(
    endpoint: &XdnsResolver,
    protector: Option<Arc<dyn SocketProtector>>,
) -> Result<(Box<dyn Resolver>, mpsc::Receiver<Vec<u8>>), XdnsError> {
    let (tx, rx) = mpsc::channel(RESPONSE_QUEUE);
    let resolver: Box<dyn Resolver> = match endpoint {
        XdnsResolver::Udp(candidates) => Box::new(UdpResolver::open(candidates, protector, tx)?),
        XdnsResolver::Tcp(candidates) => {
            Box::new(TcpResolver::open(candidates.clone(), protector, tx).await?)
        }
    };
    Ok((resolver, rx))
}

/// `UDPResolver`: an unconnected socket sending to the resolver and reading
/// whatever arrives. When reading fails the socket is dropped, and the next
/// query opens another.
struct UdpResolver {
    shared: Arc<UdpShared>,
}

struct UdpShared {
    addr: SocketAddr,
    protector: Option<Arc<dyn SocketProtector>>,
    responses: mpsc::Sender<Vec<u8>>,
    runtime: tokio::runtime::Handle,
    state: Mutex<UdpState>,
    closed: AtomicBool,
}

/// The socket queries go out on, sent directly so a fresh one need not
/// wait for the reactor to call it writable, and its reader.
#[derive(Default)]
struct UdpState {
    socket: Option<Arc<StdUdpSocket>>,
    reader: Option<JoinHandle<()>>,
}

impl UdpResolver {
    fn open(
        candidates: &[SocketAddr],
        protector: Option<Arc<dyn SocketProtector>>,
        responses: mpsc::Sender<Vec<u8>>,
    ) -> Result<Self, XdnsError> {
        let mut last = None;
        for &candidate in candidates {
            let addr = crate::canonicalize_socket_addr(candidate);
            let shared = Arc::new(UdpShared {
                addr,
                protector: protector.clone(),
                responses: responses.clone(),
                runtime: tokio::runtime::Handle::current(),
                state: Mutex::default(),
                closed: AtomicBool::new(false),
            });
            match shared.dial() {
                Ok(_) => return Ok(Self { shared }),
                Err(error) => last = Some(error),
            }
        }
        Err(XdnsError::Resolver(last.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no address for the resolver",
            )
        })))
    }
}

impl UdpShared {
    /// The current socket, opening one if there is none.
    fn dial(self: &Arc<Self>) -> io::Result<Arc<StdUdpSocket>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(socket) = &state.socket {
            return Ok(socket.clone());
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the resolver is closed",
            ));
        }
        let bind: SocketAddr = if self.addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = StdUdpSocket::bind(bind)?;
        crate::protect_std_udp_socket(&socket, self.protector.as_deref())
            .map_err(io::Error::other)?;
        socket.set_nonblocking(true)?;
        let reading = {
            let _guard = self.runtime.enter();
            UdpSocket::from_std(socket.try_clone()?)?
        };
        let socket = Arc::new(socket);
        state.socket = Some(socket.clone());
        let shared = self.clone();
        let sending = socket.clone();
        state.reader = Some(self.runtime.spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            // The resolver's datagrams alone; a failed read drops the
            // socket. Xray reads its unconnected socket from any source, so
            // whoever knows the tunnel's domain and reaches this port feeds
            // the carrier packets and has the client poll at their pace.
            while let Ok((length, from)) = reading.recv_from(&mut buf).await {
                if (from.ip().to_canonical(), from.port())
                    != (shared.addr.ip().to_canonical(), shared.addr.port())
                {
                    continue;
                }
                if shared.responses.send(buf[..length].to_vec()).await.is_err() {
                    return;
                }
            }
            let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            if state
                .socket
                .as_ref()
                .is_some_and(|socket| Arc::ptr_eq(socket, &sending))
            {
                state.socket = None;
                state.reader = None;
            }
        }));
        Ok(socket)
    }
}

impl Resolver for UdpResolver {
    fn send(&self, query: Vec<u8>) {
        if let Ok(socket) = self.shared.dial() {
            let _ = socket.send_to(&query, self.shared.addr);
        }
    }

    fn addr(&self) -> SocketAddr {
        self.shared.addr
    }

    fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(reader) = state.reader.take() {
            reader.abort();
        }
        state.socket = None;
    }
}

/// `TCPResolver`: one connection at a time, messages framed by their
/// length. A connection whose reading fails is dropped, and the next query
/// opens another.
struct TcpResolver {
    queue: mpsc::Sender<Vec<u8>>,
    addr: Arc<Mutex<SocketAddr>>,
    writer: JoinHandle<()>,
}

impl TcpResolver {
    /// Connects at once, as Xray's resolver does, so one that refuses fails
    /// the client.
    async fn open(
        candidates: Vec<SocketAddr>,
        protector: Option<Arc<dyn SocketProtector>>,
        responses: mpsc::Sender<Vec<u8>>,
    ) -> Result<Self, XdnsError> {
        let (stream, peer) = crate::happy_eyeballs::connect_tcp_dual_stack_with_peer(
            &candidates,
            protector.as_deref(),
        )
        .await
        .map_err(|error| XdnsError::Resolver(io::Error::other(error)))?;
        let addr = Arc::new(Mutex::new(peer));
        let connection = Connection::start(stream, responses.clone());
        let (queue, rx) = mpsc::channel(TCP_QUEUE);
        let writer = tokio::spawn(write(
            rx,
            Some(connection),
            candidates,
            protector,
            responses,
            addr.clone(),
        ));
        Ok(Self {
            queue,
            addr,
            writer,
        })
    }
}

/// One connection's writing half and the task reading the other.
struct Connection {
    writer: OwnedWriteHalf,
    reader: JoinHandle<()>,
}

impl Connection {
    fn start(stream: tokio::net::TcpStream, responses: mpsc::Sender<Vec<u8>>) -> Self {
        let (mut read, writer) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let Ok(length) = read.read_u16().await else {
                    return;
                };
                let length = usize::from(length);
                // Xray skips an empty or oversized message and reads on.
                if length == 0 || length > MAX_PACKET {
                    let mut skip = (&mut read).take(length as u64);
                    if tokio::io::copy(&mut skip, &mut tokio::io::sink())
                        .await
                        .ok()
                        != Some(length as u64)
                    {
                        return;
                    }
                    continue;
                }
                if read.read_exact(&mut buf[..length]).await.is_err() {
                    return;
                }
                if responses.send(buf[..length].to_vec()).await.is_err() {
                    return;
                }
            }
        });
        Self { writer, reader }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Writes queued queries, connecting again when the connection is gone.
async fn write(
    mut queue: mpsc::Receiver<Vec<u8>>,
    mut connection: Option<Connection>,
    candidates: Vec<SocketAddr>,
    protector: Option<Arc<dyn SocketProtector>>,
    responses: mpsc::Sender<Vec<u8>>,
    addr: Arc<Mutex<SocketAddr>>,
) {
    while let Some(query) = queue.recv().await {
        if connection
            .as_ref()
            .is_some_and(|connection| connection.reader.is_finished())
        {
            connection = None;
        }
        if connection.is_none() {
            let Ok((stream, peer)) = crate::happy_eyeballs::connect_tcp_dual_stack_with_peer(
                &candidates,
                protector.as_deref(),
            )
            .await
            else {
                continue;
            };
            *addr.lock().unwrap_or_else(|e| e.into_inner()) = peer;
            connection = Some(Connection::start(stream, responses.clone()));
        }
        let Some(current) = connection.as_mut() else {
            continue;
        };
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&query);
        if current.writer.write_all(&framed).await.is_err() {
            connection = None;
        }
    }
}

impl Resolver for TcpResolver {
    fn send(&self, query: Vec<u8>) {
        let _ = self.queue.try_send(query);
    }

    fn addr(&self) -> SocketAddr {
        *self.addr.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn close(&self) {
        self.writer.abort();
    }
}

impl Drop for TcpResolver {
    fn drop(&mut self) {
        self.writer.abort();
    }
}
