//! Xray-core's `xicmpConnClient`: each packet goes out in an echo request
//! after the client's id, and echo replies bring the server's packets.
//!
//! Xray-core listens on one unconnected socket per family, bound to the
//! wildcard. Here each server address gets its own socket, never bound and
//! connected to it: an unbound socket is bound on its first send, and a
//! Network Extension refuses to bind an ICMP socket or read an unconnected
//! one. Replies then come only from the address the socket sends to, as
//! Xray-core's Linux server makes them.
use super::{message, XicmpConfig, XicmpError};
use crate::SocketProtector;
use rand::{Rng, RngCore};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};

/// `finalmask.UDPSize`: the largest echo either side writes or reads.
pub(crate) const MAX_PACKET: usize = 4096;
/// What an echo adds before a packet: its header and the client's id.
const OVERHEAD: usize = message::HEADER_LEN + 8;
/// Packets read and not yet taken. Xray hands each over unbuffered, so a
/// reader waits; here it waits once this many are queued.
const RECEIVE_QUEUE: usize = 64;

/// A packet the client read and the address that sent it.
#[derive(Debug)]
pub(crate) struct Packet {
    pub(crate) data: Vec<u8>,
    pub(crate) from: SocketAddr,
}

/// One client: an id the server knows it by, the identifier its echoes
/// carry and a socket per server address. Dropping it stops its readers
/// and closes its sockets.
pub struct XicmpClient {
    shared: Arc<Shared>,
    received: Mutex<mpsc::Receiver<Packet>>,
    tasks: Vec<JoinHandle<()>>,
    /// Hands packets to the client as its readers would.
    #[cfg(test)]
    pub(crate) inject: mpsc::Sender<Packet>,
}

impl std::fmt::Debug for XicmpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XicmpClient")
            .field("addresses", &self.shared.addresses)
            .field("dgram", &self.shared.dgram)
            .finish_non_exhaustive()
    }
}

struct Shared {
    /// The addresses packets are drawn among, duplicates kept, as Xray-core
    /// draws among `ips`.
    addresses: Vec<IpAddr>,
    /// The socket of each distinct address. Sends go straight to the
    /// system, which a Tokio socket defers until its reactor has seen the
    /// socket writable; a clone of each reads.
    sockets: Vec<(IpAddr, std::net::UdpSocket)>,
    client_id: [u8; 8],
    id: u16,
    seq: Mutex<u16>,
    dgram: bool,
}

impl XicmpClient {
    /// Opens a socket to every address `config` lists, or to `destination`
    /// when it lists none, each protected before it connects.
    pub async fn connect(
        config: &XicmpConfig,
        destination: IpAddr,
        protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<Self, XicmpError> {
        let addresses: Vec<IpAddr> = if config.ips.is_empty() {
            vec![destination.to_canonical()]
        } else {
            config.ips.iter().map(IpAddr::to_canonical).collect()
        };
        let mut sockets: Vec<(IpAddr, std::net::UdpSocket)> = Vec::new();
        let mut readers = Vec::new();
        for &address in &addresses {
            if sockets.iter().any(|(ip, _)| *ip == address) {
                continue;
            }
            let socket = open(address, config.dgram, protector.as_deref())?;
            let reader = socket
                .try_clone()
                .and_then(UdpSocket::from_std)
                .map_err(XicmpError::Socket)?;
            readers.push((address, reader));
            sockets.push((address, socket));
        }
        let mut client_id = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut client_id);
        let shared = Arc::new(Shared {
            addresses,
            sockets,
            client_id,
            id: rand::thread_rng().gen(),
            seq: Mutex::new(1),
            dgram: config.dgram,
        });
        let (sender, received) = mpsc::channel(RECEIVE_QUEUE);
        let tasks = readers
            .into_iter()
            .map(|(address, reader)| {
                tokio::spawn(read(shared.clone(), address, reader, sender.clone()))
            })
            .collect();
        Ok(Self {
            shared,
            received: Mutex::new(received),
            tasks,
            #[cfg(test)]
            inject: sender,
        })
    }

    /// `WriteTo`: one echo request to an address drawn from the list. A
    /// packet too large for an echo is dropped, as is one the system has no
    /// room for.
    pub(crate) fn send(&self, packet: &[u8]) -> io::Result<()> {
        if packet.len() + OVERHEAD > MAX_PACKET {
            return Ok(());
        }
        let seq = {
            let mut seq = self.shared.seq.lock().unwrap_or_else(|e| e.into_inner());
            let current = *seq;
            *seq = seq.wrapping_add(1);
            current
        };
        let addresses = &self.shared.addresses;
        let address = addresses[rand::thread_rng().gen_range(0..addresses.len())];
        let Some((_, socket)) = self.shared.sockets.iter().find(|(ip, _)| *ip == address) else {
            return Ok(());
        };
        let mut data = Vec::with_capacity(8 + packet.len());
        data.extend_from_slice(&self.shared.client_id);
        data.extend_from_slice(packet);
        let kind = if address.is_ipv4() {
            message::ECHO_REQUEST_V4
        } else {
            message::ECHO_REQUEST_V6
        };
        match socket.send(&message::echo(kind, self.shared.id, seq, &data)) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            result => result.map(drop),
        }
    }

    pub(crate) async fn recv(&self) -> Option<Packet> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    pub(crate) fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<Packet>> {
        self.received
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .poll_recv(cx)
    }

    pub(crate) fn try_recv(&self) -> Option<Packet> {
        self.received
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .try_recv()
            .ok()
    }
}

impl Drop for XicmpClient {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// A nonblocking ICMP socket for `address`'s family, connected to it. On
/// Apple systems an IPv4 datagram socket returns the IP header unless told
/// not to, which Go's `icmp.ListenPacket` does.
fn open(
    address: IpAddr,
    dgram: bool,
    protector: Option<&dyn SocketProtector>,
) -> Result<std::net::UdpSocket, XicmpError> {
    use socket2::{Domain, Protocol, Socket, Type};
    let (domain, protocol) = if address.is_ipv4() {
        (Domain::IPV4, Protocol::ICMPV4)
    } else {
        (Domain::IPV6, Protocol::ICMPV6)
    };
    let kind = if dgram { Type::DGRAM } else { Type::RAW };
    let socket = Socket::new(domain, kind, Some(protocol)).map_err(XicmpError::Socket)?;
    #[cfg(target_vendor = "apple")]
    if dgram && address.is_ipv4() {
        strip_header(&socket).map_err(XicmpError::Socket)?;
    }
    let socket: std::net::UdpSocket = socket.into();
    crate::protect_std_udp_socket(&socket, protector).map_err(XicmpError::Protection)?;
    socket
        .connect(SocketAddr::new(address, 0))
        .map_err(XicmpError::Socket)?;
    socket.set_nonblocking(true).map_err(XicmpError::Socket)?;
    Ok(socket)
}

/// `IP_STRIPHDR`, Darwin's option to read an ICMP datagram socket without
/// the IP header.
#[cfg(target_vendor = "apple")]
fn strip_header(socket: &socket2::Socket) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    const IP_STRIPHDR: libc::c_int = 0x17;
    let on: libc::c_int = 1;
    // SAFETY: the descriptor is open for the call, and the option value is
    // a live c_int of the length passed.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_STRIPHDR,
            std::ptr::addr_of!(on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `recv4` and `recv6`: echo replies, with this client's identifier where
/// the socket keeps it, whose data does not start with the client's id,
/// which the server's own system echoes back. A read error stops the
/// reader, as it stops Xray-core's.
async fn read(
    shared: Arc<Shared>,
    address: IpAddr,
    socket: UdpSocket,
    sender: mpsc::Sender<Packet>,
) {
    let mut buf = vec![0u8; MAX_PACKET];
    let v6 = address.is_ipv6();
    loop {
        let Ok(length) = socket.recv(&mut buf).await else {
            return;
        };
        let Some(data) = accept(&buf[..length], v6, &shared) else {
            continue;
        };
        let packet = Packet {
            data: data.to_vec(),
            from: SocketAddr::new(address, 0),
        };
        if sender.send(packet).await.is_err() {
            return;
        }
    }
}

/// What a reader keeps of a message: the echo reply's data.
fn accept<'a>(message: &'a [u8], v6: bool, shared: &Shared) -> Option<&'a [u8]> {
    accept_echo(
        message,
        v6,
        shared.dgram,
        own_identifier(shared.dgram),
        shared.id,
        &shared.client_id,
    )
}

/// Whether replies to this socket carry the identifier the client wrote,
/// for it to tell them from other sockets'. A raw socket's do. A Linux
/// datagram socket writes its own and gets only the replies with it; an
/// Apple one keeps the client's and gets every reply from its address, so
/// two connections to one server would read each other's, as Xray-core's
/// datagram sockets do there.
fn own_identifier(dgram: bool) -> bool {
    !dgram || cfg!(target_vendor = "apple")
}

pub(super) fn accept_echo<'a>(
    message: &'a [u8],
    v6: bool,
    dgram: bool,
    check_id: bool,
    id: u16,
    client_id: &[u8; 8],
) -> Option<&'a [u8]> {
    // Go strips the header a raw IPv4 socket returns.
    let message = if !v6 && !dgram {
        message::strip_ipv4_header(message)
    } else {
        message
    };
    let echo = message::parse_echo(message, v6)?;
    let reply = if v6 {
        message::ECHO_REPLY_V6
    } else {
        message::ECHO_REPLY_V4
    };
    if echo.kind != reply || (check_id && echo.id != id) {
        return None;
    }
    if echo.data.len() > 8 && echo.data[..8] == client_id[..] {
        return None;
    }
    Some(echo.data)
}

#[cfg(test)]
mod tests;
