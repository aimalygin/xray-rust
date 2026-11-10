//! FinalMask's UDP masks over a socket that carries plain datagrams: a
//! freedom flow's and a WireGuard client's. Xray-core's `FinalMask.DialUDP`
//! wraps those sockets as it wraps a QUIC carrier's, so the masks here are
//! the QUIC carriers' own, driven one datagram at a time.
//!
//! The socket sends to one peer, the address the masks were opened for, and
//! takes replies only from it, as the carriers' masks do. udphop and realm
//! are refused: each needs a driver that replaces or introduces the socket,
//! which only the QUIC carriers have.
//!
//! Under the masks the socket stays a plain one, connected to the peer,
//! with none of Quinn's UDP state: that sets the don't-fragment bit,
//! coalesces datagrams under GRO, and on Apple systems drops a datagram
//! longer than the receiver's buffer instead of cutting it.
//!
//! A standalone header-custom mask holds a send until the server answers
//! its request, and only a read takes the answer in. Xray-core reads in a
//! goroutine of its own meanwhile. Here a held send reads in the receiver's
//! place, so a flow that receives only between its sends, or in the task
//! that sends, still moves. What it reads for the receiver it keeps, up to
//! about what a socket's receive buffer holds, and drops past that.
use std::{
    collections::VecDeque,
    fmt,
    future::{poll_fn, Future},
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{ready, Context, Poll, Waker},
};

use quinn::{udp, AsyncUdpSocket, UdpPoller};
use tokio::io::ReadBuf;

use crate::hysteria::{
    carrier::{self, CarrierSession},
    HysteriaCarrierConfig,
};

/// Datagrams one poll reads, dropped or kept, before it yields.
const READS_PER_POLL: usize = 64;

/// Bytes of datagrams a held send keeps for the receiver, about what a
/// socket's receive buffer holds; past them it drops what it reads.
const HELD_BYTES: usize = 256 * 1024;

/// The largest datagram a held send reads whole.
const LARGEST_DATAGRAM: usize = u16::MAX as usize;

/// A UDP socket under FinalMask's UDP masks. One task receives at a time;
/// any number may send.
pub struct MaskedUdpSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    peer: SocketAddr,
    /// What held sends read for the receiver; present when a mask holds a
    /// send until a datagram arrives, as a standalone header-custom does.
    held: Option<Mutex<Held>>,
}

impl fmt::Debug for MaskedUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaskedUdpSocket")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl MaskedUdpSocket {
    /// Whether `masks` can run on a plain socket: they must be valid as a
    /// carrier's, without udphop or realm.
    pub fn validate(masks: &HysteriaCarrierConfig) -> io::Result<()> {
        let invalid = |message: &'static str| io::Error::new(io::ErrorKind::InvalidInput, message);
        if masks.udp_hop.is_active() {
            return Err(invalid("udphop needs a QUIC carrier"));
        }
        if masks.realm.is_some() {
            return Err(invalid("realm needs a QUIC carrier"));
        }
        masks
            .validate()
            .map_err(|_| invalid("invalid FinalMask UDP masks"))
    }

    /// Puts `socket`, bound and protected, under `masks`, sending to `peer`.
    /// The xdns and xicmp clients the masks name open here, through
    /// `protector`; one that does not open fails, as Xray-core's dial does.
    /// Either client carries every datagram, and `socket` goes unused.
    pub async fn connect(
        socket: StdUdpSocket,
        peer: SocketAddr,
        masks: &HysteriaCarrierConfig,
        protector: Option<Arc<dyn crate::SocketProtector>>,
    ) -> io::Result<Self> {
        Self::validate(masks)?;
        let mut session = CarrierSession::new(masks)?;
        session.open_xdns(masks, protector.clone()).await?;
        session.open_xicmp(masks, peer.ip(), protector).await?;
        let wire: Arc<dyn AsyncUdpSocket> = match carrier::tunnel(masks, &session, peer)? {
            Some(tunnel) => tunnel,
            None => Arc::new(PlainSocket::connect(socket, peer)?),
        };
        let held = masks
            .header_custom
            .as_ref()
            .is_some_and(|header| header.config.standalone)
            .then(Mutex::default);
        Ok(Self {
            socket: carrier::wrap_masks(wire, peer, peer, masks, &session)?,
            peer,
            held,
        })
    }

    /// The address every datagram goes to.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The socket's local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Sends `payload` to the peer through the masks: noise first, when it
    /// is due, waiting out its delays. While a mask holds it until a datagram
    /// arrives, as a standalone header-custom holds it for the server's
    /// answer, the send reads in the receiver's place.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        let transmit = udp::Transmit {
            destination: self.peer,
            ecn: None,
            contents: payload,
            segment_size: None,
            src_ip: None,
        };
        // A poller per send: each waits on its own, so concurrent senders
        // never take one another's wakeup.
        let mut poller = None;
        let mut reader = self.held.as_ref().map(|held| Reader {
            socket: &self.socket,
            held,
            scratch: None,
            registered: None,
        });
        loop {
            match self.socket.try_send(&transmit) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let poller =
                        poller.get_or_insert_with(|| self.socket.clone().create_io_poller());
                    poll_fn(|cx| -> Poll<io::Result<()>> {
                        for _ in 0..READS_PER_POLL {
                            if poller.as_mut().poll_writable(cx)?.is_ready() {
                                return Poll::Ready(Ok(()));
                            }
                            let Some(reader) = reader.as_mut() else {
                                return Poll::Pending;
                            };
                            ready!(reader.poll_read(cx))?;
                        }
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    })
                    .await?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Receives the next datagram the masks hand over, into `buf`, with its
    /// sender. A datagram longer than `buf` is cut, as a socket's receive
    /// cuts it, or dropped by a mask that must read it whole, as Salamander
    /// must.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    /// [`Self::recv`] as a poll: the waker of the last receiver to poll is
    /// the one woken. What held sends read for the receiver comes first.
    pub fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        if let Some(held) = &self.held {
            let mut held = lock(held);
            if let Some(datagram) = held.take(buf) {
                return Poll::Ready(Ok(datagram));
            }
            // A held send that reads in this receiver's place wakes it.
            if !held
                .receiver
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                held.receiver = Some(cx.waker().clone());
            }
        }
        // A mask marks what it drops, a datagram from another sender or one
        // that does not unmask, with no bytes.
        for _ in 0..READS_PER_POLL {
            let mut meta = [udp::RecvMeta::default()];
            let count = ready!(self
                .socket
                .poll_recv(cx, &mut [IoSliceMut::new(buf)], &mut meta))?;
            if count > 0 && meta[0].len > 0 {
                return Poll::Ready(Ok((meta[0].len.min(buf.len()), meta[0].addr)));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// What held sends read for the receiver, and the receiver to wake for it.
#[derive(Default)]
struct Held {
    datagrams: VecDeque<(Box<[u8]>, SocketAddr)>,
    bytes: usize,
    /// The last receiver's waker.
    receiver: Option<Waker>,
}

impl Held {
    /// Keeps `datagram` for the receiver, unless it passes the budget.
    fn keep(&mut self, datagram: &[u8], from: SocketAddr) -> bool {
        if self.bytes + datagram.len() > HELD_BYTES {
            return false;
        }
        self.bytes += datagram.len();
        self.datagrams.push_back((datagram.into(), from));
        true
    }

    /// The oldest datagram kept, cut to `buf` as a socket's receive cuts it.
    fn take(&mut self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        let (datagram, from) = self.datagrams.pop_front()?;
        self.bytes -= datagram.len();
        if self.datagrams.is_empty() {
            // A drained queue keeps no storage.
            self.datagrams = VecDeque::new();
        }
        let len = datagram.len().min(buf.len());
        buf[..len].copy_from_slice(&datagram[..len]);
        Some((len, from))
    }

    /// Wakes the receiver, unless it runs in `sender`'s task, which receives
    /// once its send is through.
    fn wake_receiver(&self, sender: &Waker) {
        if let Some(receiver) = self
            .receiver
            .as_ref()
            .filter(|receiver| !receiver.will_wake(sender))
        {
            receiver.wake_by_ref();
        }
    }
}

fn lock(held: &Mutex<Held>) -> MutexGuard<'_, Held> {
    held.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A held send's reads in the receiver's place.
struct Reader<'a> {
    socket: &'a Arc<dyn AsyncUdpSocket>,
    held: &'a Mutex<Held>,
    /// Allocated at the first read.
    scratch: Option<Box<[u8]>>,
    /// The send's waker once it waits on the receive. The socket wakes the
    /// last to wait there, so the send took the receiver's place.
    registered: Option<Waker>,
}

impl Reader<'_> {
    /// Reads one datagram through the masks, which take in an answer they
    /// await, and keeps what they hand over for the receiver.
    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let scratch = self
            .scratch
            .get_or_insert_with(|| vec![0; LARGEST_DATAGRAM].into_boxed_slice());
        let mut meta = [udp::RecvMeta::default()];
        let Poll::Ready(count) =
            self.socket
                .poll_recv(cx, &mut [IoSliceMut::new(&mut scratch[..])], &mut meta)
        else {
            if !self
                .registered
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                self.registered = Some(cx.waker().clone());
            }
            return Poll::Pending;
        };
        if count? > 0 && meta[0].len > 0 {
            let mut held = lock(self.held);
            if held.keep(&scratch[..meta[0].len.min(scratch.len())], meta[0].addr) {
                held.wake_receiver(cx.waker());
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Reader<'_> {
    /// The receiver waits on the socket again, in the place the send took.
    fn drop(&mut self) {
        if let Some(sender) = &self.registered {
            lock(self.held).wake_receiver(sender);
        }
    }
}

/// The masks' wire: the socket as a flow without masks uses it, one
/// datagram per receive, cut to the receiver's buffer. It is connected to
/// the peer, so the system drops other senders' datagrams before any mask
/// reads them.
#[derive(Debug)]
struct PlainSocket {
    io: tokio::net::UdpSocket,
    peer: SocketAddr,
}

impl PlainSocket {
    fn connect(socket: StdUdpSocket, peer: SocketAddr) -> io::Result<Self> {
        socket.connect(peer)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            io: tokio::net::UdpSocket::from_std(socket)?,
            peer,
        })
    }
}

/// An ICMP error that an earlier datagram drew. A connected socket reports
/// it on a later call, where an unconnected one, a flow's without masks,
/// never does: it is loss, not a failure.
fn reported_icmp(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

impl AsyncUdpSocket for PlainSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable {
            socket: self,
            ready: None,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a masked UDP socket sends only to its peer",
            ));
        }
        match self.io.try_send(transmit.contents) {
            Ok(_) => Ok(()),
            // Unreachable host or network stays an error: an unconnected
            // socket's send meets it too, from its route.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut read = ReadBuf::new(&mut bufs[0]);
            match ready!(self.io.poll_recv(cx, &mut read)) {
                Ok(()) => {
                    let len = read.filled().len();
                    meta[0] = udp::RecvMeta {
                        addr: self.peer,
                        len,
                        stride: len.max(1),
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                // Each report is taken once; the next read waits or reads.
                Err(error) if reported_icmp(&error) => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

/// Waits for room in the socket's send buffer. Each poller waits on its
/// own future, so concurrent senders all wake.
struct Writable {
    socket: Arc<PlainSocket>,
    ready: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writable").finish_non_exhaustive()
    }
}

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let ready = this.ready.get_or_insert_with(|| {
            let socket = this.socket.clone();
            Box::pin(async move { socket.io.writable().await })
        });
        let result = ready!(ready.as_mut().poll(cx));
        this.ready = None;
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests;
