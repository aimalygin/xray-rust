use crate::client::Stop;
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch, Notify},
};
use xray_transport::SocketProtector;
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard closed")
}

#[derive(Clone)]
pub(crate) struct Factory {
    pub(crate) ipv4: bool,
    pub(crate) ipv6: bool,
    pub(crate) protector: Option<Arc<dyn SocketProtector>>,
    pub(crate) protection_failed: Arc<AtomicBool>,
    pub(crate) stop: Stop,
    pub(crate) carrier: watch::Sender<Option<Arc<Sockets>>>,
}
pub(crate) type Sockets = [Option<Arc<UdpSocket>>; 2];

#[derive(Clone)]
pub(crate) struct Udp {
    carrier: watch::Receiver<Option<Arc<Sockets>>>,
    next: usize,
    // Populated only by the receive half; cloned send handles hold no retired sockets.
    receiving: Option<Arc<Sockets>>,
    previous: Option<(Arc<Sockets>, tokio::time::Instant)>,
    stop: Stop,
}
impl Factory {
    /// Publish a complete, protected socket set in one step. The engine and its
    /// sessions keep running; the receive half drains one retired set briefly.
    pub(crate) fn rebind(&self) -> io::Result<()> {
        if self.stop.is_closed() {
            return Err(closed());
        }
        let mut sockets = [None, None];
        for (index, enabled) in [self.ipv4, self.ipv6].into_iter().enumerate() {
            if !enabled {
                continue;
            }
            let bind = if index == 1 {
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
            };
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(bind),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            if index == 1 {
                socket.set_only_v6(true)?;
            }
            socket.bind(&bind.into())?;
            let socket: std::net::UdpSocket = socket.into();
            // Protect every socket before the factory publishes either half.
            // If the second protection fails, the first socket is also dropped.
            xray_transport::protect_std_udp_socket(&socket, self.protector.as_deref()).map_err(
                |_| {
                    self.protection_failed.store(true, Ordering::Release);
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "WireGuard socket protection failed",
                    )
                },
            )?;
            if self.stop.is_closed() {
                return Err(closed());
            }
            socket.set_nonblocking(true)?;
            sockets[index] = Some(Arc::new(UdpSocket::from_std(socket)?));
        }
        self.carrier.send_replace(Some(Arc::new(sockets)));
        Ok(())
    }
}
impl UdpTransportFactory for Factory {
    type Send = Udp;
    type Recv = Udp;
    async fn bind(&mut self, _: &UdpTransportFactoryParams) -> io::Result<(Udp, Udp)> {
        self.rebind()?;
        let udp = Udp {
            carrier: self.carrier.subscribe(),
            next: 0,
            receiving: None,
            previous: None,
            stop: self.stop.clone(),
        };
        Ok((udp.clone(), udp))
    }
}
impl UdpSend for Udp {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let sockets = self.carrier.borrow().as_ref().ok_or_else(closed)?.clone();
        let socket = sockets[usize::from(destination.is_ipv6())]
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "WireGuard endpoint family unavailable",
                )
            })?;
        tokio::select! { biased;
            _ = self.stop.cancelled() => Err(closed()),
            result = socket.send_to(&packet, destination) => {
                if result? != packet.len() { return Err(io::Error::new(io::ErrorKind::WriteZero, "short WireGuard datagram")); }
                Ok(())
            }
        }
    }
}
impl UdpRecv for Udp {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut packet = pool.get();
        let (n, source) = loop {
            // Observe each published socket set even if replacement raced with
            // the previous recv call. Keep at most one old set for a bounded
            // drain: an authenticated reply can still be in flight to its port.
            let sockets = self
                .carrier
                .borrow_and_update()
                .as_ref()
                .ok_or_else(closed)?
                .clone();
            if self
                .receiving
                .as_ref()
                .is_some_and(|old| !Arc::ptr_eq(old, &sockets))
            {
                self.previous = self.receiving.take().map(|old| {
                    (
                        old,
                        tokio::time::Instant::now() + std::time::Duration::from_secs(3),
                    )
                });
            }
            self.receiving = Some(sockets.clone());
            let expires = self.previous.as_ref().map(|(_, expires)| *expires);
            if expires.is_some_and(|expires| expires <= tokio::time::Instant::now()) {
                self.previous = None;
                continue;
            }
            tokio::select! { biased;
                _ = self.stop.cancelled() => return Err(closed()),
                result = self.carrier.changed() => { result.map_err(|_| closed())?; },
                _ = async { match expires {
                    Some(expires) => tokio::time::sleep_until(expires).await,
                    None => std::future::pending().await,
                }} => { self.previous = None; },
                result = std::future::poll_fn(|cx| {
                    // Prefer the new carrier; alternate family priority. Old
                    // packets still pass the engine's authentication/replay checks.
                    for sockets in std::iter::once(&sockets).chain(self.previous.as_ref().map(|(sockets, _)| sockets)) {
                        for offset in 0..2 {
                            let index = (self.next + offset) % 2;
                            if let Some(socket) = &sockets[index] {
                                let mut buf = tokio::io::ReadBuf::new(&mut packet);
                                if let std::task::Poll::Ready(result) = socket.poll_recv_from(cx, &mut buf) {
                                    self.next = 1 - index;
                                    return std::task::Poll::Ready(result.map(|source| (buf.filled().len(), source)));
                                }
                            }
                        }
                    }
                    std::task::Poll::Pending
                }) => break result?,
            }
        };
        packet.truncate(n);
        Ok((packet, source))
    }
}
pub(crate) struct IpTx {
    pub(crate) tx: mpsc::Sender<Packet<Ip>>,
    pub(crate) stop: Stop,
}
pub(crate) struct IpRx {
    pub(crate) rx: mpsc::Receiver<Packet<Ip>>,
    pub(crate) mtu: u16,
    pub(crate) stop: Stop,
    pub(crate) wake: Arc<Notify>,
}
impl IpSend for IpTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        tokio::select! { biased;
            _ = self.stop.cancelled() => Err(closed()),
            result = self.tx.send(packet) => result.map_err(|_| closed()),
        }
    }
}
impl IpRecv for IpRx {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = tokio::select! { biased;
            _ = self.stop.cancelled() => return Err(closed()),
            packet = self.rx.recv() => packet.ok_or_else(closed)?,
        };
        self.wake.notify_one();
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}
