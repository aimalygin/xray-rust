use crate::client::{Stop, IP_PACKET_QUEUE};
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
            // Concurrent inner TCP windows can arrive in one carrier burst.
            // A small system UDP queue loses those packets before the bounded
            // engine sees them, producing long TCP retransmission tails. This
            // matches both pinned wireguard-go socket-buffer requests. It is
            // kernel storage per enabled family, not part of process RSS;
            // the OS may clamp or reject the request under its own limits.
            let _ = socket.set_recv_buffer_size(7 * 1024 * 1024);
            let _ = socket.set_send_buffer_size(7 * 1024 * 1024);
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
    // Reuse Gotatun's bounded recv_many path to amortize channel selection.
    // The default send_many_to keeps the existing per-packet socket selection,
    // cancellation, protection and roaming behavior, including mixed peers.
    fn max_number_of_packets_to_send(&self) -> usize {
        16
    }
    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        // The ready path must retain Tokio's cooperative scheduling budget.
        // Register a cancellation waiter only when sending actually blocks.
        tokio::task::consume_budget().await;
        if self.stop.is_closed() {
            return Err(closed());
        }
        let sockets = self.carrier.borrow().as_ref().ok_or_else(closed)?.clone();
        let socket = sockets[usize::from(destination.is_ipv6())]
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "WireGuard endpoint family unavailable",
                )
            })?;
        match socket.try_send_to(&packet, destination) {
            Ok(n) if n == packet.len() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short WireGuard datagram",
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
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
    pub(crate) batch: Vec<Packet<Ip>>,
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
        // Drain only an already available bounded batch. recv_many waits for
        // one packet, never for a full batch, so sparse traffic gains no delay.
        self.batch.clear();
        let count = tokio::select! { biased;
            _ = self.stop.cancelled() => return Err(closed()),
            count = self.rx.recv_many(&mut self.batch, IP_PACKET_QUEUE) => count,
        };
        if count == 0 {
            return Err(closed());
        }
        // One notification exposes all newly freed channel slots to the stack.
        self.wake.notify_one();
        Ok(self.batch.drain(..))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use std::time::Duration;

    fn packet(id: u8) -> Packet<Ip> {
        let mut bytes = bytes::BytesMut::zeroed(20);
        bytes[0] = 0x45;
        bytes[3] = 20;
        bytes[5] = id;
        Packet::from_bytes(bytes).try_into_ip().unwrap()
    }

    fn pair() -> (mpsc::Sender<Packet<Ip>>, IpRx) {
        let (tx, rx) = mpsc::channel(IP_PACKET_QUEUE * 2);
        (
            tx,
            IpRx {
                rx,
                batch: Vec::with_capacity(IP_PACKET_QUEUE),
                mtu: 1420,
                stop: Stop::new(),
                wake: Arc::new(Notify::new()),
            },
        )
    }

    #[tokio::test]
    async fn available_batch_is_bounded_ordered_and_notifies_capacity() {
        let (tx, mut rx) = pair();
        let mut pool = PacketBufPool::new(0);
        for id in 0..(IP_PACKET_QUEUE + 1) as u8 {
            tx.send(packet(id)).await.unwrap();
        }
        let batch: Vec<_> = rx
            .recv(&mut pool)
            .await
            .unwrap()
            .map(|p| p.into_bytes()[5])
            .collect();
        assert_eq!(batch, (0..IP_PACKET_QUEUE as u8).collect::<Vec<_>>());
        tokio::time::timeout(Duration::from_secs(1), rx.wake.notified())
            .await
            .unwrap();
        let batch: Vec<_> = tokio::time::timeout(Duration::from_secs(1), rx.recv(&mut pool))
            .await
            .unwrap()
            .unwrap()
            .map(|p| p.into_bytes()[5])
            .collect();
        assert_eq!(batch, [IP_PACKET_QUEUE as u8]);
        drop(tx);
        assert!(
            matches!(rx.recv(&mut pool).await, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[tokio::test]
    async fn cancellation_wins_over_queued_packets_and_wakes_empty_reader() {
        let (tx, mut rx) = pair();
        let mut pool = PacketBufPool::new(0);
        tx.send(packet(1)).await.unwrap();
        rx.stop.close();
        assert!(
            matches!(rx.recv(&mut pool).await, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(rx.rx.len(), 1);

        let (_tx, mut rx) = pair();
        let stop = rx.stop.clone();
        let pending = async {
            assert!(
                matches!(rx.recv(&mut pool).await, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
            );
        };
        let close = async {
            tokio::task::yield_now().await;
            stop.close();
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(pending, close);
        })
        .await
        .unwrap();
    }
}

#[cfg(test)]
mod udp_ready_send_tests {
    use super::*;
    use std::time::Duration;
    async fn sender() -> (watch::Sender<Option<Arc<Sockets>>>, Udp, Arc<UdpSocket>) {
        let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        local.writable().await.unwrap();
        let (carrier, receive) = watch::channel(Some(Arc::new([Some(local.clone()), None])));
        let udp = Udp {
            carrier: receive,
            next: 0,
            receiving: None,
            previous: None,
            stop: Stop::new(),
        };
        (carrier, udp, local)
    }
    fn packet(data: &[u8]) -> Packet {
        Packet::from_bytes(bytes::BytesMut::from(data))
    }
    #[tokio::test]
    async fn ready_send_preserves_stop_destination_and_rebind() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (carrier, udp, first) = sender().await;
            udp.send_to(packet(b"a"), a.local_addr().unwrap())
                .await
                .unwrap();
            let mut bytes = [0; 16];
            let (n, source) = a.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], b"a");
            assert_eq!(source, first.local_addr().unwrap());
            let second = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            second.writable().await.unwrap();
            carrier.send_replace(Some(Arc::new([Some(second.clone()), None])));
            udp.send_to(packet(b"b"), b.local_addr().unwrap())
                .await
                .unwrap();
            let (n, source) = b.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], b"b");
            assert_eq!(source, second.local_addr().unwrap());
            udp.stop.close();
            assert_eq!(
                udp.send_to(packet(b"cancelled"), a.local_addr().unwrap())
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(20), a.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
        })
        .await
        .unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn continuously_ready_send_yields_to_other_tasks() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (_carrier, udp, _local) = sender().await;
        let ran = Arc::new(AtomicBool::new(false));
        let mark = ran.clone();
        let task = tokio::spawn(async move {
            mark.store(true, Ordering::Release);
        });
        for _ in 0..512 {
            udp.send_to(packet(b"x"), peer.local_addr().unwrap())
                .await
                .unwrap();
        }
        assert!(
            ran.load(Ordering::Acquire),
            "ready UDP sends must honor the cooperative budget"
        );
        task.await.unwrap();
    }
}
