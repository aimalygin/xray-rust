//! The WireGuard client's userspace TCP/IP interface without WireGuard, for
//! tunnels that carry IP packets themselves, such as MASQUE's CONNECT-IP.
use crate::client::{
    Error, Flows, Routes, Stop, TcpSlot, TcpStream, UdpSession, COMMAND_QUEUE, IP_PACKET_QUEUE,
};
use crate::{stack, FlowLimits};
use bytes::Bytes;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::sync::{mpsc, watch, Notify};

/// The packet side of a [`Netstack`]: what it sends and what it receives.
#[derive(Debug)]
pub struct NetstackPackets {
    /// IP packets the stack sends, at most its MTU each.
    pub outgoing: mpsc::Receiver<Bytes>,
    /// IP packets for the stack. A full queue is backpressure; dropping it
    /// stops the stack.
    pub incoming: mpsc::Sender<Bytes>,
}

struct Owner {
    flows: Flows,
    finished: watch::Receiver<bool>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.flows.stop.close();
    }
}

/// A userspace TCP/IP interface over raw IP packets, with the bounds of the
/// WireGuard client's: the TCP flows of its [`FlowLimits`], 512 UDP flows,
/// and the same buffers.
#[derive(Clone)]
pub struct Netstack(Arc<Owner>);
impl fmt::Debug for Netstack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Netstack")
            .field("addresses", &self.0.flows.addresses)
            .field("closed", &self.0.flows.stop.is_closed())
            .finish_non_exhaustive()
    }
}
impl Netstack {
    /// Starts a stack with up to one local address per family. Flows may go
    /// to any usable address of a family it has an address of.
    pub fn start(addresses: Vec<IpAddr>, mtu: u16) -> Result<(Self, NetstackPackets), Error> {
        Self::start_with_limits(addresses, mtu, FlowLimits::default())
    }

    /// [`Self::start`] with the flow limits of a runtime profile.
    pub fn start_with_limits(
        addresses: Vec<IpAddr>,
        mtu: u16,
        limits: FlowLimits,
    ) -> Result<(Self, NetstackPackets), Error> {
        if addresses.is_empty()
            || addresses.iter().filter(|ip| ip.is_ipv4()).count() > 1
            || addresses.iter().filter(|ip| ip.is_ipv6()).count() > 1
            || addresses.iter().any(|ip| !crate::config::usable_ip(*ip))
            || !(1280..=9000).contains(&mtu)
        {
            return Err(Error::Configuration);
        }
        let stop = Stop::new();
        let wake = Arc::new(Notify::new());
        let (outgoing_tx, outgoing) = mpsc::channel(IP_PACKET_QUEUE);
        let (incoming, incoming_rx) = mpsc::channel(IP_PACKET_QUEUE);
        let (commands, requests) = mpsc::channel(COMMAND_QUEUE);
        let stack = stack::Stack::<Bytes>::new(
            &addresses,
            mtu,
            limits.tcp_buffer(),
            outgoing_tx,
            incoming_rx,
            requests,
            wake.clone(),
        );
        let (finished, done) = watch::channel(false);
        let task_stop = stop.clone();
        tokio::spawn(async move {
            stack.run(task_stop.clone()).await;
            task_stop.close();
            finished.send_replace(true);
        });
        Ok((
            Self(Arc::new(Owner {
                flows: Flows::new(
                    addresses,
                    mtu,
                    Routes::Everywhere,
                    commands,
                    stop,
                    wake,
                    limits,
                ),
                finished: done,
            })),
            NetstackPackets { outgoing, incoming },
        ))
    }
    pub fn addresses(&self) -> &[IpAddr] {
        &self.0.flows.addresses
    }
    pub fn is_live(&self) -> bool {
        self.0.flows.is_live()
    }
    /// Stops the stack: open flows fail, new ones are refused.
    pub fn close(&self) {
        self.0.flows.stop.close();
    }
    pub async fn shutdown(&self) {
        self.close();
        let mut done = self.0.finished.clone();
        if !*done.borrow() {
            let _ = done.changed().await;
        }
    }
    pub fn available_tcp_slots(&self) -> usize {
        self.0.flows.tcp.available_permits()
    }
    /// TCP flows waiting for a place.
    pub fn waiting_tcp_flows(&self) -> usize {
        self.0.flows.waiting_tcp_flows()
    }
    pub fn available_udp_slots(&self) -> usize {
        self.0.flows.udp.available_permits()
    }
    /// Waits for a place, then opens a TCP flow in it, as
    /// [`crate::Client::connect`] does.
    pub async fn connect(&self, remote: SocketAddr) -> Result<TcpStream, Error> {
        self.0.flows.connect(remote).await
    }
    /// See [`crate::Client::tcp_slot`].
    pub async fn tcp_slot(&self) -> Result<TcpSlot, Error> {
        self.0.flows.tcp_slot().await
    }
    /// See [`crate::Client::connect_with_slot`].
    pub async fn connect_with_slot(
        &self,
        slot: TcpSlot,
        remote: SocketAddr,
    ) -> Result<TcpStream, Error> {
        self.0.flows.connect_with_slot(slot, remote).await
    }
    pub async fn open_udp(&self, remote: SocketAddr) -> Result<UdpSession, Error> {
        self.0.flows.open_udp(remote).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr,
        UdpPacket, UdpRepr,
    };
    use std::time::Duration;

    fn udp_v4(src: (Ipv4Address, u16), dst: (Ipv4Address, u16), payload: &[u8]) -> Bytes {
        let udp = UdpRepr {
            src_port: src.1,
            dst_port: dst.1,
        };
        let ip = Ipv4Repr {
            src_addr: src.0,
            dst_addr: dst.0,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut bytes = bytes::BytesMut::zeroed(ip.buffer_len() + udp.header_len() + payload.len());
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
        ip.emit(&mut packet, &ChecksumCapabilities::default());
        udp.emit(
            &mut UdpPacket::new_unchecked(packet.payload_mut()),
            &src.0.into(),
            &dst.0.into(),
            payload.len(),
            |buf| buf.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        bytes.freeze()
    }

    #[tokio::test]
    async fn udp_flows_cross_the_packet_channels_in_both_families() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let local4: IpAddr = "10.66.0.2".parse().unwrap();
            let local6: IpAddr = "fd00::2".parse().unwrap();
            let (stack, mut packets) = Netstack::start(vec![local4, local6], 1280).unwrap();
            let remote: SocketAddr = "192.0.2.10:5353".parse().unwrap();
            let session = stack.open_udp(remote).await.unwrap();
            assert_eq!(session.max_payload(), 1280 - 28);
            session.send(b"ping").await.unwrap();
            let sent = packets.outgoing.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&sent[..]).unwrap();
            assert_eq!(IpAddr::from(ip.src_addr()), local4);
            assert_eq!(IpAddr::from(ip.dst_addr()), remote.ip());
            let udp = UdpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(udp.payload(), b"ping");
            let reply = udp_v4(
                (Ipv4Address::new(192, 0, 2, 10), 5353),
                (Ipv4Address::new(10, 66, 0, 2), udp.src_port()),
                b"pong",
            );
            packets.incoming.send(reply).await.unwrap();
            assert_eq!(&session.recv().await.unwrap()[..], b"pong");

            let remote6: SocketAddr = "[2001:db8::10]:53".parse().unwrap();
            let session6 = stack.open_udp(remote6).await.unwrap();
            session6.send(b"six").await.unwrap();
            let sent = packets.outgoing.recv().await.unwrap();
            let ip = Ipv6Packet::new_checked(&sent[..]).unwrap();
            assert_eq!(IpAddr::from(ip.src_addr()), local6);
            let _ = (Ipv6Address::UNSPECIFIED, Ipv6Repr::buffer_len);
            stack.shutdown().await;
            assert!(matches!(stack.open_udp(remote).await, Err(Error::Closed)));
        })
        .await
        .unwrap();
    }

    /// The reader of `outgoing` is a plain channel receiver that tells the
    /// stack nothing. A stack that filled the queue, and holds an incoming
    /// packet it could not take a reply slot for, has to notice the drain
    /// itself: MASQUE uploads hung here, with the queue empty again and the
    /// stack still asleep.
    #[tokio::test]
    async fn a_stack_that_filled_its_transmit_queue_resumes_once_it_drains() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (stack, mut packets) =
                Netstack::start(vec!["10.66.0.2".parse().unwrap()], 1280).unwrap();
            let remote: SocketAddr = "192.0.2.10:5353".parse().unwrap();
            let session = stack.open_udp(remote).await.unwrap();
            session.send(b"first").await.unwrap();
            let first = packets.outgoing.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&first[..]).unwrap();
            let port = UdpPacket::new_checked(ip.payload()).unwrap().src_port();

            // Nobody reads the queue: it fills, and datagrams stay behind.
            for _ in 0..IP_PACKET_QUEUE + 4 {
                session.send(b"ping").await.unwrap();
            }
            while packets.outgoing.len() < IP_PACKET_QUEUE {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            // The stack takes the reply off its queue and can do no more
            // with it, then goes to sleep.
            let reply = udp_v4(
                (Ipv4Address::new(192, 0, 2, 10), 5353),
                (Ipv4Address::new(10, 66, 0, 2), port),
                b"pong",
            );
            packets.incoming.send(reply).await.unwrap();
            while packets.incoming.capacity() < packets.incoming.max_capacity() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;

            for _ in 0..IP_PACKET_QUEUE {
                packets.outgoing.recv().await.unwrap();
            }
            let pong = tokio::time::timeout(Duration::from_secs(3), session.recv())
                .await
                .expect("the stack stayed asleep after its transmit queue drained");
            assert_eq!(&pong.unwrap()[..], b"pong");
            // What stayed behind follows.
            let late = tokio::time::timeout(Duration::from_secs(3), packets.outgoing.recv())
                .await
                .expect("the datagrams left behind never followed");
            let ip = Ipv4Packet::new_checked(&late.as_ref().unwrap()[..]).unwrap();
            assert_eq!(
                UdpPacket::new_checked(ip.payload()).unwrap().payload(),
                b"ping"
            );
            stack.shutdown().await;
        })
        .await
        .unwrap();
    }

    /// The far end of a stack's packets, as a peer across the tunnel: TCP
    /// echo servers on a smoltcp interface at `address`, `listeners` of them
    /// at once. Each echoes what it reads and closes once its client has.
    fn echo_peer(
        packets: NetstackPackets,
        address: Ipv4Address,
        port: u16,
        listeners: usize,
    ) -> tokio::task::JoinHandle<()> {
        use smoltcp::iface::{Config, Interface, SocketSet};
        use smoltcp::socket::tcp;
        use smoltcp::time::Instant;
        use smoltcp::wire::{HardwareAddress, IpCidr};
        let NetstackPackets {
            mut outgoing,
            incoming,
        } = packets;
        tokio::spawn(async move {
            let mut wire = Wire::default();
            let mut interface =
                Interface::new(Config::new(HardwareAddress::Ip), &mut wire, Instant::ZERO);
            interface.update_ip_addrs(|ips| ips.push(IpCidr::new(address.into(), 32)).unwrap());
            interface
                .routes_mut()
                .add_default_ipv4_route(address)
                .unwrap();
            let mut sockets = SocketSet::new(vec![]);
            let handles: Vec<_> = (0..listeners)
                .map(|_| {
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0; 16 * 1024]),
                        tcp::SocketBuffer::new(vec![0; 16 * 1024]),
                    );
                    socket.listen(port).unwrap();
                    sockets.add(socket)
                })
                .collect();
            let start = std::time::Instant::now();
            // Replies wait here rather than in a send: the stack reads no
            // reply while its own queue is full.
            let mut replies = std::collections::VecDeque::new();
            loop {
                let now = Instant::from_millis(start.elapsed().as_millis() as i64);
                interface.poll(now, &mut wire, &mut sockets);
                for &handle in &handles {
                    let socket = sockets.get_mut::<tcp::Socket>(handle);
                    // A reset connection may still hold what it read, and
                    // can no longer send: listening again discards it.
                    while socket.can_recv() && socket.can_send() {
                        let room = socket.send_capacity() - socket.send_queue();
                        let data = socket
                            .recv(|bytes| {
                                let n = bytes.len().min(room);
                                (n, bytes[..n].to_vec())
                            })
                            .unwrap();
                        socket.send_slice(&data).unwrap();
                    }
                    if socket.state() == tcp::State::CloseWait && !socket.can_recv() {
                        socket.close();
                    }
                    if socket.state() == tcp::State::Closed {
                        socket.listen(port).unwrap();
                    }
                }
                interface.poll(now, &mut wire, &mut sockets);
                replies.extend(wire.tx.drain(..));
                let delay = interface
                    .poll_delay(now, &sockets)
                    .map_or(Duration::from_millis(20), |d| {
                        Duration::from_millis(d.total_millis())
                    })
                    .min(Duration::from_millis(20));
                tokio::select! {
                    packet = outgoing.recv() => match packet {
                        Some(packet) => wire.rx.push_back(packet),
                        None => return,
                    },
                    permit = incoming.reserve(), if !replies.is_empty() => match permit {
                        Ok(permit) => permit.send(replies.pop_front().unwrap()),
                        Err(_) => return,
                    },
                    () = tokio::time::sleep(delay) => {}
                }
                while let Ok(packet) = outgoing.try_recv() {
                    wire.rx.push_back(packet);
                }
                while !replies.is_empty() {
                    let Ok(permit) = incoming.try_reserve() else {
                        break;
                    };
                    permit.send(replies.pop_front().unwrap());
                }
            }
        })
    }
    #[derive(Default)]
    struct Wire {
        rx: std::collections::VecDeque<Bytes>,
        tx: Vec<Bytes>,
    }
    struct WireRx(Bytes);
    struct WireTx<'a>(&'a mut Vec<Bytes>);
    impl smoltcp::phy::Device for Wire {
        type RxToken<'a> = WireRx;
        type TxToken<'a> = WireTx<'a>;
        fn receive(
            &mut self,
            _: smoltcp::time::Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let packet = self.rx.pop_front()?;
            Some((WireRx(packet), WireTx(&mut self.tx)))
        }
        fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
            Some(WireTx(&mut self.tx))
        }
        fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
            let mut caps = smoltcp::phy::DeviceCapabilities::default();
            caps.medium = smoltcp::phy::Medium::Ip;
            caps.max_transmission_unit = 1280;
            caps
        }
    }
    impl smoltcp::phy::RxToken for WireRx {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.0)
        }
    }
    impl smoltcp::phy::TxToken for WireTx<'_> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut bytes = bytes::BytesMut::zeroed(len);
            let result = f(&mut bytes);
            self.0.push(bytes.freeze());
            result
        }
    }

    const ECHO: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)), 80);
    fn echo_stack(limits: FlowLimits, listeners: usize) -> Netstack {
        let (stack, packets) =
            Netstack::start_with_limits(vec!["10.66.0.2".parse().unwrap()], 1280, limits).unwrap();
        echo_peer(packets, Ipv4Address::new(192, 0, 2, 10), 80, listeners);
        stack
    }
    /// Writes, reads the echo, then closes both ways: our FIN, the peer's.
    async fn echo_and_close(mut stream: TcpStream, payload: &[u8]) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(payload).await.unwrap();
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        stream.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    }
    async fn until(mut condition: impl FnMut() -> bool) {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// A browser opens more TCP connections than there are places and keeps
    /// them open. Those past the limit wait for one and complete; the order
    /// places go in is the client tests' concern.
    #[tokio::test]
    async fn tcp_flows_past_the_limit_wait_for_a_place_and_all_complete() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let limits = FlowLimits::new(4, 32, FlowLimits::MIN_TCP_BUFFER).unwrap();
            let stack = echo_stack(limits, 8);
            let mut held = Vec::new();
            for _ in 0..4 {
                held.push(stack.connect(ECHO).await.unwrap());
            }
            assert_eq!(stack.available_tcp_slots(), 0);
            let mut flows = tokio::task::JoinSet::new();
            for index in 0..20u8 {
                flows.spawn({
                    let stack = stack.clone();
                    async move {
                        let stream = stack.connect(ECHO).await.unwrap();
                        echo_and_close(stream, &[index; 3000]).await;
                    }
                });
                until(|| stack.waiting_tcp_flows() == usize::from(index) + 1).await;
            }
            // Seventeen and more flows, none refused.
            assert_eq!(stack.waiting_tcp_flows(), 20);
            drop(held);
            let mut completed = 0;
            while let Some(flow) = flows.join_next().await {
                flow.unwrap();
                completed += 1;
            }
            assert_eq!(completed, 20);
            until(|| stack.available_tcp_slots() == 4).await;
            assert_eq!(stack.waiting_tcp_flows(), 0);
            stack.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_phone_profile_carries_forty_tcp_flows_at_once() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let stack = echo_stack(FlowLimits::MOBILE, 40);
            let all_open = Arc::new(tokio::sync::Barrier::new(41));
            let mut flows = tokio::task::JoinSet::new();
            for index in 0..40u8 {
                flows.spawn({
                    let stack = stack.clone();
                    let all_open = all_open.clone();
                    async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut stream = stack.connect(ECHO).await.unwrap();
                        stream.write_all(&[index; 64]).await.unwrap();
                        let mut echoed = [0; 64];
                        stream.read_exact(&mut echoed).await.unwrap();
                        assert_eq!(echoed, [index; 64]);
                        all_open.wait().await;
                        echo_and_close(stream, b"bye").await;
                    }
                });
            }
            all_open.wait().await;
            assert_eq!(stack.available_tcp_slots(), FlowLimits::MOBILE.tcp() - 40);
            assert_eq!(stack.waiting_tcp_flows(), 0);
            while let Some(flow) = flows.join_next().await {
                flow.unwrap();
            }
            until(|| stack.available_tcp_slots() == FlowLimits::MOBILE.tcp()).await;
            stack.shutdown().await;
        })
        .await
        .unwrap();
    }

    /// Flows closed both ways, dropped mid-transfer, or abandoned while
    /// waiting each give their place back, cycle after cycle, on threads
    /// that race each other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn open_and_close_cycles_leave_no_place_behind() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let limits = FlowLimits::new(4, 64, FlowLimits::MIN_TCP_BUFFER).unwrap();
            let stack = echo_stack(limits, 8);
            let mut workers = tokio::task::JoinSet::new();
            for worker in 0..12u8 {
                workers.spawn({
                    let stack = stack.clone();
                    async move {
                        let mut abandoned = 0;
                        for cycle in 0..20u8 {
                            match (worker + cycle) % 3 {
                                0 => {
                                    let stream = stack.connect(ECHO).await.unwrap();
                                    echo_and_close(stream, &[cycle; 2000]).await;
                                }
                                1 => {
                                    use tokio::io::AsyncWriteExt;
                                    let mut stream = stack.connect(ECHO).await.unwrap();
                                    stream.write_all(&[cycle; 9000]).await.unwrap();
                                    drop(stream);
                                }
                                _ => {
                                    // Gives up its wait, or its open, at once.
                                    let open = tokio::time::timeout(
                                        Duration::from_millis(1),
                                        stack.connect(ECHO),
                                    )
                                    .await;
                                    abandoned += usize::from(open.is_err());
                                }
                            }
                        }
                        abandoned
                    }
                });
            }
            let mut abandoned = 0;
            while let Some(worker) = workers.join_next().await {
                abandoned += worker.unwrap();
            }
            assert!(abandoned > 0, "some flows gave up their wait");
            until(|| stack.available_tcp_slots() == 4).await;
            assert_eq!(stack.waiting_tcp_flows(), 0);
            // Every place is free for use again.
            let mut streams = Vec::new();
            for _ in 0..4 {
                streams.push(stack.connect(ECHO).await.unwrap());
            }
            for stream in streams {
                echo_and_close(stream, b"again").await;
            }
            stack.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn only_families_with_a_local_address_are_reachable() {
        let (stack, _packets) = Netstack::start(vec!["10.66.0.2".parse().unwrap()], 1280).unwrap();
        assert!(matches!(
            stack.open_udp("[2001:db8::1]:53".parse().unwrap()).await,
            Err(Error::NoRoute)
        ));
        assert!(matches!(
            stack.open_udp("224.0.0.1:53".parse().unwrap()).await,
            Err(Error::NoRoute)
        ));
        assert!(Netstack::start(Vec::new(), 1280).is_err());
        assert!(Netstack::start(vec!["10.0.0.1".parse().unwrap()], 576).is_err());
    }
}
