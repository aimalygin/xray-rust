use crate::client::{Command, Error, Flow, Stop, IP_PACKET_QUEUE, OPEN_TIMEOUT, PACKET_QUEUE};
use crate::Config;
use bytes::{Bytes, BytesMut};
use gotatun::packet::{Ip, Packet};
use smoltcp::{
    iface::{
        Config as InterfaceConfig, Interface, PollIngressSingleResult, PollResult, SocketHandle,
        SocketSet,
    },
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::HashMap,
    future::poll_fn,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{atomic::Ordering, Arc, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant as Clock},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit},
};

// Bound receive bursts independently of the send window for delayed paths.
// At most 32 MiB of backing storage across 16 TCP slots; active windows start smaller.
const TCP_RECEIVE_BUFFER: usize = 1024 * 1024;
const TCP_INITIAL_RECEIVE_WINDOW: usize = 64 * 1024;
const TCP_SEND_BUFFER: usize = 1024 * 1024;

fn tcp_timestamp() -> u32 {
    static EPOCH: OnceLock<Clock> = OnceLock::new();
    // RFC 7323 timestamps use a wrapping monotonic clock, not wall time.
    (EPOCH.get_or_init(Clock::now).elapsed().as_millis() as u32).wrapping_add(1)
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_RECEIVE_BUFFER]),
        tcp::SocketBuffer::new(vec![0; TCP_SEND_BUFFER]),
    );
    assert!(socket.set_receive_window_limit(TCP_INITIAL_RECEIVE_WINDOW));
    socket.set_congestion_control(tcp::CongestionControl::Reno);
    assert!(socket.set_reno_initial_window(10));
    assert!(socket.set_reno_appropriate_byte_counting(true));
    socket.set_nagle_enabled(false);
    // Peers can continue measuring RTT during retransmission, instead of
    // retaining an exponentially backed-off timeout after burst loss.
    socket.set_tsval_generator(Some(tcp_timestamp));
    socket
}
struct TcpFlow {
    handle: SocketHandle,
    flow: Arc<Flow>,
    _permit: OwnedSemaphorePermit,
    port: u16,
    bridge: DuplexStream,
    reply: Option<oneshot::Sender<Result<(), Error>>>,
    deadline: Clock,
    write_eof: bool,
    read_eof: bool,
    read_bytes: usize,
    last_read: Option<Clock>,
}
impl TcpFlow {
    fn receives_bulk(&self, socket: &tcp::Socket<'_>, now: Clock) -> bool {
        !self.read_eof
            && self.read_bytes.saturating_add(socket.recv_queue()) >= TCP_INITIAL_RECEIVE_WINDOW / 2
            && (socket.recv_queue() != 0
                || self.last_read.is_some_and(|last| {
                    now.saturating_duration_since(last) <= Duration::from_secs(1)
                }))
    }
}
struct UdpFlow {
    handle: SocketHandle,
    flow: Arc<Flow>,
    _permit: OwnedSemaphorePermit,
    port: u16,
    remote: IpEndpoint,
    incoming: mpsc::Sender<Bytes>,
}
enum Entry {
    Tcp(TcpFlow),
    Udp(UdpFlow),
}
impl Entry {
    fn port(&self) -> u16 {
        match self {
            Self::Tcp(f) => f.port,
            Self::Udp(f) => f.port,
        }
    }
    fn handle(&self) -> SocketHandle {
        match self {
            Self::Tcp(f) => f.handle,
            Self::Udp(f) => f.handle,
        }
    }
}

pub(crate) struct Stack {
    interface: Interface,
    device: Packets,
    sockets: SocketSet<'static>,
    flows: HashMap<u64, Entry>,
    commands: mpsc::Receiver<Command>,
    incoming: mpsc::Receiver<Packet<Ip>>,
    wake: Arc<Notify>,
    start: Clock,
    port: u16,
    mtu: usize,
}
impl Stack {
    pub(crate) fn new(
        config: &Config,
        tx: mpsc::Sender<Packet<Ip>>,
        incoming: mpsc::Receiver<Packet<Ip>>,
        commands: mpsc::Receiver<Command>,
        wake: Arc<Notify>,
    ) -> Self {
        let mut device = Packets {
            tx,
            rx: None,
            mtu: usize::from(config.mtu),
        };
        let mut options = InterfaceConfig::new(HardwareAddress::Ip);
        options.random_seed = rand::random();
        let mut interface = Interface::new(options, &mut device, Instant::ZERO);
        interface.set_round_robin_egress(true);
        interface.set_tcp_egress_burst(32);
        interface.update_ip_addrs(|ips| {
            for address in &config.addresses {
                ips.push(IpCidr::new(
                    (*address).into(),
                    if address.is_ipv4() { 32 } else { 128 },
                ))
                .expect("two configured addresses fit interface");
            }
        });
        // Medium::Ip has no link-layer next-hop resolution; these routes send all
        // destinations to the injected point-to-point device, then cryptokey routing.
        for address in &config.addresses {
            match address {
                IpAddr::V4(ip) => {
                    interface
                        .routes_mut()
                        .add_default_ipv4_route(*ip)
                        .expect("one default per family");
                }
                IpAddr::V6(ip) => {
                    interface
                        .routes_mut()
                        .add_default_ipv6_route(*ip)
                        .expect("one default per family");
                }
            }
        }
        Self {
            interface,
            device,
            sockets: SocketSet::new(vec![]),
            flows: HashMap::new(),
            commands,
            incoming,
            wake,
            start: Clock::now(),
            port: rand::random::<u16>() | 0xc000,
            mtu: usize::from(config.mtu),
        }
    }
    fn now(&self) -> Instant {
        Instant::from_millis(self.start.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }
    fn next_port(&mut self) -> u16 {
        loop {
            self.port = self.port.wrapping_add(1) | 0xc000;
            if !self.flows.values().any(|f| f.port() == self.port) {
                return self.port;
            }
        }
    }
    pub(crate) async fn run(mut self, stop: Stop) {
        loop {
            let mut delay = if self.device.tx.capacity() == 0 {
                None
            } else {
                self.interface
                    .poll_delay(self.now(), &self.sockets)
                    .map(|d| Duration::from_millis(d.total_millis().max(1)))
            };
            for flow in self.flows.values() {
                if let Entry::Tcp(TcpFlow {
                    reply: Some(_),
                    deadline,
                    ..
                }) = flow
                {
                    let remaining = deadline.saturating_duration_since(Clock::now());
                    delay = Some(delay.map_or(remaining, |d| d.min(remaining)));
                }
            }
            let wake = self.wake.clone();
            tokio::select! { biased;
                _ = stop.cancelled() => return,
                result = poll_fn(|cx| self.drive(cx)) => if !result { return; },
                _ = wake.notified() => {},
                _ = async { match delay { Some(d) => tokio::time::sleep(d).await, None => std::future::pending().await } } => {},
            }
            tokio::task::yield_now().await;
        }
    }
    fn drive(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        if self.device.tx.is_closed() {
            return Poll::Ready(false);
        }
        let mut progress = false;
        for _ in 0..32 {
            match self.commands.poll_recv(cx) {
                Poll::Ready(Some(command)) => {
                    self.command(command);
                    progress = true;
                }
                Poll::Ready(None) => return Poll::Ready(false),
                Poll::Pending => break,
            }
        }
        for _ in 0..IP_PACKET_QUEUE {
            if self.device.rx.is_none() {
                match self.incoming.poll_recv(cx) {
                    Poll::Ready(Some(packet)) => {
                        self.device.rx = Some(packet);
                        progress = true;
                    }
                    Poll::Ready(None) => return Poll::Ready(false),
                    Poll::Pending => {}
                }
            }
            let now = self.now();
            // Consume at most the bounded input batch before scanning every
            // socket for output. The final poll below still maintains timers,
            // drains egress and emits abort RSTs before socket removal.
            progress |=
                self.interface
                    .poll_ingress_single(now, &mut self.device, &mut self.sockets)
                    != PollIngressSingleResult::None;
            if self.device.rx.is_some() || self.incoming.is_empty() {
                break;
            }
        }
        // A delayed carrier has one shared capacity budget. Let a single
        // sender fill its high-BDP buffer, and divide pending application data
        // among concurrent senders. Existing queued data drains normally when
        // a new flow opens; EOF is read only after space becomes available.
        let active_senders = self
            .flows
            .values()
            .filter(|entry| match entry {
                Entry::Tcp(flow) => self.sockets.get::<tcp::Socket>(flow.handle).send_queue() != 0,
                Entry::Udp(_) => false,
            })
            .count()
            .max(1);
        let send_budget = TCP_SEND_BUFFER / active_senders;
        let activity_now = Clock::now();
        let active_receivers =
            self.flows
                .values()
                .filter(|entry| match entry {
                    Entry::Tcp(flow) => flow
                        .receives_bulk(self.sockets.get::<tcp::Socket>(flow.handle), activity_now),
                    Entry::Udp(_) => false,
                })
                .count()
                .max(1);
        let receive_budget =
            (TCP_RECEIVE_BUFFER / active_receivers).max(TCP_INITIAL_RECEIVE_WINDOW);
        let mut removed = Vec::new();
        for (&id, entry) in &mut self.flows {
            match entry {
                Entry::Tcp(flow) => {
                    let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
                    if flow.flow.closed.load(Ordering::Acquire) {
                        socket.abort();
                        removed.push(id);
                        continue;
                    }
                    if flow.reply.is_some() {
                        if matches!(
                            socket.state(),
                            tcp::State::Established | tcp::State::CloseWait
                        ) {
                            let _ = flow.reply.take().unwrap().send(Ok(()));
                            progress = true;
                        } else if Clock::now() >= flow.deadline
                            || socket.state() == tcp::State::Closed
                        {
                            let _ = flow.reply.take().unwrap().send(Err(
                                if socket.state() == tcp::State::Closed {
                                    Error::Connect
                                } else {
                                    Error::Timeout
                                },
                            ));
                            socket.abort();
                            removed.push(id);
                            continue;
                        } else {
                            continue;
                        }
                    }
                    // Idle keepalive connections do not divide an active flow's
                    // budget. Rebalancing preserves outstanding advertised credit
                    // until it drains, including data sent before a new flow opens.
                    let window = if flow.receives_bulk(socket, activity_now) {
                        receive_budget
                    } else {
                        TCP_INITIAL_RECEIVE_WINDOW
                    };
                    progress |= socket.set_receive_window_limit(window);
                    let allowance = send_budget.saturating_sub(socket.send_queue());
                    if !flow.write_eof && socket.can_send() && allowance != 0 {
                        // Read only available shared budget; a zero-length read
                        // must never be mistaken for the application's EOF.
                        let read = socket
                            .send(|bytes| {
                                let limit = bytes.len().min(allowance);
                                let mut buf = ReadBuf::new(&mut bytes[..limit]);
                                let result = Pin::new(&mut flow.bridge).poll_read(cx, &mut buf);
                                let n = buf.filled().len();
                                (n, result.map_ok(|()| n))
                            })
                            .expect("send capacity checked");
                        match read {
                            Poll::Ready(Ok(0)) => {
                                flow.write_eof = true;
                                socket.close();
                                progress = true;
                            }
                            Poll::Ready(Ok(_)) => {
                                progress = true;
                            }
                            Poll::Ready(Err(_)) => {
                                socket.abort();
                                removed.push(id);
                                continue;
                            }
                            Poll::Pending => {}
                        }
                    }
                    let mut failed = false;
                    if socket.can_recv() {
                        let _ = socket.recv(|bytes| {
                            match Pin::new(&mut flow.bridge).poll_write(cx, bytes) {
                                Poll::Ready(Ok(n)) if n != 0 => {
                                    progress = true;
                                    if flow.last_read.is_some_and(|last| {
                                        activity_now.saturating_duration_since(last)
                                            > Duration::from_secs(1)
                                    }) {
                                        flow.read_bytes = 0;
                                    }
                                    flow.read_bytes = flow.read_bytes.saturating_add(n);
                                    flow.last_read = Some(activity_now);
                                    (n, ())
                                }
                                Poll::Ready(_) => {
                                    failed = true;
                                    (0, ())
                                }
                                Poll::Pending => (0, ()),
                            }
                        });
                    }
                    if failed {
                        socket.abort();
                        removed.push(id);
                        continue;
                    }
                    if socket.state() == tcp::State::Closed && !flow.read_eof {
                        flow.flow.reset.store(true, Ordering::Release);
                    }
                    if !flow.read_eof
                        && !socket.may_recv()
                        && Pin::new(&mut flow.bridge).poll_shutdown(cx).is_ready()
                    {
                        flow.read_eof = true;
                        progress = true;
                    }
                    if socket.state() == tcp::State::Closed {
                        removed.push(id);
                    }
                }
                Entry::Udp(flow) => {
                    if flow.flow.closed.load(Ordering::Acquire) {
                        removed.push(id);
                        continue;
                    }
                    let socket = self.sockets.get_mut::<udp::Socket>(flow.handle);
                    while let Ok((payload, meta)) = socket.recv() {
                        if meta.endpoint == flow.remote {
                            // Reserve before copying. A stalled application drops UDP,
                            // leaving bounded storage and other flows able to progress.
                            if let Ok(slot) = flow.incoming.try_reserve() {
                                slot.send(Bytes::copy_from_slice(payload));
                            }
                        }
                        progress = true;
                    }
                }
            }
        }
        // Give TCP aborts a chance to emit RST before removing socket storage.
        let now = self.now();
        progress |= self
            .interface
            .poll(now, &mut self.device, &mut self.sockets)
            != PollResult::None;
        progress |= !removed.is_empty();
        for id in removed {
            if let Some(entry) = self.flows.remove(&id) {
                self.sockets.remove(entry.handle());
            }
        }
        if progress {
            Poll::Ready(true)
        } else {
            Poll::Pending
        }
    }
    fn command(&mut self, command: Command) {
        match command {
            Command::Tcp {
                local,
                remote,
                bridge,
                reply,
                flow,
                permit,
            } => {
                if flow.closed.load(Ordering::Acquire) || reply.is_closed() {
                    return;
                }
                // This TCP crosses a real UDP path; respect congestion instead
                // of sending every flow's entire window into bounded queues.
                let mut socket = tcp_socket();
                let port = self.next_port();
                if socket
                    .connect(
                        self.interface.context(),
                        endpoint(remote),
                        (IpAddress::from(local), port),
                    )
                    .is_err()
                {
                    let _ = reply.send(Err(Error::NoRoute));
                    return;
                }
                self.flows.insert(
                    flow.id,
                    Entry::Tcp(TcpFlow {
                        handle: self.sockets.add(socket),
                        flow,
                        _permit: permit,
                        port,
                        bridge,
                        reply: Some(reply),
                        deadline: Clock::now() + OPEN_TIMEOUT,
                        write_eof: false,
                        read_eof: false,
                        read_bytes: 0,
                        last_read: None,
                    }),
                );
            }
            Command::Udp {
                local,
                remote,
                incoming,
                reply,
                flow,
                permit,
            } => {
                if flow.closed.load(Ordering::Acquire) || reply.is_closed() {
                    return;
                }
                let mut socket = udp::Socket::new(
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; PACKET_QUEUE],
                        vec![0; self.mtu * PACKET_QUEUE],
                    ),
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; PACKET_QUEUE],
                        vec![0; self.mtu * PACKET_QUEUE],
                    ),
                );
                let port = self.next_port();
                if socket.bind((IpAddress::from(local), port)).is_err() {
                    let _ = reply.send(Err(Error::NoRoute));
                    return;
                }
                self.flows.insert(
                    flow.id,
                    Entry::Udp(UdpFlow {
                        handle: self.sockets.add(socket),
                        flow,
                        _permit: permit,
                        port,
                        remote: endpoint(remote),
                        incoming,
                    }),
                );
                let _ = reply.send(Ok(()));
            }
            Command::Send { id, payload, reply } => {
                let result = match self.flows.get(&id) {
                    Some(Entry::Udp(flow)) if !flow.flow.closed.load(Ordering::Acquire) => {
                        let socket = self.sockets.get_mut::<udp::Socket>(flow.handle);
                        match socket.send_slice(&payload, flow.remote) {
                            Ok(()) | Err(udp::SendError::BufferFull) => Ok(()),
                            Err(_) => Err(Error::NoRoute),
                        }
                    }
                    _ => Err(Error::Closed),
                };
                let _ = reply.send(result);
            }
        }
    }
}
fn endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(addr.ip().into(), addr.port())
}

struct Packets {
    tx: mpsc::Sender<Packet<Ip>>,
    rx: Option<Packet<Ip>>,
    mtu: usize,
}
struct Receive(Packet<Ip>);
struct Transmit {
    permit: mpsc::OwnedPermit<Packet<Ip>>,
    mtu: usize,
}
impl Device for Packets {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit;
    fn receive(&mut self, _: Instant) -> Option<(Receive, Transmit)> {
        self.rx.as_ref()?;
        let transmit = self.transmit(Instant::ZERO)?;
        Some((Receive(self.rx.take().unwrap()), transmit))
    }
    fn transmit(&mut self, _: Instant) -> Option<Transmit> {
        Some(Transmit {
            permit: self.tx.clone().try_reserve_owned().ok()?,
            mtu: self.mtu,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // This backpressured packet channel is not a TCP receive window.
        // smoltcp uses max_burst_size to rewrite window fields after the TCP
        // socket has recorded its advertisement, causing the peer and socket
        // to disagree. Let each bounded TCP buffer advertise its real space;
        // transmit permits still enforce IP_PACKET_QUEUE independently.
        caps.max_burst_size = None;
        caps
    }
}
impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0.into_bytes())
    }
}
impl TxToken for Transmit {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        assert!(len <= self.mtu, "smoltcp must respect the configured MTU");
        let mut bytes = BytesMut::zeroed(len);
        let result = f(&mut bytes);
        if let Ok(packet) = Packet::from_bytes(bytes).try_into_ip() {
            self.permit.send(packet);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    };

    #[test]
    fn tcp_egress_batches_without_starving_a_bounded_device() {
        for (burst, capacity) in [
            (1, 128),
            (8, 128),
            (16, 128),
            (32, 128),
            (8, 1),
            (16, 1),
            (32, 1),
        ] {
            let (tx, mut outgoing) = mpsc::channel(capacity);
            let mut device = Packets {
                tx,
                rx: None,
                mtu: 1420,
            };
            let mut interface = Interface::new(
                InterfaceConfig::new(HardwareAddress::Ip),
                &mut device,
                Instant::ZERO,
            );
            interface.set_round_robin_egress(true);
            interface.set_tcp_egress_burst(burst);
            let local = Ipv4Address::new(10, 44, 0, 2);
            let remote = Ipv4Address::new(10, 44, 0, 1);
            interface.update_ip_addrs(|addresses| {
                addresses.push(IpCidr::new(local.into(), 24)).unwrap();
            });
            let mut sockets = SocketSet::new(vec![]);
            let hole = sockets.add(udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 16]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 16]),
            ));
            let mut handles = Vec::new();
            for port in [40000, 40001] {
                let mut socket = tcp_socket();
                socket
                    .connect(interface.context(), (remote, 80), (local, port))
                    .unwrap();
                let handle = sockets.add(socket);
                handles.push(handle);
                interface.poll(Instant::ZERO, &mut device, &mut sockets);
                let syn = outgoing.try_recv().unwrap().into_bytes();
                let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
                let syn = TcpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(syn.src_port(), port);
                let repr = TcpRepr {
                    src_port: 80,
                    dst_port: port,
                    control: TcpControl::Syn,
                    seq_number: TcpSeqNumber(1000),
                    ack_number: Some(syn.seq_number() + 1),
                    window_len: u16::MAX,
                    window_scale: Some(0),
                    max_seg_size: Some(1380),
                    sack_permitted: true,
                    sack_ranges: [None; 3],
                    timestamp: None,
                    payload: &[],
                };
                let ip_repr = Ipv4Repr {
                    src_addr: remote,
                    dst_addr: local,
                    next_header: IpProtocol::Tcp,
                    payload_len: repr.buffer_len(),
                    hop_limit: 64,
                };
                let mut bytes = BytesMut::zeroed(ip_repr.buffer_len() + repr.buffer_len());
                let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
                ip_repr.emit(&mut ip, &ChecksumCapabilities::default());
                repr.emit(
                    &mut TcpPacket::new_unchecked(ip.payload_mut()),
                    &remote.into(),
                    &local.into(),
                    &ChecksumCapabilities::default(),
                );
                device.rx = Some(Packet::from_bytes(bytes).try_into_ip().unwrap());
                interface.poll(Instant::from_millis(1), &mut device, &mut sockets);
                assert_eq!(
                    sockets.get::<tcp::Socket>(handle).state(),
                    tcp::State::Established
                );
                while outgoing.try_recv().is_ok() {}
            }
            sockets.remove(hole); // Stable socket handles contain an initial gap.
            for handle in handles {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                // Exercise scheduler bounds independently of the initial Reno
                // window; production sockets keep Reno and its congestion cap.
                socket.set_congestion_control(tcp::CongestionControl::None);
                socket.send_slice(&[42; 64 * 1024]).unwrap();
            }
            if capacity == 1 {
                for expected in [40000, 40001, 40000, 40001] {
                    interface.poll_egress(Instant::from_millis(2), &mut device, &mut sockets);
                    let packet = outgoing.try_recv().unwrap().into_bytes();
                    let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
                    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                    assert!(!tcp.payload().is_empty());
                    assert_eq!(
                        tcp.src_port(),
                        expected,
                        "a partial burst must yield to the other socket"
                    );
                    assert!(outgoing.try_recv().is_err());
                }
            } else {
                interface.poll_egress(Instant::from_millis(2), &mut device, &mut sockets);
                let mut ports = Vec::new();
                while let Ok(packet) = outgoing.try_recv() {
                    let bytes = packet.into_bytes();
                    let ip = Ipv4Packet::new_checked(&bytes[..]).unwrap();
                    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                    assert!(!tcp.payload().is_empty());
                    ports.push(tcp.src_port());
                }
                let expected: Vec<_> = [40000, 40001]
                    .into_iter()
                    .flat_map(|p| std::iter::repeat_n(p, burst))
                    .collect();
                assert_eq!(
                    ports, expected,
                    "one scan must emit only the configured bounded burst per socket"
                );
            }
        }
    }

    #[test]
    fn bounded_device_egress_does_not_starve_later_sockets() {
        for (enabled, expected_ports) in [
            (false, [40000, 40000, 40001, 40001]),
            (true, [40000, 40001, 40000, 40001]),
        ] {
            let (tx, mut outgoing) = mpsc::channel(1);
            let mut device = Packets {
                tx,
                rx: None,
                mtu: 1420,
            };
            let mut interface = Interface::new(
                InterfaceConfig::new(HardwareAddress::Ip),
                &mut device,
                Instant::ZERO,
            );
            interface.set_round_robin_egress(enabled);
            let local = Ipv4Address::new(10, 44, 0, 2);
            let remote = Ipv4Address::new(10, 44, 0, 1);
            interface.update_ip_addrs(|addresses| {
                addresses.push(IpCidr::new(local.into(), 24)).unwrap();
            });
            let mut sockets = SocketSet::new(vec![]);
            assert_eq!(
                interface.poll_egress(Instant::ZERO, &mut device, &mut sockets),
                PollResult::None
            );
            let hole = sockets.add(udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 16]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 16]),
            ));
            for port in [40000, 40001] {
                let mut socket = udp::Socket::new(
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 2], vec![0; 16]),
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 2], vec![0; 16]),
                );
                socket.bind((IpAddress::from(local), port)).unwrap();
                for _ in 0..2 {
                    socket.send_slice(b"data", (remote, 80)).unwrap();
                }
                sockets.add(socket);
            }
            sockets.remove(hole); // Stable handles can leave holes before the cursor.
            for expected in expected_ports {
                interface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
                let packet = outgoing.try_recv().unwrap().into_bytes();
                let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
                let udp = smoltcp::wire::UdpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(
                    udp.src_port(),
                    expected,
                    "a busy first socket must not monopolize a one-packet device"
                );
                assert!(outgoing.try_recv().is_err());
            }
        }
    }

    #[test]
    fn tcp_advertises_receive_window_instead_of_packet_queue_depth() {
        let (tx, mut outgoing) = mpsc::channel(PACKET_QUEUE);
        let mut device = Packets {
            tx,
            rx: None,
            mtu: 1420,
        };
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        let local = Ipv4Address::new(10, 44, 0, 2);
        let remote = Ipv4Address::new(10, 44, 0, 1);
        interface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(local.into(), 24)).unwrap();
        });
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RECEIVE_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_SEND_BUFFER]),
        );
        socket
            .connect(interface.context(), (remote, 80), (local, 40000))
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        sockets.add(socket);
        interface.poll(Instant::ZERO, &mut device, &mut sockets);
        let packet = outgoing.try_recv().expect("outgoing TCP SYN");
        let bytes = packet.into_bytes();
        let ip = Ipv4Packet::new_checked(&bytes[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn());
        // SYN's window is unscaled. The packet adapter must preserve the TCP
        // stack's receive-window advertisement, including its scaling offer.
        // Packet-queue capacity is independently enforced by transmit permits.
        assert_eq!(tcp.window_len(), u16::MAX);
        let repr = TcpRepr::parse(
            &tcp,
            &local.into(),
            &remote.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert!(repr.window_scale.is_some_and(|scale| scale > 0));
    }

    #[test]
    fn tcp_reacknowledges_each_retransmitted_data_packet() {
        reacknowledges_data(false);
        reacknowledges_data(true);
    }

    fn reacknowledges_data(peer_timestamps: bool) {
        let local = Ipv4Address::new(10, 44, 0, 2);
        let remote = Ipv4Address::new(10, 44, 0, 1);
        let (tx, mut outgoing) = mpsc::channel(PACKET_QUEUE);
        let mut device = Packets {
            tx,
            rx: None,
            mtu: 1420,
        };
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(local.into(), 24)).unwrap();
        });
        let mut socket = tcp_socket();
        socket
            .connect(interface.context(), (remote, 80), (local, 40000))
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        interface.poll(Instant::ZERO, &mut device, &mut sockets);
        let syn = outgoing.try_recv().unwrap().into_bytes();
        let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
        let syn_repr = TcpRepr::parse(
            &TcpPacket::new_checked(ip.payload()).unwrap(),
            &local.into(),
            &remote.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert!(syn_repr.timestamp.is_some());
        let seq = syn_repr.seq_number + 1;
        let packet = |syn: bool| {
            let repr = TcpRepr {
                src_port: 80,
                dst_port: 40000,
                control: if syn {
                    TcpControl::Syn
                } else {
                    TcpControl::Psh
                },
                seq_number: TcpSeqNumber(if syn { 1000 } else { 1001 }),
                ack_number: Some(seq),
                window_len: u16::MAX,
                window_scale: if syn { Some(0) } else { None },
                max_seg_size: if syn { Some(1380) } else { None },
                sack_permitted: syn,
                sack_ranges: [None; 3],
                timestamp: peer_timestamps
                    .then(|| smoltcp::wire::TcpTimestampRepr::new(if syn { 100 } else { 200 }, 0)),
                payload: if syn { &[] } else { &[42] },
            };
            let ip_repr = Ipv4Repr {
                src_addr: remote,
                dst_addr: local,
                next_header: IpProtocol::Tcp,
                payload_len: repr.buffer_len(),
                hop_limit: 64,
            };
            let mut bytes = BytesMut::zeroed(ip_repr.buffer_len() + repr.buffer_len());
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip_repr.emit(&mut ip, &ChecksumCapabilities::default());
            repr.emit(
                &mut TcpPacket::new_unchecked(ip.payload_mut()),
                &remote.into(),
                &local.into(),
                &ChecksumCapabilities::default(),
            );
            Packet::from_bytes(bytes).try_into_ip().unwrap()
        };
        device.rx = Some(packet(true));
        interface.poll(Instant::from_millis(1), &mut device, &mut sockets);
        assert_eq!(
            sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );
        while outgoing.try_recv().is_ok() {}
        device.rx = Some(packet(false));
        interface.poll(Instant::from_millis(2), &mut device, &mut sockets);
        let mut byte = [0];
        assert_eq!(
            sockets
                .get_mut::<tcp::Socket>(handle)
                .recv_slice(&mut byte)
                .unwrap(),
            1
        );
        assert_eq!(byte, [42]);
        interface.poll(Instant::from_millis(20), &mut device, &mut sockets);
        while outgoing.try_recv().is_ok() {}
        // Model lost acknowledgements: the peer resends already consumed data.
        // Every retry needs an ACK; challenge-ACK throttling must not suppress
        // ordinary data ACKs and force another retransmission timeout.
        for now in [21, 22] {
            device.rx = Some(packet(false));
            interface.poll(Instant::from_millis(now), &mut device, &mut sockets);
            let bytes = outgoing
                .try_recv()
                .expect("ACK for retransmitted data")
                .into_bytes();
            let ip = Ipv4Packet::new_checked(&bytes[..]).unwrap();
            let ack = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(ack.ack());
            assert_eq!(ack.ack_number(), TcpSeqNumber(1002));
            assert!(ack.payload().is_empty());
            let ack_repr = TcpRepr::parse(
                &ack,
                &local.into(),
                &remote.into(),
                &ChecksumCapabilities::default(),
            )
            .unwrap();
            assert_eq!(
                ack_repr.timestamp.map(|t| t.tsecr),
                peer_timestamps.then_some(200)
            );
        }
    }

    #[test]
    fn tcp_initial_window_allows_ten_segments_without_an_ack() {
        let local = Ipv4Address::new(10, 44, 0, 2);
        let remote = Ipv4Address::new(10, 44, 0, 1);
        let (tx, mut outgoing) = mpsc::channel(PACKET_QUEUE);
        let mut device = Packets {
            tx,
            rx: None,
            mtu: 1420,
        };
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(local.into(), 24)).unwrap();
        });
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RECEIVE_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_SEND_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(tcp::CongestionControl::Reno);
        assert!(socket.set_reno_initial_window(10));
        socket
            .connect(interface.context(), (remote, 80), (local, 40000))
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        interface.poll(Instant::ZERO, &mut device, &mut sockets);
        let syn = outgoing.try_recv().unwrap().into_bytes();
        let ip = Ipv4Packet::new_checked(&syn[..]).unwrap();
        let seq = TcpPacket::new_checked(ip.payload()).unwrap().seq_number() + 1;
        let packet = |syn: bool| {
            let repr = TcpRepr {
                src_port: 80,
                dst_port: 40000,
                control: if syn {
                    TcpControl::Syn
                } else {
                    TcpControl::Psh
                },
                seq_number: TcpSeqNumber(if syn { 1000 } else { 1001 }),
                ack_number: Some(seq),
                window_len: u16::MAX,
                window_scale: if syn { Some(0) } else { None },
                max_seg_size: if syn { Some(1380) } else { None },
                sack_permitted: syn,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: if syn { &[] } else { &[42] },
            };
            let ip_repr = Ipv4Repr {
                src_addr: remote,
                dst_addr: local,
                next_header: IpProtocol::Tcp,
                payload_len: repr.buffer_len(),
                hop_limit: 64,
            };
            let mut bytes = BytesMut::zeroed(ip_repr.buffer_len() + repr.buffer_len());
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip_repr.emit(&mut ip, &ChecksumCapabilities::default());
            repr.emit(
                &mut TcpPacket::new_unchecked(ip.payload_mut()),
                &remote.into(),
                &local.into(),
                &ChecksumCapabilities::default(),
            );
            Packet::from_bytes(bytes).try_into_ip().unwrap()
        };
        device.rx = Some(packet(true));
        interface.poll(Instant::from_millis(1), &mut device, &mut sockets);
        assert_eq!(
            sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );
        while outgoing.try_recv().is_ok() {}
        sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&[7; 64 * 1024])
            .unwrap();
        let mut payload_bytes = 0;
        loop {
            interface.poll(Instant::from_millis(2), &mut device, &mut sockets);
            let mut packets = 0;
            while let Ok(packet) = outgoing.try_recv() {
                let bytes = packet.into_bytes();
                let ip = Ipv4Packet::new_checked(&bytes[..]).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                payload_bytes += tcp.payload().len();
                packets += 1;
            }
            if packets == 0 {
                break;
            }
        }
        // The negotiated MSS is 1380. A bounded IW10 should fill ten segments
        // before another ACK, without disabling congestion or receiver limits.
        assert_eq!(payload_bytes, 10 * 1380);
    }
}
