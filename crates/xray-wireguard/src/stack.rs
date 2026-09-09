use crate::client::{Command, Error, Flow, Stop, OPEN_TIMEOUT, PACKET_QUEUE};
use crate::Config;
use bytes::{Bytes, BytesMut};
use gotatun::packet::{Ip, Packet};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, PollResult, SocketHandle, SocketSet},
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
    sync::{atomic::Ordering, Arc},
    task::{Context, Poll},
    time::{Duration, Instant as Clock},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit},
};

const TCP_BUFFER: usize = 16 * 1024;
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
        for _ in 0..PACKET_QUEUE {
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
            progress |= self
                .interface
                .poll(now, &mut self.device, &mut self.sockets)
                != PollResult::None;
            if self.device.rx.is_some() || self.incoming.is_empty() {
                break;
            }
        }
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
                    if !flow.write_eof && socket.can_send() {
                        let mut scratch = [0; 4096];
                        let capacity = scratch
                            .len()
                            .min(socket.send_capacity() - socket.send_queue());
                        let mut buf = ReadBuf::new(&mut scratch[..capacity]);
                        match Pin::new(&mut flow.bridge).poll_read(cx, &mut buf) {
                            Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                                flow.write_eof = true;
                                socket.close();
                                progress = true;
                            }
                            Poll::Ready(Ok(())) => {
                                let sent = socket
                                    .send_slice(buf.filled())
                                    .expect("send capacity checked");
                                debug_assert_eq!(sent, buf.filled().len());
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
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                    tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                );
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
        caps.max_burst_size = Some(PACKET_QUEUE);
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
