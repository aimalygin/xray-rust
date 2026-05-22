use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Duration};
use xray_config::CoreConfig;
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{DnsResolver, TransportDialer};
use xray_tun::{TunEndpoint, TunError};

use crate::outbound::{open_tcp_stream_with_resolver_and_dialer, select_tcp_outbound_for_session};

const DEFAULT_RANDOM_SEED: u64 = 0x7872_6179_7275_7374;
const TCP_PROTOCOL: u8 = 6;
const TCP_BUFFER_SIZE: usize = 32 * 1024;
const BRIDGE_CHANNEL_DEPTH: usize = 64;
const BRIDGE_READ_BUFFER_SIZE: usize = 16 * 1024;

pub(crate) async fn serve_tun_endpoint(
    tun: Arc<TunEndpoint>,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut device = PacketDevice::new(1500);
    let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = DEFAULT_RANDOM_SEED;
    let mut iface = Interface::new(iface_config, &mut device, Instant::now());
    iface.set_any_ip(true);
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_listeners = HashMap::new();
    let mut tcp_flows = HashMap::new();
    let (stack_tx, mut stack_rx) = mpsc::channel(BRIDGE_CHANNEL_DEPTH);
    let runtime_context = TunRuntimeContext {
        inbound_tag,
        config,
        dns_resolver,
        transport_dialer,
        stack_tx,
    };

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            packet = tun.poll_inbound() => {
                match packet {
                    Ok(packet) => {
                        if let Some(endpoint) = tcp_syn_destination(&packet) {
                            ensure_tcp_listener(&mut sockets, &mut tcp_listeners, endpoint);
                        }
                        device.push_inbound(packet);
                    }
                    Err(TunError::QueueClosed) => break,
                    Err(_) => {}
                }
            }
            event = stack_rx.recv() => {
                if let Some(event) = event {
                    apply_stack_event(event, &mut tcp_flows);
                }
            }
            () = sleep(Duration::from_millis(25)) => {}
        }

        while let Ok(event) = stack_rx.try_recv() {
            apply_stack_event(event, &mut tcp_flows);
        }
        write_remote_data_to_sockets(&mut sockets, &mut tcp_flows);
        iface.poll(Instant::now(), &mut device, &mut sockets);
        open_ready_tcp_flows(
            &mut sockets,
            &mut tcp_listeners,
            &mut tcp_flows,
            &runtime_context,
            shutdown.clone(),
        );
        read_socket_data_to_remote(&mut sockets, &mut tcp_flows);
        cleanup_closed_tcp_flows(&mut sockets, &mut tcp_flows);
        iface.poll(Instant::now(), &mut device, &mut sockets);
        while let Some(packet) = device.pop_outbound() {
            if tun.push_outbound(packet).await.is_err() {
                break;
            }
        }
    }
}

#[derive(Clone)]
struct TunRuntimeContext {
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    stack_tx: mpsc::Sender<StackEvent>,
}

#[derive(Debug)]
struct TcpFlow {
    to_remote: mpsc::Sender<Bytes>,
    pending_remote: VecDeque<Bytes>,
    remote_closed: bool,
}

#[derive(Debug)]
enum StackEvent {
    RemoteData { handle: SocketHandle, data: Bytes },
    RemoteClosed { handle: SocketHandle },
}

fn open_ready_tcp_flows(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<IpEndpoint, SocketHandle>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
) {
    let ready = listeners
        .iter()
        .filter_map(|(endpoint, handle)| {
            let socket = sockets.get::<tcp::Socket>(*handle);
            if socket.is_listening() || flows.contains_key(handle) {
                return None;
            }
            let local_endpoint = socket.local_endpoint()?;
            Some((*endpoint, *handle, target_from_endpoint(local_endpoint)?))
        })
        .collect::<Vec<_>>();

    for (endpoint, handle, target) in ready {
        listeners.remove(&endpoint);
        let (to_remote, from_stack) = mpsc::channel(BRIDGE_CHANNEL_DEPTH);
        flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote: VecDeque::new(),
                remote_closed: false,
            },
        );
        tokio::spawn(bridge_tcp_flow(
            handle,
            target,
            context.clone(),
            from_stack,
            shutdown.clone(),
        ));
    }
}

fn target_from_endpoint(endpoint: IpEndpoint) -> Option<Target> {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(ip) => std::net::IpAddr::V4(ip),
        IpAddress::Ipv6(ip) => std::net::IpAddr::V6(ip),
    };
    Some(Target::new(
        RoutingTargetAddr::Ip(ip),
        endpoint.port,
        RoutingNetwork::Tcp,
    ))
}

fn apply_stack_event(event: StackEvent, flows: &mut HashMap<SocketHandle, TcpFlow>) {
    match event {
        StackEvent::RemoteData { handle, data } => {
            if let Some(flow) = flows.get_mut(&handle) {
                flow.pending_remote.push_back(data);
            }
        }
        StackEvent::RemoteClosed { handle } => {
            if let Some(flow) = flows.get_mut(&handle) {
                flow.remote_closed = true;
            }
        }
    }
}

fn write_remote_data_to_sockets(
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
) {
    for (handle, flow) in flows {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);
        while socket.can_send() {
            let Some(front) = flow.pending_remote.front_mut() else {
                break;
            };
            let written = match socket.send_slice(front) {
                Ok(written) => written,
                Err(_) => {
                    socket.abort();
                    break;
                }
            };
            if written == 0 {
                break;
            }
            if written == front.len() {
                flow.pending_remote.pop_front();
            } else {
                *front = front.slice(written..);
                break;
            }
        }
        if flow.remote_closed && flow.pending_remote.is_empty() && socket.may_send() {
            socket.close();
        }
    }
}

fn read_socket_data_to_remote(
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
) {
    for (handle, flow) in flows {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);
        while socket.can_recv() {
            let data = match socket.recv(|data| {
                let len = data.len();
                (len, Bytes::copy_from_slice(data))
            }) {
                Ok(data) => data,
                Err(_) => {
                    socket.abort();
                    break;
                }
            };
            if data.is_empty() {
                break;
            }
            if flow.to_remote.try_send(data).is_err() {
                socket.abort();
                break;
            }
        }
    }
}

fn cleanup_closed_tcp_flows(
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
) {
    let closed = flows
        .keys()
        .copied()
        .filter(|handle| !sockets.get::<tcp::Socket>(*handle).is_open())
        .collect::<Vec<_>>();

    for handle in closed {
        flows.remove(&handle);
        sockets.remove(handle);
    }
}

async fn bridge_tcp_flow(
    handle: SocketHandle,
    target: Target,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
) {
    let outbound = match select_tcp_outbound_for_session(
        &context.config,
        context.inbound_tag.as_deref(),
        &target,
    ) {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = context
                .stack_tx
                .send(StackEvent::RemoteClosed { handle })
                .await;
            return;
        }
    };
    let stream = match open_tcp_stream_with_resolver_and_dialer(
        &outbound,
        &target,
        context.dns_resolver.as_ref(),
        &context.transport_dialer,
    )
    .await
    {
        Ok(stream) => stream,
        Err(_) => {
            let _ = context
                .stack_tx
                .send(StackEvent::RemoteClosed { handle })
                .await;
            return;
        }
    };

    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    let mut read_buffer = vec![0; BRIDGE_READ_BUFFER_SIZE];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            data = from_stack.recv() => {
                let Some(data) = data else {
                    break;
                };
                if remote_writer.write_all(&data).await.is_err() {
                    break;
                }
                if remote_writer.flush().await.is_err() {
                    break;
                }
            }
            read = remote_reader.read(&mut read_buffer) => {
                let Ok(read) = read else {
                    break;
                };
                if read == 0 {
                    break;
                }
                if context
                    .stack_tx
                    .send(StackEvent::RemoteData {
                        handle,
                        data: Bytes::copy_from_slice(&read_buffer[..read]),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    let _ = context
        .stack_tx
        .send(StackEvent::RemoteClosed { handle })
        .await;
}

fn ensure_tcp_listener(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<IpEndpoint, SocketHandle>,
    endpoint: IpEndpoint,
) {
    if listeners.contains_key(&endpoint) {
        return;
    }

    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
    );
    socket.set_nagle_enabled(false);
    if socket.listen(endpoint).is_ok() {
        listeners.insert(endpoint, sockets.add(socket));
    }
}

fn tcp_syn_destination(packet: &[u8]) -> Option<IpEndpoint> {
    match packet.first()? >> 4 {
        4 => ipv4_tcp_syn_destination(packet),
        6 => ipv6_tcp_syn_destination(packet),
        _ => None,
    }
}

fn ipv4_tcp_syn_destination(packet: &[u8]) -> Option<IpEndpoint> {
    if packet.len() < 40 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 20 {
        return None;
    }
    if packet[9] != TCP_PROTOCOL {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let tcp = &packet[header_len..];
    if !is_initial_tcp_syn(tcp) {
        return None;
    }

    let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Some(IpEndpoint::new(IpAddress::Ipv4(dst_addr), dst_port))
}

fn ipv6_tcp_syn_destination(packet: &[u8]) -> Option<IpEndpoint> {
    if packet.len() < 60 || packet[6] != TCP_PROTOCOL {
        return None;
    }

    let tcp = &packet[40..];
    if !is_initial_tcp_syn(tcp) {
        return None;
    }

    let dst_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Some(IpEndpoint::new(IpAddress::Ipv6(dst_addr), dst_port))
}

fn is_initial_tcp_syn(tcp: &[u8]) -> bool {
    if tcp.len() < 20 {
        return false;
    }
    let flags = tcp[13];
    flags & 0x02 != 0 && flags & 0x10 == 0
}

#[derive(Debug)]
pub(crate) struct PacketDevice {
    mtu: usize,
    inbound: VecDeque<Bytes>,
    outbound: VecDeque<Bytes>,
}

impl PacketDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            mtu,
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
        }
    }

    pub(crate) fn push_inbound(&mut self, packet: Bytes) {
        self.inbound.push_back(packet);
    }

    pub(crate) fn pop_outbound(&mut self) -> Option<Bytes> {
        self.outbound.pop_front()
    }
}

impl Device for PacketDevice {
    type RxToken<'a>
        = PacketRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            PacketRxToken { packet },
            PacketTxToken {
                mtu: self.mtu,
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PacketTxToken {
            mtu: self.mtu,
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = None;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

#[derive(Debug)]
pub(crate) struct PacketRxToken {
    packet: Bytes,
}

impl RxToken for PacketRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[derive(Debug)]
pub(crate) struct PacketTxToken<'a> {
    mtu: usize,
    outbound: &'a mut VecDeque<Bytes>,
}

impl TxToken for PacketTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len.min(self.mtu)];
        let result = f(&mut packet);
        self.outbound.push_back(Bytes::from(packet));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_device_receives_queued_inbound_packet() {
        let mut device = PacketDevice::new(1500);
        device.push_inbound(Bytes::from_static(&[0x45, 0x00, 0x00, 0x14]));

        let (rx, _) = device.receive(Instant::from_millis(0)).unwrap();

        rx.consume(|packet| assert_eq!(packet, &[0x45, 0x00, 0x00, 0x14]));
    }

    #[test]
    fn packet_device_transmits_outbound_packet() {
        let mut device = PacketDevice::new(1500);

        let tx = device.transmit(Instant::from_millis(0)).unwrap();
        tx.consume(4, |packet| {
            packet.copy_from_slice(&[0x45, 0x00, 0x00, 0x14])
        });

        assert_eq!(
            device.pop_outbound(),
            Some(Bytes::from_static(&[0x45, 0x00, 0x00, 0x14]))
        );
    }

    #[test]
    fn tcp_syn_destination_extracts_ipv4_destination() {
        let packet = [
            0x45,
            0x00,
            0x00,
            0x28,
            0x00,
            0x00,
            0x00,
            0x00,
            64,
            TCP_PROTOCOL,
            0x00,
            0x00,
            10,
            10,
            0,
            2,
            127,
            0,
            0,
            1,
            0xc0,
            0x00,
            0x1f,
            0x90,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x50,
            0x02,
            0x04,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let endpoint = tcp_syn_destination(&packet).unwrap();

        assert_eq!(endpoint.addr, IpAddress::Ipv4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.port, 8080);
    }
}
