use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpEndpoint};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Duration};
use xray_config::CoreConfig;
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{protect_udp_socket, DnsResolver, TransportDialer};
use xray_tun::{TunEndpoint, TunError};

use crate::outbound::{
    open_tcp_stream_with_resolver_and_dialer, open_vless_udp_stream_with_resolver_and_dialer,
    select_tcp_outbound_for_session, select_udp_outbound_for_session, UdpOutbound,
    VlessTcpOutbound, VlessUdpFraming,
};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, encode_xudp_new_packet, read_udp_packet,
    read_xudp_packet,
};

const DEFAULT_RANDOM_SEED: u64 = 0x7872_6179_7275_7374;
const ICMPV4_PROTOCOL: u8 = 1;
const ICMPV6_PROTOCOL: u8 = 58;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const TCP_BUFFER_SIZE: usize = 32 * 1024;
const BRIDGE_CHANNEL_DEPTH: usize = 64;
const BRIDGE_READ_BUFFER_SIZE: usize = 16 * 1024;
const MAX_TUN_INBOUND_DRAIN_PER_TICK: usize = 256;
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpRemoteBufferPolicy {
    global_budget_bytes: usize,
    min_per_flow_bytes: usize,
    max_per_flow_bytes: usize,
}

#[cfg(any(
    test,
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
const MOBILE_TCP_REMOTE_BUFFER_POLICY: TcpRemoteBufferPolicy = TcpRemoteBufferPolicy {
    global_budget_bytes: 40 * 1024 * 1024,
    min_per_flow_bytes: 64 * 1024,
    max_per_flow_bytes: 1024 * 1024,
};

#[cfg(any(
    test,
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos"
    ))
))]
const DESKTOP_TCP_REMOTE_BUFFER_POLICY: TcpRemoteBufferPolicy = TcpRemoteBufferPolicy {
    global_budget_bytes: 96 * 1024 * 1024,
    min_per_flow_bytes: 128 * 1024,
    max_per_flow_bytes: 4 * 1024 * 1024,
};

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
const TCP_REMOTE_BUFFER_POLICY: TcpRemoteBufferPolicy = MOBILE_TCP_REMOTE_BUFFER_POLICY;

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
)))]
const TCP_REMOTE_BUFFER_POLICY: TcpRemoteBufferPolicy = DESKTOP_TCP_REMOTE_BUFFER_POLICY;

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
    let mut udp_flows = HashMap::new();
    let mut delayed_stack_events = VecDeque::new();
    let (stack_tx, mut stack_rx) = mpsc::channel(BRIDGE_CHANNEL_DEPTH);
    let runtime_context = TunRuntimeContext {
        inbound_tag,
        config,
        dns_resolver,
        transport_dialer,
        stack_tx,
        tun: Arc::clone(&tun),
    };

    'runtime: loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            packet = tun.poll_inbound() => {
                match packet {
                    Ok(packet) => {
                        if !process_tun_packet(
                            packet,
                            &tun,
                            &mut sockets,
                            &mut tcp_listeners,
                            &mut udp_flows,
                            &runtime_context,
                            shutdown.clone(),
                            &mut device,
                        )
                        .await
                        {
                            break;
                        }
                    }
                    Err(TunError::QueueClosed) => break,
                    Err(_) => {}
                }
            }
            event = stack_rx.recv(), if delayed_stack_events.is_empty() => {
                if let Some(event) = event {
                    apply_or_delay_stack_event(
                        event,
                        &mut delayed_stack_events,
                        &mut tcp_flows,
                        &mut udp_flows,
                        &mut device,
                        Some(tun.as_ref()),
                    );
                }
            }
            () = sleep(Duration::from_millis(25)) => {}
        }

        for _ in 0..MAX_TUN_INBOUND_DRAIN_PER_TICK {
            match tun.try_poll_inbound().await {
                Ok(Some(packet)) => {
                    if !process_tun_packet(
                        packet,
                        &tun,
                        &mut sockets,
                        &mut tcp_listeners,
                        &mut udp_flows,
                        &runtime_context,
                        shutdown.clone(),
                        &mut device,
                    )
                    .await
                    {
                        break 'runtime;
                    }
                }
                Ok(None) => break,
                Err(TunError::QueueClosed) => break 'runtime,
                Err(_) => {}
            }
        }

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut udp_flows,
            &mut device,
            Some(tun.as_ref()),
        );
        write_remote_data_to_sockets(&mut sockets, &mut tcp_flows);
        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut udp_flows,
            &mut device,
            Some(tun.as_ref()),
        );
        record_tcp_pending_remote_stats(tun.as_ref(), &tcp_flows);
        iface.poll(Instant::now(), &mut device, &mut sockets);
        open_ready_tcp_flows(
            &mut sockets,
            &mut tcp_listeners,
            &mut tcp_flows,
            &runtime_context,
            shutdown.clone(),
        );
        read_socket_data_to_remote(&tun, &mut sockets, &mut tcp_flows);
        cleanup_closed_tcp_flows(&mut sockets, &mut tcp_flows);
        iface.poll(Instant::now(), &mut device, &mut sockets);
        while let Some(packet) = device.pop_outbound() {
            if tun.push_outbound(packet).await.is_err() {
                break;
            }
        }
    }
}

async fn process_tun_packet(
    packet: Bytes,
    tun: &TunEndpoint,
    sockets: &mut SocketSet<'static>,
    tcp_listeners: &mut HashMap<IpEndpoint, SocketHandle>,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
    device: &mut PacketDevice,
) -> bool {
    if let Some(reply) = icmp_echo_reply(&packet) {
        return !matches!(tun.push_outbound(reply).await, Err(TunError::QueueClosed));
    }
    if let Some(packet) = parse_udp_packet(&packet) {
        handle_udp_packet(packet, udp_flows, context, shutdown);
        return true;
    }
    if let Some(endpoint) = tcp_syn_destination(&packet) {
        ensure_tcp_listener(sockets, tcp_listeners, endpoint);
    }
    device.push_inbound(packet);
    true
}

#[derive(Clone)]
struct TunRuntimeContext {
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    stack_tx: mpsc::Sender<StackEvent>,
    tun: Arc<TunEndpoint>,
}

#[derive(Debug)]
struct TcpFlow {
    to_remote: mpsc::Sender<Bytes>,
    pending_remote: VecDeque<Bytes>,
    pending_remote_bytes: usize,
    remote_closed: bool,
}

#[derive(Debug)]
struct UdpFlow {
    to_remote: mpsc::Sender<Bytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    client: EndpointKey,
    target: EndpointKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EndpointKey {
    addr: IpAddr,
    port: u16,
}

impl UdpFlowKey {
    fn new(client: IpEndpoint, target: IpEndpoint) -> Self {
        Self {
            client: EndpointKey::from_endpoint(client),
            target: EndpointKey::from_endpoint(target),
        }
    }
}

impl EndpointKey {
    fn from_endpoint(endpoint: IpEndpoint) -> Self {
        Self {
            addr: match endpoint.addr {
                IpAddress::Ipv4(ip) => IpAddr::V4(ip),
                IpAddress::Ipv6(ip) => IpAddr::V6(ip),
            },
            port: endpoint.port,
        }
    }

    fn into_endpoint(self) -> IpEndpoint {
        IpEndpoint::new(IpAddress::from(self.addr), self.port)
    }
}

#[derive(Debug)]
struct UdpTunPacket {
    client: IpEndpoint,
    target: IpEndpoint,
    payload: Bytes,
}

#[derive(Debug)]
enum StackEvent {
    RemoteData {
        handle: SocketHandle,
        data: Bytes,
    },
    RemoteClosed {
        handle: SocketHandle,
    },
    UdpDatagram {
        client: IpEndpoint,
        source: IpEndpoint,
        payload: Bytes,
    },
    UdpClosed {
        key: UdpFlowKey,
    },
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
                pending_remote_bytes: 0,
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
    target_from_endpoint_with_network(endpoint, RoutingNetwork::Tcp)
}

fn udp_target_from_endpoint(endpoint: IpEndpoint) -> Option<Target> {
    target_from_endpoint_with_network(endpoint, RoutingNetwork::Udp)
}

fn target_from_endpoint_with_network(
    endpoint: IpEndpoint,
    network: RoutingNetwork,
) -> Option<Target> {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(ip) => IpAddr::V4(ip),
        IpAddress::Ipv6(ip) => IpAddr::V6(ip),
    };
    Some(Target::new(
        RoutingTargetAddr::Ip(ip),
        endpoint.port,
        network,
    ))
}

fn drain_stack_events(
    stack_rx: &mut mpsc::Receiver<StackEvent>,
    delayed_stack_events: &mut VecDeque<StackEvent>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    device: &mut PacketDevice,
    tun: Option<&TunEndpoint>,
) {
    while let Some(event) = delayed_stack_events.pop_front() {
        if !apply_or_delay_stack_event(
            event,
            delayed_stack_events,
            tcp_flows,
            udp_flows,
            device,
            tun,
        ) {
            return;
        }
    }

    while let Ok(event) = stack_rx.try_recv() {
        if !apply_or_delay_stack_event(
            event,
            delayed_stack_events,
            tcp_flows,
            udp_flows,
            device,
            tun,
        ) {
            return;
        }
    }
}

fn apply_or_delay_stack_event(
    event: StackEvent,
    delayed_stack_events: &mut VecDeque<StackEvent>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    device: &mut PacketDevice,
    tun: Option<&TunEndpoint>,
) -> bool {
    match try_apply_stack_event(event, tcp_flows, udp_flows, device) {
        Ok(()) => true,
        Err(event) => {
            if let Some(tun) = tun {
                tun.record_tcp_backpressure();
            }
            delayed_stack_events.push_front(event);
            false
        }
    }
}

fn try_apply_stack_event(
    event: StackEvent,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    device: &mut PacketDevice,
) -> Result<(), StackEvent> {
    match event {
        StackEvent::RemoteData { handle, data } => {
            if !tcp_flows.contains_key(&handle) {
                return Ok(());
            }
            let active_flow_count = tcp_remote_active_flow_count(tcp_flows, handle);
            let per_flow_limit = tcp_remote_pending_limit_for_active_flows(
                TCP_REMOTE_BUFFER_POLICY,
                active_flow_count,
            );
            let total_pending = tcp_remote_total_pending_bytes(tcp_flows);
            if total_pending.saturating_add(data.len())
                > TCP_REMOTE_BUFFER_POLICY.global_budget_bytes
            {
                return Err(StackEvent::RemoteData { handle, data });
            }
            if let Some(flow) = tcp_flows.get_mut(&handle) {
                let next_pending_bytes = flow.pending_remote_bytes.saturating_add(data.len());
                if next_pending_bytes > per_flow_limit {
                    return Err(StackEvent::RemoteData { handle, data });
                }
                flow.pending_remote_bytes = next_pending_bytes;
                flow.pending_remote.push_back(data);
            }
        }
        StackEvent::RemoteClosed { handle } => {
            if let Some(flow) = tcp_flows.get_mut(&handle) {
                flow.remote_closed = true;
            }
        }
        StackEvent::UdpDatagram {
            client,
            source,
            payload,
        } => {
            if let Some(packet) = build_udp_packet(source, client, &payload) {
                device.push_outbound(packet);
            }
        }
        StackEvent::UdpClosed { key } => {
            udp_flows.remove(&key);
        }
    }
    Ok(())
}

fn tcp_remote_pending_limit_for_active_flows(
    policy: TcpRemoteBufferPolicy,
    active_flow_count: usize,
) -> usize {
    let active_flow_count = active_flow_count.max(1);
    let fair_share = policy.global_budget_bytes / active_flow_count;
    fair_share.clamp(policy.min_per_flow_bytes, policy.max_per_flow_bytes)
}

fn tcp_remote_active_flow_count(
    flows: &HashMap<SocketHandle, TcpFlow>,
    current_handle: SocketHandle,
) -> usize {
    let active_flow_count = flows
        .iter()
        .filter(|(handle, flow)| **handle == current_handle || flow.pending_remote_bytes > 0)
        .count();
    active_flow_count.max(1)
}

fn tcp_remote_total_pending_bytes(flows: &HashMap<SocketHandle, TcpFlow>) -> usize {
    flows
        .values()
        .map(|flow| flow.pending_remote_bytes)
        .sum::<usize>()
}

fn record_tcp_pending_remote_stats(tun: &TunEndpoint, flows: &HashMap<SocketHandle, TcpFlow>) {
    let mut total_pending_bytes = 0usize;
    let mut pending_flow_count = 0usize;
    let mut max_pending_bytes = 0usize;

    for flow in flows.values() {
        if flow.pending_remote_bytes > 0 {
            pending_flow_count += 1;
            total_pending_bytes = total_pending_bytes.saturating_add(flow.pending_remote_bytes);
            max_pending_bytes = max_pending_bytes.max(flow.pending_remote_bytes);
        }
    }

    tun.record_tcp_pending_remote(total_pending_bytes, pending_flow_count, max_pending_bytes);
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
                flow.pending_remote_bytes = flow.pending_remote_bytes.saturating_sub(front.len());
                flow.pending_remote.pop_front();
            } else {
                *front = front.slice(written..);
                flow.pending_remote_bytes = flow.pending_remote_bytes.saturating_sub(written);
                break;
            }
        }
        if flow.remote_closed && flow.pending_remote.is_empty() && socket.may_send() {
            socket.close();
        }
    }
}

fn read_socket_data_to_remote(
    tun: &TunEndpoint,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
) {
    for (handle, flow) in flows {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);
        while socket.can_recv() {
            let permit = match flow.to_remote.try_reserve() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tun.record_tcp_backpressure();
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    socket.abort();
                    break;
                }
            };
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
            tun.record_tcp_stack_to_remote(data.len());
            permit.send(data);
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
            context.tun.record_tcp_open_error();
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
            context.tun.record_tcp_open_error();
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
                let data_len = data.len();
                if remote_writer.write_all(&data).await.is_err() {
                    context.tun.record_tcp_remote_write_error();
                    break;
                }
                context.tun.record_tcp_remote_written(data_len);
                if remote_writer.flush().await.is_err() {
                    context.tun.record_tcp_remote_write_error();
                    break;
                }
            }
            read = remote_reader.read(&mut read_buffer) => {
                let read = match read {
                    Ok(read) => read,
                    Err(_) => {
                        context.tun.record_tcp_remote_read_error();
                        break;
                    }
                };
                if read == 0 {
                    context.tun.record_tcp_remote_closed();
                    break;
                }
                context.tun.record_tcp_remote_read(read);
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

fn handle_udp_packet(
    packet: UdpTunPacket,
    flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
) {
    let key = UdpFlowKey::new(packet.client, packet.target);

    if let Entry::Vacant(entry) = flows.entry(key) {
        let Some(target) = udp_target_from_endpoint(packet.target) else {
            return;
        };
        let (to_remote, from_stack) = mpsc::channel(BRIDGE_CHANNEL_DEPTH);
        entry.insert(UdpFlow { to_remote });
        tokio::spawn(bridge_udp_flow(
            key,
            target,
            context.clone(),
            from_stack,
            shutdown,
        ));
    }

    if let Some(flow) = flows.get(&key) {
        if flow.to_remote.try_send(packet.payload).is_err() {
            flows.remove(&key);
        }
    }
}

async fn bridge_udp_flow(
    key: UdpFlowKey,
    target: Target,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<Bytes>,
    shutdown: watch::Receiver<bool>,
) {
    let outbound = match select_udp_outbound_for_session(
        &context.config,
        context.inbound_tag.as_deref(),
        &target,
    ) {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
            return;
        }
    };

    match outbound {
        UdpOutbound::Freedom => {
            bridge_udp_freedom_flow(key, context, from_stack, shutdown).await;
        }
        UdpOutbound::Vless(outbound) => {
            bridge_udp_vless_flow(key, target, outbound, context, from_stack, shutdown).await;
        }
    }
}

async fn bridge_udp_freedom_flow(
    key: UdpFlowKey,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
) {
    let bind_addr = match key.target.addr {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let Ok(socket) = UdpSocket::bind(bind_addr).await else {
        let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
        return;
    };
    if protect_udp_socket(&socket, context.transport_dialer.socket_protector()).is_err() {
        let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
        return;
    }
    let target = SocketAddr::new(key.target.addr, key.target.port);
    let client = key.client.into_endpoint();
    let mut read_buffer = vec![0; BRIDGE_READ_BUFFER_SIZE];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = sleep(UDP_IDLE_TIMEOUT) => {
                break;
            }
            payload = from_stack.recv() => {
                let Some(payload) = payload else {
                    break;
                };
                if socket.send_to(&payload, target).await.is_err() {
                    break;
                }
            }
            received = socket.recv_from(&mut read_buffer) => {
                let Ok((len, source)) = received else {
                    break;
                };
                if context
                    .stack_tx
                    .send(StackEvent::UdpDatagram {
                        client,
                        source: IpEndpoint::new(IpAddress::from(source.ip()), source.port()),
                        payload: Bytes::copy_from_slice(&read_buffer[..len]),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
}

async fn bridge_udp_vless_flow(
    key: UdpFlowKey,
    target: Target,
    outbound: Box<VlessTcpOutbound>,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
) {
    let Ok((stream, framing)) = open_vless_udp_stream_with_resolver_and_dialer(
        &outbound,
        &target,
        context.dns_resolver.as_ref(),
        &context.transport_dialer,
    )
    .await
    else {
        let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
        return;
    };

    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    let fallback_source = key.target.into_endpoint();
    let client = key.client.into_endpoint();
    let global_id = udp_flow_global_id(key);
    let mut sent_xudp_new = false;

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = sleep(UDP_IDLE_TIMEOUT) => {
                break;
            }
            payload = from_stack.recv() => {
                let Some(payload) = payload else {
                    break;
                };
                let frame = match framing {
                    VlessUdpFraming::LengthPrefixed => encode_udp_packet(&payload),
                    VlessUdpFraming::Xudp => {
                        if sent_xudp_new {
                            encode_xudp_keep_packet(Some(&target), &payload)
                        } else {
                            sent_xudp_new = true;
                            encode_xudp_new_packet(&target, &payload, global_id)
                        }
                    }
                };
                let Ok(frame) = frame else {
                    break;
                };
                if remote_writer.write_all(&frame).await.is_err() {
                    break;
                }
                if remote_writer.flush().await.is_err() {
                    break;
                }
            }
            packet = read_vless_udp_response(&mut remote_reader, framing, fallback_source) => {
                let Ok((source, payload)) = packet else {
                    break;
                };
                if context
                    .stack_tx
                    .send(StackEvent::UdpDatagram {
                        client,
                        source,
                        payload,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
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

fn parse_udp_packet(packet: &[u8]) -> Option<UdpTunPacket> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_udp_packet(packet),
        6 => parse_ipv6_udp_packet(packet),
        _ => None,
    }
}

fn parse_ipv4_udp_packet(packet: &[u8]) -> Option<UdpTunPacket> {
    if packet.len() < 28 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 || packet[9] != UDP_PROTOCOL {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        return None;
    }

    let udp = &packet[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }

    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if checksum != 0 && ipv4_udp_checksum(source, destination, &udp[..udp_len]) != 0 {
        return None;
    }

    Some(UdpTunPacket {
        client: IpEndpoint::new(
            IpAddress::Ipv4(source),
            u16::from_be_bytes([udp[0], udp[1]]),
        ),
        target: IpEndpoint::new(
            IpAddress::Ipv4(destination),
            u16::from_be_bytes([udp[2], udp[3]]),
        ),
        payload: Bytes::copy_from_slice(&udp[8..udp_len]),
    })
}

fn parse_ipv6_udp_packet(packet: &[u8]) -> Option<UdpTunPacket> {
    if packet.len() < 48 || packet[6] != UDP_PROTOCOL {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len < 8 || packet.len() < 40 + payload_len {
        return None;
    }

    let source = <[u8; 16]>::try_from(&packet[8..24]).ok()?;
    let destination = <[u8; 16]>::try_from(&packet[24..40]).ok()?;
    let udp = &packet[40..40 + payload_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    if ipv6_transport_checksum(source, destination, UDP_PROTOCOL, &udp[..udp_len]) != 0 {
        return None;
    }

    Some(UdpTunPacket {
        client: IpEndpoint::new(
            IpAddress::Ipv6(Ipv6Addr::from(source)),
            u16::from_be_bytes([udp[0], udp[1]]),
        ),
        target: IpEndpoint::new(
            IpAddress::Ipv6(Ipv6Addr::from(destination)),
            u16::from_be_bytes([udp[2], udp[3]]),
        ),
        payload: Bytes::copy_from_slice(&udp[8..udp_len]),
    })
}

fn build_udp_packet(source: IpEndpoint, destination: IpEndpoint, payload: &[u8]) -> Option<Bytes> {
    match (source.addr, destination.addr) {
        (IpAddress::Ipv4(source_addr), IpAddress::Ipv4(destination_addr)) => {
            Some(Bytes::from(build_ipv4_udp_packet(
                source_addr,
                source.port,
                destination_addr,
                destination.port,
                payload,
            )?))
        }
        (IpAddress::Ipv6(source_addr), IpAddress::Ipv6(destination_addr)) => {
            Some(Bytes::from(build_ipv6_udp_packet(
                source_addr,
                source.port,
                destination_addr,
                destination.port,
                payload,
            )?))
        }
        _ => None,
    }
}

async fn read_vless_udp_response<R>(
    reader: &mut R,
    framing: VlessUdpFraming,
    fallback_source: IpEndpoint,
) -> std::io::Result<(IpEndpoint, Bytes)>
where
    R: AsyncRead + Unpin,
{
    match framing {
        VlessUdpFraming::LengthPrefixed => {
            let payload = read_udp_packet(reader).await?;
            Ok((fallback_source, payload))
        }
        VlessUdpFraming::Xudp => {
            let packet = read_xudp_packet(reader).await?;
            let source = packet
                .source
                .as_ref()
                .and_then(target_to_endpoint)
                .unwrap_or(fallback_source);
            Ok((source, packet.payload))
        }
    }
}

fn target_to_endpoint(target: &Target) -> Option<IpEndpoint> {
    let addr = match &target.addr {
        RoutingTargetAddr::Ip(ip) => IpAddress::from(*ip),
        RoutingTargetAddr::Domain(_) => return None,
    };
    Some(IpEndpoint::new(addr, target.port))
}

fn build_ipv4_udp_packet(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    let total_len = 20usize.checked_add(udp_len)?;
    let total_len = u16::try_from(total_len).ok()?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;

    let mut packet = vec![0; usize::from(total_len)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = UDP_PROTOCOL;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum = nonzero_udp_checksum(ipv4_udp_checksum(source, destination, udp));
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    Some(packet)
}

fn build_ipv6_udp_packet(
    source: Ipv6Addr,
    source_port: u16,
    destination: Ipv6Addr,
    destination_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;
    let mut packet = vec![0; 40 + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    packet[6] = UDP_PROTOCOL;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());

    let udp = &mut packet[40..];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum =
        ipv6_transport_checksum(source.octets(), destination.octets(), UDP_PROTOCOL, udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    Some(packet)
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

fn icmp_echo_reply(packet: &[u8]) -> Option<Bytes> {
    match packet.first()? >> 4 {
        4 => ipv4_icmp_echo_reply(packet),
        6 => ipv6_icmp_echo_reply(packet),
        _ => None,
    }
}

fn ipv4_icmp_echo_reply(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 28 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    if packet[9] != ICMPV4_PROTOCOL {
        return None;
    }
    if internet_checksum(&packet[..header_len]) != 0 {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        return None;
    }

    let icmp = &packet[header_len..total_len];
    if icmp[0] != 8 || icmp[1] != 0 || internet_checksum(icmp) != 0 {
        return None;
    }

    let icmp_len = icmp.len();
    let total_len = 20 + icmp_len;
    let mut reply = vec![0; total_len];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    reply[8] = 64;
    reply[9] = ICMPV4_PROTOCOL;
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);

    reply[20..].copy_from_slice(icmp);
    reply[20] = 0;
    reply[22] = 0;
    reply[23] = 0;
    let icmp_checksum = internet_checksum(&reply[20..]);
    reply[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    let ip_checksum = internet_checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    Some(Bytes::from(reply))
}

fn ipv6_icmp_echo_reply(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 48 || packet[6] != ICMPV6_PROTOCOL {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len < 8 || packet.len() < 40 + payload_len {
        return None;
    }

    let source = <[u8; 16]>::try_from(&packet[8..24]).ok()?;
    let destination = <[u8; 16]>::try_from(&packet[24..40]).ok()?;
    let icmp = &packet[40..40 + payload_len];
    if icmp[0] != 128
        || icmp[1] != 0
        || ipv6_transport_checksum(source, destination, ICMPV6_PROTOCOL, icmp) != 0
    {
        return None;
    }

    let total_len = 40 + payload_len;
    let mut reply = vec![0; total_len];
    reply[0] = 0x60;
    reply[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    reply[6] = ICMPV6_PROTOCOL;
    reply[7] = 64;
    reply[8..24].copy_from_slice(&destination);
    reply[24..40].copy_from_slice(&source);

    reply[40..].copy_from_slice(icmp);
    reply[40] = 129;
    reply[42] = 0;
    reply[43] = 0;
    let checksum = ipv6_transport_checksum(destination, source, ICMPV6_PROTOCOL, &reply[40..]);
    reply[42..44].copy_from_slice(&checksum.to_be_bytes());

    Some(Bytes::from(reply))
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&[0, UDP_PROTOCOL]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    internet_checksum(&pseudo)
}

fn nonzero_udp_checksum(checksum: u16) -> u16 {
    if checksum == 0 {
        u16::MAX
    } else {
        checksum
    }
}

fn udp_flow_global_id(key: UdpFlowKey) -> [u8; 8] {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    hash_endpoint(&mut hash, key.client);
    hash_endpoint(&mut hash, key.target);
    hash.to_be_bytes()
}

fn hash_endpoint(hash: &mut u64, endpoint: EndpointKey) {
    match endpoint.addr {
        IpAddr::V4(ip) => {
            for byte in ip.octets() {
                hash_byte(hash, byte);
            }
        }
        IpAddr::V6(ip) => {
            for byte in ip.octets() {
                hash_byte(hash, byte);
            }
        }
    }
    for byte in endpoint.port.to_be_bytes() {
        hash_byte(hash, byte);
    }
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

fn ipv6_transport_checksum(
    source: [u8; 16],
    destination: [u8; 16],
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(payload);
    internet_checksum(&pseudo)
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

    pub(crate) fn push_outbound(&mut self, packet: Bytes) {
        self.outbound.push_back(packet);
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
    fn mobile_remote_buffer_policy_uses_40mib_global_budget() {
        assert_eq!(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.global_budget_bytes,
            40 * 1024 * 1024
        );
        assert_eq!(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.min_per_flow_bytes,
            64 * 1024
        );
        assert_eq!(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.max_per_flow_bytes,
            1024 * 1024
        );
    }

    #[test]
    fn remote_buffer_policy_shares_budget_between_active_flows() {
        assert_eq!(
            tcp_remote_pending_limit_for_active_flows(MOBILE_TCP_REMOTE_BUFFER_POLICY, 1),
            1024 * 1024
        );
        assert_eq!(
            tcp_remote_pending_limit_for_active_flows(MOBILE_TCP_REMOTE_BUFFER_POLICY, 80),
            512 * 1024
        );
        assert_eq!(
            tcp_remote_pending_limit_for_active_flows(MOBILE_TCP_REMOTE_BUFFER_POLICY, 640),
            64 * 1024
        );
    }

    #[test]
    fn remote_tcp_data_is_deferred_when_pending_flow_buffer_is_full() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: TCP_REMOTE_BUFFER_POLICY.max_per_flow_bytes,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                data: Bytes::from_static(&[1, 2, 3, 4]),
            })
            .unwrap();

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert!(flow.pending_remote.is_empty());
        assert_eq!(
            flow.pending_remote_bytes,
            TCP_REMOTE_BUFFER_POLICY.max_per_flow_bytes
        );
        assert_eq!(delayed_stack_events.len(), 1);
    }

    #[test]
    fn deferred_remote_tcp_data_is_applied_after_pending_flow_buffer_has_room() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (_stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::from([StackEvent::RemoteData {
            handle,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        }]);

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert_eq!(flow.pending_remote.len(), 1);
        assert_eq!(flow.pending_remote_bytes, 4);
        assert!(delayed_stack_events.is_empty());
    }

    #[test]
    fn remote_tcp_data_can_exceed_512kib_when_few_flows_are_active() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut pending_remote = VecDeque::new();
        pending_remote.push_back(Bytes::from(vec![0; 512 * 1024]));
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote,
                pending_remote_bytes: 512 * 1024,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                data: Bytes::from_static(&[1, 2, 3, 4]),
            })
            .unwrap();

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert_eq!(flow.pending_remote.len(), 2);
        assert_eq!(flow.pending_remote_bytes, 512 * 1024 + 4);
        assert!(delayed_stack_events.is_empty());
    }

    #[test]
    fn remote_tcp_data_is_deferred_when_global_pending_budget_is_full() {
        let mut sockets = SocketSet::new(Vec::new());
        let current_handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let mut tcp_flows = HashMap::new();
        let mut remaining = TCP_REMOTE_BUFFER_POLICY.global_budget_bytes;
        while remaining > 0 {
            let handle = sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            ));
            let (to_remote, _from_stack) = mpsc::channel(1);
            let pending_remote_bytes = remaining.min(TCP_REMOTE_BUFFER_POLICY.max_per_flow_bytes);
            remaining -= pending_remote_bytes;
            tcp_flows.insert(
                handle,
                TcpFlow {
                    to_remote,
                    pending_remote: VecDeque::new(),
                    pending_remote_bytes,
                    remote_closed: false,
                },
            );
        }
        let (to_remote, _from_stack) = mpsc::channel(1);
        tcp_flows.insert(
            current_handle,
            TcpFlow {
                to_remote,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle: current_handle,
                data: Bytes::from_static(&[1, 2, 3, 4]),
            })
            .unwrap();

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&current_handle).unwrap();
        assert!(flow.pending_remote.is_empty());
        assert_eq!(flow.pending_remote_bytes, 0);
        assert_eq!(delayed_stack_events.len(), 1);
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
