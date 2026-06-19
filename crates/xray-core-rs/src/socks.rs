use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use xray_config::{CoreConfig, InboundSniffingConfig};
use xray_proxy::inbound::{
    encode_socks5_udp_datagram, negotiate_socks5_no_auth, parse_socks5_request_message,
    parse_socks5_udp_datagram, write_socks5_failure, write_socks5_success,
    write_socks5_success_with_bind, SocksCommand,
};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, encode_xudp_new_packet, read_udp_packet,
    read_xudp_packet,
};
use xray_routing::{Target, TargetAddr};
use xray_transport::{connect_tcp_stream, protect_udp_socket, DnsResolver, TransportDialer};

use crate::{
    open_vless_tcp_stream_with_resolver_and_dialer, open_vless_udp_stream_with_resolver_and_dialer,
    policy::{copy_bidirectional_with_idle_timeout, effective_policy_for_level, EffectivePolicy},
    select_tcp_outbound_for_session_with_resolver, select_udp_outbound_for_session_with_resolver,
    TcpOutbound, UdpOutbound, VlessTcpOutbound, VlessUdpFraming,
};

const SOCKS_UDP_BUFFER_SIZE: usize = 65_536;
const SOCKS_UDP_FLOW_QUEUE: usize = 256;
const SOCKS_UDP_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SOCKS_TCP_SNIFF_BUFFER_SIZE: usize = 8 * 1024;
const SOCKS_TCP_SNIFF_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone)]
struct SocksUdpFlowContext {
    client_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    flow_finished: mpsc::UnboundedSender<(SocketAddr, Target)>,
}

pub async fn serve_socks_listener(
    listener: TcpListener,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    policy: EffectivePolicy,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();

    loop {
        if *shutdown.borrow() {
            break;
        }

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => continue,
                };
                let inbound_tag = inbound_tag.clone();
                let config = Arc::clone(&config);
                let dns_resolver = Arc::clone(&dns_resolver);
                let transport_dialer = Arc::clone(&transport_dialer);
                let sniffing = sniffing.clone();
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    handle_socks_connection(
                        stream,
                        inbound_tag,
                        config,
                        dns_resolver,
                        transport_dialer,
                        sniffing,
                        policy,
                        connection_shutdown,
                    ).await;
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                let _ = joined;
            }
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn handle_socks_connection(
    mut inbound: TcpStream,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    policy: EffectivePolicy,
    shutdown: watch::Receiver<bool>,
) {
    if tokio::time::timeout(policy.handshake, negotiate_socks5_no_auth(&mut inbound))
        .await
        .ok()
        .and_then(Result::ok)
        .is_none()
    {
        return;
    }

    let request =
        match tokio::time::timeout(policy.handshake, parse_socks5_request_message(&mut inbound))
            .await
        {
            Ok(Ok(request)) => request,
            _ => {
                let _ = write_socks5_failure(&mut inbound).await;
                return;
            }
        };

    match request.command {
        SocksCommand::Connect => {
            handle_socks_connect(
                inbound,
                request.target,
                inbound_tag,
                config,
                dns_resolver,
                transport_dialer,
                sniffing,
                policy,
            )
            .await;
        }
        SocksCommand::UdpAssociate => {
            handle_socks_udp_associate(
                inbound,
                inbound_tag,
                config,
                dns_resolver,
                transport_dialer,
                sniffing,
                shutdown,
            )
            .await;
        }
    }
}

async fn handle_socks_connect(
    mut inbound: TcpStream,
    target: Target,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    policy: EffectivePolicy,
) {
    let sniffing_config = sniffing.as_ref();
    let sniff_tcp = crate::sniffing::should_sniff_tcp(sniffing_config);
    let mut route_target = target.clone();
    let mut dial_target = target.clone();
    let mut initial_payload = Bytes::new();
    #[cfg(debug_assertions)]
    let mut sniffed_protocol = None;

    if sniff_tcp {
        if write_socks5_success(&mut inbound).await.is_err() {
            return;
        }
        if let Some(config) = sniffing_config {
            let (payload, sniffed) =
                read_socks_tcp_sniff_payload(&mut inbound, config, &target).await;
            initial_payload = payload;
            if let Some(sniffed) = sniffed {
                #[cfg(debug_assertions)]
                {
                    sniffed_protocol = Some(sniffed.protocol);
                }
                route_target = sniffed.route_target;
                dial_target = sniffed.dial_target;
            }
        }
    }

    let outbound = match select_tcp_outbound_for_session_with_resolver(
        &config,
        inbound_tag.as_deref(),
        &route_target,
        dns_resolver.as_ref(),
    )
    .await
    {
        Ok(outbound) => outbound,
        Err(_) => {
            if !sniff_tcp {
                let _ = write_socks5_failure(&mut inbound).await;
            }
            return;
        }
    };

    #[cfg(debug_assertions)]
    crate::debug_log::log_route_decision(crate::debug_log::RouteDecisionLog {
        inbound_tag: inbound_tag.as_deref(),
        network: target.network,
        original_target: &target,
        sniffed_protocol,
        route_target: &route_target,
        dial_target: &dial_target,
        selected_outbound: crate::debug_log::tcp_outbound_label(&outbound),
    });

    match outbound {
        TcpOutbound::Freedom => {
            let mut outbound_stream = match tokio::time::timeout(
                policy.handshake,
                open_freedom_tcp_stream(
                    &dial_target,
                    dns_resolver.as_ref(),
                    transport_dialer.as_ref(),
                ),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                _ => {
                    if !sniff_tcp {
                        let _ = write_socks5_failure(&mut inbound).await;
                    }
                    return;
                }
            };

            if !sniff_tcp && write_socks5_success(&mut inbound).await.is_err() {
                return;
            }
            if !initial_payload.is_empty()
                && outbound_stream.write_all(&initial_payload).await.is_err()
            {
                return;
            }

            let _ = copy_bidirectional_with_idle_timeout(
                &mut inbound,
                &mut outbound_stream,
                policy.conn_idle,
            )
            .await;
        }
        TcpOutbound::Vless(outbound) => {
            let outbound_policy = effective_policy_for_level(&config, Some(outbound.user().level));
            let tunnel_idle = policy.conn_idle.min(outbound_policy.conn_idle);
            let mut outbound_stream = match tokio::time::timeout(
                outbound_policy.handshake,
                open_vless_tcp_stream_with_resolver_and_dialer(
                    &outbound,
                    &dial_target,
                    dns_resolver.as_ref(),
                    transport_dialer.as_ref(),
                ),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                _ => {
                    if !sniff_tcp {
                        let _ = write_socks5_failure(&mut inbound).await;
                    }
                    return;
                }
            };

            if !sniff_tcp && write_socks5_success(&mut inbound).await.is_err() {
                return;
            }
            if !initial_payload.is_empty()
                && outbound_stream.write_all(&initial_payload).await.is_err()
            {
                return;
            }

            let _ = copy_bidirectional_with_idle_timeout(
                &mut inbound,
                &mut outbound_stream,
                tunnel_idle,
            )
            .await;
        }
    }
}

async fn read_socks_tcp_sniff_payload(
    inbound: &mut TcpStream,
    config: &InboundSniffingConfig,
    target: &Target,
) -> (Bytes, Option<crate::sniffing::SniffedTarget>) {
    let deadline = tokio::time::Instant::now() + SOCKS_TCP_SNIFF_TIMEOUT;
    let mut buffer = Vec::with_capacity(SOCKS_TCP_SNIFF_BUFFER_SIZE);

    while buffer.len() < SOCKS_TCP_SNIFF_BUFFER_SIZE {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }

        let mut chunk = vec![0; SOCKS_TCP_SNIFF_BUFFER_SIZE - buffer.len()];
        let read = tokio::time::timeout(deadline - now, inbound.read(&mut chunk)).await;
        let len = match read {
            Ok(Ok(len)) if len > 0 => len,
            _ => break,
        };
        buffer.extend_from_slice(&chunk[..len]);

        if let Some(sniffed) = crate::sniffing::sniff_tcp_initial_payload(config, target, &buffer) {
            return (Bytes::copy_from_slice(&buffer), Some(sniffed));
        }
    }

    let sniffed = crate::sniffing::sniff_tcp_initial_payload(config, target, &buffer);
    (Bytes::copy_from_slice(&buffer), sniffed)
}

async fn open_freedom_tcp_stream(
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<TcpStream, ()> {
    let addr = match &target.addr {
        TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
        TargetAddr::Domain(domain) => dns_resolver
            .resolve(domain, target.port)
            .await
            .map_err(|_| ())?,
    };

    connect_tcp_stream(addr, transport_dialer.socket_protector())
        .await
        .map_err(|_| ())
}

async fn handle_socks_udp_associate(
    mut control: TcpStream,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    mut shutdown: watch::Receiver<bool>,
) {
    let bind_addr = match control.local_addr() {
        Ok(SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => Arc::new(socket),
        Err(_) => {
            let _ = write_socks5_failure(&mut control).await;
            return;
        }
    };
    let bind = match socket.local_addr() {
        Ok(bind) => bind,
        Err(_) => {
            let _ = write_socks5_failure(&mut control).await;
            return;
        }
    };
    if write_socks5_success_with_bind(&mut control, bind)
        .await
        .is_err()
    {
        return;
    }

    let mut flows = HashMap::<(SocketAddr, Target), mpsc::Sender<Bytes>>::new();
    let (flow_finished_sender, mut flow_finished_receiver) =
        mpsc::unbounded_channel::<(SocketAddr, Target)>();
    let mut buffer = vec![0; SOCKS_UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            readable = control.readable() => {
                if readable.is_err() {
                    break;
                }
                let mut byte = [0; 1];
                match control.try_read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
            finished = flow_finished_receiver.recv() => {
                let Some(flow_key) = finished else {
                    break;
                };
                flows.remove(&flow_key);
            }
            received = socket.recv_from(&mut buffer) => {
                let Ok((len, client_addr)) = received else {
                    break;
                };
                let Ok(datagram) = parse_socks5_udp_datagram(&buffer[..len]) else {
                    continue;
                };
                let flow_key = (client_addr, datagram.target.clone());
                let sender = match flows.get(&flow_key) {
                    Some(sender) => sender.clone(),
                    None => {
                        let (sender, receiver) = mpsc::channel(SOCKS_UDP_FLOW_QUEUE);
                        flows.insert(flow_key.clone(), sender.clone());
                        let context = SocksUdpFlowContext {
                            client_socket: Arc::clone(&socket),
                            client_addr,
                            inbound_tag: inbound_tag.clone(),
                            config: Arc::clone(&config),
                            dns_resolver: Arc::clone(&dns_resolver),
                            transport_dialer: Arc::clone(&transport_dialer),
                            sniffing: sniffing.clone(),
                            flow_finished: flow_finished_sender.clone(),
                        };
                        tokio::spawn(bridge_socks_udp_flow(
                            datagram.target.clone(),
                            context,
                            receiver,
                            shutdown.clone(),
                        ));
                        sender
                    }
                };
                if sender.send(datagram.payload).await.is_err() {
                    flows.remove(&flow_key);
                }
            }
        }
    }
}

async fn bridge_socks_udp_flow(
    target: Target,
    context: SocksUdpFlowContext,
    mut from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
) {
    let flow_key = (context.client_addr, target.clone());
    let flow_finished = context.flow_finished.clone();
    let Some(first_payload) = read_first_socks_udp_payload(&mut from_client, &mut shutdown).await
    else {
        let _ = flow_finished.send(flow_key);
        return;
    };
    let sniffed_target = sniff_socks_udp_target(&context, &target, &first_payload);
    #[cfg(debug_assertions)]
    let sniffed_protocol = sniffed_target.sniffed_protocol;
    let route_target = sniffed_target.route_target;
    let dial_target = sniffed_target.dial_target;
    let outbound = match select_udp_outbound_for_session_with_resolver(
        &context.config,
        context.inbound_tag.as_deref(),
        &route_target,
        context.dns_resolver.as_ref(),
    )
    .await
    {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = flow_finished.send(flow_key);
            return;
        }
    };

    #[cfg(debug_assertions)]
    crate::debug_log::log_route_decision(crate::debug_log::RouteDecisionLog {
        inbound_tag: context.inbound_tag.as_deref(),
        network: target.network,
        original_target: &target,
        sniffed_protocol,
        route_target: &route_target,
        dial_target: &dial_target,
        selected_outbound: crate::debug_log::udp_outbound_label(&outbound),
    });

    match outbound {
        UdpOutbound::Freedom => {
            bridge_socks_udp_freedom_flow(
                dial_target,
                context,
                from_client,
                shutdown,
                first_payload,
            )
            .await;
        }
        UdpOutbound::Vless(outbound) => {
            bridge_socks_udp_vless_flow(
                dial_target,
                outbound,
                context,
                from_client,
                shutdown,
                first_payload,
            )
            .await;
        }
    }
    let _ = flow_finished.send(flow_key);
}

async fn read_first_socks_udp_payload(
    from_client: &mut mpsc::Receiver<Bytes>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<Bytes> {
    tokio::select! {
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                None
            } else {
                from_client.recv().await
            }
        }
        payload = from_client.recv() => payload,
    }
}

struct SocksUdpSniffedTarget {
    route_target: Target,
    dial_target: Target,
    #[cfg(debug_assertions)]
    sniffed_protocol: Option<xray_config::SniffingDestination>,
}

impl SocksUdpSniffedTarget {
    fn original(target: &Target) -> Self {
        Self {
            route_target: target.clone(),
            dial_target: target.clone(),
            #[cfg(debug_assertions)]
            sniffed_protocol: None,
        }
    }

    fn sniffed(sniffed: crate::sniffing::SniffedTarget) -> Self {
        #[cfg(debug_assertions)]
        let sniffed_protocol = Some(sniffed.protocol);
        Self {
            route_target: sniffed.route_target,
            dial_target: sniffed.dial_target,
            #[cfg(debug_assertions)]
            sniffed_protocol,
        }
    }
}

fn sniff_socks_udp_target(
    context: &SocksUdpFlowContext,
    target: &Target,
    first_payload: &[u8],
) -> SocksUdpSniffedTarget {
    let Some(config) = context.sniffing.as_ref() else {
        return SocksUdpSniffedTarget::original(target);
    };
    if !crate::sniffing::should_sniff_udp(Some(config)) {
        return SocksUdpSniffedTarget::original(target);
    }
    let Some(sniffed) = crate::sniffing::sniff_udp_initial_payload(config, target, first_payload)
    else {
        return SocksUdpSniffedTarget::original(target);
    };
    SocksUdpSniffedTarget::sniffed(sniffed)
}

async fn bridge_socks_udp_freedom_flow(
    target: Target,
    context: SocksUdpFlowContext,
    mut from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    first_payload: Bytes,
) {
    let Ok(target_addr) = resolve_udp_socket_addr(&target, context.dns_resolver.as_ref()).await
    else {
        return;
    };
    let bind_addr = match target_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let Ok(remote_socket) = UdpSocket::bind(bind_addr).await else {
        return;
    };
    if protect_udp_socket(&remote_socket, context.transport_dialer.socket_protector()).is_err() {
        return;
    }
    if remote_socket
        .send_to(&first_payload, target_addr)
        .await
        .is_err()
    {
        return;
    }
    let mut buffer = vec![0; SOCKS_UDP_BUFFER_SIZE];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(SOCKS_UDP_FLOW_IDLE_TIMEOUT) => {
                break;
            }
            payload = from_client.recv() => {
                let Some(payload) = payload else {
                    break;
                };
                if remote_socket.send_to(&payload, target_addr).await.is_err() {
                    break;
                }
            }
            received = remote_socket.recv_from(&mut buffer) => {
                let Ok((len, source)) = received else {
                    break;
                };
                let source = Target::new(TargetAddr::Ip(source.ip()), source.port(), xray_routing::Network::Udp);
                let Ok(response) = encode_socks5_udp_datagram(&source, &buffer[..len]) else {
                    break;
                };
                if context
                    .client_socket
                    .send_to(&response, context.client_addr)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn bridge_socks_udp_vless_flow(
    target: Target,
    outbound: Box<VlessTcpOutbound>,
    context: SocksUdpFlowContext,
    mut from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    first_payload: Bytes,
) {
    let Ok((stream, framing)) = open_vless_udp_stream_with_resolver_and_dialer(
        &outbound,
        &target,
        context.dns_resolver.as_ref(),
        context.transport_dialer.as_ref(),
    )
    .await
    else {
        return;
    };

    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    let fallback_source = target.clone();
    let mut sent_xudp_new = false;
    let global_id = socks_udp_flow_global_id(context.client_addr, &target);
    if write_socks_vless_udp_payload(
        &mut remote_writer,
        framing,
        &target,
        global_id,
        &mut sent_xudp_new,
        first_payload,
    )
    .await
    .is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(SOCKS_UDP_FLOW_IDLE_TIMEOUT) => {
                break;
            }
            payload = from_client.recv() => {
                let Some(payload) = payload else {
                    break;
                };
                if write_socks_vless_udp_payload(
                    &mut remote_writer,
                    framing,
                    &target,
                    global_id,
                    &mut sent_xudp_new,
                    payload,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
            packet = read_socks_vless_udp_response(&mut remote_reader, framing, fallback_source.clone()) => {
                let Ok((source, payload)) = packet else {
                    break;
                };
                let Ok(response) = encode_socks5_udp_datagram(&source, &payload) else {
                    break;
                };
                if context
                    .client_socket
                    .send_to(&response, context.client_addr)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn write_socks_vless_udp_payload<W>(
    writer: &mut W,
    framing: VlessUdpFraming,
    target: &Target,
    global_id: [u8; 8],
    sent_xudp_new: &mut bool,
    payload: Bytes,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = match framing {
        VlessUdpFraming::LengthPrefixed => encode_udp_packet(&payload),
        VlessUdpFraming::Xudp => {
            if *sent_xudp_new {
                encode_xudp_keep_packet(Some(target), &payload)
            } else {
                *sent_xudp_new = true;
                encode_xudp_new_packet(target, &payload, global_id)
            }
        }
    }
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    writer.write_all(&frame).await?;
    writer.flush().await
}

async fn read_socks_vless_udp_response<R>(
    reader: &mut R,
    framing: VlessUdpFraming,
    fallback_source: Target,
) -> std::io::Result<(Target, Bytes)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    match framing {
        VlessUdpFraming::LengthPrefixed => {
            let payload = read_udp_packet(reader).await?;
            Ok((fallback_source, payload))
        }
        VlessUdpFraming::Xudp => {
            let packet = read_xudp_packet(reader).await?;
            Ok((packet.source.unwrap_or(fallback_source), packet.payload))
        }
    }
}

fn socks_udp_flow_global_id(client_addr: SocketAddr, target: &Target) -> [u8; 8] {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in client_addr
        .to_string()
        .bytes()
        .chain(format!("{target:?}").bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash.to_be_bytes()
}

async fn resolve_udp_socket_addr(
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<SocketAddr, ()> {
    match &target.addr {
        TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
        TargetAddr::Domain(domain) => dns_resolver
            .resolve(domain, target.port)
            .await
            .map_err(|_| ()),
    }
}
