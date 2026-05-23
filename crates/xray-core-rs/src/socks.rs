use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use xray_config::CoreConfig;
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
    select_tcp_outbound_for_session, select_udp_outbound_for_session, TcpOutbound, UdpOutbound,
    VlessTcpOutbound, VlessUdpFraming,
};

const SOCKS_UDP_BUFFER_SIZE: usize = 65_536;
const SOCKS_UDP_FLOW_QUEUE: usize = 64;
const SOCKS_UDP_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct SocksUdpFlowContext {
    client_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    flow_finished: mpsc::UnboundedSender<(SocketAddr, Target)>,
}

pub async fn serve_socks_listener(
    listener: TcpListener,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
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
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    handle_socks_connection(
                        stream,
                        inbound_tag,
                        config,
                        dns_resolver,
                        transport_dialer,
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
    shutdown: watch::Receiver<bool>,
) {
    if negotiate_socks5_no_auth(&mut inbound).await.is_err() {
        return;
    }

    let request = match parse_socks5_request_message(&mut inbound).await {
        Ok(request) => request,
        Err(_) => {
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
) {
    let outbound = match select_tcp_outbound_for_session(&config, inbound_tag.as_deref(), &target) {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = write_socks5_failure(&mut inbound).await;
            return;
        }
    };

    match outbound {
        TcpOutbound::Freedom => {
            let mut outbound_stream = match open_freedom_tcp_stream(
                &target,
                dns_resolver.as_ref(),
                transport_dialer.as_ref(),
            )
            .await
            {
                Ok(stream) => stream,
                Err(_) => {
                    let _ = write_socks5_failure(&mut inbound).await;
                    return;
                }
            };

            if write_socks5_success(&mut inbound).await.is_err() {
                return;
            }

            let _ = copy_bidirectional(&mut inbound, &mut outbound_stream).await;
        }
        TcpOutbound::Vless(outbound) => {
            let mut outbound_stream = match open_vless_tcp_stream_with_resolver_and_dialer(
                &outbound,
                &target,
                dns_resolver.as_ref(),
                transport_dialer.as_ref(),
            )
            .await
            {
                Ok(stream) => stream,
                Err(_) => {
                    let _ = write_socks5_failure(&mut inbound).await;
                    return;
                }
            };

            if write_socks5_success(&mut inbound).await.is_err() {
                return;
            }

            let _ = copy_bidirectional(&mut inbound, &mut outbound_stream).await;
        }
    }
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
    from_client: mpsc::Receiver<Bytes>,
    shutdown: watch::Receiver<bool>,
) {
    let flow_key = (context.client_addr, target.clone());
    let flow_finished = context.flow_finished.clone();
    let outbound = match select_udp_outbound_for_session(
        &context.config,
        context.inbound_tag.as_deref(),
        &target,
    ) {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = flow_finished.send(flow_key);
            return;
        }
    };

    match outbound {
        UdpOutbound::Freedom => {
            bridge_socks_udp_freedom_flow(target, context, from_client, shutdown).await;
        }
        UdpOutbound::Vless(outbound) => {
            bridge_socks_udp_vless_flow(target, outbound, context, from_client, shutdown).await;
        }
    }
    let _ = flow_finished.send(flow_key);
}

async fn bridge_socks_udp_freedom_flow(
    target: Target,
    context: SocksUdpFlowContext,
    mut from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
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
