use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, Id as TaskId, JoinSet};
use xray_config::{CoreConfig, InboundSniffingConfig};
use xray_proxy::inbound::{
    encode_socks5_udp_datagram, negotiate_socks5_no_auth, parse_socks5_request_message,
    parse_socks5_udp_datagram, write_socks5_failure, write_socks5_success,
    write_socks5_success_with_bind, SocksCommand,
};
use xray_proxy::vless::{
    encode_xudp_keep_packet, encode_xudp_new_packet, read_udp_packet, read_xudp_packet,
};
use xray_routing::{Target, TargetAddr};
use xray_transport::{protect_udp_socket, DnsResolver, TransportDialer};

use crate::outbound::{
    open_tcp_stream_with_resolvers_and_dialer, DnsOutbound, TcpSessionOutbound, UdpSessionOutbound,
};
use crate::{
    dns::RuntimeDnsResolvers,
    dns_outbound_runtime::{DnsOutboundRuntime, FakeIpTargetProvenance},
    open_vless_udp_stream_with_resolver_and_dialer,
    policy::{
        accept_error_wants_backoff, copy_bidirectional_with_idle_timeout,
        effective_policy_for_level, AcceptBackoff, EffectivePolicy,
    },
    runtime_log::{monotonic_millis, LogThrottle},
    OutboundRouter, RuntimeLogger, TcpOutbound, UdpOutbound, VlessTcpOutbound, VlessUdpFraming,
};

const SOCKS_UDP_BUFFER_SIZE: usize = 65_536;
const SOCKS_DNS_UDP_PATH_PAYLOAD_CAP: usize = 65_245;
const SOCKS_UDP_FLOW_QUEUE: usize = 32;
const SOCKS_UDP_MAX_FLOWS_PER_ASSOCIATION: usize = 128;
const SOCKS_UDP_MAX_FLOWS_GLOBAL: usize = 1024;
const SOCKS_UDP_MAX_PENDING_OPENS_GLOBAL: usize = 64;
const SOCKS_UDP_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SOCKS_UDP_BUDGET_LOG_INTERVAL: Duration = Duration::from_secs(5);
const SOCKS_VLESS_UDP_FLUSH_BATCH: usize = 16;
const SOCKS_VLESS_UDP_FLUSH_INTERVAL: Duration = Duration::from_millis(2);
const SOCKS_TCP_SNIFF_BUFFER_SIZE: usize = 8 * 1024;
const SOCKS_TCP_SNIFF_TIMEOUT: Duration = Duration::from_millis(250);
static SOCKS_UDP_GLOBAL_FLOWS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static SOCKS_UDP_GLOBAL_PENDING_OPENS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static SOCKS_UDP_BUDGET_EXHAUSTION_LOG: OnceLock<Arc<SocksUdpBudgetExhaustionLog>> =
    OnceLock::new();

type BoxedSocksDnsStreamFuture<'a> = Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>>;

fn serve_boxed_socks_dns_stream<'a>(
    runtime: Arc<DnsOutboundRuntime>,
    inbound: &'a mut TcpStream,
    initial_payload: Bytes,
    outbound: DnsOutbound,
    original_target: Target,
    inbound_idle_timeout: Duration,
) -> BoxedSocksDnsStreamFuture<'a> {
    // Keep the large DNS state machine out of every ordinary SOCKS TCP task.
    // Dropping this boxed future still cancels the DNS flow synchronously.
    Box::pin(async move {
        runtime
            .serve_tcp_stream(
                inbound,
                initial_payload,
                &outbound,
                &original_target,
                inbound_idle_timeout,
            )
            .await
    })
}

/// One throttle per distinct budget-exhaustion outcome, so a burst of one
/// kind cannot silence reports of the others.
struct SocksUdpBudgetExhaustionLog {
    global_flow_evictions: LogThrottle,
    global_flow_drops: LogThrottle,
    pending_open_drops: LogThrottle,
}

impl SocksUdpBudgetExhaustionLog {
    const fn new() -> Self {
        Self {
            global_flow_evictions: LogThrottle::new(SOCKS_UDP_BUDGET_LOG_INTERVAL),
            global_flow_drops: LogThrottle::new(SOCKS_UDP_BUDGET_LOG_INTERVAL),
            pending_open_drops: LogThrottle::new(SOCKS_UDP_BUDGET_LOG_INTERVAL),
        }
    }
}

#[derive(Clone)]
struct SocksUdpFlowContext {
    client_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    inbound_tag: Option<String>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    runtime_logger: RuntimeLogger,
}

#[derive(Clone)]
struct SocksUdpBudgets {
    global_flows: Arc<Semaphore>,
    pending_opens: Arc<Semaphore>,
    exhaustion_log: Arc<SocksUdpBudgetExhaustionLog>,
}

impl Default for SocksUdpBudgets {
    fn default() -> Self {
        Self {
            global_flows: Arc::clone(
                SOCKS_UDP_GLOBAL_FLOWS
                    .get_or_init(|| Arc::new(Semaphore::new(SOCKS_UDP_MAX_FLOWS_GLOBAL))),
            ),
            pending_opens: Arc::clone(
                SOCKS_UDP_GLOBAL_PENDING_OPENS
                    .get_or_init(|| Arc::new(Semaphore::new(SOCKS_UDP_MAX_PENDING_OPENS_GLOBAL))),
            ),
            exhaustion_log: Arc::clone(
                SOCKS_UDP_BUDGET_EXHAUSTION_LOG
                    .get_or_init(|| Arc::new(SocksUdpBudgetExhaustionLog::new())),
            ),
        }
    }
}

struct SocksUdpFlowEntry {
    sender: mpsc::Sender<Bytes>,
    abort_handle: AbortHandle,
    task_id: TaskId,
    last_activity: u64,
    /// Held for the flow's lifetime; reclaimed intact on eviction so the
    /// budget transfers to the replacement flow without a trip through the
    /// semaphore's free pool.
    global_permit: OwnedSemaphorePermit,
}

#[expect(
    clippy::too_many_arguments,
    reason = "listener tasks receive shared runtime dependencies explicitly"
)]
pub async fn serve_socks_listener(
    listener: TcpListener,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    policy: EffectivePolicy,
    runtime_logger: RuntimeLogger,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    let mut accept_backoff = AcceptBackoff::new();
    let udp_budgets = SocksUdpBudgets::default();

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
                    Err(error) => {
                        if !accept_error_wants_backoff(error.kind()) {
                            continue;
                        }
                        if !accept_backoff.is_backing_off() {
                            // accept() errors carry only OS errno text (no peer
                            // data), and the errno is the operator's signal to
                            // raise `ulimit -n` — so this log skips <redacted>.
                            runtime_logger.error(|| {
                                format!("Debug socksAccept failed, backing off error={error}")
                            });
                        }
                        let delay = accept_backoff.next_delay();
                        tokio::select! {
                            changed = shutdown.changed() => {
                                if changed.is_err() || *shutdown.borrow() {
                                    break;
                                }
                            }
                            _ = tokio::time::sleep(delay) => {}
                        }
                        continue;
                    }
                };
                accept_backoff.reset();
                let inbound_tag = inbound_tag.clone();
                let config = Arc::clone(&config);
                let outbound_router = Arc::clone(&outbound_router);
                let dns_resolvers = dns_resolvers.clone();
                let transport_dialer = Arc::clone(&transport_dialer);
                let sniffing = sniffing.clone();
                let runtime_logger = runtime_logger.clone();
                let connection_shutdown = shutdown.clone();
                let udp_budgets = udp_budgets.clone();
                connections.spawn(async move {
                    handle_socks_connection(
                        stream,
                        inbound_tag,
                        config,
                        outbound_router,
                        dns_resolvers,
                        transport_dialer,
                        sniffing,
                        policy,
                        runtime_logger,
                        connection_shutdown,
                        udp_budgets,
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

#[expect(
    clippy::too_many_arguments,
    reason = "connection tasks receive shared runtime dependencies explicitly"
)]
async fn handle_socks_connection(
    mut inbound: TcpStream,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    policy: EffectivePolicy,
    runtime_logger: RuntimeLogger,
    shutdown: watch::Receiver<bool>,
    udp_budgets: SocksUdpBudgets,
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
                outbound_router,
                dns_resolvers,
                transport_dialer,
                sniffing,
                policy,
                runtime_logger,
            )
            .await;
        }
        SocksCommand::UdpAssociate => {
            handle_socks_udp_associate(
                inbound,
                inbound_tag,
                outbound_router,
                dns_resolvers,
                transport_dialer,
                sniffing,
                runtime_logger,
                shutdown,
                udp_budgets,
            )
            .await;
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "connection tasks receive shared runtime dependencies explicitly"
)]
async fn handle_socks_connect(
    mut inbound: TcpStream,
    target: Target,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    policy: EffectivePolicy,
    runtime_logger: RuntimeLogger,
) {
    let source = runtime_logger.is_enabled().then(|| {
        inbound
            .peer_addr()
            .map_or_else(|_| "unknown".to_owned(), |addr| addr.to_string())
    });
    let sniffing_config = sniffing.as_ref();
    let restored_target = dns_resolvers.outbound.restore_client_target(&target);
    let provenance = restored_target.provenance;
    let sniff_tcp = should_sniff_socks_tcp(sniffing_config, provenance);
    let effective_target = restored_target.target;
    let mut route_target = effective_target.clone();
    let mut dial_target = effective_target;
    let mut initial_payload = Bytes::new();
    let mut sniffed_protocol = None;

    if sniff_tcp {
        if write_socks5_success(&mut inbound).await.is_err() {
            return;
        }
        if let Some(config) = sniffing_config {
            let (payload, sniffed) =
                read_socks_tcp_sniff_payload(&mut inbound, config, &dial_target).await;
            initial_payload = payload;
            if let Some(sniffed) = sniffed {
                let sniffed = apply_fake_ip_sniffed_dial_precedence(provenance, sniffed);
                sniffed_protocol = Some(sniffed.protocol);
                route_target = sniffed.route_target;
                dial_target = sniffed.dial_target;
            }
        }
    }

    let selected = match outbound_router
        .select_tcp_session_outbound_with_resolver(
            inbound_tag.as_deref(),
            &route_target,
            dns_resolvers.destination.as_ref(),
        )
        .await
    {
        Ok(outbound) => outbound,
        Err(error) => {
            if let Some(source) = source.as_deref() {
                crate::debug_log::log_access_rejected(
                    &runtime_logger,
                    source,
                    &route_target,
                    error,
                );
            }
            if !sniff_tcp {
                let _ = write_socks5_failure(&mut inbound).await;
            }
            return;
        }
    };

    if runtime_logger.is_enabled() {
        let selected_outbound = match &selected {
            TcpSessionOutbound::Transport(outbound) => {
                crate::debug_log::tcp_outbound_label(outbound)
            }
            TcpSessionOutbound::Dns(_) => "dns",
        };
        crate::debug_log::log_route_decision(
            &runtime_logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: inbound_tag.as_deref(),
                network: target.network,
                original_target: &target,
                sniffed_protocol,
                route_target: &route_target,
                dial_target: &dial_target,
                selected_outbound,
            },
        );
    }

    let outbound = match selected {
        TcpSessionOutbound::Transport(outbound) => outbound,
        TcpSessionOutbound::Dns(outbound) => {
            if let Some(source) = source.as_deref() {
                crate::debug_log::log_access_accepted(&runtime_logger, source, &dial_target, "dns");
            }
            if !sniff_tcp && write_socks5_success(&mut inbound).await.is_err() {
                return;
            }
            let _ = serve_boxed_socks_dns_stream(
                dns_resolvers.outbound,
                &mut inbound,
                initial_payload,
                outbound,
                dial_target,
                policy.conn_idle,
            )
            .await;
            return;
        }
    };

    let (open_timeout, tunnel_idle, relay_buffer_size) = match outbound.primary() {
        TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => (
            policy.handshake,
            policy.conn_idle,
            policy.relay_buffer_size(),
        ),
        TcpOutbound::Vless(vless) => {
            let outbound_policy = effective_policy_for_level(&config, Some(vless.user().level));
            (
                outbound_policy.handshake,
                policy.conn_idle.min(outbound_policy.conn_idle),
                outbound_policy.relay_buffer_size(),
            )
        }
        TcpOutbound::Chained { .. } => unreachable!("primary outbound is never a chain wrapper"),
    };
    let outbound_label = crate::debug_log::tcp_outbound_label(&outbound);
    let mut outbound_stream = match tokio::time::timeout(
        open_timeout,
        open_tcp_stream_with_resolvers_and_dialer(
            &outbound,
            &dial_target,
            dns_resolvers.destination.as_ref(),
            dns_resolvers.bootstrap.as_ref(),
            transport_dialer.as_ref(),
        ),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            if let Some(source) = source.as_deref() {
                crate::debug_log::log_access_rejected(&runtime_logger, source, &dial_target, error);
            }
            if !sniff_tcp {
                let _ = write_socks5_failure(&mut inbound).await;
            }
            return;
        }
        Err(_) => {
            if let Some(source) = source.as_deref() {
                crate::debug_log::log_access_rejected(
                    &runtime_logger,
                    source,
                    &dial_target,
                    "outbound tcp open timed out",
                );
            }
            if !sniff_tcp {
                let _ = write_socks5_failure(&mut inbound).await;
            }
            return;
        }
    };
    if let Some(source) = source.as_deref() {
        crate::debug_log::log_access_accepted(
            &runtime_logger,
            source,
            &dial_target,
            outbound_label,
        );
    }

    if !sniff_tcp && write_socks5_success(&mut inbound).await.is_err() {
        return;
    }
    if !initial_payload.is_empty() && outbound_stream.write_all(&initial_payload).await.is_err() {
        return;
    }

    let _ = copy_bidirectional_with_idle_timeout(
        &mut inbound,
        &mut outbound_stream,
        tunnel_idle,
        relay_buffer_size,
    )
    .await;
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

#[expect(
    clippy::too_many_arguments,
    reason = "connection tasks receive shared runtime dependencies explicitly"
)]
async fn handle_socks_udp_associate(
    mut control: TcpStream,
    inbound_tag: Option<String>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    runtime_logger: RuntimeLogger,
    mut shutdown: watch::Receiver<bool>,
    budgets: SocksUdpBudgets,
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

    let mut flows = HashMap::<(SocketAddr, Target), SocksUdpFlowEntry>::new();
    let mut flow_tasks = JoinSet::new();
    let mut activity_sequence = 0u64;
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
            joined = flow_tasks.join_next_with_id(), if !flow_tasks.is_empty() => {
                match joined {
                    Some(Ok((task_id, flow_key))) => {
                        remove_socks_udp_flow_by_task_id(&mut flows, task_id, Some(&flow_key));
                    }
                    Some(Err(error)) => {
                        remove_socks_udp_flow_by_task_id(&mut flows, error.id(), None);
                    }
                    None => {}
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let Ok((len, client_addr)) = received else {
                    break;
                };
                let Ok(datagram) = parse_socks5_udp_datagram(&buffer[..len]) else {
                    continue;
                };
                let flow_key = (client_addr, datagram.target.clone());
                activity_sequence = activity_sequence.wrapping_add(1);

                let payload = match flows.get_mut(&flow_key) {
                    Some(entry) => {
                        entry.last_activity = activity_sequence;
                        match entry.sender.try_send(datagram.payload) {
                            Ok(()) => continue,
                            Err(mpsc::error::TrySendError::Full(_)) => continue,
                            Err(mpsc::error::TrySendError::Closed(payload)) => {
                                if let Some(entry) = flows.remove(&flow_key) {
                                    entry.abort_handle.abort();
                                }
                                payload
                            }
                        }
                    }
                    None => datagram.payload,
                };

                let Some(SocksUdpFlowPermits {
                    global: global_permit,
                    pending_open: pending_open_permit,
                }) = admit_socks_udp_flow(&mut flows, &budgets, &runtime_logger)
                else {
                    continue;
                };

                let (sender, receiver) = mpsc::channel(SOCKS_UDP_FLOW_QUEUE);
                if sender.try_send(payload).is_err() {
                    continue;
                }
                let context = SocksUdpFlowContext {
                    client_socket: Arc::clone(&socket),
                    client_addr,
                    inbound_tag: inbound_tag.clone(),
                    outbound_router: Arc::clone(&outbound_router),
                    dns_resolvers: dns_resolvers.clone(),
                    transport_dialer: Arc::clone(&transport_dialer),
                    sniffing: sniffing.clone(),
                    runtime_logger: runtime_logger.clone(),
                };
                let target = datagram.target;
                let completion_key = flow_key.clone();
                let flow_shutdown = shutdown.clone();
                let abort_handle = flow_tasks.spawn(async move {
                    bridge_socks_udp_flow(
                        target,
                        context,
                        receiver,
                        flow_shutdown,
                        pending_open_permit,
                    )
                    .await;
                    completion_key
                });
                let task_id = abort_handle.id();
                flows.insert(
                    flow_key,
                    SocksUdpFlowEntry {
                        sender,
                        abort_handle,
                        task_id,
                        last_activity: activity_sequence,
                        global_permit,
                    },
                );
            }
        }
    }

    for (_, entry) in flows.drain() {
        entry.abort_handle.abort();
    }
    flow_tasks.abort_all();
    while flow_tasks.join_next().await.is_some() {}
}

struct SocksUdpFlowPermits {
    global: OwnedSemaphorePermit,
    pending_open: OwnedSemaphorePermit,
}

/// Admission control for one new SOCKS UDP flow: returns the budget permits
/// the flow must hold, or `None` when the datagram has to be dropped.
///
/// On global-budget exhaustion the association reclaims its own
/// least-recently-active flow's permit. That is the sing-box-style
/// evict-oldest limited to what our permit ownership allows synchronously:
/// evicting another association's flow releases its permit only after the
/// owning task observes the abort, too late to admit this datagram. An
/// association with nothing to evict drops the datagram (throttled log)
/// until some flow elsewhere idles out.
fn admit_socks_udp_flow(
    flows: &mut HashMap<(SocketAddr, Target), SocksUdpFlowEntry>,
    budgets: &SocksUdpBudgets,
    runtime_logger: &RuntimeLogger,
) -> Option<SocksUdpFlowPermits> {
    let pending_open = match Arc::clone(&budgets.pending_opens).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            if runtime_logger.is_enabled() {
                if let Some(drops) = budgets
                    .exhaustion_log
                    .pending_open_drops
                    .register(monotonic_millis())
                {
                    runtime_logger.error(|| {
                        format!(
                            "socks udp pending-open budget exhausted \
                             ({SOCKS_UDP_MAX_PENDING_OPENS_GLOBAL}): dropped a new flow's \
                             datagram ({drops} drops since last report)"
                        )
                    });
                }
            }
            return None;
        }
    };

    let reclaimed = if flows.len() >= SOCKS_UDP_MAX_FLOWS_PER_ASSOCIATION {
        evict_oldest_socks_udp_flow(flows)
    } else {
        None
    };
    let global = match reclaimed {
        Some(permit) => permit,
        None => match Arc::clone(&budgets.global_flows).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => match evict_oldest_socks_udp_flow(flows) {
                Some(permit) => {
                    if runtime_logger.is_enabled() {
                        if let Some(evictions) = budgets
                            .exhaustion_log
                            .global_flow_evictions
                            .register(monotonic_millis())
                        {
                            runtime_logger.debug(|| {
                                format!(
                                    "socks udp global flow budget exhausted \
                                     ({SOCKS_UDP_MAX_FLOWS_GLOBAL}): evicted the association's \
                                     oldest flow to admit a new one ({evictions} evictions \
                                     since last report)"
                                )
                            });
                        }
                    }
                    permit
                }
                None => {
                    if runtime_logger.is_enabled() {
                        if let Some(drops) = budgets
                            .exhaustion_log
                            .global_flow_drops
                            .register(monotonic_millis())
                        {
                            runtime_logger.error(|| {
                                format!(
                                    "socks udp global flow budget exhausted \
                                     ({SOCKS_UDP_MAX_FLOWS_GLOBAL}): dropped a new flow's \
                                     datagram, association has nothing to evict ({drops} \
                                     drops since last report)"
                                )
                            });
                        }
                    }
                    return None;
                }
            },
        },
    };

    Some(SocksUdpFlowPermits {
        global,
        pending_open,
    })
}

fn evict_oldest_socks_udp_flow(
    flows: &mut HashMap<(SocketAddr, Target), SocksUdpFlowEntry>,
) -> Option<OwnedSemaphorePermit> {
    let oldest_key = flows
        .iter()
        .min_by_key(|(_, entry)| entry.last_activity)
        .map(|(key, _)| key.clone())?;
    let entry = flows.remove(&oldest_key)?;
    entry.abort_handle.abort();
    Some(entry.global_permit)
}

fn remove_socks_udp_flow_by_task_id(
    flows: &mut HashMap<(SocketAddr, Target), SocksUdpFlowEntry>,
    task_id: TaskId,
    completed_key: Option<&(SocketAddr, Target)>,
) {
    if let Some(key) = completed_key {
        if flows.get(key).is_some_and(|entry| entry.task_id == task_id) {
            flows.remove(key);
            return;
        }
    }

    let matching_key = flows
        .iter()
        .find(|(_, entry)| entry.task_id == task_id)
        .map(|(key, _)| key.clone());
    if let Some(key) = matching_key {
        flows.remove(&key);
    }
}

async fn bridge_socks_udp_flow(
    target: Target,
    context: SocksUdpFlowContext,
    mut from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    pending_open_permit: OwnedSemaphorePermit,
) {
    let Some(first_payload) = read_first_socks_udp_payload(&mut from_client, &mut shutdown).await
    else {
        return;
    };
    let restored_target = context
        .dns_resolvers
        .outbound
        .restore_client_target(&target);
    let provenance = restored_target.provenance;
    let effective_target = restored_target.target;
    let client_visible_target =
        (provenance == FakeIpTargetProvenance::Mapped).then(|| target.clone());
    let sniffed_target =
        sniff_socks_udp_target(&context, &effective_target, provenance, &first_payload);
    let sniffed_protocol = sniffed_target.sniffed_protocol;
    let route_target = sniffed_target.route_target;
    let dial_target = sniffed_target.dial_target;
    let selected = match context
        .outbound_router
        .select_udp_session_outbound_with_resolver(
            context.inbound_tag.as_deref(),
            &route_target,
            context.dns_resolvers.destination.as_ref(),
        )
        .await
    {
        Ok(outbound) => outbound,
        Err(error) => {
            if context.runtime_logger.is_enabled() {
                let source = context.client_addr.to_string();
                crate::debug_log::log_access_rejected(
                    &context.runtime_logger,
                    &source,
                    &route_target,
                    error,
                );
            }
            return;
        }
    };

    if context.runtime_logger.is_enabled() {
        let selected_outbound = match &selected {
            UdpSessionOutbound::Transport(outbound) => {
                crate::debug_log::udp_outbound_label(outbound)
            }
            UdpSessionOutbound::Dns(_) => "dns",
        };
        crate::debug_log::log_route_decision(
            &context.runtime_logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: context.inbound_tag.as_deref(),
                network: target.network,
                original_target: &target,
                sniffed_protocol,
                route_target: &route_target,
                dial_target: &dial_target,
                selected_outbound,
            },
        );
    }

    let outbound = match selected {
        UdpSessionOutbound::Transport(outbound) => outbound,
        UdpSessionOutbound::Dns(outbound) => {
            if context.runtime_logger.is_enabled() {
                let source = context.client_addr.to_string();
                crate::debug_log::log_access_accepted(
                    &context.runtime_logger,
                    &source,
                    &dial_target,
                    "dns",
                );
            }
            drop(pending_open_permit);
            bridge_socks_udp_dns_flow(
                target,
                dial_target,
                outbound,
                context,
                from_client,
                shutdown,
                first_payload,
            )
            .await;
            return;
        }
    };

    match outbound {
        UdpOutbound::Freedom => {
            if context.runtime_logger.is_enabled() {
                let source = context.client_addr.to_string();
                crate::debug_log::log_access_accepted(
                    &context.runtime_logger,
                    &source,
                    &dial_target,
                    "freedom",
                );
            }
            bridge_socks_udp_freedom_flow(
                dial_target,
                client_visible_target,
                context,
                from_client,
                shutdown,
                first_payload,
                pending_open_permit,
            )
            .await;
        }
        UdpOutbound::Vless(outbound) => {
            if context.runtime_logger.is_enabled() {
                let source = context.client_addr.to_string();
                crate::debug_log::log_access_accepted(
                    &context.runtime_logger,
                    &source,
                    &dial_target,
                    "vless",
                );
            }
            bridge_socks_udp_vless_flow(
                dial_target,
                client_visible_target,
                outbound,
                context,
                from_client,
                shutdown,
                first_payload,
                pending_open_permit,
            )
            .await;
        }
    }
}

async fn bridge_socks_udp_dns_flow(
    client_target: Target,
    routed_target: Target,
    outbound: crate::DnsOutbound,
    context: SocksUdpFlowContext,
    mut from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    first_payload: Bytes,
) {
    let mut pending_payload = Some(first_payload);
    loop {
        let payload = match pending_payload.take() {
            Some(payload) => payload,
            None => {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                        continue;
                    }
                    _ = tokio::time::sleep(SOCKS_UDP_FLOW_IDLE_TIMEOUT) => return,
                    payload = from_client.recv() => {
                        let Some(payload) = payload else {
                            return;
                        };
                        payload
                    }
                }
            }
        };

        let outcome = context
            .dns_resolvers
            .outbound
            .execute_message(
                &outbound,
                &routed_target,
                payload,
                crate::dns_outbound_runtime::DnsClientTransport::Udp {
                    path_payload_cap: SOCKS_DNS_UDP_PATH_PAYLOAD_CAP,
                },
            )
            .await;
        let crate::dns_outbound_runtime::DnsMessageOutcome::Reply(response) = outcome else {
            continue;
        };
        let Ok(response) = encode_socks5_udp_datagram(&client_target, &response) else {
            continue;
        };
        let sent = tokio::select! {
            changed = shutdown.changed() => {
                changed.is_ok() && !*shutdown.borrow()
            }
            sent = context.client_socket.send_to(&response, context.client_addr) => sent.is_ok(),
        };
        if !sent {
            return;
        }
    }
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
    sniffed_protocol: Option<xray_config::SniffingDestination>,
}

impl SocksUdpSniffedTarget {
    fn original(target: &Target) -> Self {
        Self {
            route_target: target.clone(),
            dial_target: target.clone(),
            sniffed_protocol: None,
        }
    }

    fn from_sniffed(
        target: &Target,
        provenance: FakeIpTargetProvenance,
        sniffed: Option<crate::sniffing::SniffedTarget>,
    ) -> Self {
        if !fake_ip_allows_content_sniffing(provenance) {
            return Self::original(target);
        }
        let Some(sniffed) = sniffed else {
            return Self::original(target);
        };
        let sniffed = apply_fake_ip_sniffed_dial_precedence(provenance, sniffed);
        let sniffed_protocol = Some(sniffed.protocol);
        Self {
            route_target: sniffed.route_target,
            dial_target: sniffed.dial_target,
            sniffed_protocol,
        }
    }
}

fn fake_ip_allows_content_sniffing(provenance: FakeIpTargetProvenance) -> bool {
    provenance != FakeIpTargetProvenance::Mapped
}

fn should_sniff_socks_tcp(
    config: Option<&InboundSniffingConfig>,
    provenance: FakeIpTargetProvenance,
) -> bool {
    fake_ip_allows_content_sniffing(provenance) && crate::sniffing::should_sniff_tcp(config)
}

fn apply_fake_ip_sniffed_dial_precedence(
    provenance: FakeIpTargetProvenance,
    mut sniffed: crate::sniffing::SniffedTarget,
) -> crate::sniffing::SniffedTarget {
    if provenance == FakeIpTargetProvenance::InPoolUnmapped {
        sniffed.dial_target = sniffed.route_target.clone();
    }
    sniffed
}

fn sniff_socks_udp_target(
    context: &SocksUdpFlowContext,
    target: &Target,
    provenance: FakeIpTargetProvenance,
    first_payload: &[u8],
) -> SocksUdpSniffedTarget {
    if !fake_ip_allows_content_sniffing(provenance) {
        return SocksUdpSniffedTarget::from_sniffed(target, provenance, None);
    }
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
    SocksUdpSniffedTarget::from_sniffed(target, provenance, Some(sniffed))
}

async fn bridge_socks_udp_freedom_flow(
    target: Target,
    client_visible_target: Option<Target>,
    context: SocksUdpFlowContext,
    mut from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    first_payload: Bytes,
    pending_open_permit: OwnedSemaphorePermit,
) {
    let Ok(target_addr) =
        resolve_udp_socket_addr(&target, context.dns_resolvers.destination.as_ref()).await
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
    drop(pending_open_permit);
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
                let source = client_visible_target.clone().unwrap_or_else(|| {
                    Target::new(
                        TargetAddr::Ip(source.ip()),
                        source.port(),
                        xray_routing::Network::Udp,
                    )
                });
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

#[expect(
    clippy::too_many_arguments,
    reason = "SOCKS UDP flow owns client/dial targets, outbound state, shutdown, and admission"
)]
async fn bridge_socks_udp_vless_flow(
    target: Target,
    client_visible_target: Option<Target>,
    outbound: Box<VlessTcpOutbound>,
    context: SocksUdpFlowContext,
    mut from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    first_payload: Bytes,
    pending_open_permit: OwnedSemaphorePermit,
) {
    let Ok((stream, framing)) = open_vless_udp_stream_with_resolver_and_dialer(
        &outbound,
        &target,
        context.dns_resolvers.bootstrap.as_ref(),
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
        true,
    )
    .await
    .is_err()
    {
        return;
    }
    drop(pending_open_permit);

    let flush_deadline = tokio::time::sleep(SOCKS_VLESS_UDP_FLUSH_INTERVAL);
    tokio::pin!(flush_deadline);
    let mut pending_frames = 0usize;
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
            () = &mut flush_deadline, if pending_frames > 0 => {
                if remote_writer.flush().await.is_err() {
                    break;
                }
                pending_frames = 0;
            }
            payload = from_client.recv() => {
                let Some(payload) = payload else {
                    break;
                };
                let flush_now = pending_frames + 1 >= SOCKS_VLESS_UDP_FLUSH_BATCH;
                if write_socks_vless_udp_payload(
                    &mut remote_writer,
                    framing,
                    &target,
                    global_id,
                    &mut sent_xudp_new,
                    payload,
                    flush_now,
                )
                .await
                .is_err()
                {
                    break;
                }
                if flush_now {
                    pending_frames = 0;
                } else {
                    if pending_frames == 0 {
                        flush_deadline
                            .as_mut()
                            .reset(tokio::time::Instant::now() + SOCKS_VLESS_UDP_FLUSH_INTERVAL);
                    }
                    pending_frames += 1;
                }
            }
            packet = read_socks_vless_udp_response(&mut remote_reader, framing, fallback_source.clone()) => {
                let Ok((mut source, payload)) = packet else {
                    break;
                };
                if let Some(client_visible_target) = client_visible_target.as_ref() {
                    source = client_visible_target.clone();
                }
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
    if pending_frames > 0 {
        let _ = remote_writer.flush().await;
    }
}

async fn write_socks_vless_udp_payload<W>(
    writer: &mut W,
    framing: VlessUdpFraming,
    target: &Target,
    global_id: [u8; 8],
    sent_xudp_new: &mut bool,
    payload: Bytes,
    flush: bool,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match framing {
        VlessUdpFraming::LengthPrefixed => {
            let len = u16::try_from(payload.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "vless udp payload exceeds u16 framing",
                )
            })?;
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(&payload).await?;
        }
        VlessUdpFraming::Xudp => {
            let frame = if *sent_xudp_new {
                encode_xudp_keep_packet(Some(target), &payload)
            } else {
                *sent_xudp_new = true;
                encode_xudp_new_packet(target, &payload, global_id)
            }
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            writer.write_all(&frame).await?;
        }
    }
    if flush {
        writer.flush().await?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use tokio::io::AsyncWrite;
    use tokio::sync::{mpsc, Semaphore};
    use tokio::task::JoinSet;
    use xray_config::{InboundSniffingConfig, SniffingDestination};
    use xray_routing::{Network, Target, TargetAddr};

    use super::{
        admit_socks_udp_flow, apply_fake_ip_sniffed_dial_precedence, evict_oldest_socks_udp_flow,
        should_sniff_socks_tcp, write_socks_vless_udp_payload, BoxedSocksDnsStreamFuture,
        FakeIpTargetProvenance, SocksUdpBudgetExhaustionLog, SocksUdpBudgets, SocksUdpFlowEntry,
        SocksUdpSniffedTarget, VlessUdpFraming, SOCKS_UDP_FLOW_QUEUE,
        SOCKS_UDP_MAX_FLOWS_PER_ASSOCIATION,
    };
    use crate::{RuntimeLogConfig, RuntimeLogger};

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn http_sniffing_config(route_only: bool) -> InboundSniffingConfig {
        InboundSniffingConfig {
            enabled: true,
            dest_override: vec![SniffingDestination::Http],
            metadata_only: false,
            route_only,
        }
    }

    fn sniffed_target(original: &Target, domain: &str) -> crate::sniffing::SniffedTarget {
        let route_target = Target::new(
            TargetAddr::Domain(domain.to_owned()),
            original.port,
            original.network,
        );
        crate::sniffing::SniffedTarget {
            route_target: route_target.clone(),
            dial_target: original.clone(),
            protocol: SniffingDestination::Http,
        }
    }

    #[test]
    fn mapped_fake_ip_suppresses_socks_tcp_content_sniffing() {
        assert!(!should_sniff_socks_tcp(
            Some(&http_sniffing_config(false)),
            FakeIpTargetProvenance::Mapped,
        ));
        assert!(should_sniff_socks_tcp(
            Some(&http_sniffing_config(false)),
            FakeIpTargetProvenance::Outside,
        ));
    }

    #[test]
    fn socks_dns_stream_dispatch_future_stays_heap_erased() {
        assert!(
            size_of::<BoxedSocksDnsStreamFuture<'static>>() <= 2 * size_of::<usize>(),
            "boxed DNS dispatch should occupy no more than a trait-object pointer"
        );
    }

    #[test]
    fn mapped_fake_ip_keeps_socks_udp_target_a_over_sniffed_target_b() {
        let mapped = Target::new(
            TargetAddr::Domain("mapped-a.example".to_owned()),
            443,
            Network::Udp,
        );
        let result = SocksUdpSniffedTarget::from_sniffed(
            &mapped,
            FakeIpTargetProvenance::Mapped,
            Some(sniffed_target(&mapped, "sniffed-b.example")),
        );

        assert_eq!(result.route_target, mapped);
        assert_eq!(result.dial_target, mapped);
        assert_eq!(result.sniffed_protocol, None);
    }

    #[test]
    fn in_pool_unmapped_route_only_uses_sniffed_domain_for_socks_dialing() {
        let raw = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(198, 18, 1, 7))),
            443,
            Network::Tcp,
        );
        let tcp = apply_fake_ip_sniffed_dial_precedence(
            FakeIpTargetProvenance::InPoolUnmapped,
            sniffed_target(&raw, "sniffed.example"),
        );
        assert_eq!(tcp.dial_target, tcp.route_target);

        let raw_udp = Target::new(raw.addr.clone(), raw.port, Network::Udp);
        let udp = SocksUdpSniffedTarget::from_sniffed(
            &raw_udp,
            FakeIpTargetProvenance::InPoolUnmapped,
            Some(sniffed_target(&raw_udp, "sniffed.example")),
        );
        assert_eq!(udp.dial_target, udp.route_target);
    }

    #[test]
    fn socks_udp_global_flow_budget_rejects_excess_flow() {
        let budgets = SocksUdpBudgets {
            global_flows: Arc::new(Semaphore::new(1)),
            pending_opens: Arc::new(Semaphore::new(1)),
            exhaustion_log: Arc::new(SocksUdpBudgetExhaustionLog::new()),
        };
        let _permit = Arc::clone(&budgets.global_flows)
            .try_acquire_owned()
            .expect("first flow should fit");

        assert!(Arc::clone(&budgets.global_flows)
            .try_acquire_owned()
            .is_err());
    }

    #[test]
    fn socks_udp_pending_open_budget_rejects_excess_open() {
        let budgets = SocksUdpBudgets {
            global_flows: Arc::new(Semaphore::new(1)),
            pending_opens: Arc::new(Semaphore::new(1)),
            exhaustion_log: Arc::new(SocksUdpBudgetExhaustionLog::new()),
        };
        let _permit = Arc::clone(&budgets.pending_opens)
            .try_acquire_owned()
            .expect("first pending open should fit");

        assert!(Arc::clone(&budgets.pending_opens)
            .try_acquire_owned()
            .is_err());
    }

    #[test]
    fn socks_udp_flow_queue_drops_instead_of_waiting_when_full() {
        let (sender, _receiver) = mpsc::channel(1);
        sender
            .try_send(Bytes::from_static(b"first"))
            .expect("first datagram should fit");

        assert!(matches!(
            sender.try_send(Bytes::from_static(b"second")),
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }

    #[tokio::test]
    async fn vless_udp_writer_can_batch_frames_without_per_frame_flush() {
        let target = Target::new(
            TargetAddr::Ip("192.0.2.1".parse().expect("test IP should parse")),
            53,
            Network::Udp,
        );
        let mut writer = RecordingWriter::default();
        let mut sent_xudp_new = false;

        write_socks_vless_udp_payload(
            &mut writer,
            VlessUdpFraming::LengthPrefixed,
            &target,
            [0; 8],
            &mut sent_xudp_new,
            Bytes::from_static(b"one"),
            false,
        )
        .await
        .expect("first frame should write");
        write_socks_vless_udp_payload(
            &mut writer,
            VlessUdpFraming::LengthPrefixed,
            &target,
            [0; 8],
            &mut sent_xudp_new,
            Bytes::from_static(b"two"),
            true,
        )
        .await
        .expect("second frame should write and flush");

        assert_eq!(writer.bytes, b"\0\x03one\0\x03two");
        assert_eq!(writer.flushes, 1);
    }

    fn admission_test_target() -> Target {
        Target::new(
            TargetAddr::Ip("192.0.2.1".parse().expect("test IP should parse")),
            53,
            Network::Udp,
        )
    }

    fn admission_test_key(port: u16) -> (SocketAddr, Target) {
        (
            SocketAddr::from(([127, 0, 0, 1], port)),
            admission_test_target(),
        )
    }

    fn insert_admission_test_flow(
        flows: &mut HashMap<(SocketAddr, Target), SocksUdpFlowEntry>,
        tasks: &mut JoinSet<(SocketAddr, Target)>,
        global_flows: &Arc<Semaphore>,
        port: u16,
        last_activity: u64,
    ) {
        let global_permit = Arc::clone(global_flows)
            .try_acquire_owned()
            .expect("test flow should fit the global budget");
        let (sender, _receiver) = mpsc::channel::<Bytes>(SOCKS_UDP_FLOW_QUEUE);
        let abort_handle = tasks.spawn(std::future::pending::<(SocketAddr, Target)>());
        let task_id = abort_handle.id();
        flows.insert(
            admission_test_key(port),
            SocksUdpFlowEntry {
                sender,
                abort_handle,
                task_id,
                last_activity,
                global_permit,
            },
        );
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    #[tokio::test]
    async fn socks_udp_admission_at_association_cap_evicts_to_admit() {
        let budgets = SocksUdpBudgets {
            global_flows: Arc::new(Semaphore::new(SOCKS_UDP_MAX_FLOWS_PER_ASSOCIATION)),
            pending_opens: Arc::new(Semaphore::new(1)),
            exhaustion_log: Arc::new(SocksUdpBudgetExhaustionLog::new()),
        };
        let mut tasks = JoinSet::new();
        let mut flows = HashMap::new();
        for index in 0..SOCKS_UDP_MAX_FLOWS_PER_ASSOCIATION {
            insert_admission_test_flow(
                &mut flows,
                &mut tasks,
                &budgets.global_flows,
                2_000 + u16::try_from(index).expect("cap fits in u16"),
                index as u64,
            );
        }
        assert_eq!(budgets.global_flows.available_permits(), 0);

        let permits = admit_socks_udp_flow(&mut flows, &budgets, &RuntimeLogger::disabled())
            .expect("association at its cap should admit by evicting its oldest flow");

        assert_eq!(flows.len(), SOCKS_UDP_MAX_FLOWS_PER_ASSOCIATION - 1);
        assert!(!flows.contains_key(&admission_test_key(2_000)));
        assert_eq!(budgets.global_flows.available_permits(), 0);
        drop(permits);
        assert_eq!(budgets.global_flows.available_permits(), 1);
    }

    #[tokio::test]
    async fn socks_udp_admission_evicts_association_oldest_when_global_budget_exhausted() {
        let budgets = SocksUdpBudgets {
            global_flows: Arc::new(Semaphore::new(2)),
            pending_opens: Arc::new(Semaphore::new(1)),
            exhaustion_log: Arc::new(SocksUdpBudgetExhaustionLog::new()),
        };
        let mut tasks = JoinSet::new();
        let mut flows = HashMap::new();
        insert_admission_test_flow(&mut flows, &mut tasks, &budgets.global_flows, 2_001, 1);
        insert_admission_test_flow(&mut flows, &mut tasks, &budgets.global_flows, 2_002, 2);
        assert_eq!(budgets.global_flows.available_permits(), 0);

        let permits = admit_socks_udp_flow(&mut flows, &budgets, &RuntimeLogger::disabled())
            .expect(
                "global exhaustion should be absorbed by evicting the association's oldest flow",
            );

        assert!(!flows.contains_key(&admission_test_key(2_001)));
        assert!(flows.contains_key(&admission_test_key(2_002)));
        assert_eq!(budgets.global_flows.available_permits(), 0);
        drop(permits);
    }

    #[test]
    fn socks_udp_admission_logs_drop_when_global_budget_exhausted_with_nothing_to_evict() {
        let dir = unique_temp_dir("socks-udp-global-drop");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");
        let budgets = SocksUdpBudgets {
            global_flows: Arc::new(Semaphore::new(1)),
            pending_opens: Arc::new(Semaphore::new(1)),
            exhaustion_log: Arc::new(SocksUdpBudgetExhaustionLog::new()),
        };
        let _held_by_other_association = Arc::clone(&budgets.global_flows)
            .try_acquire_owned()
            .expect("first permit should fit");
        let mut flows = HashMap::new();

        let admission = admit_socks_udp_flow(&mut flows, &budgets, &logger);

        assert!(admission.is_none());
        drop(logger);
        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");
        assert!(error_log.contains("socks udp global flow budget exhausted"));
        assert!(error_log.contains("nothing to evict"));
    }

    #[tokio::test]
    async fn socks_udp_admission_logs_drop_when_pending_open_budget_exhausted() {
        let dir = unique_temp_dir("socks-udp-pending-drop");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");
        let budgets = SocksUdpBudgets {
            global_flows: Arc::new(Semaphore::new(2)),
            pending_opens: Arc::new(Semaphore::new(1)),
            exhaustion_log: Arc::new(SocksUdpBudgetExhaustionLog::new()),
        };
        let _pending_held_elsewhere = Arc::clone(&budgets.pending_opens)
            .try_acquire_owned()
            .expect("first pending open should fit");
        let mut tasks = JoinSet::new();
        let mut flows = HashMap::new();
        insert_admission_test_flow(&mut flows, &mut tasks, &budgets.global_flows, 2_001, 1);

        let admission = admit_socks_udp_flow(&mut flows, &budgets, &logger);

        assert!(admission.is_none());
        assert_eq!(flows.len(), 1, "pending exhaustion must not evict flows");
        assert_eq!(budgets.global_flows.available_permits(), 1);
        drop(logger);
        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");
        assert!(error_log.contains("socks udp pending-open budget exhausted"));
    }

    #[tokio::test]
    async fn socks_udp_eviction_returns_reclaimed_global_permit() {
        let client_addr = SocketAddr::from(([127, 0, 0, 1], 1234));
        let target = Target::new(
            TargetAddr::Ip("192.0.2.1".parse().expect("test IP should parse")),
            53,
            Network::Udp,
        );
        let global_flows = Arc::new(Semaphore::new(1));
        let global_permit = Arc::clone(&global_flows)
            .try_acquire_owned()
            .expect("flow permit should fit");
        let (sender, _receiver) = mpsc::channel::<Bytes>(SOCKS_UDP_FLOW_QUEUE);
        let mut tasks = JoinSet::new();
        let abort_handle = tasks.spawn(std::future::pending::<(SocketAddr, Target)>());
        let task_id = abort_handle.id();
        let mut flows = HashMap::from([(
            (client_addr, target),
            SocksUdpFlowEntry {
                sender,
                abort_handle,
                task_id,
                last_activity: 1,
                global_permit,
            },
        )]);

        let reclaimed = evict_oldest_socks_udp_flow(&mut flows)
            .expect("eviction should hand back the evicted flow's permit");

        assert_eq!(global_flows.available_permits(), 0);
        drop(reclaimed);
        assert_eq!(global_flows.available_permits(), 1);
    }

    #[tokio::test]
    async fn socks_udp_eviction_aborts_managed_flow_task() {
        let client_addr = SocketAddr::from(([127, 0, 0, 1], 1234));
        let target = Target::new(
            TargetAddr::Ip("192.0.2.1".parse().expect("test IP should parse")),
            53,
            Network::Udp,
        );
        let key = (client_addr, target);
        let budgets = SocksUdpBudgets {
            global_flows: Arc::new(Semaphore::new(1)),
            pending_opens: Arc::new(Semaphore::new(1)),
            exhaustion_log: Arc::new(SocksUdpBudgetExhaustionLog::new()),
        };
        let global_permit = Arc::clone(&budgets.global_flows)
            .try_acquire_owned()
            .expect("flow permit should fit");
        let (sender, _receiver) = mpsc::channel::<Bytes>(SOCKS_UDP_FLOW_QUEUE);
        let mut tasks = JoinSet::new();
        let abort_handle = tasks.spawn(std::future::pending::<(SocketAddr, Target)>());
        let task_id = abort_handle.id();
        let mut flows = HashMap::from([(
            key,
            SocksUdpFlowEntry {
                sender,
                abort_handle,
                task_id,
                last_activity: 1,
                global_permit,
            },
        )]);

        assert!(evict_oldest_socks_udp_flow(&mut flows).is_some());
        let result = tasks
            .join_next()
            .await
            .expect("aborted task should complete");

        assert!(result.expect_err("task should be cancelled").is_cancelled());
    }
}
