use std::collections::HashSet;

use tokio::time::{timeout, Instant as TokioInstant};

use super::*;

const DNS_RCODE_FORMERR: u16 = 1;
const MAX_DNS_PROXY_UPSTREAMS: usize = 8;
const MAX_DNS_XUDP_METADATA_SIZE: usize = 512;
const MAX_DNS_RESPONSE_VALIDATION_PREFIX_SIZE: usize = 512;
const MAX_DNS_PROXY_UDP_RESPONSE_SIZE: usize = 4096;
const XUDP_CMD_NEW: u8 = 1;
const XUDP_CMD_KEEP: u8 = 2;
const XUDP_CMD_DISCARD: u8 = 4;
const XUDP_OPT_DATA: u8 = 1;
const DNS_PROXY_FREEDOM_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(750);
const DNS_PROXY_VLESS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_PROXY_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_TCP_MESSAGE_SIZE: usize = 8 * 1024;
pub(super) const DNS_TCP_PROXY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const DNS_TCP_PROXY_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) enum TunDnsMode {
    Disabled,
    FakeIp(Arc<Mutex<FakeIpMapper>>),
    RawProxy(Arc<DnsProxyPlan>),
}

impl TunDnsMode {
    pub(super) fn from_config(
        config: &CoreConfig,
        fake_ip_mapper: Option<Arc<Mutex<FakeIpMapper>>>,
    ) -> Self {
        if let Some(mapper) = fake_ip_mapper {
            return Self::FakeIp(mapper);
        }
        DnsProxyPlan::from_config(config)
            .map(|plan| Self::RawProxy(Arc::new(plan)))
            .unwrap_or(Self::Disabled)
    }

    pub(super) fn fake_ip_mapper(&self) -> Option<&Arc<Mutex<FakeIpMapper>>> {
        match self {
            Self::FakeIp(mapper) => Some(mapper),
            Self::Disabled | Self::RawProxy(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum DnsProxyUpstream {
    Ip {
        addr: SocketAddr,
        inbound_tag: String,
    },
    Domain {
        domain: String,
        port: u16,
        inbound_tag: String,
    },
}

impl DnsProxyUpstream {
    pub(super) fn target(&self, network: RoutingNetwork) -> Target {
        match self {
            Self::Ip { addr, .. } => {
                Target::new(RoutingTargetAddr::Ip(addr.ip()), addr.port(), network)
            }
            Self::Domain { domain, port, .. } => {
                Target::new(RoutingTargetAddr::Domain(domain.clone()), *port, network)
            }
        }
    }

    pub(super) fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip { addr, .. } => Some(*addr),
            Self::Domain { .. } => None,
        }
    }

    pub(super) fn inbound_tag(&self) -> &str {
        match self {
            Self::Ip { inbound_tag, .. } | Self::Domain { inbound_tag, .. } => inbound_tag,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DnsProxyPlan {
    upstreams: Arc<[DnsProxyUpstream]>,
}

impl DnsProxyPlan {
    fn from_config(config: &CoreConfig) -> Option<Self> {
        Self::from_servers(&config.dns.servers, &config.dns.tag)
    }

    fn from_servers(servers: &[DnsServerConfig], global_tag: &str) -> Option<Self> {
        let mut seen = HashSet::new();
        let upstreams = servers
            .iter()
            .filter_map(|server| {
                let inbound_tag = server.effective_tag(global_tag).to_owned();
                match server.endpoint() {
                    xray_config::DnsServerEndpoint::Ip(addr)
                        if addr.port() != 0 && !is_tun_dns_socket(addr) =>
                    {
                        let upstream = DnsProxyUpstream::Ip { addr, inbound_tag };
                        seen.insert(upstream.clone()).then_some(upstream)
                    }
                    xray_config::DnsServerEndpoint::Domain { domain, port } if port != 0 => {
                        let domain = crate::dns::normalize_dns_name(&domain)?;
                        let upstream = DnsProxyUpstream::Domain {
                            domain,
                            port,
                            inbound_tag,
                        };
                        seen.insert(upstream.clone()).then_some(upstream)
                    }
                    xray_config::DnsServerEndpoint::Ip(_)
                    | xray_config::DnsServerEndpoint::Domain { .. } => None,
                }
            })
            .take(MAX_DNS_PROXY_UPSTREAMS)
            .collect::<Vec<_>>();
        (!upstreams.is_empty()).then(|| Self {
            upstreams: upstreams.into(),
        })
    }

    pub(super) fn upstreams(&self) -> &[DnsProxyUpstream] {
        &self.upstreams
    }
}

pub(super) enum DnsUdpAction {
    Pass,
    Reply(Bytes),
    Proxy(Arc<DnsProxyPlan>),
}

pub(super) enum DnsTcpAction {
    Pass,
    FakeIp(Arc<Mutex<FakeIpMapper>>),
    Proxy(Arc<DnsProxyPlan>),
    Reject,
}

#[derive(Debug)]
enum DnsUpstreamResponse {
    Payload(Bytes),
    Oversized { observed_len: usize, prefix: Bytes },
}

impl DnsUpstreamResponse {
    fn observed_len(&self) -> usize {
        match self {
            Self::Payload(payload) => payload.len(),
            Self::Oversized { observed_len, .. } => *observed_len,
        }
    }

    fn matches_query(&self, query: &[u8]) -> bool {
        match self {
            Self::Payload(payload) => dns_response_matches_query(query, payload),
            Self::Oversized { prefix, .. } => dns_response_matches_query(query, prefix),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsUdpFailurePhase {
    Open,
    Write,
    Read,
}

fn record_dns_udp_failure(context: &TunRuntimeContext, phase: DnsUdpFailurePhase) {
    match phase {
        DnsUdpFailurePhase::Open => context.tun.record_udp_open_error(),
        DnsUdpFailurePhase::Write => context.tun.record_udp_remote_write_error(),
        DnsUdpFailurePhase::Read => context.tun.record_udp_remote_read_error(),
    }
}

pub(super) fn tcp_action(mode: &TunDnsMode, endpoint: IpEndpoint) -> DnsTcpAction {
    if endpoint.port != DNS_PORT {
        return DnsTcpAction::Pass;
    }
    match mode {
        TunDnsMode::FakeIp(mapper) => DnsTcpAction::FakeIp(Arc::clone(mapper)),
        TunDnsMode::RawProxy(plan) if is_dns_anchor_endpoint(endpoint) => {
            DnsTcpAction::Proxy(Arc::clone(plan))
        }
        TunDnsMode::Disabled if is_dns_anchor_endpoint(endpoint) => DnsTcpAction::Reject,
        TunDnsMode::Disabled | TunDnsMode::RawProxy(_) => DnsTcpAction::Pass,
    }
}

pub(super) fn udp_action(mode: &TunDnsMode, packet: &UdpTunPacket) -> DnsUdpAction {
    if packet.target.port != DNS_PORT {
        return DnsUdpAction::Pass;
    }
    let is_anchor = is_dns_anchor_endpoint(packet.target);
    match mode {
        TunDnsMode::FakeIp(mapper) => {
            let response = mapper
                .lock()
                .ok()
                .and_then(|mut mapper| mapper.fake_dns_response(&packet.payload, is_anchor));
            if let Some(response) = response {
                return build_udp_packet(packet.target, packet.client, &response)
                    .map(DnsUdpAction::Reply)
                    .unwrap_or(DnsUdpAction::Pass);
            }
            if is_anchor {
                return dns_error_reply_packet(packet, DNS_RCODE_SERVFAIL)
                    .map(DnsUdpAction::Reply)
                    .unwrap_or(DnsUdpAction::Pass);
            }
            DnsUdpAction::Pass
        }
        TunDnsMode::RawProxy(plan) if is_anchor => DnsUdpAction::Proxy(Arc::clone(plan)),
        TunDnsMode::Disabled if is_anchor => dns_error_reply_packet(packet, DNS_RCODE_SERVFAIL)
            .map(DnsUdpAction::Reply)
            .unwrap_or(DnsUdpAction::Pass),
        TunDnsMode::Disabled | TunDnsMode::RawProxy(_) => DnsUdpAction::Pass,
    }
}

pub(super) async fn bridge_udp_query(
    plan: Arc<DnsProxyPlan>,
    packet: UdpTunPacket,
    context: TunRuntimeContext,
    mut shutdown: watch::Receiver<bool>,
    _global_permit: OwnedSemaphorePermit,
    _dns_permit: OwnedSemaphorePermit,
) {
    if !is_dns_query(&packet.payload) {
        push_dns_error_reply(&context, &packet, DNS_RCODE_FORMERR).await;
        return;
    }

    let response = tokio::select! {
        biased;
        () = wait_for_tun_shutdown(&mut shutdown) => return,
        response = proxy_udp_payload(plan.as_ref(), &packet, &context) => response,
    };
    let response = match response {
        Ok(response) => Some(response),
        Err(()) => {
            if context.runtime_logger.is_enabled() {
                if let Some(target) =
                    target_from_endpoint_with_network(packet.target, RoutingNetwork::Udp)
                {
                    crate::debug_log::log_access_rejected(
                        &context.runtime_logger,
                        "tun",
                        &target,
                        "all DNS UDP upstream attempts failed",
                    );
                    context.runtime_logger.error(|| {
                        format!(
                            "Debug udpDnsProxyError target={} error=<redacted>",
                            crate::debug_log::target_label(&target)
                        )
                    });
                }
            }
            dns_error_response(&packet.payload, DNS_RCODE_SERVFAIL, false)
        }
    };
    let Some(response) = response else {
        return;
    };
    let Some(reply) = build_udp_packet(packet.target, packet.client, &response) else {
        return;
    };
    let _ = context.tun.push_outbound(reply).await;
}

pub(super) async fn bridge_fake_ip_tcp_flow(
    handle: SocketHandle,
    generation: u64,
    mapper: Arc<Mutex<FakeIpMapper>>,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<StackToRemoteData>,
    mut shutdown: watch::Receiver<bool>,
    _flow_permit: OwnedSemaphorePermit,
) {
    let mut close_guard = TcpBridgeCloseGuard::new(handle, generation, context.stack_tx.clone());
    let opened = tokio::select! {
        biased;
        () = wait_for_tun_shutdown(&mut shutdown) => false,
        result = context.stack_tx.send(StackEvent::RemoteOpened { handle, generation }) => {
            result.is_ok()
        }
    };
    if !opened {
        return;
    }

    let idle_timeout = context.inbound_policy.conn_idle;
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);
    let mut buffered = BytesMut::new();

    loop {
        let data = tokio::select! {
            biased;
            () = wait_for_tun_shutdown(&mut shutdown) => {
                close_guard.close().await;
                return;
            }
            () = &mut idle_sleep => {
                close_guard.abort().await;
                return;
            }
            data = from_stack.recv() => data,
        };
        let Some(data) = data else {
            close_guard.close().await;
            return;
        };
        buffered.extend_from_slice(&data.data);

        let decoded = fake_ip_tcp_responses(&mapper, &mut buffered);
        if decoded.processed_message {
            idle_sleep
                .as_mut()
                .reset(TokioInstant::now() + idle_timeout);
        }
        let Some(response) = decoded.response else {
            if decoded.terminal_error {
                close_guard.abort().await;
                return;
            }
            continue;
        };

        let sent = tokio::select! {
            biased;
            () = wait_for_tun_shutdown(&mut shutdown) => false,
            () = &mut idle_sleep => false,
            result = context.stack_tx.send(StackEvent::RemoteData {
                handle,
                generation,
                data: response,
            }) => result.is_ok(),
        };
        if !sent {
            close_guard.abort().await;
            return;
        }
        if decoded.terminal_error {
            close_guard.close().await;
            return;
        }
    }
}

struct FakeDnsTcpDecodeResult {
    response: Option<Bytes>,
    processed_message: bool,
    terminal_error: bool,
}

fn fake_ip_tcp_responses(
    mapper: &Arc<Mutex<FakeIpMapper>>,
    buffered: &mut BytesMut,
) -> FakeDnsTcpDecodeResult {
    let mut output = BytesMut::new();
    let mut processed_message = false;

    loop {
        if buffered.len() < 2 {
            break;
        }
        let message_len = usize::from(u16::from_be_bytes([buffered[0], buffered[1]]));
        if message_len == 0 || message_len > MAX_DNS_TCP_MESSAGE_SIZE {
            return fake_dns_tcp_decode_result(output, processed_message, true);
        }
        let Some(frame_len) = message_len.checked_add(2) else {
            return fake_dns_tcp_decode_result(output, processed_message, true);
        };
        if buffered.len() < frame_len {
            break;
        }

        let frame = buffered.split_to(frame_len).freeze();
        let query = &frame[2..];
        let Some(response) = mapper
            .lock()
            .ok()
            .and_then(|mut mapper| mapper.fake_dns_response(query, true))
            .or_else(|| dns_error_response(query, DNS_RCODE_SERVFAIL, false))
        else {
            return fake_dns_tcp_decode_result(output, processed_message, true);
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            return fake_dns_tcp_decode_result(output, processed_message, true);
        };
        output.extend_from_slice(&response_len.to_be_bytes());
        output.extend_from_slice(&response);
        processed_message = true;
    }

    fake_dns_tcp_decode_result(output, processed_message, false)
}

fn fake_dns_tcp_decode_result(
    output: BytesMut,
    processed_message: bool,
    terminal_error: bool,
) -> FakeDnsTcpDecodeResult {
    FakeDnsTcpDecodeResult {
        response: (!output.is_empty()).then(|| output.freeze()),
        processed_message,
        terminal_error,
    }
}

async fn proxy_udp_payload(
    plan: &DnsProxyPlan,
    packet: &UdpTunPacket,
    context: &TunRuntimeContext,
) -> Result<Bytes, ()> {
    let deadline = TokioInstant::now() + DNS_PROXY_TOTAL_TIMEOUT;
    let max_payload = context.tun.mtu().saturating_sub(20 + 8);
    for upstream in plan.upstreams() {
        let remaining = deadline.saturating_duration_since(TokioInstant::now());
        if remaining.is_zero() {
            break;
        }
        let target = upstream.target(RoutingNetwork::Udp);
        let outbound = timeout(
            remaining,
            context
                .outbound_router
                .select_udp_outbound_for_session_with_resolver(
                    Some(upstream.inbound_tag()),
                    &target,
                    context.bootstrap_dns_resolver(),
                ),
        )
        .await;
        let Ok(Ok(outbound)) = outbound else {
            record_dns_udp_failure(context, DnsUdpFailurePhase::Open);
            continue;
        };
        let remaining = deadline.saturating_duration_since(TokioInstant::now());
        if remaining.is_zero() {
            record_dns_udp_failure(context, DnsUdpFailurePhase::Open);
            break;
        }
        let outbound_timeout = match &outbound {
            UdpOutbound::Freedom => DNS_PROXY_FREEDOM_ATTEMPT_TIMEOUT,
            UdpOutbound::Vless(_) => DNS_PROXY_VLESS_ATTEMPT_TIMEOUT,
        };
        let outbound_label = crate::debug_log::udp_outbound_label(&outbound);
        let attempt_timeout = remaining.min(outbound_timeout);
        let mut failure_phase = DnsUdpFailurePhase::Open;
        let attempt = timeout(
            attempt_timeout,
            exchange_udp_candidate(
                outbound,
                &target,
                upstream,
                &packet.payload,
                max_payload,
                context,
                &mut failure_phase,
            ),
        )
        .await;
        let response = match attempt {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => {
                record_dns_udp_failure(context, failure_phase);
                continue;
            }
        };
        if !response.matches_query(&packet.payload) {
            record_dns_udp_failure(context, DnsUdpFailurePhase::Read);
            continue;
        }
        let response = match response {
            DnsUpstreamResponse::Payload(response) => response,
            DnsUpstreamResponse::Oversized { prefix, .. } => {
                if dns_response_matches_query(&packet.payload, &prefix) {
                    log_dns_udp_route(
                        context,
                        packet,
                        &target,
                        upstream.inbound_tag(),
                        outbound_label,
                    );
                    return dns_error_response(&packet.payload, DNS_RCODE_NOERROR, true).ok_or(());
                }
                record_dns_udp_failure(context, DnsUdpFailurePhase::Read);
                continue;
            }
        };
        if !dns_response_matches_query(&packet.payload, &response) {
            record_dns_udp_failure(context, DnsUdpFailurePhase::Read);
            continue;
        }
        log_dns_udp_route(
            context,
            packet,
            &target,
            upstream.inbound_tag(),
            outbound_label,
        );
        return Ok(response);
    }
    Err(())
}

fn log_dns_udp_route(
    context: &TunRuntimeContext,
    packet: &UdpTunPacket,
    upstream: &Target,
    dns_inbound_tag: &str,
    outbound_label: &'static str,
) {
    if !context.runtime_logger.is_enabled() {
        return;
    }
    let Some(original) = target_from_endpoint_with_network(packet.target, RoutingNetwork::Udp)
    else {
        return;
    };
    crate::debug_log::log_route_decision(
        &context.runtime_logger,
        crate::debug_log::RouteDecisionLog {
            inbound_tag: Some(dns_inbound_tag),
            network: RoutingNetwork::Udp,
            original_target: &original,
            sniffed_protocol: None,
            route_target: upstream,
            dial_target: upstream,
            selected_outbound: outbound_label,
        },
    );
    crate::debug_log::log_access_accepted(
        &context.runtime_logger,
        "tun",
        &original,
        outbound_label,
    );
}

async fn exchange_udp_candidate(
    outbound: UdpOutbound,
    target: &Target,
    upstream: &DnsProxyUpstream,
    query: &[u8],
    max_payload: usize,
    context: &TunRuntimeContext,
    failure_phase: &mut DnsUdpFailurePhase,
) -> Result<DnsUpstreamResponse, crate::CoreError> {
    let response = match outbound {
        UdpOutbound::Freedom => {
            let upstream = resolve_freedom_dns_upstream(upstream, context).await?;
            exchange_udp_freedom(upstream, query, max_payload, context, failure_phase).await?
        }
        UdpOutbound::Vless(_)
            if upstream
                .socket_addr()
                .is_some_and(socket_addr_has_nonzero_scope) =>
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "scoped IPv6 DNS upstream cannot be encoded in a VLESS target",
            )
            .into());
        }
        UdpOutbound::Vless(outbound) => {
            exchange_udp_vless(
                &outbound,
                target,
                query,
                max_payload,
                context,
                failure_phase,
            )
            .await?
        }
    };
    context.tun.record_udp_remote_read(response.observed_len());
    Ok(response)
}

pub(super) async fn resolve_freedom_dns_upstream(
    upstream: &DnsProxyUpstream,
    context: &TunRuntimeContext,
) -> Result<SocketAddr, crate::CoreError> {
    resolve_freedom_dns_upstreams(upstream, context)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "DNS upstream hostname has no bootstrap address",
            )
            .into()
        })
}

pub(super) async fn resolve_freedom_dns_upstreams(
    upstream: &DnsProxyUpstream,
    context: &TunRuntimeContext,
) -> Result<Vec<SocketAddr>, crate::CoreError> {
    let resolved = match upstream {
        DnsProxyUpstream::Ip { addr, .. } => vec![*addr],
        DnsProxyUpstream::Domain { domain, port, .. } => {
            let bootstrap_domain =
                match crate::dns::static_dns_host_target(context.config.as_ref(), domain) {
                    Some(xray_config::DnsHostTarget::Ip(ip)) => {
                        return Ok(vec![validate_freedom_dns_upstream(SocketAddr::new(
                            ip, *port,
                        ))?]);
                    }
                    Some(xray_config::DnsHostTarget::Ips(ips)) => {
                        return ips
                            .into_iter()
                            .map(|ip| validate_freedom_dns_upstream(SocketAddr::new(ip, *port)))
                            .collect::<Result<Vec<_>, _>>()
                            .and_then(ensure_freedom_dns_upstreams);
                    }
                    Some(xray_config::DnsHostTarget::Domain(alias)) => alias,
                    None => domain.clone(),
                };
            let Some(resolver) = context.dns_bootstrap_resolver.as_ref() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "DNS upstream hostname has no static bootstrap mapping",
                )
                .into());
            };
            resolver
                .resolve_all(&bootstrap_domain, *port)
                .await
                .map_err(crate::CoreError::from)
                .map(|lookup| lookup.socket_addrs().to_vec())?
        }
    };
    resolved
        .into_iter()
        .map(validate_freedom_dns_upstream)
        .collect::<Result<Vec<_>, _>>()
        .and_then(ensure_freedom_dns_upstreams)
}

fn ensure_freedom_dns_upstreams(
    resolved: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, crate::CoreError> {
    if resolved.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "DNS upstream hostname has no bootstrap address",
        )
        .into());
    }
    Ok(resolved)
}

fn validate_freedom_dns_upstream(addr: SocketAddr) -> Result<SocketAddr, crate::CoreError> {
    if is_tun_dns_socket(addr) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS upstream resolves to a tunnel-local address",
        )
        .into());
    }
    Ok(addr)
}

async fn exchange_udp_freedom(
    upstream: SocketAddr,
    query: &[u8],
    max_payload: usize,
    context: &TunRuntimeContext,
    failure_phase: &mut DnsUdpFailurePhase,
) -> Result<DnsUpstreamResponse, crate::CoreError> {
    let bind_addr = if upstream.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    protect_udp_socket(&socket, context.transport_dialer.socket_protector())?;
    socket.connect(upstream).await?;
    context.tun.record_udp_remote_open(false);
    *failure_phase = DnsUdpFailurePhase::Write;
    let written = socket.send(query).await?;
    if written != query.len() {
        return Err(
            std::io::Error::new(std::io::ErrorKind::WriteZero, "short DNS UDP write").into(),
        );
    }
    context.tun.record_udp_remote_written(written);
    *failure_phase = DnsUdpFailurePhase::Read;
    let buffer_len = MAX_DNS_PROXY_UDP_RESPONSE_SIZE
        .max(max_payload)
        .saturating_add(1);
    let mut buffer = vec![0_u8; buffer_len];
    loop {
        let read = socket.recv(&mut buffer).await?;
        if !dns_response_matches_query(query, &buffer[..read]) {
            continue;
        }
        if read > max_payload {
            return Ok(DnsUpstreamResponse::Oversized {
                observed_len: read,
                prefix: Bytes::copy_from_slice(
                    &buffer[..read.min(MAX_DNS_RESPONSE_VALIDATION_PREFIX_SIZE)],
                ),
            });
        }
        return Ok(DnsUpstreamResponse::Payload(Bytes::copy_from_slice(
            &buffer[..read],
        )));
    }
}

async fn exchange_udp_vless(
    outbound: &VlessTcpOutbound,
    target: &Target,
    query: &[u8],
    max_payload: usize,
    context: &TunRuntimeContext,
    failure_phase: &mut DnsUdpFailurePhase,
) -> Result<DnsUpstreamResponse, crate::CoreError> {
    let (stream, framing) = open_vless_udp_stream_with_resolver_dialer_and_options(
        outbound,
        target,
        context.bootstrap_dns_resolver(),
        &context.transport_dialer,
        VlessUdpOpenOptions::default(),
    )
    .await?;
    context.tun.record_udp_remote_open(false);
    *failure_phase = DnsUdpFailurePhase::Write;
    // This proxy opens an independent stream per DNS attempt. An empty XUDP
    // GlobalID tells Xray not to attach it to a persistent global UDP session.
    let global_id = [0; 8];
    let frame = match framing {
        VlessUdpFraming::LengthPrefixed => encode_udp_packet(query)?,
        VlessUdpFraming::Xudp => encode_xudp_new_packet(target, query, global_id)?,
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    writer.write_all(&frame).await?;
    writer.flush().await?;
    context.tun.record_udp_remote_written(query.len());
    *failure_phase = DnsUdpFailurePhase::Read;
    loop {
        let response = read_dns_vless_udp_response(&mut reader, framing, max_payload).await?;
        if response.matches_query(query) {
            return Ok(response);
        }
    }
}

async fn read_dns_vless_udp_response<R>(
    reader: &mut R,
    framing: VlessUdpFraming,
    max_payload: usize,
) -> std::io::Result<DnsUpstreamResponse>
where
    R: AsyncRead + Unpin,
{
    match framing {
        VlessUdpFraming::LengthPrefixed => read_bounded_dns_payload(reader, max_payload).await,
        VlessUdpFraming::Xudp => loop {
            let metadata_len = usize::from(reader.read_u16().await?);
            if !(4..=MAX_DNS_XUDP_METADATA_SIZE).contains(&metadata_len) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid DNS XUDP metadata length",
                ));
            }
            let mut metadata = vec![0; metadata_len];
            reader.read_exact(&mut metadata).await?;
            let command = metadata[2];
            if !matches!(command, XUDP_CMD_NEW | XUDP_CMD_KEEP | XUDP_CMD_DISCARD) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported DNS XUDP command",
                ));
            }
            if metadata[3] != XUDP_OPT_DATA {
                continue;
            }
            let response = read_bounded_dns_payload(reader, max_payload).await?;
            if command == XUDP_CMD_DISCARD {
                if matches!(response, DnsUpstreamResponse::Oversized { .. }) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "oversized discarded DNS XUDP payload",
                    ));
                }
                continue;
            }
            if matches!(&response, DnsUpstreamResponse::Payload(payload) if payload.is_empty()) {
                continue;
            }
            return Ok(response);
        },
    }
}

async fn read_bounded_dns_payload<R>(
    reader: &mut R,
    max_payload: usize,
) -> std::io::Result<DnsUpstreamResponse>
where
    R: AsyncRead + Unpin,
{
    let payload_len = usize::from(reader.read_u16().await?);
    if payload_len > max_payload {
        let mut prefix = vec![0; payload_len.min(MAX_DNS_RESPONSE_VALIDATION_PREFIX_SIZE)];
        reader.read_exact(&mut prefix).await?;
        let mut remaining = payload_len - prefix.len();
        let mut discard = [0_u8; 1024];
        while remaining > 0 {
            let chunk = remaining.min(discard.len());
            reader.read_exact(&mut discard[..chunk]).await?;
            remaining -= chunk;
        }
        return Ok(DnsUpstreamResponse::Oversized {
            observed_len: payload_len,
            prefix: Bytes::from(prefix),
        });
    }
    let mut payload = vec![0; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok(DnsUpstreamResponse::Payload(Bytes::from(payload)))
}

async fn push_dns_error_reply(context: &TunRuntimeContext, packet: &UdpTunPacket, rcode: u16) {
    let Some(reply) = dns_error_reply_packet(packet, rcode) else {
        return;
    };
    let _ = context.tun.push_outbound(reply).await;
}

pub(super) fn dns_error_reply_packet(packet: &UdpTunPacket, rcode: u16) -> Option<Bytes> {
    let response = dns_error_response(&packet.payload, rcode, false)?;
    build_udp_packet(packet.target, packet.client, &response)
}

fn dns_error_response(query: &[u8], rcode: u16, truncated: bool) -> Option<Bytes> {
    if query.len() < 12 {
        return None;
    }
    let question_end = dns_question_section_end(query).unwrap_or(12);
    let mut response = Vec::with_capacity(question_end);
    response.extend_from_slice(&query[..question_end]);
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let mut response_flags = 0x8000 | (request_flags & 0x7910) | 0x0080 | (rcode & 0x000f);
    if truncated {
        response_flags |= 0x0200;
    }
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    if question_end == 12 {
        response[4..6].copy_from_slice(&0_u16.to_be_bytes());
    }
    response[6..12].fill(0);
    Some(Bytes::from(response))
}

fn dns_question_section_end(message: &[u8]) -> Option<usize> {
    let question_count = usize::from(u16::from_be_bytes([*message.get(4)?, *message.get(5)?]));
    let mut offset = 12usize;
    for _ in 0..question_count {
        loop {
            let label_len = usize::from(*message.get(offset)?);
            offset = offset.checked_add(1)?;
            if label_len == 0 {
                break;
            }
            if label_len & 0xc0 == 0xc0 {
                offset = offset.checked_add(1)?;
                message.get(offset - 1)?;
                break;
            }
            if label_len > 63 {
                return None;
            }
            offset = offset.checked_add(label_len)?;
            message.get(offset - 1)?;
        }
        offset = offset.checked_add(4)?;
        message.get(offset - 1)?;
    }
    Some(offset)
}

fn is_dns_query(message: &[u8]) -> bool {
    message.len() >= 12 && u16::from_be_bytes([message[2], message[3]]) & 0x8000 == 0
}

pub(super) fn is_dns_anchor_endpoint(endpoint: IpEndpoint) -> bool {
    endpoint.addr == IpAddress::Ipv4(TUN_DNS_ANCHOR) && endpoint.port == DNS_PORT
}

fn is_tun_dns_socket(addr: SocketAddr) -> bool {
    let is_tun_ip = match addr.ip() {
        IpAddr::V4(ip) => matches!(ip, TUN_DNS_ANCHOR | TUN_CLIENT_IPV4),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .is_some_and(|ip| matches!(ip, TUN_DNS_ANCHOR | TUN_CLIENT_IPV4)),
    };
    is_tun_ip && addr.port() == DNS_PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_a_query(id: u16, domain: &str) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        query
    }

    #[test]
    fn dns_error_response_preserves_question_and_sets_servfail() {
        let query = dns_a_query(0x1234, "example.com");

        let response = dns_error_response(&query, DNS_RCODE_SERVFAIL, false).unwrap();

        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 2);
        assert_eq!(&response[12..], &query[12..]);
    }

    #[test]
    fn oversized_response_fallback_sets_truncated_and_removes_answers() {
        let query = dns_a_query(0x1235, "example.com");

        let response = dns_error_response(&query, DNS_RCODE_NOERROR, true).unwrap();

        assert_ne!(u16::from_be_bytes([response[2], response[3]]) & 0x0200, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[tokio::test]
    async fn bounded_vless_reader_keeps_only_validation_prefix_for_oversized_payload() {
        let query = dns_a_query(0x1236, "large.example");
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response.resize(2_000, 0);
        let mut framed = Vec::new();
        framed.extend_from_slice(&2_000_u16.to_be_bytes());
        framed.extend_from_slice(&response);
        let mut reader = std::io::Cursor::new(framed);

        let response = read_bounded_dns_payload(&mut reader, 1_472).await.unwrap();

        let DnsUpstreamResponse::Oversized {
            observed_len,
            prefix,
        } = response
        else {
            panic!("oversized payload must not be allocated");
        };
        assert_eq!(observed_len, 2_000);
        assert_eq!(prefix.len(), MAX_DNS_RESPONSE_VALIDATION_PREFIX_SIZE);
        assert!(dns_response_matches_query(&query, &prefix));
    }

    #[tokio::test]
    async fn bounded_xudp_reader_rejects_oversized_metadata_before_allocation() {
        let mut reader = std::io::Cursor::new(
            ((MAX_DNS_XUDP_METADATA_SIZE + 1) as u16)
                .to_be_bytes()
                .to_vec(),
        );

        let error = read_dns_vless_udp_response(&mut reader, VlessUdpFraming::Xudp, 1_472)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn oversized_response_prefix_must_match_query_before_tc_fallback() {
        let query = dns_a_query(0x1237, "large.example");
        let mut unrelated = query[..12].to_vec();
        unrelated[0..2].copy_from_slice(&0x9999_u16.to_be_bytes());
        unrelated[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());

        assert!(!dns_response_matches_query(&query, &unrelated));
    }

    #[test]
    fn dns_response_with_same_id_but_different_question_is_unrelated() {
        let query = dns_a_query(0x1238, "expected.example");
        let mut unrelated = dns_a_query(0x1238, "other.example");
        unrelated[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());

        assert!(!dns_response_matches_query(&query, &unrelated));
    }

    fn fake_ip_mapper() -> Arc<Mutex<FakeIpMapper>> {
        Arc::new(Mutex::new(
            FakeIpMapper::new(FakeIpRuntimeConfig {
                ipv4_network: Ipv4Addr::new(198, 18, 0, 0),
                ipv4_prefix: 15,
                pool_size: 32_768,
                ttl: 60,
            })
            .unwrap(),
        ))
    }

    #[test]
    fn fake_dns_tcp_decoder_keeps_fragmented_frame_until_complete() {
        let query = dns_a_query(0x2401, "fragmented.example");
        let mut frame = Vec::with_capacity(query.len() + 2);
        frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
        frame.extend_from_slice(&query);
        let mut buffered = BytesMut::from(&frame[..1]);

        let partial = fake_ip_tcp_responses(&fake_ip_mapper(), &mut buffered);
        assert!(partial.response.is_none());
        assert!(!partial.processed_message);
        assert!(!partial.terminal_error);

        buffered.extend_from_slice(&frame[1..]);
        let decoded = fake_ip_tcp_responses(&fake_ip_mapper(), &mut buffered);
        let response = decoded.response.unwrap();
        assert!(decoded.processed_message);
        assert!(!decoded.terminal_error);
        assert_eq!(
            usize::from(u16::from_be_bytes([response[0], response[1]])),
            response.len() - 2
        );
        assert_eq!(&response[2..4], &0x2401_u16.to_be_bytes());
        assert!(buffered.is_empty());
    }

    #[test]
    fn fake_dns_tcp_decoder_answers_coalesced_pipelined_frames() {
        let mut buffered = BytesMut::new();
        for (id, domain) in [(0x2402, "first.example"), (0x2403, "second.example")] {
            let query = dns_a_query(id, domain);
            buffered.extend_from_slice(&(query.len() as u16).to_be_bytes());
            buffered.extend_from_slice(&query);
        }

        let decoded = fake_ip_tcp_responses(&fake_ip_mapper(), &mut buffered);
        let response = decoded.response.unwrap();
        let first_len = usize::from(u16::from_be_bytes([response[0], response[1]]));
        let second_offset = first_len + 2;

        assert!(decoded.processed_message);
        assert!(!decoded.terminal_error);
        assert_eq!(&response[2..4], &0x2402_u16.to_be_bytes());
        assert_eq!(
            &response[second_offset + 2..second_offset + 4],
            &0x2403_u16.to_be_bytes()
        );
        assert!(buffered.is_empty());
    }

    #[test]
    fn fake_dns_tcp_decoder_rejects_oversized_frame_before_payload_arrives() {
        let mut buffered = BytesMut::from(
            &(u16::try_from(MAX_DNS_TCP_MESSAGE_SIZE + 1).unwrap()).to_be_bytes()[..],
        );

        let decoded = fake_ip_tcp_responses(&fake_ip_mapper(), &mut buffered);

        assert!(decoded.response.is_none());
        assert!(!decoded.processed_message);
        assert!(decoded.terminal_error);
    }

    #[test]
    fn fake_dns_tcp_decoder_keeps_valid_response_before_terminal_frame_error() {
        let query = dns_a_query(0x2404, "valid.example");
        let mut buffered = BytesMut::new();
        buffered.extend_from_slice(&(query.len() as u16).to_be_bytes());
        buffered.extend_from_slice(&query);
        buffered.extend_from_slice(
            &(u16::try_from(MAX_DNS_TCP_MESSAGE_SIZE + 1).unwrap()).to_be_bytes(),
        );

        let decoded = fake_ip_tcp_responses(&fake_ip_mapper(), &mut buffered);
        let response = decoded.response.unwrap();

        assert!(decoded.processed_message);
        assert!(decoded.terminal_error);
        assert_eq!(&response[2..4], &0x2404_u16.to_be_bytes());
    }

    #[test]
    fn proxy_plan_keeps_ordered_unique_servers_and_filters_unsafe_entries() {
        let first = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
        let second = SocketAddr::from((Ipv6Addr::LOCALHOST, 5_353));
        let plan = DnsProxyPlan::from_servers(
            &[
                DnsServerConfig::Domain {
                    domain: "resolver.example.".to_owned(),
                    port: 53,
                },
                DnsServerConfig::Domain {
                    domain: "Resolver.Example".to_owned(),
                    port: 53,
                },
                DnsServerConfig::Policy(xray_config::DnsNameServerConfig {
                    endpoint: xray_config::DnsServerEndpoint::Domain {
                        domain: "policy.example.".to_owned(),
                        port: 5_353,
                    },
                    domains: vec![xray_config::DomainMatcher::Suffix(
                        "internal.example".to_owned(),
                    )],
                    expected_ips: xray_config::DnsIpFilter::default(),
                    unexpected_ips: xray_config::DnsIpFilter::default(),
                    tag: "policy-dns".to_owned(),
                    timeout_ms: 0,
                    skip_fallback: true,
                    query_strategy: xray_config::DnsQueryStrategy::UseIpv6,
                    final_query: true,
                }),
                DnsServerConfig::Ip(first),
                DnsServerConfig::Ip(first),
                DnsServerConfig::Ip(SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 0))),
                DnsServerConfig::Ip(SocketAddr::from((TUN_DNS_ANCHOR, DNS_PORT))),
                DnsServerConfig::Ip(SocketAddr::from((TUN_CLIENT_IPV4, DNS_PORT))),
                DnsServerConfig::Ip("[::ffff:198.18.0.1]:53".parse().unwrap()),
                DnsServerConfig::Ip("[::ffff:198.18.0.2]:53".parse().unwrap()),
                DnsServerConfig::Ip(second),
            ],
            "global-dns",
        )
        .unwrap();

        assert_eq!(
            plan.upstreams(),
            &[
                DnsProxyUpstream::Domain {
                    domain: "resolver.example".to_owned(),
                    port: 53,
                    inbound_tag: "global-dns".to_owned(),
                },
                DnsProxyUpstream::Domain {
                    domain: "policy.example".to_owned(),
                    port: 5_353,
                    inbound_tag: "policy-dns".to_owned(),
                },
                DnsProxyUpstream::Ip {
                    addr: first,
                    inbound_tag: "global-dns".to_owned(),
                },
                DnsProxyUpstream::Ip {
                    addr: second,
                    inbound_tag: "global-dns".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn compiled_dns_ip_filters_remain_irrelevant_to_the_raw_proxy_plan() {
        let raw = r#"{
          "dns": {
            "tag": "dns-route",
            "servers": [{
              "address": "policy.example",
              "port": 5353,
              "expectedIPs": ["192.0.2.0/24"],
              "unexpectedIPs": ["!198.51.100.0/24"]
            }]
          },
          "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let mut config = xray_config::parse_xray_json(raw)
            .expect("DNS IP policy should parse")
            .config;

        let _compiled = crate::take_name_server_policy_set(&mut config);
        let plan = DnsProxyPlan::from_config(&config).unwrap();

        assert_eq!(
            plan.upstreams(),
            &[DnsProxyUpstream::Domain {
                domain: "policy.example".to_owned(),
                port: 5353,
                inbound_tag: "dns-route".to_owned(),
            }]
        );
    }

    #[test]
    fn proxy_plan_keeps_same_endpoint_clients_with_different_tags() {
        let raw = r#"{
          "dns": {
            "tag": "dns-global",
            "servers": [
              "192.0.2.53",
              { "address": "192.0.2.53", "tag": "dns-alternate" },
              { "address": "192.0.2.53", "tag": "dns-alternate" }
            ]
          },
          "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let config = xray_config::parse_xray_json(raw)
            .expect("tagged DNS clients should parse")
            .config;
        let plan = DnsProxyPlan::from_config(&config).unwrap();

        assert_eq!(
            plan.upstreams(),
            &[
                DnsProxyUpstream::Ip {
                    addr: SocketAddr::from(([192, 0, 2, 53], 53)),
                    inbound_tag: "dns-global".to_owned(),
                },
                DnsProxyUpstream::Ip {
                    addr: SocketAddr::from(([192, 0, 2, 53], 53)),
                    inbound_tag: "dns-alternate".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn proxy_plan_requires_at_least_one_usable_upstream() {
        let plan = DnsProxyPlan::from_servers(
            &[DnsServerConfig::Ip(SocketAddr::from((
                TUN_DNS_ANCHOR,
                DNS_PORT,
            )))],
            "dns-route",
        );

        assert!(plan.is_none());
    }

    #[test]
    fn tcp_anchor_uses_the_configured_dns_mode() {
        let upstream = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
        let plan = Arc::new(
            DnsProxyPlan::from_servers(&[DnsServerConfig::Ip(upstream)], "dns-route").unwrap(),
        );
        let anchor = IpEndpoint::new(IpAddress::Ipv4(TUN_DNS_ANCHOR), DNS_PORT);
        let ordinary = IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(203, 0, 113, 1)), DNS_PORT);

        assert!(matches!(
            tcp_action(&TunDnsMode::RawProxy(Arc::clone(&plan)), anchor),
            DnsTcpAction::Proxy(_)
        ));
        assert!(matches!(
            tcp_action(&TunDnsMode::RawProxy(plan), ordinary),
            DnsTcpAction::Pass
        ));
        assert!(matches!(
            tcp_action(&TunDnsMode::Disabled, anchor),
            DnsTcpAction::Reject
        ));
        let fake_mapper = FakeIpMapper::new(FakeIpRuntimeConfig {
            ipv4_network: Ipv4Addr::new(198, 18, 0, 0),
            ipv4_prefix: 15,
            pool_size: 32_768,
            ttl: 60,
        })
        .unwrap();
        let fake_mode = TunDnsMode::FakeIp(Arc::new(Mutex::new(fake_mapper)));
        assert!(matches!(
            tcp_action(&fake_mode, anchor),
            DnsTcpAction::FakeIp(_)
        ));
        assert!(matches!(
            tcp_action(&fake_mode, ordinary),
            DnsTcpAction::FakeIp(_)
        ));
        assert!(matches!(
            tcp_action(&TunDnsMode::Disabled, ordinary),
            DnsTcpAction::Pass
        ));
    }
}
