use std::collections::HashSet;

use tokio::time::{timeout, Instant as TokioInstant};

use super::*;

const DNS_RCODE_FORMERR: u16 = 1;
const MAX_DNS_PROXY_UPSTREAMS: usize = 8;
const MAX_DNS_XUDP_METADATA_SIZE: usize = 512;
const XUDP_CMD_NEW: u8 = 1;
const XUDP_CMD_KEEP: u8 = 2;
const XUDP_CMD_DISCARD: u8 = 4;
const XUDP_OPT_DATA: u8 = 1;
const DNS_PROXY_FREEDOM_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(750);
const DNS_PROXY_VLESS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_PROXY_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DnsProxyPlan {
    upstreams: Arc<[SocketAddr]>,
}

impl DnsProxyPlan {
    fn from_config(config: &CoreConfig) -> Option<Self> {
        Self::from_servers(&config.dns.servers)
    }

    fn from_servers(servers: &[DnsServerConfig]) -> Option<Self> {
        let mut seen = HashSet::new();
        let upstreams = servers
            .iter()
            .filter_map(|server| match server {
                DnsServerConfig::Ip(addr)
                    if addr.port() != 0 && !is_dns_anchor_socket(*addr) && seen.insert(*addr) =>
                {
                    Some(*addr)
                }
                DnsServerConfig::Ip(_) | DnsServerConfig::Domain { .. } => None,
            })
            .take(MAX_DNS_PROXY_UPSTREAMS)
            .collect::<Vec<_>>();
        (!upstreams.is_empty()).then(|| Self {
            upstreams: upstreams.into(),
        })
    }

    pub(super) fn upstreams(&self) -> &[SocketAddr] {
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
    if !is_dns_anchor_endpoint(endpoint) {
        return DnsTcpAction::Pass;
    }
    match mode {
        TunDnsMode::RawProxy(plan) => DnsTcpAction::Proxy(Arc::clone(plan)),
        TunDnsMode::Disabled | TunDnsMode::FakeIp(_) => DnsTcpAction::Reject,
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
        let target = Target::new(
            RoutingTargetAddr::Ip(upstream.ip()),
            upstream.port(),
            RoutingNetwork::Udp,
        );
        let selection = timeout(
            remaining,
            context
                .outbound_router
                .select_udp_outbound_for_session_with_resolver(
                    context.inbound_tag.as_deref(),
                    &target,
                    context.dns_resolver.as_ref(),
                ),
        )
        .await;
        let Ok(Ok(outbound)) = selection else {
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
                *upstream,
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
        let response = match response {
            DnsUpstreamResponse::Payload(response) => response,
            DnsUpstreamResponse::Oversized { prefix, .. } => {
                if valid_dns_response(&packet.payload, &prefix) {
                    log_dns_udp_route(context, packet, &target, outbound_label);
                    return dns_error_response(&packet.payload, DNS_RCODE_NOERROR, true).ok_or(());
                }
                record_dns_udp_failure(context, DnsUdpFailurePhase::Read);
                continue;
            }
        };
        if !valid_dns_response(&packet.payload, &response) {
            record_dns_udp_failure(context, DnsUdpFailurePhase::Read);
            continue;
        }
        log_dns_udp_route(context, packet, &target, outbound_label);
        return Ok(response);
    }
    Err(())
}

fn log_dns_udp_route(
    context: &TunRuntimeContext,
    packet: &UdpTunPacket,
    upstream: &Target,
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
            inbound_tag: context.inbound_tag.as_deref(),
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
    upstream: SocketAddr,
    query: &[u8],
    max_payload: usize,
    context: &TunRuntimeContext,
    failure_phase: &mut DnsUdpFailurePhase,
) -> Result<DnsUpstreamResponse, crate::CoreError> {
    let response = match outbound {
        UdpOutbound::Freedom => {
            exchange_udp_freedom(upstream, query, max_payload, context, failure_phase).await?
        }
        UdpOutbound::Vless(_) if socket_addr_has_nonzero_scope(upstream) => {
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
    let mut buffer = vec![0_u8; max_payload.saturating_add(1).max(1)];
    let read = socket.recv(&mut buffer).await?;
    if read > max_payload {
        return Ok(DnsUpstreamResponse::Oversized {
            observed_len: read,
            prefix: Bytes::copy_from_slice(&buffer[..read.min(12)]),
        });
    }
    Ok(DnsUpstreamResponse::Payload(Bytes::copy_from_slice(
        &buffer[..read],
    )))
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
        context.dns_resolver.as_ref(),
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
    read_dns_vless_udp_response(&mut reader, framing, max_payload)
        .await
        .map_err(Into::into)
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
        let mut prefix = vec![0; payload_len.min(12)];
        reader.read_exact(&mut prefix).await?;
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

fn valid_dns_response(query: &[u8], response: &[u8]) -> bool {
    is_dns_query(query)
        && response.len() >= 12
        && response[0..2] == query[0..2]
        && u16::from_be_bytes([response[2], response[3]]) & 0x8000 != 0
}

pub(super) fn is_dns_anchor_endpoint(endpoint: IpEndpoint) -> bool {
    endpoint.addr == IpAddress::Ipv4(TUN_DNS_ANCHOR) && endpoint.port == DNS_PORT
}

fn is_dns_anchor_socket(addr: SocketAddr) -> bool {
    let is_anchor_ip = match addr.ip() {
        IpAddr::V4(ip) => ip == TUN_DNS_ANCHOR,
        IpAddr::V6(ip) => ip.to_ipv4_mapped() == Some(TUN_DNS_ANCHOR),
    };
    is_anchor_ip && addr.port() == DNS_PORT
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
    async fn bounded_vless_reader_keeps_only_dns_header_for_oversized_payload() {
        let query = dns_a_query(0x1236, "large.example");
        let mut response_prefix = query[..12].to_vec();
        response_prefix[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let mut framed = Vec::new();
        framed.extend_from_slice(&2_000_u16.to_be_bytes());
        framed.extend_from_slice(&response_prefix);
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
        assert_eq!(prefix.len(), 12);
        assert!(valid_dns_response(&query, &prefix));
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

        assert!(!valid_dns_response(&query, &unrelated));
    }

    #[test]
    fn proxy_plan_keeps_ordered_unique_ip_servers_and_filters_unsafe_entries() {
        let first = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
        let second = SocketAddr::from((Ipv6Addr::LOCALHOST, 5_353));
        let plan = DnsProxyPlan::from_servers(&[
            DnsServerConfig::Domain {
                domain: "resolver.example".to_owned(),
                port: 53,
            },
            DnsServerConfig::Ip(first),
            DnsServerConfig::Ip(first),
            DnsServerConfig::Ip(SocketAddr::from((Ipv4Addr::new(9, 9, 9, 9), 0))),
            DnsServerConfig::Ip(SocketAddr::from((TUN_DNS_ANCHOR, DNS_PORT))),
            DnsServerConfig::Ip("[::ffff:198.18.0.1]:53".parse().unwrap()),
            DnsServerConfig::Ip(second),
        ])
        .unwrap();

        assert_eq!(plan.upstreams(), &[first, second]);
    }

    #[test]
    fn proxy_plan_requires_at_least_one_safe_ip_literal() {
        let plan = DnsProxyPlan::from_servers(&[
            DnsServerConfig::Domain {
                domain: "resolver.example".to_owned(),
                port: 53,
            },
            DnsServerConfig::Ip(SocketAddr::from((TUN_DNS_ANCHOR, DNS_PORT))),
        ]);

        assert!(plan.is_none());
    }

    #[test]
    fn tcp_anchor_is_proxied_only_in_raw_proxy_mode() {
        let upstream = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
        let plan = Arc::new(DnsProxyPlan::from_servers(&[DnsServerConfig::Ip(upstream)]).unwrap());
        let anchor = IpEndpoint::new(IpAddress::Ipv4(TUN_DNS_ANCHOR), DNS_PORT);
        let ordinary = IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(203, 0, 113, 1)), DNS_PORT);

        assert!(matches!(
            tcp_action(&TunDnsMode::RawProxy(plan), anchor),
            DnsTcpAction::Proxy(_)
        ));
        assert!(matches!(
            tcp_action(&TunDnsMode::Disabled, anchor),
            DnsTcpAction::Reject
        ));
        let fake_mapper = FakeIpMapper::new(FakeIpRuntimeConfig {
            ipv4_network: Ipv4Addr::new(198, 18, 0, 0),
            ipv4_prefix: 15,
            ttl: 60,
        })
        .unwrap();
        assert!(matches!(
            tcp_action(
                &TunDnsMode::FakeIp(Arc::new(Mutex::new(fake_mapper))),
                anchor
            ),
            DnsTcpAction::Reject
        ));
        assert!(matches!(
            tcp_action(&TunDnsMode::Disabled, ordinary),
            DnsTcpAction::Pass
        ));
    }
}
