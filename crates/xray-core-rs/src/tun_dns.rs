use std::collections::HashSet;

use tokio::time::{timeout, timeout_at, Instant as TokioInstant};

use super::*;

const DNS_RCODE_FORMERR: u16 = 1;
const DNS_RCODE_REFUSED: u16 = 5;
const DNS_TYPE_OPT: u16 = 41;
const DNS_TYPE_IXFR: u16 = 251;
const DNS_TYPE_AXFR: u16 = 252;
const DNS_LEGACY_UDP_PAYLOAD_SIZE: usize = 512;
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
const MAX_RAW_DNS_TCP_PENDING_QUERIES: usize = 16;
const MAX_RAW_DNS_TCP_PENDING_BYTES: usize = 128 * 1024;
const RAW_DNS_TCP_DRAIN_QUANTUM: usize = 16;
const RAW_DNS_TCP_WRITE_QUANTUM_BYTES: usize = 16 * 1024;
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
        transport: xray_config::DnsServerTransport,
    },
    Domain {
        domain: String,
        port: u16,
        inbound_tag: String,
        transport: xray_config::DnsServerTransport,
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

    pub(super) fn transport(&self) -> xray_config::DnsServerTransport {
        match self {
            Self::Ip { transport, .. } | Self::Domain { transport, .. } => *transport,
        }
    }

    pub(super) fn is_local(&self) -> bool {
        self.transport() == xray_config::DnsServerTransport::TcpLocal
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
                let transport = server.transport();
                match server.endpoint() {
                    xray_config::DnsServerEndpoint::Ip(addr)
                        if addr.port() != 0 && !is_tun_dns_socket(addr) =>
                    {
                        let upstream = DnsProxyUpstream::Ip {
                            addr,
                            inbound_tag,
                            transport,
                        };
                        seen.insert(upstream.clone()).then_some(upstream)
                    }
                    xray_config::DnsServerEndpoint::Domain { domain, port } if port != 0 => {
                        let domain = crate::dns::normalize_dns_name(&domain)?;
                        let upstream = DnsProxyUpstream::Domain {
                            domain,
                            port,
                            inbound_tag,
                            transport,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsTcpConnectionPoolLimits {
    per_upstream: usize,
    global: usize,
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
const DEFAULT_DNS_TCP_POOL_PROFILE: TunRuntimeProfile = TunRuntimeProfile::Mobile;

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
)))]
const DEFAULT_DNS_TCP_POOL_PROFILE: TunRuntimeProfile = TunRuntimeProfile::Desktop;

impl DnsTcpConnectionPoolLimits {
    fn for_profile(profile: TunRuntimeProfile) -> Self {
        match profile {
            TunRuntimeProfile::Default => Self::for_profile(DEFAULT_DNS_TCP_POOL_PROFILE),
            TunRuntimeProfile::LowMemory => Self {
                per_upstream: 1,
                global: 8,
            },
            TunRuntimeProfile::Mobile => Self {
                per_upstream: 2,
                global: 16,
            },
            TunRuntimeProfile::MobilePlus | TunRuntimeProfile::Desktop => Self {
                per_upstream: 4,
                global: 32,
            },
            TunRuntimeProfile::Throughput => Self {
                per_upstream: 8,
                global: 64,
            },
        }
    }

    fn idle_ttl_for_profile(profile: TunRuntimeProfile) -> Duration {
        match profile {
            TunRuntimeProfile::Default => Self::idle_ttl_for_profile(DEFAULT_DNS_TCP_POOL_PROFILE),
            TunRuntimeProfile::LowMemory => Duration::from_secs(15),
            TunRuntimeProfile::Mobile => Duration::from_secs(30),
            TunRuntimeProfile::MobilePlus => Duration::from_secs(45),
            TunRuntimeProfile::Desktop | TunRuntimeProfile::Throughput => Duration::from_secs(60),
        }
    }
}

pub(super) struct DnsTcpConnectionPool {
    entries: Mutex<HashMap<DnsProxyUpstream, Arc<DnsTcpConnectionPoolEntry>>>,
    per_upstream_limit: usize,
    idle_ttl: Duration,
    active_query_permits: Arc<Semaphore>,
    connection_permits: Arc<Semaphore>,
}

struct DnsTcpConnectionPoolEntry {
    idle: Mutex<Vec<DnsTcpPooledConnection>>,
    idle_limit: usize,
    active_query_permits: Arc<Semaphore>,
}

struct DnsTcpPooledConnection {
    stream: BoxedTransportStream,
    last_used: TokioInstant,
    _global_connection_permit: OwnedSemaphorePermit,
}

struct DnsTcpConnectionLease {
    entry: Arc<DnsTcpConnectionPoolEntry>,
    connection: Option<DnsTcpPooledConnection>,
    _per_upstream_query_permit: OwnedSemaphorePermit,
    _global_query_permit: OwnedSemaphorePermit,
}

impl DnsTcpConnectionPool {
    pub(super) fn new(profile: TunRuntimeProfile) -> Self {
        Self::with_limits_and_idle_ttl(
            DnsTcpConnectionPoolLimits::for_profile(profile),
            DnsTcpConnectionPoolLimits::idle_ttl_for_profile(profile),
        )
    }

    #[cfg(test)]
    fn with_limits(limits: DnsTcpConnectionPoolLimits) -> Self {
        Self::with_limits_and_idle_ttl(limits, Duration::from_secs(60))
    }

    fn with_limits_and_idle_ttl(limits: DnsTcpConnectionPoolLimits, idle_ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            per_upstream_limit: limits.per_upstream,
            idle_ttl,
            active_query_permits: Arc::new(Semaphore::new(limits.global)),
            connection_permits: Arc::new(Semaphore::new(limits.global)),
        }
    }

    async fn lease(&self, upstream: &DnsProxyUpstream) -> std::io::Result<DnsTcpConnectionLease> {
        self.prune_expired(TokioInstant::now());
        let entry = self.entry(upstream)?;
        let per_upstream_query_permit = Arc::clone(&entry.active_query_permits)
            .acquire_owned()
            .await
            .map_err(std::io::Error::other)?;
        let global_query_permit = Arc::clone(&self.active_query_permits)
            .acquire_owned()
            .await
            .map_err(std::io::Error::other)?;
        let connection = entry.take_idle_connection(TokioInstant::now(), self.idle_ttl);
        Ok(DnsTcpConnectionLease {
            entry,
            connection,
            _per_upstream_query_permit: per_upstream_query_permit,
            _global_query_permit: global_query_permit,
        })
    }

    fn entry(
        &self,
        upstream: &DnsProxyUpstream,
    ) -> std::io::Result<Arc<DnsTcpConnectionPoolEntry>> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = entries.get(upstream) {
            return Ok(Arc::clone(entry));
        }
        if entries.len() >= MAX_DNS_PROXY_UPSTREAMS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DNS TCP connection pool upstream limit exceeded",
            ));
        }
        let entry = Arc::new(DnsTcpConnectionPoolEntry {
            idle: Mutex::new(Vec::with_capacity(self.per_upstream_limit)),
            idle_limit: self.per_upstream_limit,
            active_query_permits: Arc::new(Semaphore::new(self.per_upstream_limit)),
        });
        entries.insert(upstream.clone(), Arc::clone(&entry));
        Ok(entry)
    }

    fn reserve_connection_slot(&self) -> std::io::Result<OwnedSemaphorePermit> {
        self.prune_expired(TokioInstant::now());
        loop {
            match Arc::clone(&self.connection_permits).try_acquire_owned() {
                Ok(permit) => return Ok(permit),
                Err(tokio::sync::TryAcquireError::NoPermits)
                    if self.evict_one_idle_connection() => {}
                Err(error) => return Err(std::io::Error::other(error)),
            }
        }
    }

    fn evict_one_idle_connection(&self) -> bool {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        entries.into_iter().any(|entry| {
            let connection = entry
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop();
            connection.is_some()
        })
    }

    pub(super) fn prune_expired(&self, now: TokioInstant) -> usize {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        entries
            .into_iter()
            .map(|entry| entry.prune_expired(now, self.idle_ttl))
            .sum()
    }
}

impl DnsTcpConnectionPoolEntry {
    fn take_idle_connection(
        &self,
        now: TokioInstant,
        idle_ttl: Duration,
    ) -> Option<DnsTcpPooledConnection> {
        let (connection, expired) = {
            let mut idle = self
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let expired = remove_expired_idle_connections(&mut idle, now, idle_ttl);
            (idle.pop(), expired)
        };
        drop(expired);
        connection
    }

    fn prune_expired(&self, now: TokioInstant, idle_ttl: Duration) -> usize {
        let expired = {
            let mut idle = self
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            remove_expired_idle_connections(&mut idle, now, idle_ttl)
        };
        let count = expired.len();
        drop(expired);
        count
    }
}

fn remove_expired_idle_connections(
    idle: &mut Vec<DnsTcpPooledConnection>,
    now: TokioInstant,
    idle_ttl: Duration,
) -> Vec<DnsTcpPooledConnection> {
    let mut expired = Vec::new();
    let mut index = 0;
    while index < idle.len() {
        if now.saturating_duration_since(idle[index].last_used) >= idle_ttl {
            expired.push(idle.swap_remove(index));
        } else {
            index += 1;
        }
    }
    expired
}

impl DnsTcpConnectionLease {
    fn take_connection(&mut self) -> Option<DnsTcpPooledConnection> {
        self.connection.take()
    }

    #[cfg(test)]
    fn reused(&self) -> bool {
        self.connection.is_some()
    }

    fn recycle(self, connection: DnsTcpPooledConnection) {
        self.recycle_at(connection, TokioInstant::now());
    }

    fn recycle_at(self, mut connection: DnsTcpPooledConnection, last_used: TokioInstant) {
        connection.last_used = last_used;
        let mut idle = self
            .entry
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if idle.len() < self.entry.idle_limit {
            idle.push(connection);
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EdnsRequest {
    udp_payload_size: usize,
    dnssec_ok: bool,
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

    fn is_successful_tcp_response(&self) -> bool {
        let response = match self {
            Self::Payload(payload) => payload,
            Self::Oversized { prefix, .. } => prefix,
        };
        response
            .get(2..4)
            .is_some_and(|flags| u16::from_be_bytes([flags[0], flags[1]]) & (0x0200 | 0x000f) == 0)
    }

    fn into_udp_client_payload(self, query: &[u8], max_payload: usize) -> Option<Bytes> {
        match self {
            Self::Payload(payload) => {
                dns_response_matches_query(query, &payload).then_some(payload)
            }
            Self::Oversized { prefix, .. } if dns_response_matches_query(query, &prefix) => {
                dns_error_response_with_payload_size(query, DNS_RCODE_NOERROR, true, max_payload)
            }
            Self::Oversized { .. } => None,
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
    let mut decoder = DnsTcpFrameDecoder::default();

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
        decoder.push(&data.data);

        let decoded = fake_ip_tcp_responses(&mapper, &mut decoder);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawDnsTcpClientFrameKind {
    Query,
    Transparent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawDnsTcpResponseKind {
    Terminal,
    Retry,
}

#[derive(Debug)]
struct RawDnsTcpPendingQuery {
    framed: Bytes,
    payload: Bytes,
    sequence: u64,
    deadline: TokioInstant,
    attempted_candidates: u16,
    preferred_candidate: Option<usize>,
    generation: u64,
    attempt_deadline: Option<TokioInstant>,
    sent: bool,
    upload_frame_id: Option<u64>,
}

#[derive(Debug)]
struct RawDnsTcpUploadChunk {
    end: usize,
    _reservation: Option<TcpUploadReservation>,
}

#[derive(Debug)]
struct RawDnsTcpUploadFrame {
    id: u64,
    end: usize,
    committed: bool,
}

#[derive(Debug, Default)]
struct RawDnsTcpUploadLedger {
    received_end: usize,
    decoded_end: usize,
    committed_end: usize,
    next_frame_id: u64,
    chunks: VecDeque<RawDnsTcpUploadChunk>,
    frames: VecDeque<RawDnsTcpUploadFrame>,
}

impl RawDnsTcpUploadLedger {
    fn push(&mut self, mut data: StackToRemoteData) -> bool {
        let Some(end) = self.received_end.checked_add(data.len()) else {
            return false;
        };
        self.received_end = end;
        self.chunks.push_back(RawDnsTcpUploadChunk {
            end,
            _reservation: data.reservation.take(),
        });
        true
    }

    fn register_frame(&mut self, frame_len: usize) -> Option<u64> {
        let end = self.decoded_end.checked_add(frame_len)?;
        if end > self.received_end {
            return None;
        }
        let id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);
        self.decoded_end = end;
        self.frames.push_back(RawDnsTcpUploadFrame {
            id,
            end,
            committed: false,
        });
        Some(id)
    }

    fn commit_frame(&mut self, id: u64) -> bool {
        let Some(frame) = self.frames.iter_mut().find(|frame| frame.id == id) else {
            return false;
        };
        frame.committed = true;
        while self.frames.front().is_some_and(|frame| frame.committed) {
            let frame = self
                .frames
                .pop_front()
                .expect("committed upload frame must remain at the front");
            self.committed_end = frame.end;
        }
        while self
            .chunks
            .front()
            .is_some_and(|chunk| chunk.end <= self.committed_end)
        {
            self.chunks.pop_front();
        }
        true
    }
}

#[derive(Debug, Default)]
struct RawDnsTcpPendingQueries {
    entries: VecDeque<RawDnsTcpPendingQuery>,
    bytes: usize,
    next_sequence: u64,
}

impl RawDnsTcpPendingQueries {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn buffered_bytes(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    fn push(&mut self, framed: Bytes, now: TokioInstant) -> bool {
        self.push_with_preferred_candidate(framed, now, None, None)
    }

    fn push_with_preferred_candidate(
        &mut self,
        framed: Bytes,
        now: TokioInstant,
        preferred_candidate: Option<usize>,
        upload_frame_id: Option<u64>,
    ) -> bool {
        let next_bytes = self.bytes.saturating_add(framed.len());
        if self.entries.len() >= MAX_RAW_DNS_TCP_PENDING_QUERIES
            || next_bytes > MAX_RAW_DNS_TCP_PENDING_BYTES
        {
            return false;
        }
        let payload = framed.slice(2..);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.entries.push_back(RawDnsTcpPendingQuery {
            framed,
            payload,
            sequence,
            deadline: now + DNS_TCP_PROXY_TOTAL_TIMEOUT,
            attempted_candidates: 0,
            preferred_candidate,
            generation: 0,
            attempt_deadline: None,
            sent: false,
            upload_frame_id,
        });
        self.bytes = next_bytes;
        true
    }

    fn remove(&mut self, index: usize) -> Option<RawDnsTcpPendingQuery> {
        let query = self.entries.remove(index)?;
        self.bytes = self.bytes.saturating_sub(query.framed.len());
        Some(query)
    }

    fn matching_response_index(&self, generation: u64, response: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, query)| query.generation == generation && query.sent)
            .filter(|(_, query)| dns_response_matches_query(&query.payload, response))
            .min_by_key(|(_, query)| query.sequence)
            .map(|(index, _)| index)
    }

    fn next_candidate(&self, candidate_count: usize) -> Option<usize> {
        let query = self.entries.iter().find(|query| query.generation == 0)?;
        raw_dns_next_candidate(
            query.attempted_candidates,
            query.preferred_candidate,
            candidate_count,
        )
    }

    fn prepare_candidate(
        &mut self,
        candidate_index: usize,
        candidate_count: usize,
        generation: u64,
        now: TokioInstant,
    ) -> Option<TokioInstant> {
        let candidate_bit = raw_dns_candidate_bit(candidate_index);
        let mut earliest_deadline = self
            .entries
            .iter()
            .filter(|query| query.generation == generation)
            .filter_map(|query| query.attempt_deadline)
            .min();
        for query in &mut self.entries {
            if query.generation != 0 || query.attempted_candidates & candidate_bit != 0 {
                continue;
            }
            if raw_dns_next_candidate(
                query.attempted_candidates,
                query.preferred_candidate,
                candidate_count,
            ) != Some(candidate_index)
            {
                continue;
            }
            let remaining = query.deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                continue;
            }
            let attempted =
                usize::try_from(query.attempted_candidates.count_ones()).unwrap_or(candidate_count);
            let remaining_candidates = candidate_count.saturating_sub(attempted).max(1);
            let divisor = u32::try_from(remaining_candidates).unwrap_or(u32::MAX);
            let candidate_budget = remaining / divisor;
            if candidate_budget.is_zero() {
                continue;
            }
            let attempt_deadline = now + candidate_budget.min(DNS_TCP_PROXY_ATTEMPT_TIMEOUT);
            query.attempted_candidates |= candidate_bit;
            query.generation = generation;
            query.attempt_deadline = Some(attempt_deadline);
            query.sent = false;
            earliest_deadline = Some(
                earliest_deadline.map_or(attempt_deadline, |current: TokioInstant| {
                    current.min(attempt_deadline)
                }),
            );
        }
        earliest_deadline
    }

    fn retire_generation_preserving_attempts(&mut self, generation: u64) {
        for query in &mut self.entries {
            if query.generation == generation {
                query.generation = 0;
                query.attempt_deadline = None;
                query.sent = false;
            }
        }
    }

    fn retire_generation_for_timeout(
        &mut self,
        generation: u64,
        candidate_index: usize,
        now: TokioInstant,
    ) {
        let candidate_bit = raw_dns_candidate_bit(candidate_index);
        for query in &mut self.entries {
            if query.generation != generation {
                continue;
            }
            let attempt_expired = query
                .attempt_deadline
                .is_some_and(|deadline| deadline <= now);
            if !attempt_expired {
                query.attempted_candidates &= !candidate_bit;
            }
            query.generation = 0;
            query.attempt_deadline = None;
            query.sent = false;
        }
    }

    fn has_generation(&self, generation: u64) -> bool {
        self.entries
            .iter()
            .any(|query| query.generation == generation)
    }

    fn has_unsent_generation(&self, generation: u64) -> bool {
        self.entries
            .iter()
            .any(|query| query.generation == generation && !query.sent)
    }

    fn mark_generation_sent(&mut self, generation: u64) -> Vec<u64> {
        let mut upload_frame_ids = Vec::new();
        for query in &mut self.entries {
            if query.generation == generation {
                query.sent = true;
                if let Some(upload_frame_id) = query.upload_frame_id.take() {
                    upload_frame_ids.push(upload_frame_id);
                }
            }
        }
        upload_frame_ids
    }

    fn nearest_deadline(&self) -> Option<TokioInstant> {
        self.entries.iter().fold(None, |nearest, query| {
            let nearest = Some(nearest.map_or(query.deadline, |current: TokioInstant| {
                current.min(query.deadline)
            }));
            match query.attempt_deadline {
                Some(attempt_deadline) => {
                    Some(nearest.map_or(attempt_deadline, |current| current.min(attempt_deadline)))
                }
                None => nearest,
            }
        })
    }

    fn next_failed_index(&self, candidate_count: usize, now: TokioInstant) -> Option<usize> {
        let all_candidates = raw_dns_all_candidates_mask(candidate_count);
        self.entries.iter().position(|query| {
            query.deadline <= now
                || (query.generation == 0
                    && query.attempted_candidates & all_candidates == all_candidates)
        })
    }

    fn generation_has_expired_query(&self, generation: u64, now: TokioInstant) -> bool {
        self.entries.iter().any(|query| {
            query.generation == generation
                && (query.deadline <= now
                    || query
                        .attempt_deadline
                        .is_some_and(|deadline| deadline <= now))
        })
    }
}

struct RawDnsTcpUpstreamSession {
    stream: BoxedTransportStream,
    decoder: DnsTcpFrameDecoder,
    candidate_index: usize,
    generation: u64,
    target: Target,
    outbound_tag: Option<String>,
    timing: Option<TcpFirstByteTimingEnabled>,
}

struct RawDnsTcpOpenedCandidate {
    stream: BoxedTransportStream,
    target: Target,
    outbound_tag: Option<String>,
    timing: Option<TcpFirstByteTimingEnabled>,
}

enum RawDnsTcpOpenResult {
    Opened(RawDnsTcpOpenedCandidate),
    Failed,
    TimedOut,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawDnsTcpRetireReason {
    CandidateFailure,
    Timeout(TokioInstant),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawDnsTcpIoResult {
    Complete,
    Failed,
    TimedOut,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawDnsTcpDrainResult {
    Complete,
    More,
    Close,
    Shutdown,
}

enum RawDnsTcpLoopEvent {
    Client(Option<StackToRemoteData>),
    Upstream(std::io::Result<usize>),
    Drain,
    Deadline,
    Idle,
    Shutdown,
}

fn retire_raw_dns_tcp_upstream(
    upstream: &mut Option<RawDnsTcpUpstreamSession>,
    pending: &mut RawDnsTcpPendingQueries,
    context: &TunRuntimeContext,
    reason: RawDnsTcpRetireReason,
) {
    let Some(mut session) = upstream.take() else {
        return;
    };
    match reason {
        RawDnsTcpRetireReason::CandidateFailure => {
            pending.retire_generation_preserving_attempts(session.generation);
        }
        RawDnsTcpRetireReason::Timeout(now) => {
            pending.retire_generation_for_timeout(session.generation, session.candidate_index, now)
        }
    }
    if let Some(timing) = session.timing.as_mut() {
        timing.record_flow_summary(context.tun.as_ref(), &session.target, true);
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "raw DNS bridge owns the admitted TUN flow, routing plan, shutdown, and permits"
)]
pub(super) async fn bridge_raw_dns_tcp_flow(
    handle: SocketHandle,
    generation: u64,
    client_target: Target,
    plan: Arc<DnsProxyPlan>,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<StackToRemoteData>,
    mut shutdown: watch::Receiver<bool>,
    pending_open: OwnedSemaphorePermit,
    dns_flow_permit: Option<OwnedSemaphorePermit>,
) {
    drop(pending_open);
    let mut close_guard = TcpBridgeCloseGuard::new(handle, generation, context.stack_tx.clone());
    let opened = tokio::select! {
        biased;
        () = wait_for_tun_shutdown(&mut shutdown) => false,
        result = timeout(
            DNS_TCP_PROXY_ATTEMPT_TIMEOUT,
            context.stack_tx.send(StackEvent::RemoteOpened { handle, generation }),
        ) => matches!(result, Ok(Ok(()))),
    };
    if !opened {
        return;
    }

    let idle_timeout = context.inbound_policy.conn_idle;
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);
    let mut client_decoder = DnsTcpFrameDecoder::default();
    let mut initial_upload = VecDeque::new();
    let first_frame = loop {
        let event = tokio::select! {
            biased;
            () = wait_for_tun_shutdown(&mut shutdown) => RawDnsTcpLoopEvent::Shutdown,
            () = &mut idle_sleep => RawDnsTcpLoopEvent::Idle,
            data = from_stack.recv() => RawDnsTcpLoopEvent::Client(data),
        };
        let RawDnsTcpLoopEvent::Client(Some(data)) = event else {
            if matches!(event, RawDnsTcpLoopEvent::Idle) {
                bounded_raw_dns_tcp_close(&mut close_guard, true).await;
            } else {
                bounded_raw_dns_tcp_close(&mut close_guard, false).await;
            }
            return;
        };
        let buffered = client_decoder
            .buffered_len()
            .saturating_add(data.data.len());
        if buffered > MAX_RAW_DNS_TCP_PENDING_BYTES {
            bounded_raw_dns_tcp_close(&mut close_guard, true).await;
            return;
        }
        client_decoder.push(&data.data);
        initial_upload.push_back(data);
        idle_sleep
            .as_mut()
            .reset(TokioInstant::now() + idle_timeout);
        match client_decoder.next_frame() {
            Ok(Some(frame)) => break frame,
            Ok(None) => {}
            Err(_) => {
                bounded_raw_dns_tcp_close(&mut close_guard, true).await;
                return;
            }
        }
    };

    if raw_dns_tcp_client_frame_kind(&first_frame[2..]) == RawDnsTcpClientFrameKind::Transparent {
        bridge_preopened_dns_tcp_flow(
            handle,
            generation,
            client_target,
            plan,
            context,
            from_stack,
            shutdown,
            dns_flow_permit,
            close_guard,
            initial_upload,
        )
        .await;
        return;
    }
    let mut upload_ledger = RawDnsTcpUploadLedger::default();
    while let Some(data) = initial_upload.pop_front() {
        if !upload_ledger.push(data) {
            bounded_raw_dns_tcp_close(&mut close_guard, true).await;
            return;
        }
    }
    let Some(first_upload_frame_id) = upload_ledger.register_frame(first_frame.len()) else {
        bounded_raw_dns_tcp_close(&mut close_guard, true).await;
        return;
    };
    let mut pending = RawDnsTcpPendingQueries::default();
    if !pending.push_with_preferred_candidate(
        first_frame,
        TokioInstant::now(),
        None,
        Some(first_upload_frame_id),
    ) {
        bounded_raw_dns_tcp_close(&mut close_guard, true).await;
        return;
    }
    let mut upstream: Option<RawDnsTcpUpstreamSession> = None;
    let mut upstream_buffer = vec![0_u8; BRIDGE_READ_BUFFER_SIZE];
    let mut next_generation = 1_u64;

    loop {
        let preferred_candidate = upstream.as_ref().map(|session| session.candidate_index);
        let client_drain_more = match drain_raw_dns_client_frames(
            &mut client_decoder,
            &mut pending,
            &mut upload_ledger,
            preferred_candidate,
            handle,
            generation,
            &context,
            &mut shutdown,
        )
        .await
        {
            RawDnsTcpDrainResult::Complete => false,
            RawDnsTcpDrainResult::More => true,
            RawDnsTcpDrainResult::Close => {
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
                bounded_raw_dns_tcp_close(&mut close_guard, true).await;
                return;
            }
            RawDnsTcpDrainResult::Shutdown => {
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
                bounded_raw_dns_tcp_close(&mut close_guard, false).await;
                return;
            }
        };
        let now = TokioInstant::now();
        if upstream
            .as_ref()
            .is_some_and(|session| pending.generation_has_expired_query(session.generation, now))
        {
            context.tun.record_tcp_remote_read_error();
            retire_raw_dns_tcp_upstream(
                &mut upstream,
                &mut pending,
                &context,
                RawDnsTcpRetireReason::Timeout(now),
            );
        }
        match fail_finished_raw_dns_queries(
            &mut pending,
            plan.upstreams().len(),
            handle,
            generation,
            &context,
            &mut upload_ledger,
            &mut shutdown,
        )
        .await
        {
            RawDnsTcpIoResult::Complete => {}
            RawDnsTcpIoResult::Shutdown => {
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
                bounded_raw_dns_tcp_close(&mut close_guard, false).await;
                return;
            }
            RawDnsTcpIoResult::Failed | RawDnsTcpIoResult::TimedOut => {
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
                bounded_raw_dns_tcp_close(&mut close_guard, true).await;
                return;
            }
        }

        if let Some(session) = upstream.as_mut() {
            pending.prepare_candidate(
                session.candidate_index,
                plan.upstreams().len(),
                session.generation,
                TokioInstant::now(),
            );
            if pending.has_unsent_generation(session.generation) {
                match write_raw_dns_pending(
                    session,
                    &mut pending,
                    &mut upload_ledger,
                    &context,
                    &mut shutdown,
                )
                .await
                {
                    RawDnsTcpIoResult::Complete => {}
                    RawDnsTcpIoResult::Failed => {
                        retire_raw_dns_tcp_upstream(
                            &mut upstream,
                            &mut pending,
                            &context,
                            RawDnsTcpRetireReason::CandidateFailure,
                        );
                        continue;
                    }
                    RawDnsTcpIoResult::TimedOut => {
                        retire_raw_dns_tcp_upstream(
                            &mut upstream,
                            &mut pending,
                            &context,
                            RawDnsTcpRetireReason::Timeout(TokioInstant::now()),
                        );
                        continue;
                    }
                    RawDnsTcpIoResult::Shutdown => {
                        retire_raw_dns_tcp_upstream(
                            &mut upstream,
                            &mut pending,
                            &context,
                            RawDnsTcpRetireReason::CandidateFailure,
                        );
                        bounded_raw_dns_tcp_close(&mut close_guard, false).await;
                        return;
                    }
                }
            }
            if !pending.has_generation(session.generation) && !pending.is_empty() {
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
                continue;
            }
        } else if !pending.is_empty() {
            let Some(candidate_index) = pending.next_candidate(plan.upstreams().len()) else {
                continue;
            };
            let attempt_generation = next_generation;
            next_generation = next_generation.wrapping_add(1).max(1);
            let Some(candidate_deadline) = pending.prepare_candidate(
                candidate_index,
                plan.upstreams().len(),
                attempt_generation,
                TokioInstant::now(),
            ) else {
                continue;
            };
            match open_raw_dns_tcp_candidate(
                candidate_index,
                candidate_deadline,
                plan.as_ref(),
                &client_target,
                &context,
                &mut shutdown,
            )
            .await
            {
                RawDnsTcpOpenResult::Opened(opened) => {
                    upstream = Some(RawDnsTcpUpstreamSession {
                        stream: opened.stream,
                        decoder: DnsTcpFrameDecoder::default(),
                        candidate_index,
                        generation: attempt_generation,
                        target: opened.target,
                        outbound_tag: opened.outbound_tag,
                        timing: opened.timing,
                    });
                    continue;
                }
                RawDnsTcpOpenResult::Failed => {
                    pending.retire_generation_preserving_attempts(attempt_generation);
                    continue;
                }
                RawDnsTcpOpenResult::TimedOut => {
                    pending.retire_generation_for_timeout(
                        attempt_generation,
                        candidate_index,
                        TokioInstant::now(),
                    );
                    continue;
                }
                RawDnsTcpOpenResult::Shutdown => {
                    bounded_raw_dns_tcp_close(&mut close_guard, false).await;
                    return;
                }
            }
        }

        let now = TokioInstant::now();
        let wake_deadline = pending
            .nearest_deadline()
            .unwrap_or_else(|| now + idle_timeout);
        let deadline_sleep = tokio::time::sleep_until(wake_deadline);
        tokio::pin!(deadline_sleep);
        let can_read_client = pending.len() < MAX_RAW_DNS_TCP_PENDING_QUERIES
            && pending
                .buffered_bytes()
                .saturating_add(client_decoder.buffered_len())
                < MAX_RAW_DNS_TCP_PENDING_BYTES;
        let event = if let Some(session) = upstream.as_mut() {
            tokio::select! {
                biased;
                () = wait_for_tun_shutdown(&mut shutdown) => RawDnsTcpLoopEvent::Shutdown,
                () = &mut idle_sleep => RawDnsTcpLoopEvent::Idle,
                () = &mut deadline_sleep => RawDnsTcpLoopEvent::Deadline,
                read = session.stream.read(&mut upstream_buffer) => RawDnsTcpLoopEvent::Upstream(read),
                () = tokio::task::yield_now(), if client_drain_more => RawDnsTcpLoopEvent::Drain,
                data = from_stack.recv(), if can_read_client => RawDnsTcpLoopEvent::Client(data),
            }
        } else {
            tokio::select! {
                biased;
                () = wait_for_tun_shutdown(&mut shutdown) => RawDnsTcpLoopEvent::Shutdown,
                () = &mut idle_sleep => RawDnsTcpLoopEvent::Idle,
                () = &mut deadline_sleep => RawDnsTcpLoopEvent::Deadline,
                () = tokio::task::yield_now(), if client_drain_more => RawDnsTcpLoopEvent::Drain,
                data = from_stack.recv(), if can_read_client => RawDnsTcpLoopEvent::Client(data),
            }
        };

        match event {
            RawDnsTcpLoopEvent::Drain => {}
            RawDnsTcpLoopEvent::Client(Some(data)) => {
                let total_buffered = pending
                    .buffered_bytes()
                    .saturating_add(client_decoder.buffered_len())
                    .saturating_add(data.data.len());
                if total_buffered > MAX_RAW_DNS_TCP_PENDING_BYTES {
                    retire_raw_dns_tcp_upstream(
                        &mut upstream,
                        &mut pending,
                        &context,
                        RawDnsTcpRetireReason::CandidateFailure,
                    );
                    bounded_raw_dns_tcp_close(&mut close_guard, true).await;
                    return;
                }
                let bytes = data.data.clone();
                if !upload_ledger.push(data) {
                    retire_raw_dns_tcp_upstream(
                        &mut upstream,
                        &mut pending,
                        &context,
                        RawDnsTcpRetireReason::CandidateFailure,
                    );
                    bounded_raw_dns_tcp_close(&mut close_guard, true).await;
                    return;
                }
                client_decoder.push(&bytes);
                idle_sleep
                    .as_mut()
                    .reset(TokioInstant::now() + idle_timeout);
            }
            RawDnsTcpLoopEvent::Client(None) | RawDnsTcpLoopEvent::Shutdown => {
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
                bounded_raw_dns_tcp_close(&mut close_guard, false).await;
                return;
            }
            RawDnsTcpLoopEvent::Idle => {
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
                bounded_raw_dns_tcp_close(&mut close_guard, true).await;
                return;
            }
            RawDnsTcpLoopEvent::Deadline => {
                let now = TokioInstant::now();
                if let Some(session) = upstream.as_ref() {
                    let attempt_expired = pending.entries.iter().any(|query| {
                        query.generation == session.generation
                            && query
                                .attempt_deadline
                                .is_some_and(|deadline| deadline <= now)
                    });
                    if attempt_expired {
                        context.tun.record_tcp_remote_read_error();
                        retire_raw_dns_tcp_upstream(
                            &mut upstream,
                            &mut pending,
                            &context,
                            RawDnsTcpRetireReason::Timeout(now),
                        );
                    }
                }
            }
            RawDnsTcpLoopEvent::Upstream(Ok(0)) => {
                context.tun.record_tcp_remote_closed();
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
            }
            RawDnsTcpLoopEvent::Upstream(Err(_)) => {
                context.tun.record_tcp_remote_read_error();
                retire_raw_dns_tcp_upstream(
                    &mut upstream,
                    &mut pending,
                    &context,
                    RawDnsTcpRetireReason::CandidateFailure,
                );
            }
            RawDnsTcpLoopEvent::Upstream(Ok(read)) => {
                context.tun.record_tcp_remote_read(read);
                idle_sleep
                    .as_mut()
                    .reset(TokioInstant::now() + idle_timeout);
                let Some(session) = upstream.as_mut() else {
                    continue;
                };
                if let Some(timing) = session.timing.as_mut() {
                    timing.record_first_byte(context.tun.as_ref(), &session.target);
                    timing.record_remote_read(context.tun.as_ref(), &session.target, read);
                }
                session.decoder.push(&upstream_buffer[..read]);
                match handle_raw_dns_upstream_frames(
                    session,
                    &mut pending,
                    handle,
                    generation,
                    &context,
                    &mut shutdown,
                )
                .await
                {
                    RawDnsTcpUpstreamFramesResult::Continue => {}
                    RawDnsTcpUpstreamFramesResult::Retire => {
                        retire_raw_dns_tcp_upstream(
                            &mut upstream,
                            &mut pending,
                            &context,
                            RawDnsTcpRetireReason::CandidateFailure,
                        );
                    }
                    RawDnsTcpUpstreamFramesResult::Close => {
                        retire_raw_dns_tcp_upstream(
                            &mut upstream,
                            &mut pending,
                            &context,
                            RawDnsTcpRetireReason::CandidateFailure,
                        );
                        bounded_raw_dns_tcp_close(&mut close_guard, true).await;
                        return;
                    }
                    RawDnsTcpUpstreamFramesResult::Shutdown => {
                        retire_raw_dns_tcp_upstream(
                            &mut upstream,
                            &mut pending,
                            &context,
                            RawDnsTcpRetireReason::CandidateFailure,
                        );
                        bounded_raw_dns_tcp_close(&mut close_guard, false).await;
                        return;
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawDnsTcpUpstreamFramesResult {
    Continue,
    Retire,
    Close,
    Shutdown,
}

fn raw_dns_candidate_bit(candidate_index: usize) -> u16 {
    let shift = u32::try_from(candidate_index).unwrap_or(u32::MAX);
    1_u16.checked_shl(shift).unwrap_or(0)
}

fn raw_dns_next_candidate(
    attempted_candidates: u16,
    preferred_candidate: Option<usize>,
    candidate_count: usize,
) -> Option<usize> {
    if let Some(candidate_index) = preferred_candidate.filter(|index| *index < candidate_count) {
        if attempted_candidates & raw_dns_candidate_bit(candidate_index) == 0 {
            return Some(candidate_index);
        }
    }
    (0..candidate_count).find(|index| {
        let mask = raw_dns_candidate_bit(*index);
        attempted_candidates & mask == 0
    })
}

fn raw_dns_all_candidates_mask(candidate_count: usize) -> u16 {
    if candidate_count >= u16::BITS as usize {
        u16::MAX
    } else {
        let shift = u32::try_from(candidate_count).unwrap_or(u32::MAX);
        1_u16.checked_shl(shift).unwrap_or(0).saturating_sub(1)
    }
}

fn raw_dns_tcp_client_frame_kind(message: &[u8]) -> RawDnsTcpClientFrameKind {
    if !dns_wire_envelope_is_well_formed(message) {
        return RawDnsTcpClientFrameKind::Transparent;
    }
    let Some(flags) = read_dns_wire_u16(message, 2) else {
        return RawDnsTcpClientFrameKind::Transparent;
    };
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 || read_dns_wire_u16(message, 4) != Some(1) {
        return RawDnsTcpClientFrameKind::Transparent;
    }
    let Some(question_end) = dns_question_section_end(message) else {
        return RawDnsTcpClientFrameKind::Transparent;
    };
    let Some(question_type_offset) = question_end.checked_sub(4) else {
        return RawDnsTcpClientFrameKind::Transparent;
    };
    match read_dns_wire_u16(message, question_type_offset) {
        Some(DNS_TYPE_AXFR | DNS_TYPE_IXFR) | None => RawDnsTcpClientFrameKind::Transparent,
        Some(_) => RawDnsTcpClientFrameKind::Query,
    }
}

fn raw_dns_tcp_response_kind(message: &[u8]) -> Option<RawDnsTcpResponseKind> {
    if !dns_wire_envelope_is_well_formed(message) {
        return None;
    }
    let flags = read_dns_wire_u16(message, 2)?;
    if flags & 0x8000 == 0 {
        return None;
    }
    if flags & 0x0200 != 0 || flags & 0x000f == DNS_RCODE_SERVFAIL {
        Some(RawDnsTcpResponseKind::Retry)
    } else {
        Some(RawDnsTcpResponseKind::Terminal)
    }
}

fn dns_wire_envelope_is_well_formed(message: &[u8]) -> bool {
    let Some(question_count) = read_dns_wire_u16(message, 4).map(usize::from) else {
        return false;
    };
    let Some(answer_count) = read_dns_wire_u16(message, 6).map(usize::from) else {
        return false;
    };
    let Some(authority_count) = read_dns_wire_u16(message, 8).map(usize::from) else {
        return false;
    };
    let Some(additional_count) = read_dns_wire_u16(message, 10).map(usize::from) else {
        return false;
    };
    let mut offset = 12usize;
    for _ in 0..question_count {
        if validate_dns_wire_name(message, &mut offset).is_none() {
            return false;
        }
        let Some(question_end) = offset.checked_add(4) else {
            return false;
        };
        if message.get(offset..question_end).is_none() {
            return false;
        }
        offset = question_end;
    }
    for record_count in [answer_count, authority_count, additional_count] {
        for _ in 0..record_count {
            if validate_dns_wire_name(message, &mut offset).is_none() {
                return false;
            }
            let Some(record_header_end) = offset.checked_add(10) else {
                return false;
            };
            if message.get(offset..record_header_end).is_none() {
                return false;
            }
            let Some(data_len_offset) = offset.checked_add(8) else {
                return false;
            };
            let Some(data_len) = read_dns_wire_u16(message, data_len_offset).map(usize::from)
            else {
                return false;
            };
            let Some(record_end) = record_header_end.checked_add(data_len) else {
                return false;
            };
            if message.get(record_header_end..record_end).is_none() {
                return false;
            }
            offset = record_end;
        }
    }
    offset == message.len()
}

fn validate_dns_wire_name(message: &[u8], offset: &mut usize) -> Option<()> {
    let mut cursor = *offset;
    let mut encoded_end = None;
    let mut expanded_len = 0usize;
    for _ in 0..128 {
        let label_offset = cursor;
        let label_len = *message.get(cursor)?;
        cursor = cursor.checked_add(1)?;
        match label_len & 0xc0 {
            0x00 if label_len == 0 => {
                expanded_len = expanded_len.checked_add(1)?;
                if expanded_len > 255 {
                    return None;
                }
                *offset = encoded_end.unwrap_or(cursor);
                return Some(());
            }
            0x00 => {
                let label_len = usize::from(label_len);
                if label_len > 63 {
                    return None;
                }
                let label_end = cursor.checked_add(label_len)?;
                message.get(cursor..label_end)?;
                expanded_len = expanded_len.checked_add(label_len + 1)?;
                if expanded_len > 255 {
                    return None;
                }
                cursor = label_end;
            }
            0xc0 => {
                let pointer_low = usize::from(*message.get(cursor)?);
                let pointer = (usize::from(label_len & 0x3f) << 8) | pointer_low;
                if pointer < 12 || pointer >= label_offset {
                    return None;
                }
                encoded_end.get_or_insert(cursor.checked_add(1)?);
                cursor = pointer;
            }
            _ => return None,
        }
    }
    None
}

#[expect(
    clippy::too_many_arguments,
    reason = "client frame draining keeps flow identity, upload accounting, and shutdown explicit"
)]
async fn drain_raw_dns_client_frames(
    decoder: &mut DnsTcpFrameDecoder,
    pending: &mut RawDnsTcpPendingQueries,
    upload_ledger: &mut RawDnsTcpUploadLedger,
    preferred_candidate: Option<usize>,
    handle: SocketHandle,
    generation: u64,
    context: &TunRuntimeContext,
    shutdown: &mut watch::Receiver<bool>,
) -> RawDnsTcpDrainResult {
    let mut processed = 0usize;
    while pending.len() < MAX_RAW_DNS_TCP_PENDING_QUERIES && processed < RAW_DNS_TCP_DRAIN_QUANTUM {
        let frame = match decoder.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => return RawDnsTcpDrainResult::Complete,
            Err(_) => return RawDnsTcpDrainResult::Close,
        };
        processed = processed.saturating_add(1);
        let Some(upload_frame_id) = upload_ledger.register_frame(frame.len()) else {
            return RawDnsTcpDrainResult::Close;
        };
        let payload = &frame[2..];
        match raw_dns_tcp_client_frame_kind(payload) {
            RawDnsTcpClientFrameKind::Query => {
                if !pending.push_with_preferred_candidate(
                    frame,
                    TokioInstant::now(),
                    preferred_candidate,
                    Some(upload_frame_id),
                ) {
                    return RawDnsTcpDrainResult::Close;
                }
            }
            RawDnsTcpClientFrameKind::Transparent => {
                let Some(response) = framed_dns_error_response(payload, DNS_RCODE_REFUSED) else {
                    return RawDnsTcpDrainResult::Close;
                };
                match send_raw_dns_tcp_frame(handle, generation, response, context, shutdown).await
                {
                    RawDnsTcpIoResult::Complete => {
                        if !upload_ledger.commit_frame(upload_frame_id) {
                            return RawDnsTcpDrainResult::Close;
                        }
                    }
                    RawDnsTcpIoResult::Shutdown => return RawDnsTcpDrainResult::Shutdown,
                    RawDnsTcpIoResult::Failed | RawDnsTcpIoResult::TimedOut => {
                        return RawDnsTcpDrainResult::Close;
                    }
                }
            }
        }
    }
    if pending.len() >= MAX_RAW_DNS_TCP_PENDING_QUERIES {
        return RawDnsTcpDrainResult::Complete;
    }
    match decoder.peek_frame_len() {
        Ok(Some(_)) => RawDnsTcpDrainResult::More,
        Ok(None) => RawDnsTcpDrainResult::Complete,
        Err(_) => RawDnsTcpDrainResult::Close,
    }
}

async fn fail_finished_raw_dns_queries(
    pending: &mut RawDnsTcpPendingQueries,
    candidate_count: usize,
    handle: SocketHandle,
    generation: u64,
    context: &TunRuntimeContext,
    upload_ledger: &mut RawDnsTcpUploadLedger,
    shutdown: &mut watch::Receiver<bool>,
) -> RawDnsTcpIoResult {
    loop {
        let Some(index) = pending.next_failed_index(candidate_count, TokioInstant::now()) else {
            return RawDnsTcpIoResult::Complete;
        };
        let Some(query) = pending.remove(index) else {
            return RawDnsTcpIoResult::Failed;
        };
        let Some(response) = framed_dns_error_response(&query.payload, DNS_RCODE_SERVFAIL) else {
            return RawDnsTcpIoResult::Failed;
        };
        let result = send_raw_dns_tcp_frame(handle, generation, response, context, shutdown).await;
        if result != RawDnsTcpIoResult::Complete {
            return result;
        }
        if query
            .upload_frame_id
            .is_some_and(|upload_frame_id| !upload_ledger.commit_frame(upload_frame_id))
        {
            return RawDnsTcpIoResult::Failed;
        }
    }
}

fn framed_dns_error_response(query: &[u8], rcode: u16) -> Option<Bytes> {
    let response = dns_error_response(query, rcode, false)?;
    if !dns_response_matches_query(query, &response) {
        return None;
    }
    let response_len = u16::try_from(response.len()).ok()?;
    let mut framed = BytesMut::with_capacity(response.len() + 2);
    framed.extend_from_slice(&response_len.to_be_bytes());
    framed.extend_from_slice(&response);
    Some(framed.freeze())
}

async fn send_raw_dns_tcp_frame(
    handle: SocketHandle,
    generation: u64,
    frame: Bytes,
    context: &TunRuntimeContext,
    shutdown: &mut watch::Receiver<bool>,
) -> RawDnsTcpIoResult {
    let result = tokio::select! {
        biased;
        () = wait_for_tun_shutdown(shutdown) => return RawDnsTcpIoResult::Shutdown,
        result = timeout(
            DNS_TCP_PROXY_ATTEMPT_TIMEOUT,
            context.stack_tx.send(StackEvent::RemoteData {
                handle,
                generation,
                data: frame,
            }),
        ) => result,
    };
    match result {
        Ok(Ok(())) => RawDnsTcpIoResult::Complete,
        Ok(Err(_)) => RawDnsTcpIoResult::Failed,
        Err(_) => RawDnsTcpIoResult::TimedOut,
    }
}

async fn bounded_raw_dns_tcp_close(close_guard: &mut TcpBridgeCloseGuard, abort: bool) {
    let close = async {
        if abort {
            close_guard.abort().await;
        } else {
            close_guard.close().await;
        }
    };
    let _ = timeout(DNS_TCP_PROXY_ATTEMPT_TIMEOUT, close).await;
}

async fn write_raw_dns_pending(
    session: &mut RawDnsTcpUpstreamSession,
    pending: &mut RawDnsTcpPendingQueries,
    upload_ledger: &mut RawDnsTcpUploadLedger,
    context: &TunRuntimeContext,
    shutdown: &mut watch::Receiver<bool>,
) -> RawDnsTcpIoResult {
    let frames = pending
        .entries
        .iter()
        .filter(|query| query.generation == session.generation && !query.sent)
        .map(|query| (query.framed.clone(), query.attempt_deadline))
        .collect::<Vec<_>>();
    if frames.is_empty() {
        return RawDnsTcpIoResult::Complete;
    }
    let now = TokioInstant::now();
    let deadline = frames
        .iter()
        .filter_map(|(_, deadline)| *deadline)
        .min()
        .unwrap_or(now);
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        context.tun.record_tcp_remote_write_error();
        return RawDnsTcpIoResult::TimedOut;
    }
    let bytes = frames.iter().fold(0usize, |total, (frame, _)| {
        total.saturating_add(frame.len())
    });
    let messages = frames.len();
    let write_start = StdInstant::now();
    let mut result = RawDnsTcpIoResult::Complete;
    let mut bytes_since_yield = 0usize;
    'write: for (frame, _) in &frames {
        let frame_result = tokio::select! {
            biased;
            () = wait_for_tun_shutdown(shutdown) => RawDnsTcpIoResult::Shutdown,
            result = timeout_at(deadline, session.stream.write_all(frame)) => match result {
                Ok(Ok(())) => RawDnsTcpIoResult::Complete,
                Ok(Err(_)) => RawDnsTcpIoResult::Failed,
                Err(_) => RawDnsTcpIoResult::TimedOut,
            },
        };
        if frame_result != RawDnsTcpIoResult::Complete {
            result = frame_result;
            break 'write;
        }
        bytes_since_yield = bytes_since_yield.saturating_add(frame.len());
        if bytes_since_yield >= RAW_DNS_TCP_WRITE_QUANTUM_BYTES {
            bytes_since_yield = 0;
            let shutdown_requested = tokio::select! {
                biased;
                () = wait_for_tun_shutdown(shutdown) => true,
                () = tokio::task::yield_now() => false,
            };
            if shutdown_requested {
                result = RawDnsTcpIoResult::Shutdown;
                break 'write;
            }
        }
    }
    if result == RawDnsTcpIoResult::Complete {
        result = tokio::select! {
            biased;
            () = wait_for_tun_shutdown(shutdown) => RawDnsTcpIoResult::Shutdown,
            flush = timeout_at(deadline, session.stream.flush()) => match flush {
                Ok(Ok(())) => RawDnsTcpIoResult::Complete,
                Ok(Err(_)) => RawDnsTcpIoResult::Failed,
                Err(_) => RawDnsTcpIoResult::TimedOut,
            },
        };
    }
    let write_duration_ms = elapsed_ms_since(&write_start);
    context.tun.record_tcp_remote_write_wait(write_duration_ms);
    record_tcp_remote_write_slow_event(
        context.tun.as_ref(),
        &session.target,
        session.outbound_tag.as_deref(),
        write_duration_ms,
        bytes,
        messages,
    );
    if matches!(
        result,
        RawDnsTcpIoResult::Failed | RawDnsTcpIoResult::TimedOut
    ) {
        context.tun.record_tcp_remote_write_error();
    }
    if result != RawDnsTcpIoResult::Complete {
        return result;
    }
    context.tun.record_tcp_remote_written(bytes);
    context.tun.record_tcp_remote_write_batch(messages, bytes);
    let upload_frame_ids = pending.mark_generation_sent(session.generation);
    if upload_frame_ids
        .into_iter()
        .any(|upload_frame_id| !upload_ledger.commit_frame(upload_frame_id))
    {
        context.tun.record_tcp_remote_write_error();
        return RawDnsTcpIoResult::Failed;
    }
    RawDnsTcpIoResult::Complete
}

async fn handle_raw_dns_upstream_frames(
    session: &mut RawDnsTcpUpstreamSession,
    pending: &mut RawDnsTcpPendingQueries,
    handle: SocketHandle,
    generation: u64,
    context: &TunRuntimeContext,
    shutdown: &mut watch::Receiver<bool>,
) -> RawDnsTcpUpstreamFramesResult {
    let mut processed = 0usize;
    loop {
        let frame = match session.decoder.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => return RawDnsTcpUpstreamFramesResult::Continue,
            Err(_) => {
                context.tun.record_tcp_remote_read_error();
                return RawDnsTcpUpstreamFramesResult::Retire;
            }
        };
        let response = &frame[2..];
        let Some(response_kind) = raw_dns_tcp_response_kind(response) else {
            context.tun.record_tcp_remote_read_error();
            return RawDnsTcpUpstreamFramesResult::Retire;
        };
        let Some(index) = pending.matching_response_index(session.generation, response) else {
            context.tun.record_tcp_remote_read_error();
            return RawDnsTcpUpstreamFramesResult::Retire;
        };
        if response_kind == RawDnsTcpResponseKind::Retry {
            return RawDnsTcpUpstreamFramesResult::Retire;
        }
        match send_raw_dns_tcp_frame(handle, generation, frame, context, shutdown).await {
            RawDnsTcpIoResult::Complete => {}
            RawDnsTcpIoResult::Shutdown => return RawDnsTcpUpstreamFramesResult::Shutdown,
            RawDnsTcpIoResult::Failed | RawDnsTcpIoResult::TimedOut => {
                return RawDnsTcpUpstreamFramesResult::Close;
            }
        }
        if pending.remove(index).is_none() {
            return RawDnsTcpUpstreamFramesResult::Close;
        }
        processed = processed.saturating_add(1);
        if processed >= RAW_DNS_TCP_DRAIN_QUANTUM {
            processed = 0;
            let shutdown_requested = tokio::select! {
                biased;
                () = wait_for_tun_shutdown(shutdown) => true,
                () = tokio::task::yield_now() => false,
            };
            if shutdown_requested {
                return RawDnsTcpUpstreamFramesResult::Shutdown;
            }
        }
    }
}

async fn open_raw_dns_tcp_candidate(
    candidate_index: usize,
    candidate_deadline: TokioInstant,
    plan: &DnsProxyPlan,
    client_target: &Target,
    context: &TunRuntimeContext,
    shutdown: &mut watch::Receiver<bool>,
) -> RawDnsTcpOpenResult {
    let Some(upstream) = plan.upstreams().get(candidate_index) else {
        return RawDnsTcpOpenResult::Failed;
    };
    let target = upstream.target(RoutingNetwork::Tcp);
    let routing_inbound_tag = upstream.inbound_tag();
    let collect_tcp_timings = context.tun_runtime_options.collect_tcp_timings;
    let open_started = collect_tcp_timings.then(StdInstant::now);
    let selection = if upstream.is_local() {
        Ok((TcpOutbound::Freedom, None))
    } else {
        context
            .outbound_router
            .select_tcp_outbound_for_session_with_tag(
                Some(routing_inbound_tag),
                &target,
                collect_tcp_timings,
            )
            .map(|selection| (selection.outbound, selection.tag))
            .map_err(|error| error.to_string())
    };
    let (outbound, outbound_tag) = match selection {
        Ok(selection) => selection,
        Err(error) => {
            record_raw_dns_tcp_open_failure(context, client_target, None, &error);
            return RawDnsTcpOpenResult::Failed;
        }
    };
    let remaining = candidate_deadline.saturating_duration_since(TokioInstant::now());
    if remaining.is_zero() {
        record_raw_dns_tcp_open_failure(
            context,
            client_target,
            outbound_tag.as_deref(),
            "DNS TCP proxy candidate deadline elapsed",
        );
        return RawDnsTcpOpenResult::TimedOut;
    }
    let policy_timeout = match &outbound {
        TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => {
            context.inbound_policy.handshake
        }
        TcpOutbound::Vless(outbound) => {
            effective_policy_for_level(&context.config, Some(outbound.user().level)).handshake
        }
    };
    let policy_deadline = TokioInstant::now() + DNS_TCP_PROXY_ATTEMPT_TIMEOUT.min(policy_timeout);
    let open_deadline = candidate_deadline.min(policy_deadline);
    let result = tokio::select! {
        biased;
        () = wait_for_tun_shutdown(shutdown) => return RawDnsTcpOpenResult::Shutdown,
        result = timeout_at(
            open_deadline,
            open_tcp_bridge_stream(&outbound, &target, Some(upstream), context),
        ) => result,
    };
    let stream = match result {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            record_raw_dns_tcp_open_failure(
                context,
                client_target,
                outbound_tag.as_deref(),
                &error.to_string(),
            );
            return RawDnsTcpOpenResult::Failed;
        }
        Err(_) => {
            record_raw_dns_tcp_open_failure(
                context,
                client_target,
                outbound_tag.as_deref(),
                "DNS TCP upstream open timed out",
            );
            return if candidate_deadline <= TokioInstant::now() {
                RawDnsTcpOpenResult::TimedOut
            } else {
                RawDnsTcpOpenResult::Failed
            };
        }
    };
    let outbound_label = outbound_tag
        .as_deref()
        .unwrap_or_else(|| crate::debug_log::tcp_outbound_label(&outbound));
    if context.runtime_logger.is_enabled() {
        crate::debug_log::log_route_decision(
            &context.runtime_logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: Some(routing_inbound_tag),
                network: client_target.network,
                original_target: client_target,
                sniffed_protocol: None,
                route_target: &target,
                dial_target: &target,
                selected_outbound: outbound_label,
            },
        );
        crate::debug_log::log_access_accepted(
            &context.runtime_logger,
            "tun",
            client_target,
            outbound_label,
        );
    }
    let timing = open_started.map(|open_started| {
        let duration_ms = elapsed_ms_since(&open_started);
        context.tun.record_tcp_open_timing(duration_ms, false);
        record_tcp_slow_flow_event(
            context.tun.as_ref(),
            client_target,
            TunTcpSlowFlowKind::Open,
            duration_ms,
            0,
        );
        TcpFirstByteTimingEnabled::new(open_started, false, duration_ms, outbound_tag.clone())
    });
    RawDnsTcpOpenResult::Opened(RawDnsTcpOpenedCandidate {
        stream,
        target,
        outbound_tag,
        timing,
    })
}

fn record_raw_dns_tcp_open_failure(
    context: &TunRuntimeContext,
    client_target: &Target,
    outbound_tag: Option<&str>,
    error: &str,
) {
    context.tun.record_tcp_open_error();
    record_tcp_open_error_event(context.tun.as_ref(), client_target, outbound_tag, error);
    if context.runtime_logger.is_enabled() {
        crate::debug_log::log_access_rejected(&context.runtime_logger, "tun", client_target, error);
    }
}

struct FakeDnsTcpDecodeResult {
    response: Option<Bytes>,
    processed_message: bool,
    terminal_error: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsTcpFrameDecodeError {
    ZeroLength,
    MessageTooLarge,
}

#[derive(Debug, Default)]
struct DnsTcpFrameDecoder {
    buffered: BytesMut,
    terminal_error: Option<DnsTcpFrameDecodeError>,
}

impl DnsTcpFrameDecoder {
    fn push(&mut self, chunk: &[u8]) {
        self.buffered.extend_from_slice(chunk);
    }

    fn buffered_len(&self) -> usize {
        self.buffered.len()
    }

    fn peek_frame_len(&mut self) -> Result<Option<usize>, DnsTcpFrameDecodeError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        if self.buffered.len() < 2 {
            return Ok(None);
        }

        let message_len = usize::from(u16::from_be_bytes([self.buffered[0], self.buffered[1]]));
        let error = if message_len == 0 {
            Some(DnsTcpFrameDecodeError::ZeroLength)
        } else if message_len > MAX_DNS_TCP_MESSAGE_SIZE {
            Some(DnsTcpFrameDecodeError::MessageTooLarge)
        } else {
            None
        };
        if let Some(error) = error {
            self.terminal_error = Some(error);
            return Err(error);
        }

        let frame_len = message_len + 2;
        if self.buffered.len() < frame_len {
            return Ok(None);
        }

        Ok(Some(frame_len))
    }

    fn next_frame(&mut self) -> Result<Option<Bytes>, DnsTcpFrameDecodeError> {
        let Some(frame_len) = self.peek_frame_len()? else {
            return Ok(None);
        };
        Ok(Some(self.buffered.split_to(frame_len).freeze()))
    }
}

fn fake_ip_tcp_responses(
    mapper: &Arc<Mutex<FakeIpMapper>>,
    decoder: &mut DnsTcpFrameDecoder,
) -> FakeDnsTcpDecodeResult {
    let mut output = BytesMut::new();
    let mut processed_message = false;

    loop {
        let frame = match decoder.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(_) => return fake_dns_tcp_decode_result(output, processed_message, true),
        };
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
    let total_deadline = TokioInstant::now() + DNS_PROXY_TOTAL_TIMEOUT;
    let path_payload_cap = context.tun.mtu().saturating_sub(20 + 8);
    let max_payload = dns_udp_client_payload_limit(&packet.payload, path_payload_cap);
    let upstreams = plan.upstreams();
    for (index, upstream) in upstreams.iter().enumerate() {
        let candidate_started = TokioInstant::now();
        let remaining = total_deadline.saturating_duration_since(candidate_started);
        if remaining.is_zero() {
            break;
        }
        let remaining_candidate_count = u32::try_from(upstreams.len() - index).unwrap_or(u32::MAX);
        let candidate_budget = remaining / remaining_candidate_count;
        if candidate_budget.is_zero() {
            break;
        }
        let candidate_deadline = candidate_started + candidate_budget;
        let mut failure_phase = DnsUdpFailurePhase::Open;
        let (target, outbound_label, attempt) = match upstream.transport() {
            xray_config::DnsServerTransport::Classic => {
                let target = upstream.target(RoutingNetwork::Udp);
                let outbound = context
                    .outbound_router
                    .select_udp_outbound_for_session(Some(upstream.inbound_tag()), &target);
                let Ok(outbound) = outbound else {
                    record_dns_udp_failure(context, DnsUdpFailurePhase::Open);
                    continue;
                };
                let outbound_timeout = match &outbound {
                    UdpOutbound::Freedom => DNS_PROXY_FREEDOM_ATTEMPT_TIMEOUT,
                    UdpOutbound::Vless(_) => DNS_PROXY_VLESS_ATTEMPT_TIMEOUT,
                };
                let outbound_label = crate::debug_log::udp_outbound_label(&outbound);
                let attempt = timeout(
                    candidate_deadline
                        .saturating_duration_since(TokioInstant::now())
                        .min(outbound_timeout),
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
                (target, outbound_label, attempt)
            }
            xray_config::DnsServerTransport::TcpRouted
            | xray_config::DnsServerTransport::TcpLocal => {
                let target = upstream.target(RoutingNetwork::Tcp);
                let selected = if upstream.is_local() {
                    Ok((None, "local"))
                } else {
                    context
                        .outbound_router
                        .select_tcp_outbound_for_session_with_tag(
                            Some(upstream.inbound_tag()),
                            &target,
                            false,
                        )
                        .map(|selected| {
                            let label = crate::debug_log::tcp_outbound_label(&selected.outbound);
                            (Some(selected.outbound), label)
                        })
                };
                let Ok((outbound, outbound_label)) = selected else {
                    record_dns_udp_failure(context, DnsUdpFailurePhase::Open);
                    continue;
                };
                let attempt = timeout(
                    candidate_deadline.saturating_duration_since(TokioInstant::now()),
                    exchange_tcp_candidate_for_udp_client(
                        outbound,
                        &target,
                        upstream,
                        &packet.payload,
                        max_payload,
                        context,
                        &mut failure_phase,
                        candidate_deadline,
                    ),
                )
                .await;
                (target, outbound_label, attempt)
            }
        };
        let response = match attempt {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => {
                record_dns_udp_failure(context, failure_phase);
                continue;
            }
        };
        if upstream.transport() != xray_config::DnsServerTransport::Classic
            && !response.is_successful_tcp_response()
        {
            record_dns_udp_failure(context, DnsUdpFailurePhase::Read);
            continue;
        }
        let Some(response) = response.into_udp_client_payload(&packet.payload, max_payload) else {
            record_dns_udp_failure(context, DnsUdpFailurePhase::Read);
            continue;
        };
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

#[expect(
    clippy::too_many_arguments,
    reason = "DNS TCP candidate keeps route, query, metrics, and candidate deadline explicit"
)]
async fn exchange_tcp_candidate_for_udp_client(
    outbound: Option<TcpOutbound>,
    target: &Target,
    upstream: &DnsProxyUpstream,
    query: &[u8],
    max_payload: usize,
    context: &TunRuntimeContext,
    failure_phase: &mut DnsUdpFailurePhase,
    deadline: TokioInstant,
) -> Result<DnsUpstreamResponse, crate::CoreError> {
    let query_len = u16::try_from(query.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS TCP query is too large",
        )
    })?;
    let mut lease = context.dns_tcp_connection_pool.lease(upstream).await?;
    let (connection, response) = match lease.take_connection() {
        Some(mut connection) => {
            let reused_attempt = run_dns_tcp_network_attempt(
                deadline,
                exchange_and_validate_dns_tcp_query(
                    &mut connection.stream,
                    query,
                    query_len,
                    max_payload,
                    context,
                    failure_phase,
                ),
            )
            .await;
            if let Ok(response) = reused_attempt {
                (connection, response)
            } else {
                record_dns_udp_failure(context, *failure_phase);
                drop(connection);
                *failure_phase = DnsUdpFailurePhase::Open;
                open_and_exchange_dns_tcp_attempt(
                    outbound.as_ref(),
                    target,
                    upstream,
                    query,
                    query_len,
                    max_payload,
                    context,
                    failure_phase,
                    deadline,
                )
                .await?
            }
        }
        None => {
            open_and_exchange_dns_tcp_attempt(
                outbound.as_ref(),
                target,
                upstream,
                query,
                query_len,
                max_payload,
                context,
                failure_phase,
                deadline,
            )
            .await?
        }
    };
    lease.recycle(connection);
    Ok(response)
}

#[expect(
    clippy::too_many_arguments,
    reason = "DNS TCP attempt keeps transport, framing, metrics, and deadline explicit"
)]
async fn open_and_exchange_dns_tcp_attempt(
    outbound: Option<&TcpOutbound>,
    target: &Target,
    upstream: &DnsProxyUpstream,
    query: &[u8],
    query_len: u16,
    max_payload: usize,
    context: &TunRuntimeContext,
    failure_phase: &mut DnsUdpFailurePhase,
    deadline: TokioInstant,
) -> Result<(DnsTcpPooledConnection, DnsUpstreamResponse), crate::CoreError> {
    run_dns_tcp_network_attempt(deadline, async {
        *failure_phase = DnsUdpFailurePhase::Open;
        let mut connection =
            open_dns_tcp_pooled_connection(outbound, target, upstream, context).await?;
        let response = exchange_and_validate_dns_tcp_query(
            &mut connection.stream,
            query,
            query_len,
            max_payload,
            context,
            failure_phase,
        )
        .await?;
        Ok((connection, response))
    })
    .await
}

async fn run_dns_tcp_network_attempt<T>(
    deadline: TokioInstant,
    attempt: impl std::future::Future<Output = Result<T, crate::CoreError>>,
) -> Result<T, crate::CoreError> {
    let remaining = deadline.saturating_duration_since(TokioInstant::now());
    if remaining.is_zero() {
        return Err(dns_tcp_attempt_timeout_error());
    }
    timeout(remaining.min(DNS_TCP_PROXY_ATTEMPT_TIMEOUT), attempt)
        .await
        .map_err(|_| dns_tcp_attempt_timeout_error())?
}

fn dns_tcp_attempt_timeout_error() -> crate::CoreError {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "DNS TCP network attempt timed out",
    )
    .into()
}

async fn open_dns_tcp_pooled_connection(
    outbound: Option<&TcpOutbound>,
    target: &Target,
    upstream: &DnsProxyUpstream,
    context: &TunRuntimeContext,
) -> Result<DnsTcpPooledConnection, crate::CoreError> {
    let global_connection_permit = context.dns_tcp_connection_pool.reserve_connection_slot()?;
    let stream = match outbound {
        Some(outbound) => open_tcp_bridge_stream(outbound, target, Some(upstream), context).await?,
        None => {
            let candidates = resolve_freedom_dns_upstreams(upstream, context).await?;
            crate::dns::open_local_dns_tcp_stream(
                context.transport_dialer.as_ref(),
                target,
                &candidates,
            )
            .await?
        }
    };
    context.tun.record_udp_remote_open(false);
    Ok(DnsTcpPooledConnection {
        stream,
        last_used: TokioInstant::now(),
        _global_connection_permit: global_connection_permit,
    })
}

async fn exchange_dns_tcp_query(
    stream: &mut BoxedTransportStream,
    query: &[u8],
    query_len: u16,
    max_payload: usize,
    context: &TunRuntimeContext,
    failure_phase: &mut DnsUdpFailurePhase,
) -> Result<DnsUpstreamResponse, crate::CoreError> {
    *failure_phase = DnsUdpFailurePhase::Write;
    stream.write_u16(query_len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    context.tun.record_udp_remote_written(query.len());
    *failure_phase = DnsUdpFailurePhase::Read;
    let response = read_bounded_dns_payload(stream, max_payload).await?;
    context.tun.record_udp_remote_read(response.observed_len());
    Ok(response)
}

async fn exchange_and_validate_dns_tcp_query(
    stream: &mut BoxedTransportStream,
    query: &[u8],
    query_len: u16,
    max_payload: usize,
    context: &TunRuntimeContext,
    failure_phase: &mut DnsUdpFailurePhase,
) -> Result<DnsUpstreamResponse, crate::CoreError> {
    let response = exchange_dns_tcp_query(
        stream,
        query,
        query_len,
        max_payload,
        context,
        failure_phase,
    )
    .await?;
    if !response.matches_query(query) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS TCP response does not match the query",
        )
        .into());
    }
    Ok(response)
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
    let response_payload_size = validated_edns_request(query)
        .map(|edns| edns.udp_payload_size)
        .unwrap_or(DNS_LEGACY_UDP_PAYLOAD_SIZE);
    dns_error_response_with_payload_size(query, rcode, truncated, response_payload_size)
}

fn dns_error_response_with_payload_size(
    query: &[u8],
    rcode: u16,
    truncated: bool,
    response_payload_size: usize,
) -> Option<Bytes> {
    if query.len() < 12 {
        return None;
    }
    let question_end = dns_question_section_end(query).unwrap_or(12);
    let edns = validated_edns_request(query);
    let mut response = Vec::with_capacity(question_end + edns.map_or(0, |_| 11));
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
    if let Some(edns) = edns {
        let response_payload_size = response_payload_size
            .max(DNS_LEGACY_UDP_PAYLOAD_SIZE)
            .min(usize::from(u16::MAX));
        let response_payload_size = u16::try_from(response_payload_size).ok()?;
        response[10..12].copy_from_slice(&1_u16.to_be_bytes());
        response.push(0);
        response.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        response.extend_from_slice(&response_payload_size.to_be_bytes());
        let response_ttl = if edns.dnssec_ok { 0x8000_u32 } else { 0 };
        response.extend_from_slice(&response_ttl.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
    }
    Some(Bytes::from(response))
}

fn dns_question_section_end(message: &[u8]) -> Option<usize> {
    let question_count = usize::from(u16::from_be_bytes([*message.get(4)?, *message.get(5)?]));
    let mut offset = 12usize;
    for _ in 0..question_count {
        skip_dns_wire_name(message, &mut offset)?;
        offset = offset.checked_add(4)?;
        message.get(offset - 1)?;
    }
    Some(offset)
}

fn dns_udp_client_payload_limit(query: &[u8], path_payload_cap: usize) -> usize {
    validated_edns_request(query)
        .map(|edns| edns.udp_payload_size)
        .unwrap_or(DNS_LEGACY_UDP_PAYLOAD_SIZE)
        .max(DNS_LEGACY_UDP_PAYLOAD_SIZE)
        .min(path_payload_cap)
}

fn validated_edns_request(message: &[u8]) -> Option<EdnsRequest> {
    let question_count = usize::from(read_dns_wire_u16(message, 4)?);
    let answer_count = usize::from(read_dns_wire_u16(message, 6)?);
    let authority_count = usize::from(read_dns_wire_u16(message, 8)?);
    let additional_count = usize::from(read_dns_wire_u16(message, 10)?);
    let mut offset = 12usize;
    for _ in 0..question_count {
        skip_dns_wire_name(message, &mut offset)?;
        offset = offset.checked_add(4)?;
        message.get(offset - 1)?;
    }

    let mut advertised_size = None;
    for (record_count, is_additional) in [
        (answer_count, false),
        (authority_count, false),
        (additional_count, true),
    ] {
        for _ in 0..record_count {
            let owner_start = offset;
            skip_dns_wire_name(message, &mut offset)?;
            let owner_end = offset;
            let record_type = read_dns_wire_u16(message, offset)?;
            let record_class = read_dns_wire_u16(message, offset.checked_add(2)?)?;
            let record_ttl = read_dns_wire_u32(message, offset.checked_add(4)?)?;
            let data_len = usize::from(read_dns_wire_u16(message, offset.checked_add(8)?)?);
            offset = offset.checked_add(10)?;
            let data_end = offset.checked_add(data_len)?;
            message.get(offset..data_end)?;

            if record_type == DNS_TYPE_OPT && !is_additional {
                return None;
            }
            if is_additional && record_type == DNS_TYPE_OPT {
                let root_owner = owner_start.checked_add(1) == Some(owner_end)
                    && message.get(owner_start) == Some(&0);
                if !root_owner
                    || advertised_size.is_some()
                    || !edns_options_are_well_formed(message, offset, data_end)
                {
                    return None;
                }
                advertised_size = Some(EdnsRequest {
                    udp_payload_size: usize::from(record_class),
                    dnssec_ok: record_ttl & 0x8000 != 0,
                });
            }
            offset = data_end;
        }
    }

    if offset == message.len() {
        advertised_size
    } else {
        None
    }
}

fn edns_options_are_well_formed(message: &[u8], mut offset: usize, data_end: usize) -> bool {
    while offset < data_end {
        let Some(option_header_end) = offset.checked_add(4) else {
            return false;
        };
        if option_header_end > data_end {
            return false;
        }
        let Some(option_len_offset) = offset.checked_add(2) else {
            return false;
        };
        let Some(option_len) = read_dns_wire_u16(message, option_len_offset) else {
            return false;
        };
        let Some(option_end) = option_header_end.checked_add(usize::from(option_len)) else {
            return false;
        };
        if option_end > data_end {
            return false;
        }
        offset = option_end;
    }
    true
}

fn read_dns_wire_u16(message: &[u8], offset: usize) -> Option<u16> {
    let bytes = message.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_dns_wire_u32(message: &[u8], offset: usize) -> Option<u32> {
    let bytes = message.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn skip_dns_wire_name(message: &[u8], offset: &mut usize) -> Option<()> {
    let name_start = *offset;
    loop {
        let label_offset = *offset;
        let label_len = *message.get(label_offset)?;
        *offset = (*offset).checked_add(1)?;
        match label_len & 0xc0 {
            0x00 if label_len == 0 => {
                return ((*offset).checked_sub(name_start)? <= 255).then_some(())
            }
            0x00 => {
                *offset = (*offset).checked_add(usize::from(label_len))?;
                message.get((*offset).checked_sub(1)?)?;
                if (*offset).checked_sub(name_start)? > 255 {
                    return None;
                }
            }
            0xc0 => {
                let pointer_low = usize::from(*message.get(*offset)?);
                let pointer = (usize::from(label_len & 0x3f) << 8) | pointer_low;
                if pointer < 12 || pointer >= label_offset {
                    return None;
                }
                *offset = (*offset).checked_add(1)?;
                return Some(());
            }
            _ => return None,
        }
    }
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
    use std::future::pending;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    use super::*;

    struct PendingTestTransportStream;

    impl AsyncRead for PendingTestTransportStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingTestTransportStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl xray_transport::TransportStream for PendingTestTransportStream {
        fn poll_read_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            AsyncRead::poll_read(self, cx, output)
        }

        fn poll_write_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            AsyncWrite::poll_write(self, cx, input)
        }
    }

    fn tcp_local_pool_upstream(index: u16) -> DnsProxyUpstream {
        DnsProxyUpstream::Ip {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 10_000 + index)),
            inbound_tag: format!("dns-{index}"),
            transport: xray_config::DnsServerTransport::TcpLocal,
        }
    }

    fn pending_pool_connection(pool: &DnsTcpConnectionPool) -> DnsTcpPooledConnection {
        DnsTcpPooledConnection {
            stream: Box::new(PendingTestTransportStream),
            last_used: TokioInstant::now(),
            _global_connection_permit: pool.reserve_connection_slot().unwrap(),
        }
    }

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

    fn dns_a_query_with_edns(id: u16, domain: &str, udp_payload_size: u16) -> Vec<u8> {
        let mut query = dns_a_query(id, domain);
        query[10..12].copy_from_slice(&1_u16.to_be_bytes());
        query.push(0);
        query.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        query.extend_from_slice(&udp_payload_size.to_be_bytes());
        query.extend_from_slice(&0_u32.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query
    }

    fn framed_dns_response(query: &[u8], response_len: usize) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response.resize(response_len, 0);
        let mut framed = Vec::with_capacity(response.len() + 2);
        framed.extend_from_slice(&u16::try_from(response.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(&response);
        framed
    }

    fn dns_response_with_flags(query: &[u8], flags: u16) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response
    }

    fn framed_dns_query(query: &[u8]) -> Bytes {
        let mut framed = BytesMut::with_capacity(query.len() + 2);
        framed.extend_from_slice(&u16::try_from(query.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(query);
        framed.freeze()
    }

    fn dns_a_response_with_answer(query: &[u8]) -> Vec<u8> {
        let mut response = dns_response_with_flags(query, 0x8180);
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[192, 0, 2, 1]);
        response
    }

    #[test]
    fn raw_dns_tcp_classifier_accepts_standard_single_question_query() {
        let query = dns_a_query(0x4100, "standard.example");

        assert_eq!(
            raw_dns_tcp_client_frame_kind(&query),
            RawDnsTcpClientFrameKind::Query
        );
    }

    #[test]
    fn raw_dns_tcp_classifier_uses_transparent_mode_for_axfr_and_ixfr() {
        let kinds = [DNS_TYPE_AXFR, DNS_TYPE_IXFR].map(|query_type| {
            let mut query = dns_a_query(0x4101, "transfer.example");
            let type_offset = query.len() - 4;
            query[type_offset..type_offset + 2].copy_from_slice(&query_type.to_be_bytes());
            raw_dns_tcp_client_frame_kind(&query)
        });

        assert_eq!(kinds, [RawDnsTcpClientFrameKind::Transparent; 2]);
    }

    #[test]
    fn raw_dns_tcp_classifier_uses_transparent_mode_for_non_query_opcode() {
        let mut query = dns_a_query(0x4102, "opcode.example");
        query[2..4].copy_from_slice(&0x0900_u16.to_be_bytes());

        assert_eq!(
            raw_dns_tcp_client_frame_kind(&query),
            RawDnsTcpClientFrameKind::Transparent
        );
    }

    #[test]
    fn raw_dns_tcp_classifier_uses_transparent_mode_for_non_single_question() {
        let mut query = dns_a_query(0x4103, "multi.example");
        query[4..6].copy_from_slice(&2_u16.to_be_bytes());

        assert_eq!(
            raw_dns_tcp_client_frame_kind(&query),
            RawDnsTcpClientFrameKind::Transparent
        );
    }

    #[test]
    fn raw_dns_tcp_envelope_rejects_record_with_truncated_rdata() {
        let query = dns_a_query(0x4104, "rdlength.example");
        let mut response = dns_a_response_with_answer(&query);
        let rdlength_offset = response.len() - 6;
        response[rdlength_offset..rdlength_offset + 2].copy_from_slice(&5_u16.to_be_bytes());

        assert!(!dns_wire_envelope_is_well_formed(&response));
    }

    #[test]
    fn raw_dns_tcp_envelope_rejects_trailing_bytes() {
        let query = dns_a_query(0x4105, "trailing.example");
        let mut response = dns_a_response_with_answer(&query);
        response.push(0);

        assert!(!dns_wire_envelope_is_well_formed(&response));
    }

    #[test]
    fn raw_dns_tcp_response_classifier_retries_tc_and_servfail() {
        let query = dns_a_query(0x4106, "retry.example");
        let kinds = [0x8380_u16, 0x8182_u16]
            .map(|flags| raw_dns_tcp_response_kind(&dns_response_with_flags(&query, flags)));

        assert_eq!(kinds, [Some(RawDnsTcpResponseKind::Retry); 2]);
    }

    #[test]
    fn raw_dns_tcp_response_classifier_accepts_nxdomain_and_nodata_as_terminal() {
        let query = dns_a_query(0x4107, "terminal.example");
        let kinds = [0x8183_u16, 0x8180_u16]
            .map(|flags| raw_dns_tcp_response_kind(&dns_response_with_flags(&query, flags)));

        assert_eq!(kinds, [Some(RawDnsTcpResponseKind::Terminal); 2]);
    }

    #[test]
    fn raw_dns_tcp_pending_matches_duplicate_id_by_question() {
        let first = dns_a_query(0x4108, "first.example");
        let second = dns_a_query(0x4108, "second.example");
        let now = TokioInstant::now();
        let mut pending = RawDnsTcpPendingQueries::default();
        assert!(pending.push(framed_dns_query(&first), now));
        assert!(pending.push(framed_dns_query(&second), now));
        pending.prepare_candidate(0, 2, 7, now);
        let _ = pending.mark_generation_sent(7);
        let response = dns_response_with_flags(&second, 0x8180);

        assert_eq!(pending.matching_response_index(7, &response), Some(1));
    }

    #[test]
    fn raw_dns_tcp_pending_exhausts_each_candidate_once() {
        let query = dns_a_query(0x4109, "exhaust.example");
        let now = TokioInstant::now();
        let mut pending = RawDnsTcpPendingQueries::default();
        assert!(pending.push(framed_dns_query(&query), now));
        assert_eq!(pending.next_candidate(2), Some(0));
        pending.prepare_candidate(0, 2, 1, now);
        pending.retire_generation_preserving_attempts(1);
        assert_eq!(pending.next_candidate(2), Some(1));
        pending.prepare_candidate(1, 2, 2, now);
        pending.retire_generation_preserving_attempts(2);

        assert_eq!(pending.next_failed_index(2, now), Some(0));
    }

    #[tokio::test(start_paused = true)]
    async fn raw_dns_tcp_timeout_rolls_back_collateral_query_candidate() {
        let first = dns_a_query(0x4110, "old.example");
        let second = dns_a_query(0x4111, "new.example");
        let now = TokioInstant::now();
        let mut pending = RawDnsTcpPendingQueries::default();
        assert!(pending.push(framed_dns_query(&first), now));
        let first_deadline = pending.prepare_candidate(0, 2, 9, now).unwrap();
        tokio::time::advance(
            first_deadline
                .saturating_duration_since(now)
                .saturating_sub(Duration::from_millis(1)),
        )
        .await;
        let almost_expired = TokioInstant::now();
        assert!(pending.push(framed_dns_query(&second), almost_expired));
        pending.prepare_candidate(0, 2, 9, almost_expired);

        assert_eq!(pending.entries[1].generation, 9);
        assert!(pending.entries[1].attempt_deadline > pending.entries[0].attempt_deadline);
        tokio::time::advance(Duration::from_millis(1)).await;
        pending.retire_generation_for_timeout(9, 0, TokioInstant::now());

        assert_eq!(pending.entries[0].attempted_candidates, 0b01);
        assert_eq!(pending.entries[1].attempted_candidates, 0);
        assert_eq!(pending.next_candidate(2), Some(1));
        pending.remove(0);
        assert_eq!(pending.next_candidate(2), Some(0));
    }

    #[tokio::test(start_paused = true)]
    async fn raw_dns_tcp_pending_joins_generation_while_candidate_budget_is_usable() {
        let first = dns_a_query(0x4113, "early-first.example");
        let second = dns_a_query(0x4114, "early-second.example");
        let now = TokioInstant::now();
        let mut pending = RawDnsTcpPendingQueries::default();
        assert!(pending.push(framed_dns_query(&first), now));
        pending.prepare_candidate(0, 2, 11, now);
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(pending.push(framed_dns_query(&second), TokioInstant::now()));
        pending.prepare_candidate(0, 2, 11, TokioInstant::now());

        assert_eq!(pending.entries[1].generation, 11);
        assert!(pending.entries[1].attempt_deadline > pending.entries[0].attempt_deadline);
    }

    #[test]
    fn raw_dns_tcp_pending_reuses_healthy_fallback_for_a_fresh_cycle() {
        let query = dns_a_query(0x4115, "sticky-fallback.example");
        let now = TokioInstant::now();
        let mut pending = RawDnsTcpPendingQueries::default();
        assert!(pending.push_with_preferred_candidate(
            framed_dns_query(&query),
            now,
            Some(1),
            None,
        ));
        assert_eq!(pending.next_candidate(2), Some(1));

        pending.prepare_candidate(1, 2, 12, now);

        assert_eq!(pending.entries[0].attempted_candidates, 0b10);
    }

    #[test]
    fn raw_dns_tcp_pending_joins_healthy_fallback_during_continuous_pipeline() {
        let first = dns_a_query(0x4116, "fallback-old.example");
        let second = dns_a_query(0x4117, "fallback-new.example");
        let now = TokioInstant::now();
        let mut pending = RawDnsTcpPendingQueries::default();
        assert!(pending.push_with_preferred_candidate(
            framed_dns_query(&first),
            now,
            Some(1),
            None,
        ));
        pending.prepare_candidate(1, 2, 13, now);
        assert!(pending.push_with_preferred_candidate(
            framed_dns_query(&second),
            now,
            Some(1),
            None,
        ));
        pending.prepare_candidate(1, 2, 13, now);

        assert_eq!(pending.entries[1].generation, 13);
        assert_eq!(pending.entries[1].attempted_candidates, 0b10);
    }

    #[test]
    fn raw_dns_tcp_upload_ledger_releases_only_committed_prefix() {
        let state = Arc::new(TcpUploadBufferState::default());
        let bytes = Bytes::from_static(b"abcdefgh");
        let reservation = TcpUploadReservation::new(Arc::clone(&state), bytes.len());
        let mut ledger = RawDnsTcpUploadLedger::default();
        assert!(ledger.push(StackToRemoteData::tracked(bytes, reservation)));
        let first = ledger.register_frame(4).unwrap();
        let second = ledger.register_frame(4).unwrap();

        assert!(ledger.commit_frame(second));
        assert_eq!(state.pending_bytes(), 8);
        assert!(ledger.commit_frame(first));
        assert_eq!(state.pending_bytes(), 0);
        assert_eq!(ledger.committed_end, 8);
    }

    #[test]
    fn raw_dns_tcp_upload_ledger_handles_fragmented_frame_and_replay_once() {
        let state = Arc::new(TcpUploadBufferState::default());
        let mut ledger = RawDnsTcpUploadLedger::default();
        let query = dns_a_query(0x4118, "replay-accounting.example");
        let framed = framed_dns_query(&query);
        for bytes in [framed.slice(..3), framed.slice(3..)] {
            let reservation = TcpUploadReservation::new(Arc::clone(&state), bytes.len());
            assert!(ledger.push(StackToRemoteData::tracked(bytes, reservation)));
        }
        let upload_frame_id = ledger.register_frame(framed.len()).unwrap();
        let now = TokioInstant::now();
        let mut pending = RawDnsTcpPendingQueries::default();
        assert!(pending.push_with_preferred_candidate(framed, now, None, Some(upload_frame_id),));
        pending.prepare_candidate(0, 2, 14, now);
        let first_flush = pending.mark_generation_sent(14);
        assert_eq!(first_flush, vec![upload_frame_id]);
        for frame_id in first_flush {
            assert!(ledger.commit_frame(frame_id));
        }
        assert_eq!(state.pending_bytes(), 0);

        pending.retire_generation_preserving_attempts(14);
        pending.prepare_candidate(1, 2, 15, now);
        assert!(pending.mark_generation_sent(15).is_empty());
        assert_eq!(state.pending_bytes(), 0);
    }

    #[test]
    fn raw_dns_tcp_pending_enforces_query_and_byte_bounds() {
        let now = TokioInstant::now();
        let mut count_bounded = RawDnsTcpPendingQueries::default();
        let query = dns_a_query(0x4112, "bound.example");
        for _ in 0..MAX_RAW_DNS_TCP_PENDING_QUERIES {
            assert!(count_bounded.push(framed_dns_query(&query), now));
        }
        assert!(!count_bounded.push(framed_dns_query(&query), now));

        let mut byte_bounded = RawDnsTcpPendingQueries::default();
        let maximum_frame = Bytes::from(vec![0_u8; MAX_DNS_TCP_MESSAGE_SIZE + 2]);
        for _ in 0..(MAX_RAW_DNS_TCP_PENDING_QUERIES - 1) {
            assert!(byte_bounded.push(maximum_frame.clone(), now));
        }
        assert!(!byte_bounded.push(maximum_frame, now));
    }

    #[test]
    fn dns_tcp_pool_limits_are_profile_aware() {
        assert_eq!(
            [
                TunRuntimeProfile::LowMemory,
                TunRuntimeProfile::Mobile,
                TunRuntimeProfile::MobilePlus,
                TunRuntimeProfile::Desktop,
                TunRuntimeProfile::Throughput,
            ]
            .map(DnsTcpConnectionPoolLimits::for_profile),
            [
                DnsTcpConnectionPoolLimits {
                    per_upstream: 1,
                    global: 8,
                },
                DnsTcpConnectionPoolLimits {
                    per_upstream: 2,
                    global: 16,
                },
                DnsTcpConnectionPoolLimits {
                    per_upstream: 4,
                    global: 32,
                },
                DnsTcpConnectionPoolLimits {
                    per_upstream: 4,
                    global: 32,
                },
                DnsTcpConnectionPoolLimits {
                    per_upstream: 8,
                    global: 64,
                },
            ]
        );
        assert_eq!(
            DnsTcpConnectionPoolLimits::for_profile(TunRuntimeProfile::Default),
            DnsTcpConnectionPoolLimits::for_profile(DEFAULT_DNS_TCP_POOL_PROFILE)
        );
    }

    #[test]
    fn dns_tcp_pool_idle_ttl_is_profile_aware() {
        assert_eq!(
            [
                TunRuntimeProfile::LowMemory,
                TunRuntimeProfile::Mobile,
                TunRuntimeProfile::MobilePlus,
                TunRuntimeProfile::Desktop,
                TunRuntimeProfile::Throughput,
            ]
            .map(DnsTcpConnectionPoolLimits::idle_ttl_for_profile),
            [
                Duration::from_secs(15),
                Duration::from_secs(30),
                Duration::from_secs(45),
                Duration::from_secs(60),
                Duration::from_secs(60),
            ]
        );
        assert_eq!(
            DnsTcpConnectionPoolLimits::idle_ttl_for_profile(TunRuntimeProfile::Default),
            DnsTcpConnectionPoolLimits::idle_ttl_for_profile(DEFAULT_DNS_TCP_POOL_PROFILE)
        );
    }

    #[tokio::test]
    async fn dns_tcp_pool_reuses_one_connection_across_many_sequential_leases() {
        let pool = DnsTcpConnectionPool::new(TunRuntimeProfile::Default);
        let upstream = tcp_local_pool_upstream(1);
        let lease = pool.lease(&upstream).await.unwrap();
        assert!(!lease.reused());
        lease.recycle(pending_pool_connection(&pool));

        for _ in 0..32 {
            let mut lease = pool.lease(&upstream).await.unwrap();
            assert!(lease.reused());
            let connection = lease.take_connection().unwrap();
            lease.recycle(connection);
        }

        let global_limit =
            DnsTcpConnectionPoolLimits::for_profile(TunRuntimeProfile::Default).global;
        assert_eq!(
            pool.connection_permits.available_permits(),
            global_limit - 1
        );
    }

    #[tokio::test]
    async fn dns_tcp_pool_bounds_concurrent_leases_per_key_and_globally() {
        let pool = DnsTcpConnectionPool::with_limits(DnsTcpConnectionPoolLimits {
            per_upstream: 2,
            global: 2,
        });
        let first = pool.lease(&tcp_local_pool_upstream(1)).await.unwrap();
        let second = pool.lease(&tcp_local_pool_upstream(2)).await.unwrap();
        assert_eq!(pool.active_query_permits.available_permits(), 0);
        assert!(timeout(
            Duration::from_millis(10),
            pool.lease(&tcp_local_pool_upstream(3))
        )
        .await
        .is_err());
        drop(first);
        let third = timeout(
            Duration::from_millis(100),
            pool.lease(&tcp_local_pool_upstream(3)),
        )
        .await
        .unwrap()
        .unwrap();
        drop(second);
        drop(third);

        let pool = DnsTcpConnectionPool::with_limits(DnsTcpConnectionPoolLimits {
            per_upstream: 1,
            global: 8,
        });
        let upstream = tcp_local_pool_upstream(4);
        let first = pool.lease(&upstream).await.unwrap();
        assert!(timeout(Duration::from_millis(10), pool.lease(&upstream))
            .await
            .is_err());
        drop(first);
        assert!(timeout(Duration::from_millis(100), pool.lease(&upstream))
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn dns_tcp_pool_global_socket_cap_includes_idle_connections() {
        let pool = DnsTcpConnectionPool::with_limits(DnsTcpConnectionPoolLimits {
            per_upstream: 2,
            global: 2,
        });
        for index in 1..=2 {
            let lease = pool.lease(&tcp_local_pool_upstream(index)).await.unwrap();
            lease.recycle(pending_pool_connection(&pool));
        }
        assert_eq!(pool.connection_permits.available_permits(), 0);

        let third_upstream = tcp_local_pool_upstream(3);
        let third_lease = pool.lease(&third_upstream).await.unwrap();
        third_lease.recycle(pending_pool_connection(&pool));
        let idle_connections = pool
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|entry| {
                entry
                    .idle
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len()
            })
            .sum::<usize>();

        assert_eq!(idle_connections, 2);
        assert_eq!(pool.connection_permits.available_permits(), 0);
    }

    #[tokio::test]
    async fn dns_tcp_pool_timeout_drops_a_leased_connection_instead_of_recycling_it() {
        let pool = DnsTcpConnectionPool::new(TunRuntimeProfile::LowMemory);
        let upstream = tcp_local_pool_upstream(1);
        let lease = pool.lease(&upstream).await.unwrap();
        lease.recycle(pending_pool_connection(&pool));

        let timed_out = timeout(Duration::from_millis(10), async {
            let mut lease = pool.lease(&upstream).await.unwrap();
            let connection = lease.take_connection().unwrap();
            pending::<()>().await;
            lease.recycle(connection);
        })
        .await;
        assert!(timed_out.is_err());
        assert_eq!(pool.connection_permits.available_permits(), 8);
        assert!(!pool.lease(&upstream).await.unwrap().reused());
    }

    #[tokio::test]
    async fn dns_tcp_pool_prunes_expired_idle_connection_and_recovers_permit() {
        let idle_ttl = Duration::from_secs(5);
        let pool = DnsTcpConnectionPool::with_limits_and_idle_ttl(
            DnsTcpConnectionPoolLimits {
                per_upstream: 1,
                global: 1,
            },
            idle_ttl,
        );
        let upstream = tcp_local_pool_upstream(1);
        let last_used = TokioInstant::now();
        let lease = pool.lease(&upstream).await.unwrap();
        lease.recycle_at(pending_pool_connection(&pool), last_used);
        assert_eq!(pool.connection_permits.available_permits(), 0);
        assert_eq!(pool.prune_expired(last_used + idle_ttl), 1);
        assert_eq!(pool.connection_permits.available_permits(), 1);
        assert!(!pool.lease(&upstream).await.unwrap().reused());
    }

    #[test]
    fn udp_payload_limit_defaults_to_legacy_size_without_edns() {
        let query = dns_a_query(0x1200, "legacy.example");

        assert_eq!(dns_udp_client_payload_limit(&query, 1_472), 512);
    }

    #[test]
    fn udp_payload_limit_uses_edns_advertised_size() {
        let query = dns_a_query_with_edns(0x1201, "edns.example", 1_232);

        assert_eq!(dns_udp_client_payload_limit(&query, 1_472), 1_232);
    }

    #[test]
    fn udp_payload_limit_caps_edns_size_to_path_mtu() {
        let query = dns_a_query_with_edns(0x1202, "large-edns.example", 4_096);

        assert_eq!(dns_udp_client_payload_limit(&query, 1_472), 1_472);
    }

    #[test]
    fn udp_payload_limit_floors_small_edns_size_to_legacy_size() {
        let query = dns_a_query_with_edns(0x1203, "small-edns.example", 128);

        assert_eq!(dns_udp_client_payload_limit(&query, 1_472), 512);
    }

    #[test]
    fn udp_payload_limit_falls_back_safely_for_truncated_edns_options() {
        let mut query = dns_a_query_with_edns(0x1204, "broken-edns.example", 1_232);
        let option_data_len_offset = query.len() - 2;
        query[option_data_len_offset..].copy_from_slice(&3_u16.to_be_bytes());
        query.extend_from_slice(&[0, 15, 0]);

        assert_eq!(dns_udp_client_payload_limit(&query, 1_472), 512);
    }

    #[test]
    fn udp_payload_limit_falls_back_safely_for_duplicate_opt_records() {
        let mut query = dns_a_query_with_edns(0x1205, "duplicate-edns.example", 1_232);
        let opt_start = dns_question_section_end(&query).unwrap();
        let duplicate_opt = query[opt_start..].to_vec();
        query[10..12].copy_from_slice(&2_u16.to_be_bytes());
        query.extend_from_slice(&duplicate_opt);

        assert_eq!(dns_udp_client_payload_limit(&query, 1_472), 512);
    }

    #[test]
    fn udp_payload_limit_falls_back_safely_for_non_root_opt_owner() {
        let mut query = dns_a_query(0x1206, "owned-edns.example");
        query[10..12].copy_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[1, b'x', 0]);
        query.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        query.extend_from_slice(&1_232_u16.to_be_bytes());
        query.extend_from_slice(&0_u32.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());

        assert_eq!(dns_udp_client_payload_limit(&query, 1_472), 512);
    }

    #[test]
    fn udp_payload_limit_rejects_opt_outside_additional_section() {
        let mut query = dns_a_query(0x1207, "answer-edns.example");
        query[6..8].copy_from_slice(&1_u16.to_be_bytes());
        query.push(0);
        query.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        query.extend_from_slice(&1_232_u16.to_be_bytes());
        query.extend_from_slice(&0_u32.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());

        assert_eq!(dns_udp_client_payload_limit(&query, 1_472), 512);
    }

    #[tokio::test]
    async fn tcp_upstream_response_over_legacy_udp_limit_becomes_matching_tc_response() {
        let query = dns_a_query(0x1208, "legacy-tcp.example");
        let mut reader = std::io::Cursor::new(framed_dns_response(&query, 600));
        let max_payload = dns_udp_client_payload_limit(&query, 1_472);

        let response = read_bounded_dns_payload(&mut reader, max_payload)
            .await
            .unwrap()
            .into_udp_client_payload(&query, max_payload)
            .unwrap();

        assert!(dns_response_matches_query(&query, &response));
        assert_ne!(u16::from_be_bytes([response[2], response[3]]) & 0x0200, 0);
        assert_eq!(response.len(), dns_question_section_end(&query).unwrap());
        assert_eq!(&response[6..12], &[0; 6]);
    }

    #[tokio::test]
    async fn tcp_upstream_response_within_edns_limit_is_preserved() {
        let query = dns_a_query_with_edns(0x1209, "edns-tcp.example", 1_232);
        let mut reader = std::io::Cursor::new(framed_dns_response(&query, 800));
        let max_payload = dns_udp_client_payload_limit(&query, 1_472);

        let response = read_bounded_dns_payload(&mut reader, max_payload)
            .await
            .unwrap()
            .into_udp_client_payload(&query, max_payload)
            .unwrap();

        assert_eq!(response.len(), 800);
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x0200, 0);
    }

    #[tokio::test]
    async fn tcp_upstream_response_over_edns_limit_becomes_tc_response() {
        let mut query = dns_a_query_with_edns(0x120a, "capped-edns-tcp.example", 1_232);
        let opt_ttl_start = query.len() - 6;
        query[opt_ttl_start..opt_ttl_start + 4].copy_from_slice(&0x8000_u32.to_be_bytes());
        let mut reader = std::io::Cursor::new(framed_dns_response(&query, 1_300));
        let max_payload = dns_udp_client_payload_limit(&query, 1_472);

        let response = read_bounded_dns_payload(&mut reader, max_payload)
            .await
            .unwrap()
            .into_udp_client_payload(&query, max_payload)
            .unwrap();

        assert!(dns_response_matches_query(&query, &response));
        assert_ne!(u16::from_be_bytes([response[2], response[3]]) & 0x0200, 0);
        assert_eq!(
            response.len(),
            dns_question_section_end(&query).unwrap() + 11
        );
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
        assert_eq!(
            validated_edns_request(&response),
            Some(EdnsRequest {
                udp_payload_size: max_payload,
                dnssec_ok: true,
            })
        );
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

    fn dns_tcp_frame(payload: &[u8]) -> Vec<u8> {
        let payload_len = u16::try_from(payload.len()).unwrap();
        let mut frame = Vec::with_capacity(payload.len() + 2);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn dns_tcp_frame_decoder_reassembles_fragmented_prefix_and_payload() {
        let frame = dns_tcp_frame(b"fragmented-query");
        let mut decoder = DnsTcpFrameDecoder::default();

        decoder.push(&frame[..1]);
        assert_eq!(decoder.next_frame(), Ok(None));

        decoder.push(&frame[1..4]);
        assert_eq!(decoder.next_frame(), Ok(None));

        decoder.push(&frame[4..]);
        assert_eq!(
            decoder.next_frame(),
            Ok(Some(Bytes::copy_from_slice(&frame)))
        );
    }

    #[test]
    fn dns_tcp_frame_decoder_yields_coalesced_frames_byte_for_byte() {
        let first = dns_tcp_frame(b"first-query");
        let second = dns_tcp_frame(b"second-query");
        let mut coalesced = first.clone();
        coalesced.extend_from_slice(&second);
        let mut decoder = DnsTcpFrameDecoder::default();
        decoder.push(&coalesced);

        assert_eq!(
            decoder.next_frame(),
            Ok(Some(Bytes::copy_from_slice(&first)))
        );
        assert_eq!(
            decoder.next_frame(),
            Ok(Some(Bytes::copy_from_slice(&second)))
        );
        assert_eq!(decoder.next_frame(), Ok(None));
    }

    #[test]
    fn dns_tcp_frame_decoder_rejects_zero_length_after_prefix() {
        let mut decoder = DnsTcpFrameDecoder::default();
        decoder.push(&0_u16.to_be_bytes());

        assert_eq!(
            decoder.next_frame(),
            Err(DnsTcpFrameDecodeError::ZeroLength)
        );
        assert_eq!(
            decoder.next_frame(),
            Err(DnsTcpFrameDecodeError::ZeroLength)
        );
    }

    #[test]
    fn dns_tcp_frame_decoder_rejects_oversized_message_after_prefix() {
        let oversized_len = u16::try_from(MAX_DNS_TCP_MESSAGE_SIZE + 1).unwrap();
        let mut decoder = DnsTcpFrameDecoder::default();
        decoder.push(&oversized_len.to_be_bytes());

        assert_eq!(
            decoder.next_frame(),
            Err(DnsTcpFrameDecodeError::MessageTooLarge)
        );
        assert_eq!(
            decoder.next_frame(),
            Err(DnsTcpFrameDecodeError::MessageTooLarge)
        );
    }

    #[test]
    fn fake_dns_tcp_decoder_keeps_fragmented_frame_until_complete() {
        let query = dns_a_query(0x2401, "fragmented.example");
        let frame = dns_tcp_frame(&query);
        let mut decoder = DnsTcpFrameDecoder::default();
        decoder.push(&frame[..1]);

        let partial = fake_ip_tcp_responses(&fake_ip_mapper(), &mut decoder);
        assert!(partial.response.is_none());
        assert!(!partial.processed_message);
        assert!(!partial.terminal_error);

        decoder.push(&frame[1..]);
        let decoded = fake_ip_tcp_responses(&fake_ip_mapper(), &mut decoder);
        let response = decoded.response.unwrap();
        assert!(decoded.processed_message);
        assert!(!decoded.terminal_error);
        assert_eq!(
            usize::from(u16::from_be_bytes([response[0], response[1]])),
            response.len() - 2
        );
        assert_eq!(&response[2..4], &0x2401_u16.to_be_bytes());
        assert!(decoder.buffered.is_empty());
    }

    #[test]
    fn fake_dns_tcp_decoder_answers_coalesced_pipelined_frames() {
        let mut decoder = DnsTcpFrameDecoder::default();
        for (id, domain) in [(0x2402, "first.example"), (0x2403, "second.example")] {
            let query = dns_a_query(id, domain);
            decoder.push(&dns_tcp_frame(&query));
        }

        let decoded = fake_ip_tcp_responses(&fake_ip_mapper(), &mut decoder);
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
        assert!(decoder.buffered.is_empty());
    }

    #[test]
    fn fake_dns_tcp_decoder_rejects_oversized_frame_before_payload_arrives() {
        let oversized_len = u16::try_from(MAX_DNS_TCP_MESSAGE_SIZE + 1).unwrap();
        let mut decoder = DnsTcpFrameDecoder::default();
        decoder.push(&oversized_len.to_be_bytes());

        let decoded = fake_ip_tcp_responses(&fake_ip_mapper(), &mut decoder);

        assert!(decoded.response.is_none());
        assert!(!decoded.processed_message);
        assert!(decoded.terminal_error);
    }

    #[test]
    fn fake_dns_tcp_decoder_keeps_valid_response_before_terminal_frame_error() {
        let query = dns_a_query(0x2404, "valid.example");
        let oversized_len = u16::try_from(MAX_DNS_TCP_MESSAGE_SIZE + 1).unwrap();
        let mut decoder = DnsTcpFrameDecoder::default();
        decoder.push(&dns_tcp_frame(&query));
        decoder.push(&oversized_len.to_be_bytes());

        let decoded = fake_ip_tcp_responses(&fake_ip_mapper(), &mut decoder);
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
                    transport: xray_config::DnsServerTransport::Classic,
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
                    transport: xray_config::DnsServerTransport::Classic,
                },
                DnsProxyUpstream::Domain {
                    domain: "policy.example".to_owned(),
                    port: 5_353,
                    inbound_tag: "policy-dns".to_owned(),
                    transport: xray_config::DnsServerTransport::Classic,
                },
                DnsProxyUpstream::Ip {
                    addr: first,
                    inbound_tag: "global-dns".to_owned(),
                    transport: xray_config::DnsServerTransport::Classic,
                },
                DnsProxyUpstream::Ip {
                    addr: second,
                    inbound_tag: "global-dns".to_owned(),
                    transport: xray_config::DnsServerTransport::Classic,
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
                transport: xray_config::DnsServerTransport::Classic,
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
                    transport: xray_config::DnsServerTransport::Classic,
                },
                DnsProxyUpstream::Ip {
                    addr: SocketAddr::from(([192, 0, 2, 53], 53)),
                    inbound_tag: "dns-alternate".to_owned(),
                    transport: xray_config::DnsServerTransport::Classic,
                },
            ]
        );
    }

    #[test]
    fn proxy_plan_keeps_same_endpoint_with_distinct_transports() {
        let raw = r#"{
          "dns": {
            "tag": "dns-route",
            "servers": [
              "192.0.2.53",
              "tcp://192.0.2.53",
              "tcp+local://192.0.2.53",
              "tcp://192.0.2.53"
            ]
          },
          "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let config = xray_config::parse_xray_json(raw)
            .expect("mixed DNS transports should parse")
            .config;
        let plan = DnsProxyPlan::from_config(&config).unwrap();

        assert_eq!(plan.upstreams().len(), 3);
        assert_eq!(
            plan.upstreams()
                .iter()
                .map(DnsProxyUpstream::transport)
                .collect::<Vec<_>>(),
            [
                xray_config::DnsServerTransport::Classic,
                xray_config::DnsServerTransport::TcpRouted,
                xray_config::DnsServerTransport::TcpLocal,
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
