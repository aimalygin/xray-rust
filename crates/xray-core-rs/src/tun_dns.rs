use std::collections::HashSet;

use tokio::time::{timeout, Instant as TokioInstant};

use super::*;

const DNS_RCODE_FORMERR: u16 = 1;
const DNS_TYPE_OPT: u16 = 41;
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

    fn next_frame(&mut self) -> Result<Option<Bytes>, DnsTcpFrameDecodeError> {
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
