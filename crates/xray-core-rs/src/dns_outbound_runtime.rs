use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, timeout, Instant};
use xray_config::{DnsHostTarget, DnsQueryStrategy as ConfigDnsQueryStrategy, DomainHostIndex};
use xray_routing::{Target, TargetAddr};
use xray_transport::{
    BoxedTransportStream, DnsLookup, DnsQueryStrategy, DnsResolver, TransportDialer, TransportError,
};

use crate::dns::{
    exchange_direct_dns_query_with_udp_admission, static_dns_host_target_from_index,
    DirectDnsTcpSession,
};
use crate::dns_outbound::{parse_dns_query, parse_dns_query_prefix, DnsOutboundQuery};
use crate::fake_dns::{FakeIpLookup, FakeIpMapper};
use crate::{DnsOutbound, DnsOutboundDecision};

const DNS_PORT: u16 = 53;
const DNS_HEADER_LEN: usize = 12;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_OPT: u16 = 41;
const DNS_TYPE_IXFR: u16 = 251;
const DNS_TYPE_AXFR: u16 = 252;
const DNS_LEGACY_UDP_PAYLOAD_SIZE: usize = 512;
const MAX_DNS_WIRE_MESSAGE_SIZE: usize = u16::MAX as usize;
const MAX_DNS_TCP_PENDING_BYTES: usize = 128 * 1024;
const DNS_TCP_READ_CHUNK_SIZE: usize = 16 * 1024;
const DNS_RCODE_NOERROR: u16 = 0;
const DNS_RCODE_FORMERR: u16 = 1;
const DNS_RCODE_NXDOMAIN: u16 = 3;
const DNS_RCODE_SERVFAIL: u16 = 2;
const DNS_HIJACK_DEFAULT_TTL: u32 = 300;
const DNS_STATIC_HOST_TTL: Duration = Duration::from_secs(10);

/// Framing and response-size semantics of the client side of a DNS outbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsClientTransport {
    Tcp,
    Udp { path_payload_cap: usize },
}

impl DnsClientTransport {
    fn response_payload_limit(self, query: &DnsOutboundQuery) -> usize {
        match self {
            Self::Tcp => MAX_DNS_WIRE_MESSAGE_SIZE,
            Self::Udp { path_payload_cap } => usize::from(
                query
                    .edns_udp_payload_size()
                    .unwrap_or(DNS_LEGACY_UDP_PAYLOAD_SIZE as u16),
            )
            .max(DNS_LEGACY_UDP_PAYLOAD_SIZE)
            .min(path_payload_cap)
            .min(MAX_DNS_WIRE_MESSAGE_SIZE),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsMessageOutcome {
    Reply(Bytes),
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DirectDnsTcpPoolKey {
    rewritten_target: Target,
    outbound_identity: u64,
}

impl DirectDnsTcpPoolKey {
    fn new(outbound: &DnsOutbound, original_target: &Target) -> Self {
        Self {
            rewritten_target: outbound.rewrite_target(original_target),
            outbound_identity: outbound.runtime_identity(),
        }
    }
}

/// Resource policy shared by Direct DNS TCP/TLS exchanges in one Core.
///
/// The global socket/query budget and key table scale from the same runtime
/// concurrency limit used by the DNS message handler. The per-key fraction
/// preserves fairness when one upstream stalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DnsDirectPoolConfig {
    per_key_connections: usize,
    global_connections: usize,
    max_keys: usize,
    idle_ttl_cap: Duration,
}

impl DnsDirectPoolConfig {
    pub(crate) fn from_runtime_limit(
        max_concurrent_operations: usize,
        idle_ttl_cap: Duration,
    ) -> Self {
        let global_connections = max_concurrent_operations.max(1);
        let per_key_connections = global_connections.div_ceil(8).clamp(1, 8);
        Self {
            per_key_connections,
            global_connections,
            max_keys: global_connections.saturating_mul(16).max(16),
            idle_ttl_cap,
        }
    }
}

struct DirectDnsTcpSessionPool {
    entries: Mutex<HashMap<DirectDnsTcpPoolKey, Arc<DirectDnsTcpPoolEntry>>>,
    config: DnsDirectPoolConfig,
    idle_ttl: Duration,
    active_query_permits: Arc<Semaphore>,
    connection_permits: Arc<Semaphore>,
}

struct DirectDnsTcpPoolEntry {
    idle: Mutex<Vec<PooledDirectDnsTcpSession>>,
    idle_limit: usize,
    idle_ttl: Duration,
    cleanup_scheduled: AtomicBool,
    active_query_permits: Arc<Semaphore>,
}

struct PooledDirectDnsTcpSession {
    session: DirectDnsTcpSession,
    last_used: Instant,
    _connection_permit: OwnedSemaphorePermit,
}

struct DirectDnsTcpSessionLease {
    entry: Arc<DirectDnsTcpPoolEntry>,
    session: Option<PooledDirectDnsTcpSession>,
    _per_key_query_permit: OwnedSemaphorePermit,
    _global_query_permit: OwnedSemaphorePermit,
}

impl DirectDnsTcpSessionPool {
    fn with_config(config: DnsDirectPoolConfig) -> Self {
        let per_key_connections = config.per_key_connections.max(1);
        let global_connections = config.global_connections.max(1);
        let max_keys = config.max_keys.max(1);
        let config = DnsDirectPoolConfig {
            per_key_connections: per_key_connections.min(global_connections),
            global_connections,
            max_keys,
            idle_ttl_cap: config.idle_ttl_cap,
        };
        let idle_ttl = config.idle_ttl_cap;
        Self {
            entries: Mutex::new(HashMap::new()),
            config,
            idle_ttl,
            active_query_permits: Arc::new(Semaphore::new(global_connections)),
            connection_permits: Arc::new(Semaphore::new(global_connections)),
        }
    }

    async fn lease(
        &self,
        key: &DirectDnsTcpPoolKey,
        requested_idle_ttl: Duration,
    ) -> io::Result<DirectDnsTcpSessionLease> {
        let entry = self.entry(key, requested_idle_ttl)?;
        let per_key_query_permit = Arc::clone(&entry.active_query_permits)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let global_query_permit = Arc::clone(&self.active_query_permits)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let session = entry.take_idle(Instant::now());
        Ok(DirectDnsTcpSessionLease {
            entry,
            session,
            _per_key_query_permit: per_key_query_permit,
            _global_query_permit: global_query_permit,
        })
    }

    fn entry(
        &self,
        key: &DirectDnsTcpPoolKey,
        requested_idle_ttl: Duration,
    ) -> io::Result<Arc<DirectDnsTcpPoolEntry>> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = entries.get(key) {
            return Ok(Arc::clone(entry));
        }
        if entries.len() >= self.config.max_keys {
            let evictable = entries
                .iter()
                .find(|(_, entry)| {
                    Arc::strong_count(entry) == 1
                        && entry.active_query_permits.available_permits()
                            == self.config.per_key_connections
                })
                .map(|(key, _)| key.clone());
            let Some(evictable) = evictable else {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Direct DNS TCP pool key limit reached",
                ));
            };
            entries.remove(&evictable);
        }
        let entry = Arc::new(DirectDnsTcpPoolEntry {
            idle: Mutex::new(Vec::with_capacity(self.config.per_key_connections)),
            idle_limit: self.config.per_key_connections,
            idle_ttl: self.idle_ttl.min(requested_idle_ttl),
            cleanup_scheduled: AtomicBool::new(false),
            active_query_permits: Arc::new(Semaphore::new(self.config.per_key_connections)),
        });
        entries.insert(key.clone(), Arc::clone(&entry));
        Ok(entry)
    }

    fn reserve_connection_slot(&self) -> io::Result<OwnedSemaphorePermit> {
        loop {
            match Arc::clone(&self.connection_permits).try_acquire_owned() {
                Ok(permit) => return Ok(permit),
                Err(tokio::sync::TryAcquireError::NoPermits) => {
                    if self.prune_expired(Instant::now()) != 0 || self.evict_one_idle() {
                        continue;
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Direct DNS TCP connection limit reached",
                    ));
                }
                Err(error @ tokio::sync::TryAcquireError::Closed) => {
                    return Err(io::Error::other(error));
                }
            }
        }
    }

    fn evict_one_idle(&self) -> bool {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        entries.into_iter().any(|entry| {
            entry
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop()
                .is_some()
        })
    }

    fn prune_expired(&self, now: Instant) -> usize {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        entries
            .into_iter()
            .map(|entry| entry.prune_expired(now))
            .sum()
    }
}

impl DirectDnsTcpPoolEntry {
    fn take_idle(&self, now: Instant) -> Option<PooledDirectDnsTcpSession> {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        remove_expired_direct_dns_tcp_sessions(&mut idle, now, self.idle_ttl);
        idle.pop()
    }

    fn prune_expired(&self, now: Instant) -> usize {
        let mut idle = self
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        remove_expired_direct_dns_tcp_sessions(&mut idle, now, self.idle_ttl)
    }
}

fn remove_expired_direct_dns_tcp_sessions(
    idle: &mut Vec<PooledDirectDnsTcpSession>,
    now: Instant,
    idle_ttl: Duration,
) -> usize {
    let before = idle.len();
    idle.retain(|session| now.saturating_duration_since(session.last_used) < idle_ttl);
    before.saturating_sub(idle.len())
}

impl DirectDnsTcpSessionLease {
    fn take_session(&mut self) -> Option<PooledDirectDnsTcpSession> {
        self.session.take()
    }

    fn recycle(self, mut session: PooledDirectDnsTcpSession) {
        if self.entry.idle_ttl.is_zero() {
            return;
        }
        session.last_used = Instant::now();
        let schedule_cleanup = {
            let mut idle = self
                .entry
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if idle.len() >= self.entry.idle_limit {
                return;
            }
            idle.push(session);
            !self.entry.cleanup_scheduled.swap(true, Ordering::AcqRel)
        };
        if schedule_cleanup {
            schedule_direct_dns_tcp_cleanup(&self.entry);
        }
    }
}

fn schedule_direct_dns_tcp_cleanup(entry: &Arc<DirectDnsTcpPoolEntry>) {
    let Ok(handle) = Handle::try_current() else {
        let mut idle = entry
            .idle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        idle.clear();
        entry.cleanup_scheduled.store(false, Ordering::Release);
        return;
    };
    let entry = Arc::downgrade(entry);
    handle.spawn(expire_idle_direct_dns_tcp_sessions(entry));
}

async fn expire_idle_direct_dns_tcp_sessions(entry: Weak<DirectDnsTcpPoolEntry>) {
    loop {
        let Some(entry) = entry.upgrade() else {
            return;
        };
        let sleep_for = {
            let mut idle = entry
                .idle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            remove_expired_direct_dns_tcp_sessions(&mut idle, now, entry.idle_ttl);
            if idle.is_empty() {
                // Recyclers take the same mutex before observing this flag, so
                // an insertion cannot be stranded without a replacement task.
                entry.cleanup_scheduled.store(false, Ordering::Release);
                None
            } else {
                idle.iter()
                    .map(|session| {
                        entry
                            .idle_ttl
                            .saturating_sub(now.saturating_duration_since(session.last_used))
                    })
                    .min()
            }
        };
        drop(entry);
        let Some(sleep_for) = sleep_for else {
            return;
        };
        sleep(sleep_for).await;
    }
}

/// One globally/per-target admitted Direct DNS TCP session owned by a single
/// exchange or a dedicated transfer handoff. Healthy ordinary sessions return
/// to the shared idle pool on drop; failed and transfer sessions retire.
pub(crate) struct ManagedDirectDnsTcpSession {
    lease: Option<DirectDnsTcpSessionLease>,
    pooled: Option<PooledDirectDnsTcpSession>,
    operation_permit: Option<OwnedSemaphorePermit>,
    recyclable: bool,
    completed_exchange: bool,
}

impl ManagedDirectDnsTcpSession {
    fn with_operation_permit(mut self, permit: OwnedSemaphorePermit) -> Self {
        debug_assert!(self.operation_permit.is_none());
        self.operation_permit = Some(permit);
        self
    }

    async fn exchange(&mut self, query: &[u8]) -> io::Result<Vec<u8>> {
        // A cancelled future may have written a complete request or consumed
        // only part of a response. Keep the connection out of the idle pool
        // until a complete matching DNS frame has been read.
        let recyclable_after_success = self.recyclable;
        self.recyclable = false;
        let result = self
            .pooled
            .as_mut()
            .expect("managed DNS TCP session must own a connection")
            .session
            .exchange(query)
            .await;
        if result.is_ok() {
            self.completed_exchange = true;
            self.recyclable = recyclable_after_success;
        }
        result
    }

    pub(crate) async fn send(&mut self, query: &[u8]) -> io::Result<()> {
        self.pooled
            .as_mut()
            .expect("managed DNS TCP session must own a connection")
            .session
            .send(query)
            .await
    }

    fn may_retry_stale_query(&self) -> bool {
        self.completed_exchange
    }

    fn retire(mut self) {
        self.recyclable = false;
        drop(self.pooled.take());
        drop(self.lease.take());
    }

    pub(crate) fn into_stream(mut self) -> ManagedDirectDnsTcpStream {
        self.recyclable = false;
        let pooled = self
            .pooled
            .take()
            .expect("managed DNS TCP session must own a connection");
        let lease = self
            .lease
            .take()
            .expect("managed DNS TCP session must own a lease");
        ManagedDirectDnsTcpStream {
            inner: pooled.session.into_stream(),
            _connection_permit: pooled._connection_permit,
            _per_key_query_permit: lease._per_key_query_permit,
            _global_query_permit: lease._global_query_permit,
            _operation_permit: self.operation_permit.take(),
        }
    }
}

impl Drop for ManagedDirectDnsTcpSession {
    fn drop(&mut self) {
        if !self.recyclable {
            return;
        }
        let (Some(lease), Some(pooled)) = (self.lease.take(), self.pooled.take()) else {
            return;
        };
        lease.recycle(pooled);
    }
}

pub(crate) struct ManagedDirectDnsTcpStream {
    inner: BoxedTransportStream,
    _connection_permit: OwnedSemaphorePermit,
    _per_key_query_permit: OwnedSemaphorePermit,
    _global_query_permit: OwnedSemaphorePermit,
    _operation_permit: Option<OwnedSemaphorePermit>,
}

impl AsyncRead for ManagedDirectDnsTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

/// Shared Direct execution resources used by managed `dns.servers`, TUN,
/// SOCKS, and HTTP. Keeping one instance prevents connector-specific paths
/// from escaping the same socket budget.
#[derive(Clone)]
pub(crate) struct DnsDirectExecutor {
    bootstrap: Arc<dyn DnsResolver>,
    dialer: Arc<TransportDialer>,
    forbidden_servers: Arc<[SocketAddr]>,
    tcp_pool: Arc<DirectDnsTcpSessionPool>,
    udp_exchange_permits: Arc<Semaphore>,
}

impl DnsDirectExecutor {
    #[cfg(test)]
    pub(crate) fn new(
        bootstrap: Arc<dyn DnsResolver>,
        dialer: Arc<TransportDialer>,
        forbidden_servers: impl Into<Arc<[SocketAddr]>>,
    ) -> Self {
        Self::with_pool_config(
            bootstrap,
            dialer,
            forbidden_servers,
            DnsDirectPoolConfig::from_runtime_limit(16, Duration::from_secs(30)),
        )
    }

    pub(crate) fn with_pool_config(
        bootstrap: Arc<dyn DnsResolver>,
        dialer: Arc<TransportDialer>,
        forbidden_servers: impl Into<Arc<[SocketAddr]>>,
        pool_config: DnsDirectPoolConfig,
    ) -> Self {
        let max_udp_exchanges = pool_config.global_connections.max(1);
        Self {
            bootstrap,
            dialer,
            forbidden_servers: forbidden_servers.into(),
            tcp_pool: Arc::new(DirectDnsTcpSessionPool::with_config(pool_config)),
            udp_exchange_permits: Arc::new(Semaphore::new(max_udp_exchanges)),
        }
    }

    /// Reserves one Core-wide DNS UDP exchange slot without waiting.
    ///
    /// Managed `dns.servers` Freedom UDP and DNS-outbound Direct UDP both use
    /// this guard. It is intentionally distinct from the ingress operation
    /// semaphore: an ingress may hold its policy permit while acquiring this
    /// socket permit, and saturation fails closed instead of self-deadlocking.
    pub(crate) fn try_reserve_udp_exchange(&self) -> io::Result<OwnedSemaphorePermit> {
        match Arc::clone(&self.udp_exchange_permits).try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(tokio::sync::TryAcquireError::NoPermits) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DNS UDP exchange limit reached",
            )),
            Err(error @ tokio::sync::TryAcquireError::Closed) => Err(io::Error::other(error)),
        }
    }

    async fn open_managed_session(
        &self,
        outbound: &DnsOutbound,
        original_target: &Target,
        recyclable: bool,
        allow_idle: bool,
    ) -> io::Result<ManagedDirectDnsTcpSession> {
        let key = DirectDnsTcpPoolKey::new(outbound, original_target);
        let mut lease = self
            .tcp_pool
            .lease(&key, outbound.conn_idle_timeout())
            .await?;
        let pooled = if allow_idle {
            lease.take_session()
        } else {
            drop(lease.take_session());
            None
        };
        let (pooled, completed_exchange) = match pooled {
            Some(pooled) => (pooled, true),
            None => {
                let connection_permit = self.tcp_pool.reserve_connection_slot()?;
                let session = DirectDnsTcpSession::open(
                    original_target,
                    outbound,
                    self.bootstrap.as_ref(),
                    self.dialer.as_ref(),
                    self.forbidden_servers.as_ref(),
                )
                .await?;
                (
                    PooledDirectDnsTcpSession {
                        session,
                        last_used: Instant::now(),
                        _connection_permit: connection_permit,
                    },
                    false,
                )
            }
        };
        Ok(ManagedDirectDnsTcpSession {
            lease: Some(lease),
            pooled: Some(pooled),
            operation_permit: None,
            recyclable,
            completed_exchange,
        })
    }

    pub(crate) async fn exchange_stateless(
        &self,
        outbound: &DnsOutbound,
        original_target: &Target,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        if original_target.network == xray_routing::Network::Udp && is_dns_tcp_transfer_query(query)
        {
            return crate::build_refused_response(query)
                .map(|response| response.to_vec())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
        if outbound.rewrite_target(original_target).network != xray_routing::Network::Tcp {
            return exchange_direct_dns_query_with_udp_admission(
                original_target,
                outbound,
                query,
                self.bootstrap.as_ref(),
                self.dialer.as_ref(),
                self.forbidden_servers.as_ref(),
                || self.try_reserve_udp_exchange(),
            )
            .await;
        }
        if is_dns_tcp_transfer_query(query) {
            let mut session = self
                .open_managed_session(outbound, original_target, false, false)
                .await?;
            return session.exchange(query).await;
        }

        let mut session = self
            .open_managed_session(outbound, original_target, true, true)
            .await?;
        match session.exchange(query).await {
            Ok(response) => Ok(response),
            Err(_) if session.may_retry_stale_query() && is_retry_safe_dns_query(query) => {
                session.retire();
                let mut fresh = self
                    .open_managed_session(outbound, original_target, true, false)
                    .await?;
                match fresh.exchange(query).await {
                    Ok(response) => Ok(response),
                    Err(error) => {
                        fresh.retire();
                        Err(error)
                    }
                }
            }
            Err(error) => {
                session.retire();
                Err(error)
            }
        }
    }

    pub(crate) async fn open_transfer_session(
        &self,
        outbound: &DnsOutbound,
        original_target: &Target,
    ) -> io::Result<ManagedDirectDnsTcpSession> {
        self.open_managed_session(outbound, original_target, false, false)
            .await
    }
}

fn is_retry_safe_dns_query(message: &[u8]) -> bool {
    parse_dns_query(message).is_ok()
}

fn is_dns_tcp_transfer_query(message: &[u8]) -> bool {
    parse_dns_query_prefix(message)
        .is_ok_and(|query| matches!(query.qtype(), DNS_TYPE_AXFR | DNS_TYPE_IXFR))
}

/// Core-wide execution context for an explicit Xray DNS outbound.
///
/// It is intentionally ingress-neutral: TUN, SOCKS and HTTP adapters provide
/// only framing, the original destination and their client-side payload cap.
#[derive(Clone)]
pub(crate) struct DnsOutboundRuntime {
    resolver: Arc<dyn DnsResolver>,
    direct_executor: Arc<DnsDirectExecutor>,
    fake_ip_mapper: Option<Arc<Mutex<FakeIpMapper>>>,
    static_hosts: Arc<DomainHostIndex<DnsHostTarget>>,
    operation_permits: Arc<Semaphore>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FakeIpTargetProvenance {
    Mapped,
    InPoolUnmapped,
    Outside,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestoredClientTarget {
    pub(crate) target: Target,
    pub(crate) provenance: FakeIpTargetProvenance,
}

impl DnsOutboundRuntime {
    #[cfg(test)]
    pub(crate) fn new(
        resolver: Arc<dyn DnsResolver>,
        bootstrap: Arc<dyn DnsResolver>,
        dialer: Arc<TransportDialer>,
        forbidden_servers: impl Into<Arc<[SocketAddr]>>,
        max_concurrent_operations: usize,
    ) -> Self {
        let direct_executor =
            Arc::new(DnsDirectExecutor::new(bootstrap, dialer, forbidden_servers));
        Self::with_direct_executor(resolver, direct_executor, max_concurrent_operations)
    }

    #[cfg(test)]
    pub(crate) fn with_direct_executor(
        resolver: Arc<dyn DnsResolver>,
        direct_executor: Arc<DnsDirectExecutor>,
        max_concurrent_operations: usize,
    ) -> Self {
        Self::with_direct_executor_and_fake_ip(
            resolver,
            direct_executor,
            None,
            Arc::new(DomainHostIndex::default()),
            max_concurrent_operations,
        )
    }

    pub(crate) fn with_direct_executor_and_fake_ip(
        resolver: Arc<dyn DnsResolver>,
        direct_executor: Arc<DnsDirectExecutor>,
        fake_ip_mapper: Option<Arc<Mutex<FakeIpMapper>>>,
        static_hosts: Arc<DomainHostIndex<DnsHostTarget>>,
        max_concurrent_operations: usize,
    ) -> Self {
        Self {
            resolver,
            direct_executor,
            fake_ip_mapper,
            static_hosts,
            operation_permits: Arc::new(Semaphore::new(max_concurrent_operations.max(1))),
        }
    }

    pub(crate) fn static_host_target(&self, domain: &str) -> Option<DnsHostTarget> {
        static_dns_host_target_from_index(&self.static_hosts, domain)
    }

    pub(crate) fn fake_ip_mapper(&self) -> Option<Arc<Mutex<FakeIpMapper>>> {
        self.fake_ip_mapper.clone()
    }

    /// Restores a client-supplied fake IPv4 target before sniffing, routing,
    /// or dialing. Internal/control-plane targets deliberately never call this
    /// method, so DNS bootstrap and outbound server addresses cannot recurse
    /// through FakeDNS state.
    pub(crate) fn restore_client_target(&self, target: &Target) -> RestoredClientTarget {
        let TargetAddr::Ip(IpAddr::V4(ip)) = target.addr else {
            return RestoredClientTarget {
                target: target.clone(),
                provenance: FakeIpTargetProvenance::Outside,
            };
        };
        let Some(mapper) = self.fake_ip_mapper.as_ref() else {
            return RestoredClientTarget {
                target: target.clone(),
                provenance: FakeIpTargetProvenance::Outside,
            };
        };
        let lookup = mapper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .lookup_ipv4(ip);
        match lookup {
            FakeIpLookup::Mapped(domain) => RestoredClientTarget {
                target: Target::new(
                    TargetAddr::Domain(domain.to_string()),
                    target.port,
                    target.network,
                ),
                provenance: FakeIpTargetProvenance::Mapped,
            },
            FakeIpLookup::InPoolUnmapped => RestoredClientTarget {
                target: target.clone(),
                provenance: FakeIpTargetProvenance::InPoolUnmapped,
            },
            FakeIpLookup::Outside => RestoredClientTarget {
                target: target.clone(),
                provenance: FakeIpTargetProvenance::Outside,
            },
        }
    }

    pub(crate) async fn execute_message(
        &self,
        outbound: &DnsOutbound,
        original_target: &Target,
        query: Bytes,
        client_transport: DnsClientTransport,
    ) -> DnsMessageOutcome {
        let decision = match outbound.policy().decide_message(&query, false) {
            Ok(decision) => decision,
            Err(_) => {
                return dns_error_response(&query, DNS_RCODE_FORMERR, false)
                    .map_or(DnsMessageOutcome::Drop, DnsMessageOutcome::Reply);
            }
        };

        match decision {
            DnsOutboundDecision::Drop => DnsMessageOutcome::Drop,
            DnsOutboundDecision::Return(r_code) => crate::build_return_response(&query, r_code)
                .ok()
                .map_or(DnsMessageOutcome::Drop, DnsMessageOutcome::Reply),
            DnsOutboundDecision::HijackUnsafe(_) => crate::build_refused_response(&query)
                .ok()
                .map_or(DnsMessageOutcome::Drop, DnsMessageOutcome::Reply),
            DnsOutboundDecision::Hijack => {
                let Some(_permit) = Arc::clone(&self.operation_permits).try_acquire_owned().ok()
                else {
                    return dns_reply_or_servfail(&query, None);
                };
                let parsed = match parse_dns_query(&query) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        return dns_error_response(&query, DNS_RCODE_FORMERR, false)
                            .map_or(DnsMessageOutcome::Drop, DnsMessageOutcome::Reply);
                    }
                };
                let payload_limit = client_transport.response_payload_limit(&parsed);
                let response = if let Some(resolution) = self.resolve_fake_ip_hijack(&parsed) {
                    build_hijack_response(&query, &parsed, resolution, payload_limit)
                } else {
                    timeout(
                        outbound.operation_timeout(),
                        resolve_hijack(self.resolver.as_ref(), &query, &parsed, payload_limit),
                    )
                    .await
                    .ok()
                    .flatten()
                };
                dns_reply_or_servfail(&query, response)
            }
            DnsOutboundDecision::Direct => {
                if matches!(client_transport, DnsClientTransport::Udp { .. })
                    && is_dns_tcp_transfer_query(&query)
                {
                    return crate::build_refused_response(&query)
                        .ok()
                        .map_or(DnsMessageOutcome::Drop, DnsMessageOutcome::Reply);
                }
                let Some(_permit) = Arc::clone(&self.operation_permits).try_acquire_owned().ok()
                else {
                    return dns_reply_or_servfail(&query, None);
                };
                let response = timeout(
                    outbound.operation_timeout(),
                    self.exchange_direct(outbound, original_target, &query),
                )
                .await;
                let response = match response {
                    Ok(Ok(response)) => response,
                    Ok(Err(_)) | Err(_) => {
                        return dns_reply_or_servfail(&query, None);
                    }
                };
                match client_transport {
                    DnsClientTransport::Tcp => DnsMessageOutcome::Reply(Bytes::from(response)),
                    DnsClientTransport::Udp { .. } => {
                        let payload_limit = parse_dns_query(&query)
                            .or_else(|_| parse_dns_query_prefix(&query))
                            .ok()
                            .map_or(DNS_LEGACY_UDP_PAYLOAD_SIZE, |parsed| {
                                client_transport.response_payload_limit(&parsed)
                            });
                        let response = if response.len() <= payload_limit {
                            Some(Bytes::from(response))
                        } else {
                            dns_error_response_with_limit(
                                &query,
                                DNS_RCODE_NOERROR,
                                true,
                                payload_limit,
                            )
                        };
                        dns_reply_or_servfail(&query, response)
                    }
                }
            }
        }
    }

    fn resolve_fake_ip_hijack(&self, parsed: &DnsOutboundQuery) -> Option<HijackResolution> {
        let mapper = self.fake_ip_mapper.as_ref()?;
        if parsed.domain() == "." {
            return Some(HijackResolution::NoData);
        }

        let query_strategy = mapper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .query_strategy();
        if matches!(
            (parsed.qtype(), query_strategy),
            (DNS_TYPE_A, ConfigDnsQueryStrategy::UseIpv6)
                | (DNS_TYPE_AAAA, ConfigDnsQueryStrategy::UseIpv4)
        ) {
            return Some(HijackResolution::NoData);
        }

        let fake_domain =
            match static_dns_host_target_from_index(&self.static_hosts, parsed.domain()) {
                Some(DnsHostTarget::Ip(address)) => {
                    return Some(static_host_hijack_resolution(parsed.qtype(), [address]));
                }
                Some(DnsHostTarget::Ips(addresses)) => {
                    return Some(static_host_hijack_resolution(parsed.qtype(), addresses));
                }
                Some(DnsHostTarget::Domain(alias)) => alias,
                None => parsed.domain().to_owned(),
            };

        let mut mapper = mapper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match parsed.qtype() {
            DNS_TYPE_A => Some(mapper.allocate_ipv4(&fake_domain).map_or(
                HijackResolution::ServerFailure,
                |address| HijackResolution::Answers {
                    addresses: vec![IpAddr::V4(address)],
                    ttl: mapper.ttl(),
                },
            )),
            DNS_TYPE_AAAA => Some(HijackResolution::NoData),
            _ => Some(HijackResolution::ServerFailure),
        }
    }

    async fn exchange_direct(
        &self,
        outbound: &DnsOutbound,
        original_target: &Target,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        // Ordinary TCP clients retain only their inbound flow. Each DNS
        // message checks out and recycles an upstream session independently,
        // so client think-time cannot pin the shared control-plane budget.
        self.direct_executor
            .exchange_stateless(outbound, original_target, query)
            .await
    }

    pub(crate) fn is_direct_tcp_transfer(
        &self,
        outbound: &DnsOutbound,
        original_target: &Target,
        query: &[u8],
    ) -> bool {
        parse_dns_query_prefix(query).is_ok_and(|parsed| {
            matches!(parsed.qtype(), DNS_TYPE_AXFR | DNS_TYPE_IXFR)
                && matches!(
                    outbound.policy().decide_message(query, false),
                    Ok(DnsOutboundDecision::Direct)
                )
                && outbound.rewrite_target(original_target).network == xray_routing::Network::Tcp
        })
    }

    pub(crate) async fn open_direct_tcp_transfer_session(
        &self,
        outbound: &DnsOutbound,
        original_target: &Target,
    ) -> io::Result<ManagedDirectDnsTcpSession> {
        let operation_permit = Arc::clone(&self.operation_permits)
            .try_acquire_owned()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "DNS operation budget exhausted")
            })?;
        self.direct_executor
            .open_transfer_session(outbound, original_target)
            .await
            .map(|session| session.with_operation_permit(operation_permit))
    }

    /// Runs the bounded RFC 7766 request loop shared by SOCKS and HTTP TCP
    /// inbounds. AXFR/IXFR uses a response-only transparent handoff so all
    /// upstream response messages are preserved without allowing later client
    /// frames to bypass policy.
    pub(crate) async fn serve_tcp_stream<S>(
        &self,
        inbound: &mut S,
        initial_payload: Bytes,
        outbound: &DnsOutbound,
        original_target: &Target,
        inbound_idle_timeout: Duration,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let idle_timeout = inbound_idle_timeout.min(outbound.conn_idle_timeout());
        let mut decoder = DnsTcpFrameDecoder::default();
        if initial_payload.len() > MAX_DNS_TCP_PENDING_BYTES {
            return Err(invalid_dns_tcp_data(
                "DNS TCP initial payload exceeds buffer limit",
            ));
        }
        decoder.push(&initial_payload);
        let mut read_buffer = vec![0_u8; DNS_TCP_READ_CHUNK_SIZE];

        loop {
            while let Some(query) = decoder.next_message()? {
                if self.is_direct_tcp_transfer(outbound, original_target, &query) {
                    if decoder.buffered_len() != 0 {
                        return Err(invalid_dns_tcp_data(
                            "DNS transfer cannot bypass a buffered client frame",
                        ));
                    }
                    return self
                        .serve_direct_tcp_transfer(
                            inbound,
                            outbound,
                            original_target,
                            &query,
                            idle_timeout,
                        )
                        .await;
                }

                let outcome = self
                    .execute_message(outbound, original_target, query, DnsClientTransport::Tcp)
                    .await;
                if let DnsMessageOutcome::Reply(response) = outcome {
                    let response_len = u16::try_from(response.len())
                        .map_err(|_| invalid_dns_tcp_data("DNS TCP response exceeds wire limit"))?;
                    timeout(outbound.operation_timeout(), async {
                        inbound.write_u16(response_len).await?;
                        inbound.write_all(&response).await?;
                        inbound.flush().await
                    })
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "DNS TCP write timed out")
                    })??;
                }
            }

            let read = timeout(idle_timeout, inbound.read(&mut read_buffer))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP flow idle"))??;
            if read == 0 {
                return Ok(());
            }
            if decoder.buffered_len().saturating_add(read) > MAX_DNS_TCP_PENDING_BYTES {
                return Err(invalid_dns_tcp_data("DNS TCP input exceeds buffer limit"));
            }
            decoder.push(&read_buffer[..read]);
        }
    }

    async fn serve_direct_tcp_transfer<S>(
        &self,
        inbound: &mut S,
        outbound: &DnsOutbound,
        original_target: &Target,
        query: &[u8],
        idle_timeout: Duration,
    ) -> io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let mut session = timeout(
            outbound.operation_timeout(),
            self.open_direct_tcp_transfer_session(outbound, original_target),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS transfer open timed out"))??;
        timeout(outbound.operation_timeout(), session.send(query))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DNS transfer write timed out")
            })??;
        let mut upstream = session.into_stream();
        let mut buffer = vec![0_u8; DNS_TCP_READ_CHUNK_SIZE];
        loop {
            let read = timeout(idle_timeout, upstream.read(&mut buffer))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS transfer idle"))??;
            if read == 0 {
                return Ok(());
            }
            timeout(
                outbound.operation_timeout(),
                inbound.write_all(&buffer[..read]),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DNS transfer write timed out")
            })??;
        }
    }
}

fn static_host_hijack_resolution(
    qtype: u16,
    addresses: impl IntoIterator<Item = IpAddr>,
) -> HijackResolution {
    hijack_lookup(
        qtype,
        DnsLookup::from_ips(addresses, DNS_PORT, Some(DNS_STATIC_HOST_TTL)),
    )
}

#[derive(Debug, Default)]
struct DnsTcpFrameDecoder {
    buffered: BytesMut,
}

impl DnsTcpFrameDecoder {
    fn push(&mut self, chunk: &[u8]) {
        self.buffered.extend_from_slice(chunk);
    }

    fn buffered_len(&self) -> usize {
        self.buffered.len()
    }

    fn next_message(&mut self) -> io::Result<Option<Bytes>> {
        if self.buffered.len() < 2 {
            return Ok(None);
        }
        let message_len = usize::from(u16::from_be_bytes([self.buffered[0], self.buffered[1]]));
        if message_len == 0 {
            return Err(invalid_dns_tcp_data("zero-length DNS TCP message"));
        }
        let frame_len = message_len.saturating_add(2);
        if frame_len > MAX_DNS_TCP_PENDING_BYTES {
            return Err(invalid_dns_tcp_data("DNS TCP message exceeds buffer limit"));
        }
        if self.buffered.len() < frame_len {
            return Ok(None);
        }
        let frame = self.buffered.split_to(frame_len).freeze();
        Ok(Some(frame.slice(2..)))
    }
}

fn invalid_dns_tcp_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

enum HijackResolution {
    Answers { addresses: Vec<IpAddr>, ttl: u32 },
    NameError,
    NoData,
    ServerFailure,
}

async fn resolve_hijack(
    resolver: &dyn DnsResolver,
    query: &[u8],
    parsed: &DnsOutboundQuery,
    payload_limit: usize,
) -> Option<Bytes> {
    let strategy = match parsed.qtype() {
        DNS_TYPE_A => DnsQueryStrategy::UseIpv4,
        DNS_TYPE_AAAA => DnsQueryStrategy::UseIpv6,
        _ => return dns_error_response(query, DNS_RCODE_SERVFAIL, false),
    };
    let resolution = if parsed.domain() == "." {
        HijackResolution::NoData
    } else {
        match resolver
            .resolve_all_with_strategy(parsed.domain(), DNS_PORT, strategy)
            .await
        {
            Ok(lookup) => hijack_lookup(parsed.qtype(), lookup),
            Err(TransportError::DnsNameError(_, _)) => HijackResolution::NameError,
            Err(TransportError::DnsNoData(_, _) | TransportError::NoResolvedAddress(_, _)) => {
                HijackResolution::NoData
            }
            Err(_) => HijackResolution::ServerFailure,
        }
    };
    build_hijack_response(query, parsed, resolution, payload_limit)
}

fn hijack_lookup(qtype: u16, lookup: DnsLookup) -> HijackResolution {
    let addresses = lookup
        .ips()
        .filter(|address| {
            matches!(
                (qtype, address),
                (DNS_TYPE_A, IpAddr::V4(_)) | (DNS_TYPE_AAAA, IpAddr::V6(_))
            )
        })
        .take(MAX_DNS_WIRE_MESSAGE_SIZE / 16 + 1)
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return HijackResolution::NoData;
    }
    let ttl = lookup.ttl().map_or(DNS_HIJACK_DEFAULT_TTL, |ttl| {
        let seconds = ttl
            .as_secs()
            .saturating_add(u64::from(ttl.subsec_nanos() != 0));
        u32::try_from(seconds).unwrap_or(u32::MAX)
    });
    HijackResolution::Answers { addresses, ttl }
}

fn build_hijack_response(
    query: &[u8],
    parsed: &DnsOutboundQuery,
    resolution: HijackResolution,
    max_payload: usize,
) -> Option<Bytes> {
    if parsed.question_count() != 1 || parsed.qclass() != DNS_CLASS_IN {
        return None;
    }
    let (addresses, ttl, rcode) = match resolution {
        HijackResolution::Answers { addresses, ttl } => (addresses, ttl, DNS_RCODE_NOERROR),
        HijackResolution::NameError => (Vec::new(), 0, DNS_RCODE_NXDOMAIN),
        HijackResolution::NoData => (Vec::new(), 0, DNS_RCODE_NOERROR),
        HijackResolution::ServerFailure => (Vec::new(), 0, DNS_RCODE_SERVFAIL),
    };
    let answer_size = match parsed.qtype() {
        DNS_TYPE_A => 16usize,
        DNS_TYPE_AAAA => 28usize,
        _ => return None,
    };
    let edns_len = usize::from(parsed.edns_udp_payload_size().is_some()) * 11;
    let full_len = parsed
        .question_section_end()
        .checked_add(answer_size.checked_mul(addresses.len())?)?
        .checked_add(edns_len)?;
    let truncated = full_len > max_payload && !addresses.is_empty();
    let answer_count = if truncated { 0 } else { addresses.len() };
    let answer_count = u16::try_from(answer_count).ok()?;

    let mut response = Vec::with_capacity(full_len.min(max_payload.max(DNS_HEADER_LEN)));
    response.extend_from_slice(query.get(..parsed.question_section_end())?);
    let mut flags = 0x8000 | 0x0400 | 0x0080 | (parsed.request_flags() & 0x0110) | rcode;
    if truncated {
        flags |= 0x0200;
    }
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    response[4..6].copy_from_slice(&1_u16.to_be_bytes());
    response[6..8].copy_from_slice(&answer_count.to_be_bytes());
    response[8..10].fill(0);
    response[10..12]
        .copy_from_slice(&(parsed.edns_udp_payload_size().is_some() as u16).to_be_bytes());

    if !truncated {
        for address in addresses {
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&parsed.qtype().to_be_bytes());
            response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
            response.extend_from_slice(&ttl.to_be_bytes());
            match address {
                IpAddr::V4(address) if parsed.qtype() == DNS_TYPE_A => {
                    response.extend_from_slice(&4_u16.to_be_bytes());
                    response.extend_from_slice(&address.octets());
                }
                IpAddr::V6(address) if parsed.qtype() == DNS_TYPE_AAAA => {
                    response.extend_from_slice(&16_u16.to_be_bytes());
                    response.extend_from_slice(&address.octets());
                }
                IpAddr::V4(_) | IpAddr::V6(_) => return None,
            }
        }
    }

    if let Some(advertised) = parsed.edns_udp_payload_size() {
        let response_payload_size = usize::from(advertised)
            .max(DNS_LEGACY_UDP_PAYLOAD_SIZE)
            .min(max_payload)
            .min(MAX_DNS_WIRE_MESSAGE_SIZE);
        response.push(0);
        response.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        response.extend_from_slice(&u16::try_from(response_payload_size).ok()?.to_be_bytes());
        response.extend_from_slice(&0_u32.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
    }
    Some(Bytes::from(response))
}

fn dns_error_response(query: &[u8], rcode: u16, truncated: bool) -> Option<Bytes> {
    dns_error_response_with_limit(query, rcode, truncated, DNS_LEGACY_UDP_PAYLOAD_SIZE)
}

fn dns_reply_or_servfail(query: &[u8], response: Option<Bytes>) -> DnsMessageOutcome {
    response
        .filter(|response| !response.is_empty())
        .or_else(|| dns_error_response(query, DNS_RCODE_SERVFAIL, false))
        .map_or(DnsMessageOutcome::Drop, DnsMessageOutcome::Reply)
}

fn dns_error_response_with_limit(
    query: &[u8],
    rcode: u16,
    truncated: bool,
    max_payload: usize,
) -> Option<Bytes> {
    if query.len() < DNS_HEADER_LEN {
        return None;
    }
    let parsed = parse_dns_query_prefix(query).ok();
    let question_end = parsed
        .as_ref()
        .map_or(DNS_HEADER_LEN, |query| query.question_section_end());
    let mut response = Vec::with_capacity(question_end.min(max_payload));
    response.extend_from_slice(query.get(..question_end)?);
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let mut response_flags = 0x8000 | 0x0080 | (request_flags & 0x7910) | (rcode & 0x000f);
    if truncated {
        response_flags |= 0x0200;
    }
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[4..6].copy_from_slice(&(parsed.is_some() as u16).to_be_bytes());
    response[6..12].fill(0);
    Some(Bytes::from(response))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use xray_config::{
        DnsFakeIpConfig, DnsHostTarget, DnsOutboundRule, DnsOutboundRuleAction,
        DnsOutboundSettings, DomainMatcher, DomainMatcherSet, IpCidr, Network,
        TargetAddr as ConfigTargetAddr,
    };
    use xray_routing::{Network as RoutingNetwork, TargetAddr};
    use xray_transport::{SystemDnsResolver, TransportDialer};

    use super::*;

    fn query_with_flags_and_type(id: u16, domain: &str, flags: u16, qtype: u16) -> Bytes {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&flags.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[0; 6]);
        for label in domain.split('.') {
            query.push(u8::try_from(label.len()).unwrap());
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        Bytes::from(query)
    }

    fn query(id: u16, domain: &str) -> Bytes {
        query_with_flags_and_type(id, domain, 0x0100, DNS_TYPE_A)
    }

    fn response_for(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        let request_flags = u16::from_be_bytes([query[2], query[3]]);
        response[2..4].copy_from_slice(&(request_flags | 0x8080).to_be_bytes());
        response
    }

    fn framed_query(domain: &str) -> Bytes {
        let query = query(0x1234, domain);
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&u16::try_from(query.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(&query);
        Bytes::from(framed)
    }

    fn direct_tcp_outbound(server: SocketAddr) -> DnsOutbound {
        DnsOutbound::new(DnsOutboundSettings {
            rewrite_network: Some(Network::Tcp),
            rewrite_address: Some(ConfigTargetAddr::Ip(server.ip())),
            rewrite_port: server.port(),
            rules: vec![DnsOutboundRule {
                action: DnsOutboundRuleAction::Direct,
                r_code: 0,
                qtype_ranges: Vec::new(),
                domain_matchers: DomainMatcherSet::default(),
            }],
            ..DnsOutboundSettings::default()
        })
    }

    fn test_runtime() -> DnsOutboundRuntime {
        let resolver = Arc::new(SystemDnsResolver);
        DnsOutboundRuntime::new(
            resolver.clone(),
            resolver,
            Arc::new(TransportDialer::system().expect("build test DNS dialer")),
            Vec::new(),
            8,
        )
    }

    fn test_runtime_with_fake_ip() -> (DnsOutboundRuntime, Arc<Mutex<FakeIpMapper>>) {
        let config = DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 29).unwrap(),
            pool_size: 1,
            ttl: 60,
        };
        let mapper = Arc::new(Mutex::new(
            FakeIpMapper::from_config(&config, ConfigDnsQueryStrategy::UseIp, &[]).unwrap(),
        ));
        let mut runtime = test_runtime();
        runtime.fake_ip_mapper = Some(Arc::clone(&mapper));
        (runtime, mapper)
    }

    fn hijack_outbound() -> DnsOutbound {
        DnsOutbound::new(DnsOutboundSettings::default())
    }

    fn udp_dns_target() -> Target {
        Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
            DNS_PORT,
            RoutingNetwork::Udp,
        )
    }

    #[test]
    fn client_target_restoration_preserves_fake_ip_provenance() {
        let (runtime, mapper) = test_runtime_with_fake_ip();
        let mapped_ip = mapper
            .lock()
            .unwrap()
            .allocate_ipv4("mapped.example")
            .unwrap();
        let mapped = Target::new(
            TargetAddr::Ip(IpAddr::V4(mapped_ip)),
            443,
            RoutingNetwork::Tcp,
        );
        let in_pool_unmapped = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2))),
            443,
            RoutingNetwork::Tcp,
        );
        let outside = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            443,
            RoutingNetwork::Tcp,
        );

        assert_eq!(
            runtime.restore_client_target(&mapped),
            RestoredClientTarget {
                target: Target::new(
                    TargetAddr::Domain("mapped.example".to_owned()),
                    443,
                    RoutingNetwork::Tcp,
                ),
                provenance: FakeIpTargetProvenance::Mapped,
            }
        );
        assert_eq!(
            runtime.restore_client_target(&in_pool_unmapped),
            RestoredClientTarget {
                target: in_pool_unmapped,
                provenance: FakeIpTargetProvenance::InPoolUnmapped,
            }
        );
        assert_eq!(
            runtime.restore_client_target(&outside),
            RestoredClientTarget {
                target: outside,
                provenance: FakeIpTargetProvenance::Outside,
            }
        );
    }

    #[test]
    fn client_target_restoration_recovers_a_poisoned_fake_ip_mapper() {
        let (runtime, mapper) = test_runtime_with_fake_ip();
        let mapped_ip = mapper
            .lock()
            .unwrap()
            .allocate_ipv4("poisoned.example")
            .unwrap();
        let poisoned_mapper = Arc::clone(&mapper);
        assert!(std::thread::spawn(move || {
            let _guard = poisoned_mapper.lock().unwrap();
            panic!("poison FakeDNS mapper for recovery test");
        })
        .join()
        .is_err());

        let restored = runtime.restore_client_target(&Target::new(
            TargetAddr::Ip(IpAddr::V4(mapped_ip)),
            443,
            RoutingNetwork::Tcp,
        ));

        assert_eq!(restored.provenance, FakeIpTargetProvenance::Mapped);
        assert_eq!(
            restored.target.addr,
            TargetAddr::Domain("poisoned.example".to_owned())
        );
    }

    #[tokio::test]
    async fn static_hosts_precede_fake_ip_hijack_without_allocating_a_mapping() {
        let (mut runtime, mapper) = test_runtime_with_fake_ip();
        let static_ip = Ipv4Addr::new(192, 0, 2, 44);
        runtime.static_hosts = Arc::new(DomainHostIndex::from_iter([(
            DomainMatcher::Full("blocked.example".to_owned()),
            DnsHostTarget::Ip(IpAddr::V4(static_ip)),
        )]));
        let request = query(0x2201, "blocked.example");

        let outcome = runtime
            .execute_message(
                &hijack_outbound(),
                &udp_dns_target(),
                request.clone(),
                DnsClientTransport::Udp {
                    path_payload_cap: 1_232,
                },
            )
            .await;

        let DnsMessageOutcome::Reply(response) = outcome else {
            panic!("static host Hijack must reply");
        };
        let question_end = parse_dns_query(&request).unwrap().question_section_end();
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(
            u32::from_be_bytes(
                response[question_end + 6..question_end + 10]
                    .try_into()
                    .unwrap()
            ),
            10
        );
        assert_eq!(
            &response[question_end + 12..question_end + 16],
            &static_ip.octets()
        );
        assert_eq!(mapper.lock().unwrap().mapping_count(), 0);
    }

    #[tokio::test]
    async fn wrong_family_static_host_returns_nodata_instead_of_fake_ip() {
        let (mut runtime, mapper) = test_runtime_with_fake_ip();
        runtime.static_hosts = Arc::new(DomainHostIndex::from_iter([(
            DomainMatcher::Full("ipv6-only.example".to_owned()),
            DnsHostTarget::Ip(IpAddr::V6("2001:db8::44".parse().unwrap())),
        )]));
        let request = query(0x2202, "ipv6-only.example");

        let outcome = runtime
            .execute_message(
                &hijack_outbound(),
                &udp_dns_target(),
                request,
                DnsClientTransport::Udp {
                    path_payload_cap: 1_232,
                },
            )
            .await;

        let DnsMessageOutcome::Reply(response) = outcome else {
            panic!("wrong-family static host must return NODATA");
        };
        assert_eq!(response[3] & 0x0f, DNS_RCODE_NOERROR as u8);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(mapper.lock().unwrap().mapping_count(), 0);
    }

    #[tokio::test]
    async fn static_host_alias_allocates_fake_ip_for_the_terminal_name() {
        let (mut runtime, mapper) = test_runtime_with_fake_ip();
        runtime.static_hosts = Arc::new(DomainHostIndex::from_iter([(
            DomainMatcher::Full("public.example".to_owned()),
            DnsHostTarget::Domain("internal.example".to_owned()),
        )]));
        let request = query(0x2203, "public.example");

        let outcome = runtime
            .execute_message(
                &hijack_outbound(),
                &udp_dns_target(),
                request,
                DnsClientTransport::Udp {
                    path_payload_cap: 1_232,
                },
            )
            .await;

        let DnsMessageOutcome::Reply(response) = outcome else {
            panic!("static alias FakeIP Hijack must reply");
        };
        let fake_ip = Ipv4Addr::new(
            response[response.len() - 4],
            response[response.len() - 3],
            response[response.len() - 2],
            response[response.len() - 1],
        );
        assert_eq!(
            mapper.lock().unwrap().domain_for_ipv4(fake_ip).as_deref(),
            Some("internal.example")
        );
    }

    async fn serve_dns_queries(listener: TcpListener, total: usize) -> usize {
        let mut accepted = 0_usize;
        let mut processed = 0_usize;
        while processed < total {
            let (mut stream, _) = listener.accept().await.expect("accept DNS TCP client");
            accepted = accepted.saturating_add(1);
            while processed < total {
                let query_len = match timeout(Duration::from_secs(1), stream.read_u16()).await {
                    Ok(Ok(query_len)) => usize::from(query_len),
                    Ok(Err(_)) | Err(_) => break,
                };
                let mut query = vec![0_u8; query_len];
                stream
                    .read_exact(&mut query)
                    .await
                    .expect("read pooled DNS query");
                let mut response = query;
                response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                stream
                    .write_u16(u16::try_from(response.len()).expect("bounded DNS response"))
                    .await
                    .expect("write pooled DNS response length");
                stream
                    .write_all(&response)
                    .await
                    .expect("write pooled DNS response");
                stream.flush().await.expect("flush pooled DNS response");
                processed = processed.saturating_add(1);
            }
        }
        accepted
    }

    async fn serve_one_dns_query_per_connection(listener: TcpListener, total: usize) -> usize {
        for _ in 0..total {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept short-lived DNS TCP client");
            let query_len = usize::from(
                stream
                    .read_u16()
                    .await
                    .expect("read short-lived DNS query length"),
            );
            let mut query = vec![0_u8; query_len];
            stream
                .read_exact(&mut query)
                .await
                .expect("read short-lived DNS query");
            query[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            stream
                .write_u16(u16::try_from(query.len()).expect("bounded DNS response"))
                .await
                .expect("write short-lived DNS response length");
            stream
                .write_all(&query)
                .await
                .expect("write short-lived DNS response");
            stream
                .shutdown()
                .await
                .expect("close short-lived DNS connection");
        }
        total
    }

    #[test]
    fn tcp_decoder_accepts_fragmented_and_coalesced_frames() {
        let first = framed_query("one.example");
        let second = framed_query("two.example");
        let mut decoder = DnsTcpFrameDecoder::default();
        decoder.push(&first[..3]);
        assert!(decoder.next_message().unwrap().is_none());
        decoder.push(&first[3..]);
        decoder.push(&second);

        assert_eq!(decoder.next_message().unwrap().unwrap(), first.slice(2..));
        assert_eq!(decoder.next_message().unwrap().unwrap(), second.slice(2..));
        assert!(decoder.next_message().unwrap().is_none());
    }

    #[test]
    fn tcp_decoder_rejects_zero_length_and_oversized_buffer() {
        let mut zero = DnsTcpFrameDecoder::default();
        zero.push(&[0, 0]);
        assert_eq!(
            zero.next_message().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut oversized = DnsTcpFrameDecoder::default();
        oversized.push(&u16::MAX.to_be_bytes());
        assert!(oversized.next_message().unwrap().is_none());
    }

    #[test]
    fn stale_retry_requires_a_complete_standard_query() {
        assert!(is_retry_safe_dns_query(&query(0x1101, "retry.test")));
        assert!(!is_retry_safe_dns_query(&[0x11, 0x02, 0, 0]));
        assert!(!is_retry_safe_dns_query(&query_with_flags_and_type(
            0x1103,
            "update.test",
            5 << 11,
            DNS_TYPE_A,
        )));
        assert!(!is_retry_safe_dns_query(&query_with_flags_and_type(
            0x1104,
            "response.test",
            0x8100,
            DNS_TYPE_A,
        )));
    }

    #[test]
    fn missing_dns_response_uses_servfail_or_drops_instead_of_empty_reply() {
        let valid = query(0x1105, "fallback.test");
        let DnsMessageOutcome::Reply(response) = dns_reply_or_servfail(&valid, Some(Bytes::new()))
        else {
            panic!("valid query should produce SERVFAIL");
        };
        assert!(!response.is_empty());
        assert_eq!(response[3] & 0x0f, DNS_RCODE_SERVFAIL as u8);
        assert_eq!(
            dns_reply_or_servfail(&[0x11, 0x06, 0, 0], None),
            DnsMessageOutcome::Drop
        );
    }

    #[test]
    fn direct_pool_config_scales_with_runtime_concurrency() {
        for (runtime_limit, per_key, global, max_keys) in [
            (8, 1, 8, 128),
            (16, 2, 16, 256),
            (32, 4, 32, 512),
            (64, 8, 64, 1_024),
        ] {
            let config =
                DnsDirectPoolConfig::from_runtime_limit(runtime_limit, Duration::from_secs(45));
            assert_eq!(config.per_key_connections, per_key);
            assert_eq!(config.global_connections, global);
            assert_eq!(config.max_keys, max_keys);
            assert_eq!(config.idle_ttl_cap, Duration::from_secs(45));
        }
    }

    #[tokio::test]
    async fn transfer_session_releases_its_ingress_operation_permit_on_cancellation() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind transfer permit DNS server");
        let server_addr = listener
            .local_addr()
            .expect("read transfer permit DNS address");
        let (first_accepted_tx, first_accepted_rx) = oneshot::channel();
        let (second_accepted_tx, second_accepted_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (first, _) = listener
                .accept()
                .await
                .expect("accept first transfer session");
            first_accepted_tx
                .send(())
                .expect("signal first transfer session");
            let (second, _) = listener
                .accept()
                .await
                .expect("accept replacement transfer session");
            second_accepted_tx
                .send(())
                .expect("signal replacement transfer session");
            (first, second)
        });

        let resolver: Arc<dyn DnsResolver> = Arc::new(SystemDnsResolver);
        let direct_executor = Arc::new(DnsDirectExecutor::new(
            Arc::clone(&resolver),
            Arc::new(TransportDialer::system().expect("build transfer permit dialer")),
            Vec::new(),
        ));
        let runtime = Arc::new(DnsOutboundRuntime::with_direct_executor(
            resolver,
            direct_executor,
            1,
        ));
        let outbound = direct_tcp_outbound(server_addr);
        let original_target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
            DNS_PORT,
            RoutingNetwork::Tcp,
        );
        let (opened_tx, opened_rx) = oneshot::channel();
        let holder_runtime = Arc::clone(&runtime);
        let holder_outbound = outbound.clone();
        let holder_target = original_target.clone();
        let holder = tokio::spawn(async move {
            let _session = holder_runtime
                .open_direct_tcp_transfer_session(&holder_outbound, &holder_target)
                .await
                .expect("open first transfer session");
            opened_tx.send(()).expect("signal held transfer session");
            std::future::pending::<()>().await;
        });
        opened_rx.await.expect("first transfer session should open");
        first_accepted_rx
            .await
            .expect("server should accept first transfer session");

        let saturated = runtime
            .open_direct_tcp_transfer_session(&outbound, &original_target)
            .await;
        let Err(error) = saturated else {
            panic!("second transfer session must fail at the ingress operation cap");
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        holder.abort();
        assert!(holder
            .await
            .expect_err("held transfer task should be cancelled")
            .is_cancelled());
        let replacement = timeout(
            Duration::from_secs(1),
            runtime.open_direct_tcp_transfer_session(&outbound, &original_target),
        )
        .await
        .expect("cancelled transfer must promptly release its operation permit")
        .expect("replacement transfer session should open");
        second_accepted_rx
            .await
            .expect("server should accept replacement transfer session");
        drop(replacement);
        let _connections = server.await.expect("join transfer permit DNS server");
    }

    #[tokio::test]
    async fn udp_client_reuses_one_direct_dns_tcp_connection() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind pooled DNS TCP server");
        let server_addr = listener.local_addr().expect("read pooled DNS address");
        let server = tokio::spawn(serve_dns_queries(listener, 2));
        let outbound = direct_tcp_outbound(server_addr);
        let runtime = test_runtime();
        let original_target = Target::new(
            TargetAddr::Ip("192.0.2.53".parse().expect("valid test IP")),
            53,
            RoutingNetwork::Udp,
        );
        for (id, domain) in [(0x1001, "first.pool.test"), (0x1002, "second.pool.test")] {
            let request = query(id, domain);
            let outcome = runtime
                .execute_message(
                    &outbound,
                    &original_target,
                    request.clone(),
                    DnsClientTransport::Udp {
                        path_payload_cap: 1_232,
                    },
                )
                .await;
            let DnsMessageOutcome::Reply(response) = outcome else {
                panic!("pooled DNS query must receive a response");
            };
            assert_eq!(&response[0..2], &request[0..2]);
            assert_eq!(&response[2..4], &0x8180_u16.to_be_bytes());
        }

        assert_eq!(
            timeout(Duration::from_secs(1), server)
                .await
                .expect("pooled DNS server should finish")
                .expect("join pooled DNS server"),
            1
        );
    }

    #[tokio::test]
    async fn sixteen_idle_tcp_clients_do_not_pin_the_shared_direct_pool() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind idle-client DNS server");
        let server_addr = listener.local_addr().expect("read idle-client DNS address");
        let server = tokio::spawn(serve_dns_queries(listener, 17));
        let outbound = direct_tcp_outbound(server_addr);
        let runtime = Arc::new(test_runtime());
        let original_target = Target::new(
            TargetAddr::Ip("192.0.2.53".parse().expect("valid test IP")),
            53,
            RoutingNetwork::Tcp,
        );
        let mut clients = Vec::new();
        let mut client_tasks = Vec::new();

        for index in 0..16 {
            let (mut client, mut inbound) = tokio::io::duplex(4_096);
            let runtime = Arc::clone(&runtime);
            let outbound = outbound.clone();
            let target = original_target.clone();
            let initial = framed_query(&format!("idle-{index}.client.test"));
            client_tasks.push(tokio::spawn(async move {
                runtime
                    .serve_tcp_stream(
                        &mut inbound,
                        initial,
                        &outbound,
                        &target,
                        Duration::from_secs(10),
                    )
                    .await
            }));

            let response_len = timeout(Duration::from_secs(1), client.read_u16())
                .await
                .expect("idle TCP client response should not stall")
                .expect("read idle TCP response length");
            let mut response = vec![0_u8; usize::from(response_len)];
            client
                .read_exact(&mut response)
                .await
                .expect("read idle TCP response");
            assert_eq!(&response[2..4], &0x8180_u16.to_be_bytes());
            clients.push(client);
        }

        let stateless = query(0x7001, "managed-after-idle.test");
        let outcome = timeout(
            Duration::from_secs(1),
            runtime.execute_message(
                &outbound,
                &Target::new(
                    original_target.addr.clone(),
                    original_target.port,
                    RoutingNetwork::Udp,
                ),
                stateless.clone(),
                DnsClientTransport::Udp {
                    path_payload_cap: 1_232,
                },
            ),
        )
        .await
        .expect("idle TCP clients must not block a managed/stateless query");
        let DnsMessageOutcome::Reply(response) = outcome else {
            panic!("stateless query after idle clients must receive a response");
        };
        assert_eq!(&response[0..2], &stateless[0..2]);
        assert_eq!(
            timeout(Duration::from_secs(1), server)
                .await
                .expect("idle-client DNS server should finish")
                .expect("join idle-client DNS server"),
            1,
            "ordinary TCP clients pinned dedicated upstream sessions"
        );

        drop(clients);
        for task in client_tasks {
            timeout(Duration::from_secs(1), task)
                .await
                .expect("idle TCP service task should observe client close")
                .expect("join idle TCP service task")
                .expect("idle TCP service task should stop cleanly");
        }
    }

    #[tokio::test]
    async fn udp_client_retires_a_stale_pooled_session_and_retries_once() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind short-lived DNS TCP server");
        let server_addr = listener.local_addr().expect("read short-lived DNS address");
        let server = tokio::spawn(serve_one_dns_query_per_connection(listener, 2));
        let outbound = direct_tcp_outbound(server_addr);
        let runtime = test_runtime();
        let original_target = Target::new(
            TargetAddr::Ip("192.0.2.53".parse().expect("valid test IP")),
            53,
            RoutingNetwork::Udp,
        );
        for (index, (id, domain)) in [(0x2001, "first.stale.test"), (0x2002, "second.stale.test")]
            .into_iter()
            .enumerate()
        {
            let request = query(id, domain);
            let outcome = runtime
                .execute_message(
                    &outbound,
                    &original_target,
                    request.clone(),
                    DnsClientTransport::Udp {
                        path_payload_cap: 1_232,
                    },
                )
                .await;
            let DnsMessageOutcome::Reply(response) = outcome else {
                panic!("stale pooled DNS session must retry on a fresh connection");
            };
            assert_eq!(&response[0..2], &request[0..2]);
            assert_eq!(&response[2..4], &0x8180_u16.to_be_bytes());
            if index == 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        assert_eq!(
            timeout(Duration::from_secs(1), server)
                .await
                .expect("short-lived DNS server should finish")
                .expect("join short-lived DNS server"),
            2
        );
    }

    #[tokio::test]
    async fn stale_pooled_session_does_not_retry_dns_update() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UPDATE retry test server");
        let server_addr = listener.local_addr().expect("read UPDATE test address");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("accept first DNS client");
            let first_len = usize::from(first.read_u16().await.expect("read first query length"));
            let mut first_query = vec![0_u8; first_len];
            first
                .read_exact(&mut first_query)
                .await
                .expect("read first query");
            let first_response = response_for(&first_query);
            first
                .write_u16(u16::try_from(first_response.len()).expect("bounded first response"))
                .await
                .expect("write first response length");
            first
                .write_all(&first_response)
                .await
                .expect("write first response");
            first.shutdown().await.expect("close stale DNS stream");

            let Ok(Ok((mut retried, _))) =
                timeout(Duration::from_millis(300), listener.accept()).await
            else {
                return false;
            };
            let retry_len = usize::from(
                retried
                    .read_u16()
                    .await
                    .expect("read unexpected retry length"),
            );
            let mut retry = vec![0_u8; retry_len];
            retried
                .read_exact(&mut retry)
                .await
                .expect("read unexpected retry");
            let retry_response = response_for(&retry);
            retried
                .write_u16(u16::try_from(retry_response.len()).expect("bounded retry response"))
                .await
                .expect("write retry response length");
            retried
                .write_all(&retry_response)
                .await
                .expect("write retry response");
            true
        });
        let outbound = direct_tcp_outbound(server_addr);
        let runtime = test_runtime();
        let original_target = Target::new(
            TargetAddr::Ip("192.0.2.53".parse().expect("valid test IP")),
            53,
            RoutingNetwork::Udp,
        );
        let first = query(0x3001, "prime.update.test");
        let first_outcome = runtime
            .execute_message(
                &outbound,
                &original_target,
                first,
                DnsClientTransport::Udp {
                    path_payload_cap: 1_232,
                },
            )
            .await;
        assert!(matches!(first_outcome, DnsMessageOutcome::Reply(_)));
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Opcode 5 (UPDATE) can have side effects and must never be replayed
        // merely because a reused connection turned out to be stale.
        let update = query_with_flags_and_type(0x3002, "zone.update.test", 5 << 11, DNS_TYPE_A);
        let update_outcome = runtime
            .execute_message(
                &outbound,
                &original_target,
                update,
                DnsClientTransport::Udp {
                    path_payload_cap: 1_232,
                },
            )
            .await;
        let DnsMessageOutcome::Reply(update_response) = update_outcome else {
            panic!("failed UPDATE should receive SERVFAIL");
        };
        assert_eq!(update_response[3] & 0x0f, DNS_RCODE_SERVFAIL as u8);
        assert!(
            !timeout(Duration::from_secs(1), server)
                .await
                .expect("UPDATE retry observer should finish")
                .expect("join UPDATE retry observer"),
            "DNS UPDATE was replayed on a fresh connection"
        );
    }

    #[tokio::test]
    async fn udp_axfr_and_ixfr_are_refused_without_dialing_tcp() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind transfer refusal observer");
        let server_addr = listener
            .local_addr()
            .expect("read transfer refusal observer address");
        let outbound = direct_tcp_outbound(server_addr);
        let runtime = test_runtime();
        let original_target = Target::new(
            TargetAddr::Ip("192.0.2.53".parse().expect("valid test IP")),
            53,
            RoutingNetwork::Udp,
        );
        for (id, qtype) in [(0x4001, DNS_TYPE_AXFR), (0x4002, DNS_TYPE_IXFR)] {
            let transfer = query_with_flags_and_type(id, "transfer.test", 0x0100, qtype);
            let direct_response = runtime
                .direct_executor
                .exchange_stateless(&outbound, &original_target, &transfer)
                .await
                .expect("shared Direct executor should refuse a UDP transfer");
            assert_eq!(direct_response[3] & 0x0f, 5);
            let outcome = runtime
                .execute_message(
                    &outbound,
                    &original_target,
                    transfer,
                    DnsClientTransport::Udp {
                        path_payload_cap: 1_232,
                    },
                )
                .await;
            let DnsMessageOutcome::Reply(response) = outcome else {
                panic!("UDP transfer query should receive REFUSED");
            };
            assert_eq!(u16::from_be_bytes([response[0], response[1]]), id);
            assert_eq!(response[3] & 0x0f, 5, "UDP transfer must be REFUSED");
        }
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "UDP transfer refusal must happen before opening an upstream TCP stream"
        );
    }

    #[tokio::test]
    async fn cancelled_exchange_does_not_recycle_partially_consumed_session() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cancellation test server");
        let server_addr = listener
            .local_addr()
            .expect("read cancellation test address");
        let server = tokio::spawn(async move {
            let (mut abandoned, _) = listener.accept().await.expect("accept abandoned query");
            let abandoned_len = usize::from(
                abandoned
                    .read_u16()
                    .await
                    .expect("read abandoned query length"),
            );
            let mut abandoned_query = vec![0_u8; abandoned_len];
            abandoned
                .read_exact(&mut abandoned_query)
                .await
                .expect("read abandoned query");
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(abandoned);

            let (mut fresh, _) = timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("cancelled session must not be reused")
                .expect("accept fresh query");
            let fresh_len = usize::from(fresh.read_u16().await.expect("read fresh query length"));
            let mut fresh_query = vec![0_u8; fresh_len];
            fresh
                .read_exact(&mut fresh_query)
                .await
                .expect("read fresh query");
            let response = response_for(&fresh_query);
            fresh
                .write_u16(u16::try_from(response.len()).expect("bounded fresh response"))
                .await
                .expect("write fresh response length");
            fresh
                .write_all(&response)
                .await
                .expect("write fresh response");
        });
        let outbound = direct_tcp_outbound(server_addr);
        let runtime = test_runtime();
        let original_target = Target::new(
            TargetAddr::Ip("192.0.2.53".parse().expect("valid test IP")),
            53,
            RoutingNetwork::Udp,
        );

        let abandoned = query(0x5001, "cancelled.test");
        assert!(timeout(
            Duration::from_millis(25),
            runtime
                .direct_executor
                .exchange_stateless(&outbound, &original_target, &abandoned,),
        )
        .await
        .is_err());

        // UPDATE is intentionally non-retryable. Its success proves it used a
        // fresh connection rather than the cancelled, now-poisoned stream.
        let update = query_with_flags_and_type(0x5002, "fresh.test", 5 << 11, DNS_TYPE_A);
        let response = runtime
            .direct_executor
            .exchange_stateless(&outbound, &original_target, &update)
            .await
            .expect("fresh non-retryable exchange should succeed");
        assert_eq!(&response[0..2], &update[0..2]);
        timeout(Duration::from_secs(1), server)
            .await
            .expect("cancellation server should finish")
            .expect("join cancellation server");
    }

    #[tokio::test]
    async fn idle_pool_closes_connection_without_waiting_for_another_query() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind idle-expiry test server");
        let server_addr = listener
            .local_addr()
            .expect("read idle-expiry test address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept idle DNS client");
            let query_len = usize::from(stream.read_u16().await.expect("read idle query length"));
            let mut query = vec![0_u8; query_len];
            stream
                .read_exact(&mut query)
                .await
                .expect("read idle query");
            let response = response_for(&query);
            stream
                .write_u16(u16::try_from(response.len()).expect("bounded idle response"))
                .await
                .expect("write idle response length");
            stream
                .write_all(&response)
                .await
                .expect("write idle response");
            stream.flush().await.expect("flush idle response");

            let mut byte = [0_u8; 1];
            assert_eq!(
                timeout(Duration::from_secs(1), stream.read(&mut byte))
                    .await
                    .expect("idle pool should close connection")
                    .expect("observe idle connection close"),
                0
            );
        });
        let resolver: Arc<dyn DnsResolver> = Arc::new(SystemDnsResolver);
        let executor = DnsDirectExecutor::with_pool_config(
            Arc::clone(&resolver),
            Arc::new(TransportDialer::system().expect("build idle-expiry dialer")),
            Vec::new(),
            DnsDirectPoolConfig::from_runtime_limit(16, Duration::from_millis(30)),
        );
        let outbound = direct_tcp_outbound(server_addr);
        let original_target = Target::new(
            TargetAddr::Ip("192.0.2.53".parse().expect("valid test IP")),
            53,
            RoutingNetwork::Udp,
        );

        executor
            .exchange_stateless(
                &outbound,
                &original_target,
                &query(0x6001, "idle-expiry.test"),
            )
            .await
            .expect("idle-expiry query should succeed");
        timeout(Duration::from_secs(1), server)
            .await
            .expect("idle-expiry server should finish")
            .expect("join idle-expiry server");
    }

    #[tokio::test]
    async fn direct_dns_tcp_pool_bounds_per_key_and_global_leases() {
        let pool = DirectDnsTcpSessionPool::with_config(DnsDirectPoolConfig {
            per_key_connections: 1,
            global_connections: 2,
            max_keys: 3,
            idle_ttl_cap: Duration::from_secs(60),
        });
        let first_outbound = DnsOutbound::new(DnsOutboundSettings::default());
        let second_outbound = DnsOutbound::new(DnsOutboundSettings::default());
        let third_outbound = DnsOutbound::new(DnsOutboundSettings::default());
        let target = Target::new(
            TargetAddr::Domain("pool.test".to_owned()),
            53,
            RoutingNetwork::Tcp,
        );
        let first_key = DirectDnsTcpPoolKey::new(&first_outbound, &target);
        let second_key = DirectDnsTcpPoolKey::new(&second_outbound, &target);
        let third_key = DirectDnsTcpPoolKey::new(&third_outbound, &target);

        let idle_ttl = Duration::from_secs(60);
        let first = pool
            .lease(&first_key, idle_ttl)
            .await
            .expect("lease first pool key");
        assert!(
            timeout(Duration::from_millis(10), pool.lease(&first_key, idle_ttl))
                .await
                .is_err()
        );
        let second = pool
            .lease(&second_key, idle_ttl)
            .await
            .expect("lease second pool key");
        assert!(
            timeout(Duration::from_millis(10), pool.lease(&third_key, idle_ttl))
                .await
                .is_err()
        );
        drop(first);
        drop(second);

        let first_connection = pool
            .reserve_connection_slot()
            .expect("reserve first connection");
        let second_connection = pool
            .reserve_connection_slot()
            .expect("reserve second connection");
        assert_eq!(
            pool.reserve_connection_slot().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(first_connection);
        drop(second_connection);
    }
}
