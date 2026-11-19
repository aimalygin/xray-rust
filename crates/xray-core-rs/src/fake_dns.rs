use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use xray_config::{DnsFakeIpConfig, DnsQueryStrategy};
use xray_transport::RouteProbe;

/// Stateful, bounded mapping between DNS names and synthetic IPv4 addresses.
///
/// The mapper owns no ingress or transport concerns. Callers decide how DNS
/// messages are parsed and synthesized, and which addresses must be reserved
/// by their embedding.
#[derive(Debug)]
pub(crate) struct FakeIpMapper {
    query_strategy: DnsQueryStrategy,
    /// Set for `queryStrategy: "UseSystem"`: a family without a route gets
    /// no answers, as Xray-core's `checkSystem` leaves it.
    route_probe: Option<Arc<dyn RouteProbe>>,
    ttl: u32,
    network_base: u32,
    address_count: u64,
    first_offset: u64,
    allocation_span: u64,
    max_mappings: usize,
    reserved_ipv4: Box<[Ipv4Addr]>,
    next_offset: u64,
    entries: Vec<Option<FakeIpEntry>>,
    lease_index: BTreeSet<(Instant, usize)>,
    by_domain: HashMap<Arc<str>, usize>,
    by_ipv4: HashMap<Ipv4Addr, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FakeIpLookup {
    Mapped(Arc<str>),
    InPoolUnmapped,
    Outside,
}

#[derive(Debug)]
struct FakeIpEntry {
    domain: Arc<str>,
    ip: Ipv4Addr,
    reusable_after: Instant,
}

/// The pool definition carried-over mappings must share to be adopted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeIpPool {
    network_base: u32,
    address_count: u64,
    max_mappings: usize,
}

impl FakeIpMapper {
    /// Builds a mapper from core DNS configuration.
    ///
    /// Sequential allocation starts at a random point of the pool, so a core
    /// restart does not hand the same first addresses to different domains
    /// while applications may still hold previously advertised fake IPs.
    ///
    /// Returns `None` when TTL is zero, the pool is not IPv4, has no
    /// allocatable address, or is smaller than the configured mapping capacity
    /// after reservations.
    pub(crate) fn from_config(
        config: &DnsFakeIpConfig,
        query_strategy: DnsQueryStrategy,
        reserved_ipv4: &[Ipv4Addr],
    ) -> Option<Self> {
        Self::from_config_with_start(config, query_strategy, reserved_ipv4, rand::random())
    }

    /// Same as [`Self::from_config`], with allocation starting at
    /// `start % allocatable addresses` past the first allocatable address.
    pub(crate) fn from_config_with_start(
        config: &DnsFakeIpConfig,
        query_strategy: DnsQueryStrategy,
        reserved_ipv4: &[Ipv4Addr],
        start: u64,
    ) -> Option<Self> {
        if !config.enabled || config.ttl == 0 {
            return None;
        }
        let IpAddr::V4(ipv4_network) = config.ipv4_pool.network() else {
            return None;
        };
        let ipv4_prefix = config.ipv4_pool.prefix();
        if ipv4_prefix > 32 {
            return None;
        }

        let address_count = 1_u64 << u32::from(32 - ipv4_prefix);
        let first_offset: u64 = if address_count > 2 { 1 } else { 0 };
        let allocation_span = if address_count > 2 {
            address_count - 2
        } else {
            address_count
        };
        if allocation_span == 0 {
            return None;
        }

        let mask = if ipv4_prefix == 0 {
            0
        } else {
            u32::MAX << u32::from(32 - ipv4_prefix)
        };
        let network_base = u32::from(ipv4_network) & mask;
        let allocation_range = first_offset..first_offset.saturating_add(allocation_span);
        let mut reserved_ipv4 = reserved_ipv4.to_vec();
        reserved_ipv4.sort_unstable();
        reserved_ipv4.dedup();
        let reserved_address_count = reserved_ipv4
            .iter()
            .filter(|ip| {
                u32::from(**ip)
                    .checked_sub(network_base)
                    .map(u64::from)
                    .is_some_and(|offset| allocation_range.contains(&offset))
            })
            .count();
        let available_addresses = allocation_span - reserved_address_count as u64;
        if config.pool_size == 0 || u64::from(config.pool_size) > available_addresses {
            return None;
        }

        Some(Self {
            query_strategy,
            route_probe: None,
            ttl: config.ttl,
            network_base,
            address_count,
            first_offset,
            allocation_span,
            max_mappings: usize::try_from(config.pool_size).ok()?,
            reserved_ipv4: reserved_ipv4.into_boxed_slice(),
            next_offset: start % allocation_span,
            entries: Vec::new(),
            lease_index: BTreeSet::new(),
            by_domain: HashMap::new(),
            by_ipv4: HashMap::new(),
        })
    }

    pub(crate) fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Narrows the answers to the families `probe` reports a route for.
    pub(crate) fn with_route_probe(mut self, probe: Arc<dyn RouteProbe>) -> Self {
        self.route_probe = Some(probe);
        self
    }

    /// Whether an `A` query (or with `ipv6`, an `AAAA` query) may be
    /// answered: the strategy allows the family, and with a route probe the
    /// system has a route for it.
    pub(crate) fn answers(&self, ipv6: bool) -> bool {
        let allowed = match self.query_strategy {
            DnsQueryStrategy::UseIp => true,
            DnsQueryStrategy::UseIpv4 => !ipv6,
            DnsQueryStrategy::UseIpv6 => ipv6,
        };
        allowed
            && self.route_probe.as_ref().is_none_or(|probe| {
                let routes = probe.families();
                if ipv6 {
                    routes.ipv6
                } else {
                    routes.ipv4
                }
            })
    }

    #[cfg(test)]
    pub(crate) fn mapping_count(&self) -> usize {
        self.by_domain.len()
    }

    /// Returns a stable synthetic IPv4 address for a normalized DNS name.
    ///
    /// A mapping is never reassigned before the TTL most recently advertised
    /// for it has elapsed. Capacity exhaustion therefore fails closed until
    /// the earliest lease becomes reusable.
    pub(crate) fn allocate_ipv4(&mut self, domain: &str) -> Option<Ipv4Addr> {
        self.allocate_ipv4_at(domain, Instant::now())
    }

    fn allocate_ipv4_at(&mut self, domain: &str, now: Instant) -> Option<Ipv4Addr> {
        let domain = normalize_dns_domain(domain)?;
        let reusable_after = now.checked_add(Duration::from_secs(u64::from(self.ttl)))?;
        if let Some(&slot) = self.by_domain.get(domain.as_str()) {
            let entry = self.entries.get_mut(slot)?.as_mut()?;
            let ip = entry.ip;
            self.lease_index.remove(&(entry.reusable_after, slot));
            entry.reusable_after = reusable_after;
            self.lease_index.insert((reusable_after, slot));
            return Some(ip);
        }

        if self.by_domain.len() >= self.max_mappings {
            let (slot, ip) = self.remove_earliest_expired(now)?;
            self.insert_mapping(slot, Arc::from(domain), ip, reusable_after)?;
            return Some(ip);
        }

        let slot = self.entries.len();
        let ip = self.next_available_ipv4()?;
        self.insert_mapping(slot, Arc::from(domain), ip, reusable_after)?;
        Some(ip)
    }

    /// Resolves a synthetic IPv4 address back to its DNS name. Reverse lookups
    /// deliberately do not extend the lease because they advertise no DNS TTL.
    pub(crate) fn domain_for_ipv4(&mut self, ip: Ipv4Addr) -> Option<Arc<str>> {
        let slot = *self.by_ipv4.get(&ip)?;
        Some(Arc::clone(&self.entries.get(slot)?.as_ref()?.domain))
    }

    /// Classifies a client-supplied IPv4 address without erasing whether an
    /// absent mapping still belongs to the configured fake-IP pool.
    pub(crate) fn lookup_ipv4(&mut self, ip: Ipv4Addr) -> FakeIpLookup {
        if let Some(domain) = self.domain_for_ipv4(ip) {
            return FakeIpLookup::Mapped(domain);
        }
        if self.contains_ipv4(ip) {
            FakeIpLookup::InPoolUnmapped
        } else {
            FakeIpLookup::Outside
        }
    }

    fn contains_ipv4(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip)
            .checked_sub(self.network_base)
            .map(u64::from)
            .is_some_and(|offset| offset < self.address_count)
    }

    fn next_available_ipv4(&mut self) -> Option<Ipv4Addr> {
        for _ in 0..self.allocation_span {
            let offset = self.first_offset + (self.next_offset % self.allocation_span);
            self.next_offset = (self.next_offset + 1) % self.allocation_span;
            let raw_ip = self.network_base.checked_add(u32::try_from(offset).ok()?)?;
            let ip = Ipv4Addr::from(raw_ip);
            if self.reserved_ipv4.binary_search(&ip).is_ok() {
                continue;
            }
            if !self.by_ipv4.contains_key(&ip) {
                return Some(ip);
            }
        }
        None
    }

    fn insert_mapping(
        &mut self,
        slot: usize,
        domain: Arc<str>,
        ip: Ipv4Addr,
        reusable_after: Instant,
    ) -> Option<()> {
        let entry = FakeIpEntry {
            domain: Arc::clone(&domain),
            ip,
            reusable_after,
        };
        if slot == self.entries.len() {
            self.entries.push(Some(entry));
        } else {
            *self.entries.get_mut(slot)? = Some(entry);
        }
        self.by_domain.insert(domain, slot);
        self.by_ipv4.insert(ip, slot);
        self.lease_index
            .insert((reusable_after, slot))
            .then_some(())
    }

    fn remove_earliest_expired(&mut self, now: Instant) -> Option<(usize, Ipv4Addr)> {
        let &(reusable_after, slot) = self.lease_index.first()?;
        if reusable_after > now {
            return None;
        }
        self.lease_index.remove(&(reusable_after, slot));
        let entry = self.entries.get_mut(slot)?.take()?;
        self.by_domain.remove(entry.domain.as_ref());
        self.by_ipv4.remove(&entry.ip);
        Some((slot, entry.ip))
    }

    fn pool(&self) -> FakeIpPool {
        FakeIpPool {
            network_base: self.network_base,
            address_count: self.address_count,
            max_mappings: self.max_mappings,
        }
    }

    /// Whether this mapper could have handed out `ip`: an allocatable pool
    /// address the embedding did not reserve.
    fn is_allocatable(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip)
            .checked_sub(self.network_base)
            .map(u64::from)
            .and_then(|offset| offset.checked_sub(self.first_offset))
            .is_some_and(|position| position < self.allocation_span)
            && self.reserved_ipv4.binary_search(&ip).is_err()
    }

    fn snapshot(&self) -> FakeIpSnapshot {
        FakeIpSnapshot {
            pool: self.pool(),
            entries: self
                .entries
                .iter()
                .flatten()
                .map(|entry| (Arc::clone(&entry.domain), entry.ip, entry.reusable_after))
                .collect(),
        }
    }

    /// Adopts the mappings of a stopped mapper with the same pool, returning
    /// how many. A lease still running is extended to at least a full TTL
    /// from `now`, since applications keep addresses past it; one already
    /// run out stays reusable, so a table full of stale mappings cannot fail
    /// the new mapper closed. Allocation goes on from this mapper's own
    /// random start and skips the adopted addresses as it skips any mapped
    /// one.
    fn restore(&mut self, snapshot: FakeIpSnapshot, now: Instant) -> usize {
        if snapshot.pool != self.pool() {
            return 0;
        }
        let extended = now.checked_add(Duration::from_secs(u64::from(self.ttl)));
        let mut restored = 0;
        for (domain, ip, saved) in snapshot.entries {
            if self.by_domain.len() >= self.max_mappings {
                break;
            }
            if !self.is_allocatable(ip)
                || self.by_ipv4.contains_key(&ip)
                || self.by_domain.contains_key(&domain)
            {
                continue;
            }
            let reusable_after = match extended {
                Some(extended) if saved > now => saved.max(extended),
                _ => saved,
            };
            if self
                .insert_mapping(self.entries.len(), domain, ip, reusable_after)
                .is_some()
            {
                restored += 1;
            }
        }
        restored
    }
}

/// The mappings of a stopped mapper, at most `poolSize` of them.
struct FakeIpSnapshot {
    pool: FakeIpPool,
    entries: Vec<(Arc<str>, Ipv4Addr, Instant)>,
}

static PROCESS_FAKE_IP_STORE: LazyLock<FakeIpStore> = LazyLock::new(FakeIpStore::new);

/// Where a stopping [`Core`](crate::Core) leaves its fake-IP mappings for
/// the next `Core` started with the same store.
///
/// Applications keep the fake IPs they were given in caches and connection
/// pools past the DNS TTL. A `Core` started with fake IP takes the mappings
/// held here and, when they come from the same `ipv4Pool` and `poolSize`,
/// adopts them, so those addresses keep naming the same domains instead of
/// being unmapped. Any other `Core` started with the store drops them. A
/// store holds at most one set, at most `poolSize` mappings, replaced each
/// time a `Core` using it stops; nothing is written to disk.
///
/// Every `Core` uses [`FakeIpStore::process`] unless given another with
/// [`Core::with_fake_ip_store`](crate::Core::with_fake_ip_store). Clones
/// share what is held.
#[derive(Clone, Default)]
pub struct FakeIpStore(Arc<Mutex<Option<FakeIpSnapshot>>>);

impl FakeIpStore {
    /// An empty store of its own, shared only by the cores given it or one
    /// of its clones.
    pub fn new() -> Self {
        Self::default()
    }

    /// The process-wide store every `Core` uses by default.
    pub fn process() -> Self {
        PROCESS_FAKE_IP_STORE.clone()
    }

    /// Drops the held mappings, for a host done with fake IP before it is
    /// done with the process.
    pub fn clear(&self) {
        drop(self.take());
    }

    fn take(&self) -> Option<FakeIpSnapshot> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }

    fn save(&self, snapshot: FakeIpSnapshot) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(snapshot);
    }

    /// How many mappings the store holds.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or(0, |snapshot| snapshot.entries.len())
    }
}

impl std::fmt::Debug for FakeIpStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeIpStore")
            .finish_non_exhaustive()
    }
}

/// Carries a running core's fake-IP mappings across a restart.
///
/// Built as the core starts, it moves the mappings its store holds into the
/// new mapper. Dropped as the core stops, or with a running core, it leaves
/// the mapper's mappings in the store for the next core.
pub(crate) struct FakeIpCarryOver {
    mapper: Arc<Mutex<FakeIpMapper>>,
    store: FakeIpStore,
    adopted: usize,
}

impl FakeIpCarryOver {
    /// Takes what `store` holds: `mapper` adopts the mappings when they come
    /// from its pool, and they are dropped otherwise, as they are by a core
    /// without fake IP (`None`), which carries nothing over.
    pub(crate) fn adopt(
        store: &FakeIpStore,
        mapper: Option<Arc<Mutex<FakeIpMapper>>>,
    ) -> Option<Self> {
        let held = store.take();
        let mapper = mapper?;
        let adopted = held.map_or(0, |snapshot| {
            mapper
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .restore(snapshot, Instant::now())
        });
        Some(Self {
            mapper,
            store: store.clone(),
            adopted,
        })
    }

    /// How many mappings the mapper took over as the core started.
    pub(crate) fn adopted(&self) -> usize {
        self.adopted
    }

    #[cfg(test)]
    pub(crate) fn mapper(&self) -> &Arc<Mutex<FakeIpMapper>> {
        &self.mapper
    }
}

impl Drop for FakeIpCarryOver {
    fn drop(&mut self) {
        let mapper = self.mapper.lock().unwrap_or_else(PoisonError::into_inner);
        // A mapper without mappings leaves what another core saved meanwhile.
        if mapper.by_domain.is_empty() {
            return;
        }
        let snapshot = mapper.snapshot();
        drop(mapper);
        self.store.save(snapshot);
    }
}

impl std::fmt::Debug for FakeIpCarryOver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeIpCarryOver")
            .field("adopted", &self.adopted)
            .finish_non_exhaustive()
    }
}

fn normalize_dns_domain(domain: &str) -> Option<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_config::IpCidr;

    fn config(network: Ipv4Addr, prefix: u8, pool_size: u32, ttl: u32) -> DnsFakeIpConfig {
        DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddr::V4(network), prefix).unwrap(),
            pool_size,
            ttl,
        }
    }

    #[test]
    fn allocation_is_stable_and_reverse_lookup_normalizes_domain() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 32_768, 60);
        let mut mapper = FakeIpMapper::from_config(
            &config,
            DnsQueryStrategy::UseIp,
            &[Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2)],
        )
        .unwrap();

        let first = mapper.allocate_ipv4("Example.COM.").unwrap();
        let second = mapper.allocate_ipv4("example.com").unwrap();

        assert_ne!(mapper.lookup_ipv4(first), FakeIpLookup::Outside);
        assert!(![Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2)].contains(&first));
        assert_eq!(second, first);
        assert_eq!(
            mapper.domain_for_ipv4(first).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn allocation_skips_embedding_reservations_without_double_counting_duplicates() {
        let config = config(Ipv4Addr::new(192, 0, 2, 0), 29, 4, 60);
        let reserved = [
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 3),
        ];
        let mut mapper =
            FakeIpMapper::from_config_with_start(&config, DnsQueryStrategy::UseIp, &reserved, 0)
                .unwrap();

        let first = mapper.allocate_ipv4("first.example").unwrap();
        let second = mapper.allocate_ipv4("second.example").unwrap();

        assert_eq!(first, Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(second, Ipv4Addr::new(192, 0, 2, 4));
    }

    #[test]
    fn capacity_fails_closed_until_the_earliest_advertised_lease_expires() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 2, 120);
        let mut mapper =
            FakeIpMapper::from_config_with_start(&config, DnsQueryStrategy::UseIp, &[], 0).unwrap();
        let start = Instant::now();
        let first = mapper.allocate_ipv4_at("first.example", start).unwrap();
        let second = mapper
            .allocate_ipv4_at("second.example", start + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            mapper.allocate_ipv4_at("first.example", start + Duration::from_secs(60)),
            Some(first)
        );
        assert_eq!(
            mapper.domain_for_ipv4(second).as_deref(),
            Some("second.example")
        );

        assert_eq!(
            mapper.allocate_ipv4_at("third.example", start + Duration::from_secs(120)),
            None
        );
        let third = mapper
            .allocate_ipv4_at("third.example", start + Duration::from_secs(121))
            .unwrap();

        assert_eq!(first, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(second, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(third, second);
        assert_eq!(
            mapper.lookup_ipv4(second),
            FakeIpLookup::Mapped(Arc::from("third.example"))
        );
        assert_eq!(
            mapper.lookup_ipv4(Ipv4Addr::new(203, 0, 113, 1)),
            FakeIpLookup::Outside
        );
    }

    #[test]
    fn full_single_address_pool_never_reassigns_before_refreshed_ttl() {
        let config = config(Ipv4Addr::new(198, 19, 0, 1), 32, 1, 60);
        let mut mapper = FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &[]).unwrap();
        let start = Instant::now();
        let first_ip = mapper.allocate_ipv4_at("first.example", start).unwrap();

        assert_eq!(
            mapper.allocate_ipv4_at("first.example", start + Duration::from_secs(30)),
            Some(first_ip)
        );
        assert_eq!(
            mapper.allocate_ipv4_at("second.example", start + Duration::from_secs(60)),
            None
        );
        assert_eq!(
            mapper.lookup_ipv4(first_ip),
            FakeIpLookup::Mapped(Arc::from("first.example"))
        );

        assert_eq!(
            mapper.allocate_ipv4_at("second.example", start + Duration::from_secs(90)),
            Some(first_ip)
        );
        assert_eq!(
            mapper.lookup_ipv4(first_ip),
            FakeIpLookup::Mapped(Arc::from("second.example"))
        );
    }

    #[test]
    fn lookup_distinguishes_live_mapping_from_unmapped_pool_addresses() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 30, 1, 60);
        let mut mapper = FakeIpMapper::from_config(
            &config,
            DnsQueryStrategy::UseIp,
            &[Ipv4Addr::new(198, 18, 0, 1)],
        )
        .unwrap();
        let mapped = mapper.allocate_ipv4("mapped.example").unwrap();

        assert_eq!(
            mapper.lookup_ipv4(mapped),
            FakeIpLookup::Mapped(Arc::from("mapped.example"))
        );
        assert_eq!(
            mapper.lookup_ipv4(Ipv4Addr::new(198, 18, 0, 1)),
            FakeIpLookup::InPoolUnmapped
        );
        assert_eq!(
            mapper.lookup_ipv4(Ipv4Addr::new(198, 18, 0, 0)),
            FakeIpLookup::InPoolUnmapped
        );
        assert_eq!(
            mapper.lookup_ipv4(Ipv4Addr::new(198, 18, 0, 3)),
            FakeIpLookup::InPoolUnmapped
        );
    }

    #[test]
    fn allocation_start_differs_between_mappers_so_restarts_do_not_reuse_addresses() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 32_768, 60);
        let reserved = [Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2)];
        let firsts: Vec<_> = (0..8)
            .map(|_| {
                FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &reserved)
                    .unwrap()
                    .allocate_ipv4("example.com")
                    .unwrap()
            })
            .collect();

        assert!(firsts.iter().any(|ip| *ip != firsts[0]), "{firsts:?}");
    }

    #[test]
    fn seeded_start_allocates_sequentially_and_wraps_past_reservations() {
        let config = config(Ipv4Addr::new(192, 0, 2, 0), 29, 4, 60);
        let reserved = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 3)];
        // Allocatable offsets are .1..=.6; start 4 points at .5.
        let mut mapper =
            FakeIpMapper::from_config_with_start(&config, DnsQueryStrategy::UseIp, &reserved, 4)
                .unwrap();

        let allocated: Vec<_> = ["a.example", "b.example", "c.example", "d.example"]
            .into_iter()
            .map(|domain| mapper.allocate_ipv4(domain).unwrap())
            .collect();

        assert_eq!(
            allocated,
            [
                Ipv4Addr::new(192, 0, 2, 5),
                Ipv4Addr::new(192, 0, 2, 6),
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(192, 0, 2, 4),
            ]
        );
    }

    #[test]
    fn restore_adopts_a_stopped_mappers_mappings_and_extends_only_running_leases() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 2, 60);
        let start = Instant::now();
        let mut stopped = FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &[]).unwrap();
        let expired = stopped.allocate_ipv4_at("expired.example", start).unwrap();
        let running = stopped
            .allocate_ipv4_at("running.example", start + Duration::from_secs(40))
            .unwrap();

        let mut started = FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &[]).unwrap();
        let now = start + Duration::from_secs(70);
        assert_eq!(started.restore(stopped.snapshot(), now), 2);

        assert_eq!(
            started.lookup_ipv4(expired),
            FakeIpLookup::Mapped(Arc::from("expired.example"))
        );
        assert_eq!(
            started.lookup_ipv4(running),
            FakeIpLookup::Mapped(Arc::from("running.example"))
        );
        // The expired lease makes room at once; the running one was extended
        // from its own deadline at 100 s to a full TTL from the restore.
        assert_eq!(
            started.allocate_ipv4_at("new.example", start + Duration::from_secs(75)),
            Some(expired)
        );
        assert_eq!(
            started.allocate_ipv4_at("newer.example", start + Duration::from_secs(129)),
            None
        );
        assert_eq!(
            started.allocate_ipv4_at("newer.example", start + Duration::from_secs(130)),
            Some(running)
        );
    }

    #[test]
    fn restore_skips_another_pool_and_addresses_the_new_mapper_reserves() {
        let config_a = config(Ipv4Addr::new(192, 0, 2, 0), 29, 4, 60);
        let mut stopped =
            FakeIpMapper::from_config_with_start(&config_a, DnsQueryStrategy::UseIp, &[], 0)
                .unwrap();
        let first = stopped.allocate_ipv4("first.example").unwrap();
        let second = stopped.allocate_ipv4("second.example").unwrap();
        assert_eq!(first, Ipv4Addr::new(192, 0, 2, 1));

        let other_size = config(Ipv4Addr::new(192, 0, 2, 0), 29, 3, 60);
        let mut other =
            FakeIpMapper::from_config(&other_size, DnsQueryStrategy::UseIp, &[]).unwrap();
        assert_eq!(other.restore(stopped.snapshot(), Instant::now()), 0);
        assert_eq!(other.mapping_count(), 0);

        let mut reserving =
            FakeIpMapper::from_config(&config_a, DnsQueryStrategy::UseIp, &[first]).unwrap();
        assert_eq!(reserving.restore(stopped.snapshot(), Instant::now()), 1);
        assert_eq!(reserving.lookup_ipv4(first), FakeIpLookup::InPoolUnmapped);
        assert_eq!(
            reserving.domain_for_ipv4(second).as_deref(),
            Some("second.example")
        );
        assert_ne!(reserving.allocate_ipv4("first.example"), Some(first));
    }

    #[test]
    fn a_store_hands_its_mappings_to_the_next_mapper_of_the_pool_and_drops_them_otherwise() {
        let config_a = config(Ipv4Addr::new(198, 18, 0, 0), 15, 64, 60);
        let config_b = config(Ipv4Addr::new(198, 20, 0, 0), 15, 64, 60);
        let mapper = |config: &DnsFakeIpConfig| {
            Some(Arc::new(Mutex::new(
                FakeIpMapper::from_config(config, DnsQueryStrategy::UseIp, &[]).unwrap(),
            )))
        };
        let store = FakeIpStore::new();
        let leave = |config: &DnsFakeIpConfig| {
            let carry_over = FakeIpCarryOver::adopt(&store, mapper(config)).unwrap();
            let ip = carry_over
                .mapper()
                .lock()
                .unwrap()
                .allocate_ipv4("carried.example")
                .unwrap();
            drop(carry_over);
            ip
        };

        let ip = leave(&config_a);
        assert_eq!(store.held(), 1);
        let carry_over = FakeIpCarryOver::adopt(&store, mapper(&config_a)).unwrap();
        assert_eq!(carry_over.adopted(), 1);
        assert_eq!(store.held(), 0);
        assert_eq!(
            carry_over
                .mapper()
                .lock()
                .unwrap()
                .domain_for_ipv4(ip)
                .as_deref(),
            Some("carried.example")
        );
        drop(carry_over);
        assert_eq!(store.held(), 1);

        // A core without fake IP, or with another pool, drops them.
        assert!(FakeIpCarryOver::adopt(&store, None).is_none());
        assert_eq!(store.held(), 0);
        leave(&config_a);
        let carry_over = FakeIpCarryOver::adopt(&store, mapper(&config_b)).unwrap();
        assert_eq!(carry_over.adopted(), 0);
        assert_eq!(store.held(), 0);
        // Its mapper made no mapping, so stopping it leaves nothing.
        drop(carry_over);
        assert_eq!(store.held(), 0);

        leave(&config_a);
        store.clear();
        assert_eq!(store.held(), 0);
        assert_eq!(FakeIpStore::new().held(), 0);
    }

    #[test]
    fn response_metadata_is_preserved_from_core_config() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 2, 123);
        let mapper = FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIpv6, &[]).unwrap();

        assert_eq!(mapper.ttl(), 123);
        assert!(mapper.answers(true));
        assert!(!mapper.answers(false));
    }

    #[test]
    fn disabled_config_does_not_construct_mapper() {
        let mut config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 2, 60);
        config.enabled = false;

        let mapper = FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &[]);

        assert!(mapper.is_none());
    }

    #[test]
    fn zero_ttl_config_does_not_construct_mapper() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 2, 0);

        let mapper = FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &[]);

        assert!(mapper.is_none());
    }
}
