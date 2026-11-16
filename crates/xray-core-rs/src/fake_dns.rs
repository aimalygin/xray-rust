use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use xray_config::{DnsFakeIpConfig, DnsQueryStrategy};
use xray_transport::RouteProbe;

/// Pool positions a new name probes from its home address for a free or
/// expired one. Past them, and only below capacity, the search for a free
/// address goes on around the pool.
const PROBE_WINDOW: u64 = 64;

/// The mappings the last stopped core left for the next core this process
/// starts with the same pool.
static PROCESS_CARRY_OVER: FakeIpCarryOverStore = FakeIpCarryOverStore::new();

/// Stateful, bounded mapping between DNS names and synthetic IPv4 addresses.
///
/// The mapper owns no ingress or transport concerns. Callers decide how DNS
/// messages are parsed and synthesized, and which addresses must be reserved
/// by their embedding.
///
/// A name's address derives from a stable hash of the name, so a fresh
/// mapper, in a restarted core or a restarted process, gives a name the
/// address an application may still hold from before instead of handing that
/// address to another name.
#[derive(Debug)]
pub(crate) struct FakeIpMapper {
    query_strategy: DnsQueryStrategy,
    /// Set for `queryStrategy: "UseSystem"`: a family without a route gets
    /// no answers, as Xray-core's `checkSystem` leaves it.
    route_probe: Option<Arc<dyn RouteProbe>>,
    ttl: u32,
    pool: FakeIpPool,
    network_base: u32,
    address_count: u64,
    first_offset: u64,
    allocation_span: u64,
    max_mappings: usize,
    reserved_ipv4: Box<[Ipv4Addr]>,
    lease_index: BTreeSet<(Instant, Ipv4Addr)>,
    by_domain: HashMap<Arc<str>, Ipv4Addr>,
    by_ipv4: HashMap<Ipv4Addr, FakeIpEntry>,
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
    reusable_after: Instant,
}

/// The pool definition carried-over mappings must share to be adopted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeIpPool {
    network_base: u32,
    prefix: u8,
    pool_size: u32,
}

impl FakeIpMapper {
    /// Builds a mapper from core DNS configuration.
    ///
    /// Returns `None` when TTL is zero, the pool is not IPv4, has no
    /// allocatable address, or is smaller than the configured mapping capacity
    /// after reservations.
    pub(crate) fn from_config(
        config: &DnsFakeIpConfig,
        query_strategy: DnsQueryStrategy,
        reserved_ipv4: &[Ipv4Addr],
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
            pool: FakeIpPool {
                network_base,
                prefix: ipv4_prefix,
                pool_size: config.pool_size,
            },
            network_base,
            address_count,
            first_offset,
            allocation_span,
            max_mappings: usize::try_from(config.pool_size).ok()?,
            reserved_ipv4: reserved_ipv4.into_boxed_slice(),
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
    /// A new name takes its home address, a stable hash of the name over the
    /// pool, or the first free address the probe finds after it, else the
    /// probed address whose lease ran out earliest. A mapping is never
    /// reassigned before the TTL most recently advertised for it has elapsed.
    /// Capacity exhaustion therefore fails closed until the earliest lease
    /// becomes reusable.
    pub(crate) fn allocate_ipv4(&mut self, domain: &str) -> Option<Ipv4Addr> {
        self.allocate_ipv4_at(domain, Instant::now())
    }

    fn allocate_ipv4_at(&mut self, domain: &str, now: Instant) -> Option<Ipv4Addr> {
        let domain = normalize_dns_domain(domain)?;
        let reusable_after = now.checked_add(Duration::from_secs(u64::from(self.ttl)))?;
        if let Some(&ip) = self.by_domain.get(domain.as_str()) {
            let entry = self.by_ipv4.get_mut(&ip)?;
            self.lease_index.remove(&(entry.reusable_after, ip));
            entry.reusable_after = reusable_after;
            self.lease_index.insert((reusable_after, ip));
            return Some(ip);
        }

        let ip = self.assign_ipv4(&domain, now)?;
        self.insert_mapping(Arc::from(domain), ip, reusable_after);
        Some(ip)
    }

    /// Picks the address for a name without one, removing at most one
    /// mapping whose lease has run out.
    fn assign_ipv4(&mut self, domain: &str, now: Instant) -> Option<Ipv4Addr> {
        let home = fnv1a_64(domain.as_bytes()) % self.allocation_span;
        let window = self.allocation_span.min(PROBE_WINDOW);
        let mut free = None;
        let mut expired: Option<(Instant, Ipv4Addr)> = None;
        for step in 0..window {
            let Some(ip) = self.address_at(home + step) else {
                continue;
            };
            match self.by_ipv4.get(&ip) {
                None => {
                    free = Some(ip);
                    break;
                }
                Some(entry)
                    if entry.reusable_after <= now
                        && expired.is_none_or(|(lease, _)| entry.reusable_after < lease) =>
                {
                    expired = Some((entry.reusable_after, ip));
                }
                Some(_) => {}
            }
        }

        if self.by_domain.len() >= self.max_mappings {
            // Some mapping must go, and only one whose lease ran out may.
            let &(earliest, earliest_ip) = self.lease_index.first()?;
            if earliest > now {
                return None;
            }
            let ip = match (free, expired) {
                (Some(free), _) => {
                    self.remove_mapping(earliest_ip);
                    free
                }
                (None, Some((_, expired))) => {
                    self.remove_mapping(expired);
                    expired
                }
                (None, None) => {
                    self.remove_mapping(earliest_ip);
                    earliest_ip
                }
            };
            return Some(ip);
        }

        if let Some(ip) = free {
            return Some(ip);
        }
        if let Some((_, ip)) = expired {
            self.remove_mapping(ip);
            return Some(ip);
        }
        // Below capacity a free address exists: `poolSize` never exceeds the
        // allocatable addresses.
        (window..self.allocation_span).find_map(|step| {
            self.address_at(home + step)
                .filter(|ip| !self.by_ipv4.contains_key(ip))
        })
    }

    /// The allocatable address `position` places after the first one,
    /// wrapping around the pool, unless the embedding reserved it.
    fn address_at(&self, position: u64) -> Option<Ipv4Addr> {
        let offset = self.first_offset + position % self.allocation_span;
        let raw_ip = self.network_base.checked_add(u32::try_from(offset).ok()?)?;
        let ip = Ipv4Addr::from(raw_ip);
        self.reserved_ipv4.binary_search(&ip).is_err().then_some(ip)
    }

    fn is_allocatable(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip)
            .checked_sub(self.network_base)
            .map(u64::from)
            .and_then(|offset| offset.checked_sub(self.first_offset))
            .is_some_and(|position| position < self.allocation_span)
            && self.reserved_ipv4.binary_search(&ip).is_err()
    }

    /// Resolves a synthetic IPv4 address back to its DNS name. Reverse lookups
    /// deliberately do not extend the lease because they advertise no DNS TTL.
    pub(crate) fn domain_for_ipv4(&mut self, ip: Ipv4Addr) -> Option<Arc<str>> {
        Some(Arc::clone(&self.by_ipv4.get(&ip)?.domain))
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

    fn insert_mapping(&mut self, domain: Arc<str>, ip: Ipv4Addr, reusable_after: Instant) {
        self.by_domain.insert(Arc::clone(&domain), ip);
        self.by_ipv4.insert(
            ip,
            FakeIpEntry {
                domain,
                reusable_after,
            },
        );
        self.lease_index.insert((reusable_after, ip));
    }

    fn remove_mapping(&mut self, ip: Ipv4Addr) {
        if let Some(entry) = self.by_ipv4.remove(&ip) {
            self.by_domain.remove(entry.domain.as_ref());
            self.lease_index.remove(&(entry.reusable_after, ip));
        }
    }

    fn snapshot(&self) -> FakeIpSnapshot {
        FakeIpSnapshot {
            pool: self.pool,
            entries: self
                .by_ipv4
                .iter()
                .map(|(ip, entry)| (Arc::clone(&entry.domain), *ip, entry.reusable_after))
                .collect(),
        }
    }

    /// Adopts carried-over mappings, returning how many. A lease still
    /// running is extended to at least a full TTL from `now`, since
    /// applications keep addresses past it; one already run out stays
    /// reusable, so a table full of stale mappings cannot fail the new core
    /// closed.
    fn restore(&mut self, snapshot: FakeIpSnapshot, now: Instant) -> usize {
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
            self.insert_mapping(domain, ip, reusable_after);
            restored += 1;
        }
        restored
    }
}

/// The mappings of a stopped core, at most `poolSize` of them.
#[derive(Debug)]
struct FakeIpSnapshot {
    pool: FakeIpPool,
    entries: Vec<(Arc<str>, Ipv4Addr, Instant)>,
}

/// Holds the mappings of the core stopped last until a core with the same
/// pool adopts them. One snapshot at most, replaced by each stop.
#[derive(Debug)]
struct FakeIpCarryOverStore(Mutex<Option<FakeIpSnapshot>>);

impl FakeIpCarryOverStore {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// Keeps `mapper`'s mappings in place of any held before. A mapper
    /// with none leaves the held ones.
    fn save(&self, mapper: &FakeIpMapper) {
        if mapper.by_ipv4.is_empty() {
            return;
        }
        let snapshot = mapper.snapshot();
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(snapshot);
    }

    /// Moves the held mappings into `mapper` when they come from the same
    /// pool, returning how many it took. Another pool's stay held.
    fn restore(&self, mapper: &mut FakeIpMapper, now: Instant) -> usize {
        let snapshot = {
            let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if held
                .as_ref()
                .is_none_or(|snapshot| snapshot.pool != mapper.pool)
            {
                return 0;
            }
            held.take()
        };
        snapshot.map_or(0, |snapshot| mapper.restore(snapshot, now))
    }
}

/// Carries a running core's fake-IP mappings across a restart in the same
/// process.
///
/// Built as the core starts, it moves the mappings the core stopped last
/// left into the new mapper. Dropped as the core stops, or with a running
/// core, it leaves the mapper's mappings for the next core with the same
/// pool. Applications keep the addresses they were given past the DNS TTL,
/// and a mapping that outlives its core keeps those addresses meaning the
/// same names.
pub(crate) struct FakeIpCarryOver {
    mapper: Arc<Mutex<FakeIpMapper>>,
    store: &'static FakeIpCarryOverStore,
    adopted: usize,
}

impl FakeIpCarryOver {
    pub(crate) fn adopt(mapper: Arc<Mutex<FakeIpMapper>>) -> Self {
        Self::adopt_from(&PROCESS_CARRY_OVER, mapper)
    }

    fn adopt_from(store: &'static FakeIpCarryOverStore, mapper: Arc<Mutex<FakeIpMapper>>) -> Self {
        let adopted = store.restore(
            &mut mapper.lock().unwrap_or_else(PoisonError::into_inner),
            Instant::now(),
        );
        Self {
            mapper,
            store,
            adopted,
        }
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
        self.store.save(&mapper);
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

/// FNV-1a 64: stable across processes, builds and platforms, unlike the
/// randomly keyed standard hasher.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash: u64, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn normalize_dns_domain(domain: &str) -> Option<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_config::IpCidr;

    const TUN_RESERVED: [Ipv4Addr; 2] =
        [Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2)];

    fn config(network: Ipv4Addr, prefix: u8, pool_size: u32, ttl: u32) -> DnsFakeIpConfig {
        DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddr::V4(network), prefix).unwrap(),
            pool_size,
            ttl,
        }
    }

    fn mapper(config: &DnsFakeIpConfig, reserved: &[Ipv4Addr]) -> FakeIpMapper {
        FakeIpMapper::from_config(config, DnsQueryStrategy::UseIp, reserved).unwrap()
    }

    fn home_position(mapper: &FakeIpMapper, domain: &str) -> u64 {
        fnv1a_64(domain.as_bytes()) % mapper.allocation_span
    }

    fn position_of(mapper: &FakeIpMapper, ip: Ipv4Addr) -> u64 {
        u64::from(u32::from(ip) - mapper.network_base) - mapper.first_offset
    }

    /// The first `count` generated names whose home is `position`.
    fn names_at_home(mapper: &FakeIpMapper, position: u64, count: usize) -> Vec<String> {
        (0..)
            .map(|index| format!("n{index}.example"))
            .filter(|name| home_position(mapper, name) == position)
            .take(count)
            .collect()
    }

    #[test]
    fn fnv1a_64_matches_the_reference_vectors() {
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn allocation_is_stable_and_reverse_lookup_normalizes_domain() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 32_768, 60);
        let mut mapper = mapper(&config, &TUN_RESERVED);

        let first = mapper.allocate_ipv4("Example.COM.").unwrap();
        let second = mapper.allocate_ipv4("example.com").unwrap();

        assert_ne!(mapper.lookup_ipv4(first), FakeIpLookup::Outside);
        assert!(!TUN_RESERVED.contains(&first));
        assert_eq!(second, first);
        assert_eq!(
            mapper.domain_for_ipv4(first).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn fresh_mappers_give_each_name_the_same_address_whatever_the_query_order() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 32_768, 60);
        let names = [
            "example.com",
            "www.example.com",
            "api.example.net",
            "cdn.example.org",
            "Mail.Example.COM.",
            "a.b.c.example",
            "xn--bcher-kva.example",
            "198.51.100.7.example",
        ];
        let mut forward = mapper(&config, &TUN_RESERVED);
        let mut backward = mapper(&config, &TUN_RESERVED);

        let forward_ips: Vec<_> = names
            .iter()
            .map(|name| forward.allocate_ipv4(name).unwrap())
            .collect();
        let mut backward_ips: Vec<_> = names
            .iter()
            .rev()
            .map(|name| backward.allocate_ipv4(name).unwrap())
            .collect();
        backward_ips.reverse();

        assert_eq!(forward_ips, backward_ips);
        let distinct: BTreeSet<_> = forward_ips.iter().collect();
        assert_eq!(distinct.len(), names.len());
    }

    #[test]
    fn home_addresses_stay_what_earlier_releases_gave() {
        // A release that changed the hash would move every name to another
        // address across an app upgrade. xray-bench's fake-DNS workload
        // expects the second address.
        let cases = [
            (
                Ipv4Addr::new(198, 18, 0, 0),
                15,
                "example.com",
                [198, 19, 0, 185],
            ),
            (
                Ipv4Addr::new(198, 19, 0, 0),
                16,
                "bench.example",
                [198, 19, 41, 78],
            ),
        ];
        for (network, prefix, name, expected) in cases {
            let mut mapper = mapper(&config(network, prefix, 32_768, 60), &TUN_RESERVED);

            assert_eq!(mapper.allocate_ipv4(name), Some(Ipv4Addr::from(expected)));
        }
    }

    #[test]
    fn a_name_whose_home_is_taken_probes_forward_past_reservations() {
        // Allocatable .1 to .6, positions 0 to 5; .3 is reserved.
        let config = config(Ipv4Addr::new(192, 0, 2, 0), 29, 5, 60);
        let reserved = [Ipv4Addr::new(192, 0, 2, 3)];
        let mut mapper = mapper(&config, &reserved);
        let colliding = names_at_home(&mapper, 1, 2);
        let reserved_home = names_at_home(&mapper, 2, 1).remove(0);

        let first = mapper.allocate_ipv4(&colliding[0]).unwrap();
        let second = mapper.allocate_ipv4(&colliding[1]).unwrap();
        let third = mapper.allocate_ipv4(&reserved_home).unwrap();

        assert_eq!(first, Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(second, Ipv4Addr::new(192, 0, 2, 4));
        assert_eq!(third, Ipv4Addr::new(192, 0, 2, 5));
        assert_eq!(
            mapper.lookup_ipv4(second),
            FakeIpLookup::Mapped(Arc::from(colliding[1].as_str()))
        );
        assert_eq!(
            mapper.allocate_ipv4(&colliding[0]),
            Some(first),
            "a name keeps the address it was given"
        );
    }

    #[test]
    fn reserved_tun_addresses_are_never_handed_out_even_as_a_home() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 29, 4, 60);
        let mut mapper = mapper(&config, &TUN_RESERVED);
        let anchor_home = names_at_home(&mapper, 0, 1).remove(0);

        assert_eq!(
            mapper.allocate_ipv4(&anchor_home),
            Some(Ipv4Addr::new(198, 18, 0, 3))
        );
        let allocated: BTreeSet<_> = (0..3)
            .map(|index| {
                mapper
                    .allocate_ipv4(&format!("fill{index}.example"))
                    .unwrap()
            })
            .chain([Ipv4Addr::new(198, 18, 0, 3)])
            .collect();

        assert_eq!(allocated.len(), 4);
        assert!(allocated.iter().all(|ip| !TUN_RESERVED.contains(ip)));
        assert!(allocated.iter().all(|ip| mapper.is_allocatable(*ip)));
        assert_eq!(mapper.allocate_ipv4("one-too-many.example"), None);
    }

    #[test]
    fn allocation_skips_embedding_reservations_without_double_counting_duplicates() {
        let config = config(Ipv4Addr::new(192, 0, 2, 0), 29, 4, 60);
        let reserved = [
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 3),
        ];
        let mut mapper = mapper(&config, &reserved);

        let allocated: BTreeSet<_> = ["a.example", "b.example", "c.example", "d.example"]
            .into_iter()
            .map(|domain| mapper.allocate_ipv4(domain).unwrap())
            .collect();

        assert_eq!(
            allocated.into_iter().collect::<Vec<_>>(),
            [
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(192, 0, 2, 4),
                Ipv4Addr::new(192, 0, 2, 5),
                Ipv4Addr::new(192, 0, 2, 6),
            ]
        );
    }

    #[test]
    fn a_full_probe_window_falls_back_to_any_free_address_below_capacity() {
        let config = config(Ipv4Addr::new(192, 0, 2, 0), 24, 254, 60);
        let mut mapper = mapper(&config, &[]);
        let start = Instant::now();

        let mut farthest = 0;
        let mut allocated = BTreeSet::new();
        for index in 0..254 {
            let name = format!("n{index}.example");
            let ip = mapper.allocate_ipv4_at(&name, start).unwrap();
            let distance = (position_of(&mapper, ip) + mapper.allocation_span
                - home_position(&mapper, &name))
                % mapper.allocation_span;
            farthest = farthest.max(distance);
            allocated.insert(ip);
        }

        assert_eq!(allocated.len(), 254);
        assert!(farthest >= PROBE_WINDOW, "{farthest}");
        assert_eq!(mapper.allocate_ipv4_at("n254.example", start), None);
    }

    #[test]
    fn capacity_fails_closed_until_the_earliest_advertised_lease_expires() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 2, 120);
        let mut mapper = mapper(&config, &[]);
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

        // The earliest lease, second's, made room; third still takes its own
        // home address rather than second's.
        assert_eq!(mapper.mapping_count(), 2);
        assert_eq!(
            third,
            FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &[])
                .unwrap()
                .allocate_ipv4("third.example")
                .unwrap()
        );
        assert_eq!(
            mapper.lookup_ipv4(third),
            FakeIpLookup::Mapped(Arc::from("third.example"))
        );
        assert_eq!(mapper.lookup_ipv4(second), FakeIpLookup::InPoolUnmapped);
        assert_eq!(
            mapper.lookup_ipv4(first),
            FakeIpLookup::Mapped(Arc::from("first.example"))
        );
        assert_eq!(
            mapper.lookup_ipv4(Ipv4Addr::new(203, 0, 113, 1)),
            FakeIpLookup::Outside
        );
    }

    #[test]
    fn a_full_pool_reuses_the_address_whose_lease_ran_out_first() {
        // Allocatable .1 to .6, all of them mappings.
        let config = config(Ipv4Addr::new(192, 0, 2, 0), 29, 6, 60);
        let mut mapper = mapper(&config, &[]);
        let start = Instant::now();
        let ips: Vec<_> = (0..6_u64)
            .map(|index| {
                mapper
                    .allocate_ipv4_at(
                        &format!("n{index}.example"),
                        start + Duration::from_secs(index),
                    )
                    .unwrap()
            })
            .collect();

        assert_eq!(
            mapper.allocate_ipv4_at("late.example", start + Duration::from_secs(59)),
            None
        );
        let late = mapper
            .allocate_ipv4_at("late.example", start + Duration::from_secs(63))
            .unwrap();

        assert_eq!(late, ips[0]);
        assert_eq!(mapper.mapping_count(), 6);
        assert_eq!(
            mapper.lookup_ipv4(ips[1]),
            FakeIpLookup::Mapped(Arc::from("n1.example"))
        );
    }

    #[test]
    fn full_single_address_pool_never_reassigns_before_refreshed_ttl() {
        let config = config(Ipv4Addr::new(198, 19, 0, 1), 32, 1, 60);
        let mut mapper = mapper(&config, &[]);
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
        let mut mapper = mapper(&config, &[Ipv4Addr::new(198, 18, 0, 1)]);
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
    fn a_restarted_mapper_adopts_the_mappings_and_extends_running_leases() {
        static STORE: FakeIpCarryOverStore = FakeIpCarryOverStore::new();
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 3, 60);
        let start = Instant::now();
        let mut stopped = mapper(&config, &TUN_RESERVED);
        let first = stopped.allocate_ipv4_at("first.example", start).unwrap();
        let second = stopped.allocate_ipv4_at("second.example", start).unwrap();
        STORE.save(&stopped);
        drop(stopped);

        let restart = start + Duration::from_secs(30);
        let mut started = mapper(&config, &TUN_RESERVED);
        assert_eq!(STORE.restore(&mut started, restart), 2);
        assert_eq!(STORE.restore(&mut started, restart), 0, "adopted once");

        assert_eq!(
            started.lookup_ipv4(second),
            FakeIpLookup::Mapped(Arc::from("second.example"))
        );
        let third = started.allocate_ipv4_at("third.example", restart).unwrap();
        assert!(![first, second].contains(&third));
        assert_eq!(
            started.allocate_ipv4_at("first.example", restart),
            Some(first)
        );
        // second's lease ran to start + 60 and now runs a full TTL from the
        // restart, so the full pool stays closed until then.
        assert_eq!(
            started.allocate_ipv4_at("fourth.example", restart + Duration::from_secs(59)),
            None
        );
        assert!(started
            .allocate_ipv4_at("fourth.example", restart + Duration::from_secs(60))
            .is_some());
    }

    #[test]
    fn carried_over_mappings_whose_lease_ran_out_stay_mapped_but_reusable() {
        static STORE: FakeIpCarryOverStore = FakeIpCarryOverStore::new();
        let config = config(Ipv4Addr::new(198, 19, 0, 1), 32, 1, 60);
        let start = Instant::now();
        let mut stopped = mapper(&config, &[]);
        let ip = stopped.allocate_ipv4_at("old.example", start).unwrap();
        STORE.save(&stopped);

        let restart = start + Duration::from_secs(120);
        let mut started = mapper(&config, &[]);
        assert_eq!(STORE.restore(&mut started, restart), 1);

        assert_eq!(
            started.lookup_ipv4(ip),
            FakeIpLookup::Mapped(Arc::from("old.example"))
        );
        assert_eq!(started.allocate_ipv4_at("new.example", restart), Some(ip));
    }

    #[test]
    fn another_pool_leaves_the_carried_over_mappings_held() {
        static STORE: FakeIpCarryOverStore = FakeIpCarryOverStore::new();
        let saved = config(Ipv4Addr::new(198, 18, 0, 0), 15, 32_768, 60);
        let mut stopped = mapper(&saved, &TUN_RESERVED);
        let ip = stopped.allocate_ipv4("kept.example").unwrap();
        STORE.save(&stopped);
        let now = Instant::now();

        let mut other_size = mapper(
            &config(Ipv4Addr::new(198, 18, 0, 0), 15, 1_024, 60),
            &TUN_RESERVED,
        );
        let mut other_network = mapper(
            &config(Ipv4Addr::new(198, 19, 0, 0), 16, 32_768, 60),
            &TUN_RESERVED,
        );
        assert_eq!(STORE.restore(&mut other_size, now), 0);
        assert_eq!(STORE.restore(&mut other_network, now), 0);
        STORE.save(&mapper(&saved, &TUN_RESERVED));

        let mut same = mapper(&saved, &TUN_RESERVED);
        assert_eq!(STORE.restore(&mut same, now), 1);
        assert_eq!(
            same.lookup_ipv4(ip),
            FakeIpLookup::Mapped(Arc::from("kept.example"))
        );
    }

    #[test]
    fn a_carry_over_leaves_its_mappings_when_dropped() {
        static STORE: FakeIpCarryOverStore = FakeIpCarryOverStore::new();
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 32_768, 60);
        let first = FakeIpCarryOver::adopt_from(
            &STORE,
            Arc::new(Mutex::new(mapper(&config, &TUN_RESERVED))),
        );
        assert_eq!(first.adopted(), 0);
        let ip = first
            .mapper()
            .lock()
            .unwrap()
            .allocate_ipv4("carried.example")
            .unwrap();
        drop(first);

        let second = FakeIpCarryOver::adopt_from(
            &STORE,
            Arc::new(Mutex::new(mapper(&config, &TUN_RESERVED))),
        );

        assert_eq!(second.adopted(), 1);
        assert_eq!(
            second.mapper().lock().unwrap().lookup_ipv4(ip),
            FakeIpLookup::Mapped(Arc::from("carried.example"))
        );
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
