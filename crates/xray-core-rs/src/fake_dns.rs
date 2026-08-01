use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use xray_config::{DnsFakeIpConfig, DnsQueryStrategy};

/// Stateful, bounded mapping between DNS names and synthetic IPv4 addresses.
///
/// The mapper owns no ingress or transport concerns. Callers decide how DNS
/// messages are parsed and synthesized, and which addresses must be reserved
/// by their embedding.
#[derive(Debug)]
pub(crate) struct FakeIpMapper {
    query_strategy: DnsQueryStrategy,
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
            ttl: config.ttl,
            network_base,
            address_count,
            first_offset,
            allocation_span,
            max_mappings: usize::try_from(config.pool_size).ok()?,
            reserved_ipv4: reserved_ipv4.into_boxed_slice(),
            next_offset: 0,
            entries: Vec::new(),
            lease_index: BTreeSet::new(),
            by_domain: HashMap::new(),
            by_ipv4: HashMap::new(),
        })
    }

    pub(crate) fn ttl(&self) -> u32 {
        self.ttl
    }

    pub(crate) fn query_strategy(&self) -> DnsQueryStrategy {
        self.query_strategy
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
            self.insert_mapping(slot, domain, ip, reusable_after)?;
            return Some(ip);
        }

        let slot = self.entries.len();
        let ip = self.next_available_ipv4()?;
        self.insert_mapping(slot, domain, ip, reusable_after)?;
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
        domain: String,
        ip: Ipv4Addr,
        reusable_after: Instant,
    ) -> Option<()> {
        let domain = Arc::<str>::from(domain);
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

        assert_eq!(first, Ipv4Addr::new(198, 18, 0, 3));
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
            FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &reserved).unwrap();

        let first = mapper.allocate_ipv4("first.example").unwrap();
        let second = mapper.allocate_ipv4("second.example").unwrap();

        assert_eq!(first, Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(second, Ipv4Addr::new(192, 0, 2, 4));
    }

    #[test]
    fn capacity_fails_closed_until_the_earliest_advertised_lease_expires() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 2, 120);
        let mut mapper = FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIp, &[]).unwrap();
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
    fn response_metadata_is_preserved_from_core_config() {
        let config = config(Ipv4Addr::new(198, 18, 0, 0), 15, 2, 123);
        let mapper = FakeIpMapper::from_config(&config, DnsQueryStrategy::UseIpv6, &[]).unwrap();

        assert_eq!(mapper.ttl(), 123);
        assert_eq!(mapper.query_strategy(), DnsQueryStrategy::UseIpv6);
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
