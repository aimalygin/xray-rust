use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;

use async_trait::async_trait;
use xray_config::DomainStrategy;
use xray_transport::{DnsLookup, DnsQueryStrategy, DnsResolver, TransportError};

use super::DomainStrategyResolver;

const DOMAIN: &str = "dual.example";
const PORT: u16 = 443;

/// `None` stands for a plain `resolve_all`, `Some` for a family lookup.
type Query = Option<DnsQueryStrategy>;

/// Answers each kind of lookup from a script and records the order of calls.
#[derive(Default)]
struct ScriptedResolver {
    answers: HashMap<Query, Option<Vec<SocketAddr>>>,
    calls: Mutex<Vec<Query>>,
    single_lookups: Mutex<usize>,
}

impl ScriptedResolver {
    /// A dual-stack name: every lookup answers with its families' addresses.
    fn dual_stack() -> Self {
        let mut resolver = Self::default();
        resolver.answer(None, Some(vec![v6(), v4()]));
        resolver.answer(Some(DnsQueryStrategy::UseIp), Some(vec![v6(), v4()]));
        resolver.answer(Some(DnsQueryStrategy::UseIpv4), Some(vec![v4()]));
        resolver.answer(Some(DnsQueryStrategy::UseIpv6), Some(vec![v6()]));
        resolver
    }

    /// `None` makes that lookup fail; an empty list makes it find nothing.
    fn answer(&mut self, query: Query, answer: Option<Vec<SocketAddr>>) {
        self.answers.insert(query, answer);
    }

    fn lookup(&self, query: Query) -> Result<DnsLookup, TransportError> {
        self.calls.lock().unwrap().push(query);
        match self.answers.get(&query).cloned().flatten() {
            Some(addresses) => Ok(DnsLookup::new(addresses, None)),
            None => Err(TransportError::DnsNoData(DOMAIN.to_owned(), PORT)),
        }
    }

    fn calls(&self) -> Vec<Query> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl DnsResolver for ScriptedResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        *self.single_lookups.lock().unwrap() += 1;
        let answer = self.answers.get(&None).cloned().flatten();
        answer
            .and_then(|addresses| addresses.first().copied())
            .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
    }

    async fn resolve_all(&self, _domain: &str, _port: u16) -> Result<DnsLookup, TransportError> {
        self.lookup(None)
    }

    async fn resolve_all_with_strategy(
        &self,
        _domain: &str,
        _port: u16,
        strategy: DnsQueryStrategy,
    ) -> Result<DnsLookup, TransportError> {
        self.lookup(Some(strategy))
    }
}

fn v4() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), PORT))
}

fn v6() -> SocketAddr {
    SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), PORT))
}

async fn resolve(
    resolver: &ScriptedResolver,
    strategy: DomainStrategy,
) -> Result<Vec<SocketAddr>, TransportError> {
    DomainStrategyResolver::new(resolver, strategy)
        .resolve_all(DOMAIN, PORT)
        .await
        .map(|lookup| lookup.socket_addrs().to_vec())
}

const V4: Query = Some(DnsQueryStrategy::UseIpv4);
const V6: Query = Some(DnsQueryStrategy::UseIpv6);
const BOTH: Query = Some(DnsQueryStrategy::UseIp);

#[tokio::test]
async fn as_is_looks_up_as_before() {
    let resolver = ScriptedResolver::dual_stack();
    assert_eq!(
        resolve(&resolver, DomainStrategy::AsIs).await.unwrap(),
        [v6(), v4()]
    );
    assert_eq!(resolver.calls(), [None]);
}

#[tokio::test]
async fn each_strategy_asks_for_its_families_first() {
    for (strategy, query, expected) in [
        (DomainStrategy::UseIp, BOTH, vec![v6(), v4()]),
        (DomainStrategy::ForceIp, BOTH, vec![v6(), v4()]),
        (DomainStrategy::UseIpv4, V4, vec![v4()]),
        (DomainStrategy::ForceIpv4, V4, vec![v4()]),
        (DomainStrategy::UseIpv6, V6, vec![v6()]),
        (DomainStrategy::UseIpv4v6, V4, vec![v4()]),
        (DomainStrategy::ForceIpv6v4, V6, vec![v6()]),
    ] {
        let resolver = ScriptedResolver::dual_stack();
        assert_eq!(resolve(&resolver, strategy).await.unwrap(), expected);
        assert_eq!(resolver.calls(), [query], "{strategy:?}");
    }
}

#[tokio::test]
async fn the_fallback_family_follows_a_failed_or_empty_lookup() {
    for failed in [None, Some(Vec::new())] {
        let mut resolver = ScriptedResolver::dual_stack();
        resolver.answer(V4, failed.clone());
        assert_eq!(
            resolve(&resolver, DomainStrategy::UseIpv4v6).await.unwrap(),
            [v6()]
        );
        assert_eq!(resolver.calls(), [V4, V6]);

        let mut resolver = ScriptedResolver::dual_stack();
        resolver.answer(V6, failed);
        assert_eq!(
            resolve(&resolver, DomainStrategy::ForceIpv6v4)
                .await
                .unwrap(),
            [v4()]
        );
        assert_eq!(resolver.calls(), [V6, V4]);
    }
}

#[tokio::test]
async fn use_strategies_fall_back_to_both_families() {
    // Xray-core hands the domain to the system dialer, which asks for both.
    let mut resolver = ScriptedResolver::dual_stack();
    resolver.answer(V4, None);
    assert_eq!(
        resolve(&resolver, DomainStrategy::UseIpv4).await.unwrap(),
        [v6(), v4()]
    );
    assert_eq!(resolver.calls(), [V4, None]);

    let mut resolver = ScriptedResolver::dual_stack();
    resolver.answer(V6, Some(Vec::new()));
    resolver.answer(V4, None);
    assert_eq!(
        resolve(&resolver, DomainStrategy::UseIpv6v4).await.unwrap(),
        [v6(), v4()]
    );
    assert_eq!(resolver.calls(), [V6, V4, None]);
}

#[tokio::test]
async fn force_strategies_fail_without_looking_further() {
    let mut resolver = ScriptedResolver::dual_stack();
    resolver.answer(V4, None);
    assert!(resolve(&resolver, DomainStrategy::ForceIpv4).await.is_err());
    assert_eq!(resolver.calls(), [V4]);

    let mut resolver = ScriptedResolver::dual_stack();
    resolver.answer(V4, Some(Vec::new()));
    resolver.answer(V6, None);
    assert!(resolve(&resolver, DomainStrategy::ForceIpv4v6)
        .await
        .is_err());
    assert_eq!(resolver.calls(), [V4, V6]);

    let mut resolver = ScriptedResolver::dual_stack();
    resolver.answer(BOTH, Some(Vec::new()));
    assert!(resolve(&resolver, DomainStrategy::ForceIp).await.is_err());
    assert_eq!(resolver.calls(), [BOTH]);
}

#[tokio::test]
async fn resolve_returns_the_first_permitted_address() {
    let resolver = ScriptedResolver::dual_stack();
    let first = DomainStrategyResolver::new(&resolver, DomainStrategy::UseIpv4)
        .resolve(DOMAIN, PORT)
        .await
        .unwrap();
    assert_eq!(first, v4());
    assert_eq!(resolver.calls(), [V4]);

    // AsIs leaves the single-address lookup to the resolver, as before.
    let resolver = ScriptedResolver::dual_stack();
    let first = DomainStrategyResolver::new(&resolver, DomainStrategy::AsIs)
        .resolve(DOMAIN, PORT)
        .await
        .unwrap();
    assert_eq!(first, v6());
    assert!(resolver.calls().is_empty());
    assert_eq!(*resolver.single_lookups.lock().unwrap(), 1);
}

#[tokio::test]
async fn family_queries_pass_through_as_is_and_narrow_a_strategy() {
    let resolver = ScriptedResolver::dual_stack();
    let lookup = DomainStrategyResolver::new(&resolver, DomainStrategy::AsIs)
        .resolve_all_with_strategy(DOMAIN, PORT, DnsQueryStrategy::UseIpv6)
        .await
        .unwrap();
    assert_eq!(lookup.socket_addrs(), [v6()]);
    assert_eq!(resolver.calls(), [V6]);

    let resolver = ScriptedResolver::dual_stack();
    let lookup = DomainStrategyResolver::new(&resolver, DomainStrategy::UseIp)
        .resolve_all_with_strategy(DOMAIN, PORT, DnsQueryStrategy::UseIpv4)
        .await
        .unwrap();
    assert_eq!(lookup.socket_addrs(), [v4()]);
    assert_eq!(resolver.calls(), [BOTH]);

    let resolver = ScriptedResolver::dual_stack();
    assert!(
        DomainStrategyResolver::new(&resolver, DomainStrategy::ForceIpv4)
            .resolve_all_with_strategy(DOMAIN, PORT, DnsQueryStrategy::UseIpv6)
            .await
            .is_err()
    );
}
