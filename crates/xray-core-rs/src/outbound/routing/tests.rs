use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::{Notify, Semaphore};
use xray_config::{parse_xray_json, CoreConfig};
use xray_routing::{Network as RoutingNetwork, TargetAddr};
use xray_transport::{CachingDnsResolver, DnsLookup, TransportError};

use super::super::OutboundRouter;
use super::*;

fn config(routing: Value) -> CoreConfig {
    parse_xray_json(
        &json!({
            "inbounds": [],
            "outbounds": (["default", "ip", "domain", "second"].map(|tag|
                json!({"tag": tag, "protocol": "freedom", "settings": {}}))),
            "routing": routing,
        })
        .to_string(),
    )
    .unwrap()
    .config
}

fn on_demand_config() -> CoreConfig {
    config(json!({"domainStrategy": "IPOnDemand", "rules": [
        {"type": "field", "ip": ["203.0.113.7/32"], "outboundTag": "ip"},
        {"type": "field", "domain": ["full:example.test"], "outboundTag": "domain"}
    ]}))
}

fn target() -> Target {
    Target::new(
        TargetAddr::Domain("example.test".into()),
        443,
        RoutingNetwork::Tcp,
    )
}

struct Resolver {
    lookup: DnsLookup,
    fail: bool,
    calls: AtomicUsize,
}

impl Resolver {
    fn new(addresses: Vec<IpAddr>) -> Self {
        Self {
            lookup: DnsLookup::from_ips(addresses, 443, None),
            fail: false,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, _: &str, _: u16) -> Result<SocketAddr, TransportError> {
        panic!("routing must consume every address through resolve_all")
    }
    async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        assert_eq!((domain, port), ("example.test", 443));
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(TransportError::NoResolvedAddress(domain.into(), port))
        } else {
            Ok(self.lookup.clone())
        }
    }
}

async fn selected_tag(
    router: &OutboundRouter,
    target: &Target,
    resolver: &dyn DnsResolver,
) -> String {
    let node = router
        .select_configured_node_with_resolver(Some("socks-in"), target, resolver)
        .await
        .unwrap();
    router.graph().node(node).unwrap().tag().unwrap().to_owned()
}

#[tokio::test]
async fn domain_strategy_matches_pinned_go_routing_oracle() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/routing/domain_strategy.json"
    ))
    .unwrap();
    assert_eq!(fixture["schemaVersion"], 1);
    assert_eq!(
        fixture["xrayCoreCommit"],
        "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let router = OutboundRouter::new(Arc::new(config(case["routing"].clone())));
        let address = case["target"]["address"].as_str().unwrap();
        let target = Target::new(
            address
                .parse()
                .map(TargetAddr::Ip)
                .unwrap_or_else(|_| TargetAddr::Domain(address.into())),
            case["target"]["port"].as_u64().unwrap().try_into().unwrap(),
            match case["target"]["network"].as_str().unwrap() {
                "tcp" => RoutingNetwork::Tcp,
                "udp" => RoutingNetwork::Udp,
                _ => panic!("unknown fixture network"),
            },
        );
        let original = target.clone();
        let mut resolver = Resolver::new(
            case["answers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|ip| ip.as_str().unwrap().parse().unwrap())
                .collect(),
        );
        resolver.fail = case["dnsFailure"].as_bool().unwrap();
        let tag = if case["skipDNSResolve"].as_bool().unwrap() {
            // Exercise the actual resolver-free internal DNS client path.
            router
                .select_tcp_outbound_for_session_with_tag(Some("socks-in"), &target, true)
                .unwrap()
                .tag
                .unwrap()
        } else {
            selected_tag(&router, &target, &resolver).await
        };
        assert_eq!(tag, case["expectedTag"], "{}", case["name"]);
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst) as u64,
            case["expectedLookups"].as_u64().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(target, original, "routing must preserve the destination");
    }
}

#[tokio::test]
async fn ip_on_demand_checks_the_last_address_at_the_limit_and_rejects_overflow() {
    let router = OutboundRouter::new(Arc::new(on_demand_config()));
    let mut addresses: Vec<IpAddr> = (1..MAX_IP_ON_DEMAND_ADDRESSES)
        .map(|n| {
            IpAddr::V6(std::net::Ipv6Addr::from(
                (0x2001_0db8_u128 << 96) + n as u128,
            ))
        })
        .collect();
    addresses.push("203.0.113.7".parse().unwrap());
    assert_eq!(
        selected_tag(&router, &target(), &Resolver::new(addresses.clone())).await,
        "ip"
    );
    addresses.push("192.0.2.1".parse().unwrap());
    let error = router
        .select_configured_node_with_resolver(None, &target(), &Resolver::new(addresses))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        CoreError::RoutingDnsAddressLimitExceeded { limit: 256 }
    ));
}

#[tokio::test]
async fn ip_on_demand_empty_success_does_not_retry_or_skip_later_domain_rules() {
    let mut config = on_demand_config();
    config
        .routing
        .rules
        .insert(1, config.routing.rules[0].clone());
    let router = OutboundRouter::new(Arc::new(config));
    let resolver = Resolver::new(vec![]);
    assert_eq!(selected_tag(&router, &target(), &resolver).await, "domain");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
}

struct ActiveLookup<'a>(&'a AtomicUsize);
impl Drop for ActiveLookup<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ControlledResolver {
    calls: AtomicUsize,
    active: AtomicUsize,
    entered: Notify,
    release: Semaphore,
    stale: bool,
}

impl ControlledResolver {
    fn new(stale: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Semaphore::new(0),
            stale,
        }
    }
}

#[async_trait]
impl DnsResolver for ControlledResolver {
    async fn resolve(&self, _: &str, _: u16) -> Result<SocketAddr, TransportError> {
        unreachable!()
    }
    async fn resolve_all(&self, _: &str, port: u16) -> Result<DnsLookup, TransportError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        let _guard = ActiveLookup(&self.active);
        self.entered.notify_one();
        if !self.stale || call > 0 {
            self.release.acquire().await.unwrap().forget();
        }
        Ok(DnsLookup::single(
            SocketAddr::new("203.0.113.7".parse().unwrap(), port),
            self.stale.then_some(Duration::from_millis(5)),
        ))
    }
}

#[tokio::test]
async fn ip_on_demand_shares_cache_and_singleflight_across_concurrent_flows() {
    let upstream = Arc::new(ControlledResolver::new(false));
    let cache = Arc::new(CachingDnsResolver::new(upstream.clone()));
    let router = Arc::new(OutboundRouter::new(Arc::new(on_demand_config())));
    let mut flows = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let (cache, router) = (cache.clone(), router.clone());
        flows.spawn(async move { selected_tag(&router, &target(), cache.as_ref()).await });
    }
    upstream.entered.notified().await;
    upstream.release.add_permits(1);
    while let Some(result) = flows.join_next().await {
        assert_eq!(result.unwrap(), "ip");
    }
    assert_eq!(selected_tag(&router, &target(), cache.as_ref()).await, "ip");
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ip_on_demand_cancellation_releases_dns_and_does_not_poison_the_cache() {
    let upstream = Arc::new(ControlledResolver::new(false));
    let cache = Arc::new(CachingDnsResolver::new(upstream.clone()));
    let router = Arc::new(OutboundRouter::new(Arc::new(on_demand_config())));
    let pending = {
        let (cache, router) = (cache.clone(), router.clone());
        tokio::spawn(async move { selected_tag(&router, &target(), cache.as_ref()).await })
    };
    upstream.entered.notified().await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert_eq!(upstream.active.load(Ordering::SeqCst), 0);
    upstream.release.add_permits(1);
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            selected_tag(&router, &target(), cache.as_ref())
        )
        .await
        .unwrap(),
        "ip"
    );
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn ip_on_demand_serves_stale_during_one_owned_refresh() {
    let upstream = Arc::new(ControlledResolver::new(true));
    let cache = CachingDnsResolver::with_stale_ttl(upstream.clone(), Duration::from_secs(60));
    let router = OutboundRouter::new(Arc::new(on_demand_config()));
    assert_eq!(selected_tag(&router, &target(), &cache).await, "ip");
    upstream.entered.notified().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    for _ in 0..4 {
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                selected_tag(&router, &target(), &cache)
            )
            .await
            .unwrap(),
            "ip"
        );
    }
    upstream.entered.notified().await;
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    drop(cache);
    tokio::time::timeout(Duration::from_secs(1), async {
        while upstream.active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ip_on_demand_keeps_one_policy_revision_across_dns_await() {
    let resolver = Arc::new(ControlledResolver::new(false));
    let router = Arc::new(OutboundRouter::new(Arc::new(on_demand_config())));
    let pending = {
        let (resolver, router) = (resolver.clone(), router.clone());
        tokio::spawn(async move { selected_tag(&router, &target(), resolver.as_ref()).await })
    };
    resolver.entered.notified().await;
    assert_eq!(
        router
            .replace_routing_policy(RoutingConfig::default())
            .unwrap(),
        1
    );
    resolver.release.add_permits(1);
    assert_eq!(pending.await.unwrap(), "ip");
    assert_eq!(
        selected_tag(&router, &target(), resolver.as_ref()).await,
        "default"
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
}
