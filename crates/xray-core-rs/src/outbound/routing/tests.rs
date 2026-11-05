use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::{Notify, Semaphore};
use xray_config::{parse_xray_json, CoreConfig};
use xray_routing::{
    DnsHostTarget, DomainHostIndex, DomainMatcher, Network as RoutingNetwork, TargetAddr,
};
use xray_transport::{CachingDnsResolver, ConfiguredDnsResolver, DnsLookup, TransportError};

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
        .select_configured_node_with_resolver(
            &xray_config::RouteContext::inbound(Some("socks-in")),
            target,
            resolver,
        )
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
        "a4a3dff5b20c2faae567b742c172c7b95e75c083"
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
                .select_tcp_outbound_for_session_with_tag(
                    &xray_config::RouteContext::inbound(Some("socks-in")),
                    &target,
                    true,
                )
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
        .select_configured_node_with_resolver(
            &xray_config::RouteContext::default(),
            &target(),
            &Resolver::new(addresses),
        )
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

#[tokio::test]
async fn ip_on_demand_treats_static_rcode_host_as_no_addresses() {
    let router = OutboundRouter::new(Arc::new(on_demand_config()));
    for rcode in [0, 3, 5] {
        let fallback = Arc::new(Resolver::new(vec!["203.0.113.7".parse().unwrap()]));
        let resolver = ConfiguredDnsResolver::new(
            DomainHostIndex::from_iter([(
                DomainMatcher::Full("example.test".into()),
                DnsHostTarget::Rcode(rcode),
            )]),
            Vec::new(),
            fallback.clone(),
        );
        let selected = tokio::time::timeout(
            Duration::from_secs(5),
            selected_tag(&router, &target(), &resolver),
        )
        .await
        .expect("static rcode routing lookup must not wait");
        assert_eq!(selected, "domain", "#{rcode}");
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0, "#{rcode}");
    }
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

#[tokio::test]
async fn local_os_rules_apply_only_on_their_platforms() {
    // No platform is named `no-such-os` or the empty string. The second rule
    // names this one in upper case inside a comma-separated string.
    let this_os = format!("plan9,{}", xray_config::LOCAL_OS.to_ascii_uppercase());
    let router = OutboundRouter::new(Arc::new(config(json!({
        "domainStrategy": "IPOnDemand",
        "rules": [
            {"type": "field", "localOS": ["no-such-os", ""], "domain": ["full:example.test"],
                "outboundTag": "domain"},
            {"type": "field", "localOS": this_os, "ip": ["203.0.113.7/32"], "outboundTag": "ip"},
            {"type": "field", "localOS": "", "network": "tcp", "outboundTag": "second"}
        ]
    }))));
    let resolver = Resolver::new(vec!["203.0.113.7".parse().unwrap()]);
    assert_eq!(selected_tag(&router, &target(), &resolver).await, "ip");

    let address = Target::new(
        TargetAddr::Ip("203.0.113.7".parse().unwrap()),
        443,
        RoutingNetwork::Tcp,
    );
    let selected = router
        .select_tcp_outbound_for_session_with_tag(
            &xray_config::RouteContext::inbound(Some("socks-in")),
            &address,
            true,
        )
        .unwrap();
    assert_eq!(selected.tag.as_deref(), Some("ip"));
    // Excluded everywhere, the last rule never routes; the first outbound does.
    let other = Target::new(
        TargetAddr::Ip("198.51.100.9".parse().unwrap()),
        443,
        RoutingNetwork::Tcp,
    );
    let selected = router
        .select_tcp_outbound_for_session_with_tag(
            &xray_config::RouteContext::inbound(Some("socks-in")),
            &other,
            true,
        )
        .unwrap();
    assert_eq!(selected.tag.as_deref(), Some("default"));
}

/// Under `IPOnDemand`, a rule whose ports or user fail is skipped before the
/// lookup, while source and local IPs are checked after the destination IP,
/// in Xray-core's condition order.
#[tokio::test]
async fn ip_on_demand_checks_origin_conditions_in_xray_core_order() {
    let config = config(json!({"domainStrategy": "IPOnDemand", "rules": [
        {"user": ["alice"], "ip": ["203.0.113.7/32"], "outboundTag": "ip"},
        {"source": ["10.0.0.0/8"], "ip": ["203.0.113.7/32"], "outboundTag": "second"},
        {"domain": ["full:example.test"], "outboundTag": "domain"}
    ]}));
    let router = OutboundRouter::new(Arc::new(config));
    let selected = |route: xray_config::RouteContext<'static>| {
        let router = &router;
        async move {
            let resolver = Resolver::new(vec!["203.0.113.7".parse().unwrap()]);
            let node = router
                .select_configured_node_with_resolver(&route, &target(), &resolver)
                .await
                .unwrap();
            (
                router.graph().node(node).unwrap().tag().unwrap().to_owned(),
                resolver.calls.load(Ordering::SeqCst),
            )
        }
    };
    let elsewhere = Some("192.0.2.1:5000".parse().unwrap());
    let route = |source, user| xray_config::RouteContext {
        attributes: None,
        protocol: None,
        inbound_tag: Some("socks-in"),
        source,
        local: None,
        user,
    };
    // Only the second rule looks the name up, and its source then misses.
    assert_eq!(
        selected(route(elsewhere, None)).await,
        ("domain".to_owned(), 1)
    );
    assert_eq!(
        selected(route(elsewhere, Some("alice"))).await,
        ("ip".to_owned(), 1)
    );
    let inside = Some("10.1.2.3:5000".parse().unwrap());
    assert_eq!(
        selected(route(inside, None)).await,
        ("second".to_owned(), 1)
    );
}

/// Under `IPOnDemand`, `protocol` holds as everywhere else, and is checked
/// before the destination IP, so a flow it rules out looks nothing up.
#[tokio::test]
async fn ip_on_demand_checks_the_sniffed_protocol() {
    let config = config(json!({"domainStrategy": "IPOnDemand", "rules": [
        {"protocol": ["bittorrent"], "outboundTag": "second"},
        {"protocol": ["tls"], "ip": ["203.0.113.7/32"], "outboundTag": "ip"},
        {"domain": ["full:example.test"], "outboundTag": "domain"}
    ]}));
    let router = OutboundRouter::new(Arc::new(config));
    let selected = |protocol: Option<&'static str>| {
        let router = &router;
        async move {
            let resolver = Resolver::new(vec!["203.0.113.7".parse().unwrap()]);
            let route = xray_config::RouteContext {
                protocol,
                ..xray_config::RouteContext::inbound(Some("socks-in"))
            };
            let node = router
                .select_configured_node_with_resolver(&route, &target(), &resolver)
                .await
                .unwrap();
            (
                router.graph().node(node).unwrap().tag().unwrap().to_owned(),
                resolver.calls.load(Ordering::SeqCst),
            )
        }
    };
    assert_eq!(selected(None).await, ("domain".to_owned(), 0));
    assert_eq!(selected(Some("bittorrent")).await, ("second".to_owned(), 0));
    assert_eq!(selected(Some("tls")).await, ("ip".to_owned(), 1));
}

/// Under `IPOnDemand`, `attrs` is checked before the destination IP too.
#[tokio::test]
async fn ip_on_demand_checks_attributes_before_the_lookup() {
    let config = config(json!({"domainStrategy": "IPOnDemand", "rules": [
        {"attrs": {"user-agent": "^curl/"}, "ip": ["203.0.113.7/32"], "outboundTag": "ip"},
        {"attrs": {":method": "POST"}, "outboundTag": "second"},
        {"domain": ["full:example.test"], "outboundTag": "domain"}
    ]}));
    let router = OutboundRouter::new(Arc::new(config));
    let selected = |attributes: Option<xray_config::ContentAttributes>| {
        let router = &router;
        async move {
            let resolver = Resolver::new(vec!["203.0.113.7".parse().unwrap()]);
            let route = xray_config::RouteContext {
                attributes: attributes.as_ref(),
                ..xray_config::RouteContext::inbound(Some("socks-in"))
            };
            let node = router
                .select_configured_node_with_resolver(&route, &target(), &resolver)
                .await
                .unwrap();
            (
                router.graph().node(node).unwrap().tag().unwrap().to_owned(),
                resolver.calls.load(Ordering::SeqCst),
            )
        }
    };
    let request = |method: &str, agent: &str| {
        let mut attributes = xray_config::ContentAttributes::default();
        attributes.set(":method", method.to_owned());
        attributes.set("user-agent", agent.to_owned());
        Some(attributes)
    };
    assert_eq!(selected(None).await, ("domain".to_owned(), 0));
    assert_eq!(
        selected(request("POST", "wget/1.21")).await,
        ("second".to_owned(), 0)
    );
    assert_eq!(
        selected(request("GET", "curl/8.7")).await,
        ("ip".to_owned(), 1)
    );
}

/// Outbounds for loopback tests: `lb` routes again from `again`, and `spin`
/// from `spin`.
fn loopback_config(routing: Value) -> CoreConfig {
    parse_xray_json(
        &json!({
            "inbounds": [],
            "outbounds": [
                {"tag": "default", "protocol": "freedom"},
                {"tag": "lb", "protocol": "loopback", "settings": {"inboundTag": "again"}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "second", "protocol": "freedom"},
                {"tag": "spin", "protocol": "loopback", "settings": {"inboundTag": "spin"}},
            ],
            "routing": routing,
        })
        .to_string(),
    )
    .unwrap()
    .config
}

fn ip_target() -> Target {
    Target::new(
        TargetAddr::Ip("203.0.113.7".parse().unwrap()),
        443,
        RoutingNetwork::Tcp,
    )
}

/// The tag a session from `route` to `target`, going to `dial_target`, ends
/// at, and how many lookups routing made.
async fn loopback_selection(
    router: &OutboundRouter,
    route: &xray_config::RouteContext<'_>,
    target: &Target,
    dial_target: &Target,
) -> (Result<String, CoreError>, usize) {
    let resolver = Resolver::new(vec!["203.0.113.7".parse().unwrap()]);
    let node = router
        .select_session_node_with_resolver(route, target, dial_target, &resolver)
        .await
        .map(|node| router.graph().node(node).unwrap().tag().unwrap().to_owned());
    (node, resolver.calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn loopbacks_route_again_from_their_inbound_tag() {
    let router = OutboundRouter::new(Arc::new(loopback_config(json!({"rules": [
        {"inboundTag": ["socks-in"], "outboundTag": "lb"},
        {"inboundTag": ["again"], "user": ["alice"], "outboundTag": "second"},
        {"inboundTag": ["again"], "protocol": ["tls"], "outboundTag": "second"},
        {"inboundTag": ["again"], "attrs": {":method": "GET"}, "outboundTag": "second"},
        {"inboundTag": ["again"], "outboundTag": "direct"}
    ]}))));
    let socks = xray_config::RouteContext::inbound(Some("socks-in"));
    assert_eq!(
        loopback_selection(&router, &socks, &target(), &target())
            .await
            .0
            .unwrap(),
        "direct"
    );
    // The user stays, as Xray-core's loopback copies the inbound.
    let alice = xray_config::RouteContext {
        user: Some("alice"),
        ..socks
    };
    assert_eq!(
        loopback_selection(&router, &alice, &target(), &target())
            .await
            .0
            .unwrap(),
        "second"
    );
    // A sniffed protocol and attrs do not: the loopback starts a new
    // content.
    let mut get = xray_config::ContentAttributes::default();
    get.set(":method", "GET".to_owned());
    let sniffed = xray_config::RouteContext {
        protocol: Some("tls"),
        attributes: Some(&get),
        ..socks
    };
    assert_eq!(
        loopback_selection(&router, &sniffed, &target(), &target())
            .await
            .0
            .unwrap(),
        "direct"
    );
}

#[test]
fn a_loopback_cannot_join_a_transport_chain() {
    for raw in [
        r#"{"outbounds": [
            {"tag": "direct", "protocol": "freedom", "proxySettings": {"tag": "lb", "transportLayer": true}},
            {"tag": "lb", "protocol": "loopback"}
        ]}"#,
        r#"{"outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "lb", "protocol": "loopback", "proxySettings": {"tag": "direct", "transportLayer": true}}
        ]}"#,
    ] {
        let parsed = parse_xray_json(raw).expect("chain shape parses");
        let graph = super::super::OutboundGraph::new(Arc::new(parsed.config));
        assert!(matches!(
            graph.validate_proxy_chains(),
            Err(super::super::OutboundProxyGraphError::UnsupportedNode { outbound, reason })
                if outbound == "lb" && reason.contains("loopback")
        ));
    }
}

#[tokio::test]
async fn loopbacks_route_the_dial_target_without_lookups() {
    let router = OutboundRouter::new(Arc::new(loopback_config(json!({
        "domainStrategy": "IPOnDemand",
        "rules": [
            {"inboundTag": ["socks-in"], "outboundTag": "lb"},
            {"inboundTag": ["again"], "ip": ["203.0.113.7/32"], "outboundTag": "second"},
            {"inboundTag": ["again"], "domain": ["full:example.test"], "outboundTag": "direct"}
        ]
    }))));
    let socks = xray_config::RouteContext::inbound(Some("socks-in"));
    // Routing again checks the address the session goes to.
    let (selected, lookups) = loopback_selection(&router, &socks, &target(), &ip_target()).await;
    assert_eq!((selected.unwrap(), lookups), ("second".to_owned(), 0));
    // A domain is not looked up for the IP rule, as Xray-core's loopback
    // skips DNS resolution.
    let (selected, lookups) = loopback_selection(&router, &socks, &ip_target(), &target()).await;
    assert_eq!((selected.unwrap(), lookups), ("direct".to_owned(), 0));
}

#[tokio::test]
async fn a_default_loopback_routes_again_too() {
    let router = OutboundRouter::new(Arc::new(
        parse_xray_json(
            &json!({
                "inbounds": [],
                "outbounds": [
                    {"tag": "lb", "protocol": "loopback", "settings": {"inboundTag": "again"}},
                    {"tag": "direct", "protocol": "freedom"},
                ],
                "routing": {"rules": [{"inboundTag": ["again"], "outboundTag": "direct"}]},
            })
            .to_string(),
        )
        .unwrap()
        .config,
    ));
    let socks = xray_config::RouteContext::inbound(Some("socks-in"));
    assert_eq!(
        loopback_selection(&router, &socks, &target(), &target())
            .await
            .0
            .unwrap(),
        "direct"
    );
}

#[tokio::test]
async fn a_loopback_chain_ends_after_the_hop_limit() {
    // `hN` loops back from `inN` to the next; the last goes to freedom.
    let chain = |hops: usize| {
        let mut outbounds = vec![json!({"tag": "direct", "protocol": "freedom"})];
        let mut rules = vec![json!({"inboundTag": ["socks-in"], "outboundTag": "h1"})];
        for hop in 1..=hops {
            outbounds.push(json!({"tag": format!("h{hop}"), "protocol": "loopback",
                "settings": {"inboundTag": format!("in{hop}")}}));
            let next = if hop == hops {
                "direct".to_owned()
            } else {
                format!("h{}", hop + 1)
            };
            rules.push(json!({"inboundTag": [format!("in{hop}")], "outboundTag": next}));
        }
        OutboundRouter::new(Arc::new(
            parse_xray_json(
                &json!({"inbounds": [], "outbounds": outbounds, "routing": {"rules": rules}})
                    .to_string(),
            )
            .unwrap()
            .config,
        ))
    };
    let socks = xray_config::RouteContext::inbound(Some("socks-in"));
    let router = chain(super::super::MAX_LOOPBACK_HOPS);
    assert_eq!(
        loopback_selection(&router, &socks, &target(), &target())
            .await
            .0
            .unwrap(),
        "direct"
    );
    let router = chain(super::super::MAX_LOOPBACK_HOPS + 1);
    assert!(matches!(
        loopback_selection(&router, &socks, &target(), &target())
            .await
            .0,
        Err(CoreError::LoopbackChainTooLong(
            super::super::MAX_LOOPBACK_HOPS
        ))
    ));

    // A loopback that routes back to itself fails the same way.
    let router = OutboundRouter::new(Arc::new(loopback_config(
        json!({"rules": [{"outboundTag": "spin", "network": "tcp,udp"}]}),
    )));
    assert!(matches!(
        loopback_selection(&router, &socks, &target(), &target())
            .await
            .0,
        Err(CoreError::LoopbackChainTooLong(_))
    ));
}
