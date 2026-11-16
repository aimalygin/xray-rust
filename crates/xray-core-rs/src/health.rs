use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::futures::Notified;
use tokio::sync::{watch, Notify};
use tokio::task::JoinSet;
use tokio::time::Instant;
use xray_config::{ObservatoryConfig, OBSERVATORY_PROBE_TIMEOUT};
use xray_transport::{DnsResolver, TransportDialer, TransportError};

use crate::outbound::{
    OutboundGraph, OutboundHealthState, OutboundNodeId, OutboundRouter, OutboundSelectionOverlay,
};
use crate::startup_probe::{
    run_outbound_url_probe, ProbeStatusPolicy, StartupProbeError, StartupProbeOptions,
};
use crate::CoreError;

const MAX_CONCURRENT_HEALTH_PROBES: usize = 4;

/// How soon after its last probe an outbound real traffic failed through is
/// probed again. However many flows fail, as they all do while a site is
/// down behind a working server, an outbound is probed at most this often.
const FAILURE_REPROBE_COOLDOWN: Duration = Duration::from_secs(10);

/// How soon after the last time a balancer with no healthy observed member
/// had all of them probed for a failure it may have them probed again.
const GROUP_REPROBE_COOLDOWN: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy)]
struct ReprobeCooldowns {
    leaf: Duration,
    group: Duration,
}

const REPROBE_COOLDOWNS: ReprobeCooldowns = ReprobeCooldowns {
    leaf: FAILURE_REPROBE_COOLDOWN,
    group: GROUP_REPROBE_COOLDOWN,
};

pub(crate) struct ObservatoryRuntime {
    config: ObservatoryConfig,
    nodes: Vec<OutboundNodeId>,
    outbound_router: Arc<OutboundRouter>,
    selection: Arc<OutboundSelectionOverlay>,
    destination_resolver: Arc<dyn DnsResolver>,
    bootstrap_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    cooldowns: ReprobeCooldowns,
}

impl ObservatoryRuntime {
    pub(crate) fn new(
        config: ObservatoryConfig,
        nodes: Vec<OutboundNodeId>,
        outbound_router: Arc<OutboundRouter>,
        selection: Arc<OutboundSelectionOverlay>,
        destination_resolver: Arc<dyn DnsResolver>,
        bootstrap_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
    ) -> Self {
        Self {
            config,
            nodes,
            outbound_router,
            selection,
            destination_resolver,
            bootstrap_resolver,
            transport_dialer,
            cooldowns: REPROBE_COOLDOWNS,
        }
    }

    #[cfg(test)]
    fn with_cooldowns(mut self, cooldowns: ReprobeCooldowns) -> Self {
        self.cooldowns = cooldowns;
        self
    }
}

/// Failures of real traffic, reported by the flows that met them and read by
/// the observatory: one slot per leaf outbound. A report for a leaf the
/// observatory does not watch is one atomic load; otherwise it is one swap,
/// and only the first report of a leaf still waiting wakes the observatory.
#[derive(Debug)]
pub(crate) struct FailureReports {
    slots: Box<[FailureSlot]>,
    wake: Notify,
}

#[derive(Debug, Default)]
struct FailureSlot {
    watched: AtomicBool,
    pending: AtomicBool,
}

impl FailureReports {
    pub(crate) fn new(leaf_count: usize) -> Self {
        Self {
            slots: (0..leaf_count).map(|_| FailureSlot::default()).collect(),
            wake: Notify::new(),
        }
    }

    pub(crate) fn report(&self, index: usize) {
        let Some(slot) = self.slots.get(index) else {
            return;
        };
        if !slot.watched.load(Ordering::Acquire) {
            return;
        }
        if !slot.pending.swap(true, Ordering::AcqRel) {
            // One stored permit at most: a report made while the observatory
            // probes wakes its next wait at once.
            self.wake.notify_one();
        }
    }

    fn watch(&self, index: usize, watched: bool) {
        if let Some(slot) = self.slots.get(index) {
            slot.pending.store(false, Ordering::Release);
            slot.watched.store(watched, Ordering::Release);
        }
    }

    fn is_pending(&self, index: usize) -> bool {
        self.slots
            .get(index)
            .is_some_and(|slot| slot.pending.load(Ordering::Acquire))
    }

    fn clear(&self, index: usize) {
        if let Some(slot) = self.slots.get(index) {
            slot.pending.store(false, Ordering::Release);
        }
    }

    fn notified(&self) -> Notified<'_> {
        self.wake.notified()
    }
}

/// Whether `error`, from opening a flow through an outbound, says that the
/// outbound's server could not be reached or failed its handshake: a refused,
/// reset or timed-out connection, a TLS, REALITY or transport handshake that
/// failed. A remote that closes, a server that refuses the flow's target, a
/// destination that does not resolve or the local network being down say
/// nothing about the server, and the configuration errors every open meets
/// are left to the probes.
pub(crate) fn is_dial_failure(error: &CoreError) -> bool {
    use xray_proxy::outbound::{HttpClientError, SocksClientError};
    use xray_transport::hysteria::HysteriaError;
    use xray_transport::masque::MasqueError;

    match error {
        CoreError::Transport(error) => is_transport_dial_failure(error),
        CoreError::Io(error) => is_io_dial_failure(error.kind()),
        CoreError::Socks(SocksClientError::Io(kind))
        | CoreError::Http(HttpClientError::Io(kind)) => is_io_dial_failure(*kind),
        CoreError::Hysteria(error) => matches!(
            error,
            HysteriaError::Connect | HysteriaError::Timeout | HysteriaError::Authentication
        ),
        CoreError::Masque(error) => matches!(error, MasqueError::Dial(_) | MasqueError::Timeout),
        CoreError::Wireguard(error) => matches!(error, xray_wireguard::Error::Timeout),
        _ => false,
    }
}

fn is_transport_dial_failure(error: &TransportError) -> bool {
    match error {
        TransportError::Tcp(error) | TransportError::Kcp(error) => is_io_dial_failure(error.kind()),
        TransportError::Tls(error) => !is_local_network_failure(error.kind()),
        TransportError::Reality(_)
        | TransportError::HttpUpgradeRejected(_)
        | TransportError::WebSocketProtocol(_)
        | TransportError::Http2Connect(_)
        | TransportError::Grpc(_)
        | TransportError::Xhttp(_)
        | TransportError::Xdrive(_)
        | TransportError::ChainedOutbound(_) => true,
        _ => false,
    }
}

fn is_io_dial_failure(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
    )
}

fn is_local_network_failure(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::NetworkDown | io::ErrorKind::NetworkUnreachable
    )
}

pub(crate) async fn run_observatory(
    runtime: ObservatoryRuntime,
    mut shutdown: watch::Receiver<bool>,
) {
    if runtime.nodes.is_empty() {
        return;
    }
    let mut reprobes = Reprobes::new(
        Arc::clone(&runtime.selection),
        runtime.outbound_router.graph(),
        &runtime.nodes,
        runtime.cooldowns,
    );

    loop {
        let completed = if runtime.config.enable_concurrency {
            probe_nodes(&runtime, &runtime.nodes, &mut reprobes, &mut shutdown).await
                && idle(&runtime, &mut reprobes, &mut shutdown).await
        } else {
            run_sequential_round(&runtime, &mut reprobes, &mut shutdown).await
        };
        if !completed {
            return;
        }
    }
}

async fn run_sequential_round(
    runtime: &ObservatoryRuntime,
    reprobes: &mut Reprobes,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    for node in &runtime.nodes {
        if !probe_nodes(runtime, std::slice::from_ref(node), reprobes, shutdown).await
            || !idle(runtime, reprobes, shutdown).await
        {
            return false;
        }
    }
    true
}

/// Probes `nodes`, at most four at once in concurrent mode and one at a time
/// otherwise. Returns false when the core shuts down meanwhile.
async fn probe_nodes(
    runtime: &ObservatoryRuntime,
    nodes: &[OutboundNodeId],
    reprobes: &mut Reprobes,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    let concurrency = if runtime.config.enable_concurrency {
        MAX_CONCURRENT_HEALTH_PROBES
    } else {
        1
    };
    for chunk in nodes.chunks(concurrency) {
        let started = Instant::now();
        let mut tasks = JoinSet::new();
        for node in chunk.iter().copied() {
            reprobes.probe_started(node, started);
            let config = runtime.config.clone();
            let outbound_router = Arc::clone(&runtime.outbound_router);
            let destination_resolver = Arc::clone(&runtime.destination_resolver);
            let bootstrap_resolver = Arc::clone(&runtime.bootstrap_resolver);
            let transport_dialer = Arc::clone(&runtime.transport_dialer);
            tasks.spawn(async move {
                let result = probe_node(
                    &config,
                    node,
                    &outbound_router,
                    &destination_resolver,
                    &bootstrap_resolver,
                    &transport_dialer,
                )
                .await;
                (node, result)
            });
        }

        while !tasks.is_empty() {
            tokio::select! {
                biased;
                () = wait_for_shutdown(shutdown) => {
                    tasks.abort_all();
                    return false;
                }
                joined = tasks.join_next() => {
                    if let Some(Ok((node, result))) = joined {
                        record_result(&runtime.selection, node, result);
                    }
                }
            }
        }
    }
    true
}

/// Waits out the probe interval. A failure that real traffic reports wakes
/// the wait, and the outbounds it concerns are probed as soon as their
/// cooldowns allow, without moving the next scheduled probe. Returns false
/// when the core shuts down meanwhile.
async fn idle(
    runtime: &ObservatoryRuntime,
    reprobes: &mut Reprobes,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    let deadline = Instant::now() + runtime.config.probe_interval;
    loop {
        let now = Instant::now();
        let due = reprobes.take_due(now);
        if !due.is_empty() {
            if !probe_nodes(runtime, &due, reprobes, shutdown).await {
                return false;
            }
            continue;
        }
        if now >= deadline {
            return true;
        }
        let wake_at = reprobes
            .next_due(now)
            .map_or(deadline, |due| due.min(deadline));
        tokio::select! {
            biased;
            () = wait_for_shutdown(shutdown) => return false,
            () = runtime.selection.failure_reports().notified() => {}
            () = tokio::time::sleep_until(wake_at) => {}
        }
    }
}

/// What the observatory makes of the failures real traffic reports.
///
/// It watches the leaves it observes, and the outbound each balancer with an
/// observed member falls back to: its `fallbackTag`, or else the default
/// outbound. A reported leaf is probed again once [`FAILURE_REPROBE_COOLDOWN`]
/// has passed since its last probe. When the report reaches a balancer none
/// of whose observed members is healthy, through a member or its fallback,
/// every observed member is probed again too, at most once per
/// [`GROUP_REPROBE_COOLDOWN`], so that one which came back is found.
struct Reprobes {
    selection: Arc<OutboundSelectionOverlay>,
    cooldowns: ReprobeCooldowns,
    leaves: Vec<WatchedLeaf>,
    positions: HashMap<OutboundNodeId, usize>,
    groups: Vec<WatchedGroup>,
}

struct WatchedLeaf {
    node: OutboundNodeId,
    slot: usize,
    observed: bool,
    /// When it was last probed or its report last handled.
    last: Option<Instant>,
    /// The balancers whose flows may reach it, as indexes into `groups`.
    groups: Vec<usize>,
}

struct WatchedGroup {
    /// Its observed members.
    members: Vec<OutboundNodeId>,
    last_reprobe: Option<Instant>,
}

impl Reprobes {
    fn new(
        selection: Arc<OutboundSelectionOverlay>,
        graph: &OutboundGraph,
        observed: &[OutboundNodeId],
        cooldowns: ReprobeCooldowns,
    ) -> Self {
        let mut reprobes = Self {
            selection,
            cooldowns,
            leaves: Vec::new(),
            positions: HashMap::new(),
            groups: Vec::new(),
        };
        for node in observed {
            reprobes.watch(*node, true);
        }
        let observed = observed.iter().copied().collect::<HashSet<_>>();
        for group in graph.selector_groups() {
            let members = group
                .members()
                .iter()
                .copied()
                .filter(|member| observed.contains(member))
                .collect::<Vec<_>>();
            if members.is_empty() {
                continue;
            }
            let group_index = reprobes.groups.len();
            let fallback = match group.fallback_tag() {
                Some(tag) => graph.node_for_tag(tag),
                None => graph.default_node(),
            };
            for node in members.iter().copied().chain(fallback) {
                if let Some(position) = reprobes.watch(node, false) {
                    let groups = &mut reprobes.leaves[position].groups;
                    if !groups.contains(&group_index) {
                        groups.push(group_index);
                    }
                }
            }
            reprobes.groups.push(WatchedGroup {
                members,
                last_reprobe: None,
            });
        }
        reprobes
    }

    /// Starts watching leaf `node`, and returns its position.
    fn watch(&mut self, node: OutboundNodeId, observed: bool) -> Option<usize> {
        if let Some(position) = self.positions.get(&node) {
            return Some(*position);
        }
        let slot = self.selection.leaf_index(node)?;
        self.selection.failure_reports().watch(slot, true);
        let position = self.leaves.len();
        self.leaves.push(WatchedLeaf {
            node,
            slot,
            observed,
            last: None,
            groups: Vec::new(),
        });
        self.positions.insert(node, position);
        Some(position)
    }

    /// Records that a probe of `node` started at `now`, which answers the
    /// reports made before it.
    fn probe_started(&mut self, node: OutboundNodeId, now: Instant) {
        if let Some(position) = self.positions.get(&node) {
            let leaf = &mut self.leaves[*position];
            self.selection.failure_reports().clear(leaf.slot);
            leaf.last = Some(now);
        }
    }

    /// When, from `now` on, the earliest report still waiting can be
    /// handled.
    fn next_due(&self, now: Instant) -> Option<Instant> {
        self.leaves
            .iter()
            .filter(|leaf| self.selection.failure_reports().is_pending(leaf.slot))
            .map(|leaf| self.due(leaf, now).max(now))
            .min()
    }

    /// Handles every report whose time has come, and returns the outbounds
    /// to probe for them.
    fn take_due(&mut self, now: Instant) -> Vec<OutboundNodeId> {
        let mut nodes = Vec::new();
        for position in 0..self.leaves.len() {
            let leaf = &self.leaves[position];
            if !self.selection.failure_reports().is_pending(leaf.slot) || self.due(leaf, now) > now
            {
                continue;
            }
            if leaf.observed && self.leaf_due(leaf, now) <= now {
                push_unique(&mut nodes, leaf.node);
            }
            let due_groups = leaf
                .groups
                .iter()
                .copied()
                .filter(|group| self.group_due(*group, now).is_some_and(|due| due <= now))
                .collect::<Vec<_>>();
            for group in due_groups {
                let group = &mut self.groups[group];
                group.last_reprobe = Some(now);
                for member in &group.members {
                    push_unique(&mut nodes, *member);
                }
            }
            let leaf = &mut self.leaves[position];
            self.selection.failure_reports().clear(leaf.slot);
            leaf.last = Some(now);
        }
        nodes
    }

    /// When a report of `leaf` can be handled: when it may be probed again
    /// or a balancer it may serve may have its members probed. A report
    /// of a leaf that is only a fallback, with no such balancer, is dropped
    /// then, so that it wakes the observatory no more often.
    fn due(&self, leaf: &WatchedLeaf, now: Instant) -> Instant {
        let group_due = leaf
            .groups
            .iter()
            .filter_map(|group| self.group_due(*group, now))
            .min();
        match group_due {
            Some(group_due) if leaf.observed => group_due.min(self.leaf_due(leaf, now)),
            Some(group_due) => group_due,
            None => self.leaf_due(leaf, now),
        }
    }

    fn leaf_due(&self, leaf: &WatchedLeaf, now: Instant) -> Instant {
        leaf.last.map_or(now, |last| last + self.cooldowns.leaf)
    }

    /// When the members of balancer `group` may all be probed again, if
    /// none of them is healthy.
    fn group_due(&self, group: usize, now: Instant) -> Option<Instant> {
        let group = &self.groups[group];
        let healthy = group
            .members
            .iter()
            .any(|member| self.selection.health_state_of(*member) == OutboundHealthState::Healthy);
        (!healthy).then(|| {
            group
                .last_reprobe
                .map_or(now, |last| last + self.cooldowns.group)
        })
    }
}

impl Drop for Reprobes {
    fn drop(&mut self) {
        for leaf in &self.leaves {
            self.selection.failure_reports().watch(leaf.slot, false);
        }
    }
}

fn push_unique(nodes: &mut Vec<OutboundNodeId>, node: OutboundNodeId) {
    if !nodes.contains(&node) {
        nodes.push(node);
    }
}

async fn probe_node(
    config: &ObservatoryConfig,
    node: OutboundNodeId,
    outbound_router: &OutboundRouter,
    destination_resolver: &Arc<dyn DnsResolver>,
    bootstrap_resolver: &Arc<dyn DnsResolver>,
    transport_dialer: &TransportDialer,
) -> Result<Duration, StartupProbeError> {
    let outbound_tag = outbound_router
        .graph()
        .node(node)
        .and_then(|node| node.tag())
        .map(ToOwned::to_owned);
    run_outbound_url_probe(
        outbound_router,
        StartupProbeOptions {
            url: config.probe_url.clone(),
            timeout: OBSERVATORY_PROBE_TIMEOUT,
            outbound_tag,
        },
        destination_resolver.as_ref(),
        bootstrap_resolver.as_ref(),
        transport_dialer,
        ProbeStatusPolicy::AnyResponse,
    )
    .await
}

fn record_result(
    selection: &OutboundSelectionOverlay,
    node: OutboundNodeId,
    result: Result<Duration, StartupProbeError>,
) {
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    match result {
        Ok(delay) => selection.record_health_success(node, delay, now_unix_ms),
        Err(error) => {
            selection.record_health_failure(node, error.health_failure(), now_unix_ms);
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OutboundHealthFailure;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_config::{
        CoreConfig, Network, OutboundConfig, OutboundSettings, RoutingBalancer,
        RoutingBalancerStrategy, RoutingConfig, StreamSecurity, StreamSettings, StreamTransport,
    };

    #[test]
    fn failure_classification_is_structured() {
        let error = StartupProbeError::HttpStatus {
            url: "http://<redacted-host>:80".to_owned(),
            status: 503,
        };

        assert_eq!(
            error.health_failure(),
            OutboundHealthFailure::HttpStatus(503)
        );
    }

    fn freedom(tag: &str) -> OutboundConfig {
        OutboundConfig {
            mux: None,
            tag: Some(tag.to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                tcp_xmc: None,
                udp_xdns: None,
                udp_realm: None,
                udp_xicmp: None,
                udp_salamander: None,
                udp_sudoku: None,
                udp_noise: None,
                socket_options: None,
            },
            settings: OutboundSettings::Freedom(Default::default()),
        }
    }

    /// `proxy-a` and `proxy-b` observed under a `leastPing` balancer falling
    /// back to `direct`, and `other`, which nothing watches.
    fn config(probe_url: String) -> CoreConfig {
        CoreConfig {
            inbounds: Vec::new(),
            outbounds: vec![
                freedom("direct"),
                freedom("proxy-a"),
                freedom("proxy-b"),
                freedom("other"),
            ],
            default_outbound_tag: Some("direct".to_owned()),
            routing: RoutingConfig {
                balancers: vec![RoutingBalancer {
                    tag: "auto".to_owned(),
                    selectors: vec!["proxy-".to_owned()],
                    strategy: RoutingBalancerStrategy::LeastPing,
                    fallback_tag: Some("direct".to_owned()),
                }],
                ..Default::default()
            },
            observatory: Some(ObservatoryConfig {
                subject_selectors: vec!["proxy-".to_owned()],
                probe_url,
                probe_interval: Duration::from_secs(600),
                enable_concurrency: true,
            }),
            dns: Default::default(),
            policy: Default::default(),
        }
    }

    struct Fixture {
        router: Arc<OutboundRouter>,
        proxy_a: OutboundNodeId,
        proxy_b: OutboundNodeId,
        direct: OutboundNodeId,
        other: OutboundNodeId,
    }

    impl Fixture {
        fn new() -> Self {
            let router = Arc::new(OutboundRouter::new(Arc::new(config(
                "http://192.0.2.1/generate_204".to_owned(),
            ))));
            let node = |tag| router.graph().node_for_tag(tag).unwrap();
            Self {
                proxy_a: node("proxy-a"),
                proxy_b: node("proxy-b"),
                direct: node("direct"),
                other: node("other"),
                router: Arc::clone(&router),
            }
        }

        fn observed(&self) -> Vec<OutboundNodeId> {
            self.router
                .graph()
                .leaf_nodes_matching_prefixes(&["proxy-".to_owned()])
        }

        /// A watcher whose first round started at `start` and found both
        /// proxies healthy.
        fn reprobes(&self, start: Instant) -> Reprobes {
            let mut reprobes = Reprobes::new(
                self.router.selection_handle(),
                self.router.graph(),
                &self.observed(),
                REPROBE_COOLDOWNS,
            );
            for node in [self.proxy_a, self.proxy_b] {
                reprobes.probe_started(node, start);
                self.healthy(node);
            }
            reprobes
        }

        fn healthy(&self, node: OutboundNodeId) {
            self.router
                .selection()
                .record_health_success(node, Duration::from_millis(50), 1_000);
        }

        fn unhealthy(&self, node: OutboundNodeId) {
            self.router.selection().record_health_failure(
                node,
                OutboundHealthFailure::Timeout,
                2_000,
            );
        }

        fn report(&self, node: OutboundNodeId) {
            self.router.selection().report_dial_failure(node);
        }

        fn pending(&self, node: OutboundNodeId) -> bool {
            let slot = self.router.selection().leaf_index(node).unwrap();
            self.router.selection().failure_reports().is_pending(slot)
        }
    }

    #[test]
    fn without_reports_nothing_is_probed_between_rounds() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);

        for elapsed in [0, 11, 16, 3_600] {
            let now = start + Duration::from_secs(elapsed);
            assert_eq!(reprobes.next_due(now), None);
            assert!(reprobes.take_due(now).is_empty());
        }
        // A leaf nothing watches is no report at all.
        fixture.report(fixture.other);
        assert!(!fixture.pending(fixture.other));
        assert_eq!(reprobes.next_due(start + Duration::from_secs(20)), None);
    }

    #[test]
    fn reports_wait_for_an_observatory() {
        let fixture = Fixture::new();
        fixture.report(fixture.proxy_a);
        assert!(!fixture.pending(fixture.proxy_a));

        let reprobes = fixture.reprobes(Instant::now());
        fixture.report(fixture.proxy_a);
        assert!(fixture.pending(fixture.proxy_a));

        drop(reprobes);
        assert!(!fixture.pending(fixture.proxy_a));
        fixture.report(fixture.proxy_a);
        assert!(!fixture.pending(fixture.proxy_a));
    }

    #[test]
    fn reported_failure_is_probed_at_once_after_the_cooldown() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        let now = start + Duration::from_secs(60);

        fixture.report(fixture.proxy_a);
        fixture.report(fixture.proxy_a);
        assert_eq!(reprobes.next_due(now), Some(now));
        assert_eq!(reprobes.take_due(now), vec![fixture.proxy_a]);
        reprobes.probe_started(fixture.proxy_a, now);
        assert!(!fixture.pending(fixture.proxy_a));
        assert_eq!(reprobes.next_due(now), None);
    }

    #[test]
    fn reports_within_the_cooldown_wait_for_it() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);

        // Three seconds after the round probed it, traffic through
        // `proxy-a` fails: its next probe waits for the ten seconds.
        let early = start + Duration::from_secs(3);
        fixture.report(fixture.proxy_a);
        assert_eq!(
            reprobes.next_due(early),
            Some(start + FAILURE_REPROBE_COOLDOWN)
        );
        assert!(reprobes.take_due(early).is_empty());
        assert!(fixture.pending(fixture.proxy_a));

        let due = start + FAILURE_REPROBE_COOLDOWN;
        assert_eq!(reprobes.take_due(due), vec![fixture.proxy_a]);
        reprobes.probe_started(fixture.proxy_a, due);

        // So does a report made while that probe runs.
        fixture.report(fixture.proxy_a);
        let later = due + Duration::from_secs(1);
        assert_eq!(
            reprobes.next_due(later),
            Some(due + FAILURE_REPROBE_COOLDOWN)
        );
        assert!(reprobes.take_due(later).is_empty());
    }

    #[test]
    fn group_without_healthy_member_is_probed_whole() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        fixture.unhealthy(fixture.proxy_a);
        fixture.unhealthy(fixture.proxy_b);

        // The balancer falls back; a failure through any of its outbounds
        // has every observed member probed, whatever their own cooldowns.
        let first = start + Duration::from_secs(1);
        fixture.report(fixture.proxy_a);
        assert_eq!(reprobes.next_due(first), Some(first));
        assert_eq!(
            reprobes.take_due(first),
            vec![fixture.proxy_a, fixture.proxy_b]
        );
        for node in [fixture.proxy_a, fixture.proxy_b] {
            reprobes.probe_started(node, first);
        }

        // Within the group cooldown only the reported leaf is, once its own
        // cooldown passed.
        fixture.report(fixture.proxy_a);
        let leaf_due = first + FAILURE_REPROBE_COOLDOWN;
        assert_eq!(reprobes.next_due(first), Some(leaf_due));
        assert_eq!(reprobes.take_due(leaf_due), vec![fixture.proxy_a]);
        reprobes.probe_started(fixture.proxy_a, leaf_due);

        // The fallback failing too has the whole group probed again once the
        // group cooldown passed.
        fixture.report(fixture.direct);
        let group_due = first + GROUP_REPROBE_COOLDOWN;
        assert_eq!(reprobes.next_due(leaf_due), Some(group_due));
        assert!(reprobes.take_due(leaf_due).is_empty());
        assert_eq!(
            reprobes.take_due(group_due),
            vec![fixture.proxy_a, fixture.proxy_b]
        );
    }

    #[test]
    fn fallback_failure_is_ignored_while_a_member_is_healthy() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        fixture.unhealthy(fixture.proxy_a);

        let now = start + Duration::from_secs(1);
        fixture.report(fixture.direct);
        assert!(reprobes.take_due(now).is_empty());
        assert!(!fixture.pending(fixture.direct));
        // Handled reports of the fallback are rate limited like any other.
        fixture.report(fixture.direct);
        assert_eq!(reprobes.next_due(now), Some(now + FAILURE_REPROBE_COOLDOWN));
        assert_eq!(
            fixture.router.selection().health_state_of(fixture.proxy_b),
            OutboundHealthState::Healthy
        );
    }

    #[test]
    fn dial_failures_are_told_from_other_errors() {
        let io = |kind| CoreError::Io(io::Error::from(kind));
        let tcp = |kind| CoreError::Transport(TransportError::Tcp(io::Error::from(kind)));

        assert!(is_dial_failure(&tcp(io::ErrorKind::ConnectionRefused)));
        assert!(is_dial_failure(&tcp(io::ErrorKind::TimedOut)));
        assert!(is_dial_failure(&CoreError::Transport(TransportError::Tls(
            io::Error::from(io::ErrorKind::UnexpectedEof)
        ))));
        assert!(is_dial_failure(&io(io::ErrorKind::ConnectionReset)));
        assert!(is_dial_failure(&CoreError::Hysteria(
            xray_transport::hysteria::HysteriaError::Connect
        )));
        assert!(is_dial_failure(&CoreError::Socks(
            xray_proxy::outbound::SocksClientError::Io(io::ErrorKind::ConnectionRefused)
        )));

        assert!(!is_dial_failure(&tcp(io::ErrorKind::NetworkUnreachable)));
        assert!(!is_dial_failure(&io(io::ErrorKind::UnexpectedEof)));
        assert!(!is_dial_failure(&io(io::ErrorKind::BrokenPipe)));
        assert!(!is_dial_failure(&CoreError::Transport(
            TransportError::DnsNameError("example.test".to_owned(), 443)
        )));
        assert!(!is_dial_failure(&CoreError::Socks(
            xray_proxy::outbound::SocksClientError::RequestRejected(5)
        )));
        assert!(!is_dial_failure(&CoreError::Http(
            xray_proxy::outbound::HttpClientError::Rejected(502)
        )));
        assert!(!is_dial_failure(&CoreError::VisionUdp443Rejected));
    }

    /// Answers every probe with `204` until the returned task is aborted,
    /// which closes the port.
    async fn probe_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe server");
        let url = format!(
            "http://127.0.0.1:{}/generate_204",
            listener.local_addr().expect("probe server address").port()
        );
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await;
                });
            }
        });
        (url, server)
    }

    async fn wait_for_state(
        selection: &OutboundSelectionOverlay,
        node: OutboundNodeId,
        state: OutboundHealthState,
    ) {
        tokio::time::timeout(Duration::from_secs(4), async {
            while selection.health_state_of(node) != state {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("outbound should become {state:?}"));
    }

    #[tokio::test]
    async fn reported_failure_is_probed_long_before_the_interval() {
        let (url, server) = probe_server().await;
        let config = config(url);
        let observatory = config.observatory.clone().unwrap();
        let router = Arc::new(OutboundRouter::new(Arc::new(config)));
        let nodes = router
            .graph()
            .leaf_nodes_matching_prefixes(&observatory.subject_selectors);
        let proxy_a = router.graph().node_for_tag("proxy-a").unwrap();
        let proxy_b = router.graph().node_for_tag("proxy-b").unwrap();
        let resolver = crate::system_dns_resolver();
        let runtime = ObservatoryRuntime::new(
            observatory,
            nodes,
            Arc::clone(&router),
            router.selection_handle(),
            Arc::clone(&resolver),
            resolver,
            Arc::new(TransportDialer::system().expect("system dialer")),
        )
        // The first round has just probed `proxy-a`: a cooldown this short
        // lets the report be served at once.
        .with_cooldowns(ReprobeCooldowns {
            leaf: Duration::from_millis(1),
            group: GROUP_REPROBE_COOLDOWN,
        });
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let observer = tokio::spawn(run_observatory(runtime, shutdown_rx));
        let selection = router.selection();
        wait_for_state(selection, proxy_a, OutboundHealthState::Healthy).await;
        wait_for_state(selection, proxy_b, OutboundHealthState::Healthy).await;

        // The server goes away. Without a report nothing notices it for the
        // ten-minute interval; the report has `proxy-a` probed again now.
        server.abort();
        let _ = server.await;
        router.report_open_error(
            proxy_a,
            &CoreError::Transport(TransportError::Tcp(io::Error::from(
                io::ErrorKind::ConnectionRefused,
            ))),
        );
        wait_for_state(selection, proxy_a, OutboundHealthState::Unhealthy).await;
        assert_eq!(
            selection.health_state_of(proxy_b),
            OutboundHealthState::Healthy
        );

        shutdown_tx.send(true).expect("observer listens");
        observer.await.expect("observer stops");
        router.selection().report_dial_failure(proxy_b);
        let slot = selection.leaf_index(proxy_b).unwrap();
        assert!(!selection.failure_reports().is_pending(slot));
    }
}
