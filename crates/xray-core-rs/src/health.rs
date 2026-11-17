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
    OutboundGraph, OutboundHealthState, OutboundNodeId, OutboundNodeKind, OutboundRouter,
    OutboundSelectionOverlay,
};
use crate::startup_probe::{
    run_outbound_url_probe, ProbeStatusPolicy, StartupProbeError, StartupProbeOptions,
};
use crate::CoreError;

const MAX_CONCURRENT_HEALTH_PROBES: usize = 4;

/// How long after its last probe finished an outbound real traffic failed
/// through is probed again, and how long a failed re-probe waits for the
/// probe that confirms it. However many flows fail, as they all do while a
/// site is down behind a working server, an outbound is probed at most this
/// often for them.
const FAILURE_REPROBE_COOLDOWN: Duration = Duration::from_secs(10);

/// How long after its last pass finished a balancer with no healthy observed
/// member may have all of them probed again for a failure. Doubled after each
/// pass in which every probe failed, up to the probe interval.
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

/// Whether `error`, from opening a flow through an outbound, may mean that
/// the outbound's server is gone: a connection refused, reset or timed out,
/// or a TLS or REALITY handshake the server broke off or failed. A remote
/// that closes, a server that refuses the flow's target, a destination that
/// does not resolve, a local network that is down or unreachable, and the
/// configuration errors every open meets are not. Neither are errors that
/// carry only a message:
/// XHTTP, gRPC, XDRIVE, WebSocket, HTTP upgrade and HTTP/2 CONNECT opens and
/// a chained hop flatten whatever went wrong, the local network included,
/// into text. A timeout is reported, though a local network that is changing
/// produces one too: it is what a server that drops packets gives. That is
/// why a report only has the observatory probe the outbound, and one failed
/// re-probe does not change its health.
pub(crate) fn is_dial_failure(error: &CoreError) -> bool {
    use xray_proxy::outbound::{HttpClientError, SocksClientError};
    use xray_transport::hysteria::HysteriaError;
    use xray_transport::masque::MasqueError;

    match error {
        CoreError::Transport(error) => is_transport_dial_failure(error),
        CoreError::Io(error) => is_server_io_failure(error.kind()),
        CoreError::Socks(SocksClientError::Io(kind))
        | CoreError::Http(HttpClientError::Io(kind)) => is_server_io_failure(*kind),
        // `Connect` also covers a local socket that could not be bound or
        // rebound; a server that does not answer ends in `Timeout`.
        CoreError::Hysteria(error) => matches!(
            error,
            HysteriaError::Timeout | HysteriaError::Authentication
        ),
        CoreError::Masque(error) => matches!(error, MasqueError::Timeout),
        CoreError::Wireguard(error) => matches!(error, xray_wireguard::Error::Timeout),
        _ => false,
    }
}

fn is_transport_dial_failure(error: &TransportError) -> bool {
    use xray_transport::reality::RealityError;

    match error {
        TransportError::Tcp(error) | TransportError::Kcp(error) => {
            is_server_io_failure(error.kind())
        }
        // A handshake the server, or something in its place, broke off or
        // answered with an alert or a certificate that does not verify.
        TransportError::Tls(error) => {
            is_server_io_failure(error.kind())
                || matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
                )
        }
        // The server did not authenticate as the configured REALITY server.
        TransportError::Reality(RealityError::RealCertificate) => true,
        _ => false,
    }
}

/// A connection refused or reset by the server or the path to it, or one
/// that timed out. `ConnectionAborted`, `HostUnreachable`, `NetworkDown`,
/// `NetworkUnreachable` and `AddrNotAvailable` come from the local network
/// stack and are not counted.
fn is_server_io_failure(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::TimedOut | io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
    )
}

/// Whether a flow through an outbound of `kind` is carried by a server of
/// its own, whose failure to answer says something about that outbound.
/// Freedom dials the flow's target itself, blackhole and DNS outbounds open
/// no connection, and loopback hands the flow back to routing.
fn reaches_its_own_server(kind: OutboundNodeKind) -> bool {
    !matches!(
        kind,
        OutboundNodeKind::Freedom
            | OutboundNodeKind::Blackhole
            | OutboundNodeKind::Dns
            | OutboundNodeKind::Loopback
            | OutboundNodeKind::Selector
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
        runtime.config.probe_interval,
        runtime.cooldowns,
    );

    loop {
        let completed = if runtime.config.enable_concurrency {
            probe_nodes(
                &runtime,
                &runtime.nodes,
                ProbeKind::Scheduled,
                &mut reprobes,
                &mut shutdown,
            )
            .await
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
        if !probe_nodes(
            runtime,
            std::slice::from_ref(node),
            ProbeKind::Scheduled,
            reprobes,
            shutdown,
        )
        .await
            || !idle(runtime, reprobes, shutdown).await
        {
            return false;
        }
    }
    true
}

/// Why an outbound is probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeKind {
    /// The round of the probe interval. Its result is recorded as it is.
    Scheduled,
    /// For a failure of real traffic, or a follow-up of such a probe.
    Reprobe,
}

/// Probes `nodes`, at most four at once in concurrent mode and one at a time
/// otherwise. Returns false when the core shuts down meanwhile.
async fn probe_nodes(
    runtime: &ObservatoryRuntime,
    nodes: &[OutboundNodeId],
    kind: ProbeKind,
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
                        if reprobes.probe_finished(node, result.is_ok(), kind, Instant::now()) {
                            record_result(&runtime.selection, node, result);
                        }
                    }
                }
            }
        }
    }
    true
}

/// Waits out the probe interval. A failure that real traffic reports wakes
/// the wait, and the outbounds it concerns are probed as soon as their
/// cooldowns allow, as are the follow-ups failed re-probes left, without
/// moving the next scheduled probe. Returns false when the core shuts down
/// meanwhile.
async fn idle(
    runtime: &ObservatoryRuntime,
    reprobes: &mut Reprobes,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    let deadline = Instant::now() + runtime.config.probe_interval;
    loop {
        let now = Instant::now();
        let pass = reprobes.take_due(now);
        if !pass.nodes.is_empty() {
            if !probe_nodes(runtime, &pass.nodes, ProbeKind::Reprobe, reprobes, shutdown).await {
                return false;
            }
            reprobes.pass_finished(&pass, Instant::now());
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
/// It watches the leaves it observes and the outbound each balancer with an
/// observed member falls back to, its `fallbackTag` or else the default
/// outbound, when they reach a server of their own. A reported leaf is
/// probed again once [`FAILURE_REPROBE_COOLDOWN`] has passed since its last
/// probe finished. When the report reaches a balancer none of whose observed
/// members is healthy, through a member or its fallback, every observed
/// member is probed again too, once the balancer's cooldown has passed since
/// its last such pass finished, so that one which came back is found.
///
/// Re-probes run exactly when traffic fails, which may be because the local
/// network went away for a moment. So a failed re-probe of an outbound that
/// is not unhealthy is not recorded: the outbound is probed again a cooldown
/// later, and only that probe's result counts. When re-probes marked an
/// outbound unhealthy, it gets no flows that could report it again, so it is
/// probed again after the cooldown, then after twice as long while it fails,
/// up to the probe interval. Results of the scheduled round are recorded as
/// they are and end any such follow-up.
struct Reprobes {
    selection: Arc<OutboundSelectionOverlay>,
    cooldowns: ReprobeCooldowns,
    probe_interval: Duration,
    leaves: Vec<WatchedLeaf>,
    positions: HashMap<OutboundNodeId, usize>,
    groups: Vec<WatchedGroup>,
}

struct WatchedLeaf {
    node: OutboundNodeId,
    slot: usize,
    observed: bool,
    /// When its last probe finished, or its last report was handled
    /// without one.
    last: Option<Instant>,
    /// Whether its last probe failed.
    failed: bool,
    /// The probe a failed re-probe left it waiting for.
    followup: Option<Followup>,
    /// The balancers whose flows may reach it, as indexes into `groups`.
    groups: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Followup {
    /// A re-probe failed while the outbound was not unhealthy. This probe,
    /// a leaf cooldown after it, decides.
    Confirm,
    /// Re-probes marked it unhealthy; it is probed again this long after
    /// its last probe.
    Recheck(Duration),
}

struct WatchedGroup {
    /// Its observed members.
    members: Vec<OutboundNodeId>,
    /// When its last pass finished.
    last_pass: Option<Instant>,
    /// How long after `last_pass` the next pass may start.
    cooldown: Duration,
}

/// What [`Reprobes::take_due`] hands out: the outbounds to probe, and the
/// balancers all of whose members are among them.
#[derive(Debug, Default)]
struct ReprobePass {
    nodes: Vec<OutboundNodeId>,
    groups: Vec<usize>,
}

impl Reprobes {
    fn new(
        selection: Arc<OutboundSelectionOverlay>,
        graph: &OutboundGraph,
        observed: &[OutboundNodeId],
        probe_interval: Duration,
        cooldowns: ReprobeCooldowns,
    ) -> Self {
        let mut reprobes = Self {
            selection,
            cooldowns,
            probe_interval,
            leaves: Vec::new(),
            positions: HashMap::new(),
            groups: Vec::new(),
        };
        for node in observed {
            reprobes.watch(graph, *node, true);
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
                if let Some(position) = reprobes.watch(graph, node, false) {
                    let groups = &mut reprobes.leaves[position].groups;
                    if !groups.contains(&group_index) {
                        groups.push(group_index);
                    }
                }
            }
            reprobes.groups.push(WatchedGroup {
                members,
                last_pass: None,
                cooldown: cooldowns.group,
            });
        }
        reprobes
    }

    /// Starts tracking leaf `node`, and returns its position. Its failures
    /// are watched when it reaches a server of its own; an observed leaf
    /// that does not is tracked for its probes alone, and a fallback that
    /// does not is left out.
    fn watch(
        &mut self,
        graph: &OutboundGraph,
        node: OutboundNodeId,
        observed: bool,
    ) -> Option<usize> {
        if let Some(position) = self.positions.get(&node) {
            return Some(*position);
        }
        let reported = graph
            .node(node)
            .is_some_and(|node| reaches_its_own_server(node.kind()));
        if !reported && !observed {
            return None;
        }
        let slot = self.selection.leaf_index(node)?;
        if reported {
            self.selection.failure_reports().watch(slot, true);
        }
        let position = self.leaves.len();
        self.leaves.push(WatchedLeaf {
            node,
            slot,
            observed,
            last: None,
            failed: false,
            followup: None,
            groups: Vec::new(),
        });
        self.positions.insert(node, position);
        Some(position)
    }

    /// Records that a probe of `node` starts at `now`, which answers the
    /// reports made before it. Its end moves `last` again; a probe that
    /// never ends, as one whose task panicked, still counts from its start.
    fn probe_started(&mut self, node: OutboundNodeId, now: Instant) {
        if let Some(position) = self.positions.get(&node) {
            let leaf = &mut self.leaves[*position];
            self.selection.failure_reports().clear(leaf.slot);
            leaf.last = Some(now);
        }
    }

    /// Records that a probe of `node` of `kind` finished at `now`, and
    /// returns whether its result is to be recorded in the outbound's
    /// health.
    fn probe_finished(
        &mut self,
        node: OutboundNodeId,
        succeeded: bool,
        kind: ProbeKind,
        now: Instant,
    ) -> bool {
        let Some(position) = self.positions.get(&node).copied() else {
            return true;
        };
        let unhealthy = self.selection.health_state_of(node) == OutboundHealthState::Unhealthy;
        let longest_recheck = self.probe_interval.max(self.cooldowns.leaf);
        let leaf = &mut self.leaves[position];
        leaf.last = Some(now);
        leaf.failed = !succeeded;
        if succeeded {
            leaf.followup = None;
            for group in &leaf.groups {
                let group = &mut self.groups[*group];
                if group.members.contains(&node) {
                    group.cooldown = self.cooldowns.group;
                }
            }
            return true;
        }
        let (followup, record) = match (kind, leaf.followup) {
            (ProbeKind::Scheduled, _) => (None, true),
            (ProbeKind::Reprobe, None) if unhealthy => (None, true),
            (ProbeKind::Reprobe, None) => (Some(Followup::Confirm), false),
            (ProbeKind::Reprobe, Some(Followup::Confirm)) => {
                (Some(Followup::Recheck(self.cooldowns.leaf)), true)
            }
            (ProbeKind::Reprobe, Some(Followup::Recheck(after))) => (
                (after < longest_recheck)
                    .then(|| Followup::Recheck(after.saturating_mul(2).min(longest_recheck))),
                true,
            ),
        };
        leaf.followup = followup;
        record
    }

    /// Records that `pass` finished at `now`: the cooldown of each balancer
    /// it probed whole counts from now, doubled when all of its members
    /// failed again.
    fn pass_finished(&mut self, pass: &ReprobePass, now: Instant) {
        let longest = self.probe_interval.max(self.cooldowns.group);
        for group in pass.groups.iter().copied() {
            let all_failed = self.groups[group].members.iter().all(|member| {
                self.positions
                    .get(member)
                    .is_some_and(|position| self.leaves[*position].failed)
            });
            let group = &mut self.groups[group];
            group.last_pass = Some(now);
            group.cooldown = if all_failed {
                group.cooldown.saturating_mul(2).min(longest)
            } else {
                self.cooldowns.group
            };
        }
    }

    /// When, from `now` on, the earliest report or follow-up still waiting
    /// can be handled.
    fn next_due(&self, now: Instant) -> Option<Instant> {
        self.leaves
            .iter()
            .flat_map(|leaf| {
                let report = self
                    .selection
                    .failure_reports()
                    .is_pending(leaf.slot)
                    .then(|| self.due(leaf, now));
                report.into_iter().chain(self.followup_due(leaf))
            })
            .map(|due| due.max(now))
            .min()
    }

    /// Handles every report and follow-up whose time has come, and returns
    /// the outbounds to probe for them.
    fn take_due(&mut self, now: Instant) -> ReprobePass {
        let mut pass = ReprobePass::default();
        for position in 0..self.leaves.len() {
            let leaf = &self.leaves[position];
            let (node, slot) = (leaf.node, leaf.slot);
            if self.followup_due(leaf).is_some_and(|due| due <= now) {
                push_unique(&mut pass.nodes, node);
            }
            if !self.selection.failure_reports().is_pending(slot) || self.due(leaf, now) > now {
                continue;
            }
            if leaf.observed && self.leaf_due(leaf, now) <= now {
                push_unique(&mut pass.nodes, node);
            }
            for group in leaf.groups.iter().copied() {
                if !pass.groups.contains(&group)
                    && self.group_due(group, now).is_some_and(|due| due <= now)
                {
                    pass.groups.push(group);
                    for member in &self.groups[group].members {
                        push_unique(&mut pass.nodes, *member);
                    }
                }
            }
            self.selection.failure_reports().clear(slot);
            if !pass.nodes.contains(&node) {
                self.leaves[position].last = Some(now);
            }
        }
        pass
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

    /// When the follow-up probe a failed re-probe left `leaf` waiting for
    /// is due.
    fn followup_due(&self, leaf: &WatchedLeaf) -> Option<Instant> {
        let after = match leaf.followup? {
            Followup::Confirm => self.cooldowns.leaf,
            Followup::Recheck(after) => after,
        };
        leaf.last.map(|last| last + after)
    }

    /// When the members of balancer `group` may all be probed again, if
    /// none of them is healthy.
    fn group_due(&self, group: usize, now: Instant) -> Option<Instant> {
        let group = &self.groups[group];
        let healthy = group
            .members
            .iter()
            .any(|member| self.selection.health_state_of(*member) == OutboundHealthState::Healthy);
        (!healthy).then(|| group.last_pass.map_or(now, |last| last + group.cooldown))
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
mod call_site_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OutboundHealthFailure;
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use xray_config::CoreConfig;

    /// The probe interval of the watchers below: the longest a follow-up or
    /// a balancer's cooldown waits.
    const PROBE_INTERVAL: Duration = Duration::from_secs(60);

    fn secs(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

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

    pub(super) fn parse(profile: &Value) -> CoreConfig {
        xray_config::parse_xray_json(&profile.to_string())
            .expect("synthetic profile parses")
            .config
    }

    pub(super) fn socks(tag: &str, address: &str, port: u16) -> Value {
        json!({"tag": tag, "protocol": "socks",
            "settings": {"address": address, "port": port}})
    }

    /// `proxy-a` and `proxy-b` observed under a `leastPing` balancer falling
    /// back to `backup`; `direct`, the default; and `other`, which nothing
    /// watches.
    fn profile() -> Value {
        json!({
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                socks("proxy-a", "192.0.2.1", 1080),
                socks("proxy-b", "192.0.2.2", 1080),
                socks("backup", "192.0.2.3", 1080),
                socks("other", "192.0.2.4", 1080),
            ],
            "routing": {"balancers": [{"tag": "auto", "selector": ["proxy-"],
                "strategy": {"type": "leastPing"}, "fallbackTag": "backup"}]},
        })
    }

    struct Fixture {
        router: Arc<OutboundRouter>,
        proxy_a: OutboundNodeId,
        proxy_b: OutboundNodeId,
        backup: OutboundNodeId,
        other: OutboundNodeId,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with(&profile())
        }

        fn with(profile: &Value) -> Self {
            let router = Arc::new(OutboundRouter::new(Arc::new(parse(profile))));
            let node = |tag| router.graph().node_for_tag(tag);
            Self {
                proxy_a: node("proxy-a").unwrap(),
                proxy_b: node("proxy-b").unwrap(),
                backup: node("backup").unwrap_or(node("direct").unwrap()),
                other: node("other").unwrap_or(node("direct").unwrap()),
                router: Arc::clone(&router),
            }
        }

        fn observed(&self) -> Vec<OutboundNodeId> {
            self.router
                .graph()
                .leaf_nodes_matching_prefixes(&["proxy-".to_owned()])
        }

        /// A watcher whose first round finished at `start` and found both
        /// proxies healthy.
        fn reprobes(&self, start: Instant) -> Reprobes {
            let mut reprobes = Reprobes::new(
                self.router.selection_handle(),
                self.router.graph(),
                &self.observed(),
                PROBE_INTERVAL,
                REPROBE_COOLDOWNS,
            );
            for node in [self.proxy_a, self.proxy_b] {
                reprobes.probe_started(node, start);
                self.finish(&mut reprobes, node, true, ProbeKind::Scheduled, start);
            }
            reprobes
        }

        /// Ends a probe of `node` as the observatory does, recording its
        /// result unless the watcher holds it back, and returns whether it
        /// was recorded.
        fn finish(
            &self,
            reprobes: &mut Reprobes,
            node: OutboundNodeId,
            succeeded: bool,
            kind: ProbeKind,
            at: Instant,
        ) -> bool {
            let recorded = reprobes.probe_finished(node, succeeded, kind, at);
            if recorded {
                if succeeded {
                    self.healthy(node);
                } else {
                    self.unhealthy(node);
                }
            }
            recorded
        }

        /// Runs `pass` from `at`, every probe failing, to `finished`.
        fn fail_pass(&self, reprobes: &mut Reprobes, pass: &ReprobePass, finished: Instant) {
            for node in &pass.nodes {
                reprobes.probe_started(*node, finished);
            }
            for node in &pass.nodes {
                self.finish(reprobes, *node, false, ProbeKind::Reprobe, finished);
            }
            reprobes.pass_finished(pass, finished);
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

        fn state(&self, node: OutboundNodeId) -> OutboundHealthState {
            self.router.selection().health_state_of(node)
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
            let now = start + secs(elapsed);
            assert_eq!(reprobes.next_due(now), None);
            assert!(reprobes.take_due(now).nodes.is_empty());
        }
        // A leaf nothing watches is no report at all.
        fixture.report(fixture.other);
        assert!(!fixture.pending(fixture.other));
        assert_eq!(reprobes.next_due(start + secs(20)), None);
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

    /// Freedom reaches the flow's target itself: a target that refuses or
    /// times out says nothing about a server, observed or a fallback.
    #[test]
    fn outbounds_without_a_server_of_their_own_are_not_watched() {
        let fixture = Fixture::with(&json!({
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                socks("proxy-a", "192.0.2.1", 1080),
                {"tag": "proxy-b", "protocol": "freedom"},
            ],
            // No `fallbackTag`: the balancer falls back to `direct`.
            "routing": {"balancers": [{"tag": "auto", "selector": ["proxy-"],
                "strategy": {"type": "leastPing"}}]},
        }));
        let direct = fixture.backup;
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        fixture.unhealthy(fixture.proxy_a);
        fixture.unhealthy(fixture.proxy_b);

        for node in [direct, fixture.proxy_b] {
            fixture.report(node);
            assert!(!fixture.pending(node));
        }
        assert_eq!(reprobes.next_due(start + secs(60)), None);
        fixture.report(fixture.proxy_a);
        assert!(fixture.pending(fixture.proxy_a));
        // The observed freedom member is still probed with its balancer.
        let pass = reprobes.take_due(start + secs(60));
        assert_eq!(pass.nodes, vec![fixture.proxy_a, fixture.proxy_b]);
        assert_eq!(pass.groups, vec![0]);
    }

    #[test]
    fn reported_failure_is_probed_at_once_after_the_cooldown() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        let now = start + secs(60);

        fixture.report(fixture.proxy_a);
        fixture.report(fixture.proxy_a);
        assert_eq!(reprobes.next_due(now), Some(now));
        let pass = reprobes.take_due(now);
        assert_eq!(pass.nodes, vec![fixture.proxy_a]);
        assert!(pass.groups.is_empty());
        reprobes.probe_started(fixture.proxy_a, now);
        assert!(!fixture.pending(fixture.proxy_a));
        let finished = now + secs(1);
        assert!(fixture.finish(
            &mut reprobes,
            fixture.proxy_a,
            true,
            ProbeKind::Reprobe,
            finished
        ));
        assert_eq!(reprobes.next_due(finished), None);
    }

    #[test]
    fn the_cooldown_counts_from_when_the_last_probe_finished() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);

        // Three seconds after the round's probe of `proxy-a` finished,
        // traffic through it fails: its next probe waits for the ten
        // seconds.
        let early = start + secs(3);
        fixture.report(fixture.proxy_a);
        assert_eq!(
            reprobes.next_due(early),
            Some(start + FAILURE_REPROBE_COOLDOWN)
        );
        assert!(reprobes.take_due(early).nodes.is_empty());
        assert!(fixture.pending(fixture.proxy_a));

        let due = start + FAILURE_REPROBE_COOLDOWN;
        assert_eq!(reprobes.take_due(due).nodes, vec![fixture.proxy_a]);
        reprobes.probe_started(fixture.proxy_a, due);

        // A report made while that probe runs waits for ten seconds from
        // when it finished, however long it took.
        fixture.report(fixture.proxy_a);
        let finished = due + secs(5);
        fixture.finish(
            &mut reprobes,
            fixture.proxy_a,
            true,
            ProbeKind::Reprobe,
            finished,
        );
        assert_eq!(
            reprobes.next_due(finished),
            Some(finished + FAILURE_REPROBE_COOLDOWN)
        );
        assert!(reprobes.take_due(finished + secs(9)).nodes.is_empty());
    }

    /// The re-probe runs while traffic fails, which is also while the local
    /// network is away for a moment: alone it marks nothing unhealthy.
    #[test]
    fn a_failed_reprobe_counts_only_when_a_second_one_confirms_it() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        let now = start + secs(60);

        fixture.report(fixture.proxy_a);
        assert_eq!(reprobes.take_due(now).nodes, vec![fixture.proxy_a]);
        reprobes.probe_started(fixture.proxy_a, now);
        let failed = now + OBSERVATORY_PROBE_TIMEOUT;
        assert!(!fixture.finish(
            &mut reprobes,
            fixture.proxy_a,
            false,
            ProbeKind::Reprobe,
            failed
        ));
        assert_eq!(fixture.state(fixture.proxy_a), OutboundHealthState::Healthy);

        // The confirming probe runs a cooldown later; by then the network
        // is back and `proxy-a` stays healthy.
        let confirm = failed + FAILURE_REPROBE_COOLDOWN;
        assert_eq!(reprobes.next_due(failed), Some(confirm));
        assert!(reprobes.take_due(confirm - secs(1)).nodes.is_empty());
        assert_eq!(reprobes.take_due(confirm).nodes, vec![fixture.proxy_a]);
        reprobes.probe_started(fixture.proxy_a, confirm);
        assert!(fixture.finish(
            &mut reprobes,
            fixture.proxy_a,
            true,
            ProbeKind::Reprobe,
            confirm + secs(1)
        ));
        assert_eq!(fixture.state(fixture.proxy_a), OutboundHealthState::Healthy);
        assert_eq!(reprobes.next_due(confirm + secs(1)), None);
    }

    /// An outbound re-probes marked unhealthy gets no flows that could
    /// report it again; it is probed again at doubling intervals up to the
    /// probe interval, in case what failed was the local network.
    #[test]
    fn a_confirmed_failure_is_probed_again_at_doubling_intervals() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        let now = start + secs(60);

        fixture.report(fixture.proxy_a);
        let pass = reprobes.take_due(now);
        fixture.fail_pass(&mut reprobes, &pass, now);
        assert_eq!(fixture.state(fixture.proxy_a), OutboundHealthState::Healthy);
        let mut finished = now + FAILURE_REPROBE_COOLDOWN;
        let pass = reprobes.take_due(finished);
        assert_eq!(pass.nodes, vec![fixture.proxy_a]);
        fixture.fail_pass(&mut reprobes, &pass, finished);
        assert_eq!(
            fixture.state(fixture.proxy_a),
            OutboundHealthState::Unhealthy
        );

        for after in [10, 20, 40, 60] {
            let due = finished + secs(after);
            assert_eq!(reprobes.next_due(finished), Some(due));
            assert!(reprobes.take_due(due - secs(1)).nodes.is_empty());
            let pass = reprobes.take_due(due);
            assert_eq!(pass.nodes, vec![fixture.proxy_a]);
            fixture.fail_pass(&mut reprobes, &pass, due);
            finished = due;
        }
        // Then the scheduled round takes over.
        assert_eq!(reprobes.next_due(finished), None);
    }

    #[test]
    fn follow_ups_end_when_the_outbound_answers() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        let now = start + secs(60);

        fixture.report(fixture.proxy_a);
        let pass = reprobes.take_due(now);
        fixture.fail_pass(&mut reprobes, &pass, now);
        let confirm = now + FAILURE_REPROBE_COOLDOWN;
        let pass = reprobes.take_due(confirm);
        fixture.fail_pass(&mut reprobes, &pass, confirm);
        assert_eq!(
            fixture.state(fixture.proxy_a),
            OutboundHealthState::Unhealthy
        );

        let recheck = confirm + FAILURE_REPROBE_COOLDOWN;
        assert_eq!(reprobes.take_due(recheck).nodes, vec![fixture.proxy_a]);
        reprobes.probe_started(fixture.proxy_a, recheck);
        assert!(fixture.finish(
            &mut reprobes,
            fixture.proxy_a,
            true,
            ProbeKind::Reprobe,
            recheck
        ));
        assert_eq!(fixture.state(fixture.proxy_a), OutboundHealthState::Healthy);
        assert_eq!(reprobes.next_due(recheck), None);
    }

    #[test]
    fn scheduled_probes_are_recorded_as_they_are_and_end_follow_ups() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        let now = start + secs(60);

        fixture.report(fixture.proxy_a);
        let pass = reprobes.take_due(now);
        fixture.fail_pass(&mut reprobes, &pass, now);
        assert!(reprobes.next_due(now).is_some());

        // The scheduled round fails `proxy-a` before the confirming probe.
        let round = now + secs(2);
        reprobes.probe_started(fixture.proxy_a, round);
        assert!(fixture.finish(
            &mut reprobes,
            fixture.proxy_a,
            false,
            ProbeKind::Scheduled,
            round
        ));
        assert_eq!(
            fixture.state(fixture.proxy_a),
            OutboundHealthState::Unhealthy
        );
        assert_eq!(reprobes.next_due(round), None);
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
        let first = start + secs(1);
        fixture.report(fixture.proxy_a);
        assert_eq!(reprobes.next_due(first), Some(first));
        let pass = reprobes.take_due(first);
        assert_eq!(pass.nodes, vec![fixture.proxy_a, fixture.proxy_b]);
        assert_eq!(pass.groups, vec![0]);
        let finished = first + secs(1);
        fixture.fail_pass(&mut reprobes, &pass, finished);

        // Within the group cooldown only the reported leaf is, once its own
        // cooldown passed.
        fixture.report(fixture.proxy_a);
        let leaf_due = finished + FAILURE_REPROBE_COOLDOWN;
        assert_eq!(reprobes.next_due(finished), Some(leaf_due));
        let pass = reprobes.take_due(leaf_due);
        assert_eq!(pass.nodes, vec![fixture.proxy_a]);
        assert!(pass.groups.is_empty());
        fixture.fail_pass(&mut reprobes, &pass, leaf_due);

        // The fallback failing too has the whole group probed again once
        // the group cooldown, doubled as every probe of the last pass
        // failed, has passed since that pass finished.
        fixture.report(fixture.backup);
        let group_due = finished + GROUP_REPROBE_COOLDOWN * 2;
        assert_eq!(reprobes.next_due(leaf_due), Some(group_due));
        assert!(reprobes.take_due(leaf_due).nodes.is_empty());
        assert_eq!(
            reprobes.take_due(group_due).nodes,
            vec![fixture.proxy_a, fixture.proxy_b]
        );
    }

    /// A pass over many members on a half-dead network can outlast the
    /// cooldown: the next one waits for the cooldown from when it finished,
    /// twice as long after each pass in which every probe failed.
    #[test]
    fn group_cooldown_counts_from_the_end_of_a_pass_and_backs_off() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        fixture.unhealthy(fixture.proxy_a);
        fixture.unhealthy(fixture.proxy_b);

        let mut taken = start + secs(1);
        fixture.report(fixture.backup);
        let mut pass = reprobes.take_due(taken);
        for cooldown in [30, 60, 60] {
            assert_eq!(pass.groups, vec![0]);
            // Longer than the cooldown itself.
            let finished = taken + secs(20);
            fixture.fail_pass(&mut reprobes, &pass, finished);
            fixture.report(fixture.backup);
            let due = finished + secs(cooldown);
            assert_eq!(reprobes.next_due(finished), Some(due));
            assert!(reprobes.take_due(due - secs(1)).groups.is_empty());
            taken = due;
            pass = reprobes.take_due(taken);
        }

        // One member answering resets the cooldown.
        assert_eq!(pass.groups, vec![0]);
        for node in &pass.nodes {
            reprobes.probe_started(*node, taken);
        }
        let finished = taken + secs(1);
        fixture.finish(
            &mut reprobes,
            fixture.proxy_a,
            true,
            ProbeKind::Reprobe,
            finished,
        );
        fixture.finish(
            &mut reprobes,
            fixture.proxy_b,
            false,
            ProbeKind::Reprobe,
            finished,
        );
        reprobes.pass_finished(&pass, finished);
        fixture.unhealthy(fixture.proxy_a);
        fixture.report(fixture.backup);
        assert_eq!(
            reprobes.next_due(finished),
            Some(finished + GROUP_REPROBE_COOLDOWN)
        );
    }

    #[test]
    fn fallback_failure_is_ignored_while_a_member_is_healthy() {
        let fixture = Fixture::new();
        let start = Instant::now();
        let mut reprobes = fixture.reprobes(start);
        fixture.unhealthy(fixture.proxy_a);

        let now = start + secs(1);
        fixture.report(fixture.backup);
        assert!(reprobes.take_due(now).nodes.is_empty());
        assert!(!fixture.pending(fixture.backup));
        // Handled reports of the fallback are rate limited like any other.
        fixture.report(fixture.backup);
        assert_eq!(reprobes.next_due(now), Some(now + FAILURE_REPROBE_COOLDOWN));
        assert_eq!(fixture.state(fixture.proxy_b), OutboundHealthState::Healthy);
    }

    #[test]
    fn dial_failures_are_told_from_other_errors() {
        use xray_proxy::outbound::{HttpClientError, SocksClientError};
        use xray_transport::hysteria::HysteriaError;
        use xray_transport::masque::MasqueError;
        use xray_transport::reality::RealityError;

        let io = |kind| CoreError::Io(io::Error::from(kind));
        let tcp = |kind| CoreError::Transport(TransportError::Tcp(io::Error::from(kind)));
        let tls = |kind| CoreError::Transport(TransportError::Tls(io::Error::from(kind)));

        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::TimedOut,
        ] {
            assert!(is_dial_failure(&tcp(kind)), "{kind:?}");
            assert!(is_dial_failure(&tls(kind)), "{kind:?}");
            assert!(is_dial_failure(&io(kind)), "{kind:?}");
            assert!(is_dial_failure(&CoreError::Socks(SocksClientError::Io(
                kind
            ))));
            assert!(is_dial_failure(&CoreError::Http(HttpClientError::Io(kind))));
        }
        assert!(is_dial_failure(&tls(io::ErrorKind::UnexpectedEof)));
        assert!(is_dial_failure(&tls(io::ErrorKind::InvalidData)));
        assert!(is_dial_failure(&CoreError::Transport(
            TransportError::Reality(RealityError::RealCertificate)
        )));
        assert!(is_dial_failure(&CoreError::Hysteria(
            HysteriaError::Timeout
        )));
        assert!(is_dial_failure(&CoreError::Hysteria(
            HysteriaError::Authentication
        )));
        assert!(is_dial_failure(&CoreError::Masque(MasqueError::Timeout)));

        // What the local network stack says when it is down or changing.
        for kind in [
            io::ErrorKind::NetworkDown,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::AddrNotAvailable,
        ] {
            assert!(!is_dial_failure(&tcp(kind)), "{kind:?}");
            assert!(!is_dial_failure(&tls(kind)), "{kind:?}");
            assert!(!is_dial_failure(&io(kind)), "{kind:?}");
        }
        // A remote that closes after the handshake.
        assert!(!is_dial_failure(&io(io::ErrorKind::UnexpectedEof)));
        assert!(!is_dial_failure(&io(io::ErrorKind::BrokenPipe)));
        // Errors that carry only a message, whatever went wrong.
        for error in [
            TransportError::Xhttp("XHTTP dial failed: tcp connect failed".to_owned()),
            TransportError::Grpc("shared gRPC connection attempt failed".to_owned()),
            TransportError::Xdrive("dial failed".to_owned()),
            TransportError::WebSocketProtocol("unexpected close".to_owned()),
            TransportError::HttpUpgradeRejected("502".to_owned()),
            TransportError::ChainedOutbound("hop failed".to_owned()),
        ] {
            assert!(!is_dial_failure(&CoreError::Transport(error)));
        }
        assert!(!is_dial_failure(&CoreError::Hysteria(
            HysteriaError::Connect
        )));
        assert!(!is_dial_failure(&CoreError::Masque(MasqueError::Dial(
            "network is unreachable".to_owned()
        ))));
        assert!(!is_dial_failure(&CoreError::Transport(
            TransportError::Reality(RealityError::AllZeroSharedSecret)
        )));
        // The flow's destination, not the server.
        assert!(!is_dial_failure(&CoreError::Transport(
            TransportError::DnsNameError("example.test".to_owned(), 443)
        )));
        assert!(!is_dial_failure(&CoreError::Socks(
            SocksClientError::RequestRejected(5)
        )));
        assert!(!is_dial_failure(&CoreError::Http(
            HttpClientError::Rejected(502)
        )));
        assert!(!is_dial_failure(&CoreError::VisionUdp443Rejected));
    }

    /// A SOCKS5 server for a `proxy-*` outbound. It grants every CONNECT,
    /// counting them, and answers the request that follows with `204` after
    /// `delay`, as the observatory's probe expects. Aborting the returned
    /// task closes its port.
    pub(super) async fn socks_server(
        delay: Duration,
    ) -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind SOCKS server");
        let port = listener.local_addr().expect("SOCKS server address").port();
        let connects = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&connects);
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let counted = Arc::clone(&counted);
                tokio::spawn(async move {
                    let _ = serve_socks(&mut stream, delay, &counted).await;
                });
            }
        });
        (port, connects, server)
    }

    async fn serve_socks(
        stream: &mut TcpStream,
        delay: Duration,
        connects: &AtomicUsize,
    ) -> io::Result<()> {
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await?;
        let mut methods = vec![0; usize::from(greeting[1])];
        stream.read_exact(&mut methods).await?;
        stream.write_all(&[5, 0]).await?;
        let mut request = [0; 4];
        stream.read_exact(&mut request).await?;
        let address = match request[3] {
            1 => 4,
            4 => 16,
            3 => usize::from(stream.read_u8().await?),
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        let mut rest = vec![0; address + 2];
        stream.read_exact(&mut rest).await?;
        connects.fetch_add(1, Ordering::AcqRel);
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut head = [0; 1024];
        let _ = stream.read(&mut head).await?;
        tokio::time::sleep(delay).await;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
    }

    /// A SOCKS5 CONNECT through `proxy` to a documentation address; returns
    /// the reply code.
    pub(super) async fn socks_connect(proxy: std::net::SocketAddr) -> u8 {
        let mut client = TcpStream::connect(proxy)
            .await
            .expect("reach SOCKS inbound");
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 192, 0, 2, 10, 0, 80])
            .await
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        reply[1]
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

    /// End to end: a SOCKS flow routed by a `leastPing` balancer fails to
    /// open through its dead server, the SOCKS inbound reports it, the
    /// observatory confirms it with two probes and the next flow takes the
    /// other server, all long before the ten-minute probe interval.
    #[tokio::test]
    async fn a_dead_server_is_left_after_a_failed_flow_and_two_probes() {
        let (port_a, _, server_a) = socks_server(Duration::ZERO).await;
        // Slower, so that `leastPing` prefers `proxy-a`.
        let (port_b, connects_b, server_b) = socks_server(Duration::from_millis(200)).await;
        let config = parse(&json!({
            "inbounds": [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
                "port": 0, "settings": {"auth": "noauth"}}],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                socks("proxy-a", "127.0.0.1", port_a),
                socks("proxy-b", "127.0.0.1", port_b),
            ],
            "routing": {
                "balancers": [{"tag": "auto", "selector": ["proxy-"],
                    "strategy": {"type": "leastPing"}, "fallbackTag": "direct"}],
                "rules": [{"type": "field", "inboundTag": ["socks-in"], "balancerTag": "auto"}],
            },
        }));
        let mut core = crate::Core::new(config).expect("build core");
        core.start().await.expect("start core");
        let router = Arc::clone(&core.outbound_router);
        let observatory = ObservatoryConfig {
            subject_selectors: vec!["proxy-".to_owned()],
            probe_url: "http://192.0.2.1/generate_204".to_owned(),
            probe_interval: Duration::from_secs(600),
            enable_concurrency: true,
        };
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
        // The first round has just probed both: cooldowns this short let the
        // report be served at once.
        .with_cooldowns(ReprobeCooldowns {
            leaf: Duration::from_millis(50),
            group: GROUP_REPROBE_COOLDOWN,
        });
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let observer = tokio::spawn(run_observatory(runtime, shutdown_rx));
        let selection = router.selection();
        wait_for_state(selection, proxy_a, OutboundHealthState::Healthy).await;
        wait_for_state(selection, proxy_b, OutboundHealthState::Healthy).await;

        // `proxy-a`'s server goes away. Nothing would notice it before the
        // ten-minute interval; the flow that fails through it is reported.
        server_a.abort();
        let _ = server_a.await;
        let inbound = core.inbound_addr(Some("socks-in")).unwrap();
        assert_ne!(socks_connect(inbound).await, 0);
        wait_for_state(selection, proxy_a, OutboundHealthState::Unhealthy).await;
        assert_eq!(
            selection.health_state_of(proxy_b),
            OutboundHealthState::Healthy
        );

        let before = connects_b.load(Ordering::Acquire);
        assert_eq!(socks_connect(inbound).await, 0);
        assert_eq!(connects_b.load(Ordering::Acquire), before + 1);

        shutdown_tx.send(true).expect("observer listens");
        observer.await.expect("observer stops");
        selection.report_dial_failure(proxy_b);
        let slot = selection.leaf_index(proxy_b).unwrap();
        assert!(!selection.failure_reports().is_pending(slot));
        core.stop().await.expect("stop core");
        server_b.abort();
    }
}
