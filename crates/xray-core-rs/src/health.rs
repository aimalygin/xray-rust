use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tokio::sync::futures::Notified;
use tokio::sync::{watch, Notify};
use tokio::task::JoinSet;
use tokio::time::Instant;
use xray_config::{BurstPingConfig, ObservatoryConfig, OBSERVATORY_PROBE_TIMEOUT};
use xray_transport::{DnsResolver, TransportDialer, TransportError};

use crate::outbound::{
    OutboundGraph, OutboundHealthFailure, OutboundHealthState, OutboundNodeId, OutboundNodeKind,
    OutboundRouter, OutboundSelectionOverlay,
};
use crate::startup_probe::{
    run_health_probe, run_outbound_url_probe, ProbePath, ProbeRequest, ProbeStatusPolicy,
    StartupProbeError, StartupProbeOptions,
};
use crate::CoreError;

const MAX_CONCURRENT_HEALTH_PROBES: usize = 4;
/// After the device changes network a burst observatory waits this long for
/// the new one to carry traffic before it probes its subjects again.
const BURST_NETWORK_SETTLE: Duration = Duration::from_secs(1);
/// The probes that follow a network change are spread over this much more,
/// so that they do not all leave in one radio burst.
const BURST_NETWORK_REPROBE_JITTER: Duration = Duration::from_secs(2);
/// The first wait before a burst observatory tries the network again after
/// its connectivity check failed. It doubles up to `pingConfig.interval`.
const BURST_CONNECTIVITY_BACKOFF_MIN: Duration = Duration::from_secs(5);

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

/// Xray's burst observatory over the probe and the health overlay the
/// classic one uses.
pub(crate) struct BurstObservatoryRuntime {
    ping: Arc<BurstPingConfig>,
    nodes: Vec<OutboundNodeId>,
    selection: Arc<OutboundSelectionOverlay>,
    probes: BurstProbes,
    network_changes: watch::Receiver<u64>,
}

/// What one ping needs, shared by every ping task.
#[derive(Clone)]
struct BurstProbes {
    outbound_router: Arc<OutboundRouter>,
    destination_resolver: Arc<dyn DnsResolver>,
    bootstrap_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
}

impl BurstObservatoryRuntime {
    pub(crate) fn new(
        ping: BurstPingConfig,
        nodes: Vec<OutboundNodeId>,
        outbound_router: Arc<OutboundRouter>,
        selection: Arc<OutboundSelectionOverlay>,
        destination_resolver: Arc<dyn DnsResolver>,
        bootstrap_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
    ) -> Self {
        Self {
            ping: Arc::new(ping),
            nodes,
            selection,
            network_changes: transport_dialer.network_changes().observe(),
            probes: BurstProbes {
                outbound_router,
                destination_resolver,
                bootstrap_resolver,
                transport_dialer,
            },
        }
    }
}

/// The extra ping of every subject that opens a round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BurstKick {
    /// At once: Xray-core's one-time check when the scheduler starts.
    Start,
    /// Once the network the device moved to has settled.
    NetworkChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScheduledPing {
    /// From the start of the round.
    offset: Duration,
    /// Index into the runtime's subjects.
    subject: usize,
}

/// One period of pings in firing order: `sampling` per subject, each at a
/// uniformly random point of the period as in `healthping.go` `doCheck`,
/// after the kick's one per subject.
fn burst_schedule(
    subjects: usize,
    sampling: u32,
    period: Duration,
    kick: Option<BurstKick>,
    rng: &mut impl Rng,
) -> Vec<ScheduledPing> {
    let period_nanos = u64::try_from(period.as_nanos()).unwrap_or(u64::MAX).max(1);
    let per_subject = sampling as usize + usize::from(kick.is_some());
    let mut schedule = Vec::with_capacity(subjects.saturating_mul(per_subject));
    for subject in 0..subjects {
        match kick {
            Some(BurstKick::Start) => schedule.push(ScheduledPing {
                offset: Duration::ZERO,
                subject,
            }),
            Some(BurstKick::NetworkChange) => {
                let jitter = rng.gen_range(0..=BURST_NETWORK_REPROBE_JITTER.as_millis() as u64);
                schedule.push(ScheduledPing {
                    offset: BURST_NETWORK_SETTLE + Duration::from_millis(jitter),
                    subject,
                });
            }
            None => {}
        }
        for _ in 0..sampling {
            schedule.push(ScheduledPing {
                offset: Duration::from_nanos(rng.gen_range(0..period_nanos)),
                subject,
            });
        }
    }
    schedule.sort_by_key(|ping| ping.offset);
    schedule
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PingRole {
    Scheduled,
    /// The one ping let through while the network is taken to be down.
    Canary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BurstSample {
    Rtt(Duration),
    Failed(OutboundHealthFailure),
    /// The ping failed and so did the connectivity check: not a sample.
    NetworkDown,
}

/// Holds scheduled pings back while the connectivity check says the device
/// has no network, letting one through after each backoff.
#[derive(Debug, Default)]
struct ConnectivityGate {
    pause: Option<ConnectivityPause>,
}

#[derive(Debug)]
struct ConnectivityPause {
    backoff: Duration,
    next_canary: tokio::time::Instant,
    canary_in_flight: bool,
}

impl ConnectivityGate {
    /// Whether a ping due at `now` is sent, and as what.
    fn admit(&mut self, now: tokio::time::Instant) -> Option<PingRole> {
        let Some(pause) = &mut self.pause else {
            return Some(PingRole::Scheduled);
        };
        if pause.canary_in_flight || now < pause.next_canary {
            return None;
        }
        pause.canary_in_flight = true;
        Some(PingRole::Canary)
    }

    /// A ping and the connectivity check after it both failed. `longest` is
    /// the longest wait between two canaries.
    fn network_down(&mut self, role: PingRole, now: tokio::time::Instant, longest: Duration) {
        match (&mut self.pause, role) {
            (None, _) => {
                let backoff = BURST_CONNECTIVITY_BACKOFF_MIN.min(longest);
                self.pause = Some(ConnectivityPause {
                    backoff,
                    next_canary: now + backoff,
                    canary_in_flight: false,
                });
            }
            (Some(pause), PingRole::Canary) => {
                pause.backoff = pause.backoff.saturating_mul(2).min(longest);
                pause.next_canary = now + pause.backoff;
                pause.canary_in_flight = false;
            }
            // A ping sent before the pause began says nothing new.
            (Some(_), PingRole::Scheduled) => {}
        }
    }

    /// A ping produced a sample, so the network carries traffic.
    fn network_up(&mut self) {
        self.pause = None;
    }

    /// The canary's task ended without a result.
    fn canary_lost(&mut self) {
        if let Some(pause) = &mut self.pause {
            pause.canary_in_flight = false;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BurstRoundEnd {
    Shutdown,
    Elapsed,
    NetworkChanged,
}

pub(crate) async fn run_burst_observatory(
    mut runtime: BurstObservatoryRuntime,
    mut shutdown: watch::Receiver<bool>,
) {
    if runtime.nodes.is_empty() {
        return;
    }

    let mut gate = ConnectivityGate::default();
    let mut kick = Some(BurstKick::Start);
    loop {
        match run_burst_round(&mut runtime, kick.take(), &mut gate, &mut shutdown).await {
            BurstRoundEnd::Shutdown => return,
            BurstRoundEnd::Elapsed => {}
            BurstRoundEnd::NetworkChanged => {
                runtime.selection.start_health_epoch();
                gate = ConnectivityGate::default();
                kick = Some(BurstKick::NetworkChange);
            }
        }
    }
}

/// Runs the pings of one sampling period. Pings still pending or in flight
/// when it ends are dropped, as Xray-core cancels a round the next overtakes.
async fn run_burst_round(
    runtime: &mut BurstObservatoryRuntime,
    kick: Option<BurstKick>,
    gate: &mut ConnectivityGate,
    shutdown: &mut watch::Receiver<bool>,
) -> BurstRoundEnd {
    let period = runtime.ping.sampling_period();
    let schedule = burst_schedule(
        runtime.nodes.len(),
        runtime.ping.sampling,
        period,
        kick,
        &mut rand::thread_rng(),
    );
    let started = tokio::time::Instant::now();
    let deadline = started + period;
    let mut tasks = JoinSet::new();
    let mut next = 0;
    // The previous round's canary, if any, was dropped with its tasks.
    gate.canary_lost();
    runtime
        .selection
        .expire_health_samples(std::time::Instant::now());

    loop {
        let due = schedule.get(next).map(|ping| started + ping.offset);
        tokio::select! {
            biased;
            () = wait_for_shutdown(shutdown) => return BurstRoundEnd::Shutdown,
            () = network_changed(&mut runtime.network_changes) => {
                return BurstRoundEnd::NetworkChanged;
            }
            () = tokio::time::sleep_until(deadline) => return BurstRoundEnd::Elapsed,
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                let Ok((node, role, sample)) = joined else {
                    gate.canary_lost();
                    continue;
                };
                let outcome = match sample {
                    BurstSample::Rtt(delay) => Ok(delay),
                    BurstSample::Failed(failure) => Err(failure),
                    BurstSample::NetworkDown => {
                        gate.network_down(
                            role,
                            tokio::time::Instant::now(),
                            runtime.ping.interval,
                        );
                        // Nothing is recorded while the network is down, so
                        // only time can change an outbound's statistics.
                        runtime.selection.expire_health_samples(std::time::Instant::now());
                        continue;
                    }
                };
                gate.network_up();
                runtime
                    .selection
                    .record_health_probe(node, outcome, unix_ms_now(), std::time::Instant::now());
            }
            () = sleep_until_due(due), if due.is_some() && tasks.len() < MAX_CONCURRENT_HEALTH_PROBES => {
                let subject = schedule[next].subject;
                next += 1;
                let Some(role) = gate.admit(tokio::time::Instant::now()) else {
                    continue;
                };
                let node = runtime.nodes[subject];
                let probes = runtime.probes.clone();
                let ping = Arc::clone(&runtime.ping);
                tasks.spawn(async move { (node, role, burst_ping(&probes, &ping, node).await) });
            }
        }
    }
}

/// One ping of `node`, as `healthping.go` `doCheck` judges it: a failure
/// counts against the outbound unless the connectivity URL, requested over
/// the device's own network, fails too.
async fn burst_ping(
    probes: &BurstProbes,
    ping: &BurstPingConfig,
    node: OutboundNodeId,
) -> BurstSample {
    let outbound_tag = probes
        .outbound_router
        .graph()
        .node(node)
        .and_then(|node| node.tag())
        .map(ToOwned::to_owned);
    let error = match burst_request(
        probes,
        ping,
        &ping.destination,
        outbound_tag,
        ProbePath::Outbound,
    )
    .await
    {
        Ok(delay) => return BurstSample::Rtt(delay),
        Err(error) => error,
    };
    if let Some(connectivity) = &ping.connectivity {
        if burst_request(probes, ping, connectivity, None, ProbePath::Direct)
            .await
            .is_err()
        {
            return BurstSample::NetworkDown;
        }
    }
    BurstSample::Failed(error.health_failure())
}

async fn burst_request(
    probes: &BurstProbes,
    ping: &BurstPingConfig,
    url: &str,
    outbound_tag: Option<String>,
    path: ProbePath,
) -> Result<Duration, StartupProbeError> {
    run_health_probe(
        &probes.outbound_router,
        StartupProbeOptions {
            url: url.to_owned(),
            timeout: ping.timeout,
            outbound_tag,
        },
        ProbeRequest {
            method: &ping.http_method,
            path,
        },
        probes.destination_resolver.as_ref(),
        probes.bootstrap_resolver.as_ref(),
        &probes.transport_dialer,
        ProbeStatusPolicy::AnyResponse,
    )
    .await
}

async fn sleep_until_due(due: Option<tokio::time::Instant>) {
    match due {
        Some(due) => tokio::time::sleep_until(due).await,
        None => std::future::pending().await,
    }
}

/// Resolves on the next network change, and never once nothing can announce one.
async fn network_changed(changes: &mut watch::Receiver<u64>) {
    if changes.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[allow(clippy::too_many_arguments)]
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
    /// The round of the probe interval. Its result is recorded as it is,
    /// and is a sample of the `leastLoad` window.
    Scheduled,
    /// For a failure of real traffic, or a follow-up of such a probe. Its
    /// result, when recorded, moves the health state but adds no sample.
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
                            record_result(&runtime.selection, node, result, kind);
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

/// Records a probe's result in the outbound's health. Only the scheduled
/// round adds samples to the `leastLoad` window, so that it holds the last
/// evenly spaced probes and not the bursts of re-probes failing traffic
/// brings; a re-probe moves the state, the last delay and the failure count.
fn record_result(
    selection: &OutboundSelectionOverlay,
    node: OutboundNodeId,
    result: Result<Duration, StartupProbeError>,
    kind: ProbeKind,
) {
    let now_unix_ms = unix_ms_now();
    match (result, kind) {
        (Ok(delay), ProbeKind::Scheduled) => {
            selection.record_health_success(node, delay, now_unix_ms);
        }
        (Ok(delay), ProbeKind::Reprobe) => {
            selection.record_reprobe_success(node, delay, now_unix_ms);
        }
        (Err(error), ProbeKind::Scheduled) => {
            selection.record_health_failure(node, error.health_failure(), now_unix_ms);
        }
        (Err(error), ProbeKind::Reprobe) => {
            selection.record_reprobe_failure(node, error.health_failure(), now_unix_ms);
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

    /// `healthping.go` `doCheck`: `sampling` pings per subject, each at a
    /// random point of `interval * sampling`.
    #[test]
    fn burst_schedule_spreads_sampling_pings_per_subject_over_the_period() {
        let period = Duration::from_secs(600);
        let schedule = burst_schedule(3, 10, period, None, &mut rand::thread_rng());

        assert_eq!(schedule.len(), 30);
        for subject in 0..3 {
            let pings = schedule.iter().filter(|ping| ping.subject == subject);
            assert_eq!(pings.count(), 10, "subject {subject}");
        }
        assert!(schedule.iter().all(|ping| ping.offset < period));
        assert!(schedule.is_sorted_by_key(|ping| ping.offset));
        let distinct = schedule
            .iter()
            .map(|ping| ping.offset)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(distinct.len() > 20, "pings must not fire together");
    }

    #[test]
    fn burst_schedule_opens_with_one_ping_per_subject() {
        let period = Duration::from_secs(600);

        let start = burst_schedule(
            4,
            2,
            period,
            Some(BurstKick::Start),
            &mut rand::thread_rng(),
        );
        assert_eq!(start.len(), 4 * 3);
        let immediate = start
            .iter()
            .take_while(|ping| ping.offset.is_zero())
            .map(|ping| ping.subject)
            .collect::<Vec<_>>();
        assert_eq!(immediate, [0, 1, 2, 3]);

        let moved = burst_schedule(
            4,
            0,
            period,
            Some(BurstKick::NetworkChange),
            &mut rand::thread_rng(),
        );
        assert_eq!(moved.len(), 4);
        assert!(moved.iter().all(|ping| {
            (BURST_NETWORK_SETTLE..=BURST_NETWORK_SETTLE + BURST_NETWORK_REPROBE_JITTER)
                .contains(&ping.offset)
        }));
    }

    /// While the connectivity check fails only one ping per backoff leaves,
    /// and the backoff never exceeds `pingConfig.interval`.
    #[tokio::test(start_paused = true)]
    async fn connectivity_gate_lets_one_canary_through_per_bounded_backoff() {
        let interval = Duration::from_secs(15);
        let mut gate = ConnectivityGate::default();
        let now = tokio::time::Instant::now();
        assert_eq!(gate.admit(now), Some(PingRole::Scheduled));

        gate.network_down(PingRole::Scheduled, now, interval);
        // A ping already in flight when the pause began changes nothing.
        gate.network_down(PingRole::Scheduled, now, interval);
        assert_eq!(gate.admit(now + Duration::from_secs(4)), None);

        let mut now = now + BURST_CONNECTIVITY_BACKOFF_MIN;
        let mut waits = Vec::new();
        for _ in 0..4 {
            assert_eq!(gate.admit(now), Some(PingRole::Canary));
            assert_eq!(gate.admit(now), None, "one canary at a time");
            gate.network_down(PingRole::Canary, now, interval);
            let wait = gate.pause.as_ref().expect("still paused").backoff;
            assert_eq!(gate.admit(now + wait - Duration::from_millis(1)), None);
            waits.push(wait);
            now += wait;
        }
        assert_eq!(
            waits,
            [10, 15, 15, 15].map(Duration::from_secs),
            "doubles from 5s up to the interval"
        );

        assert_eq!(gate.admit(now), Some(PingRole::Canary));
        gate.network_up();
        assert_eq!(gate.admit(now), Some(PingRole::Scheduled));
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

    /// A [`socks_server`] that, while `up` is false, closes every connection
    /// at once, so that a probe through it fails as through a dead server.
    async fn switchable_socks_server(up: Arc<AtomicBool>) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind SOCKS server");
        let port = listener.local_addr().expect("SOCKS server address").port();
        let server = tokio::spawn(async move {
            let connects = Arc::new(AtomicUsize::new(0));
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                if !up.load(Ordering::Acquire) {
                    continue;
                }
                let connects = Arc::clone(&connects);
                tokio::spawn(async move {
                    let _ = serve_socks(&mut stream, Duration::ZERO, &connects).await;
                });
            }
        });
        (port, server)
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

    /// Probes `node` once as the observatory does for `kind`.
    async fn probe_once(
        runtime: &ObservatoryRuntime,
        reprobes: &mut Reprobes,
        node: OutboundNodeId,
        kind: ProbeKind,
    ) {
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        assert!(
            probe_nodes(runtime, &[node], kind, reprobes, &mut shutdown).await,
            "a {kind:?} probe runs to its end"
        );
    }

    /// Re-probes run because traffic failed, several per probe interval and
    /// mostly failing. They move the health state, the last delay and the
    /// failure count, but the `leastLoad` window keeps holding the scheduled
    /// round's samples alone.
    #[tokio::test]
    async fn reprobes_leave_the_least_load_window_to_the_scheduled_round() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let up = Arc::new(AtomicBool::new(true));
            let (port, server) = switchable_socks_server(Arc::clone(&up)).await;
            let router = Arc::new(OutboundRouter::new(Arc::new(parse(&json!({
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom"},
                    socks("proxy-a", "127.0.0.1", port),
                    socks("proxy-b", "127.0.0.1", port),
                ],
                "routing": {"balancers": [{"tag": "auto", "selector": ["proxy-"],
                    "strategy": {"type": "leastLoad"}, "fallbackTag": "direct"}]},
            })))));
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
            let resolver = crate::system_dns_resolver();
            let runtime = ObservatoryRuntime::new(
                observatory,
                nodes,
                Arc::clone(&router),
                router.selection_handle(),
                Arc::clone(&resolver),
                resolver,
                Arc::new(TransportDialer::system().expect("system dialer")),
            );
            let mut reprobes = Reprobes::new(
                Arc::clone(&runtime.selection),
                router.graph(),
                &runtime.nodes,
                runtime.config.probe_interval,
                REPROBE_COOLDOWNS,
            );
            let selection = router.selection();
            let status = || {
                selection
                    .health_snapshot()
                    .outbounds
                    .into_iter()
                    .find(|outbound| outbound.outbound_tag == "proxy-a")
                    .expect("proxy-a has a health status")
            };
            let window = || selection.least_load_window_of(proxy_a).unwrap();

            // Three scheduled rounds: a success, a failure, a success.
            for answers in [true, false, true] {
                up.store(answers, Ordering::Release);
                probe_once(&runtime, &mut reprobes, proxy_a, ProbeKind::Scheduled).await;
            }
            assert_eq!(status().state, OutboundHealthState::Healthy);
            let scheduled = window();
            assert_eq!(scheduled, (3, 1));

            // The server goes away and traffic through it fails. The first
            // re-probe is held back for the one that confirms it.
            up.store(false, Ordering::Release);
            probe_once(&runtime, &mut reprobes, proxy_a, ProbeKind::Reprobe).await;
            assert_eq!(status().state, OutboundHealthState::Healthy);
            assert_eq!(window(), scheduled);

            // The confirming probe marks it unhealthy, the first recheck
            // finds it still down.
            for consecutive_failures in [1, 2] {
                probe_once(&runtime, &mut reprobes, proxy_a, ProbeKind::Reprobe).await;
                let status = status();
                assert_eq!(status.state, OutboundHealthState::Unhealthy);
                assert_eq!(status.consecutive_failures, consecutive_failures);
                assert_eq!(status.delay_ms, None);
                assert_eq!(window(), scheduled, "after failure {consecutive_failures}");
                assert!(reprobes.next_due(Instant::now()).is_some());
            }

            // It is back, and the next recheck marks it healthy again.
            up.store(true, Ordering::Release);
            probe_once(&runtime, &mut reprobes, proxy_a, ProbeKind::Reprobe).await;
            let status_now = status();
            assert_eq!(status_now.state, OutboundHealthState::Healthy);
            assert_eq!(status_now.consecutive_failures, 0);
            assert!(status_now.delay_ms.is_some());
            assert_eq!(window(), scheduled);
            assert_eq!(reprobes.next_due(Instant::now()), None);

            // The next scheduled round adds its sample as before.
            probe_once(&runtime, &mut reprobes, proxy_a, ProbeKind::Scheduled).await;
            assert_eq!(window(), (4, 1));
            server.abort();
        })
        .await
        .expect("the probes finish in time");
    }

    /// With `burstObservatory` alone nothing watches the failures of real
    /// traffic: a failed open is dropped where it is reported and brings no
    /// re-probe. A re-probe's result recorded all the same would leave the
    /// `sampling` window, and the health read from it, as the pings left
    /// them.
    #[test]
    fn traffic_failures_bring_no_reprobe_under_the_burst_observatory() {
        let router = OutboundRouter::new(Arc::new(parse(&json!({
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                socks("proxy-a", "127.0.0.1", 9),
            ],
        }))));
        let selection = router.selection();
        selection.use_burst_health(crate::outbound::BurstHealthPolicy {
            sampling: 4,
            validity: Duration::from_secs(600),
        });
        let proxy_a = router.graph().node_for_tag("proxy-a").unwrap();
        let status = || {
            selection
                .health_snapshot()
                .outbounds
                .into_iter()
                .find(|outbound| outbound.outbound_tag == "proxy-a")
                .expect("proxy-a has a health status")
        };

        // Two pings of the burst schedule: a success and a failure.
        let at = std::time::Instant::now();
        selection.record_health_probe(proxy_a, Ok(Duration::from_millis(20)), 1, at);
        selection.record_health_probe(proxy_a, Err(OutboundHealthFailure::Timeout), 2, at);
        let pinged = selection.least_load_window_of(proxy_a).unwrap();
        assert_eq!(pinged, (2, 1));
        assert_eq!(status().state, OutboundHealthState::Healthy);
        assert_eq!(status().delay_ms, Some(20));

        // A flow fails to open through it. No observatory watches the slot,
        // so nothing is left pending for anyone to probe.
        selection.report_dial_failure(proxy_a);
        let slot = selection.leaf_index(proxy_a).unwrap();
        assert!(!selection.failure_reports().is_pending(slot));

        selection.record_reprobe_failure(proxy_a, OutboundHealthFailure::Transport, 3);
        assert_eq!(selection.least_load_window_of(proxy_a).unwrap(), pinged);
        assert_eq!(status().state, OutboundHealthState::Healthy);
        selection.record_reprobe_success(proxy_a, Duration::from_millis(5), 4);
        assert_eq!(selection.least_load_window_of(proxy_a).unwrap(), pinged);
        assert_eq!(status().delay_ms, Some(20));
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
