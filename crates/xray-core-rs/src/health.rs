use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tokio::sync::watch;
use tokio::task::JoinSet;
use xray_config::{BurstPingConfig, ObservatoryConfig, OBSERVATORY_PROBE_TIMEOUT};
use xray_transport::{DnsResolver, TransportDialer};

use crate::outbound::{
    OutboundHealthFailure, OutboundNodeId, OutboundRouter, OutboundSelectionOverlay,
};
use crate::startup_probe::{
    run_health_probe, run_outbound_url_probe, ProbePath, ProbeRequest, ProbeStatusPolicy,
    StartupProbeError, StartupProbeOptions,
};

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

pub(crate) struct ObservatoryRuntime {
    config: ObservatoryConfig,
    nodes: Vec<OutboundNodeId>,
    outbound_router: Arc<OutboundRouter>,
    selection: Arc<OutboundSelectionOverlay>,
    destination_resolver: Arc<dyn DnsResolver>,
    bootstrap_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
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
        }
    }
}

pub(crate) async fn run_observatory(
    runtime: ObservatoryRuntime,
    mut shutdown: watch::Receiver<bool>,
) {
    if runtime.nodes.is_empty() {
        return;
    }

    loop {
        let completed = if runtime.config.enable_concurrency {
            run_concurrent_round(
                &runtime.config,
                &runtime.nodes,
                &runtime.outbound_router,
                &runtime.selection,
                &runtime.destination_resolver,
                &runtime.bootstrap_resolver,
                &runtime.transport_dialer,
                &mut shutdown,
            )
            .await
        } else {
            run_sequential_round(
                &runtime.config,
                &runtime.nodes,
                &runtime.outbound_router,
                &runtime.selection,
                &runtime.destination_resolver,
                &runtime.bootstrap_resolver,
                &runtime.transport_dialer,
                &mut shutdown,
            )
            .await
        };
        if !completed || !runtime.config.enable_concurrency {
            if !completed {
                return;
            }
            continue;
        }

        if wait_interval_or_shutdown(runtime.config.probe_interval, &mut shutdown).await {
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
    runtime.selection.expire_health_samples(Instant::now());

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
                        runtime.selection.expire_health_samples(Instant::now());
                        continue;
                    }
                };
                gate.network_up();
                runtime
                    .selection
                    .record_health_probe(node, outcome, unix_ms_now(), Instant::now());
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
    config: &ObservatoryConfig,
    nodes: &[OutboundNodeId],
    outbound_router: &Arc<OutboundRouter>,
    selection: &Arc<OutboundSelectionOverlay>,
    destination_resolver: &Arc<dyn DnsResolver>,
    bootstrap_resolver: &Arc<dyn DnsResolver>,
    transport_dialer: &Arc<TransportDialer>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    for node in nodes {
        let result = tokio::select! {
            biased;
            () = wait_for_shutdown(shutdown) => return false,
            result = probe_node(
                config,
                *node,
                outbound_router,
                destination_resolver,
                bootstrap_resolver,
                transport_dialer,
            ) => result,
        };
        record_result(selection, *node, result);
        if wait_interval_or_shutdown(config.probe_interval, shutdown).await {
            return false;
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
async fn run_concurrent_round(
    config: &ObservatoryConfig,
    nodes: &[OutboundNodeId],
    outbound_router: &Arc<OutboundRouter>,
    selection: &Arc<OutboundSelectionOverlay>,
    destination_resolver: &Arc<dyn DnsResolver>,
    bootstrap_resolver: &Arc<dyn DnsResolver>,
    transport_dialer: &Arc<TransportDialer>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    for chunk in nodes.chunks(MAX_CONCURRENT_HEALTH_PROBES) {
        let mut tasks = JoinSet::new();
        for node in chunk.iter().copied() {
            let config = config.clone();
            let outbound_router = Arc::clone(outbound_router);
            let destination_resolver = Arc::clone(destination_resolver);
            let bootstrap_resolver = Arc::clone(bootstrap_resolver);
            let transport_dialer = Arc::clone(transport_dialer);
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
                        record_result(selection, node, result);
                    }
                }
            }
        }
    }
    true
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
    let now_unix_ms = unix_ms_now();
    match result {
        Ok(delay) => selection.record_health_success(node, delay, now_unix_ms),
        Err(error) => {
            selection.record_health_failure(node, error.health_failure(), now_unix_ms);
        }
    }
}

async fn wait_interval_or_shutdown(
    interval: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => true,
        () = tokio::time::sleep(interval) => false,
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
}
