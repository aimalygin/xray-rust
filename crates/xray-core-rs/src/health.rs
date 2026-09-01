use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tokio::task::JoinSet;
use xray_config::{ObservatoryConfig, OBSERVATORY_PROBE_TIMEOUT};
use xray_transport::{DnsResolver, TransportDialer};

use crate::outbound::{
    OutboundHealthFailure, OutboundNodeId, OutboundRouter, OutboundSelectionOverlay,
};
use crate::startup_probe::{run_outbound_url_probe, StartupProbeError, StartupProbeOptions};

const MAX_CONCURRENT_HEALTH_PROBES: usize = 4;

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
        "xray-rust-health-probe",
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
            selection.record_health_failure(node, classify_failure(&error), now_unix_ms);
        }
    }
}

fn classify_failure(error: &StartupProbeError) -> OutboundHealthFailure {
    match error {
        StartupProbeError::UnsupportedUrl | StartupProbeError::Core { .. } => {
            OutboundHealthFailure::Transport
        }
        StartupProbeError::Timeout { .. } => OutboundHealthFailure::Timeout,
        StartupProbeError::Tls { .. } => OutboundHealthFailure::Tls,
        StartupProbeError::Io { .. } => OutboundHealthFailure::Io,
        StartupProbeError::MalformedHttpResponse(_) => OutboundHealthFailure::MalformedHttpResponse,
        StartupProbeError::HttpStatus { status, .. } => OutboundHealthFailure::HttpStatus(*status),
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

    #[test]
    fn failure_classification_is_structured() {
        let error = StartupProbeError::HttpStatus {
            url: "http://<redacted-host>:80".to_owned(),
            status: 503,
        };

        assert_eq!(
            classify_failure(&error),
            OutboundHealthFailure::HttpStatus(503)
        );
    }
}
