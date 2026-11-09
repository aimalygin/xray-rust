//! The bridge side of Xray-core v26.10.31's VLESS reverse proxy.
//!
//! A VLESS outbound with `reverse` keeps tunnels open to its server: VLESS
//! connections with the reverse command, over which the server, the portal,
//! opens sessions back to the bridge as a Mux.Cool client. Each session is
//! routed as if an inbound tagged `reverse.tag` had accepted it from the
//! portal's client, so it reaches only what routing sends it to, and a
//! freedom outbound refuses it unless its final rules allow
//! (`proxy/vless/outbound/outbound.go`, `app/reverse/bridge.go`).
//!
//! A monitor runs every 2 seconds from 2 seconds after the start. It opens a
//! tunnel when none is active, or when the active ones hold more than 16
//! sessions each on average. A tunnel stops being active when it closes or
//! when the portal's control session asks it to drain, which Xray-core's
//! portal does once more than 256 sessions, its control session included, were opened on it; a draining tunnel finishes
//! its sessions and closes when idle. A tunnel lost to a network change is
//! replaced at the next run once the loss is noticed: by the carrier, or
//! when nothing crossed it for the `connIdle` of its user's level, the
//! portal sending a control message every 10 seconds.

mod mux;
mod session;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use xray_config::{CoreConfig, OutboundSettings, VlessReverseSettings};
use xray_transport::TransportDialer;

use crate::dns::RuntimeDnsResolvers;
use crate::outbound::{open_vless_reverse_tunnel, OutboundNodeId};
use crate::policy::{effective_policy_for_level, EffectivePolicy};
use crate::{ConnectionRegistry, OutboundRouter, RuntimeLogger};

pub(crate) use mux::Session;

/// Xray-core starts the monitor 2 seconds after it builds the outbound.
const START_DELAY: Duration = Duration::from_secs(2);
/// How often the monitor runs.
const MONITOR_INTERVAL: Duration = Duration::from_secs(2);
/// More sessions than this per active tunnel, on average, opens another.
const SESSIONS_PER_TUNNEL: usize = 16;
/// The tunnels one bridge keeps open at once, draining ones included.
/// Xray-core's bridge has no bound; its portal keeps far fewer busy.
const MAX_TUNNELS: usize = 16;
/// New sessions a tunnel's reader may hand over before it waits.
const NEW_SESSION_QUEUE: usize = 16;

/// What the monitor knows of one tunnel.
#[derive(Debug, Default)]
pub(crate) struct TunnelState {
    closed: AtomicBool,
    draining: AtomicBool,
    sessions: AtomicUsize,
}

impl TunnelState {
    /// Whether the tunnel still takes sessions: Xray-core's
    /// `BridgeWorker.IsActive`, true from before it connects.
    fn is_active(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && !self.draining.load(Ordering::Acquire)
    }

    fn sessions(&self) -> usize {
        self.sessions.load(Ordering::Acquire)
    }
}

/// Whether the monitor opens another tunnel: when no tunnel is active, or
/// when the active ones hold more than 16 sessions each, as Xray-core
/// divides, in whole numbers.
fn wants_tunnel(active: usize, sessions: usize) -> bool {
    active == 0 || sessions / active > SESSIONS_PER_TUNNEL
}

/// One bridge: a VLESS outbound with `reverse`, and what its sessions need.
pub(crate) struct BridgeContext {
    pub(crate) node: OutboundNodeId,
    pub(crate) reverse: VlessReverseSettings,
    /// The level of the outbound's user: the tunnel's `connIdle`, and the
    /// buffer its sessions relay with.
    pub(crate) policy: EffectivePolicy,
    pub(crate) config: Arc<CoreConfig>,
    pub(crate) router: Arc<OutboundRouter>,
    pub(crate) dns: RuntimeDnsResolvers,
    pub(crate) dialer: Arc<TransportDialer>,
    pub(crate) logger: RuntimeLogger,
    pub(crate) registry: Arc<ConnectionRegistry>,
}

impl BridgeContext {
    /// The user routing sees on the sessions: the outbound's email.
    pub(crate) fn user(&self) -> Option<&str> {
        Some(self.reverse.email.as_str()).filter(|email| !email.is_empty())
    }
}

/// The outbounds that are bridges, with their reverse settings and their
/// user's level, in configuration order.
pub(crate) fn bridges(config: &CoreConfig) -> Vec<(usize, VlessReverseSettings, u32)> {
    config
        .outbounds
        .iter()
        .enumerate()
        .filter_map(|(index, outbound)| match &outbound.settings {
            OutboundSettings::Vless(vless) => vless.reverse.as_ref().map(|reverse| {
                let level = vless.users.first().map_or(0, |user| user.level);
                (index, reverse.clone(), level)
            }),
            _ => None,
        })
        .collect()
}

/// Builds the context of the bridge at configuration index `index`.
#[expect(
    clippy::too_many_arguments,
    reason = "a bridge receives the shared runtime dependencies explicitly"
)]
pub(crate) fn context(
    index: usize,
    reverse: VlessReverseSettings,
    level: u32,
    config: Arc<CoreConfig>,
    router: Arc<OutboundRouter>,
    dns: RuntimeDnsResolvers,
    dialer: Arc<TransportDialer>,
    logger: RuntimeLogger,
    registry: Arc<ConnectionRegistry>,
) -> Option<Arc<BridgeContext>> {
    let node = router.graph().nodes().get(index)?.id();
    Some(Arc::new(BridgeContext {
        node,
        reverse,
        policy: effective_policy_for_level(&config, Some(level)),
        config,
        router,
        dns,
        dialer,
        logger,
        registry,
    }))
}

/// Runs one bridge's monitor and tunnels until shutdown.
pub(crate) async fn run_bridge(context: Arc<BridgeContext>, mut shutdown: watch::Receiver<bool>) {
    let mut tunnels: Vec<Arc<TunnelState>> = Vec::new();
    let mut tasks = JoinSet::new();
    let mut delay = START_DELAY;
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            () = tokio::time::sleep(delay) => {}
        }
        delay = MONITOR_INTERVAL;
        while tasks.try_join_next().is_some() {}
        tunnels.retain(|tunnel| tunnel.is_active());
        let sessions = tunnels.iter().map(|tunnel| tunnel.sessions()).sum();
        if wants_tunnel(tunnels.len(), sessions) && tasks.len() < MAX_TUNNELS {
            let tunnel = Arc::new(TunnelState::default());
            tunnels.push(Arc::clone(&tunnel));
            tasks.spawn(run_tunnel(Arc::clone(&context), tunnel, shutdown.clone()));
        }
    }
    // Each tunnel watches the same shutdown and closes its sessions.
    while tasks.join_next().await.is_some() {}
}

/// Opens one tunnel and serves the portal's sessions on it until it closes.
async fn run_tunnel(
    context: Arc<BridgeContext>,
    tunnel: Arc<TunnelState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let tag = context.reverse.tag.clone();
    let opened = async {
        let outbound = context.router.factory().cached_tcp_outbound(context.node)?;
        open_vless_reverse_tunnel(
            &outbound,
            context.dns.bootstrap.as_ref(),
            context.dialer.as_ref(),
        )
        .await
    };
    let stream = tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut shutdown) => None,
        opened = opened => match opened {
            Ok(stream) => Some(stream),
            // Dial errors can name the server, which logs keep out.
            Err(_) => {
                context
                    .logger
                    .error(|| format!("Debug reverse tunnel failed tag={tag} error=<redacted>"));
                None
            }
        },
    };
    let Some(stream) = stream else {
        tunnel.closed.store(true, Ordering::Release);
        return;
    };
    context
        .logger
        .debug(|| format!("Debug reverse tunnel open tag={tag}"));

    let shared = mux::Shared::new(Arc::clone(&tunnel));
    let (read, write) = tokio::io::split(stream);
    let (opened_tx, mut opened_rx) = mpsc::channel(NEW_SESSION_QUEUE);
    let reader = mux::read_loop(Arc::clone(&shared), read, opened_tx);
    let writer = mux::write_loop(Arc::clone(&shared), write);
    let idle = mux::idle_loop(Arc::clone(&shared));
    let inactive = mux::inactivity_loop(Arc::clone(&shared), context.policy.conn_idle);
    tokio::pin!(reader, writer, idle, inactive);
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => break,
            _ = &mut reader => break,
            _ = &mut writer => break,
            () = &mut idle => break,
            () = &mut inactive => break,
            Some(new) = opened_rx.recv() => {
                sessions.spawn(session::serve(Arc::clone(&context), new, shutdown.clone()));
            }
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
        }
    }
    tunnel.closed.store(true, Ordering::Release);
    shared.close();
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    context
        .logger
        .debug(|| format!("Debug reverse tunnel closed tag={tag}"));
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow_and_update() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

/// A label for a session's client in access logs.
fn client_label(source: Option<SocketAddr>) -> String {
    source.map_or_else(|| "unknown".to_owned(), |source| source.to_string())
}

#[cfg(test)]
mod tests;
