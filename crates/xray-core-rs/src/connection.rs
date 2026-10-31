use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::sync::watch;
use xray_routing::{Network, Target};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub const fn from_raw(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Opening,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub id: ConnectionId,
    pub state: ConnectionState,
    pub inbound_tag: Option<String>,
    pub outbound_tag: Option<String>,
    pub network: Network,
    pub target: Target,
    pub started_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSnapshot {
    pub revision: u64,
    pub connections: Vec<ConnectionInfo>,
}

/// Per-outbound connection and payload byte accounting.
///
/// Byte counters count relayed application payload: uplink flows from the
/// inbound client toward the target, downlink flows back. Transport framing,
/// encryption and handshake overhead are not included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundAccounting {
    pub outbound_tag: Option<String>,
    pub opened_connections: u64,
    pub completed_connections: u64,
    pub host_closed_connections: u64,
    /// Payload bytes of completed connections only. A connection adds its
    /// bytes here once, when it leaves the active inventory.
    pub uplink_bytes: u64,
    /// Downlink counterpart of `uplink_bytes`.
    pub downlink_bytes: u64,
    /// Payload bytes relayed so far by the connections that are still opening
    /// or active, read when the snapshot is taken. When such a connection
    /// completes, its bytes move from here to `uplink_bytes`, so
    /// `uplink_bytes + active_uplink_bytes` never decreases between snapshots.
    pub active_uplink_bytes: u64,
    /// Downlink counterpart of `active_uplink_bytes`.
    pub active_downlink_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundAccountingSnapshot {
    /// The registry revision shared with [`ConnectionSnapshot`]. It advances
    /// when a connection opens, becomes active, is asked to close, or
    /// completes; relayed bytes alone do not advance it, so active byte
    /// counters can differ between snapshots with the same revision.
    pub revision: u64,
    pub outbounds: Vec<OutboundAccounting>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConnectionCloseError {
    #[error("connection {0} was not found")]
    NotFound(u64),
}

#[derive(Debug)]
struct ConnectionEntry {
    info: ConnectionInfo,
    close: watch::Sender<bool>,
    host_close_requested: bool,
    traffic: Arc<ConnectionTraffic>,
}

#[derive(Debug, Default)]
pub(crate) struct ConnectionTraffic {
    pub(crate) uplink_bytes: AtomicU64,
    pub(crate) downlink_bytes: AtomicU64,
}

impl ConnectionTraffic {
    pub(crate) fn record_uplink(&self, bytes: u64) {
        self.uplink_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn record_downlink(&self, bytes: u64) {
        self.downlink_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
struct ConnectionRegistryState {
    revision: u64,
    active: BTreeMap<ConnectionId, ConnectionEntry>,
    accounting: BTreeMap<Option<String>, OutboundAccounting>,
}

#[derive(Debug, Default)]
pub struct ConnectionRegistry {
    next_id: AtomicU64,
    state: Mutex<ConnectionRegistryState>,
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            state: Mutex::new(ConnectionRegistryState::default()),
        }
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ConnectionSnapshot {
            revision: state.revision,
            connections: state
                .active
                .values()
                .map(|entry| entry.info.clone())
                .collect(),
        }
    }

    pub fn accounting_snapshot(&self) -> OutboundAccountingSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Completed totals and live counters are read under the same lock that
        // `finish` holds while it moves a connection's bytes into the totals,
        // so a snapshot counts every byte exactly once. `outbounds` keeps the
        // map's key order, and `register` creates an outbound's entry before
        // its first connection, so every active tag is found.
        let mut outbounds = state.accounting.values().cloned().collect::<Vec<_>>();
        for entry in state.active.values() {
            let tag = entry.info.outbound_tag.as_deref();
            let Ok(index) = outbounds
                .binary_search_by(|accounting| accounting.outbound_tag.as_deref().cmp(&tag))
            else {
                continue;
            };
            let accounting = &mut outbounds[index];
            accounting.active_uplink_bytes = accounting
                .active_uplink_bytes
                .saturating_add(entry.traffic.uplink_bytes.load(Ordering::Acquire));
            accounting.active_downlink_bytes = accounting
                .active_downlink_bytes
                .saturating_add(entry.traffic.downlink_bytes.load(Ordering::Acquire));
        }
        OutboundAccountingSnapshot {
            revision: state.revision,
            outbounds,
        }
    }

    pub fn close(&self, id: ConnectionId) -> Result<u64, ConnectionCloseError> {
        let close = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(entry) = state.active.get_mut(&id) else {
                return Err(ConnectionCloseError::NotFound(id.get()));
            };
            entry.host_close_requested = true;
            let close = entry.close.clone();
            state.revision = state.revision.saturating_add(1);
            (close, state.revision)
        };
        let _ = close.0.send(true);
        Ok(close.1)
    }

    pub(crate) fn register(
        self: &Arc<Self>,
        inbound_tag: Option<String>,
        outbound_tag: Option<String>,
        target: Target,
    ) -> ConnectionLease {
        let id = loop {
            let value = self.next_id.fetch_add(1, Ordering::Relaxed);
            if let Some(id) = ConnectionId::from_raw(value) {
                break id;
            }
        };
        let (close, close_receiver) = watch::channel(false);
        let traffic = Arc::new(ConnectionTraffic::default());
        let info = ConnectionInfo {
            id,
            state: ConnectionState::Opening,
            inbound_tag,
            outbound_tag: outbound_tag.clone(),
            network: target.network,
            target,
            started_unix_ms: unix_millis(),
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active.insert(
            id,
            ConnectionEntry {
                info,
                close,
                host_close_requested: false,
                traffic: Arc::clone(&traffic),
            },
        );
        let accounting = state
            .accounting
            .entry(outbound_tag.clone())
            .or_insert_with(|| OutboundAccounting {
                outbound_tag,
                opened_connections: 0,
                completed_connections: 0,
                host_closed_connections: 0,
                uplink_bytes: 0,
                downlink_bytes: 0,
                active_uplink_bytes: 0,
                active_downlink_bytes: 0,
            });
        accounting.opened_connections = accounting.opened_connections.saturating_add(1);
        state.revision = state.revision.saturating_add(1);
        drop(state);
        ConnectionLease {
            id,
            registry: Arc::downgrade(self),
            close_receiver,
            traffic,
            finished: false,
        }
    }

    fn mark_active(&self, id: ConnectionId) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = state.active.get_mut(&id) else {
            return;
        };
        if entry.info.state != ConnectionState::Active {
            entry.info.state = ConnectionState::Active;
            state.revision = state.revision.saturating_add(1);
        }
    }

    fn finish(&self, id: ConnectionId) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = state.active.remove(&id) else {
            return;
        };
        let uplink_bytes = entry.traffic.uplink_bytes.load(Ordering::Acquire);
        let downlink_bytes = entry.traffic.downlink_bytes.load(Ordering::Acquire);
        if let Some(accounting) = state.accounting.get_mut(&entry.info.outbound_tag) {
            accounting.completed_connections = accounting.completed_connections.saturating_add(1);
            accounting.host_closed_connections = accounting
                .host_closed_connections
                .saturating_add(u64::from(entry.host_close_requested));
            accounting.uplink_bytes = accounting.uplink_bytes.saturating_add(uplink_bytes);
            accounting.downlink_bytes = accounting.downlink_bytes.saturating_add(downlink_bytes);
        }
        state.revision = state.revision.saturating_add(1);
    }
}

pub(crate) struct ConnectionLease {
    id: ConnectionId,
    registry: Weak<ConnectionRegistry>,
    close_receiver: watch::Receiver<bool>,
    traffic: Arc<ConnectionTraffic>,
    finished: bool,
}

impl ConnectionLease {
    pub(crate) fn close_receiver(&self) -> watch::Receiver<bool> {
        self.close_receiver.clone()
    }

    pub(crate) fn traffic(&self) -> Arc<ConnectionTraffic> {
        Arc::clone(&self.traffic)
    }

    pub(crate) fn mark_active(&self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.mark_active(self.id);
        }
    }

    pub(crate) fn finish(mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.finish(self.id);
        }
        self.finished = true;
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(registry) = self.registry.upgrade() {
            registry.finish(self.id);
        }
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub(crate) async fn wait_for_connection_close(close: &mut watch::Receiver<bool>) {
    if *close.borrow() {
        return;
    }
    while close.changed().await.is_ok() {
        if *close.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use xray_routing::{Network, Target, TargetAddr};

    use super::{ConnectionCloseError, ConnectionRegistry, ConnectionState};

    fn target() -> Target {
        Target::new(
            TargetAddr::Domain("example.test".to_owned()),
            443,
            Network::Tcp,
        )
    }

    #[test]
    fn snapshot_close_and_accounting_share_one_revisioned_registry() {
        let registry = Arc::new(ConnectionRegistry::new());
        let lease = registry.register(
            Some("http-in".to_owned()),
            Some("proxy-a".to_owned()),
            target(),
        );
        let id = lease.id;
        lease.mark_active();

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].id, id);
        assert_eq!(snapshot.connections[0].state, ConnectionState::Active);

        let close = lease.close_receiver();
        registry.close(id).unwrap();
        assert!(close.has_changed().unwrap());
        lease.traffic.uplink_bytes.store(128, Ordering::Release);
        lease.traffic.downlink_bytes.store(256, Ordering::Release);
        lease.finish();

        assert!(registry.snapshot().connections.is_empty());
        let accounting = registry.accounting_snapshot();
        assert_eq!(accounting.outbounds.len(), 1);
        assert_eq!(accounting.outbounds[0].opened_connections, 1);
        assert_eq!(accounting.outbounds[0].completed_connections, 1);
        assert_eq!(accounting.outbounds[0].host_closed_connections, 1);
        assert_eq!(accounting.outbounds[0].uplink_bytes, 128);
        assert_eq!(accounting.outbounds[0].downlink_bytes, 256);
        assert_eq!(accounting.outbounds[0].active_uplink_bytes, 0);
        assert_eq!(accounting.outbounds[0].active_downlink_bytes, 0);
        assert_eq!(
            registry.close(id),
            Err(ConnectionCloseError::NotFound(id.get()))
        );
    }

    #[test]
    fn dropping_a_lease_removes_it_and_completes_zero_byte_accounting() {
        let registry = Arc::new(ConnectionRegistry::new());
        let lease = registry.register(None, None, target());
        drop(lease);

        assert!(registry.snapshot().connections.is_empty());
        let accounting = registry.accounting_snapshot();
        assert_eq!(accounting.outbounds[0].opened_connections, 1);
        assert_eq!(accounting.outbounds[0].completed_connections, 1);
        assert_eq!(accounting.outbounds[0].uplink_bytes, 0);
    }

    #[test]
    fn accounting_reports_live_bytes_of_active_connections_per_outbound() {
        let registry = Arc::new(ConnectionRegistry::new());
        let first = registry.register(None, Some("proxy".to_owned()), target());
        let second = registry.register(None, Some("proxy".to_owned()), target());
        let direct = registry.register(None, Some("direct".to_owned()), target());
        let untagged = registry.register(None, None, target());
        first.mark_active();
        let revision = registry.accounting_snapshot().revision;

        first.traffic.record_uplink(10);
        first.traffic.record_downlink(100);
        second.traffic.record_uplink(1);
        direct.traffic.record_downlink(7);
        untagged.traffic.record_uplink(3);

        let live = registry.accounting_snapshot();
        assert_eq!(
            live.revision, revision,
            "relayed bytes must not advance the revision"
        );
        let tags = live
            .outbounds
            .iter()
            .map(|accounting| accounting.outbound_tag.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(tags, [None, Some("direct"), Some("proxy")]);
        let totals = live
            .outbounds
            .iter()
            .map(|accounting| {
                (
                    accounting.uplink_bytes,
                    accounting.downlink_bytes,
                    accounting.active_uplink_bytes,
                    accounting.active_downlink_bytes,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(totals, [(0, 0, 3, 0), (0, 0, 0, 7), (0, 0, 11, 100)]);

        first.traffic.record_downlink(20);
        first.finish();
        let after_first = registry.accounting_snapshot();
        let proxy = &after_first.outbounds[2];
        assert_eq!(proxy.completed_connections, 1);
        assert_eq!((proxy.uplink_bytes, proxy.downlink_bytes), (10, 120));
        assert_eq!(
            (proxy.active_uplink_bytes, proxy.active_downlink_bytes),
            (1, 0)
        );
        assert!(
            proxy.uplink_bytes + proxy.active_uplink_bytes
                >= live.outbounds[2].uplink_bytes + live.outbounds[2].active_uplink_bytes
        );

        drop(second);
        drop(direct);
        drop(untagged);
        let closed = registry.accounting_snapshot();
        let totals = closed
            .outbounds
            .iter()
            .map(|accounting| {
                (
                    accounting.uplink_bytes,
                    accounting.downlink_bytes,
                    accounting.active_uplink_bytes,
                    accounting.active_downlink_bytes,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(totals, [(3, 0, 0, 0), (0, 7, 0, 0), (11, 120, 0, 0)]);
    }
}
