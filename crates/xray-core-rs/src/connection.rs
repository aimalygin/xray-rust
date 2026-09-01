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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundAccounting {
    pub outbound_tag: Option<String>,
    pub opened_connections: u64,
    pub completed_connections: u64,
    pub host_closed_connections: u64,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundAccountingSnapshot {
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
        OutboundAccountingSnapshot {
            revision: state.revision,
            outbounds: state.accounting.values().cloned().collect(),
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
}
