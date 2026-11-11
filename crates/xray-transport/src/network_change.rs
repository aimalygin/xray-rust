//! The OS network changed under live QUIC connections.

use std::sync::Arc;

use tokio::sync::watch;

/// One core's signal that the OS network changed. A QUIC connection dialed
/// with it takes a fresh protected socket on every change and keeps its
/// streams, as a Hysteria client does on its own rebind. A connection that
/// cannot move, behind a `realm`, `xdns` or `xicmp` mask, is left alone.
#[derive(Clone, Debug)]
pub struct NetworkChanges(Arc<watch::Sender<u64>>);

impl Default for NetworkChanges {
    fn default() -> Self {
        Self(Arc::new(watch::channel(0).0))
    }
}

impl NetworkChanges {
    /// Asks every connection that follows these changes for a fresh socket.
    /// Returns how many follow them: requests accepted, not paths validated.
    pub fn notify(&self) -> u64 {
        self.0
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        self.0.receiver_count() as u64
    }

    pub(crate) fn follow(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One signal for a core: a dialer made from another by cloning shares
    /// it, so a notification on the first reaches whoever follows the second.
    #[test]
    fn dialers_made_from_one_share_its_changes() {
        let base = crate::TransportDialer::system().unwrap();
        let derived = base
            .clone()
            .with_socket_options(Arc::new(crate::SocketOptions::default()));
        assert_eq!(base.network_changes().notify(), 0);
        let follower = derived.network_changes().follow();
        assert!(!follower.has_changed().unwrap());
        assert_eq!(base.network_changes().notify(), 1);
        assert!(follower.has_changed().unwrap());
        drop(follower);
        assert_eq!(base.network_changes().notify(), 0);

        let other = crate::TransportDialer::system().unwrap();
        let _stranger = other.network_changes().follow();
        assert_eq!(base.network_changes().notify(), 0);
    }
}
