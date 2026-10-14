use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::Connection;
use tokio::sync::{mpsc, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use xray_proxy::hysteria::{
    decode_udp_message, encode_udp_message, fragment_udp_message, Reassembler, UdpMessage,
};
use xray_routing::{Network, Target};

use super::client::Shared;
use super::{HysteriaClient, HysteriaError, HysteriaLimits};

pub struct HysteriaDatagram {
    pub source: Target,
    pub payload: Vec<u8>,
}

struct Queued {
    packet: HysteriaDatagram,
    _bytes: OwnedSemaphorePermit,
}
struct RetryDelivery {
    sender: mpsc::Sender<Queued>,
    queued: Queued,
}
struct Sink {
    sender: mpsc::Sender<Queued>,
    reassembly: Reassembler,
}
struct Entries {
    closed: bool,
    next_id: u64,
    sessions: HashMap<u32, Sink>,
}

pub(super) struct Registry {
    entries: Mutex<Entries>,
    queued_bytes: Arc<Semaphore>,
    limits: HysteriaLimits,
}

impl Registry {
    pub fn new(limits: HysteriaLimits) -> Self {
        Self {
            entries: Mutex::new(Entries {
                closed: false,
                next_id: 1,
                sessions: HashMap::new(),
            }),
            queued_bytes: Arc::new(Semaphore::new(limits.udp_queue_bytes)),
            limits,
        }
    }
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .len()
    }
    pub fn close(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.closed = true;
        entries.sessions.clear();
        self.queued_bytes.close();
    }
    fn register(&self) -> Result<(u32, mpsc::Receiver<Queued>), HysteriaError> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.closed {
            return Err(HysteriaError::Closed);
        }
        if entries.sessions.len() >= self.limits.max_udp_sessions {
            return Err(HysteriaError::SessionLimit);
        }
        // Never reuse IDs on a connection: delayed server packets must not be
        // delivered to a different flow. Reconnect on exhaustion.
        let id = u32::try_from(entries.next_id).map_err(|_| HysteriaError::SessionLimit)?;
        entries.next_id += 1;
        let (sender, receiver) = mpsc::channel(self.limits.udp_queue_packets);
        let reassembly = Reassembler::new(
            id,
            self.limits.udp_payload_bytes,
            self.limits.fragment_timeout,
        )
        .map_err(|_| HysteriaError::Configuration)?;
        entries.sessions.insert(id, Sink { sender, reassembly });
        Ok((id, receiver))
    }
    fn remove(&self, id: u32) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .remove(&id);
    }
    fn expire(&self, now: Instant) {
        for sink in self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .values_mut()
        {
            sink.reassembly.expire(now);
        }
    }
    fn feed(&self, bytes: &[u8], now: Instant) -> Option<RetryDelivery> {
        let Ok(message) = decode_udp_message(bytes) else {
            return None;
        };
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let sink = entries.sessions.get_mut(&message.session_id)?;
        let Ok(Some(packet)) = sink.reassembly.feed(&message, now) else {
            return None;
        };
        let Ok(source) = super::parse_udp_source(&packet.address) else {
            return None;
        };
        let Ok(permit) =
            Arc::clone(&self.queued_bytes).try_acquire_many_owned(packet.payload.len() as u32)
        else {
            return None;
        };
        let queued = Queued {
            packet: HysteriaDatagram {
                source,
                payload: packet.payload,
            },
            _bytes: permit,
        };
        match sink.sender.try_send(queued) {
            Err(mpsc::error::TrySendError::Full(queued)) => Some(RetryDelivery {
                sender: sink.sender.clone(),
                queued,
            }),
            _ => None,
        }
    }

    async fn deliver(&self, bytes: &[u8], now: Instant) {
        if let Some(retry) = self.feed(bytes, now) {
            // A socket receive batch can fill a small queue before its ready
            // consumer runs. Offer it a scheduling opportunity, without holding the
            // registry lock or waiting for capacity on a slow session. The
            // single pending packet still owns its global byte-budget permit.
            tokio::task::yield_now().await;
            // If it is still full, retain UDP's bounded drop policy. Never
            // block every other session behind this consumer.
            let _ = retry.sender.try_send(retry.queued);
        }
    }
}

pub(super) fn spawn_receiver(connection: Connection, registry: Arc<Registry>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                packet = connection.read_datagram() => match packet {
                    Ok(bytes) => registry.deliver(&bytes, Instant::now()).await,
                    Err(_) => break,
                },
                _ = cleanup.tick() => registry.expire(Instant::now()),
            }
        }
        registry.close();
    })
}

pub struct HysteriaUdpSession {
    shared: Arc<Shared>,
    id: u32,
    receiver: AsyncMutex<mpsc::Receiver<Queued>>,
    packet_id: AsyncMutex<u16>,
}

impl HysteriaClient {
    pub fn open_udp(&self) -> Result<HysteriaUdpSession, HysteriaError> {
        if !self.is_live() {
            return Err(HysteriaError::Closed);
        }
        if !self.shared.udp_enabled || self.shared.connection()?.max_datagram_size().is_none() {
            return Err(HysteriaError::UdpUnsupported);
        }
        let (id, receiver) = self.shared.udp.register()?;
        Ok(HysteriaUdpSession {
            shared: Arc::clone(&self.shared),
            id,
            receiver: AsyncMutex::new(receiver),
            packet_id: AsyncMutex::new(0),
        })
    }
}

impl HysteriaUdpSession {
    pub fn session_id(&self) -> u32 {
        self.id
    }

    pub async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), HysteriaError> {
        let address = super::address(target, Network::Udp)?;
        if payload.is_empty() || payload.len() > self.shared.limits.udp_payload_bytes {
            return Err(HysteriaError::DatagramSize);
        }
        if !self.shared.is_live() {
            return Err(HysteriaError::Closed);
        }
        timeout(self.shared.limits.operation_timeout, async {
            let connection = self.shared.connection()?;
            // Serialize fragments for a flow while letting its receiver progress.
            let mut packet_id = self.packet_id.lock().await;
            *packet_id = packet_id.wrapping_add(1);
            let message = UdpMessage {
                session_id: self.id,
                packet_id: *packet_id,
                fragment_id: 0,
                fragment_count: 1,
                address: &address,
                payload,
            };
            let max_size = connection
                .max_datagram_size()
                .ok_or(HysteriaError::UdpUnsupported)?;
            let fragments = fragment_udp_message(&message, max_size)
                .map_err(|_| HysteriaError::DatagramSize)?;
            for fragment in fragments {
                let wire =
                    encode_udp_message(&fragment).map_err(|_| HysteriaError::DatagramSize)?;
                connection
                    .send_datagram_wait(Bytes::from(wire))
                    .await
                    .map_err(|_| HysteriaError::DatagramSend)?;
            }
            Ok(())
        })
        .await
        .map_err(|_| HysteriaError::Timeout)?
    }

    /// Cancel-safe: timing out or dropping this future does not close the flow
    /// or discard a packet before it is returned. Receive has no idle deadline;
    /// the runtime owns flow idle policy and explicit cancellation.
    pub async fn recv(&self) -> Result<HysteriaDatagram, HysteriaError> {
        if !self.shared.is_live() {
            return Err(HysteriaError::Closed);
        }
        let queued = self
            .receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or(HysteriaError::Closed)?;
        Ok(queued.packet)
    }
}

impl Drop for HysteriaUdpSession {
    fn drop(&mut self) {
        self.shared.udp.remove(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(id: u32, payload: &[u8]) -> Vec<u8> {
        encode_udp_message(&UdpMessage {
            session_id: id,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 1,
            address: "127.0.0.1:53",
            payload,
        })
        .unwrap()
    }

    #[test]
    fn default_queue_absorbs_a_short_burst_and_retains_its_memory_bound() {
        let limits = HysteriaLimits::default();
        assert_eq!(limits.udp_queue_packets, 16);
        assert_eq!(limits.udp_queue_bytes, 1024 * 1024);
        let registry = Registry::new(limits);
        let (id, mut receiver) = registry.register().unwrap();
        // A receive burst may finish before the ready relay is scheduled.
        for sequence in 0..16 {
            drop(registry.feed(&wire(id, &[sequence]), Instant::now()));
        }
        drop(registry.feed(&wire(id, b"excess"), Instant::now()));
        for sequence in 0..16 {
            assert_eq!(receiver.try_recv().unwrap().packet.payload, [sequence]);
        }
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            registry.queued_bytes.available_permits(),
            limits.udp_queue_bytes
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_consumer_receives_a_burst_larger_than_its_queue() {
        let registry = Registry::new(HysteriaLimits {
            udp_queue_packets: 4,
            ..HysteriaLimits::default()
        });
        let (id, mut receiver) = registry.register().unwrap();
        let consumer = tokio::spawn(async move {
            let mut received = Vec::new();
            while let Some(packet) = receiver.recv().await {
                received.push(packet.packet.payload[0]);
            }
            received
        });
        // Quinn can return an entire socket receive batch without Pending.
        // A ready consumer must get a scheduling turn before this burst drops.
        for sequence in 0..32 {
            registry
                .deliver(&wire(id, &[sequence]), Instant::now())
                .await;
        }
        registry.close();
        assert_eq!(consumer.await.unwrap(), (0..32).collect::<Vec<u8>>());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_consumer_does_not_block_other_sessions_or_retain_retry_budget() {
        let registry = Registry::new(HysteriaLimits {
            udp_queue_packets: 1,
            udp_queue_bytes: 8,
            ..HysteriaLimits::default()
        });
        let (slow, mut slow_rx) = registry.register().unwrap();
        let (fast, mut fast_rx) = registry.register().unwrap();
        timeout(Duration::from_secs(2), async {
            registry.deliver(&wire(slow, b"one"), Instant::now()).await;
            for _ in 0..32 {
                registry.deliver(&wire(slow, b"drop"), Instant::now()).await;
                // The dropped retry must release four bytes; otherwise this
                // unrelated session cannot acquire its three-byte budget.
                registry.deliver(&wire(fast, b"two"), Instant::now()).await;
                assert_eq!(fast_rx.recv().await.unwrap().packet.payload, b"two");
            }
        })
        .await
        .expect("a full session must not hold up the shared receive driver");
        assert_eq!(slow_rx.try_recv().unwrap().packet.payload, b"one");
        assert!(slow_rx.try_recv().is_err());
        assert_eq!(registry.queued_bytes.available_permits(), 8);
    }

    #[tokio::test]
    async fn global_queue_budget_is_shared_released_and_unknown_ids_are_ignored() {
        let registry = Registry::new(HysteriaLimits {
            udp_queue_bytes: 8,
            ..HysteriaLimits::default()
        });
        let (a, mut rx_a) = registry.register().unwrap();
        let (b, mut rx_b) = registry.register().unwrap();
        drop(registry.feed(&wire(999, b"xxxx"), Instant::now()));
        drop(registry.feed(&wire(a, b"12345678"), Instant::now()));
        drop(registry.feed(&wire(b, b"xxxx"), Instant::now()));
        assert!(rx_b.try_recv().is_err());
        drop(rx_a.try_recv().unwrap());
        drop(registry.feed(&wire(b, b"xxxx"), Instant::now()));
        assert_eq!(rx_b.try_recv().unwrap().packet.payload, b"xxxx");
        assert_eq!(registry.queued_bytes.available_permits(), 8);
    }

    #[test]
    fn per_session_queue_and_id_allocation_are_bounded() {
        let registry = Registry::new(HysteriaLimits {
            max_udp_sessions: 1,
            udp_queue_packets: 1,
            ..HysteriaLimits::default()
        });
        let (id, mut rx) = registry.register().unwrap();
        assert!(matches!(
            registry.register(),
            Err(HysteriaError::SessionLimit)
        ));
        drop(registry.feed(&wire(id, b"one"), Instant::now()));
        drop(registry.feed(&wire(id, b"two"), Instant::now()));
        assert_eq!(rx.try_recv().unwrap().packet.payload, b"one");
        assert!(rx.try_recv().is_err());
        registry.remove(id);
        let (next, _) = registry.register().unwrap();
        assert_ne!(id, next);
        registry.close();
        assert!(matches!(registry.register(), Err(HysteriaError::Closed)));
    }
}
