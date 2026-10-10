use super::*;
use crate::{TunAdmissionPolicy, TunFlow};

const MAX_PENDING: usize = 64;
const MAX_BUFFERED_BYTES: usize = 1024 * 1024;
const MAX_PACKETS_PER_FLOW: usize = 4;

enum Decision {
    Pending(Vec<Bytes>),
    Allowed { generation: Option<u64> },
    Denied,
}

struct Entry {
    id: u64,
    last_seen: StdInstant,
    decision: Decision,
}

pub(super) struct UdpAdmission {
    policy: TunAdmissionPolicy,
    entries: HashMap<UdpFlowKey, Entry>,
    limit: usize,
    buffered_bytes: usize,
    last_prune: StdInstant,
    pub(super) tasks: JoinSet<(UdpFlowKey, u64, bool)>,
    ready: VecDeque<Bytes>,
}

impl UdpAdmission {
    pub(super) fn new(policy: TunAdmissionPolicy, limit: usize) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
            limit,
            buffered_bytes: 0,
            last_prune: StdInstant::now(),
            tasks: JoinSet::new(),
            ready: VecDeque::new(),
        }
    }

    pub(super) fn pop_ready(&mut self) -> Option<Bytes> {
        let packet = self.ready.pop_front()?;
        self.buffered_bytes -= packet.len();
        Some(packet)
    }

    pub(super) fn complete(&mut self, completion: Result<(UdpFlowKey, u64, bool), JoinError>) {
        let Ok((key, id, allowed)) = completion else {
            return;
        };
        let Some(entry) = self.entries.get_mut(&key).filter(|entry| entry.id == id) else {
            return;
        };
        let next = if allowed {
            Decision::Allowed { generation: None }
        } else {
            Decision::Denied
        };
        if let Decision::Pending(packets) = std::mem::replace(&mut entry.decision, next) {
            if allowed {
                self.ready.extend(packets);
            } else {
                self.buffered_bytes -= packets.iter().map(Bytes::len).sum::<usize>();
            }
        }
    }

    pub(super) fn bind(&mut self, key: UdpFlowKey, flows: &HashMap<UdpFlowKey, UdpFlow>) {
        if let Some(Entry {
            decision: Decision::Allowed { generation },
            ..
        }) = self.entries.get_mut(&key)
        {
            *generation = flows.get(&key).map(|flow| flow.generation);
        }
    }

    pub(super) fn allow(
        &mut self,
        udp: &UdpTunPacket,
        packet: &Bytes,
        flows: &HashMap<UdpFlowKey, UdpFlow>,
        next_id: &AtomicU64,
        shutdown: watch::Receiver<bool>,
    ) -> bool {
        let now = StdInstant::now();
        // One bounded sweep per second; never an O(n) scan per datagram.
        if now.duration_since(self.last_prune) >= Duration::from_secs(1) {
            self.entries.retain(|_, entry| {
                matches!(entry.decision, Decision::Pending(_))
                    || now.duration_since(entry.last_seen) < UDP_IDLE_TIMEOUT
            });
            self.last_prune = now;
        }
        let key = UdpFlowKey::new(udp.client, udp.target);
        let stale = self.entries.get(&key).is_some_and(|entry| {
            now.duration_since(entry.last_seen) >= UDP_IDLE_TIMEOUT
                || matches!(entry.decision, Decision::Allowed { generation: Some(generation) }
                    if flows.get(&key).is_none_or(|flow| flow.generation != generation))
        });
        if stale {
            let removed = self.entries.remove(&key);
            if let Some(Entry {
                decision: Decision::Pending(packets),
                ..
            }) = removed
            {
                // A suspended executor can observe idle expiry before it
                // consumes the timeout/completion of the pending decision.
                self.buffered_bytes -= packets.iter().map(Bytes::len).sum::<usize>();
            }
        }
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_seen = now;
            return match &mut entry.decision {
                Decision::Allowed { .. } => true,
                Decision::Denied => false,
                Decision::Pending(packets) => {
                    if packets.len() < MAX_PACKETS_PER_FLOW
                        && self.buffered_bytes + packet.len() <= MAX_BUFFERED_BYTES
                    {
                        packets.push(packet.clone());
                        self.buffered_bytes += packet.len();
                    }
                    false
                }
            };
        }
        // Resource exhaustion always drops: fail-open applies to host lookup
        // errors/timeouts, never to bypassing the admission/cache memory limits.
        if self.entries.len() >= self.limit
            || self.tasks.len() >= MAX_PENDING
            || self.buffered_bytes + packet.len() > MAX_BUFFERED_BYTES
        {
            return false;
        }
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let flow = raw_flow(id, UDP_PROTOCOL, udp.client, udp.target);
        let policy = self.policy.clone();
        self.tasks
            .spawn(async move { (key, id, policy.admit(flow, shutdown).await) });
        self.buffered_bytes += packet.len();
        self.entries.insert(
            key,
            Entry {
                id,
                last_seen: now,
                decision: Decision::Pending(vec![packet.clone()]),
            },
        );
        false
    }
}

pub(super) fn raw_flow(
    id: u64,
    protocol: u8,
    source: IpEndpoint,
    destination: IpEndpoint,
) -> TunFlow {
    let source = EndpointKey::from_endpoint(source);
    let destination = EndpointKey::from_endpoint(destination);
    TunFlow {
        id,
        protocol,
        source: SocketAddr::new(source.addr, source.port),
        destination: SocketAddr::new(destination.addr, destination.port),
    }
}

/// The optional policy supports only complete TCP/UDP IP packets. Reject other
/// protocols and fragments before the local ICMP responder or IP reassembly.
pub(super) fn supported_packet(packet: &[u8]) -> bool {
    match packet[0] >> 4 {
        4 => {
            matches!(packet[9], TCP_PROTOCOL | UDP_PROTOCOL)
                && u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff == 0
        }
        6 => matches!(packet[6], TCP_PROTOCOL | UDP_PROTOCOL),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp(port: u16) -> UdpTunPacket {
        UdpTunPacket {
            client: IpEndpoint::new(IpAddress::v4(10, 0, 0, 2), port),
            target: IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), 9000),
            payload: Bytes::new(),
        }
    }

    #[tokio::test]
    async fn pending_udp_admission_has_fixed_work_and_memory_bounds() {
        let policy =
            TunAdmissionPolicy::new(Arc::new(|_| true), Duration::from_secs(1), false).unwrap();
        let mut state = UdpAdmission::new(policy, 1024);
        let (_, shutdown) = watch::channel(false);
        let next_id = AtomicU64::new(0);
        let flows = HashMap::new();
        let packet = Bytes::from(vec![0; MAX_BUFFERED_BYTES / MAX_PENDING]);
        for port in 0..100 {
            assert!(!state.allow(&udp(port), &packet, &flows, &next_id, shutdown.clone()));
        }
        assert_eq!(state.tasks.len(), MAX_PENDING);
        assert_eq!(state.entries.len(), MAX_PENDING);
        assert_eq!(state.buffered_bytes, MAX_BUFFERED_BYTES);
        let pending: Vec<_> = state
            .entries
            .iter()
            .map(|(key, entry)| (*key, entry.id))
            .collect();
        for (key, id) in pending {
            state.complete(Ok((key, id, false)));
        }
        assert_eq!(state.buffered_bytes, 0);
        assert!(state.ready.is_empty());
    }

    #[tokio::test]
    async fn stale_pending_udp_releases_budget_and_ignores_old_completion() {
        let policy =
            TunAdmissionPolicy::new(Arc::new(|_| true), Duration::from_secs(1), false).unwrap();
        let mut state = UdpAdmission::new(policy, 1024);
        let (_stop, shutdown) = watch::channel(false);
        let next_id = AtomicU64::new(10);
        let flows = HashMap::new();
        let packet = Bytes::from_static(b"packet");
        let udp = udp(1234);
        let key = UdpFlowKey::new(udp.client, udp.target);
        // Do not yield: simulate a suspended runtime whose pending decision has
        // not been consumed when the first packet after idle expiry arrives.
        for _ in 0..2 {
            assert!(!state.allow(&udp, &packet, &flows, &next_id, shutdown.clone()));
        }
        let old_id = state.entries[&key].id;
        state.entries.get_mut(&key).unwrap().last_seen -= UDP_IDLE_TIMEOUT + Duration::from_secs(1);
        assert!(!state.allow(&udp, &packet, &flows, &next_id, shutdown));
        assert_eq!(state.buffered_bytes, packet.len());
        let new_id = state.entries[&key].id;
        assert_ne!(new_id, old_id);
        state.complete(Ok((key, old_id, true)));
        assert!(state.ready.is_empty());
        assert_eq!(state.buffered_bytes, packet.len());
        state.complete(Ok((key, new_id, true)));
        assert_eq!(state.pop_ready(), Some(packet));
        assert_eq!(state.buffered_bytes, 0);
    }

    #[tokio::test]
    async fn denied_udp_tuple_expires_only_after_idle() {
        let policy =
            TunAdmissionPolicy::new(Arc::new(|_| false), Duration::from_secs(1), false).unwrap();
        let mut state = UdpAdmission::new(policy, 1024);
        let (_stop, shutdown) = watch::channel(false);
        let next_id = AtomicU64::new(10);
        let flows = HashMap::new();
        let packet = Bytes::from_static(b"packet");
        let udp = udp(1234);
        let key = UdpFlowKey::new(udp.client, udp.target);
        assert!(!state.allow(&udp, &packet, &flows, &next_id, shutdown.clone()));
        let result = state.tasks.join_next().await.unwrap();
        state.complete(result);
        assert!(!state.allow(&udp, &packet, &flows, &next_id, shutdown.clone()));
        assert_eq!(next_id.load(Ordering::Relaxed), 11);
        state.entries.get_mut(&key).unwrap().last_seen -= UDP_IDLE_TIMEOUT + Duration::from_secs(1);
        assert!(!state.allow(&udp, &packet, &flows, &next_id, shutdown));
        assert_eq!(next_id.load(Ordering::Relaxed), 12);
    }
}
