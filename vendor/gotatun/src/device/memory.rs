// SPDX-License-Identifier: MPL-2.0
//! Optional packet-memory admission for the injected mobile device adapter.
//! Budgets cover engine-owned packet storage, not caller adapters or process RSS.
use crate::packet::Packet;
use bytes::BytesMut;
use std::sync::{Arc, Mutex};

/// One normalized allocation and its temporary encryption copy.
pub const PACKET_ALLOCATION_BYTES: usize = 4096;
pub const PACKET_RESERVATION_BYTES: usize = PACKET_ALLOCATION_BYTES * 2;

/// Immutable limits, validated before socket creation. Opt-in; stock defaults are unchanged.
#[derive(Clone, Debug)]
pub struct DeviceLimits {
    pub io_queue_packets: usize,
    pub cached_pool_packets: usize,
    pub packet_reservations: usize,
    pub control_reservations: usize,
    pub pending_packets: usize,
    pub pending_packets_per_peer: usize,
    pub pending_bytes_per_peer: usize,
    pub max_ip_packet_size: usize,
    pub max_udp_packet_size: usize,
    pub max_peers: usize,
    pub max_allowed_ips: usize,
    pub rate_limit_sources: usize,
}
impl DeviceLimits {
    pub const fn mobile() -> Self {
        Self {
            io_queue_packets: 16,
            cached_pool_packets: 32,
            packet_reservations: 64,
            control_reservations: 8,
            pending_packets: 16,
            pending_packets_per_peer: 8,
            pending_bytes_per_peer: 12 * 1024,
            max_ip_packet_size: 1420,
            max_udp_packet_size: 1500,
            max_peers: 8,
            max_allowed_ips: 256,
            rate_limit_sources: 128,
        }
    }
    pub fn validate(&self) -> Result<(), super::Error> {
        let valid = (1..=64).contains(&self.io_queue_packets)
            && self.cached_pool_packets <= 128
            && (4..=256).contains(&self.packet_reservations)
            && (1..=16).contains(&self.control_reservations)
            && self.control_reservations < self.packet_reservations
            && self.pending_packets > 0
            && self.pending_packets < self.packet_reservations - self.control_reservations
            && (1..=32).contains(&self.pending_packets_per_peer)
            && self.pending_packets_per_peer <= self.pending_packets
            && (1..=64 * 1024).contains(&self.pending_bytes_per_peer)
            && (576..=3500).contains(&self.max_ip_packet_size)
            && self.max_udp_packet_size >= self.max_ip_packet_size + 64
            && self.max_udp_packet_size <= PACKET_ALLOCATION_BYTES
            && (1..=32).contains(&self.max_peers)
            && (1..=4096).contains(&self.max_allowed_ips)
            && (1..=4096).contains(&self.rate_limit_sources);
        if valid {
            Ok(())
        } else {
            Err(super::Error::InvalidMemoryLimits)
        }
    }
}

/// Live counters contain no peer identities, packet contents or keys.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemorySnapshot {
    pub reservations: usize,
    pub data_reservations: usize,
    pub peak_reservations: usize,
    pub pending_packets: usize,
    pub peak_pending_packets: usize,
    pub admission_drops: u64,
    pub oversized_drops: u64,
    pub pending_drops: u64,
}
impl MemorySnapshot {
    pub fn reserved_packet_bytes(&self) -> usize {
        self.reservations * PACKET_RESERVATION_BYTES
    }
}
#[derive(Clone)]
pub(crate) struct MemoryBudget(Arc<BudgetInner>);
struct BudgetInner {
    limits: DeviceLimits,
    state: Mutex<MemorySnapshot>,
}
impl MemoryBudget {
    pub(crate) fn new(limits: DeviceLimits) -> Self {
        Self(Arc::new(BudgetInner {
            limits,
            state: Mutex::new(MemorySnapshot::default()),
        }))
    }
    pub(crate) fn limits(&self) -> &DeviceLimits {
        &self.0.limits
    }
    pub(crate) fn snapshot(&self) -> MemorySnapshot {
        *self.0.state.lock().unwrap()
    }
    /// Copy at entry so a small slice cannot retain an oversized adapter allocation.
    /// Already-owned packets keep their reservation across queues and cryptography.
    pub(crate) fn admit(&self, packet: Packet, max_len: usize, control: bool) -> Option<Packet> {
        if packet.len() > max_len {
            self.0.state.lock().unwrap().oversized_drops += 1;
            return None;
        }
        if packet
            .memory_lease()
            .is_some_and(|l| Arc::ptr_eq(&l.budget.0, &self.0))
        {
            return Some(packet);
        }
        let lease = self.reserve(control)?;
        let mut bytes = BytesMut::with_capacity(PACKET_ALLOCATION_BYTES);
        bytes.extend_from_slice(&packet);
        let mut normalized = Packet::from_bytes(bytes);
        normalized.set_memory_lease(Some(lease));
        Some(normalized)
    }
    fn reserve(&self, control: bool) -> Option<MemoryLease> {
        let mut state = self.0.state.lock().unwrap();
        if state.reservations >= self.limits().packet_reservations
            || (!control
                && state.data_reservations
                    >= self.limits().packet_reservations - self.limits().control_reservations)
        {
            state.admission_drops += 1;
            return None;
        }
        state.reservations += 1;
        state.data_reservations += usize::from(!control);
        state.peak_reservations = state.peak_reservations.max(state.reservations);
        Some(MemoryLease {
            budget: self.clone(),
            control,
            pending: false,
        })
    }
    pub(crate) fn pending_drop(&self) {
        self.0.state.lock().unwrap().pending_drops += 1;
    }
}

pub(crate) struct MemoryLease {
    budget: MemoryBudget,
    control: bool,
    pending: bool,
}
impl MemoryLease {
    pub(crate) fn mark_pending(&mut self) -> bool {
        if self.pending {
            return true;
        }
        let mut state = self.budget.0.state.lock().unwrap();
        if state.pending_packets >= self.budget.limits().pending_packets {
            state.pending_drops += 1;
            return false;
        }
        state.pending_packets += 1;
        state.peak_pending_packets = state.peak_pending_packets.max(state.pending_packets);
        self.pending = true;
        true
    }
    pub(crate) fn clear_pending(&mut self) {
        if self.pending {
            self.budget.0.state.lock().unwrap().pending_packets -= 1;
            self.pending = false;
        }
    }
}
impl Drop for MemoryLease {
    fn drop(&mut self) {
        let mut state = self.budget.0.state.lock().unwrap();
        state.reservations -= 1;
        state.data_reservations -= usize::from(!self.control);
        state.pending_packets -= usize::from(self.pending);
    }
}

pub(crate) fn is_control(packet: &[u8]) -> bool {
    matches!(
        (packet.first(), packet.len()),
        (Some(1), 148) | (Some(2), 92) | (Some(3), 64)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Barrier, thread};

    #[test]
    fn data_saturation_preserves_control_slots_and_releases_all_leases() {
        let memory = MemoryBudget::new(DeviceLimits::mobile());
        for _ in 0..100 {
            let data: Vec<_> = (0..56)
                .map(|_| {
                    memory
                        .admit(Packet::copy_from(&[0; 1420][..]), 1420, false)
                        .unwrap()
                })
                .collect();
            assert!(
                memory
                    .admit(Packet::copy_from(&[0; 1][..]), 1420, false)
                    .is_none()
            );
            let control: Vec<_> = (0..8)
                .map(|_| {
                    memory
                        .admit(Packet::copy_from(&[1; 148][..]), 1500, true)
                        .unwrap()
                })
                .collect();
            assert!(
                memory
                    .admit(Packet::copy_from(&[1; 148][..]), 1500, true)
                    .is_none()
            );
            assert_eq!(memory.snapshot().reserved_packet_bytes(), 512 * 1024);
            drop((data, control));
            assert_eq!(memory.snapshot().reservations, 0);
        }
        assert_eq!(memory.snapshot().peak_reservations, 64);
    }

    #[test]
    fn small_slice_cannot_retain_large_adapter_allocation() {
        let memory = MemoryBudget::new(DeviceLimits::mobile());
        let mut large = BytesMut::zeroed(4 * 1024 * 1024);
        let slice = large.split_to(1420);
        let old = slice.as_ptr();
        drop(large);
        let packet = memory
            .admit(Packet::from_bytes(slice), 1420, false)
            .unwrap();
        assert_ne!(packet.as_ptr(), old);
        let mut packet = memory.admit(packet, 1420, false).unwrap();
        assert_eq!(packet.buf_mut().capacity(), PACKET_ALLOCATION_BYTES);
        assert_eq!(memory.snapshot().reservations, 1);
        drop(packet);
        assert_eq!(memory.snapshot().reservations, 0);
        assert!(
            memory
                .admit(Packet::copy_from(&[0; 1421][..]), 1420, false)
                .is_none()
        );
        assert_eq!(memory.snapshot().oversized_drops, 1);
    }

    #[test]
    fn concurrent_admission_stays_bounded_under_pressure() {
        let memory = MemoryBudget::new(DeviceLimits::mobile());
        let barrier = Barrier::new(16);
        thread::scope(|scope| {
            for _ in 0..16 {
                let memory = &memory;
                let barrier = &barrier;
                scope.spawn(move || {
                    for _ in 0..100 {
                        let held: Vec<_> = (0..8)
                            .filter_map(|_| {
                                memory.admit(Packet::copy_from(&[0; 1420][..]), 1420, false)
                            })
                            .collect();
                        barrier.wait();
                        for _ in 0..100 {
                            drop(memory.admit(Packet::copy_from(&[0; 1420][..]), 1420, false));
                        }
                        assert!(memory.snapshot().reservations <= 56);
                        barrier.wait();
                        drop(held);
                        barrier.wait();
                    }
                });
            }
        });
        let stats = memory.snapshot();
        assert_eq!(stats.reservations, 0);
        assert_eq!(stats.peak_reservations, 56);
        assert!(stats.admission_drops >= 160_000);
    }

    #[test]
    fn transferred_lease_survives_original_packet_drop() {
        let memory = MemoryBudget::new(DeviceLimits::mobile());
        let mut input = memory
            .admit(Packet::copy_from(&[0; 1420][..]), 1420, false)
            .unwrap();
        let mut output = Packet::from_bytes(BytesMut::zeroed(1452));
        input.transfer_memory_to(&mut output);
        drop(input);
        assert_eq!(memory.snapshot().reservations, 1);
        drop(output);
        assert_eq!(memory.snapshot().reservations, 0);
    }
}
