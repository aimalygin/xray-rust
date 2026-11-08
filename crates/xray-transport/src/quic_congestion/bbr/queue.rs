//! Xray-core's `bbr/packet_number_indexed_queue.go`: a deque of mostly
//! consecutive packet numbers, each slot present or not. The front is always
//! the lowest present packet; insertion is only allowed past the end, filling
//! skipped numbers with absent slots.
//!
//! Like the original it is not a general container: inserting a packet
//! number far past the end allocates every slot in between.

use std::collections::VecDeque;

use super::{PacketNumber, INVALID_PACKET_NUMBER};

#[derive(Debug, Clone)]
pub(super) struct PacketNumberIndexedQueue<T> {
    entries: VecDeque<Option<T>>,
    number_of_present_entries: usize,
    first_packet: PacketNumber,
}

impl<T> PacketNumberIndexedQueue<T> {
    pub(super) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            number_of_present_entries: 0,
            first_packet: INVALID_PACKET_NUMBER,
        }
    }

    /// `Emplace`: whether the entry was inserted. A packet number at or
    /// below the last one ever inserted is refused.
    pub(super) fn emplace(&mut self, packet_number: PacketNumber, entry: T) -> bool {
        if packet_number == INVALID_PACKET_NUMBER {
            return false;
        }
        if self.is_empty() {
            self.entries.push_back(Some(entry));
            self.number_of_present_entries = 1;
            self.first_packet = packet_number;
            return true;
        }
        // Do not allow insertion out of order.
        if packet_number <= self.last_packet() {
            return false;
        }
        // Handle potentially missing elements.
        let offset = packet_number.wrapping_sub(self.first_packet) as usize;
        for _ in self.entries.len()..offset {
            self.entries.push_back(None);
        }
        self.entries.push_back(Some(entry));
        self.number_of_present_entries += 1;
        true
    }

    /// `GetEntry`.
    pub(super) fn get(&self, packet_number: PacketNumber) -> Option<&T> {
        let index = self.index_of(packet_number)?;
        self.entries[index].as_ref()
    }

    /// `RemoveUpTo`: removes every entry below `packet_number`, then any
    /// absent slots at the front, so the first packet may end up above it.
    pub(super) fn remove_up_to(&mut self, packet_number: PacketNumber) {
        while !self.entries.is_empty()
            && self.first_packet != INVALID_PACKET_NUMBER
            && self.first_packet < packet_number
        {
            if self.entries.pop_front().flatten().is_some() {
                self.number_of_present_entries -= 1;
            }
            self.first_packet += 1;
        }
        self.clear_up();
    }

    pub(super) fn is_empty(&self) -> bool {
        self.number_of_present_entries == 0
    }

    #[cfg(test)]
    pub(super) fn number_of_present_entries(&self) -> usize {
        self.number_of_present_entries
    }

    #[cfg(test)]
    pub(super) fn first_packet(&self) -> PacketNumber {
        self.first_packet
    }

    /// The last packet number ever inserted, which may have been removed
    /// since; invalid when empty.
    pub(super) fn last_packet(&self) -> PacketNumber {
        if self.is_empty() {
            return INVALID_PACKET_NUMBER;
        }
        self.first_packet + self.entries.len() as PacketNumber - 1
    }

    fn clear_up(&mut self) {
        while matches!(self.entries.front(), Some(None)) {
            self.entries.pop_front();
            self.first_packet += 1;
        }
        if self.entries.is_empty() {
            self.first_packet = INVALID_PACKET_NUMBER;
        }
    }

    fn index_of(&self, packet_number: PacketNumber) -> Option<usize> {
        if packet_number == INVALID_PACKET_NUMBER
            || self.is_empty()
            || packet_number < self.first_packet
        {
            return None;
        }
        let offset = packet_number.wrapping_sub(self.first_packet) as usize;
        (offset < self.entries.len()).then_some(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_numbers_are_absent_and_out_of_order_inserts_refused() {
        let mut queue = PacketNumberIndexedQueue::new();
        assert!(queue.emplace(5, 'a'));
        assert!(queue.emplace(8, 'b'));
        assert!(!queue.emplace(7, 'c'), "below the last packet");
        assert!(!queue.emplace(8, 'c'), "already inserted");
        assert_eq!(queue.get(5), Some(&'a'));
        assert_eq!(queue.get(6), None);
        assert_eq!(queue.get(8), Some(&'b'));
        assert_eq!(queue.get(9), None);
        assert_eq!(queue.last_packet(), 8);
        assert_eq!(queue.number_of_present_entries(), 2);
    }

    #[test]
    fn removing_up_to_a_packet_also_drops_absent_front_slots() {
        let mut queue = PacketNumberIndexedQueue::new();
        for pn in [1, 2, 6] {
            assert!(queue.emplace(pn, pn));
        }
        queue.remove_up_to(3);
        // 3, 4 and 5 were never present: the front jumps to 6.
        assert_eq!(queue.first_packet, 6);
        assert_eq!(queue.get(2), None);
        queue.remove_up_to(100);
        assert!(queue.is_empty());
        assert_eq!(queue.first_packet, INVALID_PACKET_NUMBER);
        assert_eq!(queue.last_packet(), INVALID_PACKET_NUMBER);
        assert!(queue.emplace(3, 3), "an empty queue accepts any number");
    }
}
