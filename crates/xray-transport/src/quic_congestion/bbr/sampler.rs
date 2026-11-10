//! Xray-core's `bbr/bandwidth_sampler.go`: a bandwidth sample for every
//! acknowledged packet, the minimum of the slope of bytes sent and the slope
//! of bytes acknowledged between that packet and the packet acknowledged
//! last before it was sent, plus the ack-aggregation ("ack height") tracker.
//!
//! Once the sender reports being application-limited, every packet sent
//! until a packet sent after that report is acknowledged yields an
//! application-limited sample.
//!
//! Xray never enables the options `BBRB` (limiting the ack-height tracker by
//! the send rate) or starting a new aggregation epoch after a full round, so
//! those branches, and the statistics only they read, are left out.

use std::cmp::Ordering;
use std::collections::VecDeque;

use super::filter::WindowedFilter;
use super::queue::PacketNumberIndexedQueue;
use super::{
    bandwidth_from_delta, bytes_from_bandwidth_and_time_delta, AckedPacket, Bandwidth, ByteCount,
    LostPacket, Nanos, PacketNumber, RoundTripCount, Time, INF_BANDWIDTH, INVALID_PACKET_NUMBER,
};

/// `infRTT`: no RTT sample.
pub(super) const INF_RTT: Nanos = i64::MAX;

/// The connection's totals when a packet was sent, returned when it is
/// acknowledged or lost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct SendTimeState {
    pub(super) is_valid: bool,
    /// Whether the sender was application-limited when the packet was sent.
    pub(super) is_app_limited: bool,
    /// Bytes sent so far, including this packet.
    pub(super) total_bytes_sent: ByteCount,
    pub(super) total_bytes_acked: ByteCount,
    pub(super) total_bytes_lost: ByteCount,
    /// Bytes in flight as the sampler recorded them for this packet.
    pub(super) bytes_in_flight: ByteCount,
}

/// `extraAckedEvent`, compared by `extra_acked` alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ExtraAckedEvent {
    extra_acked: ByteCount,
    bytes_acked: ByteCount,
    time_delta: Nanos,
    round: RoundTripCount,
}

fn compare_extra_acked(a: &ExtraAckedEvent, b: &ExtraAckedEvent) -> Ordering {
    a.extra_acked.cmp(&b.extra_acked)
}

#[derive(Debug, Clone, Copy)]
struct BandwidthSample {
    bandwidth: Bandwidth,
    rtt: Nanos,
    state_at_send: SendTimeState,
}

impl BandwidthSample {
    fn new() -> Self {
        Self {
            bandwidth: 0,
            rtt: 0,
            state_at_send: SendTimeState::default(),
        }
    }
}

/// `maxAckHeightTracker`: the most bytes acknowledged beyond what the
/// estimated bandwidth explains, over a window of round trips.
#[derive(Debug, Clone)]
struct MaxAckHeightTracker {
    max_ack_height_filter: WindowedFilter<ExtraAckedEvent>,
    aggregation_epoch_start_time: Time,
    aggregation_epoch_bytes: ByteCount,
    ack_aggregation_bandwidth_threshold: f64,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

impl MaxAckHeightTracker {
    fn new(window_length: RoundTripCount) -> Self {
        Self {
            max_ack_height_filter: WindowedFilter::new(window_length, compare_extra_acked),
            aggregation_epoch_start_time: 0,
            aggregation_epoch_bytes: 0,
            ack_aggregation_bandwidth_threshold: 1.0,
            reduce_extra_acked_on_bandwidth_increase: false,
        }
    }

    fn get(&self) -> ByteCount {
        self.max_ack_height_filter.best().extra_acked
    }

    fn update(
        &mut self,
        bandwidth_estimate: Bandwidth,
        is_new_max_bandwidth: bool,
        round_trip_count: RoundTripCount,
        ack_time: Time,
        bytes_acked: ByteCount,
    ) -> ByteCount {
        if self.reduce_extra_acked_on_bandwidth_increase && is_new_max_bandwidth {
            // Save and clear existing entries, then reinsert them after
            // recalculating against the new bandwidth.
            let saved = [
                self.max_ack_height_filter.best(),
                self.max_ack_height_filter.second_best(),
                self.max_ack_height_filter.third_best(),
            ];
            self.max_ack_height_filter.clear();
            for mut event in saved {
                let expected =
                    bytes_from_bandwidth_and_time_delta(bandwidth_estimate, event.time_delta);
                if expected < event.bytes_acked {
                    event.extra_acked = event.bytes_acked - expected;
                    self.max_ack_height_filter.update(event, event.round);
                }
            }
        }

        if self.aggregation_epoch_start_time == 0 {
            self.start_epoch(bytes_acked, ack_time);
            return 0;
        }

        // How many bytes the estimated bandwidth would have delivered.
        let aggregation_delta = ack_time.wrapping_sub(self.aggregation_epoch_start_time);
        let expected_bytes_acked =
            bytes_from_bandwidth_and_time_delta(bandwidth_estimate, aggregation_delta);
        // Reset the epoch as soon as the ack arrival rate is at most the
        // bandwidth.
        if self.aggregation_epoch_bytes
            <= (self.ack_aggregation_bandwidth_threshold * expected_bytes_acked as f64) as ByteCount
        {
            self.start_epoch(bytes_acked, ack_time);
            return 0;
        }

        self.aggregation_epoch_bytes = self.aggregation_epoch_bytes.wrapping_add(bytes_acked);

        // Extra bytes delivered compared with the bandwidth.
        let extra_bytes_acked = self
            .aggregation_epoch_bytes
            .wrapping_sub(expected_bytes_acked);
        let new_event = ExtraAckedEvent {
            extra_acked: extra_bytes_acked,
            bytes_acked: self.aggregation_epoch_bytes,
            time_delta: aggregation_delta,
            // Go leaves the round of a measured event at zero.
            round: 0,
        };
        self.max_ack_height_filter
            .update(new_event, round_trip_count);
        extra_bytes_acked
    }

    fn start_epoch(&mut self, bytes_acked: ByteCount, ack_time: Time) {
        self.aggregation_epoch_bytes = bytes_acked;
        self.aggregation_epoch_start_time = ack_time;
    }

    fn reset(&mut self, new_height: ByteCount, new_time: RoundTripCount) {
        let event = ExtraAckedEvent {
            extra_acked: new_height,
            round: new_time,
            ..ExtraAckedEvent::default()
        };
        self.max_ack_height_filter.reset(event, new_time);
    }
}

/// `ackPoint`: a point on the acknowledged-bytes line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AckPoint {
    ack_time: Time,
    total_bytes_acked: ByteCount,
}

/// `recentAckPoints`: the latest two ack points at distinct times.
#[derive(Debug, Clone, Copy, Default)]
struct RecentAckPoints {
    ack_points: [AckPoint; 2],
}

impl RecentAckPoints {
    fn update(&mut self, ack_time: Time, total_bytes_acked: ByteCount) {
        if ack_time < self.ack_points[1].ack_time {
            self.ack_points[1].ack_time = ack_time;
        } else if ack_time > self.ack_points[1].ack_time {
            self.ack_points[0] = self.ack_points[1];
            self.ack_points[1].ack_time = ack_time;
        }
        self.ack_points[1].total_bytes_acked = total_bytes_acked;
    }

    fn clear(&mut self) {
        self.ack_points = [AckPoint::default(); 2];
    }

    fn most_recent_point(&self) -> AckPoint {
        self.ack_points[1]
    }

    fn less_recent_point(&self) -> AckPoint {
        if self.ack_points[0].total_bytes_acked != 0 {
            self.ack_points[0]
        } else {
            self.ack_points[1]
        }
    }
}

/// `connectionStateOnSentPacket`: a sent packet and the sampler's state when
/// it was sent.
#[derive(Debug, Clone, Copy)]
struct ConnectionStateOnSentPacket {
    sent_time: Time,
    size: ByteCount,
    total_bytes_sent_at_last_acked_packet: ByteCount,
    last_acked_packet_sent_time: Time,
    last_acked_packet_ack_time: Time,
    send_time_state: SendTimeState,
}

/// `congestionEventSample`: what one congestion event tells the sender.
#[derive(Debug, Clone, Copy)]
pub(super) struct CongestionEventSample {
    /// The largest bandwidth sample, zero without one.
    pub(super) sample_max_bandwidth: Bandwidth,
    /// Whether that sample is application-limited.
    pub(super) sample_is_app_limited: bool,
    /// The smallest RTT sample, [`INF_RTT`] without one.
    pub(super) sample_rtt: Nanos,
    /// The send state of the largest acknowledged packet, or without one,
    /// of the largest lost packet.
    pub(super) last_packet_send_state: SendTimeState,
    /// Bytes acknowledged beyond what the bandwidth explains.
    pub(super) extra_acked: ByteCount,
}

impl CongestionEventSample {
    fn new() -> Self {
        Self {
            sample_max_bandwidth: 0,
            sample_is_app_limited: false,
            sample_rtt: INF_RTT,
            last_packet_send_state: SendTimeState::default(),
            extra_acked: 0,
        }
    }
}

/// `bandwidthSampler`.
#[derive(Debug, Clone)]
pub(super) struct BandwidthSampler {
    total_bytes_sent: ByteCount,
    total_bytes_acked: ByteCount,
    total_bytes_lost: ByteCount,
    total_bytes_sent_at_last_acked_packet: ByteCount,
    last_acked_packet_sent_time: Time,
    last_acked_packet_ack_time: Time,
    last_sent_packet: PacketNumber,
    is_app_limited: bool,
    end_of_app_limited_phase: PacketNumber,
    connection_state_map: PacketNumberIndexedQueue<ConnectionStateOnSentPacket>,
    recent_ack_points: RecentAckPoints,
    a0_candidates: VecDeque<AckPoint>,
    max_ack_height_tracker: MaxAckHeightTracker,
    total_bytes_acked_after_last_ack_event: ByteCount,
    /// Connection option `BSAO`.
    overestimate_avoidance: bool,
}

impl BandwidthSampler {
    pub(super) fn new(max_ack_height_tracker_window_length: RoundTripCount) -> Self {
        Self {
            total_bytes_sent: 0,
            total_bytes_acked: 0,
            total_bytes_lost: 0,
            total_bytes_sent_at_last_acked_packet: 0,
            last_acked_packet_sent_time: 0,
            last_acked_packet_ack_time: 0,
            last_sent_packet: INVALID_PACKET_NUMBER,
            is_app_limited: false,
            end_of_app_limited_phase: INVALID_PACKET_NUMBER,
            connection_state_map: PacketNumberIndexedQueue::new(),
            recent_ack_points: RecentAckPoints::default(),
            a0_candidates: VecDeque::new(),
            max_ack_height_tracker: MaxAckHeightTracker::new(max_ack_height_tracker_window_length),
            total_bytes_acked_after_last_ack_event: 0,
            overestimate_avoidance: false,
        }
    }

    pub(super) fn max_ack_height(&self) -> ByteCount {
        self.max_ack_height_tracker.get()
    }

    pub(super) fn reset_max_ack_height_tracker(
        &mut self,
        new_height: ByteCount,
        new_time: RoundTripCount,
    ) {
        self.max_ack_height_tracker.reset(new_height, new_time);
    }

    pub(super) fn set_reduce_extra_acked_on_bandwidth_increase(&mut self, value: bool) {
        self.max_ack_height_tracker
            .reduce_extra_acked_on_bandwidth_increase = value;
    }

    pub(super) fn enable_overestimate_avoidance(&mut self) {
        if self.overestimate_avoidance {
            return;
        }
        self.overestimate_avoidance = true;
        self.max_ack_height_tracker
            .ack_aggregation_bandwidth_threshold = 2.0;
    }

    #[cfg(test)]
    pub(super) fn is_overestimate_avoidance_enabled(&self) -> bool {
        self.overestimate_avoidance
    }

    #[cfg(test)]
    pub(super) fn reduces_extra_acked_on_bandwidth_increase(&self) -> bool {
        self.max_ack_height_tracker
            .reduce_extra_acked_on_bandwidth_increase
    }

    /// `OnPacketSent`. `bytes_in_flight` is what the transport reports with
    /// the packet; a packet sent with nothing in flight opens a new A0 point.
    pub(super) fn on_packet_sent(
        &mut self,
        sent_time: Time,
        packet_number: PacketNumber,
        bytes: ByteCount,
        bytes_in_flight: ByteCount,
        is_retransmittable: bool,
    ) {
        self.last_sent_packet = packet_number;

        if !is_retransmittable {
            return;
        }

        self.total_bytes_sent = self.total_bytes_sent.wrapping_add(bytes);

        // With nothing in flight, the time this transmission opens is the A0
        // point: it underestimates bandwidth somewhat, but yields samples
        // where there would be none, most importantly at the start.
        if bytes_in_flight == 0 {
            self.last_acked_packet_ack_time = sent_time;
            if self.overestimate_avoidance {
                self.recent_ack_points.clear();
                self.recent_ack_points
                    .update(sent_time, self.total_bytes_acked);
                self.a0_candidates.clear();
                self.a0_candidates
                    .push_back(self.recent_ack_points.most_recent_point());
            }
            self.total_bytes_sent_at_last_acked_packet = self.total_bytes_sent;
            // Ack compression is not a concern here: the send rate is
            // effectively infinite.
            self.last_acked_packet_sent_time = sent_time;
        }

        let state = ConnectionStateOnSentPacket {
            sent_time,
            size: bytes,
            total_bytes_sent_at_last_acked_packet: self.total_bytes_sent_at_last_acked_packet,
            last_acked_packet_sent_time: self.last_acked_packet_sent_time,
            last_acked_packet_ack_time: self.last_acked_packet_ack_time,
            send_time_state: SendTimeState {
                is_valid: true,
                is_app_limited: self.is_app_limited,
                total_bytes_sent: self.total_bytes_sent,
                total_bytes_acked: self.total_bytes_acked,
                total_bytes_lost: self.total_bytes_lost,
                bytes_in_flight: bytes_in_flight.wrapping_add(bytes),
            },
        };
        self.connection_state_map.emplace(packet_number, state);
    }

    /// `OnCongestionEvent`.
    pub(super) fn on_congestion_event(
        &mut self,
        ack_time: Time,
        acked_packets: &[AckedPacket],
        lost_packets: &[LostPacket],
        max_bandwidth: Bandwidth,
        est_bandwidth_upper_bound: Bandwidth,
        round_trip_count: RoundTripCount,
    ) -> CongestionEventSample {
        let mut event_sample = CongestionEventSample::new();

        let mut last_lost_packet_send_state = SendTimeState::default();
        for packet in lost_packets {
            let send_state = self.on_packet_lost(packet.packet_number, packet.bytes_lost);
            if send_state.is_valid {
                last_lost_packet_send_state = send_state;
            }
        }

        if acked_packets.is_empty() {
            // Only populate the send state for a loss-only event.
            event_sample.last_packet_send_state = last_lost_packet_send_state;
            return event_sample;
        }

        let mut last_acked_packet_send_state = SendTimeState::default();
        for packet in acked_packets {
            let sample = self.on_packet_acknowledged(ack_time, packet.packet_number);
            if !sample.state_at_send.is_valid {
                continue;
            }

            last_acked_packet_send_state = sample.state_at_send;

            if sample.rtt != 0 {
                event_sample.sample_rtt = event_sample.sample_rtt.min(sample.rtt);
            }
            if sample.bandwidth > event_sample.sample_max_bandwidth {
                event_sample.sample_max_bandwidth = sample.bandwidth;
                event_sample.sample_is_app_limited = sample.state_at_send.is_app_limited;
            }
        }

        event_sample.last_packet_send_state = if !last_lost_packet_send_state.is_valid {
            last_acked_packet_send_state
        } else if !last_acked_packet_send_state.is_valid {
            last_lost_packet_send_state
        } else if lost_packets[lost_packets.len() - 1].packet_number
            > acked_packets[acked_packets.len() - 1].packet_number
        {
            // A late loss alarm can declare the later of two packets lost
            // after the first was acknowledged.
            last_lost_packet_send_state
        } else {
            last_acked_packet_send_state
        };

        let is_new_max_bandwidth = event_sample.sample_max_bandwidth > max_bandwidth;
        let max_bandwidth = max_bandwidth.max(event_sample.sample_max_bandwidth);

        event_sample.extra_acked = self.on_ack_event_end(
            est_bandwidth_upper_bound.min(max_bandwidth),
            is_new_max_bandwidth,
            round_trip_count,
        );

        event_sample
    }

    fn on_packet_lost(
        &mut self,
        packet_number: PacketNumber,
        bytes_lost: ByteCount,
    ) -> SendTimeState {
        self.total_bytes_lost = self.total_bytes_lost.wrapping_add(bytes_lost);
        self.connection_state_map
            .get(packet_number)
            .map(|sent| SendTimeState {
                is_valid: true,
                ..sent.send_time_state
            })
            .unwrap_or_default()
    }

    pub(super) fn on_app_limited(&mut self) {
        self.is_app_limited = true;
        self.end_of_app_limited_phase = self.last_sent_packet;
    }

    pub(super) fn remove_obsolete_packets(&mut self, least_unacked: PacketNumber) {
        self.connection_state_map.remove_up_to(least_unacked);
    }

    pub(super) fn total_bytes_acked(&self) -> ByteCount {
        self.total_bytes_acked
    }

    pub(super) fn total_bytes_lost(&self) -> ByteCount {
        self.total_bytes_lost
    }

    /// The sampler's part of the state Xray-core's oracle digests, in its
    /// order.
    #[cfg(test)]
    pub(super) fn oracle_state(&self) -> Vec<String> {
        let tracker = &self.max_ack_height_tracker;
        let heights = &tracker.max_ack_height_filter;
        [
            self.total_bytes_sent,
            self.total_bytes_acked,
            self.total_bytes_lost,
            self.total_bytes_sent_at_last_acked_packet,
            self.last_acked_packet_sent_time,
            self.last_acked_packet_ack_time,
            self.last_sent_packet,
            i64::from(self.is_app_limited),
            self.end_of_app_limited_phase,
            self.total_bytes_acked_after_last_ack_event,
            self.connection_state_map.number_of_present_entries() as i64,
            self.connection_state_map.first_packet(),
            self.a0_candidates.len() as i64,
            tracker.aggregation_epoch_start_time,
            tracker.aggregation_epoch_bytes,
            heights.best().extra_acked,
            heights.second_best().extra_acked,
            heights.third_best().extra_acked,
        ]
        .iter()
        .map(ToString::to_string)
        .collect()
    }

    fn choose_a0_point(&mut self, total_bytes_acked: ByteCount) -> Option<AckPoint> {
        if self.a0_candidates.is_empty() {
            return None;
        }
        if self.a0_candidates.len() == 1 {
            return self.a0_candidates.front().copied();
        }
        for i in 1..self.a0_candidates.len() {
            if self.a0_candidates[i].total_bytes_acked > total_bytes_acked {
                let a0 = self.a0_candidates[i - 1];
                if i > 1 {
                    self.a0_candidates.drain(..i - 1);
                }
                return Some(a0);
            }
        }
        let a0 = self.a0_candidates.back().copied();
        // Go pops while `k < Len()-1`, re-reading the shrinking length, so it
        // drops half the candidates rather than all but the last.
        let popped = self.a0_candidates.len() / 2;
        self.a0_candidates.drain(..popped);
        a0
    }

    fn on_packet_acknowledged(
        &mut self,
        ack_time: Time,
        packet_number: PacketNumber,
    ) -> BandwidthSample {
        let mut sample = BandwidthSample::new();
        let Some(sent) = self.connection_state_map.get(packet_number).copied() else {
            return sample;
        };

        self.total_bytes_acked = self.total_bytes_acked.wrapping_add(sent.size);
        self.total_bytes_sent_at_last_acked_packet = sent.send_time_state.total_bytes_sent;
        self.last_acked_packet_sent_time = sent.sent_time;
        self.last_acked_packet_ack_time = ack_time;
        if self.overestimate_avoidance {
            self.recent_ack_points
                .update(ack_time, self.total_bytes_acked);
        }

        if self.is_app_limited {
            // Leave the application-limited phase once a packet sent after
            // it began is acknowledged, or if it never had an end.
            if self.end_of_app_limited_phase == INVALID_PACKET_NUMBER
                || packet_number > self.end_of_app_limited_phase
            {
                self.is_app_limited = false;
            }
        }

        // No packet may have been acknowledged when this one was sent, in
        // which case there is no bandwidth sample.
        if sent.last_acked_packet_sent_time == 0 {
            return sample;
        }

        // An infinite rate discards the send rate and keeps the ack rate.
        let mut send_rate = INF_BANDWIDTH;
        if sent.sent_time > sent.last_acked_packet_sent_time {
            send_rate = bandwidth_from_delta(
                sent.send_time_state
                    .total_bytes_sent
                    .wrapping_sub(sent.total_bytes_sent_at_last_acked_packet),
                sent.sent_time
                    .wrapping_sub(sent.last_acked_packet_sent_time),
            );
        }

        let a0 = match self
            .overestimate_avoidance
            .then(|| self.choose_a0_point(sent.send_time_state.total_bytes_acked))
            .flatten()
        {
            Some(a0) => a0,
            None => AckPoint {
                ack_time: sent.last_acked_packet_ack_time,
                total_bytes_acked: sent.send_time_state.total_bytes_acked,
            },
        };

        // The acknowledgement must come after the previous one, or the slope
        // divides by zero or underflows.
        if ack_time.wrapping_sub(a0.ack_time) <= 0 {
            return sample;
        }

        let ack_rate = bandwidth_from_delta(
            self.total_bytes_acked.wrapping_sub(a0.total_bytes_acked),
            ack_time.wrapping_sub(a0.ack_time),
        );

        sample.bandwidth = send_rate.min(ack_rate);
        // Not corrected for delayed acknowledgement: RTTs here can be high,
        // especially at low bandwidth.
        sample.rtt = ack_time.wrapping_sub(sent.sent_time);
        sample.state_at_send = SendTimeState {
            is_valid: true,
            ..sent.send_time_state
        };
        sample
    }

    fn on_ack_event_end(
        &mut self,
        bandwidth_estimate: Bandwidth,
        is_new_max_bandwidth: bool,
        round_trip_count: RoundTripCount,
    ) -> ByteCount {
        let newly_acked_bytes = self
            .total_bytes_acked
            .wrapping_sub(self.total_bytes_acked_after_last_ack_event);
        if newly_acked_bytes == 0 {
            return 0;
        }
        self.total_bytes_acked_after_last_ack_event = self.total_bytes_acked;
        let extra_acked = self.max_ack_height_tracker.update(
            bandwidth_estimate,
            is_new_max_bandwidth,
            round_trip_count,
            self.last_acked_packet_ack_time,
            newly_acked_bytes,
        );
        // Zero marks a new aggregation epoch: the last ack point of the one
        // before is an A0 candidate.
        if self.overestimate_avoidance && extra_acked == 0 {
            self.a0_candidates
                .push_back(self.recent_ack_points.less_recent_point());
        }
        extra_acked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Nanos = 1_000_000;
    const T: Time = 3_600_000 * MS;

    fn acked(packet_number: PacketNumber) -> AckedPacket {
        AckedPacket {
            packet_number,
            bytes_acked: 1000,
        }
    }

    fn lost(packet_number: PacketNumber) -> LostPacket {
        LostPacket {
            packet_number,
            bytes_lost: 1000,
        }
    }

    /// Packet 0 acknowledged, then packet 1 sent normally and packet 2 in
    /// an application-limited phase.
    fn sampler() -> BandwidthSampler {
        let mut sampler = BandwidthSampler::new(10);
        sampler.on_packet_sent(T, 0, 1000, 1000, true);
        sampler.on_congestion_event(T + 40 * MS, &[acked(0)], &[], 0, INF_BANDWIDTH, 1);
        sampler.on_packet_sent(T + 41 * MS, 1, 1000, 1000, true);
        sampler.on_app_limited();
        sampler.on_packet_sent(T + 42 * MS, 2, 1000, 2000, true);
        sampler
    }

    #[test]
    fn the_later_of_an_events_last_packets_supplies_the_send_state() {
        // A late loss alarm: packet 2 lost after packet 1 was acknowledged.
        let event = sampler().on_congestion_event(
            T + 81 * MS,
            &[acked(1)],
            &[lost(2)],
            0,
            INF_BANDWIDTH,
            2,
        );
        let state = event.last_packet_send_state;
        assert!(
            state.is_app_limited && state.bytes_in_flight == 3000,
            "{state:?}"
        );
        // The usual order: the acknowledged packet is the later one.
        let event = sampler().on_congestion_event(
            T + 82 * MS,
            &[acked(2)],
            &[lost(1)],
            0,
            INF_BANDWIDTH,
            2,
        );
        let state = event.last_packet_send_state;
        assert!(
            state.is_app_limited && state.bytes_in_flight == 3000,
            "{state:?}"
        );
        let event =
            sampler().on_congestion_event(T + 82 * MS, &[acked(1)], &[], 0, INF_BANDWIDTH, 2);
        assert!(!event.last_packet_send_state.is_app_limited);
    }

    #[test]
    fn heights_reinserted_on_a_new_maximum_keep_gos_round_of_zero() {
        let mut tracker = MaxAckHeightTracker::new(10);
        tracker.reduce_extra_acked_on_bandwidth_increase = true;
        let measured = ExtraAckedEvent {
            extra_acked: 5000,
            bytes_acked: 10_000,
            time_delta: 10 * MS,
            round: 0,
        };
        tracker.max_ack_height_filter.update(measured, 15);
        // A new maximum in round 20 recalculates the height and reinserts it
        // at the event's own round, which Go leaves at zero for a measured
        // event, then opens an aggregation epoch.
        let extra = tracker.update(8000, true, 20, T, 3000);
        assert_eq!(extra, 0);
        assert_eq!(tracker.get(), 10_000 - 10);
        // Round 21 is more than ten rounds after round zero: the next
        // measurement replaces the reinserted height.
        let extra = tracker.update(8000, false, 21, T + 1000 * MS, 500);
        assert_eq!(extra, 3000 + 500 - 1000);
        assert_eq!(tracker.get(), 2500);
    }

    /// The first ACK after two idle minutes at 100 Mbit/s: far fewer bytes
    /// than the bandwidth would have delivered, so the epoch restarts and
    /// nothing counts as extra. Go's wrapped product made it a gigabyte.
    #[test]
    fn an_ack_after_a_long_idle_restarts_the_aggregation_epoch() {
        let mut tracker = MaxAckHeightTracker::new(10);
        assert_eq!(tracker.update(100_000_000, false, 1, T, 1200), 0);
        assert_eq!(
            tracker.update(100_000_000, false, 2, T + 120_000 * MS, 1200),
            0
        );
        assert_eq!(tracker.get(), 0);
    }
}
