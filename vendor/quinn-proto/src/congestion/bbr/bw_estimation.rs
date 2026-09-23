use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};

use super::min_max::MinMax;
use crate::{Duration, Instant};

// Loss or abandoned packet-number spaces must not retain unbounded history.
// One entry is shared by packets sent in the same driver batch. Eviction only
// omits a rate sample; ACK accounting and congestion-window updates continue.
const MAX_SEND_BATCHES: usize = 4096;

#[derive(Clone, Copy, Debug)]
struct SendBatch {
    sent: Instant,
    end: u64,
    retired: u64,
    delivered: u64,
    ack_time: Instant,
    last_acked_sent: Instant,
    sent_at_last_ack: u64,
    app_limited: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    total_sent: u64,
    acked_time: Option<Instant>,
    last_acked_sent: Option<Instant>,
    sent_at_last_ack: u64,
    batches: BTreeMap<u64, SendBatch>,
    max_filter: MinMax,
    acked_at_last_window: u64,
    non_app_limited_sample: bool,
}

impl BandwidthEstimation {
    // Compatibility with the original timestamp-only controller callbacks.
    // The transport uses explicit packet tokens and flight state below.
    pub(crate) fn on_sent(&mut self, now: Instant, bytes: u64) {
        self.record_sent(now, bytes, 1, false);
    }

    pub(crate) fn record_sent(
        &mut self,
        now: Instant,
        bytes: u64,
        in_flight: u64,
        app_limited: bool,
    ) -> u64 {
        if bytes == 0 {
            return 0;
        }
        let first = self.total_sent + 1;
        self.total_sent += bytes;
        if in_flight == 0 || self.acked_time.is_none() {
            self.acked_time = Some(now);
            self.last_acked_sent = Some(now);
            self.sent_at_last_ack = self.total_sent;
        }
        let ack_time = self.acked_time.unwrap();
        let last_acked_sent = self.last_acked_sent.unwrap();
        if let Some(mut entry) = self.batches.last_entry() {
            let batch = entry.get_mut();
            if batch.sent == now
                && batch.delivered == self.total_acked
                && batch.ack_time == ack_time
                && batch.last_acked_sent == last_acked_sent
                && batch.sent_at_last_ack == self.sent_at_last_ack
                && batch.app_limited == app_limited
            {
                batch.end = self.total_sent;
                return self.total_sent;
            }
        }
        if self.batches.len() == MAX_SEND_BATCHES {
            self.batches.pop_first();
        }
        self.batches.insert(
            first,
            SendBatch {
                sent: now,
                end: self.total_sent,
                retired: 0,
                delivered: self.total_acked,
                ack_time,
                last_acked_sent,
                sent_at_last_ack: self.sent_at_last_ack,
                app_limited,
            },
        );
        self.total_sent
    }

    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        round: u64,
        app_limited: bool,
    ) {
        // The old interface cannot distinguish reordered equal-time packets.
        // Preserve it for callers that ACK each timestamp batch in send order.
        let token = self
            .batches
            .iter()
            .find_map(|(&first, batch)| {
                (batch.sent == sent).then_some(first - 1 + batch.retired + bytes)
            })
            .unwrap_or(0);
        self.ack_sample(now, sent, bytes, round, token, Some(app_limited));
    }

    pub(crate) fn ack_packet(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        round: u64,
        token: u64,
    ) {
        self.ack_sample(now, sent, bytes, round, token, None);
    }

    fn ack_sample(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        round: u64,
        token: u64,
        legacy_app_limited: Option<bool>,
    ) {
        self.total_acked += bytes;
        let Some((&first, &batch)) = self.batches.range(..=token).next_back() else {
            return;
        };
        if token > batch.end || batch.sent != sent || bytes == 0 {
            return;
        }
        self.batches.get_mut(&first).unwrap().retired += bytes;
        if batch.retired + bytes == batch.end - first + 1 {
            self.batches.remove(&first);
        }

        self.acked_time = Some(now);
        self.last_acked_sent = Some(sent);
        self.sent_at_last_ack = token;

        // Both slopes describe the ACKed packet's own delivery interval.
        // A later burst or compressed ACK spacing cannot replace that interval.
        let send_rate = if sent > batch.last_acked_sent {
            Self::bw_from_delta(
                token.saturating_sub(batch.sent_at_last_ack),
                sent - batch.last_acked_sent,
            )
            .unwrap_or(0)
        } else {
            u64::MAX
        };
        let Some(ack_rate) = Self::bw_from_delta(
            self.total_acked.saturating_sub(batch.delivered),
            now.saturating_duration_since(batch.ack_time),
        ) else {
            return;
        };
        let bandwidth = send_rate.min(ack_rate);
        let app_limited = batch.app_limited || legacy_app_limited.unwrap_or(false);
        if bandwidth != 0 {
            self.non_app_limited_sample |= !app_limited;
            if !app_limited || bandwidth > self.max_filter.get() {
                self.max_filter.update_max(round, bandwidth);
            }
        }
    }

    pub(crate) fn app_limited_this_window(&self) -> bool {
        !self.non_app_limited_sample
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub(crate) fn end_acks(&mut self, _current_round: u64, _app_limited: bool) {
        self.acked_at_last_window = self.total_acked;
        self.non_app_limited_sample = false;
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub(crate) const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let nanos = delta.as_nanos();
        if nanos == 0 {
            return None;
        }
        let rate = (bytes as u128 * 1_000_000_000) / nanos;
        Some(if rate > u64::MAX as u128 {
            u64::MAX
        } else {
            rate as u64
        })
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}

#[cfg(test)]
mod sample_filter_tests {
    use super::*;

    fn first_samples(app_limited: bool) -> (BandwidthEstimation, Instant) {
        let now = Instant::now();
        let mut b = BandwidthEstimation::default();
        b.on_sent(now, 1200);
        b.on_ack(now + Duration::from_millis(10), now, 1200, 0, app_limited);
        b.on_sent(now + Duration::from_millis(10), 1200);
        b.on_ack(
            now + Duration::from_millis(20),
            now + Duration::from_millis(10),
            1200,
            1,
            app_limited,
        );
        (b, now)
    }

    #[test]
    fn packets_in_one_send_and_ack_batch_contribute_to_the_rate() {
        let (mut b, now) = first_samples(false);
        for _ in 0..4 {
            b.on_sent(now + Duration::from_millis(20), 1200);
        }
        for _ in 0..4 {
            b.on_ack(
                now + Duration::from_millis(30),
                now + Duration::from_millis(20),
                1200,
                2,
                false,
            );
        }
        assert_eq!(b.get_estimate(), 480_000);
    }

    #[test]
    fn higher_application_limited_sample_can_initialize_bandwidth() {
        let (b, _) = first_samples(true);
        assert_eq!(b.get_estimate(), 120_000);
    }

    #[test]
    fn lower_non_application_limited_sample_expires_old_peak() {
        let (mut b, now) = first_samples(false);
        assert_eq!(b.get_estimate(), 120_000);
        b.on_sent(now + Duration::from_millis(30), 1200);
        b.on_ack(
            now + Duration::from_millis(40),
            now + Duration::from_millis(30),
            1200,
            12,
            false,
        );
        assert_eq!(b.get_estimate(), 60_000);
    }

    #[test]
    fn lower_application_limited_samples_do_not_lower_peak() {
        let (mut b, now) = first_samples(false);
        b.on_sent(now + Duration::from_millis(30), 1200);
        let ack = now + Duration::from_millis(40);
        b.on_ack(ack, now + Duration::from_millis(30), 1200, 12, true);
        assert_eq!(b.get_estimate(), 120_000);
    }

    #[test]
    fn initial_batch_uses_elapsed_delivery_time() {
        let now = Instant::now();
        let mut b = BandwidthEstimation::default();
        b.on_sent(now, 1200);
        b.on_sent(now, 1200);
        for _ in 0..2 {
            b.on_ack(now + Duration::from_millis(20), now, 1200, 1, false);
        }
        assert_eq!(b.get_estimate(), 120_000);
    }
}

#[cfg(test)]
mod delivery_snapshot_regression {
    use super::*;

    #[test]
    fn compressed_acks_of_old_packets_ignore_new_send_bursts() {
        let t = Instant::now();
        let mut b = BandwidthEstimation::default();
        b.on_sent(t, 1200);
        b.on_ack(t + Duration::from_millis(50), t, 1200, 0, false);
        let a = t + Duration::from_millis(50);
        let c = t + Duration::from_millis(51);
        b.on_sent(a, 1200);
        b.on_sent(c, 1200);
        b.on_sent(t + Duration::from_millis(99), 100_000);
        b.on_sent(t + Duration::from_micros(99_001), 100_000);
        b.on_ack(t + Duration::from_millis(100), a, 1200, 1, false);
        b.on_ack(t + Duration::from_micros(100_001), c, 1200, 1, false);
        assert!(
            b.get_estimate() <= 48_000,
            "new sends cannot define the delivery rate of old ACKed packets: {}",
            b.get_estimate()
        );
        assert_eq!(b.total_acked, 3600);
    }

    #[test]
    fn first_delivery_has_a_send_to_ack_interval() {
        let t = Instant::now();
        let mut b = BandwidthEstimation::default();
        b.on_sent(t, 1200);
        b.on_ack(t + Duration::from_millis(50), t, 1200, 0, false);
        assert_eq!(b.get_estimate(), 24_000);
    }
}

#[cfg(test)]
mod packet_delivery_tests {
    use super::*;

    #[test]
    fn reordered_packets_sharing_a_timestamp_keep_their_send_positions() {
        let t = Instant::now();
        let mut b = BandwidthEstimation::default();
        let a = b.record_sent(t, 1200, 0, false);
        let c = b.record_sent(t, 800, 1200, false);
        let d = b.record_sent(t, 1400, 2000, false);
        assert_eq!(b.batches.len(), 1);
        let now = t + Duration::from_millis(10);
        b.ack_packet(now, t, 1400, 0, d);
        assert_eq!(b.sent_at_last_ack, d);
        b.ack_packet(now, t, 1200, 0, a);
        assert_eq!(b.sent_at_last_ack, a);
        b.ack_packet(now, t, 800, 0, c);
        assert_eq!(b.sent_at_last_ack, c);
        assert!(b.batches.is_empty());
        assert_eq!(b.get_estimate(), 340_000);
        assert_eq!(b.bytes_acked_this_window(), 3400);
    }

    #[test]
    fn compressed_acks_use_exact_tokens_after_packet_reordering() {
        let t = Instant::now();
        let mut b = BandwidthEstimation::default();
        let seed = b.record_sent(t, 1200, 0, false);
        b.ack_packet(t + Duration::from_millis(50), t, 1200, 0, seed);
        let sent = t + Duration::from_millis(50);
        let a = b.record_sent(sent, 1200, 1, false);
        let c = b.record_sent(sent, 800, 1201, false);
        let d = b.record_sent(sent, 1400, 2001, false);
        b.record_sent(t + Duration::from_millis(99), 100_000, 3401, false);
        b.record_sent(t + Duration::from_micros(99_001), 100_000, 103_401, false);
        b.ack_packet(t + Duration::from_millis(100), sent, 1400, 1, d);
        b.ack_packet(t + Duration::from_micros(100_001), sent, 1200, 1, a);
        b.ack_packet(t + Duration::from_micros(100_002), sent, 800, 1, c);
        assert!(b.get_estimate() <= 68_000);
        assert_eq!(b.total_acked, 4600);
    }

    #[test]
    fn idle_time_is_excluded_when_flight_restarts() {
        let t = Instant::now();
        let mut b = BandwidthEstimation::default();
        let first = b.record_sent(t, 1200, 0, false);
        b.ack_packet(t + Duration::from_millis(10), t, 1200, 0, first);
        let later = t + Duration::from_secs(60);
        let next = b.record_sent(later, 1200, 0, false);
        b.ack_packet(later + Duration::from_millis(10), later, 1200, 12, next);
        assert_eq!(b.get_estimate(), 120_000);
    }

    #[test]
    fn application_limit_belongs_to_sent_packet() {
        let t = Instant::now();
        let mut b = BandwidthEstimation::default();
        let first = b.record_sent(t, 1200, 0, false);
        b.ack_packet(t + Duration::from_millis(10), t, 1200, 0, first);
        assert!(!b.app_limited_this_window());
        b.end_acks(0, true);
        let sent = t + Duration::from_millis(30);
        let limited = b.record_sent(sent, 1200, 0, true);
        b.ack_packet(sent + Duration::from_millis(20), sent, 1200, 12, limited);
        assert!(b.app_limited_this_window());
        assert_eq!(b.get_estimate(), 120_000);
        b.end_acks(12, false);
        let sent = t + Duration::from_millis(60);
        let normal = b.record_sent(sent, 1200, 0, false);
        b.ack_packet(sent + Duration::from_millis(20), sent, 1200, 24, normal);
        assert!(!b.app_limited_this_window());
        assert_eq!(b.get_estimate(), 60_000);
    }

    #[test]
    fn lost_history_is_bounded_and_late_acks_still_count() {
        let t = Instant::now();
        let mut b = BandwidthEstimation::default();
        let first = b.record_sent(t, 1200, 0, false);
        for i in 1..=MAX_SEND_BATCHES * 2 {
            b.record_sent(t + Duration::from_micros(i as u64), 1200, 1, false);
        }
        assert_eq!(b.batches.len(), MAX_SEND_BATCHES);
        b.ack_packet(t + Duration::from_secs(1), t, 1200, 0, first);
        assert_eq!(b.total_acked, 1200);
        assert_eq!(b.bytes_acked_this_window(), 1200);
        assert_eq!(b.get_estimate(), 0);
        let cloned = b.clone();
        assert_eq!(cloned.batches.len(), MAX_SEND_BATCHES);
    }

    #[test]
    fn zero_elapsed_time_and_large_byte_counts_are_safe() {
        let t = Instant::now();
        let mut b = BandwidthEstimation::default();
        let token = b.record_sent(t, 1200, 0, false);
        b.ack_packet(t, t, 1200, 0, token);
        assert_eq!(b.get_estimate(), 0);
        assert_eq!(b.total_acked, 1200);
        assert_eq!(
            BandwidthEstimation::bw_from_delta(u64::MAX, Duration::from_nanos(1)),
            Some(u64::MAX)
        );
        assert_eq!(
            BandwidthEstimation::bw_from_delta(1200, Duration::from_secs(60)),
            Some(20)
        );
    }
}
