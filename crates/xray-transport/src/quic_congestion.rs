//! Congestion control that Xray-core's QUIC carriers use and quinn lacks.
//!
//! [`Brutal`] ports Hysteria's Brutal sender as Xray-core v26.10.31 ships it
//! (`transport/internet/hysteria/congestion/brutal/brutal.go`). It paces at a
//! fixed rate that loss never lowers and lets twice that rate's
//! bandwidth-delay product be in flight. Unless loss compensation is disabled,
//! both are divided by the share of packets acknowledged over the last five
//! one-second slots, never by less than 0.8, once those slots hold at least 50
//! packets.
//!
//! Hysteria's default mode only learns whether Brutal applies from the server's
//! authentication reply, after the connection exists. quinn builds a
//! connection's controller up front, so [`NegotiatedBrutalFactory`] starts with
//! BBR and switches to Brutal once [`BrutalDecision::decide`] supplies a rate,
//! as Xray's `congestion.UseBrutal` replaces the connection's sender.

use std::any::Any;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// One-second slots of acknowledgement and loss counts.
const SLOT_COUNT: usize = 5;
/// Packets the slots must hold before their acknowledgement share counts.
const MIN_SAMPLE_COUNT: u64 = 50;
/// The lowest acknowledgement share loss compensation divides by.
const MIN_ACK_RATE: f64 = 0.8;
/// In-flight allowance, in bandwidth-delay products of the paced rate.
const WINDOW_MULTIPLIER: f64 = 2.0;
/// The window before the path has a smoothed RTT.
const NO_RTT_WINDOW: u64 = 10_240;

/// A fixed Brutal send rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BrutalRate {
    pub(crate) bytes_per_second: u64,
    /// `brutalDisableLossCompensation`: always send at exactly this rate.
    pub(crate) disable_loss_compensation: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Slot {
    second: i64,
    acked: u64,
    lost: u64,
}

/// Hysteria's Brutal sender.
#[derive(Debug, Clone)]
pub(crate) struct Brutal {
    rate: BrutalRate,
    epoch: Instant,
    max_datagram_size: u64,
    smoothed_rtt: Option<Duration>,
    slots: [Slot; SLOT_COUNT],
    ack_rate: f64,
    batch_acked: u64,
}

impl Brutal {
    pub(crate) fn new(rate: BrutalRate, now: Instant, mtu: u16) -> Self {
        Self {
            rate,
            epoch: now,
            max_datagram_size: u64::from(mtu),
            smoothed_rtt: None,
            slots: [Slot::default(); SLOT_COUNT],
            ack_rate: 1.0,
            batch_acked: 0,
        }
    }

    fn observe_rtt(&mut self, smoothed: Duration) {
        self.smoothed_rtt = Some(smoothed);
    }

    /// Adds one event's counts to the current second's slot and recomputes
    /// the acknowledgement share, as Xray's `OnCongestionEventEx` does.
    fn record(&mut self, now: Instant, acked: u64, lost: u64) {
        let second =
            i64::try_from(now.saturating_duration_since(self.epoch).as_secs()).unwrap_or(i64::MAX);
        let slot = &mut self.slots[(second % SLOT_COUNT as i64) as usize];
        if slot.second == second {
            slot.acked += acked;
            slot.lost += lost;
        } else {
            *slot = Slot {
                second,
                acked,
                lost,
            };
        }
        self.update_ack_rate(second);
    }

    fn update_ack_rate(&mut self, second: i64) {
        if self.rate.disable_loss_compensation {
            self.ack_rate = 1.0;
            return;
        }
        let oldest = second - SLOT_COUNT as i64;
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|slot| slot.second >= oldest)
            .fold((0, 0), |(acked, lost), slot| {
                (acked + slot.acked, lost + slot.lost)
            });
        let total = acked + lost;
        self.ack_rate = if total < MIN_SAMPLE_COUNT {
            1.0
        } else {
            (acked as f64 / total as f64).max(MIN_ACK_RATE)
        };
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.observe_rtt(rtt.get());
        self.batch_acked += 1;
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        let acked = std::mem::take(&mut self.batch_acked);
        if acked > 0 {
            self.record(now, acked, 0);
        }
    }

    fn on_packets_lost(&mut self, now: Instant, packets: u64, _bytes: u64) {
        self.record(now, 0, packets);
    }

    /// Brutal deliberately does not slow down on loss or persistent
    /// congestion; loss only feeds the acknowledgement share.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = u64::from(new_mtu);
    }

    /// Xray's window in quinn's terms. quic-go sends while the bytes in
    /// flight are at most its window; quinn sends a packet only while the
    /// bytes in flight plus that packet stay below it. One datagram plus one
    /// byte converts the first rule into the second, so at the one-datagram
    /// floor two packets may still be in flight, as in Xray, instead of
    /// none.
    fn window(&self) -> u64 {
        self.xray_window() + self.max_datagram_size + 1
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some((self.rate.bytes_per_second as f64 / self.ack_rate) as u64)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        NO_RTT_WINDOW + self.max_datagram_size + 1
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl Brutal {
    /// `GetCongestionWindow`: twice the compensated rate's bandwidth-delay
    /// product, at least one datagram, and 10,240 bytes before an RTT.
    fn xray_window(&self) -> u64 {
        let Some(rtt) = self.smoothed_rtt.filter(|rtt| !rtt.is_zero()) else {
            return NO_RTT_WINDOW;
        };
        let window = self.rate.bytes_per_second as f64 * rtt.as_secs_f64() * WINDOW_MULTIPLIER
            / self.ack_rate;
        (window as u64).max(self.max_datagram_size)
    }
}

/// Builds a [`Brutal`] sender at a fixed rate: Xray's `force-brutal`.
pub(crate) struct BrutalFactory(pub(crate) BrutalRate);

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.0, now, current_mtu))
    }
}

/// Hysteria's choice between BBR and Brutal, settled by the server's reply.
#[derive(Debug, Default)]
pub(crate) struct BrutalDecision(OnceLock<Option<u64>>);

impl BrutalDecision {
    /// Settles the choice once: a nonzero rate switches to Brutal at that
    /// rate, `None` or zero keeps BBR. Later calls are ignored.
    pub(crate) fn decide(&self, bytes_per_second: Option<u64>) {
        let _ = self.0.set(bytes_per_second.filter(|rate| *rate > 0));
    }

    fn rate(&self) -> Option<u64> {
        self.0.get().copied().flatten()
    }
}

/// Builds controllers that run BBR until a [`BrutalDecision`] selects Brutal.
pub(crate) struct NegotiatedBrutalFactory {
    pub(crate) bbr: Arc<BbrConfig>,
    pub(crate) disable_loss_compensation: bool,
    pub(crate) decision: Arc<BrutalDecision>,
}

impl ControllerFactory for NegotiatedBrutalFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let mut controller = NegotiatedBrutal {
            bbr: Arc::clone(&self.bbr).build(now, current_mtu),
            brutal: None,
            decision: Arc::clone(&self.decision),
            disable_loss_compensation: self.disable_loss_compensation,
            mtu: current_mtu,
        };
        controller.settle(now);
        Box::new(controller)
    }
}

/// BBR until the decision names a rate, then a fresh Brutal sender, which,
/// like Xray's replaced sender, starts without loss history.
struct NegotiatedBrutal {
    bbr: Box<dyn Controller>,
    brutal: Option<Brutal>,
    decision: Arc<BrutalDecision>,
    disable_loss_compensation: bool,
    mtu: u16,
}

impl NegotiatedBrutal {
    fn settle(&mut self, now: Instant) {
        if self.brutal.is_none() {
            if let Some(bytes_per_second) = self.decision.rate() {
                let rate = BrutalRate {
                    bytes_per_second,
                    disable_loss_compensation: self.disable_loss_compensation,
                };
                self.brutal = Some(Brutal::new(rate, now, self.mtu));
            }
        }
    }

    fn active(&mut self, now: Instant) -> &mut dyn Controller {
        self.settle(now);
        match &mut self.brutal {
            Some(brutal) => brutal,
            None => self.bbr.as_mut(),
        }
    }

    fn current(&self) -> &dyn Controller {
        match &self.brutal {
            Some(brutal) => brutal,
            None => self.bbr.as_ref(),
        }
    }
}

impl Controller for NegotiatedBrutal {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.active(now).on_sent(now, bytes, last_packet_number);
    }

    fn on_sent_with_in_flight(
        &mut self,
        now: Instant,
        bytes: u64,
        last_packet_number: u64,
        in_flight: u64,
        app_limited: bool,
    ) -> u64 {
        self.active(now).on_sent_with_in_flight(
            now,
            bytes,
            last_packet_number,
            in_flight,
            app_limited,
        )
    }

    fn on_ack_with_token(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
        token: u64,
    ) {
        self.active(now)
            .on_ack_with_token(now, sent, bytes, app_limited, rtt, token);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.active(now).on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_rtt_sample(&mut self, now: Instant, rtt: Duration, app_limited: bool) {
        self.active(now).on_rtt_sample(now, rtt, app_limited);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.active(now)
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_packets_lost(&mut self, now: Instant, packets: u64, bytes: u64) {
        self.active(now).on_packets_lost(now, packets, bytes);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.active(now)
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.bbr.on_mtu_update(new_mtu);
        if let Some(brutal) = &mut self.brutal {
            brutal.on_mtu_update(new_mtu);
        }
    }

    fn window(&self) -> u64 {
        self.current().window()
    }

    fn pacing_rate(&self) -> Option<u64> {
        self.current().pacing_rate()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            bbr: self.bbr.clone_box(),
            brutal: self.brutal.clone(),
            decision: Arc::clone(&self.decision),
            disable_loss_compensation: self.disable_loss_compensation,
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        self.bbr.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn brutal(bytes_per_second: u64, disable_loss_compensation: bool) -> (Brutal, Instant) {
        let now = Instant::now();
        let rate = BrutalRate {
            bytes_per_second,
            disable_loss_compensation,
        };
        (Brutal::new(rate, now, 1200), now)
    }

    #[test]
    fn window_waits_for_an_rtt_then_allows_two_bandwidth_delay_products() {
        let (mut sender, _) = brutal(MIB, false);
        assert_eq!(sender.xray_window(), NO_RTT_WINDOW);
        assert_eq!(sender.pacing_rate(), Some(MIB));

        sender.observe_rtt(Duration::from_millis(100));
        assert_eq!(sender.xray_window(), 2 * MIB / 10);

        // A rate too low for one datagram per RTT still allows one datagram.
        let (mut slow, _) = brutal(1000, false);
        slow.observe_rtt(Duration::from_millis(1));
        assert_eq!(slow.xray_window(), 1200);
        slow.on_mtu_update(1400);
        assert_eq!(slow.xray_window(), 1400);
    }

    /// quinn blocks a packet once `in_flight + packet >= window`; quic-go
    /// blocks once `in_flight > window`.
    fn quinn_sends(controller: &dyn Controller, in_flight: u64, packet: u64) -> bool {
        in_flight + packet < controller.window()
    }

    #[test]
    fn quinn_sends_exactly_while_xray_would() {
        let (mut sender, _) = brutal(MIB, false);
        for rtt in [Duration::from_micros(200), Duration::from_millis(80)] {
            sender.observe_rtt(rtt);
            let mtu = 1200;
            let xray = sender.xray_window();
            for in_flight in [0, xray - 1, xray, xray + 1, xray + mtu] {
                assert_eq!(
                    quinn_sends(&sender, in_flight, mtu),
                    in_flight <= xray,
                    "rtt {rtt:?}, {in_flight} bytes in flight, window {xray}"
                );
            }
        }
        // Before an RTT, and at the one-datagram floor on a fast path, a
        // second packet may follow the first, as in Xray.
        let (fresh, _) = brutal(MIB, false);
        assert!(quinn_sends(&fresh, NO_RTT_WINDOW, 1200));
        assert_eq!(fresh.initial_window(), fresh.window());
        sender.observe_rtt(Duration::from_micros(10));
        assert_eq!(sender.xray_window(), 1200);
        assert!(quinn_sends(&sender, 1200, 1200));
        assert!(!quinn_sends(&sender, 2400, 1200));
    }

    #[test]
    fn loss_raises_rate_and_window_by_the_acknowledged_share() {
        let (mut sender, now) = brutal(MIB, false);
        sender.observe_rtt(Duration::from_millis(100));
        sender.record(now, 90, 0);
        sender.record(now, 0, 10);
        assert!((sender.ack_rate - 0.9).abs() < 1e-12);
        assert_eq!(sender.pacing_rate(), Some((MIB as f64 / 0.9) as u64));
        assert_eq!(
            sender.xray_window(),
            (MIB as f64 * 0.1 * 2.0 / 0.9) as u64,
            "the window follows the compensated rate"
        );
    }

    #[test]
    fn too_few_samples_keep_the_configured_rate() {
        let (mut sender, now) = brutal(MIB, false);
        sender.record(now, 25, 24);
        assert_eq!(sender.ack_rate, 1.0, "49 packets are not enough");
        sender.record(now, 0, 1);
        assert_eq!(
            sender.ack_rate, MIN_ACK_RATE,
            "50 packets at half acknowledged"
        );
    }

    #[test]
    fn heavy_loss_is_compensated_at_most_by_the_floor() {
        let (mut sender, now) = brutal(MIB, false);
        sender.record(now, 10, 90);
        assert_eq!(sender.ack_rate, MIN_ACK_RATE);
        assert_eq!(
            sender.pacing_rate(),
            Some((MIB as f64 / MIN_ACK_RATE) as u64)
        );
    }

    #[test]
    fn disabled_compensation_keeps_the_exact_rate_through_loss() {
        let (mut sender, now) = brutal(MIB, true);
        sender.record(now, 10, 90);
        assert_eq!(sender.ack_rate, 1.0);
        assert_eq!(sender.pacing_rate(), Some(MIB));
    }

    #[test]
    fn samples_older_than_five_seconds_expire() {
        let (mut sender, start) = brutal(MIB, false);
        sender.record(start, 90, 10);
        assert!((sender.ack_rate - 0.9).abs() < 1e-12);
        // Four seconds later the lossy second still counts.
        sender.record(start + Duration::from_secs(4), 100, 0);
        assert!((sender.ack_rate - 190.0 / 200.0).abs() < 1e-12);
        // Its slot is reused five seconds later: only clean samples remain.
        sender.record(start + Duration::from_secs(5), 100, 0);
        assert_eq!(sender.ack_rate, 1.0);
        assert_eq!(sender.slots.iter().map(|slot| slot.lost).sum::<u64>(), 0);
    }

    #[test]
    fn congestion_events_do_not_slow_brutal_down() {
        let (mut sender, now) = brutal(MIB, false);
        sender.observe_rtt(Duration::from_millis(50));
        let before = (sender.window(), sender.pacing_rate());
        sender.on_congestion_event(now, now, true, 1_000_000);
        assert_eq!((sender.window(), sender.pacing_rate()), before);
    }

    #[test]
    fn acknowledgements_count_once_per_batch_end() {
        let (mut sender, now) = brutal(MIB, false);
        sender.batch_acked = 60;
        sender.on_end_acks(now, 0, false, None);
        assert_eq!(sender.batch_acked, 0);
        sender.on_packets_lost(now, 15, 15 * 1200);
        assert!((sender.ack_rate - 60.0 / 75.0).abs() < 1e-12);
        sender.on_end_acks(now, 0, false, None);
        assert!(
            (sender.ack_rate - 60.0 / 75.0).abs() < 1e-12,
            "an empty batch records nothing"
        );
    }

    fn negotiated(decision: &Arc<BrutalDecision>) -> Box<dyn Controller> {
        Arc::new(NegotiatedBrutalFactory {
            bbr: Arc::new(BbrConfig::default()),
            disable_loss_compensation: false,
            decision: Arc::clone(decision),
        })
        .build(Instant::now(), 1200)
    }

    #[test]
    fn negotiation_keeps_bbr_until_the_server_names_a_rate() {
        let decision = Arc::new(BrutalDecision::default());
        let mut controller = negotiated(&decision);
        assert_ne!(controller.pacing_rate(), Some(MIB));

        decision.decide(Some(MIB));
        decision.decide(Some(2 * MIB));
        let now = Instant::now();
        controller.on_sent_with_in_flight(now, 1200, 1, 1200, false);
        assert_eq!(
            controller.pacing_rate(),
            Some(MIB),
            "the first decision wins"
        );
        assert_eq!(controller.window(), NO_RTT_WINDOW + 1200 + 1);
        let controller = controller
            .into_any()
            .downcast::<NegotiatedBrutal>()
            .unwrap();
        assert!(controller.brutal.is_some());
    }

    #[test]
    fn negotiation_without_a_rate_stays_on_bbr() {
        for rate in [None, Some(0)] {
            let decision = Arc::new(BrutalDecision::default());
            let mut controller = negotiated(&decision);
            decision.decide(rate);
            let now = Instant::now();
            controller.on_sent_with_in_flight(now, 1200, 1, 1200, false);
            let controller = controller
                .into_any()
                .downcast::<NegotiatedBrutal>()
                .unwrap();
            assert!(controller.brutal.is_none(), "{rate:?} must keep BBR");
        }
    }

    #[test]
    fn controllers_built_after_the_decision_start_as_brutal() {
        let decision = Arc::new(BrutalDecision::default());
        decision.decide(Some(3 * MIB));
        let controller = negotiated(&decision);
        assert_eq!(controller.pacing_rate(), Some(3 * MIB));
    }
}
