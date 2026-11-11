use std::collections::VecDeque;

use super::*;

const MS: Nanos = MILLISECOND;
/// quic-go's monotonic clock starts an hour into the past.
const START: Time = 3_600 * SECOND;

// Ported from Xray-core's `bbr_sender_test.go`.

#[test]
fn set_max_datagram_size_rescales_packet_sized_windows() {
    const OLD: ByteCount = 1000;
    const NEW: ByteCount = 1400;
    let mut sender = BbrSender::with_windows(START, OLD, 20 * OLD, 80 * OLD, BbrProfile::Standard);
    sender.congestion_window = sender.initial_congestion_window;

    sender.set_max_datagram_size(NEW);

    assert_eq!(sender.initial_congestion_window, 20 * NEW);
    assert_eq!(sender.max_congestion_window, 80 * NEW);
    assert_eq!(
        sender.min_congestion_window,
        MIN_CONGESTION_WINDOW_PACKETS * NEW
    );
    assert_eq!(sender.congestion_window, 20 * NEW);
}

#[test]
fn set_max_datagram_size_clamps_congestion_window() {
    const OLD: ByteCount = 1000;
    let mut sender = BbrSender::new(START, OLD, BbrProfile::Standard);
    sender.congestion_window = sender.min_congestion_window + OLD;
    sender.recovery_window = sender.min_congestion_window + OLD;

    sender.set_max_datagram_size(1400);

    assert_eq!(sender.congestion_window, sender.min_congestion_window);
    assert_eq!(sender.recovery_window, sender.min_congestion_window);
}

#[test]
fn new_bbr_sender_applies_profiles() {
    struct Case {
        profile: BbrProfile,
        high_gain: f64,
        high_cwnd_gain: f64,
        congestion_window_gain_constant: f64,
        num_startup_rtts: i64,
        drain_to_target: bool,
        detect_overshooting: bool,
        bytes_lost_multiplier: u8,
        enable_ack_aggregation_during_startup: bool,
        expire_ack_aggregation_in_startup: bool,
        enable_overestimate_avoidance: bool,
        reduce_extra_acked_on_bandwidth_increase: bool,
    }
    let cases = [
        Case {
            profile: BbrProfile::Standard,
            high_gain: DEFAULT_HIGH_GAIN,
            high_cwnd_gain: DERIVED_HIGH_CWND_GAIN,
            congestion_window_gain_constant: 2.0,
            num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_multiplier: 2,
            enable_ack_aggregation_during_startup: false,
            expire_ack_aggregation_in_startup: false,
            enable_overestimate_avoidance: false,
            reduce_extra_acked_on_bandwidth_increase: false,
        },
        Case {
            profile: BbrProfile::Conservative,
            high_gain: 2.25,
            high_cwnd_gain: 1.75,
            congestion_window_gain_constant: 1.75,
            num_startup_rtts: 2,
            drain_to_target: true,
            detect_overshooting: true,
            bytes_lost_multiplier: 1,
            enable_ack_aggregation_during_startup: false,
            expire_ack_aggregation_in_startup: false,
            enable_overestimate_avoidance: true,
            reduce_extra_acked_on_bandwidth_increase: true,
        },
        Case {
            profile: BbrProfile::Aggressive,
            high_gain: 3.0,
            high_cwnd_gain: 2.25,
            congestion_window_gain_constant: 2.5,
            num_startup_rtts: 4,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_multiplier: 2,
            enable_ack_aggregation_during_startup: true,
            expire_ack_aggregation_in_startup: true,
            enable_overestimate_avoidance: false,
            reduce_extra_acked_on_bandwidth_increase: false,
        },
    ];
    for case in cases {
        let sender = BbrSender::new(START, UDP_INITIAL_PACKET_SIZE, case.profile);
        let name = format!("{:?}", case.profile);
        assert_eq!(sender.profile, case.profile, "{name}");
        assert_eq!(sender.high_gain, case.high_gain, "{name}");
        assert_eq!(sender.high_cwnd_gain, case.high_cwnd_gain, "{name}");
        assert_eq!(
            sender.congestion_window_gain_constant, case.congestion_window_gain_constant,
            "{name}"
        );
        assert_eq!(sender.num_startup_rtts, case.num_startup_rtts, "{name}");
        assert_eq!(sender.drain_to_target, case.drain_to_target, "{name}");
        assert_eq!(
            sender.detect_overshooting, case.detect_overshooting,
            "{name}"
        );
        assert_eq!(
            sender.bytes_lost_multiplier_while_detecting_overshooting, case.bytes_lost_multiplier,
            "{name}"
        );
        assert_eq!(
            sender.enable_ack_aggregation_during_startup,
            case.enable_ack_aggregation_during_startup,
            "{name}"
        );
        assert_eq!(
            sender.expire_ack_aggregation_in_startup, case.expire_ack_aggregation_in_startup,
            "{name}"
        );
        assert_eq!(
            sender.sampler.is_overestimate_avoidance_enabled(),
            case.enable_overestimate_avoidance,
            "{name}"
        );
        assert_eq!(
            sender.sampler.reduces_extra_acked_on_bandwidth_increase(),
            case.reduce_extra_acked_on_bandwidth_increase,
            "{name}"
        );
        assert_eq!(sender.pacing_gain, sender.high_gain, "{name}");
        assert_eq!(
            sender.congestion_window_gain, sender.high_cwnd_gain,
            "{name}"
        );
        assert_eq!(sender.drain_gain, 1.0 / case.high_gain, "{name}");
    }
}

// Behavior on a simulated path.

/// A paced sender on a path with a fixed propagation RTT and bottleneck
/// rate and an unbounded queue. Acknowledgements arrive in send order; a
/// lost packet is reported with the next acknowledgement, as quic-go's
/// packet threshold finds it.
struct Path {
    sender: BbrSender,
    now: Time,
    next_packet_number: PacketNumber,
    in_flight: ByteCount,
    rtt: Nanos,
    /// Nanoseconds per datagram at the bottleneck.
    spacing: Nanos,
    datagram: ByteCount,
    /// Each packet's number, size, send time and acknowledgement time.
    pending: VecDeque<(PacketNumber, ByteCount, Time, Time)>,
    bottleneck_free_at: Time,
    next_send_at: Time,
    lost: Vec<LostPacket>,
}

impl Path {
    fn new(profile: BbrProfile, rtt: Nanos, bytes_per_second: i64) -> Self {
        let datagram = 1200;
        let mut sender = BbrSender::new(START, datagram, profile);
        sender.set_gain_cycle_draw(GainCycleDraw::Scripted((0..64).collect()));
        Self {
            sender,
            now: START,
            next_packet_number: 0,
            in_flight: 0,
            rtt,
            spacing: datagram * SECOND / bytes_per_second,
            datagram,
            pending: VecDeque::new(),
            bottleneck_free_at: START,
            next_send_at: START,
            lost: Vec::new(),
        }
    }

    fn send(&mut self) {
        let packet_number = self.next_packet_number;
        self.next_packet_number += 1;
        self.in_flight += self.datagram;
        self.sender
            .on_packet_sent(self.now, self.in_flight, packet_number, self.datagram, true);
        let leaves = self.bottleneck_free_at.max(self.now) + self.spacing;
        self.bottleneck_free_at = leaves;
        self.pending
            .push_back((packet_number, self.datagram, self.now, leaves + self.rtt));
        let rate = self.sender.bandwidth_for_pacer();
        self.next_send_at = self.now + self.datagram * SECOND / rate;
    }

    /// Runs until `acks` acknowledgements were delivered, losing the
    /// packets `lose` selects.
    fn run(&mut self, acks: usize, lose: impl Fn(PacketNumber) -> bool) {
        let mut delivered = 0;
        while delivered < acks {
            let next_ack = self.pending.front().map(|packet| packet.3);
            let send_at = self.next_send_at.max(self.now);
            if self.in_flight < self.sender.congestion_window()
                && next_ack.is_none_or(|ack| send_at <= ack)
            {
                self.now = send_at;
                self.send();
                continue;
            }
            let (packet_number, bytes, sent, at) = self.pending.pop_front().expect("in flight");
            self.now = self.now.max(at);
            if lose(packet_number) {
                self.lost.push(LostPacket {
                    packet_number,
                    bytes_lost: bytes,
                });
                continue;
            }
            let prior = self.in_flight;
            let lost = std::mem::take(&mut self.lost);
            self.in_flight -= bytes + lost.iter().map(|packet| packet.bytes_lost).sum::<i64>();
            self.sender.on_rtt_sample(self.now - sent);
            let acked = [AckedPacket {
                packet_number,
                bytes_acked: bytes,
            }];
            self.sender
                .on_congestion_event(prior, self.now, &acked, &lost);
            delivered += 1;
        }
    }

    /// Delivers everything in flight without sending more.
    fn drain(&mut self) {
        while let Some((packet_number, bytes, sent, at)) = self.pending.pop_front() {
            self.now = self.now.max(at);
            let prior = self.in_flight;
            self.in_flight -= bytes;
            self.sender.on_rtt_sample(self.now - sent);
            let acked = [AckedPacket {
                packet_number,
                bytes_acked: bytes,
            }];
            self.sender
                .on_congestion_event(prior, self.now, &acked, &[]);
        }
    }
}

fn rounds_in_startup(profile: BbrProfile) -> u64 {
    let mut path = Path::new(profile, 50 * MS, 1_250_000);
    for _ in 0..20_000 {
        path.run(1, |_| false);
        if path.sender.mode != Mode::Startup {
            return path.sender.round_trip_count;
        }
    }
    panic!("{profile:?} never left STARTUP");
}

#[test]
fn startup_ends_after_the_profiles_rounds_without_growth() {
    let standard = rounds_in_startup(BbrProfile::Standard);
    let conservative = rounds_in_startup(BbrProfile::Conservative);
    let aggressive = rounds_in_startup(BbrProfile::Aggressive);
    // Two, three and four rounds without 25% growth end STARTUP.
    assert!(conservative < standard, "{conservative} vs {standard}");
    assert!(standard < aggressive, "{standard} vs {aggressive}");
}

#[test]
fn the_gain_cycle_never_starts_in_the_lowered_phase() {
    for draw in 0..PACKETS_PER_CONNECTION_ID {
        let mut sender = BbrSender::new(START, 1200, BbrProfile::Standard);
        sender.set_gain_cycle_draw(GainCycleDraw::Scripted(VecDeque::from([draw])));
        sender.enter_probe_bandwidth_mode(START);
        assert_ne!(sender.cycle_current_offset, 1, "draw {draw}");
        assert_eq!(sender.pacing_gain, PACING_GAIN[sender.cycle_current_offset]);
        assert_eq!(sender.congestion_window_gain, 2.0);
    }
}

#[test]
fn a_steady_flow_reaches_probe_bw_near_the_bottleneck_rate() {
    for profile in [
        BbrProfile::Conservative,
        BbrProfile::Standard,
        BbrProfile::Aggressive,
    ] {
        let mut path = Path::new(profile, 40 * MS, 2_500_000);
        path.run(3000, |_| false);
        assert_eq!(path.sender.mode, Mode::ProbeBw, "{profile:?}");
        let estimate = path.sender.bandwidth_estimate() / BYTES_PER_SECOND;
        assert!(
            (2_400_000..=2_600_000).contains(&estimate),
            "{profile:?}: {estimate} B/s"
        );
        assert!(path.sender.min_rtt >= 40 * MS, "{profile:?}");
    }
}

#[test]
fn loss_after_startup_enters_recovery_and_a_clean_round_leaves_it() {
    let mut path = Path::new(BbrProfile::Standard, 40 * MS, 2_500_000);
    path.run(3000, |_| false);
    assert!(path.sender.is_at_full_bandwidth);
    // One loss: CONSERVATION for a round, and the first acknowledgement past
    // that round, clean, ends recovery at once.
    let lost = path.pending.back().expect("in flight").0 + 1;
    while path.sender.recovery_state == RecoveryState::NotInRecovery {
        path.run(1, |pn| pn == lost);
    }
    assert_eq!(path.sender.recovery_state, RecoveryState::Conservation);
    let window = path.sender.congestion_window();
    assert!(
        window < path.sender.congestion_window,
        "the recovery window binds"
    );
    // A second loss, the first packet sent in CONSERVATION, is found by the
    // acknowledgement that starts the next round: GROWTH, until a clean
    // acknowledgement passes the packets sent by then.
    let second = path.next_packet_number;
    let mut states = vec![path.sender.recovery_state];
    for _ in 0..600 {
        path.run(1, |pn| pn == second);
        if states.last() != Some(&path.sender.recovery_state) {
            states.push(path.sender.recovery_state);
        }
    }
    assert_eq!(
        states,
        [
            RecoveryState::Conservation,
            RecoveryState::Growth,
            RecoveryState::NotInRecovery
        ]
    );
}

#[test]
fn an_expired_min_rtt_enters_probe_rtt_unless_leaving_quiescence() {
    let mut paths: Vec<Path> = (0..2)
        .map(|_| Path::new(BbrProfile::Standard, 40 * MS, 2_500_000))
        .collect();
    for path in &mut paths {
        path.run(3000, |_| false);
        assert_eq!(path.sender.mode, Mode::ProbeBw);
        path.drain();
        // Eleven idle seconds later the minimum RTT has expired.
        path.now += 11 * SECOND;
        path.bottleneck_free_at = path.now;
        path.next_send_at = path.now;
    }
    // A packet sent with nothing in flight, here an ACK-only one, marks the
    // end of quiescence: the next event skips PROBE_RTT.
    let quiescent = &mut paths[1];
    let ack_only = quiescent.next_packet_number;
    quiescent.next_packet_number += 1;
    quiescent
        .sender
        .on_packet_sent(quiescent.now, 0, ack_only, 50, false);
    for path in &mut paths {
        path.run(1, |_| false);
    }
    assert_eq!(paths[0].sender.mode, Mode::ProbeRtt);
    assert_eq!(
        paths[0].sender.congestion_window(),
        paths[0].sender.min_congestion_window
    );
    assert_eq!(paths[1].sender.mode, Mode::ProbeBw);
}

#[test]
fn only_conservative_lowers_an_overshooting_startup_pacing_rate() {
    for (profile, lowered) in [
        (BbrProfile::Conservative, true),
        (BbrProfile::Standard, false),
        (BbrProfile::Aggressive, false),
    ] {
        let mut sender = BbrSender::new(START, 1200, profile);
        sender.on_rtt_sample(SECOND);
        sender.max_bandwidth.update(1_000_000, 1);
        sender.pacing_rate = 10_000_000;
        sender.has_no_app_limited_sample = true;
        sender.calculate_pacing_rate(1200);
        if lowered {
            // The target rate, above the initial window over the RTT.
            assert_eq!(sender.pacing_rate, (2.25 * 1_000_000.0) as Bandwidth);
            assert!(!sender.detect_overshooting, "detected once");
        } else {
            assert_eq!(sender.pacing_rate, 10_000_000, "{profile:?}");
        }
    }
}

#[test]
fn without_a_clean_sample_conservative_waits_for_lost_bytes_beyond_the_initial_window() {
    let mut sender = BbrSender::new(START, 1200, BbrProfile::Conservative);
    sender.on_rtt_sample(SECOND);
    sender.max_bandwidth.update(1_000_000, 1);
    sender.pacing_rate = 10_000_000;
    // The multiplier is one: 32 datagrams' worth must be lost first.
    sender.calculate_pacing_rate(32 * 1200);
    assert_eq!(sender.pacing_rate, 10_000_000);
    sender.calculate_pacing_rate(1);
    assert_eq!(sender.pacing_rate, (2.25 * 1_000_000.0) as Bandwidth);
}

#[test]
fn aggressive_adds_the_latest_excess_to_its_startup_window() {
    for (profile, added) in [
        (BbrProfile::Aggressive, true),
        (BbrProfile::Standard, false),
    ] {
        let mut sender = BbrSender::new(START, 1200, profile);
        // Acknowledge more than the initial window: from then on the
        // STARTUP window only grows while below its target.
        sender.on_packet_sent(START, 40_000, 0, 40_000, true);
        sender.on_rtt_sample(100 * MS);
        let acked = [AckedPacket {
            packet_number: 0,
            bytes_acked: 40_000,
        }];
        sender.on_congestion_event(40_000, START + 100 * MS, &acked, &[]);
        assert_eq!(sender.mode, Mode::Startup);
        let target = sender.target_congestion_window(sender.congestion_window_gain);
        sender.congestion_window = target + 10_000;
        // An excess of 20,000 bytes lifts the target above the window.
        sender.calculate_congestion_window(1200, 20_000);
        let expected = if added {
            target + 11_200
        } else {
            target + 10_000
        };
        assert_eq!(sender.congestion_window, expected, "{profile:?}");
    }
}

#[test]
fn drain_to_target_holds_the_low_gain_until_the_flight_drains() {
    for (profile, held) in [
        (BbrProfile::Conservative, true),
        (BbrProfile::Standard, false),
    ] {
        let mut sender = BbrSender::new(START, 1200, profile);
        sender.on_rtt_sample(100 * MS);
        sender.max_bandwidth.update(8_000_000, 1);
        sender.mode = Mode::ProbeBw;
        sender.cycle_current_offset = 1;
        sender.pacing_gain = PACING_GAIN[1];
        sender.last_cycle_start = START;
        // A BDP of 100,000 bytes, and more than that in flight.
        sender.bytes_in_flight = 150_000;
        sender.update_gain_cycle_phase(START + SECOND, 150_000, false);
        assert_eq!(sender.cycle_current_offset, 2, "{profile:?}");
        let expected = if held { PACING_GAIN[1] } else { PACING_GAIN[2] };
        assert_eq!(sender.pacing_gain, expected, "{profile:?}");
    }
}

#[test]
fn reduce_extra_acked_rescales_the_ack_height_on_a_new_bandwidth_maximum() {
    // Conservative recalculates the recorded excess against a new maximum;
    // standard keeps it.
    let excess_after = |profile| {
        let mut path = Path::new(profile, 40 * MS, 2_500_000);
        path.run(400, |_| false);
        path.sender.sampler.max_ack_height()
    };
    let conservative = excess_after(BbrProfile::Conservative);
    let standard = excess_after(BbrProfile::Standard);
    assert!(conservative <= standard, "{conservative} vs {standard}");
}

#[test]
fn bandwidth_arithmetic_matches_go() {
    // 1,000 bytes in a millisecond: 8 Mbit/s.
    assert_eq!(bandwidth_from_delta(1000, MS), 8_000_000);
    // Integer division happens before the final multiplication by eight.
    assert_eq!(bandwidth_from_delta(1, 3), 333_333_333 * 8);
    assert_eq!(
        bytes_from_bandwidth_and_time_delta(8_000_000, SECOND),
        1_000_000
    );
    assert_eq!(bdp_from_rtt_and_bandwidth(100 * MS, 8_000_000), 100_000);
    // Go's int64 products wrap instead of saturating.
    assert_eq!(
        bdp_from_rtt_and_bandwidth(Nanos::MAX, 2),
        Nanos::MAX.wrapping_mul(2) / 8 / SECOND
    );
}

/// The bytes a bandwidth delivers over an idle period: 100 Mbit/s for two
/// minutes is 1.5 GB, where Go's wrapped product gives a negative count
/// that keeps the ack-aggregation epoch open.
#[test]
fn expected_bytes_over_a_long_interval_do_not_wrap() {
    let bandwidth: Bandwidth = 100_000_000;
    let idle = 120 * SECOND;
    assert!(
        (bandwidth as ByteCount).wrapping_mul(idle) < 0,
        "Go's wraps"
    );
    assert_eq!(
        bytes_from_bandwidth_and_time_delta(bandwidth, idle),
        1_500_000_000
    );
    assert_eq!(
        bytes_from_bandwidth_and_time_delta(Bandwidth::MAX, Nanos::MAX),
        ByteCount::MAX
    );
}

#[test]
fn the_pacer_rate_has_a_floor_and_follows_the_initial_window_before_a_sample() {
    let mut sender = BbrSender::new(START, 1200, BbrProfile::Aggressive);
    // No RTT at all: 100 ms, at the high gain.
    assert_eq!(
        sender.pacing_rate(),
        (3.0 * bandwidth_from_delta(32 * 1200, 100 * MS) as f64) as Bandwidth
    );
    sender.on_rtt_sample(10 * MS);
    assert_eq!(
        sender.pacing_rate(),
        (3.0 * bandwidth_from_delta(32 * 1200, 10 * MS) as f64) as Bandwidth
    );
    sender.pacing_rate = 1;
    assert_eq!(sender.bandwidth_for_pacer(), MIN_BPS);
}
