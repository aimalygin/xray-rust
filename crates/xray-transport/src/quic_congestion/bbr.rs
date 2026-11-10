//! Xray-core's BBR sender, ported from Xray-core v26.10.31
//! (`transport/internet/hysteria/congestion/bbr/bbr_sender.go` and its
//! helpers) with its three profiles.
//!
//! BBR estimates the bottleneck bandwidth and the minimum RTT and sets the
//! pacing rate and the congestion window from them. The port keeps quic-go's
//! types and arithmetic: byte counts are `i64`, bandwidths `u64` bits per
//! second, times nanoseconds with zero meaning unset, and every product Go
//! lets wrap wraps here too. [`BbrSender`] takes the calls quic-go makes on a
//! `CongestionControlEx`; [`super::XrayBbr`] adapts quinn's callbacks to
//! them.
//!
//! What the port leaves out: the pacer (quinn paces from
//! [`BbrSender::bandwidth_for_pacer`] with its own token bucket), debug
//! logging, and state Xray declares but never reads. One deliberate
//! difference: quic-go never lowers a connection's datagram size and the Go
//! sender panics if asked to; quinn lowers it after detecting a black hole,
//! so [`BbrSender::set_max_datagram_size`] rescales its windows down as it
//! would up.

mod filter;
mod queue;
mod sampler;

use std::cmp::Ordering;

use filter::WindowedFilter;
use sampler::{BandwidthSampler, SendTimeState, INF_RTT};

pub(crate) type ByteCount = i64;
pub(crate) type PacketNumber = i64;
/// Bits per second.
pub(crate) type Bandwidth = u64;
type RoundTripCount = u64;
/// quic-go's `monotime.Time`: nanoseconds, zero meaning unset.
pub(crate) type Time = i64;
/// Go's `time.Duration`.
pub(crate) type Nanos = i64;

pub(crate) const INVALID_PACKET_NUMBER: PacketNumber = -1;
const INF_BANDWIDTH: Bandwidth = u64::MAX;
const BYTES_PER_SECOND: Bandwidth = 8;
const SECOND: Nanos = 1_000_000_000;
const MILLISECOND: Nanos = 1_000_000;

/// The lowest rate handed to the pacer, in bytes per second.
const MIN_BPS: ByteCount = 65_536;
const INITIAL_CONGESTION_WINDOW_PACKETS: ByteCount = 32;
const MIN_CONGESTION_WINDOW_PACKETS: ByteCount = 4;
/// quic-go's `MaxCongestionWindowPackets`.
const MAX_CONGESTION_WINDOW_PACKETS: ByteCount = 20_000;
/// quic-go's `MaxPacketBufferSize`.
const MAX_PACKET_BUFFER_SIZE: ByteCount = 1452;
/// quic-go's `PacketsPerConnectionID`, the range of the gain-cycle draw.
pub(crate) const PACKETS_PER_CONNECTION_ID: u32 = 10_000;
/// quic-go's `InitialPacketSize`: Xray's datagram size guess for UDP peers.
pub(crate) const UDP_INITIAL_PACKET_SIZE: ByteCount = 1280;

/// The STARTUP pacing gain, 2/ln(2).
const DEFAULT_HIGH_GAIN: f64 = 2.885;
/// The STARTUP congestion-window gain.
const DERIVED_HIGH_CWND_GAIN: f64 = 2.0;
/// The PROBE_BW pacing gains.
const PACING_GAIN: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const GAIN_CYCLE_LENGTH: usize = PACING_GAIN.len();
/// The bandwidth filter's window, in round trips.
const BANDWIDTH_WINDOW_SIZE: RoundTripCount = GAIN_CYCLE_LENGTH as RoundTripCount + 2;
/// How long a minimum RTT holds before PROBE_RTT measures it again.
const MIN_RTT_EXPIRY: Nanos = 10 * SECOND;
/// The shortest PROBE_RTT.
const PROBE_RTT_TIME: Nanos = 200 * MILLISECOND;
/// STARTUP ends once the bandwidth grows by less than this factor for the
/// profile's number of rounds.
const STARTUP_GROWTH_TARGET: f64 = 1.25;
const ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: i64 = 3;
const DEFAULT_STARTUP_FULL_LOSS_COUNT: u64 = 8;
const QUIC_BBR2_DEFAULT_LOSS_THRESHOLD: f64 = 0.02;

/// One acknowledged packet of a congestion event, quic-go's
/// `AckedPacketInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AckedPacket {
    pub(crate) packet_number: PacketNumber,
    pub(crate) bytes_acked: ByteCount,
}

/// One lost packet of a congestion event, quic-go's `LostPacketInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LostPacket {
    pub(crate) packet_number: PacketNumber,
    pub(crate) bytes_lost: ByteCount,
}

/// Xray's `bbrProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BbrProfile {
    Conservative,
    Standard,
    Aggressive,
}

/// Xray's `profileConfig`.
#[derive(Debug, Clone, Copy, PartialEq)]
struct ProfileConfig {
    high_gain: f64,
    high_cwnd_gain: f64,
    congestion_window_gain_constant: f64,
    num_startup_rtts: i64,
    drain_to_target: bool,
    detect_overshooting: bool,
    bytes_lost_multiplier: u8,
    enable_ack_aggregation_startup: bool,
    expire_ack_aggregation_startup: bool,
    enable_overestimate_avoidance: bool,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

impl BbrProfile {
    /// `configForProfile`.
    fn config(self) -> ProfileConfig {
        match self {
            Self::Conservative => ProfileConfig {
                high_gain: 2.25,
                high_cwnd_gain: 1.75,
                congestion_window_gain_constant: 1.75,
                num_startup_rtts: 2,
                drain_to_target: true,
                detect_overshooting: true,
                bytes_lost_multiplier: 1,
                enable_ack_aggregation_startup: false,
                expire_ack_aggregation_startup: false,
                enable_overestimate_avoidance: true,
                reduce_extra_acked_on_bandwidth_increase: true,
            },
            Self::Aggressive => ProfileConfig {
                high_gain: 3.0,
                high_cwnd_gain: 2.25,
                congestion_window_gain_constant: 2.5,
                num_startup_rtts: 4,
                drain_to_target: false,
                detect_overshooting: false,
                bytes_lost_multiplier: 2,
                enable_ack_aggregation_startup: true,
                expire_ack_aggregation_startup: true,
                enable_overestimate_avoidance: false,
                reduce_extra_acked_on_bandwidth_increase: false,
            },
            Self::Standard => ProfileConfig {
                high_gain: DEFAULT_HIGH_GAIN,
                high_cwnd_gain: DERIVED_HIGH_CWND_GAIN,
                congestion_window_gain_constant: 2.0,
                num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
                drain_to_target: false,
                detect_overshooting: false,
                bytes_lost_multiplier: 2,
                enable_ack_aggregation_startup: false,
                expire_ack_aggregation_startup: false,
                enable_overestimate_avoidance: false,
                reduce_extra_acked_on_bandwidth_increase: false,
            },
        }
    }
}

/// `bbrMode`, numbered as in Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Grow the pacing rate by the high gain every round.
    Startup = 0,
    /// Drain the queue STARTUP built.
    Drain = 1,
    /// Cruise, probing for more bandwidth one round in eight.
    ProbeBw = 2,
    /// Shrink the window to measure the minimum RTT again.
    ProbeRtt = 3,
}

/// `bbrRecoveryState`, numbered as in Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryState {
    NotInRecovery = 0,
    /// One extra outstanding byte per byte acknowledged.
    Conservation = 1,
    /// Two extra outstanding bytes per byte acknowledged.
    Growth = 2,
}

/// Where the PROBE_BW gain cycle starts: Go's
/// `rand.Int31n(PacketsPerConnectionID)`, a draw below
/// [`PACKETS_PER_CONNECTION_ID`].
#[derive(Debug, Clone, Default)]
pub(crate) enum GainCycleDraw {
    #[default]
    Random,
    /// Recorded draws, for replaying a Go trace.
    #[cfg(test)]
    Scripted(std::collections::VecDeque<u32>),
}

impl GainCycleDraw {
    fn next(&mut self) -> u32 {
        match self {
            Self::Random => {
                rand::Rng::gen_range(&mut rand::thread_rng(), 0..PACKETS_PER_CONNECTION_ID)
            }
            #[cfg(test)]
            Self::Scripted(draws) => draws.pop_front().expect("a recorded gain-cycle draw"),
        }
    }
}

/// `BandwidthFromDelta`: bytes over a duration, in bits per second.
fn bandwidth_from_delta(bytes: ByteCount, delta: Nanos) -> Bandwidth {
    (bytes as Bandwidth)
        .wrapping_mul(SECOND as Bandwidth)
        .wrapping_div(delta as Bandwidth)
        .wrapping_mul(BYTES_PER_SECOND)
}

/// `bytesFromBandwidthAndTimeDelta`, without its overflow. Go's int64
/// product wraps once bandwidth times interval passes 2^63, which 100 Mbit/s
/// reaches after 92 seconds: an idle connection's first ACK then finds a
/// negative number of expected bytes, the ack-aggregation epoch is not
/// restarted, and about a gigabyte of "extra" acked bytes lifts the cap off
/// the congestion window. The product is taken in 128 bits instead.
fn bytes_from_bandwidth_and_time_delta(bandwidth: Bandwidth, delta: Nanos) -> ByteCount {
    let bytes = i128::from(bandwidth) * i128::from(delta) / i128::from(SECOND * 8);
    bytes.clamp(i128::from(ByteCount::MIN), i128::from(ByteCount::MAX)) as ByteCount
}

/// `bdpFromRttAndBandwidth`.
fn bdp_from_rtt_and_bandwidth(rtt: Nanos, bandwidth: Bandwidth) -> ByteCount {
    rtt.wrapping_mul(bandwidth as ByteCount) / BYTES_PER_SECOND as ByteCount / SECOND
}

fn min_congestion_window_for_max_datagram_size(max_datagram_size: ByteCount) -> ByteCount {
    MIN_CONGESTION_WINDOW_PACKETS.wrapping_mul(max_datagram_size)
}

fn scale_byte_window_for_datagram_size(
    window: ByteCount,
    old_max_datagram_size: ByteCount,
    new_max_datagram_size: ByteCount,
) -> ByteCount {
    if old_max_datagram_size == new_max_datagram_size {
        return window;
    }
    (window as u64)
        .wrapping_mul(new_max_datagram_size as u64)
        .wrapping_div(old_max_datagram_size as u64) as ByteCount
}

fn compare_bandwidth(a: &Bandwidth, b: &Bandwidth) -> Ordering {
    a.cmp(b)
}

/// Xray's `bbrSender`.
#[derive(Debug, Clone)]
pub(crate) struct BbrSender {
    /// quic-go's `RTTStats.MinRTT`: the smallest raw RTT sample, zero before
    /// the first.
    rtt_stats_min_rtt: Nanos,
    mode: Mode,
    sampler: BandwidthSampler,
    round_trip_count: RoundTripCount,
    last_sent_packet: PacketNumber,
    /// Acknowledging any packet after this one advances the round trip.
    current_round_trip_end: PacketNumber,
    num_loss_events_in_round: u64,
    bytes_lost_in_round: ByteCount,
    max_bandwidth: WindowedFilter<Bandwidth>,
    /// The windowed minimum RTT, expiring after ten seconds.
    min_rtt: Nanos,
    min_rtt_timestamp: Time,
    congestion_window: ByteCount,
    initial_congestion_window: ByteCount,
    max_congestion_window: ByteCount,
    min_congestion_window: ByteCount,
    profile: BbrProfile,
    high_gain: f64,
    high_cwnd_gain: f64,
    drain_gain: f64,
    pacing_rate: Bandwidth,
    pacing_gain: f64,
    congestion_window_gain: f64,
    congestion_window_gain_constant: f64,
    num_startup_rtts: i64,
    cycle_current_offset: usize,
    last_cycle_start: Time,
    is_at_full_bandwidth: bool,
    rounds_without_bandwidth_gain: i64,
    bandwidth_at_last_round: Bandwidth,
    exiting_quiescence: bool,
    exit_probe_rtt_at: Time,
    probe_rtt_round_passed: bool,
    last_sample_is_app_limited: bool,
    has_no_app_limited_sample: bool,
    recovery_state: RecoveryState,
    end_recovery_at: PacketNumber,
    recovery_window: ByteCount,
    enable_ack_aggregation_during_startup: bool,
    expire_ack_aggregation_in_startup: bool,
    drain_to_target: bool,
    detect_overshooting: bool,
    bytes_lost_while_detecting_overshooting: ByteCount,
    bytes_lost_multiplier_while_detecting_overshooting: u8,
    cwnd_to_calculate_min_pacing_rate: ByteCount,
    max_datagram_size: ByteCount,
    bytes_in_flight: ByteCount,
    gain_cycle_draw: GainCycleDraw,
}

impl BbrSender {
    /// `NewBbrSender`: a 32-datagram initial window, at most 20,000.
    pub(crate) fn new(
        now: Time,
        initial_max_datagram_size: ByteCount,
        profile: BbrProfile,
    ) -> Self {
        Self::with_windows(
            now,
            initial_max_datagram_size,
            INITIAL_CONGESTION_WINDOW_PACKETS.wrapping_mul(initial_max_datagram_size),
            MAX_CONGESTION_WINDOW_PACKETS.wrapping_mul(initial_max_datagram_size),
            profile,
        )
    }

    /// `newBbrSender`.
    fn with_windows(
        now: Time,
        initial_max_datagram_size: ByteCount,
        initial_congestion_window: ByteCount,
        initial_max_congestion_window: ByteCount,
        profile: BbrProfile,
    ) -> Self {
        let mut sender = Self {
            rtt_stats_min_rtt: 0,
            mode: Mode::Startup,
            sampler: BandwidthSampler::new(BANDWIDTH_WINDOW_SIZE),
            round_trip_count: 0,
            last_sent_packet: INVALID_PACKET_NUMBER,
            current_round_trip_end: INVALID_PACKET_NUMBER,
            num_loss_events_in_round: 0,
            bytes_lost_in_round: 0,
            max_bandwidth: WindowedFilter::new(BANDWIDTH_WINDOW_SIZE, compare_bandwidth),
            min_rtt: 0,
            min_rtt_timestamp: 0,
            congestion_window: initial_congestion_window,
            initial_congestion_window,
            max_congestion_window: initial_max_congestion_window,
            min_congestion_window: min_congestion_window_for_max_datagram_size(
                initial_max_datagram_size,
            ),
            profile: BbrProfile::Standard,
            high_gain: DEFAULT_HIGH_GAIN,
            high_cwnd_gain: DERIVED_HIGH_CWND_GAIN,
            drain_gain: 1.0 / DEFAULT_HIGH_GAIN,
            pacing_rate: 0,
            pacing_gain: 1.0,
            congestion_window_gain: 1.0,
            congestion_window_gain_constant: 2.0,
            num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
            cycle_current_offset: 0,
            last_cycle_start: 0,
            is_at_full_bandwidth: false,
            rounds_without_bandwidth_gain: 0,
            bandwidth_at_last_round: 0,
            exiting_quiescence: false,
            exit_probe_rtt_at: 0,
            probe_rtt_round_passed: false,
            last_sample_is_app_limited: false,
            has_no_app_limited_sample: false,
            recovery_state: RecoveryState::NotInRecovery,
            end_recovery_at: INVALID_PACKET_NUMBER,
            recovery_window: initial_max_congestion_window,
            enable_ack_aggregation_during_startup: false,
            expire_ack_aggregation_in_startup: false,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_while_detecting_overshooting: 0,
            bytes_lost_multiplier_while_detecting_overshooting: 2,
            cwnd_to_calculate_min_pacing_rate: initial_congestion_window,
            max_datagram_size: initial_max_datagram_size,
            bytes_in_flight: 0,
            gain_cycle_draw: GainCycleDraw::Random,
        };
        sender.apply_profile(profile);
        sender.enter_startup_mode(now);
        sender
    }

    fn apply_profile(&mut self, profile: BbrProfile) {
        let config = profile.config();
        self.profile = profile;
        self.high_gain = config.high_gain;
        self.high_cwnd_gain = config.high_cwnd_gain;
        self.drain_gain = 1.0 / config.high_gain;
        self.congestion_window_gain_constant = config.congestion_window_gain_constant;
        self.num_startup_rtts = config.num_startup_rtts;
        self.drain_to_target = config.drain_to_target;
        self.detect_overshooting = config.detect_overshooting;
        self.bytes_lost_multiplier_while_detecting_overshooting = config.bytes_lost_multiplier;
        self.enable_ack_aggregation_during_startup = config.enable_ack_aggregation_startup;
        self.expire_ack_aggregation_in_startup = config.expire_ack_aggregation_startup;
        if config.enable_overestimate_avoidance {
            self.sampler.enable_overestimate_avoidance();
        }
        self.sampler.set_reduce_extra_acked_on_bandwidth_increase(
            config.reduce_extra_acked_on_bandwidth_increase,
        );
    }

    pub(crate) fn profile(&self) -> BbrProfile {
        self.profile
    }

    #[cfg(test)]
    pub(crate) fn set_gain_cycle_draw(&mut self, draw: GainCycleDraw) {
        self.gain_cycle_draw = draw;
    }

    /// A raw RTT sample, as quic-go's `RTTStats.UpdateRTT` sees it before
    /// the congestion event of the same ACK: the smallest positive one is
    /// the RTT stats' minimum.
    pub(crate) fn on_rtt_sample(&mut self, rtt: Nanos) {
        if rtt > 0 && (self.rtt_stats_min_rtt == 0 || rtt < self.rtt_stats_min_rtt) {
            self.rtt_stats_min_rtt = rtt;
        }
    }

    fn rescale_packet_sized_windows(&mut self, max_datagram_size: ByteCount) {
        let old = self.max_datagram_size;
        self.max_datagram_size = max_datagram_size;
        self.initial_congestion_window = scale_byte_window_for_datagram_size(
            self.initial_congestion_window,
            old,
            max_datagram_size,
        );
        self.max_congestion_window =
            scale_byte_window_for_datagram_size(self.max_congestion_window, old, max_datagram_size);
        self.min_congestion_window = min_congestion_window_for_max_datagram_size(max_datagram_size);
        self.cwnd_to_calculate_min_pacing_rate = scale_byte_window_for_datagram_size(
            self.cwnd_to_calculate_min_pacing_rate,
            old,
            max_datagram_size,
        );
    }

    /// `OnPacketSent`. quic-go reports every packet, with the bytes in
    /// flight after counting it when it is retransmittable.
    pub(crate) fn on_packet_sent(
        &mut self,
        sent_time: Time,
        bytes_in_flight: ByteCount,
        packet_number: PacketNumber,
        bytes: ByteCount,
        is_retransmittable: bool,
    ) {
        self.last_sent_packet = packet_number;
        self.bytes_in_flight = bytes_in_flight;
        if bytes_in_flight == 0 {
            self.exiting_quiescence = true;
        }
        self.sampler.on_packet_sent(
            sent_time,
            packet_number,
            bytes,
            bytes_in_flight,
            is_retransmittable,
        );
    }

    /// `SetMaxDatagramSize`, which Go only allows to grow.
    pub(crate) fn set_max_datagram_size(&mut self, size: ByteCount) {
        if size <= 0 {
            return;
        }
        let old_min_congestion_window = self.min_congestion_window;
        let old_initial_congestion_window = self.initial_congestion_window;
        self.rescale_packet_sized_windows(size);
        if self.congestion_window == old_min_congestion_window {
            self.congestion_window = self.min_congestion_window;
        } else if self.congestion_window == old_initial_congestion_window {
            self.congestion_window = self.initial_congestion_window;
        } else {
            self.congestion_window = self
                .max_congestion_window
                .min(self.congestion_window.max(self.min_congestion_window));
        }
        self.recovery_window = self
            .max_congestion_window
            .min(self.recovery_window.max(self.min_congestion_window));
    }

    #[cfg(test)]
    pub(crate) fn max_datagram_size(&self) -> ByteCount {
        self.max_datagram_size
    }

    pub(crate) fn in_recovery(&self) -> bool {
        self.recovery_state != RecoveryState::NotInRecovery
    }

    /// `GetCongestionWindow`.
    pub(crate) fn congestion_window(&self) -> ByteCount {
        if self.mode == Mode::ProbeRtt {
            return self.probe_rtt_congestion_window();
        }
        if self.in_recovery() {
            return self.congestion_window.min(self.recovery_window);
        }
        self.congestion_window
    }

    /// `OnCongestionEventEx`: the packets one ACK frame acknowledged and
    /// those it, or a loss timer, declared lost, in ascending order.
    pub(crate) fn on_congestion_event(
        &mut self,
        prior_in_flight: ByteCount,
        event_time: Time,
        acked_packets: &[AckedPacket],
        lost_packets: &[LostPacket],
    ) {
        // quic-go never reports an empty event; Go would index past the end
        // of one.
        if acked_packets.is_empty() && lost_packets.is_empty() {
            return;
        }
        let total_bytes_acked_before = self.sampler.total_bytes_acked();
        let total_bytes_lost_before = self.sampler.total_bytes_lost();

        let mut is_round_start = false;
        let mut min_rtt_expired = false;

        self.maybe_app_limited(prior_in_flight);

        self.bytes_in_flight = prior_in_flight;
        for packet in acked_packets {
            self.bytes_in_flight = self.bytes_in_flight.wrapping_sub(packet.bytes_acked);
        }
        for packet in lost_packets {
            self.bytes_in_flight = self.bytes_in_flight.wrapping_sub(packet.bytes_lost);
        }

        if let Some(last_acked) = acked_packets.last() {
            is_round_start = self.update_round_trip_counter(last_acked.packet_number);
            self.update_recovery_state(
                last_acked.packet_number,
                !lost_packets.is_empty(),
                is_round_start,
            );
        }

        let sample = self.sampler.on_congestion_event(
            event_time,
            acked_packets,
            lost_packets,
            self.max_bandwidth.best(),
            INF_BANDWIDTH,
            self.round_trip_count,
        );
        if sample.last_packet_send_state.is_valid {
            self.last_sample_is_app_limited = sample.last_packet_send_state.is_app_limited;
            self.has_no_app_limited_sample =
                self.has_no_app_limited_sample || !self.last_sample_is_app_limited;
        }
        // Leave the bandwidth filter alone for a loss-only event and for
        // acknowledgements that produced no valid sample: neither changes the
        // sampler's acknowledged total.
        if total_bytes_acked_before != self.sampler.total_bytes_acked()
            && (!sample.sample_is_app_limited
                || sample.sample_max_bandwidth > self.max_bandwidth.best())
        {
            self.max_bandwidth
                .update(sample.sample_max_bandwidth, self.round_trip_count);
        }

        if sample.sample_rtt != INF_RTT {
            min_rtt_expired = self.maybe_update_min_rtt(event_time, sample.sample_rtt);
        }
        let bytes_lost = self
            .sampler
            .total_bytes_lost()
            .wrapping_sub(total_bytes_lost_before);

        let excess_acked = sample.extra_acked;
        let last_packet_send_state = sample.last_packet_send_state;

        if !lost_packets.is_empty() {
            self.num_loss_events_in_round += 1;
            self.bytes_lost_in_round = self.bytes_lost_in_round.wrapping_add(bytes_lost);
        }

        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle_phase(event_time, prior_in_flight, !lost_packets.is_empty());
        }

        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bandwidth_reached(&last_packet_send_state);
        }

        self.maybe_exit_startup_or_drain(event_time);

        self.maybe_enter_or_exit_probe_rtt(event_time, is_round_start, min_rtt_expired);

        let bytes_acked = self
            .sampler
            .total_bytes_acked()
            .wrapping_sub(total_bytes_acked_before);

        // With the model updated, recalculate the pacing rate and windows.
        self.calculate_pacing_rate(bytes_lost);
        self.calculate_congestion_window(bytes_acked, excess_acked);
        self.calculate_recovery_window(bytes_acked, bytes_lost);

        // Forget packets that can no longer be acknowledged or lost. Xray
        // estimates the first outstanding packet from this event: fast
        // retransmission keeps it within two of the last acknowledgement.
        let least_unacked = match (acked_packets.last(), lost_packets.last()) {
            (Some(acked), _) => acked.packet_number.wrapping_sub(2),
            (None, Some(lost)) => lost.packet_number.wrapping_add(1),
            (None, None) => unreachable!("an empty event returned early"),
        };
        self.sampler.remove_obsolete_packets(least_unacked);

        if is_round_start {
            self.num_loss_events_in_round = 0;
            self.bytes_lost_in_round = 0;
        }
    }

    /// `PacingRate`, in bits per second: the initial window over the RTT at
    /// the high gain until a rate is calculated.
    pub(crate) fn pacing_rate(&self) -> Bandwidth {
        if self.pacing_rate == 0 {
            return (self.high_gain
                * bandwidth_from_delta(self.initial_congestion_window, self.min_rtt_estimate())
                    as f64) as Bandwidth;
        }
        self.pacing_rate
    }

    /// `bandwidthForPacer`: the pacing rate in bytes per second, never
    /// below 64 KiB/s so the pacer always makes progress.
    pub(crate) fn bandwidth_for_pacer(&self) -> ByteCount {
        let bytes_per_second = (self.pacing_rate() as f64 / BYTES_PER_SECOND as f64) as ByteCount;
        bytes_per_second.max(MIN_BPS)
    }

    fn bandwidth_estimate(&self) -> Bandwidth {
        self.max_bandwidth.best()
    }

    /// `getMinRtt`: the windowed minimum, else the RTT stats' minimum, else
    /// 100 ms.
    fn min_rtt_estimate(&self) -> Nanos {
        if self.min_rtt != 0 {
            return self.min_rtt;
        }
        if self.rtt_stats_min_rtt == 0 {
            100 * MILLISECOND
        } else {
            self.rtt_stats_min_rtt
        }
    }

    /// `getTargetCongestionWindow`.
    fn target_congestion_window(&self, gain: f64) -> ByteCount {
        let bdp = bdp_from_rtt_and_bandwidth(self.min_rtt_estimate(), self.bandwidth_estimate());
        let mut congestion_window = (gain * bdp as f64) as ByteCount;
        // Without a bandwidth sample the BDP is zero.
        if congestion_window == 0 {
            congestion_window = (gain * self.initial_congestion_window as f64) as ByteCount;
        }
        congestion_window.max(self.min_congestion_window)
    }

    fn probe_rtt_congestion_window(&self) -> ByteCount {
        self.min_congestion_window
    }

    fn maybe_update_min_rtt(&mut self, now: Time, sample_min_rtt: Nanos) -> bool {
        // Do not expire a minimum that was never set.
        let min_rtt_expired =
            self.min_rtt != 0 && now > self.min_rtt_timestamp.wrapping_add(MIN_RTT_EXPIRY);
        if min_rtt_expired || sample_min_rtt < self.min_rtt || self.min_rtt == 0 {
            self.min_rtt = sample_min_rtt;
            self.min_rtt_timestamp = now;
        }
        min_rtt_expired
    }

    fn enter_startup_mode(&mut self, _now: Time) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.congestion_window_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Time) {
        self.mode = Mode::ProbeBw;
        self.congestion_window_gain = self.congestion_window_gain_constant;
        // A random start in {0, 2..7}: never 1, so the raised gain is always
        // followed by the lowered one.
        self.cycle_current_offset = self.gain_cycle_draw.next() as usize % (GAIN_CYCLE_LENGTH - 1);
        if self.cycle_current_offset >= 1 {
            self.cycle_current_offset += 1;
        }
        self.last_cycle_start = now;
        self.pacing_gain = PACING_GAIN[self.cycle_current_offset];
    }

    /// Advances the round trip once a packet sent after the round's last one
    /// is acknowledged.
    fn update_round_trip_counter(&mut self, last_acked_packet: PacketNumber) -> bool {
        if self.current_round_trip_end == INVALID_PACKET_NUMBER
            || last_acked_packet > self.current_round_trip_end
        {
            self.round_trip_count += 1;
            self.current_round_trip_end = self.last_sent_packet;
            return true;
        }
        false
    }

    fn update_gain_cycle_phase(&mut self, now: Time, prior_in_flight: ByteCount, has_losses: bool) {
        // Usually the cycle advances once per minimum RTT.
        let mut should_advance_gain_cycling =
            now > self.last_cycle_start.wrapping_add(self.min_rtt_estimate());
        // While probing, stay until the flight reaches the gain's target,
        // unless losses say the buffers cannot hold that much.
        if self.pacing_gain > 1.0
            && !has_losses
            && prior_in_flight < self.target_congestion_window(self.pacing_gain)
        {
            should_advance_gain_cycling = false;
        }
        // While draining, leave early once the flight is down to the BDP.
        if self.pacing_gain < 1.0 && self.bytes_in_flight <= self.target_congestion_window(1.0) {
            should_advance_gain_cycling = true;
        }

        if should_advance_gain_cycling {
            self.cycle_current_offset = (self.cycle_current_offset + 1) % GAIN_CYCLE_LENGTH;
            self.last_cycle_start = now;
            // Stay in the low gain until the target BDP is hit.
            if self.drain_to_target
                && self.pacing_gain < 1.0
                && PACING_GAIN[self.cycle_current_offset] == 1.0
                && self.bytes_in_flight > self.target_congestion_window(1.0)
            {
                return;
            }
            self.pacing_gain = PACING_GAIN[self.cycle_current_offset];
        }
    }

    /// Counts the rounds without significant bandwidth growth.
    fn check_if_full_bandwidth_reached(&mut self, last_packet_send_state: &SendTimeState) {
        if self.last_sample_is_app_limited {
            return;
        }

        let target = (self.bandwidth_at_last_round as f64 * STARTUP_GROWTH_TARGET) as Bandwidth;
        if self.bandwidth_estimate() >= target {
            self.bandwidth_at_last_round = self.bandwidth_estimate();
            self.rounds_without_bandwidth_gain = 0;
            if self.expire_ack_aggregation_in_startup {
                // Expire old excess delivery now that the bandwidth grew.
                self.sampler
                    .reset_max_ack_height_tracker(0, self.round_trip_count);
            }
            return;
        }

        self.rounds_without_bandwidth_gain += 1;
        if self.rounds_without_bandwidth_gain >= self.num_startup_rtts
            || self.should_exit_startup_due_to_loss(last_packet_send_state)
        {
            self.is_at_full_bandwidth = true;
        }
    }

    fn maybe_app_limited(&mut self, bytes_in_flight: ByteCount) {
        if bytes_in_flight < self.target_congestion_window(1.0) {
            self.sampler.on_app_limited();
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Time) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.congestion_window_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && self.bytes_in_flight <= self.target_congestion_window(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Time,
        is_round_start: bool,
        min_rtt_expired: bool,
    ) {
        if min_rtt_expired && !self.exiting_quiescence && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            // The exit time waits for the flight to reach its small target.
            self.exit_probe_rtt_at = 0;
        }

        if self.mode == Mode::ProbeRtt {
            self.sampler.on_app_limited();

            if self.exit_probe_rtt_at == 0 {
                // The window is the minimum, plus one packet since QUIC
                // checks the window before sending.
                if self.bytes_in_flight
                    < self
                        .probe_rtt_congestion_window()
                        .wrapping_add(MAX_PACKET_BUFFER_SIZE)
                {
                    self.exit_probe_rtt_at = now.wrapping_add(PROBE_RTT_TIME);
                    self.probe_rtt_round_passed = false;
                }
            } else {
                if is_round_start {
                    self.probe_rtt_round_passed = true;
                }
                if now.wrapping_sub(self.exit_probe_rtt_at) >= 0 && self.probe_rtt_round_passed {
                    self.min_rtt_timestamp = now;
                    if !self.is_at_full_bandwidth {
                        self.enter_startup_mode(now);
                    } else {
                        self.enter_probe_bandwidth_mode(now);
                    }
                }
            }
        }

        self.exiting_quiescence = false;
    }

    fn update_recovery_state(
        &mut self,
        last_acked_packet: PacketNumber,
        has_losses: bool,
        is_round_start: bool,
    ) {
        // No recovery in STARTUP.
        if !self.is_at_full_bandwidth {
            return;
        }

        // Recovery ends after a round without losses.
        if has_losses {
            self.end_recovery_at = self.last_sent_packet;
        }

        match self.recovery_state {
            RecoveryState::NotInRecovery => {
                if has_losses {
                    self.recovery_state = RecoveryState::Conservation;
                    // CalculateRecoveryWindow sets the window from zero.
                    self.recovery_window = 0;
                    // Conservation lasts a whole round: extend the current
                    // round as if it started now.
                    self.current_round_trip_end = self.last_sent_packet;
                }
            }
            RecoveryState::Conservation | RecoveryState::Growth => {
                if self.recovery_state == RecoveryState::Conservation && is_round_start {
                    self.recovery_state = RecoveryState::Growth;
                }
                // Go falls through from CONSERVATION into GROWTH's exit check.
                if !has_losses && last_acked_packet > self.end_recovery_at {
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            }
        }
    }

    fn calculate_pacing_rate(&mut self, bytes_lost: ByteCount) {
        if self.bandwidth_estimate() == 0 {
            return;
        }

        let target_rate = (self.pacing_gain * self.bandwidth_estimate() as f64) as Bandwidth;
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Pace at the initial window over the RTT once RTT measurements are
        // available.
        if self.pacing_rate == 0 && self.rtt_stats_min_rtt != 0 {
            self.pacing_rate =
                bandwidth_from_delta(self.initial_congestion_window, self.rtt_stats_min_rtt);
            return;
        }

        if self.detect_overshooting {
            self.bytes_lost_while_detecting_overshooting = self
                .bytes_lost_while_detecting_overshooting
                .wrapping_add(bytes_lost);
            // Overshooting: the rate is above the target and loss happened.
            // It is fairly sure with a non-application-limited sample, or
            // once enough of the initial window is lost: slow down.
            let lost_enough =
                self.bytes_lost_while_detecting_overshooting
                    .wrapping_mul(ByteCount::from(
                        self.bytes_lost_multiplier_while_detecting_overshooting,
                    ))
                    > self.initial_congestion_window;
            if self.pacing_rate > target_rate
                && self.bytes_lost_while_detecting_overshooting > 0
                && (self.has_no_app_limited_sample || lost_enough)
            {
                self.pacing_rate = target_rate.max(bandwidth_from_delta(
                    self.cwnd_to_calculate_min_pacing_rate,
                    self.rtt_stats_min_rtt,
                ));
                self.bytes_lost_while_detecting_overshooting = 0;
                self.detect_overshooting = false;
            }
        }

        // Do not lower the pacing rate during STARTUP.
        self.pacing_rate = self.pacing_rate.max(target_rate);
    }

    fn calculate_congestion_window(&mut self, bytes_acked: ByteCount, excess_acked: ByteCount) {
        if self.mode == Mode::ProbeRtt {
            return;
        }

        let mut target_window = self.target_congestion_window(self.congestion_window_gain);
        if self.is_at_full_bandwidth {
            // Add the largest recent ack aggregation.
            target_window = target_window.wrapping_add(self.sampler.max_ack_height());
        } else if self.enable_ack_aggregation_during_startup {
            // Add the latest excess: the window never shrinks in STARTUP, so
            // this acts as a very local maximum filter.
            target_window = target_window.wrapping_add(excess_acked);
        }

        // Grow toward the target by the bytes acknowledged at a time.
        if self.is_at_full_bandwidth {
            self.congestion_window =
                target_window.min(self.congestion_window.wrapping_add(bytes_acked));
        } else if self.congestion_window < target_window
            || self.sampler.total_bytes_acked() < self.initial_congestion_window
        {
            // Before STARTUP ends the window never shrinks.
            self.congestion_window = self.congestion_window.wrapping_add(bytes_acked);
        }

        self.congestion_window = self.congestion_window.max(self.min_congestion_window);
        self.congestion_window = self.congestion_window.min(self.max_congestion_window);
    }

    fn calculate_recovery_window(&mut self, bytes_acked: ByteCount, bytes_lost: ByteCount) {
        if self.recovery_state == RecoveryState::NotInRecovery {
            return;
        }

        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = self.bytes_in_flight.wrapping_add(bytes_acked);
            self.recovery_window = self.min_congestion_window.max(self.recovery_window);
            return;
        }

        // Remove losses, guarding against underflow.
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            self.recovery_window = self.max_datagram_size;
        }

        // CONSERVATION only subtracts losses; GROWTH also releases the bytes
        // acknowledged, like slow start.
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window = self.recovery_window.wrapping_add(bytes_acked);
        }

        // Always allow sending at least the bytes acknowledged in response.
        self.recovery_window = self
            .recovery_window
            .max(self.bytes_in_flight.wrapping_add(bytes_acked));
        self.recovery_window = self.min_congestion_window.max(self.recovery_window);
    }

    /// Whether STARTUP ends for excessive loss.
    fn should_exit_startup_due_to_loss(&self, last_packet_send_state: &SendTimeState) -> bool {
        if self.num_loss_events_in_round < DEFAULT_STARTUP_FULL_LOSS_COUNT
            || !last_packet_send_state.is_valid
        {
            return false;
        }
        let inflight_at_send = last_packet_send_state.bytes_in_flight;
        inflight_at_send > 0
            && self.bytes_lost_in_round > 0
            && self.bytes_lost_in_round
                > (inflight_at_send as f64 * QUIC_BBR2_DEFAULT_LOSS_THRESHOLD) as ByteCount
    }
}

#[cfg(test)]
mod oracle;
#[cfg(test)]
mod tests;
