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
//! [`XrayBbr`] runs the port of Xray's BBR sender ([`bbr`]) with its
//! `conservative`, `standard` and `aggressive` profiles.
//!
//! Xray replaces a connection's controller only once the connection is up:
//! XHTTP H3 right after the handshake, Hysteria after the server's
//! authentication reply, which also tells it whether Brutal applies. Until
//! then quic-go's default sender, Reno, runs. quinn builds a connection's
//! controller up front, so [`SwitchedFactory`] starts with NewReno and
//! switches to what [`ControllerSwitch::install`] names, as Xray's
//! `congestion.UseBBR` and `UseBrutal` replace the connection's sender.

mod bbr;

use std::any::Any;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, NewRenoConfig};
use quinn_proto::RttEstimator;

pub(crate) use bbr::BbrProfile;
use bbr::{AckedPacket, BbrSender, LostPacket, Time, UDP_INITIAL_PACKET_SIZE};

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

/// How far quic-go's clock is from zero when a controller is built: its
/// monotonic time starts an hour in the past, and zero means unset.
const QUIC_GO_CLOCK_START: Time = 3_600 * 1_000_000_000;

/// Xray's BBR sender ([`bbr::BbrSender`]) driven by quinn's callbacks.
///
/// quic-go hands its controller the bytes in flight after counting a sent
/// packet, every packet including ACK-only ones, and one
/// `OnCongestionEventEx` per ACK frame or loss timeout with the packets it
/// acknowledged and lost. quinn reports the same through
/// `on_sent_with_in_flight` (before counting), `on_sent_not_ack_eliciting`,
/// `on_ack_with_token` and `on_packet_lost_with_token`, closed by
/// `on_congestion_event_end`. A sent packet's delivery token is its packet
/// number, which the sender keys its samples by, as in quic-go.
#[derive(Debug, Clone)]
pub(crate) struct XrayBbr {
    sender: BbrSender,
    epoch: Instant,
    /// quinn's datagram size, which turns quic-go's window rule into quinn's.
    mtu: u64,
    acked: Vec<AckedPacket>,
    lost: Vec<LostPacket>,
}

impl XrayBbr {
    /// A sender seeded like Xray's `UseBBR`: with the smaller of QUIC's
    /// initial datagram size and the 1,280 bytes it assumes for UDP.
    pub(crate) fn new(profile: BbrProfile, now: Instant, initial_mtu: u16, mtu: u16) -> Self {
        let seed = i64::from(initial_mtu).min(UDP_INITIAL_PACKET_SIZE);
        Self {
            sender: BbrSender::new(QUIC_GO_CLOCK_START, seed, profile),
            epoch: now,
            mtu: u64::from(mtu),
            acked: Vec::new(),
            lost: Vec::new(),
        }
    }

    fn time(&self, now: Instant) -> Time {
        let elapsed = now.saturating_duration_since(self.epoch).as_nanos();
        QUIC_GO_CLOCK_START.saturating_add(i64::try_from(elapsed).unwrap_or(i64::MAX))
    }

    fn record_ack(&mut self, bytes: u64, token: u64) {
        self.acked.push(AckedPacket {
            packet_number: signed(token),
            bytes_acked: signed(bytes),
        });
    }
}

/// quinn counts bytes and packet numbers as `u64`, quic-go as `int64`.
fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl Controller for XrayBbr {
    fn on_sent_with_in_flight(
        &mut self,
        now: Instant,
        bytes: u64,
        last_packet_number: u64,
        in_flight: u64,
        _app_limited: bool,
    ) -> u64 {
        self.sender.on_packet_sent(
            self.time(now),
            signed(in_flight.saturating_add(bytes)),
            signed(last_packet_number),
            signed(bytes),
            true,
        );
        last_packet_number
    }

    fn on_sent_not_ack_eliciting(
        &mut self,
        now: Instant,
        bytes: u64,
        packet_number: u64,
        in_flight: u64,
    ) {
        self.sender.on_packet_sent(
            self.time(now),
            signed(in_flight),
            signed(packet_number),
            signed(bytes),
            false,
        );
    }

    fn on_ack_with_token(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        _rtt: &RttEstimator,
        token: u64,
    ) {
        self.record_ack(bytes, token);
    }

    fn on_rtt_sample(&mut self, _now: Instant, rtt: Duration, _app_limited: bool) {
        self.sender
            .on_rtt_sample(i64::try_from(rtt.as_nanos()).unwrap_or(i64::MAX));
    }

    fn on_packet_lost_with_token(&mut self, _now: Instant, bytes: u64, token: u64) {
        self.lost.push(LostPacket {
            packet_number: signed(token),
            bytes_lost: signed(bytes),
        });
    }

    /// A lost MTU probe is left out of the event. quic-go lists it for the
    /// sender, which then enters recovery as for any loss; a probe larger
    /// than the path carries is lost by design and says nothing of
    /// congestion (RFC 9000, section 14.4). The sampler drops the probe's
    /// record with the packets around it.
    fn on_mtu_probe_lost_with_token(&mut self, _now: Instant, _bytes: u64, _token: u64) {}

    fn on_congestion_event_end(&mut self, now: Instant, prior_in_flight: u64) {
        if self.acked.is_empty() && self.lost.is_empty() {
            return;
        }
        // quic-go lists both in packet-number order.
        self.acked.sort_by_key(|packet| packet.packet_number);
        self.lost.sort_by_key(|packet| packet.packet_number);
        let time = self.time(now);
        self.sender
            .on_congestion_event(signed(prior_in_flight), time, &self.acked, &self.lost);
        self.acked.clear();
        self.lost.clear();
    }

    /// The sender reacts to the losses of the whole event, in
    /// `on_congestion_event_end`; like quic-go's BBR it ignores persistent
    /// congestion and ECN.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
        self.sender.set_max_datagram_size(i64::from(new_mtu));
    }

    /// quic-go sends while the bytes in flight are below the window; quinn
    /// sends a packet while the flight plus that packet stays below it.
    fn window(&self) -> u64 {
        u64::try_from(self.sender.congestion_window())
            .unwrap_or(0)
            .saturating_add(self.mtu)
    }

    fn pacing_rate(&self) -> Option<u64> {
        u64::try_from(self.sender.bandwidth_for_pacer()).ok()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// What Xray's dialer installs once a connection is up, with
/// `congestion.UseBBR` or `UseBrutal`. Its `reno` keeps quic-go's default
/// sender, which needs no switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Installed {
    /// quinn's BBR, which `standard` keeps (see [`bbr_for_profile`]).
    QuinnBbr,
    /// Xray's BBR sender.
    XrayBbr(BbrProfile),
    Brutal(BrutalRate),
}

/// Whether `bbrProfile: standard`, the default, runs the port of Xray's
/// sender, switching from quic-go's startup Reno like the other profiles,
/// rather than quinn's BBR from the first packet. The port is complete for
/// `standard` too, but this moves every default Hysteria and XHTTP H3
/// connection to another congestion controller, so it waits for a decision.
pub(crate) const STANDARD_RUNS_XRAY_BBR: bool = false;

/// The BBR Xray's `UseBBR` installs for `profile`.
pub(crate) const fn bbr_for_profile(profile: BbrProfile) -> Installed {
    match profile {
        BbrProfile::Standard if !STANDARD_RUNS_XRAY_BBR => Installed::QuinnBbr,
        profile => Installed::XrayBbr(profile),
    }
}

/// Settles once what replaces a connection's startup controller.
#[derive(Debug, Default)]
pub(crate) struct ControllerSwitch(OnceLock<Installed>);

impl ControllerSwitch {
    /// Names the replacement; later calls are ignored.
    pub(crate) fn install(&self, installed: Installed) {
        let _ = self.0.set(installed);
    }

    fn installed(&self) -> Option<Installed> {
        self.0.get().copied()
    }
}

/// quic-go's initial congestion window in packets (`initialCongestionWindow`)
const QUIC_GO_INITIAL_WINDOW_PACKETS: u64 = 32;

/// quic-go's sender before Xray replaces it: Reno, as quinn's NewReno, from
/// quic-go's initial window of 32 packets of the initial size. A ChromeParrot
/// connection's packet number lengths are read off this window.
fn startup_controller(now: Instant, mtu: u16) -> Box<dyn Controller> {
    let mut reno = NewRenoConfig::default();
    reno.initial_window(QUIC_GO_INITIAL_WINDOW_PACKETS * u64::from(mtu));
    Arc::new(reno).build(now, mtu)
}

/// quic-go's default sender for a connection that keeps it: Xray's
/// `congestion: reno`. quinn's own NewReno starts at 10 packets, which is a
/// slower start than Xray's and gives a ChromeParrot handshake other packet
/// number lengths.
pub(crate) struct RenoFactory;

impl ControllerFactory for RenoFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        startup_controller(now, current_mtu)
    }
}

/// Builds controllers that start as quic-go's default sender, as an Xray
/// connection does, and switch once [`ControllerSwitch::install`] names the
/// replacement: after the handshake on XHTTP, after authentication on
/// Hysteria.
pub(crate) struct SwitchedFactory(pub(crate) Arc<ControllerSwitch>);

impl ControllerFactory for SwitchedFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let mut controller = Switched {
            startup: startup_controller(now, current_mtu),
            replacement: None,
            switch: Arc::clone(&self.0),
            initial_mtu: current_mtu,
            mtu: current_mtu,
            min_rtt: None,
            smoothed_rtt: None,
            sent_packets: 0,
        };
        controller.settle(now);
        Box::new(controller)
    }
}

/// Marks a token as a packet sent before the switch; the rest of it is the
/// packet's place among all the connection sent.
const SENT_BEFORE_SWITCH: u64 = 1 << 63;

/// The replacement and the kind it is, which says how it reads tokens.
struct Replacement {
    installed: Installed,
    controller: Box<dyn Controller>,
}

impl Replacement {
    /// The number the replacement knows a sent packet by. Xray's BBR keys
    /// its samples, rounds and recovery by one number per packet, and QUIC
    /// numbers each packet space from zero: it gets the packet's place among
    /// all the connection sent. The others get the packet number.
    fn number(&self, sequence: u64, packet_number: u64) -> u64 {
        match self.installed {
            Installed::XrayBbr(_) => sequence,
            Installed::QuinnBbr | Installed::Brutal(_) => packet_number,
        }
    }

    /// The token the replacement reads for a packet: its own, the packet's
    /// place among all sent for Xray's BBR when sent before the switch, or
    /// `None` for quinn's untokened path.
    fn token(&self, token: u64) -> Option<u64> {
        if token & SENT_BEFORE_SWITCH == 0 {
            return Some(token);
        }
        match self.installed {
            Installed::XrayBbr(_) => Some(token & !SENT_BEFORE_SWITCH),
            Installed::QuinnBbr | Installed::Brutal(_) => None,
        }
    }
}

/// quic-go's default sender until the switch, then a fresh replacement that,
/// like Xray's, starts without the old one's history but with the
/// connection's RTT statistics, which quic-go hands it. Packets sent before
/// the switch carry their place among all sent as token, so Xray's BBR can
/// tell them from its own when they are acknowledged or lost, as quic-go's
/// does. quic-go hands its sender packet numbers, which repeat between the
/// Initial, Handshake and 1-RTT spaces: an acknowledged Handshake packet
/// then closes the sample of the 1-RTT packet with its number. Here every
/// packet has a number of its own, in the order sent.
struct Switched {
    startup: Box<dyn Controller>,
    replacement: Option<Replacement>,
    switch: Arc<ControllerSwitch>,
    initial_mtu: u16,
    mtu: u16,
    /// quic-go's `MinRTT`: the smallest raw RTT sample so far.
    min_rtt: Option<Duration>,
    /// The path's latest smoothed RTT.
    smoothed_rtt: Option<Duration>,
    /// How many packets the connection sent, in every packet number space.
    sent_packets: u64,
}

impl Switched {
    /// The place of the packet being sent among all the connection sent.
    fn next_sequence(&mut self) -> u64 {
        let sequence = self.sent_packets;
        self.sent_packets += 1;
        sequence
    }

    fn settle(&mut self, now: Instant) {
        if self.replacement.is_some() {
            return;
        }
        let Some(installed) = self.switch.installed() else {
            return;
        };
        let controller: Box<dyn Controller> = match installed {
            Installed::QuinnBbr => quinn_bbr().build(now, self.mtu),
            Installed::XrayBbr(profile) => {
                let mut bbr = XrayBbr::new(profile, now, self.initial_mtu, self.mtu);
                if let Some(min_rtt) = self.min_rtt {
                    bbr.on_rtt_sample(now, min_rtt, false);
                }
                Box::new(bbr)
            }
            Installed::Brutal(rate) => {
                let mut brutal = Brutal::new(rate, now, self.mtu);
                if let Some(smoothed) = self.smoothed_rtt {
                    brutal.observe_rtt(smoothed);
                }
                Box::new(brutal)
            }
        };
        self.replacement = Some(Replacement {
            installed,
            controller,
        });
    }

    fn active(&mut self, now: Instant) -> &mut dyn Controller {
        self.settle(now);
        match &mut self.replacement {
            Some(replacement) => replacement.controller.as_mut(),
            None => self.startup.as_mut(),
        }
    }

    fn current(&self) -> &dyn Controller {
        match &self.replacement {
            Some(replacement) => replacement.controller.as_ref(),
            None => self.startup.as_ref(),
        }
    }
}

impl Controller for Switched {
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
        let sequence = self.next_sequence();
        self.settle(now);
        match &mut self.replacement {
            Some(replacement) => replacement.controller.on_sent_with_in_flight(
                now,
                bytes,
                replacement.number(sequence, last_packet_number),
                in_flight,
                app_limited,
            ),
            None => {
                self.startup.on_sent_with_in_flight(
                    now,
                    bytes,
                    last_packet_number,
                    in_flight,
                    app_limited,
                );
                SENT_BEFORE_SWITCH | sequence
            }
        }
    }

    fn on_sent_not_ack_eliciting(
        &mut self,
        now: Instant,
        bytes: u64,
        packet_number: u64,
        in_flight: u64,
    ) {
        let sequence = self.next_sequence();
        self.settle(now);
        match &mut self.replacement {
            Some(replacement) => replacement.controller.on_sent_not_ack_eliciting(
                now,
                bytes,
                replacement.number(sequence, packet_number),
                in_flight,
            ),
            None => self
                .startup
                .on_sent_not_ack_eliciting(now, bytes, packet_number, in_flight),
        }
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
        self.smoothed_rtt = Some(rtt.get());
        self.settle(now);
        let Some(replacement) = &mut self.replacement else {
            return self
                .startup
                .on_ack_with_token(now, sent, bytes, app_limited, rtt, token);
        };
        match replacement.token(token) {
            Some(token) => {
                replacement
                    .controller
                    .on_ack_with_token(now, sent, bytes, app_limited, rtt, token)
            }
            // The replacement never issued this token.
            None => replacement
                .controller
                .on_ack(now, sent, bytes, app_limited, rtt),
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.smoothed_rtt = Some(rtt.get());
        self.active(now).on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_rtt_sample(&mut self, now: Instant, rtt: Duration, app_limited: bool) {
        if !rtt.is_zero() && self.min_rtt.is_none_or(|min| rtt < min) {
            self.min_rtt = Some(rtt);
        }
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

    fn on_packet_lost_with_token(&mut self, now: Instant, bytes: u64, token: u64) {
        self.settle(now);
        match &mut self.replacement {
            Some(replacement) => {
                if let Some(token) = replacement.token(token) {
                    replacement
                        .controller
                        .on_packet_lost_with_token(now, bytes, token);
                }
            }
            None => self.startup.on_packet_lost_with_token(now, bytes, token),
        }
    }

    fn on_mtu_probe_lost_with_token(&mut self, now: Instant, bytes: u64, token: u64) {
        self.settle(now);
        match &mut self.replacement {
            Some(replacement) => {
                if let Some(token) = replacement.token(token) {
                    replacement
                        .controller
                        .on_mtu_probe_lost_with_token(now, bytes, token);
                }
            }
            None => self.startup.on_mtu_probe_lost_with_token(now, bytes, token),
        }
    }

    fn on_congestion_event_end(&mut self, now: Instant, prior_in_flight: u64) {
        self.active(now)
            .on_congestion_event_end(now, prior_in_flight);
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
        self.startup.on_mtu_update(new_mtu);
        if let Some(replacement) = &mut self.replacement {
            replacement.controller.on_mtu_update(new_mtu);
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
            startup: self.startup.clone_box(),
            replacement: self.replacement.as_ref().map(|replacement| Replacement {
                installed: replacement.installed,
                controller: replacement.controller.clone_box(),
            }),
            switch: Arc::clone(&self.switch),
            initial_mtu: self.initial_mtu,
            mtu: self.mtu,
            min_rtt: self.min_rtt,
            smoothed_rtt: self.smoothed_rtt,
            sent_packets: self.sent_packets,
        })
    }

    fn initial_window(&self) -> u64 {
        self.current().initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// The controller a connection runs now, by name: `new-reno`, `quinn-bbr`,
/// `xray-bbr-conservative`, `xray-bbr-standard`, `xray-bbr-aggressive` or
/// `brutal`.
pub(crate) fn controller_name(controller: Box<dyn Controller>) -> &'static str {
    fn name(controller: Box<dyn Any>) -> &'static str {
        let controller = match controller.downcast::<Switched>() {
            Ok(switched) => {
                return match switched.replacement {
                    Some(replacement) => name(replacement.controller.into_any()),
                    None => name(switched.startup.into_any()),
                }
            }
            Err(other) => other,
        };
        if let Some(bbr) = controller.downcast_ref::<XrayBbr>() {
            return match bbr.sender.profile() {
                BbrProfile::Conservative => "xray-bbr-conservative",
                BbrProfile::Standard => "xray-bbr-standard",
                BbrProfile::Aggressive => "xray-bbr-aggressive",
            };
        }
        if controller.is::<Brutal>() {
            "brutal"
        } else if controller.is::<quinn::congestion::Bbr>() {
            "quinn-bbr"
        } else if controller.is::<quinn::congestion::NewReno>() {
            "new-reno"
        } else {
            "other"
        }
    }
    name(controller.into_any())
}

/// quinn's BBR as this project configures it: quic-go's 32-datagram initial
/// window of 1,280 bytes.
pub(crate) fn quinn_bbr() -> Arc<BbrConfig> {
    let mut bbr = BbrConfig::default();
    bbr.initial_window(QUINN_BBR_INITIAL_WINDOW);
    Arc::new(bbr)
}

const QUINN_BBR_INITIAL_WINDOW: u64 = 32 * 1280;

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

    fn switched(switch: &Arc<ControllerSwitch>) -> Box<dyn Controller> {
        Arc::new(SwitchedFactory(Arc::clone(switch))).build(Instant::now(), 1200)
    }

    fn downcast(controller: Box<dyn Controller>) -> Box<Switched> {
        controller.into_any().downcast::<Switched>().ok().unwrap()
    }

    #[test]
    fn the_startup_controller_runs_until_a_replacement_is_installed() {
        let switch = Arc::new(ControllerSwitch::default());
        let mut controller = switched(&switch);
        let reno = startup_controller(Instant::now(), 1200);
        assert_eq!(
            reno.window(),
            32 * 1200,
            "quic-go starts Reno at 32 packets"
        );
        assert_eq!(controller.window(), reno.window());
        assert_eq!(controller.pacing_rate(), None, "Reno paces from its window");
        let now = Instant::now();
        let token = controller.on_sent_with_in_flight(now, 1200, 7, 0, false);
        assert_eq!(
            token, SENT_BEFORE_SWITCH,
            "the connection's first packet, whatever its number"
        );

        switch.install(Installed::Brutal(BrutalRate {
            bytes_per_second: MIB,
            disable_loss_compensation: false,
        }));
        switch.install(Installed::QuinnBbr);
        assert_eq!(
            controller.on_sent_with_in_flight(now, 1200, 8, 1200, false),
            0
        );
        assert_eq!(
            controller.pacing_rate(),
            Some(MIB),
            "the first install wins"
        );
        assert_eq!(controller.window(), NO_RTT_WINDOW + 1200 + 1);
    }

    #[test]
    fn standard_keeps_quinn_bbr_and_other_profiles_run_xray_bbr() {
        assert_eq!(bbr_for_profile(BbrProfile::Standard), Installed::QuinnBbr);
        for profile in [BbrProfile::Conservative, BbrProfile::Aggressive] {
            assert_eq!(bbr_for_profile(profile), Installed::XrayBbr(profile));
            let switch = Arc::new(ControllerSwitch::default());
            switch.install(bbr_for_profile(profile));
            let controller = downcast(switched(&switch));
            let replacement = controller.replacement.unwrap();
            let bbr = replacement
                .controller
                .into_any()
                .downcast::<XrayBbr>()
                .ok()
                .unwrap();
            assert_eq!(bbr.sender.congestion_window(), 32 * 1200);
        }
    }

    /// The packets Xray's BBR saw, through the switch.
    fn xray_bbr_events(switch: &Arc<ControllerSwitch>) -> (Box<dyn Controller>, Instant) {
        let now = Instant::now();
        let mut controller = switched(switch);
        // Sent before the switch: packet 3, the connection's first.
        let early = controller.on_sent_with_in_flight(now, 1000, 3, 0, false);
        switch.install(Installed::XrayBbr(BbrProfile::Aggressive));
        let late = controller.on_sent_with_in_flight(now, 1100, 4, 1000, false);
        assert_eq!((early, late), (SENT_BEFORE_SWITCH, 1));
        let later = now + Duration::from_millis(30);
        controller.on_packet_lost_with_token(later, 1000, early);
        controller.on_packet_lost_with_token(later, 1100, late);
        (controller, later)
    }

    #[test]
    fn xray_bbr_reads_the_place_of_packets_sent_before_the_switch() {
        let switch = Arc::new(ControllerSwitch::default());
        let (controller, _) = xray_bbr_events(&switch);
        let controller = downcast(controller);
        let bbr = controller
            .replacement
            .unwrap()
            .controller
            .into_any()
            .downcast::<XrayBbr>()
            .ok()
            .unwrap();
        assert_eq!(
            bbr.lost,
            [
                LostPacket {
                    packet_number: 0,
                    bytes_lost: 1000
                },
                LostPacket {
                    packet_number: 1,
                    bytes_lost: 1100
                }
            ]
        );
    }

    fn xray_bbr(controller: Box<dyn Controller>) -> Box<XrayBbr> {
        let replacement = downcast(controller).replacement.unwrap();
        replacement
            .controller
            .into_any()
            .downcast::<XrayBbr>()
            .ok()
            .unwrap()
    }

    /// QUIC numbers the Initial, Handshake and 1-RTT spaces from zero each.
    /// The client's Finished, Handshake packet 1, is acknowledged or lost
    /// after 1-RTT packets 0 to 2 went out: handed to the sender by packet
    /// number, as quic-go hands it, that would be taken for 1-RTT packet 1
    /// and counted as its delivery or its loss.
    #[test]
    fn xray_bbr_tells_packets_of_different_spaces_apart() {
        let now = Instant::now();
        let switch = Arc::new(ControllerSwitch::default());
        let mut controller = switched(&switch);
        let finished = controller.on_sent_with_in_flight(now, 97, 1, 0, false);
        switch.install(Installed::XrayBbr(BbrProfile::Conservative));
        let data: Vec<u64> = (0..3)
            .map(|packet_number| {
                controller.on_sent_with_in_flight(now, 1200, packet_number, 0, false)
            })
            .collect();
        // A Handshake ACK after the switch, then 1-RTT packet 3.
        controller.on_sent_not_ack_eliciting(now, 50, 2, 3600);
        let last = controller.on_sent_with_in_flight(now, 1200, 3, 3600, false);
        assert_eq!(finished, SENT_BEFORE_SWITCH);
        assert_eq!((data, last), (vec![1, 2, 3], 5));

        // What the sender is told of each when it is acknowledged or lost.
        let later = now + Duration::from_millis(30);
        controller.on_packet_lost_with_token(later, 97, finished);
        controller.on_packet_lost_with_token(later, 1200, 2);
        assert_eq!(
            xray_bbr(controller).lost,
            [
                LostPacket {
                    packet_number: 0,
                    bytes_lost: 97
                },
                LostPacket {
                    packet_number: 2,
                    bytes_lost: 1200
                }
            ]
        );
    }

    /// quinn's BBR and Brutal still get packet numbers: quinn's BBR ends its
    /// rounds on the largest acknowledged one.
    #[test]
    fn other_replacements_keep_packet_numbers() {
        let replacement = |installed| Replacement {
            installed,
            controller: startup_controller(Instant::now(), 1200),
        };
        let brutal = Installed::Brutal(BrutalRate {
            bytes_per_second: MIB,
            disable_loss_compensation: false,
        });
        assert_eq!(replacement(Installed::QuinnBbr).number(9, 4), 4);
        assert_eq!(replacement(brutal).number(9, 4), 4);
        let bbr = Installed::XrayBbr(BbrProfile::Aggressive);
        assert_eq!(replacement(bbr).number(9, 4), 9);
    }

    /// A lost MTU probe is no sign of congestion: the sender is not told of
    /// it, directly or through the switch, and keeps its window, where an
    /// ordinary loss is listed for the event.
    #[test]
    fn xray_bbr_leaves_a_lost_mtu_probe_out_of_the_event() {
        let now = Instant::now();
        let switch = Arc::new(ControllerSwitch::default());
        switch.install(Installed::XrayBbr(BbrProfile::Conservative));
        let mut controller = switched(&switch);
        let tokens: Vec<u64> = (0..4)
            .map(|packet_number| {
                controller.on_sent_with_in_flight(now, 1200, packet_number, 0, false)
            })
            .collect();
        let probe = controller.on_sent_with_in_flight(now, 1400, 4, 4800, false);
        let window = controller.window();
        let later = now + Duration::from_millis(30);

        controller.on_mtu_probe_lost_with_token(later, 1400, probe);
        controller.on_congestion_event_end(later, 6200);
        assert_eq!(controller.window(), window);
        let mut bbr = xray_bbr(controller);
        assert_eq!(bbr.lost, []);

        bbr.on_packet_lost_with_token(later, 1200, tokens[3]);
        assert_eq!(bbr.lost.len(), 1);
    }

    #[test]
    fn reno_starts_at_quic_gos_window() {
        let now = Instant::now();
        let reno = Arc::new(RenoFactory).build(now, 1200);
        assert_eq!(reno.window(), 32 * 1200);
        assert_eq!(
            reno.window(),
            switched(&Arc::new(ControllerSwitch::default())).window(),
            "the sender every other Xray connection starts with"
        );
        assert_eq!(controller_name(reno), "new-reno");
    }

    #[test]
    fn replacements_read_tokens_of_packets_sent_before_the_switch() {
        let replacement = |installed| Replacement {
            installed,
            controller: startup_controller(Instant::now(), 1200),
        };
        let bbr = replacement(Installed::XrayBbr(BbrProfile::Conservative));
        assert_eq!(bbr.token(SENT_BEFORE_SWITCH | 9), Some(9));
        assert_eq!(bbr.token(9), Some(9));
        let brutal = replacement(Installed::Brutal(BrutalRate {
            bytes_per_second: MIB,
            disable_loss_compensation: false,
        }));
        for other in [replacement(Installed::QuinnBbr), brutal] {
            assert_eq!(other.token(SENT_BEFORE_SWITCH | 9), None);
            assert_eq!(other.token(5), Some(5));
        }
    }

    #[test]
    fn an_event_end_hands_xray_bbr_the_whole_event_in_order() {
        let now = Instant::now();
        let mut bbr = XrayBbr::new(BbrProfile::Conservative, now, 1200, 1200);
        for packet_number in 0..4 {
            bbr.on_sent_with_in_flight(now, 1200, packet_number, packet_number * 1200, false);
        }
        assert_eq!(bbr.sender.max_datagram_size(), 1200);
        let later = now + Duration::from_millis(40);
        bbr.on_rtt_sample(later, Duration::from_millis(40), false);
        bbr.record_ack(1200, 3);
        bbr.record_ack(1200, 2);
        bbr.on_packet_lost_with_token(later, 1200, 1);
        bbr.on_packet_lost_with_token(later, 1200, 0);
        let mut reference = BbrSender::new(QUIC_GO_CLOCK_START, 1200, BbrProfile::Conservative);
        for packet_number in 0..4 {
            reference.on_packet_sent(
                QUIC_GO_CLOCK_START,
                (packet_number + 1) * 1200,
                packet_number,
                1200,
                true,
            );
        }
        reference.on_rtt_sample(40_000_000);
        reference.on_congestion_event(
            4 * 1200,
            QUIC_GO_CLOCK_START + 40_000_000,
            &[
                AckedPacket {
                    packet_number: 2,
                    bytes_acked: 1200,
                },
                AckedPacket {
                    packet_number: 3,
                    bytes_acked: 1200,
                },
            ],
            &[
                LostPacket {
                    packet_number: 0,
                    bytes_lost: 1200,
                },
                LostPacket {
                    packet_number: 1,
                    bytes_lost: 1200,
                },
            ],
        );
        bbr.on_congestion_event_end(later, 4 * 1200);
        assert!(bbr.acked.is_empty() && bbr.lost.is_empty());
        assert_eq!(format!("{:?}", bbr.sender), format!("{reference:?}"));
        assert_eq!(
            bbr.window(),
            reference.congestion_window() as u64 + 1200,
            "quinn's window is quic-go's plus the packet it checks"
        );
        assert_eq!(
            bbr.pacing_rate(),
            Some(reference.bandwidth_for_pacer() as u64)
        );
        // Nothing to report: no event.
        bbr.on_congestion_event_end(later, 0);
        assert_eq!(format!("{:?}", bbr.sender), format!("{reference:?}"));
        // A loss timeout: quinn reports a lost MTU probe after the others,
        // and the last lost packet bounds what the sampler forgets.
        for packet_number in 4..8 {
            bbr.on_sent_with_in_flight(later, 1200, packet_number, 0, false);
            reference.on_packet_sent(
                QUIC_GO_CLOCK_START + 40_000_000,
                1200,
                packet_number as i64,
                1200,
                true,
            );
        }
        bbr.on_packet_lost_with_token(later, 1200, 6);
        bbr.on_packet_lost_with_token(later, 1200, 5);
        bbr.on_congestion_event_end(later, 4 * 1200);
        reference.on_congestion_event(
            4 * 1200,
            QUIC_GO_CLOCK_START + 40_000_000,
            &[],
            &[
                LostPacket {
                    packet_number: 5,
                    bytes_lost: 1200,
                },
                LostPacket {
                    packet_number: 6,
                    bytes_lost: 1200,
                },
            ],
        );
        assert_eq!(format!("{:?}", bbr.sender), format!("{reference:?}"));
    }

    #[test]
    fn xrays_dialers_choose_the_controller_they_install() {
        use crate::stream::{H3BbrProfile, H3Congestion, H3QuicConfig};
        let config = |congestion| H3QuicConfig {
            congestion,
            brutal_disable_loss_compensation: true,
            ..H3QuicConfig::default()
        };
        let brutal = |bytes_per_second| {
            Some(Installed::Brutal(BrutalRate {
                bytes_per_second,
                disable_loss_compensation: true,
            }))
        };
        let negotiated = |up_bytes_per_second, bbr_profile| {
            config(H3Congestion::Brutal {
                up_bytes_per_second,
                bbr_profile,
            })
        };
        // Brutal at the lower rate once both are known.
        let aggressive = negotiated(10 * MIB, H3BbrProfile::Aggressive);
        assert_eq!(aggressive.installed_controller(Some(MIB)), brutal(MIB));
        assert_eq!(
            aggressive.installed_controller(Some(20 * MIB)),
            brutal(10 * MIB)
        );
        // Otherwise the profile's BBR.
        for rate in [Some(0), None] {
            assert_eq!(
                aggressive.installed_controller(rate),
                Some(Installed::XrayBbr(BbrProfile::Aggressive))
            );
        }
        assert_eq!(
            negotiated(0, H3BbrProfile::Conservative).installed_controller(Some(MIB)),
            Some(Installed::XrayBbr(BbrProfile::Conservative))
        );
        assert_eq!(
            negotiated(MIB, H3BbrProfile::Standard).installed_controller(Some(0)),
            Some(Installed::QuinnBbr)
        );
        let forced = config(H3Congestion::ForceBrutal {
            bytes_per_second: 10 * MIB,
        });
        assert_eq!(forced.installed_controller(Some(MIB)), brutal(10 * MIB));
        assert_eq!(
            config(H3Congestion::BbrConservative).installed_controller(None),
            Some(Installed::XrayBbr(BbrProfile::Conservative))
        );
        assert_eq!(
            config(H3Congestion::BbrStandard).installed_controller(None),
            None
        );
        assert_eq!(
            config(H3Congestion::Reno).installed_controller(Some(MIB)),
            None
        );
    }

    #[test]
    fn xray_bbr_is_seeded_with_at_most_1280_byte_datagrams() {
        let now = Instant::now();
        let bbr = XrayBbr::new(BbrProfile::Standard, now, 1452, 1452);
        assert_eq!(bbr.sender.max_datagram_size(), 1280);
        assert_eq!(bbr.window(), 32 * 1280 + 1452);
        let mut bbr = XrayBbr::new(BbrProfile::Standard, now, 1200, 1400);
        assert_eq!(bbr.sender.max_datagram_size(), 1200);
        bbr.on_mtu_update(1452);
        assert_eq!(bbr.sender.max_datagram_size(), 1452);
        assert_eq!(bbr.sender.congestion_window(), 32 * 1452);
    }

    #[test]
    fn a_replacement_starts_with_the_connections_rtt() {
        let switch = Arc::new(ControllerSwitch::default());
        let mut controller = switched(&switch);
        let now = Instant::now();
        for rtt in [30, 12, 20] {
            controller.on_rtt_sample(now, Duration::from_millis(rtt), false);
        }
        switch.install(Installed::XrayBbr(BbrProfile::Conservative));
        controller.on_sent_with_in_flight(now, 1200, 9, 0, false);
        let mut reference = BbrSender::new(QUIC_GO_CLOCK_START, 1200, BbrProfile::Conservative);
        reference.on_rtt_sample(12_000_000);
        assert_eq!(
            controller.pacing_rate(),
            Some(reference.bandwidth_for_pacer() as u64),
            "paced from the 12 ms minimum, not the 100 ms default"
        );

        let switch = Arc::new(ControllerSwitch::default());
        let mut switched = downcast(switched(&switch));
        switched.smoothed_rtt = Some(Duration::from_millis(100));
        switch.install(Installed::Brutal(BrutalRate {
            bytes_per_second: MIB,
            disable_loss_compensation: false,
        }));
        switched.settle(now);
        assert_eq!(
            switched.window(),
            2 * MIB / 10 + 1200 + 1,
            "two bandwidth-delay products at once"
        );
    }

    #[test]
    fn controllers_built_after_the_install_start_replaced() {
        let switch = Arc::new(ControllerSwitch::default());
        switch.install(Installed::Brutal(BrutalRate {
            bytes_per_second: 3 * MIB,
            disable_loss_compensation: false,
        }));
        let controller = switched(&switch);
        assert_eq!(controller.pacing_rate(), Some(3 * MIB));
    }
}
