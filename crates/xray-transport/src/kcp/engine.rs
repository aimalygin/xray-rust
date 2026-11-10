//! The mKCP connection, Xray-core v26.10.31's `Connection` with its sending
//! and receiving workers, without I/O or clocks: the driver hands it the
//! segments it receives and the milliseconds since the connection opened,
//! and sends the datagrams it leaves in `out`.
//!
//! Time and sequence numbers are `u32` and compared as Xray compares them,
//! wrapping where Xray wraps and not where it does not.
use std::collections::{HashMap, VecDeque};

use super::segment::{
    encode_data, AckSegment, CmdSegment, DataHeader, DataSegment, Segment, CMD_PING, CMD_TERMINATE,
    DATA_OVERHEAD, OPTION_CLOSE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    Active,
    /// Closed here; draining what is left to send.
    ReadyToClose,
    /// Closed by the peer.
    PeerClosed,
    /// Sending terminate commands before going away.
    Terminating,
    /// The peer is terminating.
    PeerTerminating,
    Terminated,
}

impl State {
    fn terminating(self) -> bool {
        matches!(self, Self::Terminating | Self::Terminated)
    }
}

/// `kcpSettings`, already checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Config {
    pub(super) mtu: u32,
    pub(super) tti: u32,
    pub(super) uplink_capacity: u32,
    pub(super) downlink_capacity: u32,
    pub(super) cwnd_multiplier: u32,
    pub(super) max_sending_window: u32,
}

impl Config {
    /// Segments per flush that `capacity` megabytes a second allow, at least 8.
    fn in_flight_size(&self, capacity: u32) -> u32 {
        (capacity.wrapping_mul(1024 * 1024) / self.mtu / (1000 / self.tti)).max(8)
    }

    fn sending_in_flight_size(&self) -> u32 {
        self.in_flight_size(self.uplink_capacity)
    }

    fn receiving_in_flight_size(&self) -> u32 {
        self.in_flight_size(self.downlink_capacity)
    }

    fn sending_buffer_size(&self) -> u32 {
        self.max_sending_window / self.mtu
    }
}

/// RFC 6298 round-trip estimation as `RoundTripInfo` does it.
#[derive(Debug)]
struct RoundTrip {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated_timestamp: u32,
}

impl RoundTrip {
    fn update_peer_rto(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated_timestamp) < 3000 {
            return;
        }
        self.updated_timestamp = current;
        self.rto = rto;
    }

    fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7FFF_FFFF {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            let delta = self.srtt.abs_diff(rtt);
            self.variation = 3u32.wrapping_mul(self.variation).wrapping_add(delta) / 4;
            self.srtt = 7u32.wrapping_mul(self.srtt).wrapping_add(rtt) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }
        let four = 4u32.wrapping_mul(self.variation);
        let rto = if self.min_rtt < four {
            self.srtt.wrapping_add(four)
        } else {
            self.srtt.wrapping_add(self.variation)
        };
        self.rto = rto.min(10_000) * 5 / 4;
        self.updated_timestamp = current;
    }
}

/// A data segment waiting for its ack.
#[derive(Debug)]
struct Unacked {
    number: u32,
    timestamp: u32,
    payload: Vec<u8>,
    timeout: u32,
    transmit: u32,
}

#[derive(Debug)]
struct SendingWorker {
    window: VecDeque<Unacked>,
    total_in_flight_size: u32,
    first_unacknowledged: u32,
    next_number: u32,
    remote_next_number: u32,
    control_window: u32,
    window_size: u32,
    first_unacknowledged_updated: bool,
    closed: bool,
}

impl SendingWorker {
    fn new(config: &Config) -> Self {
        Self {
            window: VecDeque::new(),
            total_in_flight_size: 0,
            first_unacknowledged: 0,
            next_number: 0,
            remote_next_number: 32,
            control_window: config.sending_in_flight_size(),
            window_size: config.sending_buffer_size(),
            first_unacknowledged_updated: false,
            closed: false,
        }
    }

    fn release(&mut self) {
        self.window.clear();
        self.closed = true;
    }

    /// Drops every segment numbered below `una`.
    fn clear(&mut self, una: u32) {
        while self
            .window
            .front()
            .is_some_and(|segment| segment.number < una)
        {
            self.window.pop_front();
        }
    }

    fn find_first_unacknowledged(&mut self) {
        let first = self.first_unacknowledged;
        self.first_unacknowledged = match self.window.front() {
            Some(segment) => segment.number,
            None => self.next_number,
        };
        if first != self.first_unacknowledged {
            self.first_unacknowledged_updated = true;
        }
    }

    fn process_receiving_next(&mut self, next_number: u32) {
        self.clear(next_number);
        self.find_first_unacknowledged();
    }

    fn remove(&mut self, number: u32) -> bool {
        for (index, segment) in self.window.iter().enumerate() {
            if segment.number > number {
                return false;
            }
            if segment.number == number {
                if self.total_in_flight_size > 0 {
                    self.total_in_flight_size -= 1;
                }
                self.window.remove(index);
                return true;
            }
        }
        false
    }

    fn process_ack(&mut self, number: u32) -> bool {
        // number < first_unacknowledged || number >= next_number
        if number.wrapping_sub(self.first_unacknowledged) > 0x7FFF_FFFF
            || number.wrapping_sub(self.next_number) < 0x7FFF_FFFF
        {
            return false;
        }
        let removed = self.remove(number);
        if removed {
            self.find_first_unacknowledged();
        }
        removed
    }

    fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        for segment in &mut self.window {
            if number == segment.number || number.wrapping_sub(segment.number) > 0x7FFF_FFFF {
                break;
            }
            if segment.transmit > 0 && segment.timeout > rto / 3 {
                segment.timeout -= rto / 3;
            }
        }
    }

    fn process_segment(
        &mut self,
        current: u32,
        segment: &AckSegment,
        rto: u32,
        round_trip: &mut RoundTrip,
    ) {
        if self.closed {
            return;
        }
        if self.remote_next_number < segment.receiving_window {
            self.remote_next_number = segment.receiving_window;
        }
        self.process_receiving_next(segment.receiving_next);
        if segment.numbers.is_empty() {
            return;
        }
        let mut max_ack = 0;
        let mut max_ack_removed = false;
        for &number in &segment.numbers {
            let removed = self.process_ack(number);
            if max_ack < number {
                max_ack = number;
                max_ack_removed = removed;
            }
        }
        if max_ack_removed {
            self.handle_fast_ack(max_ack, rto);
            let rtt = current.wrapping_sub(segment.timestamp);
            if rtt < 10_000 {
                round_trip.update(rtt, current);
            }
        }
    }

    fn push(&mut self, payload: Vec<u8>) -> bool {
        if self.closed || self.window.len() as u32 > self.window_size {
            return false;
        }
        self.window.push_back(Unacked {
            number: self.next_number,
            timestamp: 0,
            payload,
            timeout: 0,
            transmit: 0,
        });
        self.next_number = self.next_number.wrapping_add(1);
        true
    }

    fn on_packet_loss(&mut self, loss_rate: u32, rto: u32, config: &Config) {
        if rto == 0 {
            return;
        }
        if loss_rate >= 15 {
            self.control_window = 3u32.wrapping_mul(self.control_window) / 4;
        }
        if loss_rate <= 5 {
            self.control_window = self.control_window.wrapping_add(self.control_window / 4);
        }
        if self.control_window < 16 {
            self.control_window = 16;
        }
        self.control_window = self.control_window.min(config.sending_in_flight_size());
    }

    fn close_write(&mut self) {
        self.clear(0xFFFF_FFFF);
    }
}

#[derive(Debug)]
struct AckList {
    timestamps: Vec<u32>,
    numbers: Vec<u32>,
    next_flush: Vec<u32>,
    flush_candidates: Vec<u32>,
    dirty: bool,
    /// Xray names it mss; it is the segment size, header included.
    mtu: u32,
}

/// The most not-yet-due numbers an ack repeats.
const FLUSH_CANDIDATES: usize = 128;

impl AckList {
    /// A number already listed is acknowledged again at once, in its place:
    /// Xray lists it a second time, so a peer that repeats one segment grows
    /// the list, and every flush, without bound.
    fn add(&mut self, number: u32, timestamp: u32) {
        if let Some(listed) = self.numbers.iter().position(|&n| n == number) {
            self.timestamps[listed] = timestamp;
            self.next_flush[listed] = 0;
        } else {
            self.timestamps.push(timestamp);
            self.numbers.push(number);
            self.next_flush.push(0);
        }
        self.dirty = true;
    }

    fn clear(&mut self, una: u32) {
        let mut count = 0;
        for i in 0..self.numbers.len() {
            if self.numbers[i] < una {
                continue;
            }
            self.numbers[count] = self.numbers[i];
            self.timestamps[count] = self.timestamps[i];
            self.next_flush[count] = self.next_flush[i];
            count += 1;
        }
        if count < self.numbers.len() {
            self.numbers.truncate(count);
            self.timestamps.truncate(count);
            self.next_flush.truncate(count);
            self.dirty = true;
        }
    }

    fn new_segment(&self) -> AckSegment {
        AckSegment::new((i64::from(self.mtu) - 17) / 4)
    }

    /// The ack segments due at `current`, each as `write` sends it.
    fn flush(&mut self, current: u32, rto: u32, mut write: impl FnMut(AckSegment)) {
        self.flush_candidates.clear();
        let mut segment = self.new_segment();
        for i in 0..self.numbers.len() {
            if self.next_flush[i] > current {
                if self.flush_candidates.len() < FLUSH_CANDIDATES {
                    self.flush_candidates.push(self.numbers[i]);
                }
                continue;
            }
            segment.numbers.push(self.numbers[i]);
            segment.put_timestamp(self.timestamps[i]);
            self.next_flush[i] = current.wrapping_add((rto / 2).max(20));
            if segment.is_full() {
                write(std::mem::replace(&mut segment, self.new_segment()));
                self.dirty = false;
            }
        }
        if self.dirty || !segment.numbers.is_empty() {
            for &number in &self.flush_candidates {
                if segment.is_full() {
                    break;
                }
                segment.numbers.push(number);
            }
            write(segment);
            self.dirty = false;
        }
    }
}

#[derive(Debug)]
struct ReceivingWorker {
    /// Bytes handed over from the window and not read yet.
    left_over: VecDeque<u8>,
    window: HashMap<u32, Vec<u8>>,
    acks: AckList,
    next_number: u32,
    window_size: u32,
}

impl ReceivingWorker {
    fn new(config: &Config) -> Self {
        Self {
            left_over: VecDeque::new(),
            window: HashMap::new(),
            acks: AckList {
                timestamps: Vec::new(),
                numbers: Vec::new(),
                next_flush: Vec::new(),
                flush_candidates: Vec::with_capacity(FLUSH_CANDIDATES),
                dirty: false,
                mtu: config.mtu,
            },
            next_number: 0,
            window_size: config.receiving_in_flight_size(),
        }
    }

    fn release(&mut self) {
        self.left_over = VecDeque::new();
    }

    fn process_segment(&mut self, segment: DataSegment) {
        if segment.number.wrapping_sub(self.next_number) >= self.window_size {
            return;
        }
        self.acks.clear(segment.sending_next);
        self.acks.add(segment.number, segment.timestamp);
        self.window.entry(segment.number).or_insert(segment.payload);
    }

    fn is_data_available(&self) -> bool {
        self.window.contains_key(&self.next_number)
    }

    /// Copies what is in order into `out`; zero when nothing is.
    fn read(&mut self, out: &mut [u8]) -> usize {
        if self.left_over.is_empty() {
            while let Some(payload) = self.window.remove(&self.next_number) {
                self.next_number = self.next_number.wrapping_add(1);
                self.left_over.extend(payload);
            }
        }
        let count = out.len().min(self.left_over.len());
        for (slot, byte) in out.iter_mut().zip(self.left_over.drain(..count)) {
            *slot = byte;
        }
        count
    }

    fn update_necessary(&self) -> bool {
        !self.acks.numbers.is_empty()
    }
}

/// The largest payload a data segment carries: Xray reads one into an
/// 8192-byte buffer.
const MAX_SEGMENT_PAYLOAD: usize = 8192;

#[derive(Debug)]
pub(super) struct Engine {
    conv: u16,
    config: Config,
    state: State,
    state_begin_time: u32,
    last_incoming_time: u32,
    last_ping_time: u32,
    mss: u32,
    round_trip: RoundTrip,
    receiving: ReceivingWorker,
    sending: SendingWorker,
    /// Encoded segments to send, one datagram each.
    pub(super) out: Vec<Vec<u8>>,
    /// Xray's `dataInput` signal: a reader should look again.
    pub(super) input_ready: bool,
    /// Xray's `dataOutput` signal: a writer should look again.
    pub(super) output_ready: bool,
    /// Xray's `dataUpdater.WakeUp()`.
    pub(super) wake_data: bool,
}

/// Why a write took nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteBlocked {
    /// Not active: closed on either side.
    Closed,
    /// The sending window is full.
    Full,
}

impl Engine {
    pub(super) fn new(conv: u16, config: Config) -> Self {
        Self {
            conv,
            config,
            state: State::Active,
            state_begin_time: 0,
            last_incoming_time: 0,
            last_ping_time: 0,
            mss: config.mtu - DATA_OVERHEAD,
            round_trip: RoundTrip {
                variation: 0,
                srtt: 0,
                rto: 100,
                min_rtt: config.tti,
                updated_timestamp: 0,
            },
            receiving: ReceivingWorker::new(&config),
            sending: SendingWorker::new(&config),
            out: Vec::new(),
            input_ready: false,
            output_ready: false,
            wake_data: false,
        }
    }

    pub(super) fn state(&self) -> State {
        self.state
    }

    pub(super) fn tti(&self) -> u32 {
        self.config.tti
    }

    /// Whether Xray's data updater keeps running.
    pub(super) fn data_update_necessary(&self) -> bool {
        !self.state.terminating()
            && (!self.sending.window.is_empty() || self.receiving.update_necessary())
    }

    /// Whether Xray's data updater stays stopped on a wake-up.
    pub(super) fn data_update_terminated(&self) -> bool {
        self.state.terminating()
    }

    fn set_state(&mut self, state: State, current: u32) {
        self.state = state;
        self.state_begin_time = current;
        match state {
            State::Active | State::ReadyToClose => {}
            State::PeerClosed | State::Terminating | State::PeerTerminating => {
                self.sending.close_write();
            }
            State::Terminated => {
                self.sending.close_write();
                self.wake_data = true;
                // `Terminate`: the driver closes the socket once it has sent
                // what is queued.
                self.input_ready = true;
                self.output_ready = true;
                self.sending.release();
                self.receiving.release();
            }
        }
    }

    /// Stops a carrier that can no longer finish its pending write.
    pub(super) fn abort(&mut self, current: u32) {
        self.out.clear();
        self.set_state(State::Terminated, current);
    }

    /// `Close`: false when the connection was closed already.
    pub(super) fn close(&mut self, current: u32) -> bool {
        self.input_ready = true;
        self.output_ready = true;
        match self.state {
            State::ReadyToClose | State::Terminating | State::Terminated => return false,
            State::Active => self.set_state(State::ReadyToClose, current),
            State::PeerClosed => self.set_state(State::Terminating, current),
            State::PeerTerminating => self.set_state(State::Terminated, current),
        }
        true
    }

    /// Reads what has arrived in order. `None` at the end of the stream,
    /// zero when nothing is there yet.
    pub(super) fn read(&mut self, out: &mut [u8]) -> Option<usize> {
        if matches!(
            self.state,
            State::ReadyToClose | State::Terminating | State::Terminated
        ) {
            return None;
        }
        let count = self.receiving.read(out);
        if count > 0 {
            self.wake_data = true;
            return Some(count);
        }
        // Xray's `ReadMultiBuffer` ends the stream here once it is drained.
        if self.state == State::PeerTerminating {
            return None;
        }
        Some(0)
    }

    /// Queues as much of `data` as the sending window takes, in segments of
    /// at most the MSS.
    pub(super) fn write(&mut self, data: &[u8]) -> Result<usize, WriteBlocked> {
        let chunk = (self.mss as usize).min(MAX_SEGMENT_PAYLOAD);
        let mut written = 0;
        for piece in data.chunks(chunk) {
            if self.state != State::Active {
                break;
            }
            if !self.sending.push(piece.to_vec()) {
                break;
            }
            written += piece.len();
        }
        if written > 0 {
            self.wake_data = true;
            return Ok(written);
        }
        Err(if self.state == State::Active {
            WriteBlocked::Full
        } else {
            WriteBlocked::Closed
        })
    }

    fn on_peer_closed(&mut self, current: u32) {
        match self.state {
            State::ReadyToClose => self.set_state(State::Terminating, current),
            State::Active => self.set_state(State::PeerClosed, current),
            _ => {}
        }
    }

    fn handle_option(&mut self, option: u8, current: u32) {
        if option & OPTION_CLOSE == OPTION_CLOSE {
            self.on_peer_closed(current);
        }
    }

    /// `Input`: the segments of one datagram.
    pub(super) fn input(&mut self, segments: Vec<Segment>, current: u32) {
        self.last_incoming_time = current;
        for segment in segments {
            if segment.conv() != self.conv {
                break;
            }
            match segment {
                Segment::Data(segment) => {
                    self.handle_option(segment.option, current);
                    self.receiving.process_segment(segment);
                    if self.receiving.is_data_available() {
                        self.input_ready = true;
                    }
                    self.wake_data = true;
                }
                Segment::Ack(segment) => {
                    self.handle_option(segment.option, current);
                    let rto = self.round_trip.rto;
                    self.sending
                        .process_segment(current, &segment, rto, &mut self.round_trip);
                    self.output_ready = true;
                    self.wake_data = true;
                }
                Segment::Cmd(segment) => {
                    self.handle_option(segment.option, current);
                    if segment.cmd == CMD_TERMINATE {
                        match self.state {
                            State::Active | State::PeerClosed => {
                                self.set_state(State::PeerTerminating, current)
                            }
                            State::ReadyToClose => self.set_state(State::Terminating, current),
                            State::Terminating => self.set_state(State::Terminated, current),
                            State::PeerTerminating | State::Terminated => {}
                        }
                    }
                    if segment.option == OPTION_CLOSE || segment.cmd == CMD_TERMINATE {
                        self.input_ready = true;
                        self.output_ready = true;
                    }
                    self.sending.process_receiving_next(segment.receiving_next);
                    self.receiving.acks.clear(segment.sending_next);
                    self.round_trip.update_peer_rto(segment.peer_rto, current);
                }
            }
        }
    }

    fn close_option(&self) -> u8 {
        if self.state == State::ReadyToClose {
            OPTION_CLOSE
        } else {
            0
        }
    }

    fn ping(&mut self, current: u32, cmd: u8) {
        let segment = CmdSegment {
            conv: self.conv,
            cmd,
            option: self.close_option(),
            sending_next: self.sending.first_unacknowledged,
            receiving_next: self.receiving.next_number,
            peer_rto: self.round_trip.rto,
        };
        let mut datagram = Vec::with_capacity(16);
        segment.encode(&mut datagram);
        self.out.push(datagram);
        self.last_ping_time = current;
    }

    fn flush_acks(&mut self, current: u32) {
        let option = self.close_option();
        let Self {
            conv,
            receiving,
            out,
            round_trip,
            ..
        } = self;
        let receiving_next = receiving.next_number;
        let receiving_window = receiving.next_number.wrapping_add(receiving.window_size);
        receiving
            .acks
            .flush(current, round_trip.rto, |mut segment| {
                segment.conv = *conv;
                segment.receiving_next = receiving_next;
                segment.receiving_window = receiving_window;
                segment.option = option;
                let mut datagram = Vec::with_capacity(17 + 4 * segment.numbers.len());
                segment.encode(&mut datagram);
                out.push(datagram);
            });
    }

    fn flush_data(&mut self, current: u32) {
        if self.sending.closed {
            return;
        }
        let option = self.close_option();
        let config = self.config;
        let sending = &mut self.sending;
        let mut cwnd = config.sending_in_flight_size();
        let remote = sending
            .remote_next_number
            .wrapping_sub(sending.first_unacknowledged);
        if cwnd > remote {
            cwnd = remote;
        }
        if cwnd > sending.control_window {
            cwnd = sending.control_window;
        }
        let cwnd = cwnd.wrapping_mul(config.cwnd_multiplier);
        if !sending.window.is_empty() {
            let rto = self.round_trip.rto;
            let mut lost = 0u32;
            let mut in_flight = 0u32;
            for segment in &mut sending.window {
                if current.wrapping_sub(segment.timeout) >= 0x7FFF_FFFF {
                    continue;
                }
                if segment.transmit == 0 {
                    sending.total_in_flight_size = sending.total_in_flight_size.wrapping_add(1);
                } else {
                    lost = lost.wrapping_add(1);
                }
                segment.timeout = current.wrapping_add(rto);
                segment.timestamp = current;
                segment.transmit = segment.transmit.wrapping_add(1);
                let mut datagram =
                    Vec::with_capacity(DATA_OVERHEAD as usize + segment.payload.len());
                encode_data(
                    &mut datagram,
                    DataHeader {
                        conv: self.conv,
                        option,
                        timestamp: segment.timestamp,
                        number: segment.number,
                        sending_next: sending.first_unacknowledged,
                    },
                    &segment.payload,
                );
                self.out.push(datagram);
                in_flight += 1;
                if in_flight >= cwnd {
                    break;
                }
            }
            if in_flight > 0 && sending.total_in_flight_size != 0 {
                let rate = lost.wrapping_mul(100) / sending.total_in_flight_size;
                sending.on_packet_loss(rate, rto, &config);
            }
            sending.first_unacknowledged_updated = false;
        }
        let updated = sending.first_unacknowledged_updated;
        sending.first_unacknowledged_updated = false;
        if updated {
            self.ping(current, CMD_PING);
        }
    }

    /// `flush`, the work of both of Xray's updaters.
    pub(super) fn flush(&mut self, current: u32) {
        if self.state == State::Terminated {
            return;
        }
        if self.state == State::Active && current.wrapping_sub(self.last_incoming_time) >= 30_000 {
            self.close(current);
        }
        if self.state == State::ReadyToClose && self.sending.window.is_empty() {
            self.set_state(State::Terminating, current);
        }
        if self.state == State::Terminating {
            self.ping(current, CMD_TERMINATE);
            if current.wrapping_sub(self.state_begin_time) > 8000 {
                self.set_state(State::Terminated, current);
            }
            return;
        }
        if self.state == State::PeerTerminating
            && current.wrapping_sub(self.state_begin_time) > 4000
        {
            self.set_state(State::Terminating, current);
        }
        if self.state == State::ReadyToClose && current.wrapping_sub(self.state_begin_time) > 15_000
        {
            self.set_state(State::Terminating, current);
        }
        self.flush_acks(current);
        self.flush_data(current);
        if current.wrapping_sub(self.last_ping_time) >= 3000 {
            self.ping(current, CMD_PING);
        }
    }
}

#[cfg(test)]
mod tests;
