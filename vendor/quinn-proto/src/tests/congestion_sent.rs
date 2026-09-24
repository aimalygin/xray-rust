use super::*;
use crate::congestion::{Controller, ControllerFactory, CubicConfig};
use crate::connection::RttEstimator;
use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
struct Recorder(Arc<Mutex<Vec<u64>>>, Arc<AtomicU64>, Arc<AtomicU64>);

impl ControllerFactory for Recorder {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(RecordingController {
            bytes: self.0.clone(),
            window_override: self.1.clone(),
            rate_override: self.2.clone(),
            tokens: Default::default(),
            next_token: 1,
            rtt_samples: Vec::new(),
            fresh_rtt: false,
            rtt_before_end: 0,
            inner: Arc::new(CubicConfig::default()).build(now, mtu),
        })
    }
}

struct RecordingController {
    bytes: Arc<Mutex<Vec<u64>>>,
    window_override: Arc<AtomicU64>,
    rate_override: Arc<AtomicU64>,
    inner: Box<dyn Controller>,
    tokens: std::collections::BTreeMap<u64, (Instant, u64)>,
    next_token: u64,
    rtt_samples: Vec<Duration>,
    fresh_rtt: bool,
    rtt_before_end: usize,
}

impl Controller for RecordingController {
    fn on_sent_with_in_flight(
        &mut self,
        now: Instant,
        bytes: u64,
        pn: u64,
        _flight: u64,
        _limited: bool,
    ) -> u64 {
        self.on_sent(now, bytes, pn);
        let token = self.next_token;
        self.next_token += 1;
        assert!(self.tokens.insert(token, (now, bytes)).is_none());
        token
    }
    fn on_ack_with_token(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        limited: bool,
        rtt: &RttEstimator,
        token: u64,
    ) {
        assert_eq!(
            self.tokens.remove(&token),
            Some((sent, bytes)),
            "ACK must return this packet's original delivery token"
        );
        self.on_ack(now, sent, bytes, limited, rtt);
    }
    fn on_sent(&mut self, now: Instant, bytes: u64, last: u64) {
        self.bytes.lock().unwrap().push(bytes);
        self.inner.on_sent(now, bytes, last);
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        limited: bool,
        rtt: &RttEstimator,
    ) {
        self.inner.on_ack(now, sent, bytes, limited, rtt);
    }
    fn on_rtt_sample(&mut self, now: Instant, rtt: Duration, limited: bool) {
        self.rtt_samples.push(rtt);
        self.fresh_rtt = true;
        self.inner.on_rtt_sample(now, rtt, limited);
    }
    fn on_end_acks(&mut self, now: Instant, flight: u64, limited: bool, largest: Option<u64>) {
        if self.fresh_rtt {
            self.rtt_before_end += 1;
            self.fresh_rtt = false;
        }
        self.inner.on_end_acks(now, flight, limited, largest);
    }
    fn on_congestion_event(&mut self, now: Instant, sent: Instant, persistent: bool, lost: u64) {
        self.inner.on_congestion_event(now, sent, persistent, lost);
    }
    fn on_mtu_update(&mut self, mtu: u16) {
        self.inner.on_mtu_update(mtu);
    }
    fn window(&self) -> u64 {
        match self.window_override.load(Ordering::Relaxed) {
            0 => self.inner.window(),
            value => value,
        }
    }
    fn pacing_rate(&self) -> Option<u64> {
        match self.rate_override.load(Ordering::Relaxed) {
            0 => self.inner.pacing_rate(),
            value => Some(value),
        }
    }
    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            bytes: self.bytes.clone(),
            window_override: self.window_override.clone(),
            rate_override: self.rate_override.clone(),
            tokens: self.tokens.clone(),
            next_token: self.next_token,
            rtt_samples: self.rtt_samples.clone(),
            fresh_rtt: self.fresh_rtt,
            rtt_before_end: self.rtt_before_end,
            inner: self.inner.clone_box(),
        })
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

fn connected(
    discovery: bool,
) -> (
    Pair,
    ConnectionHandle,
    ConnectionHandle,
    Arc<Mutex<Vec<u64>>>,
) {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mut transport = TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(Recorder(
        recorded.clone(),
        Arc::default(),
        Arc::default(),
    )));
    if discovery {
        // The simulated path accepts DEFAULT_MTU. Oversized search probes
        // cannot be confused with ordinary packets padded to the known MTU.
        let mut mtu = MtuDiscoveryConfig::default();
        mtu.upper_bound(1600);
        transport.mtu_discovery_config(Some(mtu));
    } else {
        transport.mtu_discovery_config(None);
    }
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let mut pair = Pair::default();
    let (client, server) = pair.connect_with(config);
    (pair, client, server, recorded)
}

#[test]
fn gso_send_bytes_count_each_packet_once() {
    let (mut pair, client, _, recorded) = connected(false);
    recorded.lock().unwrap().clear();
    let stream = pair
        .client_conn_mut(client)
        .streams()
        .open(Dir::Uni)
        .unwrap();
    let payload = vec![0x5a; 32 * 1024];
    assert_eq!(
        pair.client_conn_mut(client)
            .send_stream(stream)
            .write(&payload)
            .unwrap(),
        payload.len()
    );
    let now = pair.time;
    let mut buffer = Vec::new();
    let transmit = pair
        .client_conn_mut(client)
        .poll_transmit(now, 8, &mut buffer)
        .unwrap();
    assert!(
        transmit.segment_size.is_some(),
        "test must exercise a multi-packet GSO transmit"
    );
    let samples = recorded.lock().unwrap();
    assert_eq!(
        samples.iter().sum::<u64>(),
        transmit.size as u64,
        "GSO send samples must preserve the total encrypted data packet bytes"
    );
}

#[test]
fn pure_ack_does_not_create_a_delivery_rate_send_sample() {
    let (mut pair, client, server, recorded) = connected(false);
    recorded.lock().unwrap().clear();
    let before = pair.client_conn_mut(client).stats().frame_tx.acks;
    pair.server_conn_mut(server).ping();
    pair.drive();
    let after = pair.client_conn_mut(client).stats().frame_tx.acks;
    assert!(after > before, "test must actually emit an ACK");
    assert!(
        recorded.lock().unwrap().is_empty(),
        "ACK-only packets have no matching congestion on_ack sample"
    );
}

#[test]
fn ack_eliciting_mtu_probe_creates_a_send_sample() {
    let (mut pair, client, _, recorded) = connected(true);
    assert!(
        pair.client_conn_mut(client)
            .stats()
            .path
            .sent_plpmtud_probes
            > 0
    );
    assert!(
        recorded
            .lock()
            .unwrap()
            .iter()
            .any(|&size| size > DEFAULT_MTU as u64),
        "ack-eliciting oversized MTU probes must be sampled even when subsequently lost"
    );
}

#[test]
fn delivery_tokens_survive_delayed_reordered_and_lost_packets() {
    let (mut pair, client, server, _) = connected(false);
    pair.latency = Duration::from_millis(25);
    let stream = pair
        .client_conn_mut(client)
        .streams()
        .open(Dir::Uni)
        .unwrap();
    let payload = vec![0x69; 64 * 1024];
    assert_eq!(
        pair.client_send(client, stream).write(&payload).unwrap(),
        payload.len()
    );
    pair.client_send(client, stream).finish().unwrap();
    let before = pair.client_conn_mut(client).stats().path.lost_packets;
    pair.drive_client();
    assert!(
        pair.server.inbound.pop_front().is_some(),
        "drop a real sent datagram"
    );
    if pair.server.inbound.len() > 1 {
        let front = pair.server.inbound.pop_front().unwrap();
        pair.server.inbound.push_back(front);
    }
    let mut idle = false;
    for _ in 0..1000 {
        if !pair.step() {
            idle = true;
            break;
        }
    }
    assert!(idle, "transfer must complete without an endless timer loop");
    assert!(pair.client_conn_mut(client).stats().path.lost_packets > before);
    assert_eq!(pair.server_streams(server).accept(Dir::Uni), Some(stream));
    let mut recv = pair.server_recv(server, stream);
    let mut chunks = recv.read(true).unwrap();
    let mut bytes = Vec::new();
    while let Some(chunk) = chunks.next(usize::MAX).unwrap() {
        bytes.extend_from_slice(&chunk.bytes);
    }
    let _ = chunks.finalize();
    assert_eq!(bytes, payload);
}

#[test]
fn measured_rtt_callback_arrives_before_batch_end() {
    let (mut pair, client, _, _) = connected(false);
    pair.latency = Duration::from_millis(25);
    pair.client_conn_mut(client).ping();
    pair.drive();
    let controller = pair
        .client_conn_mut(client)
        .congestion_state()
        .clone_box()
        .into_any();
    let recorder = controller.downcast::<RecordingController>().ok().unwrap();
    assert!(
        recorder.rtt_before_end > 0,
        "fresh RTT callback must reach the controller before ACK-batch completion"
    );
    assert!(recorder
        .rtt_samples
        .iter()
        .any(|rtt| *rtt >= Duration::from_millis(50)));
    assert!(
        !recorder.fresh_rtt,
        "RTT callback must belong to a completed ACK batch"
    );
}

fn pending_ack_bypasses_blocked_data(pacing: bool) {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let window = Arc::new(AtomicU64::new(0));
    let rate = Arc::new(AtomicU64::new(0));
    let mut transport = TransportConfig::default();
    transport.mtu_discovery_config(None);
    transport.congestion_controller_factory(Arc::new(Recorder(
        recorded.clone(),
        window.clone(),
        rate.clone(),
    )));
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let mut pair = Pair::default();
    let (client, server) = pair.connect_with(config);
    let stream = pair.client_streams(client).open(Dir::Uni).unwrap();
    assert_eq!(
        pair.client_send(client, stream)
            .write(&[0x5a; 64 * 1024])
            .unwrap(),
        64 * 1024
    );
    window.store(if pacing { 1024 * 1024 } else { 1 }, Ordering::Relaxed);
    if pacing {
        rate.store(1000, Ordering::Relaxed);
    }
    let now = pair.time;
    let mut buffer = Vec::new();
    let mut sent = 0;
    while pair
        .client_conn_mut(client)
        .poll_transmit(now, 1, &mut buffer)
        .is_some()
    {
        // Withhold these data packets, so no ACK can reopen the send window.
        buffer.clear();
        sent += 1;
        assert!(
            sent < 32,
            "pacing must block before all queued data is sent"
        );
    }
    assert_eq!(sent > 0, pacing);
    let before = pair.client_conn_mut(client).stats();
    recorded.lock().unwrap().clear();
    // Two peer packets require an ACK without advancing the pacing timer.
    pair.server_conn_mut(server).ping();
    pair.drive_server();
    pair.server_conn_mut(server).ping();
    pair.drive_server();
    pair.drive_client();
    let after = pair.client_conn_mut(client).stats();
    assert!(
        after.frame_tx.acks > before.frame_tx.acks,
        "pending ACK was held behind blocked outgoing data"
    );
    assert_eq!(
        after.frame_tx.stream, before.frame_tx.stream,
        "ACK bypass must not send blocked stream data"
    );
    assert!(
        recorded.lock().unwrap().is_empty(),
        "pure ACK must not consume congestion window or delivery accounting"
    );
    assert!(!pair.server.inbound.is_empty(), "ACK must reach the peer");
}

#[test]
fn pending_ack_bypasses_full_congestion_window() {
    pending_ack_bypasses_blocked_data(false);
}

#[test]
fn pending_ack_bypasses_exhausted_pacer() {
    pending_ack_bypasses_blocked_data(true);
}
