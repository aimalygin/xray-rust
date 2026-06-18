use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, Notify};

const TCP_SLOW_FLOW_EVENT_CAPACITY: usize = 64;
const TCP_FLOW_SUMMARY_EVENT_CAPACITY: usize = 64;
const TCP_REMOTE_WRITE_SLOW_EVENT_CAPACITY: usize = 64;
const TCP_OPEN_ERROR_EVENT_CAPACITY: usize = 64;
const UDP_SLOW_FLOW_EVENT_CAPACITY: usize = 64;
const UDP_RESPONSE_GAP_EVENT_CAPACITY: usize = 64;
const UDP_QUIC_BLOCKED_EVENT_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunConfig {
    pub mtu: usize,
    /// Queue depths of zero are treated as a minimum capacity of one packet.
    pub queue_depth: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TunError {
    #[error("packet length {len} exceeds mtu {mtu}")]
    PacketTooLarge { len: usize, mtu: usize },
    #[error("tun queue is full")]
    QueueFull,
    #[error("tun queue is closed")]
    QueueClosed,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunStats {
    pub inbound_packets: u64,
    pub outbound_packets: u64,
    pub dropped_packets: u64,
    pub inbound_dropped_packets: u64,
    pub outbound_dropped_packets: u64,
    pub tcp_stack_to_remote_bytes: u64,
    pub tcp_remote_written_bytes: u64,
    pub tcp_remote_read_bytes: u64,
    pub tcp_backpressure_events: u64,
    pub tcp_stack_to_remote_backpressure_events: u64,
    pub tcp_remote_to_stack_backpressure_events: u64,
    pub tcp_remote_write_batches: u64,
    pub tcp_remote_write_batch_messages: u64,
    pub tcp_remote_write_batch_max_messages: u64,
    pub tcp_remote_write_batch_max_bytes: u64,
    pub tcp_remote_write_wait_events: u64,
    pub tcp_remote_write_wait_ms_total: u64,
    pub tcp_remote_write_wait_ms_max: u64,
    pub tcp_remote_flush_wait_events: u64,
    pub tcp_remote_flush_wait_ms_total: u64,
    pub tcp_remote_flush_wait_ms_max: u64,
    pub tcp_pending_remote_bytes: u64,
    pub tcp_pending_remote_flows: u64,
    pub tcp_pending_remote_max_bytes: u64,
    pub tcp_remote_buffer_limit_bytes: u64,
    pub tcp_remote_buffer_pressure_active: bool,
    pub tcp_remote_write_errors: u64,
    pub tcp_remote_closed_events: u64,
    pub tcp_remote_read_errors: u64,
    pub tcp_open_errors: u64,
    pub tcp_open_events: u64,
    pub tcp_open_duration_ms_total: u64,
    pub tcp_open_duration_ms_max: u64,
    pub tcp_first_byte_events: u64,
    pub tcp_first_byte_duration_ms_total: u64,
    pub tcp_first_byte_duration_ms_max: u64,
    pub tcp443_open_events: u64,
    pub tcp443_open_duration_ms_total: u64,
    pub tcp443_open_duration_ms_max: u64,
    pub tcp443_first_byte_events: u64,
    pub tcp443_first_byte_duration_ms_total: u64,
    pub tcp443_first_byte_duration_ms_max: u64,
    pub active_tcp_flows: u64,
    pub active_udp_flows: u64,
    pub udp_flow_limit: u64,
    pub udp_budget_drops: u64,
    pub udp_evicted_flows: u64,
    pub udp_channel_dropped_packets: u64,
    pub udp_remote_open_events: u64,
    pub udp_remote_udp443_open_events: u64,
    pub udp_remote_written_bytes: u64,
    pub udp_remote_read_bytes: u64,
    pub udp_open_errors: u64,
    pub udp_vision_udp443_rejections: u64,
    pub udp_remote_write_errors: u64,
    pub udp_remote_read_errors: u64,
    pub udp_remote_closed_events: u64,
    pub udp_quic_blocked_packets: u64,
    pub inbound_queue_depth: u64,
    pub outbound_queue_depth: u64,
    pub inbound_queue_max_packets: u64,
    pub outbound_queue_max_packets: u64,
    pub tun_fd_write_batches: u64,
    pub tun_fd_write_batch_packets: u64,
    pub tun_fd_write_batch_max_packets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunTcpSlowFlowKind {
    Open,
    FirstByte,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpSlowFlowEvent {
    pub kind: TunTcpSlowFlowKind,
    pub target: String,
    pub open_duration_ms: u64,
    pub first_byte_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpFlowSummaryEvent {
    pub target: String,
    pub outbound_tag: Option<String>,
    pub closed: bool,
    pub duration_ms: u64,
    pub open_duration_ms: u64,
    pub first_byte_duration_ms: u64,
    pub remote_read_bytes: u64,
    pub ms_to_64kib: u64,
    pub ms_to_128kib: u64,
    pub ms_to_256kib: u64,
    pub ms_to_512kib: u64,
    pub ms_to_1mib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpRemoteWriteSlowEvent {
    pub target: String,
    pub outbound_tag: Option<String>,
    pub duration_ms: u64,
    pub bytes: u64,
    pub messages: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpOpenErrorEvent {
    pub target: String,
    pub outbound_tag: Option<String>,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunUdpSlowFlowEvent {
    pub target: String,
    pub first_response_duration_ms: u64,
    pub written_bytes: u64,
    pub read_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunUdpResponseGapEvent {
    pub target: String,
    pub response_gap_duration_ms: u64,
    pub written_bytes: u64,
    pub read_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunUdpQuicBlockedEvent {
    pub target: String,
    pub bytes: u64,
}

pub struct TunEndpoint {
    config: TunConfig,
    inbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    outbound_tx: mpsc::Sender<Bytes>,
    outbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    inbound_queue_depth: usize,
    outbound_queue_depth: usize,
    inbound_packets: AtomicU64,
    outbound_packets: AtomicU64,
    dropped_packets: AtomicU64,
    inbound_dropped_packets: AtomicU64,
    outbound_dropped_packets: AtomicU64,
    inbound_queue_max_packets: AtomicU64,
    outbound_queue_max_packets: AtomicU64,
    tun_fd_write_batches: AtomicU64,
    tun_fd_write_batch_packets: AtomicU64,
    tun_fd_write_batch_max_packets: AtomicU64,
    tcp_stack_to_remote_bytes: AtomicU64,
    tcp_remote_written_bytes: AtomicU64,
    tcp_remote_read_bytes: AtomicU64,
    tcp_backpressure_events: AtomicU64,
    tcp_stack_to_remote_backpressure_events: AtomicU64,
    tcp_remote_to_stack_backpressure_events: AtomicU64,
    tcp_remote_write_batches: AtomicU64,
    tcp_remote_write_batch_messages: AtomicU64,
    tcp_remote_write_batch_max_messages: AtomicU64,
    tcp_remote_write_batch_max_bytes: AtomicU64,
    tcp_remote_write_wait_events: AtomicU64,
    tcp_remote_write_wait_ms_total: AtomicU64,
    tcp_remote_write_wait_ms_max: AtomicU64,
    tcp_remote_flush_wait_events: AtomicU64,
    tcp_remote_flush_wait_ms_total: AtomicU64,
    tcp_remote_flush_wait_ms_max: AtomicU64,
    tcp_pending_remote_bytes: AtomicU64,
    tcp_pending_remote_flows: AtomicU64,
    tcp_pending_remote_max_bytes: AtomicU64,
    tcp_remote_buffer_limit_bytes: AtomicU64,
    tcp_remote_buffer_pressure_active: AtomicBool,
    tcp_remote_write_errors: AtomicU64,
    tcp_remote_closed_events: AtomicU64,
    tcp_remote_read_errors: AtomicU64,
    tcp_open_errors: AtomicU64,
    tcp_open_events: AtomicU64,
    tcp_open_duration_ms_total: AtomicU64,
    tcp_open_duration_ms_max: AtomicU64,
    tcp_first_byte_events: AtomicU64,
    tcp_first_byte_duration_ms_total: AtomicU64,
    tcp_first_byte_duration_ms_max: AtomicU64,
    tcp443_open_events: AtomicU64,
    tcp443_open_duration_ms_total: AtomicU64,
    tcp443_open_duration_ms_max: AtomicU64,
    tcp443_first_byte_events: AtomicU64,
    tcp443_first_byte_duration_ms_total: AtomicU64,
    tcp443_first_byte_duration_ms_max: AtomicU64,
    active_tcp_flows: AtomicU64,
    active_udp_flows: AtomicU64,
    udp_flow_limit: AtomicU64,
    udp_budget_drops: AtomicU64,
    udp_evicted_flows: AtomicU64,
    udp_channel_dropped_packets: AtomicU64,
    udp_remote_open_events: AtomicU64,
    udp_remote_udp443_open_events: AtomicU64,
    udp_remote_written_bytes: AtomicU64,
    udp_remote_read_bytes: AtomicU64,
    udp_open_errors: AtomicU64,
    udp_vision_udp443_rejections: AtomicU64,
    udp_remote_write_errors: AtomicU64,
    udp_remote_read_errors: AtomicU64,
    udp_remote_closed_events: AtomicU64,
    udp_quic_blocked_packets: AtomicU64,
    tcp_slow_flow_events: StdMutex<VecDeque<TunTcpSlowFlowEvent>>,
    tcp_flow_summary_events: StdMutex<VecDeque<TunTcpFlowSummaryEvent>>,
    tcp_remote_write_slow_events: StdMutex<VecDeque<TunTcpRemoteWriteSlowEvent>>,
    tcp_open_error_events: StdMutex<VecDeque<TunTcpOpenErrorEvent>>,
    udp_slow_flow_events: StdMutex<VecDeque<TunUdpSlowFlowEvent>>,
    udp_response_gap_events: StdMutex<VecDeque<TunUdpResponseGapEvent>>,
    udp_quic_blocked_events: StdMutex<VecDeque<TunUdpQuicBlockedEvent>>,
    closed: AtomicBool,
    closed_notify: Notify,
}

impl TunEndpoint {
    pub fn new(config: TunConfig) -> Self {
        let queue_depth = config.queue_depth.max(1);
        Self::new_with_queue_depths(config, queue_depth, queue_depth)
    }

    pub fn new_with_queue_depths(
        config: TunConfig,
        inbound_queue_depth: usize,
        outbound_queue_depth: usize,
    ) -> Self {
        let inbound_queue_depth = inbound_queue_depth.max(1);
        let outbound_queue_depth = outbound_queue_depth.max(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(inbound_queue_depth);
        let (outbound_tx, outbound_rx) = mpsc::channel(outbound_queue_depth);

        Self {
            config,
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            outbound_tx,
            outbound_rx: Mutex::new(outbound_rx),
            inbound_queue_depth,
            outbound_queue_depth,
            inbound_packets: AtomicU64::new(0),
            outbound_packets: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            inbound_dropped_packets: AtomicU64::new(0),
            outbound_dropped_packets: AtomicU64::new(0),
            inbound_queue_max_packets: AtomicU64::new(0),
            outbound_queue_max_packets: AtomicU64::new(0),
            tun_fd_write_batches: AtomicU64::new(0),
            tun_fd_write_batch_packets: AtomicU64::new(0),
            tun_fd_write_batch_max_packets: AtomicU64::new(0),
            tcp_stack_to_remote_bytes: AtomicU64::new(0),
            tcp_remote_written_bytes: AtomicU64::new(0),
            tcp_remote_read_bytes: AtomicU64::new(0),
            tcp_backpressure_events: AtomicU64::new(0),
            tcp_stack_to_remote_backpressure_events: AtomicU64::new(0),
            tcp_remote_to_stack_backpressure_events: AtomicU64::new(0),
            tcp_remote_write_batches: AtomicU64::new(0),
            tcp_remote_write_batch_messages: AtomicU64::new(0),
            tcp_remote_write_batch_max_messages: AtomicU64::new(0),
            tcp_remote_write_batch_max_bytes: AtomicU64::new(0),
            tcp_remote_write_wait_events: AtomicU64::new(0),
            tcp_remote_write_wait_ms_total: AtomicU64::new(0),
            tcp_remote_write_wait_ms_max: AtomicU64::new(0),
            tcp_remote_flush_wait_events: AtomicU64::new(0),
            tcp_remote_flush_wait_ms_total: AtomicU64::new(0),
            tcp_remote_flush_wait_ms_max: AtomicU64::new(0),
            tcp_pending_remote_bytes: AtomicU64::new(0),
            tcp_pending_remote_flows: AtomicU64::new(0),
            tcp_pending_remote_max_bytes: AtomicU64::new(0),
            tcp_remote_buffer_limit_bytes: AtomicU64::new(0),
            tcp_remote_buffer_pressure_active: AtomicBool::new(false),
            tcp_remote_write_errors: AtomicU64::new(0),
            tcp_remote_closed_events: AtomicU64::new(0),
            tcp_remote_read_errors: AtomicU64::new(0),
            tcp_open_errors: AtomicU64::new(0),
            tcp_open_events: AtomicU64::new(0),
            tcp_open_duration_ms_total: AtomicU64::new(0),
            tcp_open_duration_ms_max: AtomicU64::new(0),
            tcp_first_byte_events: AtomicU64::new(0),
            tcp_first_byte_duration_ms_total: AtomicU64::new(0),
            tcp_first_byte_duration_ms_max: AtomicU64::new(0),
            tcp443_open_events: AtomicU64::new(0),
            tcp443_open_duration_ms_total: AtomicU64::new(0),
            tcp443_open_duration_ms_max: AtomicU64::new(0),
            tcp443_first_byte_events: AtomicU64::new(0),
            tcp443_first_byte_duration_ms_total: AtomicU64::new(0),
            tcp443_first_byte_duration_ms_max: AtomicU64::new(0),
            active_tcp_flows: AtomicU64::new(0),
            active_udp_flows: AtomicU64::new(0),
            udp_flow_limit: AtomicU64::new(0),
            udp_budget_drops: AtomicU64::new(0),
            udp_evicted_flows: AtomicU64::new(0),
            udp_channel_dropped_packets: AtomicU64::new(0),
            udp_remote_open_events: AtomicU64::new(0),
            udp_remote_udp443_open_events: AtomicU64::new(0),
            udp_remote_written_bytes: AtomicU64::new(0),
            udp_remote_read_bytes: AtomicU64::new(0),
            udp_open_errors: AtomicU64::new(0),
            udp_vision_udp443_rejections: AtomicU64::new(0),
            udp_remote_write_errors: AtomicU64::new(0),
            udp_remote_read_errors: AtomicU64::new(0),
            udp_remote_closed_events: AtomicU64::new(0),
            udp_quic_blocked_packets: AtomicU64::new(0),
            tcp_slow_flow_events: StdMutex::new(VecDeque::new()),
            tcp_flow_summary_events: StdMutex::new(VecDeque::new()),
            tcp_remote_write_slow_events: StdMutex::new(VecDeque::new()),
            tcp_open_error_events: StdMutex::new(VecDeque::new()),
            udp_slow_flow_events: StdMutex::new(VecDeque::new()),
            udp_response_gap_events: StdMutex::new(VecDeque::new()),
            udp_quic_blocked_events: StdMutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        }
    }

    pub async fn push_inbound(&self, packet: Bytes) -> Result<(), TunError> {
        self.push_packet(packet, Direction::Inbound).await
    }

    pub async fn poll_inbound(&self) -> Result<Bytes, TunError> {
        self.poll_packet(&self.inbound_rx).await
    }

    pub async fn try_poll_inbound(&self) -> Result<Option<Bytes>, TunError> {
        self.try_poll_packet(&self.inbound_rx).await
    }

    pub async fn push_outbound(&self, packet: Bytes) -> Result<(), TunError> {
        self.push_packet(packet, Direction::Outbound).await
    }

    pub async fn poll_outbound(&self) -> Result<Bytes, TunError> {
        self.poll_packet(&self.outbound_rx).await
    }

    pub async fn try_poll_outbound(&self) -> Result<Option<Bytes>, TunError> {
        self.try_poll_packet(&self.outbound_rx).await
    }

    pub fn mtu(&self) -> usize {
        self.config.mtu
    }

    /// Waits for at least one outbound packet (or queue close), then drains up
    /// to `max_packets` without further waiting. Holding the receiver lock for
    /// the whole batch keeps per-packet locking off the host packet pump path.
    pub async fn poll_outbound_batch(&self, max_packets: usize) -> Result<Vec<Bytes>, TunError> {
        let max_packets = max_packets.max(1);
        let mut rx = self.outbound_rx.lock().await;
        let mut packets = Vec::with_capacity(max_packets.min(64));

        loop {
            let closed = self.closed_notify.notified();

            if self.closed.load(Ordering::Acquire) {
                match rx.try_recv() {
                    Ok(packet) => {
                        packets.push(packet);
                        break;
                    }
                    Err(_) => return Err(TunError::QueueClosed),
                }
            }

            tokio::select! {
                packet = rx.recv() => match packet {
                    Some(packet) => {
                        packets.push(packet);
                        break;
                    }
                    None => return Err(TunError::QueueClosed),
                },
                () = closed => {}
            }
        }

        while packets.len() < max_packets {
            match rx.try_recv() {
                Ok(packet) => packets.push(packet),
                Err(_) => break,
            }
        }

        Ok(packets)
    }

    pub async fn stats(&self) -> TunStats {
        TunStats {
            inbound_packets: self.inbound_packets.load(Ordering::Relaxed),
            outbound_packets: self.outbound_packets.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            inbound_dropped_packets: self.inbound_dropped_packets.load(Ordering::Relaxed),
            outbound_dropped_packets: self.outbound_dropped_packets.load(Ordering::Relaxed),
            tcp_stack_to_remote_bytes: self.tcp_stack_to_remote_bytes.load(Ordering::Relaxed),
            tcp_remote_written_bytes: self.tcp_remote_written_bytes.load(Ordering::Relaxed),
            tcp_remote_read_bytes: self.tcp_remote_read_bytes.load(Ordering::Relaxed),
            tcp_backpressure_events: self.tcp_backpressure_events.load(Ordering::Relaxed),
            tcp_stack_to_remote_backpressure_events: self
                .tcp_stack_to_remote_backpressure_events
                .load(Ordering::Relaxed),
            tcp_remote_to_stack_backpressure_events: self
                .tcp_remote_to_stack_backpressure_events
                .load(Ordering::Relaxed),
            tcp_remote_write_batches: self.tcp_remote_write_batches.load(Ordering::Relaxed),
            tcp_remote_write_batch_messages: self
                .tcp_remote_write_batch_messages
                .load(Ordering::Relaxed),
            tcp_remote_write_batch_max_messages: self
                .tcp_remote_write_batch_max_messages
                .load(Ordering::Relaxed),
            tcp_remote_write_batch_max_bytes: self
                .tcp_remote_write_batch_max_bytes
                .load(Ordering::Relaxed),
            tcp_remote_write_wait_events: self.tcp_remote_write_wait_events.load(Ordering::Relaxed),
            tcp_remote_write_wait_ms_total: self
                .tcp_remote_write_wait_ms_total
                .load(Ordering::Relaxed),
            tcp_remote_write_wait_ms_max: self.tcp_remote_write_wait_ms_max.load(Ordering::Relaxed),
            tcp_remote_flush_wait_events: self.tcp_remote_flush_wait_events.load(Ordering::Relaxed),
            tcp_remote_flush_wait_ms_total: self
                .tcp_remote_flush_wait_ms_total
                .load(Ordering::Relaxed),
            tcp_remote_flush_wait_ms_max: self.tcp_remote_flush_wait_ms_max.load(Ordering::Relaxed),
            tcp_pending_remote_bytes: self.tcp_pending_remote_bytes.load(Ordering::Relaxed),
            tcp_pending_remote_flows: self.tcp_pending_remote_flows.load(Ordering::Relaxed),
            tcp_pending_remote_max_bytes: self.tcp_pending_remote_max_bytes.load(Ordering::Relaxed),
            tcp_remote_buffer_limit_bytes: self
                .tcp_remote_buffer_limit_bytes
                .load(Ordering::Relaxed),
            tcp_remote_buffer_pressure_active: self
                .tcp_remote_buffer_pressure_active
                .load(Ordering::Relaxed),
            tcp_remote_write_errors: self.tcp_remote_write_errors.load(Ordering::Relaxed),
            tcp_remote_closed_events: self.tcp_remote_closed_events.load(Ordering::Relaxed),
            tcp_remote_read_errors: self.tcp_remote_read_errors.load(Ordering::Relaxed),
            tcp_open_errors: self.tcp_open_errors.load(Ordering::Relaxed),
            tcp_open_events: self.tcp_open_events.load(Ordering::Relaxed),
            tcp_open_duration_ms_total: self.tcp_open_duration_ms_total.load(Ordering::Relaxed),
            tcp_open_duration_ms_max: self.tcp_open_duration_ms_max.load(Ordering::Relaxed),
            tcp_first_byte_events: self.tcp_first_byte_events.load(Ordering::Relaxed),
            tcp_first_byte_duration_ms_total: self
                .tcp_first_byte_duration_ms_total
                .load(Ordering::Relaxed),
            tcp_first_byte_duration_ms_max: self
                .tcp_first_byte_duration_ms_max
                .load(Ordering::Relaxed),
            tcp443_open_events: self.tcp443_open_events.load(Ordering::Relaxed),
            tcp443_open_duration_ms_total: self
                .tcp443_open_duration_ms_total
                .load(Ordering::Relaxed),
            tcp443_open_duration_ms_max: self.tcp443_open_duration_ms_max.load(Ordering::Relaxed),
            tcp443_first_byte_events: self.tcp443_first_byte_events.load(Ordering::Relaxed),
            tcp443_first_byte_duration_ms_total: self
                .tcp443_first_byte_duration_ms_total
                .load(Ordering::Relaxed),
            tcp443_first_byte_duration_ms_max: self
                .tcp443_first_byte_duration_ms_max
                .load(Ordering::Relaxed),
            active_tcp_flows: self.active_tcp_flows.load(Ordering::Relaxed),
            active_udp_flows: self.active_udp_flows.load(Ordering::Relaxed),
            udp_flow_limit: self.udp_flow_limit.load(Ordering::Relaxed),
            udp_budget_drops: self.udp_budget_drops.load(Ordering::Relaxed),
            udp_evicted_flows: self.udp_evicted_flows.load(Ordering::Relaxed),
            udp_channel_dropped_packets: self.udp_channel_dropped_packets.load(Ordering::Relaxed),
            udp_remote_open_events: self.udp_remote_open_events.load(Ordering::Relaxed),
            udp_remote_udp443_open_events: self
                .udp_remote_udp443_open_events
                .load(Ordering::Relaxed),
            udp_remote_written_bytes: self.udp_remote_written_bytes.load(Ordering::Relaxed),
            udp_remote_read_bytes: self.udp_remote_read_bytes.load(Ordering::Relaxed),
            udp_open_errors: self.udp_open_errors.load(Ordering::Relaxed),
            udp_vision_udp443_rejections: self.udp_vision_udp443_rejections.load(Ordering::Relaxed),
            udp_remote_write_errors: self.udp_remote_write_errors.load(Ordering::Relaxed),
            udp_remote_read_errors: self.udp_remote_read_errors.load(Ordering::Relaxed),
            udp_remote_closed_events: self.udp_remote_closed_events.load(Ordering::Relaxed),
            udp_quic_blocked_packets: self.udp_quic_blocked_packets.load(Ordering::Relaxed),
            inbound_queue_depth: self.inbound_queue_depth as u64,
            outbound_queue_depth: self.outbound_queue_depth as u64,
            inbound_queue_max_packets: self.inbound_queue_max_packets.load(Ordering::Relaxed),
            outbound_queue_max_packets: self.outbound_queue_max_packets.load(Ordering::Relaxed),
            tun_fd_write_batches: self.tun_fd_write_batches.load(Ordering::Relaxed),
            tun_fd_write_batch_packets: self.tun_fd_write_batch_packets.load(Ordering::Relaxed),
            tun_fd_write_batch_max_packets: self
                .tun_fd_write_batch_max_packets
                .load(Ordering::Relaxed),
        }
    }

    pub fn record_tcp_stack_to_remote(&self, bytes: usize) {
        self.tcp_stack_to_remote_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_tcp_remote_written(&self, bytes: usize) {
        self.tcp_remote_written_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_tcp_remote_read(&self, bytes: usize) {
        self.tcp_remote_read_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_tcp_backpressure(&self) {
        self.tcp_backpressure_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_stack_to_remote_backpressure(&self) {
        self.record_tcp_backpressure();
        self.tcp_stack_to_remote_backpressure_events
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_remote_to_stack_backpressure(&self) {
        self.record_tcp_backpressure();
        self.tcp_remote_to_stack_backpressure_events
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_remote_write_batch(&self, messages: usize, bytes: usize) {
        self.tcp_remote_write_batches
            .fetch_add(1, Ordering::Relaxed);
        self.tcp_remote_write_batch_messages
            .fetch_add(messages as u64, Ordering::Relaxed);
        self.tcp_remote_write_batch_max_messages
            .fetch_max(messages as u64, Ordering::Relaxed);
        self.tcp_remote_write_batch_max_bytes
            .fetch_max(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_tcp_remote_write_wait(&self, duration_ms: u64) {
        record_duration_ms(
            &self.tcp_remote_write_wait_events,
            &self.tcp_remote_write_wait_ms_total,
            &self.tcp_remote_write_wait_ms_max,
            duration_ms,
        );
    }

    pub fn record_tcp_remote_flush_wait(&self, duration_ms: u64) {
        record_duration_ms(
            &self.tcp_remote_flush_wait_events,
            &self.tcp_remote_flush_wait_ms_total,
            &self.tcp_remote_flush_wait_ms_max,
            duration_ms,
        );
    }

    pub fn record_tcp_pending_remote(
        &self,
        bytes: usize,
        flows: usize,
        max_bytes: usize,
        limit_bytes: usize,
        pressure_active: bool,
    ) {
        self.tcp_pending_remote_bytes
            .store(bytes as u64, Ordering::Relaxed);
        self.tcp_pending_remote_flows
            .store(flows as u64, Ordering::Relaxed);
        self.tcp_pending_remote_max_bytes
            .store(max_bytes as u64, Ordering::Relaxed);
        self.tcp_remote_buffer_limit_bytes
            .store(limit_bytes as u64, Ordering::Relaxed);
        self.tcp_remote_buffer_pressure_active
            .store(pressure_active, Ordering::Relaxed);
    }

    pub fn record_tun_fd_write_batch(&self, packets: usize) {
        self.tun_fd_write_batches.fetch_add(1, Ordering::Relaxed);
        self.tun_fd_write_batch_packets
            .fetch_add(packets as u64, Ordering::Relaxed);
        self.tun_fd_write_batch_max_packets
            .fetch_max(packets as u64, Ordering::Relaxed);
    }

    pub fn record_tcp_remote_write_error(&self) {
        self.tcp_remote_write_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_remote_closed(&self) {
        self.tcp_remote_closed_events
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_remote_read_error(&self) {
        self.tcp_remote_read_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_open_error(&self) {
        self.tcp_open_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_open_timing(&self, duration_ms: u64, is_tcp443: bool) {
        record_duration_ms(
            &self.tcp_open_events,
            &self.tcp_open_duration_ms_total,
            &self.tcp_open_duration_ms_max,
            duration_ms,
        );
        if is_tcp443 {
            record_duration_ms(
                &self.tcp443_open_events,
                &self.tcp443_open_duration_ms_total,
                &self.tcp443_open_duration_ms_max,
                duration_ms,
            );
        }
    }

    pub fn record_tcp_first_byte_timing(&self, duration_ms: u64, is_tcp443: bool) {
        record_duration_ms(
            &self.tcp_first_byte_events,
            &self.tcp_first_byte_duration_ms_total,
            &self.tcp_first_byte_duration_ms_max,
            duration_ms,
        );
        if is_tcp443 {
            record_duration_ms(
                &self.tcp443_first_byte_events,
                &self.tcp443_first_byte_duration_ms_total,
                &self.tcp443_first_byte_duration_ms_max,
                duration_ms,
            );
        }
    }

    pub fn record_tcp_slow_flow_event(&self, event: TunTcpSlowFlowEvent) {
        let mut events = self
            .tcp_slow_flow_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() >= TCP_SLOW_FLOW_EVENT_CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn poll_tcp_slow_flow_event(&self) -> Option<TunTcpSlowFlowEvent> {
        self.tcp_slow_flow_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
    }

    pub fn record_tcp_flow_summary_event(&self, event: TunTcpFlowSummaryEvent) {
        let mut events = self
            .tcp_flow_summary_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() >= TCP_FLOW_SUMMARY_EVENT_CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn poll_tcp_flow_summary_event(&self) -> Option<TunTcpFlowSummaryEvent> {
        self.tcp_flow_summary_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
    }

    pub fn record_tcp_remote_write_slow_event(&self, event: TunTcpRemoteWriteSlowEvent) {
        let mut events = self
            .tcp_remote_write_slow_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() >= TCP_REMOTE_WRITE_SLOW_EVENT_CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn poll_tcp_remote_write_slow_event(&self) -> Option<TunTcpRemoteWriteSlowEvent> {
        self.tcp_remote_write_slow_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
    }

    pub fn record_tcp_open_error_event(&self, event: TunTcpOpenErrorEvent) {
        let mut events = self
            .tcp_open_error_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() >= TCP_OPEN_ERROR_EVENT_CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn poll_tcp_open_error_event(&self) -> Option<TunTcpOpenErrorEvent> {
        self.tcp_open_error_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
    }

    pub fn record_udp_slow_flow_event(&self, event: TunUdpSlowFlowEvent) {
        let mut events = self
            .udp_slow_flow_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() >= UDP_SLOW_FLOW_EVENT_CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn poll_udp_slow_flow_event(&self) -> Option<TunUdpSlowFlowEvent> {
        self.udp_slow_flow_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
    }

    pub fn record_udp_response_gap_event(&self, event: TunUdpResponseGapEvent) {
        let mut events = self
            .udp_response_gap_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() >= UDP_RESPONSE_GAP_EVENT_CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn poll_udp_response_gap_event(&self) -> Option<TunUdpResponseGapEvent> {
        self.udp_response_gap_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
    }

    pub fn record_udp_quic_blocked_event(&self, event: TunUdpQuicBlockedEvent) {
        let mut events = self
            .udp_quic_blocked_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() >= UDP_QUIC_BLOCKED_EVENT_CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn poll_udp_quic_blocked_event(&self) -> Option<TunUdpQuicBlockedEvent> {
        self.udp_quic_blocked_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
    }

    pub fn record_flow_budget(
        &self,
        active_tcp_flows: usize,
        active_udp_flows: usize,
        udp_flow_limit: usize,
        udp_budget_drops: u64,
        udp_evicted_flows: u64,
        udp_channel_dropped_packets: u64,
    ) {
        self.active_tcp_flows
            .store(active_tcp_flows as u64, Ordering::Relaxed);
        self.active_udp_flows
            .store(active_udp_flows as u64, Ordering::Relaxed);
        self.udp_flow_limit
            .store(udp_flow_limit as u64, Ordering::Relaxed);
        self.udp_budget_drops
            .store(udp_budget_drops, Ordering::Relaxed);
        self.udp_evicted_flows
            .store(udp_evicted_flows, Ordering::Relaxed);
        self.udp_channel_dropped_packets
            .store(udp_channel_dropped_packets, Ordering::Relaxed);
    }

    pub fn record_udp_open_error(&self) {
        self.udp_open_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_remote_open(&self, is_udp443: bool) {
        self.udp_remote_open_events.fetch_add(1, Ordering::Relaxed);
        if is_udp443 {
            self.udp_remote_udp443_open_events
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_udp_remote_written(&self, bytes: usize) {
        self.udp_remote_written_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_udp_remote_read(&self, bytes: usize) {
        self.udp_remote_read_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_udp_vision_udp443_rejection(&self) {
        self.udp_vision_udp443_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_remote_write_error(&self) {
        self.udp_remote_write_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_remote_read_error(&self) {
        self.udp_remote_read_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_remote_closed(&self) {
        self.udp_remote_closed_events
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_udp_quic_blocked(&self) {
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
        self.inbound_dropped_packets.fetch_add(1, Ordering::Relaxed);
        self.udp_quic_blocked_packets
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.closed_notify.notify_waiters();
    }

    async fn push_packet(&self, packet: Bytes, direction: Direction) -> Result<(), TunError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TunError::QueueClosed);
        }

        let len = packet.len();
        if len > self.config.mtu {
            self.record_drop(direction);
            return Err(TunError::PacketTooLarge {
                len,
                mtu: self.config.mtu,
            });
        }

        let send_result = match direction {
            Direction::Inbound => self.inbound_tx.try_send(packet),
            Direction::Outbound => self.outbound_tx.try_send(packet),
        };

        match send_result {
            Ok(()) => {
                match direction {
                    Direction::Inbound => self.inbound_packets.fetch_add(1, Ordering::Relaxed),
                    Direction::Outbound => self.outbound_packets.fetch_add(1, Ordering::Relaxed),
                };
                self.record_queue_occupancy(direction);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.record_drop(direction);
                Err(TunError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TunError::QueueClosed),
        }
    }

    async fn poll_packet(&self, rx: &Mutex<mpsc::Receiver<Bytes>>) -> Result<Bytes, TunError> {
        let mut rx = rx.lock().await;

        loop {
            let closed = self.closed_notify.notified();

            if self.closed.load(Ordering::Acquire) {
                return match rx.try_recv() {
                    Ok(packet) => Ok(packet),
                    Err(
                        mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected,
                    ) => Err(TunError::QueueClosed),
                };
            }

            tokio::select! {
                packet = rx.recv() => return packet.ok_or(TunError::QueueClosed),
                () = closed => {}
            }
        }
    }

    async fn try_poll_packet(
        &self,
        rx: &Mutex<mpsc::Receiver<Bytes>>,
    ) -> Result<Option<Bytes>, TunError> {
        let mut rx = rx.lock().await;

        match rx.try_recv() {
            Ok(packet) => Ok(Some(packet)),
            Err(mpsc::error::TryRecvError::Empty) if !self.closed.load(Ordering::Acquire) => {
                Ok(None)
            }
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                Err(TunError::QueueClosed)
            }
        }
    }

    fn record_drop(&self, direction: Direction) {
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
        match direction {
            Direction::Inbound => self.inbound_dropped_packets.fetch_add(1, Ordering::Relaxed),
            Direction::Outbound => self
                .outbound_dropped_packets
                .fetch_add(1, Ordering::Relaxed),
        };
    }

    fn record_queue_occupancy(&self, direction: Direction) {
        let (depth, capacity, max_packets) = match direction {
            Direction::Inbound => (
                self.inbound_queue_depth,
                self.inbound_tx.capacity(),
                &self.inbound_queue_max_packets,
            ),
            Direction::Outbound => (
                self.outbound_queue_depth,
                self.outbound_tx.capacity(),
                &self.outbound_queue_max_packets,
            ),
        };
        let queued = depth.saturating_sub(capacity);
        max_packets.fetch_max(queued as u64, Ordering::Relaxed);
    }
}

fn record_duration_ms(
    events: &AtomicU64,
    total_ms: &AtomicU64,
    max_ms: &AtomicU64,
    duration_ms: u64,
) {
    events.fetch_add(1, Ordering::Relaxed);
    total_ms.fetch_add(duration_ms, Ordering::Relaxed);
    max_ms.fetch_max(duration_ms, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Inbound,
    Outbound,
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
