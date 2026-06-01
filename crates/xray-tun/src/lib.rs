use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, Notify};

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
    pub tcp_pending_remote_bytes: u64,
    pub tcp_pending_remote_flows: u64,
    pub tcp_pending_remote_max_bytes: u64,
    pub tcp_remote_buffer_limit_bytes: u64,
    pub tcp_remote_buffer_pressure_active: bool,
    pub tcp_remote_write_errors: u64,
    pub tcp_remote_closed_events: u64,
    pub tcp_remote_read_errors: u64,
    pub tcp_open_errors: u64,
}

pub struct TunEndpoint {
    config: TunConfig,
    inbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    outbound_tx: mpsc::Sender<Bytes>,
    outbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    inbound_packets: AtomicU64,
    outbound_packets: AtomicU64,
    dropped_packets: AtomicU64,
    inbound_dropped_packets: AtomicU64,
    outbound_dropped_packets: AtomicU64,
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
    tcp_pending_remote_bytes: AtomicU64,
    tcp_pending_remote_flows: AtomicU64,
    tcp_pending_remote_max_bytes: AtomicU64,
    tcp_remote_buffer_limit_bytes: AtomicU64,
    tcp_remote_buffer_pressure_active: AtomicBool,
    tcp_remote_write_errors: AtomicU64,
    tcp_remote_closed_events: AtomicU64,
    tcp_remote_read_errors: AtomicU64,
    tcp_open_errors: AtomicU64,
    closed: AtomicBool,
    closed_notify: Notify,
}

impl TunEndpoint {
    pub fn new(config: TunConfig) -> Self {
        let queue_depth = config.queue_depth.max(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(queue_depth);
        let (outbound_tx, outbound_rx) = mpsc::channel(queue_depth);

        Self {
            config,
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            outbound_tx,
            outbound_rx: Mutex::new(outbound_rx),
            inbound_packets: AtomicU64::new(0),
            outbound_packets: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            inbound_dropped_packets: AtomicU64::new(0),
            outbound_dropped_packets: AtomicU64::new(0),
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
            tcp_pending_remote_bytes: AtomicU64::new(0),
            tcp_pending_remote_flows: AtomicU64::new(0),
            tcp_pending_remote_max_bytes: AtomicU64::new(0),
            tcp_remote_buffer_limit_bytes: AtomicU64::new(0),
            tcp_remote_buffer_pressure_active: AtomicBool::new(false),
            tcp_remote_write_errors: AtomicU64::new(0),
            tcp_remote_closed_events: AtomicU64::new(0),
            tcp_remote_read_errors: AtomicU64::new(0),
            tcp_open_errors: AtomicU64::new(0),
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
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Inbound,
    Outbound,
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
