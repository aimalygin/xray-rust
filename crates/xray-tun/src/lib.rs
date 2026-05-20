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

    pub async fn push_outbound(&self, packet: Bytes) -> Result<(), TunError> {
        self.push_packet(packet, Direction::Outbound).await
    }

    pub async fn poll_outbound(&self) -> Result<Bytes, TunError> {
        self.poll_packet(&self.outbound_rx).await
    }

    pub async fn stats(&self) -> TunStats {
        TunStats {
            inbound_packets: self.inbound_packets.load(Ordering::Relaxed),
            outbound_packets: self.outbound_packets.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
        }
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
            self.record_drop();
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
                self.record_drop();
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

    fn record_drop(&self) {
        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
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
