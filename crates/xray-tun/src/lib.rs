use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunConfig {
    pub mtu: usize,
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
    stats: Mutex<TunStats>,
}

impl TunEndpoint {
    pub fn new(config: TunConfig) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(config.queue_depth);
        let (outbound_tx, outbound_rx) = mpsc::channel(config.queue_depth);

        Self {
            config,
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            outbound_tx,
            outbound_rx: Mutex::new(outbound_rx),
            stats: Mutex::new(TunStats::default()),
        }
    }

    pub async fn push_inbound(&self, packet: Bytes) -> Result<(), TunError> {
        self.push_packet(packet, Direction::Inbound).await
    }

    pub async fn poll_inbound(&self) -> Result<Bytes, TunError> {
        Self::poll_packet(&self.inbound_rx).await
    }

    pub async fn push_outbound(&self, packet: Bytes) -> Result<(), TunError> {
        self.push_packet(packet, Direction::Outbound).await
    }

    pub async fn poll_outbound(&self) -> Result<Bytes, TunError> {
        Self::poll_packet(&self.outbound_rx).await
    }

    pub async fn stats(&self) -> TunStats {
        *self.stats.lock().await
    }

    async fn push_packet(&self, packet: Bytes, direction: Direction) -> Result<(), TunError> {
        let len = packet.len();
        if len > self.config.mtu {
            self.record_drop().await;
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
                let mut stats = self.stats.lock().await;
                match direction {
                    Direction::Inbound => stats.inbound_packets += 1,
                    Direction::Outbound => stats.outbound_packets += 1,
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.record_drop().await;
                Err(TunError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TunError::QueueClosed),
        }
    }

    async fn poll_packet(rx: &Mutex<mpsc::Receiver<Bytes>>) -> Result<Bytes, TunError> {
        rx.lock().await.recv().await.ok_or(TunError::QueueClosed)
    }

    async fn record_drop(&self) {
        self.stats.lock().await.dropped_packets += 1;
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
