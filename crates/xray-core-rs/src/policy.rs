use std::io;
use std::time::Duration;

use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use xray_config::CoreConfig;

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_UPLINK_ONLY_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_DOWNLINK_ONLY_TIMEOUT: Duration = Duration::from_secs(2);
const COPY_BUFFER_SIZE: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectivePolicy {
    pub handshake: Duration,
    pub conn_idle: Duration,
    pub uplink_only: Duration,
    pub downlink_only: Duration,
    pub buffer_size: Option<usize>,
}

impl Default for EffectivePolicy {
    fn default() -> Self {
        Self {
            handshake: DEFAULT_HANDSHAKE_TIMEOUT,
            conn_idle: DEFAULT_CONN_IDLE_TIMEOUT,
            uplink_only: DEFAULT_UPLINK_ONLY_TIMEOUT,
            downlink_only: DEFAULT_DOWNLINK_ONLY_TIMEOUT,
            buffer_size: None,
        }
    }
}

pub(crate) fn effective_policy_for_level(
    config: &CoreConfig,
    level: Option<u32>,
) -> EffectivePolicy {
    let level = level.unwrap_or(0);
    let Some(policy) = config.policy.levels.get(&level) else {
        return EffectivePolicy::default();
    };
    let defaults = EffectivePolicy::default();
    EffectivePolicy {
        handshake: policy.handshake.map(seconds).unwrap_or(defaults.handshake),
        conn_idle: policy.conn_idle.map(seconds).unwrap_or(defaults.conn_idle),
        uplink_only: policy
            .uplink_only
            .map(seconds)
            .unwrap_or(defaults.uplink_only),
        downlink_only: policy
            .downlink_only
            .map(seconds)
            .unwrap_or(defaults.downlink_only),
        buffer_size: policy
            .buffer_size
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size > 0),
    }
}

fn seconds(value: u32) -> Duration {
    Duration::from_secs(u64::from(value))
}

pub(crate) async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = split(a);
    let (mut b_read, mut b_write) = split(b);
    let (activity_tx, mut activity_rx) = mpsc::unbounded_channel();
    let mut a_to_b = Box::pin(copy_direction(
        &mut a_read,
        &mut b_write,
        activity_tx.clone(),
    ));
    let mut b_to_a = Box::pin(copy_direction(&mut b_read, &mut a_write, activity_tx));
    let mut a_to_b_result = None;
    let mut b_to_a_result = None;
    let mut idle_sleep = Box::pin(tokio::time::sleep(idle));

    loop {
        tokio::select! {
            result = &mut a_to_b, if a_to_b_result.is_none() => {
                a_to_b_result = Some(result?);
            }
            result = &mut b_to_a, if b_to_a_result.is_none() => {
                b_to_a_result = Some(result?);
            }
            activity = activity_rx.recv() => {
                if activity.is_some() {
                    idle_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle);
                }
            }
            () = &mut idle_sleep => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connection idle timeout"));
            }
        }

        if let (Some(a_to_b), Some(b_to_a)) = (a_to_b_result, b_to_a_result) {
            return Ok((a_to_b, b_to_a));
        }
    }
}

async fn copy_direction<R, W>(
    reader: &mut ReadHalf<R>,
    writer: &mut WriteHalf<W>,
    activity: mpsc::UnboundedSender<()>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buffer = vec![0; COPY_BUFFER_SIZE];
    loop {
        let len = reader.read(&mut buffer).await?;
        if len == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        writer.write_all(&buffer[..len]).await?;
        writer.flush().await?;
        total = total.saturating_add(len as u64);
        let _ = activity.send(());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::sync::mpsc;
    use xray_config::{
        CoreConfig, OutboundConfig, OutboundSettings, PolicyConfig, PolicyLevelConfig,
        StreamSecurity, StreamSettings,
    };

    use super::{copy_bidirectional_with_idle_timeout, copy_direction, effective_policy_for_level};

    #[derive(Default)]
    struct RecordingWriteState {
        bytes_written: usize,
        flushes: usize,
        shutdowns: usize,
    }

    struct RecordingIo {
        state: Arc<Mutex<RecordingWriteState>>,
    }

    impl AsyncRead for RecordingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for RecordingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.state.lock().unwrap().bytes_written += buf.len();
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.state.lock().unwrap().flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.state.lock().unwrap().shutdowns += 1;
            Poll::Ready(Ok(()))
        }
    }

    fn config_with_policy(level: u32, policy: PolicyLevelConfig) -> CoreConfig {
        CoreConfig {
            inbounds: Vec::new(),
            outbounds: vec![OutboundConfig {
                tag: Some("direct".to_owned()),
                stream: StreamSettings {
                    network: xray_config::Network::Tcp,
                    security: StreamSecurity::None,
                },
                settings: OutboundSettings::Freedom,
            }],
            default_outbound_tag: Some("direct".to_owned()),
            routing: Default::default(),
            dns: Default::default(),
            policy: PolicyConfig {
                levels: BTreeMap::from([(level, policy)]),
                system: Default::default(),
            },
        }
    }

    #[test]
    fn effective_policy_uses_configured_level_values() {
        let config = config_with_policy(
            7,
            PolicyLevelConfig {
                handshake: Some(3),
                conn_idle: Some(4),
                uplink_only: Some(5),
                downlink_only: Some(6),
                buffer_size: Some(8),
                ..Default::default()
            },
        );

        let policy = effective_policy_for_level(&config, Some(7));

        assert_eq!(policy.handshake, Duration::from_secs(3));
        assert_eq!(policy.conn_idle, Duration::from_secs(4));
        assert_eq!(policy.uplink_only, Duration::from_secs(5));
        assert_eq!(policy.downlink_only, Duration::from_secs(6));
        assert_eq!(policy.buffer_size, Some(8));
    }

    #[test]
    fn effective_policy_defaults_missing_level_to_compatible_values() {
        let config = config_with_policy(1, PolicyLevelConfig::default());

        let policy = effective_policy_for_level(&config, Some(9));

        assert_eq!(policy.handshake, Duration::from_secs(10));
        assert_eq!(policy.conn_idle, Duration::from_secs(300));
        assert_eq!(policy.buffer_size, None);
    }

    #[tokio::test]
    async fn copy_bidirectional_returns_idle_timeout() {
        let (mut left, _right_peer) = tokio::io::duplex(64);
        let (mut right, _left_peer) = tokio::io::duplex(64);

        let error =
            copy_bidirectional_with_idle_timeout(&mut left, &mut right, Duration::from_millis(1))
                .await
                .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn copy_direction_flushes_after_forwarding_chunk() {
        let (reader_io, mut reader_peer) = tokio::io::duplex(64);
        let (mut reader, _unused_writer) = tokio::io::split(reader_io);
        let state = Arc::new(Mutex::new(RecordingWriteState::default()));
        let writer_io = RecordingIo {
            state: state.clone(),
        };
        let (_unused_reader, mut writer) = tokio::io::split(writer_io);
        let (activity_tx, _activity_rx) = mpsc::unbounded_channel();

        reader_peer.write_all(b"hello").await.unwrap();
        reader_peer.shutdown().await.unwrap();
        let copied = copy_direction(&mut reader, &mut writer, activity_tx)
            .await
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(copied, 5);
        assert_eq!(state.bytes_written, 5);
        assert_eq!(state.flushes, 1);
        assert_eq!(state.shutdowns, 1);
    }
}
