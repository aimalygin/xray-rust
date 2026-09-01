use std::io;
use std::time::Duration;

use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use xray_config::CoreConfig;

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_UPLINK_ONLY_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_DOWNLINK_ONLY_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_COPY_BUFFER_SIZE: usize = 128 * 1024;
const INITIAL_COPY_BUFFER_SIZE: usize = 4 * 1024;
const MIN_COPY_BUFFER_SIZE: usize = 1024;
const MAX_COPY_BUFFER_SIZE: usize = 1024 * 1024;
const COPY_FLUSH_THRESHOLD: usize = 64 * 1024;
const COPY_FLUSH_INTERVAL: Duration = Duration::from_millis(2);

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

impl EffectivePolicy {
    pub(crate) fn relay_buffer_size(self) -> usize {
        self.buffer_size
            .map(|size_kib| size_kib.saturating_mul(1024))
            .unwrap_or(DEFAULT_COPY_BUFFER_SIZE)
            .clamp(MIN_COPY_BUFFER_SIZE, MAX_COPY_BUFFER_SIZE)
    }
}

const ACCEPT_BACKOFF_INITIAL_DELAY: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_MAX_DELAY: Duration = Duration::from_secs(1);

// A client that resets while queued in the backlog surfaces ECONNABORTED from
// accept(); that is not resource exhaustion, so pausing the listener for it
// would stall unrelated clients (Go's poller retries it silently).
pub(crate) fn accept_error_wants_backoff(kind: io::ErrorKind) -> bool {
    kind != io::ErrorKind::ConnectionAborted
}

// Accept errors such as EMFILE stay hot until fds free up; retrying without a
// pause turns the listener loop into a busy spin that starves the process.
#[derive(Debug, Default)]
pub(crate) struct AcceptBackoff {
    delay: Option<Duration>,
}

impl AcceptBackoff {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let delay = self.delay.unwrap_or(ACCEPT_BACKOFF_INITIAL_DELAY);
        self.delay = Some((delay * 2).min(ACCEPT_BACKOFF_MAX_DELAY));
        delay
    }

    pub(crate) fn reset(&mut self) {
        self.delay = None;
    }

    pub(crate) fn is_backing_off(&self) -> bool {
        self.delay.is_some()
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
    buffer_size: usize,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = split(a);
    let (mut b_read, mut b_write) = split(b);
    let (activity_tx, mut activity_rx) = mpsc::channel(1);
    let mut a_to_b = Box::pin(copy_direction(
        &mut a_read,
        &mut b_write,
        activity_tx.clone(),
        buffer_size,
    ));
    let mut b_to_a = Box::pin(copy_direction(
        &mut b_read,
        &mut a_write,
        activity_tx,
        buffer_size,
    ));
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
    activity: mpsc::Sender<()>,
    buffer_size: usize,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut unflushed = 0usize;
    // Start small so idle/chatty connections stay cheap; double toward the cap
    // only while reads keep filling the buffer (bulk transfers).
    let buffer_cap = buffer_size.clamp(MIN_COPY_BUFFER_SIZE, MAX_COPY_BUFFER_SIZE);
    let mut buffer = vec![0; buffer_cap.min(INITIAL_COPY_BUFFER_SIZE)];
    let flush_deadline = tokio::time::sleep(COPY_FLUSH_INTERVAL);
    tokio::pin!(flush_deadline);

    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => {
                let len = read?;
                if len == 0 {
                    if unflushed > 0 {
                        writer.flush().await?;
                    }
                    writer.shutdown().await?;
                    return Ok(total);
                }

                writer.write_all(&buffer[..len]).await?;
                if len == buffer.len() && buffer.len() < buffer_cap {
                    buffer.resize((buffer.len() * 2).min(buffer_cap), 0);
                }
                total = total.saturating_add(len as u64);
                let was_clean = unflushed == 0;
                unflushed = unflushed.saturating_add(len);
                let _ = activity.try_send(());

                if unflushed >= COPY_FLUSH_THRESHOLD {
                    writer.flush().await?;
                    unflushed = 0;
                } else if was_clean {
                    flush_deadline
                        .as_mut()
                        .reset(tokio::time::Instant::now() + COPY_FLUSH_INTERVAL);
                }
            }
            () = &mut flush_deadline, if unflushed > 0 => {
                writer.flush().await?;
                unflushed = 0;
            }
        }
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
        StreamSecurity, StreamSettings, StreamTransport,
    };

    use super::{
        copy_bidirectional_with_idle_timeout, copy_direction, effective_policy_for_level,
        AcceptBackoff,
    };

    #[derive(Default)]
    struct RecordingWriteState {
        bytes_written: usize,
        write_lengths: Vec<usize>,
        flushes: usize,
        shutdowns: usize,
    }

    struct RecordingIo {
        state: Arc<Mutex<RecordingWriteState>>,
    }

    struct ChunkedReadIo {
        remaining: usize,
        chunk_size: usize,
    }

    impl AsyncRead for ChunkedReadIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let len = self.remaining.min(self.chunk_size).min(buf.remaining());
            buf.initialize_unfilled_to(len).fill(0);
            buf.advance(len);
            self.remaining -= len;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ChunkedReadIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
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
            let mut state = self.state.lock().unwrap();
            state.bytes_written += buf.len();
            state.write_lengths.push(buf.len());
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
                proxy_settings: None,
                stream: StreamSettings {
                    network: xray_config::Network::Tcp,
                    transport: StreamTransport::Raw,
                    security: StreamSecurity::None,
                    quic_params: None,
                    socket_options: None,
                },
                settings: OutboundSettings::Freedom,
            }],
            default_outbound_tag: Some("direct".to_owned()),
            routing: Default::default(),
            observatory: None,
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

        let error = copy_bidirectional_with_idle_timeout(
            &mut left,
            &mut right,
            Duration::from_millis(1),
            8 * 1024,
        )
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
        let (activity_tx, _activity_rx) = mpsc::channel(1);

        reader_peer.write_all(b"hello").await.unwrap();
        reader_peer.shutdown().await.unwrap();
        let copied = copy_direction(&mut reader, &mut writer, activity_tx, 8 * 1024)
            .await
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(copied, 5);
        assert_eq!(state.bytes_written, 5);
        assert_eq!(state.flushes, 1);
        assert_eq!(state.shutdowns, 1);
    }

    #[tokio::test]
    async fn copy_direction_coalesces_flushes_and_activity_notifications() {
        let reader_io = ChunkedReadIo {
            remaining: 128 * 1024,
            chunk_size: 8 * 1024,
        };
        let (mut reader, _unused_writer) = tokio::io::split(reader_io);
        let state = Arc::new(Mutex::new(RecordingWriteState::default()));
        let writer_io = RecordingIo {
            state: state.clone(),
        };
        let (_unused_reader, mut writer) = tokio::io::split(writer_io);
        let (activity_tx, mut activity_rx) = mpsc::channel(1);

        let copied = copy_direction(&mut reader, &mut writer, activity_tx, 8 * 1024)
            .await
            .unwrap();

        assert_eq!(copied, 128 * 1024);
        assert_eq!(state.lock().unwrap().flushes, 2);
        assert!(activity_rx.try_recv().is_ok());
        assert!(activity_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn copy_direction_grows_buffer_toward_cap_on_full_reads() {
        let reader_io = ChunkedReadIo {
            remaining: 1024 * 1024,
            chunk_size: 1024 * 1024,
        };
        let (mut reader, _unused_writer) = tokio::io::split(reader_io);
        let state = Arc::new(Mutex::new(RecordingWriteState::default()));
        let writer_io = RecordingIo {
            state: state.clone(),
        };
        let (_unused_reader, mut writer) = tokio::io::split(writer_io);
        let (activity_tx, _activity_rx) = mpsc::channel(1);

        let copied = copy_direction(&mut reader, &mut writer, activity_tx, 128 * 1024)
            .await
            .unwrap();

        assert_eq!(copied, 1024 * 1024);
        let state = state.lock().unwrap();
        assert_eq!(
            state.write_lengths[..6],
            [
                4 * 1024,
                8 * 1024,
                16 * 1024,
                32 * 1024,
                64 * 1024,
                128 * 1024
            ]
        );
        let (last, steady) = state.write_lengths[6..].split_last().unwrap();
        assert!(steady.iter().all(|len| *len == 128 * 1024));
        assert!(*last <= 128 * 1024);
    }

    #[tokio::test]
    async fn copy_direction_keeps_buffer_at_configured_cap_when_small() {
        let reader_io = ChunkedReadIo {
            remaining: 8 * 1024,
            chunk_size: 8 * 1024,
        };
        let (mut reader, _unused_writer) = tokio::io::split(reader_io);
        let state = Arc::new(Mutex::new(RecordingWriteState::default()));
        let writer_io = RecordingIo {
            state: state.clone(),
        };
        let (_unused_reader, mut writer) = tokio::io::split(writer_io);
        let (activity_tx, _activity_rx) = mpsc::channel(1);

        let copied = copy_direction(&mut reader, &mut writer, activity_tx, 4 * 1024)
            .await
            .unwrap();

        assert_eq!(copied, 8 * 1024);
        let state = state.lock().unwrap();
        assert!(state.write_lengths.iter().all(|len| *len <= 4 * 1024));
    }

    #[tokio::test]
    #[ignore = "manual relay throughput microbenchmark"]
    async fn relay_copy_microbenchmark() {
        const BYTES: usize = 64 * 1024 * 1024;
        let reader_io = ChunkedReadIo {
            remaining: BYTES,
            chunk_size: 32 * 1024,
        };
        let (mut reader, _unused_writer) = tokio::io::split(reader_io);
        let state = Arc::new(Mutex::new(RecordingWriteState::default()));
        let writer_io = RecordingIo {
            state: state.clone(),
        };
        let (_unused_reader, mut writer) = tokio::io::split(writer_io);
        let (activity_tx, _activity_rx) = mpsc::channel(1);
        let started = std::time::Instant::now();

        let copied = copy_direction(&mut reader, &mut writer, activity_tx, 32 * 1024)
            .await
            .expect("relay benchmark should complete");
        let elapsed = started.elapsed();
        let mib_per_second = copied as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();

        eprintln!(
            "relay_copy_microbenchmark bytes={copied} elapsed_ms={} mib_per_second={mib_per_second:.1}",
            elapsed.as_millis()
        );
        assert_eq!(copied as usize, BYTES);
    }

    #[test]
    fn accept_error_backoff_skips_connection_aborted() {
        use std::io;

        assert!(!super::accept_error_wants_backoff(
            io::ErrorKind::ConnectionAborted
        ));
        assert!(super::accept_error_wants_backoff(io::ErrorKind::Other));
        assert!(super::accept_error_wants_backoff(io::ErrorKind::WouldBlock));
    }

    #[test]
    fn accept_backoff_escalates_delays_up_to_the_cap() {
        let mut backoff = AcceptBackoff::new();

        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
        assert_eq!(backoff.next_delay(), Duration::from_millis(20));
        assert_eq!(backoff.next_delay(), Duration::from_millis(40));

        let mut last = Duration::ZERO;
        for _ in 0..16 {
            last = backoff.next_delay();
        }
        assert_eq!(last, Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn accept_backoff_reset_returns_to_the_initial_delay() {
        let mut backoff = AcceptBackoff::new();
        assert!(!backoff.is_backing_off());

        backoff.next_delay();
        backoff.next_delay();
        assert!(backoff.is_backing_off());

        backoff.reset();
        assert!(!backoff.is_backing_off());
        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
    }

    #[test]
    fn relay_buffer_size_interprets_policy_value_as_kibibytes() {
        let policy = super::EffectivePolicy {
            buffer_size: Some(32),
            ..Default::default()
        };

        assert_eq!(policy.relay_buffer_size(), 32 * 1024);
    }

    #[test]
    fn relay_buffer_size_caps_untrusted_configuration() {
        let policy = super::EffectivePolicy {
            buffer_size: Some(usize::MAX),
            ..Default::default()
        };

        assert_eq!(policy.relay_buffer_size(), 1024 * 1024);
    }
}
