use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use xray_tun::{
    TunEndpoint, TunStats, TunTcpFlowSummaryEvent, TunTcpOpenErrorEvent,
    TunTcpRemoteWriteSlowEvent, TunTcpSlowFlowEvent, TunTcpSlowFlowKind, TunUdpQuicBlockedEvent,
    TunUdpResponseGapEvent, TunUdpSlowFlowEvent,
};

use crate::RuntimeLogger;

const RUNTIME_STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);
const RUNTIME_EVENT_DRAIN_LIMIT_PER_KIND: usize = 64;

pub(crate) fn spawn_runtime_stats_logger(
    tun: Arc<TunEndpoint>,
    logger: RuntimeLogger,
    mut shutdown: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if !logger.is_enabled() {
        return None;
    }

    Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                () = sleep(RUNTIME_STATS_LOG_INTERVAL) => {
                    log_runtime_stats_snapshot(tun.as_ref(), &logger).await;
                }
            }
        }
    }))
}

async fn log_runtime_stats_snapshot(tun: &TunEndpoint, logger: &RuntimeLogger) {
    let stats = tun.stats().await;
    for message in format_tun_stats_debug_lines(&stats) {
        logger.debug(|| message);
    }
    let dropped_lines = logger.dropped_lines();
    if dropped_lines > 0 {
        logger.debug(|| format!("Debug runtimeLog droppedLines={dropped_lines}"));
    }
    drain_runtime_events(tun, logger);
}

fn drain_runtime_events(tun: &TunEndpoint, logger: &RuntimeLogger) {
    for _ in 0..RUNTIME_EVENT_DRAIN_LIMIT_PER_KIND {
        let Some(event) = tun.poll_tcp_slow_flow_event() else {
            break;
        };
        logger.debug(|| format_tcp_slow_flow_event(&event));
    }
    for _ in 0..RUNTIME_EVENT_DRAIN_LIMIT_PER_KIND {
        let Some(event) = tun.poll_tcp_flow_summary_event() else {
            break;
        };
        logger.debug(|| format_tcp_flow_summary_event(&event));
    }
    for _ in 0..RUNTIME_EVENT_DRAIN_LIMIT_PER_KIND {
        let Some(event) = tun.poll_tcp_remote_write_slow_event() else {
            break;
        };
        logger.debug(|| format_tcp_remote_write_slow_event(&event));
    }
    for _ in 0..RUNTIME_EVENT_DRAIN_LIMIT_PER_KIND {
        let Some(event) = tun.poll_tcp_open_error_event() else {
            break;
        };
        logger.debug(|| format_tcp_open_error_event(&event));
    }
    for _ in 0..RUNTIME_EVENT_DRAIN_LIMIT_PER_KIND {
        let Some(event) = tun.poll_udp_slow_flow_event() else {
            break;
        };
        logger.debug(|| format_udp_slow_flow_event(&event));
    }
    for _ in 0..RUNTIME_EVENT_DRAIN_LIMIT_PER_KIND {
        let Some(event) = tun.poll_udp_response_gap_event() else {
            break;
        };
        logger.debug(|| format_udp_response_gap_event(&event));
    }
    for _ in 0..RUNTIME_EVENT_DRAIN_LIMIT_PER_KIND {
        let Some(event) = tun.poll_udp_quic_blocked_event() else {
            break;
        };
        logger.debug(|| format_udp_quic_blocked_event(&event));
    }
}

fn format_tun_stats_debug_lines(stats: &TunStats) -> Vec<String> {
    vec![
        format!(
            "Debug stats core inbound={} outbound={} dropped={} inboundDropped={} outboundDropped={} activeTCPFlows={} activeUDPFlows={}",
            stats.inbound_packets,
            stats.outbound_packets,
            stats.dropped_packets,
            stats.inbound_dropped_packets,
            stats.outbound_dropped_packets,
            stats.active_tcp_flows,
            stats.active_udp_flows
        ),
        format!(
            "Debug stats queues inboundQueueDepth={} outboundQueueDepth={} inboundQueueMaxPackets={} outboundQueueMaxPackets={} tunFdWriteBatches={} tunFdWriteBatchPackets={} tunFdWriteBatchMaxPackets={} tunFdReadLoopExits={} tunFdWriteLoopExits={} tunFdTransientIoErrors={}",
            stats.inbound_queue_depth,
            stats.outbound_queue_depth,
            stats.inbound_queue_max_packets,
            stats.outbound_queue_max_packets,
            stats.tun_fd_write_batches,
            stats.tun_fd_write_batch_packets,
            stats.tun_fd_write_batch_max_packets,
            stats.tun_fd_read_loop_exits,
            stats.tun_fd_write_loop_exits,
            stats.tun_fd_transient_io_errors
        ),
        format!(
            "Debug stats tcpBytes tcpStackToRemoteBytes={} tcpRemoteWrittenBytes={} tcpRemoteReadBytes={} tcpBackpressure={} tcpStackToRemoteBackpressure={} tcpRemoteToStackBackpressure={}",
            stats.tcp_stack_to_remote_bytes,
            stats.tcp_remote_written_bytes,
            stats.tcp_remote_read_bytes,
            stats.tcp_backpressure_events,
            stats.tcp_stack_to_remote_backpressure_events,
            stats.tcp_remote_to_stack_backpressure_events
        ),
        format!(
            "Debug stats tcpBuffers tcpRemoteWriteBatches={} tcpRemoteWriteBatchMessages={} tcpRemoteWriteBatchMaxMessages={} tcpRemoteWriteBatchMaxBytes={} tcpPendingRemoteBytes={} tcpPendingRemoteFlows={} tcpPendingRemoteMaxBytes={} tcpWriteErrors={} tcpRemoteClosed={} tcpReadErrors={} tcpOpenErrors={}",
            stats.tcp_remote_write_batches,
            stats.tcp_remote_write_batch_messages,
            stats.tcp_remote_write_batch_max_messages,
            stats.tcp_remote_write_batch_max_bytes,
            stats.tcp_pending_remote_bytes,
            stats.tcp_pending_remote_flows,
            stats.tcp_pending_remote_max_bytes,
            stats.tcp_remote_write_errors,
            stats.tcp_remote_closed_events,
            stats.tcp_remote_read_errors,
            stats.tcp_open_errors
        ),
        format!(
            "Debug stats tcpBudget tcpPendingUploadBytes={} tcpPendingUploadMaxBytes={} tcpPendingTotalBytes={} tcpRemoteBufferLimitBytes={} tcpBufferHardLimitBytes={} tcpRemoteBufferPressureActive={}",
            stats.tcp_pending_upload_bytes,
            stats.tcp_pending_upload_max_bytes,
            stats.tcp_pending_total_bytes,
            stats.tcp_remote_buffer_limit_bytes,
            stats.tcp_buffer_hard_limit_bytes,
            stats.tcp_remote_buffer_pressure_active
        ),
        format!(
            "Debug stats tcpWriteWait tcpRemoteWriteWaitEvents={} tcpRemoteWriteWaitAvgMs={} tcpRemoteWriteWaitMaxMs={} tcpRemoteFlushWaitEvents={} tcpRemoteFlushWaitAvgMs={} tcpRemoteFlushWaitMaxMs={}",
            stats.tcp_remote_write_wait_events,
            average_duration_ms(stats.tcp_remote_write_wait_ms_total, stats.tcp_remote_write_wait_events),
            stats.tcp_remote_write_wait_ms_max,
            stats.tcp_remote_flush_wait_events,
            average_duration_ms(stats.tcp_remote_flush_wait_ms_total, stats.tcp_remote_flush_wait_events),
            stats.tcp_remote_flush_wait_ms_max
        ),
        format!(
            "Debug stats tcpTiming tcpOpenEvents={} tcpOpenAvgMs={} tcpOpenMaxMs={} tcpFirstByteEvents={} tcpFirstByteAvgMs={} tcpFirstByteMaxMs={} tcp443OpenEvents={} tcp443OpenAvgMs={} tcp443OpenMaxMs={} tcp443FirstByteEvents={} tcp443FirstByteAvgMs={} tcp443FirstByteMaxMs={}",
            stats.tcp_open_events,
            average_duration_ms(stats.tcp_open_duration_ms_total, stats.tcp_open_events),
            stats.tcp_open_duration_ms_max,
            stats.tcp_first_byte_events,
            average_duration_ms(stats.tcp_first_byte_duration_ms_total, stats.tcp_first_byte_events),
            stats.tcp_first_byte_duration_ms_max,
            stats.tcp443_open_events,
            average_duration_ms(stats.tcp443_open_duration_ms_total, stats.tcp443_open_events),
            stats.tcp443_open_duration_ms_max,
            stats.tcp443_first_byte_events,
            average_duration_ms(stats.tcp443_first_byte_duration_ms_total, stats.tcp443_first_byte_events),
            stats.tcp443_first_byte_duration_ms_max
        ),
        format!(
            "Debug stats udpFlows udpFlowLimit={} udpBudgetDrops={} udpEvictedFlows={} udpChannelDroppedPackets={}",
            stats.udp_flow_limit,
            stats.udp_budget_drops,
            stats.udp_evicted_flows,
            stats.udp_channel_dropped_packets
        ),
        format!(
            "Debug stats udpRemote udpOpenEvents={} udpUDP443OpenEvents={} udpWrittenBytes={} udpReadBytes={} udpOpenErrors={} udpVisionUDP443Rejections={} udpWriteErrors={} udpReadErrors={} udpRemoteClosed={} udpQuicBlockedPackets={}",
            stats.udp_remote_open_events,
            stats.udp_remote_udp443_open_events,
            stats.udp_remote_written_bytes,
            stats.udp_remote_read_bytes,
            stats.udp_open_errors,
            stats.udp_vision_udp443_rejections,
            stats.udp_remote_write_errors,
            stats.udp_remote_read_errors,
            stats.udp_remote_closed_events,
            stats.udp_quic_blocked_packets
        ),
    ]
}

fn format_tcp_slow_flow_event(event: &TunTcpSlowFlowEvent) -> String {
    let kind = match event.kind {
        TunTcpSlowFlowKind::Open => "open",
        TunTcpSlowFlowKind::FirstByte => "firstByte",
    };
    format!(
        "Debug tcpSlowFlow kind={} target={} openMs={} firstByteMs={}",
        kind,
        redact_target(&event.target),
        event.open_duration_ms,
        event.first_byte_duration_ms
    )
}

fn format_tcp_flow_summary_event(event: &TunTcpFlowSummaryEvent) -> String {
    format!(
        "Debug tcpFlowSummary target={} outbound={} closed={} durationMs={} openMs={} firstByteMs={} remoteReadBytes={} msTo64KiB={} msTo128KiB={} msTo256KiB={} msTo512KiB={} msTo1MiB={}",
        redact_target(&event.target),
        crate::debug_log::configured_tag_label(event.outbound_tag.as_deref()),
        event.closed,
        event.duration_ms,
        event.open_duration_ms,
        event.first_byte_duration_ms,
        event.remote_read_bytes,
        event.ms_to_64kib,
        event.ms_to_128kib,
        event.ms_to_256kib,
        event.ms_to_512kib,
        event.ms_to_1mib
    )
}

fn format_tcp_remote_write_slow_event(event: &TunTcpRemoteWriteSlowEvent) -> String {
    format!(
        "Debug tcpRemoteWriteSlow target={} outbound={} writeWaitMs={} bytes={} messages={}",
        redact_target(&event.target),
        crate::debug_log::configured_tag_label(event.outbound_tag.as_deref()),
        event.duration_ms,
        event.bytes,
        event.messages
    )
}

fn format_tcp_open_error_event(event: &TunTcpOpenErrorEvent) -> String {
    format!(
        "Debug tcpOpenError target={} outbound={} error=<redacted>",
        redact_target(&event.target),
        crate::debug_log::configured_tag_label(event.outbound_tag.as_deref())
    )
}

fn format_udp_slow_flow_event(event: &TunUdpSlowFlowEvent) -> String {
    format!(
        "Debug udpSlowFlow target={} firstResponseMs={} writtenBytes={} readBytes={}",
        redact_target(&event.target),
        event.first_response_duration_ms,
        event.written_bytes,
        event.read_bytes
    )
}

fn format_udp_response_gap_event(event: &TunUdpResponseGapEvent) -> String {
    format!(
        "Debug udpResponseGap target={} responseGapMs={} writtenBytes={} readBytes={}",
        redact_target(&event.target),
        event.response_gap_duration_ms,
        event.written_bytes,
        event.read_bytes
    )
}

fn format_udp_quic_blocked_event(event: &TunUdpQuicBlockedEvent) -> String {
    format!(
        "Debug quicBlocked target={} bytes={}",
        redact_target(&event.target),
        event.bytes
    )
}

fn redact_target(target: &str) -> String {
    target
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .map_or_else(
            || "<redacted>".to_owned(),
            |port| format!("<redacted>:{port}"),
        )
}

fn average_duration_ms(total: u64, events: u64) -> u64 {
    total.checked_div(events).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::watch;
    use xray_tun::TunConfig;
    use xray_tun::{TunStats, TunTcpFlowSummaryEvent, TunTcpOpenErrorEvent};

    use super::{
        format_tcp_flow_summary_event, format_tcp_open_error_event, format_tun_stats_debug_lines,
        spawn_runtime_stats_logger,
    };
    use crate::RuntimeLogger;

    #[test]
    fn format_tun_stats_debug_lines_includes_speedtest_diagnostics() {
        let stats = TunStats {
            tcp_remote_read_bytes: 1_048_576,
            tcp_open_events: 12,
            tcp_first_byte_events: 11,
            udp_vision_udp443_rejections: 3,
            udp_quic_blocked_packets: 5,
            ..TunStats::default()
        };

        let lines = format_tun_stats_debug_lines(&stats);

        assert!(lines
            .iter()
            .any(|line| line.contains("tcpRemoteReadBytes=1048576")));
        assert!(lines
            .iter()
            .any(|line| line.contains("udpVisionUDP443Rejections=3")));
        assert!(lines
            .iter()
            .any(|line| line.contains("udpQuicBlockedPackets=5")));
    }

    #[test]
    fn format_tun_stats_debug_lines_includes_pump_give_up_counters() {
        let stats = TunStats {
            tun_fd_read_loop_exits: 1,
            tun_fd_write_loop_exits: 2,
            tun_fd_transient_io_errors: 9,
            ..TunStats::default()
        };

        let lines = format_tun_stats_debug_lines(&stats);

        let queues = lines
            .iter()
            .find(|line| line.starts_with("Debug stats queues"))
            .expect("queues line");
        assert!(queues.contains("tunFdReadLoopExits=1"));
        assert!(queues.contains("tunFdWriteLoopExits=2"));
        assert!(queues.contains("tunFdTransientIoErrors=9"));
    }

    #[test]
    fn format_tcp_flow_summary_event_includes_threshold_timings() {
        let event = TunTcpFlowSummaryEvent {
            target: "203.0.113.10:443".to_owned(),
            outbound_tag: Some("proxy".to_owned()),
            closed: false,
            duration_ms: 1200,
            open_duration_ms: 80,
            first_byte_duration_ms: 140,
            remote_read_bytes: 1_048_576,
            ms_to_64kib: 160,
            ms_to_128kib: 180,
            ms_to_256kib: 220,
            ms_to_512kib: 300,
            ms_to_1mib: 900,
        };

        let line = format_tcp_flow_summary_event(&event);

        assert!(line.contains("Debug tcpFlowSummary"));
        assert!(line.contains("remoteReadBytes=1048576"));
        assert!(line.contains("msTo1MiB=900"));
        assert!(line.contains("target=<redacted>:443"));
        assert!(line.contains("outbound=<configured>"));
        assert!(!line.contains("outbound=proxy"));
        assert!(!line.contains("203.0.113.10"));
    }

    #[test]
    fn runtime_event_formatting_redacts_domain_target() {
        let event = TunTcpOpenErrorEvent {
            target: "secret.example:8443".to_owned(),
            outbound_tag: Some("proxy".to_owned()),
            error: "lookup failed for another-secret.example".to_owned(),
        };

        let line = format_tcp_open_error_event(&event);

        assert!(line.contains("target=<redacted>:8443"));
        assert!(line.contains("error=<redacted>"));
        assert!(!line.contains("secret.example"));
        assert!(!line.contains("another-secret.example"));
    }

    #[test]
    fn spawn_runtime_stats_logger_returns_none_when_logger_is_disabled() {
        let tun = Arc::new(xray_tun::TunEndpoint::new(TunConfig {
            mtu: 1500,
            queue_depth: 1,
        }));
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = spawn_runtime_stats_logger(tun, RuntimeLogger::disabled(), shutdown_rx);

        assert!(task.is_none());
    }
}
