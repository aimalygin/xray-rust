use bytes::Bytes;
use xray_tun::{
    TunConfig, TunEndpoint, TunError, TunStats, TunTcpFlowSummaryEvent, TunTcpSlowFlowEvent,
    TunTcpSlowFlowKind, TunUdpQuicBlockedEvent, TunUdpResponseGapEvent, TunUdpSlowFlowEvent,
};

#[tokio::test]
async fn tun_endpoint_moves_packets_in_both_directions() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 2,
    });

    tun.push_inbound(Bytes::from_static(&[0x45, 0, 0, 20]))
        .await
        .unwrap();
    assert_eq!(
        tun.poll_inbound().await.unwrap(),
        Bytes::from_static(&[0x45, 0, 0, 20])
    );

    tun.push_outbound(Bytes::from_static(&[0x60, 0, 0, 0]))
        .await
        .unwrap();
    assert_eq!(
        tun.poll_outbound().await.unwrap(),
        Bytes::from_static(&[0x60, 0, 0, 0])
    );
}

#[tokio::test]
async fn tun_endpoint_rejects_oversized_packet() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 4,
        queue_depth: 1,
    });

    let err = tun
        .push_inbound(Bytes::from_static(&[1, 2, 3, 4, 5]))
        .await
        .unwrap_err();
    assert_eq!(err, TunError::PacketTooLarge { len: 5, mtu: 4 });
}

#[tokio::test]
async fn tun_endpoint_treats_zero_queue_depth_as_one() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 0,
    });

    tun.push_inbound(Bytes::from_static(&[0x45])).await.unwrap();
    assert_eq!(
        tun.poll_inbound().await.unwrap(),
        Bytes::from_static(&[0x45])
    );
    assert_eq!(tun.stats().await.inbound_queue_depth, 1);
    assert_eq!(tun.stats().await.outbound_queue_depth, 1);
}

#[tokio::test]
async fn tun_endpoint_supports_split_queue_depths_and_tracks_peak_occupancy() {
    let tun = TunEndpoint::new_with_queue_depths(
        TunConfig {
            mtu: 1500,
            queue_depth: 1,
        },
        1,
        3,
    );

    tun.push_inbound(Bytes::from_static(&[1])).await.unwrap();
    tun.push_outbound(Bytes::from_static(&[2])).await.unwrap();
    tun.push_outbound(Bytes::from_static(&[3])).await.unwrap();

    let stats = tun.stats().await;
    assert_eq!(stats.inbound_queue_depth, 1);
    assert_eq!(stats.outbound_queue_depth, 3);
    assert_eq!(stats.inbound_queue_max_packets, 1);
    assert_eq!(stats.outbound_queue_max_packets, 2);
}

#[tokio::test]
async fn tun_endpoint_rejects_packets_when_queue_is_full() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.push_inbound(Bytes::from_static(&[1])).await.unwrap();
    let err = tun
        .push_inbound(Bytes::from_static(&[2]))
        .await
        .unwrap_err();

    assert_eq!(err, TunError::QueueFull);
}

#[tokio::test]
async fn tun_endpoint_try_poll_returns_none_when_queue_is_empty() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    assert_eq!(tun.try_poll_outbound().await.unwrap(), None);
}

#[tokio::test]
async fn tun_endpoint_try_poll_returns_queued_packet() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.push_outbound(Bytes::from_static(&[1, 2, 3]))
        .await
        .unwrap();

    assert_eq!(
        tun.try_poll_outbound().await.unwrap(),
        Some(Bytes::from_static(&[1, 2, 3]))
    );
}

#[tokio::test]
async fn tun_endpoint_stats_track_accepted_and_dropped_packets() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 2,
        queue_depth: 1,
    });

    tun.push_inbound(Bytes::from_static(&[1])).await.unwrap();
    tun.push_outbound(Bytes::from_static(&[2])).await.unwrap();
    let oversized = tun.push_inbound(Bytes::from_static(&[1, 2, 3])).await;
    let full = tun.push_inbound(Bytes::from_static(&[3])).await;

    assert_eq!(
        oversized.unwrap_err(),
        TunError::PacketTooLarge { len: 3, mtu: 2 }
    );
    assert_eq!(full.unwrap_err(), TunError::QueueFull);
    assert_eq!(
        tun.stats().await,
        TunStats {
            inbound_packets: 1,
            outbound_packets: 1,
            dropped_packets: 2,
            inbound_dropped_packets: 2,
            outbound_dropped_packets: 0,
            inbound_queue_depth: 1,
            outbound_queue_depth: 1,
            inbound_queue_max_packets: 1,
            outbound_queue_max_packets: 1,
            ..TunStats::default()
        }
    );
}

#[tokio::test]
async fn tun_endpoint_stats_track_outbound_dropped_packets() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 2,
        queue_depth: 1,
    });

    tun.push_outbound(Bytes::from_static(&[1])).await.unwrap();
    let oversized = tun.push_outbound(Bytes::from_static(&[1, 2, 3])).await;
    let full = tun.push_outbound(Bytes::from_static(&[2])).await;

    assert_eq!(
        oversized.unwrap_err(),
        TunError::PacketTooLarge { len: 3, mtu: 2 }
    );
    assert_eq!(full.unwrap_err(), TunError::QueueFull);
    assert_eq!(
        tun.stats().await,
        TunStats {
            inbound_packets: 0,
            outbound_packets: 1,
            dropped_packets: 2,
            inbound_dropped_packets: 0,
            outbound_dropped_packets: 2,
            inbound_queue_depth: 1,
            outbound_queue_depth: 1,
            inbound_queue_max_packets: 0,
            outbound_queue_max_packets: 1,
            ..TunStats::default()
        }
    );
}

#[tokio::test]
async fn tun_endpoint_stats_track_tcp_bridge_counters() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.record_tcp_stack_to_remote(120);
    tun.record_tcp_remote_written(100);
    tun.record_tcp_remote_read(80);
    tun.record_tcp_stack_to_remote_backpressure();
    tun.record_tcp_remote_to_stack_backpressure();
    tun.record_tcp_remote_write_batch(3, 96);
    tun.record_tcp_remote_write_batch(5, 160);
    tun.record_tcp_pending_remote(4096, 3, 2048, 2 * 1024 * 1024, false);
    tun.record_tcp_pending_remote(1024, 1, 512, 1024 * 1024, true);
    tun.record_tcp_remote_write_error();
    tun.record_tcp_remote_closed();
    tun.record_tcp_remote_read_error();
    tun.record_tcp_open_error();
    tun.record_tcp_open_timing(120, false);
    tun.record_tcp_open_timing(80, true);
    tun.record_tcp_first_byte_timing(300, false);
    tun.record_tcp_first_byte_timing(250, true);
    tun.record_tun_fd_write_batch(3);
    tun.record_tun_fd_write_batch(7);

    assert_eq!(
        tun.stats().await,
        TunStats {
            inbound_packets: 0,
            outbound_packets: 0,
            dropped_packets: 0,
            inbound_dropped_packets: 0,
            outbound_dropped_packets: 0,
            tcp_stack_to_remote_bytes: 120,
            tcp_remote_written_bytes: 100,
            tcp_remote_read_bytes: 80,
            tcp_backpressure_events: 2,
            tcp_stack_to_remote_backpressure_events: 1,
            tcp_remote_to_stack_backpressure_events: 1,
            tcp_remote_write_batches: 2,
            tcp_remote_write_batch_messages: 8,
            tcp_remote_write_batch_max_messages: 5,
            tcp_remote_write_batch_max_bytes: 160,
            tcp_pending_remote_bytes: 1024,
            tcp_pending_remote_flows: 1,
            tcp_pending_remote_max_bytes: 512,
            tcp_remote_buffer_limit_bytes: 1024 * 1024,
            tcp_remote_buffer_pressure_active: true,
            tcp_remote_write_errors: 1,
            tcp_remote_closed_events: 1,
            tcp_remote_read_errors: 1,
            tcp_open_errors: 1,
            tcp_open_events: 2,
            tcp_open_duration_ms_total: 200,
            tcp_open_duration_ms_max: 120,
            tcp_first_byte_events: 2,
            tcp_first_byte_duration_ms_total: 550,
            tcp_first_byte_duration_ms_max: 300,
            tcp443_open_events: 1,
            tcp443_open_duration_ms_total: 80,
            tcp443_open_duration_ms_max: 80,
            tcp443_first_byte_events: 1,
            tcp443_first_byte_duration_ms_total: 250,
            tcp443_first_byte_duration_ms_max: 250,
            inbound_queue_depth: 1,
            outbound_queue_depth: 1,
            tun_fd_write_batches: 2,
            tun_fd_write_batch_packets: 10,
            tun_fd_write_batch_max_packets: 7,
            ..TunStats::default()
        }
    );
}

#[tokio::test]
async fn tun_endpoint_buffers_tcp_slow_flow_events_in_fifo_order() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.record_tcp_slow_flow_event(TunTcpSlowFlowEvent {
        kind: TunTcpSlowFlowKind::Open,
        target: "93.184.216.34:443".to_owned(),
        open_duration_ms: 1_200,
        first_byte_duration_ms: 0,
    });
    tun.record_tcp_slow_flow_event(TunTcpSlowFlowEvent {
        kind: TunTcpSlowFlowKind::FirstByte,
        target: "speedtest.example:443".to_owned(),
        open_duration_ms: 450,
        first_byte_duration_ms: 1_800,
    });

    assert_eq!(
        tun.poll_tcp_slow_flow_event(),
        Some(TunTcpSlowFlowEvent {
            kind: TunTcpSlowFlowKind::Open,
            target: "93.184.216.34:443".to_owned(),
            open_duration_ms: 1_200,
            first_byte_duration_ms: 0,
        })
    );
    assert_eq!(
        tun.poll_tcp_slow_flow_event(),
        Some(TunTcpSlowFlowEvent {
            kind: TunTcpSlowFlowKind::FirstByte,
            target: "speedtest.example:443".to_owned(),
            open_duration_ms: 450,
            first_byte_duration_ms: 1_800,
        })
    );
    assert_eq!(tun.poll_tcp_slow_flow_event(), None);
}

#[tokio::test]
async fn tun_endpoint_buffers_udp_slow_flow_events_in_fifo_order() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.record_udp_slow_flow_event(TunUdpSlowFlowEvent {
        target: "speedtest.example:443".to_owned(),
        first_response_duration_ms: 1_200,
        written_bytes: 1_350,
        read_bytes: 1_180,
    });
    tun.record_udp_slow_flow_event(TunUdpSlowFlowEvent {
        target: "cdn.example:443".to_owned(),
        first_response_duration_ms: 2_400,
        written_bytes: 2_700,
        read_bytes: 1_420,
    });

    assert_eq!(
        tun.poll_udp_slow_flow_event(),
        Some(TunUdpSlowFlowEvent {
            target: "speedtest.example:443".to_owned(),
            first_response_duration_ms: 1_200,
            written_bytes: 1_350,
            read_bytes: 1_180,
        })
    );
    assert_eq!(
        tun.poll_udp_slow_flow_event(),
        Some(TunUdpSlowFlowEvent {
            target: "cdn.example:443".to_owned(),
            first_response_duration_ms: 2_400,
            written_bytes: 2_700,
            read_bytes: 1_420,
        })
    );
    assert_eq!(tun.poll_udp_slow_flow_event(), None);
}

#[tokio::test]
async fn tun_endpoint_buffers_udp_response_gap_events_in_fifo_order() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.record_udp_response_gap_event(TunUdpResponseGapEvent {
        target: "speedtest.example:443".to_owned(),
        response_gap_duration_ms: 1_500,
        written_bytes: 2_400,
        read_bytes: 1_180,
    });
    tun.record_udp_response_gap_event(TunUdpResponseGapEvent {
        target: "cdn.example:443".to_owned(),
        response_gap_duration_ms: 3_100,
        written_bytes: 4_800,
        read_bytes: 1_420,
    });

    assert_eq!(
        tun.poll_udp_response_gap_event(),
        Some(TunUdpResponseGapEvent {
            target: "speedtest.example:443".to_owned(),
            response_gap_duration_ms: 1_500,
            written_bytes: 2_400,
            read_bytes: 1_180,
        })
    );
    assert_eq!(
        tun.poll_udp_response_gap_event(),
        Some(TunUdpResponseGapEvent {
            target: "cdn.example:443".to_owned(),
            response_gap_duration_ms: 3_100,
            written_bytes: 4_800,
            read_bytes: 1_420,
        })
    );
    assert_eq!(tun.poll_udp_response_gap_event(), None);
}

#[tokio::test]
async fn tun_endpoint_buffers_udp_quic_blocked_events_in_fifo_order() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.record_udp_quic_blocked_event(TunUdpQuicBlockedEvent {
        target: "1.1.1.1:443".to_owned(),
        bytes: 1_200,
    });
    tun.record_udp_quic_blocked_event(TunUdpQuicBlockedEvent {
        target: "speedtest.example:443".to_owned(),
        bytes: 482,
    });

    assert_eq!(
        tun.poll_udp_quic_blocked_event(),
        Some(TunUdpQuicBlockedEvent {
            target: "1.1.1.1:443".to_owned(),
            bytes: 1_200,
        })
    );
    assert_eq!(
        tun.poll_udp_quic_blocked_event(),
        Some(TunUdpQuicBlockedEvent {
            target: "speedtest.example:443".to_owned(),
            bytes: 482,
        })
    );
    assert_eq!(tun.poll_udp_quic_blocked_event(), None);
}

#[tokio::test]
async fn tun_endpoint_buffers_tcp_flow_summary_events_in_fifo_order() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.record_tcp_flow_summary_event(TunTcpFlowSummaryEvent {
        target: "speedtest.example:443".to_owned(),
        outbound_tag: Some("proxy".to_owned()),
        closed: false,
        duration_ms: 1_250,
        open_duration_ms: 320,
        first_byte_duration_ms: 520,
        remote_read_bytes: 1_048_576,
        ms_to_64kib: 340,
        ms_to_128kib: 420,
        ms_to_256kib: 610,
        ms_to_512kib: 610,
        ms_to_1mib: 1_250,
    });
    tun.record_tcp_flow_summary_event(TunTcpFlowSummaryEvent {
        target: "cdn.example:443".to_owned(),
        outbound_tag: None,
        closed: true,
        duration_ms: 3_288,
        open_duration_ms: 330,
        first_byte_duration_ms: 650,
        remote_read_bytes: 786_432,
        ms_to_64kib: 800,
        ms_to_128kib: 1_100,
        ms_to_256kib: 1_450,
        ms_to_512kib: 1_900,
        ms_to_1mib: 0,
    });

    assert_eq!(
        tun.poll_tcp_flow_summary_event(),
        Some(TunTcpFlowSummaryEvent {
            target: "speedtest.example:443".to_owned(),
            outbound_tag: Some("proxy".to_owned()),
            closed: false,
            duration_ms: 1_250,
            open_duration_ms: 320,
            first_byte_duration_ms: 520,
            remote_read_bytes: 1_048_576,
            ms_to_64kib: 340,
            ms_to_128kib: 420,
            ms_to_256kib: 610,
            ms_to_512kib: 610,
            ms_to_1mib: 1_250,
        })
    );
    assert_eq!(
        tun.poll_tcp_flow_summary_event(),
        Some(TunTcpFlowSummaryEvent {
            target: "cdn.example:443".to_owned(),
            outbound_tag: None,
            closed: true,
            duration_ms: 3_288,
            open_duration_ms: 330,
            first_byte_duration_ms: 650,
            remote_read_bytes: 786_432,
            ms_to_64kib: 800,
            ms_to_128kib: 1_100,
            ms_to_256kib: 1_450,
            ms_to_512kib: 1_900,
            ms_to_1mib: 0,
        })
    );
    assert_eq!(tun.poll_tcp_flow_summary_event(), None);
}

#[tokio::test]
async fn tun_endpoint_stats_track_flow_budget_counters() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.record_flow_budget(12, 34, 256, 5, 6, 7);
    tun.record_udp_remote_open(false);
    tun.record_udp_remote_open(true);
    tun.record_udp_remote_written(1200);
    tun.record_udp_remote_written(300);
    tun.record_udp_remote_read(4096);
    tun.record_udp_open_error();
    tun.record_udp_vision_udp443_rejection();
    tun.record_udp_remote_write_error();
    tun.record_udp_remote_read_error();
    tun.record_udp_remote_closed();
    tun.record_udp_quic_blocked();

    assert_eq!(
        tun.stats().await,
        TunStats {
            dropped_packets: 1,
            inbound_dropped_packets: 1,
            active_tcp_flows: 12,
            active_udp_flows: 34,
            udp_flow_limit: 256,
            udp_budget_drops: 5,
            udp_evicted_flows: 6,
            udp_channel_dropped_packets: 7,
            udp_remote_open_events: 2,
            udp_remote_udp443_open_events: 1,
            udp_remote_written_bytes: 1500,
            udp_remote_read_bytes: 4096,
            udp_open_errors: 1,
            udp_vision_udp443_rejections: 1,
            udp_remote_write_errors: 1,
            udp_remote_read_errors: 1,
            udp_remote_closed_events: 1,
            udp_quic_blocked_packets: 1,
            inbound_queue_depth: 1,
            outbound_queue_depth: 1,
            ..TunStats::default()
        }
    );
}

#[tokio::test]
async fn tun_endpoint_poll_returns_queue_closed_after_close() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.close();

    assert_eq!(tun.poll_inbound().await.unwrap_err(), TunError::QueueClosed);
    assert_eq!(
        tun.poll_outbound().await.unwrap_err(),
        TunError::QueueClosed
    );
}

#[tokio::test]
async fn tun_endpoint_rejects_pushes_after_close() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.close();

    assert_eq!(
        tun.push_inbound(Bytes::from_static(&[1]))
            .await
            .unwrap_err(),
        TunError::QueueClosed
    );
    assert_eq!(
        tun.push_outbound(Bytes::from_static(&[2]))
            .await
            .unwrap_err(),
        TunError::QueueClosed
    );
}

#[tokio::test]
async fn tun_endpoint_drains_queued_packet_after_close_then_reports_closed() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 1,
    });

    tun.push_inbound(Bytes::from_static(&[0x45])).await.unwrap();
    tun.close();

    assert_eq!(
        tun.poll_inbound().await.unwrap(),
        Bytes::from_static(&[0x45])
    );
    assert_eq!(tun.poll_inbound().await.unwrap_err(), TunError::QueueClosed);
}
