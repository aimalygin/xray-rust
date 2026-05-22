use bytes::Bytes;
use xray_tun::{TunConfig, TunEndpoint, TunError, TunStats};

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
