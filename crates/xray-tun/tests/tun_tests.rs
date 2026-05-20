use bytes::Bytes;
use xray_tun::{TunConfig, TunEndpoint, TunError};

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
