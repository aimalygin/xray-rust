#[path = "hysteria/support.rs"]
mod support;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use support::{ReferenceServer, Task, DEADLINE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::hysteria::{HysteriaClient, HysteriaError};

#[tokio::test]
#[ignore = "requires pinned reference; use check-hysteria-interop.sh or check-native-hysteria-interop.sh"]
async fn pinned_reference_tcp_udp_fragmentation_limits_and_reconnect() {
    let server = ReferenceServer::start().await;
    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let tcp_address = tcp_listener.local_addr().unwrap();
    let tcp_target = Target::new(
        TargetAddr::Ip(tcp_address.ip()),
        tcp_address.port(),
        Network::Tcp,
    );
    let tcp_task = Task(tokio::spawn(async move {
        // Two connections: the first client and a fresh connection after close.
        for _ in 0..2 {
            let (socket, _) = tcp_listener.accept().await.unwrap();
            let (mut reader, mut writer) = socket.into_split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        }
    }));
    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp_address = udp_socket.local_addr().unwrap();
    let udp_target = Target::new(
        TargetAddr::Ip(udp_address.ip()),
        udp_address.port(),
        Network::Udp,
    );
    let udp_task = Task(tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            let (count, remote) = udp_socket.recv_from(&mut buffer).await.unwrap();
            udp_socket.send_to(&buffer[..count], remote).await.unwrap();
        }
    }));
    let mut config = server.config();
    config.limits.max_tcp_streams = 1;
    config.limits.max_udp_sessions = 2;
    let client = HysteriaClient::connect(config, &server.connector)
        .await
        .unwrap();
    assert!(client.is_live());
    assert!(client.udp_enabled());
    let mut tcp = client.open_tcp(&tcp_target).await.unwrap();
    assert!(matches!(
        client.open_tcp(&tcp_target).await,
        Err(HysteriaError::SessionLimit)
    ));
    tcp.write_all(b"hysteria tcp echo").await.unwrap();
    let mut echo = vec![0; b"hysteria tcp echo".len()];
    timeout(DEADLINE, tcp.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, b"hysteria tcp echo");
    tcp.shutdown().await.unwrap();
    drop(tcp);

    let first = Arc::new(client.open_udp().unwrap());
    let second = client.open_udp().unwrap();
    assert_ne!(first.session_id(), second.session_id());
    assert!(matches!(
        client.open_udp(),
        Err(HysteriaError::SessionLimit)
    ));
    let payload = vec![0x42; server.fragmented_udp_payload_len()];
    // Receiving can run concurrently with sending on the same flow.
    let receiver = Arc::clone(&first);
    let receiving =
        tokio::spawn(async move { timeout(DEADLINE, receiver.recv()).await.unwrap().unwrap() });
    first.send(&udp_target, &payload).await.unwrap();
    second.send(&udp_target, b"second UDP flow").await.unwrap();
    let first_reply = receiving.await.unwrap();
    assert_eq!(first_reply.payload, payload);
    assert_eq!(first_reply.source, udp_target);
    let second_reply = timeout(DEADLINE, second.recv()).await.unwrap().unwrap();
    assert_eq!(second_reply.payload, b"second UDP flow");
    let old = second.session_id();
    drop(second);
    assert_eq!(client.active_udp_sessions(), 1);
    let third = client.open_udp().unwrap();
    assert_ne!(old, third.session_id());
    assert!(timeout(Duration::from_millis(20), third.recv())
        .await
        .is_err());
    third
        .send(&udp_target, b"after cancelled receive")
        .await
        .unwrap();
    assert_eq!(
        timeout(DEADLINE, third.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"after cancelled receive"
    );
    client.close();
    assert!(!client.is_live());
    assert_eq!(first.recv().await.err(), Some(HysteriaError::Closed));
    assert_eq!(client.active_udp_sessions(), 0);
    drop(first);
    drop(third);
    drop(client);

    let reconnected = HysteriaClient::connect(server.config(), &server.connector)
        .await
        .unwrap();
    let mut tcp = reconnected.open_tcp(&tcp_target).await.unwrap();
    drop(reconnected); // The stream lease must retain the connection.
    tcp.write_all(b"after reconnect").await.unwrap();
    echo.resize(b"after reconnect".len(), 0);
    timeout(DEADLINE, tcp.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, b"after reconnect");
    tcp.shutdown().await.unwrap();
    drop(tcp);
    drop(tcp_task);
    drop(udp_task);
}

#[tokio::test]
#[ignore = "requires pinned reference; use check-hysteria-interop.sh or check-native-hysteria-interop.sh"]
async fn pinned_reference_rejects_wrong_auth_and_closes_failed_tcp_destination() {
    let server = ReferenceServer::start().await;
    let mut wrong = server.config();
    wrong.auth = zeroize::Zeroizing::new("wrong-synthetic-auth".into());
    assert_eq!(
        HysteriaClient::connect(wrong, &server.connector)
            .await
            .err(),
        Some(HysteriaError::Authentication)
    );
    let client = HysteriaClient::connect(server.config(), &server.connector)
        .await
        .unwrap();
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    if server.is_native() {
        // Native Hysteria dials before acknowledging the request.
        assert!(matches!(
            client.open_tcp(&target).await,
            Err(HysteriaError::TcpRejected)
        ));
    } else {
        // Xray acknowledges before DispatchLink dials; failure arrives on the stream.
        let mut tcp = client.open_tcp(&target).await.unwrap();
        let mut byte = [0];
        let result = timeout(DEADLINE, tcp.read(&mut byte)).await.unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }
    assert!(client.is_live());
    client.close();
}

/// Moves `PAYLOAD` bytes through one Hysteria stream and returns how long it
/// took. `b'U'` uploads to the target, which acknowledges the last byte;
/// `b'D'` asks it for the bytes instead.
async fn timed_transfer(client: &HysteriaClient, target: &Target, direction: u8) -> Duration {
    let mut tcp = client.open_tcp(target).await.unwrap();
    tcp.write_all(&[direction]).await.unwrap();
    let started = std::time::Instant::now();
    if direction == b'U' {
        tcp.write_all(&vec![0x55; BRUTAL_PAYLOAD]).await.unwrap();
        let mut ack = [0];
        timeout(DEADLINE * 2, tcp.read_exact(&mut ack))
            .await
            .unwrap()
            .unwrap();
    } else {
        let mut received = vec![0; BRUTAL_PAYLOAD];
        timeout(DEADLINE * 2, tcp.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
    }
    started.elapsed()
}

const BRUTAL_PAYLOAD: usize = 3 * 1024 * 1024;

#[tokio::test]
#[ignore = "requires pinned reference; use check-hysteria-interop.sh or check-native-hysteria-interop.sh"]
async fn pinned_reference_brutal_paces_both_directions_at_the_negotiated_rate() {
    use xray_transport::stream::H3Congestion;
    // The server sends at up to 100 Mbps but takes only 8 Mbps, about 1 MiB/s
    // (Xray counts 2^20 bits per Mbps, native Hysteria 10^6).
    let server = ReferenceServer::start_with_bandwidth("100 mbps", "8 mbps").await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    let _endpoint = Task(tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut direction = [0];
                socket.read_exact(&mut direction).await.unwrap();
                if direction[0] == b'U' {
                    let mut buffer = vec![0; BRUTAL_PAYLOAD];
                    socket.read_exact(&mut buffer).await.unwrap();
                    socket.write_all(b"k").await.unwrap();
                } else {
                    socket.write_all(&vec![0x44; BRUTAL_PAYLOAD]).await.unwrap();
                }
                let _ = socket.shutdown().await;
            });
        }
    }));
    let connect = |congestion: H3Congestion, receive: u64| {
        let mut config = server.config();
        config.quic.congestion = congestion;
        config.receive_bytes_per_second = receive;
        HysteriaClient::connect(config, &server.connector)
    };
    let brutal = H3Congestion::Brutal {
        up_bytes_per_second: 100 << 17,
    };

    // Upload: Brutal at the server's announced 8 Mbps, not our 100 Mbps.
    let client = connect(brutal, 0).await.unwrap();
    let paced = timed_transfer(&client, &target, b'U').await;
    client.close();
    // Our announced 8 Mbps makes the server pace the download with Brutal.
    let client = connect(H3Congestion::BbrStandard, 1 << 20).await.unwrap();
    let paced_down = timed_transfer(&client, &target, b'D').await;
    // Neither side paces when the client announces no rate and runs BBR.
    let free_up = timed_transfer(&client, &target, b'U').await;
    client.close();
    let client = connect(H3Congestion::BbrStandard, 0).await.unwrap();
    let free_down = timed_transfer(&client, &target, b'D').await;
    client.close();

    eprintln!(
        "3 MiB: Brutal up {paced:?}, Brutal down {paced_down:?}, BBR up {free_up:?}, BBR down {free_down:?}"
    );
    for (name, elapsed) in [("upload", paced), ("download", paced_down)] {
        // About 3 s at 1 MiB/s; pacing never lets it finish much sooner.
        assert!(
            elapsed >= Duration::from_millis(2400) && elapsed <= Duration::from_secs(10),
            "Brutal {name} took {elapsed:?}"
        );
    }
    for (name, elapsed) in [("upload", free_up), ("download", free_down)] {
        assert!(
            elapsed < Duration::from_millis(1500),
            "unpaced {name} took {elapsed:?}"
        );
    }
}

#[path = "hysteria/network_change.rs"]
mod network_change;

#[path = "hysteria/carrier.rs"]
mod carrier;

#[path = "hysteria/header_custom.rs"]
mod header_custom;
