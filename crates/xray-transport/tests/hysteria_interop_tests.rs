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
