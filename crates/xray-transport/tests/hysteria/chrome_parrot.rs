//! Xray's ChromeParrot over Hysteria against the pinned server: with it on,
//! as Xray dials by default, and with `disableChromeParrot`, TCP and a
//! fragmented UDP datagram cross intact, and the client's first flight on the
//! wire has ChromeParrot's shape or the stock one.
use super::support::{tls_settings, ReferenceServer, Task, DEADLINE};
use crate::chrome_parrot_wire::{
    assert_chrome_first_flight, assert_stock_first_flight, RecordingRelay,
};
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{hysteria::HysteriaClient, TlsConnector};

#[tokio::test]
#[ignore = "requires pinned reference; use check-chrome-parrot-interop.sh, check-hysteria-interop.sh or check-native-hysteria-interop.sh"]
async fn pinned_reference_with_and_without_chrome_parrot() {
    let server = ReferenceServer::start().await;
    let relay = RecordingRelay::start(server.address).await;
    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let tcp_address = tcp_listener.local_addr().unwrap();
    let tcp_target = Target::new(
        TargetAddr::Ip(tcp_address.ip()),
        tcp_address.port(),
        Network::Tcp,
    );
    let _tcp = Task(tokio::spawn(async move {
        loop {
            let (socket, _) = tcp_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.into_split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    }));
    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp_address = udp_socket.local_addr().unwrap();
    let udp_target = Target::new(
        TargetAddr::Ip(udp_address.ip()),
        udp_address.port(),
        Network::Udp,
    );
    let _udp = Task(tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            let (count, remote) = udp_socket.recv_from(&mut buffer).await.unwrap();
            udp_socket.send_to(&buffer[..count], remote).await.unwrap();
        }
    }));

    // A connector of the client's own, verifying by the pinned certificate
    // hash, so the ChromeParrot ClientHello is the one on the wire.
    let connector = TlsConnector::system().unwrap();
    for chrome_parrot in [true, false] {
        let mut config = server.config();
        config.remote_addr = relay.address;
        config.tls = tls_settings();
        config.tls.pinned_peer_cert_sha256 = vec![server.certificate_sha256];
        config.quic.chrome_parrot = chrome_parrot;
        let client = HysteriaClient::connect(config, &connector)
            .await
            .unwrap_or_else(|error| panic!("chrome_parrot {chrome_parrot}: {error}"));

        let mut tcp = client.open_tcp(&tcp_target).await.unwrap();
        let message = format!("chrome_parrot {chrome_parrot} tcp echo");
        tcp.write_all(message.as_bytes()).await.unwrap();
        let mut echo = vec![0; message.len()];
        timeout(DEADLINE, tcp.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echo, message.as_bytes());
        drop(tcp);

        // A datagram the server fragments on the way back.
        let udp = client.open_udp().unwrap();
        let payload = vec![0x5a; server.fragmented_udp_payload_len()];
        udp.send(&udp_target, &payload).await.unwrap();
        let reply = timeout(DEADLINE, udp.recv()).await.unwrap().unwrap();
        assert_eq!(reply.payload, payload, "chrome_parrot {chrome_parrot}");
        drop(udp);
        client.close();

        let datagrams = relay.take();
        if chrome_parrot {
            assert_chrome_first_flight(&datagrams, b"h3");
        } else {
            assert_stock_first_flight(&datagrams);
        }
    }
}

/// ChromeParrot under a Salamander mask, as an Xray client dials it by
/// default: the server takes it, and the first flight leaves as 1250-byte
/// Initial datagrams each with Salamander's 8-byte salt in front.
#[tokio::test]
#[ignore = "requires pinned reference; use check-chrome-parrot-interop.sh or check-hysteria-interop.sh"]
async fn pinned_reference_chrome_parrot_under_salamander() {
    let server = ReferenceServer::start_with_carrier(true, true).await;
    let relay = RecordingRelay::start(server.address).await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    let _echo = Task(tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = socket.into_split();
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
    }));
    let mut config = server.config();
    config.remote_addr = relay.address;
    config.tls = tls_settings();
    config.tls.pinned_peer_cert_sha256 = vec![server.certificate_sha256];
    config.quic.chrome_parrot = true;
    config.carrier.salamander_password = Some(std::sync::Arc::new(zeroize::Zeroizing::new(
        super::support::SALAMANDER_PASSWORD.into(),
    )));
    let connector = TlsConnector::system().unwrap();
    let client = HysteriaClient::connect(config, &connector).await.unwrap();
    let mut tcp = client.open_tcp(&target).await.unwrap();
    tcp.write_all(b"chrome parrot under salamander")
        .await
        .unwrap();
    let mut echo = [0; 30];
    timeout(DEADLINE, tcp.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo, b"chrome parrot under salamander");
    client.close();
    let datagrams = relay.take();
    assert!(
        datagrams[..2].iter().all(|d| d.len() == 1250 + 8),
        "{:?}",
        datagrams.iter().map(Vec::len).collect::<Vec<_>>()
    );
}
