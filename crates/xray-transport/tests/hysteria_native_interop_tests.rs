#[path = "hysteria/support.rs"]
mod support;

use std::net::Ipv4Addr;
use support::{ReferenceServer, Task, DEADLINE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::hysteria::{HysteriaClient, HysteriaError};

#[tokio::test]
#[ignore = "requires official Hysteria; run scripts/check-native-hysteria-interop.sh"]
async fn native_hysteria_udp_fragmentation_at_reference_serialization_limit() {
    timeout(DEADLINE, async {
        let server = ReferenceServer::start().await;
        assert!(server.is_native());
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        // Native v2.12.2 allocates MaxUDPSize (4096) for payload AND for the
        // serialization buffer. The reply must fit the latter before fragmentation.
        let wire_header_len = 8 + 1 + address.to_string().len();
        let payload = vec![0x6b; 4096 - wire_header_len];
        let expected = payload.clone();
        let _echo = Task(tokio::spawn(async move {
            let mut packet = [0; 8192];
            let (n, peer) = socket.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..n], expected);
            socket.send_to(&packet[..n], peer).await.unwrap();
        }));
        let client = HysteriaClient::connect(server.config(), &server.connector)
            .await
            .unwrap();
        let flow = client.open_udp().unwrap();
        let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Udp);
        flow.send(&target, &payload).await.unwrap();
        let reply = flow.recv().await.unwrap();
        assert_eq!(reply.source, target);
        assert_eq!(reply.payload, payload);
        client.close();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires official Hysteria; run scripts/check-native-hysteria-interop.sh"]
async fn native_hysteria_udp_disabled_keeps_tcp_usable_without_allocating_udp_sessions() {
    timeout(DEADLINE, async {
        let server = ReferenceServer::start_with_udp(false).await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let _echo = Task(tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = socket.into_split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        }));
        let client = HysteriaClient::connect(server.config(), &server.connector)
            .await
            .unwrap();
        assert!(client.is_live());
        assert!(!client.udp_enabled());
        for _ in 0..3 {
            assert!(matches!(
                client.open_udp(),
                Err(HysteriaError::UdpUnsupported)
            ));
            assert_eq!(client.active_udp_sessions(), 0);
        }
        let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
        let mut stream = client.open_tcp(&target).await.unwrap();
        let payload = b"TCP survives UDP being disabled";
        stream.write_all(payload).await.unwrap();
        let mut reply = vec![0; payload.len()];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, payload);
        stream.shutdown().await.unwrap();
        client.close();
        assert!(!client.is_live());
    })
    .await
    .unwrap();
}
