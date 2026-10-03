#[path = "hysteria_runtime/support.rs"]
mod hysteria_support;
#[path = "trojan_runtime/support.rs"]
mod support;
use std::sync::atomic::Ordering;
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use xray_proxy::inbound::{encode_socks5_udp_datagram, parse_socks5_udp_datagram};
use xray_routing::{Network, Target, TargetAddr};

#[tokio::test]
#[ignore = "requires pinned reference; run scripts/check-shadowsocks2022-interop.sh"]
async fn shadowsocks_runtime_udp_reopens_after_port_change_and_survives_server_restart() {
    use std::sync::Arc;
    use xray_proxy::shadowsocks2022::{Method, UdpSession};

    for (method, identity) in [
        ("2022-blake3-aes-128-gcm", false),
        ("2022-blake3-aes-256-gcm", false),
        ("2022-blake3-chacha20-poly1305", false),
        ("2022-blake3-aes-128-gcm", true),
        ("2022-blake3-aes-256-gcm", true),
    ] {
        eprintln!("SS2022 recovery: {method}, identity={identity}");
        let mut server = ReferenceServer::start_shadowsocks("raw", method, identity).await;
        timeout(DEADLINE, async {
            let (origin, _echo) = udp_echo().await;
            let target = Target::new(TargetAddr::Ip(origin.ip()), origin.port(), Network::Udp);
            let profile = server.profile();
            let password = profile["outbounds"][0]["settings"]["password"]
                .as_str()
                .unwrap();
            let method = Arc::new(Method::new(method, password).unwrap());
            let mut session = UdpSession::new(method.clone()).unwrap();
            let mut unrelated = UdpSession::new(method.clone()).unwrap();
            let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let rebound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            assert_ne!(first.local_addr().unwrap(), rebound.local_addr().unwrap());
            let mut old_response: Option<Vec<u8>> = None;
            // Both pinned servers retain the first UDP return address for a
            // cryptographic session. Verify that limitation, then reopen the
            // client session on the new path before restarting the server.
            for (phase, socket) in [&first, &rebound, &rebound, &rebound]
                .into_iter()
                .enumerate()
            {
                eprintln!("SS2022 recovery phase {phase}");
                if phase == 2 {
                    session = UdpSession::new(method.clone()).unwrap();
                }
                if phase == 3 {
                    server.restart().await;
                }
                let payload = vec![phase as u8; 1200];
                let request = session.encode(&target, &payload).unwrap();
                socket.send_to(&request, server.address).await.unwrap();
                let mut response = vec![0; 9000];
                let return_socket = if phase == 1 { &first } else { socket };
                let (length, source) = return_socket.recv_from(&mut response).await.unwrap();
                assert_eq!(source, server.address);
                response.truncate(length);
                assert!(unrelated.decode(&response).is_err(), "response binding");
                let mut forged = response.clone();
                *forged.last_mut().unwrap() ^= 1;
                assert!(
                    session.decode(&forged).is_err(),
                    "authentication before replay state"
                );
                let (address, reply) = session.decode(&response).unwrap();
                assert_eq!(address, target);
                assert_eq!(reply, payload);
                assert!(session.decode(&response).is_err(), "duplicate response");
                if let Some(previous) = &old_response {
                    assert!(session.decode(previous).is_err(), "old-session replay");
                }
                old_response = Some(response);
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-shadowsocks2022-interop.sh"]
async fn shadowsocks_runtime_carriers_socks_http_udp_accounting_and_close() {
    let cases = [
        ("raw", "2022-blake3-aes-128-gcm", false),
        ("raw", "2022-blake3-aes-256-gcm", false),
        ("raw", "2022-blake3-chacha20-poly1305", false),
        ("raw", "2022-blake3-aes-128-gcm", true),
        ("raw", "2022-blake3-aes-256-gcm", true),
        ("ws", "2022-blake3-aes-128-gcm", false),
        ("httpupgrade", "2022-blake3-aes-128-gcm", false),
        ("grpc", "2022-blake3-aes-128-gcm", false),
        ("xhttp", "2022-blake3-aes-128-gcm", false),
    ];
    for (carrier, method, identity) in cases {
        if !reference_supports("shadowsocks", carrier) {
            continue;
        }
        eprintln!("SS2022: {carrier}, {method}, identity={identity}");
        let server = ReferenceServer::start_shadowsocks(carrier, method, identity).await;
        timeout(DEADLINE, async {
            let (tcp_addr, _tcp) = tcp_echo().await;
            let (udp_addr, _udp) = udp_echo().await;
            let (mut core, protector, bootstrap, _) = server.core();
            core.start().await.unwrap();
            let proxy = core.inbound_addr(Some("socks-in")).unwrap();
            let (mut tcp, _) = socks(proxy, 1, "localhost", tcp_addr.port()).await;
            echo(&mut tcp, b"TCP through Trojan").await;
            eprintln!("SOCKS TCP passed");
            let mut http = TcpStream::connect(core.inbound_addr(Some("http-in")).unwrap())
                .await
                .unwrap();
            http.write_all(
                format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    tcp_addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let mut reply = Vec::new();
            while !reply.ends_with(b"\r\n\r\n") {
                reply.push(http.read_u8().await.unwrap());
                assert!(reply.len() < 1024);
            }
            assert!(reply.starts_with(b"HTTP/1.1 200"));
            echo(&mut http, b"HTTP through Trojan").await;
            eprintln!("HTTP CONNECT passed");
            let (_control, relay) = socks(proxy, 3, "0.0.0.0", 0).await;
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = Target::new(TargetAddr::Ip(udp_addr.ip()), udp_addr.port(), Network::Udp);
            for size in [1, 4096, 8000] {
                eprintln!("UDP {size}");
                let payload = vec![0x5a; size];
                udp.send_to(
                    &encode_socks5_udp_datagram(&target, &payload).unwrap(),
                    relay,
                )
                .await
                .unwrap();
                let mut buffer = vec![0; 9000];
                let n = udp.recv(&mut buffer).await.unwrap();
                let packet = parse_socks5_udp_datagram(&buffer[..n]).unwrap();
                assert_eq!(packet.target, target);
                assert_eq!(packet.payload.as_ref(), payload);
            }
            assert!(protector.0.load(Ordering::SeqCst) > 0);
            assert!(bootstrap.0.load(Ordering::SeqCst) > 0);
            let snapshot = core.connection_snapshot();
            assert_eq!(snapshot.connections.len(), 3);
            assert!(snapshot
                .connections
                .iter()
                .all(|c| c.outbound_tag.as_deref() == Some("proxy")));
            let id = snapshot
                .connections
                .iter()
                .find(|c| c.network == Network::Udp)
                .unwrap()
                .id;
            core.close_connection(id).unwrap();
            while core
                .connection_snapshot()
                .connections
                .iter()
                .any(|c| c.id == id)
            {
                tokio::task::yield_now().await;
            }
            echo(&mut tcp, b"TCP survives UDP close").await;
            let accounting = core.outbound_accounting_snapshot();
            let proxy = accounting
                .outbounds
                .iter()
                .find(|c| c.outbound_tag.as_deref() == Some("proxy"))
                .unwrap();
            assert!(proxy.uplink_bytes >= 12097 && proxy.downlink_bytes >= 12097);
            core.stop().await.unwrap();
            assert!(core.connection_snapshot().connections.is_empty());
            assert!(tcp.read_u8().await.is_err());
        })
        .await
        .unwrap();
    }
}
