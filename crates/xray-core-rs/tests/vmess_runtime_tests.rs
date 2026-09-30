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
#[ignore = "requires pinned Xray; run scripts/check-vmess-interop.sh"]
async fn vmess_runtime_carriers_socks_http_udp_accounting_and_close() {
    let cases = [
        ("raw", "aes-128-gcm", ""),
        ("raw", "chacha20-poly1305", ""),
        ("raw", "auto", ""),
        ("raw", "aes-128-gcm", "AuthenticatedLength"),
        ("raw", "chacha20-poly1305", "AuthenticatedLength"),
        ("raw", "aes-128-gcm", "NoTerminationSignal"),
        (
            "raw",
            "aes-128-gcm",
            "AuthenticatedLength|NoTerminationSignal",
        ),
        ("ws", "aes-128-gcm", ""),
        ("httpupgrade", "aes-128-gcm", ""),
        ("grpc", "aes-128-gcm", ""),
        ("xhttp", "aes-128-gcm", ""),
    ];
    for (carrier, cipher, experiments) in cases {
        if !reference_supports("vmess", carrier) {
            continue;
        }
        eprintln!("VMess: {carrier}, {cipher}, {experiments}");
        let server = ReferenceServer::start_vmess(carrier, cipher, experiments).await;
        timeout(DEADLINE, async {
            let (tcp_addr, _tcp) = tcp_echo().await;
            let (udp_addr, _udp) = udp_echo().await;
            let (mut core, protector, bootstrap, _) = server.core();
            core.start().await.unwrap();
            let proxy = core.inbound_addr(Some("socks-in")).unwrap();
            let (mut tcp, _) = socks(proxy, 1, "localhost", tcp_addr.port()).await;
            echo(&mut tcp, b"TCP through VMess").await;
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
            echo(&mut http, b"HTTP through VMess").await;
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

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-vmess-interop.sh"]
async fn vmess_runtime_rejects_wrong_uuid_and_untrusted_peer() {
    use std::sync::Arc;
    use xray_core_rs::{open_tcp_stream_with_resolver_and_dialer, OutboundRouter};
    use xray_transport::TransportDialer;
    let server = ReferenceServer::start_vmess("ws", "aes-128-gcm", "").await;
    timeout(DEADLINE, async {
        let (address, _echo) = tcp_echo().await;
        let (_, protector, bootstrap, dialer) = server.core();
        let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
        let mut profile = server.profile();
        profile["outbounds"][0]["settings"]["id"] =
            serde_json::json!("11112233-4455-6677-8899-aabbccddeeff");
        let config = xray_config::parse_xray_json(&profile.to_string())
            .unwrap()
            .config;
        let router = OutboundRouter::new(Arc::new(config));
        let outbound = router.select_tcp_outbound().unwrap();
        let mut denied = open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            bootstrap.as_ref(),
            &dialer,
        )
        .await
        .unwrap();
        denied.write_all(b"must not be echoed").await.unwrap();
        let result = denied.read_u8().await;
        assert!(result.is_err(), "invalid UUID reached the destination");
        let untrusted = TransportDialer::system()
            .unwrap()
            .with_socket_protector(protector);
        assert!(
            open_tcp_stream_with_resolver_and_dialer(
                &outbound,
                &target,
                bootstrap.as_ref(),
                &untrusted,
            )
            .await
            .is_err(),
            "untrusted self-signed certificate was accepted"
        );
    })
    .await
    .unwrap();
}
