#[path = "hysteria_runtime/support.rs"]
#[allow(unused_imports)]
mod hysteria_support;
#[path = "wireguard_runtime/support.rs"]
mod support;
use std::sync::atomic::Ordering;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use xray_proxy::inbound::{encode_socks5_udp_datagram, parse_socks5_udp_datagram};
use xray_routing::{Network, Target, TargetAddr};

#[tokio::test]
#[ignore = "requires pinned reference; use check-wireguard-runtime.sh or check-native-wireguard-interop.sh"]
async fn wireguard_runtime_socks_http_udp_share_session_account_and_stop() {
    sharing_accounting_and_stop(None).await;
}
#[tokio::test]
#[ignore = "requires pinned reference; use check-wireguard-runtime.sh or check-native-wireguard-interop.sh"]
async fn wireguard_runtime_psk_socks_http_udp_share_session_account_and_stop() {
    sharing_accounting_and_stop(Some([0x64; 32])).await;
}
async fn sharing_accounting_and_stop(psk: Option<[u8; 32]>) {
    timeout(DEADLINE, async {
        let server = ReferenceServer::start_with_psk(psk).await;
        let (tcp_addr, _tcp) = tcp_echo().await;
        let (udp_addr, _udp) = udp_echo().await;
        let (mut core, protector, bootstrap, _dialer) = core(&server);
        core.start().await.unwrap();
        let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
        let (mut tcp, _) = socks(socks_addr, 1, "198.51.100.7", tcp_addr.port()).await;
        echo(&mut tcp, b"socks through wireguard").await;
        let mut http = TcpStream::connect(core.inbound_addr(Some("http-in")).unwrap())
            .await
            .unwrap();
        http.write_all(
            format!(
                "CONNECT 198.51.100.7:{} HTTP/1.1\r\nHost: 198.51.100.7:{}\r\n\r\n",
                tcp_addr.port(),
                tcp_addr.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(http.read_u8().await.unwrap());
            assert!(response.len() < 1024);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
        echo(&mut http, b"http through wireguard").await;
        let (_control, relay) = socks(socks_addr, 3, "0.0.0.0", 0).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = Target::new(
            TargetAddr::Ip(INNER_IP.into()),
            udp_addr.port(),
            Network::Udp,
        );
        let payload = vec![0x5a; 1200];
        udp.send_to(
            &encode_socks5_udp_datagram(&target, &payload).unwrap(),
            relay,
        )
        .await
        .unwrap();
        let mut packet = [0; 8192];
        let n = udp.recv(&mut packet).await.unwrap();
        let reply = parse_socks5_udp_datagram(&packet[..n]).unwrap();
        assert_eq!(reply.target, target);
        assert_eq!(reply.payload.as_ref(), payload);
        assert_eq!(
            protector.0.load(Ordering::SeqCst),
            1,
            "TCP and UDP must share protected WireGuard"
        );
        assert_eq!(bootstrap.0.load(Ordering::SeqCst), 1);
        let snapshot = core.connection_snapshot();
        assert_eq!(snapshot.connections.len(), 3);
        assert!(snapshot
            .connections
            .iter()
            .all(|c| c.outbound_tag.as_deref() == Some("proxy")));
        let tcp_id = snapshot
            .connections
            .iter()
            .find(|c| c.inbound_tag.as_deref() == Some("socks-in") && c.network == Network::Tcp)
            .unwrap()
            .id;
        core.close_connection(tcp_id).unwrap();
        assert!(tcp.read_u8().await.is_err());
        echo(&mut http, b"other flow survives host close").await;
        let udp_id = snapshot
            .connections
            .iter()
            .find(|c| c.network == Network::Udp)
            .unwrap()
            .id;
        core.close_connection(udp_id).unwrap();
        while core
            .connection_snapshot()
            .connections
            .iter()
            .any(|c| c.id == udp_id)
        {
            tokio::task::yield_now().await;
        }
        let accounting = core.outbound_accounting_snapshot();
        let proxy = accounting
            .outbounds
            .iter()
            .find(|o| o.outbound_tag.as_deref() == Some("proxy"))
            .unwrap();
        assert!(proxy.uplink_bytes >= 1200 && proxy.downlink_bytes >= 1200);
        assert_eq!(proxy.host_closed_connections, 2);
        core.stop().await.unwrap();
        while !core.connection_snapshot().connections.is_empty() {
            tokio::task::yield_now().await;
        }
        assert!(http.read_u8().await.is_err());
        // A new core owns a fresh connection and freshly invokes protection.
        let (mut fresh, fresh_protector, _, _) = support::core(&server);
        fresh.start().await.unwrap();
        let (mut tcp, _) = socks(
            fresh.inbound_addr(Some("socks-in")).unwrap(),
            1,
            "198.51.100.7",
            tcp_addr.port(),
        )
        .await;
        echo(&mut tcp, b"fresh core").await;
        assert_eq!(fresh_protector.0.load(Ordering::SeqCst), 1);
        fresh.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires pinned reference; use check-wireguard-runtime.sh or check-native-wireguard-interop.sh"]
async fn wireguard_runtime_concurrent_open_isolated_socket_policy() {
    use std::sync::Arc;
    use xray_core_rs::{open_tcp_stream_with_resolver_and_dialer, CoreError, OutboundRouter};
    use xray_wireguard::Error;
    timeout(DEADLINE, async {
        let server = ReferenceServer::start().await;
        let (address, _echo) = tcp_echo().await;
        let (_core, protector, bootstrap, dialer) = core(&server);
        let config = xray_config::parse_xray_json(&profile(server.address).to_string())
            .unwrap()
            .config;
        let router = OutboundRouter::new(Arc::new(config));
        let outbound = router.select_tcp_outbound().unwrap();
        let target = Target::new(
            TargetAddr::Ip(INNER_IP.into()),
            address.port(),
            Network::Tcp,
        );
        let (left, right) = tokio::join!(
            open_tcp_stream_with_resolver_and_dialer(
                &outbound,
                &target,
                bootstrap.as_ref(),
                &dialer
            ),
            open_tcp_stream_with_resolver_and_dialer(
                &outbound,
                &target,
                bootstrap.as_ref(),
                &dialer
            )
        );
        let (mut left, _right) = (left.unwrap(), right.unwrap());
        assert_eq!(protector.0.load(Ordering::SeqCst), 1);
        assert_eq!(bootstrap.0.load(Ordering::SeqCst), 1);
        let alternative = Arc::new(Protector::default());
        let changed_policy = dialer
            .as_ref()
            .clone()
            .with_socket_protector(alternative.clone());
        assert!(matches!(
            open_tcp_stream_with_resolver_and_dialer(
                &outbound,
                &target,
                bootstrap.as_ref(),
                &changed_policy
            )
            .await,
            Err(CoreError::Wireguard(Error::Configuration))
        ));
        assert_eq!(alternative.0.load(Ordering::SeqCst), 0);
        left.write_all(b"original policy still works")
            .await
            .unwrap();
        let mut response = [0; 27];
        left.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"original policy still works");
    })
    .await
    .unwrap();
}

#[path = "wireguard_runtime/multi_peer.rs"]
mod multi_peer;
