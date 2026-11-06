//! Freedom's `sockopt` on the UDP sockets the SOCKS inbound and TUN open
//! through it, and on DNS queries TUN forwards through it.

use super::*;

const SOCKS_IN: &str = r#"{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
    "port": 0, "settings": {"udp": true}}"#;
const TUN_IN: &str = r#"{"tag": "tun-in", "protocol": "tun"}"#;
/// An interface no host has: a socket bound to it fails, so nothing leaves.
const MISSING_INTERFACE: &str = r#"{"interface": "xray-missing0"}"#;

async fn start(inbound: &str, sockopt: &str, dns: &str) -> Core {
    let raw = format!(
        r#"{{
        "dns": {dns},
        "inbounds": [{inbound}],
        "outbounds": [{{"tag": "direct", "protocol": "freedom",
                        "streamSettings": {{"sockopt": {sockopt}}}}}]
    }}"#
    );
    let config = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

/// Whether `server` receives a datagram within a short wait.
async fn arrives(server: &UdpSocket) -> bool {
    let mut buffer = [0; 2048];
    timeout(Duration::from_millis(500), server.recv_from(&mut buffer))
        .await
        .is_ok()
}

#[tokio::test]
async fn socks_udp_through_freedom_takes_its_socket_options() {
    for (sockopt, expected) in [("{}", true), (MISSING_INTERFACE, false)] {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut core = start(SOCKS_IN, sockopt, "{}").await;
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let mut control = TcpStream::connect(socks).await.unwrap();
        let relay = socks5_udp_associate(&mut control).await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = Target::new(
            RoutingTargetAddr::Ip(server_addr.ip()),
            server_addr.port(),
            RoutingNetwork::Udp,
        );
        let request = encode_socks5_udp_datagram(&target, b"options").unwrap();
        client.send_to(&request, relay).await.unwrap();
        assert_eq!(arrives(&server).await, expected, "{sockopt}");
        drop(control);
        core.stop().await.unwrap();
    }
}

#[tokio::test]
async fn tun_udp_through_freedom_takes_its_socket_options() {
    for (sockopt, expected) in [("{}", true), (MISSING_INTERFACE, false)] {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = server.local_addr().unwrap().port();
        let mut core = start(TUN_IN, sockopt, "{}").await;
        let packet = ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            49_191,
            Ipv4Addr::LOCALHOST,
            port,
            b"options",
        );
        core.tun().push_inbound(Bytes::from(packet)).await.unwrap();
        assert_eq!(arrives(&server).await, expected, "{sockopt}");
        core.stop().await.unwrap();
    }
}

/// TUN answers an A or AAAA question through the resolver and forwards any
/// other one itself; both leave through freedom with its options.
#[tokio::test]
async fn tun_dns_queries_through_freedom_take_its_socket_options() {
    for (sockopt, expected, qtype) in [
        ("{}", true, 1),
        (MISSING_INTERFACE, false, 1),
        ("{}", true, 65),
        (MISSING_INTERFACE, false, 65),
    ] {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        let dns = format!(r#"{{"servers": [{{"address": "127.0.0.1", "port": {port}}}]}}"#);
        let mut core = start(TUN_IN, sockopt, &dns).await;
        let query = build_dns_query(0x2420, "options.example", qtype, 1);
        let packet = ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            53_042,
            Ipv4Addr::new(198, 18, 0, 1),
            53,
            &query,
        );
        core.tun().push_inbound(Bytes::from(packet)).await.unwrap();
        assert_eq!(arrives(&upstream).await, expected, "{sockopt} {qtype}");
        core.stop().await.unwrap();
    }
}
