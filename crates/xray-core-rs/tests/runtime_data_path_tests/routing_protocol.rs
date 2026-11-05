//! Routing rules on the sniffed protocol: `protocol`, matched by prefix
//! against the names Xray-core's sniffers give.

use super::*;

const PROTOCOL_CONFIG: &str = r#"{
    "inbounds": [
        {"tag": "sniffed-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
         "settings": {"auth": "noauth", "udp": true},
         "sniffing": {"enabled": true, "destOverride": []}},
        {"tag": "plain-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
         "settings": {"auth": "noauth", "udp": true}},
        {"tag": "tun-in", "protocol": "tun",
         "sniffing": {"enabled": true, "destOverride": ["http"], "routeOnly": true}}
    ],
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}
    ],
    "routing": {"rules": [
        {"protocol": ["bittorrent"], "outboundTag": "block"},
        {"inboundTag": ["sniffed-in"], "protocol": "http", "outboundTag": "block"}
    ]}
}"#;

async fn start_protocol_core() -> Core {
    let config = parse_xray_json(PROTOCOL_CONFIG)
        .expect("synthetic protocol config parses")
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

fn bittorrent_handshake() -> Vec<u8> {
    let mut handshake = vec![19];
    handshake.extend_from_slice(b"BitTorrent protocol");
    handshake.extend_from_slice(&[0; 8]);
    handshake.extend_from_slice(&[0x11; 40]);
    handshake
}

/// Sends `payload` through the SOCKS inbound at `socks_addr` to the echo
/// server and reports whether it came back.
async fn echoes_through(socks_addr: SocketAddr, echo_addr: SocketAddr, payload: &[u8]) -> bool {
    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;
    if client.write_all(payload).await.is_err() {
        return false;
    }
    let mut received = Vec::new();
    let mut buffer = vec![0; payload.len()];
    while received.len() < payload.len() {
        match timeout(Duration::from_secs(2), client.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => received.extend_from_slice(&buffer[..read]),
        }
    }
    received == payload
}

#[tokio::test]
async fn socks_flows_route_by_their_sniffed_protocol() {
    timeout(Duration::from_secs(10), async {
        let core = start_protocol_core().await;
        let sniffed = core.inbound_addr(Some("sniffed-in")).unwrap();
        let (echo_addr, _echo_handle) = spawn_echo_server().await;

        // `destOverride` is empty, yet the flows are sniffed for routing.
        assert!(!echoes_through(sniffed, echo_addr, &bittorrent_handshake()).await);
        let http = b"GET / HTTP/1.1\r\nHost: sniffed.example\r\n\r\n";
        assert!(
            !echoes_through(sniffed, echo_addr, http).await,
            "http1 starts with http"
        );
        assert!(echoes_through(sniffed, echo_addr, b"plain bytes, no protocol").await);

        // Without sniffing a flow has no protocol, so no protocol rule applies.
        // Each echo server answers one connection.
        let plain = core.inbound_addr(Some("plain-in")).unwrap();
        let (echo_addr, _echo_handle) = spawn_echo_server().await;
        assert!(echoes_through(plain, echo_addr, &bittorrent_handshake()).await);
    })
    .await
    .unwrap();
}

/// The outbound that took the UDP flow to `destination`, once it is open.
async fn udp_outbound(core: &Core, destination: Ipv4Addr) -> Option<String> {
    let deadline = TokioInstant::now() + Duration::from_secs(2);
    loop {
        let snapshot = core.connection_snapshot();
        if let Some(connection) = snapshot.connections.iter().find(|connection| {
            connection.target.addr == xray_routing::TargetAddr::Ip(IpAddr::V4(destination))
                && connection.network == xray_routing::Network::Udp
        }) {
            return connection.outbound_tag.clone();
        }
        if TokioInstant::now() >= deadline {
            return None;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn tun_udp_flows_route_by_their_sniffed_protocol() {
    timeout(Duration::from_secs(5), async {
        let mut core = start_protocol_core().await;
        let app = Ipv4Addr::new(10, 10, 0, 2);
        // A uTP `ST_SYN`, which Xray-core's sniffer names `bittorrent`.
        let mut syn = vec![0x41, 0];
        syn.extend_from_slice(&[0; 18]);
        let utp = Ipv4Addr::new(192, 0, 2, 20);
        let request = ipv4_udp_packet(app, 49_300, utp, 6881, &syn);
        core.tun().push_inbound(Bytes::from(request)).await.unwrap();
        assert_eq!(udp_outbound(&core, utp).await.as_deref(), Some("block"));

        let other = Ipv4Addr::new(192, 0, 2, 21);
        let request = ipv4_udp_packet(app, 49_301, other, 6881, b"not utp at all, twenty+");
        core.tun().push_inbound(Bytes::from(request)).await.unwrap();
        assert_eq!(udp_outbound(&core, other).await.as_deref(), Some("direct"));
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_tcp_flows_route_by_their_sniffed_protocol() {
    timeout(Duration::from_secs(5), async {
        let mut core = start_protocol_core().await;
        let mut client = TunTcpClient::new();
        client.connect("192.0.2.30:6881".parse().unwrap());
        let mut sent = false;
        let mut received = Vec::new();
        pump_tun_until(&mut client, core.tun(), |client| {
            if !sent && client.may_send() {
                client.send_payload(&bittorrent_handshake());
                sent = true;
            }
            received.extend_from_slice(&client.recv_available());
            received.starts_with(b"HTTP/1.1 403")
        })
        .await;
        assert!(received.starts_with(b"HTTP/1.1 403 Forbidden"));
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}
