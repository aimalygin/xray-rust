//! FinalMask filters, which Xray-core's client never applies: a carrier
//! with them sends, byte for byte, what it sends without them, and takes
//! replies from the addresses they name.

use super::*;

/// A filter that, applied, would refuse everything the loopback tests send
/// and receive.
fn filter() -> serde_json::Value {
    serde_json::json!({"type": "filter", "settings": {
        "blockedSourceIPs": ["127.0.0.0/8", "::1"],
        "allowedSourceIPs": ["192.0.2.0/24"]}})
}

/// What the server sees of one TUN UDP flow through freedom under `masks`,
/// whose reply must come back to the TUN client.
async fn freedom_udp_flow_under(masks: serde_json::Value) -> Vec<Vec<u8>> {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let SocketAddr::V4(server_addr) = server.local_addr().unwrap() else {
        unreachable!("bound to IPv4");
    };
    let mut config = runtime_tun_config_with_freedom_outbound();
    let raw = serde_json::json!({"outbounds": [{"protocol": "freedom", "tag": "direct",
        "streamSettings": {"finalmask": {"udp": masks}}}]});
    config.outbounds = parse_xray_json(&raw.to_string()).unwrap().config.outbounds;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let client_addr = Ipv4Addr::new(10, 10, 0, 2);
    let request = ipv4_udp_packet(
        client_addr,
        49155,
        *server_addr.ip(),
        server_addr.port(),
        b"filtered tun udp",
    );
    core.tun().push_inbound(Bytes::from(request)).await.unwrap();
    let mut seen = Vec::new();
    let mut buffer = [0; 256];
    while seen.len() < 2 {
        let (n, peer) = server.recv_from(&mut buffer).await.unwrap();
        let datagram = buffer[..n].to_vec();
        if let Some(payload) = datagram.strip_prefix(b"hello") {
            let mut reply = b"world".to_vec();
            reply.extend_from_slice(payload);
            server.send_to(&reply, peer).await.unwrap();
        }
        seen.push(datagram);
    }
    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet).is_some_and(|payload| payload == b"filtered tun udp")
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        *server_addr.ip(),
        server_addr.port(),
        client_addr,
        49155,
        b"filtered tun udp",
    );
    core.stop().await.unwrap();
    seen
}

#[tokio::test]
async fn freedom_udp_under_filters_sends_and_takes_what_it_does_without_them() {
    timeout(Duration::from_secs(10), async {
        let noise = serde_json::json!({"type": "noise",
            "settings": {"noise": [{"type": "str", "packet": "noise"}]}});
        let header = serde_json::json!({"type": "header-custom", "settings": {"mode": "prefix",
            "client": [{"type": "str", "packet": "hello"}],
            "server": [{"type": "str", "packet": "world"}]}});
        // The noise goes out through the header-custom mask listed after it.
        let plain = freedom_udp_flow_under(serde_json::json!([noise, header])).await;
        assert_eq!(
            plain,
            [b"hellonoise".to_vec(), b"hellofiltered tun udp".to_vec()]
        );
        let filtered = freedom_udp_flow_under(serde_json::json!([
            filter(),
            noise,
            filter(),
            header,
            filter()
        ]))
        .await;
        assert_eq!(filtered, plain);
    })
    .await
    .unwrap();
}

/// What a VLESS server over plain TCP reads of one SOCKS connection whose
/// outbound runs under `masks`.
async fn vless_tcp_bytes_under(masks: serde_json::Value, payload: &[u8]) -> Vec<u8> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let raw = serde_json::json!({
        "inbounds": [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0}],
        "outbounds": [{"protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": server_addr.port(),
                "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]},
            "streamSettings": {"network": "raw", "finalmask": {"tcp": masks}}}]});
    let config = parse_xray_json(&raw.to_string()).unwrap().config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    socks5_connect(&mut client, SocketAddr::from(([192, 0, 2, 7], 80))).await;
    client.write_all(payload).await.unwrap();
    let (mut inbound, _) = listener.accept().await.unwrap();
    // The handshake, then VLESS: version, UUID, no addons, command, port,
    // an IPv4 address, then the payload.
    let mut seen = vec![0; 5 + 26 + payload.len()];
    inbound.read_exact(&mut seen).await.unwrap();
    drop(client);
    core.stop().await.unwrap();
    seen
}

#[tokio::test]
async fn vless_tcp_under_filters_sends_what_it_sends_without_them() {
    timeout(Duration::from_secs(10), async {
        let header = serde_json::json!({"type": "header-custom",
            "settings": {"clients": [[{"type": "str", "packet": "hello"}]]}});
        let payload = b"through the filters";
        let plain = vless_tcp_bytes_under(serde_json::json!([header]), payload).await;
        assert!(plain.starts_with(b"hello\0"), "{plain:?}");
        assert!(plain.ends_with(payload), "{plain:?}");
        let filtered =
            vless_tcp_bytes_under(serde_json::json!([filter(), header, filter()]), payload).await;
        assert_eq!(filtered, plain);
    })
    .await
    .unwrap();
}
