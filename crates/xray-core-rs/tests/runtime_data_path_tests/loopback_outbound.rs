//! The `loopback` outbound routes a connection again, as Xray-core's does.

use super::*;

/// A core whose default outbound blocks, and whose `lb` loopback routes
/// again from `again`, which reaches freedom.
async fn start(inbound: &str, rules: &str) -> Core {
    let raw = format!(
        r#"{{
        "inbounds": [{inbound}],
        "outbounds": [
            {{"tag": "block", "protocol": "blackhole"}},
            {{"tag": "lb", "protocol": "loopback", "settings": {{"inboundTag": "again"}}}},
            {{"tag": "spin", "protocol": "loopback", "settings": {{"inboundTag": "spin"}}}},
            {{"tag": "direct", "protocol": "freedom"}}
        ],
        "routing": {{"rules": {rules}}}
    }}"#
    );
    let config = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

const SOCKS_IN: &str = r#"{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
    "port": 0, "settings": {"udp": true}}"#;

const THROUGH_LOOPBACK: &str = r#"[
    {"inboundTag": ["socks-in", "tun-in"], "outboundTag": "lb"},
    {"inboundTag": ["again"], "outboundTag": "direct"}
]"#;

#[tokio::test]
async fn socks_tcp_goes_through_a_loopback() {
    let (echo, echo_handle) = spawn_echo_server().await;
    let mut core = start(SOCKS_IN, THROUGH_LOOPBACK).await;
    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    socks5_connect(&mut client, echo).await;
    assert_echoes(&mut client, b"looped back").await;

    // The connection is the final outbound's.
    let snapshot = core.connection_snapshot();
    assert_eq!(snapshot.connections.len(), 1);
    assert_eq!(
        snapshot.connections[0].outbound_tag.as_deref(),
        Some("direct")
    );
    assert_eq!(
        snapshot.connections[0].inbound_tag.as_deref(),
        Some("socks-in")
    );
    drop(client);
    core.stop().await.unwrap();
    echo_handle.await.unwrap();
}

#[tokio::test]
async fn socks_udp_goes_through_a_loopback() {
    let (echo, echo_handle) = spawn_udp_echo_server().await;
    let mut core = start(SOCKS_IN, THROUGH_LOOPBACK).await;
    let mut control = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(echo.ip()),
        echo.port(),
        RoutingNetwork::Udp,
    );
    let request = encode_socks5_udp_datagram(&target, b"looped datagram").unwrap();
    client.send_to(&request, relay).await.unwrap();
    let mut response = [0; 2048];
    let (len, _) = timeout(Duration::from_secs(5), client.recv_from(&mut response))
        .await
        .expect("freedom carries the datagram")
        .unwrap();
    let response = parse_socks5_udp_datagram(&response[..len]).unwrap();
    assert_eq!(&response.payload[..], b"looped datagram");
    drop(control);
    core.stop().await.unwrap();
    echo_handle.await.unwrap();
}

#[tokio::test]
async fn tun_udp_goes_through_a_loopback() {
    let (echo, echo_handle) = spawn_udp_echo_server().await;
    let mut core = start(r#"{"tag": "tun-in", "protocol": "tun"}"#, THROUGH_LOOPBACK).await;
    let app = Ipv4Addr::new(10, 10, 0, 2);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            app,
            49_200,
            Ipv4Addr::LOCALHOST,
            echo.port(),
            b"tun looped",
        )))
        .await
        .unwrap();
    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(b"tun looped".as_slice())
    })
    .await;
    assert_ipv4_udp_packet(
        &reply,
        Ipv4Addr::LOCALHOST,
        echo.port(),
        app,
        49_200,
        b"tun looped",
    );
    core.stop().await.unwrap();
    echo_handle.await.unwrap();
}

#[tokio::test]
async fn a_loopback_that_loops_fails_the_connection() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut core = start(
        SOCKS_IN,
        r#"[{"network": "tcp,udp", "outboundTag": "spin"}]"#,
    )
    .await;
    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&listener.local_addr().unwrap().port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 1, "a general failure");
    // Nothing is dialed.
    assert!(timeout(Duration::from_millis(200), listener.accept())
        .await
        .is_err());
    core.stop().await.unwrap();
}
