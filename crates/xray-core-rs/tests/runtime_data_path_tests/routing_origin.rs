//! Routing rules on where a connection comes from: `source`, `sourcePort`,
//! `localIP`, `localPort` and `user`, across the SOCKS and HTTP inbounds.

use super::*;

const ORIGIN_CONFIG: &str = r#"{
    "inbounds": [
        {"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
         "settings": {"auth": "password", "udp": true, "accounts": [
             {"user": "alice", "pass": "alice-pass"},
             {"user": "bob", "pass": "bob-pass"}
         ]}},
        {"tag": "open-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
         "settings": {"auth": "noauth", "udp": true}},
        {"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 0}
    ],
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"}
    ],
    "routing": {"rules": [
        {"inboundTag": ["socks-in"], "user": ["alice"], "outboundTag": "block"},
        {"inboundTag": ["open-in"], "localIP": "127.0.0.1", "source": ["127.0.0.0/8"],
         "sourcePort": "1-65535", "outboundTag": "block"},
        {"inboundTag": ["http-in"], "localIP": ["192.0.2.1"], "outboundTag": "block"},
        {"inboundTag": ["http-in"], "source": ["127.0.0.1"], "localIP": ["127.0.0.1"],
         "localPort": "1-65535", "outboundTag": "block"}
    ]}
}"#;

async fn start_origin_core() -> Core {
    let config = parse_xray_json(ORIGIN_CONFIG)
        .expect("synthetic origin config parses")
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

/// Logs in as `user` and asks the SOCKS inbound to connect to `target`.
async fn socks5_connect_as(client: &mut TcpStream, user: &[u8], pass: &[u8], target: SocketAddr) {
    assert_eq!(socks5_password_login(client, user, pass).await, 0);
    let SocketAddr::V4(target) = target else {
        panic!("the echo server binds IPv4 loopback");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..2], [5, 0]);
}

/// Whether the flow reaches the echo server: `false` when the blackhole
/// closes it instead.
async fn echoes(client: &mut TcpStream) -> bool {
    if client.write_all(b"origin").await.is_err() {
        return false;
    }
    let mut received = Vec::new();
    let mut buffer = [0; 6];
    while received.len() < buffer.len() {
        match client.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => received.extend_from_slice(&buffer[..read]),
        }
    }
    received == b"origin"
}

#[tokio::test]
async fn socks_users_route_by_the_account_they_logged_in_with() {
    timeout(Duration::from_secs(5), async {
        let core = start_origin_core().await;
        let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
        let (echo_addr, _echo_handle) = spawn_echo_server().await;

        let mut alice = TcpStream::connect(socks_addr).await.unwrap();
        socks5_connect_as(&mut alice, b"alice", b"alice-pass", echo_addr).await;
        assert!(!echoes(&mut alice).await, "alice's flow was not blackholed");

        let mut bob = TcpStream::connect(socks_addr).await.unwrap();
        socks5_connect_as(&mut bob, b"bob", b"bob-pass", echo_addr).await;
        assert!(echoes(&mut bob).await, "bob's flow did not go direct");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn source_and_local_addresses_route_socks_and_http_flows() {
    timeout(Duration::from_secs(5), async {
        let core = start_origin_core().await;
        let (echo_addr, _echo_handle) = spawn_echo_server().await;

        // The client on 127.0.0.1 reaches the inbound on 127.0.0.1.
        let mut open = TcpStream::connect(core.inbound_addr(Some("open-in")).unwrap())
            .await
            .unwrap();
        socks5_connect(&mut open, echo_addr).await;
        assert!(!echoes(&mut open).await, "the source and local rule missed");

        // The HTTP inbound's first rule names another local address; the
        // second matches the client and the inbound's address.
        let mut http = TcpStream::connect(core.inbound_addr(Some("http-in")).unwrap())
            .await
            .unwrap();
        http.write_all(
            format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        let mut byte = [0; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if http.read(&mut byte).await.unwrap_or(0) == 0 {
                break;
            }
            head.push(byte[0]);
        }
        assert!(!echoes(&mut http).await, "the HTTP origin rule missed");
    })
    .await
    .unwrap();
}

const TUN_ORIGIN_CONFIG: &str = r#"{
    "inbounds": [{"tag": "tun-in", "protocol": "tun"}],
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
        {"tag": "drop", "protocol": "blackhole"}
    ],
    "routing": {"rules": [
        {"source": ["10.10.0.2"], "sourcePort": "49200", "network": "udp", "outboundTag": "block"},
        {"source": ["10.10.0.3"], "outboundTag": "drop"},
        {"source": ["10.10.0.2"], "network": "tcp", "outboundTag": "block"},
        {"localIP": ["0.0.0.0/0", "::/0"], "outboundTag": "drop"}
    ]}
}"#;

async fn start_tun_origin_core() -> Core {
    let config = parse_xray_json(TUN_ORIGIN_CONFIG)
        .expect("synthetic TUN origin config parses")
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

/// The outbound that took the UDP flow to `destination`, once it is open.
async fn outbound_of(core: &Core, destination: Ipv4Addr) -> Option<String> {
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
async fn tun_udp_flows_route_by_the_app_address() {
    timeout(Duration::from_secs(5), async {
        let mut core = start_tun_origin_core().await;
        let app = Ipv4Addr::new(10, 10, 0, 2);

        // The app's address and port select the block rule.
        let blocked = Ipv4Addr::new(192, 0, 2, 10);
        let request = ipv4_udp_packet(app, 49_200, blocked, 443, b"quic");
        core.tun().push_inbound(Bytes::from(request)).await.unwrap();
        assert_eq!(outbound_of(&core, blocked).await.as_deref(), Some("block"));

        // Another port misses it, and the `localIP` rule never matches a TUN
        // flow, which has no local address.
        let direct = Ipv4Addr::new(192, 0, 2, 11);
        let request = ipv4_udp_packet(app, 49_201, direct, 443, b"quic");
        core.tun().push_inbound(Bytes::from(request)).await.unwrap();
        assert_eq!(outbound_of(&core, direct).await.as_deref(), Some("direct"));

        // Another app address selects the drop rule.
        let dropped = Ipv4Addr::new(192, 0, 2, 12);
        let request = ipv4_udp_packet(Ipv4Addr::new(10, 10, 0, 3), 49_200, dropped, 443, b"quic");
        core.tun().push_inbound(Bytes::from(request)).await.unwrap();
        assert_eq!(outbound_of(&core, dropped).await.as_deref(), Some("drop"));
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_tcp_flows_route_by_the_app_address() {
    timeout(Duration::from_secs(5), async {
        let mut core = start_tun_origin_core().await;
        let mut client = TunTcpClient::new();
        client.connect("192.0.2.10:80".parse().unwrap());
        let mut received = Vec::new();
        pump_tun_until(&mut client, core.tun(), |client| {
            received.extend_from_slice(&client.recv_available());
            received.len() >= XRAY_BLACKHOLE_HTTP_RESPONSE_LEN
        })
        .await;
        assert!(
            received.starts_with(b"HTTP/1.1 403 Forbidden"),
            "{}",
            String::from_utf8_lossy(&received)
        );
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

/// The length of Xray-core's blackhole `http` response.
const XRAY_BLACKHOLE_HTTP_RESPONSE_LEN: usize = 97;

/// Whether a datagram sent through a UDP association made as `user` comes
/// back from the echo server.
async fn udp_echoes_as(socks_addr: SocketAddr, user: &[u8], echo_addr: SocketAddr) -> bool {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut control = TcpStream::connect(socks_addr).await.unwrap();
    let mut pass = user.to_vec();
    pass.extend_from_slice(b"-pass");
    assert_eq!(socks5_password_login(&mut control, user, &pass).await, 0);
    let mut associate = vec![5, 3, 0, 1, 127, 0, 0, 1];
    associate.extend_from_slice(&client.local_addr().unwrap().port().to_be_bytes());
    control.write_all(&associate).await.unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..4], [5, 0, 0, 1]);
    let target = Target::new(
        RoutingTargetAddr::Ip(echo_addr.ip()),
        echo_addr.port(),
        RoutingNetwork::Udp,
    );
    let request = encode_socks5_udp_datagram(&target, b"origin").unwrap();
    client
        .send_to(&request, socks5_ipv4_reply_addr(reply))
        .await
        .unwrap();
    let mut response = vec![0; 2048];
    let echoed = timeout(Duration::from_millis(300), client.recv_from(&mut response)).await;
    drop(control);
    echoed.is_ok_and(|received| {
        let (len, _) = received.unwrap();
        parse_socks5_udp_datagram(&response[..len])
            .is_ok_and(|reply| &reply.payload[..] == b"origin")
    })
}

#[tokio::test]
async fn socks_udp_associations_route_by_the_account_that_made_them() {
    timeout(Duration::from_secs(5), async {
        let core = start_origin_core().await;
        let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
        let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
        assert!(
            !udp_echoes_as(socks_addr, b"alice", echo_addr).await,
            "alice's datagram was not blackholed"
        );
        assert!(
            udp_echoes_as(socks_addr, b"bob", echo_addr).await,
            "bob's datagram did not go direct"
        );
        echo_handle.abort();
    })
    .await
    .unwrap();
}
