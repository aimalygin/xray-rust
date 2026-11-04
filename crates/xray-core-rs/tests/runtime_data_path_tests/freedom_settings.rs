//! Freedom's `redirect` and `userLevel`, from the parsed profile to the
//! socket. Destinations in 192.0.2.0/24 route nowhere, so only the redirect
//! reaches the loopback servers.

use super::*;

const NOWHERE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

async fn start(inbound: &str, freedom_settings: &str, extra: &str) -> Core {
    let raw = format!(
        r#"{{
        "inbounds": [{inbound}],
        "outbounds": [{{"protocol": "freedom", "settings": {freedom_settings}}}]{extra}
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

#[tokio::test]
async fn socks_tcp_goes_to_the_redirect_destination() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut core = start(
        SOCKS_IN,
        &format!(r#"{{"redirect": "127.0.0.1:{port}"}}"#),
        "",
    )
    .await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();

    // The destination name is never resolved: the redirect replaces it.
    let mut client = TcpStream::connect(socks).await.unwrap();
    socks5_connect_domain(&mut client, "nowhere.invalid", 9).await;
    let (mut accepted, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the redirect destination accepts")
        .unwrap();
    client.write_all(b"redirected").await.unwrap();
    let mut received = [0; 10];
    accepted.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"redirected");
    core.stop().await.unwrap();
}

#[tokio::test]
async fn socks_tcp_redirect_keeps_the_port_when_it_names_only_an_address() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut core = start(SOCKS_IN, r#"{"redirect": "127.0.0.1:0"}"#, "").await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks).await.unwrap();
    socks5_connect(&mut client, SocketAddr::from((NOWHERE, port))).await;
    timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the redirect keeps the destination port")
        .unwrap();
    core.stop().await.unwrap();
}

#[tokio::test]
async fn socks_udp_replies_come_from_the_addressed_destination() {
    let (echo, echo_handle) = spawn_udp_echo_server().await;
    let mut core = start(SOCKS_IN, &format!(r#"{{"redirect": "{echo}"}}"#), "").await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let mut control = TcpStream::connect(socks).await.unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(NOWHERE)),
        9,
        RoutingNetwork::Udp,
    );
    let request = encode_socks5_udp_datagram(&target, b"redirected datagram").unwrap();
    client.send_to(&request, relay).await.unwrap();

    let mut response = [0; 2048];
    let (len, _) = timeout(Duration::from_secs(5), client.recv_from(&mut response))
        .await
        .expect("the redirect destination answers")
        .unwrap();
    let response = parse_socks5_udp_datagram(&response[..len]).unwrap();
    assert_eq!(&response.payload[..], b"redirected datagram");
    // Xray-core attributes the reply to the destination the client addressed.
    assert_eq!(response.target, target);
    drop(control);
    core.stop().await.unwrap();
    echo_handle.await.unwrap();
}

#[tokio::test]
async fn tun_udp_goes_to_the_redirect_destination() {
    let (echo, echo_handle) = spawn_udp_echo_server().await;
    let mut core = start(
        r#"{"tag": "tun-in", "protocol": "tun"}"#,
        &format!(r#"{{"redirect": "{echo}"}}"#),
        "",
    )
    .await;
    let client = Ipv4Addr::new(10, 10, 0, 2);
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            client,
            49_180,
            NOWHERE,
            9,
            b"tun redirected",
        )))
        .await
        .unwrap();
    let reply = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(b"tun redirected".as_slice())
    })
    .await;
    // The app sees the reply come from the address it sent to.
    assert_ipv4_udp_packet(&reply, NOWHERE, 9, client, 49_180, b"tun redirected");
    core.stop().await.unwrap();
    echo_handle.await.unwrap();
}

#[derive(Clone, Copy)]
enum Inbound {
    Socks,
    Http,
}

/// Whether a freedom connection is still open 200 ms after CONNECT.
async fn stays_open(inbound: Inbound, freedom_settings: &str) -> bool {
    let (echo, echo_handle) = spawn_echo_server().await;
    let listener = match inbound {
        Inbound::Socks => SOCKS_IN,
        Inbound::Http => {
            r#"{"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 0}"#
        }
    };
    let mut core = start(
        listener,
        freedom_settings,
        r#", "policy": {"levels": {"8": {"connIdle": 0}}}"#,
    )
    .await;
    let mut client;
    match inbound {
        Inbound::Socks => {
            client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
                .await
                .unwrap();
            socks5_connect(&mut client, echo).await;
        }
        Inbound::Http => {
            client = TcpStream::connect(core.inbound_addr(Some("http-in")).unwrap())
                .await
                .unwrap();
            http_connect(&mut client, echo).await;
        }
    }
    let mut byte = [0; 1];
    let open = match timeout(Duration::from_millis(200), client.read(&mut byte)).await {
        Err(_) => true,
        Ok(read) => {
            assert_eq!(read.unwrap(), 0, "the echo server sends nothing first");
            false
        }
    };
    drop(client);
    core.stop().await.unwrap();
    let _ = timeout(Duration::from_secs(1), echo_handle).await;
    open
}

#[tokio::test]
async fn freedom_user_level_sets_its_idle_timeout() {
    // Level 8 has no idle time at all; the inbound stays at level 0.
    for inbound in [Inbound::Socks, Inbound::Http] {
        assert!(stays_open(inbound, "{}").await);
        assert!(!stays_open(inbound, r#"{"userLevel": 8}"#).await);
    }
}

/// Whether a TUN TCP flow through freedom is still open 300 ms after its
/// handshake.
async fn tun_stays_open(freedom_settings: &str) -> bool {
    let (echo, echo_handle) = spawn_echo_server().await;
    let mut core = start(
        r#"{"tag": "tun-in", "protocol": "tun"}"#,
        freedom_settings,
        r#", "policy": {"levels": {"8": {"connIdle": 0}}}"#,
    )
    .await;
    let mut client = TunTcpClient::new();
    client.connect(echo);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;
    let established = TokioInstant::now();
    pump_tun_until(&mut client, core.tun(), |client| {
        !client.may_recv() || established.elapsed() > Duration::from_millis(300)
    })
    .await;
    let open = client.may_recv();
    core.stop().await.unwrap();
    let _ = timeout(Duration::from_secs(1), echo_handle).await;
    open
}

#[tokio::test]
async fn freedom_user_level_sets_the_tun_idle_timeout() {
    assert!(tun_stays_open("{}").await);
    assert!(!tun_stays_open(r#"{"userLevel": 8}"#).await);
}
