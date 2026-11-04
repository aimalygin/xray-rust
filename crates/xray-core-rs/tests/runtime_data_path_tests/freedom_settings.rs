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

const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

/// go-proxyproto's version 2 header between two IPv4 ends.
fn v2_ipv4_header(transport: u8, source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
        panic!("IPv4 ends");
    };
    let mut header = V2_SIGNATURE.to_vec();
    header.extend_from_slice(&[0x21, 0x10 | transport, 0, 12]);
    header.extend_from_slice(&source.ip().octets());
    header.extend_from_slice(&destination.ip().octets());
    header.extend_from_slice(&source.port().to_be_bytes());
    header.extend_from_slice(&destination.port().to_be_bytes());
    header
}

/// Accepts one connection and reads exactly `len` bytes from it.
async fn accept_and_read(listener: &TcpListener, len: usize) -> Vec<u8> {
    let (mut accepted, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("freedom connects")
        .unwrap();
    let mut received = vec![0; len];
    timeout(Duration::from_secs(5), accepted.read_exact(&mut received))
        .await
        .expect("the header and payload arrive")
        .unwrap();
    received
}

#[tokio::test]
async fn tcp_connections_start_with_the_proxy_protocol_header() {
    for (version, inbound) in [(1, Inbound::Socks), (2, Inbound::Socks), (1, Inbound::Http)] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server = listener.local_addr().unwrap();
        let inbound_config = match inbound {
            Inbound::Socks => SOCKS_IN,
            Inbound::Http => {
                r#"{"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 0}"#
            }
        };
        let mut core = start(
            inbound_config,
            &format!(r#"{{"proxyProtocol": {version}}}"#),
            "",
        )
        .await;
        let mut client;
        match inbound {
            Inbound::Socks => {
                client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
                    .await
                    .unwrap();
                socks5_connect(&mut client, server).await;
            }
            Inbound::Http => {
                client = TcpStream::connect(core.inbound_addr(Some("http-in")).unwrap())
                    .await
                    .unwrap();
                http_connect(&mut client, server).await;
            }
        }
        client.write_all(b"payload").await.unwrap();
        // The source is the inbound's client.
        let source = client.local_addr().unwrap();
        let mut expected = match version {
            1 => format!(
                "PROXY TCP4 127.0.0.1 127.0.0.1 {} {}\r\n",
                source.port(),
                server.port()
            )
            .into_bytes(),
            _ => v2_ipv4_header(0x1, source, server),
        };
        expected.extend_from_slice(b"payload");
        assert_eq!(
            accept_and_read(&listener, expected.len()).await,
            expected,
            "version {version}"
        );
        core.stop().await.unwrap();
    }
}

#[tokio::test]
async fn tun_tcp_names_the_app_in_the_proxy_protocol_header() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    let mut core = start(
        r#"{"tag": "tun-in", "protocol": "tun"}"#,
        r#"{"proxyProtocol": 1}"#,
        "",
    )
    .await;
    let expected = format!(
        "PROXY TCP4 10.10.0.2 127.0.0.1 49152 {}\r\npayload",
        server.port()
    );
    let accepted = tokio::spawn(async move { accept_and_read(&listener, expected.len()).await });
    let mut client = TunTcpClient::new();
    client.connect(server);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;
    client.send_payload(b"payload");
    pump_tun_until(&mut client, core.tun(), |_| accepted.is_finished()).await;
    let received = accepted.await.unwrap();
    assert_eq!(
        String::from_utf8(received).unwrap(),
        format!(
            "PROXY TCP4 10.10.0.2 127.0.0.1 49152 {}\r\npayload",
            server.port()
        )
    );
    core.stop().await.unwrap();
}

#[tokio::test]
async fn udp_flows_send_the_proxy_protocol_header_as_their_first_datagram() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut core = start(SOCKS_IN, r#"{"proxyProtocol": 2}"#, "").await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let mut control = TcpStream::connect(socks).await.unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(server_addr.ip()),
        server_addr.port(),
        RoutingNetwork::Udp,
    );
    let request = encode_socks5_udp_datagram(&target, b"datagram").unwrap();
    client.send_to(&request, relay).await.unwrap();

    let mut buffer = [0; 2048];
    let (len, _) = timeout(Duration::from_secs(5), server.recv_from(&mut buffer))
        .await
        .expect("the header arrives")
        .unwrap();
    assert_eq!(
        &buffer[..len],
        v2_ipv4_header(0x2, client.local_addr().unwrap(), server_addr)
    );
    let (len, _) = timeout(Duration::from_secs(5), server.recv_from(&mut buffer))
        .await
        .expect("the payload follows")
        .unwrap();
    assert_eq!(&buffer[..len], b"datagram");
    drop(control);
    core.stop().await.unwrap();

    // Version 1 has no UDP form: the header is go-proxyproto's UNKNOWN.
    let mut core = start(
        r#"{"tag": "tun-in", "protocol": "tun"}"#,
        r#"{"proxyProtocol": 1}"#,
        "",
    )
    .await;
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            49_180,
            Ipv4Addr::LOCALHOST,
            server_addr.port(),
            b"tun datagram",
        )))
        .await
        .unwrap();
    for expected in [b"PROXY UNKNOWN\r\n".as_slice(), b"tun datagram"] {
        let (len, _) = timeout(Duration::from_secs(5), server.recv_from(&mut buffer))
            .await
            .expect("the datagram arrives")
            .unwrap();
        assert_eq!(&buffer[..len], expected);
    }
    core.stop().await.unwrap();
}

#[tokio::test]
async fn a_blocked_tcp_connection_is_held_and_then_closed() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    let mut core = start(
        SOCKS_IN,
        &format!(
            r#"{{"finalRules": [{{"action": "block", "port": {}, "blockDelay": 1}}]}}"#,
            server.port()
        ),
        "",
    )
    .await;
    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    // As in Xray-core, the client sees success, then nothing, then a close.
    socks5_connect(&mut client, server).await;
    client.write_all(b"swallowed").await.unwrap();
    let held = TokioInstant::now();
    let mut buffer = [0; 16];
    let closed = timeout(Duration::from_secs(5), client.read(&mut buffer))
        .await
        .expect("the block delay closes the connection");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
    assert!(
        held.elapsed() >= Duration::from_millis(900),
        "{:?}",
        held.elapsed()
    );
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "a blocked destination is never dialed"
    );
    core.stop().await.unwrap();
}

#[tokio::test]
async fn an_earlier_allow_shields_an_address_and_names_are_checked_resolved() {
    let (echo, echo_handle) = spawn_echo_server().await;
    let rules = format!(
        r#"{{"finalRules": [
            {{"action": "allow", "network": "tcp", "port": "{}"}},
            {{"action": "block", "ip": ["127.0.0.0/8"], "blockDelay": 0}}
        ]}}"#,
        echo.port()
    );
    let mut core = start(
        SOCKS_IN,
        &rules,
        r#", "dns": {"hosts": {"loopback.test": "127.0.0.1"}}"#,
    )
    .await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let mut allowed = TcpStream::connect(socks).await.unwrap();
    socks5_connect(&mut allowed, echo).await;
    allowed.write_all(b"allowed").await.unwrap();
    let mut received = [0; 7];
    allowed.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"allowed");

    // A name is blocked by what it resolves to.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut blocked = TcpStream::connect(socks).await.unwrap();
    socks5_connect_domain(
        &mut blocked,
        "loopback.test",
        listener.local_addr().unwrap().port(),
    )
    .await;
    let mut buffer = [0; 1];
    let closed = timeout(Duration::from_secs(5), blocked.read(&mut buffer))
        .await
        .expect("a zero block delay closes at once");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
    assert!(timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_err());
    drop(allowed);
    core.stop().await.unwrap();
    let _ = timeout(Duration::from_secs(1), echo_handle).await;
}

/// A UDP server that receives on one socket and answers from another, so its
/// replies come from a second source.
async fn spawn_udp_reflector() -> (SocketAddr, SocketAddr, JoinHandle<()>) {
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let replier = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (receiver_addr, replier_addr) = (
        receiver.local_addr().unwrap(),
        replier.local_addr().unwrap(),
    );
    let handle = tokio::spawn(async move {
        let mut buffer = [0; 2048];
        loop {
            let (len, peer) = receiver.recv_from(&mut buffer).await.unwrap();
            replier.send_to(&buffer[..len], peer).await.unwrap();
        }
    });
    (receiver_addr, replier_addr, handle)
}

/// Sends `payload` to `target` over SOCKS UDP and returns the reply, if one
/// comes within half a second.
async fn socks_udp_exchange(
    socks: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut control = TcpStream::connect(socks).await.unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(target.ip()),
        target.port(),
        RoutingNetwork::Udp,
    );
    let request = encode_socks5_udp_datagram(&target, payload).unwrap();
    client.send_to(&request, relay).await.unwrap();
    let mut buffer = [0; 2048];
    let reply = timeout(Duration::from_millis(500), client.recv_from(&mut buffer))
        .await
        .ok()?
        .unwrap();
    Some(
        parse_socks5_udp_datagram(&buffer[..reply.0])
            .unwrap()
            .payload
            .to_vec(),
    )
}

#[tokio::test]
async fn udp_rules_block_destinations_and_reply_sources() {
    let (receiver, replier, reflector) = spawn_udp_reflector().await;
    // Without rules the reply arrives from the second socket.
    let mut core = start(SOCKS_IN, "{}", "").await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    assert_eq!(
        socks_udp_exchange(socks, receiver, b"control")
            .await
            .as_deref(),
        Some(b"control".as_slice())
    );
    core.stop().await.unwrap();

    for blocked in [receiver, replier] {
        let mut core = start(
            SOCKS_IN,
            &format!(
                r#"{{"finalRules": [{{"action": "block", "network": "udp", "port": {}}}]}}"#,
                blocked.port()
            ),
            "",
        )
        .await;
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        assert_eq!(
            socks_udp_exchange(socks, receiver, b"dropped").await,
            None,
            "blocking {blocked}"
        );
        core.stop().await.unwrap();
    }
    reflector.abort();
}

#[tokio::test]
async fn a_blocked_tun_udp_flow_sends_nothing() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut core = start(
        r#"{"tag": "tun-in", "protocol": "tun"}"#,
        r#"{"finalRules": [{"action": "block", "ip": "127.0.0.1"}]}"#,
        "",
    )
    .await;
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            49_181,
            Ipv4Addr::LOCALHOST,
            server_addr.port(),
            b"blocked",
        )))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(300), server.recv_from(&mut buffer))
            .await
            .is_err(),
        "a blocked flow sends nothing"
    );
    core.stop().await.unwrap();
}

/// A config whose HTTP outbound reaches `server` through a freedom hop with
/// these settings.
fn http_through_freedom_hop(server: SocketAddr, hop_settings: &str) -> String {
    format!(
        r#"{{
        "inbounds": [{SOCKS_IN}],
        "outbounds": [
            {{"protocol": "http", "settings": {{"address": "127.0.0.1", "port": {}}},
              "streamSettings": {{"sockopt": {{"dialerProxy": "hop"}}}}}},
            {{"tag": "hop", "protocol": "freedom", "settings": {hop_settings}}}
        ]
    }}"#,
        server.port()
    )
}

async fn start_raw(raw: &str) -> Core {
    let config = parse_xray_json(raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

#[tokio::test]
async fn a_freedom_hop_writes_the_header_before_the_next_protocol() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    let mut core = start_raw(&http_through_freedom_hop(server, r#"{"proxyProtocol": 1}"#)).await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let client = TcpStream::connect(socks).await.unwrap();
    let client_port = client.local_addr().unwrap().port();
    let connect = tokio::spawn(async move {
        let mut client = client;
        socks5_connect_domain(&mut client, "example.test", 443).await;
        client
    });

    let (accepted, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the hop connects")
        .unwrap();
    let mut reader = tokio::io::BufReader::new(accepted);
    let mut header = String::new();
    tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut header)
        .await
        .unwrap();
    // The hop names the client of the connection it carries.
    assert_eq!(
        header,
        format!(
            "PROXY TCP4 127.0.0.1 127.0.0.1 {client_port} {}\r\n",
            server.port()
        )
    );
    let mut request = String::new();
    tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut request)
        .await
        .unwrap();
    assert_eq!(request, "CONNECT example.test:443 HTTP/1.1\r\n");
    connect.abort();
    core.stop().await.unwrap();
}

#[tokio::test]
async fn a_freedom_hop_blocks_the_next_server() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    let mut core = start_raw(&http_through_freedom_hop(
        server,
        r#"{"finalRules": [{"action": "block", "blockDelay": 0}]}"#,
    ))
    .await;
    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 3, 12];
    request.extend_from_slice(b"example.test");
    request.extend_from_slice(&443_u16.to_be_bytes());
    client.write_all(&request).await.unwrap();
    // The HTTP outbound reads its CONNECT answer from the held stream, which
    // closes at once, so the SOCKS request fails.
    let mut reply = [0; 2];
    timeout(Duration::from_secs(5), client.read_exact(&mut reply))
        .await
        .expect("the request is answered")
        .unwrap();
    assert_ne!(reply[1], 0, "the chained request fails");
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "the blocked server is never dialed"
    );
    core.stop().await.unwrap();
}

#[tokio::test]
async fn the_header_goes_beneath_the_fragment_mask() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    let mut core = start(
        SOCKS_IN,
        r#"{"proxyProtocol": 1,
            "fragment": {"packets": "tlshello", "length": 2, "interval": 0}}"#,
        "",
    )
    .await;
    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    socks5_connect(&mut client, server).await;
    client
        .write_all(&[22, 3, 1, 0, 4, 1, 2, 3, 4])
        .await
        .unwrap();
    // Xray-core's freedom writes the header on the connection itself, so its
    // fragmenter still sees the hello as the first write and splits it.
    let mut expected = format!(
        "PROXY TCP4 127.0.0.1 127.0.0.1 {} {}\r\n",
        client.local_addr().unwrap().port(),
        server.port()
    )
    .into_bytes();
    expected.extend_from_slice(&[22, 3, 1, 0, 2, 1, 2, 22, 3, 1, 0, 2, 3, 4]);
    assert_eq!(accept_and_read(&listener, expected.len()).await, expected);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn tun_udp_drops_replies_from_blocked_sources() {
    let (receiver, replier, reflector) = spawn_udp_reflector().await;
    let client = Ipv4Addr::new(10, 10, 0, 2);
    for (rules, delivered) in [
        ("[]".to_owned(), true),
        (
            format!(
                r#"[{{"action": "block", "network": "udp", "port": {}}}]"#,
                replier.port()
            ),
            false,
        ),
    ] {
        let mut core = start(
            r#"{"tag": "tun-in", "protocol": "tun"}"#,
            &format!(r#"{{"finalRules": {rules}}}"#),
            "",
        )
        .await;
        core.tun()
            .push_inbound(Bytes::from(ipv4_udp_packet(
                client,
                49_182,
                Ipv4Addr::LOCALHOST,
                receiver.port(),
                b"reflected",
            )))
            .await
            .unwrap();
        let reply = timeout(
            Duration::from_millis(500),
            poll_tun_outbound_until(core.tun(), |packet| {
                ipv4_udp_payload(packet) == Some(b"reflected".as_slice())
            }),
        )
        .await;
        assert_eq!(reply.is_ok(), delivered, "rules {rules}");
        core.stop().await.unwrap();
    }
    reflector.abort();
}
