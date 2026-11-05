//! The SOCKS inbound's handshake as Xray-core v26.10.31 reads it: addresses,
//! commands, replies and the handshake deadline.

use super::*;

async fn start(settings: &str, extra: &str) -> Core {
    let raw = format!(
        r#"{{
        "inbounds": [{{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
            "port": 0, "settings": {settings}}}],
        "outbounds": [{{"tag": "direct", "protocol": "freedom"}}]{extra}
    }}"#
    );
    let config = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

/// Connects to the SOCKS inbound and completes no-auth method selection.
async fn greeted(core: &Core) -> TcpStream {
    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    client
}

/// Everything the inbound sends until it closes the connection.
async fn rest(client: &mut TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut received))
        .await
        .expect("the inbound closes the connection")
        .unwrap();
    received
}

const SUCCESS: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
const COMMAND_NOT_SUPPORTED: [u8; 10] = [5, 7, 0, 1, 0, 0, 0, 0, 0, 0];

fn domain_request(command: u8, name: &[u8], port: u16) -> Vec<u8> {
    let mut request = vec![5, command, 0, 3, u8::try_from(name.len()).unwrap()];
    request.extend_from_slice(name);
    request.extend_from_slice(&port.to_be_bytes());
    request
}

#[tokio::test]
async fn an_ip_literal_sent_as_a_domain_is_routed_as_that_ip() {
    let (echo, echo_handle) = spawn_echo_server().await;
    // Only the IP rule reaches freedom; everything else is blocked.
    let raw = r#"{
        "inbounds": [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
            "port": 0}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}],
        "routing": {"rules": [
            {"ip": ["127.0.0.1"], "outboundTag": "direct"},
            {"network": "tcp,udp", "outboundTag": "block"}
        ]}
    }"#;
    let config = parse_xray_json(raw).unwrap().config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();

    let mut client = greeted(&core).await;
    client
        .write_all(&domain_request(1, b"127.0.0.1", echo.port()))
        .await
        .unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, SUCCESS);
    client.write_all(b"routed as an IP").await.unwrap();
    let mut echoed = [0; 15];
    timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
        .await
        .expect("freedom carries the connection")
        .unwrap();
    assert_eq!(&echoed, b"routed as an IP");
    drop(client);
    core.stop().await.unwrap();
    echo_handle.await.unwrap();
}

#[tokio::test]
async fn a_domain_xray_core_refuses_closes_without_a_reply() {
    let mut core = start("{}", "").await;
    for name in [b"exa mple.com".as_slice(), b"example.com:80", b"::1"] {
        let mut client = greeted(&core).await;
        client
            .write_all(&domain_request(1, name, 80))
            .await
            .unwrap();
        assert_eq!(rest(&mut client).await, b"", "{name:?}");
    }
    core.stop().await.unwrap();
}

#[tokio::test]
async fn unserved_commands_are_refused_before_their_address() {
    let mut core = start(r#"{"udp": false}"#, "").await;
    // BIND, an unknown command, and UDP while `udp` is false get REP 0x07
    // after the three bytes before the address.
    for command in [2, 9, 3] {
        let mut client = greeted(&core).await;
        client.write_all(&[5, command, 0]).await.unwrap();
        let mut reply = [0; 10];
        timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .expect("the refusal does not wait for an address")
            .unwrap();
        assert_eq!(reply, COMMAND_NOT_SUPPORTED, "command {command}");
        assert_eq!(rest(&mut client).await, b"", "command {command}");

        // An address that came with the request is read, so the close after
        // the reply is not a reset.
        let mut client = greeted(&core).await;
        client
            .write_all(&[5, command, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        assert_eq!(
            rest(&mut client).await,
            COMMAND_NOT_SUPPORTED,
            "command {command}"
        );
    }
    core.stop().await.unwrap();
}

#[tokio::test]
async fn tor_resolve_and_a_loose_header_still_connect() {
    let mut core = start("{}", "").await;
    // Tor's RESOLVE and RESOLVE_PTR connect, and the version and reserved
    // bytes of the request are not checked.
    for head in [[5, 0xf0, 0], [5, 0xf1, 0], [4, 1, 9]] {
        let (echo, echo_handle) = spawn_echo_server().await;
        let mut client = greeted(&core).await;
        let mut request = head.to_vec();
        request.push(1);
        request.extend_from_slice(&[127, 0, 0, 1]);
        request.extend_from_slice(&echo.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SUCCESS, "{head:?}");
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);
        echo_handle.await.unwrap();
    }
    core.stop().await.unwrap();
}

#[tokio::test]
async fn a_failed_login_gets_xray_core_status() {
    let mut core = start(
        r#"{"auth": "password", "users": [{"user": "synthetic-user", "pass": "old"},
            {"user": "synthetic-user", "pass": "synthetic-pass"}]}"#,
        "",
    )
    .await;
    let login = |pass: &'static [u8]| {
        let core_addr = core.inbound_addr(Some("socks-in")).unwrap();
        async move {
            let mut client = TcpStream::connect(core_addr).await.unwrap();
            client.write_all(&[5, 1, 2]).await.unwrap();
            let mut method = [0; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 2]);
            let mut request = vec![1, 14];
            request.extend_from_slice(b"synthetic-user");
            request.push(u8::try_from(pass.len()).unwrap());
            request.extend_from_slice(pass);
            client.write_all(&request).await.unwrap();
            let mut status = [0; 2];
            client.read_exact(&mut status).await.unwrap();
            status
        }
    };
    // The later account of the name replaces the earlier one.
    assert_eq!(login(b"synthetic-pass").await, [1, 0]);
    assert_eq!(login(b"old").await, [1, 0xff]);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn the_handshake_has_one_deadline() {
    let mut core = start("{}", r#", "policy": {"levels": {"0": {"handshake": 1}}}"#).await;
    // Each step comes within the deadline, but not the whole handshake.
    let mut client = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    sleep(Duration::from_millis(700)).await;
    client.write_all(&[5, 1, 0]).await.unwrap();
    sleep(Duration::from_millis(700)).await;
    let _ = client.write_all(&[1, 127, 0, 0, 1, 0, 80]).await;
    assert_eq!(rest(&mut client).await, b"");
    core.stop().await.unwrap();
}

#[tokio::test]
async fn udp_datagrams_without_a_payload_are_dropped() {
    let sink = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let sink_addr = sink.local_addr().unwrap();
    let mut core = start(r#"{"udp": true}"#, "").await;
    let mut control = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(sink_addr.ip()),
        sink_addr.port(),
        RoutingNetwork::Udp,
    );
    for payload in [b"".as_slice(), b"payload"] {
        let datagram = encode_socks5_udp_datagram(&target, payload).unwrap();
        client.send_to(&datagram, relay).await.unwrap();
    }
    let mut buffer = [0; 64];
    let (len, _) = timeout(Duration::from_secs(5), sink.recv_from(&mut buffer))
        .await
        .expect("the datagram with a payload arrives")
        .unwrap();
    assert_eq!(&buffer[..len], b"payload");
    drop(control);
    core.stop().await.unwrap();
}
