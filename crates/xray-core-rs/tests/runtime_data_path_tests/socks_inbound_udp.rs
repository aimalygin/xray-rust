//! SOCKS inbound `settings.udp`.
//!
//! With `"udp": false`, the pinned Xray-core v26.7.28 answers `UDP ASSOCIATE`
//! with `REP = 0x07` (command not supported) and a zero IPv4 bind, before it
//! creates a relay socket, and then closes the control connection; `CONNECT`
//! is unaffected. A counting socket protector observes every socket the
//! transport dialer creates, and a `CONNECT` or relayed datagram proves it counts.

use std::net::SocketAddrV4;

use super::blackhole::CountingSocketProtector;
use super::*;

/// Xray-core v26.7.28's reply to `UDP ASSOCIATE` with `"udp": false`, as
/// captured from the pinned reference binary for noauth and password inbounds.
const XRAY_UDP_DISABLED_REPLY: [u8; 10] = [5, 7, 0, 1, 0, 0, 0, 0, 0, 0];

const PASSWORD_SETTINGS: &str = r#"{"auth": "password", "udp": false,
    "accounts": [{"user": "synthetic-user", "pass": "synthetic-pass"}]}"#;

async fn start_socks_core(settings: &str) -> (Core, Arc<CountingSocketProtector>, SocketAddr) {
    let raw = format!(
        r#"{{
        "inbounds": [
            {{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
             "settings": {settings}}}
        ],
        "outbounds": [{{"tag": "direct", "protocol": "freedom"}}]
    }}"#
    );
    let config = parse_xray_json(&raw)
        .expect("synthetic SOCKS config parses")
        .config;
    let protector = Arc::new(CountingSocketProtector::default());
    let dialer = TransportDialer::system()
        .unwrap()
        .with_socket_protector(Arc::clone(&protector) as Arc<dyn xray_transport::SocketProtector>);
    let mut core = Core::with_transport_dialer_and_tun_options(
        config,
        Arc::new(dialer),
        TunRuntimeOptions::default(),
    )
    .unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
    (core, protector, socks_addr)
}

/// A declared client socket, which a password inbound would otherwise accept,
/// and the unspecified request most clients send.
fn declared_endpoints(client: &UdpSocket) -> [SocketAddrV4; 2] {
    let SocketAddr::V4(client) = client.local_addr().unwrap() else {
        panic!("the client UDP socket binds IPv4 loopback");
    };
    [client, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)]
}

async fn negotiate_no_auth(control: &mut TcpStream) {
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
}

async fn assert_udp_associate_refused(control: &mut TcpStream, declared: SocketAddrV4) {
    let mut request = vec![5, 3, 0, 1];
    request.extend_from_slice(&declared.ip().octets());
    request.extend_from_slice(&declared.port().to_be_bytes());
    control.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        reply, XRAY_UDP_DISABLED_REPLY,
        "UDP ASSOCIATE for {declared} must be refused without a relay"
    );
    let mut byte = [0; 1];
    assert_eq!(
        control.read(&mut byte).await.unwrap(),
        0,
        "the control connection must close after the refusal"
    );
}

async fn assert_connect_echoes(client: &mut TcpStream, echo_addr: SocketAddr, payload: &[u8]) {
    let SocketAddr::V4(echo) = echo_addr else {
        panic!("the echo server binds IPv4 loopback");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&echo.ip().octets());
    request.extend_from_slice(&echo.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..2], [5, 0]);

    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn socks_udp_false_refuses_udp_associate_without_relay_or_dial() {
    timeout(Duration::from_secs(5), async {
        let (mut core, protector, socks_addr) =
            start_socks_core(r#"{"auth": "noauth", "udp": false}"#).await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

        for declared in declared_endpoints(&client) {
            let mut control = TcpStream::connect(socks_addr).await.unwrap();
            negotiate_no_auth(&mut control).await;
            assert_udp_associate_refused(&mut control, declared).await;
        }
        assert_eq!(protector.calls(), 0, "a refused association dialed");
        assert!(core.connection_snapshot().connections.is_empty());

        let (echo_addr, echo_handle) = spawn_echo_server().await;
        let mut connect = TcpStream::connect(socks_addr).await.unwrap();
        negotiate_no_auth(&mut connect).await;
        assert_connect_echoes(&mut connect, echo_addr, b"connect with udp off").await;
        assert!(protector.calls() > 0, "control dial was not observed");
        drop(connect);

        core.stop().await.unwrap();
        echo_handle.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_password_udp_false_refuses_udp_associate_after_login() {
    timeout(Duration::from_secs(5), async {
        let (mut core, protector, socks_addr) = start_socks_core(PASSWORD_SETTINGS).await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

        for declared in declared_endpoints(&client) {
            let mut control = TcpStream::connect(socks_addr).await.unwrap();
            assert_eq!(
                socks5_password_login(&mut control, b"synthetic-user", b"synthetic-pass").await,
                0
            );
            assert_udp_associate_refused(&mut control, declared).await;
        }
        assert_eq!(protector.calls(), 0, "a refused association dialed");

        let (echo_addr, echo_handle) = spawn_echo_server().await;
        let mut connect = TcpStream::connect(socks_addr).await.unwrap();
        assert_eq!(
            socks5_password_login(&mut connect, b"synthetic-user", b"synthetic-pass").await,
            0
        );
        assert_connect_echoes(&mut connect, echo_addr, b"password connect").await;
        assert!(protector.calls() > 0, "control dial was not observed");
        drop(connect);

        core.stop().await.unwrap();
        echo_handle.await.unwrap();
    })
    .await
    .unwrap();
}

/// An absent `udp` keeps `UDP ASSOCIATE` enabled, as before; Xray-core would
/// treat it as `false`. The docs record this as an open compatibility question.
#[tokio::test]
async fn socks_udp_true_or_absent_keeps_relaying() {
    timeout(Duration::from_secs(5), async {
        for settings in [
            r#"{"auth": "noauth", "udp": true}"#,
            r#"{"auth": "noauth"}"#,
        ] {
            let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
            let (mut core, protector, socks_addr) = start_socks_core(settings).await;

            let mut control = TcpStream::connect(socks_addr).await.unwrap();
            let relay_addr = socks5_udp_associate(&mut control).await;
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let target = Target::new(
                RoutingTargetAddr::Ip(echo_addr.ip()),
                echo_addr.port(),
                RoutingNetwork::Udp,
            );
            let request = encode_socks5_udp_datagram(&target, b"udp on").unwrap();
            socket.send_to(&request, relay_addr).await.unwrap();
            let mut response = vec![0; 2048];
            let (len, _) = socket.recv_from(&mut response).await.unwrap();
            let response = parse_socks5_udp_datagram(&response[..len]).unwrap();
            assert_eq!(&response.payload[..], b"udp on", "{settings}");
            assert!(protector.calls() > 0, "relay dial was not observed");

            drop(socket);
            drop(control);
            core.stop().await.unwrap();
            echo_handle.await.unwrap();
        }
    })
    .await
    .unwrap();
}
