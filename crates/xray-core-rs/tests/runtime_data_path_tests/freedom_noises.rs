//! Freedom's legacy UDP `noises`, from the parsed profile to the socket.

use super::*;

async fn start(inbound: &str, freedom_settings: &str) -> Core {
    let raw = format!(
        r#"{{
        "inbounds": [{inbound}],
        "outbounds": [{{"tag": "direct", "protocol": "freedom", "settings": {freedom_settings}}}]
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

/// Noises after a PROXY protocol header, one of them only for IPv6.
const NOISES: &str = r#"{"proxyProtocol": 1, "noises": [
    {"type": "str", "packet": " first "},
    {"type": "hex", "packet": "0001ff"},
    {"type": "str", "packet": "never", "applyTo": "ipv6"},
    {"type": "rand", "packet": "5-5", "applyTo": "IPv4"},
    {"type": "base64", "packet": "bGFzdA"}
]}"#;

async fn receive(server: &UdpSocket) -> Vec<u8> {
    let mut buffer = [0; 2048];
    let (len, _) = timeout(Duration::from_secs(5), server.recv_from(&mut buffer))
        .await
        .expect("a datagram arrives")
        .unwrap();
    buffer[..len].to_vec()
}

/// What an IPv4 destination receives from `NOISES` before `payload`.
async fn assert_noises_then(server: &UdpSocket, payload: &[u8]) {
    assert_eq!(receive(server).await, b"PROXY UNKNOWN\r\n");
    assert_eq!(receive(server).await, b"first");
    assert_eq!(receive(server).await, [0, 1, 0xff]);
    assert_eq!(receive(server).await.len(), 5);
    assert_eq!(receive(server).await, b"last");
    assert_eq!(receive(server).await, payload);
}

/// Opens a SOCKS UDP association and returns its client socket and relay.
async fn associate(socks: SocketAddr) -> (TcpStream, UdpSocket, SocketAddr) {
    let mut control = TcpStream::connect(socks).await.unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    (control, client, relay)
}

async fn socks_send(client: &UdpSocket, relay: SocketAddr, target: SocketAddr, payload: &[u8]) {
    let target = Target::new(
        RoutingTargetAddr::Ip(target.ip()),
        target.port(),
        RoutingNetwork::Udp,
    );
    let request = encode_socks5_udp_datagram(&target, payload).unwrap();
    client.send_to(&request, relay).await.unwrap();
}

#[tokio::test]
async fn socks_udp_sends_the_noises_before_its_first_datagram() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut core = start(SOCKS_IN, NOISES).await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let (control, client, relay) = associate(socks).await;

    socks_send(&client, relay, server_addr, b"one").await;
    assert_noises_then(&server, b"one").await;
    // Later datagrams of the flow go alone.
    socks_send(&client, relay, server_addr, b"two").await;
    assert_eq!(receive(&server).await, b"two");
    drop(control);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn tun_udp_sends_the_noises_before_its_first_datagram() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = server.local_addr().unwrap().port();
    let mut core = start(r#"{"tag": "tun-in", "protocol": "tun"}"#, NOISES).await;
    let app = Ipv4Addr::new(10, 10, 0, 2);
    let send = |payload: &[u8]| {
        Bytes::from(ipv4_udp_packet(
            app,
            49_190,
            Ipv4Addr::LOCALHOST,
            port,
            payload,
        ))
    };

    core.tun().push_inbound(send(b"one")).await.unwrap();
    assert_noises_then(&server, b"one").await;
    core.tun().push_inbound(send(b"two")).await.unwrap();
    assert_eq!(receive(&server).await, b"two");
    core.stop().await.unwrap();
}

#[tokio::test]
async fn noises_follow_the_family_of_the_address_dialed() {
    let settings = |redirect: &str| {
        format!(
            r#"{{{redirect}"noises": [
            {{"type": "str", "packet": "v4", "applyTo": "ipv4"}},
            {{"type": "str", "packet": "v6", "applyTo": "ipv6"}},
            {{"type": "str", "packet": "both", "applyTo": "ip"}}
        ]}}"#
        )
    };

    // An IPv6 destination gets the IPv6 noises.
    let server = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
    let mut core = start(SOCKS_IN, &settings("")).await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let (control, client, relay) = associate(socks).await;
    socks_send(&client, relay, server.local_addr().unwrap(), b"payload").await;
    for expected in [b"v6".as_slice(), b"both", b"payload"] {
        assert_eq!(receive(&server).await, expected);
    }
    drop(control);
    core.stop().await.unwrap();

    // A redirect decides the family, and receives the noises.
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let redirect = format!(r#""redirect": "{}", "#, server.local_addr().unwrap());
    let mut core = start(SOCKS_IN, &settings(&redirect)).await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let (control, client, relay) = associate(socks).await;
    let nowhere = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9));
    socks_send(&client, relay, nowhere, b"payload").await;
    for expected in [b"v4".as_slice(), b"both", b"payload"] {
        assert_eq!(receive(&server).await, expected);
    }
    drop(control);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn the_first_datagram_waits_out_the_noise_delays() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut core = start(
        SOCKS_IN,
        r#"{"noises": [
            {"type": "str", "packet": "wait", "delay": "150-150"},
            {"type": "str", "packet": "then", "delay": 100}
        ]}"#,
    )
    .await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let (control, client, relay) = associate(socks).await;

    let sent = TokioInstant::now();
    socks_send(&client, relay, server.local_addr().unwrap(), b"payload").await;
    for expected in [b"wait".as_slice(), b"then", b"payload"] {
        assert_eq!(receive(&server).await, expected);
    }
    assert!(
        sent.elapsed() >= Duration::from_millis(250),
        "{:?}",
        sent.elapsed()
    );
    drop(control);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn noise_bytes_count_toward_the_outbound_uplink() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut core = start(
        SOCKS_IN,
        r#"{"noises": [{"type": "str", "packet": "noise"}]}"#,
    )
    .await;
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let (control, client, relay) = associate(socks).await;
    socks_send(&client, relay, server.local_addr().unwrap(), b"payload").await;
    for expected in [b"noise".as_slice(), b"payload"] {
        assert_eq!(receive(&server).await, expected);
    }

    // Xray-core counts what freedom writes on its socket.
    let snapshot = core.connection_snapshot();
    core.close_connection(snapshot.connections[0].id).unwrap();
    wait_for_empty_connection_snapshot(&core).await;
    let accounting = core.outbound_accounting_snapshot();
    let direct = accounting
        .outbounds
        .iter()
        .find(|outbound| outbound.outbound_tag.as_deref() == Some("direct"))
        .unwrap();
    assert_eq!(
        direct.uplink_bytes,
        (b"noise".len() + b"payload".len()) as u64
    );
    drop(control);
    core.stop().await.unwrap();
}
