//! UDP flows whose outbound waits on a server that never answers.
//!
//! The upstream accepts TCP and stays silent, so no outbound handshake ends.
//! Like a TCP open, the UDP open must give up after the outbound level's
//! `handshake` policy and close the upstream connection. That ends the flow
//! (and, for SOCKS, frees its global pending-open permit), so the next
//! datagram for the same target opens a new upstream connection.

use super::*;
use serde_json::{json, Value};

const HANDSHAKE: Duration = Duration::from_secs(1);
const UDP_TARGET: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 5_000);

/// An outbound whose UDP open waits on the server: `socks` for the method
/// reply to its greeting, Trojan and VLESS for the TLS server hello.
#[derive(Debug, Clone, Copy)]
enum Waiting {
    Socks,
    Trojan,
    Vless,
}

impl Waiting {
    fn outbound(self, port: u16) -> Value {
        let tls = json!({"network": "raw", "security": "tls",
            "tlsSettings": {"serverName": "localhost"}});
        match self {
            Self::Socks => json!({"tag": "proxy", "protocol": "socks",
                "settings": {"address": "127.0.0.1", "port": port}}),
            Self::Trojan => json!({"tag": "proxy", "protocol": "trojan", "streamSettings": tls,
                "settings": {"address": "127.0.0.1", "port": port, "password": "synthetic-pass"}}),
            Self::Vless => json!({"tag": "proxy", "protocol": "vless", "streamSettings": tls,
                "settings": {"vnext": [{"address": "127.0.0.1", "port": port,
                    "users": [{"id": "00010203-0405-0607-0809-0a0b0c0d0e0f"}]}]}}),
        }
    }
}

async fn start_core(inbound: Value, waiting: Waiting) -> (Core, TcpListener) {
    start_core_with_handshake(inbound, waiting, HANDSHAKE.as_secs()).await
}

async fn start_core_with_handshake(
    inbound: Value,
    waiting: Waiting,
    handshake_secs: u64,
) -> (Core, TcpListener) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let profile = json!({
        "inbounds": [inbound],
        "outbounds": [waiting.outbound(listener.local_addr().unwrap().port())],
        "policy": {"levels": {"0": {"handshake": handshake_secs}}}
    });
    let config = parse_xray_json(&profile.to_string()).unwrap().config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    (core, listener)
}

/// Accepts the outbound's connection, answers nothing and waits until the
/// outbound closes it, which must not happen before its handshake policy.
async fn hold_until_abandoned(listener: &TcpListener, waiting: Waiting) {
    let (mut upstream, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap_or_else(|_| panic!("{waiting:?} outbound dials the upstream"))
        .unwrap();
    let accepted = TokioInstant::now();
    let mut sink = [0; 4_096];
    timeout(HANDSHAKE * 4, async {
        while upstream.read(&mut sink).await.is_ok_and(|read| read > 0) {}
    })
    .await
    .unwrap_or_else(|_| panic!("{waiting:?} outbound keeps an unanswered handshake open"));
    let held = accepted.elapsed();
    assert!(
        held >= HANDSHAKE - Duration::from_millis(250),
        "{waiting:?} outbound gave up after {held:?}, before its handshake policy"
    );
}

async fn wait_for_no_connections(core: &Core, waiting: Waiting) {
    timeout(Duration::from_secs(2), async {
        while !core.connection_snapshot().connections.is_empty() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{waiting:?} flow outlives its abandoned open"));
}

async fn socks_udp_open_gives_up_on_a_silent_upstream(waiting: Waiting) {
    let (mut core, listener) = start_core(
        json!({"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
            "settings": {"auth": "noauth", "udp": true}}),
        waiting,
    )
    .await;
    let mut control = TcpStream::connect(core.inbound_addr(Some("socks-in")).unwrap())
        .await
        .unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(UDP_TARGET.ip()),
        UDP_TARGET.port(),
        RoutingNetwork::Udp,
    );
    let datagram = encode_socks5_udp_datagram(&target, b"first").unwrap();

    client.send_to(&datagram, relay).await.unwrap();
    hold_until_abandoned(&listener, waiting).await;
    wait_for_no_connections(&core, waiting).await;

    // The association survives and the same target gets a fresh open.
    client.send_to(&datagram, relay).await.unwrap();
    hold_until_abandoned(&listener, waiting).await;

    drop((control, client));
    core.stop().await.unwrap();
}

async fn tun_udp_open_gives_up_on_a_silent_upstream(waiting: Waiting) {
    let (mut core, listener) =
        start_core(json!({"tag": "tun-in", "protocol": "tun"}), waiting).await;
    let IpAddr::V4(target_ip) = UDP_TARGET.ip() else {
        unreachable!("the target is IPv4");
    };
    let packet = Bytes::from(ipv4_udp_packet(
        Ipv4Addr::new(10, 10, 0, 2),
        49_300,
        target_ip,
        UDP_TARGET.port(),
        b"first",
    ));

    core.tun().push_inbound(packet.clone()).await.unwrap();
    hold_until_abandoned(&listener, waiting).await;
    wait_for_no_connections(&core, waiting).await;
    let stats = core.tun().stats().await;
    assert_eq!(stats.udp_open_errors, 1, "{waiting:?}: {stats:?}");
    // The stack task drops the flow from its table asynchronously.
    timeout(Duration::from_secs(2), async {
        while core.tun().stats().await.active_udp_flows != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{waiting:?} flow keeps its TUN flow slot"));

    core.tun().push_inbound(packet).await.unwrap();
    hold_until_abandoned(&listener, waiting).await;

    core.stop().await.unwrap();
}

#[tokio::test]
async fn socks_udp_via_socks_gives_up_on_a_silent_upstream() {
    socks_udp_open_gives_up_on_a_silent_upstream(Waiting::Socks).await;
}

#[tokio::test]
async fn socks_udp_via_trojan_tls_gives_up_on_a_silent_upstream() {
    socks_udp_open_gives_up_on_a_silent_upstream(Waiting::Trojan).await;
}

#[tokio::test]
async fn socks_udp_via_vless_tls_gives_up_on_a_silent_upstream() {
    socks_udp_open_gives_up_on_a_silent_upstream(Waiting::Vless).await;
}

#[tokio::test]
async fn tun_udp_via_socks_gives_up_on_a_silent_upstream() {
    tun_udp_open_gives_up_on_a_silent_upstream(Waiting::Socks).await;
}

#[tokio::test]
async fn tun_udp_via_trojan_tls_gives_up_on_a_silent_upstream() {
    tun_udp_open_gives_up_on_a_silent_upstream(Waiting::Trojan).await;
}

#[tokio::test]
async fn tun_udp_via_vless_tls_gives_up_on_a_silent_upstream() {
    tun_udp_open_gives_up_on_a_silent_upstream(Waiting::Vless).await;
}

/// `handshake: 0` means no bound, as for Xray-core's WireGuard client: a zero
/// deadline failed every open on its first poll, before dialing the upstream.
async fn tun_udp_open_without_handshake_bound_waits(waiting: Waiting) {
    let (mut core, listener) =
        start_core_with_handshake(json!({"tag": "tun-in", "protocol": "tun"}), waiting, 0).await;
    let IpAddr::V4(target_ip) = UDP_TARGET.ip() else {
        unreachable!("the target is IPv4");
    };
    let packet = Bytes::from(ipv4_udp_packet(
        Ipv4Addr::new(10, 10, 0, 2),
        49_301,
        target_ip,
        UDP_TARGET.port(),
        b"first",
    ));

    core.tun().push_inbound(packet).await.unwrap();
    let (mut upstream, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap_or_else(|_| panic!("{waiting:?} outbound dials the upstream"))
        .unwrap();
    let mut sink = [0; 4_096];
    let abandoned = timeout(HANDSHAKE * 2, async {
        while upstream.read(&mut sink).await.is_ok_and(|read| read > 0) {}
    })
    .await;
    assert!(
        abandoned.is_err(),
        "{waiting:?} outbound gave up an unbounded open"
    );
    assert_eq!(core.tun().stats().await.udp_open_errors, 0, "{waiting:?}");

    core.stop().await.unwrap();
}

#[tokio::test]
async fn tun_udp_via_socks_waits_without_a_handshake_bound() {
    tun_udp_open_without_handshake_bound_waits(Waiting::Socks).await;
}

#[tokio::test]
async fn tun_udp_via_trojan_tls_waits_without_a_handshake_bound() {
    tun_udp_open_without_handshake_bound_waits(Waiting::Trojan).await;
}

#[tokio::test]
async fn tun_udp_via_vless_tls_waits_without_a_handshake_bound() {
    tun_udp_open_without_handshake_bound_waits(Waiting::Vless).await;
}
