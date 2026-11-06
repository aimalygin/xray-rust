//! Freedom's domain strategy, from the parsed profile to the socket.
//!
//! `dns.hosts` answers `dual.test` with an IPv6 and an IPv4 loopback address,
//! both serving the same port. Which listener a SOCKS client reaches shows
//! the families freedom asked for.

use super::*;

const NAME: &str = "dual.test";

/// The same port on 127.0.0.1 and ::1, or `None` without IPv6 loopback.
pub(super) async fn dual_stack_listeners() -> Option<(TcpListener, TcpListener, u16)> {
    for _ in 0..32 {
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = v4.local_addr().unwrap().port();
        match TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
            Ok(v6) => return Some((v4, v6, port)),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(_) => return None,
        }
    }
    None
}

async fn start(freedom: &str, hosts: &str) -> (Core, SocketAddr) {
    let raw = format!(
        r#"{{
        "inbounds": [{{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0}}],
        "outbounds": [{freedom}],
        "dns": {{"hosts": {{"{NAME}": {hosts}}}}}
    }}"#
    );
    let config = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    (core, socks)
}

/// SOCKS5 CONNECT to `dual.test`; returns the reply code.
async fn connect(socks: SocketAddr, port: u16) -> (TcpStream, u8) {
    let mut client = TcpStream::connect(socks).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, 3, NAME.len() as u8];
    request.extend_from_slice(NAME.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    (client, reply[1])
}

#[derive(Debug, PartialEq, Eq)]
enum Reached {
    Ipv4,
    Ipv6,
}

/// Connects through `freedom` and reports which loopback listener accepted.
async fn reached(freedom: &str) -> Option<Reached> {
    let (v4, v6, port) = dual_stack_listeners().await?;
    let (mut core, socks) = start(freedom, r#"["::1", "127.0.0.1"]"#).await;
    let (_client, reply) = connect(socks, port).await;
    assert_eq!(reply, 0, "{freedom}");
    let accepted = timeout(Duration::from_secs(5), async {
        tokio::select! {
            accepted = v4.accept() => accepted.map(|_| Reached::Ipv4),
            accepted = v6.accept() => accepted.map(|_| Reached::Ipv6),
        }
    })
    .await
    .expect("one listener accepts")
    .unwrap();
    core.stop().await.unwrap();
    Some(accepted)
}

#[tokio::test]
async fn the_domain_strategy_picks_the_family_freedom_dials() {
    // Without a strategy freedom dials the answers in order, as Go's dialer does.
    let Some(baseline) = reached(r#"{"protocol": "freedom"}"#).await else {
        eprintln!("skipping: this host has no IPv6 loopback");
        return;
    };
    assert_eq!(baseline, Reached::Ipv6);

    for (freedom, expected) in [
        (
            r#"{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}}"#,
            Reached::Ipv4,
        ),
        // The deprecated freedom setting migrates into sockopt.
        (
            r#"{"protocol": "freedom", "settings": {"domainStrategy": "ForceIPv4v6"}}"#,
            Reached::Ipv4,
        ),
        // An outbound targetStrategy wins over the freedom setting.
        (
            r#"{"protocol": "direct", "targetStrategy": "useipv4", "settings": {"domainStrategy": "UseIPv6"}}"#,
            Reached::Ipv4,
        ),
        (
            r#"{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "ForceIPv6"}}}"#,
            Reached::Ipv6,
        ),
    ] {
        assert_eq!(reached(freedom).await, Some(expected), "{freedom}");
    }
}

#[tokio::test]
async fn use_falls_back_to_the_other_family_and_force_does_not() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // UseIPv6 finds no IPv6 address and then dials as AsIs would.
    let (mut core, socks) = start(
        r#"{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv6"}}}"#,
        r#"["127.0.0.1"]"#,
    )
    .await;
    let (_client, reply) = connect(socks, port).await;
    assert_eq!(reply, 0);
    timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("UseIPv6 falls back to IPv4")
        .unwrap();
    core.stop().await.unwrap();

    // ForceIPv6 fails the dial instead.
    let (mut core, socks) = start(
        r#"{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "ForceIPv6"}}}"#,
        r#"["127.0.0.1"]"#,
    )
    .await;
    let (_client, reply) = connect(socks, port).await;
    assert_ne!(reply, 0);
    assert!(
        timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "ForceIPv6 must not dial IPv4"
    );
    core.stop().await.unwrap();
}

/// The same UDP port on 127.0.0.1 and ::1, or `None` without IPv6 loopback.
async fn dual_stack_udp() -> Option<(UdpSocket, UdpSocket, u16)> {
    for _ in 0..32 {
        let v4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = v4.local_addr().unwrap().port();
        match UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).await {
            Ok(v6) => return Some((v4, v6, port)),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(_) => return None,
        }
    }
    None
}

/// Sends one SOCKS UDP datagram addressed to `original` and reports which
/// loopback socket received it. A QUIC Initial naming `dual.test` lets
/// sniffing replace an IP destination with the name, as Xray's does.
async fn udp_reached(sockopt: &str, original: Option<IpAddr>) -> Option<Reached> {
    let (v4, v6, port) = dual_stack_udp().await?;
    let raw = format!(
        r#"{{
        "inbounds": [{{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
            "settings": {{"udp": true}},
            "sniffing": {{"enabled": true, "destOverride": ["quic"]}}}}],
        "outbounds": [{{"protocol": "freedom", "streamSettings": {{"sockopt": {sockopt}}}}}],
        "dns": {{"hosts": {{"{NAME}": ["::1", "127.0.0.1"]}}}}
    }}"#
    );
    let config = parse_xray_json(&raw).expect("UDP profile parses").config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let mut control = TcpStream::connect(socks).await.unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = match original {
        Some(ip) => RoutingTargetAddr::Ip(ip),
        None => RoutingTargetAddr::Domain(NAME.to_owned()),
    };
    let target = Target::new(address, port, RoutingNetwork::Udp);
    let payload = quic_initial_packet_with_sni(NAME);
    let request = encode_socks5_udp_datagram(&target, &payload).unwrap();
    client.send_to(&request, relay).await.unwrap();

    let (mut on_v4, mut on_v6) = ([0; 2048], [0; 2048]);
    let reached = timeout(Duration::from_secs(5), async {
        tokio::select! {
            received = v4.recv_from(&mut on_v4) => received.map(|_| Reached::Ipv4),
            received = v6.recv_from(&mut on_v6) => received.map(|_| Reached::Ipv6),
        }
    })
    .await
    .expect("one socket receives the datagram")
    .unwrap();
    drop(control);
    core.stop().await.unwrap();
    Some(reached)
}

#[tokio::test]
async fn udp_flows_follow_the_strategy_and_their_original_family() {
    let Some(baseline) = udp_reached("{}", None).await else {
        eprintln!("skipping: this host has no IPv6 loopback");
        return;
    };
    // UDP takes the first answer when no strategy is set.
    assert_eq!(baseline, Reached::Ipv6);
    let use_ipv4 = r#"{"domainStrategy": "UseIPv4"}"#;
    assert_eq!(udp_reached(use_ipv4, None).await, Some(Reached::Ipv4));

    // UseIP prefers the family of the address the client sent to before
    // sniffing named the flow; the documentation addresses route nowhere.
    let use_ip = r#"{"domainStrategy": "UseIP"}"#;
    let test_net = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let documentation = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert_eq!(
        udp_reached(use_ip, Some(test_net)).await,
        Some(Reached::Ipv4)
    );
    assert_eq!(
        udp_reached(use_ip, Some(documentation)).await,
        Some(Reached::Ipv6)
    );
    // Without a strategy the sniffed name still takes the first answer.
    assert_eq!(udp_reached("{}", Some(test_net)).await, Some(Reached::Ipv6));
}

/// The TUN flavour of [`udp_reached`]: an app sends a QUIC Initial naming
/// `dual.test` to an unroutable IPv4 address, and sniffing names the flow.
async fn tun_udp_reached(sockopt: &str) -> Option<Reached> {
    let (v4, v6, port) = dual_stack_udp().await?;
    let raw = format!(
        r#"{{
        "inbounds": [{{"tag": "tun-in", "protocol": "tun",
            "sniffing": {{"enabled": true, "destOverride": ["quic"]}}}}],
        "outbounds": [{{"protocol": "freedom", "streamSettings": {{"sockopt": {sockopt}}}}}],
        "dns": {{"hosts": {{"{NAME}": ["::1", "127.0.0.1"]}}}}
    }}"#
    );
    let config = parse_xray_json(&raw).expect("TUN profile parses").config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let packet = ipv4_udp_packet(
        Ipv4Addr::new(10, 10, 0, 2),
        49_170,
        Ipv4Addr::new(192, 0, 2, 1),
        port,
        &quic_initial_packet_with_sni(NAME),
    );
    core.tun().push_inbound(Bytes::from(packet)).await.unwrap();

    let (mut on_v4, mut on_v6) = ([0; 2048], [0; 2048]);
    let reached = timeout(Duration::from_secs(5), async {
        tokio::select! {
            received = v4.recv_from(&mut on_v4) => received.map(|_| Reached::Ipv4),
            received = v6.recv_from(&mut on_v6) => received.map(|_| Reached::Ipv6),
        }
    })
    .await
    .expect("one socket receives the datagram")
    .unwrap();
    core.stop().await.unwrap();
    Some(reached)
}

#[tokio::test]
async fn tun_udp_flows_prefer_their_original_family() {
    let Some(baseline) = tun_udp_reached("{}").await else {
        eprintln!("skipping: this host has no IPv6 loopback");
        return;
    };
    assert_eq!(baseline, Reached::Ipv6);
    assert_eq!(
        tun_udp_reached(r#"{"domainStrategy": "UseIP"}"#).await,
        Some(Reached::Ipv4)
    );
    assert_eq!(
        tun_udp_reached(r#"{"domainStrategy": "ForceIPv6"}"#).await,
        Some(Reached::Ipv6)
    );
}
