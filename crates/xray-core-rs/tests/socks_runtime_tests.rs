//! `socks` outbound against the pinned Go Xray-core SOCKS5 server.
//!
//! One Xray process runs a password inbound with a synthetic account and a
//! no-auth inbound, both forwarding to Freedom. Freedom resolves through
//! Xray's DNS, whose `hosts` maps a test-only domain to the loopback echo
//! server, so a domain target is resolved on the Xray side only; the local
//! resolver accepts nothing but the SOCKS server name.
#[path = "hysteria_runtime/support.rs"]
mod hysteria_support;
use hysteria_support::{tcp_echo, udp_echo, Bootstrap, Protector, Task};
use serde_json::{json, Value};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use xray_core_rs::Core;
use xray_proxy::inbound::{encode_socks5_udp_datagram, parse_socks5_udp_datagram};
use xray_proxy::outbound::socks5_udp_associate;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{TlsConnector, TransportDialer};

#[path = "socks_runtime/support.rs"]
mod support;
use support::*;
const PAYLOAD_LEN: usize = 64 * 1024;

fn core(settings: Value) -> (Core, Arc<Protector>, Arc<Bootstrap>) {
    core_with_tls(settings, None)
}

fn core_with_tls(
    settings: Value,
    tls: Option<TlsConnector>,
) -> (Core, Arc<Protector>, Arc<Bootstrap>) {
    let protector = Arc::new(Protector::default());
    let bootstrap = Arc::new(Bootstrap::default());
    let profile = profile(settings, tls.is_some());
    let dialer = Arc::new(
        tls.map_or_else(
            || TransportDialer::system().unwrap(),
            TransportDialer::with_tls_connector,
        )
        .with_socket_protector(protector.clone()),
    );
    let config = xray_config::parse_xray_json(&profile.to_string())
        .unwrap()
        .config;
    (
        Core::with_runtime_dependencies(config, bootstrap.clone(), dialer).unwrap(),
        protector,
        bootstrap,
    )
}

enum Destination<'a> {
    Ipv4(SocketAddr),
    Domain(&'a str, u16),
}

/// No-auth CONNECT to the core's inbound; returns the stream and reply code.
async fn connect(proxy: SocketAddr, destination: Destination<'_>) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0];
    match destination {
        Destination::Ipv4(SocketAddr::V4(target)) => {
            request.push(1);
            request.extend_from_slice(&target.ip().octets());
            request.extend_from_slice(&target.port().to_be_bytes());
        }
        Destination::Ipv4(target) => panic!("not IPv4: {target}"),
        Destination::Domain(domain, port) => {
            request.extend_from_slice(&[3, domain.len() as u8]);
            request.extend_from_slice(domain.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    (stream, reply[1])
}

/// Writes and reads concurrently so a large payload cannot stall on buffers.
async fn echo_round_trip(stream: &mut TcpStream, len: usize) {
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = stream.split();
    let mut received = vec![0; len];
    let (written, echoed) = tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
    written.unwrap();
    echoed.unwrap();
    assert!(received == payload, "echoed bytes differ");
}

async fn assert_tunnels(settings: Value, echo: SocketAddr) {
    let (mut core, protector, bootstrap) = core(settings);
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let mut open = Vec::new();
    for destination in [
        Destination::Ipv4(echo),
        Destination::Domain(REMOTE_DOMAIN, echo.port()),
    ] {
        let (mut stream, reply) = connect(proxy, destination).await;
        assert_eq!(reply, 0, "the tunnel must open");
        echo_round_trip(&mut stream, PAYLOAD_LEN).await;
        open.push(stream);
    }
    assert!(protector.0.load(Ordering::SeqCst) > 0);
    assert!(bootstrap.0.load(Ordering::SeqCst) > 0);
    let snapshot = core.connection_snapshot();
    assert_eq!(snapshot.connections.len(), 2);
    assert!(snapshot
        .connections
        .iter()
        .all(|c| c.outbound_tag.as_deref() == Some("proxy")));
    drop(open);
    core.stop().await.unwrap();
}

/// The flow fails, and Xray logs `reason` for one more inbound connection.
async fn assert_refused(server: &XrayServer, settings: Value, echo: SocketAddr, reason: &str) {
    let before = server.log().matches(reason).count();
    let (mut core, _, _) = core(settings);
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let (_stream, reply) = connect(proxy, Destination::Ipv4(echo)).await;
    assert_ne!(reply, 0, "a rejected login must not open the tunnel");
    core.stop().await.unwrap();
    while server.log().matches(reason).count() == before {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-socks-interop.sh"]
async fn socks_runtime_password_and_noauth_against_pinned_xray() {
    let server = XrayServer::start().await;
    timeout(DEADLINE * 3, async {
        let (echo, _echo) = tcp_echo().await;
        assert_eq!(echo.ip(), Ipv4Addr::LOCALHOST);
        for form in [Form::Flat, Form::Servers] {
            eprintln!("SOCKS outbound form: {form:?}");
            let account = Some((USER, PASS));
            assert_tunnels(outbound_settings(form, server.password, account), echo).await;
            eprintln!("password passed");
            assert_tunnels(outbound_settings(form, server.noauth, None), echo).await;
            eprintln!("noauth passed");
            let wrong = Some((USER, "synthetic-wrong-pass"));
            let settings = outbound_settings(form, server.password, wrong);
            assert_refused(&server, settings, echo, "invalid username or password").await;
            eprintln!("wrong password refused");
            let settings = outbound_settings(form, server.password, None);
            assert_refused(&server, settings, echo, "no matching auth method").await;
            eprintln!("missing credentials refused");
        }
    })
    .await
    .unwrap();
}

async fn associate(proxy: SocketAddr) -> (TcpStream, UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut control = TcpStream::connect(proxy).await.unwrap();
    let relay = socks5_udp_associate(&mut control, None, socket.local_addr().unwrap(), proxy.ip())
        .await
        .unwrap();
    (control, socket, relay)
}

async fn assert_udp_refused(server: &XrayServer, settings: Value, echo: SocketAddr, reason: &str) {
    let before = server.log().matches(reason).count();
    let (mut core, _, _) = core_with_tls(settings, server.connector.clone());
    core.start().await.unwrap();
    let (_control, socket, relay) = associate(core.inbound_addr(Some("socks-in")).unwrap()).await;
    let target = Target::new(TargetAddr::Ip(echo.ip()), echo.port(), Network::Udp);
    socket
        .send_to(
            &encode_socks5_udp_datagram(&target, b"must be refused").unwrap(),
            relay,
        )
        .await
        .unwrap();
    while server.log().matches(reason).count() == before {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        timeout(Duration::from_millis(100), socket.recv(&mut [0; 256]))
            .await
            .is_err()
    );
    core.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-socks-interop.sh"]
async fn socks_runtime_udp_password_noauth_and_tls_against_pinned_xray() {
    timeout(DEADLINE * 4, async {
        let (echo, _echo) = udp_echo().await;
        let ipv6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let echo6 = ipv6.local_addr().unwrap();
        let _echo6 = Task(tokio::spawn(async move {
            let mut buffer = [0; 8192];
            loop {
                let (len, peer) = ipv6.recv_from(&mut buffer).await.unwrap();
                ipv6.send_to(&buffer[..len], peer).await.unwrap();
            }
        }));
        for tls in [false, true] {
            let server = if tls {
                XrayServer::start_tls().await
            } else {
                XrayServer::start().await
            };
            for form in [Form::Flat, Form::Servers] {
                for (port, account) in
                    [(server.password, Some((USER, PASS))), (server.noauth, None)]
                {
                    let (mut core, protector, bootstrap) = core_with_tls(
                        outbound_settings(form, port, account),
                        server.connector.clone(),
                    );
                    core.start().await.unwrap();
                    let (control, socket, relay) =
                        associate(core.inbound_addr(Some("socks-in")).unwrap()).await;
                    for (address, endpoint) in [
                        (TargetAddr::Ip(echo.ip()), echo),
                        (TargetAddr::Ip(echo6.ip()), echo6),
                        (TargetAddr::Domain(REMOTE_DOMAIN.into()), echo),
                    ] {
                        let target = Target::new(address, endpoint.port(), Network::Udp);
                        let header_len = encode_socks5_udp_datagram(&target, &[]).unwrap().len();
                        for size in [1, 1200, 8192 - header_len] {
                            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                            let datagram = encode_socks5_udp_datagram(&target, &payload).unwrap();
                            socket.send_to(&datagram, relay).await.unwrap();
                            let mut buffer = [0; 9000];
                            let (len, source) = timeout(DEADLINE, socket.recv_from(&mut buffer))
                                .await
                                .unwrap()
                                .unwrap();
                            assert_eq!(source, relay);
                            let reply = parse_socks5_udp_datagram(&buffer[..len]).unwrap();
                            assert_eq!(reply.payload.as_ref(), payload);
                            // Xray retains a domain target in the reply; the
                            // hostname must not be resolved by the Rust client.
                            assert_eq!(reply.target, target);
                        }
                    }
                    assert!(
                        protector.0.load(Ordering::SeqCst) >= 6,
                        "protect TCP and UDP for every flow"
                    );
                    assert!(bootstrap.0.load(Ordering::SeqCst) >= 3);
                    let snapshot = core.connection_snapshot();
                    assert_eq!(snapshot.connections.len(), 3);
                    assert!(snapshot
                        .connections
                        .iter()
                        .all(|c| c.network == Network::Udp
                            && c.outbound_tag.as_deref() == Some("proxy")));
                    for connection in snapshot.connections {
                        core.close_connection(connection.id).unwrap();
                    }
                    drop((control, socket));
                    core.stop().await.unwrap();
                    assert!(core.connection_snapshot().connections.is_empty());
                    eprintln!(
                        "SOCKS UDP {form:?}, TLS={tls}, password={}: IPv4/IPv6/domain passed",
                        account.is_some()
                    );
                }
                assert_udp_refused(
                    &server,
                    outbound_settings(form, server.password, Some((USER, "synthetic-wrong-pass"))),
                    echo,
                    "invalid username or password",
                )
                .await;
                assert_udp_refused(
                    &server,
                    outbound_settings(form, server.password, None),
                    echo,
                    "no matching auth method",
                )
                .await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-socks-interop.sh"]
async fn socks_runtime_pinned_xray_client_preserves_password_udp_restriction() {
    timeout(DEADLINE * 2, async {
        let profile = json!({
            "inbounds":[{"tag":"upstream", "protocol":"socks", "listen":"127.0.0.1", "port":0,
                "settings":{"auth":"password", "udp":true,"accounts":[{"user":USER,"pass":PASS}]}}],
            "outbounds":[{"protocol":"freedom"}]
        });
        let mut upstream = Core::new(
            xray_config::parse_xray_json(&profile.to_string())
                .unwrap()
                .config,
        )
        .unwrap();
        upstream.start().await.unwrap();
        let address = upstream.inbound_addr(Some("upstream")).unwrap();
        let server = XrayServer::forwarding(json!({"protocol":"socks", "settings": {
            "address":address.ip().to_string(), "port":address.port(), "user":USER, "pass":PASS
        }}))
        .await;
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, server.noauth));
        let (echo, _echo) = tcp_echo().await;
        let (mut stream, reply) = connect(proxy, Destination::Ipv4(echo)).await;
        assert_eq!(reply, 0, "the pinned Go client authenticates for TCP");
        echo_round_trip(&mut stream, 64).await;
        let (echo, _udp) = udp_echo().await;
        let (_control, socket, relay) = associate(proxy).await;
        let target = Target::new(TargetAddr::Ip(echo.ip()), echo.port(), Network::Udp);
        socket
            .send_to(
                &encode_socks5_udp_datagram(&target, b"must be refused").unwrap(),
                relay,
            )
            .await
            .unwrap();
        while !server.log().contains("server rejects request") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            timeout(Duration::from_millis(200), socket.recv(&mut [0; 256]))
                .await
                .is_err(),
            "the Go client's undeclared UDP port must not bypass password-inbound policy"
        );
        upstream.stop().await.unwrap();
    })
    .await
    .unwrap();
}
