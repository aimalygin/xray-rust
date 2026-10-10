//! Xray-compatible `blackhole` outbound across SOCKS, HTTP and TUN.
//!
//! Every blackholed flow must be answered without allocating an outbound
//! socket; a counting socket protector observes each TCP/UDP socket the
//! transport dialer creates, and the direct control flows prove it counts.

use super::*;

/// Xray-core v26.7.28 `proxy/blackhole` HTTP response, as captured from the
/// pinned reference binary through a raw dokodemo-door inbound.
const XRAY_BLACKHOLE_HTTP_RESPONSE: &[u8] = b"HTTP/1.1 403 Forbidden\nConnection: close\nCache-Control: max-age=3600, public\nContent-Length: 0\n\n\n";

const BLACKHOLE_CONFIG: &str = r#"{
    "inbounds": [
        {"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
         "settings": {"auth": "noauth", "udp": true}},
        {"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 0},
        {"tag": "tun-in", "protocol": "tun",
         "sniffing": {"enabled": true, "destOverride": ["http"], "routeOnly": true}}
    ],
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
        {"tag": "drop", "protocol": "blackhole", "settings": {}}
    ],
    "routing": {"rules": [
        {"type": "field", "domain": ["domain:blocked.example"], "outboundTag": "block"},
        {"type": "field", "ip": ["192.0.2.0/24"], "outboundTag": "block"},
        {"type": "field", "ip": ["198.51.100.0/24"], "outboundTag": "drop"}
    ]}
}"#;

#[derive(Default)]
struct CountingSocketProtector(AtomicUsize);

impl CountingSocketProtector {
    fn calls(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl xray_transport::SocketProtector for CountingSocketProtector {
    fn protect(&self, _socket: xray_transport::SocketHandle) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// TUN TCP sniffing applies to unmapped fake-IP targets, so it is enabled
/// together with a fake-IP pool. This covers both the unopened and the
/// sniffed (already opened) TUN TCP flow shapes.
async fn start_blackhole_core(tun_sniffing: bool) -> (Core, Arc<CountingSocketProtector>) {
    let mut config = parse_xray_json(BLACKHOLE_CONFIG)
        .expect("synthetic blackhole config parses")
        .config;
    if tun_sniffing {
        config.dns.fake_ip = Some(DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15).unwrap(),
            pool_size: 32_768,
            ttl: 60,
        });
    } else {
        config.inbounds[2].sniffing = None;
    }
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
    (core, protector)
}

fn assert_blackhole_accounting(core: &Core, tag: &str, connections: u64) {
    let accounting = core.outbound_accounting_snapshot();
    let outbound = accounting
        .outbounds
        .iter()
        .find(|outbound| outbound.outbound_tag.as_deref() == Some(tag))
        .unwrap_or_else(|| panic!("no accounting for {tag}: {accounting:?}"));
    assert_eq!(outbound.opened_connections, connections, "{tag}");
    assert_eq!(outbound.completed_connections, connections, "{tag}");
    assert_eq!(outbound.uplink_bytes, 0, "{tag}");
    assert_eq!(outbound.downlink_bytes, 0, "{tag}");
}

fn tun_client_state(client: &TunTcpClient) -> smol_tcp::State {
    client.sockets.get::<smol_tcp::Socket>(client.tcp).state()
}

#[tokio::test]
async fn socks_tcp_blackhole_acknowledges_then_closes_without_dialing() {
    timeout(Duration::from_secs(5), async {
        let (mut core, protector) = start_blackhole_core(false).await;
        let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

        // Xray's SOCKS server replies success before dispatching, then the
        // blackhole closes the link.
        let mut client = TcpStream::connect(socks_addr).await.unwrap();
        socks5_connect(&mut client, "198.51.100.10:443".parse().unwrap()).await;
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty(), "{received:?}");

        let mut client = TcpStream::connect(socks_addr).await.unwrap();
        socks5_connect(&mut client, "192.0.2.10:80".parse().unwrap()).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, XRAY_BLACKHOLE_HTTP_RESPONSE);
        drop(client);

        wait_for_empty_connection_snapshot(&core).await;
        assert_eq!(protector.calls(), 0, "blackhole allocated a socket");
        assert_blackhole_accounting(&core, "drop", 1);
        assert_blackhole_accounting(&core, "block", 1);

        let (echo_addr, echo_handle) = spawn_echo_server().await;
        let mut client = TcpStream::connect(socks_addr).await.unwrap();
        socks5_connect(&mut client, echo_addr).await;
        client.write_all(b"direct").await.unwrap();
        let mut echoed = [0; 6];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"direct");
        assert!(protector.calls() > 0, "control dial was not observed");
        drop(client);

        core.stop().await.unwrap();
        echo_handle.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_connect_blackhole_answers_inside_the_tunnel_without_dialing() {
    timeout(Duration::from_secs(5), async {
        let (mut core, protector) = start_blackhole_core(false).await;
        let http_addr = core.inbound_addr(Some("http-in")).unwrap();

        let mut client = TcpStream::connect(http_addr).await.unwrap();
        http_connect(&mut client, "192.0.2.10:443".parse().unwrap()).await;
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, XRAY_BLACKHOLE_HTTP_RESPONSE);
        drop(client);

        let mut client = TcpStream::connect(http_addr).await.unwrap();
        http_connect(&mut client, "198.51.100.10:443".parse().unwrap()).await;
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty(), "{received:?}");

        wait_for_empty_connection_snapshot(&core).await;
        assert_eq!(protector.calls(), 0, "blackhole allocated a socket");
        assert_blackhole_accounting(&core, "block", 1);
        assert_blackhole_accounting(&core, "drop", 1);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

fn blocked_udp_target(octets: [u8; 4]) -> Target {
    Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets))),
        443,
        RoutingNetwork::Udp,
    )
}

/// Xray dispatches a blackholed UDP flow once and then discards its
/// datagrams until the flow is idle, so each flow is routed and recorded once
/// and an `http` response comes back once, from the address the client used.
#[tokio::test]
async fn socks_udp_blackhole_answers_once_and_absorbs_the_flow_without_a_socket() {
    timeout(Duration::from_secs(5), async {
        let (mut core, protector) = start_blackhole_core(false).await;
        let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        let relay_addr = socks5_udp_associate(&mut control).await;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

        // `block` answers with the 403, `drop` (type `none`) stays silent.
        let http_target = blocked_udp_target([192, 0, 2, 10]);
        let none_target = blocked_udp_target([198, 51, 100, 10]);
        for target in [&http_target, &none_target] {
            let request = encode_socks5_udp_datagram(target, b"blocked quic").unwrap();
            for _ in 0..3 {
                socket.send_to(&request, relay_addr).await.unwrap();
            }
        }
        let mut response = vec![0; 2048];
        let (len, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut response))
            .await
            .expect("the http blackhole did not answer")
            .unwrap();
        let reply = parse_socks5_udp_datagram(&response[..len]).unwrap();
        assert_eq!(reply.target, http_target);
        assert_eq!(&reply.payload[..], XRAY_BLACKHOLE_HTTP_RESPONSE);
        assert!(
            timeout(Duration::from_millis(300), socket.recv_from(&mut response))
                .await
                .is_err(),
            "a blackholed flow was answered more than once"
        );
        let mut byte = [0; 1];
        assert!(
            timeout(Duration::from_millis(50), control.read(&mut byte))
                .await
                .is_err(),
            "absorbing datagrams must not end the UDP association"
        );

        // Both flows stay registered while they absorb later datagrams.
        let snapshot = core.connection_snapshot();
        let mut tags = snapshot
            .connections
            .iter()
            .map(|connection| {
                assert_eq!(connection.state, ConnectionState::Active, "{snapshot:?}");
                connection.outbound_tag.as_deref()
            })
            .collect::<Vec<_>>();
        tags.sort_unstable();
        assert_eq!(tags, [Some("block"), Some("drop")]);
        assert_eq!(protector.calls(), 0, "blackhole allocated a socket");

        let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
        let target = Target::new(
            RoutingTargetAddr::Ip(echo_addr.ip()),
            echo_addr.port(),
            RoutingNetwork::Udp,
        );
        let request = encode_socks5_udp_datagram(&target, b"direct").unwrap();
        socket.send_to(&request, relay_addr).await.unwrap();
        let (len, _) = socket.recv_from(&mut response).await.unwrap();
        let response = parse_socks5_udp_datagram(&response[..len]).unwrap();
        assert_eq!(&response.payload[..], b"direct");
        assert!(protector.calls() > 0, "control UDP socket was not observed");

        // Ending the association releases the absorbed flows.
        drop(socket);
        drop(control);
        wait_for_empty_connection_snapshot(&core).await;
        assert_blackhole_accounting(&core, "block", 1);
        assert_blackhole_accounting(&core, "drop", 1);
        core.stop().await.unwrap();
        echo_handle.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_tcp_blackhole_closes_with_fin_after_the_handshake() {
    timeout(Duration::from_secs(5), async {
        let (mut core, protector) = start_blackhole_core(false).await;

        let mut client = TunTcpClient::new();
        client.connect("198.51.100.10:443".parse().unwrap());
        let mut received = Vec::new();
        // The client stays idle: the FIN must not wait for another segment.
        pump_tun_until(&mut client, core.tun(), |client| {
            received.extend_from_slice(&client.recv_available());
            tun_client_state(client) == smol_tcp::State::CloseWait
        })
        .await;
        assert!(received.is_empty(), "{received:?}");

        let mut client = TunTcpClient::new();
        client.connect("192.0.2.10:80".parse().unwrap());
        let mut received = Vec::new();
        pump_tun_until(&mut client, core.tun(), |client| {
            received.extend_from_slice(&client.recv_available());
            tun_client_state(client) == smol_tcp::State::CloseWait
        })
        .await;
        assert_eq!(received, XRAY_BLACKHOLE_HTTP_RESPONSE);

        let stats = core.tun().stats().await;
        assert_eq!(stats.tcp_open_errors, 0, "{stats:?}");
        assert_eq!(protector.calls(), 0, "blackhole allocated a socket");
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

/// A flow routed by IP is never opened for sniffing. Xray interrupts the
/// link, so a client that keeps uploading is reset; it must not stall at a
/// zero window on a flow that nothing reads.
#[tokio::test]
async fn tun_tcp_blackhole_resets_a_client_that_keeps_uploading() {
    timeout(Duration::from_secs(10), async {
        let (mut core, protector) = start_blackhole_core(false).await;

        for (target, expected) in [
            ("198.51.100.10:443", &b""[..]),
            ("192.0.2.10:80", XRAY_BLACKHOLE_HTTP_RESPONSE),
        ] {
            let mut client = TunTcpClient::new();
            client.connect(target.parse().unwrap());
            let mut received = Vec::new();
            pump_tun_until(&mut client, core.tun(), |client| {
                received.extend_from_slice(&client.recv_available());
                tun_client_state(client) == smol_tcp::State::CloseWait
            })
            .await;
            assert_eq!(received, expected, "{target}");

            // Upload past the 32 KiB TUN receive window, which an unread flow
            // would fill, until the flow is reset.
            let chunk = [0x5a; 1024];
            let mut uploaded = 0_usize;
            pump_tun_until_with_timeout(
                &mut client,
                core.tun(),
                Duration::from_secs(3),
                |client| {
                    let socket = client.sockets.get_mut::<smol_tcp::Socket>(client.tcp);
                    while socket.can_send() {
                        match socket.send_slice(&chunk) {
                            Ok(written) if written > 0 => uploaded += written,
                            _ => break,
                        }
                    }
                    !client.is_open()
                },
            )
            .await;
            assert!(uploaded > 0, "{target}");
        }

        wait_for_empty_connection_snapshot(&core).await;
        let stats = core.tun().stats().await;
        assert_eq!(stats.tcp_open_errors, 0, "{stats:?}");
        assert_eq!(protector.calls(), 0, "blackhole allocated a socket");
        assert_blackhole_accounting(&core, "drop", 1);
        assert_blackhole_accounting(&core, "block", 1);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tun_tcp_sniffed_domain_blackhole_replies_without_reset() {
    timeout(Duration::from_secs(5), async {
        let (mut core, protector) = start_blackhole_core(true).await;

        let mut client = TunTcpClient::new();
        // An unmapped fake IP: only the sniffed domain can route this flow.
        client.connect("198.18.20.20:80".parse().unwrap());
        pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;
        client.send_payload(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n");
        let mut received = Vec::new();
        pump_tun_until(&mut client, core.tun(), |client| {
            received.extend_from_slice(&client.recv_available());
            tun_client_state(client) == smol_tcp::State::CloseWait
        })
        .await;
        assert_eq!(received, XRAY_BLACKHOLE_HTTP_RESPONSE);

        // The client keeps uploading after the response; the opened flow is
        // drained instead of reset while it reads and closes.
        client.send_payload(b"late upload");
        pump_tun_until(&mut client, core.tun(), |client| {
            tun_client_state(client) == smol_tcp::State::CloseWait
                && client
                    .sockets
                    .get::<smol_tcp::Socket>(client.tcp)
                    .send_queue()
                    == 0
        })
        .await;
        client
            .sockets
            .get_mut::<smol_tcp::Socket>(client.tcp)
            .close();
        pump_tun_until(&mut client, core.tun(), |client| !client.is_open()).await;
        wait_for_empty_connection_snapshot(&core).await;
        assert_eq!(protector.calls(), 0, "blackhole allocated a socket");
        assert_blackhole_accounting(&core, "block", 1);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

/// As with SOCKS, each blackholed TUN UDP flow is routed once and then absorbs
/// its datagrams. Xray's TUN inbound returns an `http` response as one UDP
/// packet from the original destination; nothing answers with ICMP.
#[tokio::test]
async fn tun_udp_blackhole_answers_once_and_absorbs_the_flow_without_icmp_or_socket() {
    timeout(Duration::from_secs(5), async {
        let (mut core, protector) = start_blackhole_core(false).await;
        let client_addr = Ipv4Addr::new(10, 10, 0, 2);
        let http_destination = Ipv4Addr::new(192, 0, 2, 10);
        let none_destination = Ipv4Addr::new(198, 51, 100, 10);
        for destination in [http_destination, none_destination] {
            for _ in 0..3 {
                let request = ipv4_udp_packet(client_addr, 49_200, destination, 443, b"quic");
                core.tun().push_inbound(Bytes::from(request)).await.unwrap();
            }
        }

        let mut packets = Vec::new();
        let deadline = TokioInstant::now() + Duration::from_millis(300);
        while TokioInstant::now() < deadline {
            if let Some(packet) = core.tun().try_poll_outbound().await.unwrap() {
                packets.push(packet);
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(packets.len(), 1, "{packets:?}");
        assert_ipv4_udp_packet(
            &packets[0],
            http_destination,
            443,
            client_addr,
            49_200,
            XRAY_BLACKHOLE_HTTP_RESPONSE,
        );

        let stats = core.tun().stats().await;
        assert_eq!(stats.active_udp_flows, 2, "{stats:?}");
        assert_eq!(stats.udp_open_errors, 0, "{stats:?}");
        assert_eq!(stats.udp_channel_dropped_packets, 0, "{stats:?}");
        let snapshot = core.connection_snapshot();
        assert_eq!(snapshot.connections.len(), 2, "{snapshot:?}");

        // A host close releases an absorbed flow like any other UDP flow.
        for connection in &snapshot.connections {
            assert_eq!(connection.state, ConnectionState::Active, "{snapshot:?}");
            core.close_connection(connection.id).unwrap();
        }
        wait_for_empty_connection_snapshot(&core).await;
        let deadline = TokioInstant::now() + Duration::from_secs(1);
        loop {
            let stats = core.tun().stats().await;
            if stats.active_udp_flows == 0 {
                break;
            }
            assert!(
                TokioInstant::now() < deadline,
                "closed blackhole UDP flow stayed active: {stats:?}"
            );
            sleep(Duration::from_millis(10)).await;
        }
        assert_blackhole_accounting(&core, "block", 1);
        assert_blackhole_accounting(&core, "drop", 1);
        assert_eq!(protector.calls(), 0, "blackhole allocated a socket");
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}
