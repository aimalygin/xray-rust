//! `socks` outbound through xray-rust's own password-protected SOCKS inbound.
//!
//! One core runs both hops: `client-in` routes everything to the `socks`
//! outbound, which dials `upstream-in` on a fixed loopback port; `upstream-in`
//! authenticates with RFC 1929 and forwards to Freedom. UDP edge cases use a
//! scripted upstream instead of `upstream-in`, so the test controls the relay.

use super::*;
use xray_proxy::inbound::SocksUdpDatagram;

#[path = "../socks_runtime/support.rs"]
mod reference;

const UPSTREAM_INBOUND: &str = r#",
    {"tag": "upstream-in", "protocol": "socks", "listen": "127.0.0.1", "port": UPSTREAM_PORT,
     "settings": {"auth": "password", "udp": true,
        "accounts": [{"user": "synthetic-user", "pass": "synthetic-pass"}]}}"#;

/// `client-in` → `via-socks` → `127.0.0.1:upstream_port`, optionally served by
/// the core's own `upstream-in`.
fn chain_config(upstream_port: u16, pass: &str, upstream_inbound: bool) -> CoreConfig {
    let upstream = if upstream_inbound {
        UPSTREAM_INBOUND.replace("UPSTREAM_PORT", &upstream_port.to_string())
    } else {
        String::new()
    };
    let raw = format!(
        r#"{{
        "inbounds": [
            {{"tag": "client-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
             "settings": {{"auth": "noauth", "udp": true}}}}{upstream}
        ],
        "outbounds": [
            {{"tag": "direct", "protocol": "freedom"}},
            {{"tag": "via-socks", "protocol": "socks",
             "settings": {{"address": "127.0.0.1", "port": {upstream_port},
                "user": "synthetic-user", "pass": "{pass}"}}}}
        ],
        "routing": {{"rules": [
            {{"type": "field", "inboundTag": ["client-in"], "outboundTag": "via-socks"}}
        ]}}
    }}"#
    );
    parse_xray_json(&raw)
        .expect("synthetic SOCKS chain config parses")
        .config
}

fn socks_chain_config(upstream_port: u16, pass: &str) -> CoreConfig {
    chain_config(upstream_port, pass, true)
}

async fn start_socks_chain(pass: &str) -> (Core, SocketAddr) {
    let mut core = Core::new(socks_chain_config(allocate_unused_loopback_port(), pass)).unwrap();
    core.start().await.unwrap();
    let client_in = core.inbound_addr(Some("client-in")).unwrap();
    (core, client_in)
}

/// No-auth SOCKS5 CONNECT to an IPv4 target; returns the reply code.
async fn socks5_connect_ipv4(client: &mut TcpStream, target: SocketAddr) -> u8 {
    let SocketAddr::V4(target) = target else {
        panic!("echo servers bind IPv4 loopback");
    };
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    reply[1]
}

#[tokio::test]
async fn socks_outbound_tunnels_tcp_through_a_password_upstream() {
    timeout(Duration::from_secs(5), async {
        let (echo_addr, echo_handle) = spawn_echo_server().await;
        let (mut core, client_in) = start_socks_chain("synthetic-pass").await;

        let mut client = TcpStream::connect(client_in).await.unwrap();
        assert_eq!(socks5_connect_ipv4(&mut client, echo_addr).await, 0);
        client
            .write_all(b"through the socks outbound")
            .await
            .unwrap();
        let mut echoed = [0; 26];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"through the socks outbound");

        drop(client);
        core.stop().await.unwrap();
        timeout(Duration::from_secs(1), echo_handle)
            .await
            .unwrap()
            .unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_outbound_fails_the_flow_when_the_upstream_rejects_its_password() {
    timeout(Duration::from_secs(5), async {
        let (echo_addr, echo_handle) = spawn_echo_server().await;
        let (mut core, client_in) = start_socks_chain("wrong-pass").await;

        let mut client = TcpStream::connect(client_in).await.unwrap();
        assert_ne!(
            socks5_connect_ipv4(&mut client, echo_addr).await,
            0,
            "a rejected upstream login must not open the tunnel"
        );

        drop(client);
        core.stop().await.unwrap();
        echo_handle.abort();
    })
    .await
    .unwrap();
}

/// A client of `client-in`'s own UDP association.
struct UdpClient {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

impl UdpClient {
    async fn associate(client_in: SocketAddr) -> Self {
        let mut control = TcpStream::connect(client_in).await.unwrap();
        let relay = socks5_udp_associate(&mut control).await;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        Self {
            _control: control,
            socket,
            relay,
        }
    }

    async fn send(&self, target: SocketAddr, payload: &[u8]) {
        let target = Target::new(
            RoutingTargetAddr::Ip(target.ip()),
            target.port(),
            RoutingNetwork::Udp,
        );
        let request = encode_socks5_udp_datagram(&target, payload).unwrap();
        self.socket.send_to(&request, self.relay).await.unwrap();
    }

    async fn recv(&self) -> Bytes {
        let mut response = [0; 2048];
        let (len, _) = timeout(Duration::from_secs(2), self.socket.recv_from(&mut response))
            .await
            .expect("a datagram comes back through the chain")
            .unwrap();
        parse_socks5_udp_datagram(&response[..len]).unwrap().payload
    }
}

/// One association accepted by [`scripted_upstream_association`].
struct ScriptedAssociation {
    control: TcpStream,
    /// The client endpoint declared in the UDP ASSOCIATE request.
    declared: SocketAddr,
    relay: UdpSocket,
}

/// Plays a password SOCKS5 server for one UDP ASSOCIATE on `listener`. It
/// replies with an unspecified bound address, so the client must substitute
/// the server address.
async fn scripted_upstream_association(listener: &TcpListener) -> ScriptedAssociation {
    let (mut control, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("the outbound opens a control connection")
        .unwrap();
    let mut greeting = [0; 3];
    control.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 2]);
    control.write_all(&[5, 2]).await.unwrap();
    let mut auth = [0; 2 + 14 + 1 + 14];
    control.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, *b"\x01\x0esynthetic-user\x0esynthetic-pass");
    control.write_all(&[1, 0]).await.unwrap();

    let mut head = [0; 4];
    control.read_exact(&mut head).await.unwrap();
    assert_eq!(&head[..3], &[5, 3, 0]);
    let declared = match head[3] {
        1 => {
            let mut raw = [0; 6];
            control.read_exact(&mut raw).await.unwrap();
            SocketAddr::from((
                Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]),
                u16::from_be_bytes([raw[4], raw[5]]),
            ))
        }
        other => panic!("unexpected declared address type {other}"),
    };

    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0];
    reply.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
    control.write_all(&reply).await.unwrap();
    ScriptedAssociation {
        control,
        declared,
        relay,
    }
}

impl ScriptedAssociation {
    /// Receives one request datagram and checks that it comes from the
    /// declared endpoint.
    async fn recv(&self) -> (SocketAddr, SocksUdpDatagram) {
        let mut buffer = [0; 2048];
        let (len, source) = timeout(Duration::from_secs(2), self.relay.recv_from(&mut buffer))
            .await
            .expect("the outbound relays the datagram")
            .unwrap();
        assert_ne!(self.declared.port(), 0, "Xray's 0.0.0.0:0 is not declared");
        assert_eq!(source.port(), self.declared.port());
        assert!(self.declared.ip().is_unspecified() || self.declared.ip() == source.ip());
        (source, parse_socks5_udp_datagram(&buffer[..len]).unwrap())
    }
}

const SYNTHETIC_UDP_TARGET: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53);

async fn start_scripted_chain() -> (Core, SocketAddr, TcpListener) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut core = Core::new(chain_config(port, "synthetic-pass", false)).unwrap();
    core.start().await.unwrap();
    let client_in = core.inbound_addr(Some("client-in")).unwrap();
    (core, client_in, listener)
}

#[tokio::test]
async fn socks_outbound_relays_udp_through_a_password_upstream() {
    timeout(Duration::from_secs(5), async {
        let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
        let (mut core, client_in) = start_socks_chain("synthetic-pass").await;

        // `upstream-in` refuses an association whose declared port is unset
        // and admits datagrams only from the declared endpoint, so the echo
        // proves the outbound declared its real relay socket.
        let client = UdpClient::associate(client_in).await;
        client.send(echo_addr, b"udp via socks").await;
        assert_eq!(client.recv().await.as_ref(), b"udp via socks");

        drop(client);
        core.stop().await.unwrap();
        timeout(Duration::from_secs(1), echo_handle)
            .await
            .unwrap()
            .unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_outbound_drops_bad_relay_datagrams_without_ending_the_session() {
    timeout(Duration::from_secs(10), async {
        let (mut core, client_in, listener) = start_scripted_chain().await;
        let client = UdpClient::associate(client_in).await;

        client.send(SYNTHETIC_UDP_TARGET, b"ping").await;
        let upstream = scripted_upstream_association(&listener).await;
        let (source, request) = upstream.recv().await;
        assert_eq!(request.payload.as_ref(), b"ping");
        assert_eq!(
            request.target,
            Target::new(
                RoutingTargetAddr::Ip(SYNTHETIC_UDP_TARGET.ip()),
                SYNTHETIC_UDP_TARGET.port(),
                RoutingNetwork::Udp,
            )
        );

        let fragmented = [&[0, 0, 1, 1, 192, 0, 2, 10, 0, 53][..], b"fragment"].concat();
        for bad in [
            &[0, 0][..],
            &[0, 0, 0, 9, 1, 2, 3],
            &[0, 0, 0, 3, 0, 0, 53],
            &fragmented,
        ] {
            upstream.relay.send_to(bad, source).await.unwrap();
        }
        let reply = [&[0, 0, 0, 1, 192, 0, 2, 10, 0, 53][..], b"pong"].concat();
        upstream.relay.send_to(&reply, source).await.unwrap();
        assert_eq!(client.recv().await.as_ref(), b"pong");

        // The same association still carries traffic both ways.
        client.send(SYNTHETIC_UDP_TARGET, b"again").await;
        let (_, request) = upstream.recv().await;
        assert_eq!(request.payload.as_ref(), b"again");
        upstream.relay.send_to(&reply, source).await.unwrap();
        assert_eq!(client.recv().await.as_ref(), b"pong");
        assert!(
            timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "dropped datagrams must not end the association"
        );

        drop(client);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_outbound_ends_the_udp_session_when_the_upstream_closes_control() {
    timeout(Duration::from_secs(10), async {
        let (mut core, client_in, listener) = start_scripted_chain().await;
        let client = UdpClient::associate(client_in).await;

        client.send(SYNTHETIC_UDP_TARGET, b"first").await;
        let upstream = scripted_upstream_association(&listener).await;
        let (source, _) = upstream.recv().await;
        let reply = [&[0, 0, 0, 1, 192, 0, 2, 10, 0, 53][..], b"reply"].concat();
        upstream.relay.send_to(&reply, source).await.unwrap();
        assert_eq!(client.recv().await.as_ref(), b"reply");

        // Close only the control connection; the relay socket stays open, so
        // a session that ignored the control connection would keep using it.
        let ScriptedAssociation { control, relay, .. } = upstream;
        drop(control);
        let reopened = async {
            loop {
                client.send(SYNTHETIC_UDP_TARGET, b"next").await;
                if let Ok(accepted) = timeout(Duration::from_millis(50), listener.accept()).await {
                    return accepted.unwrap();
                }
            }
        };
        timeout(Duration::from_secs(3), reopened)
            .await
            .expect("the next datagram opens a new association");

        drop((client, relay));
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_outbound_udp_unspecified_relay_uses_the_connected_server_candidate() {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // The first same-family candidate refuses TCP. The second accepts and
        // returns 0.0.0.0, which must refer to that connected server, not the
        // first DNS result. This also covers mobile bootstrap IP arrays.
        let profile = serde_json::json!({
            "dns": {"hosts": {"fallback.socks.test": ["127.0.0.2", "127.0.0.1"]}},
            "inbounds": [{"tag": "client-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
                "settings": {"auth": "noauth", "udp": true}}],
            "outbounds": [{"protocol": "socks", "settings": {
                "address": "fallback.socks.test", "port": port,
                "user": "synthetic-user", "pass": "synthetic-pass"
            }, "streamSettings": {"sockopt": {"happyEyeballs": {"tryDelayMs": 10}}}}]
        });
        let mut core = Core::new(parse_xray_json(&profile.to_string()).unwrap().config).unwrap();
        core.start().await.unwrap();
        let client = UdpClient::associate(core.inbound_addr(Some("client-in")).unwrap()).await;
        client.send(SYNTHETIC_UDP_TARGET, b"fallback").await;
        let upstream = scripted_upstream_association(&listener).await;
        let (source, request) = upstream.recv().await;
        assert_eq!(request.payload.as_ref(), b"fallback");
        let reply = encode_socks5_udp_datagram(&request.target, b"connected candidate").unwrap();
        upstream.relay.send_to(&reply, source).await.unwrap();
        assert_eq!(client.recv().await.as_ref(), b"connected candidate");
        drop(client);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-socks-interop.sh"]
async fn socks_runtime_tun_udp_and_dns_against_pinned_xray() {
    timeout(reference::DEADLINE * 2, async {
        let server = reference::XrayServer::start().await;
        let upstream = spawn_observed_udp_dns_a_server(Ipv4Addr::LOCALHOST).await;
        let probe = upstream.probe();
        let (echo, _echo) = crate::hysteria_support::udp_echo().await;
        let settings = reference::outbound_settings(
            reference::Form::Flat,
            server.password,
            Some((reference::USER, reference::PASS)),
        );
        let mut profile = reference::profile(settings, false);
        profile["dns"] = serde_json::json!({
            "queryStrategy":"UseIPv4", "hosts":{"bootstrap.example":"127.0.0.1"},
            "servers":[{"address":"127.0.0.1", "port":upstream.addr().port()}]
        });
        let protector = Arc::new(crate::hysteria_support::Protector::default());
        let dialer = Arc::new(
            TransportDialer::system()
                .unwrap()
                .with_socket_protector(protector.clone()),
        );
        let mut core = Core::with_transport_dialer_and_tun_options(
            parse_xray_json(&profile.to_string()).unwrap().config,
            dialer,
            TunRuntimeOptions {
                dns_bootstrap: DnsBootstrapMode::StaticOnly,
                ..Default::default()
            },
        )
        .unwrap();
        core.start().await.unwrap();
        let client = Ipv4Addr::new(10, 10, 0, 2);
        let payload = b"tun UDP via pinned SOCKS";
        core.tun()
            .push_inbound(Bytes::from(ipv4_udp_packet(
                client,
                49154,
                Ipv4Addr::LOCALHOST,
                echo.port(),
                payload,
            )))
            .await
            .unwrap();
        let reply =
            poll_tun_outbound_until_with_timeout(core.tun(), reference::DEADLINE, |packet| {
                ipv4_udp_payload(packet).is_some_and(|p| p == payload)
            })
            .await;
        assert_ipv4_udp_packet(
            &reply,
            Ipv4Addr::LOCALHOST,
            echo.port(),
            client,
            49154,
            payload,
        );

        let query = build_dns_a_query(0x7287, "wire-socks.example");
        let anchor = Ipv4Addr::new(198, 18, 0, 1);
        core.tun()
            .push_inbound(Bytes::from(ipv4_udp_packet(
                client, 53044, anchor, 53, &query,
            )))
            .await
            .unwrap();
        let reply =
            poll_tun_outbound_until_with_timeout(core.tun(), reference::DEADLINE, |packet| {
                ipv4_udp_payload(packet)
                    .is_some_and(|p| p.get(..2) == Some(&0x7287_u16.to_be_bytes()))
            })
            .await;
        let response = ipv4_udp_payload(&reply).unwrap();
        assert_eq!(
            dns_response_answer_ipv4(response),
            Some(Ipv4Addr::LOCALHOST)
        );
        assert_ipv4_udp_packet(&reply, anchor, 53, client, 53044, response);
        assert_eq!(probe.snapshot().len(), 1);
        assert_eq!(
            protector.0.load(Ordering::SeqCst),
            4,
            "each flow protects its TCP control and UDP socket"
        );
        core.stop().await.unwrap();
        upstream.stop().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_outbound_udp_uses_ipv4_socket_for_mapped_proxy_address() {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut config = chain_config(
            listener.local_addr().unwrap().port(),
            "synthetic-pass",
            false,
        );
        let OutboundSettings::Socks(settings) = &mut config.outbounds[1].settings else {
            unreachable!()
        };
        settings.server = TargetAddr::Ip(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()));
        let mut core = Core::new(config).unwrap();
        core.start().await.unwrap();
        let client = UdpClient::associate(core.inbound_addr(Some("client-in")).unwrap()).await;
        client.send(SYNTHETIC_UDP_TARGET, b"mapped").await;
        let upstream = scripted_upstream_association(&listener).await;
        let (source, request) = upstream.recv().await;
        let reply = encode_socks5_udp_datagram(&request.target, &request.payload).unwrap();
        upstream.relay.send_to(&reply, source).await.unwrap();
        assert_eq!(client.recv().await.as_ref(), b"mapped");
        drop(client);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}
