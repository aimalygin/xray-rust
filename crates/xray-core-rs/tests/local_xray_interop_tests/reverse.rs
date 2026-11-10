//! The bridge side of the VLESS reverse proxy against Xray-core v26.10.31's
//! portal: a VLESS inbound whose user may open a reverse proxy, and public
//! tunnel inbounds routed into it. TCP and UDP services behind the bridge
//! answer clients of the portal over raw, TLS with Vision, WebSocket, gRPC
//! and XHTTP; freedom refuses what its final rules do not allow; a wrong UUID
//! opens nothing; the portal's DRAIN after more than 256 sessions brings a second
//! tunnel.
use super::proxy_carriers::certificate_pin;
use super::*;
use serde_json::{json, Value};
use tokio::net::UdpSocket;

const BRIDGE_TAG: &str = "r-in";
const WRONG_UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e10";

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The services behind the bridge: a TCP echo counting its connections,
/// and a UDP echo.
struct Services {
    tcp: SocketAddr,
    udp: SocketAddr,
    accepted: Arc<AtomicUsize>,
    _tasks: [Task; 2],
}

async fn start_services() -> Services {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let tcp = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    let tcp_task = Task(tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    }));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp = socket.local_addr().unwrap();
    let udp_task = Task(tokio::spawn(async move {
        let mut buffer = [0; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..n], from).await;
        }
    }));
    Services {
        tcp,
        udp,
        accepted,
        _tasks: [tcp_task, udp_task],
    }
}

/// The portal's public inbounds: one TCP, one UDP.
struct Public {
    tcp: SocketAddr,
    udp: SocketAddr,
}

/// Starts Xray as the portal for `services`, with the VLESS inbound on the
/// carrier `server` and its `decryption`, when not none.
async fn start_portal(
    checkout: &Path,
    server: XrayVlessServerConfig,
    services: &Services,
    decryption: Option<&str>,
) -> (XrayServer, Public) {
    start_portal_with(checkout, server, services, decryption, |_| {}).await
}

/// [`start_portal`], with `extra` changing the portal's configuration last.
async fn start_portal_with(
    checkout: &Path,
    server: XrayVlessServerConfig,
    services: &Services,
    decryption: Option<&str>,
    extra: impl FnOnce(&mut Value),
) -> (XrayServer, Public) {
    let public = Public {
        tcp: SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_loopback_port())),
        udp: SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_loopback_udp_port())),
    };
    let (tcp, udp) = (services.tcp, services.udp);
    let portal = start_xray_vless_server_customized(checkout, server, |config| {
        config["log"]["loglevel"] = "debug".into();
        config["inbounds"][0]["tag"] = "vless-in".into();
        config["inbounds"][0]["settings"]["clients"][0]["reverse"] = json!({"tag": "r-out"});
        if let Some(decryption) = decryption {
            config["inbounds"][0]["settings"]["decryption"] = decryption.into();
        }
        let inbounds = config["inbounds"].as_array_mut().unwrap();
        inbounds.push(
            json!({"tag": "public-tcp", "protocol": "tunnel", "listen": "127.0.0.1",
            "port": public.tcp.port(), "settings": {"address": tcp.ip().to_string(),
            "port": tcp.port(), "network": "tcp"}}),
        );
        inbounds.push(
            json!({"tag": "public-udp", "protocol": "tunnel", "listen": "127.0.0.1",
            "port": public.udp.port(), "settings": {"address": udp.ip().to_string(),
            "port": udp.port(), "network": "udp"}}),
        );
        config["routing"] = json!({"rules": [{"inboundTag": ["public-tcp", "public-udp"],
            "outboundTag": "r-out"}]});
        extra(config);
    })
    .await;
    (portal, public)
}

/// Our bridge for a portal at `portal`: `stream` and `flow` as the portal's
/// VLESS inbound wants them, `freedom` the settings of its direct outbound.
fn bridge_profile(
    portal: SocketAddr,
    uuid: &str,
    flow: Option<&str>,
    stream: Value,
    freedom: Value,
) -> Value {
    bridge_profile_encrypted(portal, uuid, flow, stream, freedom, "none")
}

fn bridge_profile_encrypted(
    portal: SocketAddr,
    uuid: &str,
    flow: Option<&str>,
    stream: Value,
    freedom: Value,
    encryption: &str,
) -> Value {
    let mut settings = json!({"address": "127.0.0.1", "port": portal.port(), "id": uuid,
        "encryption": encryption, "reverse": {"tag": BRIDGE_TAG}});
    if let Some(flow) = flow {
        settings["flow"] = flow.into();
    }
    json!({"outbounds": [
            {"tag": "portal", "protocol": "vless", "settings": settings, "streamSettings": stream},
            {"tag": "direct", "protocol": "freedom", "settings": freedom}],
        "routing": {"rules": [{"inboundTag": [BRIDGE_TAG], "outboundTag": "direct"}]}})
}

/// A fresh X25519 pair for VLESS encryption: the portal's `decryption` and
/// the bridge's `encryption`.
fn vless_encryption_pair() -> (String, String) {
    use base64::Engine as _;
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    (
        format!("mlkem768x25519plus.native.0s.{}", encode(secret.as_bytes())),
        format!(
            "mlkem768x25519plus.native.1rtt.{}",
            encode(public.as_bytes())
        ),
    )
}

fn allow(services: &Services) -> Value {
    json!({"finalRules": [{"action": "allow", "ip": ["127.0.0.1"],
        "port": format!("{},{}", services.tcp.port(), services.udp.port())}]})
}

async fn start_bridge(profile: Value) -> Core {
    let config = parse_xray_json(&profile.to_string())
        .unwrap_or_else(|error| panic!("{:?}", error.diagnostics))
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

/// One TCP echo through the portal's public inbound.
async fn tcp_round_trip(public: SocketAddr, payload: &[u8]) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(public).await?;
    stream.write_all(payload).await?;
    let mut echoed = vec![0; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .map_err(|_| std::io::Error::from(ErrorKind::TimedOut))??;
    if echoed != payload {
        return Err(std::io::Error::other("echo differs"));
    }
    Ok(())
}

/// One UDP echo through the portal's public inbound.
async fn udp_round_trip(public: SocketAddr, payload: &[u8]) -> std::io::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    socket.send_to(payload, public).await?;
    let mut echoed = [0; 65536];
    let (n, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut echoed))
        .await
        .map_err(|_| std::io::Error::from(ErrorKind::TimedOut))??;
    if &echoed[..n] != payload {
        return Err(std::io::Error::other("echo differs"));
    }
    Ok(())
}

/// Waits until the bridge's tunnel carries a TCP echo: the monitor's first
/// run and the portal adding its reverse outbound take a few seconds.
async fn wait_for_tunnel(public: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if tcp_round_trip(public, b"tunnel up?").await.is_ok() {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

fn tunnels_opened(portal: &XrayServer) -> usize {
    portal
        .logs()
        .matches("received request for tcp:v1.rvs.cool:0")
        .count()
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-reverse-interop.sh"]
async fn reverse_bridge_serves_tcp_and_udp_over_every_carrier() {
    let checkout = resolve_xray_checkout();
    let (decryption, encryption) = vless_encryption_pair();
    let cases = [
        (
            "raw",
            XrayVlessServerConfig {
                security: XrayInboundSecurity::None,
                transport: XrayInboundTransport::Raw,
                flow: None,
            },
            json!({"network": "raw"}),
        ),
        (
            "raw with VLESS encryption",
            XrayVlessServerConfig {
                security: XrayInboundSecurity::None,
                transport: XrayInboundTransport::Raw,
                flow: None,
            },
            json!({"network": "raw"}),
        ),
        (
            "TLS with Vision",
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Tls,
                transport: XrayInboundTransport::Raw,
                flow: Some("xtls-rprx-vision"),
            },
            json!({"network": "raw"}),
        ),
        (
            "WebSocket TLS",
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Tls,
                transport: XrayInboundTransport::WebSocket { path: "/rvs" },
                flow: None,
            },
            json!({"network": "ws", "wsSettings": {"path": "/rvs"}}),
        ),
        (
            "gRPC TLS",
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Tls,
                transport: XrayInboundTransport::Grpc {
                    service_name: "rvs",
                },
                flow: None,
            },
            json!({"network": "grpc", "grpcSettings": {"serviceName": "rvs"}}),
        ),
        (
            "XHTTP TLS",
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Tls,
                transport: XrayInboundTransport::Xhttp {
                    path: "/rvs",
                    mode: "stream-one",
                    tls_alpn: None,
                },
                flow: None,
            },
            // The padding the harness's XHTTP inbound wants.
            json!({"network": "xhttp", "xhttpSettings": {"path": "/rvs", "mode": "stream-one",
                "xPaddingBytes": 64, "scMaxEachPostBytes": 4096, "scMinPostsIntervalMs": 1}}),
        ),
    ];
    for (name, server, mut stream) in cases {
        eprintln!("reverse over {name}");
        let encrypted = name.contains("encryption");
        let services = start_services().await;
        let (portal, public) = start_portal(
            &checkout,
            server,
            &services,
            encrypted.then_some(decryption.as_str()),
        )
        .await;
        if matches!(server.security, XrayInboundSecurity::Tls) {
            stream["security"] = "tls".into();
            stream["tlsSettings"] = json!({"serverName": TLS_SERVER_NAME,
                "pinnedPeerCertSha256": certificate_pin(&portal)});
        }
        let mut core = start_bridge(bridge_profile_encrypted(
            portal.addr,
            TEST_UUID,
            server.flow,
            stream,
            allow(&services),
            if encrypted { &encryption } else { "none" },
        ))
        .await;
        assert!(
            wait_for_tunnel(public.tcp).await,
            "{name}: no tunnel; {}",
            portal.logs()
        );
        let payload: Vec<u8> = (0..65_537).map(|n| (n * 31 + 7) as u8).collect();
        tcp_round_trip(public.tcp, &payload)
            .await
            .unwrap_or_else(|error| panic!("{name}: TCP {error}; {}", portal.logs()));
        for size in [1, 1200, 8192] {
            let datagram = vec![0x5a; size];
            let mut answered = false;
            // UDP may lose a datagram; three tries are plenty on loopback.
            for _ in 0..3 {
                if udp_round_trip(public.udp, &datagram).await.is_ok() {
                    answered = true;
                    break;
                }
            }
            assert!(answered, "{name}: UDP {size}; {}", portal.logs());
        }
        let reverse_flows = core
            .connection_snapshot()
            .connections
            .iter()
            .filter(|connection| connection.inbound_tag.as_deref() == Some(BRIDGE_TAG))
            .count();
        assert!(reverse_flows >= 1, "{name}: no reverse flow registered");
        core.stop().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-reverse-interop.sh"]
async fn reverse_bridge_freedom_refuses_and_a_wrong_uuid_opens_nothing() {
    let checkout = resolve_xray_checkout();
    let server = XrayVlessServerConfig {
        security: XrayInboundSecurity::None,
        transport: XrayInboundTransport::Raw,
        flow: None,
    };
    // Freedom without final rules: the tunnel is up, as the portal logs, but
    // nothing behind the bridge is dialed.
    let services = start_services().await;
    let (portal, public) = start_portal(&checkout, server, &services, None).await;
    let mut core = start_bridge(bridge_profile(
        portal.addr,
        TEST_UUID,
        None,
        json!({"network": "raw"}),
        json!({}),
    ))
    .await;
    let deadline = Instant::now() + Duration::from_secs(20);
    while tunnels_opened(&portal) == 0 && Instant::now() < deadline {
        sleep(Duration::from_millis(250)).await;
    }
    assert!(tunnels_opened(&portal) >= 1, "{}", portal.logs());
    for _ in 0..3 {
        assert!(tcp_round_trip(public.tcp, b"refused").await.is_err());
        assert!(udp_round_trip(public.udp, b"refused").await.is_err());
    }
    assert_eq!(services.accepted.load(Ordering::SeqCst), 0);
    core.stop().await.unwrap();
    drop(portal);

    // A UUID the portal does not know: no tunnel, so no reverse outbound.
    let services = start_services().await;
    let (portal, public) = start_portal(&checkout, server, &services, None).await;
    let mut core = start_bridge(bridge_profile(
        portal.addr,
        WRONG_UUID,
        None,
        json!({"network": "raw"}),
        allow(&services),
    ))
    .await;
    sleep(Duration::from_secs(5)).await;
    assert!(tcp_round_trip(public.tcp, b"stranger").await.is_err());
    assert!(udp_round_trip(public.udp, b"stranger").await.is_err());
    assert_eq!(tunnels_opened(&portal), 0, "{}", portal.logs());
    assert_eq!(services.accepted.load(Ordering::SeqCst), 0);
    core.stop().await.unwrap();
}

/// The bridge's chains meet freedom's reverse rule where Xray-core's do, as
/// checked against an Xray-core bridge: the freedom a chain ends on refuses
/// the portal's sessions, and the tunnel, unless its final rules allow the
/// next hop, while a Mux.Cool or gRPC connection, which Xray-core opens
/// without the session's context, is not refused. The portal also runs plain
/// VLESS inbounds for the chains to reach.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-reverse-interop.sh"]
async fn reverse_bridge_chains_meet_freedoms_rule_where_xray_does() {
    let checkout = resolve_xray_checkout();
    let server = XrayVlessServerConfig {
        security: XrayInboundSecurity::None,
        transport: XrayInboundTransport::Raw,
        flow: None,
    };
    let services = start_services().await;
    let relay_raw = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_loopback_port()));
    let relay_grpc = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_loopback_port()));
    let portal_freedom = allow(&services);
    let (portal, public) = start_portal_with(&checkout, server, &services, None, |config| {
        let relay = |tag: &str, port: u16, stream: Value| {
            json!({"tag": tag, "protocol": "vless", "listen": "127.0.0.1", "port": port,
                "settings": {"clients": [{"id": WRONG_UUID}], "decryption": "none"},
                "streamSettings": stream})
        };
        let inbounds = config["inbounds"].as_array_mut().unwrap();
        inbounds.push(relay(
            "relay-raw",
            relay_raw.port(),
            json!({"network": "raw"}),
        ));
        inbounds.push(relay(
            "relay-grpc",
            relay_grpc.port(),
            json!({"network": "grpc", "grpcSettings": {"serviceName": "relay"}}),
        ));
        // Xray-core's freedom refuses private addresses to VLESS sessions.
        config["outbounds"] =
            json!([{"tag": "direct", "protocol": "freedom", "settings": portal_freedom}]);
        config["routing"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({"inboundTag": ["relay-raw", "relay-grpc"], "outboundTag": "direct"}));
    })
    .await;
    let via = |relay: SocketAddr, stream: Value, mux: bool| {
        let mut outbound = json!({"protocol": "vless", "settings": {"address": "127.0.0.1",
            "port": relay.port(), "id": WRONG_UUID, "encryption": "none"},
            "streamSettings": stream});
        if mux {
            outbound["mux"] = json!({"enabled": true, "concurrency": 8});
        }
        outbound
    };
    let through = |proxy: &str| json!({"network": "raw", "sockopt": {"dialerProxy": proxy}});
    let grpc = json!({"network": "grpc", "grpcSettings": {"serviceName": "relay"},
        "sockopt": {"dialerProxy": "link"}});
    let allow_relay = json!({"finalRules": [{"action": "allow", "ip": ["127.0.0.1"],
        "port": relay_raw.port().to_string()}]});
    let allow_portal = json!({"finalRules": [{"action": "allow", "ip": ["127.0.0.1"],
        "port": portal.addr.port().to_string()}]});
    // (case, the outbound sessions take or none for freedom, the link's
    // settings, whether the tunnel dials through the link, whether a
    // session reaches the service)
    let cases = [
        (
            "vless through a freedom",
            Some(via(relay_raw, through("link"), false)),
            json!({}),
            false,
            false,
        ),
        (
            "vless through a freedom allowing it",
            Some(via(relay_raw, through("link"), false)),
            allow_relay.clone(),
            false,
            true,
        ),
        (
            "vless through two freedoms",
            Some(via(relay_raw, through("hop"), false)),
            json!({}),
            false,
            false,
        ),
        (
            "vless through two freedoms, the last allowing it",
            Some(via(relay_raw, through("hop"), false)),
            allow_relay,
            false,
            true,
        ),
        (
            "vless with Mux through a freedom",
            Some(via(relay_raw, through("link"), true)),
            json!({}),
            false,
            true,
        ),
        (
            "vless over gRPC through a freedom",
            Some(via(relay_grpc, grpc, false)),
            json!({}),
            false,
            true,
        ),
        ("a tunnel through a freedom", None, json!({}), true, false),
        (
            "a tunnel through a freedom allowing the portal",
            None,
            allow_portal,
            true,
            true,
        ),
    ];
    for (name, via, link, tunnel_through_link, reaches) in cases {
        eprintln!("reverse chain: {name}");
        let mut portal_outbound = json!({"tag": "portal", "protocol": "vless", "settings": {
            "address": "127.0.0.1", "port": portal.addr.port(), "id": TEST_UUID,
            "encryption": "none", "reverse": {"tag": BRIDGE_TAG}}});
        if tunnel_through_link {
            portal_outbound["streamSettings"] = through("link");
        }
        let mut outbounds = vec![
            portal_outbound,
            json!({"tag": "hop", "protocol": "freedom",
                "streamSettings": {"sockopt": {"dialerProxy": "link"}}}),
            json!({"tag": "link", "protocol": "freedom", "settings": link}),
            json!({"tag": "direct", "protocol": "freedom", "settings": allow(&services)}),
        ];
        let route = match via {
            Some(mut via) => {
                via["tag"] = "via".into();
                outbounds.push(via);
                "via"
            }
            None => "direct",
        };
        let tunnels = tunnels_opened(&portal);
        let served = services.accepted.load(Ordering::SeqCst);
        let mut core = start_bridge(json!({"outbounds": outbounds,
            "routing": {"rules": [{"inboundTag": [BRIDGE_TAG], "outboundTag": route}]}}))
        .await;
        if reaches {
            assert!(
                wait_for_tunnel(public.tcp).await,
                "{name}: nothing reached the service; {}",
                portal.logs()
            );
        } else if tunnel_through_link {
            sleep(Duration::from_secs(5)).await;
            assert_eq!(
                tunnels_opened(&portal),
                tunnels,
                "{name}; {}",
                portal.logs()
            );
            assert!(
                tcp_round_trip(public.tcp, b"no tunnel").await.is_err(),
                "{name}"
            );
        } else {
            let deadline = Instant::now() + Duration::from_secs(20);
            while tunnels_opened(&portal) == tunnels && Instant::now() < deadline {
                sleep(Duration::from_millis(250)).await;
            }
            assert!(
                tunnels_opened(&portal) > tunnels,
                "{name}; {}",
                portal.logs()
            );
            for _ in 0..3 {
                assert!(
                    tcp_round_trip(public.tcp, b"refused").await.is_err(),
                    "{name}"
                );
            }
            assert_eq!(services.accepted.load(Ordering::SeqCst), served, "{name}");
        }
        core.stop().await.unwrap();
    }
}

/// Over XHTTP, whose connections are shared, the freedom a chain ends on
/// refuses the portal's sessions, and the tunnel, before anything is
/// dialed unless its final rules allow the next hop: always, by the owner's
/// choice, where Xray-core refuses only when the session itself dials.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-reverse-interop.sh"]
async fn reverse_bridge_refuses_xhttp_chains_until_their_freedom_allows() {
    let checkout = resolve_xray_checkout();
    let server = XrayVlessServerConfig {
        security: XrayInboundSecurity::Tls,
        transport: XrayInboundTransport::Xhttp {
            path: "/rvs",
            mode: "stream-one",
            tls_alpn: None,
        },
        flow: None,
    };
    let services = start_services().await;
    let relay = SocketAddr::from((Ipv4Addr::LOCALHOST, allocate_loopback_port()));
    let portal_freedom = allow(&services);
    let (portal, public) = start_portal_with(&checkout, server, &services, None, |config| {
        config["inbounds"].as_array_mut().unwrap().push(json!({
            "tag": "relay-xhttp", "protocol": "vless", "listen": "127.0.0.1",
            "port": relay.port(),
            "settings": {"clients": [{"id": WRONG_UUID}], "decryption": "none"},
            "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/relay"}}}));
        config["outbounds"] =
            json!([{"tag": "direct", "protocol": "freedom", "settings": portal_freedom}]);
        config["routing"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({"inboundTag": ["relay-xhttp"], "outboundTag": "direct"}));
    })
    .await;
    let allowing = |port: u16| {
        json!({"finalRules": [{"action": "allow", "ip": ["127.0.0.1"],
            "port": port.to_string()}]})
    };
    // (case, sessions through the XHTTP relay or freedom, the link's
    // settings, whether the tunnel dials through the link, whether a session
    // reaches the service)
    let cases = [
        ("XHTTP through a freedom", true, json!({}), false, false),
        (
            "XHTTP through a freedom allowing it",
            true,
            allowing(relay.port()),
            false,
            true,
        ),
        (
            "an XHTTP tunnel through a freedom",
            false,
            json!({}),
            true,
            false,
        ),
        (
            "an XHTTP tunnel through a freedom allowing the portal",
            false,
            allowing(portal.addr.port()),
            true,
            true,
        ),
    ];
    for (name, through_relay, link, tunnel_through_link, reaches) in cases {
        eprintln!("reverse XHTTP chain: {name}");
        let mut stream = json!({"network": "xhttp", "security": "tls",
            "tlsSettings": {"serverName": TLS_SERVER_NAME,
                "pinnedPeerCertSha256": certificate_pin(&portal)},
            "xhttpSettings": {"path": "/rvs", "mode": "stream-one", "xPaddingBytes": 64,
                "scMaxEachPostBytes": 4096, "scMinPostsIntervalMs": 1}});
        if tunnel_through_link {
            stream["sockopt"] = json!({"dialerProxy": "link"});
        }
        let mut outbounds = vec![
            json!({"tag": "portal", "protocol": "vless", "settings": {
                "address": "127.0.0.1", "port": portal.addr.port(), "id": TEST_UUID,
                "encryption": "none", "reverse": {"tag": BRIDGE_TAG}},
                "streamSettings": stream}),
            json!({"tag": "link", "protocol": "freedom", "settings": link}),
            json!({"tag": "direct", "protocol": "freedom", "settings": allow(&services)}),
        ];
        let route = if through_relay {
            outbounds.push(json!({"tag": "via", "protocol": "vless", "settings": {
                "address": "127.0.0.1", "port": relay.port(), "id": WRONG_UUID,
                "encryption": "none"},
                "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/relay"},
                    "sockopt": {"dialerProxy": "link"}}}));
            "via"
        } else {
            "direct"
        };
        let tunnels = tunnels_opened(&portal);
        let served = services.accepted.load(Ordering::SeqCst);
        let mut core = start_bridge(json!({"outbounds": outbounds,
            "routing": {"rules": [{"inboundTag": [BRIDGE_TAG], "outboundTag": route}]}}))
        .await;
        if reaches {
            assert!(
                wait_for_tunnel(public.tcp).await,
                "{name}: nothing reached the service; {}",
                portal.logs()
            );
        } else if tunnel_through_link {
            sleep(Duration::from_secs(5)).await;
            assert_eq!(
                tunnels_opened(&portal),
                tunnels,
                "{name}; {}",
                portal.logs()
            );
            assert!(
                tcp_round_trip(public.tcp, b"no tunnel").await.is_err(),
                "{name}"
            );
        } else {
            let deadline = Instant::now() + Duration::from_secs(20);
            while tunnels_opened(&portal) == tunnels && Instant::now() < deadline {
                sleep(Duration::from_millis(250)).await;
            }
            assert!(
                tunnels_opened(&portal) > tunnels,
                "{name}; {}",
                portal.logs()
            );
            for _ in 0..3 {
                assert!(
                    tcp_round_trip(public.tcp, b"refused").await.is_err(),
                    "{name}"
                );
            }
            assert_eq!(services.accepted.load(Ordering::SeqCst), served, "{name}");
            assert!(
                !portal.logs().contains("relay-xhttp"),
                "{name}: the relay was dialed; {}",
                portal.logs()
            );
        }
        core.stop().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-reverse-interop.sh"]
async fn reverse_bridge_opens_a_second_tunnel_when_the_portal_drains() {
    let checkout = resolve_xray_checkout();
    let server = XrayVlessServerConfig {
        security: XrayInboundSecurity::None,
        transport: XrayInboundTransport::Raw,
        flow: None,
    };
    let services = start_services().await;
    let (portal, public) = start_portal(&checkout, server, &services, None).await;
    let mut core = start_bridge(bridge_profile(
        portal.addr,
        TEST_UUID,
        None,
        json!({"network": "raw"}),
        allow(&services),
    ))
    .await;
    assert!(wait_for_tunnel(public.tcp).await, "{}", portal.logs());
    assert_eq!(tunnels_opened(&portal), 1);
    // Xray-core's portal drains a tunnel once it opened more than 256
    // sessions on it; every session here takes one.
    for index in 0..260u32 {
        tcp_round_trip(public.tcp, &index.to_be_bytes())
            .await
            .unwrap_or_else(|error| panic!("session {index}: {error}; {}", portal.logs()));
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while tunnels_opened(&portal) < 2 && Instant::now() < deadline {
        sleep(Duration::from_millis(250)).await;
    }
    assert!(tunnels_opened(&portal) >= 2, "{}", portal.logs());
    tcp_round_trip(public.tcp, b"after the drain")
        .await
        .unwrap_or_else(|error| panic!("{error}; {}", portal.logs()));
    core.stop().await.unwrap();
}
