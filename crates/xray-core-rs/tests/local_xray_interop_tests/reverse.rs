//! The bridge side of the VLESS reverse proxy against Xray-core v26.10.31's
//! portal: a VLESS inbound whose user may open a reverse proxy, and public
//! tunnel inbounds routed into it. TCP and UDP services behind the bridge
//! answer clients of the portal over raw, TLS with Vision, WebSocket, gRPC
//! and XHTTP; freedom refuses what its final rules do not allow; a wrong UUID
//! opens nothing; the portal's DRAIN after 256 sessions brings a second
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
