//! `http` outbound end to end.
//!
//! In-process tests drive a scripted CONNECT proxy, plain or over TLS, to pin
//! the request bytes, status handling, early tunnel bytes, ALPN, UDP refusal,
//! chaining and outbound probes. The ignored tests run against the pinned Go
//! Xray-core HTTP inbound and compare the CONNECT request with the pinned Go
//! client's; `scripts/check-http-interop.sh` builds Xray and runs them.
#[path = "hysteria_runtime/support.rs"]
mod hysteria_support;
use hysteria_support::{tcp_echo, Bootstrap, Protector, Task};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use xray_core_rs::{Core, OutboundProbeOutcome, StartupProbeOptions};
use xray_proxy::inbound::encode_socks5_udp_datagram;
use xray_proxy::outbound::{encode_connect_request, HttpAccount};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::stream::{apply_masquerade, HeaderMap};
use xray_transport::{TlsConnector, TransportDialer};

#[path = "http_runtime/import.rs"]
mod import;

#[path = "http_runtime/support.rs"]
mod support;
use support::*;
const PAYLOAD_LEN: usize = 64 * 1024;
/// `base64("synthetic-http-user:synthetic-http-pass")`.
const BASIC: &str = "Basic c3ludGhldGljLWh0dHAtdXNlcjpzeW50aGV0aWMtaHR0cC1wYXNz";

fn core(profile: Value) -> (Core, Arc<Protector>, Arc<Bootstrap>) {
    core_with_tls(profile, None)
}

fn core_with_tls(
    profile: Value,
    tls: Option<TlsConnector>,
) -> (Core, Arc<Protector>, Arc<Bootstrap>) {
    let protector = Arc::new(Protector::default());
    let bootstrap = Arc::new(Bootstrap::default());
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
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

/// No-auth SOCKS5 CONNECT to the core's inbound; returns the stream and reply code.
async fn connect(proxy: SocketAddr, destination: Destination<'_>) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0];
    match destination {
        Destination::Ip(SocketAddr::V4(target)) => {
            request.push(1);
            request.extend_from_slice(&target.ip().octets());
            request.extend_from_slice(&target.port().to_be_bytes());
        }
        Destination::Ip(SocketAddr::V6(target)) => {
            request.push(4);
            request.extend_from_slice(&target.ip().octets());
            request.extend_from_slice(&target.port().to_be_bytes());
        }
        Destination::Domain(domain, port) => {
            request.extend_from_slice(&[3, domain.len() as u8]);
            request.extend_from_slice(domain.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&request).await.unwrap();
    let mut head = [0; 4];
    stream.read_exact(&mut head).await.unwrap();
    let rest = match head[3] {
        4 => 16 + 2,
        _ => 4 + 2,
    };
    stream.read_exact(&mut vec![0; rest]).await.unwrap();
    (stream, head[1])
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

async fn ipv6_echo() -> (SocketAddr, Task) {
    let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut read, mut write) = socket.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    }));
    (address, task)
}

/// The CONNECT xray-rust sends for `authority` with the masquerade block.
fn expected_request(target: &Target, account: Option<&HttpAccount>) -> String {
    let mut masquerade = HeaderMap::new();
    apply_masquerade(&mut masquerade, "nav");
    let headers: Vec<(&str, &str)> = masquerade.iter().collect();
    String::from_utf8(
        encode_connect_request(target, account, &headers)
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn http_runtime_tunnels_ipv4_ipv6_and_proxy_resolved_domains() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let (echo6, _echo6) = ipv6_echo().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b""), None, echo.ip()).await;
        for form in [Form::Flat, Form::Servers] {
            let settings = outbound_settings(form, proxy.address.port(), Some((USER, PASS)));
            let (mut core, protector, bootstrap) = core(profile(settings, None));
            core.start().await.unwrap();
            let socks = core.inbound_addr(Some("socks-in")).unwrap();
            let mut open = Vec::new();
            for destination in [
                Destination::Ip(echo),
                Destination::Ip(echo6),
                Destination::Domain(REMOTE_DOMAIN, echo.port()),
            ] {
                let (mut stream, reply) = connect(socks, destination).await;
                assert_eq!(reply, 0, "the tunnel must open");
                echo_round_trip(&mut stream, PAYLOAD_LEN).await;
                open.push(stream);
            }
            // Only the proxy name is resolved locally; `Bootstrap` panics on
            // any other name, so the destination domain went to the proxy.
            assert!(bootstrap.0.load(Ordering::SeqCst) >= 3);
            assert!(protector.0.load(Ordering::SeqCst) >= 3);
            let snapshot = core.connection_snapshot();
            assert_eq!(snapshot.connections.len(), 3);
            assert!(snapshot
                .connections
                .iter()
                .all(|c| c.outbound_tag.as_deref() == Some("proxy")));
            drop(open);
            core.stop().await.unwrap();
        }

        let account = HttpAccount::new(USER, PASS).unwrap();
        let captured = proxy.captured();
        assert_eq!(captured.len(), 6);
        let targets = [
            Target::new(TargetAddr::Ip(echo.ip()), echo.port(), Network::Tcp),
            Target::new(TargetAddr::Ip(echo6.ip()), echo6.port(), Network::Tcp),
            Target::new(
                TargetAddr::Domain(REMOTE_DOMAIN.into()),
                echo.port(),
                Network::Tcp,
            ),
        ];
        for (request, target) in captured.iter().zip(targets.iter().cycle()) {
            assert_eq!(request.head, expected_request(target, Some(&account)));
            assert_eq!(header(&request.head, "Proxy-Authorization"), Some(BASIC));
            assert!(header(&request.head, "User-Agent")
                .unwrap()
                .contains("Chrome/"));
        }
        assert!(captured[1].head.starts_with(&format!(
            "CONNECT [::1]:{0} HTTP/1.1\r\nHost: [::1]:{0}\r\n",
            echo6.port()
        )));
        assert!(captured[2].head.starts_with(&format!(
            "CONNECT {REMOTE_DOMAIN}:{} HTTP/1.1\r\n",
            echo.port()
        )));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_without_credentials_sends_no_authorization() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b""), None, echo.ip()).await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), None);
        let (mut core, _, _) = core(profile(settings, None));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let (mut stream, reply) = connect(socks, Destination::Ip(echo)).await;
        assert_eq!(reply, 0);
        echo_round_trip(&mut stream, 1024).await;
        let head = &proxy.captured()[0].head;
        assert!(!head.contains("Proxy-Authorization"), "{head}");
        assert_eq!(header(head, "Proxy-Connection"), Some("Keep-Alive"));
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_delivers_tunnel_bytes_that_arrive_with_the_200() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b"proxy-first"), None, echo.ip()).await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), Some((USER, PASS)));
        let (mut core, _, _) = core(profile(settings, None));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let (mut stream, reply) = connect(socks, Destination::Ip(echo)).await;
        assert_eq!(reply, 0);
        let mut early = [0; 11];
        stream.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"proxy-first");
        echo_round_trip(&mut stream, PAYLOAD_LEN).await;
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_offers_only_http11_over_tls() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let proxy =
            ScriptedProxy::start(Reply::Tunnel(b""), Some(identity.acceptor), echo.ip()).await;
        // The unshaped hello and a shaped one whose profile carries h2.
        for fingerprint in [None, Some("chrome"), Some("firefox")] {
            let settings =
                outbound_settings(Form::Servers, proxy.address.port(), Some((USER, PASS)));
            let (mut core, _, _) = core(profile(settings, Some((&identity.pin, fingerprint))));
            core.start().await.unwrap();
            let socks = core.inbound_addr(Some("socks-in")).unwrap();
            let (mut stream, reply) =
                connect(socks, Destination::Domain(REMOTE_DOMAIN, echo.port())).await;
            assert_eq!(reply, 0, "TLS tunnel with fingerprint {fingerprint:?}");
            echo_round_trip(&mut stream, PAYLOAD_LEN).await;
            core.stop().await.unwrap();
        }
        let captured = proxy.captured();
        assert_eq!(captured.len(), 3);
        for request in captured {
            assert_eq!(request.alpn.as_deref(), Some(b"http/1.1".as_slice()));
            assert_eq!(header(&request.head, "Proxy-Authorization"), Some(BASIC));
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_refuses_every_status_but_200() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        for status in [
            "407 Proxy Authentication Required",
            "403 Forbidden",
            "502 Bad Gateway",
            "204 No Content",
        ] {
            let proxy = ScriptedProxy::start(Reply::Status(status), None, echo.ip()).await;
            let settings = outbound_settings(Form::Flat, proxy.address.port(), Some((USER, PASS)));
            let (mut core, _, _) = core(profile(settings, None));
            core.start().await.unwrap();
            let socks = core.inbound_addr(Some("socks-in")).unwrap();
            let (_stream, reply) = connect(socks, Destination::Ip(echo)).await;
            assert_ne!(reply, 0, "{status} must not open the tunnel");
            assert_eq!(proxy.captured().len(), 1);
            core.stop().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_refuses_udp_without_dialing_the_proxy() {
    timeout(DEADLINE, async {
        let proxy =
            ScriptedProxy::start(Reply::Tunnel(b""), None, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), None);
        let (mut core, _, _) = core(profile(settings, None));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut control = TcpStream::connect(socks).await.unwrap();
        let relay = xray_proxy::outbound::socks5_udp_associate(
            &mut control,
            None,
            socket.local_addr().unwrap(),
            socks.ip(),
        )
        .await
        .unwrap();
        let target = Target::new(
            TargetAddr::Ip(Ipv4Addr::new(192, 0, 2, 1).into()),
            53,
            Network::Udp,
        );
        socket
            .send_to(
                &encode_socks5_udp_datagram(&target, b"must be refused").unwrap(),
                relay,
            )
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(300), socket.recv(&mut [0; 256]))
                .await
                .is_err()
        );
        assert!(proxy.captured().is_empty(), "UDP must not dial the proxy");
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

/// `socks-in` → `entry` carried over `hop`; the core's own `upstream-in`
/// SOCKS inbound and Freedom stand in for a remote SOCKS server.
fn chain_profile(entry: Value, hop: Value, upstream_port: u16) -> Value {
    json!({
        "inbounds": [
            {"tag":"socks-in", "protocol":"socks", "listen":"127.0.0.1", "port":0,
             "settings":{"auth":"noauth"}},
            {"tag":"upstream-in", "protocol":"socks", "listen":"127.0.0.1", "port":upstream_port,
             "settings":{"auth":"noauth"}}
        ],
        "outbounds": [
            {"tag":"direct", "protocol":"freedom"},
            entry,
            hop
        ],
        "routing": {"rules": [
            {"type":"field", "inboundTag":["socks-in"], "outboundTag":"entry"}
        ]}
    })
}

#[tokio::test]
async fn http_runtime_chains_in_both_directions() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b""), None, echo.ip()).await;
        let upstream_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let http = |tag: &str| {
            json!({"tag":tag, "protocol":"http", "settings":{
                "address":"127.0.0.1", "port":proxy.address.port(), "user":USER, "pass":PASS}})
        };
        let socks = |tag: &str| {
            json!({"tag":tag, "protocol":"socks", "settings":{
                "address":"127.0.0.1", "port":upstream_port}})
        };
        let carried = |mut outbound: Value| {
            outbound["proxySettings"] = json!({"tag":"hop", "transportLayer":true});
            outbound
        };
        for (entry, hop) in [
            // HTTP is the hop: the proxy CONNECTs to the SOCKS upstream.
            (carried(socks("entry")), http("hop")),
            // HTTP rides the SOCKS hop: Freedom dials the proxy.
            (carried(http("entry")), socks("hop")),
        ] {
            let before = proxy.captured().len();
            let (mut core, _, _) = core(chain_profile(entry, hop, upstream_port));
            core.start().await.unwrap();
            let socks_in = core.inbound_addr(Some("socks-in")).unwrap();
            let (mut stream, reply) = connect(socks_in, Destination::Ip(echo)).await;
            assert_eq!(reply, 0);
            echo_round_trip(&mut stream, PAYLOAD_LEN).await;
            assert_eq!(proxy.captured().len(), before + 1);
            core.stop().await.unwrap();
        }
        let captured = proxy.captured();
        assert!(captured[0]
            .head
            .starts_with(&format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n")));
        assert!(captured[1]
            .head
            .starts_with(&format!("CONNECT {echo} HTTP/1.1\r\n")));
    })
    .await
    .unwrap();
}

/// Answers each request on `listener` with `204` and no body.
async fn http_204_server() -> (SocketAddr, Task) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let Ok(byte) = socket.read_u8().await else {
                        return;
                    };
                    request.push(byte);
                }
                let _ = socket
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    }));
    (address, task)
}

#[tokio::test]
async fn http_runtime_outbound_probe_goes_through_the_proxy() {
    timeout(DEADLINE, async {
        let (server, _server) = http_204_server().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b""), None, server.ip()).await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), Some((USER, PASS)));
        let (mut core, _, _) = core(profile(settings, None));
        core.start().await.unwrap();
        let outcome = core
            .probe_outbound_url(StartupProbeOptions {
                url: format!("http://{REMOTE_DOMAIN}:{}/health", server.port()),
                timeout: Duration::from_secs(5),
                outbound_tag: Some("proxy".to_owned()),
            })
            .await
            .unwrap();
        assert!(
            matches!(outcome, OutboundProbeOutcome::Reachable { .. }),
            "{outcome:?}"
        );
        assert!(proxy.captured()[0].head.starts_with(&format!(
            "CONNECT {REMOTE_DOMAIN}:{} HTTP/1.1\r\n",
            server.port()
        )));
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

async fn assert_tunnels(profile: Value, echo: SocketAddr) {
    let (mut core, protector, bootstrap) = core(profile);
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    for destination in [
        Destination::Ip(echo),
        Destination::Domain(REMOTE_DOMAIN, echo.port()),
    ] {
        let (mut stream, reply) = connect(proxy, destination).await;
        assert_eq!(reply, 0, "the tunnel must open");
        echo_round_trip(&mut stream, PAYLOAD_LEN).await;
    }
    assert!(protector.0.load(Ordering::SeqCst) > 0);
    assert!(bootstrap.0.load(Ordering::SeqCst) > 0);
    core.stop().await.unwrap();
}

async fn assert_refused(profile: Value, echo: SocketAddr) {
    let (mut core, _, _) = core(profile);
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let (_stream, reply) = connect(proxy, Destination::Ip(echo)).await;
    assert_ne!(reply, 0, "a rejected login must not open the tunnel");
    core.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-http-interop.sh"]
async fn http_runtime_basic_and_noauth_against_pinned_xray() {
    timeout(DEADLINE * 4, async {
        let (echo, _echo) = tcp_echo().await;
        assert_eq!(echo.ip(), Ipv4Addr::LOCALHOST);
        for tls in [false, true] {
            let server = if tls {
                XrayServer::start_tls().await
            } else {
                XrayServer::start().await
            };
            let security = server.pin.as_deref().map(|pin| (pin, Some("chrome")));
            for form in [Form::Flat, Form::Servers] {
                let account = Some((USER, PASS));
                let settings = outbound_settings(form, server.password, account);
                assert_tunnels(profile(settings, security), echo).await;
                let settings = outbound_settings(form, server.noauth, None);
                assert_tunnels(profile(settings, security), echo).await;
                let wrong = Some((USER, "synthetic-wrong-pass"));
                let settings = outbound_settings(form, server.password, wrong);
                assert_refused(profile(settings, security), echo).await;
                let settings = outbound_settings(form, server.password, None);
                assert_refused(profile(settings, security), echo).await;
                eprintln!("HTTP {form:?}, TLS={tls}: Basic, no-auth and refusals passed");
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-http-interop.sh"]
async fn http_runtime_request_matches_the_pinned_go_client() {
    timeout(DEADLINE * 2, async {
        let (echo, _echo) = tcp_echo().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b""), None, echo.ip()).await;
        let server = XrayServer::forwarding(json!({"protocol":"http", "settings": {
            "address":"127.0.0.1", "port":proxy.address.port(), "user":USER, "pass":PASS
        }}))
        .await;
        let socks = SocketAddr::from((Ipv4Addr::LOCALHOST, server.noauth));
        let (mut stream, reply) =
            connect(socks, Destination::Domain(REMOTE_DOMAIN, echo.port())).await;
        assert_eq!(
            reply, 0,
            "the pinned Go client tunnels through the scripted proxy"
        );
        echo_round_trip(&mut stream, 1024).await;
        let go = proxy.captured().remove(0).head;
        let target = Target::new(
            TargetAddr::Domain(REMOTE_DOMAIN.into()),
            echo.port(),
            Network::Tcp,
        );
        let ours = expected_request(&target, Some(&HttpAccount::new(USER, PASS).unwrap()));
        // Browser versions are drawn per process on both sides; everything
        // else, including the order of the header names, must match.
        assert_eq!(header_names(&ours), header_names(&go), "{ours}\n{go}");
        for (line, go_line) in ours.split("\r\n").zip(go.split("\r\n")) {
            let name = line.split_once(':').map_or("", |(name, _)| name);
            if !matches!(name, "User-Agent" | "Sec-CH-UA") {
                assert_eq!(line, go_line);
            }
        }
    })
    .await
    .unwrap();
}
