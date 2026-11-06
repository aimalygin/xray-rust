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
async fn http_runtime_tunnels_over_httpupgrade() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let proxy =
            ScriptedProxy::start_behind_upgrade(Reply::Tunnel(b""), echo.ip(), "/proxy-upgrade")
                .await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), Some((USER, PASS)));
        let mut profile = profile(settings, None);
        profile["outbounds"][0]["streamSettings"] =
            json!({"network":"httpupgrade","httpupgradeSettings":{"path":"/proxy-upgrade"}});
        let (mut core, _, _) = core(profile);
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let (mut stream, reply) = connect(socks, Destination::Ip(echo)).await;
        assert_eq!(reply, 0);
        echo_round_trip(&mut stream, PAYLOAD_LEN).await;
        let captured = proxy.captured();
        assert_eq!(captured.len(), 1);
        assert!(
            captured[0]
                .head
                .starts_with(&format!("CONNECT {echo} HTTP/1.1\r\n")),
            "{}",
            captured[0].head
        );
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

/// A profile with TLS settings beyond the pin, such as `alpn`.
fn profile_with_tls(settings: Value, pin: &str, extra: Value) -> Value {
    let mut profile = profile(settings, Some((pin, None)));
    let tls = &mut profile["outbounds"][0]["streamSettings"]["tlsSettings"];
    for (key, value) in extra.as_object().unwrap() {
        tls[key] = value.clone();
    }
    profile
}

#[tokio::test]
async fn http_runtime_tunnels_over_http2_when_tls_picks_it() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let proxy = ScriptedProxy::start(
            Reply::Tunnel(b"proxy-first"),
            Some(identity.acceptor),
            echo.ip(),
        )
        .await;
        // Shaped hellos carry their profile's h2, as Xray-core's do.
        for fingerprint in [None, Some("firefox")] {
            let settings =
                outbound_settings(Form::Servers, proxy.address.port(), Some((USER, PASS)));
            let (mut core, _, _) = core(profile(settings, Some((&identity.pin, fingerprint))));
            core.start().await.unwrap();
            let socks = core.inbound_addr(Some("socks-in")).unwrap();
            let (mut stream, reply) =
                connect(socks, Destination::Domain(REMOTE_DOMAIN, echo.port())).await;
            assert_eq!(reply, 0, "HTTP/2 tunnel with fingerprint {fingerprint:?}");
            // Bytes the proxy sends with its 200 come first.
            let mut early = [0; 11];
            stream.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"proxy-first");
            echo_round_trip(&mut stream, PAYLOAD_LEN).await;
            core.stop().await.unwrap();
        }
        let captured = proxy.captured();
        assert_eq!(captured.len(), 2);
        for request in &captured {
            assert_eq!(request.alpn.as_deref(), Some(b"h2".as_slice()));
            let authority = format!("{REMOTE_DOMAIN}:{}", echo.port());
            assert_eq!(request.head, format!("CONNECT {authority} HTTP/2"));
            assert_eq!(field(request, "proxy-authorization"), Some(BASIC));
            // Go's HTTP/2 client asks for gzip: the masquerade block sets
            // no Accept-Encoding.
            assert_eq!(field(request, "accept-encoding"), Some("gzip"));
            assert!(field(request, "user-agent").unwrap().contains("Chrome/"));
            for absent in ["host", "proxy-connection", "connection"] {
                assert_eq!(field(request, absent), None, "{absent}");
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_stays_on_http11_unless_tls_picks_h2() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let both = ScriptedProxy::start(
            Reply::Tunnel(b""),
            Some(identity.acceptor.clone()),
            echo.ip(),
        )
        .await;
        let http11 = ScriptedProxy::start(
            Reply::Tunnel(b""),
            Some(identity.http11_acceptor.clone()),
            echo.ip(),
        )
        .await;
        let cases = [
            // A proxy that offers HTTP/1.1 alone.
            (&http11, json!({})),
            // `["http/1.1"]` is the one list a shaped hello sends as configured.
            (&both, json!({"alpn": ["http/1.1"]})),
            // With `unsafe` and no list, the hello offers no protocol at all.
            (&both, json!({"fingerprint": "unsafe"})),
        ];
        for (proxy, tls) in cases {
            let settings = outbound_settings(Form::Flat, proxy.address.port(), Some((USER, PASS)));
            let (mut core, _, _) = core(profile_with_tls(settings, &identity.pin, tls.clone()));
            core.start().await.unwrap();
            let socks = core.inbound_addr(Some("socks-in")).unwrap();
            let (mut stream, reply) =
                connect(socks, Destination::Domain(REMOTE_DOMAIN, echo.port())).await;
            assert_eq!(reply, 0, "{tls}");
            echo_round_trip(&mut stream, PAYLOAD_LEN).await;
            core.stop().await.unwrap();
        }
        let mut captured = http11.captured();
        captured.extend(both.captured());
        assert_eq!(captured.len(), 3);
        let alpn: Vec<_> = captured
            .iter()
            .map(|request| request.alpn.clone())
            .collect();
        assert_eq!(
            alpn,
            [Some(b"http/1.1".to_vec()), Some(b"http/1.1".to_vec()), None]
        );
        for request in captured {
            assert!(request.head.starts_with("CONNECT "), "{}", request.head);
            assert!(request.head.contains(" HTTP/1.1\r\n"), "{}", request.head);
            assert_eq!(header(&request.head, "Proxy-Authorization"), Some(BASIC));
            assert_eq!(
                header(&request.head, "Proxy-Connection"),
                Some("Keep-Alive")
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_tunnels_share_one_http2_connection() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let proxy =
            ScriptedProxy::start(Reply::Tunnel(b""), Some(identity.acceptor), echo.ip()).await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), None);
        let (mut core, protector, bootstrap) = core(profile(settings, Some((&identity.pin, None))));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let destination = || Destination::Domain(REMOTE_DOMAIN, echo.port());
        // One after another, and two at once beside a third.
        let (mut first, reply) = connect(socks, destination()).await;
        assert_eq!(reply, 0);
        echo_round_trip(&mut first, 1024).await;
        drop(first);
        let (mut second, reply) = connect(socks, destination()).await;
        assert_eq!(reply, 0);
        let (mut third, reply) = connect(socks, destination()).await;
        assert_eq!(reply, 0);
        let (a, b) = tokio::join!(
            echo_round_trip(&mut second, PAYLOAD_LEN),
            echo_round_trip(&mut third, PAYLOAD_LEN)
        );
        let ((), ()) = (a, b);
        drop((second, third));
        assert_eq!(
            proxy.http2_ended(),
            0,
            "the connection is kept for later tunnels"
        );
        // Stopping the core lets the shared connection go.
        core.stop().await.unwrap();
        for _ in 0..200 {
            if proxy.http2_ended() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            proxy.http2_ended(),
            1,
            "the stopped core must close its connection"
        );

        let captured = proxy.captured();
        assert_eq!(captured.len(), 3);
        assert!(captured.iter().all(|request| request.connection == 0));
        // The proxy was resolved and dialed once, through the protector.
        assert_eq!(bootstrap.0.load(Ordering::SeqCst), 1);
        assert_eq!(protector.0.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_refuses_every_status_but_200_over_http2() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        for status in [
            "407 Proxy Authentication Required",
            "403 Forbidden",
            "204 No Content",
        ] {
            let proxy = ScriptedProxy::start(
                Reply::Status(status),
                Some(identity.acceptor.clone()),
                echo.ip(),
            )
            .await;
            let settings = outbound_settings(Form::Flat, proxy.address.port(), Some((USER, PASS)));
            let (mut core, _, _) = core(profile(settings, Some((&identity.pin, None))));
            core.start().await.unwrap();
            let socks = core.inbound_addr(Some("socks-in")).unwrap();
            let (_stream, reply) =
                connect(socks, Destination::Domain(REMOTE_DOMAIN, echo.port())).await;
            assert_ne!(reply, 0, "{status} must not open the tunnel");
            core.stop().await.unwrap();
            let captured = proxy.captured();
            assert_eq!(captured.len(), 1, "{status}");
            assert_eq!(captured[0].alpn.as_deref(), Some(b"h2".as_slice()));
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

#[tokio::test]
async fn http_runtime_sends_custom_headers_naming_source_and_target() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b""), None, echo.ip()).await;
        let mut settings = outbound_settings(Form::Flat, proxy.address.port(), None);
        settings["headers"] = json!({
            "x-target": "{{.Target}}",
            "X-Source": "{{.Source}}",
            "User-Agent": "synthetic-agent",
        });
        let (mut core, _, _) = core(profile(settings, None));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let (mut stream, reply) = connect(socks, Destination::Ip(echo)).await;
        assert_eq!(reply, 0);
        echo_round_trip(&mut stream, 1024).await;
        let head = &proxy.captured()[0].head;
        assert_eq!(
            header(head, "X-Target"),
            Some(format!("tcp:{echo}").as_str())
        );
        assert_eq!(
            header(head, "X-Source"),
            Some(format!("tcp:{}", stream.local_addr().unwrap()).as_str())
        );
        // A custom User-Agent other than a browser's name keeps the
        // masquerade block out, as in Xray-core.
        assert_eq!(header(head, "User-Agent"), Some("synthetic-agent"));
        assert_eq!(header(head, "Sec-Fetch-Mode"), None);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_hop_headers_name_the_client_the_chain_carries() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b""), None, echo.ip()).await;
        let upstream_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let entry = json!({"tag":"entry", "protocol":"socks", "settings":{
            "address":"127.0.0.1", "port":upstream_port},
            "proxySettings": {"tag":"hop", "transportLayer":true}});
        let hop = json!({"tag":"hop", "protocol":"http", "settings":{
            "address":"127.0.0.1", "port":proxy.address.port(),
            "headers": {"X-Source": "{{.Source}}", "X-Target": "{{.Target}}"}}});
        let (mut core, _, _) = core(chain_profile(entry, hop, upstream_port));
        core.start().await.unwrap();
        let socks_in = core.inbound_addr(Some("socks-in")).unwrap();
        let (mut stream, reply) = connect(socks_in, Destination::Ip(echo)).await;
        assert_eq!(reply, 0);
        echo_round_trip(&mut stream, 1024).await;
        let head = &proxy.captured()[0].head;
        // The hop's target is the next server.
        assert_eq!(
            header(head, "X-Target"),
            Some(format!("tcp:127.0.0.1:{upstream_port}").as_str())
        );
        assert_eq!(
            header(head, "X-Source"),
            Some(format!("tcp:{}", stream.local_addr().unwrap()).as_str())
        );
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_custom_headers_keep_the_masquerade_without_a_user_agent() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let proxy = ScriptedProxy::start(Reply::Tunnel(b""), None, echo.ip()).await;
        let mut settings = outbound_settings(Form::Flat, proxy.address.port(), Some((USER, PASS)));
        settings["headers"] =
            json!({"X-Extra": "1", "Proxy-Authorization": "Bearer synthetic-token"});
        let (mut core, _, _) = core(profile(settings, None));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let (mut stream, reply) = connect(socks, Destination::Ip(echo)).await;
        assert_eq!(reply, 0);
        echo_round_trip(&mut stream, 1024).await;
        let head = &proxy.captured()[0].head;
        assert_eq!(header(head, "X-Extra"), Some("1"));
        assert_eq!(header(head, "Sec-Fetch-Mode"), Some("navigate"));
        // The custom credentials replace the account's.
        assert_eq!(
            header(head, "Proxy-Authorization"),
            Some("Bearer synthetic-token")
        );
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

/// Opens a tunnel through `socks` to the echo server and checks it works.
async fn open_echo(socks: SocketAddr, echo: SocketAddr) -> TcpStream {
    let (mut stream, reply) = connect(socks, Destination::Domain(REMOTE_DOMAIN, echo.port())).await;
    assert_eq!(reply, 0);
    echo_round_trip(&mut stream, 1024).await;
    stream
}

#[tokio::test]
async fn http_runtime_dials_again_at_the_proxys_stream_limit() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let options = Http2Options {
            max_streams: Some(1),
            ..Http2Options::default()
        };
        let proxy = ScriptedProxy::start_http2(
            Reply::Tunnel(b""),
            Some(identity.acceptor),
            echo.ip(),
            options,
        )
        .await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), None);
        let (mut core, _, _) = core(profile(settings, Some((&identity.pin, None))));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        // Each open tunnel fills the one stream its connection allows, so
        // every new one dials, and the newest connection is the one kept.
        let first = open_echo(socks, echo).await;
        let second = open_echo(socks, echo).await;
        let third = open_echo(socks, echo).await;
        drop((first, second, third));
        core.stop().await.unwrap();
        let connections: Vec<_> = proxy
            .captured()
            .iter()
            .map(|request| request.connection)
            .collect();
        assert_eq!(connections, [0, 1, 2]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_dials_again_after_a_goaway() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let options = Http2Options {
            goaway_after: Some(1),
            ..Http2Options::default()
        };
        let proxy = ScriptedProxy::start_http2(
            Reply::Tunnel(b""),
            Some(identity.acceptor),
            echo.ip(),
            options,
        )
        .await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), None);
        let (mut core, _, _) = core(profile(settings, Some((&identity.pin, None))));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        // The first tunnel stays open, so the connection that sent GOAWAY is
        // still up when the second asks for a tunnel.
        let mut first = open_echo(socks, echo).await;
        let second = open_echo(socks, echo).await;
        echo_round_trip(&mut first, 1024).await;
        drop((first, second));
        core.stop().await.unwrap();
        let connections: Vec<_> = proxy
            .captured()
            .iter()
            .map(|request| request.connection)
            .collect();
        assert_eq!(connections, [0, 1]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_fails_on_another_application_protocol() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let proxy = ScriptedProxy::start(
            Reply::Tunnel(b""),
            Some(identity.acceptor_offering(&[b"spdy/3"])),
            echo.ip(),
        )
        .await;
        let settings = outbound_settings(Form::Flat, proxy.address.port(), None);
        let tls = json!({"fingerprint": "unsafe", "alpn": ["spdy/3"]});
        let (mut core, _, _) = core(profile_with_tls(settings, &identity.pin, tls));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let (_stream, reply) =
            connect(socks, Destination::Domain(REMOTE_DOMAIN, echo.port())).await;
        assert_ne!(reply, 0, "Xray-core supports only http/1.1 and h2");
        core.stop().await.unwrap();
        assert!(proxy.captured().is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_http2_sends_custom_values_as_they_are() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let proxy =
            ScriptedProxy::start(Reply::Tunnel(b""), Some(identity.acceptor), echo.ip()).await;
        let mut settings = outbound_settings(Form::Flat, proxy.address.port(), None);
        settings["headers"] = json!({
            "User-Agent": "golang",
            "X-Padded": "  padded\t",
            "x-target": "{{.Target}}",
            "Cookie": "a=1; b=2",
        });
        let (mut core, _, _) = core(profile(settings, Some((&identity.pin, None))));
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        drop(open_echo(socks, echo).await);
        core.stop().await.unwrap();
        let captured = proxy.captured();
        let fields: Vec<(&str, &str)> = captured[0]
            .fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let target = format!("tcp:{REMOTE_DOMAIN}:{}", echo.port());
        // `golang` drops the masquerade block and the agent, so Go's HTTP/2
        // default is sent.
        assert_eq!(
            fields,
            [
                ("cookie", "a=1"),
                ("cookie", "b=2"),
                ("x-padded", "  padded\t"),
                ("x-target", target.as_str()),
                ("accept-encoding", "gzip"),
                ("user-agent", "Go-http-client/2.0"),
            ]
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_runtime_stopping_closes_a_chained_http2_connection() {
    timeout(DEADLINE, async {
        let (echo, _echo) = tcp_echo().await;
        let identity = tls_identity();
        let proxy =
            ScriptedProxy::start(Reply::Tunnel(b""), Some(identity.acceptor), echo.ip()).await;
        // The HTTP outbound rides a freedom hop, so the core keeps it inside
        // a chain.
        let profile = json!({
            "inbounds": [{"tag":"socks-in", "protocol":"socks", "listen":"127.0.0.1", "port":0,
                          "settings":{"auth":"noauth"}}],
            "outbounds": [
                {"tag":"entry", "protocol":"http",
                 "settings":{"address":"127.0.0.1", "port":proxy.address.port()},
                 "streamSettings":{"network":"raw", "security":"tls",
                    "tlsSettings":{"serverName":"localhost", "pinnedPeerCertSha256":identity.pin},
                    "sockopt":{"dialerProxy":"hop"}}},
                {"tag":"hop", "protocol":"freedom"}
            ]
        });
        let (mut core, _, _) = core(profile);
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        drop(open_echo(socks, echo).await);
        core.stop().await.unwrap();
        for _ in 0..200 {
            if proxy.http2_ended() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(proxy.captured()[0].alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(
            proxy.http2_ended(),
            1,
            "the stopped core must close its connection"
        );
    })
    .await
    .unwrap();
}
