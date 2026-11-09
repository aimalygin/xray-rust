//! The `xicmp` UDP mask against Xray-core v26.10.31's own server, which
//! reads echo requests on raw ICMP sockets and so needs root or
//! `CAP_NET_RAW`: `scripts/check-xicmp-interop.sh` runs these on Linux, as
//! root, with `XRAY_XICMP_LIVE=1`. Without it they skip, so the binary's
//! other `--ignored` runs, unprivileged, pass them by.
//! The client takes datagram ICMP sockets, and raw ones where the test may
//! open them.
use super::v08_carriers::exercise;
use super::*;
use serde_json::{json, Value};

fn xicmp(dgram: bool, ips: &[&str]) -> Value {
    json!({"type": "xicmp", "settings": {"dgram": dgram, "ips": ips}})
}

fn profile(address: &str, port: u16, masks: Value) -> Value {
    json!({"inbounds":[{"protocol":"socks","tag":"socks-in","listen":"127.0.0.1","port":0,"settings":{"udp":true}}],
        "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":address,"port":port,
            "users":[{"id":TEST_UUID,"encryption":"none"}]}]},
            "streamSettings":{"network":"kcp","finalmask":{"udp":masks}}}]})
}

async fn kcp_server(checkout: &Path, masks: Value) -> XrayServer {
    start_xray_vless_server_listening(
        checkout,
        XrayVlessServerConfig {
            security: XrayInboundSecurity::None,
            transport: XrayInboundTransport::Kcp,
            flow: None,
        },
        |config| {
            config["inbounds"][0]["streamSettings"]["finalmask"] = json!({"udp": masks});
        },
        false,
    )
    .await
}

/// Whether this run may start Xray-core's xicmp server: only
/// `check-xicmp-interop.sh` says so.
fn live() -> bool {
    let live = env::var_os("XRAY_XICMP_LIVE").is_some_and(|value| value == "1");
    if !live {
        eprintln!(
            "xicmp: needs root and XRAY_XICMP_LIVE=1, as check-xicmp-interop.sh runs it; skipped"
        );
    }
    live
}

/// Whether this process may open raw ICMP sockets.
fn raw_icmp() -> bool {
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .is_ok()
}

async fn check(server: &XrayServer, config: Value, case: &str) {
    eprintln!("xicmp {case}");
    let result = timeout(Duration::from_secs(90), exercise(config, true)).await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{case}: {result:?}; {}",
        server.logs()
    );
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core with raw ICMP sockets; run check-xicmp-interop.sh"]
async fn xicmp_carries_mkcp_to_xray() {
    if !live() {
        return;
    }
    let checkout = resolve_xray_checkout();
    let server = kcp_server(&checkout, json!([xicmp(false, &[])])).await;
    let port = server.addr.port();
    check(
        &server,
        profile("127.0.0.1", port, json!([xicmp(true, &[])])),
        "mKCP, datagram sockets, the outbound's address",
    )
    .await;
    // Each packet goes to one of the addresses, whatever the outbound's;
    // the server answers from the address each was sent to.
    check(
        &server,
        profile(
            "127.0.0.1",
            port,
            json!([xicmp(true, &["127.0.0.2", "127.0.0.3"])]),
        ),
        "mKCP, datagram sockets, two addresses",
    )
    .await;
    if raw_icmp() {
        check(
            &server,
            profile("127.0.0.1", port, json!([xicmp(false, &[])])),
            "mKCP, raw sockets",
        )
        .await;
    } else {
        eprintln!("xicmp: raw ICMP sockets refused here; raw client skipped");
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core with raw ICMP sockets; run check-xicmp-interop.sh"]
async fn xicmp_carries_mkcp_masks_inside_it() {
    if !live() {
        return;
    }
    let checkout = resolve_xray_checkout();
    let legacy = json!({"type":"mkcp-legacy","settings":{"value":"kcp-seed"}});
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"hello","delay":"5-10"}]}});
    for (case, inner) in [
        ("aes", vec![legacy.clone()]),
        ("aes and noise", vec![legacy, noise]),
    ] {
        let mut server_masks = inner.clone();
        server_masks.push(xicmp(false, &[]));
        let server = kcp_server(&checkout, Value::Array(server_masks)).await;
        let mut masks = inner;
        masks.push(xicmp(true, &[]));
        check(
            &server,
            profile("127.0.0.1", server.addr.port(), Value::Array(masks)),
            case,
        )
        .await;
    }
}

/// XHTTP over HTTP/3: every QUIC packet in an echo.
#[tokio::test]
#[ignore = "requires a pinned Xray-core with raw ICMP sockets; run check-xicmp-interop.sh"]
async fn xicmp_carries_xhttp_h3() {
    if !live() {
        return;
    }
    let checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
        start_xray_vless_server_listening(
            &checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::Tls,
                transport: XrayInboundTransport::Xhttp {
                    path: XHTTP_PATH,
                    mode: "stream-one",
                    tls_alpn: Some("h3"),
                },
                flow: None,
            },
            |json| {
                json["inbounds"][0]["streamSettings"]["finalmask"] =
                    json!({"udp":[xicmp(false, &[])]});
            },
            false,
        ),
    )
    .await
    .unwrap();
    let mut config = rust_xhttp_core_config(
        xray.addr,
        StreamSecurity::Tls(TlsSettings {
            server_name: Some(TLS_SERVER_NAME.to_owned()),
            fingerprint: Some("chrome".to_owned()),
            allow_insecure: true,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: vec!["h3".to_owned()],
        }),
        XhttpMode::StreamOne,
    );
    let raw = json!({"outbounds":[{"protocol":"freedom","streamSettings":{
        "network":"xhttp","security":"tls",
        "tlsSettings":{"serverName":"example.com","alpn":["h3"]},
        "finalmask":{"udp":[xicmp(true, &[])]}}}]});
    config.outbounds[0].stream.udp_xicmp =
        parse_xray_json(&raw.to_string()).unwrap().config.outbounds[0]
            .stream
            .udp_xicmp
            .clone();
    timeout(
        Duration::from_secs(120),
        run_local_xray_xhttp_interop_scenario(xray, config, XhttpMode::StreamOne),
    )
    .await
    .unwrap();
}

/// MASQUE over HTTP/3: every packet of the tunnel's QUIC connection in an
/// echo, TCP and UDP through the tunnel.
#[tokio::test]
#[ignore = "requires a pinned Xray-core with raw ICMP sockets; run check-xicmp-interop.sh"]
async fn xicmp_carries_masque_h3() {
    use super::masque::{
        check, client_config, core, credentials, echo_servers, start_server, tcp_echo, udp_echo,
        ECHO_V4, ECHO_V6,
    };
    if !live() {
        return;
    }
    let checkout = resolve_xray_checkout();
    let server = timeout(
        Duration::from_secs(60),
        start_server(&checkout, "h3", |config| {
            config["inbounds"][0]["streamSettings"]["finalmask"] =
                json!({"udp": [xicmp(false, &[])]});
        }),
    )
    .await
    .unwrap();
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let mut config = client_config(&server, "h3", credentials());
    config["outbounds"][0]["streamSettings"]["finalmask"] = json!({"udp": [xicmp(true, &[])]});
    let mut core = core(config).await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    check(
        &server,
        "H3 TCP over xicmp",
        tcp_echo(proxy, ECHO_V4, tcp_port),
    )
    .await;
    check(
        &server,
        "H3 UDP over IPv6 over xicmp",
        udp_echo(proxy, ECHO_V6, udp_port),
    )
    .await;
    core.stop().await.unwrap();
}
