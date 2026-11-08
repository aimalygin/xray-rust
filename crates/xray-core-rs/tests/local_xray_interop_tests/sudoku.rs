//! The `sudoku` TCP mask against Xray-core v26.10.31's own server: raw
//! (plain, TLS and REALITY), WebSocket, HTTPUpgrade, gRPC and XHTTP, and
//! after a `header-custom` handshake.
use super::proxy_carriers::certificate_pin;
use super::v08_carriers::exercise;
use super::*;
use serde_json::{json, Value};

fn sudoku(password: &str) -> Value {
    json!({"type": "sudoku", "settings": {"password": password,
        "customTables": ["xppvvvvx", "vvxpvxpv"], "paddingMin": 5, "paddingMax": 25}})
}

fn profile(port: u16, mut stream: Value, masks: Value) -> Value {
    stream["finalmask"] = json!({"tcp": masks});
    json!({"inbounds":[{"protocol":"socks","tag":"socks-in","listen":"127.0.0.1","port":0,"settings":{"udp":true}}],
        "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"upload.test","port":port,
            "users":[{"id":TEST_UUID,"encryption":"none"}]}]},"streamSettings":stream}]})
}

/// Carries a TCP echo and UDP through Xray's server with `masks`, and
/// checks that a client with another password gets nothing through.
async fn check(
    checkout: &Path,
    name: &str,
    security: XrayInboundSecurity,
    transport: XrayInboundTransport,
    mut stream: Value,
    masks: Value,
    wrong: Value,
) {
    let server_masks = masks.clone();
    let server = start_xray_vless_server_customized(
        checkout,
        XrayVlessServerConfig {
            security,
            transport,
            flow: None,
        },
        |config| {
            config["inbounds"][0]["streamSettings"]["finalmask"] = json!({"tcp": server_masks});
        },
    )
    .await;
    match security {
        XrayInboundSecurity::Tls => {
            stream["security"] = "tls".into();
            stream["tlsSettings"] = json!({"serverName":TLS_SERVER_NAME,
                "pinnedPeerCertSha256":certificate_pin(&server)});
        }
        XrayInboundSecurity::Reality => {
            stream["security"] = "reality".into();
            stream["realitySettings"] = json!({"serverName":REALITY_SERVER_NAME,"fingerprint":"chrome",
                "publicKey":REALITY_PUBLIC_KEY_BASE64,"shortId":REALITY_SHORT_ID_HEX});
        }
        XrayInboundSecurity::None => {}
    }
    eprintln!("sudoku over {name}");
    let result = timeout(
        Duration::from_secs(60),
        exercise(profile(server.addr.port(), stream.clone(), masks), true),
    )
    .await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{name}: {result:?}; {}",
        server.logs()
    );
    let refused = timeout(
        Duration::from_secs(20),
        exercise(profile(server.addr.port(), stream, wrong), false),
    )
    .await;
    assert!(
        !matches!(refused, Ok(Ok(()))),
        "{name}: another password got through"
    );
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-sudoku-interop.sh"]
async fn sudoku_wraps_every_tcp_carrier() {
    let checkout = resolve_xray_checkout();
    let cases = [
        (
            "raw",
            XrayInboundSecurity::None,
            XrayInboundTransport::Raw,
            json!({"network":"raw"}),
        ),
        (
            "raw TLS",
            XrayInboundSecurity::Tls,
            XrayInboundTransport::Raw,
            json!({"network":"raw"}),
        ),
        (
            "raw REALITY",
            XrayInboundSecurity::Reality,
            XrayInboundTransport::Raw,
            json!({"network":"raw"}),
        ),
        (
            "WebSocket",
            XrayInboundSecurity::None,
            XrayInboundTransport::WebSocket { path: "/sd" },
            json!({"network":"ws","wsSettings":{"path":"/sd"}}),
        ),
        (
            "HTTPUpgrade TLS",
            XrayInboundSecurity::Tls,
            XrayInboundTransport::HttpUpgrade { path: "/sd" },
            json!({"network":"httpupgrade","httpupgradeSettings":{"path":"/sd"}}),
        ),
        (
            "gRPC TLS",
            XrayInboundSecurity::Tls,
            XrayInboundTransport::Grpc { service_name: "sd" },
            json!({"network":"grpc","grpcSettings":{"serviceName":"sd"}}),
        ),
        (
            "XHTTP",
            XrayInboundSecurity::None,
            XrayInboundTransport::Xhttp {
                path: "/sd/",
                mode: "auto",
                tls_alpn: None,
            },
            json!({"network":"xhttp","xhttpSettings":{"path":"/sd/","mode":"packet-up","xPaddingBytes":64,
                "scMaxEachPostBytes":4096,"scMinPostsIntervalMs":1}}),
        ),
    ];
    for (name, security, transport, stream) in cases {
        check(
            &checkout,
            name,
            security,
            transport,
            stream,
            json!([sudoku("synthetic-sudoku")]),
            json!([sudoku("another-password")]),
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-sudoku-interop.sh"]
async fn sudoku_carries_a_header_custom_handshake_and_ascii() {
    let checkout = resolve_xray_checkout();
    let header = json!({"type": "header-custom", "settings": {
        "clients": [[{"type": "str", "packet": "HELLO"}]],
        "servers": [[{"type": "str", "packet": "OK"}]]}});
    let ascii = json!({"type": "sudoku", "settings": {"password": "synthetic-sudoku", "ascii": "prefer_ascii"}});
    for (name, masks, wrong) in [
        (
            "header-custom then sudoku",
            json!([header, sudoku("synthetic-sudoku")]),
            json!([header, sudoku("another-password")]),
        ),
        (
            "ASCII",
            json!([ascii]),
            json!([{"type": "sudoku", "settings": {"password": "synthetic-sudoku"}}]),
        ),
    ] {
        check(
            &checkout,
            name,
            XrayInboundSecurity::Tls,
            XrayInboundTransport::Raw,
            json!({"network":"raw"}),
            masks,
            wrong,
        )
        .await;
    }
}

/// XHTTP over HTTP/3 with a `sudoku` UDP mask against an Xray server
/// applying the same mask: alone, and with the client's noise inside or
/// outside it. A client with another password carries nothing.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-sudoku-interop.sh"]
async fn sudoku_udp_xhttp_h3_alone_and_with_noise() {
    let checkout = resolve_xray_checkout();
    let h3 = || {
        StreamSecurity::Tls(TlsSettings {
            server_name: Some(TLS_SERVER_NAME.to_owned()),
            fingerprint: Some("chrome".to_owned()),
            allow_insecure: true,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: vec!["h3".to_owned()],
        })
    };
    let mask = |password: &str| json!({"type":"sudoku","settings":{"password":password,"paddingMin":5,"paddingMax":25}});
    let noise = json!({"type":"noise","settings":{"noise":[
        {"type":"str","packet":"synthetic-noise","delay":2}]}});
    let client = |masks: Value, server: SocketAddr| {
        let mut config = rust_xhttp_core_config(server, h3(), XhttpMode::StreamOne);
        let raw = json!({"outbounds":[{"protocol":"freedom","streamSettings":{
            "network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"example.com","alpn":["h3"]},
            "finalmask":{"udp":masks}}}]});
        let parsed = parse_xray_json(&raw.to_string()).unwrap().config.outbounds[0]
            .stream
            .clone();
        config.outbounds[0].stream.udp_sudoku = parsed.udp_sudoku;
        config.outbounds[0].stream.udp_noise = parsed.udp_noise;
        config
    };
    let server = || {
        start_xray_vless_server_customized(
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
                    json!({"udp":[mask("synthetic-sudoku")]});
            },
        )
    };
    for (order, masks) in [
        ("alone", json!([mask("synthetic-sudoku")])),
        ("noise-inner", json!([noise, mask("synthetic-sudoku")])),
        ("noise-outer", json!([mask("synthetic-sudoku"), noise])),
    ] {
        eprintln!("XHTTP H3 sudoku {order}");
        let xray = timeout(Duration::from_secs(60), server()).await.unwrap();
        let config = client(masks, xray.addr);
        timeout(
            Duration::from_secs(90),
            run_local_xray_xhttp_interop_scenario(xray, config, XhttpMode::StreamOne),
        )
        .await
        .unwrap();
    }
    eprintln!("XHTTP H3 sudoku with another password");
    let xray = timeout(Duration::from_secs(60), server()).await.unwrap();
    let config = client(json!([mask("another-password")]), xray.addr);
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
    let (echo_addr, _echo) = spawn_echo_server().await;
    let attempt = async {
        let mut stream = TcpStream::connect(socks_addr).await.ok()?;
        socks5_connect(&mut stream, echo_addr).await.ok()?;
        stream.write_all(b"ping").await.ok()?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.ok()?;
        Some(reply)
    };
    let result = timeout(Duration::from_secs(4), attempt).await;
    assert!(
        !matches!(result, Ok(Some(_))),
        "another password carried data"
    );
    drop(core);
    drop(xray);
}
