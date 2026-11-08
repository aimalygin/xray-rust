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
