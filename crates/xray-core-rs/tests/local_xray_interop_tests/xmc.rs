//! The `xmc` TCP mask against Xray-core v26.10.31's own server: raw (plain
//! and TLS), WebSocket, HTTPUpgrade, gRPC and XHTTP, and around a
//! `header-custom` handshake. Not REALITY: its server panics on every
//! connection through xmc, whose server connection cannot half-close.
use super::proxy_carriers::certificate_pin;
use super::v08_carriers::exercise;
use super::*;
use serde_json::{json, Value};

const PASSWORD: &str = "synthetic-xmc-password";

fn player(username: &str, uuid: &str) -> Value {
    json!({"username": username, "uuid": uuid,
        "texturesValue": format!("synthetic-textures-of-{username}"),
        "texturesSignature": format!("synthetic-signature-of-{username}")})
}

/// The profiles the server holds; the client picks one per connection.
fn players() -> Value {
    json!([
        player("Steve", "8667ba71-b85a-4004-af54-457a9734eed7"),
        player("Alex_2", "ec561538f3fd461daff5086b22154bce"),
    ])
}

fn xmc(password: &str, profiles: Value) -> Value {
    json!({"type": "xmc", "settings": {"hostname": "mc.example.com",
        "password": password, "profiles": profiles}})
}

/// What another client sends: another password, whose key the client
/// refuses, or a profile the server does not hold, which it refuses.
fn strangers() -> [Value; 2] {
    [
        xmc("another-password", players()),
        xmc(
            PASSWORD,
            json!([player("Herobrine", "00000000-0000-0000-0000-000000000001")]),
        ),
    ]
}

fn profile(port: u16, mut stream: Value, masks: Value) -> Value {
    stream["finalmask"] = json!({"tcp": masks});
    json!({"inbounds":[{"protocol":"socks","tag":"socks-in","listen":"127.0.0.1","port":0,"settings":{"udp":true}}],
        "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"upload.test","port":port,
            "users":[{"id":TEST_UUID,"encryption":"none"}]}]},"streamSettings":stream}]})
}

/// Carries a TCP echo and UDP through Xray's server with `masks`, and
/// checks that no stranger gets through.
async fn check(
    checkout: &Path,
    name: &str,
    security: XrayInboundSecurity,
    transport: XrayInboundTransport,
    mut stream: Value,
    masks: Value,
    wrong: [Value; 2],
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
    if matches!(security, XrayInboundSecurity::Tls) {
        stream["security"] = "tls".into();
        stream["tlsSettings"] = json!({"serverName":TLS_SERVER_NAME,
            "pinnedPeerCertSha256":certificate_pin(&server)});
    }
    eprintln!("xmc over {name}");
    let result = timeout(
        Duration::from_secs(90),
        exercise(profile(server.addr.port(), stream.clone(), masks), true),
    )
    .await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{name}: {result:?}; {}",
        server.logs()
    );
    for masks in wrong {
        let refused = timeout(
            Duration::from_secs(30),
            exercise(
                profile(server.addr.port(), stream.clone(), masks.clone()),
                false,
            ),
        )
        .await;
        assert!(
            !matches!(refused, Ok(Ok(()))),
            "{name}: {masks} got through"
        );
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xmc-interop.sh"]
async fn xmc_wraps_every_tcp_carrier() {
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
            "WebSocket",
            XrayInboundSecurity::None,
            XrayInboundTransport::WebSocket { path: "/mc" },
            json!({"network":"ws","wsSettings":{"path":"/mc"}}),
        ),
        (
            "HTTPUpgrade TLS",
            XrayInboundSecurity::Tls,
            XrayInboundTransport::HttpUpgrade { path: "/mc" },
            json!({"network":"httpupgrade","httpupgradeSettings":{"path":"/mc"}}),
        ),
        (
            "gRPC TLS",
            XrayInboundSecurity::Tls,
            XrayInboundTransport::Grpc { service_name: "mc" },
            json!({"network":"grpc","grpcSettings":{"serviceName":"mc"}}),
        ),
        (
            "XHTTP",
            XrayInboundSecurity::None,
            XrayInboundTransport::Xhttp {
                path: "/mc/",
                mode: "auto",
                tls_alpn: None,
            },
            json!({"network":"xhttp","xhttpSettings":{"path":"/mc/","mode":"packet-up","xPaddingBytes":64,
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
            json!([xmc(PASSWORD, players())]),
            strangers().map(|mask| json!([mask])),
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xmc-interop.sh"]
async fn xmc_carries_a_header_custom_handshake() {
    let checkout = resolve_xray_checkout();
    let header = json!({"type": "header-custom", "settings": {
        "clients": [[{"type": "str", "packet": "HELLO"}]],
        "servers": [[{"type": "str", "packet": "OK"}]]}});
    let [another_password, unknown_profile] = strangers();
    check(
        &checkout,
        "header-custom then xmc",
        XrayInboundSecurity::Tls,
        XrayInboundTransport::Raw,
        json!({"network":"raw"}),
        json!([header, xmc(PASSWORD, players())]),
        [
            json!([header, another_password]),
            json!([header, unknown_profile]),
        ],
    )
    .await;
}
