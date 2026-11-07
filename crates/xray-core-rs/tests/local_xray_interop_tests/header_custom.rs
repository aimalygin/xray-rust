//! The `header-custom` TCP mask against Xray-core v26.10.31's own server: the
//! handshake before every TCP carrier, on raw (plain and TLS), WebSocket,
//! HTTPUpgrade, gRPC and XHTTP. Not REALITY: Xray-core's REALITY server
//! panics on a `header-custom` connection, which lacks the `CloseWrite` it
//! asserts (`reality@v0.0.0-20261014101318-83f621788ca8/tls.go:187`).
use super::proxy_carriers::certificate_pin;
use super::v08_carriers::exercise;
use super::*;
use serde_json::{json, Value};

/// Two rounds: the client sends a greeting, eight random bytes it keeps, the
/// server's port, then after a pause a packed number; the server echoes the
/// random bytes and says OK. Each side reads its own addresses, so the
/// server checks its local port where the client sent its remote one.
fn header(server: bool) -> Value {
    let port = if server { "local_port" } else { "remote_port" };
    json!({
        "clients": [
            [{"type": "str", "packet": "HELLO"}, {"rand": 8, "randRange": "65-90", "capture": "nonce"},
             {"transform": {"op": "be16", "args": [{"metadata": port}]}}],
            [{"delay": "10-20", "transform": {"op": "le32", "args": [{"u64": 123_456}]}}]
        ],
        "servers": [[{"reuse": "nonce"}, {"type": "str", "packet": "OK"}]]
    })
}

fn profile(port: u16, mut stream: Value, header: Value) -> Value {
    stream["finalmask"] = json!({"tcp": [{"type": "header-custom", "settings": header}]});
    json!({"inbounds":[{"protocol":"socks","tag":"socks-in","listen":"127.0.0.1","port":0,"settings":{"udp":true}}],
        "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"upload.test","port":port,
            "users":[{"id":TEST_UUID,"encryption":"none"}]}]},"streamSettings":stream}]})
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-header-custom-interop.sh"]
async fn header_custom_runs_before_every_tcp_carrier() {
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
            XrayInboundTransport::WebSocket { path: "/hc" },
            json!({"network":"ws","wsSettings":{"path":"/hc"}}),
        ),
        (
            "HTTPUpgrade TLS",
            XrayInboundSecurity::Tls,
            XrayInboundTransport::HttpUpgrade { path: "/hc" },
            json!({"network":"httpupgrade","httpupgradeSettings":{"path":"/hc"}}),
        ),
        (
            "gRPC TLS",
            XrayInboundSecurity::Tls,
            XrayInboundTransport::Grpc { service_name: "hc" },
            json!({"network":"grpc","grpcSettings":{"serviceName":"hc"}}),
        ),
        (
            "XHTTP",
            XrayInboundSecurity::None,
            XrayInboundTransport::Xhttp {
                path: "/hc/",
                mode: "auto",
                tls_alpn: None,
            },
            json!({"network":"xhttp","xhttpSettings":{"path":"/hc/","mode":"packet-up","xPaddingBytes":64,
                "scMaxEachPostBytes":4096,"scMinPostsIntervalMs":1}}),
        ),
    ];
    for (name, security, transport, mut stream) in cases {
        let server = start_xray_vless_server_customized(
            &checkout,
            XrayVlessServerConfig {
                security,
                transport,
                flow: None,
            },
            |config| {
                config["log"]["loglevel"] = "debug".into();
                config["inbounds"][0]["streamSettings"]["finalmask"] =
                    json!({"tcp": [{"type": "header-custom", "settings": header(true)}]});
            },
        )
        .await;
        if security == XrayInboundSecurity::Tls {
            stream["security"] = "tls".into();
            stream["tlsSettings"] = json!({"serverName":TLS_SERVER_NAME,
                "pinnedPeerCertSha256":certificate_pin(&server)});
        }
        eprintln!("header-custom over {name}");
        let result = timeout(
            Duration::from_secs(60),
            exercise(
                profile(server.addr.port(), stream.clone(), header(false)),
                true,
            ),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "{name}: {result:?}; {}",
            server.logs()
        );
        // A greeting the server does not expect never gets through.
        let mut wrong = header(false);
        wrong["clients"][0][0]["packet"] = "HOWDY".into();
        let refused = timeout(
            Duration::from_secs(20),
            exercise(profile(server.addr.port(), stream, wrong), false),
        )
        .await;
        assert!(
            !matches!(refused, Ok(Ok(()))),
            "{name}: a wrong greeting got through"
        );
    }
}
