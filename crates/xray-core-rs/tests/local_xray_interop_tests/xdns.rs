//! The `xdns` UDP mask against Xray-core v26.10.31's own server, which
//! answers as the domain's DNS server: mKCP and XHTTP over HTTP/3, through
//! UDP and TCP resolvers, with every record type and with masks inside it.
use super::v08_carriers::exercise;
use super::*;
use serde_json::{json, Value};
use tokio::net::UdpSocket;

const DOMAIN: &str = "t.example.com";

fn xdns(resolvers: &[String], extra: Value) -> Value {
    let mut settings = json!({
        "domains": [{"names": [DOMAIN], "types": [1, 5, 16, 28], "edns0": 4096}],
        "resolvers": [{"addrs": resolvers}],
    });
    for (key, value) in extra.as_object().into_iter().flatten() {
        settings[key] = value.clone();
    }
    json!({"type": "xdns", "settings": settings})
}

/// The server's side: it answers for the domain and never reads the
/// resolvers.
fn server_xdns() -> Value {
    json!({"type": "xdns", "settings": {"domains": [{"names": [DOMAIN], "edns0": 4096}]}})
}

fn profile(port: u16, masks: Value) -> Value {
    json!({"inbounds":[{"protocol":"socks","tag":"socks-in","listen":"127.0.0.1","port":0,"settings":{"udp":true}}],
        "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":port,
            "users":[{"id":TEST_UUID,"encryption":"none"}]}]},
            "streamSettings":{"network":"kcp","finalmask":{"udp":masks}}}]})
}

async fn kcp_server(checkout: &Path, masks: Value) -> XrayServer {
    start_xray_vless_server_customized(
        checkout,
        XrayVlessServerConfig {
            security: XrayInboundSecurity::None,
            transport: XrayInboundTransport::Kcp,
            flow: None,
        },
        |config| {
            config["inbounds"][0]["streamSettings"]["finalmask"] = json!({"udp": masks});
        },
    )
    .await
}

struct Task(tokio::task::JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A DNS server over TCP that relays each message to `upstream` over UDP
/// and frames its answers back, as a recursive resolver would.
async fn tcp_relay(upstream: SocketAddr) -> (SocketAddr, Task) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                socket.connect(upstream).await.unwrap();
                let (mut reader, mut writer) = stream.into_split();
                let socket = Arc::new(socket);
                let receiving = socket.clone();
                let answers = tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    while let Ok(length) = receiving.recv(&mut buf).await {
                        if writer.write_u16(length as u16).await.is_err()
                            || writer.write_all(&buf[..length]).await.is_err()
                        {
                            return;
                        }
                    }
                });
                while let Ok(length) = reader.read_u16().await {
                    let mut query = vec![0u8; usize::from(length)];
                    if reader.read_exact(&mut query).await.is_err() {
                        break;
                    }
                    let _ = socket.send(&query).await;
                }
                answers.abort();
            });
        }
    }));
    (address, task)
}

async fn check(server: &XrayServer, config: Value, case: &str) {
    eprintln!("xdns {case}");
    let result = timeout(Duration::from_secs(90), exercise(config, true)).await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{case}: {result:?}; {}",
        server.logs()
    );
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdns-interop.sh"]
async fn xdns_carries_mkcp_through_udp_and_tcp_resolvers() {
    let checkout = resolve_xray_checkout();
    let server = kcp_server(&checkout, json!([server_xdns()])).await;
    let port = server.addr.port();
    let udp = format!("127.0.0.1:{port}");
    check(
        &server,
        profile(port, json!([xdns(std::slice::from_ref(&udp), json!({}))])),
        "mKCP, UDP resolver",
    )
    .await;
    check(
        &server,
        profile(
            port,
            json!([xdns(&[format!("udp://{udp}")], json!({"extraPoll": 2}))]),
        ),
        "mKCP, UDP resolver, two extra polls",
    )
    .await;
    let (relay, _relay) = tcp_relay(server.addr).await;
    check(
        &server,
        profile(port, json!([xdns(&[format!("tcp://{relay}")], json!({}))])),
        "mKCP, TCP resolver",
    )
    .await;
    // Two resolvers share the queries.
    check(
        &server,
        profile(
            port,
            json!([xdns(&[udp.clone(), format!("tcp://{relay}")], json!({}))]),
        ),
        "mKCP, UDP and TCP resolvers",
    )
    .await;
    // A domain the server does not answer for carries nothing.
    let mut wrong = xdns(&[udp], json!({}));
    wrong["settings"]["domains"][0]["names"] = json!(["u.example.com"]);
    let refused = timeout(
        Duration::from_secs(20),
        exercise(profile(port, json!([wrong])), false),
    )
    .await;
    assert!(!matches!(refused, Ok(Ok(()))), "another domain got through");
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdns-interop.sh"]
async fn xdns_carries_mkcp_masks_inside_it() {
    let checkout = resolve_xray_checkout();
    let legacy = json!({"type":"mkcp-legacy","settings":{"value":"kcp-seed"}});
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"hello","delay":"5-10"}]}});
    for (case, inner) in [("aes", vec![legacy]), ("noise", vec![noise])] {
        let mut server_masks = inner.clone();
        server_masks.push(server_xdns());
        let server = kcp_server(&checkout, Value::Array(server_masks)).await;
        let port = server.addr.port();
        let mut masks = inner;
        masks.push(xdns(&[format!("127.0.0.1:{port}")], json!({})));
        check(&server, profile(port, Value::Array(masks)), case).await;
    }
}

/// XHTTP over HTTP/3 through xdns. Every QUIC packet is fragmented over
/// several queries, and the answers carry whole packets.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdns-interop.sh"]
async fn xdns_carries_xhttp_h3() {
    let checkout = resolve_xray_checkout();
    let xray = timeout(
        Duration::from_secs(60),
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
                json["inbounds"][0]["streamSettings"]["finalmask"] = json!({"udp":[server_xdns()]});
            },
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
        "finalmask":{"udp":[xdns(&[xray.addr.to_string()], json!({}))]}}}]});
    config.outbounds[0].stream.udp_xdns =
        parse_xray_json(&raw.to_string()).unwrap().config.outbounds[0]
            .stream
            .udp_xdns
            .clone();
    // Xray-core's server drops a downlink packet that does not fit the answer
    // to the query it meets, and an A answer holds at most 764 bytes, short
    // of a full QUIC packet. QUIC resends it through the polls, whose delay
    // doubles from half a second, so the echo can stall for over a second
    // once the upload is handed over. The one-second half-close timers, as
    // in Xray-core, then close the flow mid-echo: about one run in ten.
    config.policy.levels.insert(
        0,
        xray_config::PolicyLevelConfig {
            uplink_only: Some(30),
            downlink_only: Some(30),
            ..Default::default()
        },
    );
    timeout(
        Duration::from_secs(120),
        run_local_xray_xhttp_interop_scenario(xray, config, XhttpMode::StreamOne),
    )
    .await
    .unwrap();
}
