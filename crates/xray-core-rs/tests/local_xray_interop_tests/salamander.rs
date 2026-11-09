//! The `salamander` UDP mask, Gecko's fragments with it, against Xray-core
//! v26.10.31's own XHTTP-over-HTTP/3 server applying the same mask.
use super::*;
use serde_json::{json, Value};

/// XHTTP over HTTP/3 under Salamander: alone, with Gecko's fragments, and
/// with the client's noise inside or outside it. Another password carries
/// nothing.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-hysteria-interop.sh"]
async fn xhttp_h3_salamander_and_gecko() {
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
    let salamander = |password: &str, packet_size: Option<&str>| {
        let mut mask = json!({"type":"salamander","settings":{"password":password}});
        if let Some(size) = packet_size {
            mask["settings"]["packetSize"] = json!(size);
        }
        mask
    };
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
        config.outbounds[0].stream.udp_salamander = parsed.udp_salamander;
        config.outbounds[0].stream.udp_noise = parsed.udp_noise;
        config
    };
    let server = |mask: Value| {
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
            move |json| {
                json["inbounds"][0]["streamSettings"]["finalmask"] = json!({"udp":[mask]});
            },
        )
    };
    let plain = salamander("synthetic-salamander", None);
    let gecko = salamander("synthetic-salamander", Some("512-1200"));
    for (case, server_mask, client_masks) in [
        ("alone", plain.clone(), json!([plain.clone()])),
        ("gecko", gecko.clone(), json!([gecko])),
        (
            "noise inside",
            plain.clone(),
            json!([noise.clone(), plain.clone()]),
        ),
        (
            "noise outside",
            plain.clone(),
            json!([plain.clone(), noise]),
        ),
    ] {
        eprintln!("XHTTP H3 salamander {case}");
        let xray = timeout(Duration::from_secs(60), server(server_mask))
            .await
            .unwrap();
        let config = client(client_masks, xray.addr);
        timeout(
            Duration::from_secs(90),
            run_local_xray_xhttp_interop_scenario(xray, config, XhttpMode::StreamOne),
        )
        .await
        .unwrap();
    }
    eprintln!("XHTTP H3 salamander with another password");
    let xray = timeout(Duration::from_secs(60), server(plain))
        .await
        .unwrap();
    let config = client(json!([salamander("another-password", None)]), xray.addr);
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
