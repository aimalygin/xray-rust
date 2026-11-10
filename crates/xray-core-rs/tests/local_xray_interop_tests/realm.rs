//! The `realm` UDP mask against Xray-core v26.10.31's own server. Both
//! sides find their addresses with a local STUN server; the server registers
//! with a local rendezvous speaking Hysteria's realm API, the client asks it
//! for an introduction, both punch, and mKCP or XHTTP over HTTP/3 runs over
//! the punched path.
use super::realm_rendezvous::{stun_server, Rendezvous};
use super::v08_carriers::exercise;
use super::*;
use serde_json::{json, Value};

const TOKEN: &str = "interop-token";

fn realm(rendezvous: &Rendezvous, name: &str, stun: SocketAddr, extra: Value) -> Value {
    let mut settings = json!({"url": rendezvous.url(name), "stunServers": [stun.to_string()]});
    for (key, value) in extra.as_object().into_iter().flatten() {
        settings[key] = value.clone();
    }
    json!({"type": "realm", "settings": settings})
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

async fn check(server: &XrayServer, config: Value, case: &str) {
    eprintln!("realm {case}");
    let result = timeout(Duration::from_secs(90), exercise(config, true)).await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{case}: {result:?}; {}",
        server.logs()
    );
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-realm-interop.sh"]
async fn realm_introduces_mkcp_to_xray() {
    let checkout = resolve_xray_checkout();
    let rendezvous = Rendezvous::start(TOKEN).await;
    let (stun, _stun) = stun_server().await;
    let name = "kcp-realm";
    let server = kcp_server(
        &checkout,
        json!([realm(&rendezvous, name, stun, json!({}))]),
    )
    .await;
    rendezvous.registered(name).await;
    let port = server.addr.port();
    // A dual-stack socket reaching the server's IPv4 address, then IPv4
    // alone.
    check(
        &server,
        profile(port, json!([realm(&rendezvous, name, stun, json!({}))])),
        "mKCP, dual",
    )
    .await;
    check(
        &server,
        profile(
            port,
            json!([realm(&rendezvous, name, stun, json!({"ipMode": "v4"}))]),
        ),
        "mKCP, v4",
    )
    .await;
    // The server's address in the outbound is never used: the punched one
    // is.
    check(
        &server,
        profile(
            allocate_loopback_udp_port(),
            json!([realm(&rendezvous, name, stun, json!({}))]),
        ),
        "mKCP, another server port",
    )
    .await;
    let introductions = rendezvous.connects();
    assert!(introductions >= 3, "{introductions}");
    // A name no server registered gets no introduction.
    let refused = timeout(
        Duration::from_secs(30),
        exercise(
            profile(
                port,
                json!([realm(&rendezvous, "unknown-realm", stun, json!({}))]),
            ),
            false,
        ),
    )
    .await;
    assert!(!matches!(refused, Ok(Ok(()))), "an unknown realm connected");
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-realm-interop.sh"]
async fn realm_carries_mkcp_masks_inside_it() {
    let checkout = resolve_xray_checkout();
    let rendezvous = Rendezvous::start(TOKEN).await;
    let (stun, _stun) = stun_server().await;
    let legacy = json!({"type":"mkcp-legacy","settings":{"value":"kcp-seed"}});
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"hello","delay":"5-10"}]}});
    for (case, inner) in [
        ("aes", vec![legacy.clone()]),
        ("aes and noise", vec![legacy, noise]),
    ] {
        let name = format!("kcp-{}", case.replace(' ', "-"));
        let mut server_masks = inner.clone();
        server_masks.push(realm(&rendezvous, &name, stun, json!({})));
        let server = kcp_server(&checkout, Value::Array(server_masks)).await;
        rendezvous.registered(&name).await;
        let mut masks = inner;
        masks.push(realm(&rendezvous, &name, stun, json!({})));
        check(
            &server,
            profile(server.addr.port(), Value::Array(masks)),
            case,
        )
        .await;
    }
}

/// XHTTP over HTTP/3: each QUIC connection's socket is introduced first.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-realm-interop.sh"]
async fn realm_introduces_xhttp_h3_to_xray() {
    let checkout = resolve_xray_checkout();
    let rendezvous = Rendezvous::start(TOKEN).await;
    let (stun, _stun) = stun_server().await;
    let name = "xhttp-realm";
    let server_realm = realm(&rendezvous, name, stun, json!({}));
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
                json["inbounds"][0]["streamSettings"]["finalmask"] = json!({"udp":[server_realm]});
            },
        ),
    )
    .await
    .unwrap();
    rendezvous.registered(name).await;
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
    // Read off a VLESS outbound: freedom would take the mask for its own
    // UDP flows, where realm is refused.
    let raw = json!({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1",
        "port":xray.addr.port(),"users":[{"id":TEST_UUID,"encryption":"none"}]}]},
        "streamSettings":{
        "network":"xhttp","security":"tls",
        "tlsSettings":{"serverName":"example.com","alpn":["h3"]},
        "finalmask":{"udp":[realm(&rendezvous, name, stun, json!({}))]}}}]});
    config.outbounds[0].stream.udp_realm =
        parse_xray_json(&raw.to_string()).unwrap().config.outbounds[0]
            .stream
            .udp_realm
            .clone();
    timeout(
        Duration::from_secs(120),
        run_local_xray_xhttp_interop_scenario(xray, config, XhttpMode::StreamOne),
    )
    .await
    .unwrap();
    assert!(rendezvous.connects() >= 1);
}
