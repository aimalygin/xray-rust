//! mKCP against Xray-core v26.10.31's own mKCP inbound: each protocol over
//! it, plain and under TLS, each `mkcp-legacy` mask, noise, Mux and Vision.
use super::proxy_carriers::{certificate_pin, proxy_inbound, PASS, USER};
use super::v08_carriers::{exercise, inbound, settings};
use super::*;
use serde_json::{json, Value};

fn profile(protocol: &str, port: u16, stream: &Value) -> Value {
    let settings = match protocol {
        "vless" => json!({"vnext":[{"address":"upload.test","port":port,
            "users":[{"id":TEST_UUID,"encryption":"none"}]}]}),
        "http" => json!({"address":"upload.test","port":port,"user":USER,"pass":PASS}),
        _ => settings(protocol, port),
    };
    json!({"inbounds":[{"protocol":"socks","tag":"socks-in","listen":"127.0.0.1","port":0,"settings":{"udp":true}}],
        "outbounds":[{"tag":"proxy","protocol":protocol,"settings":settings,"streamSettings":stream}]})
}

/// An Xray-core mKCP server for `protocol` with these `finalmask.udp` masks.
async fn start_server(
    checkout: &Path,
    protocol: &str,
    security: XrayInboundSecurity,
    masks: &Value,
    flow: Option<&'static str>,
) -> XrayServer {
    start_xray_vless_server_customized(
        checkout,
        XrayVlessServerConfig {
            security,
            transport: XrayInboundTransport::Kcp,
            flow,
        },
        |config| {
            match protocol {
                "vless" => {}
                "http" => proxy_inbound(config, protocol),
                _ => inbound(config, protocol),
            }
            // Its native UDP would need the port mKCP listens on.
            if protocol == "shadowsocks" {
                config["inbounds"][0]["settings"]["network"] = "tcp".into();
            }
            config["inbounds"][0]["streamSettings"]["finalmask"] = json!({"udp": masks});
        },
    )
    .await
}

async fn check(server: &XrayServer, config: Value, datagram: bool, case: &str) {
    eprintln!("mKCP {case}");
    let result = timeout(Duration::from_secs(60), exercise(config, datagram)).await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{case}: {result:?}; {}",
        server.logs()
    );
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-kcp-interop.sh"]
async fn kcp_carries_each_protocol_plain_and_under_tls() {
    let checkout = resolve_xray_checkout();
    // Not SOCKS: Xray-core's SOCKS inbound panics over mKCP, taking its local
    // address for a TCP one (`proxy/socks/server.go:112`).
    for protocol in ["vless", "vmess", "trojan", "shadowsocks", "http"] {
        for security in [XrayInboundSecurity::None, XrayInboundSecurity::Tls] {
            let server = start_server(&checkout, protocol, security, &json!([]), None).await;
            let mut stream = json!({"network":"kcp"});
            if security == XrayInboundSecurity::Tls {
                stream["security"] = "tls".into();
                stream["tlsSettings"] = json!({"serverName":TLS_SERVER_NAME,
                    "pinnedPeerCertSha256":certificate_pin(&server)});
            }
            // Shadowsocks sends datagrams outside the stream; HTTP has none.
            let datagram = !matches!(protocol, "shadowsocks" | "http");
            let config = profile(protocol, server.addr.port(), &stream);
            check(
                &server,
                config,
                datagram,
                &format!("{protocol} {security:?}"),
            )
            .await;
        }
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-kcp-interop.sh"]
async fn kcp_masks_match_xrays_on_the_wire() {
    let checkout = resolve_xray_checkout();
    let legacy = |settings: Value| json!({"type":"mkcp-legacy","settings":settings});
    let cases = [
        ("original", json!([legacy(json!({}))])),
        ("aes", json!([legacy(json!({"value":"kcp-seed"}))])),
        (
            "aes under wechat",
            json!([
                legacy(json!({"value":"kcp-seed"})),
                legacy(json!({"header":"wechat"}))
            ]),
        ),
        (
            "dns",
            json!([legacy(json!({"header":"dns","value":"kcp.example"}))]),
        ),
        (
            "dtls srtp utp wireguard",
            json!([
                legacy(json!({"header":"dtls"})),
                legacy(json!({"header":"srtp"})),
                legacy(json!({"header":"utp"})),
                legacy(json!({"header":"wireguard"})),
            ]),
        ),
        (
            "noise between masks",
            json!([
                legacy(json!({})),
                {"type":"noise","settings":{"noise":[{"type":"str","packet":"hello","delay":"5-10"},{"rand":"10-20"}]}},
                legacy(json!({"header":"srtp"})),
            ]),
        ),
    ];
    for (case, masks) in cases {
        let server =
            start_server(&checkout, "vless", XrayInboundSecurity::None, &masks, None).await;
        let stream = json!({"network":"kcp","finalmask":{"udp":masks}});
        check(
            &server,
            profile("vless", server.addr.port(), &stream),
            true,
            case,
        )
        .await;
    }
    // A mismatched seed never connects.
    let server = start_server(
        &checkout,
        "vless",
        XrayInboundSecurity::None,
        &json!([legacy(json!({"value":"kcp-seed"}))]),
        None,
    )
    .await;
    let stream = json!({"network":"kcp","finalmask":{"udp":[legacy(json!({"value":"other"}))]}});
    let result = timeout(
        Duration::from_secs(20),
        exercise(profile("vless", server.addr.port(), &stream), false),
    )
    .await;
    assert!(!matches!(result, Ok(Ok(()))), "a wrong seed connected");
}

/// Salamander on mKCP, a header mask Xray-core groups with mkcp-legacy's:
/// alone, inside a header group split by noise, and with noise inside it.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-kcp-interop.sh"]
async fn kcp_salamander_alone_and_among_header_masks() {
    let checkout = resolve_xray_checkout();
    let legacy = |settings: Value| json!({"type":"mkcp-legacy","settings":settings});
    let salamander = |password: &str| json!({"type":"salamander","settings":{"password":password}});
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"hello","delay":"5-10"},{"rand":"10-20"}]}});
    let cases = [
        ("salamander", json!([salamander("kcp-salamander")])),
        (
            "wechat and salamander, noise, srtp",
            json!([
                legacy(json!({"header":"wechat"})),
                salamander("kcp-salamander"),
                noise.clone(),
                legacy(json!({"header":"srtp"})),
            ]),
        ),
        (
            "noise inside salamander, aes inside both",
            json!([
                legacy(json!({"value":"kcp-seed"})),
                noise,
                salamander("kcp-salamander"),
            ]),
        ),
    ];
    for (case, masks) in cases {
        let server =
            start_server(&checkout, "vless", XrayInboundSecurity::None, &masks, None).await;
        let stream = json!({"network":"kcp","finalmask":{"udp":masks}});
        check(
            &server,
            profile("vless", server.addr.port(), &stream),
            true,
            case,
        )
        .await;
    }
    // Another password never connects.
    let server = start_server(
        &checkout,
        "vless",
        XrayInboundSecurity::None,
        &json!([salamander("kcp-salamander")]),
        None,
    )
    .await;
    let stream = json!({"network":"kcp","finalmask":{"udp":[salamander("another-password")]}});
    let result = timeout(
        Duration::from_secs(20),
        exercise(profile("vless", server.addr.port(), &stream), false),
    )
    .await;
    assert!(!matches!(result, Ok(Ok(()))), "a wrong password connected");
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-kcp-interop.sh"]
async fn kcp_carries_mux_and_vision() {
    let checkout = resolve_xray_checkout();
    let server = start_server(
        &checkout,
        "vless",
        XrayInboundSecurity::None,
        &json!([]),
        None,
    )
    .await;
    let mut config = profile("vless", server.addr.port(), &json!({"network":"kcp"}));
    config["outbounds"][0]["mux"] = json!({"enabled":true,"concurrency":4,"xudpConcurrency":4});
    check(&server, config, true, "vless Mux and XUDP").await;
    let server = start_server(
        &checkout,
        "vless",
        XrayInboundSecurity::Tls,
        &json!([]),
        Some("xtls-rprx-vision"),
    )
    .await;
    let stream = json!({"network":"kcp","security":"tls","tlsSettings":{"serverName":TLS_SERVER_NAME,
        "pinnedPeerCertSha256":certificate_pin(&server)}});
    let mut config = profile("vless", server.addr.port(), &stream);
    config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] = "xtls-rprx-vision".into();
    check(&server, config, true, "vless Vision under TLS").await;
}

/// Vision switches to direct mode over mKCP's TLS as it does over raw TLS:
/// inner TLS rounds, then a bulk round across many inner records.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-kcp-interop.sh"]
async fn kcp_vision_switches_to_direct_mode_under_inner_tls() {
    let checkout = resolve_xray_checkout();
    let xray = start_xray_vless_server(
        &checkout,
        XrayVlessServerConfig {
            security: XrayInboundSecurity::Tls,
            transport: XrayInboundTransport::Kcp,
            flow: Some("xtls-rprx-vision"),
        },
    )
    .await;
    let (mut config, dialer) = rust_tls_core_config_and_dialer(&xray, Some("xtls-rprx-vision"));
    config.outbounds[0].stream.transport =
        StreamTransport::Kcp(xray_config::KcpSettings::default());
    run_inner_tls_interop_scenario(xray, config, Some(dialer)).await;
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-header-custom-interop.sh"]
async fn kcp_header_custom_udp_modes_and_mask_order() {
    let checkout = resolve_xray_checkout();
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"noise","delay":"1-2"}]}});
    let legacy = json!({"type":"mkcp-legacy","settings":{"value":"header-udp-seed"}});
    for mode in ["prefix", "standalone"] {
        let header = json!({"type":"header-custom","settings":{"mode":mode,
            "client":[{"rand":8,"capture":"token"},{"type":"str","packet":"hello"}],
            "server":[{"reuse":"token"},{"transform":{"op":"be16","args":[{"u64":443}]}}]}});
        for (order, masks) in [
            ("plain", json!([header])),
            ("noise-inner", json!([noise, header, legacy])),
            ("noise-outer", json!([legacy, header, noise])),
        ] {
            let server =
                start_server(&checkout, "vless", XrayInboundSecurity::None, &masks, None).await;
            let stream = json!({"network":"kcp","finalmask":{"udp":masks}});
            check(
                &server,
                profile("vless", server.addr.port(), &stream),
                true,
                &format!("header-custom {mode} {order}"),
            )
            .await;
        }
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-sudoku-interop.sh"]
async fn kcp_sudoku_alone_and_among_other_masks() {
    let checkout = resolve_xray_checkout();
    let sudoku = |password: &str| json!({"type":"sudoku","settings":{"password":password,"paddingMin":5,"paddingMax":20}});
    let noise = json!({"type":"noise","settings":{"noise":[{"type":"str","packet":"noise","delay":"1-2"}]}});
    let legacy = json!({"type":"mkcp-legacy","settings":{"value":"sudoku-udp-seed"}});
    // A legacy mask outside sudoku would drop every segment: it takes at
    // most 4096 bytes, and sudoku makes mKCP's 1350 at least four times
    // that, in Xray-core as here.
    for (order, masks) in [
        ("alone", json!([sudoku("synthetic-sudoku")])),
        ("noise-inner", json!([noise, sudoku("synthetic-sudoku")])),
        (
            "legacy-inner",
            json!([legacy, sudoku("synthetic-sudoku"), noise]),
        ),
    ] {
        let server =
            start_server(&checkout, "vless", XrayInboundSecurity::None, &masks, None).await;
        let stream = json!({"network":"kcp","finalmask":{"udp":masks}});
        check(
            &server,
            profile("vless", server.addr.port(), &stream),
            true,
            &format!("sudoku {order}"),
        )
        .await;
    }
}
