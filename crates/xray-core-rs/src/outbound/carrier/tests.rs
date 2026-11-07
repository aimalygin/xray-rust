//! The `header-custom` TCP handshake, from parsed config to the wire, against
//! what Xray-core's own client and server sent for the same configs
//! (`tools/header-custom-oracle`).
use super::*;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/header-custom/tcp-vectors.json"
    ))
    .unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The `header-custom` settings as our parser reads them.
fn parse(settings: &Value) -> Result<xray_config::HeaderCustomTcp, Vec<String>> {
    let config = json!({"outbounds": [{"protocol": "vless",
        "settings": {"vnext": [{"address": "server.example", "port": 443,
            "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]},
        "streamSettings": {"security": "tls", "tlsSettings": {"serverName": "server.example"},
            "finalmask": {"tcp": [{"type": "header-custom", "settings": settings}]}}}]});
    xray_config::parse_xray_json(&config.to_string())
        .map(|parsed| {
            parsed.config.outbounds[0]
                .stream
                .tcp_header_custom
                .clone()
                .unwrap()
        })
        .map_err(|error| {
            error
                .diagnostics
                .into_iter()
                .map(|diagnostic| diagnostic.message)
                .collect()
        })
}

#[tokio::test]
async fn every_handshake_matches_xrays_bytes_and_outcome() {
    let local = SocketAddr::from(([192, 0, 2, 10], 40000));
    let remote = SocketAddr::from(([198, 51, 100, 20], 443));
    for case in vectors().as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let parsed = parse(&case["client"]);
        if let Some(error) = case["buildError"].as_str() {
            assert!(parsed.is_err(), "{name}: Xray refused it with {error}");
            continue;
        }
        let config = header_custom_config(Some(&parsed.unwrap())).unwrap();
        // The client reads exactly what each server sequence measures, so the
        // server's bytes can all be waiting from the start.
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        server
            .write_all(&hex(case["serverToClient"].as_str().unwrap()))
            .await
            .unwrap();
        // Then nothing more, as when Xray's server gives up.
        server.shutdown().await.unwrap();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            xray_transport::header_custom::client_handshake(
                &mut client,
                &config,
                Some(local),
                Some(remote),
            ),
        )
        .await;
        let ok = matches!(outcome, Ok(Ok(())));
        drop(client);
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).await.unwrap();
        assert_eq!(
            ok,
            case["clientOk"].as_bool().unwrap(),
            "{name}: {outcome:?}"
        );
        assert_eq!(
            sent,
            hex(case["clientToServer"].as_str().unwrap()),
            "{name}"
        );
    }
}

#[test]
fn every_config_xray_refuses_is_refused() {
    for case in vectors().as_array().unwrap() {
        if case["buildError"].is_string() {
            assert!(parse(&case["client"]).is_err(), "{}", case["name"]);
        }
    }
}

fn vless(stream: Value) -> xray_config::OutboundConfig {
    xray_config::parse_xray_json(
        &json!({"outbounds": [{"protocol": "vless",
            "settings": {"vnext": [{"address": "server.example", "port": 443,
                "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]},
            "streamSettings": stream}]})
        .to_string(),
    )
    .unwrap()
    .config
    .outbounds
    .remove(0)
}

fn with_header(mut stream: Value) -> Value {
    stream["finalmask"]["tcp"] = json!([{"type": "header-custom",
        "settings": {"clients": [[{"packet": [1]}]]}}]);
    stream
}

#[test]
fn tcp_carriers_take_the_handshake_and_udp_ones_do_not() {
    let tls = json!({"serverName": "server.example"});
    for stream in [
        json!({"security": "tls", "tlsSettings": tls}),
        json!({"network": "ws", "security": "tls", "tlsSettings": tls}),
        json!({"network": "grpc", "security": "tls", "tlsSettings": tls}),
        json!({"network": "xhttp", "security": "tls", "tlsSettings": tls}),
    ] {
        let built =
            super::super::build_vless_tcp_outbound(&vless(with_header(stream.clone()))).unwrap();
        assert!(built.payload.carrier.header_custom.is_some(), "{stream}");
    }
    for stream in [
        json!({"network": "kcp", "security": "tls", "tlsSettings": tls}),
        json!({"network": "xhttp", "security": "tls",
            "tlsSettings": {"serverName": "server.example", "alpn": ["h3"]}}),
        json!({"network": "xhttp", "security": "tls", "tlsSettings": tls,
            "xhttpSettings": {"downloadSettings": {"address": "down.example", "port": 443,
                "network": "xhttp", "security": "tls", "tlsSettings": tls}}}),
    ] {
        assert!(
            matches!(
                super::super::build_vless_tcp_outbound(&vless(with_header(stream.clone()))),
                Err(CoreError::UnsupportedOutboundNetwork)
            ),
            "{stream}"
        );
    }
}

#[test]
fn direct_and_dns_dials_take_no_handshake() {
    for outbound in [
        json!({"protocol": "freedom", "streamSettings": with_header(json!({}))}),
        json!({"protocol": "dns", "streamSettings": with_header(json!({}))}),
    ] {
        let config =
            xray_config::parse_xray_json(&json!({"outbounds": [outbound.clone()]}).to_string())
                .unwrap()
                .config;
        assert!(
            matches!(
                crate::Core::new(config),
                Err(CoreError::UnsupportedOutboundNetwork)
            ),
            "{outbound}"
        );
    }
}
