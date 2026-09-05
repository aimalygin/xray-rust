use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_config::parse_xray_json;
use xray_core_rs::{
    open_vless_tcp_stream, open_vless_udp_stream_with_resolver_and_dialer, OutboundRouter,
    TcpOutbound, VlessUdpFraming,
};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_new_packet, read_udp_packet, read_xudp_packet,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{SystemDnsResolver, TransportDialer};

#[path = "../../../tools/vless-encryption-oracle/support.rs"]
mod support;
use support::Oracle;

#[tokio::test]
#[ignore = "requires the guarded pinned Go oracle; run scripts/check-vless-encryption-oracle.sh"]
async fn encrypted_vless_tcp_udp_and_xudp_use_runtime_outbound() {
    for outer_tls in [false, true] {
        for mode in ["native", "xorpub", "random"] {
            for application in ["vless", "udp", "xudp"] {
                let server_application = if outer_tls {
                    format!("tls:{application}")
                } else {
                    application.to_owned()
                };
                let oracle = Oracle::start(mode, "mlkem768", -1, &server_application);
                let mut raw = serde_json::json!({"outbounds": [{"protocol": "vless", "settings": {"vnext": [{
                    "address": oracle.address.ip().to_string(), "port": oracle.address.port(),
                    "users": [{"id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": oracle.encryption}]
                }]}}]});
                if outer_tls {
                    raw["outbounds"][0]["streamSettings"] = serde_json::json!({"network": "tcp", "security": "tls", "tlsSettings": {
                    "serverName": "encryption-oracle.test", "pinnedPeerCertSha256": oracle.tls_pin
                    }});
                }
                let parsed = parse_xray_json(&raw.to_string()).unwrap();
                assert!(!format!("{:?}", parsed.config)
                    .contains(oracle.encryption.rsplit('.').next().unwrap()));
                let TcpOutbound::Vless(outbound) = OutboundRouter::new(Arc::new(parsed.config))
                    .select_tcp_outbound()
                    .unwrap()
                else {
                    panic!("VLESS required")
                };
                let port = if application == "udp" { 53 } else { 12345 };
                let target = Target::new(
                    TargetAddr::Domain("encrypted.example.test".to_owned()),
                    port,
                    if application == "vless" {
                        Network::Tcp
                    } else {
                        Network::Udp
                    },
                );
                tokio::time::timeout(Duration::from_secs(10), async {
                    if application == "vless" {
                        let mut stream = open_vless_tcp_stream(&outbound, &target).await.unwrap();
                        stream.write_all(b"encrypted runtime TCP").await.unwrap();
                        stream.shutdown().await.unwrap();
                        let mut response = Vec::new();
                        stream.read_to_end(&mut response).await.unwrap();
                        assert_eq!(response, b"encrypted runtime TCP");
                    } else {
                        let dialer = TransportDialer::system().unwrap();
                        let (mut stream, framing) = open_vless_udp_stream_with_resolver_and_dialer(
                            &outbound,
                            &target,
                            &SystemDnsResolver,
                            &dialer,
                        )
                        .await
                        .unwrap();
                        let payload = b"encrypted runtime UDP";
                        let packet = if application == "udp" {
                            assert_eq!(framing, VlessUdpFraming::LengthPrefixed);
                            encode_udp_packet(payload).unwrap()
                        } else {
                            assert_eq!(framing, VlessUdpFraming::Xudp);
                            encode_xudp_new_packet(&target, payload, [0; 8]).unwrap()
                        };
                        stream.write_all(&packet).await.unwrap();
                        stream.flush().await.unwrap();
                        let received = if application == "udp" {
                            read_udp_packet(&mut stream).await.unwrap()
                        } else {
                            read_xudp_packet(&mut stream).await.unwrap().payload
                        };
                        assert_eq!(received.as_ref(), payload);
                        stream.shutdown().await.unwrap();
                    }
                })
                .await
                .unwrap();
                oracle.finish();
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires the guarded pinned Go oracle; run scripts/check-vless-encryption-oracle.sh"]
async fn encrypted_vless_runtime_reuses_0rtt_session() {
    let oracle = Oracle::start("random", "x25519+mlkem768+x25519", -1, "session-vless");
    let raw = serde_json::json!({"outbounds": [{"protocol": "vless", "settings": {"vnext": [{
        "address": oracle.address.ip().to_string(), "port": oracle.address.port(),
        "users": [{"id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": oracle.encryption}]
    }]}}]});
    let parsed = parse_xray_json(&raw.to_string()).unwrap();
    let TcpOutbound::Vless(outbound) = OutboundRouter::new(Arc::new(parsed.config))
        .select_tcp_outbound()
        .unwrap()
    else {
        panic!("VLESS required")
    };
    let target = Target::new(
        TargetAddr::Domain("encrypted.example.test".to_owned()),
        12345,
        Network::Tcp,
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        for payload in [b"cold runtime flow".as_slice(), b"early runtime flow"] {
            let mut stream = open_vless_tcp_stream(&outbound, &target).await.unwrap();
            stream.write_all(payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, payload);
        }
    })
    .await
    .unwrap();
    oracle.finish();
}
