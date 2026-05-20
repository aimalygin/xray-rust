use xray_config::{
    Diagnostic, DiagnosticSeverity, InboundConfig, InboundProtocol, Network, OutboundConfig,
    OutboundProtocol, RealitySettings, StreamSecurity, StreamSettings, TargetAddr, VlessUser,
};

#[test]
fn diagnostic_carries_json_path() {
    let diagnostic = Diagnostic::error("$.outbounds[0].settings", "unsupported protocol field");
    assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
    assert_eq!(diagnostic.path.as_deref(), Some("$.outbounds[0].settings"));
    assert_eq!(diagnostic.message, "unsupported protocol field");
}

#[test]
fn normalized_model_can_represent_vless_reality_vision() {
    let outbound = OutboundConfig {
        tag: Some("proxy".to_owned()),
        protocol: OutboundProtocol::Vless,
        server: TargetAddr::Domain("server.example".to_owned()),
        port: 443,
        users: vec![VlessUser {
            id: "00010203-0405-0607-0809-0a0b0c0d0e0f".parse().unwrap(),
            encryption: "none".to_owned(),
            flow: Some("xtls-rprx-vision".to_owned()),
        }],
        stream: StreamSettings {
            network: Network::Tcp,
            security: StreamSecurity::Reality(RealitySettings {
                server_name: "www.example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: vec![1; 32],
                short_id: vec![2, 3, 4, 5],
                spider_x: "/".to_owned(),
            }),
        },
    };

    let inbound = InboundConfig {
        tag: Some("socks".to_owned()),
        protocol: InboundProtocol::Socks,
        listen: "127.0.0.1".to_owned(),
        port: 1080,
    };

    assert_eq!(inbound.port, 1080);
    assert_eq!(outbound.users[0].flow.as_deref(), Some("xtls-rprx-vision"));
}
