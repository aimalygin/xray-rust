mod transport_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::{
        ConnectorConfig, RealityClientConfig, TcpConnector, TlsClientConfig, TransportConnector,
        TransportError,
    };

    #[tokio::test]
    async fn tcp_connector_reports_target_without_network_io_when_resolved() {
        let config = ConnectorConfig::Tcp;
        let connector = TcpConnector::new(config);
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );

        assert_eq!(connector.describe_target(&target), "127.0.0.1:9");
    }

    #[tokio::test]
    async fn tcp_connector_requires_dns_for_domain_targets() {
        let config = ConnectorConfig::Tcp;
        let connector = TcpConnector::new(config);
        let target = Target::new(
            TargetAddr::Domain("example.com".to_string()),
            443,
            Network::Tcp,
        );

        let result = connector.connect(&target).await;

        assert!(matches!(result, Err(TransportError::NeedsDns(domain)) if domain == "example.com"));
    }

    #[tokio::test]
    async fn tcp_connector_rejects_tls_config_without_plaintext_downgrade() {
        let connector = TcpConnector::new(ConnectorConfig::Tls(TlsClientConfig {
            server_name: "example.com".to_owned(),
        }));
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );

        let result = connector.connect(&target).await;

        assert!(matches!(
            result,
            Err(TransportError::UnsupportedConnectorConfig("tls"))
        ));
    }

    #[tokio::test]
    async fn tcp_connector_rejects_reality_config_without_plaintext_downgrade() {
        let connector = TcpConnector::new(ConnectorConfig::Reality(RealityClientConfig {
            server_name: "www.example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [1; 32],
            short_id: vec![2, 3, 4, 5],
            spider_x: "/".to_owned(),
        }));
        let target = Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            9,
            Network::Tcp,
        );

        let result = connector.connect(&target).await;

        assert!(matches!(
            result,
            Err(TransportError::UnsupportedConnectorConfig("reality"))
        ));
    }
}
