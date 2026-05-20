mod transport_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use xray_routing::{Network, Target, TargetAddr};
    use xray_transport::{ConnectorConfig, TcpConnector, TransportConnector, TransportError};

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
}
