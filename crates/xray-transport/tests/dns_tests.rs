use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    DnsResolver, SystemDnsResolver, TcpConnector, TransportConnector, TransportError,
};

#[tokio::test]
async fn system_dns_resolver_resolves_localhost_without_tcp_io() {
    let resolver = SystemDnsResolver::default();

    let addr = resolver.resolve("localhost", 443).await.unwrap();

    assert_eq!(addr.port(), 443);
}

#[tokio::test]
async fn tcp_connector_still_rejects_domain_targets_without_dns() {
    let connector = TcpConnector::new(xray_transport::ConnectorConfig::Tcp);
    let target = Target::new(
        TargetAddr::Domain("localhost".to_owned()),
        443,
        Network::Tcp,
    );

    let result = connector.connect(&target).await;

    assert!(matches!(result, Err(TransportError::NeedsDns(domain)) if domain == "localhost"));
}
