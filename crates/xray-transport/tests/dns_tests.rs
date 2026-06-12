use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    CachingDnsResolver, DnsResolver, SystemDnsResolver, TcpConnector, TransportConnector,
    TransportError,
};

#[derive(Default)]
struct CountingResolver {
    calls: AtomicUsize,
}

#[async_trait]
impl DnsResolver for CountingResolver {
    async fn resolve(&self, _domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SocketAddr::from(([192, 0, 2, 1], port)))
    }
}

#[tokio::test]
async fn caching_resolver_reuses_fresh_entries() {
    let inner = Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::from_secs(60));

    let first = resolver.resolve("example.com", 443).await.unwrap();
    let second = resolver.resolve("example.com", 443).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn caching_resolver_expires_entries() {
    let inner = Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::ZERO);

    resolver.resolve("example.com", 443).await.unwrap();
    resolver.resolve("example.com", 443).await.unwrap();

    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn caching_resolver_keys_by_domain_and_port() {
    let inner = Arc::new(CountingResolver::default());
    let resolver = CachingDnsResolver::with_ttl(inner.clone(), Duration::from_secs(60));

    resolver.resolve("example.com", 443).await.unwrap();
    resolver.resolve("example.com", 80).await.unwrap();

    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn system_dns_resolver_resolves_localhost_without_tcp_io() {
    let resolver = SystemDnsResolver;

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
