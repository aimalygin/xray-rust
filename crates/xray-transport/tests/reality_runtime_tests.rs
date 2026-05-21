use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    reality::RealityPreparedClientHello,
    reality_connector::{
        RealityClientHelloProvider, RealityClientHelloRequest, RealityHandshakeContext,
    },
    DnsResolver, RealityClientConfig, RealityHandshakeContextProvider, RealityRuntimeEngine,
    RealityTlsEngine, TransportError,
};

#[derive(Debug, Default)]
struct PanickingClientHelloProvider;

impl RealityClientHelloProvider for PanickingClientHelloProvider {
    fn prepare_client_hello(
        &self,
        _request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, xray_transport::reality::RealityError> {
        panic!("unsupported fingerprint must be rejected before ClientHello provider use")
    }
}

#[derive(Debug, Default)]
struct PanickingContextProvider;

impl RealityHandshakeContextProvider for PanickingContextProvider {
    fn context(&self) -> RealityHandshakeContext {
        panic!("unsupported fingerprint must be rejected before context provider use")
    }
}

#[derive(Debug, Default)]
struct PanickingDnsResolver;

#[async_trait]
impl DnsResolver for PanickingDnsResolver {
    async fn resolve(&self, _domain: &str, _port: u16) -> Result<SocketAddr, TransportError> {
        panic!("unsupported fingerprint must be rejected before DNS resolution")
    }
}

fn reality_config() -> RealityClientConfig {
    RealityClientConfig {
        server_name: "www.example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [9u8; 32],
        short_id: vec![2, 3, 4, 5],
        spider_x: "/".to_owned(),
    }
}

#[tokio::test]
async fn reality_runtime_rejects_unsupported_fingerprint_before_dependencies() {
    let engine = RealityRuntimeEngine::new(Arc::new(PanickingClientHelloProvider))
        .with_dns_resolver(Arc::new(PanickingDnsResolver))
        .with_context_provider(Arc::new(PanickingContextProvider));
    let mut config = reality_config();
    config.fingerprint = "firefox".to_owned();
    let target = Target::new(
        TargetAddr::Domain("origin.example".to_owned()),
        443,
        Network::Tcp,
    );

    let result = engine.connect(&config, &target).await;

    assert!(matches!(
        result,
        Err(TransportError::Reality(
            xray_transport::reality::RealityError::UnsupportedRealityFingerprint(fingerprint)
        )) if fingerprint == "firefox"
    ));
}
