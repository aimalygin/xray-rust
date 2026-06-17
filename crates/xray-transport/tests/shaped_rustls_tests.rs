use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::client::{ClientHelloContext, ClientHelloCustomizer, ClientHelloPlan};
use rustls::{crypto, ClientConfig, Error as RustlsError};

#[derive(Debug)]
struct NoopClientHelloCustomizer {
    called: Mutex<bool>,
}

impl ClientHelloCustomizer for NoopClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        *self.called.lock().expect("customizer mutex poisoned") = true;
        Ok(Some(ClientHelloPlan::new()))
    }
}

impl fmt::Display for NoopClientHelloCustomizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoopClientHelloCustomizer")
    }
}

#[test]
fn shaped_rustls_exposes_client_hello_customizer_api() {
    let customizer = Arc::new(NoopClientHelloCustomizer {
        called: Mutex::new(false),
    });
    let mut config = ClientConfig::builder_with_provider(crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 should be supported by the ring provider")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    config.client_hello_customizer = Some(customizer);

    assert!(config.client_hello_customizer().is_some());
}
