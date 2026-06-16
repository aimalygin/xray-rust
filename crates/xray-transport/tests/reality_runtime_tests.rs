use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    reality::{RealityPreparedClientHello, RealityPreparedHandshake},
    reality_connector::{
        RealityClientHelloRequest, RealityHandshakeContext, RealityTlsSession,
        RealityTlsSessionProvider,
    },
    DnsResolver, RealityClientConfig, RealityHandshakeContextProvider, RealityRuntimeEngine,
    RealityTlsEngine, TransportError,
};

const CLIENTHELLO_FIXTURE_JSON: &str =
    include_str!("../../../tests/fixtures/reality/clienthello_chrome_auto.json");

#[derive(Debug, Clone, serde::Deserialize)]
struct ClientHelloFixture {
    raw_client_hello_hex: String,
    hello_random_hex: String,
    session_id_offset: usize,
    local_x25519_private_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletionRecord {
    original_session_id: Vec<u8>,
    patched_session_id: Vec<u8>,
    session_id: [u8; 32],
    auth_key: [u8; 32],
}

#[derive(Debug)]
struct RecordingSessionProvider {
    fixture: ClientHelloFixture,
    seen: Mutex<Vec<(String, String)>>,
    completions: Arc<Mutex<Vec<CompletionRecord>>>,
    completion_error: Option<String>,
}

impl RecordingSessionProvider {
    fn new(fixture: ClientHelloFixture) -> Self {
        Self {
            fixture,
            seen: Mutex::new(Vec::new()),
            completions: Arc::new(Mutex::new(Vec::new())),
            completion_error: None,
        }
    }

    fn with_completion_error(mut self, message: impl Into<String>) -> Self {
        self.completion_error = Some(message.into());
        self
    }

    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().expect("provider seen lock").clone()
    }

    fn completions(&self) -> Vec<CompletionRecord> {
        self.completions
            .lock()
            .expect("completion records lock")
            .clone()
    }
}

impl RealityTlsSessionProvider for RecordingSessionProvider {
    fn create_session(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<Box<dyn RealityTlsSession>, xray_transport::reality::RealityError> {
        self.seen.lock().expect("provider seen lock").push((
            request.server_name.to_owned(),
            request.fingerprint.to_owned(),
        ));

        let raw_client_hello = decode_hex(&self.fixture.raw_client_hello_hex);
        let original_session_id = raw_client_hello
            [self.fixture.session_id_offset..self.fixture.session_id_offset + 32]
            .to_vec();

        Ok(Box::new(RecordingRealityTlsSession {
            prepared_client_hello: Mutex::new(Some(prepared_from_fixture(&self.fixture))),
            session_id_offset: self.fixture.session_id_offset,
            original_session_id,
            completions: self.completions.clone(),
            completion_error: self.completion_error.clone(),
        }))
    }
}

#[derive(Debug)]
struct RecordingRealityTlsSession {
    prepared_client_hello: Mutex<Option<RealityPreparedClientHello>>,
    session_id_offset: usize,
    original_session_id: Vec<u8>,
    completions: Arc<Mutex<Vec<CompletionRecord>>>,
    completion_error: Option<String>,
}

#[async_trait]
impl RealityTlsSession for RecordingRealityTlsSession {
    fn prepared_client_hello(
        &self,
    ) -> Result<RealityPreparedClientHello, xray_transport::reality::RealityError> {
        Ok(self
            .prepared_client_hello
            .lock()
            .expect("prepared ClientHello lock")
            .take()
            .expect("prepared ClientHello should be consumed once"))
    }

    async fn complete(
        self: Box<Self>,
        _tcp_stream: TcpStream,
        prepared: RealityPreparedHandshake,
        _mldsa65_verify: Option<Vec<u8>>,
    ) -> Result<xray_transport::BoxedTransportStream, TransportError> {
        let patched_session_id = prepared.patched_client_hello
            [self.session_id_offset..self.session_id_offset + 32]
            .to_vec();

        self.completions
            .lock()
            .expect("completion records lock")
            .push(CompletionRecord {
                original_session_id: self.original_session_id.clone(),
                patched_session_id,
                session_id: prepared.session_id,
                auth_key: prepared.auth_key,
            });

        match self.completion_error {
            Some(message) => Err(TransportError::TlsConfig(message)),
            None => Err(TransportError::RealityTlsCompletionUnsupported),
        }
    }
}

#[derive(Debug, Default)]
struct PanickingSessionProvider;

impl RealityTlsSessionProvider for PanickingSessionProvider {
    fn create_session(
        &self,
        _request: RealityClientHelloRequest<'_>,
    ) -> Result<Box<dyn RealityTlsSession>, xray_transport::reality::RealityError> {
        panic!("unsupported fingerprint must be rejected before REALITY TLS session creation")
    }
}

#[derive(Debug)]
struct FixedContextProvider {
    context: RealityHandshakeContext,
    calls: Mutex<usize>,
}

impl FixedContextProvider {
    fn new(context: RealityHandshakeContext) -> Self {
        Self {
            context,
            calls: Mutex::new(0),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.lock().expect("context calls lock")
    }
}

impl RealityHandshakeContextProvider for FixedContextProvider {
    fn context(&self) -> RealityHandshakeContext {
        *self.calls.lock().expect("context calls lock") += 1;
        self.context
    }
}

#[derive(Debug, Default)]
struct PanickingContextProvider;

impl RealityHandshakeContextProvider for PanickingContextProvider {
    fn context(&self) -> RealityHandshakeContext {
        panic!("unsupported fingerprint must be rejected before context provider use")
    }
}

#[derive(Debug)]
struct RecordingDnsResolver {
    resolved: SocketAddr,
    seen: Mutex<Vec<(String, u16)>>,
}

impl RecordingDnsResolver {
    fn new(resolved: SocketAddr) -> Self {
        Self {
            resolved,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<(String, u16)> {
        self.seen.lock().expect("resolver seen lock").clone()
    }
}

#[async_trait]
impl DnsResolver for RecordingDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        {
            self.seen
                .lock()
                .expect("resolver seen lock")
                .push((domain.to_owned(), port));
        }

        Ok(self.resolved)
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
        mldsa65_verify: None,
    }
}

fn clienthello_fixture() -> ClientHelloFixture {
    serde_json::from_str(CLIENTHELLO_FIXTURE_JSON).expect("fixture json should decode")
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string length must be even");
    (0..hex.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&hex[idx..idx + 2], 16).expect("valid hex byte"))
        .collect()
}

fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = decode_hex(hex);
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("hex string should decode to {N} bytes"))
}

fn prepared_from_fixture(fixture: &ClientHelloFixture) -> RealityPreparedClientHello {
    RealityPreparedClientHello {
        fingerprint: "chrome".to_owned(),
        raw_client_hello: decode_hex(&fixture.raw_client_hello_hex),
        hello_random: decode_hex_array(&fixture.hello_random_hex),
        session_id_offset: fixture.session_id_offset,
        local_x25519_private_key: decode_hex_array(&fixture.local_x25519_private_key_hex),
    }
}

fn fixed_context() -> RealityHandshakeContext {
    RealityHandshakeContext {
        version: [1, 8, 0],
        unix_time: 1_700_000_000,
    }
}

async fn spawn_accept_once() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind REALITY runtime listener");
    let addr = listener.local_addr().expect("read listener address");

    let handle = tokio::spawn(async move {
        let (_stream, _) = listener
            .accept()
            .await
            .expect("accept REALITY runtime TCP client");
    });

    (addr, handle)
}

async fn assert_accept_completed(handle: tokio::task::JoinHandle<()>) {
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("tcp accept should finish")
        .expect("tcp accept task should not panic");
}

#[tokio::test]
async fn reality_runtime_rejects_unsupported_fingerprint_before_dependencies() {
    let engine = RealityRuntimeEngine::new(Arc::new(PanickingSessionProvider))
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

#[tokio::test]
async fn reality_runtime_rejects_invalid_session_clienthello_before_dns_or_tcp() {
    let mut fixture = clienthello_fixture();
    fixture.hello_random_hex.replace_range(0..2, "ff");
    let provider = Arc::new(RecordingSessionProvider::new(fixture));
    let context = Arc::new(FixedContextProvider::new(fixed_context()));
    let engine = RealityRuntimeEngine::new(provider.clone())
        .with_dns_resolver(Arc::new(PanickingDnsResolver))
        .with_context_provider(context.clone());
    let config = reality_config();
    let target = Target::new(
        TargetAddr::Domain("origin.example".to_owned()),
        443,
        Network::Tcp,
    );

    let result = engine.connect(&config, &target).await;

    assert!(matches!(
        result,
        Err(TransportError::Reality(
            xray_transport::reality::RealityError::ClientHelloRandomMismatch
        ))
    ));
    assert_eq!(
        provider.seen(),
        vec![("www.example.com".to_owned(), "chrome".to_owned())]
    );
    assert_eq!(provider.completions(), Vec::<CompletionRecord>::new());
    assert_eq!(context.calls(), 1);
}

#[tokio::test]
async fn reality_runtime_prepares_handshake_and_connects_ip_before_live_tls_gate() {
    let (addr, handle) = spawn_accept_once().await;
    let provider = Arc::new(RecordingSessionProvider::new(clienthello_fixture()));
    let context = Arc::new(FixedContextProvider::new(fixed_context()));
    let resolver = Arc::new(RecordingDnsResolver::new(addr));
    let engine = RealityRuntimeEngine::new(provider.clone())
        .with_dns_resolver(resolver.clone())
        .with_context_provider(context.clone());
    let config = reality_config();
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);

    let result = engine.connect(&config, &target).await;

    assert!(matches!(
        result,
        Err(TransportError::RealityTlsCompletionUnsupported)
    ));
    assert_accept_completed(handle).await;
    assert_eq!(resolver.seen(), Vec::<(String, u16)>::new());
    assert_eq!(
        provider.seen(),
        vec![("www.example.com".to_owned(), "chrome".to_owned())]
    );
    assert_eq!(context.calls(), 1);
    let completions = provider.completions();
    assert_eq!(completions.len(), 1);
    assert_eq!(
        completions[0].patched_session_id.as_slice(),
        &completions[0].session_id[..]
    );
    assert_ne!(
        completions[0].patched_session_id,
        completions[0].original_session_id
    );
    assert_ne!(completions[0].auth_key, [0u8; 32]);
}

#[tokio::test]
async fn reality_runtime_resolves_domain_targets_before_tcp_connect() {
    let (addr, handle) = spawn_accept_once().await;
    let provider = Arc::new(RecordingSessionProvider::new(clienthello_fixture()));
    let context = Arc::new(FixedContextProvider::new(fixed_context()));
    let resolver = Arc::new(RecordingDnsResolver::new(addr));
    let engine = RealityRuntimeEngine::new(provider.clone())
        .with_dns_resolver(resolver.clone())
        .with_context_provider(context.clone());
    let config = reality_config();
    let target = Target::new(
        TargetAddr::Domain("origin.example".to_owned()),
        443,
        Network::Tcp,
    );

    let result = engine.connect(&config, &target).await;

    assert!(matches!(
        result,
        Err(TransportError::RealityTlsCompletionUnsupported)
    ));
    assert_accept_completed(handle).await;
    assert_eq!(resolver.seen(), vec![("origin.example".to_owned(), 443)]);
    assert_eq!(
        provider.seen(),
        vec![("www.example.com".to_owned(), "chrome".to_owned())]
    );
    assert_eq!(context.calls(), 1);
    let completions = provider.completions();
    assert_eq!(completions.len(), 1);
    assert_eq!(
        completions[0].patched_session_id.as_slice(),
        &completions[0].session_id[..]
    );
}

#[tokio::test]
async fn reality_runtime_propagates_session_completion_errors_unchanged() {
    let (addr, handle) = spawn_accept_once().await;
    let provider = Arc::new(
        RecordingSessionProvider::new(clienthello_fixture())
            .with_completion_error("scripted completion failure"),
    );
    let context = Arc::new(FixedContextProvider::new(fixed_context()));
    let resolver = Arc::new(RecordingDnsResolver::new(addr));
    let engine = RealityRuntimeEngine::new(provider.clone())
        .with_dns_resolver(resolver.clone())
        .with_context_provider(context.clone());
    let config = reality_config();
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);

    let result = engine.connect(&config, &target).await;

    assert!(matches!(
        result,
        Err(TransportError::TlsConfig(message)) if message == "scripted completion failure"
    ));
    assert_accept_completed(handle).await;
    assert_eq!(resolver.seen(), Vec::<(String, u16)>::new());
    assert_eq!(
        provider.seen(),
        vec![("www.example.com".to_owned(), "chrome".to_owned())]
    );
    assert_eq!(context.calls(), 1);
    assert_eq!(provider.completions().len(), 1);
}
