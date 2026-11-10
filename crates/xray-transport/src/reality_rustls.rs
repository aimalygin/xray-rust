use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        CapturesClientHello, ClientHelloContext, ClientHelloCustomizer, ClientHelloPlan,
        ClientHelloSessionId, FinalizesClientHello, FixedX25519KeyShare, WebPkiServerVerifier,
    },
    crypto::{self, CryptoProvider, GetRandomFailed},
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError,
    RootCertStore, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as TokioTlsConnector;
use zeroize::Zeroize;

use crate::{
    reality::{
        prepare_reality_handshake, validate_reality_client_hello_metadata,
        validate_reality_fingerprint, verify_reality_certificate_der_with_mldsa65, RealityError,
        RealityHandshakeInput, RealityMldsa65CertificateInput, RealityPreparedClientHello,
    },
    reality_connector::{RealityClientHelloRequest, RealityTlsSession, RealityTlsSessionProvider},
    reality_spider::{spider, RealitySpider},
    utls_profiles::{reality_profile_for_fingerprint, UtlsClientHelloProfile},
    utls_shaping::{apply_utls_profile, retain_profile_certificate_decompressors, HelloDraws},
    BoxedTransportStream, CapturedStream, PenetratingTlsStream, ServerReadLog, TransportError,
};

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const REALITY_SESSION_ID_LEN: usize = 32;
const TLS_CLIENT_HELLO_SESSION_ID_OFFSET: usize = 39;

#[derive(Debug, Clone, Default)]
pub struct RustlsRealityTlsSessionProvider;

impl RustlsRealityTlsSessionProvider {
    pub fn new() -> Self {
        Self
    }
}

impl RealityTlsSessionProvider for RustlsRealityTlsSessionProvider {
    fn create_session(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<Box<dyn RealityTlsSession>, RealityError> {
        validate_reality_fingerprint(request.fingerprint)?;

        let plan = RustlsRealityPlan::random().map_err(|_| {
            RealityError::ClientHelloGenerationFailed(
                "failed to fill REALITY handshake entropy".to_owned(),
            )
        })?;
        let prepared = plan.prepare_client_hello(request)?;

        Ok(Box::new(RustlsRealityTlsSession {
            server_name: request.server_name.to_owned(),
            fingerprint: request.fingerprint.to_owned(),
            plan,
            prepared_client_hello: prepared,
            spider: RealitySpider::parse(""),
            roots: None,
        }))
    }
}

#[derive(Clone)]
struct RustlsRealityPlan {
    hello_random: [u8; 32],
    local_x25519_private_key: [u8; 32],
}

impl fmt::Debug for RustlsRealityPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityPlan")
            .field("hello_random", &"<redacted>")
            .field("local_x25519_private_key", &"<redacted>")
            .finish()
    }
}

impl Drop for RustlsRealityPlan {
    fn drop(&mut self) {
        self.local_x25519_private_key.zeroize();
    }
}

impl RustlsRealityPlan {
    fn random() -> Result<Self, GetRandomFailed> {
        let mut hello_random = [0; 32];
        let mut local_x25519_private_key = [0; 32];
        let secure_random = crypto::ring::default_provider().secure_random;

        secure_random.fill(&mut hello_random)?;
        secure_random.fill(&mut local_x25519_private_key)?;

        let plan = Self {
            hello_random,
            local_x25519_private_key,
        };
        local_x25519_private_key.zeroize();

        Ok(plan)
    }

    fn prepare_client_hello(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, RealityError> {
        let raw_client_hello = self
            .client_hello_message(
                request.server_name,
                request.fingerprint,
                [0; REALITY_SESSION_ID_LEN],
                [0; 32],
            )
            .map_err(|error| RealityError::ClientHelloGenerationFailed(error.to_string()))?;
        let prepared = RealityPreparedClientHello {
            fingerprint: request.fingerprint.to_owned(),
            raw_client_hello,
            hello_random: self.hello_random,
            session_id_offset: TLS_CLIENT_HELLO_SESSION_ID_OFFSET,
            local_x25519_private_key: self.local_x25519_private_key,
        };
        let validation = validate_reality_client_hello_metadata(&prepared)?;

        debug_assert_eq!(
            validation.session_id_offset,
            TLS_CLIENT_HELLO_SESSION_ID_OFFSET
        );

        Ok(prepared)
    }

    fn client_hello_message(
        &self,
        server_name: &str,
        fingerprint: &str,
        session_id: [u8; REALITY_SESSION_ID_LEN],
        auth_key: [u8; 32],
    ) -> Result<Vec<u8>, TransportError> {
        self.client_hello_message_inner(server_name, fingerprint, session_id, auth_key, None)
    }

    #[cfg(test)]
    fn client_hello_message_with_finalizer(
        &self,
        server_name: &str,
        fingerprint: &str,
        finalizer: Arc<dyn FinalizesClientHello>,
    ) -> Result<Vec<u8>, TransportError> {
        self.client_hello_message_inner(
            server_name,
            fingerprint,
            [0; REALITY_SESSION_ID_LEN],
            [0; 32],
            Some(finalizer),
        )
    }

    fn client_hello_message_inner(
        &self,
        server_name: &str,
        fingerprint: &str,
        session_id: [u8; REALITY_SESSION_ID_LEN],
        auth_key: [u8; 32],
        finalizer: Option<Arc<dyn FinalizesClientHello>>,
    ) -> Result<Vec<u8>, TransportError> {
        let profile = reality_profile_for_fingerprint(fingerprint).ok_or_else(|| {
            TransportError::TlsConfig(format!(
                "unsupported REALITY uTLS fingerprint profile: {fingerprint}"
            ))
        })?;
        let capture = Arc::new(RealityClientHelloCapture::default());
        let customizer = Arc::new(RustlsRealityClientHelloCustomizer::new(
            self,
            profile,
            session_id,
            Some(capture.clone()),
            finalizer,
        ));
        let config = reality_client_config(
            RealityVerificationMaterial::Static {
                auth_key,
                client_hello: None,
            },
            None,
            None,
            Some(customizer),
            profile,
        )?;
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| TransportError::InvalidTlsServerName(server_name.to_owned()))?;
        let mut connection =
            ClientConnection::new(Arc::new(config), server_name).map_err(rustls_config_error)?;
        let mut record = Vec::new();
        connection
            .write_tls(&mut record)
            .map_err(TransportError::Tcp)?;

        capture.take()
    }
}

#[derive(Debug, Default)]
struct RealityClientHelloCapture {
    bytes: Mutex<Option<Vec<u8>>>,
}

impl RealityClientHelloCapture {
    fn take(&self) -> Result<Vec<u8>, TransportError> {
        let mut bytes = self.bytes.lock().map_err(|_| {
            TransportError::TlsConfig("REALITY ClientHello capture lock was poisoned".to_owned())
        })?;
        bytes.take().ok_or_else(|| {
            TransportError::TlsConfig("rustls did not capture a REALITY ClientHello".to_owned())
        })
    }
}

impl CapturesClientHello for RealityClientHelloCapture {
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), RustlsError> {
        let mut captured = self.bytes.lock().map_err(|_| {
            RustlsError::General("REALITY ClientHello capture lock was poisoned".to_owned())
        })?;
        *captured = Some(bytes.to_vec());
        Ok(())
    }
}

struct RustlsRealityClientHelloCustomizer {
    profile: &'static UtlsClientHelloProfile,
    hello_random: [u8; 32],
    session_id: [u8; REALITY_SESSION_ID_LEN],
    local_x25519_private_key: [u8; 32],
    capture: Option<Arc<RealityClientHelloCapture>>,
    finalizer: Option<Arc<dyn FinalizesClientHello>>,
}

impl RustlsRealityClientHelloCustomizer {
    fn new(
        plan: &RustlsRealityPlan,
        profile: &'static UtlsClientHelloProfile,
        session_id: [u8; REALITY_SESSION_ID_LEN],
        capture: Option<Arc<RealityClientHelloCapture>>,
        finalizer: Option<Arc<dyn FinalizesClientHello>>,
    ) -> Self {
        Self {
            profile,
            hello_random: plan.hello_random,
            session_id,
            local_x25519_private_key: plan.local_x25519_private_key,
            capture,
            finalizer,
        }
    }
}

impl fmt::Debug for RustlsRealityClientHelloCustomizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityClientHelloCustomizer")
            .field("profile", &self.profile)
            .field("hello_random", &"<redacted>")
            .field("session_id", &"<redacted>")
            .field("local_x25519_private_key", &"<redacted>")
            .field("capture", &self.capture.is_some())
            .field("finalizer", &self.finalizer.is_some())
            .finish()
    }
}

impl Drop for RustlsRealityClientHelloCustomizer {
    fn drop(&mut self) {
        self.hello_random.zeroize();
        self.session_id.zeroize();
        self.local_x25519_private_key.zeroize();
    }
}

impl ClientHelloCustomizer for RustlsRealityClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        let session_id = ClientHelloSessionId::try_from(self.session_id.to_vec())?;
        let mut plan = ClientHelloPlan::new()
            .with_random(self.hello_random)
            .with_session_id(session_id)
            .with_fixed_x25519(FixedX25519KeyShare::new(self.local_x25519_private_key));

        plan = apply_utls_profile(
            plan,
            self.profile,
            context,
            &HelloDraws::draw(self.profile)?,
            None,
        )?;

        if let Some(capture) = &self.capture {
            plan = plan.with_capture(capture.clone());
        }
        if let Some(finalizer) = &self.finalizer {
            plan = plan.with_finalizer(finalizer.clone());
        }

        Ok(Some(plan))
    }
}

#[derive(Clone)]
struct RealityFinalizedClientHello {
    auth_key: [u8; 32],
    session_id: [u8; REALITY_SESSION_ID_LEN],
    client_hello: Vec<u8>,
}

impl fmt::Debug for RealityFinalizedClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityFinalizedClientHello")
            .field("auth_key", &"<redacted>")
            .field("session_id", &"<redacted>")
            .field("client_hello_len", &self.client_hello.len())
            .finish()
    }
}

impl Drop for RealityFinalizedClientHello {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.session_id.zeroize();
        self.client_hello.zeroize();
    }
}

#[derive(Default)]
struct RealityFinalizedClientHelloState {
    finalized: Mutex<Option<RealityFinalizedClientHello>>,
}

impl fmt::Debug for RealityFinalizedClientHelloState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityFinalizedClientHelloState")
            .finish_non_exhaustive()
    }
}

impl RealityFinalizedClientHelloState {
    fn store(&self, finalized: RealityFinalizedClientHello) -> Result<(), RustlsError> {
        let mut stored = self.finalized.lock().map_err(|_| {
            RustlsError::General("REALITY ClientHello finalizer state lock was poisoned".to_owned())
        })?;
        if stored.is_some() {
            return Err(RustlsError::General(
                "REALITY ClientHello finalizer ran more than once".to_owned(),
            ));
        }
        *stored = Some(finalized);
        Ok(())
    }

    fn snapshot(&self) -> Result<RealityFinalizedClientHello, RustlsError> {
        let stored = self.finalized.lock().map_err(|_| {
            RustlsError::General("REALITY ClientHello finalizer state lock was poisoned".to_owned())
        })?;
        stored.as_ref().cloned().ok_or_else(|| {
            RustlsError::General("REALITY ClientHello finalizer did not run".to_owned())
        })
    }
}

struct RustlsRealityClientHelloFinalizer {
    fingerprint: String,
    hello_random: [u8; 32],
    local_x25519_private_key: [u8; 32],
    version: [u8; 3],
    unix_time: u32,
    short_id: Vec<u8>,
    server_public_key: [u8; 32],
    finalized_state: Arc<RealityFinalizedClientHelloState>,
}

impl RustlsRealityClientHelloFinalizer {
    fn new(
        plan: &RustlsRealityPlan,
        fingerprint: &str,
        prepared: &crate::reality::RealityPreparedHandshake,
        finalized_state: Arc<RealityFinalizedClientHelloState>,
    ) -> Self {
        Self {
            fingerprint: fingerprint.to_owned(),
            hello_random: plan.hello_random,
            local_x25519_private_key: plan.local_x25519_private_key,
            version: prepared.version,
            unix_time: prepared.unix_time,
            short_id: prepared.short_id.clone(),
            server_public_key: prepared.server_public_key,
            finalized_state,
        }
    }
}

impl fmt::Debug for RustlsRealityClientHelloFinalizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityClientHelloFinalizer")
            .field("fingerprint", &self.fingerprint)
            .field("hello_random", &"<redacted>")
            .field("local_x25519_private_key", &"<redacted>")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &"<redacted>")
            .field("server_public_key", &self.server_public_key)
            .finish()
    }
}

impl Drop for RustlsRealityClientHelloFinalizer {
    fn drop(&mut self) {
        self.local_x25519_private_key.zeroize();
        self.short_id.zeroize();
    }
}

impl FinalizesClientHello for RustlsRealityClientHelloFinalizer {
    fn finalize_client_hello(&self, bytes: &mut Vec<u8>) -> Result<(), RustlsError> {
        let prepared = prepare_reality_handshake(RealityHandshakeInput {
            version: self.version,
            unix_time: self.unix_time,
            short_id: self.short_id.clone(),
            server_public_key: self.server_public_key,
            prepared_client_hello: RealityPreparedClientHello {
                fingerprint: self.fingerprint.clone(),
                raw_client_hello: bytes.clone(),
                hello_random: self.hello_random,
                session_id_offset: TLS_CLIENT_HELLO_SESSION_ID_OFFSET,
                local_x25519_private_key: self.local_x25519_private_key,
            },
        })
        .map_err(|error| {
            RustlsError::General(format!("REALITY ClientHello finalization failed: {error}"))
        })?;

        if prepared.patched_client_hello.len() != bytes.len() {
            return Err(RustlsError::General(
                "REALITY ClientHello finalizer changed ClientHello length".to_owned(),
            ));
        }

        let finalized_client_hello = prepared.patched_client_hello.clone();
        bytes.copy_from_slice(&finalized_client_hello);
        self.finalized_state.store(RealityFinalizedClientHello {
            auth_key: prepared.auth_key,
            session_id: prepared.session_id,
            client_hello: finalized_client_hello,
        })
    }
}

struct RustlsRealityTlsSession {
    server_name: String,
    fingerprint: String,
    plan: RustlsRealityPlan,
    prepared_client_hello: RealityPreparedClientHello,
    spider: RealitySpider,
    /// Trust anchors for a server that answers with a real certificate;
    /// `None` is the bundled Web PKI roots. Tests substitute their own.
    roots: Option<Arc<RootCertStore>>,
}

impl fmt::Debug for RustlsRealityTlsSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityTlsSession")
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("plan", &self.plan)
            .field("spider", &self.spider)
            .finish()
    }
}

#[async_trait]
impl RealityTlsSession for RustlsRealityTlsSession {
    fn set_spider_x(&mut self, spider_x: &str) {
        self.spider = RealitySpider::parse(spider_x);
    }

    fn prepared_client_hello(&self) -> Result<RealityPreparedClientHello, RealityError> {
        Ok(RealityPreparedClientHello {
            fingerprint: self.prepared_client_hello.fingerprint.clone(),
            raw_client_hello: self.prepared_client_hello.raw_client_hello.clone(),
            hello_random: self.prepared_client_hello.hello_random,
            session_id_offset: self.prepared_client_hello.session_id_offset,
            local_x25519_private_key: self.plan.local_x25519_private_key,
        })
    }

    async fn complete(
        self: Box<Self>,
        tcp_stream: TcpStream,
        prepared: crate::reality::RealityPreparedHandshake,
        mldsa65_verify: Option<Vec<u8>>,
    ) -> Result<BoxedTransportStream, TransportError> {
        self.complete_over(tcp_stream, prepared, mldsa65_verify)
            .await
    }
    async fn complete_fragmented(
        self: Box<Self>,
        tcp_stream: TcpStream,
        prepared: crate::reality::RealityPreparedHandshake,
        mldsa65_verify: Option<Vec<u8>>,
        fragment: Arc<crate::TcpFragmentConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let stream = crate::fragment::FragmentStream::new(Box::new(tcp_stream), fragment);
        self.complete_over(stream, prepared, mldsa65_verify).await
    }
    async fn complete_over_stream(
        self: Box<Self>,
        stream: BoxedTransportStream,
        prepared: crate::reality::RealityPreparedHandshake,
        mldsa65_verify: Option<Vec<u8>>,
    ) -> Result<BoxedTransportStream, TransportError> {
        self.complete_over(stream, prepared, mldsa65_verify).await
    }
}
impl RustlsRealityTlsSession {
    async fn complete_over<S>(
        self: Box<Self>,
        tcp_stream: S,
        prepared: crate::reality::RealityPreparedHandshake,
        mldsa65_verify: Option<Vec<u8>>,
    ) -> Result<BoxedTransportStream, TransportError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let profile = reality_profile_for_fingerprint(&self.fingerprint).ok_or_else(|| {
            TransportError::TlsConfig(format!(
                "unsupported REALITY uTLS fingerprint profile: {}",
                self.fingerprint
            ))
        })?;
        let finalized_state = Arc::new(RealityFinalizedClientHelloState::default());
        let finalizer = Arc::new(RustlsRealityClientHelloFinalizer::new(
            &self.plan,
            &self.fingerprint,
            &prepared,
            finalized_state.clone(),
        ));

        let server_read_log = mldsa65_verify
            .as_ref()
            .map(|_| Arc::new(Mutex::new(Some(Vec::new()))));
        let mldsa65 = mldsa65_verify.map(|verifying_key| RealityMldsa65VerifierContext {
            verifying_key,
            server_read_log: server_read_log
                .as_ref()
                .expect("ML-DSA verifier has a server read log")
                .clone(),
        });
        let customizer = Arc::new(RustlsRealityClientHelloCustomizer::new(
            &self.plan,
            profile,
            [0; REALITY_SESSION_ID_LEN],
            None,
            Some(finalizer),
        ));
        let real_certificate = Arc::new(RealCertificateFallback {
            roots: self.roots.clone(),
            accepted: AtomicBool::new(false),
        });
        let config = Arc::new(reality_client_config(
            RealityVerificationMaterial::Finalized(finalized_state),
            mldsa65,
            Some(real_certificate.clone()),
            Some(customizer),
            profile,
        )?);
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| TransportError::InvalidTlsServerName(self.server_name.clone()))?;
        let connector = TokioTlsConnector::from(config);
        let tcp_stream = CapturedStream::new(tcp_stream, server_read_log);
        let connect = connector.connect(server_name, tcp_stream);
        let stream = connect.await.map_err(TransportError::Tls)?;

        if real_certificate.accepted.load(Ordering::Acquire) {
            // Xray-core finishes this handshake and crawls the real site
            // before failing (`reality.go` `UClient`, lines 207-298). The
            // stream goes to the crawl; no user data is ever written to it.
            spider(stream, &self.server_name, &self.spider).await;
            return Err(RealityError::RealCertificate.into());
        }

        Ok(Box::new(PenetratingTlsStream::new(stream)))
    }
}

fn reality_client_config(
    material: RealityVerificationMaterial,
    mldsa65: Option<RealityMldsa65VerifierContext>,
    real_certificate: Option<Arc<RealCertificateFallback>>,
    client_hello_customizer: Option<Arc<dyn ClientHelloCustomizer>>,
    profile: &'static UtlsClientHelloProfile,
) -> Result<ClientConfig, TransportError> {
    let provider = Arc::new(reality_crypto_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
    let verifier = RealityServerVerifier {
        material,
        mldsa65,
        real_certificate,
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    retain_profile_certificate_decompressors(profile, &mut config.cert_decompressors);
    config.resumption = rustls::client::Resumption::disabled();
    config.client_hello_customizer = client_hello_customizer;

    Ok(config)
}

fn reality_crypto_provider() -> CryptoProvider {
    let mut provider = crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        crypto::aws_lc_rs::kx_group::X25519KYBER768DRAFT00,
        crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        crypto::aws_lc_rs::kx_group::X25519,
        crypto::aws_lc_rs::kx_group::SECP256R1,
        crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    provider
}

/// Exercises the ServerHello capture without exposing it in normal builds.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn extract_server_hello_for_fuzzing(records: &[u8]) -> Option<Vec<u8>> {
    extract_server_hello(records).ok()
}

fn extract_server_hello(records: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut record_offset = 0;
    while record_offset + TLS_RECORD_HEADER_LEN <= records.len() {
        let record_type = records[record_offset];
        let record_len =
            u16::from_be_bytes([records[record_offset + 3], records[record_offset + 4]]) as usize;
        let record_body_start = record_offset + TLS_RECORD_HEADER_LEN;
        let record_end = record_body_start
            .checked_add(record_len)
            .ok_or_else(|| TransportError::TlsConfig("TLS record length overflow".to_owned()))?;
        if record_end > records.len() {
            return Err(TransportError::TlsConfig(
                "truncated TLS server record".to_owned(),
            ));
        }

        if record_type == TLS_RECORD_HANDSHAKE {
            let mut handshake_offset = record_body_start;
            while handshake_offset + TLS_HANDSHAKE_HEADER_LEN <= record_end {
                let handshake_len = ((records[handshake_offset + 1] as usize) << 16)
                    | ((records[handshake_offset + 2] as usize) << 8)
                    | (records[handshake_offset + 3] as usize);
                let handshake_end = handshake_offset
                    .checked_add(TLS_HANDSHAKE_HEADER_LEN)
                    .and_then(|start| start.checked_add(handshake_len))
                    .ok_or_else(|| {
                        TransportError::TlsConfig("TLS handshake length overflow".to_owned())
                    })?;
                if handshake_end > record_end {
                    return Err(TransportError::TlsConfig(
                        "truncated TLS ServerHello handshake".to_owned(),
                    ));
                }
                if records[handshake_offset] == TLS_HANDSHAKE_SERVER_HELLO {
                    return Ok(records[handshake_offset..handshake_end].to_vec());
                }
                handshake_offset = handshake_end;
            }
        }

        record_offset = record_end;
    }

    Err(TransportError::TlsConfig(
        "TLS ServerHello record was not captured".to_owned(),
    ))
}

fn rustls_config_error(error: RustlsError) -> TransportError {
    TransportError::TlsConfig(error.to_string())
}

struct RealityVerificationSnapshot {
    auth_key: [u8; 32],
    client_hello: Vec<u8>,
}

impl Drop for RealityVerificationSnapshot {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.client_hello.zeroize();
    }
}

enum RealityVerificationMaterial {
    Static {
        auth_key: [u8; 32],
        client_hello: Option<Vec<u8>>,
    },
    Finalized(Arc<RealityFinalizedClientHelloState>),
}

impl fmt::Debug for RealityVerificationMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static { client_hello, .. } => formatter
                .debug_struct("RealityVerificationMaterial::Static")
                .field("auth_key", &"<redacted>")
                .field("client_hello_len", &client_hello.as_ref().map(Vec::len))
                .finish(),
            Self::Finalized(_) => formatter
                .debug_struct("RealityVerificationMaterial::Finalized")
                .finish_non_exhaustive(),
        }
    }
}

impl Drop for RealityVerificationMaterial {
    fn drop(&mut self) {
        if let Self::Static {
            auth_key,
            client_hello,
        } = self
        {
            auth_key.zeroize();
            if let Some(client_hello) = client_hello {
                client_hello.zeroize();
            }
        }
    }
}

impl RealityVerificationMaterial {
    fn snapshot(&self) -> Result<RealityVerificationSnapshot, RustlsError> {
        match self {
            Self::Static {
                auth_key,
                client_hello,
            } => Ok(RealityVerificationSnapshot {
                auth_key: *auth_key,
                client_hello: client_hello.clone().unwrap_or_default(),
            }),
            Self::Finalized(finalized_state) => {
                let finalized = finalized_state.snapshot()?;
                Ok(RealityVerificationSnapshot {
                    auth_key: finalized.auth_key,
                    client_hello: finalized.client_hello.clone(),
                })
            }
        }
    }
}

struct RealityMldsa65VerifierContext {
    verifying_key: Vec<u8>,
    server_read_log: ServerReadLog,
}

impl fmt::Debug for RealityMldsa65VerifierContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityMldsa65VerifierContext")
            .field("verifying_key_len", &self.verifying_key.len())
            .finish()
    }
}

/// What `UConn.VerifyPeerCertificate` does when the certificate is not a
/// REALITY one: verify it as an ordinary certificate for the server name
/// against the system roots (`reality.go` lines 129-139). Only a certificate
/// that passes lets the handshake finish, and `accepted` records it so the
/// caller crawls instead of using the connection.
struct RealCertificateFallback {
    roots: Option<Arc<RootCertStore>>,
    accepted: AtomicBool,
}

impl fmt::Debug for RealCertificateFallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealCertificateFallback")
            .field("custom_roots", &self.roots.is_some())
            .field("accepted", &self.accepted)
            .finish()
    }
}

impl RealCertificateFallback {
    fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let roots = self.roots.clone().unwrap_or_else(|| {
            Arc::new(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
        });
        let verified =
            WebPkiServerVerifier::builder_with_provider(roots, Arc::new(reality_crypto_provider()))
                .build()
                .map_err(|_| {
                    RustlsError::InvalidCertificate(
                        CertificateError::ApplicationVerificationFailure,
                    )
                })?
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        self.accepted.store(true, Ordering::Release);
        Ok(verified)
    }
}

struct RealityServerVerifier {
    material: RealityVerificationMaterial,
    mldsa65: Option<RealityMldsa65VerifierContext>,
    real_certificate: Option<Arc<RealCertificateFallback>>,
}

impl fmt::Debug for RealityServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityServerVerifier")
            .field("material", &self.material)
            .field("mldsa65", &self.mldsa65)
            .field("real_certificate", &self.real_certificate)
            .finish()
    }
}

impl ServerCertVerifier for RealityServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let material = self.material.snapshot()?;
        let server_hello;
        let mldsa65 = if let Some(mldsa65) = &self.mldsa65 {
            let captured = {
                let mut captured = mldsa65
                    .server_read_log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                captured.take().ok_or(RustlsError::InvalidCertificate(
                    CertificateError::BadEncoding,
                ))?
            };
            server_hello = extract_server_hello(&captured)
                .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
            Some(RealityMldsa65CertificateInput {
                verifying_key: &mldsa65.verifying_key,
                client_hello: &material.client_hello,
                server_hello: &server_hello,
            })
        } else {
            None
        };

        match verify_reality_certificate_der_with_mldsa65(
            &material.auth_key,
            end_entity.as_ref(),
            mldsa65,
        ) {
            Ok(crate::reality::RealityCertificateVerification::Verified) => {
                Ok(ServerCertVerified::assertion())
            }
            Ok(crate::reality::RealityCertificateVerification::NotReality) => {
                match &self.real_certificate {
                    Some(fallback) => {
                        fallback.verify(end_entity, intermediates, server_name, ocsp_response, now)
                    }
                    None => Err(RustlsError::InvalidCertificate(
                        CertificateError::ApplicationVerificationFailure,
                    )),
                }
            }
            Err(_) => Err(RustlsError::InvalidCertificate(
                CertificateError::BadEncoding,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // A REALITY server never speaks TLS 1.2; only a real certificate that
        // already passed Web PKI verification gets this far, as uTLS allows.
        if !self
            .real_certificate
            .as_ref()
            .is_some_and(|fallback| fallback.accepted.load(Ordering::Acquire))
        {
            return Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let provider = crypto::ring::default_provider();
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        let provider = crypto::ring::default_provider();
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::reality::{prepare_reality_handshake, RealityHandshakeInput};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

    #[test]
    fn reality_config_keeps_supported_profile_certificate_decompressors() {
        for (fingerprint, expected) in [
            ("safari", BTreeSet::from([1u16])),
            ("firefox", BTreeSet::from([1u16, 2u16, 3u16])),
            ("android", BTreeSet::new()),
        ] {
            let profile = crate::utls_profiles::profile_for_fingerprint(fingerprint)
                .unwrap_or_else(|| panic!("{fingerprint}: profile must exist"));
            let config = reality_client_config(
                RealityVerificationMaterial::Static {
                    auth_key: [0; 32],
                    client_hello: None,
                },
                None,
                None,
                None,
                profile,
            )
            .unwrap_or_else(|error| panic!("{fingerprint}: config: {error}"));
            let algorithms = config
                .cert_decompressors
                .iter()
                .map(|decompressor| u16::from(decompressor.algorithm()))
                .collect::<BTreeSet<_>>();

            assert_eq!(algorithms, expected, "{fingerprint}");
        }
    }

    #[test]
    fn reality_client_hello_finalizer_seals_actual_chrome_client_hello() {
        let plan = RustlsRealityPlan::random()
            .expect("REALITY ClientHello plan should get random material");
        let server_secret = X25519StaticSecret::from([7u8; 32]);
        let server_public_key = X25519PublicKey::from(&server_secret).to_bytes();
        let prepared = crate::reality::RealityPreparedHandshake {
            patched_client_hello: Vec::new(),
            auth_key: [0; 32],
            session_id: [0; REALITY_SESSION_ID_LEN],
            version: [0, 0, 1],
            unix_time: 1_700_000_000,
            short_id: vec![0xaa, 0xbb, 0xcc],
            server_public_key,
        };
        let finalized_state = Arc::new(RealityFinalizedClientHelloState::default());
        let finalizer = Arc::new(RustlsRealityClientHelloFinalizer::new(
            &plan,
            "chrome",
            &prepared,
            finalized_state.clone(),
        ));

        let captured = plan
            .client_hello_message_with_finalizer("www.example.com", "chrome", finalizer)
            .expect("finalized ClientHello should be generated");
        let finalized = finalized_state
            .snapshot()
            .expect("finalizer should store verification material");

        assert_eq!(captured, finalized.client_hello);
        assert_eq!(
            &captured[TLS_CLIENT_HELLO_SESSION_ID_OFFSET
                ..TLS_CLIENT_HELLO_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN],
            finalized.session_id
        );
        assert_ne!(finalized.session_id, [0; REALITY_SESSION_ID_LEN]);
        assert_ne!(finalized.auth_key, [0; 32]);
    }

    const SPIDER_SERVER_NAME: &str = "spider.example.com";

    struct SpiderRequest {
        path: String,
        referer: Option<String>,
        cookies: Vec<String>,
        user_agent: Option<String>,
    }

    fn real_certificate_server() -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
        let certified = rcgen::generate_simple_self_signed(vec![SPIDER_SERVER_NAME.to_owned()])
            .expect("generate an ordinary certificate");
        let cert = certified.cert.der().clone();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .expect("server certificate");
        config.alpn_protocols = vec![b"h2".to_vec()];
        (Arc::new(config), cert)
    }

    /// Serves the real site over HTTP/2 and reports every request it sees.
    async fn serve_real_site(
        listener: tokio::net::TcpListener,
        config: Arc<rustls::ServerConfig>,
        requests: tokio::sync::mpsc::UnboundedSender<SpiderRequest>,
    ) {
        let (tcp, _) = listener.accept().await.expect("accept");
        let Ok(tls) = tokio_rustls::TlsAcceptor::from(config).accept(tcp).await else {
            return;
        };
        let mut connection = h2::server::handshake(tls)
            .await
            .expect("the crawl speaks HTTP/2 after the handshake");
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            let header = |name: http::header::HeaderName| {
                request
                    .headers()
                    .get(name)
                    .map(|value| value.to_str().expect("ASCII header").to_owned())
            };
            let _ = requests.send(SpiderRequest {
                path: request.uri().path_and_query().expect("path").to_string(),
                referer: header(http::header::REFERER),
                cookies: request
                    .headers()
                    .get_all(http::header::COOKIE)
                    .iter()
                    .map(|value| value.to_str().expect("ASCII cookie").to_owned())
                    .collect(),
                user_agent: header(http::header::USER_AGENT),
            });
            let response = http::Response::builder()
                .status(200)
                .body(())
                .expect("response");
            let mut body = respond.send_response(response, false).expect("respond");
            let _ = body.send_data(
                bytes::Bytes::from_static(br#"<a href="/learned">x</a><a href="/style.css">y</a>"#),
                true,
            );
        }
    }

    fn real_certificate_session(
        roots: Option<Arc<RootCertStore>>,
    ) -> (
        Box<RustlsRealityTlsSession>,
        crate::reality::RealityPreparedHandshake,
    ) {
        let plan = RustlsRealityPlan::random().expect("REALITY entropy");
        let prepared_client_hello = plan
            .prepare_client_hello(RealityClientHelloRequest {
                server_name: SPIDER_SERVER_NAME,
                fingerprint: "chrome",
            })
            .expect("prepared ClientHello");
        let session = RustlsRealityTlsSession {
            server_name: SPIDER_SERVER_NAME.to_owned(),
            fingerprint: "chrome".to_owned(),
            plan,
            prepared_client_hello,
            spider: RealitySpider::parse("/probe?c=1&t=1"),
            roots,
        };
        let prepared = prepare_reality_handshake(RealityHandshakeInput {
            version: [26, 10, 31],
            unix_time: 1_700_000_000,
            short_id: vec![0xaa, 0xbb],
            server_public_key: X25519PublicKey::from(&X25519StaticSecret::from([7u8; 32]))
                .to_bytes(),
            prepared_client_hello: session
                .prepared_client_hello()
                .expect("prepared ClientHello"),
        })
        .expect("sealed ClientHello");
        (Box::new(session), prepared)
    }

    async fn next_request(
        requests: &mut tokio::sync::mpsc::UnboundedReceiver<SpiderRequest>,
    ) -> SpiderRequest {
        tokio::time::timeout(std::time::Duration::from_secs(10), requests.recv())
            .await
            .expect("the crawl sends its requests")
            .expect("request")
    }

    #[tokio::test]
    async fn real_certificate_completes_handshake_then_crawls_spider_x_and_fails() {
        let (config, cert) = real_certificate_server();
        let mut roots = RootCertStore::empty();
        roots.add(cert).expect("trust the test certificate");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let (requests_tx, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(serve_real_site(listener, config, requests_tx));
        let (session, prepared) = real_certificate_session(Some(Arc::new(roots)));
        let tcp = TcpStream::connect(addr).await.expect("connect");

        let result = session.complete_over(tcp, prepared, None).await;

        assert!(
            matches!(
                result,
                Err(TransportError::Reality(RealityError::RealCertificate))
            ),
            "a real certificate must never yield a usable stream"
        );
        let first = next_request(&mut requests).await;
        assert_eq!(first.path, "/probe");
        assert_eq!(first.referer, None);
        assert_eq!(first.cookies, ["padding="]);
        assert!(first
            .user_agent
            .is_some_and(|agent| agent.starts_with("Mozilla/5.0")));

        // `c=1&t=1`: one follow-up from the remembered paths, which now hold
        // the link without a dot and not the stylesheet.
        let second = next_request(&mut requests).await;
        assert!(
            ["/probe", "/learned"].contains(&second.path.as_str()),
            "{}",
            second.path
        );
        assert_eq!(
            second.referer.as_deref(),
            Some("https://spider.example.com/probe")
        );
        assert_eq!(second.cookies, ["padding="]);
        server.abort();
    }

    #[tokio::test]
    async fn untrusted_real_certificate_still_aborts_the_handshake() {
        let (config, _) = real_certificate_server();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let (requests_tx, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(serve_real_site(listener, config, requests_tx));
        let (session, prepared) = real_certificate_session(None);
        let tcp = TcpStream::connect(addr).await.expect("connect");

        let result = session.complete_over(tcp, prepared, None).await;

        assert!(
            matches!(result, Err(TransportError::Tls(_))),
            "Go fails x509 verification of an untrusted certificate during the handshake"
        );
        server.await.expect("server task");
        assert!(requests.recv().await.is_none(), "nothing is crawled");
    }
}
