use std::{
    cell::RefCell,
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{
        self, ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
        SupportedKxGroup,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError,
    NamedGroup, ProtocolVersion, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as TokioTlsConnector;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    reality::{
        validate_reality_client_hello_metadata, verify_reality_certificate_der_with_mldsa65,
        RealityError, RealityMldsa65CertificateInput, RealityPreparedClientHello,
    },
    reality_connector::{RealityClientHelloRequest, RealityTlsSession, RealityTlsSessionProvider},
    BoxedTransportStream, CapturedTcpStream, PenetratingTlsStream, ServerReadLog, TransportError,
};

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const REALITY_SESSION_ID_LEN: usize = 32;
const TLS_CLIENT_HELLO_SESSION_ID_OFFSET: usize = 39;

thread_local! {
    static RANDOM_PLAN: RefCell<Option<VecDeque<Vec<u8>>>> = const { RefCell::new(None) };
    static X25519_PLAN: RefCell<Option<[u8; 32]>> = const { RefCell::new(None) };
}

static PLANNED_RANDOM: PlannedSecureRandom = PlannedSecureRandom;
static PLANNED_X25519: PlannedX25519Group = PlannedX25519Group;

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
        if request.fingerprint != "chrome" {
            return Err(RealityError::UnsupportedRealityFingerprint(
                request.fingerprint.to_owned(),
            ));
        }

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
        }))
    }
}

#[derive(Clone)]
struct RustlsRealityPlan {
    hello_random: [u8; 32],
    extension_order_seed: [u8; 2],
    local_x25519_private_key: [u8; 32],
}

impl fmt::Debug for RustlsRealityPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityPlan")
            .field("hello_random", &"<redacted>")
            .field("extension_order_seed", &self.extension_order_seed)
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
        let mut extension_order_seed = [0; 2];
        let mut local_x25519_private_key = [0; 32];
        let secure_random = crypto::ring::default_provider().secure_random;

        secure_random.fill(&mut hello_random)?;
        secure_random.fill(&mut extension_order_seed)?;
        secure_random.fill(&mut local_x25519_private_key)?;

        let plan = Self {
            hello_random,
            extension_order_seed,
            local_x25519_private_key,
        };
        local_x25519_private_key.zeroize();

        Ok(plan)
    }

    fn prepare_client_hello(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, RealityError> {
        let record = self
            .client_hello_record(request.server_name, [0; REALITY_SESSION_ID_LEN], [0; 32])
            .map_err(|error| RealityError::ClientHelloGenerationFailed(error.to_string()))?;
        let raw_client_hello = extract_client_hello(&record)
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

    fn client_hello_record(
        &self,
        server_name: &str,
        session_id: [u8; REALITY_SESSION_ID_LEN],
        auth_key: [u8; 32],
    ) -> Result<Vec<u8>, TransportError> {
        let config = reality_client_config(auth_key, None)?;
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| TransportError::InvalidTlsServerName(server_name.to_owned()))?;
        let _guard = PlannedRealityValues::install(self, session_id);
        let mut connection =
            ClientConnection::new(Arc::new(config), server_name).map_err(rustls_config_error)?;
        let mut record = Vec::new();
        connection
            .write_tls(&mut record)
            .map_err(TransportError::Tcp)?;

        Ok(record)
    }
}

struct RustlsRealityTlsSession {
    server_name: String,
    fingerprint: String,
    plan: RustlsRealityPlan,
    prepared_client_hello: RealityPreparedClientHello,
}

impl fmt::Debug for RustlsRealityTlsSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsRealityTlsSession")
            .field("server_name", &self.server_name)
            .field("fingerprint", &self.fingerprint)
            .field("plan", &self.plan)
            .finish()
    }
}

#[async_trait]
impl RealityTlsSession for RustlsRealityTlsSession {
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
        let expected_record = self.plan.client_hello_record(
            &self.server_name,
            prepared.session_id,
            prepared.auth_key,
        )?;
        let expected_client_hello = extract_client_hello(&expected_record)?;
        if expected_client_hello != prepared.patched_client_hello {
            return Err(TransportError::TlsConfig(
                "REALITY patched ClientHello does not match rustls transcript ClientHello"
                    .to_owned(),
            ));
        }

        let server_read_log = mldsa65_verify
            .as_ref()
            .map(|_| Arc::new(Mutex::new(Some(Vec::new()))));
        let mldsa65 = mldsa65_verify.map(|verifying_key| RealityMldsa65VerifierContext {
            verifying_key,
            client_hello: expected_client_hello,
            server_read_log: server_read_log
                .as_ref()
                .expect("ML-DSA verifier has a server read log")
                .clone(),
        });
        let config = Arc::new(reality_client_config(prepared.auth_key, mldsa65)?);
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| TransportError::InvalidTlsServerName(self.server_name.clone()))?;
        let connector = TokioTlsConnector::from(config);
        let tcp_stream = CapturedTcpStream::new(tcp_stream, server_read_log);
        let connect = {
            let _guard = PlannedRealityValues::install(&self.plan, prepared.session_id);
            connector.connect(server_name, tcp_stream)
        };
        let stream = connect.await.map_err(TransportError::Tls)?;

        Ok(Box::new(PenetratingTlsStream::new(stream)))
    }
}

fn reality_client_config(
    mut auth_key: [u8; 32],
    mldsa65: Option<RealityMldsa65VerifierContext>,
) -> Result<ClientConfig, TransportError> {
    let provider = Arc::new(reality_crypto_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
    let verifier = RealityServerVerifier { auth_key, mldsa65 };
    auth_key.zeroize();
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();

    Ok(config)
}

fn reality_crypto_provider() -> CryptoProvider {
    let mut provider = crypto::ring::default_provider();
    provider.kx_groups = vec![&PLANNED_X25519];
    provider.secure_random = &PLANNED_RANDOM;
    provider
}

fn extract_client_hello(record: &[u8]) -> Result<Vec<u8>, TransportError> {
    if record.len() < TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN
        || record[0] != TLS_RECORD_HANDSHAKE
    {
        return Err(TransportError::TlsConfig(
            "rustls did not emit a TLS ClientHello record".to_owned(),
        ));
    }

    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let record_end = TLS_RECORD_HEADER_LEN
        .checked_add(record_len)
        .ok_or_else(|| TransportError::TlsConfig("TLS record length overflow".to_owned()))?;
    if record.len() < record_end {
        return Err(TransportError::TlsConfig(
            "truncated TLS ClientHello record".to_owned(),
        ));
    }

    let handshake = &record[TLS_RECORD_HEADER_LEN..record_end];
    if handshake.first() != Some(&TLS_HANDSHAKE_CLIENT_HELLO) {
        return Err(TransportError::TlsConfig(
            "TLS record payload is not ClientHello".to_owned(),
        ));
    }

    Ok(handshake.to_vec())
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

struct PlannedRealityValues;

impl PlannedRealityValues {
    fn install(plan: &RustlsRealityPlan, session_id: [u8; REALITY_SESSION_ID_LEN]) -> Self {
        RANDOM_PLAN.with(|cell| {
            let mut queue = VecDeque::new();
            queue.push_back(session_id.to_vec());
            queue.push_back(plan.extension_order_seed.to_vec());
            queue.push_back(plan.hello_random.to_vec());
            *cell.borrow_mut() = Some(queue);
        });
        X25519_PLAN.with(|cell| {
            *cell.borrow_mut() = Some(plan.local_x25519_private_key);
        });

        Self
    }
}

impl Drop for PlannedRealityValues {
    fn drop(&mut self) {
        RANDOM_PLAN.with(|cell| {
            if let Some(mut queue) = cell.borrow_mut().take() {
                for bytes in &mut queue {
                    bytes.zeroize();
                }
            }
        });
        X25519_PLAN.with(|cell| {
            if let Some(mut private_key) = cell.borrow_mut().take() {
                private_key.zeroize();
            }
        });
    }
}

#[derive(Debug)]
struct PlannedSecureRandom;

impl SecureRandom for PlannedSecureRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        let planned = RANDOM_PLAN.with(|cell| {
            let mut borrow = cell.borrow_mut();
            let queue = borrow.as_mut()?;

            queue.pop_front()
        });

        match planned {
            Some(mut bytes) if bytes.len() == output.len() => {
                output.copy_from_slice(&bytes);
                bytes.zeroize();
                Ok(())
            }
            Some(mut bytes) => {
                bytes.zeroize();
                Err(GetRandomFailed)
            }
            None => crypto::ring::default_provider().secure_random.fill(output),
        }
    }
}

#[derive(Debug)]
struct PlannedX25519Group;

impl SupportedKxGroup for PlannedX25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let private_key = X25519_PLAN.with(|cell| cell.borrow_mut().take());
        let private_key = match private_key {
            Some(private_key) => private_key,
            None => {
                let mut random = [0; 32];
                crypto::ring::default_provider()
                    .secure_random
                    .fill(&mut random)
                    .map_err(|_| RustlsError::FailedToGetRandomBytes)?;
                random
            }
        };
        let secret = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&secret).to_bytes();

        Ok(Box::new(PlannedX25519Exchange {
            private_key,
            public_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct PlannedX25519Exchange {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl Drop for PlannedX25519Exchange {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl ActiveKeyExchange for PlannedX25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let peer_pub_key: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::PeerMisbehaved::InvalidKeyShare)?;
        let secret = StaticSecret::from(self.private_key);
        let peer = PublicKey::from(peer_pub_key);
        let shared_secret = secret.diffie_hellman(&peer);
        if !shared_secret.was_contributory() {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }

        Ok(SharedSecret::from(shared_secret.to_bytes().to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct RealityMldsa65VerifierContext {
    verifying_key: Vec<u8>,
    client_hello: Vec<u8>,
    server_read_log: ServerReadLog,
}

impl fmt::Debug for RealityMldsa65VerifierContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityMldsa65VerifierContext")
            .field("verifying_key_len", &self.verifying_key.len())
            .field("client_hello_len", &self.client_hello.len())
            .finish()
    }
}

struct RealityServerVerifier {
    auth_key: [u8; 32],
    mldsa65: Option<RealityMldsa65VerifierContext>,
}

impl fmt::Debug for RealityServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityServerVerifier")
            .field("auth_key", &"<redacted>")
            .field("mldsa65", &self.mldsa65)
            .finish()
    }
}

impl Drop for RealityServerVerifier {
    fn drop(&mut self) {
        self.auth_key.zeroize();
    }
}

impl ServerCertVerifier for RealityServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
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
                client_hello: &mldsa65.client_hello,
                server_hello: &server_hello,
            })
        } else {
            None
        };

        match verify_reality_certificate_der_with_mldsa65(
            &self.auth_key,
            end_entity.as_ref(),
            mldsa65,
        ) {
            Ok(crate::reality::RealityCertificateVerification::Verified) => {
                Ok(ServerCertVerified::assertion())
            }
            Ok(crate::reality::RealityCertificateVerification::NotReality) => Err(
                RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
            ),
            Err(_) => Err(RustlsError::InvalidCertificate(
                CertificateError::BadEncoding,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
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
