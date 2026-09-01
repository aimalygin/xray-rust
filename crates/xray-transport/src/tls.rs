use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    crypto, CertificateError, ClientConnection, DigitallySignedStruct, Error as RustlsError,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector as TokioTlsConnector;
use x509_parser::prelude::{FromDer, X509Certificate};
use xray_routing::{Target, TargetAddr};

use crate::{
    connect_tcp_happy_eyeballs, connect_tcp_stream,
    utls_profiles::UtlsClientHelloProfile,
    utls_shaping::profile_offers_tls13,
    utls_tls::{unshaped_alpn_protocols, TlsAlpnPolicy},
    BoxedTransportStream, HappyEyeballsConfig, SocketProtector, TlsClientConfig, TransportError,
    TransportStream,
};

/// Identifies one rustls configuration shape. Two connections that agree on
/// all six fields share a config, which matters less for build cost —
/// webpki-roots ships pre-parsed statics, so building one is microseconds —
/// than for continuity: a `ClientConfig` owns the resumption session store, so
/// splitting configs splits session tickets and kx hints along with them.
///
/// `server_name` is deliberately not part of a shape: rustls takes it as a
/// `connect` argument, so it never reaches the config. `client_config_for`
/// destructures `TlsClientConfig` rather than reading fields, so a field added
/// there stops this file from compiling until someone decides which kind it is.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ClientConfigKey {
    allow_insecure: bool,
    pinned_peer_cert_sha256: Vec<[u8; 32]>,
    verify_peer_cert_by_name: Vec<String>,
    alpn: Vec<String>,
    fingerprint: Option<String>,
    alpn_policy: TlsAlpnPolicy,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Http3ClientConfigKey {
    System {
        allow_insecure: bool,
        pinned_peer_cert_sha256: Vec<[u8; 32]>,
        verify_peer_cert_by_name: Vec<String>,
    },
    Pinned,
}

/// Where a connector's rustls configs come from. The two kinds are mutually
/// exclusive by construction, so they are mutually exclusive by type: a pinned
/// connector cannot also carry a cache to consult, and a cached one cannot be
/// silently overridden.
enum ConfigSource {
    /// Builds one config per shape on demand and remembers it.
    Cached(Mutex<HashMap<ClientConfigKey, Arc<rustls::ClientConfig>>>),
    /// One prebuilt config, handed out for every shape.
    Pinned(Arc<rustls::ClientConfig>),
}

#[derive(Clone)]
pub struct TlsConnector {
    /// Shared with every clone of this connector, so a cached connector builds
    /// a shape once per connector family rather than once per clone --
    /// `tls_connector_clones_share_one_config_cache` pins that.
    source: Arc<ConfigSource>,
    /// HTTP/3 deliberately bypasses uTLS shaping and the ordinary stream
    /// config cache. Keeping its own semantic cache preserves QUIC session
    /// tickets while coalescing configs that differ only in ignored
    /// fingerprint or configured ALPN fields.
    http3_configs: Arc<Mutex<HashMap<Http3ClientConfigKey, Arc<rustls::ClientConfig>>>>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
}

pub(crate) struct PreparedTlsStream {
    client_config: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsConnector")
            .field("socket_protector", &self.socket_protector.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsConnector {
    pub fn system() -> Result<Self, TransportError> {
        Ok(Self {
            source: Arc::new(ConfigSource::Cached(Mutex::new(HashMap::new()))),
            http3_configs: Arc::new(Mutex::new(HashMap::new())),
            socket_protector: None,
        })
    }

    /// Pins one prebuilt config for every connection, for tests that supply
    /// their own roots.
    ///
    /// Such a connector has no config cache and performs no fingerprint
    /// validation: it ignores `TlsClientConfig::fingerprint` entirely, so it
    /// sends an unshaped ClientHello and returns `Ok` even for a fingerprint
    /// that `system()` would reject with `UnsupportedTlsFingerprint`.
    /// Custom certificate verification is different: silently ignoring trust
    /// policy would be unsafe, so non-empty pins or verification names are
    /// rejected. A test
    /// that means to exercise shaping or certificate pins must use `system()` — with
    /// `allow_insecure: true` if it needs to reach a self-signed local
    /// listener.
    pub fn with_pinned_client_config(client_config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            source: Arc::new(ConfigSource::Pinned(client_config)),
            http3_configs: Arc::new(Mutex::new(HashMap::new())),
            socket_protector: None,
        }
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.socket_protector = Some(protector);
        self
    }

    pub(crate) fn socket_protector_arc(&self) -> Option<Arc<dyn SocketProtector>> {
        self.socket_protector.clone()
    }

    /// Returns the config for one connection shape, building and caching it on
    /// first use.
    pub fn client_config_for(
        &self,
        config: &TlsClientConfig,
    ) -> Result<Arc<rustls::ClientConfig>, TransportError> {
        self.client_config_for_policy(config, TlsAlpnPolicy::Raw)
    }

    /// Builds the stock TLS configuration used by XHTTP HTTP/3.
    ///
    /// Xray's H3 path hands its ordinary Go TLS config directly to QUIC; its
    /// uTLS TCP dial callback is not used. Accordingly this path ignores both
    /// the fingerprint and configured ALPN, always advertises exactly `h3`,
    /// and never installs a ClientHello customizer.
    pub(crate) fn http3_client_config_for(
        &self,
        config: &TlsClientConfig,
    ) -> Result<Arc<rustls::ClientConfig>, TransportError> {
        // A prebuilt config cannot carry Xray's per-outbound verification
        // policy. Reject before consulting its shape-independent H3 cache so
        // a previously cached permissive config cannot bypass this guard.
        if matches!(&*self.source, ConfigSource::Pinned(_)) {
            reject_custom_verification_with_prebuilt_config(config)?;
        }
        let key = match &*self.source {
            ConfigSource::Cached(_) => Http3ClientConfigKey::System {
                allow_insecure: config.allow_insecure,
                pinned_peer_cert_sha256: config.pinned_peer_cert_sha256.clone(),
                verify_peer_cert_by_name: config.verify_peer_cert_by_name.clone(),
            },
            ConfigSource::Pinned(_) => Http3ClientConfigKey::Pinned,
        };
        let mut configs = self
            .http3_configs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cached) = configs.get(&key) {
            return Ok(Arc::clone(cached));
        }

        let mut client_config = match &*self.source {
            ConfigSource::Cached(_) => client_config_with_provider(
                Arc::new(rustls::crypto::ring::default_provider()),
                config.allow_insecure,
                &config.pinned_peer_cert_sha256,
                &config.verify_peer_cert_by_name,
                &[&rustls::version::TLS13],
            )?,
            ConfigSource::Pinned(pinned) => (**pinned).clone(),
        };
        client_config.alpn_protocols = vec![b"h3".to_vec()];
        client_config.client_hello_customizer = None;
        validate_http3_client_config(&client_config)?;
        let client_config = Arc::new(client_config);
        configs.insert(key, Arc::clone(&client_config));
        Ok(client_config)
    }

    fn client_config_for_policy(
        &self,
        config: &TlsClientConfig,
        alpn_policy: TlsAlpnPolicy,
    ) -> Result<Arc<rustls::ClientConfig>, TransportError> {
        match &*self.source {
            ConfigSource::Pinned(pinned) => {
                reject_custom_verification_with_prebuilt_config(config)?;
                Ok(Arc::clone(pinned))
            }
            ConfigSource::Cached(configs) => {
                let TlsClientConfig {
                    // Per-connection, not per-config: rustls receives it at `connect`.
                    server_name: _,
                    allow_insecure,
                    pinned_peer_cert_sha256,
                    verify_peer_cert_by_name,
                    alpn,
                    fingerprint,
                } = config;
                let key = ClientConfigKey {
                    allow_insecure: *allow_insecure,
                    pinned_peer_cert_sha256: pinned_peer_cert_sha256.clone(),
                    verify_peer_cert_by_name: verify_peer_cert_by_name.clone(),
                    alpn: alpn.clone(),
                    fingerprint: fingerprint.clone(),
                    alpn_policy,
                };

                // Deliberately fails open where the plan said to fail closed:
                // `insert` runs after the fallible build, so a panic leaves an
                // entry absent but never half-built, and erroring would turn
                // one unrelated panic into a tunnel that stays down until the
                // process restarts.
                let mut configs = configs
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(cached) = configs.get(&key) {
                    return Ok(Arc::clone(cached));
                }

                let client_config = Arc::new(build_client_config(config, alpn_policy)?);
                configs.insert(key, Arc::clone(&client_config));

                Ok(client_config)
            }
        }
    }

    pub async fn connect_stream(
        &self,
        stream: BoxedTransportStream,
        config: &TlsClientConfig,
    ) -> Result<BoxedTransportStream, TransportError> {
        let server_name = tls_server_name(config)?;
        self.connect_stream_with_server_name(stream, config, server_name, TlsAlpnPolicy::Raw)
            .await
    }

    pub(crate) fn prepare_stream(
        &self,
        config: &TlsClientConfig,
        alpn_policy: TlsAlpnPolicy,
    ) -> Result<PreparedTlsStream, TransportError> {
        Ok(PreparedTlsStream {
            client_config: self.client_config_for_policy(config, alpn_policy)?,
            server_name: tls_server_name(config)?,
        })
    }

    pub(crate) async fn connect_prepared_stream(
        &self,
        stream: BoxedTransportStream,
        prepared: PreparedTlsStream,
    ) -> Result<BoxedTransportStream, TransportError> {
        let stream = TokioTlsConnector::from(prepared.client_config)
            .connect(prepared.server_name, stream)
            .await
            .map_err(TransportError::Tls)?;

        Ok(Box::new(stream))
    }

    pub async fn connect(
        &self,
        target: &Target,
        config: &TlsClientConfig,
    ) -> Result<BoxedTransportStream, TransportError> {
        let server_name = tls_server_name(config)?;

        let addr = match &target.addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
            TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
        };

        let stream = connect_tcp_stream(addr, self.socket_protector.as_deref()).await?;
        self.connect_stream_with_server_name(
            Box::new(stream),
            config,
            server_name,
            TlsAlpnPolicy::Raw,
        )
        .await
    }

    /// Connects one resolved address without discarding IPv6 scope or flow metadata.
    pub async fn connect_socket_addr(
        &self,
        addr: SocketAddr,
        config: &TlsClientConfig,
    ) -> Result<BoxedTransportStream, TransportError> {
        let server_name = tls_server_name(config)?;
        let stream = connect_tcp_stream(addr, self.socket_protector.as_deref()).await?;
        self.connect_stream_with_server_name(
            Box::new(stream),
            config,
            server_name,
            TlsAlpnPolicy::Raw,
        )
        .await
    }

    /// Races raw TCP candidates, then performs exactly one TLS handshake on
    /// the winning stream.
    pub async fn connect_candidates(
        &self,
        candidates: &[SocketAddr],
        config: &TlsClientConfig,
        happy_eyeballs: &HappyEyeballsConfig,
    ) -> Result<BoxedTransportStream, TransportError> {
        // Validate SNI before opening any socket.
        let server_name = tls_server_name(config)?;
        let stream = connect_tcp_happy_eyeballs(
            candidates,
            self.socket_protector.as_deref(),
            happy_eyeballs,
        )
        .await?;

        self.connect_stream_with_server_name(
            Box::new(stream),
            config,
            server_name,
            TlsAlpnPolicy::Raw,
        )
        .await
    }

    async fn connect_stream_with_server_name(
        &self,
        stream: BoxedTransportStream,
        config: &TlsClientConfig,
        server_name: ServerName<'static>,
        alpn_policy: TlsAlpnPolicy,
    ) -> Result<BoxedTransportStream, TransportError> {
        let prepared = PreparedTlsStream {
            client_config: self.client_config_for_policy(config, alpn_policy)?,
            server_name,
        };
        self.connect_prepared_stream(stream, prepared).await
    }
}

fn tls_server_name(config: &TlsClientConfig) -> Result<ServerName<'static>, TransportError> {
    parse_tls_server_name(&config.server_name)
}

pub(crate) fn parse_tls_server_name(
    server_name: &str,
) -> Result<ServerName<'static>, TransportError> {
    ServerName::try_from(server_name.to_owned())
        .map_err(|_| TransportError::InvalidTlsServerName(server_name.to_owned()))
}

fn validate_http3_client_config(
    client_config: &rustls::ClientConfig,
) -> Result<(), TransportError> {
    let mut probe = client_config.clone();
    probe.resumption = rustls::client::Resumption::disabled();
    let server_name = parse_tls_server_name("h3-preflight.invalid")?;
    rustls::quic::ClientConnection::new(
        Arc::new(probe),
        rustls::quic::Version::V1,
        server_name,
        Vec::new(),
    )
    .map(|_| ())
    .map_err(|error| TransportError::TlsConfig(error.to_string()))
}

impl TransportStream for tokio_rustls::client::TlsStream<BoxedTransportStream> {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

/// Skips certificate verification, but still verifies handshake signatures
/// with the algorithms of the provider it was built alongside. Pinning ring's
/// set here would reject signatures the shaped provider's own profile
/// advertises — P-521, for one.
#[derive(Debug)]
struct NoCertificateVerification {
    provider: Arc<crypto::CryptoProvider>,
}

/// Xray-compatible verifier for `pinnedPeerCertSha256` and
/// `verifyPeerCertByName`.
///
/// The pins cover complete DER certificates. A leaf match intentionally
/// short-circuits all PKI and name checks, matching Xray. Otherwise the first
/// matching CA from the peer-presented chain becomes the only trust anchor.
/// With no CA pin the ordinary system roots remain in force. The configured
/// verification names are ORed and deliberately do not affect the SNI passed
/// to the handshake.
#[derive(Debug)]
struct XrayCertificateVerification {
    provider: Arc<crypto::CryptoProvider>,
    system_roots: Arc<rustls::RootCertStore>,
    pins: Vec<[u8; 32]>,
    verification_names: Vec<String>,
}

impl ServerCertVerifier for XrayCertificateVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Xray parses the complete presented chain before considering even a
        // leaf pin. Keep malformed DER from turning a matching digest into an
        // acceptance shortcut.
        certificate_ca_flag(end_entity)?;
        let intermediate_ca_flags = intermediates
            .iter()
            .map(certificate_ca_flag)
            .collect::<Result<Vec<_>, _>>()?;

        if self.matches_pin(end_entity) {
            return Ok(ServerCertVerified::assertion());
        }

        let roots =
            if self.pins.is_empty() {
                Arc::clone(&self.system_roots)
            } else {
                let Some(pinned_ca) = intermediates.iter().zip(intermediate_ca_flags).find_map(
                    |(certificate, is_ca)| {
                        (is_ca && self.matches_pin(certificate)).then_some(certificate)
                    },
                ) else {
                    return Err(certificate_verification_error());
                };

                let mut roots = rustls::RootCertStore::empty();
                roots
                    .add(pinned_ca.clone())
                    .map_err(|_| certificate_verification_error())?;
                Arc::new(roots)
            };
        let verifier =
            WebPkiServerVerifier::builder_with_provider(roots, Arc::clone(&self.provider))
                .build()
                .map_err(|_| certificate_verification_error())?;

        if self.verification_names.is_empty() {
            return verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
        }

        for verification_name in &self.verification_names {
            let Ok(verification_name) = ServerName::try_from(verification_name.clone()) else {
                continue;
            };
            if verifier
                .verify_server_cert(
                    end_entity,
                    intermediates,
                    &verification_name,
                    ocsp_response,
                    now,
                )
                .is_ok()
            {
                return Ok(ServerCertVerified::assertion());
            }
        }

        Err(certificate_verification_error())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl XrayCertificateVerification {
    fn matches_pin(&self, certificate: &CertificateDer<'_>) -> bool {
        let digest: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        self.pins.contains(&digest)
    }
}

fn certificate_ca_flag(certificate: &CertificateDer<'_>) -> Result<bool, RustlsError> {
    let (remaining, certificate) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;
    if !remaining.is_empty() {
        return Err(RustlsError::InvalidCertificate(
            CertificateError::BadEncoding,
        ));
    }
    Ok(certificate.is_ca())
}

fn certificate_verification_error() -> RustlsError {
    RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

fn reject_custom_verification_with_prebuilt_config(
    config: &TlsClientConfig,
) -> Result<(), TransportError> {
    if config.pinned_peer_cert_sha256.is_empty() && config.verify_peer_cert_by_name.is_empty() {
        Ok(())
    } else {
        Err(TransportError::TlsConfig(
            "pinnedPeerCertSha256 and verifyPeerCertByName cannot be combined with a prebuilt TLS client config"
                .to_owned(),
        ))
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Builds the rustls config one `TlsClientConfig` asks for, and is the only
/// way to obtain one: the two builders below are private so that no future
/// transport can reach past the fingerprint and emit an unshaped ClientHello
/// by accident.
fn build_client_config(
    config: &TlsClientConfig,
    alpn_policy: TlsAlpnPolicy,
) -> Result<rustls::ClientConfig, TransportError> {
    let client_config = match crate::utls_tls::shaping_profile(config.fingerprint.as_deref())? {
        Some((fingerprint, profile)) => {
            let versions = profile_protocol_versions(profile);
            let provider = Arc::new(shaping_crypto_provider());
            reject_unnegotiable_fingerprint(fingerprint, profile, &provider, versions)?;

            let mut client_config = shaped_client_config(
                provider,
                config.allow_insecure,
                &config.pinned_peer_cert_sha256,
                &config.verify_peer_cert_by_name,
                versions,
            )?;
            crate::utls_shaping::retain_profile_certificate_decompressors(
                profile,
                &mut client_config.cert_decompressors,
            );
            client_config.client_hello_customizer = Some(Arc::new(
                crate::utls_tls::UtlsClientHelloCustomizer::new(profile, &config.alpn, alpn_policy),
            ));
            client_config
        }
        None => {
            let mut client_config = unshaped_client_config(
                config.allow_insecure,
                &config.pinned_peer_cert_sha256,
                &config.verify_peer_cert_by_name,
            )?;
            // Xray's `unsafe` sentinel falls through to stock `tls.Client`,
            // which sends `tlsConfig.NextProtos`, so an unshaped hello has to
            // advertise the configured list too. Gated on the list rather than
            // on the fingerprint: `fingerprint: None` is what call sites that
            // predate fingerprint support pass, and with no ALPN configured
            // they must keep getting the hello they always got -- one with no
            // ALPN extension, which an empty list is not the same as.
            let alpn_protocols = unshaped_alpn_protocols(&config.alpn, alpn_policy);
            if !alpn_protocols.is_empty() {
                client_config.alpn_protocols = alpn_protocols;
            }
            client_config
        }
    };

    Ok(client_config)
}

/// Produces the ClientHello a plain-TLS connection would send, without opening
/// a socket. Exposed for byte-parity tests against Xray-core.
///
/// The returned bytes are the connection's whole first flight: one TLS
/// handshake record, header included, shaped or not. It shares
/// `build_client_config` with `TlsConnector` so the bytes the parity tests
/// inspect stay the bytes a real connection sends.
pub fn plain_tls_client_hello_bytes(config: &TlsClientConfig) -> Result<Vec<u8>, TransportError> {
    let client_config = build_client_config(config, TlsAlpnPolicy::Raw)?;

    let server_name = tls_server_name(config)?;
    let mut connection = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
    let mut first_flight = Vec::new();
    connection
        .write_tls(&mut first_flight)
        .map_err(TransportError::Tcp)?;

    Ok(first_flight)
}

/// The protocol versions a shaped config may offer.
///
/// Ten of the profiles describe a TLS-1.2-era ClientHello — no
/// `supported_versions` extension at all — and a config that offers TLS 1.3
/// behind one of those hellos cannot complete a handshake with anything: the
/// server answers with TLS 1.2, its ServerHello random carries the RFC 8446
/// §4.1.3 downgrade sentinel, and rustls reads that sentinel as an attack
/// because *its config* claimed 1.3 (`rustls/src/client/hs.rs:1673`, whose
/// `tls13_supported` comes from the config and not from the plan). uTLS avoids
/// it by writing the parrot's ceiling into `config.MaxVersion`; this is that
/// same write.
///
/// TLS 1.0 and 1.1, which uTLS also allows for these parrots, have no rustls
/// implementation, so the floor stays at 1.2 either way.
fn profile_protocol_versions(
    profile: &UtlsClientHelloProfile,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    const TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

    if profile_offers_tls13(profile) {
        rustls::DEFAULT_VERSIONS
    } else {
        TLS12_ONLY
    }
}

/// Refuses a fingerprint whose ClientHello no handshake of ours could finish.
///
/// Runtime shaping filters the profile's list to suites implemented by the
/// selected provider and enabled protocol versions before building the
/// ClientHello. A profile such as `hello360_7_5` contains only CBC, RC4, and
/// 3DES suites, while rustls exposes only AEAD suites, so filtering would leave
/// no usable offer. Rejecting that profile here produces a stable,
/// fingerprint-specific error before a socket is opened instead of relying on
/// a later generic ClientHello planning failure.
///
/// `versions` is part of the question rather than context for it: a suite this
/// provider implements only for the version the profile just gave up is a suite
/// this connection cannot reach.
fn reject_unnegotiable_fingerprint(
    fingerprint: &str,
    profile: &UtlsClientHelloProfile,
    provider: &crypto::CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<(), TransportError> {
    let negotiable = provider.cipher_suites.iter().any(|suite| {
        profile.cipher_suites.contains(&u16::from(suite.suite()))
            && versions
                .iter()
                .any(|version| version.version == suite.version().version)
    });

    if negotiable {
        return Ok(());
    }

    Err(TransportError::UnnegotiableTlsFingerprint(
        fingerprint.to_owned(),
    ))
}

/// Builds the client config for a handshake that sends rustls' own
/// ClientHello, on the *ring* provider plain TLS has always used. Keeping this
/// branch on *ring* is what makes "no shaping" reproduce the pre-shaping
/// ClientHello exactly.
fn unshaped_client_config(
    allow_insecure: bool,
    pinned_peer_cert_sha256: &[[u8; 32]],
    verify_peer_cert_by_name: &[String],
) -> Result<rustls::ClientConfig, TransportError> {
    client_config_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()),
        allow_insecure,
        pinned_peer_cert_sha256,
        verify_peer_cert_by_name,
        rustls::DEFAULT_VERSIONS,
    )
}

/// Builds the client config for a uTLS-shaped handshake.
///
/// The provider arrives built because `build_client_config` has already
/// consulted its cipher suites: whether the fingerprint is negotiable at all is
/// a question about this very provider, and asking it twice would let the two
/// answers drift.
fn shaped_client_config(
    provider: Arc<crypto::CryptoProvider>,
    allow_insecure: bool,
    pinned_peer_cert_sha256: &[[u8; 32]],
    verify_peer_cert_by_name: &[String],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ClientConfig, TransportError> {
    let mut config = client_config_with_provider(
        provider,
        allow_insecure,
        pinned_peer_cert_sha256,
        verify_peer_cert_by_name,
        versions,
    )?;
    // A resumed handshake sends a second ClientHello carrying pre_shared_key,
    // which is outside the shape the fingerprint describes.
    config.resumption = rustls::client::Resumption::disabled();

    Ok(config)
}

fn client_config_with_provider(
    provider: Arc<crypto::CryptoProvider>,
    allow_insecure: bool,
    pinned_peer_cert_sha256: &[[u8; 32]],
    verify_peer_cert_by_name: &[String],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ClientConfig, TransportError> {
    if allow_insecure
        && (!pinned_peer_cert_sha256.is_empty() || !verify_peer_cert_by_name.is_empty())
    {
        return Err(TransportError::TlsConfig(
            "allow_insecure cannot be combined with pinnedPeerCertSha256 or verifyPeerCertByName"
                .to_owned(),
        ));
    }
    if allow_insecure {
        return insecure_rustls_client_config(provider, versions);
    }
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if !pinned_peer_cert_sha256.is_empty() || !verify_peer_cert_by_name.is_empty() {
        return custom_verification_rustls_client_config(
            provider,
            root_store,
            pinned_peer_cert_sha256,
            verify_peer_cert_by_name,
            versions,
        );
    }

    rustls_client_config(provider, root_store, versions)
}

fn custom_verification_rustls_client_config(
    provider: Arc<crypto::CryptoProvider>,
    system_roots: rustls::RootCertStore,
    pinned_peer_cert_sha256: &[[u8; 32]],
    verify_peer_cert_by_name: &[String],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ClientConfig, TransportError> {
    let verifier = Arc::new(XrayCertificateVerification {
        provider: Arc::clone(&provider),
        system_roots: Arc::new(system_roots),
        pins: pinned_peer_cert_sha256.to_vec(),
        verification_names: verify_peer_cert_by_name.to_vec(),
    });
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|error| TransportError::TlsConfig(error.to_string()))
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        })
}

/// The provider every uTLS-shaped handshake runs on.
///
/// aws-lc-rs rather than the *ring* an unshaped hello keeps: current profiles
/// plan post-quantum key shares — X25519MLKEM768 and X25519Kyber768Draft00 —
/// that *ring* does not implement, and rustls refuses a planned key share whose
/// group its provider lacks. It is also what REALITY already uses.
///
/// The kx group list mirrors `reality_rustls::reality_crypto_provider`: every
/// key exchange group a fingerprint profile can name, post-quantum ones first.
fn shaping_crypto_provider() -> crypto::CryptoProvider {
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

fn rustls_client_config(
    provider: Arc<crypto::CryptoProvider>,
    root_store: rustls::RootCertStore,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ClientConfig, TransportError> {
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|error| TransportError::TlsConfig(error.to_string()))
        .map(|builder| {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        })
}

fn insecure_rustls_client_config(
    provider: Arc<crypto::CryptoProvider>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ClientConfig, TransportError> {
    let verifier = Arc::new(NoCertificateVerification {
        provider: Arc::clone(&provider),
    });
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|error| TransportError::TlsConfig(error.to_string()))
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        })
}

#[cfg(test)]
mod http3_tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    fn verification_chain() -> (CertificateDer<'static>, CertificateDer<'static>) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .expect("empty CA subject alt names are valid");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["server.test".to_owned(), "127.0.0.1".to_owned()])
                .expect("valid leaf names");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .expect("sign leaf with CA");

        (leaf_cert.der().clone(), ca_cert.der().clone())
    }

    fn ordinary_root_verifier(
        ca: &CertificateDer<'static>,
        names: &[&str],
    ) -> XrayCertificateVerification {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).expect("add test root");
        XrayCertificateVerification {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            system_roots: Arc::new(roots),
            pins: Vec::new(),
            verification_names: names.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    fn input(allow_insecure: bool, alpn: &[&str], fingerprint: Option<&str>) -> TlsClientConfig {
        TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: alpn.iter().map(|value| (*value).to_owned()).collect(),
            fingerprint: fingerprint.map(str::to_owned),
        }
    }

    #[test]
    fn stock_http3_tls_ignores_stream_shape_and_shares_a_semantic_cache() {
        let connector = TlsConnector::system().expect("system TLS connector");
        let first = connector
            .http3_client_config_for(&input(
                false,
                &["http/1.1"],
                Some("unsupported-stream-fingerprint"),
            ))
            .expect("H3 ignores stream fingerprint shaping");
        assert_eq!(first.alpn_protocols, [b"h3".to_vec()]);
        assert!(first.client_hello_customizer.is_none());

        let equivalent = connector
            .http3_client_config_for(&input(false, &["h2"], Some("chrome")))
            .expect("equivalent secure H3 config");
        assert!(Arc::ptr_eq(&first, &equivalent));

        let cloned_connector = connector.clone();
        let from_clone = cloned_connector
            .http3_client_config_for(&input(false, &[], None))
            .expect("connector clone shares H3 cache");
        assert!(Arc::ptr_eq(&first, &from_clone));

        let insecure = connector
            .http3_client_config_for(&input(true, &[], None))
            .expect("insecure H3 config");
        assert!(!Arc::ptr_eq(&first, &insecure));

        let mut named = input(false, &[], None);
        named.verify_peer_cert_by_name = vec!["cert.example".to_owned()];
        let named_config = connector
            .http3_client_config_for(&named)
            .expect("H3 verification-name config");
        let named_again = connector
            .http3_client_config_for(&named)
            .expect("cached H3 verification-name config");
        assert!(Arc::ptr_eq(&named_config, &named_again));
        assert!(!Arc::ptr_eq(&first, &named_config));
    }

    #[test]
    fn ordinary_roots_or_dns_and_ip_verification_names_without_reusing_sni() {
        let (leaf, ca) = verification_chain();
        let presented_chain = [ca.clone()];
        let handshake_name = ServerName::try_from("wrong-sni.test".to_owned()).expect("valid SNI");

        for names in [
            &["wrong.test", "SERVER.TEST."][..],
            &["wrong.test", "127.0.0.1"][..],
        ] {
            ordinary_root_verifier(&ca, names)
                .verify_server_cert(
                    &leaf,
                    &presented_chain,
                    &handshake_name,
                    &[],
                    UnixTime::now(),
                )
                .expect("one matching DNS/IP SAN must satisfy the OR list");
        }

        assert!(
            ordinary_root_verifier(&ca, &["wrong-one.test", "wrong-two.test"])
                .verify_server_cert(
                    &leaf,
                    &presented_chain,
                    &handshake_name,
                    &[],
                    UnixTime::now(),
                )
                .is_err()
        );
    }

    #[test]
    fn pinned_http3_tls_is_cloned_sanitized_and_requires_tls13() {
        let mut pinned = unshaped_client_config(false, &[], &[]).expect("pinned TLS config");
        pinned.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let pinned = Arc::new(pinned);
        let connector = TlsConnector::with_pinned_client_config(Arc::clone(&pinned));
        let h3 = connector
            .http3_client_config_for(&input(false, &["ignored"], Some("ignored")))
            .expect("derive H3 config from pinned roots/verifier");
        assert!(!Arc::ptr_eq(&pinned, &h3));
        assert_eq!(h3.alpn_protocols, [b"h3".to_vec()]);
        assert!(h3.client_hello_customizer.is_none());

        let mut named = input(false, &[], None);
        named.verify_peer_cert_by_name = vec!["cert.example".to_owned()];
        assert!(matches!(
            connector.http3_client_config_for(&named),
            Err(TransportError::TlsConfig(_))
        ));
        let mut pinned_policy = input(false, &[], None);
        pinned_policy.pinned_peer_cert_sha256 = vec![[0x11; 32]];
        assert!(matches!(
            connector.http3_client_config_for(&pinned_policy),
            Err(TransportError::TlsConfig(_))
        ));

        let tls12_only = client_config_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
            false,
            &[],
            &[],
            &[&rustls::version::TLS12],
        )
        .expect("TLS 1.2-only pinned config");
        let connector = TlsConnector::with_pinned_client_config(Arc::new(tls12_only));
        assert!(matches!(
            connector.http3_client_config_for(&input(false, &[], None)),
            Err(TransportError::TlsConfig(_))
        ));
    }
}
