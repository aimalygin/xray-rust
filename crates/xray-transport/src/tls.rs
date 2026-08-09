use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    crypto, ClientConnection, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector as TokioTlsConnector;
use xray_routing::{Target, TargetAddr};

use crate::{
    connect_tcp_happy_eyeballs, connect_tcp_stream, utls_profiles::UtlsClientHelloProfile,
    utls_shaping::profile_offers_tls13, BoxedTransportStream, HappyEyeballsConfig, SocketProtector,
    TlsClientConfig, TransportError, TransportStream,
};

/// Identifies one rustls configuration shape. Two connections that agree on
/// all three fields share a config, which matters less for build cost —
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
    alpn: Vec<String>,
    fingerprint: Option<String>,
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
    socket_protector: Option<Arc<dyn SocketProtector>>,
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
            socket_protector: None,
        })
    }

    /// Pins one prebuilt config for every connection, for tests that supply
    /// their own roots.
    ///
    /// Such a connector has no config cache and performs no fingerprint
    /// validation: it ignores `TlsClientConfig::fingerprint` entirely, so it
    /// sends an unshaped ClientHello and returns `Ok` even for a fingerprint
    /// that `system()` would reject with `UnsupportedTlsFingerprint`. A test
    /// that means to exercise shaping must use `system()` — with
    /// `allow_insecure: true` if it needs to reach a self-signed local
    /// listener.
    pub fn with_pinned_client_config(client_config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            source: Arc::new(ConfigSource::Pinned(client_config)),
            socket_protector: None,
        }
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.socket_protector = Some(protector);
        self
    }

    /// Returns the config for one connection shape, building and caching it on
    /// first use.
    pub fn client_config_for(
        &self,
        config: &TlsClientConfig,
    ) -> Result<Arc<rustls::ClientConfig>, TransportError> {
        match &*self.source {
            ConfigSource::Pinned(pinned) => Ok(Arc::clone(pinned)),
            ConfigSource::Cached(configs) => {
                let TlsClientConfig {
                    // Per-connection, not per-config: rustls receives it at `connect`.
                    server_name: _,
                    allow_insecure,
                    alpn,
                    fingerprint,
                } = config;
                let key = ClientConfigKey {
                    allow_insecure: *allow_insecure,
                    alpn: alpn.clone(),
                    fingerprint: fingerprint.clone(),
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

                let client_config = Arc::new(build_client_config(config)?);
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
        self.connect_stream_with_server_name(stream, config, server_name)
            .await
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
        self.connect_stream_with_server_name(Box::new(stream), config, server_name)
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
        self.connect_stream_with_server_name(Box::new(stream), config, server_name)
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

        self.connect_stream_with_server_name(Box::new(stream), config, server_name)
            .await
    }

    async fn connect_stream_with_server_name(
        &self,
        stream: BoxedTransportStream,
        config: &TlsClientConfig,
        server_name: ServerName<'static>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let client_config = self.client_config_for(config)?;
        let stream = TokioTlsConnector::from(client_config)
            .connect(server_name, stream)
            .await
            .map_err(TransportError::Tls)?;

        Ok(Box::new(stream))
    }
}

fn tls_server_name(config: &TlsClientConfig) -> Result<ServerName<'static>, TransportError> {
    ServerName::try_from(config.server_name.clone())
        .map_err(|_| TransportError::InvalidTlsServerName(config.server_name.clone()))
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
fn build_client_config(config: &TlsClientConfig) -> Result<rustls::ClientConfig, TransportError> {
    let client_config = match crate::utls_tls::shaping_profile(config.fingerprint.as_deref())? {
        Some((fingerprint, profile)) => {
            let versions = profile_protocol_versions(profile);
            let provider = Arc::new(shaping_crypto_provider());
            reject_unnegotiable_fingerprint(fingerprint, profile, &provider, versions)?;

            let mut client_config =
                shaped_client_config(provider, config.allow_insecure, versions)?;
            client_config.client_hello_customizer = Some(Arc::new(
                crate::utls_tls::UtlsClientHelloCustomizer::new(profile, &config.alpn),
            ));
            client_config
        }
        None => {
            let mut client_config = unshaped_client_config(config.allow_insecure)?;
            // Xray's `unsafe` sentinel falls through to stock `tls.Client`,
            // which sends `tlsConfig.NextProtos`, so an unshaped hello has to
            // advertise the configured list too. Gated on the list rather than
            // on the fingerprint: `fingerprint: None` is what call sites that
            // predate fingerprint support pass, and with no ALPN configured
            // they must keep getting the hello they always got -- one with no
            // ALPN extension, which an empty list is not the same as.
            if !config.alpn.is_empty() {
                client_config.alpn_protocols = config
                    .alpn
                    .iter()
                    .map(|protocol| protocol.as_bytes().to_vec())
                    .collect();
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
    let client_config = build_client_config(config)?;

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
/// A profile's cipher suites go on the wire verbatim, but rustls can only *use*
/// one its provider implements: when the server picks any of the others,
/// `find_cipher_suite` comes back empty and the connection dies at ServerHello
/// with `SelectedUnofferedCipherSuite` (`rustls/src/client/hs.rs:1774`).
/// `hello360_7_5` is such a profile — twenty suites, every one CBC, RC4 or
/// 3DES, against rustls' six TLS 1.2 AEAD suites — so every dial on it is a
/// socket opened to lose. Measured against a Go server keeping its legacy
/// suites enabled: it selects `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` (0xc009)
/// and we abort. uTLS completes that same handshake, so this is our limit
/// rather than the parrot's, and saying so here beats discovering it a round
/// trip later under an error that names neither the fingerprint nor the cause.
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
fn unshaped_client_config(allow_insecure: bool) -> Result<rustls::ClientConfig, TransportError> {
    client_config_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()),
        allow_insecure,
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
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ClientConfig, TransportError> {
    let mut config = client_config_with_provider(provider, allow_insecure, versions)?;
    // A resumed handshake sends a second ClientHello carrying pre_shared_key,
    // which is outside the shape the fingerprint describes.
    config.resumption = rustls::client::Resumption::disabled();

    Ok(config)
}

fn client_config_with_provider(
    provider: Arc<crypto::CryptoProvider>,
    allow_insecure: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ClientConfig, TransportError> {
    if allow_insecure {
        return insecure_rustls_client_config(provider, versions);
    }

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls_client_config(provider, root_store, versions)
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
