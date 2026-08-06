use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{crypto, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector as TokioTlsConnector;
use xray_routing::{Target, TargetAddr};

use crate::{
    connect_tcp_happy_eyeballs, connect_tcp_stream, BoxedTransportStream, HappyEyeballsConfig,
    SocketProtector, TlsClientConfig, TransportError, TransportStream,
};

#[derive(Clone)]
pub struct TlsConnector {
    client_config: Arc<rustls::ClientConfig>,
    insecure_client_config: Arc<rustls::ClientConfig>,
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
            client_config: Arc::new(base_client_config(false)?),
            insecure_client_config: Arc::new(base_client_config(true)?),
            socket_protector: None,
        })
    }

    pub fn with_client_config(client_config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            insecure_client_config: Arc::clone(&client_config),
            client_config,
            socket_protector: None,
        }
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.socket_protector = Some(protector);
        self
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
        let client_config = if config.allow_insecure {
            &self.insecure_client_config
        } else {
            &self.client_config
        };
        let stream = TokioTlsConnector::from(Arc::clone(client_config))
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

#[derive(Debug)]
struct NoCertificateVerification;

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

/// Builds the client config for a handshake that sends rustls' own
/// ClientHello, on the *ring* provider plain TLS has always used.
pub(crate) fn base_client_config(
    allow_insecure: bool,
) -> Result<rustls::ClientConfig, TransportError> {
    client_config_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()),
        allow_insecure,
    )
}

/// Builds the client config for a uTLS-shaped handshake.
///
/// Current fingerprint profiles plan post-quantum key shares — X25519MLKEM768
/// and X25519Kyber768Draft00 — that *ring* does not implement, and rustls
/// refuses a planned key share whose group its provider lacks. So shaped
/// handshakes run on the same aws-lc-rs provider REALITY already uses.
pub(crate) fn shaped_client_config(
    allow_insecure: bool,
) -> Result<rustls::ClientConfig, TransportError> {
    client_config_with_provider(Arc::new(shaping_crypto_provider()), allow_insecure)
}

fn client_config_with_provider(
    provider: Arc<crypto::CryptoProvider>,
    allow_insecure: bool,
) -> Result<rustls::ClientConfig, TransportError> {
    if allow_insecure {
        return insecure_rustls_client_config(provider);
    }

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls_client_config(provider, root_store)
}

/// Mirrors `reality_rustls::reality_crypto_provider`: every key exchange group
/// a fingerprint profile can name, with the post-quantum ones first.
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
) -> Result<rustls::ClientConfig, TransportError> {
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| TransportError::TlsConfig(error.to_string()))
        .map(|builder| {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        })
}

fn insecure_rustls_client_config(
    provider: Arc<crypto::CryptoProvider>,
) -> Result<rustls::ClientConfig, TransportError> {
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| TransportError::TlsConfig(error.to_string()))
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth()
        })
}
