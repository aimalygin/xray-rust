use std::{net::IpAddr, time::Duration};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{DnsResolver, TlsClientConfig, TlsConnector, TransportDialer};

use crate::outbound::open_tcp_stream_with_resolver_and_dialer;
use crate::{CoreError, OutboundRouter};

const MAX_HTTP_STATUS_LINE_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupProbeOptions {
    pub url: String,
    pub timeout: Duration,
    pub outbound_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedProbeUrl {
    pub(crate) scheme: ProbeScheme,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path_and_query: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeScheme {
    Http,
    Https,
}

impl ParsedProbeUrl {
    fn diagnostic_label(&self) -> String {
        format!("{}://<redacted-host>:{}", self.scheme.as_str(), self.port)
    }
}

impl ProbeScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartupProbeError {
    #[error("unsupported startup probe URL")]
    UnsupportedUrl,
    #[error("startup probe timed out after {timeout_ms}ms for `{url}`")]
    Timeout { url: String, timeout_ms: u128 },
    #[error("startup probe transport failed for `{url}`: {source}")]
    Core {
        url: String,
        #[source]
        source: Box<CoreError>,
    },
    #[error("startup probe TLS failed for `{url}`: {source}")]
    Tls {
        url: String,
        #[source]
        source: xray_transport::TransportError,
    },
    #[error("startup probe I/O failed for `{url}`: {source}")]
    Io {
        url: String,
        #[source]
        source: std::io::Error,
    },
    #[error("startup probe received malformed HTTP response from `{0}`")]
    MalformedHttpResponse(String),
    #[error("startup probe received HTTP status {status} from `{url}`")]
    HttpStatus { url: String, status: u16 },
}

pub(crate) async fn run_startup_probe(
    outbound_router: &OutboundRouter,
    options: StartupProbeOptions,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<(), StartupProbeError> {
    let timeout_ms = options.timeout.as_millis();
    let url = diagnostic_probe_url(&options.url);
    timeout(
        options.timeout,
        run_startup_probe_inner(
            outbound_router,
            &options,
            dns_resolver,
            transport_dialer,
            None,
        ),
    )
    .await
    .map_err(|_| StartupProbeError::Timeout { url, timeout_ms })?
}

pub(crate) fn diagnostic_probe_url(raw: &str) -> String {
    parse_probe_url(raw)
        .map(|parsed| parsed.diagnostic_label())
        .unwrap_or_else(|_| "<redacted>".to_owned())
}

async fn run_startup_probe_inner(
    outbound_router: &OutboundRouter,
    options: &StartupProbeOptions,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
    tls_connector: Option<&TlsConnector>,
) -> Result<(), StartupProbeError> {
    let parsed = parse_probe_url(&options.url)?;
    let url = parsed.diagnostic_label();
    let step_timeout = options.timeout;
    let outbound = outbound_router
        .select_tcp_outbound_direct(options.outbound_tag.as_deref())
        .map_err(|source| StartupProbeError::Core {
            url: url.clone(),
            source: Box::new(source),
        })?;
    let target = Target::new(
        probe_target_addr(&parsed.host),
        parsed.port,
        RoutingNetwork::Tcp,
    );
    let mut stream = timeout(
        step_timeout,
        open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            dns_resolver,
            transport_dialer,
        ),
    )
    .await
    .map_err(|_| StartupProbeError::Timeout {
        url: url.clone(),
        timeout_ms: step_timeout.as_millis(),
    })?
    .map_err(|source| StartupProbeError::Core {
        url: url.clone(),
        source: Box::new(source),
    })?;

    if parsed.scheme == ProbeScheme::Https {
        let system_tls;
        let tls_connector = match tls_connector {
            Some(tls_connector) => tls_connector,
            None => {
                system_tls = TlsConnector::system().map_err(|source| StartupProbeError::Tls {
                    url: url.clone(),
                    source,
                })?;
                &system_tls
            }
        };
        stream = timeout(
            step_timeout,
            tls_connector.connect_stream(
                stream,
                &TlsClientConfig {
                    server_name: parsed.host.clone(),
                    allow_insecure: false,
                },
            ),
        )
        .await
        .map_err(|_| StartupProbeError::Timeout {
            url: url.clone(),
            timeout_ms: step_timeout.as_millis(),
        })?
        .map_err(|source| StartupProbeError::Tls {
            url: url.clone(),
            source,
        })?;
    }

    let host = host_header_value(&parsed);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xray-rust-startup-probe\r\nConnection: close\r\n\r\n",
        parsed.path_and_query, host
    );
    timeout(step_timeout, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| StartupProbeError::Timeout {
            url: url.clone(),
            timeout_ms: step_timeout.as_millis(),
        })?
        .map_err(|source| StartupProbeError::Io {
            url: url.clone(),
            source,
        })?;
    timeout(step_timeout, stream.flush())
        .await
        .map_err(|_| StartupProbeError::Timeout {
            url: url.clone(),
            timeout_ms: step_timeout.as_millis(),
        })?
        .map_err(|source| StartupProbeError::Io {
            url: url.clone(),
            source,
        })?;

    let status_line = read_http_status_line(&mut stream, &url).await?;
    let status = parse_http_status_line(&status_line)
        .ok_or_else(|| StartupProbeError::MalformedHttpResponse(url.clone()))?;
    if (200..400).contains(&status) {
        Ok(())
    } else {
        Err(StartupProbeError::HttpStatus { url, status })
    }
}

fn host_header_value(parsed: &ParsedProbeUrl) -> String {
    if parsed.port == default_port(parsed.scheme) {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    }
}

fn probe_target_addr(host: &str) -> RoutingTargetAddr {
    host.parse::<IpAddr>()
        .map(RoutingTargetAddr::Ip)
        .unwrap_or_else(|_| RoutingTargetAddr::Domain(host.to_owned()))
}

fn default_port(scheme: ProbeScheme) -> u16 {
    match scheme {
        ProbeScheme::Http => 80,
        ProbeScheme::Https => 443,
    }
}

async fn read_http_status_line(
    stream: &mut (impl AsyncRead + Unpin),
    url: &str,
) -> Result<Vec<u8>, StartupProbeError> {
    let mut status_line = Vec::with_capacity(128);
    let mut chunk = [0u8; 128];

    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|source| StartupProbeError::Io {
                url: url.to_owned(),
                source,
            })?;
        if read == 0 {
            return Ok(status_line);
        }

        status_line.extend_from_slice(&chunk[..read]);
        if let Some(line_end) = status_line.windows(2).position(|window| window == b"\r\n") {
            if line_end > MAX_HTTP_STATUS_LINE_LEN {
                return Err(StartupProbeError::MalformedHttpResponse(url.to_owned()));
            }
            status_line.truncate(line_end);
            return Ok(status_line);
        }

        if status_line.len() >= MAX_HTTP_STATUS_LINE_LEN {
            return Err(StartupProbeError::MalformedHttpResponse(url.to_owned()));
        }
    }
}

pub(crate) fn parse_probe_url(raw: &str) -> Result<ParsedProbeUrl, StartupProbeError> {
    if raw.contains('#') {
        return Err(StartupProbeError::UnsupportedUrl);
    }

    let (scheme, rest, default_port) = if let Some(rest) = raw.strip_prefix("https://") {
        (ProbeScheme::Https, rest, 443)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (ProbeScheme::Http, rest, 80)
    } else {
        return Err(StartupProbeError::UnsupportedUrl);
    };

    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty()
        || authority.contains('@')
        || authority.starts_with(':')
        || contains_ascii_whitespace_or_control(authority)
    {
        return Err(StartupProbeError::UnsupportedUrl);
    }

    let (host, port) =
        parse_authority(authority, default_port).ok_or(StartupProbeError::UnsupportedUrl)?;
    let path_and_query = match &rest[authority_end..] {
        "" => "/".to_owned(),
        suffix if suffix.starts_with('/') => suffix.to_owned(),
        suffix if suffix.starts_with('?') => format!("/{suffix}"),
        _ => return Err(StartupProbeError::UnsupportedUrl),
    };
    if !is_valid_request_target(&path_and_query) {
        return Err(StartupProbeError::UnsupportedUrl);
    }

    Ok(ParsedProbeUrl {
        scheme,
        host,
        port,
        path_and_query,
    })
}

fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.starts_with('[') {
        // IPv6 literals need host-kind modeling so Host headers can preserve brackets.
        return None;
    }

    let mut parts = authority.rsplitn(2, ':');
    let last = parts.next()?;
    let maybe_host = parts.next();
    match maybe_host {
        Some(host) => {
            if host.is_empty() || last.is_empty() || host.contains(':') {
                return None;
            }
            Some((host.to_owned(), parse_port(last)?))
        }
        None => Some((authority.to_owned(), default_port)),
    }
}

fn parse_port(raw: &str) -> Option<u16> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    raw.parse::<u16>().ok()
}

fn is_valid_request_target(target: &str) -> bool {
    target.starts_with('/') && !contains_ascii_whitespace_or_control(target)
}

fn contains_ascii_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || ch.is_ascii_control())
}

fn parse_http_status_line(line: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    let status = parts.next()?.parse::<u16>().ok()?;
    version.starts_with("HTTP/").then_some(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_probe_url_accepts_https_with_default_port() {
        let parsed = parse_probe_url("https://example.com/generate_204").unwrap();

        assert_eq!(
            parsed,
            ParsedProbeUrl {
                scheme: ProbeScheme::Https,
                host: "example.com".to_owned(),
                port: 443,
                path_and_query: "/generate_204".to_owned(),
            }
        );
    }

    #[test]
    fn parse_probe_url_accepts_http_with_custom_port_and_query() {
        let parsed = parse_probe_url("http://probe.test:8080/health?check=1").unwrap();

        assert_eq!(
            parsed,
            ParsedProbeUrl {
                scheme: ProbeScheme::Http,
                host: "probe.test".to_owned(),
                port: 8080,
                path_and_query: "/health?check=1".to_owned(),
            }
        );
        assert_eq!(parsed.diagnostic_label(), "http://<redacted-host>:8080");
    }

    #[test]
    fn parse_probe_url_defaults_empty_path_to_slash() {
        let parsed = parse_probe_url("https://example.com").unwrap();

        assert_eq!(parsed.path_and_query, "/");
    }

    #[test]
    fn parse_probe_url_prefixes_query_only_target_with_slash() {
        let parsed = parse_probe_url("https://example.com?check=1").unwrap();

        assert_eq!(parsed.path_and_query, "/?check=1");
    }

    #[test]
    fn probe_target_addr_maps_ipv4_literal_to_ip_target() {
        assert_eq!(
            probe_target_addr("127.0.0.1"),
            RoutingTargetAddr::Ip("127.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn probe_target_addr_keeps_domain_host_as_domain_target() {
        assert_eq!(
            probe_target_addr("example.com"),
            RoutingTargetAddr::Domain("example.com".to_owned())
        );
    }

    #[test]
    fn parse_probe_url_rejects_unsupported_scheme() {
        let error = parse_probe_url("ftp://example.com/file").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_missing_host() {
        let error = parse_probe_url("https:///generate_204").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_authority_whitespace() {
        let error = parse_probe_url("https://exa mple.com/").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_request_target_whitespace() {
        let error = parse_probe_url("https://example.com/a b").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_request_target_raw_crlf() {
        let error = parse_probe_url("https://example.com/a\r\nHost:evil").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_userinfo_authority() {
        let error = parse_probe_url("https://user@example.com/").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_userinfo_with_password_authority() {
        let error = parse_probe_url("https://user:pass@example.com/").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn unsupported_probe_error_does_not_display_url_secrets() {
        let error =
            parse_probe_url("https://user:secret@example.com/path?token=private").unwrap_err();
        let rendered = error.to_string();
        let debug = format!("{error:?}");

        assert_eq!(rendered, "unsupported startup probe URL");
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("token"));
        assert!(!rendered.contains("example.com"));
        assert_eq!(debug, "UnsupportedUrl");
    }

    #[test]
    fn parse_probe_url_rejects_invalid_port() {
        let error = parse_probe_url("https://example.com:70000/").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_signed_port() {
        let error = parse_probe_url("https://example.com:+443/").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_non_digit_port() {
        let error = parse_probe_url("https://example.com:443x/").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_ipv6_literal() {
        let error = parse_probe_url("https://[2001:db8::1]/").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_authority_fragment() {
        let error = parse_probe_url("https://example.com#frag").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }

    #[test]
    fn parse_probe_url_rejects_path_fragment() {
        let error = parse_probe_url("https://example.com/path#frag").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl));
    }
}

#[cfg(test)]
mod https_tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use xray_config::{
        CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
        RoutingConfig, StreamSecurity, StreamSettings,
    };
    use xray_transport::{
        DnsResolver, SocketHandle, SocketProtector, TlsConnector, TransportDialer, TransportError,
    };

    use super::*;

    #[derive(Debug)]
    struct StaticDnsResolver {
        domain: &'static str,
        addr: SocketAddr,
    }

    #[async_trait]
    impl DnsResolver for StaticDnsResolver {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            if domain == self.domain && port == self.addr.port() {
                Ok(self.addr)
            } else {
                Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
            }
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSocketProtector {
        seen: Mutex<Vec<i64>>,
    }

    impl RecordingSocketProtector {
        fn seen(&self) -> Vec<i64> {
            self.seen.lock().expect("seen socket lock").clone()
        }
    }

    impl SocketProtector for RecordingSocketProtector {
        fn protect(&self, socket: SocketHandle) -> std::io::Result<()> {
            self.seen
                .lock()
                .expect("seen socket lock")
                .push(socket.raw());
            Ok(())
        }
    }

    fn freedom_config() -> CoreConfig {
        CoreConfig {
            inbounds: vec![InboundConfig {
                tag: Some("socks-in".to_owned()),
                protocol: InboundProtocol::Socks,
                listen: "127.0.0.1".to_owned(),
                port: 0,
                allow_unauthenticated_lan: false,
                sniffing: None,
                user_level: None,
            }],
            outbounds: vec![OutboundConfig {
                tag: Some("direct".to_owned()),
                stream: StreamSettings {
                    network: Network::Tcp,
                    security: StreamSecurity::None,
                },
                settings: OutboundSettings::Freedom,
            }],
            default_outbound_tag: Some("direct".to_owned()),
            routing: RoutingConfig::default(),
            dns: Default::default(),
            policy: Default::default(),
        }
    }

    fn tls_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["probe.test".to_owned()])
                .expect("generate self-signed certificate");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add test root");
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build TLS server config");

        (Arc::new(client_config), Arc::new(server_config))
    }

    async fn spawn_https_status_once(
        server_config: Arc<rustls::ServerConfig>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind HTTPS probe listener");
        let addr = listener.local_addr().expect("read HTTPS listener address");
        let acceptor = TlsAcceptor::from(server_config);
        let expected_host = format!("probe.test:{}", addr.port());

        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept HTTPS probe client");
            let mut stream = acceptor.accept(stream).await.expect("accept TLS stream");
            let mut request = Vec::new();
            let mut chunk = [0u8; 128];
            let expected_prefix = b"GET /health HTTP/1.1\r\n";
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.expect("read HTTPS request");
                assert!(read > 0, "HTTPS client closed before sending request");
                request.extend_from_slice(&chunk[..read]);
                assert!(request.len() <= 1024, "HTTPS request headers are too large");
            }
            let request = String::from_utf8_lossy(&request);
            assert!(
                request.as_bytes().starts_with(expected_prefix),
                "unexpected HTTPS request: {request}"
            );
            assert!(
                request.contains(&format!("\r\nHost: {expected_host}\r\n")),
                "HTTPS request missing expected Host header: {request}"
            );
            stream
                .write_all(b"HTTP/1.1 204 Test\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("write HTTPS response");
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn run_startup_probe_inner_succeeds_for_https_2xx_response() {
        let (client_config, server_config) = tls_configs();
        let (addr, server) = spawn_https_status_once(server_config).await;
        let options = StartupProbeOptions {
            url: format!("https://probe.test:{}/health", addr.port()),
            timeout: Duration::from_secs(2),
            outbound_tag: Some("direct".to_owned()),
        };
        let resolver = StaticDnsResolver {
            domain: "probe.test",
            addr,
        };
        let tls = TlsConnector::with_client_config(client_config);
        let protector = Arc::new(RecordingSocketProtector::default());
        let dialer_protector: Arc<dyn SocketProtector> = protector.clone();
        let transport_dialer =
            TransportDialer::system_with_socket_protector(Some(dialer_protector))
                .expect("build protected transport dialer");
        let outbound_router = OutboundRouter::new(Arc::new(freedom_config()));

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_startup_probe_inner(
                &outbound_router,
                &options,
                &resolver,
                &transport_dialer,
                Some(&tls),
            ),
        )
        .await
        .expect("HTTPS probe should complete");
        let server_result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("HTTPS server should complete");

        assert!(
            result.is_ok(),
            "expected HTTPS probe success, got {result:?}"
        );
        server_result.expect("HTTPS server task should complete");
        let seen = protector.seen();
        assert_eq!(seen.len(), 1, "expected dialer socket protector invocation");
        assert!(seen[0] >= 0, "expected valid protected socket handle");
    }
}
