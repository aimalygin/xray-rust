# Outbound HTTP Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional startup HTTP(S) probe that validates real traffic through the configured outbound before reporting the core as started.

**Architecture:** `xray-core-rs` owns probe options, URL parsing, outbound selection, and lifecycle rollback. `xray-transport` gains a TLS wrapper for an already-open outbound stream so HTTPS probes still run through the selected outbound. FFI and mobile adapters expose the option before config load; the Xray JSON parser stays unchanged.

**Tech Stack:** Rust 2021, Tokio async I/O and timeouts, rustls/tokio-rustls via `xray-transport`, C FFI, Swift, Kotlin, JNI, existing cargo test suites.

---

## File Structure

- Create `crates/xray-core-rs/src/startup_probe.rs`: probe options, URL parsing, HTTP request/response handling, and startup probe execution.
- Modify `crates/xray-core-rs/src/lib.rs`: store `StartupProbeOptions`, expose constructors/setters, invoke probe during `Core::start`, and roll back started tasks on probe failure.
- Modify `crates/xray-core-rs/src/outbound.rs`: add direct outbound selection by explicit/default tag without routing-rule evaluation.
- Modify `crates/xray-transport/src/tls.rs` and `crates/xray-transport/src/lib.rs`: expose TLS wrapping for an existing `BoxedTransportStream`.
- Add `crates/xray-core-rs/tests/startup_probe_tests.rs`: integration coverage for HTTP, HTTPS, failure, timeout, tag selection, and routing bypass.
- Modify `crates/xray-ffi/src/lib.rs` and `crates/xray-ffi/include/xray_ffi.h`: store and set startup probe options before config load.
- Modify `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift`: Swift initializer support for optional startup probe.
- Modify `platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt` and `platform/android/xraymobile/src/main/cpp/xray_mobile_jni.cpp`: Kotlin/JNI startup probe setter.
- Modify `crates/xray-ffi/tests/ffi_tests.rs`: FFI validation for setter ordering and invalid UTF-8/null arguments.

### Task 1: Core Probe Types And URL Parsing

**Files:**
- Create: `crates/xray-core-rs/src/startup_probe.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Test: `crates/xray-core-rs/src/startup_probe.rs`

- [ ] **Step 1: Write failing parser tests**

Add `mod startup_probe;` to `crates/xray-core-rs/src/lib.rs`, then create `crates/xray-core-rs/src/startup_probe.rs` with tests first:

```rust
use std::time::Duration;

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

#[derive(Debug, thiserror::Error)]
pub enum StartupProbeError {
    #[error("unsupported startup probe URL `{0}`")]
    UnsupportedUrl(String),
}

pub(crate) fn parse_probe_url(raw: &str) -> Result<ParsedProbeUrl, StartupProbeError> {
    Err(StartupProbeError::UnsupportedUrl(raw.to_owned()))
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
    }

    #[test]
    fn parse_probe_url_defaults_empty_path_to_slash() {
        let parsed = parse_probe_url("https://example.com").unwrap();

        assert_eq!(parsed.path_and_query, "/");
    }

    #[test]
    fn parse_probe_url_rejects_unsupported_scheme() {
        let error = parse_probe_url("ftp://example.com/file").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "ftp://example.com/file"));
    }

    #[test]
    fn parse_probe_url_rejects_missing_host() {
        let error = parse_probe_url("https:///generate_204").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https:///generate_204"));
    }

    #[test]
    fn parse_probe_url_rejects_invalid_port() {
        let error = parse_probe_url("https://example.com:70000/").unwrap_err();

        assert!(matches!(error, StartupProbeError::UnsupportedUrl(url) if url == "https://example.com:70000/"));
    }
}
```

- [ ] **Step 2: Run parser tests and confirm failure**

Run:

```bash
cargo test -p xray-core-rs startup_probe::tests:: --locked
```

Expected: tests compile and at least the accept/default tests fail because `parse_probe_url` always returns `UnsupportedUrl`.

- [ ] **Step 3: Implement minimal parser**

Replace `parse_probe_url` with:

```rust
pub(crate) fn parse_probe_url(raw: &str) -> Result<ParsedProbeUrl, StartupProbeError> {
    let (scheme, rest, default_port) = if let Some(rest) = raw.strip_prefix("https://") {
        (ProbeScheme::Https, rest, 443)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (ProbeScheme::Http, rest, 80)
    } else {
        return Err(StartupProbeError::UnsupportedUrl(raw.to_owned()));
    };

    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.starts_with(':') {
        return Err(StartupProbeError::UnsupportedUrl(raw.to_owned()));
    }

    let (host, port) = parse_authority(authority, default_port)
        .ok_or_else(|| StartupProbeError::UnsupportedUrl(raw.to_owned()))?;
    let path_and_query = match &rest[authority_end..] {
        "" => "/".to_owned(),
        suffix if suffix.starts_with('/') => suffix.to_owned(),
        suffix if suffix.starts_with('?') => format!("/{suffix}"),
        _ => return Err(StartupProbeError::UnsupportedUrl(raw.to_owned())),
    };

    Ok(ParsedProbeUrl {
        scheme,
        host,
        port,
        path_and_query,
    })
}

fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = authority[1..end].to_owned();
        if host.is_empty() {
            return None;
        }
        let port = match &authority[end + 1..] {
            "" => default_port,
            suffix if suffix.starts_with(':') => suffix[1..].parse::<u16>().ok()?,
            _ => return None,
        };
        return Some((host, port));
    }

    let mut parts = authority.rsplitn(2, ':');
    let last = parts.next()?;
    let maybe_host = parts.next();
    match maybe_host {
        Some(host) => {
            if host.is_empty() || last.is_empty() || host.contains(':') {
                return None;
            }
            Some((host.to_owned(), last.parse::<u16>().ok()?))
        }
        None => Some((authority.to_owned(), default_port)),
    }
}
```

- [ ] **Step 4: Run parser tests and confirm pass**

Run:

```bash
cargo test -p xray-core-rs startup_probe::tests:: --locked
```

Expected: all parser tests pass.

- [ ] **Step 5: Commit Task 1**

```bash
git add crates/xray-core-rs/src/lib.rs crates/xray-core-rs/src/startup_probe.rs
git commit -m "Add startup probe URL parsing"
```

### Task 2: Direct Outbound Selection For Probe

**Files:**
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Test: `crates/xray-core-rs/src/outbound.rs`

- [ ] **Step 1: Write failing direct selection tests**

Add these helper functions and tests inside the existing `#[cfg(test)] mod tests` in `crates/xray-core-rs/src/outbound.rs`:

```rust
fn direct_selection_freedom(tag: &str) -> OutboundConfig {
    OutboundConfig {
        tag: Some(tag.to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security: StreamSecurity::None,
        },
        settings: OutboundSettings::Freedom,
    }
}

fn direct_selection_vless(tag: &str) -> OutboundConfig {
    OutboundConfig {
        tag: Some(tag.to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security: StreamSecurity::None,
        },
        settings: OutboundSettings::Vless(VlessOutboundSettings {
            server: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 443,
            users: vec![VlessUser {
                id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                encryption: "none".to_owned(),
                flow: None,
            }],
        }),
    }
}

fn direct_selection_config() -> CoreConfig {
    CoreConfig {
        inbounds: Vec::new(),
        outbounds: vec![
            direct_selection_freedom("direct"),
            direct_selection_vless("proxy"),
        ],
        default_outbound_tag: Some("proxy".to_owned()),
        routing: RoutingConfig {
            rules: vec![RoutingRule {
                inbound_tags: Vec::new(),
                domain_matchers: Vec::new(),
                ip_matchers: Vec::new(),
                outbound_tag: "direct".to_owned(),
            }],
        },
        dns: Default::default(),
    }
}

#[test]
fn select_tcp_outbound_direct_uses_explicit_tag() {
    let selected = select_tcp_outbound_direct(&direct_selection_config(), Some("direct")).unwrap();

    assert!(matches!(selected, TcpOutbound::Freedom));
}

#[test]
fn select_tcp_outbound_direct_uses_default_tag_without_routing() {
    let selected = select_tcp_outbound_direct(&direct_selection_config(), None).unwrap();

    assert!(matches!(selected, TcpOutbound::Vless(_)));
}

#[test]
fn select_tcp_outbound_direct_errors_when_explicit_tag_is_missing() {
    let error = select_tcp_outbound_direct(&direct_selection_config(), Some("missing")).unwrap_err();

    assert!(matches!(error, CoreError::NoSupportedOutbound));
}
```

- [ ] **Step 2: Run direct selection tests and confirm failure**

Run:

```bash
cargo test -p xray-core-rs outbound::tests::select_tcp_outbound_direct --locked
```

Expected: compile fails because `select_tcp_outbound_direct` does not exist.

- [ ] **Step 3: Implement direct selection**

Add this function near `select_tcp_outbound`:

```rust
pub(crate) fn select_tcp_outbound_direct(
    config: &CoreConfig,
    outbound_tag: Option<&str>,
) -> Result<TcpOutbound, CoreError> {
    let outbound = select_configured_outbound_direct(config, outbound_tag)?;
    build_tcp_outbound(outbound)
}

fn select_configured_outbound_direct<'a>(
    config: &'a CoreConfig,
    outbound_tag: Option<&str>,
) -> Result<&'a OutboundConfig, CoreError> {
    match outbound_tag.or(config.default_outbound_tag.as_deref()) {
        Some(tag) => config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
            .ok_or(CoreError::NoSupportedOutbound),
        None => config.outbounds.first().ok_or(CoreError::NoSupportedOutbound),
    }
}
```

- [ ] **Step 4: Run direct selection tests and confirm pass**

Run:

```bash
cargo test -p xray-core-rs outbound::tests::select_tcp_outbound_direct --locked
```

Expected: all direct selection tests pass.

- [ ] **Step 5: Commit Task 2**

```bash
git add crates/xray-core-rs/src/outbound.rs
git commit -m "Add direct outbound selection for startup probe"
```

### Task 3: TLS Over Existing Outbound Stream

**Files:**
- Modify: `crates/xray-transport/src/tls.rs`
- Modify: `crates/xray-transport/src/lib.rs`
- Test: `crates/xray-transport/tests/transport_tests.rs`

- [ ] **Step 1: Write failing TLS wrapper test**

Add this test next to existing TLS connector tests in `crates/xray-transport/tests/transport_tests.rs`:

```rust
#[tokio::test]
async fn tls_connector_wraps_existing_transport_stream() {
    let (client_config, server_config) = tls_test_configs();
    let (client_raw, server_raw) = tokio::io::duplex(4096);
    let acceptor = TlsAcceptor::from(server_config);
    let server = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_raw).await.expect("accept TLS stream");
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.expect("read ping");
        stream.write_all(&buf).await.expect("write pong");
    });

    let connector = TlsConnector::with_client_config(client_config);
    let config = TlsClientConfig {
        server_name: "server.test".to_owned(),
        allow_insecure: false,
    };

    let stream = connector
        .connect_stream(Box::new(client_raw), &config)
        .await
        .expect("wrap existing stream with TLS");

    assert_boxed_transport_stream(stream).await;
    server.await.expect("TLS server task should complete");
}
```

- [ ] **Step 2: Run TLS wrapper test and confirm failure**

Run:

```bash
cargo test -p xray-transport tls_connector_wraps_existing_transport_stream --locked
```

Expected: compile fails because `TlsConnector::connect_stream` does not exist.

- [ ] **Step 3: Implement `connect_stream`**

In `crates/xray-transport/src/tls.rs`, refactor `connect` and add:

```rust
impl TlsConnector {
    pub async fn connect_stream(
        &self,
        stream: BoxedTransportStream,
        config: &TlsClientConfig,
    ) -> Result<BoxedTransportStream, TransportError> {
        let server_name = rustls::pki_types::ServerName::try_from(config.server_name.clone())
            .map_err(|_| TransportError::InvalidTlsServerName(config.server_name.clone()))?;
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

    pub async fn connect(
        &self,
        target: &Target,
        config: &TlsClientConfig,
    ) -> Result<BoxedTransportStream, TransportError> {
        let addr = match &target.addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
            TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
        };

        let stream = connect_tcp_stream(addr, self.socket_protector.as_deref()).await?;
        self.connect_stream(Box::new(stream), config).await
    }
}
```

Keep `pub use tls::TlsConnector;` unchanged in `crates/xray-transport/src/lib.rs`; no new export is needed.

- [ ] **Step 4: Run TLS wrapper test and confirm pass**

Run:

```bash
cargo test -p xray-transport tls_connector_wraps_existing_transport_stream --locked
```

Expected: test passes.

- [ ] **Step 5: Commit Task 3**

```bash
git add crates/xray-transport/src/tls.rs crates/xray-transport/tests/transport_tests.rs
git commit -m "Support TLS over existing transport streams"
```

### Task 4: HTTP Probe Execution

**Files:**
- Modify: `crates/xray-core-rs/src/startup_probe.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Test: `crates/xray-core-rs/tests/startup_probe_tests.rs`

- [ ] **Step 1: Write failing HTTP probe integration tests**

Create `crates/xray-core-rs/tests/startup_probe_tests.rs`:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
    RoutingConfig, RoutingRule, StreamSecurity, StreamSettings,
};
use xray_core_rs::{Core, CoreError, CoreState, StartupProbeOptions};
use xray_transport::{DnsResolver, SystemDnsResolver, TransportDialer, TransportError};

fn freedom(tag: &str) -> OutboundConfig {
    OutboundConfig {
        tag: Some(tag.to_owned()),
        stream: StreamSettings {
            network: Network::Tcp,
            security: StreamSecurity::None,
        },
        settings: OutboundSettings::Freedom,
    }
}

fn config_with_outbounds(outbounds: Vec<OutboundConfig>, default: Option<&str>) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds,
        default_outbound_tag: default.map(ToOwned::to_owned),
        routing: RoutingConfig::default(),
        dns: Default::default(),
    }
}

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

async fn spawn_http_status_once(status: u16) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 512];
        let read = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /health HTTP/1.1\r\n"));
        let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n");
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn startup_probe_succeeds_for_http_2xx_response() {
    let addr = spawn_http_status_once(204).await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: "http://probe.test/health".to_owned(),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}

#[tokio::test]
async fn startup_probe_fails_for_http_4xx_response_and_rolls_back_start() {
    let addr = spawn_http_status_once(404).await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: "http://probe.test/health".to_owned(),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    let error = core.start().await.unwrap_err();

    assert!(matches!(error, CoreError::StartupProbe(_)));
    assert_eq!(core.state(), CoreState::Stopped);
}
```

- [ ] **Step 2: Run HTTP probe tests and confirm failure**

Run:

```bash
cargo test -p xray-core-rs --test startup_probe_tests --locked
```

Expected: compile fails because `StartupProbeOptions`, `Core::with_startup_probe`, and `CoreError::StartupProbe` do not exist.

- [ ] **Step 3: Implement probe execution and lifecycle rollback**

In `crates/xray-core-rs/src/lib.rs`:

```rust
mod startup_probe;

pub use startup_probe::{StartupProbeError, StartupProbeOptions};

#[derive(Debug, Error)]
pub enum CoreError {
    /* existing variants */
    #[error("startup probe failed: {0}")]
    StartupProbe(#[from] StartupProbeError),
}

pub struct Core {
    /* existing fields */
    startup_probe: Option<StartupProbeOptions>,
}

impl Core {
    pub fn with_startup_probe(mut self, options: StartupProbeOptions) -> Self {
        self.startup_probe = Some(options);
        self
    }

    pub fn set_startup_probe(&mut self, options: Option<StartupProbeOptions>) {
        self.startup_probe = options;
    }
}
```

Initialize `startup_probe: None` in `with_runtime_dependencies_and_tun_options`.

At the end of `Core::start`, replace the direct success with rollback-aware probe execution:

```rust
self.runtime = Some(RuntimeState { inbounds, tasks });
self.state = CoreState::Running;

if let Some(options) = self.startup_probe.clone() {
    if let Err(error) = startup_probe::run_startup_probe(
        &self.config,
        options,
        self.dns_resolver.as_ref(),
        self.transport_dialer.as_ref(),
    )
    .await
    {
        let _ = self.stop().await;
        return Err(CoreError::StartupProbe(error));
    }
}

Ok(())
```

In `crates/xray-core-rs/src/startup_probe.rs`, add execution:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{DnsResolver, TlsClientConfig, TlsConnector, TransportDialer};

use crate::outbound::{open_tcp_stream_with_resolver_and_dialer, select_tcp_outbound_direct};
use crate::CoreError;

#[derive(Debug, thiserror::Error)]
pub enum StartupProbeError {
    #[error("unsupported startup probe URL `{0}`")]
    UnsupportedUrl(String),
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
    config: &xray_config::CoreConfig,
    options: StartupProbeOptions,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<(), StartupProbeError> {
    let timeout_ms = options.timeout.as_millis();
    let url = options.url.clone();
    timeout(
        options.timeout,
        run_startup_probe_inner(
            config,
            &options,
            dns_resolver,
            transport_dialer,
            None,
        ),
    )
        .await
        .map_err(|_| StartupProbeError::Timeout { url, timeout_ms })?
}

async fn run_startup_probe_inner(
    config: &xray_config::CoreConfig,
    options: &StartupProbeOptions,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
    tls_connector: Option<&TlsConnector>,
) -> Result<(), StartupProbeError> {
    let parsed = parse_probe_url(&options.url)?;
    let outbound = select_tcp_outbound_direct(config, options.outbound_tag.as_deref()).map_err(
        |source| StartupProbeError::Core {
            url: options.url.clone(),
            source: Box::new(source),
        },
    )?;
    let target = Target::new(
        RoutingTargetAddr::Domain(parsed.host.clone()),
        parsed.port,
        RoutingNetwork::Tcp,
    );
    let mut stream = open_tcp_stream_with_resolver_and_dialer(
        &outbound,
        &target,
        dns_resolver,
        transport_dialer,
    )
    .await
    .map_err(|source| StartupProbeError::Core {
        url: options.url.clone(),
        source: Box::new(source),
    })?;

    if parsed.scheme == ProbeScheme::Https {
        let system_tls;
        let tls_connector = match tls_connector {
            Some(tls_connector) => tls_connector,
            None => {
                system_tls = TlsConnector::system().map_err(|source| StartupProbeError::Tls {
                    url: options.url.clone(),
                    source,
                })?;
                &system_tls
            }
        };
        stream = tls_connector
            .connect_stream(
                stream,
                &TlsClientConfig {
                    server_name: parsed.host.clone(),
                    allow_insecure: false,
                },
            )
            .await
            .map_err(|source| StartupProbeError::Tls {
                url: options.url.clone(),
                source,
            })?;
    }

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: xray-rust-startup-probe\r\nConnection: close\r\n\r\n",
        parsed.path_and_query, parsed.host
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|source| StartupProbeError::Io {
            url: options.url.clone(),
            source,
        })?;
    stream.flush().await.map_err(|source| StartupProbeError::Io {
        url: options.url.clone(),
        source,
    })?;

    let mut response = vec![0u8; 1024];
    let read = stream.read(&mut response).await.map_err(|source| StartupProbeError::Io {
        url: options.url.clone(),
        source,
    })?;
    let status = parse_http_status(&response[..read])
        .ok_or_else(|| StartupProbeError::MalformedHttpResponse(options.url.clone()))?;
    if (200..400).contains(&status) {
        Ok(())
    } else {
        Err(StartupProbeError::HttpStatus {
            url: options.url.clone(),
            status,
        })
    }
}

fn parse_http_status(response: &[u8]) -> Option<u16> {
    let line_end = response.windows(2).position(|window| window == b"\r\n")?;
    let line = std::str::from_utf8(&response[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    let status = parts.next()?.parse::<u16>().ok()?;
    version.starts_with("HTTP/").then_some(status)
}
```

- [ ] **Step 4: Run HTTP probe tests and confirm pass**

Run:

```bash
cargo test -p xray-core-rs --test startup_probe_tests --locked
```

Expected: HTTP success and rollback tests pass.

- [ ] **Step 5: Commit Task 4**

```bash
git add crates/xray-core-rs/src/lib.rs crates/xray-core-rs/src/startup_probe.rs crates/xray-core-rs/tests/startup_probe_tests.rs
git commit -m "Run HTTP startup probe through configured outbound"
```

### Task 5: HTTPS, Timeout, Tag, And Routing Coverage

**Files:**
- Modify: `crates/xray-core-rs/tests/startup_probe_tests.rs`
- Modify: `crates/xray-core-rs/src/startup_probe.rs`

- [ ] **Step 1: Add HTTPS unit coverage and status-range integration tests**

Add a focused HTTPS unit test inside `crates/xray-core-rs/src/startup_probe.rs` so the test can inject a trusted `TlsConnector` without weakening production certificate validation:

```rust
#[cfg(test)]
mod https_tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
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
    use xray_transport::{DnsResolver, TlsConnector, TransportDialer, TransportError};

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

    fn freedom_config() -> CoreConfig {
        CoreConfig {
            inbounds: vec![InboundConfig {
                tag: Some("socks-in".to_owned()),
                protocol: InboundProtocol::Socks,
                listen: "127.0.0.1".to_owned(),
                port: 0,
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
        }
    }

    fn tls_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["probe.test".to_owned()]).unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
        (Arc::new(client), Arc::new(server))
    }

    async fn spawn_https_status_once(
        status: u16,
        server_config: Arc<rustls::ServerConfig>,
    ) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server_config);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = vec![0; 512];
            let read = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /health HTTP/1.1\r\n"));
            let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n");
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn run_startup_probe_inner_succeeds_for_https_2xx_response() {
        let (client_config, server_config) = tls_configs();
        let addr = spawn_https_status_once(204, server_config).await;
        let options = StartupProbeOptions {
            url: "https://probe.test/health".to_owned(),
            timeout: std::time::Duration::from_secs(2),
            outbound_tag: Some("direct".to_owned()),
        };
        let resolver = StaticDnsResolver {
            domain: "probe.test",
            addr,
        };
        let tls = TlsConnector::with_client_config(client_config);

        run_startup_probe_inner(
            &freedom_config(),
            &options,
            &resolver,
            &TransportDialer::system().unwrap(),
            Some(&tls),
        )
        .await
        .unwrap();
    }
}
```

Extend `startup_probe_tests.rs` with a `3xx` integration test:

```rust

#[tokio::test]
async fn startup_probe_accepts_http_3xx_response() {
    let addr = spawn_http_status_once(302).await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: "http://probe.test/health".to_owned(),
        timeout: Duration::from_secs(2),
        outbound_tag: Some("direct".to_owned()),
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}
```

- [ ] **Step 2: Add timeout and routing-bypass tests**

Append:

```rust
async fn spawn_stalled_http_once() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    addr
}

#[tokio::test]
async fn startup_probe_timeout_fails_and_rolls_back_start() {
    let addr = spawn_stalled_http_once().await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut core = Core::with_runtime_dependencies(
        config_with_outbounds(vec![freedom("direct")], Some("direct")),
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: "http://probe.test/health".to_owned(),
        timeout: Duration::from_millis(50),
        outbound_tag: Some("direct".to_owned()),
    });

    let error = core.start().await.unwrap_err();

    assert!(matches!(error, CoreError::StartupProbe(_)));
    assert_eq!(core.state(), CoreState::Stopped);
}

#[tokio::test]
async fn startup_probe_uses_default_outbound_without_applying_routing_rules() {
    let addr = spawn_http_status_once(204).await;
    let resolver = Arc::new(StaticDnsResolver {
        domain: "probe.test",
        addr,
    });
    let mut config = config_with_outbounds(vec![freedom("direct")], Some("direct"));
    config.routing = RoutingConfig {
        rules: vec![RoutingRule {
            inbound_tags: Vec::new(),
            domain_matchers: Vec::new(),
            ip_matchers: Vec::new(),
            outbound_tag: "missing".to_owned(),
        }],
    };
    let mut core = Core::with_runtime_dependencies(
        config,
        resolver,
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap()
    .with_startup_probe(StartupProbeOptions {
        url: "http://probe.test/health".to_owned(),
        timeout: Duration::from_secs(2),
        outbound_tag: None,
    });

    core.start().await.unwrap();

    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
}
```

- [ ] **Step 3: Run expanded startup probe tests**

Run:

```bash
cargo test -p xray-core-rs --test startup_probe_tests --locked
```

Expected: all tests pass. If the HTTPS test unexpectedly succeeds because the local certificate is trusted by a future test setup, change the assertion to require `core.state() == CoreState::Running` and stop the core; do not add insecure probe support.

- [ ] **Step 4: Commit Task 5**

```bash
git add crates/xray-core-rs/tests/startup_probe_tests.rs crates/xray-core-rs/src/startup_probe.rs
git commit -m "Cover startup probe status timeout and routing behavior"
```

### Task 6: FFI Startup Probe Setters

**Files:**
- Modify: `crates/xray-ffi/src/lib.rs`
- Modify: `crates/xray-ffi/include/xray_ffi.h`
- Test: `crates/xray-ffi/tests/ffi_tests.rs`

- [ ] **Step 1: Write failing FFI tests**

Add tests to `crates/xray-ffi/tests/ffi_tests.rs`:

```rust
#[test]
fn startup_probe_setter_accepts_url_timeout_and_optional_tag_before_config_load() {
    unsafe {
        let mut error = std::ptr::null_mut();
        let handle = xray_ffi::xray_core_new(&mut error);
        assert!(!handle.is_null());

        let url = std::ffi::CString::new("http://probe.test/health").unwrap();
        let tag = std::ffi::CString::new("direct").unwrap();
        let status = xray_ffi::xray_core_set_startup_probe(
            handle,
            url.as_ptr(),
            5000,
            tag.as_ptr(),
            &mut error,
        );

        assert_eq!(status, xray_ffi::XrayStatus::Ok);
        xray_ffi::xray_core_free(handle);
    }
}

#[test]
fn startup_probe_setter_rejects_null_url() {
    unsafe {
        let mut error = std::ptr::null_mut();
        let handle = xray_ffi::xray_core_new(&mut error);
        assert!(!handle.is_null());

        let status = xray_ffi::xray_core_set_startup_probe(
            handle,
            std::ptr::null(),
            5000,
            std::ptr::null(),
            &mut error,
        );

        assert_eq!(status, xray_ffi::XrayStatus::NullArgument);
        xray_ffi::xray_error_free(error);
        xray_ffi::xray_core_free(handle);
    }
}
```

- [ ] **Step 2: Run FFI tests and confirm failure**

Run:

```bash
cargo test -p xray-ffi startup_probe_setter --locked
```

Expected: compile fails because `xray_core_set_startup_probe` does not exist.

- [ ] **Step 3: Implement FFI storage and setter**

In `crates/xray-ffi/src/lib.rs`, import `StartupProbeOptions`, add a field to `XrayCoreHandle`, initialize it in `xray_core_new_inner`, pass it into `Core` after load, and add the setter:

```rust
use xray_core_rs::{
    Core, StartupProbeOptions, TunFdClosePolicy, TunFdConfig, TunFdPacketFormat, TunFdRuntime,
    TunRuntimeOptions, TunRuntimeProfile,
};

pub struct XrayCoreHandle {
    core: Option<Core>,
    runtime: Runtime,
    socket_protector: Option<Arc<dyn SocketProtector>>,
    geodata_search_dirs: Vec<PathBuf>,
    tun_fd_config: Option<TunFdConfig>,
    tun_fd_runtime: Option<TunFdRuntime>,
    tun_runtime_options: TunRuntimeOptions,
    startup_probe_options: Option<StartupProbeOptions>,
}
```

After creating `core` in `xray_core_load_config_json_inner`:

```rust
let mut core = core;
if let Some(options) = (*handle).startup_probe_options.clone() {
    core.set_startup_probe(Some(options));
}
```

Add:

```rust
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_startup_probe(
    handle: *mut XrayCoreHandle,
    url: *const c_char,
    timeout_ms: u64,
    outbound_tag: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            xray_core_set_startup_probe_inner(handle, url, timeout_ms, outbound_tag, error)
        })
    }
}

unsafe fn xray_core_set_startup_probe_inner(
    handle: *mut XrayCoreHandle,
    url: *const c_char,
    timeout_ms: u64,
    outbound_tag: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        clear_error(error);
    }
    if handle.is_null() {
        unsafe { set_error(error, XrayStatus::NullArgument, "core handle is null") };
        return XrayStatus::NullArgument;
    }
    if url.is_null() {
        unsafe { set_error(error, XrayStatus::NullArgument, "startup probe URL is null") };
        return XrayStatus::NullArgument;
    }

    let handle = unsafe { &mut *handle };
    if handle.core.is_some() {
        unsafe {
            set_error(
                error,
                XrayStatus::RuntimeError,
                "startup probe must be set before config load",
            );
        }
        return XrayStatus::RuntimeError;
    }

    let url = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(url) => url,
        Err(err) => {
            unsafe {
                set_error(
                    error,
                    XrayStatus::InvalidUtf8,
                    format!("startup probe URL is not valid UTF-8: {err}"),
                );
            }
            return XrayStatus::InvalidUtf8;
        }
    };
    if url.is_empty() || timeout_ms == 0 {
        unsafe {
            set_error(
                error,
                XrayStatus::ConfigError,
                "startup probe URL must be non-empty and timeout must be greater than 0",
            );
        }
        return XrayStatus::ConfigError;
    }

    let outbound_tag = if outbound_tag.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(outbound_tag) }.to_str() {
            Ok(tag) if tag.is_empty() => None,
            Ok(tag) => Some(tag.to_owned()),
            Err(err) => {
                unsafe {
                    set_error(
                        error,
                        XrayStatus::InvalidUtf8,
                        format!("startup probe outbound tag is not valid UTF-8: {err}"),
                    );
                }
                return XrayStatus::InvalidUtf8;
            }
        }
    };

    handle.startup_probe_options = Some(StartupProbeOptions {
        url: url.to_owned(),
        timeout: Duration::from_millis(timeout_ms),
        outbound_tag,
    });
    XrayStatus::Ok
}
```

In `crates/xray-ffi/include/xray_ffi.h`, add:

```c
XrayStatus xray_core_set_startup_probe(
    XrayCoreHandle *handle,
    const char *url,
    uint64_t timeout_ms,
    const char *outbound_tag,
    XrayError **error);
```

- [ ] **Step 4: Run FFI tests**

Run:

```bash
cargo test -p xray-ffi startup_probe_setter --locked
```

Expected: FFI setter tests pass.

- [ ] **Step 5: Commit Task 6**

```bash
git add crates/xray-ffi/src/lib.rs crates/xray-ffi/include/xray_ffi.h crates/xray-ffi/tests/ffi_tests.rs
git commit -m "Expose startup probe options over FFI"
```

### Task 7: Apple And Android Adapter APIs

**Files:**
- Modify: `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift`
- Modify: `platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt`
- Modify: `platform/android/xraymobile/src/main/cpp/xray_mobile_jni.cpp`
- Test: `platform/apple/Tests/XrayMobileAdapterTests` if constructors have tests; otherwise build via scripts in Task 8.

- [ ] **Step 1: Add Swift startup probe value type and initializer parameters**

In `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift`, add near other public structs:

```swift
public struct XrayStartupProbeOptions: Equatable, Sendable {
    public let url: String
    public let timeoutMs: UInt64
    public let outboundTag: String?

    public init(
        url: String,
        timeoutMs: UInt64 = 5_000,
        outboundTag: String? = nil
    ) {
        self.url = url
        self.timeoutMs = timeoutMs
        self.outboundTag = outboundTag
    }
}
```

Add `startupProbe: XrayStartupProbeOptions? = nil` to the main initializer and convenience initializer signatures. Before `xray_core_load_config_json`, call:

```swift
if let startupProbe {
    try startupProbe.url.withCString { urlPointer in
        if let outboundTag = startupProbe.outboundTag {
            try outboundTag.withCString { tagPointer in
                try check(
                    xray_core_set_startup_probe(
                        handle,
                        urlPointer,
                        startupProbe.timeoutMs,
                        tagPointer,
                        &error
                    ),
                    error: error
                )
            }
        } else {
            try check(
                xray_core_set_startup_probe(
                    handle,
                    urlPointer,
                    startupProbe.timeoutMs,
                    nil,
                    &error
                ),
                error: error
            )
        }
    }
}
```

- [ ] **Step 2: Add Kotlin startup probe options and native binding**

In `platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt`, add:

```kotlin
data class XrayStartupProbeOptions(
    val url: String,
    val timeoutMs: Long = 5_000,
    val outboundTag: String? = null,
)
```

Add `startupProbe: XrayStartupProbeOptions? = null` to `create(...)`; before `loadConfig(configJson)`:

```kotlin
if (startupProbe != null) {
    core.setStartupProbe(startupProbe)
}
```

Add:

```kotlin
private fun setStartupProbe(options: XrayStartupProbeOptions) {
    withHandle { nativeSetStartupProbe(it, options.url, options.timeoutMs, options.outboundTag) }
}

private external fun nativeSetStartupProbe(
    handle: Long,
    url: String,
    timeoutMs: Long,
    outboundTag: String?,
)
```

In `platform/android/xraymobile/src/main/cpp/xray_mobile_jni.cpp`, add:

```cpp
extern "C" JNIEXPORT void JNICALL
Java_org_xrayrust_mobile_XrayCore_nativeSetStartupProbe(
    JNIEnv *env,
    jobject,
    jlong handle,
    jstring url,
    jlong timeout_ms,
    jstring outbound_tag) {
  NativeCore *native = core_from_handle(handle);
  if (native == nullptr || native->core == nullptr) {
    return;
  }

  const char *raw_url = env->GetStringUTFChars(url, nullptr);
  if (raw_url == nullptr) {
    return;
  }
  const char *raw_tag = nullptr;
  if (outbound_tag != nullptr) {
    raw_tag = env->GetStringUTFChars(outbound_tag, nullptr);
    if (raw_tag == nullptr) {
      env->ReleaseStringUTFChars(url, raw_url);
      return;
    }
  }

  XrayError *error = nullptr;
  XrayStatus status = xray_core_set_startup_probe(
      native->core,
      raw_url,
      static_cast<uint64_t>(timeout_ms),
      raw_tag,
      &error);
  if (raw_tag != nullptr) {
    env->ReleaseStringUTFChars(outbound_tag, raw_tag);
  }
  env->ReleaseStringUTFChars(url, raw_url);
  check_status(env, status, error);
}
```

- [ ] **Step 3: Run mobile adapter compile checks**

Run:

```bash
cargo test -p xray-ffi --locked
```

Expected: Rust FFI tests pass.

If the macOS host has Swift tooling available, run:

```bash
swift test --package-path platform/apple
```

Expected: Swift package tests compile and pass.

- [ ] **Step 4: Commit Task 7**

```bash
git add platform/apple/Sources/XrayMobileAdapter/XrayCore.swift platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt platform/android/xraymobile/src/main/cpp/xray_mobile_jni.cpp
git commit -m "Add mobile startup probe options"
```

### Task 8: Full Verification

**Files:**
- No code edits unless verification exposes a bug.

- [ ] **Step 1: Run focused Rust tests**

Run:

```bash
cargo test -p xray-transport tls_connector_wraps_existing_transport_stream --locked
cargo test -p xray-core-rs startup_probe --locked
cargo test -p xray-core-rs --test startup_probe_tests --locked
cargo test -p xray-ffi startup_probe_setter --locked
```

Expected: all commands pass.

- [ ] **Step 2: Run broader workspace checks**

Run:

```bash
cargo test -p xray-core-rs --locked
cargo test -p xray-transport --locked
cargo test -p xray-ffi --locked
```

Expected: all commands pass. Existing ignored or environment-dependent tests should remain in their current state.

- [ ] **Step 3: Run formatting**

Run:

```bash
cargo fmt --all --check
```

Expected: formatting check passes. If it fails, run `cargo fmt --all`, then rerun the check.

- [ ] **Step 4: Commit verification fixes after formatting or test changes**

If formatting or test fixes changed files:

```bash
git add <changed-files>
git commit -m "Polish startup probe implementation"
```

If no files changed, do not create an empty commit.

---

## Self-Review Notes

- Spec coverage: custom `http://`/`https://` URL, `2xx/3xx` success, configured outbound path, explicit/default outbound tag, routing bypass, timeout, startup rollback, and FFI/mobile exposure are covered by Tasks 1-7.
- Placeholder scan: no task uses deferred implementation language; each code-changing step includes concrete code and commands.
- Type consistency: `StartupProbeOptions`, `StartupProbeError`, `CoreError::StartupProbe`, `Core::with_startup_probe`, `Core::set_startup_probe`, `select_tcp_outbound_direct`, and `TlsConnector::connect_stream` are introduced before later tasks reference them.
