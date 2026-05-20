# TLS Connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a live VLESS-over-TLS runtime path using the existing boxed transport stream boundary.

**Architecture:** `xray-transport` owns TLS connection setup and returns `BoxedTransportStream`; `xray-core-rs` selects `ConnectorConfig::Tls` only for supported TLS config and passes it through an injected `TransportDialer`. SOCKS relay remains unchanged semantically and continues to copy bytes between inbound and outbound streams.

**Tech Stack:** Rust 2021, Tokio, rustls 0.23 with explicit `ring` provider, tokio-rustls 0.26, webpki-roots, rcgen for local TLS tests.

---

## File Structure

- `Cargo.toml`: configure rustls/tokio-rustls provider features and add workspace dependencies for `webpki-roots` and `rcgen`.
- `crates/xray-transport/Cargo.toml`: add `webpki-roots` runtime dependency and `rcgen` dev dependency.
- `crates/xray-transport/src/lib.rs`: export TLS connector and dialer; add TLS-specific transport errors.
- `crates/xray-transport/src/tls.rs`: implement `TlsConnector`, default root store, and TLS stream wrapping.
- `crates/xray-transport/src/dialer.rs`: implement `TransportDialer` transport selection.
- `crates/xray-transport/tests/transport_tests.rs`: add TLS connector tests and keep plaintext downgrade tests.
- `crates/xray-core-rs/Cargo.toml`: add dev dependencies needed for TLS runtime E2E.
- `crates/xray-core-rs/src/lib.rs`: store injected `TransportDialer` in `Core`.
- `crates/xray-core-rs/src/outbound.rs`: carry selected `ConnectorConfig`, support TLS selection, and route connects through `TransportDialer`.
- `crates/xray-core-rs/src/socks.rs`: pass the injected dialer into outbound stream opening; keep relay semantics unchanged.
- `crates/xray-core-rs/tests/runtime_data_path_tests.rs`: add TLS selection tests and SOCKS -> VLESS-over-TLS E2E.

### Task 1: Transport TLS Connector And Dialer

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/xray-transport/Cargo.toml`
- Modify: `crates/xray-transport/src/lib.rs`
- Create: `crates/xray-transport/src/tls.rs`
- Create: `crates/xray-transport/src/dialer.rs`
- Modify: `crates/xray-transport/tests/transport_tests.rs`

- [ ] **Step 1: Update TLS dependencies and lockfile**

In workspace `Cargo.toml`, replace:

```toml
rustls = "0.23"
tokio-rustls = "0.26"
```

with:

```toml
rustls = { version = "0.23", default-features = false, features = ["logging", "ring", "std", "tls12"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["logging", "ring", "tls12"] }
```

Add these workspace dependencies next to the other dependency versions:

```toml
rcgen = { version = "0.14", default-features = false, features = ["ring"] }
webpki-roots = "1"
```

In `crates/xray-transport/Cargo.toml`, add runtime `webpki-roots`:

```toml
webpki-roots.workspace = true
```

Add a dev-dependencies section if it is not present:

```toml
[dev-dependencies]
rcgen.workspace = true
```

Run:

```bash
cargo check -p xray-transport
```

Expected: PASS and `Cargo.lock` updates. If dependency download fails because the sandbox blocks network access, rerun the same command with escalated network permission.

- [ ] **Step 2: Write failing TLS transport tests**

In `crates/xray-transport/tests/transport_tests.rs`, extend imports inside `mod transport_tests`:

```rust
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::TlsAcceptor;
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, RealityClientConfig, TcpConnector, TlsClientConfig,
    TlsConnector, TransportConnector, TransportDialer, TransportError,
};
```

Add these helpers after `assert_boxed_transport_stream`:

```rust
fn tls_test_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["server.test".to_owned()])
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

async fn spawn_tls_echo_once(server_config: Arc<rustls::ServerConfig>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind TLS echo listener");
    let addr = listener.local_addr().expect("read listener address");
    let acceptor = TlsAcceptor::from(server_config);

    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept TLS echo client");
        let mut stream = acceptor.accept(stream).await.expect("accept TLS stream");
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.expect("read ping");
        stream.write_all(&buf).await.expect("write pong");
    });

    (addr, handle)
}
```

Add these tests after `tcp_connector_returns_boxed_transport_stream`:

```rust
#[tokio::test]
async fn tls_connector_returns_boxed_transport_stream() {
    let (client_config, server_config) = tls_test_configs();
    let (addr, handle) = spawn_tls_echo_once(server_config).await;
    let connector = TlsConnector::with_client_config(client_config);
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
    let config = TlsClientConfig {
        server_name: "server.test".to_owned(),
    };

    let stream = connector
        .connect(&target, &config)
        .await
        .expect("connect TLS target");

    assert_boxed_transport_stream(stream).await;
    handle.await.expect("TLS echo task should complete");
}

#[tokio::test]
async fn tls_connector_requires_dns_for_domain_targets() {
    let (client_config, _) = tls_test_configs();
    let connector = TlsConnector::with_client_config(client_config);
    let target = Target::new(
        TargetAddr::Domain("server.test".to_owned()),
        443,
        Network::Tcp,
    );
    let config = TlsClientConfig {
        server_name: "server.test".to_owned(),
    };

    let result = connector.connect(&target, &config).await;

    assert!(matches!(result, Err(TransportError::NeedsDns(domain)) if domain == "server.test"));
}

#[tokio::test]
async fn tls_connector_rejects_invalid_server_name_before_network_io() {
    let (client_config, _) = tls_test_configs();
    let connector = TlsConnector::with_client_config(client_config);
    let target = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        9,
        Network::Tcp,
    );
    let config = TlsClientConfig {
        server_name: "bad name".to_owned(),
    };

    let result = connector.connect(&target, &config).await;

    assert!(matches!(
        result,
        Err(TransportError::InvalidTlsServerName(name)) if name == "bad name"
    ));
}

#[tokio::test]
async fn transport_dialer_routes_tls_configs_to_tls_connector() {
    let (client_config, server_config) = tls_test_configs();
    let (addr, handle) = spawn_tls_echo_once(server_config).await;
    let dialer = TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
    let config = ConnectorConfig::Tls(TlsClientConfig {
        server_name: "server.test".to_owned(),
    });

    let stream = dialer
        .connect(&config, &target)
        .await
        .expect("dial TLS target");

    assert_boxed_transport_stream(stream).await;
    handle.await.expect("TLS echo task should complete");
}
```

- [ ] **Step 3: Run focused transport tests to verify they fail**

Run:

```bash
cargo test -p xray-transport --test transport_tests tls_connector_returns_boxed_transport_stream
```

Expected: FAIL at compile time because `TlsConnector`, `TransportDialer`, and new TLS errors do not exist yet.

- [ ] **Step 4: Implement TLS errors and exports**

In `crates/xray-transport/src/lib.rs`, add modules:

```rust
mod dialer;
pub mod reality;
pub mod reality_connector;
mod tls;

pub use dialer::TransportDialer;
pub use tls::TlsConnector;
```

Replace the existing `pub mod reality; pub mod reality_connector;` block with the block above.

Change `TransportError::Tls` from:

```rust
#[error("tls connect failed")]
Tls,
```

to:

```rust
#[error("tls connect failed: {0}")]
Tls(std::io::Error),
#[error("tls configuration failed: {0}")]
TlsConfig(String),
#[error("invalid tls server name `{0}`")]
InvalidTlsServerName(String),
```

- [ ] **Step 5: Implement `TlsConnector`**

Create `crates/xray-transport/src/tls.rs`:

```rust
use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as TokioTlsConnector;
use xray_routing::{Target, TargetAddr};

use crate::{BoxedTransportStream, TlsClientConfig, TransportError};

#[derive(Debug, Clone)]
pub struct TlsConnector {
    client_config: Arc<rustls::ClientConfig>,
}

impl TlsConnector {
    pub fn system() -> Result<Self, TransportError> {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let client_config = rustls_client_config(root_store)?;

        Ok(Self::with_client_config(Arc::new(client_config)))
    }

    pub fn with_client_config(client_config: Arc<rustls::ClientConfig>) -> Self {
        Self { client_config }
    }

    pub async fn connect(
        &self,
        target: &Target,
        config: &TlsClientConfig,
    ) -> Result<BoxedTransportStream, TransportError> {
        let server_name = rustls::pki_types::ServerName::try_from(config.server_name.clone())
            .map_err(|_| TransportError::InvalidTlsServerName(config.server_name.clone()))?;

        let addr = match &target.addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
            TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
        };

        let stream = TcpStream::connect(addr)
            .await
            .map_err(TransportError::Tcp)?;
        let stream = TokioTlsConnector::from(Arc::clone(&self.client_config))
            .connect(server_name, stream)
            .await
            .map_err(TransportError::Tls)?;

        Ok(Box::new(stream))
    }
}

fn rustls_client_config(
    root_store: rustls::RootCertStore,
) -> Result<rustls::ClientConfig, TransportError> {
    rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| TransportError::TlsConfig(error.to_string()))
    .map(|builder| builder.with_root_certificates(root_store).with_no_client_auth())
}
```

- [ ] **Step 6: Implement `TransportDialer`**

Create `crates/xray-transport/src/dialer.rs`:

```rust
use crate::{
    BoxedTransportStream, ConnectorConfig, TcpConnector, TlsConnector, TransportConnector,
    TransportError,
};
use xray_routing::Target;

#[derive(Debug, Clone)]
pub struct TransportDialer {
    tls: TlsConnector,
}

impl TransportDialer {
    pub fn system() -> Result<Self, TransportError> {
        Ok(Self {
            tls: TlsConnector::system()?,
        })
    }

    pub fn with_tls_connector(tls: TlsConnector) -> Self {
        Self { tls }
    }

    pub async fn connect(
        &self,
        config: &ConnectorConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        match config {
            ConnectorConfig::Tcp => TcpConnector::new(ConnectorConfig::Tcp).connect(target).await,
            ConnectorConfig::Tls(tls_config) => self.tls.connect(target, tls_config).await,
            ConnectorConfig::Reality(_) => {
                Err(TransportError::UnsupportedConnectorConfig("reality"))
            }
        }
    }
}
```

- [ ] **Step 7: Run transport tests**

Run:

```bash
cargo test -p xray-transport --test transport_tests tls_connector_returns_boxed_transport_stream
cargo test -p xray-transport --test transport_tests tls_connector_requires_dns_for_domain_targets
cargo test -p xray-transport --test transport_tests tls_connector_rejects_invalid_server_name_before_network_io
cargo test -p xray-transport --test transport_tests transport_dialer_routes_tls_configs_to_tls_connector
cargo test -p xray-transport --test transport_tests
```

Expected: PASS. These tests use loopback bind/connect, so run with loopback permission in this sandbox.

- [ ] **Step 8: Check provider dependency selection**

Run:

```bash
cargo tree --workspace --locked
```

Expected: output includes `ring` and does not include `aws-lc-rs` or `aws-lc-sys`.

- [ ] **Step 9: Commit**

Run:

```bash
git add Cargo.toml Cargo.lock crates/xray-transport/Cargo.toml crates/xray-transport/src/lib.rs crates/xray-transport/src/tls.rs crates/xray-transport/src/dialer.rs crates/xray-transport/tests/transport_tests.rs
git commit -m "feat(transport): add tls connector"
```

### Task 2: Core TLS Selection And Dialer Injection

**Files:**
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/src/socks.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write failing core selection tests**

In `crates/xray-core-rs/tests/runtime_data_path_tests.rs`, add these tests after `rejects_tls_outbound_for_raw_tcp_runtime_path`:

```rust
#[test]
fn selects_tls_vless_outbound_without_fingerprint() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some("server.example".to_owned()),
            fingerprint: None,
        }),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server().port, 443);
    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Tls(config) if config.server_name == "server.example"
    ));
}

#[test]
fn selects_tls_server_name_from_domain_outbound_when_missing() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: None,
            fingerprint: None,
        }),
        TargetAddr::Domain("vless.test".to_owned()),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Tls(config) if config.server_name == "vless.test"
    ));
}

#[test]
fn rejects_tls_ip_server_without_server_name() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: None,
            fingerprint: None,
        }),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    ));

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(
        result,
        Err(CoreError::UnsupportedOutboundSecurity)
    ));
}

#[test]
fn rejects_tls_fingerprint_without_plain_rustls_downgrade() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some("server.example".to_owned()),
            fingerprint: Some("chrome".to_owned()),
        }),
        TargetAddr::Domain("vless.test".to_owned()),
        443,
    ));

    let result = select_vless_tcp_outbound(&config);

    assert!(matches!(
        result,
        Err(CoreError::UnsupportedOutboundSecurity)
    ));
}
```

- [ ] **Step 2: Run selection tests to verify they fail**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests selects_tls_vless_outbound_without_fingerprint
```

Expected: FAIL because TLS is still rejected and `VlessTcpOutbound::transport` does not exist.

- [ ] **Step 3: Update `VlessTcpOutbound` and TLS selection**

In `crates/xray-core-rs/src/outbound.rs`, change imports from:

```rust
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, DnsResolver, SystemDnsResolver, TcpConnector,
    TransportConnector,
};
```

to:

```rust
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, DnsResolver, SystemDnsResolver, TlsClientConfig,
    TransportDialer,
};
```

Change `VlessTcpOutbound`:

```rust
pub struct VlessTcpOutbound {
    server: Target,
    user: VlessUser,
    transport: ConnectorConfig,
}

impl VlessTcpOutbound {
    pub fn server(&self) -> &Target {
        &self.server
    }

    pub fn transport(&self) -> &ConnectorConfig {
        &self.transport
    }
}
```

Replace the current security rejection:

```rust
if !matches!(outbound.stream.security, StreamSecurity::None) {
    return Err(CoreError::UnsupportedOutboundSecurity);
}
```

with this after `let OutboundSettings::Vless(settings) = &outbound.settings;`:

```rust
let transport = match &outbound.stream.security {
    StreamSecurity::None => ConnectorConfig::Tcp,
    StreamSecurity::Tls(tls) => {
        if tls.fingerprint.is_some() {
            return Err(CoreError::UnsupportedOutboundSecurity);
        }

        let server_name = match tls.server_name.as_deref() {
            Some(name) if !name.is_empty() => name.to_owned(),
            Some(_) => return Err(CoreError::UnsupportedOutboundSecurity),
            None => match &settings.server {
                TargetAddr::Domain(domain) => domain.clone(),
                TargetAddr::Ip(_) => return Err(CoreError::UnsupportedOutboundSecurity),
            },
        };

        ConnectorConfig::Tls(TlsClientConfig { server_name })
    }
    StreamSecurity::Reality(_) => return Err(CoreError::UnsupportedOutboundSecurity),
};
```

Return the transport:

```rust
Ok(VlessTcpOutbound {
    server: Target::new(addr, settings.port, RoutingNetwork::Tcp),
    user,
    transport,
})
```

Update the unit test constructor in `outbound.rs` to include:

```rust
transport: ConnectorConfig::Tcp,
```

- [ ] **Step 4: Add dialer-aware outbound opening**

In `crates/xray-core-rs/src/outbound.rs`, add this new function and make existing helpers call it:

```rust
pub async fn open_vless_tcp_stream_with_resolver_and_dialer(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
    transport_dialer: &TransportDialer,
) -> Result<BoxedTransportStream, CoreError> {
    if outbound.user.flow.is_some() {
        return Err(CoreError::UnsupportedOutboundFlow);
    }

    let resolved_server = resolve_server_target(&outbound.server, dns_resolver).await?;
    let mut stream = transport_dialer
        .connect(&outbound.transport, &resolved_server)
        .await?;
    let request = VlessRequest {
        user_id: outbound.user.id,
        command: VlessCommand::Tcp,
        target: target.clone(),
        flow: outbound.user.flow.clone(),
    };
    let header = encode_request_header(&request)?;

    stream.write_all(&header).await?;

    Ok(stream)
}
```

Replace the body of `open_vless_tcp_stream_with_resolver` with:

```rust
let transport_dialer = TransportDialer::system()?;
open_vless_tcp_stream_with_resolver_and_dialer(
    outbound,
    target,
    dns_resolver,
    &transport_dialer,
)
.await
```

Keep `open_vless_tcp_stream` as the convenience wrapper around `SystemDnsResolver`.

In `crates/xray-core-rs/src/lib.rs`, export the new helper:

```rust
pub use outbound::{
    open_vless_tcp_stream, open_vless_tcp_stream_with_resolver,
    open_vless_tcp_stream_with_resolver_and_dialer, select_vless_tcp_outbound, VlessTcpOutbound,
};
```

- [ ] **Step 5: Inject `TransportDialer` into `Core`**

In `crates/xray-core-rs/src/lib.rs`, change imports:

```rust
use xray_transport::{DnsResolver, SystemDnsResolver, TransportDialer};
```

Add a field to `Core`:

```rust
transport_dialer: Arc<TransportDialer>,
```

Replace `Core::new` and `Core::with_dns_resolver` with:

```rust
pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
    Self::with_dns_resolver(config, Arc::new(SystemDnsResolver))
}

/// Creates a core with an injected DNS resolver.
///
/// The resolver is currently used by runtime outbound dialers to resolve
/// configured outbound server domains. It is not a full Xray DNS policy hook.
pub fn with_dns_resolver(
    config: CoreConfig,
    dns_resolver: Arc<dyn DnsResolver>,
) -> Result<Self, CoreError> {
    Self::with_runtime_dependencies(
        config,
        dns_resolver,
        Arc::new(TransportDialer::system()?),
    )
}

pub fn with_runtime_dependencies(
    config: CoreConfig,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
) -> Result<Self, CoreError> {
    let shutdown = Shutdown::new();
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 128,
    });

    Ok(Self {
        config,
        state: CoreState::Created,
        shutdown,
        tun,
        runtime: None,
        dns_resolver,
        transport_dialer,
    })
}
```

In `Core::start`, clone and pass the dialer:

```rust
let transport_dialer = Arc::clone(&self.transport_dialer);
let task = tokio::spawn(socks::serve_socks_listener(
    listener,
    Arc::clone(&config),
    dns_resolver,
    transport_dialer,
    self.shutdown.subscribe(),
));
```

In `crates/xray-core-rs/src/socks.rs`, import `TransportDialer`:

```rust
use xray_transport::{DnsResolver, TransportDialer};
```

Update function signatures and spawned task capture:

```rust
pub async fn serve_socks_listener(
    listener: TcpListener,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    mut shutdown: watch::Receiver<bool>,
)
```

```rust
let transport_dialer = Arc::clone(&transport_dialer);
connections.spawn(async move {
    handle_socks_connection(stream, config, dns_resolver, transport_dialer).await;
});
```

```rust
async fn handle_socks_connection(
    mut inbound: TcpStream,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
)
```

Call the dialer-aware helper:

```rust
let mut outbound_stream = match open_vless_tcp_stream_with_resolver_and_dialer(
    &outbound,
    &target,
    dns_resolver.as_ref(),
    transport_dialer.as_ref(),
)
.await
```

- [ ] **Step 6: Run core selection tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests selects_tls_vless_outbound_without_fingerprint
cargo test -p xray-core-rs --test runtime_data_path_tests selects_tls_server_name_from_domain_outbound_when_missing
cargo test -p xray-core-rs --test runtime_data_path_tests rejects_tls_ip_server_without_server_name
cargo test -p xray-core-rs --test runtime_data_path_tests rejects_tls_fingerprint_without_plain_rustls_downgrade
cargo test -p xray-core-rs --lib
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add crates/xray-core-rs/src/lib.rs crates/xray-core-rs/src/outbound.rs crates/xray-core-rs/src/socks.rs crates/xray-core-rs/tests/runtime_data_path_tests.rs
git commit -m "feat(core): select tls outbound transport"
```

### Task 3: Runtime VLESS-Over-TLS E2E

**Files:**
- Modify: `crates/xray-core-rs/Cargo.toml`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Add core test dev dependencies**

In `crates/xray-core-rs/Cargo.toml`, update dev-dependencies:

```toml
[dev-dependencies]
async-trait.workspace = true
rcgen.workspace = true
rustls.workspace = true
tokio-rustls.workspace = true
uuid.workspace = true
```

- [ ] **Step 2: Write failing TLS runtime E2E**

In `crates/xray-core-rs/tests/runtime_data_path_tests.rs`, extend imports:

```rust
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use xray_transport::{DnsResolver, TlsConnector, TransportDialer, TransportError};
```

Change the existing `tokio::io` import to include `AsyncRead` exactly once.

Add a TLS runtime config helper after `runtime_config_with_vless_domain_server`:

```rust
fn runtime_config_with_tls_vless_domain_server(domain: &str, port: u16, server_name: &str) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::Tls(TlsSettings {
                server_name: Some(server_name.to_owned()),
                fingerprint: None,
            }),
            TargetAddr::Domain(domain.to_owned()),
            port,
        )],
        default_outbound_tag: None,
    }
}
```

Add TLS config helpers near the fake server helpers:

```rust
fn tls_test_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["vless.test".to_owned()])
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

async fn spawn_fake_tls_vless_server(
    server_config: Arc<rustls::ServerConfig>,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut inbound = acceptor.accept(stream).await.unwrap();
        let target = read_vless_header(&mut inbound).await;
        let mut target_stream = TcpStream::connect(target).await.unwrap();
        copy_bidirectional(&mut inbound, &mut target_stream)
            .await
            .unwrap();
    });

    (addr, handle)
}
```

Add the scenario and test:

```rust
#[tokio::test]
async fn socks_client_reaches_echo_target_through_vless_tls_outbound() {
    timeout(Duration::from_secs(2), run_socks_to_vless_tls_echo_scenario())
        .await
        .unwrap();
}

async fn run_socks_to_vless_tls_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (client_config, server_config) = tls_test_configs();
    let (vless_addr, vless_handle) = spawn_fake_tls_vless_server(server_config).await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config =
        runtime_config_with_tls_vless_domain_server("vless.test", vless_addr.port(), "vless.test");
    let dialer = TransportDialer::with_tls_connector(TlsConnector::with_client_config(client_config));

    let mut core = Core::with_runtime_dependencies(
        config,
        Arc::new(resolver),
        Arc::new(dialer),
    )
    .unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello tls runtime").await.unwrap();
    let mut echoed = vec![0; "hello tls runtime".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello tls runtime");
    drop(client);
    core.stop().await.unwrap();

    timeout(Duration::from_secs(1), vless_handle)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), echo_handle)
        .await
        .unwrap()
        .unwrap();
}
```

- [ ] **Step 3: Run the TLS E2E to verify it fails before implementation wiring is complete**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tls_outbound
```

Expected: FAIL at compile time because `spawn_fake_tls_vless_server` passes a TLS stream to `read_vless_header`, but the existing helper still accepts `&mut TcpStream`.

- [ ] **Step 4: Make the E2E compile and pass**

Make VLESS header readers generic over TCP and TLS streams:

```rust
async fn read_vless_target<S>(stream: &mut S) -> Target
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await.unwrap();
    assert_eq!(version, 0);

    let mut uuid = [0; 16];
    stream.read_exact(&mut uuid).await.unwrap();
    assert_eq!(uuid, TEST_UUID_BYTES);

    let addons_len = stream.read_u8().await.unwrap();
    assert_eq!(addons_len, 0);
    let mut addons = vec![0; usize::from(addons_len)];
    stream.read_exact(&mut addons).await.unwrap();

    let command = stream.read_u8().await.unwrap();
    assert_eq!(command, 1);

    let port = stream.read_u16().await.unwrap();
    let address_type = stream.read_u8().await.unwrap();
    let addr = match address_type {
        1 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await.unwrap();
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        2 => {
            let len = stream.read_u8().await.unwrap();
            let mut domain = vec![0; usize::from(len)];
            stream.read_exact(&mut domain).await.unwrap();
            RoutingTargetAddr::Domain(String::from_utf8(domain).unwrap())
        }
        3 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await.unwrap();
            RoutingTargetAddr::Ip(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        other => panic!("unsupported VLESS address type {other}"),
    };

    Target::new(addr, port, RoutingNetwork::Tcp)
}

async fn read_vless_header<S>(stream: &mut S) -> SocketAddr
where
    S: AsyncRead + Unpin,
{
    let target = read_vless_target(stream).await;
    let RoutingTargetAddr::Ip(ip) = target.addr else {
        panic!("this E2E expects an IP VLESS target");
    };
    SocketAddr::new(ip, target.port)
}
```

Do not change production relay semantics. Do not disable certificate verification. The test client must trust only the generated self-signed test certificate through the custom `rustls::ClientConfig`.

- [ ] **Step 5: Run runtime tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tls_outbound
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tcp_outbound
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_preserves_domain_target_through_domain_vless_server
cargo test -p xray-core-rs --test runtime_data_path_tests
```

Expected: PASS. These tests use loopback bind/connect, so run with loopback permission in this sandbox.

- [ ] **Step 6: Commit**

Run:

```bash
git add crates/xray-core-rs/Cargo.toml crates/xray-core-rs/tests/runtime_data_path_tests.rs Cargo.lock
git commit -m "test(core): cover vless over tls runtime path"
```

### Task 4: Full Verification

**Files:**
- Verify: `Cargo.toml`
- Verify: `Cargo.lock`
- Verify: `crates/xray-transport/src/lib.rs`
- Verify: `crates/xray-transport/src/tls.rs`
- Verify: `crates/xray-transport/src/dialer.rs`
- Verify: `crates/xray-core-rs/src/lib.rs`
- Verify: `crates/xray-core-rs/src/outbound.rs`
- Verify: `crates/xray-core-rs/src/socks.rs`
- Verify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt --all -- --check
```

Expected: PASS.

- [ ] **Step 2: Run Clippy**

Run:

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: PASS.

- [ ] **Step 3: Run all tests**

Run:

```bash
cargo test --workspace --all-targets
```

Expected: PASS. The command needs loopback bind/connect permission in this sandbox.

- [ ] **Step 4: Verify TLS provider dependency**

Run:

```bash
cargo tree --workspace --locked
```

Expected: output includes `ring` and does not include `aws-lc-rs` or `aws-lc-sys`.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git status --short
git diff --check
git log --oneline -6
```

Expected: clean worktree, no whitespace errors, and the three implementation commits are present after the plan/spec commits.

## Self-Review Notes

- Spec coverage: The plan implements TLS connector, explicit ring provider selection, webpki root store, custom test root injection, core TLS selection rules, fingerprint rejection, runtime dialer injection, and SOCKS -> VLESS-over-TLS E2E. REALITY and Vision remain out of scope.
- Placeholder scan: No placeholder tasks, no deferred work, and every code-producing step includes concrete snippets.
- Type consistency: `TlsConnector::system` and `TransportDialer::system` return `Result<_, TransportError>`; `Core::new` and `Core::with_dns_resolver` propagate those errors through `CoreError::Transport`; `TransportDialer::connect` accepts `&ConnectorConfig`; VLESS runtime helpers return `BoxedTransportStream`.
