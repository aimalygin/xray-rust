# Outbound DNS Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow VLESS outbound server domains in the Rust runtime by resolving the outbound server address before raw TCP connect.

**Architecture:** Keep `TcpConnector` IP-only and introduce DNS as an explicit `xray-transport` resolver boundary. `xray-core-rs` owns an injectable resolver, resolves only the VLESS server target, and keeps SOCKS destination domains encoded in the VLESS request header.

**Tech Stack:** Rust 2021, Tokio `lookup_host`, `async-trait`, existing `xray-config`, `xray-core-rs`, `xray-routing`, `xray-transport`, `thiserror`.

---

## File Structure

- `crates/xray-transport/src/lib.rs`: add `DnsResolver`, `SystemDnsResolver`, and DNS-specific `TransportError` variants.
- `crates/xray-transport/tests/dns_tests.rs`: resolver boundary and localhost system resolution tests.
- `crates/xray-core-rs/src/outbound.rs`: preserve domain outbound servers in selection and add resolver-injected VLESS TCP open helper.
- `crates/xray-core-rs/src/lib.rs`: store an injectable DNS resolver in `Core`.
- `crates/xray-core-rs/src/socks.rs`: pass the runtime DNS resolver into accepted SOCKS connection handlers.
- `crates/xray-core-rs/Cargo.toml`: add `async-trait` as a dev-dependency for fake resolver tests.
- `crates/xray-core-rs/tests/runtime_data_path_tests.rs`: domain outbound selection, DNS failure, and domain-server E2E tests.
- `README.md`: document deterministic resolver-injected domain server support.
- `docs/verification.md`: document the domain-server data-path test.

---

## Task 1: Transport DNS Resolver Boundary

**Files:**
- Modify: `crates/xray-transport/src/lib.rs`
- Create: `crates/xray-transport/tests/dns_tests.rs`

- [ ] **Step 1: Write failing DNS resolver tests**

Create `crates/xray-transport/tests/dns_tests.rs`:

```rust
use xray_transport::{DnsResolver, SystemDnsResolver, TcpConnector, TransportConnector, TransportError};
use xray_routing::{Network, Target, TargetAddr};

#[tokio::test]
async fn system_dns_resolver_resolves_localhost_without_tcp_io() {
    let resolver = SystemDnsResolver::default();

    let addr = resolver.resolve("localhost", 443).await.unwrap();

    assert_eq!(addr.port(), 443);
}

#[tokio::test]
async fn tcp_connector_still_rejects_domain_targets_without_dns() {
    let connector = TcpConnector::new(xray_transport::ConnectorConfig::Tcp);
    let target = Target::new(
        TargetAddr::Domain("localhost".to_owned()),
        443,
        Network::Tcp,
    );

    let result = connector.connect(&target).await;

    assert!(matches!(result, Err(TransportError::NeedsDns(domain)) if domain == "localhost"));
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p xray-transport --test dns_tests
```

Expected: FAIL because `DnsResolver` and `SystemDnsResolver` do not exist.

- [ ] **Step 3: Implement DNS resolver boundary**

Update `crates/xray-transport/src/lib.rs` imports:

```rust
use async_trait::async_trait;
use std::net::SocketAddr;
```

Extend `TransportError`:

```rust
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("domain resolution is required for {0}")]
    NeedsDns(String),
    #[error("dns lookup failed for {domain}:{port}: {source}")]
    Dns {
        domain: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("dns lookup returned no addresses for {0}:{1}")]
    NoResolvedAddress(String, u16),
    #[error("tcp connect failed: {0}")]
    Tcp(std::io::Error),
    #[error("tls connect failed")]
    Tls,
    #[error("{0} connector config is not supported by TcpConnector")]
    UnsupportedConnectorConfig(&'static str),
    #[error("unsupported REALITY fingerprint {0}")]
    UnsupportedRealityFingerprint(String),
}
```

Add the trait and system resolver before `TransportConnector`:

```rust
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        let mut addrs =
            tokio::net::lookup_host((domain, port))
                .await
                .map_err(|source| TransportError::Dns {
                    domain: domain.to_owned(),
                    port,
                    source,
                })?;

        addrs
            .next()
            .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
    }
}
```

Keep `TcpConnector::connect` unchanged for domain targets:

```rust
TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p xray-transport --test dns_tests
cargo test -p xray-transport --test transport_tests
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/src/lib.rs crates/xray-transport/tests/dns_tests.rs
git commit -m "feat(transport): add dns resolver boundary"
```

---

## Task 2: Resolver-Injected VLESS TCP Dialer

**Files:**
- Modify: `crates/xray-core-rs/Cargo.toml`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write failing domain selection test**

Update imports in `crates/xray-core-rs/tests/runtime_data_path_tests.rs`:

```rust
use xray_routing::TargetAddr as RoutingTargetAddr;
```

Replace the old domain rejection test with:

```rust
#[test]
fn selects_domain_vless_server_for_dns_resolution() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Domain("vless.test".to_owned()),
        443,
    ));

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.server().port, 443);
    assert_eq!(
        selected.server().addr,
        RoutingTargetAddr::Domain("vless.test".to_owned())
    );
}
```

- [ ] **Step 2: Run domain selection RED**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests selects_domain_vless_server_for_dns_resolution
```

Expected: FAIL because `select_vless_tcp_outbound` still returns `UnsupportedOutboundServerAddress`.

- [ ] **Step 3: Implement domain-preserving selection**

Replace the server address match in `crates/xray-core-rs/src/outbound.rs`:

```rust
let addr = match &settings.server {
    TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
    TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
};
```

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests selects_domain_vless_server_for_dns_resolution
```

Expected: PASS.

- [ ] **Step 4: Write failing resolver-injected open test**

Update `crates/xray-core-rs/Cargo.toml`:

```toml
[dev-dependencies]
async-trait.workspace = true
uuid.workspace = true
```

Expand imports in `crates/xray-core-rs/tests/runtime_data_path_tests.rs`:

```rust
use async_trait::async_trait;
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{DnsResolver, TransportError};
```

Add this fake resolver near the test helpers:

```rust
#[derive(Debug, Clone, Default)]
struct EmptyDnsResolver;

#[async_trait]
impl DnsResolver for EmptyDnsResolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
    }
}
```

Add a resolver failure test:

```rust
#[tokio::test]
async fn vless_tcp_open_reports_dns_failure_for_unresolved_server_domain() {
    let config = config_with_outbound(vless_outbound(
        StreamSecurity::None,
        TargetAddr::Domain("missing.test".to_owned()),
        443,
    ));
    let outbound = select_vless_tcp_outbound(&config).unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        80,
        RoutingNetwork::Tcp,
    );

    let result =
        xray_core_rs::open_vless_tcp_stream_with_resolver(&outbound, &target, &EmptyDnsResolver)
            .await;

    assert!(matches!(
        result,
        Err(CoreError::Transport(TransportError::NoResolvedAddress(domain, 443)))
            if domain == "missing.test"
    ));
}
```

- [ ] **Step 5: Run resolver helper RED**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests vless_tcp_open_reports_dns_failure_for_unresolved_server_domain
```

Expected: FAIL because `open_vless_tcp_stream_with_resolver` does not exist yet.

- [ ] **Step 6: Implement resolver-injected open**

Update `crates/xray-core-rs/src/outbound.rs` imports:

```rust
use xray_transport::{
    ConnectorConfig, DnsResolver, SystemDnsResolver, TcpConnector, TransportConnector,
};
```

Add a resolver helper:

```rust
async fn resolve_server_target(
    server: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<Target, CoreError> {
    match &server.addr {
        RoutingTargetAddr::Ip(ip) => Ok(Target::new(
            RoutingTargetAddr::Ip(*ip),
            server.port,
            server.network,
        )),
        RoutingTargetAddr::Domain(domain) => {
            let resolved = dns_resolver.resolve(domain, server.port).await?;
            Ok(Target::new(
                RoutingTargetAddr::Ip(resolved.ip()),
                resolved.port(),
                server.network,
            ))
        }
    }
}
```

Add the resolver-injected public helper:

```rust
pub async fn open_vless_tcp_stream_with_resolver(
    outbound: &VlessTcpOutbound,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<tokio::net::TcpStream, CoreError> {
    if outbound.user.flow.is_some() {
        return Err(CoreError::UnsupportedOutboundFlow);
    }

    let resolved_server = resolve_server_target(&outbound.server, dns_resolver).await?;
    let connector = TcpConnector::new(ConnectorConfig::Tcp);
    let mut stream = connector.connect(&resolved_server).await?;
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

Change the existing convenience function:

```rust
pub async fn open_vless_tcp_stream(
    outbound: &VlessTcpOutbound,
    target: &Target,
) -> Result<tokio::net::TcpStream, CoreError> {
    open_vless_tcp_stream_with_resolver(outbound, target, &SystemDnsResolver).await
}
```

Update `crates/xray-core-rs/src/lib.rs` exports:

```rust
pub use outbound::{
    open_vless_tcp_stream, open_vless_tcp_stream_with_resolver, select_vless_tcp_outbound,
    VlessTcpOutbound,
};
```

- [ ] **Step 7: Run focused tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests selects_domain_vless_server_for_dns_resolution
cargo test -p xray-core-rs --test runtime_data_path_tests vless_tcp_open_reports_dns_failure_for_unresolved_server_domain
cargo test -p xray-core-rs --test runtime_data_path_tests rejects_tls_outbound_for_raw_tcp_runtime_path
cargo test -p xray-core-rs --test runtime_data_path_tests rejects_reality_outbound_for_raw_tcp_runtime_path
cargo test -p xray-core-rs --test runtime_data_path_tests rejects_vision_flow_for_raw_tcp_runtime_path
cargo test -p xray-core-rs
```

Expected: PASS. The full `xray-core-rs` package tests may require loopback permission for lifecycle and E2E tests.

- [ ] **Step 8: Commit**

```bash
git add crates/xray-core-rs/Cargo.toml crates/xray-core-rs/src/lib.rs crates/xray-core-rs/src/outbound.rs crates/xray-core-rs/tests/runtime_data_path_tests.rs
git commit -m "feat(core): resolve vless outbound domains"
```

---

## Task 3: Inject DNS Resolver into Core Runtime

**Files:**
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/src/socks.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write failing runtime E2E with domain outbound server**

Add this helper to `crates/xray-core-rs/tests/runtime_data_path_tests.rs`:

```rust
#[derive(Debug, Clone)]
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

fn runtime_config_with_vless_domain_server(domain: &str, port: u16) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![vless_outbound(
            StreamSecurity::None,
            TargetAddr::Domain(domain.to_owned()),
            port,
        )],
        default_outbound_tag: None,
    }
}
```

Add the E2E test:

```rust
#[tokio::test]
async fn socks_client_reaches_echo_target_through_domain_vless_server() {
    timeout(Duration::from_secs(2), run_domain_vless_server_echo_scenario())
        .await
        .unwrap();
}

async fn run_domain_vless_server_echo_scenario() {
    let (echo_addr, echo_handle) = spawn_echo_server().await;
    let (vless_addr, vless_handle) = spawn_fake_vless_server().await;
    let resolver = StaticDnsResolver {
        domain: "vless.test",
        addr: vless_addr,
    };
    let config = runtime_config_with_vless_domain_server("vless.test", vless_addr.port());

    let mut core = Core::with_dns_resolver(config, std::sync::Arc::new(resolver)).unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    socks5_connect(&mut client, echo_addr).await;

    client.write_all(b"hello dns runtime").await.unwrap();
    let mut echoed = vec![0; "hello dns runtime".len()];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(echoed, b"hello dns runtime");
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

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_domain_vless_server
```

Expected: FAIL because `Core::with_dns_resolver` does not exist and runtime listener does not pass a resolver to outbound open.

- [ ] **Step 3: Implement Core DNS injection**

Update `crates/xray-core-rs/src/lib.rs` imports:

```rust
use xray_transport::{DnsResolver, SystemDnsResolver};
```

Update `Core`:

```rust
pub struct Core {
    config: CoreConfig,
    state: CoreState,
    shutdown: Shutdown,
    tun: TunEndpoint,
    runtime: Option<RuntimeState>,
    dns_resolver: Arc<dyn DnsResolver>,
}
```

Change constructors:

```rust
impl Core {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        Self::with_dns_resolver(config, Arc::new(SystemDnsResolver))
    }

    pub fn with_dns_resolver(
        config: CoreConfig,
        dns_resolver: Arc<dyn DnsResolver>,
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
        })
    }
}
```

In `Core::start()`, clone the resolver before spawning listener tasks:

```rust
let dns_resolver = Arc::clone(&self.dns_resolver);
let task = tokio::spawn(socks::serve_socks_listener(
    listener,
    Arc::clone(&config),
    Arc::clone(&dns_resolver),
    self.shutdown.subscribe(),
));
```

Update `crates/xray-core-rs/src/socks.rs` imports:

```rust
use xray_transport::DnsResolver;

use crate::{open_vless_tcp_stream_with_resolver, select_vless_tcp_outbound};
```

Update listener signature:

```rust
pub async fn serve_socks_listener(
    listener: TcpListener,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    mut shutdown: watch::Receiver<bool>,
)
```

Pass resolver into connection tasks:

```rust
let dns_resolver = Arc::clone(&dns_resolver);
connections.spawn(async move {
    handle_socks_connection(stream, config, dns_resolver).await;
});
```

Update connection handler:

```rust
async fn handle_socks_connection(
    mut inbound: TcpStream,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
) {
    if negotiate_socks5_no_auth(&mut inbound).await.is_err() {
        return;
    }

    let target = match parse_socks5_request(&mut inbound).await {
        Ok(target) => target,
        Err(_) => {
            let _ = write_socks5_failure(&mut inbound).await;
            return;
        }
    };

    let outbound = match select_vless_tcp_outbound(&config) {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = write_socks5_failure(&mut inbound).await;
            return;
        }
    };

    let mut outbound_stream =
        match open_vless_tcp_stream_with_resolver(&outbound, &target, dns_resolver.as_ref()).await {
            Ok(stream) => stream,
            Err(_) => {
                let _ = write_socks5_failure(&mut inbound).await;
                return;
            }
        };

    if write_socks5_success(&mut inbound).await.is_err() {
        return;
    }

    let _ = copy_bidirectional(&mut inbound, &mut outbound_stream).await;
}
```

- [ ] **Step 4: Run focused runtime tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_domain_vless_server
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tcp_outbound
cargo test -p xray-core-rs --test core_lifecycle_tests
```

Expected: PASS with loopback permission.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-core-rs/src/lib.rs crates/xray-core-rs/src/socks.rs crates/xray-core-rs/tests/runtime_data_path_tests.rs
git commit -m "feat(core): inject dns resolver into runtime"
```

---

## Task 4: Documentation and Full Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/verification.md`

- [ ] **Step 1: Update README runtime status**

Update the current runtime status paragraph in `README.md` to:

```markdown
Current runtime status: the raw TCP VLESS path is executable for a local SOCKS5 client and covered by end-to-end Rust tests with a fake VLESS server. VLESS outbound servers may be configured as IP addresses or, when a resolver is available, domains. Full Xray DNS behavior, TLS, REALITY, and Vision live traffic remain future work; protected modes are rejected by the raw runtime path rather than silently falling back to plaintext.
```

- [ ] **Step 2: Update verification docs**

Add this command after the first live runtime data-path test in `docs/verification.md`:

````markdown
Run the resolver-injected domain outbound server data-path test:

```sh
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_domain_vless_server
```
````

Update the explanatory sentence to say the tests prove both IP outbound server and resolver-injected domain outbound server paths, but not full Xray DNS behavior.

- [ ] **Step 3: Run full verification**

Run from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
```

Expected: PASS. The full test suite needs loopback bind/connect permission for SOCKS runtime tests in this sandbox.

Run the Go oracle from `/Users/antonmalygin/xray-rust/Xray-core`:

```bash
go test ./testing/scenarios -run TestVlessXtlsVisionReality -count=1
```

Expected: PASS with loopback bind/connect permission.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/verification.md
git commit -m "docs: document outbound dns resolution"
```

---

## Self-Review Notes

Spec coverage:

- DNS boundary in `xray-transport`: Task 1.
- `TcpConnector` remains IP-only: Task 1 tests preserve `NeedsDns`.
- Domain VLESS server selection and resolver-injected dialer: Task 2.
- `Core::with_dns_resolver` and runtime listener injection: Task 3.
- Domain-server E2E with fake resolver: Task 3.
- Downgrade protections remain in place: Task 2 focused rejection tests and existing runtime tests.
- Docs and full verification: Task 4.

Known residual work after this plan:

- HTTP CONNECT runtime listener.
- DNS caching and Xray-compatible DNS app/routing behavior.
- REALITY/TLS protected connector implementation in the live runtime.
- Vision traffic wrapping in the live relay.
- TUN data path.
