# REALITY Runtime Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a gated `RealityRuntimeEngine` behind `RealityTlsEngine` that prepares REALITY handshakes and drives DNS/TCP setup, then stops before live TLS completion.

**Architecture:** `xray-transport` gets a focused `reality_runtime` module with injectable ClientHello, DNS, and handshake-context dependencies. `TransportDialer::system()` keeps rejecting REALITY until a caller explicitly injects this or another REALITY engine. `xray-core-rs` stays unchanged in this slice.

**Tech Stack:** Rust 2021, Tokio, async-trait, thiserror, existing `RealityConnector`, existing REALITY oracle fixtures.

---

## File Structure

- Create `crates/xray-transport/src/reality_runtime.rs`
  - Owns `RealityRuntimeEngine`, `RealityHandshakeContextProvider`, and `SystemRealityHandshakeContextProvider`.
  - Implements `RealityTlsEngine` for the runtime engine.
  - Keeps DNS, TCP, ClientHello, and context dependencies injectable for deterministic tests and mobile embedders.
- Create `crates/xray-transport/tests/reality_runtime_tests.rs`
  - Focused integration tests for the new runtime engine.
  - Reuses the existing Chrome ClientHello JSON fixture.
- Modify `crates/xray-transport/src/lib.rs`
  - Exports the runtime engine API.
  - Adds typed `TransportError` variants for REALITY primitive failures and the explicit live-TLS gate.
- Modify `README.md`
  - Updates status without claiming live REALITY support.
- Modify `docs/verification.md`
  - Adds the runtime engine test command and keeps compatibility caveats explicit.

---

### Task 1: Public Runtime Engine Gate

**Files:**
- Create: `crates/xray-transport/src/reality_runtime.rs`
- Create: `crates/xray-transport/tests/reality_runtime_tests.rs`
- Modify: `crates/xray-transport/src/lib.rs`

- [ ] **Step 1: Write the failing fail-fast test**

Create `crates/xray-transport/tests/reality_runtime_tests.rs` with this content:

```rust
use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    reality::RealityPreparedClientHello,
    reality_connector::{RealityClientHelloProvider, RealityClientHelloRequest, RealityHandshakeContext},
    DnsResolver, RealityClientConfig, RealityHandshakeContextProvider, RealityRuntimeEngine,
    RealityTlsEngine, TransportError,
};

#[derive(Debug, Default)]
struct PanickingClientHelloProvider;

impl RealityClientHelloProvider for PanickingClientHelloProvider {
    fn prepare_client_hello(
        &self,
        _request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, xray_transport::reality::RealityError> {
        panic!("unsupported fingerprint must be rejected before ClientHello provider use")
    }
}

#[derive(Debug, Default)]
struct PanickingContextProvider;

impl RealityHandshakeContextProvider for PanickingContextProvider {
    fn context(&self) -> RealityHandshakeContext {
        panic!("unsupported fingerprint must be rejected before context provider use")
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
    }
}

#[tokio::test]
async fn reality_runtime_rejects_unsupported_fingerprint_before_dependencies() {
    let engine = RealityRuntimeEngine::new(Arc::new(PanickingClientHelloProvider))
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```sh
cargo test -p xray-transport --test reality_runtime_tests reality_runtime_rejects_unsupported_fingerprint_before_dependencies
```

Expected: FAIL with unresolved imports or missing variants for `RealityRuntimeEngine`, `RealityHandshakeContextProvider`, and `TransportError::Reality`.

- [ ] **Step 3: Export typed REALITY runtime errors**

Modify `crates/xray-transport/src/lib.rs`.

Add the module and exports near the existing module declarations and exports:

```rust
pub mod reality;
pub mod reality_connector;
pub mod reality_runtime;
mod tls;

pub use dialer::TransportDialer;
pub use reality_runtime::{
    RealityHandshakeContextProvider, RealityRuntimeEngine, SystemRealityHandshakeContextProvider,
};
pub use tls::TlsConnector;
```

Add these variants to `TransportError` after `UnsupportedRealityFingerprint(String)`:

```rust
    #[error("reality handshake failed: {0}")]
    Reality(#[from] reality::RealityError),
    #[error("REALITY live TLS completion is not implemented")]
    RealityTlsCompletionUnsupported,
```

- [ ] **Step 4: Add the minimal runtime engine module**

Create `crates/xray-transport/src/reality_runtime.rs` with this content:

```rust
use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use xray_routing::Target;

use crate::{
    reality::RealityError,
    reality_connector::{
        RealityClientHelloProvider, RealityConnector, RealityHandshakeContext,
    },
    BoxedTransportStream, DnsResolver, RealityClientConfig, RealityTlsEngine, SystemDnsResolver,
    TransportError,
};

const REALITY_HANDSHAKE_VERSION: [u8; 3] = [1, 8, 0];

pub trait RealityHandshakeContextProvider: Send + Sync {
    fn context(&self) -> RealityHandshakeContext;
}

#[derive(Debug, Clone, Default)]
pub struct SystemRealityHandshakeContextProvider;

impl RealityHandshakeContextProvider for SystemRealityHandshakeContextProvider {
    fn context(&self) -> RealityHandshakeContext {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                duration.as_secs().min(u32::MAX as u64) as u32
            });

        RealityHandshakeContext {
            version: REALITY_HANDSHAKE_VERSION,
            unix_time,
        }
    }
}

#[derive(Clone)]
pub struct RealityRuntimeEngine {
    client_hello_provider: Arc<dyn RealityClientHelloProvider>,
    dns_resolver: Arc<dyn DnsResolver>,
    context_provider: Arc<dyn RealityHandshakeContextProvider>,
}

impl fmt::Debug for RealityRuntimeEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityRuntimeEngine")
            .field("client_hello_provider", &"<dyn RealityClientHelloProvider>")
            .field("dns_resolver", &"<dyn DnsResolver>")
            .field("context_provider", &"<dyn RealityHandshakeContextProvider>")
            .finish()
    }
}

impl RealityRuntimeEngine {
    pub fn new(client_hello_provider: Arc<dyn RealityClientHelloProvider>) -> Self {
        Self {
            client_hello_provider,
            dns_resolver: Arc::new(SystemDnsResolver),
            context_provider: Arc::new(SystemRealityHandshakeContextProvider),
        }
    }

    pub fn with_dns_resolver(mut self, dns_resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = dns_resolver;
        self
    }

    pub fn with_context_provider(
        mut self,
        context_provider: Arc<dyn RealityHandshakeContextProvider>,
    ) -> Self {
        self.context_provider = context_provider;
        self
    }
}

#[async_trait]
impl RealityTlsEngine for RealityRuntimeEngine {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        _target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        let connector = RealityConnector::new(config.clone());
        if !connector.is_fingerprint_supported() {
            return Err(RealityError::UnsupportedRealityFingerprint(
                config.fingerprint.clone(),
            )
            .into());
        }

        Err(TransportError::RealityTlsCompletionUnsupported)
    }
}
```

- [ ] **Step 5: Run the focused test to verify it passes**

Run:

```sh
cargo test -p xray-transport --test reality_runtime_tests reality_runtime_rejects_unsupported_fingerprint_before_dependencies
```

Expected: PASS.

- [ ] **Step 6: Run guard tests for existing REALITY boundaries**

Run:

```sh
cargo test -p xray-transport --test reality_connector_tests
cargo test -p xray-transport --test transport_tests reality
```

Expected: PASS.

- [ ] **Step 7: Commit Task 1**

Run:

```sh
git add crates/xray-transport/src/lib.rs crates/xray-transport/src/reality_runtime.rs crates/xray-transport/tests/reality_runtime_tests.rs
git commit -m "feat(transport): add gated reality runtime engine"
```

---

### Task 2: DNS, TCP, And Handshake Setup

**Files:**
- Modify: `crates/xray-transport/src/reality_runtime.rs`
- Modify: `crates/xray-transport/tests/reality_runtime_tests.rs`

- [ ] **Step 1: Replace the runtime test file with full setup coverage**

Replace `crates/xray-transport/tests/reality_runtime_tests.rs` with this content:

```rust
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::net::TcpListener;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    reality::RealityPreparedClientHello,
    reality_connector::{
        RealityClientHelloProvider, RealityClientHelloRequest, RealityHandshakeContext,
    },
    DnsResolver, RealityClientConfig, RealityHandshakeContextProvider, RealityRuntimeEngine,
    RealityTlsEngine, TransportError,
};

const CLIENTHELLO_FIXTURE_JSON: &str =
    include_str!("../../../tests/fixtures/reality/clienthello_chrome_auto.json");

#[derive(Debug, serde::Deserialize)]
struct ClientHelloFixture {
    raw_client_hello_hex: String,
    hello_random_hex: String,
    session_id_offset: usize,
    local_x25519_private_key_hex: String,
}

#[derive(Debug)]
struct RecordingClientHelloProvider {
    fixture: ClientHelloFixture,
    seen: Mutex<Vec<(String, String)>>,
}

impl RecordingClientHelloProvider {
    fn new(fixture: ClientHelloFixture) -> Self {
        Self {
            fixture,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().expect("provider seen lock").clone()
    }
}

impl RealityClientHelloProvider for RecordingClientHelloProvider {
    fn prepare_client_hello(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, xray_transport::reality::RealityError> {
        self.seen
            .lock()
            .expect("provider seen lock")
            .push((request.server_name.to_owned(), request.fingerprint.to_owned()));
        Ok(prepared_from_fixture(&self.fixture))
    }
}

#[derive(Debug, Default)]
struct PanickingClientHelloProvider;

impl RealityClientHelloProvider for PanickingClientHelloProvider {
    fn prepare_client_hello(
        &self,
        _request: RealityClientHelloRequest<'_>,
    ) -> Result<RealityPreparedClientHello, xray_transport::reality::RealityError> {
        panic!("unsupported fingerprint must be rejected before ClientHello provider use")
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
    let engine = RealityRuntimeEngine::new(Arc::new(PanickingClientHelloProvider))
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
async fn reality_runtime_prepares_handshake_and_connects_ip_before_live_tls_gate() {
    let (addr, handle) = spawn_accept_once().await;
    let provider = Arc::new(RecordingClientHelloProvider::new(clienthello_fixture()));
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
}

#[tokio::test]
async fn reality_runtime_resolves_domain_targets_before_tcp_connect() {
    let (addr, handle) = spawn_accept_once().await;
    let provider = Arc::new(RecordingClientHelloProvider::new(clienthello_fixture()));
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
}
```

- [ ] **Step 2: Run the expanded tests to verify they fail against the minimal engine**

Run:

```sh
cargo test -p xray-transport --test reality_runtime_tests
```

Expected: FAIL because the supported-config tests expect provider/context/TCP activity, while the minimal engine returns `RealityTlsCompletionUnsupported` immediately.

- [ ] **Step 3: Implement handshake preparation, DNS resolution, and TCP connect**

Modify `crates/xray-transport/src/reality_runtime.rs`.

Update the imports:

```rust
use std::{
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use tokio::net::TcpStream;
use xray_routing::{Target, TargetAddr};
```

Add this helper method inside `impl RealityRuntimeEngine` after `with_context_provider`:

```rust
    async fn resolve_socket_addr(&self, target: &Target) -> Result<SocketAddr, TransportError> {
        match &target.addr {
            TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
            TargetAddr::Domain(domain) => self.dns_resolver.resolve(domain, target.port).await,
        }
    }
```

Replace the `RealityTlsEngine` implementation with:

```rust
#[async_trait]
impl RealityTlsEngine for RealityRuntimeEngine {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        let connector = RealityConnector::new(config.clone());
        if !connector.is_fingerprint_supported() {
            return Err(RealityError::UnsupportedRealityFingerprint(
                config.fingerprint.clone(),
            )
            .into());
        }

        let context = self.context_provider.context();
        let _prepared = connector.prepare_handshake(self.client_hello_provider.as_ref(), context)?;
        let addr = self.resolve_socket_addr(target).await?;
        let _stream = TcpStream::connect(addr).await.map_err(TransportError::Tcp)?;

        Err(TransportError::RealityTlsCompletionUnsupported)
    }
}
```

- [ ] **Step 4: Run the runtime tests to verify they pass**

Run:

```sh
cargo test -p xray-transport --test reality_runtime_tests
```

Expected: PASS with 3 tests.

- [ ] **Step 5: Run transport guard tests**

Run:

```sh
cargo test -p xray-transport --test transport_tests reality
cargo test -p xray-transport --test reality_connector_tests
cargo test -p xray-transport --test reality_clienthello_tests
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

Run:

```sh
git add crates/xray-transport/src/reality_runtime.rs crates/xray-transport/tests/reality_runtime_tests.rs
git commit -m "feat(transport): prepare reality runtime handshake path"
```

---

### Task 3: Status And Verification Docs

**Files:**
- Modify: `README.md`
- Modify: `docs/verification.md`

- [ ] **Step 1: Update README runtime status**

In `README.md`, replace the current runtime status paragraph with:

```markdown
Current runtime status: raw TCP VLESS and plain rustls-backed VLESS over TLS are executable for local/test traffic and covered by end-to-end Rust tests with fake VLESS servers. VLESS outbound servers may be configured as IP addresses or, when a resolver is available, domains. REALITY configs can be selected into the transport boundary, prepared from a validated ClientHello provider, and driven through an explicitly injected runtime engine up to DNS/TCP connection setup. `xtls-rprx-vision` has a bounded Tokio stream wrapper, and `VLESS + REALITY + Vision` can be exercised through an explicitly injected REALITY protected-stream engine. The default system dialer still rejects live REALITY networking until a real Chrome/uTLS-compatible TLS completion path exists. Full Xray DNS behavior and local Xray-core interoperability run remain future work.
```

- [ ] **Step 2: Update verification docs**

In `docs/verification.md`, update the Vision runtime boundary command block to include the runtime engine test:

```sh
cargo test -p xray-proxy --test vision_stream_tests
cargo test -p xray-transport --test transport_tests reality
cargo test -p xray-transport --test reality_runtime_tests
cargo test -p xray-core-rs --test runtime_data_path_tests vision
cargo test -p xray-core-rs outbound::tests
```

Replace the explanatory paragraph immediately after that block with:

```markdown
These verify that `VisionStream` pads outbound bytes, unpads inbound bytes, the default system dialer still rejects live REALITY networking, an explicitly injected REALITY protected-stream engine can carry runtime bytes, the gated `RealityRuntimeEngine` can prepare a REALITY handshake and drive DNS/TCP setup before stopping at the live TLS completion boundary, `VLESS + REALITY + xtls-rprx-vision` reaches the protected transport boundary, and raw TCP/TLS Vision flows are still rejected. They do not validate a real Chrome/uTLS-compatible REALITY TLS completion path or local Xray-core interoperability yet.
```

In the REALITY Primitive Oracle command block, add:

```sh
cargo test -p xray-transport --test reality_runtime_tests
```

Replace the paragraph below that block with:

```markdown
These checks validate deterministic Xray-core-compatible session-id sealing, ClientHello patching, certificate binding primitives, a uTLS Chrome ClientHello fixture that can be validated as `RealityPreparedClientHello` metadata, the non-networked provider-to-handshake boundary in `RealityConnector`, and the gated runtime setup path in `RealityRuntimeEngine`. They do not validate the live REALITY TLS completion path, a production Chrome/uTLS provider, or local Xray-core server interoperability.
```

- [ ] **Step 3: Run docs diff checks**

Run:

```sh
git diff --check
```

Expected: PASS with no output.

- [ ] **Step 4: Commit Task 3**

Run:

```sh
git add README.md docs/verification.md
git commit -m "docs: update reality runtime engine status"
```

---

### Task 4: Full Verification And Review

**Files:**
- No code edits.

- [ ] **Step 1: Run formatting**

Run:

```sh
cargo fmt --all -- --check
```

Expected: PASS.

- [ ] **Step 2: Run clippy**

Run:

```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: PASS.

- [ ] **Step 3: Run the full Rust test suite**

Run:

```sh
cargo test --workspace --all-targets
```

Expected: PASS. In this sandbox, run with loopback permission because existing tests bind local sockets.

- [ ] **Step 4: Run REALITY oracle checks**

Run:

```sh
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

Expected: PASS with exit code 0.

- [ ] **Step 5: Confirm compat shell remains gated**

Run:

```sh
sed -n '1,20p' tests/compat/vless_reality_vision.rs
```

Expected: the test remains marked with `#[ignore = "requires local Go toolchain and completed REALITY network connector"]`.

- [ ] **Step 6: Request code review**

Dispatch a reviewer with:

- Base SHA: `1976016`
- Head SHA: current `HEAD`
- Focus: `RealityRuntimeEngine` ordering, dependency injection, error typing, default REALITY gate, docs not overclaiming live REALITY support, mobile/resource constraints.

Fix any Critical or Important findings before finishing the branch.
