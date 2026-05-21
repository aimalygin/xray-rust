# REALITY Stateful Provider Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a stateful, one-shot REALITY TLS session boundary and move `RealityRuntimeEngine` live TLS completion behind that boundary.

**Architecture:** `RealityConnector` remains the owner of REALITY ClientHello validation and session-id patching. `RealityRuntimeEngine` switches from a stateless `RealityClientHelloProvider` to a `RealityTlsSessionProvider` that creates one consumed session per connection. The first implementation keeps live TLS gated, but the gate comes from the scripted session so future pure Rust or dev-only uTLS-backed providers can plug in without changing VLESS, Vision, routing, or config code.

**Tech Stack:** Rust, Tokio, `async-trait`, existing `xray-transport` REALITY primitives, serde JSON fixture loading, Go oracle tools for compatibility fixture verification.

---

## File Structure

- Modify `crates/xray-transport/src/reality_connector.rs`
  - Add `RealityConnector::prepare_handshake_with_client_hello`.
  - Keep `RealityConnector::prepare_handshake` as a provider-based helper that delegates to the new method.
  - Add `RealityTlsSessionProvider` and `RealityTlsSession`.
- Modify `crates/xray-transport/src/reality_runtime.rs`
  - Replace `Arc<dyn RealityClientHelloProvider>` with `Arc<dyn RealityTlsSessionProvider>`.
  - Create a one-shot session, prepare the REALITY handshake, connect TCP, and call `session.complete`.
- Modify `crates/xray-transport/src/lib.rs`
  - Re-export `RealityTlsSession` and `RealityTlsSessionProvider`.
- Modify `crates/xray-transport/tests/reality_connector_tests.rs`
  - Add tests for the prepared-ClientHello connector method and validation path.
- Modify `crates/xray-transport/tests/reality_runtime_tests.rs`
  - Replace provider fixtures with stateful session fixtures.
  - Assert fail-fast ordering, DNS/TCP behavior, and completion handoff.
- Modify `README.md` and `docs/verification.md`
  - Update current status text to describe the stateful boundary without claiming live REALITY support.

---

### Task 1: Add Prepared ClientHello Connector API

**Files:**
- Modify: `crates/xray-transport/tests/reality_connector_tests.rs`
- Modify: `crates/xray-transport/src/reality_connector.rs`

- [ ] **Step 1: Write failing connector tests**

Add these tests in `crates/xray-transport/tests/reality_connector_tests.rs` after `reality_connector_prepares_handshake_from_validated_clienthello_provider`:

```rust
#[test]
fn reality_connector_prepares_handshake_from_prepared_clienthello() {
    let fixture = clienthello_fixture();
    let original_client_hello = decode_hex(&fixture.raw_client_hello_hex);
    let session_id_offset = fixture.session_id_offset;
    let prepared_client_hello = prepared_from_fixture(&fixture);
    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));

    let prepared = connector
        .prepare_handshake_with_client_hello(prepared_client_hello, handshake_context())
        .expect("valid prepared ClientHello should prepare REALITY handshake");

    assert_ne!(prepared.auth_key, [0u8; 32]);
    assert_ne!(prepared.session_id, [0u8; 32]);
    assert_eq!(
        &prepared.patched_client_hello[session_id_offset..session_id_offset + 32],
        &prepared.session_id[..]
    );
    assert_ne!(
        &prepared.patched_client_hello[session_id_offset..session_id_offset + 32],
        &original_client_hello[session_id_offset..session_id_offset + 32]
    );
}

#[test]
fn reality_connector_rejects_invalid_prepared_clienthello_metadata() {
    let fixture = clienthello_fixture();
    let mut prepared_client_hello = prepared_from_fixture(&fixture);
    prepared_client_hello.hello_random[0] ^= 0xff;
    let connector = RealityConnector::new(reality_config_with_short_id(vec![2, 3, 4, 5]));

    let err = connector
        .prepare_handshake_with_client_hello(prepared_client_hello, handshake_context())
        .unwrap_err();

    assert_eq!(
        err,
        xray_transport::reality::RealityError::ClientHelloRandomMismatch
    );
}
```

- [ ] **Step 2: Run connector tests and verify the new method is missing**

Run:

```sh
cargo test -p xray-transport --test reality_connector_tests --locked reality_connector_prepares_handshake_from_prepared_clienthello
```

Expected: FAIL with an error containing:

```text
no method named `prepare_handshake_with_client_hello`
```

- [ ] **Step 3: Implement the connector method and delegate the old provider path**

In `crates/xray-transport/src/reality_connector.rs`, replace the existing `prepare_handshake` method in `impl RealityConnector` with this block:

```rust
    pub fn prepare_handshake(
        &self,
        provider: &dyn RealityClientHelloProvider,
        context: RealityHandshakeContext,
    ) -> Result<RealityPreparedHandshake, RealityError> {
        if !self.is_fingerprint_supported() {
            return Err(RealityError::UnsupportedRealityFingerprint(
                self.config.fingerprint.clone(),
            ));
        }

        let prepared_client_hello = provider.prepare_client_hello(RealityClientHelloRequest {
            server_name: &self.config.server_name,
            fingerprint: &self.config.fingerprint,
        })?;

        self.prepare_handshake_with_client_hello(prepared_client_hello, context)
    }

    pub fn prepare_handshake_with_client_hello(
        &self,
        prepared_client_hello: RealityPreparedClientHello,
        context: RealityHandshakeContext,
    ) -> Result<RealityPreparedHandshake, RealityError> {
        if !self.is_fingerprint_supported() {
            return Err(RealityError::UnsupportedRealityFingerprint(
                self.config.fingerprint.clone(),
            ));
        }

        validate_reality_client_hello_metadata(&prepared_client_hello)?;

        prepare_reality_handshake(RealityHandshakeInput {
            version: context.version,
            unix_time: context.unix_time,
            short_id: self.config.short_id.clone(),
            server_public_key: self.config.public_key,
            prepared_client_hello,
        })
    }
```

- [ ] **Step 4: Run connector tests and verify they pass**

Run:

```sh
cargo test -p xray-transport --test reality_connector_tests --locked
```

Expected: PASS. The output should include:

```text
test result: ok.
```

- [ ] **Step 5: Commit connector API**

Run:

```sh
git add crates/xray-transport/src/reality_connector.rs crates/xray-transport/tests/reality_connector_tests.rs
git commit -m "feat(transport): add prepared reality clienthello handshake API"
```

---

### Task 2: Write Stateful Runtime Boundary Tests

**Files:**
- Modify: `crates/xray-transport/tests/reality_runtime_tests.rs`

- [ ] **Step 1: Update runtime test imports**

Replace the top import block in `crates/xray-transport/tests/reality_runtime_tests.rs` with:

```rust
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    reality::{RealityPreparedClientHello, RealityPreparedHandshake},
    reality_connector::{
        RealityClientHelloRequest, RealityHandshakeContext, RealityTlsSession,
        RealityTlsSessionProvider,
    },
    DnsResolver, RealityClientConfig, RealityHandshakeContextProvider, RealityRuntimeEngine,
    RealityTlsEngine, TransportError,
};
```

- [ ] **Step 2: Replace stateless provider fixtures with session fixtures**

In `crates/xray-transport/tests/reality_runtime_tests.rs`, change the fixture derive:

```rust
#[derive(Debug, Clone, serde::Deserialize)]
struct ClientHelloFixture {
    raw_client_hello_hex: String,
    hello_random_hex: String,
    session_id_offset: usize,
    local_x25519_private_key_hex: String,
}
```

Then replace `RecordingClientHelloProvider` and `PanickingClientHelloProvider` with this code:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletionRecord {
    original_session_id: Vec<u8>,
    patched_session_id: Vec<u8>,
    session_id: [u8; 32],
    auth_key: [u8; 32],
}

#[derive(Debug)]
struct RecordingSessionProvider {
    fixture: ClientHelloFixture,
    seen: Mutex<Vec<(String, String)>>,
    completions: Arc<Mutex<Vec<CompletionRecord>>>,
}

impl RecordingSessionProvider {
    fn new(fixture: ClientHelloFixture) -> Self {
        Self {
            fixture,
            seen: Mutex::new(Vec::new()),
            completions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().expect("provider seen lock").clone()
    }

    fn completions(&self) -> Vec<CompletionRecord> {
        self.completions
            .lock()
            .expect("completion records lock")
            .clone()
    }
}

impl RealityTlsSessionProvider for RecordingSessionProvider {
    fn create_session(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<Box<dyn RealityTlsSession>, xray_transport::reality::RealityError> {
        self.seen.lock().expect("provider seen lock").push((
            request.server_name.to_owned(),
            request.fingerprint.to_owned(),
        ));

        let raw_client_hello = decode_hex(&self.fixture.raw_client_hello_hex);
        let original_session_id =
            raw_client_hello[self.fixture.session_id_offset..self.fixture.session_id_offset + 32]
                .to_vec();

        Ok(Box::new(RecordingRealityTlsSession {
            prepared_client_hello: Mutex::new(Some(prepared_from_fixture(&self.fixture))),
            session_id_offset: self.fixture.session_id_offset,
            original_session_id,
            completions: self.completions.clone(),
        }))
    }
}

#[derive(Debug)]
struct RecordingRealityTlsSession {
    prepared_client_hello: Mutex<Option<RealityPreparedClientHello>>,
    session_id_offset: usize,
    original_session_id: Vec<u8>,
    completions: Arc<Mutex<Vec<CompletionRecord>>>,
}

#[async_trait]
impl RealityTlsSession for RecordingRealityTlsSession {
    fn prepared_client_hello(
        &self,
    ) -> Result<RealityPreparedClientHello, xray_transport::reality::RealityError> {
        Ok(self
            .prepared_client_hello
            .lock()
            .expect("prepared ClientHello lock")
            .take()
            .expect("prepared ClientHello should be consumed once"))
    }

    async fn complete(
        self: Box<Self>,
        _tcp_stream: TcpStream,
        prepared: RealityPreparedHandshake,
    ) -> Result<xray_transport::BoxedTransportStream, TransportError> {
        let patched_session_id = prepared.patched_client_hello
            [self.session_id_offset..self.session_id_offset + 32]
            .to_vec();

        self.completions
            .lock()
            .expect("completion records lock")
            .push(CompletionRecord {
                original_session_id: self.original_session_id.clone(),
                patched_session_id,
                session_id: prepared.session_id,
                auth_key: prepared.auth_key,
            });

        Err(TransportError::RealityTlsCompletionUnsupported)
    }
}

#[derive(Debug, Default)]
struct PanickingSessionProvider;

impl RealityTlsSessionProvider for PanickingSessionProvider {
    fn create_session(
        &self,
        _request: RealityClientHelloRequest<'_>,
    ) -> Result<Box<dyn RealityTlsSession>, xray_transport::reality::RealityError> {
        panic!("unsupported fingerprint must be rejected before REALITY TLS session creation")
    }
}
```

- [ ] **Step 3: Update existing runtime tests for session providers**

In `reality_runtime_rejects_unsupported_fingerprint_before_dependencies`, replace:

```rust
    let engine = RealityRuntimeEngine::new(Arc::new(PanickingClientHelloProvider))
```

with:

```rust
    let engine = RealityRuntimeEngine::new(Arc::new(PanickingSessionProvider))
```

In both supported runtime tests, replace:

```rust
    let provider = Arc::new(RecordingClientHelloProvider::new(clienthello_fixture()));
```

with:

```rust
    let provider = Arc::new(RecordingSessionProvider::new(clienthello_fixture()));
```

After the existing provider/context assertions in `reality_runtime_prepares_handshake_and_connects_ip_before_live_tls_gate`, add:

```rust
    let completions = provider.completions();
    assert_eq!(completions.len(), 1);
    assert_eq!(
        completions[0].patched_session_id.as_slice(),
        &completions[0].session_id[..]
    );
    assert_ne!(
        completions[0].patched_session_id,
        completions[0].original_session_id
    );
    assert_ne!(completions[0].auth_key, [0u8; 32]);
```

After the existing provider/context assertions in `reality_runtime_resolves_domain_targets_before_tcp_connect`, add:

```rust
    let completions = provider.completions();
    assert_eq!(completions.len(), 1);
    assert_eq!(
        completions[0].patched_session_id.as_slice(),
        &completions[0].session_id[..]
    );
```

- [ ] **Step 4: Add invalid metadata runtime test**

Add this test after `reality_runtime_rejects_unsupported_fingerprint_before_dependencies`:

```rust
#[tokio::test]
async fn reality_runtime_rejects_invalid_session_clienthello_before_dns_or_tcp() {
    let mut fixture = clienthello_fixture();
    fixture.hello_random_hex.replace_range(0..2, "ff");
    let provider = Arc::new(RecordingSessionProvider::new(fixture));
    let context = Arc::new(FixedContextProvider::new(fixed_context()));
    let engine = RealityRuntimeEngine::new(provider.clone())
        .with_dns_resolver(Arc::new(PanickingDnsResolver))
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
        Err(TransportError::Reality(
            xray_transport::reality::RealityError::ClientHelloRandomMismatch
        ))
    ));
    assert_eq!(
        provider.seen(),
        vec![("www.example.com".to_owned(), "chrome".to_owned())]
    );
    assert_eq!(provider.completions(), Vec::<CompletionRecord>::new());
    assert_eq!(context.calls(), 1);
}
```

- [ ] **Step 5: Run runtime tests and verify traits are missing**

Run:

```sh
cargo test -p xray-transport --test reality_runtime_tests --locked
```

Expected: FAIL with errors containing:

```text
unresolved imports `xray_transport::reality_connector::RealityTlsSession`
unresolved imports `xray_transport::reality_connector::RealityTlsSessionProvider`
```

---

### Task 3: Implement Stateful Session Traits And Runtime Flow

**Files:**
- Modify: `crates/xray-transport/src/reality_connector.rs`
- Modify: `crates/xray-transport/src/reality_runtime.rs`
- Modify: `crates/xray-transport/src/lib.rs`
- Modify: `crates/xray-transport/tests/reality_runtime_tests.rs`

- [ ] **Step 1: Add session traits**

In `crates/xray-transport/src/reality_connector.rs`, add these imports near the top:

```rust
use async_trait::async_trait;
use tokio::net::TcpStream;
```

Extend the `use crate::{ ... }` import so it includes `BoxedTransportStream` and `TransportError`:

```rust
use crate::{
    reality::{
        prepare_reality_handshake, validate_reality_client_hello_metadata, RealityError,
        RealityHandshakeInput, RealityPreparedClientHello, RealityPreparedHandshake,
    },
    BoxedTransportStream, RealityClientConfig, TransportError,
};
```

Add these traits immediately after `RealityClientHelloProvider`:

```rust
pub trait RealityTlsSessionProvider: Send + Sync {
    fn create_session(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<Box<dyn RealityTlsSession>, RealityError>;
}

#[async_trait]
pub trait RealityTlsSession: Send {
    fn prepared_client_hello(&self) -> Result<RealityPreparedClientHello, RealityError>;

    async fn complete(
        self: Box<Self>,
        tcp_stream: TcpStream,
        prepared: RealityPreparedHandshake,
    ) -> Result<BoxedTransportStream, TransportError>;
}
```

- [ ] **Step 2: Re-export session traits**

In `crates/xray-transport/src/lib.rs`, add this public re-export below `pub use dialer::TransportDialer;`:

```rust
pub use reality_connector::{RealityTlsSession, RealityTlsSessionProvider};
```

- [ ] **Step 3: Convert `RealityRuntimeEngine` to the session provider**

In `crates/xray-transport/src/reality_runtime.rs`, replace the connector import:

```rust
    reality_connector::{RealityClientHelloProvider, RealityConnector, RealityHandshakeContext},
```

with:

```rust
    reality_connector::{
        RealityClientHelloRequest, RealityConnector, RealityHandshakeContext,
        RealityTlsSessionProvider,
    },
```

Replace the struct field:

```rust
    client_hello_provider: Arc<dyn RealityClientHelloProvider>,
```

with:

```rust
    session_provider: Arc<dyn RealityTlsSessionProvider>,
```

Replace the `Debug` field:

```rust
            .field("client_hello_provider", &"<dyn RealityClientHelloProvider>")
```

with:

```rust
            .field("session_provider", &"<dyn RealityTlsSessionProvider>")
```

Replace the constructor:

```rust
    pub fn new(client_hello_provider: Arc<dyn RealityClientHelloProvider>) -> Self {
        Self {
            client_hello_provider,
            dns_resolver: Arc::new(SystemDnsResolver),
            context_provider: Arc::new(SystemRealityHandshakeContextProvider),
        }
    }
```

with:

```rust
    pub fn new(session_provider: Arc<dyn RealityTlsSessionProvider>) -> Self {
        Self {
            session_provider,
            dns_resolver: Arc::new(SystemDnsResolver),
            context_provider: Arc::new(SystemRealityHandshakeContextProvider),
        }
    }
```

Replace the supported branch in `connect`:

```rust
        let context = self.context_provider.context();
        let _prepared =
            connector.prepare_handshake(self.client_hello_provider.as_ref(), context)?;
        let addr = self.resolve_socket_addr(target).await?;
        let _stream = TcpStream::connect(addr)
            .await
            .map_err(TransportError::Tcp)?;

        Err(TransportError::RealityTlsCompletionUnsupported)
```

with:

```rust
        let session = self
            .session_provider
            .create_session(RealityClientHelloRequest {
                server_name: &config.server_name,
                fingerprint: &config.fingerprint,
            })?;
        let prepared_client_hello = session.prepared_client_hello()?;
        let context = self.context_provider.context();
        let prepared =
            connector.prepare_handshake_with_client_hello(prepared_client_hello, context)?;
        let addr = self.resolve_socket_addr(target).await?;
        let stream = TcpStream::connect(addr)
            .await
            .map_err(TransportError::Tcp)?;

        session.complete(stream, prepared).await
```

- [ ] **Step 4: Run focused transport tests**

Run:

```sh
cargo test -p xray-transport --test reality_connector_tests --locked
cargo test -p xray-transport --test reality_runtime_tests --locked
cargo test -p xray-transport --test transport_tests --locked
```

Expected: PASS for all three commands.

- [ ] **Step 5: Commit stateful runtime boundary**

Run:

```sh
git add crates/xray-transport/src/reality_connector.rs crates/xray-transport/src/reality_runtime.rs crates/xray-transport/src/lib.rs crates/xray-transport/tests/reality_runtime_tests.rs
git commit -m "feat(transport): add stateful reality tls session boundary"
```

---

### Task 4: Update Current Status Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/verification.md`

- [ ] **Step 1: Update README runtime status**

In `README.md`, replace this sentence fragment in the current runtime status paragraph:

```text
REALITY configs can be selected into the transport boundary, prepared from a validated ClientHello provider, and driven through an explicitly injected runtime engine up to DNS/TCP connection setup.
```

with:

```text
REALITY configs can be selected into the transport boundary, prepared through a stateful one-shot REALITY TLS session boundary, and driven through an explicitly injected runtime engine up to DNS/TCP connection setup and gated TLS completion handoff.
```

- [ ] **Step 2: Update verification matrix wording**

In `docs/verification.md`, replace:

```text
the gated `RealityRuntimeEngine` can prepare a REALITY handshake and drive DNS/TCP setup before stopping at the live TLS completion boundary
```

with:

```text
the gated `RealityRuntimeEngine` can prepare a REALITY handshake, drive DNS/TCP setup, and hand completion to a one-shot REALITY TLS session before stopping at the live TLS gate
```

Also replace:

```text
the non-networked provider-to-handshake boundary in `RealityConnector`, and the gated runtime setup path in `RealityRuntimeEngine`
```

with:

```text
the non-networked provider-to-handshake boundary in `RealityConnector`, the prepared-ClientHello connector path, and the gated stateful runtime setup path in `RealityRuntimeEngine`
```

- [ ] **Step 3: Verify docs mention no live REALITY support**

Run:

```sh
rg -n "Full Xray DNS behavior and local Xray-core interoperability run remain future work|do not validate the live REALITY TLS completion path|does not validate a real Chrome/uTLS-compatible REALITY TLS completion path" README.md docs/verification.md
```

Expected: PASS with matches in `README.md` and `docs/verification.md`.

- [ ] **Step 4: Commit docs**

Run:

```sh
git add README.md docs/verification.md
git commit -m "docs: update reality stateful runtime status"
```

---

### Task 5: Full Verification And Final Review

**Files:**
- Inspect: `crates/xray-transport/src/reality_connector.rs`
- Inspect: `crates/xray-transport/src/reality_runtime.rs`
- Inspect: `crates/xray-transport/tests/reality_runtime_tests.rs`
- Inspect: `README.md`
- Inspect: `docs/verification.md`

- [ ] **Step 1: Format check**

Run:

```sh
cargo fmt --all -- --check
```

Expected: PASS with no diff output.

- [ ] **Step 2: Oracle fixture verification**

Run:

```sh
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

Expected: both commands PASS and print no compatibility mismatch.

- [ ] **Step 3: Clippy**

Run:

```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: PASS with no warnings.

- [ ] **Step 4: Full Rust test suite**

Run:

```sh
cargo test --workspace --all-targets
```

Expected: PASS. The transport runtime tests should include the stateful session completion assertions.

- [ ] **Step 5: Review staged branch diff**

Run:

```sh
git log --oneline main..HEAD
git diff --stat main..HEAD
git diff main..HEAD -- crates/xray-transport/src/reality_connector.rs crates/xray-transport/src/reality_runtime.rs crates/xray-transport/tests/reality_runtime_tests.rs README.md docs/verification.md
```

Expected: the branch contains the spec commit, the plan commit, connector API commit, runtime boundary commit, and docs commit. The code diff should show no default enablement of REALITY in `TransportDialer::system()` and no live TLS support claim.

- [ ] **Step 6: Commit verification notes if docs changed during review**

If Task 5 review changes `README.md`, `docs/verification.md`, or this plan, run:

```sh
git add README.md docs/verification.md docs/superpowers/plans/2026-05-21-reality-stateful-provider-boundary.md
git commit -m "docs: refine reality stateful boundary notes"
```

Expected: either a small docs commit is created, or `git status --short` remains clean.
