# REALITY Runtime Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an injectable REALITY protected-stream boundary so `VLESS + REALITY + xtls-rprx-vision` can be exercised through the Rust runtime without enabling default live REALITY networking.

**Architecture:** `xray-transport` gains a `RealityTlsEngine` trait and `TransportDialer` routes `ConnectorConfig::Reality` only when such an engine is explicitly injected. `xray-core-rs` keeps VLESS header writing and Vision wrapping unchanged, but gains tests proving the injected REALITY stream receives the header first and Vision-framed payload afterward. The default system dialer still rejects REALITY configs.

**Tech Stack:** Rust 2021, Tokio `AsyncRead`/`AsyncWrite`, `async-trait`, existing `BoxedTransportStream`, existing `VisionStream`, existing transport/core runtime tests.

---

## Scope Check

This plan implements one transport/runtime boundary slice. It does not implement a real Chrome/uTLS-compatible TLS engine, does not launch local Xray-core, does not un-ignore the compatibility shell, and does not route default production REALITY traffic.

## File Structure

- Modify `crates/xray-transport/src/lib.rs`: define and export the object-safe `RealityTlsEngine` trait.
- Modify `crates/xray-transport/src/dialer.rs`: store an optional injected REALITY engine and route REALITY configs to it when present.
- Modify `crates/xray-transport/tests/transport_tests.rs`: add a recording fake REALITY engine and transport-level injection tests.
- Modify `crates/xray-core-rs/src/outbound.rs`: add core tests proving injected REALITY + Vision reaches the protected stream, and keep the default REALITY gate test.
- Modify `README.md` and `docs/verification.md`: document the new injectable runtime boundary while keeping live REALITY interop future work.

## Task 1: Add Failing Runtime Boundary Tests

**Files:**
- Modify: `crates/xray-transport/tests/transport_tests.rs`
- Modify: `crates/xray-core-rs/src/outbound.rs`

- [ ] **Step 1: Add transport fake-engine tests**

In `crates/xray-transport/tests/transport_tests.rs`, change the imports at the top of `mod transport_tests` from:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
```

to:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
```

Add these imports after the existing `use std::sync...` line:

```rust
use async_trait::async_trait;
```

Update the `xray_transport` import list so it includes `RealityTlsEngine`:

```rust
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, RealityClientConfig, RealityTlsEngine, TcpConnector,
    TlsClientConfig, TlsConnector, TransportConnector, TransportDialer, TransportError,
};
```

Add this fake engine and helper after `assert_boxed_transport_stream`:

```rust
#[derive(Debug)]
struct RecordingRealityEngine {
    stream: Mutex<Option<tokio::io::DuplexStream>>,
    seen: Mutex<Option<(RealityClientConfig, Target)>>,
}

impl RecordingRealityEngine {
    fn new(stream: tokio::io::DuplexStream) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            seen: Mutex::new(None),
        }
    }

    fn seen(&self) -> Option<(RealityClientConfig, Target)> {
        self.seen.lock().expect("seen lock").clone()
    }
}

#[async_trait]
impl RealityTlsEngine for RecordingRealityEngine {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        *self.seen.lock().expect("seen lock") = Some((config.clone(), target.clone()));
        let stream = self
            .stream
            .lock()
            .expect("stream lock")
            .take()
            .expect("fake reality stream should be used once");

        Ok(Box::new(stream))
    }
}

fn reality_test_config() -> RealityClientConfig {
    RealityClientConfig {
        server_name: "www.example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [1; 32],
        short_id: vec![2, 3, 4, 5],
        spider_x: "/".to_owned(),
    }
}
```

Replace the repeated inline REALITY config in `transport_dialer_rejects_reality_configs_without_plaintext_downgrade` with:

```rust
let config = ConnectorConfig::Reality(reality_test_config());
```

Add this test after `transport_dialer_rejects_reality_configs_without_plaintext_downgrade`:

```rust
#[tokio::test]
async fn transport_dialer_routes_reality_configs_to_injected_engine() {
    let (client_config, _) = tls_test_configs();
    let (client, mut server) = tokio::io::duplex(1024);
    let engine = Arc::new(RecordingRealityEngine::new(client));
    let dialer = TransportDialer::with_tls_connector(TlsConnector::with_client_config(
        client_config,
    ))
    .with_reality_engine(engine.clone());
    let target = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        443,
        Network::Tcp,
    );
    let reality_config = reality_test_config();
    let config = ConnectorConfig::Reality(reality_config.clone());

    let mut stream = dialer
        .connect(&config, &target)
        .await
        .expect("dial injected REALITY engine");
    stream.write_all(b"ping").await.expect("write ping");
    stream.flush().await.expect("flush ping");

    let mut received = [0u8; 4];
    server
        .read_exact(&mut received)
        .await
        .expect("read protected stream bytes");
    assert_eq!(&received, b"ping");

    let (seen_config, seen_target) = engine.seen().expect("engine saw config and target");
    assert_eq!(seen_config, reality_config);
    assert_eq!(seen_target.addr, target.addr);
    assert_eq!(seen_target.port, target.port);
    assert_eq!(seen_target.network, target.network);
}
```

The existing `tcp_connector_rejects_reality_config_without_plaintext_downgrade` test should keep using an inline `RealityClientConfig` or `reality_test_config()` and should still expect `UnsupportedConnectorConfig("reality")`.

- [ ] **Step 2: Add core injected REALITY + Vision test**

In `crates/xray-core-rs/src/outbound.rs`, update the test module imports from:

```rust
use std::net::{IpAddr, Ipv4Addr};

use uuid::Uuid;
```

to:

```rust
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use xray_proxy::vless::{unpad_vision_block, VisionCommand};
use xray_transport::{RealityTlsEngine, TransportError};
```

Add this fake engine inside the test module after `use super::*;`:

```rust
#[derive(Debug)]
struct DuplexRealityEngine {
    stream: Mutex<Option<tokio::io::DuplexStream>>,
    seen: Mutex<Option<(RealityClientConfig, Target)>>,
}

impl DuplexRealityEngine {
    fn new(stream: tokio::io::DuplexStream) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            seen: Mutex::new(None),
        }
    }

    fn seen(&self) -> Option<(RealityClientConfig, Target)> {
        self.seen.lock().expect("seen lock").clone()
    }
}

#[async_trait]
impl RealityTlsEngine for DuplexRealityEngine {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        *self.seen.lock().expect("seen lock") = Some((config.clone(), target.clone()));
        let stream = self
            .stream
            .lock()
            .expect("stream lock")
            .take()
            .expect("fake REALITY stream should be consumed once");

        Ok(Box::new(stream))
    }
}
```

Rename the existing test:

```rust
async fn open_vless_tcp_stream_reaches_reality_transport_gate_for_vision_flow()
```

to:

```rust
async fn open_vless_tcp_stream_keeps_default_reality_transport_gate_for_vision_flow()
```

Keep its body unchanged; it should still prove the default system dialer rejects REALITY.

Add this test after the renamed default-gate test:

```rust
#[tokio::test]
async fn open_vless_tcp_stream_wraps_injected_reality_stream_with_vision() {
    let reality_config = RealityClientConfig {
        server_name: "example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [7; 32],
        short_id: vec![1, 2, 3, 4],
        spider_x: "/".to_owned(),
    };
    let outbound = VlessTcpOutbound {
        server: Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            443,
            RoutingNetwork::Tcp,
        ),
        user: VlessUser {
            id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
            encryption: "none".to_owned(),
            flow: Some(VISION_FLOW.to_owned()),
        },
        transport: ConnectorConfig::Reality(reality_config.clone()),
    };
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
        RoutingNetwork::Tcp,
    );
    let (client, mut protected_side) = tokio::io::duplex(4096);
    let engine = Arc::new(DuplexRealityEngine::new(client));
    let transport_dialer = TransportDialer::system()
        .unwrap()
        .with_reality_engine(engine.clone());

    let mut stream = open_vless_tcp_stream_with_resolver_and_dialer(
        &outbound,
        &target,
        &SystemDnsResolver,
        &transport_dialer,
    )
    .await
    .expect("open VLESS over injected REALITY stream");

    let expected_header = encode_request_header(&VlessRequest {
        user_id: outbound.user.id,
        command: VlessCommand::Tcp,
        target: target.clone(),
        flow: outbound.user.flow.clone(),
    })
    .unwrap();
    let mut received_header = vec![0; expected_header.len()];
    protected_side
        .read_exact(&mut received_header)
        .await
        .expect("read VLESS header from protected stream");
    assert_eq!(received_header, expected_header);

    stream.write_all(b"vision payload").await.unwrap();
    stream.flush().await.unwrap();

    let mut padded = vec![0; 16 + 5 + "vision payload".len()];
    protected_side
        .read_exact(&mut padded)
        .await
        .expect("read first Vision block");
    let unpadded = unpad_vision_block(&padded, outbound.user.id.as_bytes()).unwrap();
    assert_eq!(unpadded.command, VisionCommand::Continue);
    assert_eq!(&unpadded.payload[..], b"vision payload");

    let (seen_config, seen_target) = engine.seen().expect("engine saw config and target");
    assert_eq!(seen_config, reality_config);
    assert_eq!(seen_target.addr, outbound.server.addr);
    assert_eq!(seen_target.port, outbound.server.port);
    assert_eq!(seen_target.network, outbound.server.network);
}
```

- [ ] **Step 3: Run RED checks**

Run:

```sh
cargo test -p xray-transport --test transport_tests reality
cargo test -p xray-core-rs outbound::tests
```

Expected: compile failure mentioning missing `RealityTlsEngine` and missing `TransportDialer::with_reality_engine`. This proves the tests are exercising the new boundary, not existing behavior.

## Task 2: Implement Injectable REALITY Engine Boundary

**Files:**
- Modify: `crates/xray-transport/src/lib.rs`
- Modify: `crates/xray-transport/src/dialer.rs`
- Test: `crates/xray-transport/tests/transport_tests.rs`
- Test: `crates/xray-core-rs/src/outbound.rs`

- [ ] **Step 1: Add the public trait**

In `crates/xray-transport/src/lib.rs`, add this trait after `pub type BoxedTransportStream = Box<dyn TransportStream>;`:

```rust
#[async_trait]
pub trait RealityTlsEngine: Send + Sync {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError>;
}
```

- [ ] **Step 2: Update `TransportDialer` storage and constructors**

Replace `crates/xray-transport/src/dialer.rs` with this structure:

```rust
use std::{fmt, sync::Arc};

use crate::{
    BoxedTransportStream, ConnectorConfig, RealityTlsEngine, TcpConnector, TlsConnector,
    TransportConnector, TransportError,
};
use xray_routing::Target;

#[derive(Clone)]
pub struct TransportDialer {
    tls: TlsConnector,
    reality: Option<Arc<dyn RealityTlsEngine>>,
}

impl fmt::Debug for TransportDialer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportDialer")
            .field("tls", &self.tls)
            .field("reality_engine", &self.reality.is_some())
            .finish()
    }
}

impl TransportDialer {
    pub fn system() -> Result<Self, TransportError> {
        Ok(Self {
            tls: TlsConnector::system()?,
            reality: None,
        })
    }

    pub fn with_tls_connector(tls: TlsConnector) -> Self {
        Self { tls, reality: None }
    }

    pub fn with_reality_engine(mut self, reality: Arc<dyn RealityTlsEngine>) -> Self {
        self.reality = Some(reality);
        self
    }

    pub async fn connect(
        &self,
        config: &ConnectorConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError> {
        match config {
            ConnectorConfig::Tcp => {
                TcpConnector::new(ConnectorConfig::Tcp)
                    .connect(target)
                    .await
            }
            ConnectorConfig::Tls(tls_config) => self.tls.connect(target, tls_config).await,
            ConnectorConfig::Reality(reality_config) => match &self.reality {
                Some(reality) => reality.connect(reality_config, target).await,
                None => Err(TransportError::UnsupportedConnectorConfig("reality")),
            },
        }
    }
}
```

- [ ] **Step 3: Run focused GREEN checks**

Run:

```sh
cargo test -p xray-transport --test transport_tests reality
cargo test -p xray-core-rs outbound::tests
```

Expected: the injected REALITY tests pass, the default REALITY rejection test still passes, and the raw flow rejection test still passes.

- [ ] **Step 4: Run nearby guard checks**

Run:

```sh
cargo test -p xray-transport --test transport_tests transport_dialer_routes_tcp_configs_to_tcp_connector
cargo test -p xray-transport --test transport_tests transport_dialer_routes_tls_configs_to_tls_connector
cargo test -p xray-core-rs --test runtime_data_path_tests vision
```

Expected: TCP/TLS dialer routing remains unchanged; raw TCP/TLS Vision guards still pass; REALITY+Vision selection still passes.

- [ ] **Step 5: Commit**

Run:

```sh
git add crates/xray-transport/src/lib.rs crates/xray-transport/src/dialer.rs crates/xray-transport/tests/transport_tests.rs crates/xray-core-rs/src/outbound.rs
git commit -m "feat(transport): add injectable reality runtime boundary"
```

## Task 3: Document Runtime Boundary Status

**Files:**
- Modify: `README.md`
- Modify: `docs/verification.md`

- [ ] **Step 1: Update README runtime status**

In `README.md`, replace the current runtime status paragraph with:

```markdown
Current runtime status: raw TCP VLESS and plain rustls-backed VLESS over TLS are executable for local/test traffic and covered by end-to-end Rust tests with fake VLESS servers. VLESS outbound servers may be configured as IP addresses or, when a resolver is available, domains. REALITY configs can be selected into the transport boundary and prepared from a validated ClientHello provider without network I/O. `xtls-rprx-vision` has a bounded Tokio stream wrapper, and `VLESS + REALITY + Vision` can now be exercised through an explicitly injected REALITY protected-stream engine. The default system dialer still rejects live REALITY networking until a real Chrome/uTLS-compatible TLS engine exists. Full Xray DNS behavior and local Xray-core interoperability run remain future work.
```

- [ ] **Step 2: Update verification matrix**

In `docs/verification.md`, update the Vision runtime boundary section so the command block becomes:

```sh
cargo test -p xray-proxy --test vision_stream_tests
cargo test -p xray-transport --test transport_tests reality
cargo test -p xray-core-rs --test runtime_data_path_tests vision
cargo test -p xray-core-rs outbound::tests
```

Replace the paragraph below that block with:

```markdown
These verify that `VisionStream` pads outbound bytes, unpads inbound bytes, the default system dialer still rejects live REALITY networking, an explicitly injected REALITY protected-stream engine can carry runtime bytes, `VLESS + REALITY + xtls-rprx-vision` reaches the protected transport boundary, and raw TCP/TLS Vision flows are still rejected. They do not validate a real Chrome/uTLS-compatible REALITY TLS engine or local Xray-core interoperability yet.
```

- [ ] **Step 3: Run doc-adjacent tests**

Run:

```sh
cargo test -p xray-transport --test transport_tests reality
cargo test -p xray-core-rs outbound::tests
```

Expected: focused runtime-boundary tests still pass after docs changes.

- [ ] **Step 4: Commit**

Run:

```sh
git add README.md docs/verification.md
git commit -m "docs: update reality runtime boundary status"
```

## Task 4: Full Verification

**Files:**
- Verify workspace.

- [ ] **Step 1: Run formatting check**

Run:

```sh
cargo fmt --all -- --check
```

Expected: command exits successfully.

- [ ] **Step 2: Run clippy**

Run:

```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: command exits successfully with no warnings.

- [ ] **Step 3: Run full Rust tests**

Run:

```sh
cargo test --workspace --all-targets
```

Expected: all non-ignored Rust tests pass. In this sandbox, use loopback bind/connect approval because existing lifecycle and transport tests bind local sockets.

- [ ] **Step 4: Run Go oracle checks**

Run:

```sh
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

Expected: both commands exit successfully and fixtures remain unchanged.

- [ ] **Step 5: Confirm compatibility shell remains gated**

Run:

```sh
rg -n "#\\[ignore\\]|vless_reality_vision" tests/compat/vless_reality_vision.rs
```

Expected: the compatibility shell still contains an ignored test and is not wired as a Cargo target.

- [ ] **Step 6: Review git state**

Run:

```sh
git status --short --branch
git log --oneline -5
```

Expected: working tree is clean; recent commits include the design commit, the implementation commit, and the docs status commit.
