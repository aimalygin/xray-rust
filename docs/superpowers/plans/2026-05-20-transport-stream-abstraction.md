# Transport Stream Abstraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a boxed transport stream boundary so future TLS, REALITY, and Vision transports can plug into VLESS outbound code without changing relay logic.

**Architecture:** `xray-transport` owns the transport stream abstraction and returns a boxed async read/write stream from every connector. The current TCP connector keeps its existing dialing behavior but boxes `TcpStream`; `xray-core-rs` consumes the boxed stream in VLESS outbound and keeps SOCKS relay behavior unchanged.

**Tech Stack:** Rust 2021, Tokio async I/O, `async-trait`, existing `xray-transport`, `xray-core-rs`, and runtime integration tests.

---

## File Structure

- `crates/xray-transport/src/lib.rs`: define `TransportStream`, `BoxedTransportStream`, update `TransportConnector`, and box TCP streams.
- `crates/xray-transport/tests/transport_tests.rs`: add a loopback echo test that proves `TcpConnector::connect` returns a boxed transport stream usable as async read/write.
- `crates/xray-core-rs/src/outbound.rs`: update VLESS outbound helper return types from `tokio::net::TcpStream` to `BoxedTransportStream`.
- `crates/xray-core-rs/src/socks.rs`: no planned source change; it must continue to compile with `copy_bidirectional` using the boxed outbound stream.
- `crates/xray-core-rs/tests/runtime_data_path_tests.rs`: no planned source change; existing runtime tests prove the relay path still works.

### Task 1: Boxed Transport Stream Boundary

**Files:**
- Modify: `crates/xray-transport/src/lib.rs`
- Modify: `crates/xray-transport/tests/transport_tests.rs`
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Verify: `crates/xray-core-rs/src/socks.rs`
- Verify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write the failing transport test**

In `crates/xray-transport/tests/transport_tests.rs`, extend the imports at the top from:

```rust
use std::net::{IpAddr, Ipv4Addr};

use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    ConnectorConfig, RealityClientConfig, TcpConnector, TlsClientConfig, TransportConnector,
    TransportError,
};
```

to:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, RealityClientConfig, TcpConnector, TlsClientConfig,
    TransportConnector, TransportError,
};
```

Add these helpers near the top of the file, after the imports:

```rust
async fn spawn_echo_once() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo listener");
    let addr = listener.local_addr().expect("read listener address");

    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept echo client");
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.expect("read ping");
        stream.write_all(&buf).await.expect("write pong");
    });

    (addr, handle)
}

async fn assert_boxed_transport_stream(mut stream: BoxedTransportStream) {
    stream.write_all(b"ping").await.expect("write ping");

    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.expect("read echoed bytes");

    assert_eq!(&echoed, b"ping");
}
```

Add this test after `tcp_connector_reports_target_without_network_io_when_resolved`:

```rust
#[tokio::test]
async fn tcp_connector_returns_boxed_transport_stream() {
    let (addr, handle) = spawn_echo_once().await;
    let connector = TcpConnector::new(ConnectorConfig::Tcp);
    let target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);

    let stream = connector.connect(&target).await.expect("connect TCP target");

    assert_boxed_transport_stream(stream).await;
    handle.await.expect("echo task should complete");
}
```

- [ ] **Step 2: Run the focused transport test to verify it fails**

Run:

```bash
cargo test -p xray-transport --test transport_tests tcp_connector_returns_boxed_transport_stream
```

Expected: FAIL at compile time because `xray_transport::BoxedTransportStream` does not exist yet.

- [ ] **Step 3: Implement boxed transport streams and update VLESS outbound**

In `crates/xray-transport/src/lib.rs`, change the Tokio imports from:

```rust
use tokio::net::TcpStream;
```

to:

```rust
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
```

Add the transport stream boundary immediately before `#[async_trait] pub trait TransportConnector`:

```rust
pub trait TransportStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TransportStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedTransportStream = Box<dyn TransportStream>;
```

Replace the `TransportConnector` trait:

```rust
#[async_trait]
pub trait TransportConnector: Send + Sync {
    type Stream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError>;

    fn describe_target(&self, target: &Target) -> String {
        target.to_string()
    }
}
```

with:

```rust
#[async_trait]
pub trait TransportConnector: Send + Sync {
    async fn connect(&self, target: &Target) -> Result<BoxedTransportStream, TransportError>;

    fn describe_target(&self, target: &Target) -> String {
        target.to_string()
    }
}
```

Replace the `TcpConnector` implementation header and return type:

```rust
#[async_trait]
impl TransportConnector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError> {
```

with:

```rust
#[async_trait]
impl TransportConnector for TcpConnector {
    async fn connect(&self, target: &Target) -> Result<BoxedTransportStream, TransportError> {
```

Replace the final TCP connect expression:

```rust
        TcpStream::connect(addr).await.map_err(TransportError::Tcp)
```

with:

```rust
        let stream = TcpStream::connect(addr).await.map_err(TransportError::Tcp)?;
        Ok(Box::new(stream))
```

In `crates/xray-core-rs/src/outbound.rs`, change the transport import from:

```rust
use xray_transport::{ConnectorConfig, DnsResolver, SystemDnsResolver, TcpConnector, TransportConnector};
```

to:

```rust
use xray_transport::{
    BoxedTransportStream, ConnectorConfig, DnsResolver, SystemDnsResolver, TcpConnector,
    TransportConnector,
};
```

Change `open_vless_tcp_stream_with_resolver` return type from:

```rust
) -> Result<tokio::net::TcpStream, CoreError>
```

to:

```rust
) -> Result<BoxedTransportStream, CoreError>
```

Change `open_vless_tcp_stream` return type from:

```rust
) -> Result<tokio::net::TcpStream, CoreError> {
```

to:

```rust
) -> Result<BoxedTransportStream, CoreError> {
```

Do not change the header-writing logic:

```rust
    let connector = TcpConnector::new(outbound.transport.clone());
    let mut stream = connector.connect(&resolved_server).await?;
    let header = build_vless_request_header(outbound, target)?;
    stream.write_all(&header).await.map_err(CoreError::Io)?;

    Ok(stream)
```

- [ ] **Step 4: Run focused checks**

Run:

```bash
cargo test -p xray-transport --test transport_tests tcp_connector_returns_boxed_transport_stream
```

Expected: PASS.

Run:

```bash
cargo test -p xray-transport --test transport_tests
```

Expected: PASS.

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_vless_tcp_outbound
```

Expected: PASS.

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_reaches_echo_target_through_domain_vless_server
```

Expected: PASS.

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests socks_client_preserves_domain_target_through_domain_vless_server
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add crates/xray-transport/src/lib.rs crates/xray-transport/tests/transport_tests.rs crates/xray-core-rs/src/outbound.rs
git commit -m "feat(transport): box outbound transport streams"
```

### Task 2: Workspace Verification

**Files:**
- Verify: `crates/xray-transport/src/lib.rs`
- Verify: `crates/xray-transport/tests/transport_tests.rs`
- Verify: `crates/xray-core-rs/src/outbound.rs`
- Verify: `crates/xray-core-rs/src/socks.rs`
- Verify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Run formatting check**

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

- [ ] **Step 3: Run the full workspace tests**

Run:

```bash
cargo test --workspace --all-targets
```

Expected: PASS.

- [ ] **Step 4: Inspect the resulting diff**

Run:

```bash
git diff --stat HEAD
git diff -- crates/xray-transport/src/lib.rs crates/xray-transport/tests/transport_tests.rs crates/xray-core-rs/src/outbound.rs
```

Expected: no uncommitted source changes after Task 1. If formatting or lint fixes were required, review that they only affect the files above.

- [ ] **Step 5: Commit any verification-only fixes**

Only run this if Step 4 shows legitimate formatting or lint fixes:

```bash
git add crates/xray-transport/src/lib.rs crates/xray-transport/tests/transport_tests.rs crates/xray-core-rs/src/outbound.rs
git commit -m "chore: clean up transport stream abstraction"
```

## Self-Review Notes

- Spec coverage: The plan adds a boxed transport stream abstraction, updates TCP connector output, adapts VLESS outbound return types, and verifies SOCKS relay behavior through existing runtime tests. TLS, REALITY, and Vision remain rejected exactly as before.
- Placeholder scan: No placeholder tasks, no deferred work, and every code edit includes concrete snippets.
- Type consistency: `TransportConnector::connect` returns `BoxedTransportStream`; `TcpConnector` boxes `TcpStream`; VLESS outbound returns `BoxedTransportStream`; `copy_bidirectional` can still use the boxed stream because `TransportStream` requires `AsyncRead + AsyncWrite + Unpin`.
