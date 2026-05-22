# TLS, REALITY, and Vision Interop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove local Xray-core interop for VLESS/TLS and VLESS/TLS/Vision, while keeping REALITY live interop gated on a real TLS session provider.

**Architecture:** Extend the existing local Xray interop test harness into a small scenario runner that can configure raw TCP and TLS Xray VLESS inbounds. Accept Vision on protected transports in Rust outbound selection, keep raw TCP Vision rejected, and leave REALITY runtime honest until live TLS completion exists.

**Tech Stack:** Rust, Tokio, rustls, tokio-rustls, rcgen, local Go Xray-core checkout, ignored integration tests.

---

## File Structure

- Modify `crates/xray-core-rs/tests/local_xray_interop_tests.rs`: reusable local Xray scenario runner, TLS certificate generation, raw/TLS/TLS+Vision ignored tests.
- Modify `crates/xray-core-rs/tests/runtime_data_path_tests.rs`: outbound selection unit test for TLS+Vision and update the old TLS+Vision rejection test.
- Modify `crates/xray-core-rs/src/outbound.rs`: allow `xtls-rprx-vision` on `ConnectorConfig::Tls` as well as `ConnectorConfig::Reality`.
- Keep `crates/xray-transport/src/reality_connector.rs` unchanged unless a real provider is implemented; do not replace it with a dummy.

## Task 1: Add TLS Scenario Test In Red

**Files:**
- Modify: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

- [ ] **Step 1: Add scenario data structures and TLS certificate helper**

Add imports:

```rust
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use xray_config::TlsSettings;
use xray_transport::{TlsConnector, TransportDialer};
```

Add helpers:

```rust
const TLS_SERVER_NAME: &str = "vless.test";

struct GeneratedTlsIdentity {
    cert_path: PathBuf,
    key_path: PathBuf,
    client_config: Arc<rustls::ClientConfig>,
}

fn generate_tls_identity(temp_dir: &TempDir) -> GeneratedTlsIdentity {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![TLS_SERVER_NAME.to_owned()])
            .expect("generate self-signed certificate");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let cert_path = temp_dir.path.join("server.crt.pem");
    let key_path = temp_dir.path.join("server.key.pem");
    fs::write(&cert_path, cert.pem()).expect("write tls cert");
    fs::write(&key_path, signing_key.serialize_pem()).expect("write tls key");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add generated cert root");
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider should support default TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();

    drop(key_der);

    GeneratedTlsIdentity {
        cert_path,
        key_path,
        client_config: Arc::new(client_config),
    }
}
```

- [ ] **Step 2: Add ignored TLS interop test**

```rust
#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_tls() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_vless_tls_interop(None),
    )
    .await
    .unwrap();
}
```

- [ ] **Step 3: Run red test**

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tls
```

Expected: compile failure or runtime failure because the harness cannot yet write TLS Xray config and inject the Rust TLS dialer.

## Task 2: Implement TLS Scenario

**Files:**
- Modify: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

- [ ] **Step 1: Replace raw-only config helper with scenario-aware config**

Add:

```rust
enum XrayInboundSecurity {
    None,
    Tls { cert_path: PathBuf, key_path: PathBuf },
}

struct XrayVlessServerConfig {
    security: XrayInboundSecurity,
    flow: Option<&'static str>,
}
```

Replace `write_xray_vless_config(path, port)` with `write_xray_vless_config(path, port, &server_config)` that emits:

```json
"streamSettings": {
  "network": "tcp",
  "security": "tls",
  "tlsSettings": {
    "certificates": [
      {
        "certificateFile": "...",
        "keyFile": "..."
      }
    ]
  }
}
```

For `XrayInboundSecurity::None`, omit `streamSettings`.

- [ ] **Step 2: Let Xray startup receive the server config**

Change:

```rust
async fn start_xray_vless_server(xray_checkout: &Path, server_config: XrayVlessServerConfig) -> XrayServer
```

Call `write_xray_vless_config(&config_path, port, &server_config)`.

- [ ] **Step 3: Add Rust TLS client config builder**

Add:

```rust
fn rust_core_config_with_security(
    xray_addr: SocketAddr,
    security: StreamSecurity,
    flow: Option<&str>,
) -> CoreConfig
```

Use it from both raw and TLS runners. The TLS case should set `StreamSecurity::Tls(TlsSettings { server_name: Some(TLS_SERVER_NAME.to_owned()), fingerprint: None })`.

- [ ] **Step 4: Add common runner with optional dialer**

Refactor `run_local_xray_vless_interop()` into a helper:

```rust
async fn run_local_xray_vless_interop_scenario(
    xray_config: XrayVlessServerConfig,
    rust_config: CoreConfig,
    transport_dialer: Option<TransportDialer>,
)
```

Use `Core::with_runtime_dependencies` when `transport_dialer` is present, otherwise `Core::new`.

- [ ] **Step 5: Implement TLS runner**

```rust
async fn run_local_xray_vless_tls_interop(flow: Option<&'static str>) {
    let temp_dir = create_temp_dir("xray-rust-local-interop-tls");
    let identity = generate_tls_identity(&temp_dir);
    let rust_config = rust_core_config_with_security(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        StreamSecurity::Tls(TlsSettings {
            server_name: Some(TLS_SERVER_NAME.to_owned()),
            fingerprint: None,
        }),
        flow,
    );
    let dialer = TransportDialer::with_tls_connector(TlsConnector::with_client_config(
        Arc::clone(&identity.client_config),
    ));
    run_local_xray_vless_interop_scenario(...).await
}
```

The implementation should allocate the Xray port before building `rust_config`, so the temporary address shown above is not kept.

- [ ] **Step 6: Run TLS test to green**

Run the same exact ignored test from Task 1. Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/xray-core-rs/tests/local_xray_interop_tests.rs
git commit -m "test(core): add local xray vless tls interop"
```

## Task 3: Add TLS+Vision Tests In Red

**Files:**
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`
- Modify: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

- [ ] **Step 1: Change runtime rejection test into acceptance test**

Replace `rejects_vision_flow_for_tls_runtime_path` with:

```rust
#[test]
fn selects_tls_vision_outbound_for_protected_stream_boundary() {
    let mut outbound = vless_outbound(
        StreamSecurity::Tls(TlsSettings {
            server_name: Some("example.com".to_owned()),
            fingerprint: None,
        }),
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        443,
    );
    let OutboundSettings::Vless(settings) = &mut outbound.settings;
    settings.users[0].flow = Some("xtls-rprx-vision".to_owned());
    let config = config_with_outbound(outbound);

    let selected = select_vless_tcp_outbound(&config).unwrap();

    assert_eq!(selected.user().flow.as_deref(), Some("xtls-rprx-vision"));
    assert!(matches!(
        selected.transport(),
        xray_transport::ConnectorConfig::Tls(_)
    ));
}
```

- [ ] **Step 2: Add ignored local Xray TLS+Vision test**

```rust
#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_tls_vision() {
    timeout(
        Duration::from_secs(120),
        run_local_xray_vless_tls_interop(Some("xtls-rprx-vision")),
    )
    .await
    .unwrap();
}
```

- [ ] **Step 3: Run red tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests -- selects_tls_vision_outbound_for_protected_stream_boundary
```

Expected: FAIL with `UnsupportedOutboundFlow`.

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tls_vision
```

Expected: FAIL before the outbound allows TLS+Vision, or fail later in Vision framing if selection is already changed.

## Task 4: Implement TLS+Vision Selection And Interop

**Files:**
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

- [ ] **Step 1: Allow Vision on protected transports**

Change:

```rust
fn validate_stream_flow(flow: Option<&str>, security: &StreamSecurity) -> Result<(), CoreError> {
    validate_vision_flow(
        flow,
        matches!(security, StreamSecurity::Tls(_) | StreamSecurity::Reality(_)),
    )
    .map(|_| ())
}

fn validate_connector_flow(
    flow: Option<&str>,
    transport: &ConnectorConfig,
) -> Result<bool, CoreError> {
    validate_vision_flow(
        flow,
        matches!(transport, ConnectorConfig::Tls(_) | ConnectorConfig::Reality(_)),
    )
}
```

- [ ] **Step 2: Ensure Xray inbound client includes Vision flow**

When `XrayVlessServerConfig.flow` is `Some(flow)`, emit the client JSON as:

```json
{ "id": "...", "flow": "xtls-rprx-vision" }
```

When flow is absent, keep the old client JSON without flow.

- [ ] **Step 3: Run unit and local interop tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests -- selects_tls_vision_outbound_for_protected_stream_boundary rejects_vision_flow_for_raw_tcp_runtime_path
```

Expected: PASS.

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tls_vision
```

Expected: PASS if current Vision stream is compatible with Xray-core. If it fails, inspect Xray logs and captured failure, then add a focused Vision stream test before changing Vision framing.

- [ ] **Step 4: Commit**

```bash
git add crates/xray-core-rs/src/outbound.rs crates/xray-core-rs/tests/runtime_data_path_tests.rs crates/xray-core-rs/tests/local_xray_interop_tests.rs
git commit -m "feat(core): allow vless vision over tls"
```

## Task 5: REALITY Boundary Check

**Files:**
- Modify only if needed: `docs/superpowers/specs/2026-05-21-tls-reality-vision-interop-design.md`
- Modify only if needed: `crates/xray-transport/src/reality_connector.rs`

- [ ] **Step 1: Verify existing REALITY tests still pass**

Run:

```bash
cargo test -p xray-transport reality
```

Expected: PASS.

- [ ] **Step 2: Verify default runtime remains honest**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests -- selects_reality_vision_outbound_for_protected_stream_boundary
```

Expected: PASS, proving config selection still supports REALITY+Vision while the runtime requires an injected engine for live dialing.

- [ ] **Step 3: Do not add dummy live REALITY interop**

If no live `RealityTlsSessionProvider` has been implemented, record the result in the final answer: REALITY crypto/config/runtime boundary remains covered, but live Xray-core REALITY interop is not claimed yet.

## Task 6: Full Verification

**Files:**
- No planned edits.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt --all -- --check
```

Expected: PASS.

- [ ] **Step 2: Targeted Rust tests**

Run:

```bash
cargo test -p xray-proxy --test vless_response_stream_tests
cargo test -p xray-core-rs --all-targets
cargo test -p xray-transport reality
```

Expected: PASS.

- [ ] **Step 3: Local Xray interop tests**

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tls
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored --exact rust_socks_client_reaches_echo_server_through_local_xray_vless_tls_vision
```

Expected: PASS for all implemented scenarios.

- [ ] **Step 4: Clippy**

Run:

```bash
cargo clippy -p xray-proxy -p xray-core-rs --all-targets --locked -- -D warnings
```

Expected: PASS.

- [ ] **Step 5: Commit verification/doc updates if needed**

```bash
git status --short
```

Expected: clean after commits, unless there are deliberate uncommitted notes.
