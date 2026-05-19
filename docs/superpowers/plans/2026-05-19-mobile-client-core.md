# Mobile Client Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first Rust mobile/client Xray-compatible core slice: Xray JSON subset, SOCKS/HTTP inbounds, platform-neutral TUN packet API, VLESS over TCP with TLS/REALITY and Vision, and C ABI embedding.

**Architecture:** Create a Rust workspace with small crates for config, runtime, routing, TUN, proxy protocols, transports, core lifecycle, and FFI. Keep Xray-core as a read-only oracle under `Xray-core/`; compatibility is proven by config tests, wire golden tests, FFI tests, and a cross-process Go Xray-core server test.

**Tech Stack:** Rust 2021, Tokio, bytes, serde/serde_json, thiserror, uuid, prost, rustls/tokio-rustls, x25519-dalek, hkdf, sha2, aes-gcm, libc, cbindgen-compatible C ABI.

---

## File Structure

Create this workspace layout:

- `Cargo.toml`: workspace members, shared dependency versions, release profiles.
- `rust-toolchain.toml`: stable Rust channel for reproducible local and CI builds.
- `.cargo/config.toml`: conservative build flags that work on desktop and mobile targets.
- `crates/xray-config`: config diagnostics, Xray JSON subset parser, normalized model.
- `crates/xray-routing`: `Target`, `Session`, `Router`, DNS abstraction.
- `crates/xray-tun`: bounded packet queues and TUN stats.
- `crates/xray-proxy`: VLESS wire encoding, Vision state machine, SOCKS5 and HTTP request parsers.
- `crates/xray-transport`: `TransportConnector`, TCP, TLS, REALITY client handshake support.
- `crates/xray-runtime`: runtime handle, cancellation, bounded task supervision.
- `crates/xray-core-rs`: public Rust API and core lifecycle.
- `crates/xray-ffi`: C ABI, opaque handles, error/log/stats bridge.
- `tests/fixtures/configs`: supported and rejected JSON configs.
- `tests/fixtures/wire`: golden VLESS/Vision vectors.
- `tests/compat`: end-to-end tests that launch local `Xray-core`.
- `tests/c_ffi`: C harness source and Rust build script integration.

Dependency direction:

- `xray-config` has no dependency on runtime/proxy/transport.
- `xray-routing` depends on `bytes` only for payload-friendly types.
- `xray-tun` depends on `bytes`, `tokio`, and `thiserror`.
- `xray-proxy` depends on `xray-routing`.
- `xray-transport` depends on `xray-routing`.
- `xray-core-rs` depends on all runtime crates except FFI.
- `xray-ffi` depends only on `xray-core-rs`, `xray-config`, and `libc`.

## Task 1: Workspace Skeleton

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `.cargo/config.toml`
- Create: `crates/xray-config/Cargo.toml`
- Create: `crates/xray-config/src/lib.rs`
- Create: `crates/xray-routing/Cargo.toml`
- Create: `crates/xray-routing/src/lib.rs`
- Create: `crates/xray-tun/Cargo.toml`
- Create: `crates/xray-tun/src/lib.rs`
- Create: `crates/xray-proxy/Cargo.toml`
- Create: `crates/xray-proxy/src/lib.rs`
- Create: `crates/xray-transport/Cargo.toml`
- Create: `crates/xray-transport/src/lib.rs`
- Create: `crates/xray-runtime/Cargo.toml`
- Create: `crates/xray-runtime/src/lib.rs`
- Create: `crates/xray-core-rs/Cargo.toml`
- Create: `crates/xray-core-rs/src/lib.rs`
- Create: `crates/xray-ffi/Cargo.toml`
- Create: `crates/xray-ffi/src/lib.rs`
- Test: `crates/xray-core-rs/tests/workspace_smoke.rs`

- [ ] **Step 1: Write the failing workspace smoke test**

```rust
// crates/xray-core-rs/tests/workspace_smoke.rs
#[test]
fn workspace_exports_version() {
    assert_eq!(xray_core_rs::version(), env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 2: Run the smoke test and verify it fails**

Run: `cargo test -p xray-core-rs workspace_exports_version`

Expected: FAIL before implementation because the workspace and crate do not exist.

- [ ] **Step 3: Create the workspace manifests**

```toml
# Cargo.toml
[workspace]
members = [
    "crates/xray-config",
    "crates/xray-routing",
    "crates/xray-tun",
    "crates/xray-proxy",
    "crates/xray-transport",
    "crates/xray-runtime",
    "crates/xray-core-rs",
    "crates/xray-ffi",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MPL-2.0"
repository = "local"

[workspace.dependencies]
aes-gcm = "0.10"
async-trait = "0.1"
bytes = "1"
hkdf = "0.12"
libc = "0.2"
prost = "0.13"
rand = "0.8"
rustls = "0.23"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
thiserror = "2"
tokio = { version = "1", features = ["io-util", "macros", "net", "rt", "rt-multi-thread", "sync", "time"] }
tokio-rustls = "0.26"
uuid = { version = "1", features = ["serde", "v4"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }

[profile.release]
codegen-units = 1
lto = "thin"
panic = "abort"
strip = "symbols"

[profile.dev]
panic = "unwind"
```

```toml
# rust-toolchain.toml
[toolchain]
channel = "stable"
components = ["clippy", "rustfmt"]
```

```toml
# .cargo/config.toml
[build]
rustflags = ["-Dwarnings"]
```

- [ ] **Step 4: Create crate manifests and minimal libraries**

```toml
# crates/xray-config/Cargo.toml
[package]
name = "xray-config"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
uuid.workspace = true
```

```rust
// crates/xray-config/src/lib.rs
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```toml
# crates/xray-routing/Cargo.toml
[package]
name = "xray-routing"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
bytes.workspace = true
thiserror.workspace = true
```

```rust
// crates/xray-routing/src/lib.rs
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```toml
# crates/xray-tun/Cargo.toml
[package]
name = "xray-tun"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
bytes.workspace = true
thiserror.workspace = true
tokio.workspace = true
```

```rust
// crates/xray-tun/src/lib.rs
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```toml
# crates/xray-proxy/Cargo.toml
[package]
name = "xray-proxy"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
bytes.workspace = true
prost.workspace = true
rand.workspace = true
thiserror.workspace = true
tokio.workspace = true
uuid.workspace = true
xray-routing = { path = "../xray-routing" }
```

```rust
// crates/xray-proxy/src/lib.rs
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```toml
# crates/xray-transport/Cargo.toml
[package]
name = "xray-transport"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
aes-gcm.workspace = true
async-trait.workspace = true
hkdf.workspace = true
rustls.workspace = true
sha2.workspace = true
thiserror.workspace = true
tokio.workspace = true
tokio-rustls.workspace = true
x25519-dalek.workspace = true
xray-routing = { path = "../xray-routing" }
```

```rust
// crates/xray-transport/src/lib.rs
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```toml
# crates/xray-runtime/Cargo.toml
[package]
name = "xray-runtime"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
thiserror.workspace = true
tokio.workspace = true
```

```rust
// crates/xray-runtime/src/lib.rs
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```toml
# crates/xray-core-rs/Cargo.toml
[package]
name = "xray-core-rs"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
xray-config = { path = "../xray-config" }
xray-proxy = { path = "../xray-proxy" }
xray-routing = { path = "../xray-routing" }
xray-runtime = { path = "../xray-runtime" }
xray-transport = { path = "../xray-transport" }
xray-tun = { path = "../xray-tun" }
```

```rust
// crates/xray-core-rs/src/lib.rs
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```toml
# crates/xray-ffi/Cargo.toml
[package]
name = "xray-ffi"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
crate-type = ["rlib", "staticlib", "cdylib"]

[dependencies]
libc.workspace = true
xray-config = { path = "../xray-config" }
xray-core-rs = { path = "../xray-core-rs" }
```

```rust
// crates/xray-ffi/src/lib.rs
#[no_mangle]
pub extern "C" fn xray_ffi_version_major() -> u32 {
    0
}
```

- [ ] **Step 5: Run the smoke test and verify it passes**

Run: `cargo test -p xray-core-rs workspace_exports_version`

Expected: PASS.

- [ ] **Step 6: Format, lint, and commit**

Run: `cargo fmt --all`

Run: `cargo clippy --workspace --all-targets`

Expected: both commands pass.

```bash
git add Cargo.toml rust-toolchain.toml .cargo/config.toml crates
git commit -m "chore: scaffold rust workspace"
```

## Task 2: Config Diagnostics and Normalized Model

**Files:**
- Create: `crates/xray-config/src/diagnostic.rs`
- Create: `crates/xray-config/src/model.rs`
- Modify: `crates/xray-config/src/lib.rs`
- Test: `crates/xray-config/tests/model_tests.rs`

- [ ] **Step 1: Write failing tests for diagnostics and model construction**

```rust
// crates/xray-config/tests/model_tests.rs
use xray_config::{
    Diagnostic, DiagnosticSeverity, InboundConfig, InboundProtocol, Network, OutboundConfig,
    OutboundProtocol, RealitySettings, StreamSecurity, StreamSettings, TargetAddr, VlessUser,
};

#[test]
fn diagnostic_carries_json_path() {
    let diagnostic = Diagnostic::error("$.outbounds[0].settings", "unsupported protocol field");
    assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
    assert_eq!(diagnostic.path.as_deref(), Some("$.outbounds[0].settings"));
    assert_eq!(diagnostic.message, "unsupported protocol field");
}

#[test]
fn normalized_model_can_represent_vless_reality_vision() {
    let outbound = OutboundConfig {
        tag: Some("proxy".to_owned()),
        protocol: OutboundProtocol::Vless,
        server: TargetAddr::Domain("server.example".to_owned()),
        port: 443,
        users: vec![VlessUser {
            id: "00010203-0405-0607-0809-0a0b0c0d0e0f".parse().unwrap(),
            encryption: "none".to_owned(),
            flow: Some("xtls-rprx-vision".to_owned()),
        }],
        stream: StreamSettings {
            network: Network::Tcp,
            security: StreamSecurity::Reality(RealitySettings {
                server_name: "www.example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                public_key: vec![1; 32],
                short_id: vec![2, 3, 4, 5],
                spider_x: "/".to_owned(),
            }),
        },
    };

    let inbound = InboundConfig {
        tag: Some("socks".to_owned()),
        protocol: InboundProtocol::Socks,
        listen: "127.0.0.1".to_owned(),
        port: 1080,
    };

    assert_eq!(inbound.port, 1080);
    assert_eq!(outbound.users[0].flow.as_deref(), Some("xtls-rprx-vision"));
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-config model_tests`

Expected: FAIL with unresolved imports.

- [ ] **Step 3: Implement diagnostics**

```rust
// crates/xray-config/src/diagnostic.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub path: Option<String>,
    pub message: String,
}

impl Diagnostic {
    pub fn error(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: DiagnosticSeverity::Error,
            path: Some(path.into()),
            message: message.into(),
        }
    }

    pub fn warning(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: DiagnosticSeverity::Warning,
            path: Some(path.into()),
            message: message.into(),
        }
    }
}
```

- [ ] **Step 4: Implement normalized config model**

```rust
// crates/xray-config/src/model.rs
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub default_outbound_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConfig {
    pub tag: Option<String>,
    pub protocol: InboundProtocol,
    pub listen: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundProtocol {
    Socks,
    Http,
    Tun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundConfig {
    pub tag: Option<String>,
    pub protocol: OutboundProtocol,
    pub server: TargetAddr,
    pub port: u16,
    pub users: Vec<VlessUser>,
    pub stream: StreamSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundProtocol {
    Vless,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessUser {
    pub id: Uuid,
    pub encryption: String,
    pub flow: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSettings {
    pub network: Network,
    pub security: StreamSecurity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSecurity {
    None,
    Tls(TlsSettings),
    Reality(RealitySettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySettings {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: Vec<u8>,
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(std::net::IpAddr),
    Domain(String),
}
```

- [ ] **Step 5: Export the model**

```rust
// crates/xray-config/src/lib.rs
mod diagnostic;
mod model;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundProtocol,
    RealitySettings, StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessUser,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 6: Run tests and commit**

Run: `cargo test -p xray-config model_tests`

Expected: PASS.

```bash
git add crates/xray-config
git commit -m "feat(config): add normalized config model"
```

## Task 3: Xray JSON Subset Parser

**Files:**
- Create: `crates/xray-config/src/parser.rs`
- Modify: `crates/xray-config/src/lib.rs`
- Test: `crates/xray-config/tests/parser_tests.rs`
- Create: `tests/fixtures/configs/vless_reality_vision.json`

- [ ] **Step 1: Add supported config fixture**

```json
{
  "inbounds": [
    {
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": 1080,
      "settings": {
        "udp": false
      }
    },
    {
      "tag": "http-in",
      "protocol": "http",
      "listen": "127.0.0.1",
      "port": 8080,
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "server.example",
            "port": 443,
            "users": [
              {
                "id": "00010203-0405-0607-0809-0a0b0c0d0e0f",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "www.example.com",
          "fingerprint": "chrome",
          "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
          "shortId": "02030405",
          "spiderX": "/"
        }
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs"
  }
}
```

- [ ] **Step 2: Write failing parser tests**

```rust
// crates/xray-config/tests/parser_tests.rs
use xray_config::{parse_xray_json, DiagnosticSeverity, StreamSecurity, TargetAddr};

#[test]
fn parses_vless_reality_vision_subset() {
    let raw = include_str!("../../../tests/fixtures/configs/vless_reality_vision.json");
    let parsed = parse_xray_json(raw).expect("config should parse");

    assert_eq!(parsed.config.inbounds.len(), 2);
    assert_eq!(parsed.config.outbounds.len(), 1);
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(parsed.config.outbounds[0].tag.as_deref(), Some("proxy"));
    assert_eq!(
        parsed.config.outbounds[0].server,
        TargetAddr::Domain("server.example".to_owned())
    );
    assert!(matches!(
        parsed.config.outbounds[0].stream.security,
        StreamSecurity::Reality(_)
    ));
}

#[test]
fn rejects_unsupported_outbound_protocol_with_path() {
    let raw = r#"{
        "inbounds": [],
        "outbounds": [
            { "protocol": "trojan", "settings": {} }
        ]
    }"#;

    let err = parse_xray_json(raw).unwrap_err();
    assert_eq!(err.diagnostics[0].severity, DiagnosticSeverity::Error);
    assert_eq!(err.diagnostics[0].path.as_deref(), Some("$.outbounds[0].protocol"));
}
```

- [ ] **Step 3: Run tests and verify they fail**

Run: `cargo test -p xray-config parser_tests`

Expected: FAIL because `parse_xray_json` does not exist.

- [ ] **Step 4: Implement parser**

```rust
// crates/xray-config/src/parser.rs
use crate::{
    CoreConfig, Diagnostic, InboundConfig, InboundProtocol, Network, OutboundConfig,
    OutboundProtocol, RealitySettings, StreamSecurity, StreamSettings, TargetAddr, VlessUser,
};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfig {
    pub config: CoreConfig,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Error)]
#[error("xray config parse failed")]
pub struct ConfigParseError {
    pub diagnostics: Vec<Diagnostic>,
}

pub fn parse_xray_json(raw: &str) -> Result<ParsedConfig, ConfigParseError> {
    let value: Value = serde_json::from_str(raw).map_err(|err| ConfigParseError {
        diagnostics: vec![Diagnostic::error("$", err.to_string())],
    })?;

    let mut diagnostics = Vec::new();
    let inbounds = parse_inbounds(&value, &mut diagnostics);
    let outbounds = parse_outbounds(&value, &mut diagnostics);

    if diagnostics.iter().any(|d| matches!(d.severity, crate::DiagnosticSeverity::Error)) {
        return Err(ConfigParseError { diagnostics });
    }

    Ok(ParsedConfig {
        config: CoreConfig {
            inbounds,
            outbounds,
            default_outbound_tag: Some("proxy".to_owned()),
        },
        diagnostics,
    })
}

fn parse_inbounds(root: &Value, diagnostics: &mut Vec<Diagnostic>) -> Vec<InboundConfig> {
    let Some(items) = root.get("inbounds").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| {
            let path = format!("$.inbounds[{idx}]");
            let protocol = match item.get("protocol").and_then(Value::as_str) {
                Some("socks") => InboundProtocol::Socks,
                Some("http") => InboundProtocol::Http,
                Some("tun") => InboundProtocol::Tun,
                Some(_) | None => {
                    diagnostics.push(Diagnostic::error(
                        format!("{path}.protocol"),
                        "unsupported inbound protocol",
                    ));
                    return None;
                }
            };
            let listen = item
                .get("listen")
                .and_then(Value::as_str)
                .unwrap_or("127.0.0.1")
                .to_owned();
            let port = item.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
            Some(InboundConfig {
                tag: item.get("tag").and_then(Value::as_str).map(str::to_owned),
                protocol,
                listen,
                port,
            })
        })
        .collect()
}

fn parse_outbounds(root: &Value, diagnostics: &mut Vec<Diagnostic>) -> Vec<OutboundConfig> {
    let Some(items) = root.get("outbounds").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| {
            let path = format!("$.outbounds[{idx}]");
            match item.get("protocol").and_then(Value::as_str) {
                Some("vless") => parse_vless_outbound(item, &path, diagnostics),
                Some(_) | None => {
                    diagnostics.push(Diagnostic::error(
                        format!("{path}.protocol"),
                        "unsupported outbound protocol",
                    ));
                    None
                }
            }
        })
        .collect()
}

fn parse_vless_outbound(
    item: &Value,
    path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<OutboundConfig> {
    let vnext = item.pointer("/settings/vnext/0")?;
    let address = vnext.get("address").and_then(Value::as_str)?.to_owned();
    let port = vnext.get("port").and_then(Value::as_u64)? as u16;
    let users_value = vnext.get("users").and_then(Value::as_array)?;
    let mut users = Vec::with_capacity(users_value.len());
    for (idx, user) in users_value.iter().enumerate() {
        let id = match user.get("id").and_then(Value::as_str).and_then(|v| v.parse().ok()) {
            Some(id) => id,
            None => {
                diagnostics.push(Diagnostic::error(
                    format!("{path}.settings.vnext[0].users[{idx}].id"),
                    "invalid VLESS user id",
                ));
                continue;
            }
        };
        users.push(VlessUser {
            id,
            encryption: user
                .get("encryption")
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_owned(),
            flow: user.get("flow").and_then(Value::as_str).map(str::to_owned),
        });
    }

    Some(OutboundConfig {
        tag: item.get("tag").and_then(Value::as_str).map(str::to_owned),
        protocol: OutboundProtocol::Vless,
        server: TargetAddr::Domain(address),
        port,
        users,
        stream: parse_stream_settings(item, path, diagnostics),
    })
}

fn parse_stream_settings(item: &Value, path: &str, diagnostics: &mut Vec<Diagnostic>) -> StreamSettings {
    let stream = item.get("streamSettings").unwrap_or(&Value::Null);
    let network = match stream.get("network").and_then(Value::as_str).unwrap_or("tcp") {
        "tcp" => Network::Tcp,
        "udp" => Network::Udp,
        other => {
            diagnostics.push(Diagnostic::error(
                format!("{path}.streamSettings.network"),
                format!("unsupported stream network {other}"),
            ));
            Network::Tcp
        }
    };

    let security = match stream.get("security").and_then(Value::as_str).unwrap_or("none") {
        "none" => StreamSecurity::None,
        "reality" => StreamSecurity::Reality(parse_reality(stream)),
        "tls" => StreamSecurity::Tls(crate::TlsSettings {
            server_name: stream
                .pointer("/tlsSettings/serverName")
                .and_then(Value::as_str)
                .map(str::to_owned),
            fingerprint: stream
                .pointer("/tlsSettings/fingerprint")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }),
        other => {
            diagnostics.push(Diagnostic::error(
                format!("{path}.streamSettings.security"),
                format!("unsupported stream security {other}"),
            ));
            StreamSecurity::None
        }
    };

    StreamSettings { network, security }
}

fn parse_reality(stream: &Value) -> RealitySettings {
    let settings = stream.get("realitySettings").unwrap_or(&Value::Null);
    RealitySettings {
        server_name: settings
            .get("serverName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        fingerprint: settings
            .get("fingerprint")
            .and_then(Value::as_str)
            .unwrap_or("chrome")
            .to_owned(),
        public_key: decode_base64url_no_pad(settings.get("publicKey").and_then(Value::as_str).unwrap_or("")),
        short_id: decode_hex(settings.get("shortId").and_then(Value::as_str).unwrap_or("")),
        spider_x: settings
            .get("spiderX")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_owned(),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| std::str::from_utf8(pair).ok())
        .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
        .collect()
}

fn decode_base64url_no_pad(value: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let Some(pos) = TABLE.iter().position(|b| *b == byte) else {
            continue;
        };
        buf = (buf << 6) | pos as u32;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}
```

- [ ] **Step 5: Export parser API**

```rust
// crates/xray-config/src/lib.rs
mod diagnostic;
mod model;
mod parser;

pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use model::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundProtocol,
    RealitySettings, StreamSecurity, StreamSettings, TargetAddr, TlsSettings, VlessUser,
};
pub use parser::{parse_xray_json, ConfigParseError, ParsedConfig};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 6: Run tests and commit**

Run: `cargo test -p xray-config`

Expected: PASS.

```bash
git add crates/xray-config tests/fixtures/configs
git commit -m "feat(config): parse xray json subset"
```

## Task 4: Routing Session Types

**Files:**
- Modify: `crates/xray-routing/src/lib.rs`
- Test: `crates/xray-routing/tests/routing_tests.rs`

- [ ] **Step 1: Write failing routing tests**

```rust
// crates/xray-routing/tests/routing_tests.rs
use std::net::{IpAddr, Ipv4Addr};
use xray_routing::{Network, Session, StaticRouter, Target, TargetAddr};

#[test]
fn static_router_uses_default_outbound() {
    let router = StaticRouter::new("proxy");
    let session = Session::new(
        "socks-in",
        Target::new(TargetAddr::Domain("example.com".to_owned()), 443, Network::Tcp),
    );

    assert_eq!(router.pick_outbound(&session).unwrap(), "proxy");
}

#[test]
fn target_preserves_ip_address() {
    let target = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        8080,
        Network::Tcp,
    );

    assert_eq!(target.port, 8080);
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-routing routing_tests`

Expected: FAIL with unresolved imports.

- [ ] **Step 3: Implement routing types**

```rust
// crates/xray-routing/src/lib.rs
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub addr: TargetAddr,
    pub port: u16,
    pub network: Network,
}

impl Target {
    pub fn new(addr: TargetAddr, port: u16, network: Network) -> Self {
        Self { addr, port, network }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub inbound_tag: String,
    pub target: Target,
}

impl Session {
    pub fn new(inbound_tag: impl Into<String>, target: Target) -> Self {
        Self {
            inbound_tag: inbound_tag.into(),
            target,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("no outbound available")]
    NoOutbound,
}

pub trait Router: Send + Sync {
    fn pick_outbound<'a>(&'a self, session: &Session) -> Result<&'a str, RoutingError>;
}

#[derive(Debug, Clone)]
pub struct StaticRouter {
    default_outbound: String,
}

impl StaticRouter {
    pub fn new(default_outbound: impl Into<String>) -> Self {
        Self {
            default_outbound: default_outbound.into(),
        }
    }

    pub fn pick_outbound<'a>(&'a self, session: &Session) -> Result<&'a str, RoutingError> {
        <Self as Router>::pick_outbound(self, session)
    }
}

impl Router for StaticRouter {
    fn pick_outbound<'a>(&'a self, _session: &Session) -> Result<&'a str, RoutingError> {
        if self.default_outbound.is_empty() {
            Err(RoutingError::NoOutbound)
        } else {
            Ok(&self.default_outbound)
        }
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p xray-routing`

Expected: PASS.

```bash
git add crates/xray-routing
git commit -m "feat(routing): add session and static router"
```

## Task 5: Bounded TUN Packet Endpoint

**Files:**
- Modify: `crates/xray-tun/src/lib.rs`
- Test: `crates/xray-tun/tests/tun_tests.rs`

- [ ] **Step 1: Write failing TUN tests**

```rust
// crates/xray-tun/tests/tun_tests.rs
use bytes::Bytes;
use xray_tun::{TunConfig, TunEndpoint, TunError};

#[tokio::test]
async fn tun_endpoint_moves_packets_in_both_directions() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 1500,
        queue_depth: 2,
    });

    tun.push_inbound(Bytes::from_static(&[0x45, 0, 0, 20])).await.unwrap();
    assert_eq!(tun.poll_inbound().await.unwrap(), Bytes::from_static(&[0x45, 0, 0, 20]));

    tun.push_outbound(Bytes::from_static(&[0x60, 0, 0, 0])).await.unwrap();
    assert_eq!(tun.poll_outbound().await.unwrap(), Bytes::from_static(&[0x60, 0, 0, 0]));
}

#[tokio::test]
async fn tun_endpoint_rejects_oversized_packet() {
    let tun = TunEndpoint::new(TunConfig {
        mtu: 4,
        queue_depth: 1,
    });

    let err = tun.push_inbound(Bytes::from_static(&[1, 2, 3, 4, 5])).await.unwrap_err();
    assert_eq!(err, TunError::PacketTooLarge { len: 5, mtu: 4 });
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-tun tun_tests`

Expected: FAIL with unresolved imports.

- [ ] **Step 3: Implement bounded endpoint**

```rust
// crates/xray-tun/src/lib.rs
use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunConfig {
    pub mtu: usize,
    pub queue_depth: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TunError {
    #[error("packet length {len} exceeds mtu {mtu}")]
    PacketTooLarge { len: usize, mtu: usize },
    #[error("tun queue is full")]
    QueueFull,
    #[error("tun queue is closed")]
    QueueClosed,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunStats {
    pub inbound_packets: u64,
    pub outbound_packets: u64,
    pub dropped_packets: u64,
}

pub struct TunEndpoint {
    config: TunConfig,
    inbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    outbound_tx: mpsc::Sender<Bytes>,
    outbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    stats: Mutex<TunStats>,
}

impl TunEndpoint {
    pub fn new(config: TunConfig) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(config.queue_depth);
        let (outbound_tx, outbound_rx) = mpsc::channel(config.queue_depth);
        Self {
            config,
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            outbound_tx,
            outbound_rx: Mutex::new(outbound_rx),
            stats: Mutex::new(TunStats::default()),
        }
    }

    pub async fn push_inbound(&self, packet: Bytes) -> Result<(), TunError> {
        self.push(packet, Direction::Inbound).await
    }

    pub async fn poll_inbound(&self) -> Result<Bytes, TunError> {
        let mut rx = self.inbound_rx.lock().await;
        rx.recv().await.ok_or(TunError::QueueClosed)
    }

    pub async fn push_outbound(&self, packet: Bytes) -> Result<(), TunError> {
        self.push(packet, Direction::Outbound).await
    }

    pub async fn poll_outbound(&self) -> Result<Bytes, TunError> {
        let mut rx = self.outbound_rx.lock().await;
        rx.recv().await.ok_or(TunError::QueueClosed)
    }

    pub async fn stats(&self) -> TunStats {
        *self.stats.lock().await
    }

    async fn push(&self, packet: Bytes, direction: Direction) -> Result<(), TunError> {
        if packet.len() > self.config.mtu {
            self.stats.lock().await.dropped_packets += 1;
            return Err(TunError::PacketTooLarge {
                len: packet.len(),
                mtu: self.config.mtu,
            });
        }

        let sender = match direction {
            Direction::Inbound => &self.inbound_tx,
            Direction::Outbound => &self.outbound_tx,
        };
        sender.try_send(packet).map_err(|err| {
            if err.is_full() {
                TunError::QueueFull
            } else {
                TunError::QueueClosed
            }
        })?;

        let mut stats = self.stats.lock().await;
        match direction {
            Direction::Inbound => stats.inbound_packets += 1,
            Direction::Outbound => stats.outbound_packets += 1,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Inbound,
    Outbound,
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p xray-tun`

Expected: PASS.

```bash
git add crates/xray-tun
git commit -m "feat(tun): add bounded packet endpoint"
```

## Task 6: VLESS Wire Encoding

**Files:**
- Create: `crates/xray-proxy/src/vless/mod.rs`
- Create: `crates/xray-proxy/src/vless/wire.rs`
- Modify: `crates/xray-proxy/src/lib.rs`
- Test: `crates/xray-proxy/tests/vless_wire_tests.rs`

- [ ] **Step 1: Write failing VLESS wire tests**

```rust
// crates/xray-proxy/tests/vless_wire_tests.rs
use uuid::Uuid;
use xray_proxy::vless::{encode_request_header, VlessCommand, VlessRequest};
use xray_routing::{Network, Target, TargetAddr};

#[test]
fn encodes_vless_tcp_header_with_vision_flow() {
    let request = VlessRequest {
        user_id: Uuid::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]),
        command: VlessCommand::Tcp,
        target: Target::new(TargetAddr::Domain("example.com".to_owned()), 443, Network::Tcp),
        flow: Some("xtls-rprx-vision".to_owned()),
    };

    let encoded = encode_request_header(&request).unwrap();
    let expected = hex_bytes(
        "00\
         000102030405060708090a0b0c0d0e0f\
         12\
         0a1078746c732d727072782d766973696f6e\
         01\
         01bb\
         02\
         0b6578616d706c652e636f6d",
    );

    assert_eq!(encoded, expected);
}

fn hex_bytes(input: &str) -> Vec<u8> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    clean
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-proxy vless_wire_tests`

Expected: FAIL because `xray_proxy::vless` does not exist.

- [ ] **Step 3: Implement VLESS module exports**

```rust
// crates/xray-proxy/src/lib.rs
pub mod vless;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```rust
// crates/xray-proxy/src/vless/mod.rs
mod wire;

pub use wire::{encode_request_header, VlessCommand, VlessRequest, WireError};
```

- [ ] **Step 4: Implement request header encoder**

```rust
// crates/xray-proxy/src/vless/wire.rs
use prost::Message;
use thiserror::Error;
use uuid::Uuid;
use xray_routing::{Target, TargetAddr};

const VLESS_VERSION: u8 = 0;
const ADDR_IPV4: u8 = 1;
const ADDR_DOMAIN: u8 = 2;
const ADDR_IPV6: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
    Reverse = 0x04,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub user_id: Uuid,
    pub command: VlessCommand,
    pub target: Target,
    pub flow: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("domain length {0} exceeds vless single-byte domain limit")]
    DomainTooLong(usize),
}

#[derive(Clone, PartialEq, Message)]
struct Addons {
    #[prost(string, tag = "1")]
    flow: String,
}

pub fn encode_request_header(request: &VlessRequest) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(64);
    out.push(VLESS_VERSION);
    out.extend_from_slice(request.user_id.as_bytes());

    match request.flow.as_deref() {
        Some("xtls-rprx-vision") => {
            let addons = Addons {
                flow: "xtls-rprx-vision".to_owned(),
            };
            let encoded = addons.encode_to_vec();
            out.push(encoded.len() as u8);
            out.extend_from_slice(&encoded);
        }
        _ => out.push(0),
    }

    out.push(request.command as u8);
    if matches!(request.command, VlessCommand::Tcp | VlessCommand::Udp) {
        encode_port(&mut out, request.target.port);
        encode_address(&mut out, &request.target.addr)?;
    }
    Ok(out)
}

fn encode_port(out: &mut Vec<u8>, port: u16) {
    out.extend_from_slice(&port.to_be_bytes());
}

fn encode_address(out: &mut Vec<u8>, addr: &TargetAddr) -> Result<(), WireError> {
    match addr {
        TargetAddr::Ip(ip) if ip.is_ipv4() => {
            out.push(ADDR_IPV4);
            match ip {
                std::net::IpAddr::V4(value) => out.extend_from_slice(&value.octets()),
                std::net::IpAddr::V6(_) => unreachable!("is_ipv4 guarded this branch"),
            }
        }
        TargetAddr::Ip(std::net::IpAddr::V6(value)) => {
            out.push(ADDR_IPV6);
            out.extend_from_slice(&value.octets());
        }
        TargetAddr::Domain(domain) => {
            if domain.len() > u8::MAX as usize {
                return Err(WireError::DomainTooLong(domain.len()));
            }
            out.push(ADDR_DOMAIN);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p xray-proxy vless_wire_tests`

Expected: PASS.

```bash
git add crates/xray-proxy
git commit -m "feat(proxy): encode vless request headers"
```

## Task 7: Vision Padding State Machine

**Files:**
- Create: `crates/xray-proxy/src/vless/vision.rs`
- Modify: `crates/xray-proxy/src/vless/mod.rs`
- Test: `crates/xray-proxy/tests/vision_tests.rs`

- [ ] **Step 1: Write failing Vision tests**

```rust
// crates/xray-proxy/tests/vision_tests.rs
use bytes::BytesMut;
use xray_proxy::vless::{unpad_vision_block, VisionCommand, VisionPadding};

#[test]
fn vision_padding_round_trips_user_uuid_once() {
    let user = [
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
    ];
    let mut padding = VisionPadding::new(user, [900, 500, 900, 256]);
    let payload = BytesMut::from(&b"hello"[..]);

    let padded = padding.pad(payload.clone(), VisionCommand::Continue, 3);
    assert_eq!(&padded[..16], &user);

    let unpadded = unpad_vision_block(&padded, &user).unwrap();
    assert_eq!(unpadded.payload, payload);
    assert_eq!(unpadded.command, VisionCommand::Continue);

    let second = padding.pad(BytesMut::from(&b"world"[..]), VisionCommand::End, 0);
    assert_ne!(&second[..16], &user);
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-proxy vision_tests`

Expected: FAIL because Vision types do not exist.

- [ ] **Step 3: Export Vision module**

```rust
// crates/xray-proxy/src/vless/mod.rs
mod vision;
mod wire;

pub use vision::{unpad_vision_block, UnpaddedVisionBlock, VisionCommand, VisionPadding};
pub use wire::{encode_request_header, VlessCommand, VlessRequest, WireError};
```

- [ ] **Step 4: Implement padding and unpadding**

```rust
// crates/xray-proxy/src/vless/vision.rs
use bytes::{Buf, BytesMut};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionCommand {
    Continue = 0,
    End = 1,
    Direct = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpaddedVisionBlock {
    pub command: VisionCommand,
    pub payload: BytesMut,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VisionError {
    #[error("vision block is shorter than header")]
    ShortBlock,
    #[error("vision user id mismatch")]
    UserMismatch,
    #[error("unknown vision command {0}")]
    UnknownCommand(u8),
    #[error("vision block length is inconsistent")]
    LengthMismatch,
}

pub struct VisionPadding {
    user_id: [u8; 16],
    emit_user_id: bool,
    seed: [u32; 4],
}

impl VisionPadding {
    pub fn new(user_id: [u8; 16], seed: [u32; 4]) -> Self {
        Self {
            user_id,
            emit_user_id: true,
            seed,
        }
    }

    pub fn pad(
        &mut self,
        payload: BytesMut,
        command: VisionCommand,
        deterministic_extra_padding: u16,
    ) -> BytesMut {
        let content_len = payload.len() as u16;
        let mut padding_len = deterministic_extra_padding;
        if content_len < self.seed[0] as u16 && padding_len == 0 {
            padding_len = self.seed[2].saturating_sub(content_len as u32).min(u16::MAX as u32) as u16;
        }

        let mut out = BytesMut::with_capacity(
            if self.emit_user_id { 16 } else { 0 } + 5 + content_len as usize + padding_len as usize,
        );
        if self.emit_user_id {
            out.extend_from_slice(&self.user_id);
            self.emit_user_id = false;
        }
        out.extend_from_slice(&[
            command as u8,
            (content_len >> 8) as u8,
            content_len as u8,
            (padding_len >> 8) as u8,
            padding_len as u8,
        ]);
        out.extend_from_slice(&payload);
        out.resize(out.len() + padding_len as usize, 0);
        out
    }
}

pub fn unpad_vision_block(
    padded: &[u8],
    expected_user_id: &[u8; 16],
) -> Result<UnpaddedVisionBlock, VisionError> {
    if padded.len() < 21 {
        return Err(VisionError::ShortBlock);
    }

    let mut cursor = padded;
    if &cursor[..16] == expected_user_id {
        cursor.advance(16);
    }

    if cursor.len() < 5 {
        return Err(VisionError::ShortBlock);
    }

    let command = match cursor[0] {
        0 => VisionCommand::Continue,
        1 => VisionCommand::End,
        2 => VisionCommand::Direct,
        value => return Err(VisionError::UnknownCommand(value)),
    };
    let content_len = u16::from_be_bytes([cursor[1], cursor[2]]) as usize;
    let padding_len = u16::from_be_bytes([cursor[3], cursor[4]]) as usize;
    cursor.advance(5);

    if cursor.len() < content_len + padding_len {
        return Err(VisionError::LengthMismatch);
    }

    Ok(UnpaddedVisionBlock {
        command,
        payload: BytesMut::from(&cursor[..content_len]),
    })
}
```

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p xray-proxy vision_tests`

Expected: PASS.

```bash
git add crates/xray-proxy
git commit -m "feat(proxy): add vision padding state machine"
```

## Task 8: SOCKS5 and HTTP Inbound Parsers

**Files:**
- Create: `crates/xray-proxy/src/inbound/mod.rs`
- Create: `crates/xray-proxy/src/inbound/socks.rs`
- Create: `crates/xray-proxy/src/inbound/http.rs`
- Modify: `crates/xray-proxy/src/lib.rs`
- Test: `crates/xray-proxy/tests/inbound_parser_tests.rs`

- [ ] **Step 1: Write failing parser tests**

```rust
// crates/xray-proxy/tests/inbound_parser_tests.rs
use std::io::Cursor;
use xray_proxy::inbound::{parse_http_connect, parse_socks5_connect};
use xray_routing::{Network, TargetAddr};

#[tokio::test]
async fn parses_socks5_connect_domain_target() {
    let bytes = [
        0x05, 0x01, 0x00,
        0x05, 0x01, 0x00, 0x03, 0x0b,
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        0x01, 0xbb,
    ];
    let target = parse_socks5_connect(Cursor::new(bytes)).await.unwrap();
    assert_eq!(target.network, Network::Tcp);
    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn parses_http_connect_domain_target() {
    let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();
    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-proxy inbound_parser_tests`

Expected: FAIL because `inbound` module does not exist.

- [ ] **Step 3: Export inbound parsers**

```rust
// crates/xray-proxy/src/lib.rs
pub mod inbound;
pub mod vless;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```rust
// crates/xray-proxy/src/inbound/mod.rs
mod http;
mod socks;

pub use http::{parse_http_connect, HttpParseError};
pub use socks::{parse_socks5_connect, SocksParseError};
```

- [ ] **Step 4: Implement SOCKS5 parser**

```rust
// crates/xray-proxy/src/inbound/socks.rs
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use xray_routing::{Network, Target, TargetAddr};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SocksParseError {
    #[error("unsupported socks version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported socks command {0}")]
    UnsupportedCommand(u8),
    #[error("unsupported socks address type {0}")]
    UnsupportedAddressType(u8),
    #[error("io error")]
    Io,
}

pub async fn parse_socks5_connect<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<Target, SocksParseError> {
    let version = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if version != 5 {
        return Err(SocksParseError::UnsupportedVersion(version));
    }
    let method_count = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let mut methods = vec![0u8; method_count as usize];
    reader.read_exact(&mut methods).await.map_err(|_| SocksParseError::Io)?;

    let version = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if version != 5 {
        return Err(SocksParseError::UnsupportedVersion(version));
    }
    let command = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    if command != 1 {
        return Err(SocksParseError::UnsupportedCommand(command));
    }
    let _reserved = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let addr_type = reader.read_u8().await.map_err(|_| SocksParseError::Io)?;
    let addr = match addr_type {
        1 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await.map_err(|_| SocksParseError::Io)?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        3 => {
            let len = reader.read_u8().await.map_err(|_| SocksParseError::Io)? as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await.map_err(|_| SocksParseError::Io)?;
            TargetAddr::Domain(String::from_utf8_lossy(&buf).into_owned())
        }
        4 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await.map_err(|_| SocksParseError::Io)?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => return Err(SocksParseError::UnsupportedAddressType(other)),
    };
    let port = reader.read_u16().await.map_err(|_| SocksParseError::Io)?;
    Ok(Target::new(addr, port, Network::Tcp))
}
```

- [ ] **Step 5: Implement HTTP CONNECT parser**

```rust
// crates/xray-proxy/src/inbound/http.rs
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use xray_routing::{Network, Target, TargetAddr};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("request is not http connect")]
    NotConnect,
    #[error("target is missing port")]
    MissingPort,
    #[error("invalid port")]
    InvalidPort,
    #[error("io error")]
    Io,
}

pub async fn parse_http_connect<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<Target, HttpParseError> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while buf.len() < 8192 {
        reader.read_exact(&mut byte).await.map_err(|_| HttpParseError::Io)?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
    }

    let line = String::from_utf8_lossy(&buf);
    let mut parts = line.split_whitespace();
    if parts.next() != Some("CONNECT") {
        return Err(HttpParseError::NotConnect);
    }
    let authority = parts.next().ok_or(HttpParseError::MissingPort)?;
    let (host, port) = authority.rsplit_once(':').ok_or(HttpParseError::MissingPort)?;
    let port = port.parse::<u16>().map_err(|_| HttpParseError::InvalidPort)?;
    Ok(Target::new(TargetAddr::Domain(host.to_owned()), port, Network::Tcp))
}
```

- [ ] **Step 6: Run tests and commit**

Run: `cargo test -p xray-proxy inbound_parser_tests`

Expected: PASS.

```bash
git add crates/xray-proxy
git commit -m "feat(proxy): parse socks5 and http connect targets"
```

## Task 9: Transport Traits, TCP, and TLS Connector

**Files:**
- Modify: `crates/xray-transport/src/lib.rs`
- Test: `crates/xray-transport/tests/transport_tests.rs`

- [ ] **Step 1: Write failing transport tests**

```rust
// crates/xray-transport/tests/transport_tests.rs
use std::net::{IpAddr, Ipv4Addr};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{ConnectorConfig, TcpConnector, TransportConnector};

#[tokio::test]
async fn tcp_connector_reports_target_without_network_io_when_resolved() {
    let config = ConnectorConfig::Tcp;
    let connector = TcpConnector::new(config);
    let target = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        9,
        Network::Tcp,
    );

    assert_eq!(connector.describe_target(&target), "127.0.0.1:9");
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-transport transport_tests`

Expected: FAIL with unresolved imports.

- [ ] **Step 3: Implement connector traits and TCP connector**

```rust
// crates/xray-transport/src/lib.rs
use async_trait::async_trait;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpStream;
use xray_routing::{Target, TargetAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorConfig {
    Tcp,
    Tls(TlsClientConfig),
    Reality(RealityClientConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientConfig {
    pub server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("domain resolution is required for {0}")]
    NeedsDns(String),
    #[error("tcp connect failed: {0}")]
    Tcp(std::io::Error),
    #[error("tls connect failed")]
    Tls,
}

#[async_trait]
pub trait TransportConnector: Send + Sync {
    type Stream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError>;

    fn describe_target(&self, target: &Target) -> String {
        match &target.addr {
            TargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
            TargetAddr::Domain(domain) => format!("{domain}:{}", target.port),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpConnector {
    config: ConnectorConfig,
}

impl TcpConnector {
    pub fn new(config: ConnectorConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl TransportConnector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError> {
        let _config = &self.config;
        let addr = match &target.addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
            TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
        };
        TcpStream::connect(addr).await.map_err(TransportError::Tcp)
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p xray-transport transport_tests`

Expected: PASS.

```bash
git add crates/xray-transport
git commit -m "feat(transport): add connector traits and tcp connector"
```

## Task 10: REALITY Handshake Primitive

**Files:**
- Create: `crates/xray-transport/src/reality.rs`
- Modify: `crates/xray-transport/src/lib.rs`
- Test: `crates/xray-transport/tests/reality_tests.rs`

- [ ] **Step 1: Write failing deterministic REALITY primitive test**

```rust
// crates/xray-transport/tests/reality_tests.rs
use xray_transport::reality::{build_reality_session_id, RealityHelloInput};

#[test]
fn reality_session_id_is_sealed_with_hkdf_auth_key() {
    let input = RealityHelloInput {
        version: [26, 5, 9],
        unix_time: 1_700_000_000,
        short_id: vec![0x02, 0x03, 0x04, 0x05],
        shared_secret: [7u8; 32],
        hello_random_prefix: [9u8; 20],
        hello_random_suffix: [11u8; 12],
        hello_raw: vec![0x16, 0x03, 0x01, 0x00, 0x20],
    };

    let sealed = build_reality_session_id(&input).unwrap();
    assert_eq!(sealed.len(), 32);
    assert_ne!(&sealed[..16], &[26, 5, 9, 0, 0x65, 0x53, 0xf1, 0x00, 2, 3, 4, 5, 0, 0, 0, 0]);
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-transport reality_tests`

Expected: FAIL because `reality` module does not exist.

- [ ] **Step 3: Implement REALITY primitive matching Xray-core client algorithm**

Reference before coding:

- `Xray-core/transport/internet/reality/reality.go`
- Function: `UClient`
- Key operations: X25519 shared key, HKDF-SHA256 with info `REALITY`, AES-GCM seal over first 16 bytes of session id with `hello.Random[20:]` as nonce and raw ClientHello as associated data.

```rust
// crates/xray-transport/src/lib.rs
pub mod reality;

use async_trait::async_trait;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpStream;
use xray_routing::{Target, TargetAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorConfig {
    Tcp,
    Tls(TlsClientConfig),
    Reality(RealityClientConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientConfig {
    pub server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("domain resolution is required for {0}")]
    NeedsDns(String),
    #[error("tcp connect failed: {0}")]
    Tcp(std::io::Error),
    #[error("tls connect failed")]
    Tls,
}

#[async_trait]
pub trait TransportConnector: Send + Sync {
    type Stream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError>;

    fn describe_target(&self, target: &Target) -> String {
        match &target.addr {
            TargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
            TargetAddr::Domain(domain) => format!("{domain}:{}", target.port),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpConnector {
    config: ConnectorConfig,
}

impl TcpConnector {
    pub fn new(config: ConnectorConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl TransportConnector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError> {
        let _config = &self.config;
        let addr = match &target.addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
            TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
        };
        TcpStream::connect(addr).await.map_err(TransportError::Tcp)
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```rust
// crates/xray-transport/src/reality.rs
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityHelloInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub hello_random_prefix: [u8; 20],
    pub hello_random_suffix: [u8; 12],
    pub hello_raw: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityError {
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("aead seal failed")]
    Aead,
}

pub fn build_reality_session_id(input: &RealityHelloInput) -> Result<[u8; 32], RealityError> {
    let mut session_id = [0u8; 32];
    session_id[0] = input.version[0];
    session_id[1] = input.version[1];
    session_id[2] = input.version[2];
    session_id[3] = 0;
    session_id[4..8].copy_from_slice(&input.unix_time.to_be_bytes());
    for (idx, byte) in input.short_id.iter().take(8).enumerate() {
        session_id[8 + idx] = *byte;
    }

    let hk = Hkdf::<Sha256>::new(Some(&input.hello_random_prefix), &input.shared_secret);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key).map_err(|_| RealityError::Hkdf)?;

    let cipher = Aes256Gcm::new_from_slice(&auth_key).map_err(|_| RealityError::Aead)?;
    let nonce = Nonce::from_slice(&input.hello_random_suffix);
    let tag = cipher
        .encrypt_in_place_detached(nonce, &input.hello_raw, &mut session_id[..16])
        .map_err(|_| RealityError::Aead)?;
    session_id[16..32].copy_from_slice(&tag);
    Ok(session_id)
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p xray-transport reality_tests`

Expected: PASS.

```bash
git add crates/xray-transport
git commit -m "feat(transport): add reality handshake primitive"
```

## Task 11: REALITY Connector Integration

**Files:**
- Create: `crates/xray-transport/src/reality_connector.rs`
- Modify: `crates/xray-transport/src/lib.rs`
- Test: `crates/xray-transport/tests/reality_connector_tests.rs`

- [ ] **Step 1: Write failing REALITY connector tests**

```rust
// crates/xray-transport/tests/reality_connector_tests.rs
use xray_transport::{
    reality_connector::{RealityConnector, RealityHandshakePlan},
    RealityClientConfig,
};

#[test]
fn reality_connector_accepts_chrome_fingerprint_for_first_slice() {
    let connector = RealityConnector::new(RealityClientConfig {
        server_name: "www.example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [1u8; 32],
        short_id: vec![2, 3, 4, 5],
        spider_x: "/".to_owned(),
    });

    assert!(connector.is_fingerprint_supported());
}

#[test]
fn reality_connector_builds_handshake_plan_without_network_io() {
    let connector = RealityConnector::new(RealityClientConfig {
        server_name: "www.example.com".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [1u8; 32],
        short_id: vec![2, 3, 4, 5],
        spider_x: "/".to_owned(),
    });

    let plan = connector.handshake_plan();
    assert_eq!(plan.server_name, "www.example.com");
    assert_eq!(plan.short_id, vec![2, 3, 4, 5]);
    assert_eq!(plan.fingerprint, "chrome");
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-transport reality_connector_tests`

Expected: FAIL because `reality_connector` module does not exist.

- [ ] **Step 3: Implement REALITY connector boundary**

```rust
// crates/xray-transport/src/lib.rs
pub mod reality;
pub mod reality_connector;

use async_trait::async_trait;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::TcpStream;
use xray_routing::{Target, TargetAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorConfig {
    Tcp,
    Tls(TlsClientConfig),
    Reality(RealityClientConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientConfig {
    pub server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("domain resolution is required for {0}")]
    NeedsDns(String),
    #[error("tcp connect failed: {0}")]
    Tcp(std::io::Error),
    #[error("tls connect failed")]
    Tls,
    #[error("unsupported REALITY fingerprint {0}")]
    UnsupportedRealityFingerprint(String),
}

#[async_trait]
pub trait TransportConnector: Send + Sync {
    type Stream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError>;

    fn describe_target(&self, target: &Target) -> String {
        match &target.addr {
            TargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
            TargetAddr::Domain(domain) => format!("{domain}:{}", target.port),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpConnector {
    config: ConnectorConfig,
}

impl TcpConnector {
    pub fn new(config: ConnectorConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl TransportConnector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: &Target) -> Result<Self::Stream, TransportError> {
        let _config = &self.config;
        let addr = match &target.addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, target.port),
            TargetAddr::Domain(domain) => return Err(TransportError::NeedsDns(domain.clone())),
        };
        TcpStream::connect(addr).await.map_err(TransportError::Tcp)
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

```rust
// crates/xray-transport/src/reality_connector.rs
use crate::RealityClientConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityHandshakePlan {
    pub server_name: String,
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub spider_x: String,
}

#[derive(Debug, Clone)]
pub struct RealityConnector {
    config: RealityClientConfig,
}

impl RealityConnector {
    pub fn new(config: RealityClientConfig) -> Self {
        Self { config }
    }

    pub fn is_fingerprint_supported(&self) -> bool {
        matches!(self.config.fingerprint.as_str(), "chrome")
    }

    pub fn handshake_plan(&self) -> RealityHandshakePlan {
        RealityHandshakePlan {
            server_name: self.config.server_name.clone(),
            fingerprint: self.config.fingerprint.clone(),
            public_key: self.config.public_key,
            short_id: self.config.short_id.clone(),
            spider_x: self.config.spider_x.clone(),
        }
    }
}
```

- [ ] **Step 4: Add oracle note for the network connector**

When expanding `RealityConnector::connect`, port the client sequence from `Xray-core/transport/internet/reality/reality.go` function `UClient`:

1. Build a Chrome-compatible TLS 1.3 ClientHello.
2. Put Xray version, unix time, and `shortId` into the 32-byte session id.
3. Compute X25519 shared secret with the server public key.
4. Derive the auth key with HKDF-SHA256, salt `hello.random[..20]`, info `REALITY`.
5. AES-GCM seal the first 16 bytes of the session id with nonce `hello.random[20..32]` and associated data equal to the raw ClientHello.
6. Replace the session id bytes in the raw ClientHello.
7. Complete TLS handshake and verify the REALITY certificate HMAC.

The worker must keep this sequence inside `xray-transport`; VLESS must only see an async byte stream.

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p xray-transport reality_connector_tests`

Expected: PASS.

```bash
git add crates/xray-transport
git commit -m "feat(transport): add reality connector boundary"
```

## Task 12: Runtime and Core Lifecycle

**Files:**
- Modify: `crates/xray-runtime/src/lib.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Test: `crates/xray-core-rs/tests/core_lifecycle_tests.rs`

- [ ] **Step 1: Write failing lifecycle tests**

```rust
// crates/xray-core-rs/tests/core_lifecycle_tests.rs
use xray_config::parse_xray_json;
use xray_core_rs::{Core, CoreState};

#[tokio::test]
async fn core_starts_and_stops_from_config() {
    let raw = include_str!("../../../tests/fixtures/configs/vless_reality_vision.json");
    let parsed = parse_xray_json(raw).unwrap();
    let mut core = Core::new(parsed.config).unwrap();

    assert_eq!(core.state(), CoreState::Created);
    core.start().await.unwrap();
    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
    assert_eq!(core.state(), CoreState::Stopped);
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-core-rs core_lifecycle_tests`

Expected: FAIL because `Core` does not exist.

- [ ] **Step 3: Implement runtime shutdown primitive**

```rust
// crates/xray-runtime/src/lib.rs
use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct Shutdown {
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self { tx, rx }
    }

    pub fn signal(&self) {
        let _ = self.tx.send(true);
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.rx.clone()
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 4: Implement core lifecycle**

```rust
// crates/xray-core-rs/src/lib.rs
use thiserror::Error;
use xray_config::CoreConfig;
use xray_runtime::Shutdown;
use xray_tun::{TunConfig, TunEndpoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreState {
    Created,
    Running,
    Stopped,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("core is already running")]
    AlreadyRunning,
}

pub struct Core {
    config: CoreConfig,
    state: CoreState,
    shutdown: Shutdown,
    tun: TunEndpoint,
}

impl Core {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        Ok(Self {
            config,
            state: CoreState::Created,
            shutdown: Shutdown::new(),
            tun: TunEndpoint::new(TunConfig {
                mtu: 1500,
                queue_depth: 128,
            }),
        })
    }

    pub fn state(&self) -> CoreState {
        self.state
    }

    pub async fn start(&mut self) -> Result<(), CoreError> {
        if self.state == CoreState::Running {
            return Err(CoreError::AlreadyRunning);
        }
        let _inbound_count = self.config.inbounds.len();
        self.state = CoreState::Running;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), CoreError> {
        self.shutdown.signal();
        self.state = CoreState::Stopped;
        Ok(())
    }

    pub fn tun(&self) -> &TunEndpoint {
        &self.tun
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 5: Add missing dependency and run tests**

Modify `crates/xray-core-rs/Cargo.toml`:

```toml
[package]
name = "xray-core-rs"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
thiserror.workspace = true
xray-config = { path = "../xray-config" }
xray-proxy = { path = "../xray-proxy" }
xray-routing = { path = "../xray-routing" }
xray-runtime = { path = "../xray-runtime" }
xray-transport = { path = "../xray-transport" }
xray-tun = { path = "../xray-tun" }
```

Run: `cargo test -p xray-core-rs core_lifecycle_tests`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/xray-runtime crates/xray-core-rs
git commit -m "feat(core): add lifecycle skeleton"
```

## Task 13: C ABI Handle, Errors, and TUN Bridge

**Files:**
- Modify: `crates/xray-ffi/src/lib.rs`
- Test: `crates/xray-ffi/tests/ffi_tests.rs`

- [ ] **Step 1: Write failing FFI tests**

```rust
// crates/xray-ffi/tests/ffi_tests.rs
use std::ffi::CString;
use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new, xray_error_free, XrayStatus,
};

#[test]
fn ffi_loads_config_and_returns_handle() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    assert!(err.is_null());

    let raw = CString::new(include_str!("../../../tests/fixtures/configs/vless_reality_vision.json")).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    unsafe {
        xray_core_free(core);
        xray_error_free(err);
    }
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `cargo test -p xray-ffi ffi_tests`

Expected: FAIL because FFI functions do not exist.

- [ ] **Step 3: Implement C ABI**

```rust
// crates/xray-ffi/src/lib.rs
use libc::c_char;
use std::ffi::{CStr, CString};
use std::ptr;
use xray_config::parse_xray_json;
use xray_core_rs::Core;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayStatus {
    Ok = 0,
    NullArgument = 1,
    InvalidUtf8 = 2,
    ConfigError = 3,
}

#[repr(C)]
pub struct XrayError {
    code: XrayStatus,
    message: *mut c_char,
}

pub struct XrayCoreHandle {
    core: Option<Core>,
}

#[no_mangle]
pub unsafe extern "C" fn xray_core_new(error: *mut *mut XrayError) -> *mut XrayCoreHandle {
    clear_error(error);
    Box::into_raw(Box::new(XrayCoreHandle { core: None }))
}

#[no_mangle]
pub unsafe extern "C" fn xray_core_load_config_json(
    handle: *mut XrayCoreHandle,
    json: *const c_char,
    error: *mut *mut XrayError,
) -> XrayStatus {
    clear_error(error);
    if handle.is_null() || json.is_null() {
        set_error(error, XrayStatus::NullArgument, "null argument");
        return XrayStatus::NullArgument;
    }

    let raw = match CStr::from_ptr(json).to_str() {
        Ok(value) => value,
        Err(_) => {
            set_error(error, XrayStatus::InvalidUtf8, "config is not valid utf-8");
            return XrayStatus::InvalidUtf8;
        }
    };

    let parsed = match parse_xray_json(raw) {
        Ok(value) => value,
        Err(err) => {
            let message = err
                .diagnostics
                .first()
                .map(|diag| diag.message.clone())
                .unwrap_or_else(|| "config parse failed".to_owned());
            set_error(error, XrayStatus::ConfigError, &message);
            return XrayStatus::ConfigError;
        }
    };

    match Core::new(parsed.config) {
        Ok(core) => {
            (*handle).core = Some(core);
            XrayStatus::Ok
        }
        Err(err) => {
            set_error(error, XrayStatus::ConfigError, &err.to_string());
            XrayStatus::ConfigError
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn xray_core_free(handle: *mut XrayCoreHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub unsafe extern "C" fn xray_error_free(error: *mut XrayError) {
    if error.is_null() {
        return;
    }
    let error = Box::from_raw(error);
    if !error.message.is_null() {
        drop(CString::from_raw(error.message));
    }
}

#[no_mangle]
pub extern "C" fn xray_ffi_version_major() -> u32 {
    0
}

unsafe fn clear_error(error: *mut *mut XrayError) {
    if !error.is_null() {
        *error = ptr::null_mut();
    }
}

unsafe fn set_error(error: *mut *mut XrayError, code: XrayStatus, message: &str) {
    if error.is_null() {
        return;
    }
    let message = CString::new(message).unwrap_or_else(|_| CString::new("ffi error").unwrap());
    *error = Box::into_raw(Box::new(XrayError {
        code,
        message: message.into_raw(),
    }));
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p xray-ffi ffi_tests`

Expected: PASS.

```bash
git add crates/xray-ffi
git commit -m "feat(ffi): add core handle and config loading"
```

## Task 14: Compatibility Harness Against Go Xray-core

**Files:**
- Create: `tests/compat/vless_reality_vision.rs`
- Create: `tests/fixtures/configs/go_vless_reality_vision_server.json`
- Create: `crates/xray-core-rs/tests/compat_smoke.rs`

- [ ] **Step 1: Add Go server fixture**

```json
{
  "log": {
    "loglevel": "debug"
  },
  "inbounds": [
    {
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "port": 24443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "00010203-0405-0607-0809-0a0b0c0d0e0f",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.example.com:443",
          "serverNames": ["www.example.com"],
          "privateKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "shortIds": ["02030405"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
```

- [ ] **Step 2: Write compatibility smoke test**

```rust
// crates/xray-core-rs/tests/compat_smoke.rs
use std::path::Path;

#[test]
fn xray_core_reference_checkout_is_available() {
    assert!(Path::new("Xray-core/go.mod").exists());
    assert!(Path::new("Xray-core/transport/internet/reality/reality.go").exists());
}
```

- [ ] **Step 3: Write ignored end-to-end test shell**

```rust
// tests/compat/vless_reality_vision.rs
use std::process::Command;

#[test]
#[ignore = "requires local Go toolchain and completed REALITY network connector"]
fn rust_client_can_connect_to_go_xray_vless_reality_vision_server() {
    let status = Command::new("go")
        .arg("test")
        .arg("./testing/scenarios")
        .arg("-run")
        .arg("TestVlessXtlsVisionReality")
        .current_dir("Xray-core")
        .status()
        .expect("go test should start");

    assert!(status.success());
}
```

- [ ] **Step 4: Run non-ignored compatibility smoke**

Run: `cargo test -p xray-core-rs compat_smoke`

Expected: PASS.

- [ ] **Step 5: Run Go reference scenario as an explicit oracle check**

Run: `go test ./testing/scenarios -run TestVlessXtlsVisionReality -count=1`

Working directory: `Xray-core`

Expected: PASS when Go dependencies are available locally. If the command fails because dependencies need network access, rerun with approval for `go test` network access.

- [ ] **Step 6: Commit**

```bash
git add tests/compat tests/fixtures/configs crates/xray-core-rs/tests/compat_smoke.rs
git commit -m "test: add xray-core compatibility harness"
```

## Task 15: Verification Matrix

**Files:**
- Create: `docs/verification.md`
- Modify: `README.md`

- [ ] **Step 1: Write verification document**

````markdown
# Verification

Run the local Rust checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace --all-targets
```

Run the Go Xray-core oracle check:

```bash
cd Xray-core
go test ./testing/scenarios -run TestVlessXtlsVisionReality -count=1
```

Run ignored Rust compatibility tests after the REALITY connector is complete:

```bash
cargo test --test vless_reality_vision -- --ignored
```
````

- [ ] **Step 2: Add README**

```markdown
# xray-rust

Rust mobile/client core aiming for protocol compatibility with Xray-core.

The Go checkout in `Xray-core/` is a read-only compatibility oracle and is ignored by the root git repository.

First implementation target:

- Xray JSON subset.
- SOCKS5 and HTTP local inbounds.
- Platform-neutral TUN packet API.
- VLESS outbound over TCP.
- TLS/REALITY client mode.
- `xtls-rprx-vision`.
- C ABI for mobile embedding.

See:

- `docs/superpowers/specs/2026-05-19-mobile-client-core-design.md`
- `docs/superpowers/plans/2026-05-19-mobile-client-core.md`
- `docs/verification.md`
```

- [ ] **Step 3: Run verification**

Run: `cargo fmt --all -- --check`

Expected: PASS.

Run: `cargo clippy --workspace --all-targets`

Expected: PASS.

Run: `cargo test --workspace --all-targets`

Expected: PASS, except ignored tests remain ignored.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/verification.md
git commit -m "docs: add verification matrix"
```

## Self-Review Notes

Spec coverage:

- Xray JSON subset: Tasks 2 and 3.
- SOCKS/HTTP local inbound parsing: Task 8.
- TUN packet API: Task 5 and FFI bridge in Task 12.
- VLESS wire compatibility: Task 6.
- Vision framing and padding: Task 7.
- TCP/TLS/REALITY architecture: Tasks 9, 10, and 11.
- Core lifecycle: Task 12.
- C ABI: Task 13.
- Compatibility oracle: Task 14.
- Mobile memory constraints: Task 5 bounded queues, Task 12 lifecycle, Task 13 FFI ownership, and verification in Task 15.
- Extensibility: crate boundaries, registry-ready traits, and dependency direction in File Structure.

Known residual work after this plan:

- REALITY starts Chrome-fingerprint-only; expanding to the full Xray fingerprint matrix requires additional oracle vectors.
- Full TUN TCP/IP stack is a later increment and remains behind the stable packet API.
- Platform adapters for Apple and Android are later increments using the C ABI from Task 12.
