# Runnable Core Binary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first runnable `xray-rust` binary with `run -config config.json`, graceful shutdown, and process-level interop coverage.

**Architecture:** Add a focused `crates/xray-cli` workspace member. Keep protocol behavior in `xray-core-rs`; the CLI only parses args, loads config, starts `Core`, prints bound inbounds, waits for shutdown, and stops the core. Integration tests spawn the binary as a process and reuse local Xray as the upstream server.

**Tech Stack:** Rust 2021, Tokio, thiserror, existing `xray-config` and `xray-core-rs`.

---

## File Structure

- Create `crates/xray-cli/Cargo.toml`: binary crate manifest.
- Create `crates/xray-cli/src/lib.rs`: `CliArgs`, `CliError`, config loading, `run_with_shutdown`, and small output helpers.
- Create `crates/xray-cli/src/main.rs`: process entrypoint that calls the library and maps errors to exit code `1`.
- Create `crates/xray-cli/tests/cli_args_tests.rs`: parser and config-load tests.
- Create `crates/xray-cli/tests/process_interop_tests.rs`: ignored process-level interop tests.
- Modify `Cargo.toml`: add workspace member and enable Tokio `signal` feature.

## Task 1: CLI Argument Contract

**Files:**
- Create: `crates/xray-cli/Cargo.toml`
- Create: `crates/xray-cli/src/lib.rs`
- Create: `crates/xray-cli/tests/cli_args_tests.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Write failing parser tests**

Create `crates/xray-cli/tests/cli_args_tests.rs`:

```rust
use std::path::PathBuf;

use xray_cli::{parse_cli_args, CliArgs, CliError};

#[test]
fn parses_run_dash_config() {
    let args = parse_cli_args(["xray-rust", "run", "-config", "client.json"]).unwrap();

    assert_eq!(
        args,
        CliArgs::Run {
            config_path: PathBuf::from("client.json")
        }
    );
}

#[test]
fn parses_run_double_dash_config() {
    let args = parse_cli_args(["xray-rust", "run", "--config", "client.json"]).unwrap();

    assert_eq!(
        args,
        CliArgs::Run {
            config_path: PathBuf::from("client.json")
        }
    );
}

#[test]
fn rejects_unknown_command() {
    let error = parse_cli_args(["xray-rust", "version"]).unwrap_err();

    assert!(matches!(
        error,
        CliError::InvalidArguments(message) if message.contains("usage:")
    ));
}

#[test]
fn rejects_missing_config_path() {
    let error = parse_cli_args(["xray-rust", "run", "-config"]).unwrap_err();

    assert!(matches!(
        error,
        CliError::InvalidArguments(message) if message.contains("missing config path")
    ));
}
```

- [ ] **Step 2: Add minimal crate manifest and workspace member**

Modify root `Cargo.toml`:

```toml
members = [
    "crates/xray-config",
    "crates/xray-routing",
    "crates/xray-tun",
    "crates/xray-proxy",
    "crates/xray-transport",
    "crates/xray-runtime",
    "crates/xray-core-rs",
    "crates/xray-ffi",
    "crates/xray-cli",
]
```

Create `crates/xray-cli/Cargo.toml`:

```toml
[package]
name = "xray-cli"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "xray-rust"
path = "src/main.rs"

[dependencies]
thiserror.workspace = true
tokio.workspace = true
xray-config = { path = "../xray-config" }
xray-core-rs = { path = "../xray-core-rs" }
```

- [ ] **Step 3: Verify RED**

Run:

```bash
cargo test -p xray-cli --test cli_args_tests
```

Expected: compile failure because `crates/xray-cli/src/lib.rs` and exported items do not exist.

- [ ] **Step 4: Implement minimal parser and errors**

Create `crates/xray-cli/src/lib.rs`:

```rust
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliArgs {
    Run { config_path: PathBuf },
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    InvalidArguments(String),
}

pub fn parse_cli_args<I, S>(args: I) -> Result<CliArgs, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let usage = "usage: xray-rust run -config <config.json>";

    match args.as_slice() {
        [_program, command, flag, config_path]
            if command == "run" && (flag == "-config" || flag == "--config") =>
        {
            Ok(CliArgs::Run {
                config_path: PathBuf::from(config_path),
            })
        }
        [_program, command, flag] if command == "run" && (flag == "-config" || flag == "--config") => {
            Err(CliError::InvalidArguments(format!(
                "missing config path\n{usage}"
            )))
        }
        [_program, ..] => Err(CliError::InvalidArguments(usage.to_owned())),
        [] => Err(CliError::InvalidArguments(usage.to_owned())),
    }
}
```

Create temporary `crates/xray-cli/src/main.rs`:

```rust
fn main() {}
```

- [ ] **Step 5: Verify GREEN**

Run:

```bash
cargo test -p xray-cli --test cli_args_tests
```

Expected: 4 parser tests pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/xray-cli
git commit -m "feat(cli): add run argument parser"
```

## Task 2: Config Loading And Core Lifecycle Library

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/xray-cli/src/lib.rs`
- Modify: `crates/xray-cli/tests/cli_args_tests.rs`

- [ ] **Step 1: Write failing config and lifecycle tests**

Append to `crates/xray-cli/tests/cli_args_tests.rs`:

```rust
use std::fs;
use std::net::SocketAddr;

use tokio::sync::oneshot;
use xray_cli::{format_bound_inbounds, load_config, run_with_shutdown};

#[test]
fn load_config_reports_json_parse_diagnostics() {
    let temp_dir = std::env::temp_dir().join(format!(
        "xray-cli-invalid-config-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let config_path = temp_dir.join("bad.json");
    fs::write(&config_path, "{").unwrap();

    let error = load_config(&config_path).unwrap_err().to_string();

    assert!(error.contains("config parse failed"));
    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn format_bound_inbounds_includes_tag_and_address() {
    let rendered = format_bound_inbounds(&[(
        Some("socks-in".to_owned()),
        "127.0.0.1:1080".parse::<SocketAddr>().unwrap(),
    )]);

    assert_eq!(rendered, "bound inbound socks-in at 127.0.0.1:1080");
}

#[tokio::test]
async fn run_with_shutdown_starts_and_stops_core() {
    let temp_dir = std::env::temp_dir().join(format!(
        "xray-cli-runtime-config-{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let config_path = temp_dir.join("client.json");
    fs::write(
        &config_path,
        r#"{
          "inbounds": [
            { "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0 }
          ],
          "outbounds": [
            {
              "tag": "proxy",
              "protocol": "vless",
              "settings": {
                "vnext": [
                  {
                    "address": "127.0.0.1",
                    "port": 443,
                    "users": [
                      { "id": "00010203-0405-0607-0809-0a0b0c0d0e0f", "encryption": "none" }
                    ]
                  }
                ]
              },
              "streamSettings": { "network": "tcp" }
            }
          ]
        }"#,
    )
    .unwrap();
    let config = load_config(&config_path).unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let result = run_with_shutdown(config, async move {
        shutdown_tx.send(()).unwrap();
        shutdown_rx.await.unwrap();
    })
    .await;

    assert!(result.is_ok());
    let _ = fs::remove_dir_all(temp_dir);
}
```

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo test -p xray-cli --test cli_args_tests
```

Expected: compile failure for missing `load_config`, `format_bound_inbounds`, or `run_with_shutdown`.

- [ ] **Step 3: Enable Tokio signal feature**

Modify root `Cargo.toml` workspace `tokio` dependency:

```toml
tokio = { version = "1", features = ["io-util", "macros", "net", "rt", "rt-multi-thread", "signal", "sync", "time"] }
```

- [ ] **Step 4: Implement config loading and lifecycle**

Replace `crates/xray-cli/src/lib.rs` with the parser from Task 1 plus:

```rust
use std::{fs, future::Future, net::SocketAddr, path::{Path, PathBuf}};

use thiserror::Error;
use xray_config::{parse_xray_json, CoreConfig, Diagnostic};
use xray_core_rs::{Core, CoreError};

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    InvalidArguments(String),
    #[error("failed to read config `{path}`: {source}")]
    ReadConfig {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("config parse failed: {0}")]
    ConfigParse(String),
    #[error("core error: {0}")]
    Core(#[from] CoreError),
}

pub fn load_config(path: &Path) -> Result<CoreConfig, CliError> {
    let raw = fs::read_to_string(path).map_err(|source| CliError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed = parse_xray_json(&raw)
        .map_err(|error| CliError::ConfigParse(format_diagnostics(&error.diagnostics)))?;
    Ok(parsed.config)
}

fn format_diagnostics(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| match &diagnostic.path {
            Some(path) => format!("{path}: {}", diagnostic.message),
            None => diagnostic.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn format_bound_inbounds(inbounds: &[(Option<String>, SocketAddr)]) -> String {
    inbounds
        .iter()
        .map(|(tag, addr)| {
            let tag = tag.as_deref().unwrap_or("<untagged>");
            format!("bound inbound {tag} at {addr}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub async fn run_with_shutdown<F>(config: CoreConfig, shutdown: F) -> Result<(), CliError>
where
    F: Future<Output = ()>,
{
    let mut core = Core::new(config)?;
    core.start().await?;
    shutdown.await;
    core.stop().await?;
    Ok(())
}
```

Keep `parse_cli_args` and `CliArgs` from Task 1 in the same file.

- [ ] **Step 5: Verify GREEN**

Run:

```bash
cargo test -p xray-cli --test cli_args_tests
```

Expected: parser, load, formatting, and lifecycle tests pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/xray-cli
git commit -m "feat(cli): load config and run core lifecycle"
```

## Task 3: Process Entrypoint

**Files:**
- Modify: `crates/xray-cli/src/main.rs`
- Modify: `crates/xray-cli/src/lib.rs`
- Test: `crates/xray-cli/tests/cli_args_tests.rs`

- [ ] **Step 1: Write failing main helper test**

Append to `crates/xray-cli/tests/cli_args_tests.rs`:

```rust
use xray_cli::run_cli_with_shutdown;

#[tokio::test]
async fn run_cli_with_shutdown_rejects_missing_config() {
    let result = run_cli_with_shutdown(["xray-rust", "run", "-config"], async {}).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing config path"));
}
```

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo test -p xray-cli --test cli_args_tests run_cli_with_shutdown_rejects_missing_config
```

Expected: compile failure for missing `run_cli_with_shutdown`.

- [ ] **Step 3: Implement CLI runner and process main**

Add to `crates/xray-cli/src/lib.rs`:

```rust
pub async fn run_cli_with_shutdown<I, S, F>(args: I, shutdown: F) -> Result<(), CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    F: Future<Output = ()>,
{
    match parse_cli_args(args)? {
        CliArgs::Run { config_path } => {
            let config = load_config(&config_path)?;
            run_with_shutdown(config, shutdown).await
        }
    }
}
```

Replace `crates/xray-cli/src/main.rs`:

```rust
#[tokio::main]
async fn main() {
    if let Err(error) = xray_cli::run_cli_with_shutdown(std::env::args(), async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to wait for shutdown signal: {error}");
        }
    })
    .await
    {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
```

- [ ] **Step 4: Verify GREEN**

Run:

```bash
cargo test -p xray-cli --test cli_args_tests run_cli_with_shutdown_rejects_missing_config
```

Expected: test passes.

- [ ] **Step 5: Build binary**

Run:

```bash
cargo build -p xray-cli --bin xray-rust
```

Expected: binary builds.

- [ ] **Step 6: Commit**

```bash
git add crates/xray-cli
git commit -m "feat(cli): add xray-rust process entrypoint"
```

## Task 4: Process-Level Interop Tests

**Files:**
- Create: `crates/xray-cli/tests/process_interop_tests.rs`

- [ ] **Step 1: Write ignored process interop tests**

Create `crates/xray-cli/tests/process_interop_tests.rs` with helpers modeled after `crates/xray-core-rs/tests/local_xray_interop_tests.rs`. The tests must:

```rust
#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, xray-rust binary, and loopback process execution"]
async fn xray_rust_process_reaches_echo_server_through_local_xray_vless_tcp() {
    // spawn local Xray VLESS/TCP server
    // write xray-rust client config with SOCKS inbound port 0 and VLESS TCP outbound
    // spawn env!("CARGO_BIN_EXE_xray-rust") run -config client.json
    // wait until stderr prints "bound inbound socks-in at ..."
    // connect SOCKS client and verify echo
}

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, xray-rust binary, and loopback process execution"]
async fn xray_rust_process_reaches_echo_server_through_local_xray_vless_reality_vision() {
    // same as above, but Xray server uses REALITY and client config uses REALITY+Vision
}
```

Use a plain stderr log file and parse the bound SOCKS address from the startup line. Terminate the child with `kill()` in `Drop`.

- [ ] **Step 2: Verify RED**

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-cli --test process_interop_tests -- --ignored --nocapture
```

Expected: fail before helper implementation or before the binary prints bound inbound lines.

- [ ] **Step 3: Implement startup output**

Update `run_with_shutdown` in `crates/xray-cli/src/lib.rs` to collect bound inbounds after `core.start().await?`:

```rust
let bound = config
    .inbounds
    .iter()
    .filter_map(|inbound| {
        core.inbound_addr(inbound.tag.as_deref())
            .map(|addr| (inbound.tag.clone(), addr))
    })
    .collect::<Vec<_>>();
if !bound.is_empty() {
    eprintln!("{}", format_bound_inbounds(&bound));
}
```

Clone the config before constructing the core if needed for this iteration.

- [ ] **Step 4: Implement process interop helpers**

Copy only the required helper shape from the core interop test:

- `TempDir`
- `XrayServer`
- `allocate_loopback_port`
- `start_xray_vless_server`
- `write_xray_vless_config`
- `write_xray_rust_client_config`
- `spawn_xray_rust`
- `wait_for_xray_rust_socks_addr`
- `spawn_echo_server`
- `socks5_connect`

Keep supported process-level cases to VLESS TCP and VLESS REALITY+Vision.

- [ ] **Step 5: Verify process interop GREEN**

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-cli --test process_interop_tests -- --ignored --nocapture
```

Expected: 2 ignored process interop tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/xray-cli
git commit -m "test(cli): add process interop coverage"
```

## Task 5: Final Verification

**Files:**
- Whole workspace touched by this milestone.

- [ ] **Step 1: Format check**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exit 0.

- [ ] **Step 2: CLI tests**

Run:

```bash
cargo test -p xray-cli --all-targets
```

Expected: non-ignored tests pass; process interop tests are ignored by default.

- [ ] **Step 3: Core and transport regression tests**

Run:

```bash
cargo test -p xray-transport reality
cargo test -p xray-core-rs --all-targets
cargo test -p xray-proxy --test vless_response_stream_tests
```

Expected: all pass.

- [ ] **Step 4: Process interop**

Run:

```bash
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-cli --test process_interop_tests -- --ignored --nocapture
```

Expected: VLESS TCP and REALITY+Vision pass through spawned `xray-rust`.

- [ ] **Step 5: Clippy**

Run:

```bash
cargo clippy -p xray-cli -p xray-transport -p xray-proxy -p xray-core-rs --all-targets --locked -- -D warnings
```

Expected: exit 0.

- [ ] **Step 6: Final commit if needed**

If verification fixes changed files:

```bash
git add .
git commit -m "chore(cli): finalize runnable core binary"
```

If no files changed, leave the branch clean.

## Self-Review

- Spec coverage: CLI contract, lifecycle, errors, tests, and future mobile boundary are covered by Tasks 1-5.
- Placeholder scan: no unresolved placeholders remain; Task 4 deliberately describes helper responsibilities because copying the whole existing harness into the plan would obscure the test goal.
- Scope check: one binary crate plus tests; no protocol expansion, mobile FFI, hot reload, service mode, or TUN work.
