# Xray File Debug Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Xray-core-style access/error file logging for diagnostics while keeping the disabled path free of file I/O, background workers, and message formatting.

**Architecture:** A per-core Rust runtime logger owns optional access/error file sinks and exposes lazy logging methods. The FFI stores file log options before config load, then installs the logger on the loaded `Core`. Apple tunnel code enables file logging only when existing debug logging is enabled and passes an app-container log directory to FFI.

**Tech Stack:** Rust standard library, Tokio runtime already present, `xray-core-rs`, `xray-ffi`, Swift `Foundation`, existing Apple package tests.

---

## Files

- Create: `crates/xray-core-rs/src/runtime_log.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/src/startup_probe.rs`
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/src/tun.rs`
- Modify: `crates/xray-ffi/src/lib.rs`
- Modify: `crates/xray-ffi/include/xray_ffi.h`
- Modify: `crates/xray-ffi/tests/ffi_tests.rs`
- Modify: `crates/xray-ffi/tests/mobile_artifacts_tests.rs`
- Modify: `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift`
- Modify: `platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift`
- Modify: `platform/apple/Tests/XrayMobileAdapterTests/XrayPacketTunnelPumpTests.swift`
- Modify: `platform/apple/Tests/XrayAppleTunnelTests/XrayPacketTunnelProviderTests.swift`

### Task 1: Rust Runtime Logger

- [ ] **Step 1: Write failing Rust tests**

Add tests in `crates/xray-core-rs/src/runtime_log.rs`:

```rust
#[test]
fn disabled_logger_does_not_evaluate_message_closure() {
    let logger = RuntimeLogger::disabled();
    let evaluated = AtomicBool::new(false);

    logger.debug(|| {
        evaluated.store(true, Ordering::SeqCst);
        "should not be built".to_owned()
    });

    assert!(!evaluated.load(Ordering::SeqCst));
}

#[test]
fn enabled_logger_writes_debug_and_access_files() {
    let dir = unique_temp_dir("xray-runtime-log");
    let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir)).unwrap();

    logger.debug(|| "Debug routeDecision target=example.com:443".to_owned());
    logger.access(|| "from 10.0.0.2:49152 accepted example.com:443 proxy".to_owned());

    drop(logger);

    assert!(std::fs::read_to_string(dir.join("xray-error.log")).unwrap().contains("Debug routeDecision"));
    assert!(std::fs::read_to_string(dir.join("xray-access.log")).unwrap().contains("accepted example.com:443"));
}
```

- [ ] **Step 2: Run red test**

Run: `cargo test -p xray-core-rs runtime_log --lib`

Expected: compile failure because `runtime_log` and `RuntimeLogger` do not exist.

- [ ] **Step 3: Implement minimal logger**

Create `runtime_log.rs` with `RuntimeLogConfig`, `RuntimeLogger::disabled`, `RuntimeLogger::new`, `is_enabled`, `debug`, `error`, and `access`. Use `OpenOptions::append(true).create(true)`, `Mutex<BufWriter<File>>`, and closure-based formatting.

- [ ] **Step 4: Run green test**

Run: `cargo test -p xray-core-rs runtime_log --lib`

Expected: tests pass.

### Task 2: Core Integration And Startup Probe Logs

- [ ] **Step 1: Write failing tests**

Add a test in `crates/xray-core-rs/src/lib.rs` that installs `RuntimeLogger::disabled()` and verifies the core exposes `runtime_logger().is_enabled() == false`; add a startup probe formatting test in `startup_probe.rs` for start/fail lines.

- [ ] **Step 2: Run red test**

Run: `cargo test -p xray-core-rs runtime_logger startup_probe --lib`

Expected: failure because `Core::set_runtime_logger`, `Core::runtime_logger`, and probe logging hooks do not exist.

- [ ] **Step 3: Implement core logger field**

Add `runtime_logger: RuntimeLogger` to `Core`, default disabled, `set_runtime_logger`, and `runtime_logger`. Pass clones into inbound tasks and startup probe boundaries. Log probe start/success/fail to error log only when enabled.

- [ ] **Step 4: Run green test**

Run: `cargo test -p xray-core-rs runtime_logger startup_probe --lib`

Expected: tests pass.

### Task 3: Route And Flow Diagnostics

- [ ] **Step 1: Write failing tests**

Extend existing route-decision tests so the runtime logger receives a line containing `Debug routeDecision`, `original_target`, `sniffed_domain`, `dial_target`, and `selected_outbound`. Add tests for access-line helpers for TCP/UDP accepted/rejected outcomes.

- [ ] **Step 2: Run red test**

Run: `cargo test -p xray-core-rs route_decision runtime_log --lib`

Expected: failure because runtime route/access logging is not connected.

- [ ] **Step 3: Implement runtime logging at boundaries**

Replace debug-only `eprintln!` route logging with runtime logger calls. Log accepted/rejected access events at TCP/UDP open boundaries and error log lines for UDP/443 rejection, QUIC blocked packets, UDP response gaps, TCP flow summaries, and TCP open errors.

- [ ] **Step 4: Run green test**

Run: `cargo test -p xray-core-rs route_decision runtime_log --lib`

Expected: tests pass.

### Task 4: FFI API

- [ ] **Step 1: Write failing FFI tests**

In `crates/xray-ffi/tests/ffi_tests.rs`, add tests that call:

```rust
xray_core_set_file_logging(core, log_dir.as_ptr(), 1, &mut err)
```

and assert invalid null path returns `NullArgument`, invalid UTF-8 returns `InvalidUtf8`, and a valid directory lets config load.

- [ ] **Step 2: Run red test**

Run: `cargo test -p xray-ffi xray_core_set_file_logging`

Expected: compile failure because the FFI function is missing.

- [ ] **Step 3: Implement FFI**

Add `xray_core_set_file_logging(handle, log_dir, debug_enabled, error)` to Rust and C header. Store `Option<RuntimeLogConfig>` on `XrayCoreHandle`; when loading config, create `RuntimeLogger` only when `debug_enabled != 0` and install it into `Core`.

- [ ] **Step 4: Run green test**

Run: `cargo test -p xray-ffi xray_core_set_file_logging`

Expected: tests pass.

### Task 5: Apple Integration

- [ ] **Step 1: Write failing Swift tests**

In `XrayPacketTunnelProviderTests`, test that `debugLoggingEnabled == false` resolves no file log directory and `debugLoggingEnabled == true` resolves a non-empty diagnostics directory path. In `XrayPacketTunnelPumpTests`, add an adapter init test that accepts `fileLogDirectory: nil`.

- [ ] **Step 2: Run red test**

Run: `swift test --package-path platform/apple --filter XrayPacketTunnelProviderTests`

Expected: failure because file log directory resolution is missing.

- [ ] **Step 3: Implement Swift wiring**

Add optional `fileLogDirectory: URL?` to `XrayCore` initializers and call FFI only when non-nil. In `XrayPacketTunnelProvider`, create a `Library/Caches/XrayRustLogs` directory only when debug logging is enabled and pass it to `XrayCore`.

- [ ] **Step 4: Run green test**

Run: `swift test --package-path platform/apple --filter XrayPacketTunnelProviderTests`

Expected: tests pass.

### Task 6: Verification

- [ ] Run `cargo test -p xray-core-rs runtime_log startup_probe route_decision --lib`.
- [ ] Run `cargo test -p xray-ffi xray_core_set_file_logging`.
- [ ] Run `cargo test -p xray-ffi mobile_artifacts`.
- [ ] Run `swift test --package-path platform/apple --filter XrayMobileAdapterTests`.
- [ ] Run `swift test --package-path platform/apple --filter XrayAppleTunnelTests`.
- [ ] Inspect `git diff --stat` and ensure unrelated dirty files were not modified.
