# Mobile FFI Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the proven core lifecycle through the C ABI so mobile hosts can create, load, start, stop, and free an embedded core without invoking the CLI process.

**Architecture:** Keep FFI as a thin ownership and error boundary over `xray_core_rs::Core`. Store a Tokio multi-thread runtime inside each `XrayCoreHandle` so async core tasks keep running after `xray_core_start` returns. Convert panics and runtime failures into stable `XrayStatus` values and `XrayError` objects.

**Tech Stack:** Rust, C ABI (`extern "C"`), Tokio runtime, existing `xray-config` and `xray-core-rs` crates.

---

## Files

- Modify: `crates/xray-ffi/Cargo.toml`
  - Add direct `tokio` dependency from the workspace.
- Modify: `crates/xray-ffi/src/lib.rs`
  - Extend status codes.
  - Add runtime ownership to `XrayCoreHandle`.
  - Add `xray_core_start` and `xray_core_stop`.
  - Add panic-safe status boundary for fallible FFI calls.
- Modify: `crates/xray-ffi/tests/ffi_tests.rs`
  - Add lifecycle tests for start/stop and unloaded-handle errors.

## Task 1: Start/Stop ABI Tests

**Files:**
- Modify: `crates/xray-ffi/tests/ffi_tests.rs`

- [x] **Step 1: Write failing tests**

Add tests with this behavior:

```rust
#[test]
fn ffi_start_reports_unloaded_core() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };

    let status = unsafe { xray_core_start(core, &mut err) };

    assert_eq!(status, XrayStatus::CoreNotLoaded);
    assert_error(&mut err, XrayStatus::CoreNotLoaded, "core config is not loaded");

    unsafe { xray_core_free(core) };
}

#[test]
fn ffi_starts_and_stops_loaded_core() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    let raw = CString::new(client_config_with_ephemeral_socks_port()).unwrap();

    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    assert_eq!(unsafe { xray_core_start(core, &mut err) }, XrayStatus::Ok);
    assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);

    unsafe { xray_core_free(core) };
}
```

- [x] **Step 2: Run red tests**

Run:

```bash
cargo test -p xray-ffi --test ffi_tests
```

Expected: compilation fails because `xray_core_start`, `xray_core_stop`, and `CoreNotLoaded` do not exist.

## Task 2: Runtime-Owned Handle

**Files:**
- Modify: `crates/xray-ffi/Cargo.toml`
- Modify: `crates/xray-ffi/src/lib.rs`

- [x] **Step 1: Add runtime to handle**

Implement a handle shape equivalent to:

```rust
pub struct XrayCoreHandle {
    core: Option<Core>,
    runtime: tokio::runtime::Runtime,
}
```

Build the runtime in `xray_core_new`; return null and set an error if runtime creation fails.

- [x] **Step 2: Add lifecycle functions**

Implement:

```rust
#[no_mangle]
pub unsafe extern "C" fn xray_core_start(
    handle: *mut XrayCoreHandle,
    error: *mut *mut XrayError,
) -> XrayStatus

#[no_mangle]
pub unsafe extern "C" fn xray_core_stop(
    handle: *mut XrayCoreHandle,
    error: *mut *mut XrayError,
) -> XrayStatus
```

Both functions clear the previous error, reject null handles, reject unloaded handles, and use `runtime.block_on(...)` for `Core::start` and `Core::stop`.

- [x] **Step 3: Run lifecycle tests green**

Run:

```bash
cargo test -p xray-ffi --test ffi_tests
```

Expected: all FFI tests pass when loopback sockets are permitted.

## Task 3: Verification And Commit

**Files:**
- Verify all modified files.

- [x] **Step 1: Format**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exit code 0.

- [x] **Step 2: Test FFI crate**

Run:

```bash
cargo test -p xray-ffi --all-targets
```

Expected: all tests pass when loopback sockets are permitted.

- [x] **Step 3: Clippy**

Run:

```bash
cargo clippy -p xray-ffi --all-targets --locked -- -D warnings
```

Expected: exit code 0.

- [x] **Step 4: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-22-mobile-ffi-lifecycle.md crates/xray-ffi/Cargo.toml crates/xray-ffi/src/lib.rs crates/xray-ffi/tests/ffi_tests.rs
git commit -m "feat(ffi): expose core lifecycle"
```

Expected: one commit containing the FFI lifecycle ABI.
