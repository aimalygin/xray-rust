# Mobile FD TUN Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional fd-backed mobile TUN backend alongside the existing packet pump backend.

**Architecture:** Keep `xray-core-rs` routing and TUN packet processing unchanged by feeding the existing `TunEndpoint` from a new fd bridge in `xray-ffi`. Mobile adapters choose packet-pump or fd-backed mode explicitly.

**Tech Stack:** Rust, Tokio `AsyncFd`, C ABI, Swift Package adapter, Android Kotlin/JNI adapter.

---

### Task 1: RED Tests And ABI Surface

**Files:**
- Modify: `crates/xray-ffi/tests/ffi_tests.rs`
- Modify: `crates/xray-ffi/tests/mobile_artifacts_tests.rs`
- Modify: `crates/xray-ffi/include/xray_ffi.h`

- [ ] Add tests for `xray_core_set_tun_fd`, fd-backed ICMP echo, and exported symbols.
- [ ] Run `cargo test -p xray-ffi --test ffi_tests ffi_registers_tun_fd_before_config_load`.
- [ ] Confirm the test fails because the new ABI does not exist.

### Task 2: Rust FD Backend

**Files:**
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-ffi/src/lib.rs`
- Create: `crates/xray-ffi/src/tun_fd.rs`

- [ ] Add `Core::tun_handle()` returning `Arc<TunEndpoint>`.
- [ ] Add `XrayTunFdPacketFormat`, `XrayTunFdClosePolicy`, `xray_core_set_tun_fd`.
- [ ] Implement Unix fd bridge with nonblocking `AsyncFd`.
- [ ] Keep non-Unix builds compiling with a clear runtime error.
- [ ] Start fd bridge after core start, stop it before core stop/free.

### Task 3: Mobile Adapter Options

**Files:**
- Modify: `platform/apple/Sources/XrayMobileAdapter/XrayCore.swift`
- Create: `platform/apple/Sources/XrayMobileAdapter/XrayDarwinTunFileDescriptor.swift`
- Modify: `platform/apple/README.md`
- Modify: `platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt`
- Modify: `platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayVpnService.kt`
- Modify: `platform/android/xraymobile/src/main/cpp/xray_mobile_jni.cpp`
- Modify: `platform/android/README.md`

- [ ] Add Swift init options for fd-backed TUN.
- [ ] Add Darwin utun fd discovery helper.
- [ ] Add Android backend enum and JNI bridge to `xray_core_set_tun_fd`.
- [ ] Keep packet-pump mode as default.

### Task 4: Verification

**Files:**
- Modify: `docs/mobile-testing.md`
- Modify: `README.md`

- [ ] Document both mobile TUN backend options.
- [ ] Run focused FFI and mobile artifact tests.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy -p xray-ffi -p xray-core-rs --all-targets --locked -- -D warnings`.
- [ ] Run `cargo test --workspace --all-targets`.
- [ ] Commit the completed feature.
