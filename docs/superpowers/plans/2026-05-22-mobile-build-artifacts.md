# Mobile Build Artifacts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add reproducible mobile artifact entrypoints for Apple iOS/tvOS XCFramework packaging and Android shared library packaging.

**Architecture:** Keep packaging outside Rust crates in `scripts/`. Keep the C ABI declaration in `crates/xray-ffi/include/xray_ffi.h`, versioned with the Rust FFI implementation. Tests assert target matrices and exported ABI names so mobile support does not silently regress.

**Tech Stack:** Bash, Cargo target builds, `xcodebuild -create-xcframework`, Android target-to-ABI copying, Rust integration tests for artifact contract.

---

## Files

- Create: `crates/xray-ffi/include/xray_ffi.h`
- Create: `scripts/build-apple-xcframework.sh`
- Create: `scripts/build-android-libs.sh`
- Create: `crates/xray-ffi/tests/mobile_artifacts_tests.rs`

## Task 1: Artifact Contract Tests

- [x] **Step 1: Write failing tests**

Add tests that assert:

- `xray_ffi.h` exists and declares lifecycle, error, and TUN functions.
- Apple script contains iOS, iOS simulator, tvOS, and tvOS simulator Rust targets.
- Apple script invokes `xcodebuild -create-xcframework`.
- Android script contains Android Rust targets and JNI ABI output directories.

- [x] **Step 2: Run red tests**

Run:

```bash
cargo test -p xray-ffi --test mobile_artifacts_tests
```

Expected: tests fail because the scripts and header do not exist.

## Task 2: Header And Scripts

- [x] **Step 1: Add C header**

Create `crates/xray-ffi/include/xray_ffi.h` with stable C declarations for:

- `XrayStatus`
- `XrayTunStats`
- opaque `XrayCoreHandle`
- opaque `XrayError`
- lifecycle functions
- error accessors
- TUN packet functions

- [x] **Step 2: Add Apple XCFramework script**

Create `scripts/build-apple-xcframework.sh` that builds `xray-ffi` static libraries for:

- `aarch64-apple-ios`
- `aarch64-apple-ios-sim`
- `x86_64-apple-ios`
- `aarch64-apple-tvos`
- `aarch64-apple-tvos-sim`
- `x86_64-apple-tvos`

It should combine simulator slices with `lipo` and create an XCFramework using `xcodebuild -create-xcframework`.

- [x] **Step 3: Add Android script**

Create `scripts/build-android-libs.sh` that builds/copies `libxray_ffi.so` for:

- `aarch64-linux-android` -> `arm64-v8a`
- `armv7-linux-androideabi` -> `armeabi-v7a`
- `i686-linux-android` -> `x86`
- `x86_64-linux-android` -> `x86_64`

- [x] **Step 4: Run tests green**

Run:

```bash
cargo test -p xray-ffi --test mobile_artifacts_tests
```

Expected: all artifact contract tests pass.

## Task 3: Verification And Commit

- [x] **Step 1: Shell syntax check**

Run:

```bash
bash -n scripts/build-apple-xcframework.sh
bash -n scripts/build-android-libs.sh
```

Expected: exit code 0.

- [x] **Step 2: FFI tests**

Run:

```bash
cargo test -p xray-ffi --all-targets
```

Expected: all tests pass when loopback sockets are permitted.

- [x] **Step 3: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-05-22-mobile-build-artifacts.md crates/xray-ffi/include/xray_ffi.h scripts/build-apple-xcframework.sh scripts/build-android-libs.sh crates/xray-ffi/tests/mobile_artifacts_tests.rs
git commit -m "build(mobile): add ffi artifact scripts"
```

Expected: one commit containing mobile artifact packaging entrypoints.
