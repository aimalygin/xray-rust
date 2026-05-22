# Mobile Test Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the current FFI/mobile artifact surface ready for first iOS, tvOS, and Android device harness testing.

**Architecture:** Keep mobile packaging in scripts and keep the FFI crate as the only C ABI owner. Add host preflight checks that report missing Rust targets, SDKs, and Android NDK state before expensive cross-builds, plus a C header harness test that validates the public ABI can be included and linked from C.

**Tech Stack:** Rust integration tests, C compiler smoke harness, Bash preflight script, Cargo staticlib build, Apple SDK discovery, Android NDK environment discovery.

---

### Task 1: C ABI Header Harness

**Files:**
- Modify: `crates/xray-ffi/tests/mobile_artifacts_tests.rs`

- [ ] **Step 1: Write the failing test**

Add a test that writes a tiny C file including `xray_ffi.h`, calls every exported lifecycle/error/TUN declaration, and compiles it with `cc -c`.

- [ ] **Step 2: Run test to verify it fails before implementation**

Run: `cargo test -p xray-ffi --test mobile_artifacts_tests ffi_header_compiles_as_c_harness -- --nocapture`

Expected: FAIL until the helper that writes and compiles the harness exists.

- [ ] **Step 3: Implement the harness helper**

Use `std::process::Command` and write the temporary C file under `target/mobile/harness`. The command must include `-I crates/xray-ffi/include` and compile only to an object file so it does not require a full platform link.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p xray-ffi --test mobile_artifacts_tests ffi_header_compiles_as_c_harness -- --nocapture`

Expected: PASS.

### Task 2: Exported Symbol Smoke Test

**Files:**
- Modify: `crates/xray-ffi/tests/mobile_artifacts_tests.rs`

- [ ] **Step 1: Write the failing test**

Add a test that builds `xray-ffi` as a native staticlib release artifact and checks the exported symbols with `nm`.

- [ ] **Step 2: Run test to verify it fails before implementation**

Run: `cargo test -p xray-ffi --test mobile_artifacts_tests native_staticlib_exports_mobile_abi_symbols -- --nocapture`

Expected: FAIL until the helper builds and inspects the library.

- [ ] **Step 3: Implement the symbol check**

Run `cargo build -p xray-ffi --release`, inspect `target/release/libxray_ffi.a` with `nm -g`, and assert exported names for core lifecycle, errors, and TUN functions.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p xray-ffi --test mobile_artifacts_tests native_staticlib_exports_mobile_abi_symbols -- --nocapture`

Expected: PASS.

### Task 3: Mobile Toolchain Preflight

**Files:**
- Create: `scripts/check-mobile-toolchains.sh`
- Modify: `crates/xray-ffi/tests/mobile_artifacts_tests.rs`

- [ ] **Step 1: Write the failing test**

Add a script-contract test that checks the preflight script mentions all Apple, tvOS, and Android Rust targets, uses `rustup target list --installed`, checks Apple SDKs with `xcrun`, and checks Android NDK variables.

- [ ] **Step 2: Run test to verify it fails before implementation**

Run: `cargo test -p xray-ffi --test mobile_artifacts_tests mobile_toolchain_preflight_script_covers_required_targets`

Expected: FAIL while the script is absent.

- [ ] **Step 3: Implement the script**

Create a Bash script that prints `OK`, `MISSING`, or `INFO` lines for:

- Rust Apple targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-apple-tvos`, `aarch64-apple-tvos-sim`, `x86_64-apple-tvos`.
- Rust Android targets: `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android`.
- Commands: `cargo`, `rustc`, `rustup`, `xcodebuild`, `xcrun`, `lipo`.
- SDKs: `iphoneos`, `iphonesimulator`, `appletvos`, `appletvsimulator`.
- Android NDK discovery through `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, `ANDROID_HOME/ndk`, `$HOME/Library/Android/sdk/ndk`, or `$HOME/Android/Sdk/ndk`.
- tvOS fallback through `TVOS_BUILD_STD=auto`, `TVOS_RUST_TOOLCHAIN=nightly`, and `rust-src` when stable has no rustup-backed tvOS std targets.

The script exits `0` when all required checks pass and `1` when required checks are missing. Android NDK remains required for Android artifact builds.

- [ ] **Step 4: Run test and syntax check**

Run:

```bash
cargo test -p xray-ffi --test mobile_artifacts_tests mobile_toolchain_preflight_script_covers_required_targets
bash -n scripts/check-mobile-toolchains.sh
```

Expected: PASS for the test and no Bash syntax errors.

### Task 4: Mobile Artifact Scripts

**Files:**
- Modify: `scripts/build-apple-xcframework.sh`
- Modify: `scripts/build-android-libs.sh`

- [ ] **Step 1: Add Android linker env coverage**

Update the Android script to discover the NDK, set `CARGO_TARGET_*_LINKER`, `CC_*`, and `AR_*` for all Android targets, and copy `libxray_ffi.so` into `jniLibs`.

- [ ] **Step 2: Add tvOS build-std coverage**

Update the Apple script to use `TVOS_BUILD_STD=auto` and `TVOS_RUST_TOOLCHAIN=nightly` for tvOS targets when stable has no prebuilt std. Set `IPHONEOS_DEPLOYMENT_TARGET` and `TVOS_DEPLOYMENT_TARGET` defaults so C objects and Rust linking agree.

- [ ] **Step 3: Build real artifacts**

Run:

```bash
scripts/check-mobile-toolchains.sh
scripts/build-apple-xcframework.sh
scripts/build-android-libs.sh
```

Expected: preflight passes, `target/mobile/apple/XrayRust.xcframework` exists, and Android `target/mobile/android/jniLibs/*/libxray_ffi.so` exists for all four ABI directories.

### Task 5: Mobile Testing Documentation

**Files:**
- Create: `docs/mobile-testing.md`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-05-22-interim-status-and-roadmap-design.md`

- [ ] **Step 1: Document the commands**

Add the commands for preflight, native ABI smoke, Apple XCFramework build, and Android `jniLibs` build.

- [ ] **Step 2: Document current known limits**

State that TUN packet ABI exists but packet-to-session VPN flow is not implemented yet, and that REALITY/Vision process interop is local-test verified for proxy mode.

- [ ] **Step 3: Verify docs references**

Run: `rg -n "mobile-testing|check-mobile-toolchains|XrayRust.xcframework|jniLibs" README.md docs`

Expected: the new docs and README references are discoverable.

### Task 6: Verification And Commit

**Files:**
- All files touched above.

- [ ] **Step 1: Run focused checks**

Run:

```bash
cargo fmt --all -- --check
cargo test -p xray-ffi --test mobile_artifacts_tests -- --nocapture
bash -n scripts/check-mobile-toolchains.sh
bash -n scripts/build-apple-xcframework.sh
bash -n scripts/build-android-libs.sh
```

Expected: all pass.

- [ ] **Step 2: Run package checks**

Run:

```bash
cargo test -p xray-ffi --all-targets
cargo clippy -p xray-ffi --all-targets --locked -- -D warnings
```

Expected: all pass.

- [ ] **Step 3: Run artifact checks**

Run:

```bash
scripts/check-mobile-toolchains.sh
scripts/build-apple-xcframework.sh
scripts/build-android-libs.sh
```

Expected: all pass on a provisioned host.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/plans/2026-05-22-mobile-test-readiness.md crates/xray-ffi/tests/mobile_artifacts_tests.rs scripts/check-mobile-toolchains.sh scripts/build-apple-xcframework.sh scripts/build-android-libs.sh docs/mobile-testing.md README.md docs/superpowers/specs/2026-05-22-interim-status-and-roadmap-design.md
git commit -m "test(mobile): add ffi readiness checks"
```

Expected: one commit with mobile test-readiness checks, artifact scripts, and docs.
