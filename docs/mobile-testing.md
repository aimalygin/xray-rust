# Mobile testing

Mobile artifact builds require a provisioned macOS host. Start with:

```sh
scripts/check-mobile-toolchains.sh --all
```

The preflight checks the pinned Rust toolchain and targets, Apple SDKs,
universal macOS support, the tvOS build-std fallback, JDK 17+, Android SDK 35,
CMake 3.22.1, NDK 26.3.11579264, and the checked-in Gradle wrapper.
Use `--apple` or `--android` when preparing for only one platform; without a
mode flag the script keeps the same `--all` behavior.

## ABI and script contracts

Run the platform-independent contract tests first:

```sh
cargo test --locked -p xray-ffi --test mobile_artifacts_tests -- --nocapture
bash scripts/tests/check-mobile-toolchains.test.sh
```

They validate the public header, required exported symbols, adapter ABI-major
checks, target matrices, and build-script guards.

## Apple XCFramework

Build:

```sh
scripts/check-mobile-toolchains.sh --apple
scripts/build-apple-xcframework.sh
```

Output:

```text
target/mobile/apple/XrayRust.xcframework
```

The static XCFramework contains:

| Slice | Architectures |
| --- | --- |
| `ios-arm64` | `arm64` device |
| `ios-arm64_x86_64-simulator` | `arm64`, `x86_64` simulator |
| `tvos-arm64` | `arm64` device |
| `tvos-arm64_x86_64-simulator` | `arm64`, `x86_64` simulator |
| `macos-arm64_x86_64` | universal `arm64`, `x86_64` |

Each XCFramework slice contains `libxray_ffi.a`, `xray_ffi.h`, and the Clang
module map that exposes the Swift import name `XrayRust`. The artifact uses
Xcode's static-library XCFramework layout; it is not a dynamic framework and is
not embedded in application bundles.

The checked-in deployment floors are:

| Layer | iOS | tvOS | macOS |
| --- | --- | --- | --- |
| Rust XCFramework | 15 | 14 | 11 |
| Swift Package declaration | 15 | 17 | 11 |
| Reference app and Packet Tunnel provider | 15 | 17 | 13 |

The macOS 11 package floor applies to the lower-level `XrayMobileAdapter` and
`XrayAppleShared` products. The macOS reference UI and provider entry points
are annotated for macOS 13 and the Xcode targets use the same minimum. Useful
build-script overrides include `PROFILE`, `OUT_DIR`,
`APPLE_CARGO_TARGET_DIR`, and the three platform deployment target variables.

When stable Rust does not provide prebuilt tvOS standard libraries, the script
uses the pinned `nightly-2026-05-22` toolchain with `rust-src` and
`-Z build-std`. The preflight reports the exact missing component.

Build and link the Swift adapter for every supported SDK/architecture:

```sh
scripts/check-apple-adapter-link.sh
```

Run Swift package tests:

```sh
HOME=target/mobile/apple-swiftpm-home \
CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache \
swift test --disable-sandbox --package-path platform/apple
```

The package references the fixed local path
`target/mobile/apple/XrayRust.xcframework`; rebuild it after Rust or C-header
changes. See [Apple integration](../platform/apple/README.md).

The CI Apple job additionally runs `scripts/fetch-geodata.sh` and builds the
shared `XrayClient`, `XrayClientTv`, and `XrayClientMac` schemes unsigned. The
downloaded `.dat` files are checksum-verified inputs in the ignored
`platform/apple/XrayClient/dat` directory, not repository contents.

The Apple provider performs no startup connectivity probe and assigns no
third-party DNS resolver by default. Fake-IP profiles use the tunnel-local
`198.18.0.1` DNS interception anchor; profiles without fake-IP must provide an
explicit IPv4 DNS override. Combining both modes, or configuring neither, fails
before applying network settings. Device tests that enable a probe or custom
DNS must use endpoints controlled or approved by the host application and
verify valid configuration, local-anchor responses, and fail-closed handling
of missing, conflicting, or malformed DNS settings.

## Android native libraries

Build:

```sh
scripts/check-mobile-toolchains.sh --android
scripts/build-android-libs.sh
```

Output:

```text
target/mobile/android/include/xray_ffi.h
target/mobile/android/jniLibs/arm64-v8a/libxray_ffi.so
target/mobile/android/jniLibs/armeabi-v7a/libxray_ffi.so
target/mobile/android/jniLibs/x86/libxray_ffi.so
target/mobile/android/jniLibs/x86_64/libxray_ffi.so
```

The build requires API level 24 and the pinned NDK. Each generated shared
library is inspected to ensure every ELF LOAD segment is aligned to at least
16 KiB.

Build the complete debug AAR:

```sh
scripts/build-android-adapter.sh
```

Output:

```text
platform/android/xraymobile/build/outputs/aar/xraymobile-debug.aar
```

The adapter build compiles the C++ JNI bridge for all four ABIs, packages both
`libxray_ffi.so` and `libxray_mobile_jni.so`, verifies 16 KiB alignment, and
checks that the packaged FFI libraries exactly match the selected Rust
artifacts. Set `XRAY_USE_PREBUILT_ARTIFACTS=1` only when the native artifact
directory has already been built and verified.

Run Kotlin tests:

```sh
platform/android/gradlew -p platform/android \
  :xraymobile:testDebugUnitTest --no-daemon
```

See [Android integration](../platform/android/README.md).

## On-device test checklist

Artifact and unit tests do not replace platform testing. Before a release,
verify at minimum:

- start, stop, rapid stop-during-start, and repeated connect cycles;
- IPv4 and IPv6 traffic where the target network supports them;
- TCP and UDP through the intended Freedom/VLESS/TLS/REALITY profile;
- DNS behavior and captive-network transitions;
- airplane mode, interface changes, sleep/wake, and process termination;
- queue pressure and packet loss under sustained traffic;
- secure profile persistence and log redaction;
- Android foreground-service behavior and Apple Network Extension lifecycle;
- release signing, entitlements/manifest declarations, and store policy.

## Current host responsibilities

- Apple requires an appropriate Developer team, app/extension identifiers,
  Packet Tunnel entitlements, provisioning, and user approval.
- Android requires `VpnService.prepare`, foreground notification/service policy
  appropriate for the target OS, VPN consent, and host-app lifecycle/UI.
- The repository does not distribute geodata databases. A host using
  `geosite`/`geoip` must package verified files and expose the correct resource
  directory to the core. The Apple sample can install the repository's pinned,
  checksum-verified assets with `scripts/fetch-geodata.sh`.
- Neither adapter is a complete production application or a substitute for
  device profiling with Instruments or Perfetto.
