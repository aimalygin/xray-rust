# Mobile Testing

This page describes the current first-pass mobile harness entrypoints for iOS, tvOS, and Android.

## Readiness Preflight

Run from the repository root:

```sh
scripts/check-mobile-toolchains.sh
```

The script checks:

- Rust iOS targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`.
- Rust Android targets: `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android`.
- tvOS build-std fallback through `TVOS_BUILD_STD=auto`, `TVOS_RUST_TOOLCHAIN=nightly`, and `rust-src`.
- Apple SDKs for iOS, iOS simulator, tvOS, and tvOS simulator.
- Android NDK discovery from `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, `ANDROID_HOME/ndk`, or the usual user SDK directories.

On the current macOS host this preflight has passed after installing the iOS/Android Rust targets and nightly `rust-src` for tvOS build-std.

## ABI Smoke Tests

Run:

```sh
cargo test -p xray-ffi --test mobile_artifacts_tests -- --nocapture
```

This validates that:

- `xray_ffi.h` declares the lifecycle, error, and TUN packet ABI.
- The public C header compiles as a C11 harness.
- The native `libxray_ffi.a` exports the expected C symbols.
- The Apple, tvOS, and Android artifact scripts keep the expected target matrix.

## Apple Artifacts

Run:

```sh
scripts/build-apple-xcframework.sh
```

Output:

```text
target/mobile/apple/XrayRust.xcframework
```

The generated XCFramework contains:

- `ios-arm64`
- `ios-arm64_x86_64-simulator`
- `tvos-arm64`
- `tvos-arm64_x86_64-simulator`

Useful environment overrides:

- `PROFILE=release`
- `OUT_DIR=/path/to/output`
- `XCFRAMEWORK_NAME=XrayRust.xcframework`
- `IPHONEOS_DEPLOYMENT_TARGET=13.0`
- `TVOS_DEPLOYMENT_TARGET=14.0`
- `TVOS_BUILD_STD=auto`
- `TVOS_RUST_TOOLCHAIN=nightly`

The current stable Rust toolchain exposes tvOS target specs but does not ship prebuilt tvOS std components through `rustup target add`, so the script uses nightly `-Z build-std=std,panic_abort` for tvOS when needed.

## Android Artifacts

Run:

```sh
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

Useful environment overrides:

- `ANDROID_NDK_HOME=/path/to/ndk`
- `ANDROID_NDK_ROOT=/path/to/ndk`
- `ANDROID_HOME=/path/to/android/sdk`
- `ANDROID_API_LEVEL=24`
- `PROFILE=release`
- `OUT_DIR=/path/to/output`

The script discovers the NDK LLVM toolchain and sets Cargo/cc linker variables for each Android target before building.

## What Can Be Tested Now

Mobile harnesses can now test:

- Loading an Xray JSON config through the C ABI.
- Starting and stopping the embedded core through the C ABI.
- Accessing structured FFI errors.
- Passing raw TUN packets through the C ABI and reading packet counters.
- Running TCP sessions through the TUN packet boundary: mobile code pushes raw IP packets with `xray_tun_push_packet`, polls response packets with `xray_tun_poll_packet`, and the Rust core bridges accepted TCP sessions through routing plus Freedom/VLESS TCP outbounds.
- Linking iOS/tvOS apps against `XrayRust.xcframework`.
- Packaging Android apps with the generated `jniLibs` tree.
- Proxy-mode local behavior with SOCKS/HTTP inbounds, Freedom direct egress, and VLESS TCP/TLS/REALITY+Vision profiles that match the current supported config subset.

Current limits:

- TUN TCP is runnable; UDP session forwarding, VLESS UDP framing, Vision XUDP/Mux, and ICMP echo parity are still pending.
- Platform adapters for `NEPacketTunnelProvider`, tvOS app lifecycle, and Android `VpnService` are still outside this repository.
- Broader Xray-core protocols, DNS app behavior, geosite/geoip data loading, and full routing parity remain future work.
