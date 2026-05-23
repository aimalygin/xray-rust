# Mobile Testing

This page describes the current first-pass mobile harness entrypoints for iOS, tvOS, and Android.

## Readiness Preflight

Run from the repository root:

```sh
scripts/check-mobile-toolchains.sh
```

The script checks:

- Rust Apple host/mobile targets: `aarch64-apple-darwin`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`.
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

- `xray_ffi.h` declares the lifecycle, error, TUN packet ABI, and optional fd-backed TUN ABI.
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
- `macos-arm64`, used as a local SwiftPM host-build slice for adapter checks.

Useful environment overrides:

- `PROFILE=release`
- `OUT_DIR=/path/to/output`
- `XCFRAMEWORK_NAME=XrayRust.xcframework`
- `IPHONEOS_DEPLOYMENT_TARGET=13.0`
- `TVOS_DEPLOYMENT_TARGET=14.0`
- `TVOS_BUILD_STD=auto`
- `TVOS_RUST_TOOLCHAIN=nightly`

The current stable Rust toolchain exposes tvOS target specs but does not ship prebuilt tvOS std components through `rustup target add`, so the script uses nightly `-Z build-std=std,panic_abort` for tvOS when needed.

## Apple Adapter Skeleton

The repository now includes a Swift Package adapter under:

```text
platform/apple
```

It provides:

- `XrayCore`, a Swift wrapper over the C ABI lifecycle, TUN packet push/poll, optional fd-backed TUN registration, stats, errors, and socket-protection registration hook.
- `XrayPacketTunnelPump`, a `NEPacketTunnelProvider` packet pump that reads OS tunnel packets into the Rust TUN boundary and writes emitted packets back through `packetFlow`.
- `XrayDarwinTunFileDescriptor`, an advanced helper for discovering an existing utun fd for `XRAY_TUN_FD_PACKET_FORMAT_DARWIN_UTUN` integrations.
- `crates/xray-ffi/include/module.modulemap`, so the generated XCFramework can be imported as `XrayRust` from Swift.

The package expects `target/mobile/apple/XrayRust.xcframework` to exist. Build it first with `scripts/build-apple-xcframework.sh`.

Run the adapter host-build check with:

```sh
scripts/build-apple-adapter.sh
```

This builds the Swift package against the generated XCFramework. The macOS slice in the XCFramework is included for this local SwiftPM check; the mobile runtime targets remain iOS and tvOS.

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

## Android Adapter Skeleton

The repository now includes an Android library skeleton under:

```text
platform/android
```

It provides:

- `XrayCore`, a Kotlin wrapper over JNI lifecycle, TUN packet push/poll, stats, and errors.
- `XrayVpnService`, a minimal `VpnService` integration that defaults to separate TUN read/write loops and can use `XrayTunBackend.FileDescriptor` for direct fd-backed Rust TUN I/O.
- `xray_mobile_jni.cpp`, a JNI bridge from Kotlin to the stable C ABI.
- Android socket protection wiring: Kotlin passes `VpnService.protect(fd)` through JNI to `xray_core_set_socket_protect_callback`, and Rust invokes it before outbound TCP connects and before outbound UDP socket use.
- Android fd-backed TUN wiring: Kotlin passes `ParcelFileDescriptor.fd` through JNI to `xray_core_set_tun_fd` before config load when `XrayTunBackend.FileDescriptor` is selected.

The Android skeleton expects generated `libxray_ffi.so` files under `target/mobile/android/jniLibs`. Build them first with `scripts/build-android-libs.sh`. The JNI bridge can also use `XRAY_FFI_ANDROID_DIR=/path/to/mobile/android` when the artifact directory lives elsewhere.

Run the adapter build check with:

```sh
scripts/build-android-adapter.sh
```

This builds the Android library AAR, compiles the JNI bridge through CMake for all configured ABIs, and compiles the Kotlin wrapper. The script discovers `ANDROID_HOME` and `ANDROID_NDK_HOME` when they are not already set.

## What Can Be Tested Now

Mobile harnesses can now test:

- Loading an Xray JSON config through the C ABI.
- Starting and stopping the embedded core through the C ABI.
- Accessing structured FFI errors.
- Passing raw TUN packets through the C ABI and reading packet counters.
- Passing a platform TUN fd through `xray_core_set_tun_fd` so Rust reads and writes the fd directly instead of crossing the Swift/Kotlin/JNI packet boundary for every packet.
- Running TCP sessions through the TUN packet boundary: mobile code pushes raw IP packets with `xray_tun_push_packet`, polls response packets with `xray_tun_poll_packet`, and the Rust core bridges accepted TCP sessions through routing plus Freedom/VLESS TCP outbounds.
- Running UDP sessions through the same TUN packet boundary for:
  - Freedom/direct UDP targets.
  - VLESS UDP length-prefixed datagrams over TCP transport.
  - Vision UDP through VLESS Mux/XUDP framing over a protected TLS/REALITY-capable stream boundary.
- Receiving ICMP echo replies for IPv4 and IPv6 ping-style probes through the TUN packet boundary.
- Linking iOS/tvOS apps against `XrayRust.xcframework`.
- Packaging Android apps with the generated `jniLibs` tree.
- Driving first iOS/tvOS `NEPacketTunnelProvider` and Android `VpnService` harnesses through the checked-in adapter skeletons.
- Compiling the checked-in Swift and Android adapter projects locally with `scripts/build-apple-adapter.sh` and `scripts/build-android-adapter.sh`.
- Proxy-mode local behavior with SOCKS/HTTP inbounds, Freedom direct egress, and VLESS TCP/TLS/REALITY+Vision profiles that match the current supported config subset.

Current limits:

- The platform-neutral TUN runtime is runnable for TCP, UDP, VLESS UDP, Vision XUDP, and ICMP echo. The checked-in Apple and Android adapters are first harness skeletons for device testing, not complete app templates with entitlements, foreground-service notification policy, user profile storage, or production UI.
- The fd-backed TUN backend is optional. The packet pump remains the default Apple path, while Android can opt into direct fd-backed mode through `XrayTunBackend.FileDescriptor`.
- iOS/tvOS `NEPacketTunnelProvider` packaging still needs a host app/extension target with the correct Apple entitlements and provisioning profile.
- Android packaging still needs a host app that requests VPN user consent and provides foreground-service behavior appropriate for the target Android version.
- Broader Xray-core protocols, DNS app behavior, geosite/geoip data loading, and full routing parity remain future work.
