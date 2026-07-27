# Android integration

This Gradle project builds an Android library around the Rust C ABI. It provides
a Kotlin wrapper, JNI bridge, and reference `VpnService`; it does not contain a
runnable Android application target.

The integration is source-only. No Maven artifact is currently published.

## Prerequisites

- JDK 17 or newer;
- Android SDK platform 35;
- Android SDK CMake 3.22.1;
- Android NDK 26.3.11579264;
- Rust Android targets for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`.

Check the complete host setup:

```sh
scripts/check-mobile-toolchains.sh --android
```

## Build the AAR

```sh
scripts/build-android-adapter.sh
```

Output:

```text
platform/android/xraymobile/build/outputs/aar/xraymobile-debug.aar
```

The script builds Rust libraries for all four ABIs, compiles
`libxray_mobile_jni.so`, packages both native libraries, verifies that the
packaged FFI binaries match the selected Rust artifacts, and checks 16 KiB ELF
LOAD alignment.

To build only the Rust artifacts:

```sh
scripts/build-android-libs.sh
```

They are written to `target/mobile/android/jniLibs`. The Gradle module reads
that path by default; `XRAY_FFI_ANDROID_DIR` can select another already-built
artifact directory.

## Library surface

- `XrayCore`: lifecycle, config warnings, packet push/batched poll, stats,
  startup probe, runtime profiles, and socket protection.
- `XrayVpnService`: reference VPN interface setup and lifecycle coordination.
- `XrayTunBackend.FileDescriptor`: default direct borrowed raw-IP fd path.
- `XrayTunBackend.PacketPump`: fallback with reusable direct buffers and
  batched blocking poll.
- `xray_mobile_jni.cpp`: checked JNI-to-C-ABI bridge with an ABI-major guard.

When `XrayCore.create` receives a `VpnService`, outbound TCP and UDP sockets are
passed through `VpnService.protect(fd)` before use. This prevents proxy sockets
from being routed back into the VPN.

## Host application responsibilities

A host app must:

1. request user consent with `VpnService.prepare`;
2. start and bind/drive the service using an application-owned lifecycle;
3. provide the required foreground-service notification and permissions for
   its target Android version;
4. supply profile storage and UI without placing credentials in logs,
   resources, fixtures, or source control;
5. choose routes, addresses, DNS behavior, and excluded applications suitable
   for the product;
6. test process death, rapid start/stop, network changes, sleep, and upgrades.

The library manifest declares the non-exported service with
`BIND_VPN_SERVICE` and the base foreground-service permission. The consuming
application must review the merged manifest and add any target-version-specific
foreground service declarations required by its distribution policy.

## Geodata

Geodata databases are not bundled. The current Kotlin wrapper does not expose a
packaged-assets geodata directory, so configs using `geosite:` or non-private
`geoip:` references require a host-specific JNI/FFI resource-directory
integration. `geoip:private` does not require an external file.

## Tests

Run Kotlin unit tests:

```sh
platform/android/gradlew -p platform/android \
  :xraymobile:testDebugUnitTest --no-daemon
```

Run ABI/artifact contract tests from the workspace root:

```sh
cargo test --locked -p xray-ffi --test mobile_artifacts_tests -- --nocapture
bash scripts/tests/check-mobile-toolchains.test.sh
```

See [mobile testing](../../docs/mobile-testing.md) for the full native artifact
matrix and on-device checklist.

## Current limits

- There is no checked-in host app, VPN consent UI, or production notification
  implementation.
- The AAR is built locally and is not signed or published.
- The adapter is a reference integration, not a production VPN product.
- Device behavior and performance must be verified with the consuming
  application's release configuration and supported Android versions.
