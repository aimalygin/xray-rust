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
  startup probe, runtime profiles, DNS bootstrap policy, and socket protection.
- `XrayVpnService`: reference VPN interface setup and lifecycle coordination.
- `XrayTunBackend.FileDescriptor`: default direct borrowed raw-IP fd path.
- `XrayTunBackend.PacketPump`: fallback with reusable direct buffers and
  batched blocking poll.
- `xray_mobile_jni.cpp`: checked JNI-to-C-ABI bridge with an ABI-major guard.

When `XrayCore.create` receives a `VpnService`, outbound TCP and UDP sockets are
passed through `VpnService.protect(fd)` before use. This prevents proxy sockets
from being routed back into the VPN.

`XrayCore.create` defaults to `XrayDnsBootstrapMode.System`, which preserves the
generic library/server behavior. Embedders that make system DNS unreachable
after installing their network interface can select `StaticOnly`, but then
every proxy and DNS-upstream hostname must resolve through an exact or otherwise
applicable `dns.hosts` rule.

## Reference VPN DNS bootstrap

`XrayVpnService` uses the stricter mobile policy automatically. Before calling
`Builder.establish()`, it resolves domain-valued VLESS server addresses and
domain-valued `dns.servers` with Android's system resolver. It adds the selected
addresses as exact `full:` entries under `dns.hosts`, then creates the core with
`XrayDnsBootstrapMode.StaticOnly`. The original VLESS address remains a domain,
so TLS/REALITY server names and domain-based routing are not changed.

`startXrayTunnel` is asynchronous: it returns after scheduling startup on a
bounded daemon worker pool. DNS preflight, tunnel establishment, core startup,
and the protected `onXrayTunnelStarted` / `onXrayTunnelStartFailed` callbacks do
not run on the main thread. A host that updates UI from either callback must
dispatch that work to its main-thread executor. Failure to schedule a worker is
reported synchronously by `startXrayTunnel` instead of invoking the failure
callback on the caller's thread. The coordinator releases the completed attempt
before invoking either callback, so a callback may synchronously stop or retry
without colliding with the previous start task.

An existing exact `full:` mapping is authoritative and is never overwritten.
Domain aliases in such mappings are followed and bootstrapped to a terminal IP;
cycles and chains longer than eight entries are rejected. If any required
domain cannot be resolved, tunnel startup fails before Android installs the VPN
interface. All lookups in one start attempt share a five-second monotonic
deadline that begins as soon as the lifecycle accepts the attempt. A stop during
startup marks that attempt as cancelled, interrupts its wait, and returns
without joining the start worker. The token is checked again after preflight and
before publication, so a late resolver result cannot establish or publish a
cancelled session. A new start remains rejected until pre-publication cleanup
has finished.

Android's `InetAddress.getAllByName` is blocking and may ignore interruption.
The deadline therefore bounds how long VPN startup waits, but cannot guarantee
that the platform lookup itself has returned. At most two daemon DNS workers can
remain blocked; the resolver uses a zero-capacity handoff and fails a later
lookup instead of growing a queue. The start-worker pool is likewise limited to
two threads so host callbacks that ignore cancellation cannot create unbounded
threads. The preflight stores one system-selected address for the tunnel
lifetime, so applications that require network migration or address failover
still need a host-specific multi-address policy.

When enabled `dns.fakeIp` or a non-empty `dns.servers` list activates the core's
local DNS endpoint, the reference service also installs `198.18.0.1` with
`Builder.addDnsServer`. Apps that override `buildTunnel()` retain control of all
other addresses, routes, and application exclusions.

Fake-IP does not itself provide the real address needed by a Freedom outbound.
When `dns.fakeIp.enabled` is true and `dns.servers` is empty, the reference
service therefore rejects the config before `Builder.establish()` if Freedom is
the default outbound or a TUN-applicable rule can route domain traffic to
Freedom. A VLESS default with IP-only Freedom split-routing rules remains valid,
because domain targets stay on the proxy while literal IP destinations can be
sent directly. Configuring at least one `dns.servers` upstream also makes these
Freedom topologies valid. The preflight never inserts or substitutes a public
DNS server.

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
