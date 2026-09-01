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

They validate the public header, required exported symbols, adapter ABI version
and capability discovery, target matrices, and build-script guards.

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
third-party DNS resolver by default. Fake-IP profiles and profiles with any
supported nonempty string or object `dns.servers` list use the tunnel-local
`198.18.0.1` DNS anchor. Classic servers plus strict `tcp://host[:port]` and
`tls://host[:port]` servers are routed through selected Freedom/VLESS
outbounds; an object server's `tag`
still applies. Strict `tcp+local://host[:port]` is the explicit exception: it
bypasses routing and uses a provider-local/system TCP socket. On Apple,
Network Extension's provider-process routing policy keeps that socket off the
provider's own tunnel; Android explicitly calls `VpnService.protect(fd)`.
VLESS receives a routed domain upstream unchanged for remote resolution;
Freedom needs a `dns.hosts` alias chain ending in an IP or nonempty IP array in
mobile `StaticOnly` mode, otherwise that candidate fails over. Domains restored
from fake-IP and sent through Freedom resolve through the same routed
`dns.servers`, not the operating-system resolver.

For the TCP and TLS URL schemes, matching is case-insensitive and the mobile preflight
accepts only an authority containing IPv4, a domain, or bracketed IPv6 with an
optional port from 1 through 65535 (default 53 for TCP and 853 for TLS). It rejects userinfo, path,
query, fragment, percent encoding, unbracketed IPv6, whitespace/control
characters, and malformed brackets. In an object server, the URL's port is
authoritative. The sibling `port` is validated as an integer from 0 through
65535 and preserved, but ignored when selecting the endpoint. TCP/TLS URLs reject a
direct or pinned tunnel-owned address on every URL port; classic non-URL
servers retain their legacy port-53 safety check.

Before Network Extension installs the anchor, the provider resolves every
domain VLESS server and domain classic/TCP/TLS-URL `dns.servers` endpoint through
the then-current dual-stack system resolver. Domain hosts from `tcp://`,
`tcp+local://`, and `tls://` are pinned with the URI port; IP-literal URLs skip the system
lookup. It writes every ordered A/AAAA result into a canonical exact `full:` IP
array in `dns.hosts` without replacing an existing bare or `full:` exact
mapping (bare keys are exact in Xray, not keywords), follows aliases for at most
eight steps, and preserves each VLESS address, DNS server URI, and object policy
field exactly in runtime JSON. Apple installs both IPv4 and IPv6
default tunnel routes plus an excluded `/32` or `/128` for every VLESS carrier
candidate before the core is created; pinned DNS-upstream addresses receive no
global route exclusion. Routed DNS follows outbound policy, while local TCP DNS
uses the provider-process policy described above. DNS64 results are accepted on
IPv6-only networks. Tunnel-owned addresses are never installed as exclusions;
finding one in a carrier result, a classic port-53 DNS alias chain, or any TCP
URL alias chain fails startup. Cycles or resolution failure stop tunnel startup.
The preflight runs away from the provider callback queue and all lookups share
one five-second deadline captured at the beginning of the start attempt. Stop,
timeout, or a superseding start completes the pending start exactly once;
generation checks discard a late resolver result before network settings or the
runtime can be installed. Because Darwin's `getaddrinfo` is not reliably
interruptible, Apple admits only one process-wide lookup worker and does not
enqueue more work behind a blocked call. A busy newer attempt still expires on
its own deadline. Pinned candidates remain fixed for one tunnel lifetime;
opt-in `sockopt.happyEyeballs` can race them, but DNS refresh and
network-migration re-bootstrap remain follow-ups. A profile without JSON DNS or
fake-IP can instead provide an explicit host IPv4/IPv6 DNS override. Combining
fake-IP with that host override, or configuring none of the supported modes,
fails before applying network settings. Device tests that enable a probe or
custom DNS must use endpoints controlled or approved by the host application
and verify UDP/TCP local-anchor responses, routed versus protected-local TCP
URL behavior, UDP-message framing onto TCP upstreams, ordered upstream failover,
UDP-truncation retry over TCP, and fail-closed handling of missing, conflicting,
malformed, or unreachable DNS settings.

Fake-only mobile configurations are accepted when the default path is VLESS
and every Freedom split rule is IP-only: restored domains then remain domains
and are resolved remotely. With no `dns.servers`, a default Freedom outbound or
a TUN-applicable domain/catch-all Freedom rule is rejected before the VPN is
installed. This applies to both reference adapters and avoids silently choosing
a public resolver. The Apple direct reference profile therefore needs an
explicit host DNS override; the compatibility helper that formerly added
fake-IP to the legacy direct profile is now a no-op.
Because the current fake-IP pool is IPv4-only and takes precedence over raw
proxying, both reference adapters reject fake-IP combined with global
`UseIPv6` before installing the VPN; that combination would otherwise return
NODATA for every usable fake-IP query even when `dns.servers` is present.

The Android reference service applies the same five-second overall deadline
before `Builder.establish()`. Its public start operation is asynchronous, stop
does not join a pending start, and lifecycle tokens reject late publication.
`InetAddress` may also ignore interruption, so both DNS lookups and start
workers use zero-queue bounded daemon pools; saturation fails closed instead of
growing threads or queued work. Every usable system A/AAAA result is retained
in the generated exact `dns.hosts` IP array. Domain TCP/TLS URLs use the same
bootstrap/pinning rules before `Builder.establish()`, while every
`tcp+local://` socket is passed through `VpnService.protect(fd)`. When Happy
Eyeballs is enabled,
each launched raw TCP candidate is independently passed through
`VpnService.protect(fd)` and losing or cancelled attempts do not remain running.
The Rust core consumes every pinned carrier candidate independently of global
`dns.queryStrategy`; the policy applies only to destination-facing managed
lookups. This preserves DNS64/NAT64 bootstrap on IPv6-only networks. The raw
UDP/TCP DNS proxy still forwards the client's original question type unchanged.

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
- dual-stack bootstrap with Happy Eyeballs enabled and disabled, including a
  failed preferred-family candidate and cancellation during the stagger;
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
