# Interim Status and Roadmap Design

## Purpose

Capture the current state of the Rust Xray-compatible core, the verified compatibility baseline, and the remaining work needed to grow it toward a clean, mobile-first analogue of Xray-core.

This document is intentionally a status spec, not a task-level implementation plan. It answers three questions:

- What is already implemented.
- What has been proven by tests against real local Xray-core.
- What still needs to be built, in a sequence that keeps the path open for full Xray-core compatibility.

## Product Direction

The project is a protocol-compatible Rust implementation of the Xray-core client/runtime surface, not a line-by-line port of the Go codebase. The architecture should stay clean, typed, memory-conscious, and suitable for mobile embedding on iOS, tvOS, Android, macOS, Linux, and other supported Rust targets.

The first practical product remains a mobile/client core:

- Xray JSON config as the public compatibility format.
- Local SOCKS and HTTP proxy inbounds.
- Platform-neutral TUN packet boundary.
- VLESS and Freedom outbounds.
- Rule-based routing for the first practical matchers.
- TCP, TLS, REALITY, and Vision for the first protected transport path.
- Stable C ABI for iOS, tvOS, Android, and desktop embedding.
- A thin CLI binary for local development and process-level interop testing.

## Current Verified Baseline

The project now has a working Rust workspace with protocol, transport, runtime, config, FFI, TUN, routing, and CLI crates separated by responsibility.

The current runnable slice is:

```text
xray-rust run -config config.json
  local SOCKS or HTTP inbound
    -> routing rule/default outbound selection
      -> Freedom direct TCP or VLESS outbound
        -> TCP, TLS, TLS+Vision, or REALITY+Vision
          -> real local Xray-core server or local echo target
```

This is no longer only unit-level code. The core has been exercised both in-process and as a spawned `xray-rust` process against the cloned Go Xray-core checkout.

## Implemented Components

### Workspace Boundary

Implemented crates:

- `xray-config`: Xray JSON subset parser, diagnostics, and normalized config model.
- `xray-core-rs`: core lifecycle, SOCKS/HTTP listener runtime, routing-aware outbound selection, and data path orchestration.
- `xray-proxy`: SOCKS and HTTP parser foundations, VLESS wire encoding, response handling, and Vision stream wrapper.
- `xray-transport`: TCP/TLS/REALITY transport boundaries, DNS resolver abstraction, rustls TLS connector, REALITY runtime abstractions, and live REALITY rustls provider.
- `xray-routing`: early routing foundation.
- `xray-runtime`: runtime integration foundation.
- `xray-tun`: platform-neutral TUN packet queues, packet validation, and stats.
- `xray-ffi`: mobile/desktop C ABI for core lifecycle, config validation, and TUN packet push/poll.
- `xray-cli`: runnable `xray-rust` binary crate.

The crate split matches the original mobile-first design: FFI does not own protocol logic, protocol code does not depend on mobile embedding, and the CLI stays a thin lifecycle shell over the core.

### Config

Implemented:

- JSON parsing into typed Rust config structures.
- Supported VLESS outbound settings for the first interop profile.
- Supported Freedom outbound for direct TCP egress.
- Supported SOCKS and HTTP inbound settings for the runnable path.
- TLS and REALITY stream settings needed by the current VLESS client slice.
- Routing rules for the supported `field` subset: `inboundTag`, `domain:`, `full:`, literal IP, CIDR, built-in `geoip:private`, and `outboundTag`.
- Structured diagnostics foundation.

The config layer is intentionally not complete yet. It accepts enough of the Xray JSON surface to drive the current local interop scenarios.

### Core Runtime

Implemented:

- `Core` lifecycle with `start` and `stop`.
- SOCKS and HTTP listener startup from config.
- Bound inbound address reporting for tests and CLI startup output.
- Routing-aware stream dispatch from local SOCKS/HTTP connections to Freedom or VLESS outbounds.
- Runtime data path for local TCP proxying.
- Graceful process-level lifecycle through the CLI.

The runtime is currently client-oriented. Server mode and admin APIs are not part of the verified baseline.

### VLESS

Implemented:

- VLESS request header encoding.
- UUID user id handling.
- TCP command and address/port encoding.
- Response header validation.
- `encryption: none` for the first supported client slice.
- Flow-aware outbound path for `xtls-rprx-vision`.

The current VLESS path is verified against real local Xray-core for the covered transport combinations.

### Freedom

Implemented:

- Xray JSON `freedom` outbound parsing for the strict direct-TCP subset.
- Runtime dispatch from SOCKS/HTTP to direct TCP targets.
- Domain target resolution through the injected DNS resolver.
- Process-level `xray-rust` coverage for SOCKS -> Freedom -> local echo.

Unsupported behavior-changing Freedom settings such as redirect remain rejected instead of being ignored.

### Routing

Implemented:

- Default outbound tag selection from the first tagged outbound.
- Rule-ordered outbound selection for the supported field-rule subset.
- `inboundTag` matcher.
- `domain:` suffix matcher.
- `full:` exact-domain matcher.
- Literal IP and CIDR matchers.
- Built-in `geoip:private` matcher for common private/local IPv4 and IPv6 ranges.
- Parser diagnostics for unsupported routing fields and unsupported domain matcher families.

Current limits:

- No port, network, protocol, user, geosite, external geoip data loading, balancer, or `domainStrategy` behavior yet.
- Domain matching is used for target domains already present in the inbound request; DNS-driven route fallback is not implemented.

### TLS

Implemented:

- rustls-based TLS connector.
- TLS config selection in the transport layer.
- Test injection of root certificates for local interop.
- VLESS over TLS local Xray-core coverage.

TLS is treated as a protected transport behind a transport abstraction, rather than being hard-wired into VLESS.

### Vision

Implemented:

- `xtls-rprx-vision` config acceptance for protected streams.
- Vision stream wrapper path.
- Rejection of Vision over raw TCP.
- Local Xray-core coverage for VLESS TLS+Vision.
- Local Xray-core coverage for VLESS REALITY+Vision.

The implementation keeps Vision separate from the core copy loop so the runtime can later add platform-specific optimizations without changing the protocol boundary.

### REALITY

Implemented:

- X25519 shared secret derivation.
- HKDF-based key derivation.
- AEAD session id sealing.
- ClientHello patch validation.
- Certificate binding validation.
- `RealityTlsSessionProvider` and `RealityRuntimeEngine` abstractions.
- Live rustls-backed REALITY provider wired into `TransportDialer::system()`.
- Process-level local Xray-core coverage for VLESS REALITY+Vision.

Current limits:

- Live fingerprint support is currently limited to `chrome`.
- Other fingerprints are rejected rather than silently producing incompatible handshakes.
- REALITY is currently client-side only.

### CLI

Implemented:

```bash
xray-rust run -config /path/to/config.json
xray-rust run --config /path/to/config.json
```

The binary:

- parses the initial `run` command;
- loads Xray JSON config;
- constructs `xray_core_rs::Core`;
- starts the core;
- prints bound SOCKS inbound information;
- waits for `Ctrl+C`;
- stops the core.

The CLI deliberately contains no protocol logic. It exists to validate the same lifecycle that mobile FFI will expose later.

### FFI, TUN, And Mobile Artifacts

Implemented:

- Opaque FFI core handle.
- Config validation/loading surface.
- Start/stop lifecycle boundary.
- Error object allocation and release.
- Panic boundary protection for exported C ABI calls.
- Outbound socket-protection callback registration for Android VPN embedding.
- TUN packet push/poll FFI functions.
- TUN packet stats and bounded queue behavior.
- Public C header checked by tests.
- C header harness test that compiles `xray_ffi.h` as C11.
- Native staticlib exported-symbol smoke test.
- Mobile toolchain preflight script for iOS, tvOS, and Android.
- Apple XCFramework build script covering iOS device/simulator and tvOS device/simulator targets.
- Android `jniLibs` build script covering arm64-v8a, armeabi-v7a, x86, and x86_64.
- Apple Swift adapter skeleton with `XrayCore` and `NEPacketTunnelProvider` packet pump.
- Android Kotlin/JNI adapter skeleton with `VpnService`, TUN packet pump, and `VpnService.protect(fd)` wiring.
- Verified Apple `XrayRust.xcframework` build on the current macOS host.
- Verified Android `jniLibs` build on the current macOS host with NDK 26.3.

Current limits:

- Cross-target artifact builds depend on installed Rust targets, Xcode SDKs, Android NDK, and nightly `rust-src` for tvOS build-std on toolchains that do not ship prebuilt tvOS std components.
- The checked-in Apple and Android adapters are first harness skeletons, not complete production host apps with entitlements, provisioning, foreground-service policy, profile UI, or release packaging.

## Verification Evidence

Recent verified commands:

```bash
cargo fmt --all -- --check
cargo test -p xray-config --all-targets
cargo test -p xray-core-rs --all-targets
cargo test -p xray-cli --all-targets
cargo test -p xray-ffi --test mobile_artifacts_tests -- --nocapture
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-cli --test process_interop_tests -- --ignored --nocapture
cargo clippy -p xray-config -p xray-core-rs -p xray-cli --all-targets --locked -- -D warnings
```

Additional targeted checks from the protected transport work:

```bash
cargo test -p xray-transport reality
cargo test -p xray-core-rs --all-targets
cargo test -p xray-proxy --test vless_response_stream_tests
cargo test -p xray-ffi --all-targets
cargo test -p xray-tun --all-targets
bash -n scripts/build-apple-xcframework.sh
bash -n scripts/build-android-libs.sh
scripts/check-mobile-toolchains.sh
scripts/build-apple-xcframework.sh
scripts/build-android-libs.sh
```

Verified local interop scenarios:

- In-process Rust core to real local Xray-core: VLESS TCP.
- In-process Rust core to real local Xray-core: VLESS TLS.
- In-process Rust core to real local Xray-core: VLESS TLS+Vision.
- In-process Rust core to real local Xray-core: VLESS REALITY+Vision.
- Spawned `xray-rust` process to real local Xray-core: VLESS TCP.
- Spawned `xray-rust` process to real local Xray-core: VLESS REALITY+Vision.
- Spawned `xray-rust` process with no Go dependency: SOCKS -> Freedom -> local echo.
- Spawned `xray-rust` process with no Go dependency: HTTP CONNECT -> Freedom -> local echo.
- In-process Rust core: SOCKS -> Freedom -> local echo.
- In-process Rust core: HTTP CONNECT -> VLESS TCP -> local echo.
- In-process Rust core: routing by `inboundTag` -> Freedom -> local echo.
- In-process Rust core: routing by `domain:` matcher -> Freedom -> local echo.
- In-process Rust core: routing by IP/CIDR matcher -> Freedom -> local echo.

## Compatibility Surface Today

The project can currently be treated as a runnable proof for this compatibility profile:

- Client-side local SOCKS inbound.
- Client-side local HTTP CONNECT inbound.
- Client-side VLESS outbound.
- Client-side Freedom outbound.
- TCP transport.
- TLS transport.
- REALITY transport with `chrome` fingerprint.
- `xtls-rprx-vision` over protected streams.
- Routing by `inboundTag`, `domain:`, `full:`, literal IP, CIDR, and built-in `geoip:private` for the supported field-rule subset.
- C ABI lifecycle/config/TUN packet boundary for embedding.
- Verified Apple iOS/tvOS `XrayRust.xcframework` and Android `jniLibs` artifact scripts on a provisioned macOS host.
- Xray JSON configs for this subset.
- Local process-level execution through `xray-rust`.

This is a real milestone: the first local proxy process can be launched, can move bytes through a real Xray server with REALITY+Vision, and can also run direct Freedom egress locally without the Go reference process.

## Remaining Work

### Config Compatibility

The config layer needs to become stricter and broader before real-world configs can be expected to load reliably.

Needed:

- Better handling of unsupported behavior-changing fields.
- Clearer warning versus error rules for ignored fields.
- More inbound and outbound fields from real Xray configs.
- More routing fields aligned with Xray-core.
- A fixture corpus from Xray examples and practical client configs.
- Golden parse tests that assert normalized internal config and diagnostics.

This should be the next hardening layer because every later feature depends on stable config semantics.

### HTTP Inbound Runtime

HTTP CONNECT is implemented in-process. Remaining HTTP work is narrower now:

- Process-level HTTP inbound interop test using the `xray-rust` binary.
- Plain HTTP proxy request support if included in the first compatibility profile.
- More HTTP inbound settings from real Xray configs.

### Mobile FFI

The `xray-ffi` crate now exposes lifecycle/config/TUN ABI plus socket-protection callback wiring. The remaining work is to make it production-grade for app embedding and packaging.

Needed:

- Log callback with bounded queue behavior.
- Bound inbound inspection or event callback.
- ABI stability/versioning checks.
- Device-level Swift/Kotlin harness runs that exercise TUN packets against local test targets.
- Host integration rules for app process lifecycle and background/network-extension constraints.

This is the highest-priority product layer once the config path is stable enough for real profiles.

### Apple iOS And tvOS Packaging

Needed:

- Add CI coverage for the verified XCFramework build path.
- Turn the checked-in Swift adapter skeleton into a host app/extension sample with real entitlements and provisioning.
- ABI stability checks for the generated header.
- App-extension-safe runtime assumptions.
- No reliance on process signals for embedded lifecycle.

The core lifecycle already points in this direction because the CLI uses the same start/stop model that FFI should expose directly.

### Android Packaging

Needed:

- Add CI coverage for the verified `jniLibs` build path.
- Turn the checked-in Gradle/Kotlin/JNI skeleton into a host app sample with VPN consent flow and foreground-service behavior.
- Runtime initialization rules that work inside Android app processes.
- ABI stability checks for the generated header.

The Rust core should not assume Android-specific APIs in protocol crates.

### TUN Runtime

The `xray-tun` crate and FFI packet boundary now route TCP, UDP, VLESS UDP, Vision XUDP, and ICMP through the core runtime.

Needed:

- Device-level TUN harness runs through iOS/tvOS `NEPacketTunnelProvider` and Android `VpnService`.
- Backpressure and memory-budget profiling under mobile-sized queues.
- Later packet-path refinements for DNS app behavior, split routing, and unsupported protocols.

TUN must stay platform-neutral. iOS `NEPacketTunnelProvider` and Android `VpnService` adapters should sit outside the core ABI.

### Routing And DNS

Needed:

- IP, CIDR, port, network, protocol, user, and source matchers.
- `geoip:` and `geosite:` data loading.
- Default outbound behavior compatible with Xray-core.
- DNS app behavior.
- Domain strategy handling.
- Sniffing and fake DNS in later slices.

Routing should evolve as a rule engine, not as ad hoc checks in individual protocol handlers.

### Additional Protocols

Outbound protocols still needed for broader Xray-core compatibility:

- Blackhole.
- Trojan.
- Shadowsocks.
- VMess.
- DNS.
- WireGuard.

Inbound protocols still needed:

- Dokodemo.
- VLESS inbound.
- Trojan inbound.
- Shadowsocks inbound.

These should be added behind explicit registries so the first VLESS path does not become the spine of the whole runtime.

### Additional Transports

Needed after the TCP/TLS/REALITY foundation:

- WebSocket.
- gRPC.
- XHTTP.
- HTTPUpgrade.
- mKCP.
- QUIC and Hysteria-family transports if included in the target compatibility matrix.

Each transport should implement the existing transport abstraction rather than changing outbound protocol code.

### REALITY Fingerprint Expansion

Needed:

- More uTLS-compatible fingerprints beyond `chrome`.
- Explicit compatibility tests per fingerprint.
- Continued rejection of unsupported fingerprints.
- Review against modern Xray-core REALITY behavior when the reference evolves.

The current implementation is intentionally narrow and verified instead of broad and speculative.

### Observability And Stats

Needed:

- Structured logs.
- Stable error codes.
- Runtime stats counters.
- Optional event callbacks for embedding.
- Admin or introspection surface for desktop/server usage later.

Mobile callback paths must be bounded and must count dropped events.

### Performance And Memory Hardening

Needed:

- Explicit resource limits surfaced in config or embedding options.
- Bounded queues across logs, TUN, stats, and accept loops.
- Buffer sizing review for stream copy paths.
- Mobile-oriented memory budget tests.
- Profiling on iOS/tvOS/Android once packaging exists.
- Dependency size and feature audit.

The goal is predictable memory behavior before adding many protocols.

### CI And Cross-Compilation

Needed:

- Fast unit test job.
- Clippy job.
- macOS and Linux build coverage.
- iOS/tvOS target build coverage.
- Android target build coverage.
- Optional local Xray-core interop job gated by Go and the reference checkout.
- Artifact packaging checks for mobile outputs.

Interop tests may remain ignored by default locally, but they should be easy to run and eventually wired into a gated CI job.

### Security Review

Needed:

- Secret zeroization review.
- Panic boundary review for FFI.
- Unsafe code audit when FFI and TUN grow.
- Dependency audit.
- TLS and REALITY transcript review against current Xray-core behavior.
- Fuzzing targets for config parsing and protocol parsers.

## Recommended Roadmap

### Milestone 1: Routing And Config Corpus Hardening

Goal: make routing/config behavior safe enough for practical Xray client profiles.

Status: partially complete for the first mobile subset. Literal IP, CIDR, and built-in `geoip:private` routing are implemented, and a practical mobile VLESS REALITY/Vision split-routing fixture is in the corpus.

Deliverables:

- Fixture corpus for current VLESS TCP/TLS/REALITY/Vision configs.
- More complete diagnostics for unsupported fields.
- Port, network, and protocol routing matchers for the supported subset.
- Explicit `geoip:`/`geosite:` unsupported-or-supported policy with tests.
- Default outbound/routing semantics checked against Xray-core for the supported subset.
- Regression tests for parse success, parse rejection, and warnings.

Why first: every mobile and runtime surface depends on config load behavior, and routing is where practical client profiles start to diverge.

### Milestone 2: Mobile Artifact Validation And Embedding Harness

Goal: prove the existing ABI and scripts on actual Apple and Android target matrices.

Status: artifact validation is complete on the current macOS host, and first Swift/Kotlin/JNI adapter skeletons are checked in. The remaining work is device execution, host app packaging, and CI.

Deliverables:

- iOS/tvOS packet tunnel extension sample that links `XrayRust.xcframework`.
- Android app sample that packages `jniLibs`, loads the JNI bridge, and confirms `protect(fd)` is invoked for Rust-created outbound sockets.
- CI or documented release job for Apple iOS/tvOS XCFramework builds.
- CI or documented release job for Android `jniLibs` builds.
- ABI/version checks for `xray_ffi.h`.

Why second: the ABI exists; the product risk has moved to cross-target builds, host integration, and lifecycle behavior inside app processes.

### Milestone 3: Process-Level HTTP And Routing Interop

Goal: prove the CLI process path for the newly implemented HTTP/Freedom/routing surface.

Status: HTTP CONNECT -> Freedom process coverage is implemented. Remaining process coverage should focus on HTTP -> VLESS and routing selection from JSON.

Deliverables:

- Spawned `xray-rust` process test for HTTP CONNECT -> local Xray-core VLESS.
- Spawned `xray-rust` process test for routing rule selection from JSON config.

Why third: in-process tests already cover the behavior; process-level tests catch config/CLI/lifecycle regressions.

### Milestone 4: TUN Flow Integration

Goal: move from packet queues over FFI to actual VPN packet forwarding.

Deliverables:

- Packet parser and flow table.
- User-space TCP/IP stack integration decision.
- Packet-to-session dispatch into existing routing/outbound selection.
- Backpressure and memory-budget tests under mobile-sized queues.

Why fourth: TUN is essential for mobile VPN mode, but it should reuse the proven routing/outbound path instead of inventing a parallel runtime.

### Milestone 5: Routing, DNS, And Protocol Expansion

Goal: move from the first client slice toward broader Xray-core compatibility.

Deliverables:

- DNS behavior compatible with supported profiles.
- Additional outbound protocols.
- Additional inbound protocols.
- Additional transports behind the existing transport abstraction.

Why fifth: this is the expansion phase and should build on stable config, runtime, routing, and mobile boundaries.

## Immediate Next Spec Recommendation

The next detailed implementation spec should be:

```text
Mobile Host Harness Samples
```

It should execute the checked-in Swift and Kotlin/JNI skeletons on real or simulator/emulator targets, load the generated artifacts, start a TUN-only config, move at least ICMP and UDP packets through the packet pump, and confirm Android outbound sockets pass through `VpnService.protect(fd)`.

After that, the next detailed implementation plan should be generated from that spec and executed task by task.
