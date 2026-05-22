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
- VLESS outbound.
- TCP, TLS, REALITY, and Vision for the first protected transport path.
- Stable C ABI for iOS, tvOS, Android, and desktop embedding.
- A thin CLI binary for local development and process-level interop testing.

## Current Verified Baseline

The project now has a working Rust workspace with protocol, transport, runtime, config, FFI, TUN, routing, and CLI crates separated by responsibility.

The current runnable slice is:

```text
xray-rust run -config config.json
  local SOCKS inbound
    -> VLESS outbound
      -> TCP, TLS, TLS+Vision, or REALITY+Vision
        -> real local Xray-core server
          -> freedom outbound
            -> local echo server
```

This is no longer only unit-level code. The core has been exercised both in-process and as a spawned `xray-rust` process against the cloned Go Xray-core checkout.

## Implemented Components

### Workspace Boundary

Implemented crates:

- `xray-config`: Xray JSON subset parser, diagnostics, and normalized config model.
- `xray-core-rs`: core lifecycle, SOCKS listener runtime, outbound selection, and data path orchestration.
- `xray-proxy`: SOCKS and HTTP parser foundations, VLESS wire encoding, response handling, and Vision stream wrapper.
- `xray-transport`: TCP/TLS/REALITY transport boundaries, DNS resolver abstraction, rustls TLS connector, REALITY runtime abstractions, and live REALITY rustls provider.
- `xray-routing`: early routing foundation.
- `xray-runtime`: runtime integration foundation.
- `xray-tun`: platform-neutral TUN foundation.
- `xray-ffi`: initial FFI foundation.
- `xray-cli`: runnable `xray-rust` binary crate.

The crate split matches the original mobile-first design: FFI does not own protocol logic, protocol code does not depend on mobile embedding, and the CLI stays a thin lifecycle shell over the core.

### Config

Implemented:

- JSON parsing into typed Rust config structures.
- Supported VLESS outbound settings for the first interop profile.
- Supported SOCKS inbound settings for the runnable path.
- TLS and REALITY stream settings needed by the current VLESS client slice.
- Structured diagnostics foundation.

The config layer is intentionally not complete yet. It accepts enough of the Xray JSON surface to drive the current local interop scenarios.

### Core Runtime

Implemented:

- `Core` lifecycle with `start` and `stop`.
- SOCKS listener startup from config.
- Bound inbound address reporting for tests and CLI startup output.
- Stream dispatch from local SOCKS connections to VLESS outbounds.
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

## Verification Evidence

Recent verified commands:

```bash
cargo fmt --all -- --check
cargo test -p xray-cli --all-targets
XRAY_CORE_CHECKOUT=/Users/antonmalygin/xray-rust/Xray-core cargo test -p xray-cli --test process_interop_tests -- --ignored --nocapture
cargo clippy -p xray-cli -p xray-transport -p xray-proxy -p xray-core-rs --all-targets --locked -- -D warnings
```

Additional targeted checks from the protected transport work:

```bash
cargo test -p xray-transport reality
cargo test -p xray-core-rs --all-targets
cargo test -p xray-proxy --test vless_response_stream_tests
```

Verified local interop scenarios:

- In-process Rust core to real local Xray-core: VLESS TCP.
- In-process Rust core to real local Xray-core: VLESS TLS.
- In-process Rust core to real local Xray-core: VLESS TLS+Vision.
- In-process Rust core to real local Xray-core: VLESS REALITY+Vision.
- Spawned `xray-rust` process to real local Xray-core: VLESS TCP.
- Spawned `xray-rust` process to real local Xray-core: VLESS REALITY+Vision.

## Compatibility Surface Today

The project can currently be treated as a runnable proof for this compatibility profile:

- Client-side local SOCKS inbound.
- Client-side VLESS outbound.
- TCP transport.
- TLS transport.
- REALITY transport with `chrome` fingerprint.
- `xtls-rprx-vision` over protected streams.
- Xray JSON configs for this subset.
- Local process-level execution through `xray-rust`.

This is a real milestone: the first local proxy process can be launched and can move bytes through a real Xray server with REALITY+Vision.

## Remaining Work

### Config Compatibility

The config layer needs to become stricter and broader before real-world configs can be expected to load reliably.

Needed:

- Better handling of unsupported behavior-changing fields.
- Clearer warning versus error rules for ignored fields.
- More inbound and outbound fields from real Xray configs.
- Routing default behavior aligned with Xray-core.
- A fixture corpus from Xray examples and practical client configs.
- Golden parse tests that assert normalized internal config and diagnostics.

This should be the next hardening layer because every later feature depends on stable config semantics.

### HTTP Inbound Runtime

The HTTP parser foundation exists in `xray-proxy`, but the runtime currently starts only SOCKS listeners.

Needed:

- HTTP listener startup from config.
- HTTP CONNECT support through the existing session/outbound path.
- Plain HTTP proxy request support if included in the first compatibility profile.
- Process-level interop test using HTTP inbound to VLESS outbound.

This closes the original local proxy target of SOCKS plus HTTP.

### Mobile FFI

The `xray-ffi` crate exists as a foundation, but the mobile embedding ABI is not yet complete.

Needed:

- Opaque core handle.
- Config load from JSON bytes/string.
- Start and stop lifecycle.
- Error object allocation and release.
- Panic boundary protection.
- Log callback with bounded queue behavior.
- Bound inbound inspection or event callback.
- C harness tests.
- Static library output for Apple platforms.
- Android shared library output.

This is the highest-priority product layer once the config path is stable enough for real profiles.

### Apple iOS And tvOS Packaging

Needed:

- Rust target matrix for iOS device, iOS simulator, tvOS device, and tvOS simulator.
- `staticlib` or compatible artifact generation.
- XCFramework packaging script.
- Header generation and ABI stability checks.
- App-extension-safe runtime assumptions.
- No reliance on process signals for embedded lifecycle.

The core lifecycle already points in this direction because the CLI uses the same start/stop model that FFI should expose directly.

### Android Packaging

Needed:

- Android target matrix for arm64 and x86_64.
- `cdylib` artifact generation.
- Header generation for JNI or direct native integration.
- Runtime initialization rules that work inside Android app processes.
- Basic Gradle-facing artifact layout.

The Rust core should not assume Android-specific APIs in protocol crates.

### TUN Runtime

The `xray-tun` crate exists, but full packet flow is not yet implemented.

Needed:

- Bounded packet ingress and egress queues.
- Packet size validation.
- Flow dispatch from IP packets into outbound sessions.
- Backpressure and drop counters.
- FFI packet push/poll functions.
- Later integration point for a user-space TCP/IP stack.

TUN must stay platform-neutral. iOS `NEPacketTunnelProvider` and Android `VpnService` adapters should sit outside the core ABI.

### Routing And DNS

Needed:

- Xray-compatible routing rules.
- Domain, IP, port, network, and inbound/outbound tag matching.
- Default outbound behavior compatible with Xray-core.
- DNS app behavior.
- Domain strategy handling.
- Sniffing and fake DNS in later slices.
- Geosite and geoip data loading.

Routing should evolve as a rule engine, not as ad hoc checks in individual protocol handlers.

### Additional Protocols

Outbound protocols still needed for broader Xray-core compatibility:

- Freedom.
- Blackhole.
- Trojan.
- Shadowsocks.
- VMess.
- DNS.
- WireGuard.

Inbound protocols still needed:

- HTTP runtime.
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

### Milestone 1: Config Compatibility Hardening

Goal: make the config layer safe enough for practical Xray client profiles.

Deliverables:

- Fixture corpus for current VLESS TCP/TLS/REALITY/Vision configs.
- More complete diagnostics for unsupported fields.
- Default outbound/routing semantics aligned with Xray-core for the supported subset.
- Regression tests for parse success, parse rejection, and warnings.

Why first: every mobile and runtime surface depends on config load behavior. Hardening this now reduces churn in CLI, FFI, and interop tests.

### Milestone 2: Mobile FFI Lifecycle

Goal: expose the already-proven core lifecycle to iOS, tvOS, Android, and desktop hosts through a stable ABI.

Deliverables:

- C ABI for create, load config, start, stop, free, and error release.
- Panic-safe FFI boundary.
- C harness tests.
- Apple and Android build artifact scripts.
- Minimal header generation.

Why second: the process binary has proven the lifecycle. The next product-critical step is letting mobile apps embed the same lifecycle directly.

### Milestone 3: HTTP Inbound Runtime

Goal: complete the original local proxy pair of SOCKS and HTTP.

Deliverables:

- HTTP listener startup from config.
- HTTP CONNECT data path through existing outbound routing.
- Process-level HTTP inbound interop test.

Why third: it expands user-visible local proxy compatibility without disturbing VLESS, TLS, REALITY, or Vision.

### Milestone 4: TUN Packet Boundary

Goal: expose a platform-neutral packet API that mobile VPN adapters can use.

Deliverables:

- Bounded packet queues.
- Packet validation.
- FFI push/poll functions.
- Drop counters and backpressure behavior.
- Initial tests for queue and packet limits.

Why fourth: TUN is essential for mobile VPN mode, but it benefits from having FFI lifecycle and config behavior already settled.

### Milestone 5: Routing, DNS, And Protocol Expansion

Goal: move from the first VLESS client slice toward broader Xray-core compatibility.

Deliverables:

- Rule-based routing.
- DNS behavior compatible with supported profiles.
- Additional outbound protocols.
- Additional inbound protocols.
- Additional transports behind the existing transport abstraction.

Why fifth: this is the expansion phase and should build on stable config, runtime, and mobile boundaries.

## Immediate Next Spec Recommendation

The next detailed implementation spec should be:

```text
Config Compatibility Hardening
```

It should define the exact supported config fixture set, diagnostics policy, routing/default outbound behavior, and the test matrix for practical VLESS REALITY/Vision client configs.

After that, the next detailed implementation plan should be generated from that spec and executed task by task.
