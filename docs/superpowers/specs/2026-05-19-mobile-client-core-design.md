# Mobile Client Core Design

## Purpose

Build a Rust implementation of the first mobile/client slice of Xray-core compatibility. The first product is an embeddable core for iOS, tvOS, Android, and desktop testing, exposed through a stable C ABI and implemented as a clean Rust workspace rather than a package-by-package port of the Go code.

The first compatibility target is a real client profile:

- Local SOCKS5 inbound.
- Local HTTP proxy inbound.
- Platform-neutral TUN packet API.
- VLESS outbound over TCP.
- TLS/REALITY client transport.
- `xtls-rprx-vision` flow.
- Xray JSON config subset accepted as the public config format.

The design must keep the path open for the rest of Xray-core: additional protocols, transports, routing features, platform adapters, server mode, and config compatibility must fit without rewriting the core.

## Repository Layout

The Rust workspace lives next to the cloned Go reference implementation:

- `Xray-core/`: read-only reference implementation and compatibility oracle.
- `Cargo.toml`: Rust workspace root.
- `crates/xray-core-rs`: public Rust API for core lifecycle.
- `crates/xray-config`: Xray JSON subset parser and normalized config model.
- `crates/xray-runtime`: Tokio runtime integration, cancellation, task supervision, resource limits.
- `crates/xray-proxy`: inbound and outbound proxy implementations.
- `crates/xray-transport`: TCP, TLS, REALITY, and future network transports.
- `crates/xray-routing`: dispatch, target resolution, DNS abstraction, routing decisions.
- `crates/xray-tun`: platform-neutral TUN packet API and packet dispatch contracts.
- `crates/xray-ffi`: C ABI for mobile embedding.
- `tests/compat`: Go Xray-core oracle tests and cross-process end-to-end tests.
- `tests/fixtures`: JSON configs, golden wire vectors, certs, and deterministic packet fixtures.

Each crate owns a stable boundary. Protocol code must not depend on FFI. FFI must not know protocol internals. Runtime code must not know Xray JSON details after normalization.

## Architecture

The core uses a typed internal model instead of carrying Go protobuf structures through the runtime. Xray JSON is parsed at the edge, validated, and normalized into Rust structs that express the behavior the runtime needs.

Main layers:

- `ConfigLoader`: parses user input and produces `CoreConfig`.
- `Core`: owns lifecycle, listeners, TUN endpoint, outbound registry, routing table, stats, and shutdown.
- `Inbound`: accepts local traffic and produces a `Session`.
- `Router`: maps a `Session` target to an `Outbound`.
- `Outbound`: opens upstream transport and proxies a stream or datagram flow.
- `Transport`: creates encrypted or plain connections.
- `TunEndpoint`: accepts and emits IP packets through bounded queues.

All protocol and transport families are registered through explicit registries:

- `InboundFactory` for SOCKS, HTTP, TUN-backed flows, and later Dokodemo, VLESS inbound, Trojan inbound, Shadowsocks inbound.
- `OutboundFactory` for VLESS first, then Freedom, Blackhole, Trojan, Shadowsocks, VMess, WireGuard, DNS.
- `TransportFactory` for TCP and REALITY/TLS first, then WebSocket, gRPC, XHTTP, QUIC/Hysteria, mKCP.
- `ConfigSectionParser` for mapping Xray protocol settings into typed internal config.

This keeps VLESS/REALITY/Vision as the first module, not as a special-case spine of the whole project.

## First Supported Config Subset

The public config input for the first slice is Xray JSON. The parser supports the fields needed for the target mobile profile:

- `inbounds[].protocol`: `socks`, `http`, and a Rust-specific TUN adapter entry if needed for embedding.
- `inbounds[].listen`, `inbounds[].port`, `inbounds[].settings`.
- `outbounds[].protocol`: `vless`.
- `outbounds[].settings.vnext[].address`, `port`, `users[].id`, `users[].encryption`, `users[].flow`.
- `outbounds[].streamSettings.network`: `tcp`.
- `outbounds[].streamSettings.security`: `tls` or `reality`.
- `tlsSettings.serverName`, certificate verification controls needed for client mode, and fingerprint strategy where supported.
- `realitySettings.serverName`, `fingerprint`, `publicKey`, `shortId`, `spiderX`.
- Minimal `routing` with default outbound selection.

Unsupported fields produce structured diagnostics. The parser must not silently ignore unknown behavior-changing fields. Diagnostics include severity, message, and JSON path. Non-critical fields can be accepted with warnings only when ignoring them is behaviorally safe for the first target.

## Mobile C ABI

The mobile embedding surface is implemented in `xray-ffi` using opaque handles:

- `xray_core_new`
- `xray_core_load_config_json`
- `xray_core_start`
- `xray_core_stop`
- `xray_core_free`
- `xray_core_set_log_callback`
- `xray_core_get_stats_snapshot`
- `xray_tun_push_packet`
- `xray_tun_poll_packet`
- `xray_error_free`

FFI returns status codes and owned error objects. Errors include a stable code, a message, and optional config path. Rust panics must not cross the FFI boundary. Callbacks must not block the async runtime; logs and events pass through bounded queues and count dropped events.

Build outputs:

- `staticlib` for Apple `XCFramework`.
- `cdylib` for Android.
- `rlib` for Rust tests and future CLI.

The first slice does not include Swift, Kotlin, `NEPacketTunnelProvider`, or Android `VpnService` adapters. It defines the ABI those adapters will use.

## TUN Design

The first TUN implementation is platform-neutral. The core exposes packet ingress and egress through the C ABI and Rust API:

- Host app pushes raw IP packets into the core.
- Core emits raw IP packets for the host app to write to the OS tunnel.
- Queues are bounded.
- Packet size is capped.
- Backpressure is explicit.
- Dropped packets are counted.

The first TUN slice includes the API, packet validation, queueing, stats, and routing hooks. A full user-space TCP/IP stack is not required in the first slice, but the design leaves a clean insertion point for `smoltcp` or another stack in a later slice.

SOCKS5 and HTTP proxy inbounds are implemented first as the fastest end-to-end validation path. TUN support is present as a stable packet contract so Apple and Android adapters can be built without changing the core ABI.

## VLESS, REALITY, and Vision

VLESS outbound is implemented in `xray-proxy` as a protocol state machine:

- Request version `0`.
- UUID user id.
- Header addons encoded as protobuf-compatible bytes for `Flow = "xtls-rprx-vision"`.
- TCP command and address/port encoding compatible with Xray-core.
- Response header validation.
- `encryption: none` for the first slice.

Vision is implemented as a separate state machine, not interleaved with copy loops:

- Padding writer.
- Unpadding reader.
- TLS ClientHello and ServerHello detection.
- TLS 1.3 recognition.
- Direct-copy eligibility state.

The first version uses portable async copy and bounded buffers. Linux/Android zero-copy and splice-like optimizations can be added later behind platform feature gates. The API must not require unsafe access to TLS internals. If exact Vision behavior requires observing buffered TLS bytes, the transport layer must expose a safe abstraction for those bytes.

REALITY is client-only in the first slice. The transport layer owns:

- TCP dial.
- TLS/uTLS-compatible client behavior.
- REALITY handshake inputs: `serverName`, `fingerprint`, `publicKey`, `shortId`, `spiderX`.
- Certificate and server-name validation semantics for the supported subset.

The implementation must isolate REALITY so normal TLS, future ECH, and other security layers can share the transport interface without special casing in VLESS.

## Routing and DNS

The first routing implementation supports:

- Default outbound.
- Target address, domain, port, and network from SOCKS/HTTP requests.
- DNS resolution behind a `DnsResolver` trait.
- Stats labels for inbound tag, outbound tag, and target.

Full Xray routing rules, geosite, geoip, balancers, observatory, DNS app behavior, sniffing, and fake DNS are outside the first slice. The internal router must still be rule-oriented so those features can be added incrementally.

## Memory and Performance Constraints

Mobile resource usage is a design constraint, not a later optimization.

Rules:

- No unbounded queues on data paths.
- No task spawn per tiny packet when a stream task can own the flow.
- Prefer `bytes::Bytes` and `BytesMut` for shared packet and stream buffers.
- Reuse buffers only through small, local pools where profiling shows benefit.
- Keep config and runtime models compact and owned.
- Avoid global mutable registries after startup; registries are constructed during core initialization.
- Apply backpressure on TUN, listener accept loops, log callbacks, and stats events.
- Expose resource limits in internal config even when the first public JSON subset does not yet surface all of them.

The first performance target is predictable memory behavior on iOS/tvOS/Android. Platform-specific zero-copy optimizations are secondary and must not complicate the portable path.

## Cross-Platform Constraints

The core must build for:

- iOS arm64 device and simulator targets supported by Rust.
- tvOS arm64 device and simulator targets supported by Rust.
- Android arm64 and x86_64.
- macOS and Linux for local testing.

The core must avoid APIs that are forbidden or unreliable in mobile app extensions. Local listeners may be platform-policy-sensitive, so the runtime must allow host apps to disable SOCKS/HTTP listeners and use only TUN or host-supplied streams in later slices.

## Compatibility Test Strategy

Compatibility is tested at three levels.

Config tests:

- Parse supported Xray JSON fixtures.
- Reject unsupported behavior-changing fields with exact JSON paths.
- Normalize configs into deterministic internal structs.

Wire tests:

- Generate golden VLESS and Vision vectors from local Go `Xray-core`.
- Compare Rust encoding and decoding byte-for-byte.
- Test fragmentation boundaries for Vision padding and unpadding.
- Test TLS detection state transitions.

End-to-end tests:

- Launch Go `Xray-core` as a server using a VLESS + TCP + REALITY + Vision config.
- Launch Rust core as the client.
- Send TCP payload through local SOCKS and HTTP inbounds.
- Verify payload round trip and connection shutdown.
- Exercise domain targets and IP targets.

FFI tests:

- C harness creates, configures, starts, stops, and frees a core.
- C harness verifies error objects and callback behavior.
- TUN packet push/poll validates queue bounds and packet size limits.

The Go repository remains an oracle, not a dependency of runtime code.

## First Slice Non-Goals

These are intentionally outside the first implementation slice:

- VMess.
- Trojan.
- Shadowsocks and Shadowsocks 2022.
- Hysteria.
- WireGuard.
- QUIC, mKCP, WebSocket, gRPC, XHTTP, HTTPUpgrade.
- Server-side VLESS inbound.
- Full TUN TCP/IP stack.
- Full routing rule compatibility.
- geosite and geoip databases.
- Xray API server.
- Commander, observatory, reverse proxy, policy parity, and stats API parity.
- Swift, Kotlin, iOS `NetworkExtension`, tvOS app, or Android `VpnService` adapters.

The architecture explicitly reserves extension points for these features. Adding them should mean implementing new factories and config parsers, not rewriting `Core`, `Router`, FFI, or transport abstractions.

## Evolution Path

After the first slice passes compatibility tests, the next increments should be:

1. Apple adapter: `XCFramework`, Swift wrapper, and `NEPacketTunnelProvider` integration for iOS/tvOS.
2. Android adapter: JNI/Kotlin wrapper and `VpnService` integration.
3. Full TUN TCP/IP stack through `xray-tun`.
4. Freedom and blackhole outbounds for routing tests and direct/block behavior.
5. Trojan and Shadowsocks outbound compatibility.
6. Additional transports: WebSocket, gRPC, XHTTP, then QUIC/Hysteria and mKCP.
7. Server-side VLESS inbound.
8. Full routing, DNS, geosite, geoip, balancers, and API compatibility.

Each increment must add compatibility fixtures against `Xray-core` before broadening behavior.

