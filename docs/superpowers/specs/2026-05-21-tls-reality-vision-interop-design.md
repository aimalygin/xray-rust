# TLS, REALITY, and Vision Interop Design

## Context

The current local interop branch already proves a real SOCKS -> Rust VLESS/TCP outbound -> local Xray-core VLESS inbound -> freedom -> echo path. The next compatibility layer is the protected VLESS path used by practical Xray deployments:

- VLESS over TLS.
- VLESS `xtls-rprx-vision` over TLS.
- VLESS `xtls-rprx-vision` over REALITY.

The runtime already has a reusable outbound boundary, DNS injection, and TLS connector injection. It also has REALITY session-id sealing, ClientHello validation, and a runtime engine abstraction, but it deliberately does not yet have a live REALITY TLS session provider.

## Approach

Use the existing local Xray-core interop harness as the oracle. The harness should run the Rust core as a SOCKS inbound and run the cloned Go Xray-core as the upstream VLESS server. The client sends bytes through SOCKS and the test only passes when the local echo server receives and returns the exact payload.

For TLS, generate a self-signed `vless.test` certificate in the Rust test, write PEM files into the Xray temp directory, configure Xray with `tlsSettings.certificates`, and inject a Rust `TlsConnector` whose root store trusts that generated certificate.

For Vision over TLS, keep the same TLS transport and configure both sides with VLESS user flow `xtls-rprx-vision`. Rust must allow Vision on any protected stream that can preserve the byte stream after TLS, so TLS and REALITY are valid carriers while raw TCP remains rejected.

For REALITY, do not fake a successful local run. The current Rust path can build and validate REALITY handshakes, but it cannot complete a live TLS handshake because rustls does not expose a patchable ClientHello/session transcript boundary. The design keeps REALITY behind the existing `RealityTlsSessionProvider` abstraction until a provider can generate a Chrome/uTLS-compatible ClientHello, patch the session id before the transcript is committed, complete TLS, and verify the REALITY certificate binding. The local Xray REALITY scenario should be documented as the next oracle target, but this slice must only claim REALITY live interop if that provider exists and passes the real process test.

## Architecture

### Local Xray Harness

Extend `crates/xray-core-rs/tests/local_xray_interop_tests.rs` with a small scenario model:

- `XrayVlessServerConfig` owns the inbound security, optional VLESS user flow, and temp files.
- `XrayInboundSecurity` supports raw TCP and TLS now, and can later grow REALITY without rewriting the test body.
- `RustVlessClientConfig` derives the Rust `CoreConfig`, optional injected DNS resolver, and optional injected `TransportDialer`.

The common runner should start Xray, start the echo server, start Rust core, perform SOCKS5 connect, write one payload, read it back, then stop all processes/tasks. On failure it should print Xray stdout/stderr.

### TLS

The TLS test should:

- Generate a `vless.test` self-signed certificate using `rcgen`.
- Write `server.crt.pem` and `server.key.pem` next to the generated Xray config.
- Configure Xray with `"security": "tls"` and `certificateFile`/`keyFile`.
- Configure Rust with `StreamSecurity::Tls(TlsSettings { server_name: Some("vless.test"), fingerprint: None })`.
- Inject a `TlsConnector` using a root store containing the generated certificate.

The test name should clearly say it reaches the echo server through local Xray VLESS/TLS.

### Vision Over TLS

The Vision test should:

- Use the same TLS setup.
- Add `"flow": "xtls-rprx-vision"` to the Xray inbound VLESS client.
- Add `Some("xtls-rprx-vision")` to the Rust outbound user.
- Keep raw TCP Vision rejected.
- Add unit coverage that TLS+Vision selection is accepted and raw Vision is still rejected.

The first passing test must be a real local Xray-core process test. Fake Vision-only unit tests are useful regression coverage but do not prove protocol compatibility.

### REALITY

The immediate code path should remain honest:

- Existing REALITY config selection and session-id cryptographic tests remain valid.
- Runtime still returns `UnsupportedConnectorConfig("reality")` without an injected live engine.
- A live REALITY interop test should only be enabled once a native `RealityTlsSessionProvider` exists.

The future provider must meet these requirements:

- Produce a Chrome-compatible ClientHello with a 32-byte session id and X25519 key share.
- Expose raw ClientHello bytes, random, session-id offset, and local X25519 private key.
- Let Rust patch the session id before any TLS transcript state is finalized.
- Complete TLS over the patched ClientHello.
- Verify Xray REALITY certificate binding before returning a protected stream to VLESS.

## Error Handling

Interop tests should wrap process startup and payload exchange in timeouts. On handshake or payload timeout, print Xray logs before panicking. Unsupported or unsafe configurations should fail before dialing whenever possible:

- TLS fingerprints remain unsupported in the rustls path.
- Vision over raw TCP remains `UnsupportedOutboundFlow`.
- REALITY without a live engine remains `UnsupportedConnectorConfig("reality")`.

## Performance And Memory

This work must keep the runtime path streaming. The local interop runner may allocate test configs and temp files freely, but production code should not buffer proxied payloads beyond existing stream wrappers. Vision should remain a streaming `AsyncRead + AsyncWrite` wrapper and TLS should use the existing boxed transport boundary.

## Verification

Required checks for this slice:

- Unit/runtime tests for outbound selection and fake TLS runtime.
- Ignored local Xray test for raw VLESS/TCP remains passing.
- New ignored local Xray test for VLESS/TLS passes.
- New ignored local Xray test for VLESS/TLS/Vision passes if the current Vision framing is compatible; otherwise the failing behavior must be captured before changing Vision internals.
- `cargo fmt --all -- --check`.
- Targeted `cargo test` for changed crates/tests.
- `cargo clippy -p xray-proxy -p xray-core-rs --all-targets --locked -- -D warnings`.

## Out Of Scope

This slice does not add TLS fingerprint emulation, uTLS, mobile packaging, Android/iOS build scripts, or a fake REALITY success path. Those remain compatible with the architecture because the protected transport is already abstracted behind `ConnectorConfig` and `TransportDialer`.
