# REALITY Runtime Engine Design

## Goal

Add the first real runtime engine behind `RealityTlsEngine` so the project has a tested transport-owned path for REALITY connection setup up to the exact point where live Chrome/uTLS TLS completion must be inserted.

This slice must not claim live Xray-core-compatible REALITY support. It should make the runtime boundary concrete, deterministic, and mobile-friendly while preserving the default production gate.

## Scope

This slice adds a `RealityRuntimeEngine` in `xray-transport`.

The engine should:

- implement the existing `RealityTlsEngine` trait;
- validate unsupported REALITY fingerprints before DNS, TCP, or ClientHello provider work;
- resolve domain targets through an injectable `DnsResolver`;
- connect TCP to IP targets or resolved domain targets;
- obtain a deterministic `RealityHandshakeContext` through an injectable time/context provider;
- call `RealityConnector::prepare_handshake` through an injectable `RealityClientHelloProvider`;
- stop with a typed "live TLS completion is not implemented" error after a prepared handshake is available.

This slice does not generate a Chrome/uTLS ClientHello, does not complete the TLS transcript, does not verify a live server certificate, does not launch local Xray-core, and does not un-ignore `tests/compat/vless_reality_vision.rs`.

## Architecture

`xray-transport` continues to own the REALITY protected-stream boundary. `xray-core-rs` should keep treating REALITY as a transport connector and should not learn about ClientHello providers, session-id sealing, or certificate verification.

Add a focused runtime module, for example `crates/xray-transport/src/reality_runtime.rs`, with these responsibilities:

- construct a `RealityConnector` from `RealityClientConfig`;
- validate the supported fingerprint gate;
- build a `RealityHandshakeContext`;
- prepare and validate the REALITY handshake;
- resolve the target if it is a domain;
- establish the underlying TCP stream;
- return a gated error before exposing any stream.

The runtime engine should be injectable, not installed into `TransportDialer::system()`. The existing default behavior remains:

```rust
TransportError::UnsupportedConnectorConfig("reality")
```

Only callers that explicitly pass `TransportDialer::with_reality_engine(Arc::new(engine))` exercise the new runtime engine.

## Public API Shape

The runtime engine should be cheap to clone and should own dependencies behind `Arc`:

```rust
#[derive(Clone)]
pub struct RealityRuntimeEngine {
    client_hello_provider: Arc<dyn RealityClientHelloProvider>,
    dns_resolver: Arc<dyn DnsResolver>,
    context_provider: Arc<dyn RealityHandshakeContextProvider>,
}
```

The exact constructor names can follow local style, but the intended shape is:

```rust
impl RealityRuntimeEngine {
    pub fn new(client_hello_provider: Arc<dyn RealityClientHelloProvider>) -> Self;

    pub fn with_dns_resolver(mut self, dns_resolver: Arc<dyn DnsResolver>) -> Self;

    pub fn with_context_provider(
        mut self,
        context_provider: Arc<dyn RealityHandshakeContextProvider>,
    ) -> Self;
}
```

The default constructor may use `SystemDnsResolver` and a system context provider. It must still require an explicit ClientHello provider because the project does not yet have a built-in Chrome/uTLS-compatible provider.

Add a small context provider trait:

```rust
pub trait RealityHandshakeContextProvider: Send + Sync {
    fn context(&self) -> RealityHandshakeContext;
}
```

The system implementation should produce the existing version bytes used in tests and the current Unix timestamp as `u32`. Tests can inject a fixed provider.

## Data Flow

For an explicit runtime engine call:

1. `TransportDialer` receives `ConnectorConfig::Reality(config)`.
2. `TransportDialer` routes to the injected `RealityRuntimeEngine`.
3. The engine builds `RealityConnector::new(config.clone())`.
4. The engine rejects unsupported fingerprints before touching DNS, TCP, or provider dependencies.
5. The engine obtains `RealityHandshakeContext` from its provider.
6. The engine calls `RealityConnector::prepare_handshake`.
7. The engine resolves `TargetAddr::Domain` through its `DnsResolver`; `TargetAddr::Ip` is used directly.
8. The engine opens a `tokio::net::TcpStream`.
9. The engine drops the TCP stream and returns the typed live-TLS gate error.

This ordering proves the real runtime shape without feeding unverified bytes to VLESS or Vision. When live TLS exists, step 9 becomes:

1. write the patched ClientHello to the TCP stream;
2. complete the TLS transcript using the same ClientHello/key-share state;
3. verify the leaf certificate with `verify_reality_certificate_der`;
4. return the verified protected stream.

## Errors

Add typed errors rather than stringly typed success paths.

`RealityConnector::prepare_handshake` failures should map into `TransportError`, for example:

```rust
#[error("reality handshake failed: {0}")]
Reality(#[from] crate::reality::RealityError),
```

The intentional live gate should be explicit:

```rust
#[error("REALITY live TLS completion is not implemented")]
RealityTlsCompletionUnsupported,
```

The old default gate must remain `UnsupportedConnectorConfig("reality")` when no engine is injected.

DNS and TCP errors should reuse existing `TransportError::Dns`, `NoResolvedAddress`, `NeedsDns`, and `Tcp` behavior.

## Memory And Mobile Constraints

The engine must not allocate unbounded buffers or spawn background tasks. It should hold only shared dependencies, clone the small `RealityClientConfig` already required by the connector path, and let `TcpStream` close immediately on gated errors.

Secret material remains governed by the existing zeroization rules in `RealityClientConfig`, `RealityPreparedClientHello`, `RealityHandshakeInput`, `RealityPreparedHandshake`, and `RealityHandshakePlan`. `Debug` output must continue to redact short ids and other secret-bearing values.

The API avoids FFI, dynamic loading, process spawning, or platform-specific TLS dependencies in this slice. That keeps iOS, tvOS, Android, Linux, macOS, and Windows build paths open for the future provider choice.

## Tests

Required transport tests:

- default `TransportDialer::system()` still rejects REALITY without an injected engine;
- unsupported fingerprint returns `RealityError::UnsupportedRealityFingerprint` mapped through `TransportError` before resolver, TCP, or provider calls;
- IP targets connect without resolver calls;
- domain targets use the injected resolver and dial the resolved socket address;
- the ClientHello provider receives the configured `server_name` and `fingerprint`;
- the fixed context provider is invoked on supported configs and skipped on unsupported fingerprints;
- a successful prepared handshake reaches `RealityTlsCompletionUnsupported`;
- short ids are still redacted in `Debug` output for runtime-facing config/plan values.

Existing REALITY oracle tests remain the source of truth for session-id sealing, ClientHello metadata validation, and certificate binding.

## Verification

Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

The full Rust test suite needs local loopback permission in this sandbox because existing runtime tests bind and connect local sockets.

## Future Extension Path

The next slice after this can choose between a Go/uTLS-backed provider, an external FFI provider, or a pure Rust Chrome/uTLS-compatible provider. That provider should satisfy the existing `RealityClientHelloProvider` boundary first.

Once a provider can preserve the ClientHello bytes and matching TLS state, `RealityRuntimeEngine` can replace the final gated error with live TLS completion and certificate verification without changing `xray-core-rs` or Vision wrapping.
