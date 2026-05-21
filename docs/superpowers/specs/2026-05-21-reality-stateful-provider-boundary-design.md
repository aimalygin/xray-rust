# REALITY Stateful Provider Boundary Design

## Goal

Introduce a stateful REALITY TLS provider boundary so `RealityRuntimeEngine` can hand live TLS completion back to the same session that generated the Chrome/uTLS-compatible ClientHello.

The current `RealityClientHelloProvider` is useful for deterministic oracle fixtures, but it only returns owned ClientHello metadata. A live REALITY TLS implementation needs more: the TLS implementation must keep the handshake state that produced the ClientHello, accept the patched REALITY session id, continue the transcript over the connected TCP stream, verify the REALITY certificate binding, and then expose the protected stream.

This slice should add that boundary without committing to Go/uTLS, FFI, subprocesses, platform TLS APIs, or a pure Rust Chrome implementation yet.

## Non-Goals

This slice does not implement a production Chrome/uTLS-compatible TLS stack, does not run a local Xray-core server, does not enable REALITY in `TransportDialer::system()`, and does not un-ignore live compatibility tests.

It also does not remove the existing oracle-backed `RealityClientHelloProvider` tests. Those tests remain the source of truth for deterministic ClientHello metadata and REALITY session-id patching until a live provider exists.

## Current Gap

`RealityRuntimeEngine` currently receives an `Arc<dyn RealityClientHelloProvider>`, asks it for `RealityPreparedClientHello`, prepares the REALITY session id, opens TCP, and then returns `TransportError::RealityTlsCompletionUnsupported`.

That shape cannot complete a real handshake because the provider has already handed over a copy of the ClientHello data. The TLS engine that generated the ClientHello must still exist when the patched ClientHello is written and the rest of the TLS transcript is processed.

The next boundary must model a one-shot TLS session, not a stateless byte factory.

## Public API Shape

Add these session traits to `crates/xray-transport/src/reality_connector.rs` and re-export them from `crates/xray-transport/src/lib.rs`:

```rust
pub trait RealityTlsSessionProvider: Send + Sync {
    fn create_session(
        &self,
        request: RealityClientHelloRequest<'_>,
    ) -> Result<Box<dyn RealityTlsSession>, RealityError>;
}
```

Add a one-shot session trait:

```rust
#[async_trait]
pub trait RealityTlsSession: Send {
    fn prepared_client_hello(&self) -> Result<RealityPreparedClientHello, RealityError>;

    async fn complete(
        self: Box<Self>,
        tcp_stream: tokio::net::TcpStream,
        prepared: RealityPreparedHandshake,
    ) -> Result<BoxedTransportStream, TransportError>;
}
```

`self: Box<Self>` on `complete` is intentional. A REALITY TLS session is consumed exactly once, which prevents accidental reuse of ClientHello state and gives provider implementations a clear place to drop private handshake state.

`RealityRuntimeEngine` should depend on `Arc<dyn RealityTlsSessionProvider>` instead of `Arc<dyn RealityClientHelloProvider>`:

```rust
#[derive(Clone)]
pub struct RealityRuntimeEngine {
    session_provider: Arc<dyn RealityTlsSessionProvider>,
    dns_resolver: Arc<dyn DnsResolver>,
    context_provider: Arc<dyn RealityHandshakeContextProvider>,
}
```

The constructor should make that dependency explicit:

```rust
impl RealityRuntimeEngine {
    pub fn new(session_provider: Arc<dyn RealityTlsSessionProvider>) -> Self;
}
```

These names are the intended public API for this slice. The ownership model is: shared provider, one-shot session, one live TCP stream, one consumed prepared handshake.

## Connector API

Keep `RealityClientHelloProvider` for low-level tests and oracle fixture validation, but add a connector method that accepts already prepared ClientHello metadata:

```rust
impl RealityConnector {
    pub fn prepare_handshake_with_client_hello(
        &self,
        prepared_client_hello: RealityPreparedClientHello,
        context: RealityHandshakeContext,
    ) -> Result<RealityPreparedHandshake, RealityError>;
}
```

The existing `prepare_handshake(&dyn RealityClientHelloProvider, context)` should delegate to this new method. That keeps all metadata validation, fingerprint checks, session-id sealing, and error behavior in one place.

This avoids duplicating the REALITY patching logic inside `RealityRuntimeEngine` and gives future live providers a small, stable contract: provide a valid prepared ClientHello, then accept the patched handshake back in `complete`.

## Runtime Flow

For an explicitly injected REALITY runtime engine:

1. Build `RealityConnector::new(config.clone())`.
2. Reject unsupported fingerprints before session provider, context provider, DNS, or TCP work.
3. Create a one-shot TLS session from `RealityTlsSessionProvider`.
4. Ask the session for `RealityPreparedClientHello`.
5. Obtain `RealityHandshakeContext`.
6. Call `RealityConnector::prepare_handshake_with_client_hello`.
7. Resolve a domain target through the injected `DnsResolver`, or use an IP target directly.
8. Open `tokio::net::TcpStream`.
9. Call `session.complete(tcp_stream, prepared_handshake).await`.
10. Return the protected stream only if the session completes TLS and REALITY verification successfully.

In this slice, scripted test sessions may return `TransportError::RealityTlsCompletionUnsupported` from `complete`. The important change is that the gate moves behind the stateful session boundary; `RealityRuntimeEngine` no longer owns the final live-TLS decision.

## Error Handling

Unsupported fingerprints must continue to fail before provider, context, DNS, or TCP dependencies are touched.

Invalid ClientHello metadata from `prepared_client_hello` must map through the existing `RealityError` path and skip DNS/TCP work.

DNS and TCP errors should keep using the existing `TransportError` variants.

Errors from `RealityTlsSession::complete` should propagate unchanged. That includes the current typed gate:

```rust
TransportError::RealityTlsCompletionUnsupported
```

This lets a future production provider replace the gate with real TLS and certificate verification without changing `TransportDialer`, VLESS, or Vision code.

## Memory And Mobile Constraints

The boundary must not introduce background tasks, unbounded buffering, process spawning, FFI requirements, dynamic loading, or platform TLS dependencies.

The session may own TLS state and one ClientHello-sized buffer, but all large or secret-bearing values should be consumed promptly:

- `RealityPreparedClientHello` remains owned and zeroized by existing rules;
- `RealityPreparedHandshake` is consumed by `complete`;
- `complete` consumes the boxed session;
- `Debug` output must keep redacting short ids and other secret-bearing values.

This keeps the architecture open for iOS, tvOS, Android, Linux, macOS, and Windows. A future pure Rust provider can implement the same traits. A dev-only Go/uTLS bridge can also implement them for desktop interop experiments without leaking that decision into the runtime architecture.

## Tests

Required tests for this slice:

- `RealityConnector::prepare_handshake_with_client_hello` accepts the existing Chrome fixture and produces the same patched handshake behavior as the provider-based method.
- The old provider-based connector method delegates to the new method and preserves validation errors.
- `RealityRuntimeEngine` rejects unsupported fingerprints before creating a session, reading context, resolving DNS, or opening TCP.
- A supported config creates exactly one session with the configured `server_name` and `fingerprint`.
- Invalid ClientHello metadata returned by a session skips DNS/TCP and returns the existing REALITY error path.
- IP targets connect without resolver calls, then invoke `RealityTlsSession::complete`.
- Domain targets resolve through the injected resolver before TCP and completion.
- `complete` receives the patched `RealityPreparedHandshake`, not the original unpatched ClientHello bytes.
- A scripted session error, including `RealityTlsCompletionUnsupported`, propagates unchanged.
- The default `TransportDialer::system()` still rejects REALITY without an explicitly injected engine.

Existing oracle and certificate-binding tests should remain unchanged except for small helper updates required by the new connector method.

## Verification

Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

The Rust suite uses local loopback tests, so it may need loopback permission in this sandbox.

## Future Extension Path

After this slice, the next independent implementation can be one of:

- a pure Rust Chrome/uTLS-compatible provider for the production mobile path;
- a dev-only Go/uTLS bridge for local interop learning;
- an FFI-backed provider if a platform-specific experiment becomes useful.

All three should satisfy the same `RealityTlsSessionProvider` and `RealityTlsSession` boundary. That keeps `xray-core-rs`, VLESS, Vision, routing, config parsing, and the transport dialer stable while the provider implementation evolves.
