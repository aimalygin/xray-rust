# REALITY Runtime Boundary Design

## Goal

Open the runtime path for `VLESS + REALITY + xtls-rprx-vision` up to an injectable protected-stream boundary, without claiming live Xray-core-compatible REALITY networking yet.

This slice should remove the last hard runtime stop at `TransportDialer::Reality` only when a caller supplies an explicit test/runtime REALITY engine. The default production dialer remains closed until a real Chrome/uTLS-compatible TLS engine exists.

## Scope

This slice adds the runtime abstraction and fake-engine test path needed to prove that:

- core selection can carry a REALITY connector config into the transport dialer;
- a REALITY engine can return a protected async stream;
- `xray-core-rs` writes the VLESS request header to that protected stream;
- `VisionStream` wraps the protected stream for `xtls-rprx-vision`;
- raw TCP/TLS Vision flows remain rejected.

This slice does not implement a real TLS 1.3 handshake engine, does not launch local Xray-core, does not un-ignore `tests/compat/vless_reality_vision.rs`, and does not use ordinary `rustls` as a fake REALITY substitute.

## Why Not Plain Rustls

Xray-core REALITY depends on uTLS/Chrome ClientHello behavior: the client builds a Chrome-shaped TLS 1.3 ClientHello, patches the raw session-id bytes, derives a REALITY auth key from the exact local ECDHE key share, completes TLS, and accepts the stream only after REALITY certificate verification.

Ordinary `rustls` does not expose a stable supported API for generating and patching that raw Chrome/uTLS ClientHello while preserving the matching TLS state. Wiring REALITY through plain `rustls` would create a working TLS stream that is not protocol-compatible with Xray-core REALITY. This design keeps the runtime path honest by introducing a replaceable engine boundary instead.

## Architecture

`xray-transport` owns the new protected-stream boundary.

Add a trait-shaped dependency for REALITY runtime connection:

```rust
#[async_trait]
pub trait RealityTlsEngine: Send + Sync {
    async fn connect(
        &self,
        config: &RealityClientConfig,
        target: &Target,
    ) -> Result<BoxedTransportStream, TransportError>;
}
```

`TransportDialer` should hold an optional `Arc<dyn RealityTlsEngine>`. The system/default constructor leaves this field empty and continues returning `TransportError::UnsupportedConnectorConfig("reality")` for REALITY configs. A test/runtime constructor accepts an engine and routes `ConnectorConfig::Reality(config)` to it.

The future real engine will own the difficult TLS work:

1. create a validated Chrome/uTLS-compatible `RealityPreparedClientHello`;
2. call `RealityConnector::prepare_handshake`;
3. write the patched ClientHello and complete TLS with the same key-share state;
4. verify the leaf certificate with `verify_reality_certificate_der`;
5. return only the verified protected stream.

The current slice only proves the runtime boundary with a fake engine that returns an already protected in-memory or loopback stream.

## Core Data Flow

For non-Vision VLESS:

1. `xray-core-rs` selects a VLESS TCP outbound.
2. `TransportDialer` returns TCP, TLS, or injected REALITY protected stream.
3. `xray-core-rs` writes the VLESS request header.
4. The caller uses the returned stream directly.

For `xtls-rprx-vision`:

1. selection allows the flow only with REALITY security;
2. `TransportDialer` must return a REALITY protected stream;
3. `xray-core-rs` writes the VLESS request header before wrapping;
4. `xray-core-rs` returns `VisionStream<protected_stream>`;
5. subsequent payload writes are Vision padded blocks.

This preserves the existing boundary where VLESS header encoding remains in `xray-core-rs`, Vision framing remains in `xray-proxy`, and REALITY protected-stream creation remains in `xray-transport`.

## Runtime Gating

The default `TransportDialer::system()` must keep REALITY closed. That preserves the no-partial-live-launch rule for real users and mobile embedding.

Only explicitly constructed dialers with an injected `RealityTlsEngine` may route REALITY. This gives tests a real runtime path without implying the default binary/client can connect to Xray-core REALITY servers yet.

Raw TCP/TLS with `xtls-rprx-vision` remain rejected through `CoreError::UnsupportedOutboundFlow`. Unknown VLESS flows remain rejected by config parsing and runtime guards.

## Errors

Keep the existing unsupported connector error for default REALITY:

```rust
TransportError::UnsupportedConnectorConfig("reality")
```

REALITY engine failures should be mapped into `TransportError` without stringly typed success paths. If a fake engine needs to surface a deliberate failure in tests, use an existing typed variant where it fits or add a narrow variant such as `TransportError::Reality(String)` only if the implementation needs it.

Malformed Vision blocks still surface as `std::io::ErrorKind::InvalidData` from `VisionStream`.

## Memory And Mobile Constraints

The runtime boundary must not introduce unbounded buffering. `TransportDialer` stores the injected engine behind `Arc<dyn RealityTlsEngine>` and clones only the small connector config already owned by `ConnectorConfig`.

The fake engine in tests must not allocate background queues larger than needed for deterministic duplex assertions. The future real engine must preserve existing secret-redaction and zeroization rules for ClientHello private keys, shared secrets, auth keys, and short ids.

## Tests

Required tests for this slice:

- `xray-transport` unit/integration test proving default `TransportDialer::system()` still rejects REALITY configs.
- `xray-transport` test proving an injected fake REALITY engine receives the exact `RealityClientConfig` and target.
- `xray-transport` test proving the injected fake engine returns a boxed protected stream that can carry bytes.
- `xray-core-rs` test proving `VLESS + REALITY + Vision` no longer fails before transport when an injected REALITY engine exists.
- `xray-core-rs` test proving the fake protected stream first receives a VLESS request header, then subsequent writes are Vision padded blocks.
- guard tests proving raw TCP/TLS Vision remain rejected.

The ignored local compatibility shell remains ignored.

## Verification

Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

The full Rust test suite needs loopback bind/connect permission in this sandbox because existing tests use local sockets. This slice should not require network access beyond local loopback tests.

## Future Extension Path

After this slice, the next major step is a real REALITY TLS engine. It should satisfy the same `RealityTlsEngine` boundary and replace the fake engine in an interop harness, not change core VLESS or Vision runtime architecture.

Once the real engine exists, the project can run the first local Xray-core interoperability scenario for `VLESS + REALITY + Vision` and then decide whether to wire `tests/compat/vless_reality_vision.rs` as a Cargo target.
