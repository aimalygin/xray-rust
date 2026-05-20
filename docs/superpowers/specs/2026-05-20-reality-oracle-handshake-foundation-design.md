# REALITY Oracle And Handshake Foundation Design

## Goal

Turn the current REALITY placeholder into a small, deterministic compatibility foundation before building the live connector.

This slice should make the Xray-core REALITY session-id sealing behavior executable as Rust tests with committed oracle fixtures. It should also define the future boundary between a Chrome/uTLS-compatible ClientHello generator and the REALITY sealing layer.

## Non-Goals

- No live REALITY connector.
- No runtime acceptance of `streamSettings.security = "reality"`.
- No Vision flow support.
- No Chrome/uTLS ClientHello synthesis.
- No certificate HMAC verification.
- No ML-DSA verification.
- No spider fallback traffic.
- No edits to the vendored `Xray-core` checkout.

## Xray-Core Source Contract

The source of truth for this slice is `Xray-core/transport/internet/reality/reality.go::UClient`.

The relevant client sequence is:

1. Build a uTLS client with the configured fingerprint.
2. Call `BuildHandshakeState`.
3. Replace `hello.SessionId` with a new 32-byte buffer.
4. Copy that zeroed session id into `hello.Raw[39:]`.
5. Fill the first 16 bytes of `hello.SessionId`:
   - bytes `0..3`: the three Xray version bytes;
   - byte `3`: reserved zero;
   - bytes `4..8`: current Unix timestamp, big endian;
   - bytes `8..16`: `shortId`, padded with zeroes when shorter than 8 bytes.
6. Compute the X25519 shared secret from the local TLS 1.3 ECDHE key share and the configured REALITY server public key.
7. Derive the REALITY auth key with HKDF-SHA256:
   - input key material: X25519 shared secret;
   - salt: `hello.Random[..20]`;
   - info: `REALITY`;
   - output length: 32 bytes.
8. AES-GCM seal the first 16 bytes of the session id:
   - key: derived auth key;
   - nonce: `hello.Random[20..32]`;
   - plaintext: `hello.SessionId[..16]`;
   - AAD: the raw ClientHello after the zeroed session id was copied into `hello.Raw[39:]`.
9. Copy the resulting 32 bytes, ciphertext plus tag, back into `hello.Raw[39:]`.

The zeroed ClientHello AAD is important. The Rust API should make that state explicit so future connector code cannot accidentally seal against a raw ClientHello that already contains plaintext or sealed session-id bytes.

## Oracle Fixture Strategy

Add committed fixtures under:

```text
tests/fixtures/reality/session_id_vectors.json
```

Each vector should contain:

- `name`;
- `version_hex`;
- `unix_time`;
- `short_id_hex`;
- `shared_secret_hex`;
- `hello_random_hex`;
- `session_id_offset`;
- `raw_client_hello_before_hex`;
- `expected_session_id_hex`;
- `expected_client_hello_after_hex`.

`raw_client_hello_before_hex` must contain a 32-byte zeroed session id at `session_id_offset`. For Xray-core's current uTLS path the offset is `39`, but the Rust patcher should accept an explicit offset so a future ClientHello builder can provide a parsed location instead of relying on a magic number everywhere.

Add a small offline Go oracle helper under:

```text
tools/reality-oracle/session_id_vectors.go
```

The helper should use only the Go standard library and mirror the primitive sequence above. Implement HKDF directly with `crypto/hmac` and `crypto/sha256` if the local Go toolchain does not provide a standard HKDF package. It should not import or modify `Xray-core`; the local `Xray-core` file remains the reviewed source contract, while the helper gives us an independent language implementation for reproducible fixture generation.

The helper should support a `--check <path>` mode that compares generated JSON with the committed fixture and exits non-zero on mismatch. The Rust test suite should use the committed JSON fixtures. The Go helper is a regeneration and review tool, not a required Cargo test dependency.

## Rust API Shape

Keep the logic in `xray-transport::reality`.

Refine the primitive API around explicit pieces:

```rust
pub struct RealitySessionIdInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub hello_random: [u8; 32],
}

pub struct RealityClientHelloPatch {
    pub session_id_offset: usize,
}
```

The implementation should expose two deterministic operations:

1. Build the sealed 32-byte REALITY session id from `RealitySessionIdInput` and pre-seal raw ClientHello bytes.
2. Seal and patch a mutable raw ClientHello buffer by:
   - validating that `session_id_offset..session_id_offset + 32` is in bounds;
   - zeroing that 32-byte range;
   - building the sealed session id with AAD equal to the zeroed raw ClientHello;
   - writing the sealed bytes back into the same range;
   - returning the sealed session id.

Replace the existing `RealityHelloInput` with `RealitySessionIdInput` in this slice and update tests/internal callers at the same time. This is not yet a public stable API.

## Validation And Errors

REALITY primitive errors should stay typed and non-panicking.

Add or preserve errors for:

- `short_id` longer than 8 bytes;
- invalid ClientHello session-id offset or short raw buffer;
- HKDF expand failure;
- AES-GCM seal failure.

Unlike the current truncating behavior in `build_reality_session_id`, the primitive should reject `short_id.len() > 8`. The config parser already rejects invalid REALITY short ids; rejecting again in transport catches accidental misuse without changing behavior for valid Xray configs.

Lengths `0..=8` are valid.

## Memory And Secret Handling

Avoid avoidable allocations in the hot primitive path:

- build the 16-byte plaintext prefix on the stack;
- use AES-GCM detached sealing so the 16-byte ciphertext and 16-byte tag are written into a fixed array;
- do not allocate a temporary `Vec` only to hold ciphertext plus tag;
- add a direct workspace `zeroize = "1"` dependency and wrap the derived auth key in `Zeroizing<[u8; 32]>`.

Do not zeroize caller-owned buffers such as `shared_secret` or raw ClientHello; ownership remains with the caller. The live connector can decide how to manage the lifetime of its ECDHE secret once the ClientHello generator exists.

## Connector Boundary

`RealityConnector` remains a non-network boundary in this slice.

Update its documentation and tests so the handshake plan names the explicit future pieces:

- supported fingerprint check stays limited to `chrome`;
- public key and short id stay carried unchanged;
- live `connect` remains unimplemented;
- `TransportDialer` and core runtime continue to reject `ConnectorConfig::Reality(_)`.

This preserves the no-plaintext-downgrade guarantee from the TLS connector slice.

## Tests

Transport tests should cover:

1. Fixture vectors from `tests/fixtures/reality/session_id_vectors.json`.
2. `seal_and_patch_client_hello` zeroes before sealing by matching `expected_client_hello_after_hex`.
3. Session id changes when AAD changes.
4. Session id changes when nonce bytes `hello_random[20..32]` change.
5. `short_id` length `0`, `8`, and `9`.
6. Invalid session-id offsets and too-short raw ClientHello buffers.
7. Existing `RealityConnector` handshake plan behavior.

The implementation should replace the current hard-coded Rust-only expected bytes with oracle fixture expectations.

Required verification for the implementation slice:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

The full Rust test suite needs loopback bind/connect permission in this sandbox.

## Future Extension Path

After this slice, the next REALITY step can build the live connector in narrower pieces:

1. Add a Chrome-compatible ClientHello generator or integrate a maintained uTLS-equivalent strategy.
2. Feed its raw ClientHello, random, session-id offset, ECDHE shared secret, and metadata into the sealed patcher from this slice.
3. Complete the TLS handshake over the patched ClientHello.
4. Add REALITY certificate HMAC verification.
5. Only then route `StreamSecurity::Reality(_)` through `TransportDialer`.
6. Add Vision wrapping after the protected REALITY byte stream works.

The design deliberately keeps the current path to those steps open without pretending that ordinary rustls TLS is REALITY-compatible.
