# REALITY ClientHello Oracle Provider Design

## Goal

Build a verified bridge from Xray-core/uTLS Chrome ClientHello generation into the Rust REALITY handshake-preparation boundary.

This slice should produce an oracle-backed fixture generated from real uTLS `HelloChrome_Auto` behavior and add Rust validation that proves the fixture can safely become a `RealityPreparedClientHello`.

The output is still test-only. It must not enable live REALITY, local Xray-core server runs, or Vision runtime flow.

## Non-Goals

- No `RealityConnector::connect`.
- No runtime acceptance of `ConnectorConfig::Reality(_)`.
- No runtime acceptance of `streamSettings.security = "reality"` in `xray-core-rs`.
- No Vision runtime wrapper.
- No local Xray-core server launch.
- No un-ignoring `tests/compat/vless_reality_vision.rs`.
- No full Rust reimplementation of Chrome/uTLS ClientHello generation.
- No non-`chrome` fingerprints.
- No ML-KEM cryptography or ML-DSA verification in Rust. Byte-level extraction of the embedded X25519 public key from a hybrid `X25519MLKEM768` key share is allowed because modern uTLS Chrome can use that shape and Xray-core falls back to `MlkemEcdhe`.
- No vendored edits to `Xray-core`.

## Xray-Core Source Contract

The source of truth remains `Xray-core/transport/internet/reality/reality.go::UClient`.

The relevant behavior is:

1. Resolve `config.Fingerprint` through `tls.GetFingerprint`; `chrome` maps to uTLS `HelloChrome_Auto`.
2. Build the uTLS handshake state with `uConn.BuildHandshakeState()`.
3. Read `hello := uConn.HandshakeState.Hello`.
4. Replace `hello.SessionId` with a 32-byte buffer and copy it into `hello.Raw[39:]`.
5. Read the TLS 1.3 local ECDHE private key from `uConn.HandshakeState.State13.KeyShareKeys.Ecdhe`, falling back to `MlkemEcdhe`.
6. Compute REALITY auth material from that ECDHE private key, the configured REALITY server public key, and `hello.Random`.
7. Seal and copy the REALITY session id back into the same raw ClientHello range.

The Rust side already has `RealityPreparedClientHello` and `prepare_reality_handshake`. This slice proves that a real uTLS-generated Chrome ClientHello can supply the required fields.

## Architecture

Keep the runtime production boundary in `xray-transport::reality`.

Add a small Rust validation boundary, not a live generator:

```rust
pub struct RealityClientHelloKeyShare {
    pub group: RealityClientHelloKeyShareGroup,
    pub offset: usize,
    pub public_key: [u8; 32],
}

pub enum RealityClientHelloKeyShareGroup {
    X25519,
    X25519MlKem768,
}

pub struct RealityClientHelloValidation {
    pub session_id_offset: usize,
    pub key_share: RealityClientHelloKeyShare,
}

pub fn validate_reality_client_hello_metadata(
    prepared: &RealityPreparedClientHello,
) -> Result<RealityClientHelloValidation, RealityError>
```

The validator should:

1. accept only `fingerprint = "chrome"`;
2. require `hello_random` to match the random bytes embedded in raw ClientHello;
3. locate the 32-byte session id range in raw ClientHello and require it to match `prepared.session_id_offset`;
4. parse the TLS extensions enough to find either an X25519 key share or a hybrid `X25519MLKEM768` key share;
5. for plain X25519, read the 32-byte key-share payload as the X25519 public key;
6. for `X25519MLKEM768`, read only the embedded trailing X25519 public key bytes from the hybrid payload and do not attempt ML-KEM operations;
7. derive the public key from `prepared.local_x25519_private_key` and require it to match the raw X25519 public key bytes;
8. return parsed offsets/metadata for tests and future diagnostics.

This keeps the future live connector replaceable: it can use any provider that emits the same validated `RealityPreparedClientHello`, but this slice only validates a fixture.

## Go Oracle Fixture

Add a new Go oracle at:

```text
tools/reality-oracle/clienthello_fixture.go
```

The oracle should:

1. use uTLS directly, not Rust code;
2. build `HelloChrome_Auto` with a deterministic `rand.Reader`;
3. set `ServerName` exactly to `example.com`;
4. call `BuildHandshakeState`;
5. replace `hello.SessionId` with 32 zero bytes and copy it into `hello.Raw[39:]`, matching Xray-core's REALITY path;
6. extract:
   - `fingerprint`;
   - `server_name`;
   - `raw_client_hello_hex`;
   - `hello_random_hex`;
   - `session_id_offset`;
   - `local_x25519_private_key_hex`;
   - `key_share_group`, either `x25519` or `x25519mlkem768`;
   - `key_share_x25519_public_key_offset`;
   - `key_share_x25519_public_key_hex`;
7. write JSON to stdout and support `--check <fixture-path>` against a committed fixture.

Commit the generated fixture at:

```text
tests/fixtures/reality/clienthello_chrome_auto.json
```

The oracle should use Go's `crypto/ecdh.PrivateKey.Bytes()` to export the local X25519 private key. It should fail if uTLS produces neither `Ecdhe` nor `MlkemEcdhe`. If uTLS uses `MlkemEcdhe`, the fixture should record the hybrid key-share group and the offset of the embedded X25519 public key inside raw ClientHello, while ignoring the ML-KEM bytes.

## Rust Fixture Loader

Add a test-only fixture loader in:

```text
crates/xray-transport/tests/reality_clienthello_tests.rs
```

The loader should decode the committed JSON into `RealityPreparedClientHello` and assert:

- raw ClientHello starts with TLS handshake type ClientHello (`0x01`);
- embedded random bytes equal `hello_random`;
- session-id length is 32;
- `session_id_offset` points at 32 zero bytes;
- parsed key-share X25519 public-key offset points at the committed X25519 public key;
- `validate_reality_client_hello_metadata` accepts the prepared fixture;
- `prepare_reality_handshake` accepts the prepared fixture and returns a patched ClientHello with the session-id bytes changed from zero.

The test should not perform network I/O.

## Parsing Scope

Do not build a general TLS parser.

The validator only needs enough ClientHello parsing for this boundary:

1. TLS handshake header;
2. legacy version;
3. random;
4. session-id length/range;
5. cipher suites length skip;
6. compression methods length skip;
7. extensions length skip loop;
8. key_share extension (`0x0033`);
9. X25519 group (`0x001d`) public key;
10. hybrid `X25519MLKEM768` group (`0x11ec`) with an embedded trailing 32-byte X25519 public key.

Malformed or truncated input should return typed `RealityError` variants instead of panicking.

## Errors

Extend `RealityError` with typed errors for:

- unsupported ClientHello fingerprint;
- invalid ClientHello structure;
- `hello_random` mismatch;
- missing or invalid 32-byte session id;
- missing X25519-compatible key share;
- key share public key mismatch.

Keep existing REALITY session-id, short-id, certificate, and all-zero shared-secret errors unchanged.

The error types should be specific enough for tests to assert failure cause without parsing strings.

## Memory And Secret Handling

The fixture contains local X25519 private key bytes for deterministic tests. Treat them as secret-shaped material even though the fixture is not production secret material.

Requirements:

- do not log raw private keys, auth keys, or full ClientHello bytes in `Debug`;
- keep existing redaction on `RealityPreparedClientHello`;
- zeroize any owned private-key arrays already covered by `RealityPreparedClientHello::Drop`;
- do not add `Clone` to secret-owning runtime structs;
- prefer borrowed parsing over copying raw ClientHello bytes.

## Runtime Gating

This slice must leave all runtime gates closed:

- `RealityConnector` remains non-networked.
- `TransportDialer` still rejects `ConnectorConfig::Reality(_)`.
- `xray-core-rs` still rejects `StreamSecurity::Reality(_)`.
- VLESS `flow = "xtls-rprx-vision"` still returns `UnsupportedOutboundFlow`.
- `tests/compat/vless_reality_vision.rs` remains ignored.

The first local server run remains after live REALITY connector and Vision runtime wrapper both exist.

## Tests

Add deterministic tests for:

1. Go oracle fixture matches the committed JSON with `--check`;
2. Rust fixture loader decodes the uTLS Chrome fixture;
3. validator accepts the committed fixture;
4. validator rejects mismatched `hello_random`;
5. validator rejects incorrect `session_id_offset`;
6. validator rejects mismatched local private key/key share;
7. validator rejects truncated ClientHello without panicking;
8. validator accepts the fixture whether uTLS emits plain X25519 or hybrid `X25519MLKEM768`, as long as the embedded X25519 public key matches;
9. `prepare_reality_handshake` accepts the validated fixture and patches session-id bytes;
10. runtime gates remain closed.

## Verification

Required verification for the implementation slice:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go --check tests/fixtures/reality/clienthello_chrome_auto.json
```

The full Rust test suite needs loopback bind/connect permission in this sandbox because existing tests use local sockets. The Go oracle may need access to Go's build cache.

## Future Extension Path

After this slice:

1. Implement a live provider that can emit a validated `RealityPreparedClientHello` while retaining enough TLS state to continue the handshake.
2. Build `RealityConnector::connect` around that provider and `prepare_reality_handshake`.
3. Add Vision runtime wrapping.
4. Enable the ignored local `VLESS + REALITY + Vision` compatibility test against a local Xray-core server.
