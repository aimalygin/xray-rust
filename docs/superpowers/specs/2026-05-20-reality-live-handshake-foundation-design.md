# REALITY Live Handshake Foundation Design

## Goal

Prepare the live REALITY client handshake path without running local compatibility tests yet.

This slice should turn the existing REALITY primitives into a deterministic handshake-preparation boundary:

- accept raw ClientHello metadata from a future Chrome/uTLS-compatible generator;
- derive the REALITY auth key explicitly;
- seal and patch the ClientHello session id;
- carry the auth key forward for certificate verification;
- keep runtime REALITY and local compat launch gated until Vision runtime wrapping exists.

The first local `VLESS + REALITY + Vision` test run is intentionally deferred until after the Vision runtime wrapper slice.

## Non-Goals

- No local Xray-core server launch.
- No un-ignoring `tests/compat/vless_reality_vision.rs`.
- No runtime acceptance of `streamSettings.security = "reality"`.
- No Vision runtime wrapper.
- No live socket connector.
- No ML-DSA verification.
- No spider fallback traffic.
- No support for fingerprints other than `chrome`.
- No attempt to reimplement a full TLS stack by hand.
- No edits to the vendored `Xray-core` checkout.

## Xray-Core Source Contract

The source of truth remains `Xray-core/transport/internet/reality/reality.go::UClient`.

The relevant sequence is:

1. Build a uTLS ClientHello for the configured fingerprint.
2. Expose `hello.Raw`, `hello.Random`, and the local TLS 1.3 ECDHE key share.
3. Zero and later patch the 32-byte session id at the ClientHello session-id range.
4. Compute the X25519 shared secret between the local ECDHE secret and configured REALITY server public key.
5. Derive the REALITY auth key with HKDF-SHA256:
   - input key material: X25519 shared secret;
   - salt: `hello.Random[..20]`;
   - info: `REALITY`;
   - output length: 32 bytes.
6. AES-GCM seal the session id with:
   - key: derived auth key;
   - nonce: `hello.Random[20..32]`;
   - plaintext: session-id prefix;
   - AAD: raw ClientHello with the target session-id bytes zeroed.
7. Complete TLS over the patched ClientHello.
8. Verify the leaf certificate with the derived auth key.

Previous slices implemented the session-id sealing primitive and the certificate verifier. This slice connects those pure pieces at the handshake-preparation level, still without doing network I/O.

## Architecture

Keep production logic in `xray-transport`.

The new boundary should have three focused responsibilities:

1. **Auth key derivation**
   Extract HKDF-SHA256 auth-key derivation into an explicit public helper in `xray_transport::reality`:

   ```rust
   pub fn derive_reality_auth_key(
       shared_secret: &[u8; 32],
       hello_random: &[u8; 32],
   ) -> Result<[u8; 32], RealityError>
   ```

   This stays public because the existing transport integration tests exercise REALITY primitives through the public `xray_transport::reality` module.

2. **Prepared ClientHello metadata**
   Define a typed input shape for future ClientHello providers:

   ```rust
   pub struct RealityPreparedClientHello {
       pub fingerprint: String,
       pub raw_client_hello: Vec<u8>,
       pub hello_random: [u8; 32],
       pub session_id_offset: usize,
       pub local_x25519_private_key: [u8; 32],
   }
   ```

   The name can be adjusted during implementation if the codebase reads better, but the fields must remain explicit. The private key field represents the TLS 1.3 local ECDHE secret for the ClientHello key share, not the REALITY server private key. The fingerprint field should accept only `chrome` in this slice.

3. **Handshake preparation**
   Add a deterministic operation that combines config, time/version inputs, and prepared ClientHello metadata:

   ```rust
   pub struct RealityHandshakeInput {
       pub version: [u8; 3],
       pub unix_time: u32,
       pub short_id: Vec<u8>,
       pub server_public_key: [u8; 32],
       pub prepared_client_hello: RealityPreparedClientHello,
   }

   pub struct RealityPreparedHandshake {
       pub patched_client_hello: Vec<u8>,
       pub auth_key: [u8; 32],
       pub session_id: [u8; 32],
   }
   ```

   The operation should:

   1. compute the X25519 shared secret with `x25519-dalek`;
   2. derive the REALITY auth key;
   3. call `seal_reality_client_hello`;
   4. return the patched ClientHello, auth key, and sealed session id.

This keeps the future live connector small: its hard job becomes obtaining a real Chrome-compatible ClientHello and then feeding this boundary.

## ClientHello Provider Boundary

Add documentation and type-level shape for a future provider, but do not implement a live generator in this slice.

A future provider must produce:

- raw ClientHello handshake bytes before REALITY sealing;
- exact session-id offset within those handshake bytes;
- `hello.Random`;
- local X25519 ECDHE private key matching the key share encoded in the ClientHello;
- fingerprint identity, initially only `chrome`.

This boundary deliberately does not assume the provider will be rustls. Ordinary rustls does not expose a stable supported hook to patch raw ClientHello bytes before they are written, so the implementation must keep the generator replaceable.

## Runtime Gating

`RealityConnector` remains non-networked after this slice.

`TransportDialer` and `xray-core-rs` continue to reject `ConnectorConfig::Reality(_)`.

The ignored local compat test remains ignored until both are true:

1. live REALITY connector exists;
2. Vision runtime wrapper exists and `flow = "xtls-rprx-vision"` is no longer rejected.

This matches the project decision that the first local server run should be `VLESS + REALITY + Vision`, not a partial non-Vision launch.

## Validation And Errors

Extend `RealityError` with typed errors for:

- all-zero X25519 shared secret after combining the local ECDHE secret with the configured REALITY server public key;
- invalid prepared ClientHello metadata through the existing session-id range error when the session-id range is out of bounds;
- unsupported fingerprint if the provider boundary carries anything other than `chrome`.

Keep existing session-id range and short-id errors unchanged.

The preparation operation should be non-panicking for malformed inputs.

## Memory And Secret Handling

The local ECDHE private key, X25519 shared secret, and derived auth key are secret material.

Implementation requirements:

- borrow where possible;
- avoid keeping extra copies of secret arrays;
- zeroize owned secret inputs when their owner type drops;
- redact secret fields in `Debug`;
- do not log raw ClientHello secrets, auth keys, short ids, or local private keys.

It is acceptable for `RealityPreparedHandshake` to own the derived auth key because the future connector needs it for certificate verification. That owner should have a redacted `Debug`.

## Tests

Add deterministic transport tests without network I/O.

Tests should cover:

1. auth-key derivation has a deterministic fixture with hard-coded expected auth-key bytes for known X25519 inputs and `hello.Random`;
2. handshake preparation patches the same ClientHello bytes as `seal_reality_client_hello`;
3. returned auth key verifies a synthetic REALITY certificate through `verify_reality_certificate_binding`;
4. changing the server public key changes the auth key and session id;
5. invalid session-id offsets return the existing range error and do not silently patch;
6. overlong short id returns the existing short-id error;
7. unsupported fingerprints other than `chrome` are rejected before patching;
8. all-zero X25519 shared secrets are rejected;
9. debug output redacts local private key, shared secret/auth key, short id, and hello random;
10. `RealityConnector`/`TransportDialer` still reject live REALITY configs.

Use deterministic X25519 keys in tests. Do not add network I/O to this slice.

## Verification

Required verification for the implementation slice:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

The full Rust test suite needs loopback bind/connect permission in this sandbox even though this slice itself should not add network I/O.

## Future Extension Path

After this slice:

1. Implement or integrate the actual Chrome-compatible ClientHello provider.
2. Build `RealityConnector::connect` around the provider and this handshake-preparation boundary.
3. Add Vision runtime wrapping so `xtls-rprx-vision` can carry data over the protected REALITY stream.
4. Only then enable the local ignored compat test against a local Xray-core server.

The sequence intentionally avoids a misleading early non-Vision REALITY launch.
