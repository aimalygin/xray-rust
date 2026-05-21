# REALITY Certificate Verifier Design

## Goal

Add the next deterministic REALITY compatibility primitive before building a live connector.

This slice should implement Xray-core's client-side REALITY certificate recognition logic as a small, testable Rust API. It should verify the REALITY HMAC binding between the derived REALITY `auth_key`, the peer Ed25519 certificate public key, and the certificate signature bytes. The `auth_key` here is the HKDF output from the ClientHello/session-id step, not the raw X25519 shared secret.

## Non-Goals

- No live REALITY connector.
- No runtime acceptance of `streamSettings.security = "reality"`.
- No normal x509 chain validation.
- No Chrome/uTLS ClientHello synthesis.
- No ML-DSA verification.
- No spider fallback traffic.
- No edits to the vendored `Xray-core` checkout.

## Xray-Core Source Contract

The source of truth is `Xray-core/transport/internet/reality/reality.go::VerifyPeerCertificate`.

For the non-ML-DSA path, Xray-core:

1. Reads the parsed peer certificates from the underlying uTLS connection.
2. Checks whether the leaf certificate public key is an Ed25519 public key.
3. Computes `HMAC-SHA512(auth_key, ed25519_public_key)`.
4. Compares the 64-byte HMAC output with the leaf certificate signature bytes.
5. Marks the REALITY connection as verified when the values match.
6. Falls back to normal x509 verification when the REALITY check does not match.

This slice implements only the REALITY recognition primitive. It should return an explicit non-match result instead of performing x509 fallback itself.

## Rust API Shape

Keep the logic in `xray-transport::reality`.

Add a pure verifier over already extracted bytes:

```rust
pub struct RealityCertificateInput<'a> {
    pub auth_key: &'a [u8; 32],
    pub ed25519_public_key: &'a [u8; 32],
    pub certificate_signature: &'a [u8],
}

pub enum RealityCertificateVerification {
    Verified,
    NotReality,
}

pub fn verify_reality_certificate_binding(
    input: RealityCertificateInput<'_>,
) -> RealityCertificateVerification;
```

Add a DER adapter for the leaf certificate:

```rust
pub fn verify_reality_certificate_der(
    auth_key: &[u8; 32],
    leaf_der: &[u8],
) -> Result<RealityCertificateVerification, RealityError>;
```

The DER adapter should parse the leaf certificate, extract the Ed25519 SubjectPublicKeyInfo raw 32-byte public key, extract the certificate signature bytes, and then call the pure verifier.

If the certificate parses correctly but is not an Ed25519 leaf certificate, return `Ok(NotReality)`. If the DER is malformed, return a typed parse error.

## Dependencies

Use `hmac` plus `sha2::Sha512` for the HMAC primitive. `hmac` is already present in `Cargo.lock`; add it as a workspace dependency when implementing.

Use the smallest practical zero-copy X.509 parser available in the current lockfile for DER extraction. `x509-parser` is already present in `Cargo.lock`, so add it as a direct dependency with default features disabled when that compiles cleanly.

Do not introduce a heavyweight TLS stack or OpenSSL dependency for this slice.

## Validation And Errors

Extend `RealityError` without weakening the existing session-id errors.

Add typed errors for:

- malformed certificate DER;
- Ed25519 public key extraction failures when the algorithm claims Ed25519 but the key payload is not 32 bytes.

Non-Ed25519 certificates and HMAC mismatches are not parse errors; they are `NotReality`.

All comparisons of expected and actual certificate signatures should use the HMAC crate's constant-time verification path rather than ordinary byte equality.

## Memory And Secret Handling

The derived REALITY `auth_key` is secret material.

This API should borrow the caller-owned auth key rather than cloning it. The HMAC output may remain stack/local temporary data and should not be exposed through debug output.

Any new debug implementations for structs that reference or own secret material must redact auth keys and signatures. The API should not allocate in the pure verifier path beyond what the HMAC implementation needs internally.

## Fixtures And Tests

Add tests in `crates/xray-transport/tests/reality_tests.rs` or a sibling transport test module.

Tests should cover:

1. Pure verifier succeeds when `signature == HMAC-SHA512(auth_key, public_key)`.
2. Pure verifier returns `NotReality` for a changed signature.
3. Pure verifier returns `NotReality` for a changed public key.
4. DER adapter returns `Verified` for a leaf certificate fixture whose Ed25519 public key and signature match the REALITY HMAC formula.
5. DER adapter returns `NotReality` for a valid non-Ed25519 certificate.
6. DER adapter returns a typed error for malformed DER.
7. Debug output redacts secret fields if debug-visible input wrappers are introduced.

Generate the DER success fixture from a deterministic minimal Ed25519 certificate with the signature BIT STRING patched to the expected HMAC output, and keep the fixture bytes in the test tree. The test should document that normal x509 signature validity is intentionally irrelevant for REALITY recognition; Xray-core compares the parsed signature bytes directly before fallback validation.

## Connector Boundary

`RealityConnector` remains non-networked.

Update its documentation so the future live connector sequence names both primitives that now exist:

1. Build a Chrome/uTLS-compatible ClientHello.
2. Compute the X25519 shared secret and derived REALITY auth key.
3. Seal and patch the ClientHello session id.
4. Complete the TLS handshake.
5. Run the REALITY certificate verifier from this slice.
6. Only then expose the protected byte stream to VLESS.

`TransportDialer` and the core runtime should continue to reject `ConnectorConfig::Reality(_)` until live handshake support is implemented end to end.

## Verification

Required verification for the implementation slice:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

The full Rust test suite needs loopback bind/connect permission in this sandbox.

## Future Extension Path

After this slice, the remaining live REALITY connector work can proceed with fewer unknowns:

1. Add a Chrome-compatible ClientHello generator or maintained uTLS-equivalent strategy.
2. Feed its raw ClientHello, random, session-id offset, ECDHE shared secret, and metadata into the existing session-id patcher.
3. Complete the TLS handshake over the patched ClientHello.
4. Verify the REALITY certificate with this slice's verifier.
5. Route `StreamSecurity::Reality(_)` through `TransportDialer`.
6. Add ML-DSA and spider fallback as later compatibility increments.
