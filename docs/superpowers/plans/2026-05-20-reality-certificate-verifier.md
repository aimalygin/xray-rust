# REALITY Certificate Verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic Xray-compatible REALITY certificate verifier primitive for the non-ML-DSA HMAC path.

**Architecture:** Keep all production logic in `xray-transport::reality`. First add a pure verifier over already extracted `auth_key`, Ed25519 public key, and certificate signature bytes; then add a narrow DER adapter that extracts those fields from a leaf certificate and delegates to the pure verifier. `RealityConnector` remains non-networked and only documents the updated future handshake sequence.

**Tech Stack:** RustCrypto `hmac` + `sha2::Sha512`, `x509-parser` for zero-copy DER parsing, existing `thiserror`, existing `rcgen` dev dependency for non-Ed25519 DER tests.

---

## File Structure

- Modify `Cargo.toml`: add workspace dependencies `hmac` and `x509-parser`.
- Modify `crates/xray-transport/Cargo.toml`: add direct dependencies on `hmac` and `x509-parser`.
- Modify `crates/xray-transport/src/reality.rs`: add certificate input/result types, HMAC verifier, DER adapter, and new typed errors.
- Modify `crates/xray-transport/src/reality_connector.rs`: update future implementation notes to include the verifier primitive.
- Modify `crates/xray-transport/tests/reality_tests.rs`: add pure verifier tests, DER adapter tests, and deterministic DER test helpers.

### Task 1: Pure Certificate Binding Verifier

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/xray-transport/Cargo.toml`
- Modify: `crates/xray-transport/src/reality.rs`
- Test: `crates/xray-transport/tests/reality_tests.rs`

- [ ] **Step 1: Add the failing pure verifier tests and the HMAC dependency**

Add this workspace dependency to `Cargo.toml` under `[workspace.dependencies]`:

```toml
hmac = "0.12"
```

Add this dependency to `crates/xray-transport/Cargo.toml` under `[dependencies]`:

```toml
hmac.workspace = true
```

Update the imports at the top of `crates/xray-transport/tests/reality_tests.rs` inside `mod reality_tests`:

```rust
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha512;
use xray_transport::reality::{
    build_reality_session_id, seal_reality_client_hello, verify_reality_certificate_binding,
    RealityCertificateInput, RealityCertificateVerification, RealityClientHelloPatch,
    RealityError, RealitySessionIdInput,
};
```

Add this helper near the existing hex helpers:

```rust
type HmacSha512 = Hmac<Sha512>;

fn reality_certificate_signature(
    auth_key: &[u8; 32],
    ed25519_public_key: &[u8; 32],
) -> [u8; 64] {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(auth_key).unwrap();
    mac.update(ed25519_public_key);
    mac.finalize().into_bytes().into()
}
```

Add these tests after `reality_session_id_input_debug_redacts_secret_fields`:

```rust
#[test]
fn reality_certificate_binding_verifies_hmac_signature() {
    let auth_key = [0x11; 32];
    let public_key = [0x22; 32];
    let signature = reality_certificate_signature(&auth_key, &public_key);

    let result = verify_reality_certificate_binding(RealityCertificateInput {
        auth_key: &auth_key,
        ed25519_public_key: &public_key,
        certificate_signature: &signature,
    });

    assert_eq!(result, RealityCertificateVerification::Verified);
}

#[test]
fn reality_certificate_binding_rejects_changed_signature() {
    let auth_key = [0x11; 32];
    let public_key = [0x22; 32];
    let mut signature = reality_certificate_signature(&auth_key, &public_key);
    signature[0] ^= 0xff;

    let result = verify_reality_certificate_binding(RealityCertificateInput {
        auth_key: &auth_key,
        ed25519_public_key: &public_key,
        certificate_signature: &signature,
    });

    assert_eq!(result, RealityCertificateVerification::NotReality);
}

#[test]
fn reality_certificate_binding_rejects_changed_public_key() {
    let auth_key = [0x11; 32];
    let public_key = [0x22; 32];
    let changed_public_key = [0x23; 32];
    let signature = reality_certificate_signature(&auth_key, &public_key);

    let result = verify_reality_certificate_binding(RealityCertificateInput {
        auth_key: &auth_key,
        ed25519_public_key: &changed_public_key,
        certificate_signature: &signature,
    });

    assert_eq!(result, RealityCertificateVerification::NotReality);
}

#[test]
fn reality_certificate_input_debug_redacts_secret_fields() {
    let auth_key = [0xab; 32];
    let public_key = [0xcd; 32];
    let signature = [0xef; 64];
    let input = RealityCertificateInput {
        auth_key: &auth_key,
        ed25519_public_key: &public_key,
        certificate_signature: &signature,
    };

    let debug = format!("{input:?}");

    assert!(debug.contains("auth_key: \"<redacted>\""));
    assert!(debug.contains("ed25519_public_key: \"<redacted>\""));
    assert!(debug.contains("certificate_signature: \"<redacted>\""));
    assert!(!debug.contains("171, 171, 171, 171"));
    assert!(!debug.contains("205, 205, 205, 205"));
    assert!(!debug.contains("239, 239, 239, 239"));
}
```

- [ ] **Step 2: Run the focused test command and confirm the expected failure**

Run:

```bash
cargo test -p xray-transport --test reality_tests reality_certificate_binding
```

Expected: fail to compile because `verify_reality_certificate_binding`, `RealityCertificateInput`, and `RealityCertificateVerification` are not defined yet.

- [ ] **Step 3: Implement the pure verifier**

In `crates/xray-transport/src/reality.rs`, replace:

```rust
use sha2::Sha256;
```

with:

```rust
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
```

Add this type alias near the existing constants:

```rust
type HmacSha512 = Hmac<Sha512>;
```

Add these types after `RealityClientHelloPatch`:

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RealityCertificateInput<'a> {
    pub auth_key: &'a [u8; 32],
    pub ed25519_public_key: &'a [u8; 32],
    pub certificate_signature: &'a [u8],
}

impl fmt::Debug for RealityCertificateInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityCertificateInput")
            .field("auth_key", &"<redacted>")
            .field("ed25519_public_key", &"<redacted>")
            .field("certificate_signature", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityCertificateVerification {
    Verified,
    NotReality,
}
```

Add this function after `build_reality_session_id`:

```rust
/// Verifies Xray-core's non-ML-DSA REALITY certificate binding.
///
/// Xray-core recognizes a REALITY peer certificate when
/// `HMAC-SHA512(auth_key, ed25519_public_key)` equals the leaf certificate
/// signature bytes. The auth key is the derived REALITY auth key, not the raw
/// X25519 shared secret.
pub fn verify_reality_certificate_binding(
    input: RealityCertificateInput<'_>,
) -> RealityCertificateVerification {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(input.auth_key)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(input.ed25519_public_key);

    if mac.verify_slice(input.certificate_signature).is_ok() {
        RealityCertificateVerification::Verified
    } else {
        RealityCertificateVerification::NotReality
    }
}
```

- [ ] **Step 4: Run the focused tests and confirm they pass**

Run:

```bash
cargo test -p xray-transport --test reality_tests reality_certificate
```

Expected: all `reality_certificate_*` tests pass.

- [ ] **Step 5: Commit the pure verifier**

Run:

```bash
git add Cargo.toml crates/xray-transport/Cargo.toml crates/xray-transport/src/reality.rs crates/xray-transport/tests/reality_tests.rs
git commit -m "feat(transport): verify reality certificate binding"
```

### Task 2: DER Leaf Certificate Adapter

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/xray-transport/Cargo.toml`
- Modify: `crates/xray-transport/src/reality.rs`
- Test: `crates/xray-transport/tests/reality_tests.rs`

- [ ] **Step 1: Add the failing DER adapter tests and parser dependency**

Add this workspace dependency to `Cargo.toml` under `[workspace.dependencies]`:

```toml
x509-parser = { version = "0.18", default-features = false }
```

Add this dependency to `crates/xray-transport/Cargo.toml` under `[dependencies]`:

```toml
x509-parser.workspace = true
```

Update the `xray_transport::reality` import in `crates/xray-transport/tests/reality_tests.rs` to include the DER adapter:

```rust
use xray_transport::reality::{
    build_reality_session_id, seal_reality_client_hello, verify_reality_certificate_binding,
    verify_reality_certificate_der, RealityCertificateInput, RealityCertificateVerification,
    RealityClientHelloPatch, RealityError, RealitySessionIdInput,
};
```

Add this import:

```rust
use rcgen::generate_simple_self_signed;
```

Add these DER helper functions near `reality_certificate_signature`:

```rust
fn push_der_length(out: &mut Vec<u8>, len: usize) {
    match len {
        0..=127 => out.push(len as u8),
        128..=255 => {
            out.push(0x81);
            out.push(len as u8);
        }
        _ => panic!("test DER helper only supports lengths up to 255 bytes"),
    }
}

fn push_der_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    push_der_length(out, content.len());
    out.extend_from_slice(content);
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_der_tlv(&mut out, tag, content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_tlv(0x30, content)
}

fn der_bit_string(unused_bits: u8, bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(unused_bits);
    content.extend_from_slice(bytes);
    der_tlv(0x03, &content)
}

fn der_utc_time(value: &[u8; 13]) -> Vec<u8> {
    der_tlv(0x17, value)
}

fn ed25519_algorithm_identifier() -> Vec<u8> {
    vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
}

fn ed25519_leaf_der(public_key: &[u8], signature: &[u8]) -> Vec<u8> {
    let algorithm = ed25519_algorithm_identifier();

    let mut validity_content = Vec::new();
    validity_content.extend_from_slice(&der_utc_time(b"250101000000Z"));
    validity_content.extend_from_slice(&der_utc_time(b"260101000000Z"));
    let validity = der_sequence(&validity_content);

    let mut spki_content = Vec::new();
    spki_content.extend_from_slice(&algorithm);
    spki_content.extend_from_slice(&der_bit_string(0, public_key));
    let spki = der_sequence(&spki_content);

    let mut tbs_content = Vec::new();
    tbs_content.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
    tbs_content.extend_from_slice(&[0x02, 0x01, 0x01]);
    tbs_content.extend_from_slice(&algorithm);
    tbs_content.extend_from_slice(&[0x30, 0x00]);
    tbs_content.extend_from_slice(&validity);
    tbs_content.extend_from_slice(&[0x30, 0x00]);
    tbs_content.extend_from_slice(&spki);
    let tbs = der_sequence(&tbs_content);

    let mut cert_content = Vec::new();
    cert_content.extend_from_slice(&tbs);
    cert_content.extend_from_slice(&algorithm);
    cert_content.extend_from_slice(&der_bit_string(0, signature));
    der_sequence(&cert_content)
}
```

Add these tests after the pure certificate binding tests:

```rust
#[test]
fn reality_certificate_der_adapter_verifies_ed25519_hmac_fixture() {
    let auth_key = [0x31; 32];
    let public_key = [0x42; 32];
    let signature = reality_certificate_signature(&auth_key, &public_key);
    let leaf_der = ed25519_leaf_der(&public_key, &signature);

    let result = verify_reality_certificate_der(&auth_key, &leaf_der).unwrap();

    assert_eq!(result, RealityCertificateVerification::Verified);
}

#[test]
fn reality_certificate_der_adapter_rejects_mismatched_signature() {
    let auth_key = [0x31; 32];
    let public_key = [0x42; 32];
    let wrong_signature = [0x55; 64];
    let leaf_der = ed25519_leaf_der(&public_key, &wrong_signature);

    let result = verify_reality_certificate_der(&auth_key, &leaf_der).unwrap();

    assert_eq!(result, RealityCertificateVerification::NotReality);
}

#[test]
fn reality_certificate_der_adapter_returns_not_reality_for_non_ed25519_leaf() {
    let auth_key = [0x31; 32];
    let cert = generate_simple_self_signed(vec!["example.test".to_owned()])
        .expect("generate non-Ed25519 certificate");

    let result = verify_reality_certificate_der(&auth_key, cert.cert.der().as_ref()).unwrap();

    assert_eq!(result, RealityCertificateVerification::NotReality);
}

#[test]
fn reality_certificate_der_adapter_rejects_malformed_der() {
    let auth_key = [0x31; 32];

    let err = verify_reality_certificate_der(&auth_key, &[0x30, 0x03, 0x02])
        .expect_err("malformed DER should fail");

    assert_eq!(err, RealityError::InvalidRealityCertificateDer);
}

#[test]
fn reality_certificate_der_adapter_rejects_invalid_ed25519_key_length() {
    let auth_key = [0x31; 32];
    let public_key = [0x42; 31];
    let signature = [0x55; 64];
    let leaf_der = ed25519_leaf_der(&public_key, &signature);

    let err = verify_reality_certificate_der(&auth_key, &leaf_der)
        .expect_err("invalid Ed25519 public key length should fail");

    assert_eq!(
        err,
        RealityError::InvalidRealityCertificatePublicKey { len: 31 }
    );
}
```

- [ ] **Step 2: Run the focused test command and confirm the expected failure**

Run:

```bash
cargo test -p xray-transport --test reality_tests reality_certificate_der_adapter
```

Expected: fail to compile because `verify_reality_certificate_der`, `InvalidRealityCertificateDer`, and `InvalidRealityCertificatePublicKey` are not implemented yet.

- [ ] **Step 3: Implement DER parsing and adapter errors**

In `crates/xray-transport/src/reality.rs`, add these imports:

```rust
use x509_parser::{
    oid_registry::OID_SIG_ED25519,
    prelude::{FromDer, X509Certificate},
};
```

Extend `RealityError` with these variants:

```rust
#[error("invalid reality certificate DER")]
InvalidRealityCertificateDer,
#[error("invalid reality Ed25519 public key length {len}")]
InvalidRealityCertificatePublicKey { len: usize },
```

Add this function after `verify_reality_certificate_binding`:

```rust
/// Parses a leaf certificate DER and verifies Xray-core's REALITY HMAC binding.
///
/// This is only the REALITY recognition step. Normal x509 fallback validation
/// stays outside this primitive.
pub fn verify_reality_certificate_der(
    auth_key: &[u8; 32],
    leaf_der: &[u8],
) -> Result<RealityCertificateVerification, RealityError> {
    let (remaining, certificate) = X509Certificate::from_der(leaf_der)
        .map_err(|_| RealityError::InvalidRealityCertificateDer)?;
    if !remaining.is_empty() {
        return Err(RealityError::InvalidRealityCertificateDer);
    }

    let public_key_info = certificate.public_key();
    if public_key_info.algorithm.algorithm != OID_SIG_ED25519 {
        return Ok(RealityCertificateVerification::NotReality);
    }

    let public_key = public_key_info.subject_public_key.data;
    let public_key: &[u8; 32] = public_key.try_into().map_err(|_| {
        RealityError::InvalidRealityCertificatePublicKey {
            len: public_key.len(),
        }
    })?;

    Ok(verify_reality_certificate_binding(
        RealityCertificateInput {
            auth_key,
            ed25519_public_key: public_key,
            certificate_signature: certificate.signature_value.data,
        },
    ))
}
```

- [ ] **Step 4: Run focused transport tests and confirm they pass**

Run:

```bash
cargo test -p xray-transport --test reality_tests reality_certificate
```

Expected: all certificate verifier and existing REALITY primitive tests pass.

- [ ] **Step 5: Commit the DER adapter**

Run:

```bash
git add Cargo.toml crates/xray-transport/Cargo.toml crates/xray-transport/src/reality.rs crates/xray-transport/tests/reality_tests.rs
git commit -m "feat(transport): verify reality certificate der"
```

### Task 3: Connector Boundary Documentation

**Files:**
- Modify: `crates/xray-transport/src/reality_connector.rs`
- Test: `crates/xray-transport/tests/reality_connector_tests.rs`

- [ ] **Step 1: Update connector future notes**

In `crates/xray-transport/src/reality_connector.rs`, replace the top module docs with:

```rust
//! REALITY connector boundary.
//!
//! Oracle/source: `Xray-core/transport/internet/reality/reality.go::UClient`.
//! Pure session-id sealing, ClientHello patching, and certificate HMAC
//! verification live in `crate::reality`.
//!
//! This connector remains non-networked until Chrome/uTLS-compatible ClientHello generation
//! and a complete REALITY TLS handshake exist.
//!
//! Future `RealityConnector::connect` implementation notes:
//!
//! 1. Build a Chrome-compatible TLS 1.3 ClientHello and expose its raw bytes,
//!    random, session-id offset, and ECDHE key share.
//! 2. Compute the X25519 shared secret with the server public key and derive the
//!    REALITY auth key.
//! 3. Call `seal_reality_client_hello`.
//! 4. Complete the TLS handshake.
//! 5. Call `verify_reality_certificate_der` on the leaf certificate.
//! 6. Expose the protected stream to VLESS only after REALITY verification.
//!
//! VLESS should only see an async byte stream once live REALITY is implemented.
```

- [ ] **Step 2: Run connector tests**

Run:

```bash
cargo test -p xray-transport --test reality_connector_tests
```

Expected: all connector boundary tests pass.

- [ ] **Step 3: Commit the connector docs**

Run:

```bash
git add crates/xray-transport/src/reality_connector.rs
git commit -m "docs(transport): clarify reality verifier boundary"
```

### Task 4: Full Verification

**Files:**
- Verify all workspace changes.

- [ ] **Step 1: Run formatting check**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exits 0.

- [ ] **Step 2: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: exits 0.

- [ ] **Step 3: Run the full Rust test suite**

Run:

```bash
cargo test --workspace --all-targets
```

Expected: exits 0. In this sandbox the full suite needs escalated loopback bind/connect permission.

- [ ] **Step 4: Run the Go REALITY oracle check**

Run:

```bash
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

Expected: exits 0 and prints no fixture mismatch.

- [ ] **Step 5: Confirm the final git state**

Run:

```bash
git status --short
git log --oneline -5
```

Expected: `git status --short` prints nothing; the recent log contains the three implementation commits from this plan after the design and plan commits.
