# REALITY Live Handshake Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic REALITY handshake-preparation boundary that derives the auth key, patches a prepared ClientHello, and keeps live REALITY gated.

**Architecture:** Keep production logic in `xray-transport::reality`; `RealityConnector` remains a non-networked boundary. The implementation accepts already prepared ClientHello metadata, computes X25519 + HKDF auth material, delegates session-id sealing to the existing primitive, and returns the patched ClientHello plus auth key for the future certificate-verification step.

**Tech Stack:** Rust, existing RustCrypto `hkdf`/`sha2`/`aes-gcm`, `x25519-dalek` with `StaticSecret`, existing `zeroize`, existing transport integration tests.

---

## Scope Check

The approved spec is one focused transport subsystem slice. It does not include live socket I/O, ClientHello generation, Vision wrapping, local Xray-core launch, or config runtime acceptance.

## File Structure

- Modify `crates/xray-transport/src/reality.rs`: add auth-key helper, prepared ClientHello/handshake types, X25519 derivation, validation errors, and redacted `Debug`/`Drop` implementations.
- Modify `crates/xray-transport/src/reality_connector.rs`: update future connector notes to point at the new preparation boundary while keeping the connector non-networked.
- Modify `crates/xray-transport/tests/reality_tests.rs`: add deterministic tests for auth-key derivation, handshake preparation, error handling, certificate verifier integration, and redaction.
- Read-only verification in `crates/xray-transport/tests/reality_connector_tests.rs`, `crates/xray-transport/tests/transport_tests.rs`, and `crates/xray-core-rs/src/outbound.rs`: existing tests must continue proving runtime REALITY and Vision flow stay gated.

### Task 1: Extract REALITY Auth-Key Derivation

**Files:**
- Modify: `crates/xray-transport/src/reality.rs`
- Test: `crates/xray-transport/tests/reality_tests.rs`

- [ ] **Step 1: Write the failing auth-key fixture test**

Update the import list inside `mod reality_tests` in `crates/xray-transport/tests/reality_tests.rs`:

```rust
use xray_transport::reality::{
    build_reality_session_id, derive_reality_auth_key, seal_reality_client_hello,
    verify_reality_certificate_binding, verify_reality_certificate_der, RealityCertificateInput,
    RealityCertificateVerification, RealityClientHelloPatch, RealityError,
    RealitySessionIdInput,
};
```

Add these constants after `SESSION_ID_VECTORS_JSON`:

```rust
const HANDSHAKE_HELLO_RANDOM: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const HANDSHAKE_SHARED_SECRET_HEX: &str =
    "9e004098efc091d4ec2663b4e9f5cfd4d7064571690b4bea97ab146ab9f35056";
const HANDSHAKE_EXPECTED_AUTH_KEY_HEX: &str =
    "f8248fa0d41d35ebabbe29b095788941bb71f1dfc0bdb70f4641412772351a48";
```

Add this test after `reality_session_id_matches_oracle_vectors`:

```rust
#[test]
fn derive_reality_auth_key_uses_xray_hkdf_contract() {
    let shared_secret = decode_hex_array::<32>(HANDSHAKE_SHARED_SECRET_HEX);
    let expected_auth_key = decode_hex_array::<32>(HANDSHAKE_EXPECTED_AUTH_KEY_HEX);

    let auth_key = derive_reality_auth_key(&shared_secret, &HANDSHAKE_HELLO_RANDOM).unwrap();

    assert_eq!(auth_key, expected_auth_key);
}
```

- [ ] **Step 2: Run the focused test and confirm the expected failure**

Run:

```bash
cargo test -p xray-transport --test reality_tests derive_reality_auth_key_uses_xray_hkdf_contract
```

Expected: fail to compile because `derive_reality_auth_key` is not defined yet.

- [ ] **Step 3: Implement the public auth-key helper**

In `crates/xray-transport/src/reality.rs`, add this function before `build_reality_session_id`:

```rust
/// Derives Xray-core's REALITY auth key from the X25519 shared secret.
///
/// Xray-core uses HKDF-SHA256 with `hello.Random[..20]` as salt and
/// `REALITY` as info. The resulting key is used both for ClientHello
/// session-id sealing and REALITY certificate binding.
pub fn derive_reality_auth_key(
    shared_secret: &[u8; 32],
    hello_random: &[u8; 32],
) -> Result<[u8; 32], RealityError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&hello_random[..20]), shared_secret);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key[..])
        .map_err(|_| RealityError::Hkdf)?;
    Ok(auth_key)
}
```

In `build_reality_session_id`, replace the inline HKDF block:

```rust
let hkdf = Hkdf::<Sha256>::new(Some(&input.hello_random[..20]), &input.shared_secret);
let mut auth_key = Zeroizing::new([0u8; 32]);
hkdf.expand(b"REALITY", &mut auth_key[..])
    .map_err(|_| RealityError::Hkdf)?;
```

with:

```rust
let auth_key = Zeroizing::new(derive_reality_auth_key(
    &input.shared_secret,
    &input.hello_random,
)?);
```

- [ ] **Step 4: Run the focused test and existing REALITY oracle tests**

Run:

```bash
cargo test -p xray-transport --test reality_tests derive_reality_auth_key_uses_xray_hkdf_contract
cargo test -p xray-transport --test reality_tests reality_session_id_matches_oracle_vectors
cargo test -p xray-transport --test reality_tests reality_client_hello_patch_matches_oracle_vectors
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/src/reality.rs crates/xray-transport/tests/reality_tests.rs
git commit -m "feat(transport): derive reality auth key"
```

### Task 2: Add Prepared Handshake Types And Redaction

**Files:**
- Modify: `crates/xray-transport/src/reality.rs`
- Test: `crates/xray-transport/tests/reality_tests.rs`

- [ ] **Step 1: Write the failing type/redaction tests**

Update the import list inside `mod reality_tests` in `crates/xray-transport/tests/reality_tests.rs`:

```rust
use xray_transport::reality::{
    build_reality_session_id, derive_reality_auth_key, seal_reality_client_hello,
    verify_reality_certificate_binding, verify_reality_certificate_der, RealityCertificateInput,
    RealityCertificateVerification, RealityClientHelloPatch, RealityError,
    RealityHandshakeInput, RealityPreparedClientHello, RealityPreparedHandshake,
    RealitySessionIdInput,
};
```

Add these constants after `HANDSHAKE_EXPECTED_AUTH_KEY_HEX`:

```rust
const HANDSHAKE_VERSION: [u8; 3] = [0x00, 0x01, 0x02];
const HANDSHAKE_UNIX_TIME: u32 = 0x0102_0304;
const HANDSHAKE_SESSION_ID_OFFSET: usize = 40;
const HANDSHAKE_LOCAL_PRIVATE_KEY: [u8; 32] = [0x11; 32];
const HANDSHAKE_SERVER_PUBLIC_KEY_HEX: &str =
    "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20";
const HANDSHAKE_ALT_SERVER_PUBLIC_KEY_HEX: &str =
    "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14";
```

Add these helpers near `input_from_vector`:

```rust
fn raw_client_hello_fixture() -> Vec<u8> {
    let mut raw_client_hello: Vec<u8> = (0u8..96).collect();
    raw_client_hello[HANDSHAKE_SESSION_ID_OFFSET..HANDSHAKE_SESSION_ID_OFFSET + 32].fill(0xa5);
    raw_client_hello
}

fn prepared_client_hello_fixture() -> RealityPreparedClientHello {
    RealityPreparedClientHello {
        fingerprint: "chrome".to_owned(),
        raw_client_hello: raw_client_hello_fixture(),
        hello_random: HANDSHAKE_HELLO_RANDOM,
        session_id_offset: HANDSHAKE_SESSION_ID_OFFSET,
        local_x25519_private_key: HANDSHAKE_LOCAL_PRIVATE_KEY,
    }
}

fn handshake_input_with_server_public_key(
    server_public_key: [u8; 32],
) -> RealityHandshakeInput {
    RealityHandshakeInput {
        version: HANDSHAKE_VERSION,
        unix_time: HANDSHAKE_UNIX_TIME,
        short_id: vec![0xaa, 0xbb, 0xcc],
        server_public_key,
        prepared_client_hello: prepared_client_hello_fixture(),
    }
}

fn handshake_input_fixture() -> RealityHandshakeInput {
    handshake_input_with_server_public_key(decode_hex_array(HANDSHAKE_SERVER_PUBLIC_KEY_HEX))
}
```

Add this test after `reality_session_id_input_debug_redacts_secret_fields`:

```rust
#[test]
fn reality_handshake_debug_redacts_secret_fields() {
    let prepared_client_hello = prepared_client_hello_fixture();
    let prepared_debug = format!("{prepared_client_hello:?}");
    assert!(prepared_debug.contains("fingerprint: \"chrome\""));
    assert!(prepared_debug.contains("raw_client_hello_len: 96"));
    assert!(prepared_debug.contains("hello_random: \"<redacted>\""));
    assert!(prepared_debug.contains("local_x25519_private_key: \"<redacted>\""));
    assert!(!prepared_debug.contains("17, 17, 17, 17"));
    assert!(!prepared_debug.contains("0, 1, 2, 3"));

    let input = handshake_input_fixture();
    let input_debug = format!("{input:?}");
    assert!(input_debug.contains("short_id: \"<redacted>\""));
    assert!(input_debug.contains("prepared_client_hello"));
    assert!(!input_debug.contains("170, 187, 204"));
    assert!(!input_debug.contains("17, 17, 17, 17"));

    let prepared_handshake = RealityPreparedHandshake {
        patched_client_hello: vec![0xab; 96],
        auth_key: [0xcd; 32],
        session_id: [0xef; 32],
    };
    let output_debug = format!("{prepared_handshake:?}");
    assert!(output_debug.contains("patched_client_hello_len: 96"));
    assert!(output_debug.contains("auth_key: \"<redacted>\""));
    assert!(output_debug.contains("session_id: \"<redacted>\""));
    assert!(!output_debug.contains("171, 171, 171, 171"));
    assert!(!output_debug.contains("205, 205, 205, 205"));
    assert!(!output_debug.contains("239, 239, 239, 239"));
}
```

- [ ] **Step 2: Run the focused test and confirm the expected failure**

Run:

```bash
cargo test -p xray-transport --test reality_tests reality_handshake_debug_redacts_secret_fields
```

Expected: fail to compile because the handshake types are not defined yet.

- [ ] **Step 3: Implement the types, errors, redacted Debug, and Drop**

In `crates/xray-transport/src/reality.rs`, add these error variants to `RealityError` after `InvalidSessionIdRange`:

```rust
#[error("unsupported REALITY fingerprint {0}")]
UnsupportedRealityFingerprint(String),
#[error("reality X25519 shared secret was all zero")]
AllZeroSharedSecret,
```

Add these types after `RealityClientHelloPatch`:

```rust
pub struct RealityPreparedClientHello {
    pub fingerprint: String,
    pub raw_client_hello: Vec<u8>,
    pub hello_random: [u8; 32],
    pub session_id_offset: usize,
    pub local_x25519_private_key: [u8; 32],
}

impl fmt::Debug for RealityPreparedClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityPreparedClientHello")
            .field("fingerprint", &self.fingerprint)
            .field("raw_client_hello_len", &self.raw_client_hello.len())
            .field("hello_random", &"<redacted>")
            .field("session_id_offset", &self.session_id_offset)
            .field("local_x25519_private_key", &"<redacted>")
            .finish()
    }
}

impl Drop for RealityPreparedClientHello {
    fn drop(&mut self) {
        self.local_x25519_private_key.zeroize();
    }
}

pub struct RealityHandshakeInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub server_public_key: [u8; 32],
    pub prepared_client_hello: RealityPreparedClientHello,
}

impl fmt::Debug for RealityHandshakeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityHandshakeInput")
            .field("version", &self.version)
            .field("unix_time", &self.unix_time)
            .field("short_id", &"<redacted>")
            .field("server_public_key", &self.server_public_key)
            .field("prepared_client_hello", &self.prepared_client_hello)
            .finish()
    }
}

impl Drop for RealityHandshakeInput {
    fn drop(&mut self) {
        self.short_id.zeroize();
    }
}

pub struct RealityPreparedHandshake {
    pub patched_client_hello: Vec<u8>,
    pub auth_key: [u8; 32],
    pub session_id: [u8; 32],
}

impl fmt::Debug for RealityPreparedHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityPreparedHandshake")
            .field("patched_client_hello_len", &self.patched_client_hello.len())
            .field("auth_key", &"<redacted>")
            .field("session_id", &"<redacted>")
            .finish()
    }
}

impl Drop for RealityPreparedHandshake {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        self.session_id.zeroize();
    }
}
```

- [ ] **Step 4: Run the focused test**

Run:

```bash
cargo test -p xray-transport --test reality_tests reality_handshake_debug_redacts_secret_fields
```

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/src/reality.rs crates/xray-transport/tests/reality_tests.rs
git commit -m "feat(transport): add reality handshake types"
```

### Task 3: Prepare And Patch REALITY Handshake

**Files:**
- Modify: `crates/xray-transport/src/reality.rs`
- Test: `crates/xray-transport/tests/reality_tests.rs`

- [ ] **Step 1: Write the failing handshake-preparation tests**

Update the import list inside `mod reality_tests` in `crates/xray-transport/tests/reality_tests.rs`:

```rust
use xray_transport::reality::{
    build_reality_session_id, derive_reality_auth_key, prepare_reality_handshake,
    seal_reality_client_hello, verify_reality_certificate_binding,
    verify_reality_certificate_der, RealityCertificateInput,
    RealityCertificateVerification, RealityClientHelloPatch, RealityError,
    RealityHandshakeInput, RealityPreparedClientHello, RealityPreparedHandshake,
    RealitySessionIdInput,
};
```

Add these tests after `reality_handshake_debug_redacts_secret_fields`:

```rust
#[test]
fn prepare_reality_handshake_patches_client_hello_and_returns_auth_key() {
    let mut expected_client_hello = raw_client_hello_fixture();
    let expected_session_id = seal_reality_client_hello(
        &RealitySessionIdInput {
            version: HANDSHAKE_VERSION,
            unix_time: HANDSHAKE_UNIX_TIME,
            short_id: vec![0xaa, 0xbb, 0xcc],
            shared_secret: decode_hex_array(HANDSHAKE_SHARED_SECRET_HEX),
            hello_random: HANDSHAKE_HELLO_RANDOM,
        },
        RealityClientHelloPatch {
            session_id_offset: HANDSHAKE_SESSION_ID_OFFSET,
        },
        &mut expected_client_hello,
    )
    .unwrap();

    let prepared = prepare_reality_handshake(handshake_input_fixture()).unwrap();

    assert_eq!(prepared.patched_client_hello, expected_client_hello);
    assert_eq!(
        prepared.auth_key,
        decode_hex_array::<32>(HANDSHAKE_EXPECTED_AUTH_KEY_HEX)
    );
    assert_eq!(prepared.session_id, expected_session_id);
}

#[test]
fn prepare_reality_handshake_auth_key_verifies_certificate_binding() {
    let prepared = prepare_reality_handshake(handshake_input_fixture()).unwrap();
    let public_key = [0x42; 32];
    let signature = reality_certificate_signature(&prepared.auth_key, &public_key);

    let result = verify_reality_certificate_binding(RealityCertificateInput {
        auth_key: &prepared.auth_key,
        ed25519_public_key: &public_key,
        certificate_signature: &signature,
    });

    assert_eq!(result, RealityCertificateVerification::Verified);
}

#[test]
fn prepare_reality_handshake_changes_when_server_public_key_changes() {
    let baseline = prepare_reality_handshake(handshake_input_fixture()).unwrap();
    let changed = prepare_reality_handshake(handshake_input_with_server_public_key(
        decode_hex_array(HANDSHAKE_ALT_SERVER_PUBLIC_KEY_HEX),
    ))
    .unwrap();

    assert_ne!(baseline.auth_key, changed.auth_key);
    assert_ne!(baseline.session_id, changed.session_id);
    assert_ne!(baseline.patched_client_hello, changed.patched_client_hello);
}

#[test]
fn prepare_reality_handshake_rejects_invalid_session_id_offset() {
    let mut input = handshake_input_fixture();
    input.prepared_client_hello.session_id_offset = raw_client_hello_fixture().len() - 31;

    let err = prepare_reality_handshake(input).unwrap_err();

    assert_eq!(
        err,
        RealityError::InvalidSessionIdRange {
            offset: 65,
            end: 97,
            len: 96,
        }
    );
}

#[test]
fn prepare_reality_handshake_rejects_overlong_short_id() {
    let mut input = handshake_input_fixture();
    input.short_id = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];

    let err = prepare_reality_handshake(input).unwrap_err();

    assert_eq!(err, RealityError::ShortIdTooLong);
}

#[test]
fn prepare_reality_handshake_rejects_unsupported_fingerprint() {
    let mut input = handshake_input_fixture();
    input.prepared_client_hello.fingerprint = "firefox".to_owned();

    let err = prepare_reality_handshake(input).unwrap_err();

    assert_eq!(
        err,
        RealityError::UnsupportedRealityFingerprint("firefox".to_owned())
    );
}

#[test]
fn prepare_reality_handshake_rejects_all_zero_shared_secret() {
    let mut input = handshake_input_fixture();
    input.server_public_key = [0; 32];

    let err = prepare_reality_handshake(input).unwrap_err();

    assert_eq!(err, RealityError::AllZeroSharedSecret);
}
```

Because `prepare_reality_handshake` consumes the prepared ClientHello, the observable failure contract is the existing range error with no returned `RealityPreparedHandshake`. The existing `reality_client_hello_patch_rejects_invalid_offsets` test continues to cover in-place no-mutation for the underlying patch primitive.

- [ ] **Step 2: Run the focused tests and confirm the expected failure**

Run:

```bash
cargo test -p xray-transport --test reality_tests prepare_reality_handshake
```

Expected: fail to compile because `prepare_reality_handshake` is not defined yet.

- [ ] **Step 3: Implement handshake preparation**

In `crates/xray-transport/src/reality.rs`, add this import:

```rust
use x25519_dalek::{PublicKey, StaticSecret};
```

Add this constant near the existing REALITY constants:

```rust
const REALITY_CHROME_FINGERPRINT: &str = "chrome";
```

Add this function after `derive_reality_auth_key`:

```rust
/// Prepares a REALITY ClientHello for the future live connector.
///
/// This function does not perform network I/O. The caller supplies raw
/// ClientHello metadata produced by a Chrome/uTLS-compatible provider.
pub fn prepare_reality_handshake(
    mut input: RealityHandshakeInput,
) -> Result<RealityPreparedHandshake, RealityError> {
    if input.prepared_client_hello.fingerprint != REALITY_CHROME_FINGERPRINT {
        return Err(RealityError::UnsupportedRealityFingerprint(
            input.prepared_client_hello.fingerprint.clone(),
        ));
    }

    let local_x25519_private_key =
        Zeroizing::new(input.prepared_client_hello.local_x25519_private_key);
    input.prepared_client_hello.local_x25519_private_key.zeroize();

    let local_secret = StaticSecret::from(*local_x25519_private_key);
    let server_public_key = PublicKey::from(input.server_public_key);
    let shared_secret = local_secret.diffie_hellman(&server_public_key);
    if !shared_secret.was_contributory() {
        return Err(RealityError::AllZeroSharedSecret);
    }

    let shared_secret = shared_secret.to_bytes();
    let auth_key = derive_reality_auth_key(
        &shared_secret,
        &input.prepared_client_hello.hello_random,
    )?;

    let session_input = RealitySessionIdInput {
        version: input.version,
        unix_time: input.unix_time,
        short_id: std::mem::take(&mut input.short_id),
        shared_secret,
        hello_random: input.prepared_client_hello.hello_random,
    };
    let mut raw_client_hello = std::mem::take(&mut input.prepared_client_hello.raw_client_hello);
    let session_id = seal_reality_client_hello(
        &session_input,
        RealityClientHelloPatch {
            session_id_offset: input.prepared_client_hello.session_id_offset,
        },
        &mut raw_client_hello,
    )?;

    Ok(RealityPreparedHandshake {
        patched_client_hello: raw_client_hello,
        auth_key,
        session_id,
    })
}
```

- [ ] **Step 4: Run the focused handshake tests**

Run:

```bash
cargo test -p xray-transport --test reality_tests prepare_reality_handshake
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/src/reality.rs crates/xray-transport/tests/reality_tests.rs
git commit -m "feat(transport): prepare reality handshake"
```

### Task 4: Keep Runtime REALITY Gated And Update Connector Notes

**Files:**
- Modify: `crates/xray-transport/src/reality_connector.rs`
- Verify: `crates/xray-transport/tests/reality_connector_tests.rs`
- Verify: `crates/xray-transport/tests/transport_tests.rs`
- Verify: `crates/xray-core-rs/src/outbound.rs`

- [ ] **Step 1: Update the connector boundary notes**

In `crates/xray-transport/src/reality_connector.rs`, replace the numbered future implementation notes with:

```rust
//! 1. Build or integrate a Chrome-compatible TLS 1.3 ClientHello provider that
//!    exposes raw bytes, random, session-id offset, and local ECDHE private key.
//! 2. Feed that provider output into `prepare_reality_handshake`.
//! 3. Write the patched ClientHello to the network stream and complete TLS.
//! 4. Call `verify_reality_certificate_der` on the leaf certificate with the
//!    derived auth key from `RealityPreparedHandshake`.
//! 5. Expose the protected stream to VLESS only after REALITY verification.
```

Keep `RealityConnector` without a `connect` method in this slice.

- [ ] **Step 2: Run the runtime-gate tests**

Run:

```bash
cargo test -p xray-transport --test reality_connector_tests
cargo test -p xray-transport --test transport_tests transport_dialer_rejects_reality_configs_without_plaintext_downgrade
cargo test -p xray-transport --test transport_tests tcp_connector_rejects_reality_config_without_plaintext_downgrade
cargo test -p xray-core-rs open_vless_tcp_stream_rejects_outbound_with_flow_before_connecting
```

Expected: all selected tests pass, proving this slice still does not enable live REALITY or Vision flow.

- [ ] **Step 3: Commit**

```bash
git add crates/xray-transport/src/reality_connector.rs
git commit -m "docs(transport): point reality connector at handshake preparation"
```

### Task 5: Full Verification

**Files:**
- Verify workspace.

- [ ] **Step 1: Run formatting check**

Run:

```bash
cargo fmt --all -- --check
```

Expected: command exits successfully.

- [ ] **Step 2: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: command exits successfully with no warnings.

- [ ] **Step 3: Run the full Rust test suite**

Run:

```bash
cargo test --workspace --all-targets
```

Expected: all non-ignored tests pass. In this sandbox, this may require loopback bind/connect approval because existing transport tests use local sockets.

- [ ] **Step 4: Re-run the Go oracle for session-id vectors**

Run:

```bash
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

Expected: oracle check exits successfully and the fixture remains unchanged.

- [ ] **Step 5: Confirm no local compat launch was enabled**

Run:

```bash
rg -n "#\\[ignore\\]|vless_reality_vision|StreamSecurity::Reality|UnsupportedOutboundFlow" \
    tests/compat/vless_reality_vision.rs crates/xray-core-rs/src/outbound.rs
```

Expected: `tests/compat/vless_reality_vision.rs` still has its ignored test, `StreamSecurity::Reality(_)` still returns `UnsupportedOutboundSecurity`, and flow still returns `UnsupportedOutboundFlow`.

- [ ] **Step 6: Review git state**

Run:

```bash
git status --short
git log --oneline -5
```

Expected: working tree is clean after the task commits; recent commits include the three feature/docs commits from this plan.
