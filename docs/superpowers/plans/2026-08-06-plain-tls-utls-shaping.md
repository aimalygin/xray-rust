# Plain-TLS uTLS ClientHello Shaping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `security: "tls"` send a uTLS-shaped ClientHello with a `chrome` default, the way Xray-core does on every transport, instead of rustls' own hello.

**Architecture:** The shaping machinery already exists but is private to the REALITY module. This plan lifts it into two shared modules (`utls_profiles`, `utls_shaping`), adds a plain-TLS `ClientHelloCustomizer` that applies only the uTLS profile — no fixed random, no REALITY session id, no fixed key share — and teaches `TlsConnector` to build per-`(allow_insecure, alpn, fingerprint)` rustls configs. Config parsing stops rejecting `tlsSettings.fingerprint` and `tlsSettings.alpn`.

**Tech Stack:** Rust 2021, the `shaped-rustls` fork (exposes `ClientConfig.client_hello_customizer`), tokio-rustls, existing `xray-utls` fingerprint tables.

**Spec:** `docs/superpowers/specs/2026-08-06-vless-stream-transports-design.md`, sections "uTLS ClientHello shaping extends to plain TLS" and "ALPN comes from the fingerprint, not from the config". This plan implements Stage 1's TLS half; the transport layer and ws/httpupgrade follow in their own plan.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/xray-utls/src/lib.rs` (modify) | Fingerprint name tables. Gains plain-TLS normalization and the `unsafe` sentinel. |
| `crates/xray-transport/src/utls_profiles.rs` (renamed from `reality_utls_profiles.rs`) | The static uTLS profile table. Visibility widens from `pub(super)` to `pub(crate)`; contents unchanged. |
| `crates/xray-transport/src/utls_shaping.rs` (create) | `apply_utls_profile` and its helpers — translating a profile into a `ClientHelloPlan`. Moved verbatim out of `reality_rustls.rs`. |
| `crates/xray-transport/src/utls_tls.rs` (create) | `UtlsClientHelloCustomizer`: the plain-TLS customizer, and `plain_tls_client_hello_bytes` for tests. |
| `crates/xray-transport/src/reality_rustls.rs` (modify) | Keeps only REALITY logic; imports shaping from the new modules. |
| `crates/xray-transport/src/tls.rs` (modify) | `TlsConnector` builds and memoizes configs per `(allow_insecure, alpn, fingerprint)`. |
| `crates/xray-transport/src/lib.rs` (modify) | Module declarations; `TlsClientConfig` gains `alpn` and `fingerprint`. |
| `crates/xray-config/src/model.rs` (modify) | `TlsSettings` gains `alpn: Vec<String>`. |
| `crates/xray-config/src/parser.rs` (modify) | Accepts `tlsSettings.fingerprint` and `tlsSettings.alpn`. |
| `crates/xray-core-rs/src/outbound.rs` (modify) | Two sites stop rejecting a TLS fingerprint and pass it through. |
| `crates/xray-transport/tests/utls_tls_shaping_tests.rs` (create) | ClientHello byte assertions for the plain-TLS path. |

Task order matters: Tasks 2 and 3 are pure code moves that must leave the existing REALITY tests green before anything new is built on top.

---

### Task 1: Plain-TLS fingerprint normalization in `xray-utls`

The existing `normalize_reality_fingerprint` defaults an empty name to `chrome` and looks it up in `XRAY_REALITY_FINGERPRINTS`. Plain TLS needs the same lookup **without** the X25519-key-share restriction, plus Xray's `unsafe` sentinel meaning "no shaping at all".

**Files:**
- Modify: `crates/xray-utls/src/lib.rs`
- Test: `crates/xray-utls/src/lib.rs` (inline `#[cfg(test)] mod tests`, the crate's existing convention)

- [ ] **Step 1: Write the failing tests**

Add these to the existing `mod tests` block at the bottom of `crates/xray-utls/src/lib.rs`, and add `normalize_tls_fingerprint, UNSAFE_TLS_FINGERPRINT` to that module's `use super::{...}` list:

```rust
    #[test]
    fn normalize_tls_fingerprint_defaults_empty_to_chrome() {
        assert_eq!(
            normalize_tls_fingerprint(""),
            Some(DEFAULT_REALITY_FINGERPRINT)
        );
    }

    #[test]
    fn normalize_tls_fingerprint_passes_through_the_unsafe_sentinel() {
        assert_eq!(
            normalize_tls_fingerprint("unsafe"),
            Some(UNSAFE_TLS_FINGERPRINT)
        );
        assert_eq!(
            normalize_tls_fingerprint("UNSAFE"),
            Some(UNSAFE_TLS_FINGERPRINT)
        );
    }

    #[test]
    fn normalize_tls_fingerprint_accepts_reality_incapable_names() {
        // Plain TLS has no X25519 key-share requirement, so every name in the
        // table is usable even when REALITY rejects it.
        for name in XRAY_REALITY_INCAPABLE_FINGERPRINTS {
            assert_eq!(
                normalize_tls_fingerprint(name),
                Some(*name),
                "plain TLS must accept {name}"
            );
            assert_eq!(
                normalize_reality_supported_fingerprint(name),
                None,
                "{name} is expected to stay REALITY-incapable"
            );
        }
    }

    #[test]
    fn normalize_tls_fingerprint_rejects_unknown_names() {
        assert_eq!(normalize_tls_fingerprint("nosuchbrowser"), None);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p xray-utls
```

Expected: compile error, `cannot find function 'normalize_tls_fingerprint' in this scope`.

- [ ] **Step 3: Write the implementation**

Add to `crates/xray-utls/src/lib.rs`, immediately after `normalize_reality_fingerprint`:

```rust
/// Xray's escape hatch: `fingerprint: "unsafe"` disables uTLS shaping and lets
/// the TLS stack send its own ClientHello. Its entry in Xray's fingerprint map
/// is permanently nil, unlike `random`/`randomized`, which `init()` fills with
/// real profiles at startup.
pub const UNSAFE_TLS_FINGERPRINT: &str = "unsafe";

/// Normalizes a `tlsSettings.fingerprint` value.
///
/// Same name table as REALITY — Xray shares one uTLS fingerprint namespace
/// across both — but without the X25519 key-share requirement, which is a
/// REALITY protocol constraint rather than a property of the fingerprint.
/// An empty name means `chrome`, matching Xray's `GetFingerprint("")`.
pub fn normalize_tls_fingerprint(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case(UNSAFE_TLS_FINGERPRINT) {
        return Some(UNSAFE_TLS_FINGERPRINT);
    }

    normalize_reality_fingerprint(name)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p xray-utls
```

Expected: PASS, all tests including the four new ones.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-utls/src/lib.rs
git commit -m "feat(utls): add plain-TLS fingerprint normalization

Same name table as REALITY, without the X25519 key-share requirement,
plus Xray's 'unsafe' sentinel meaning no shaping."
```

---

### Task 2: Rename the profile table module and widen its visibility

Pure move, no behavior change. `reality_utls_profiles.rs` holds nothing REALITY-specific — it is the uTLS profile table.

**Files:**
- Rename: `crates/xray-transport/src/reality_utls_profiles.rs` → `crates/xray-transport/src/utls_profiles.rs`
- Modify: `crates/xray-transport/src/lib.rs:26`
- Modify: `crates/xray-transport/src/reality_rustls.rs:37`

- [ ] **Step 1: Rename the file**

```bash
git mv crates/xray-transport/src/reality_utls_profiles.rs crates/xray-transport/src/utls_profiles.rs
```

- [ ] **Step 2: Widen visibility inside the moved file**

In `crates/xray-transport/src/utls_profiles.rs`, replace every `pub(super)` with `pub(crate)`. There are exactly five: the four struct declarations (`UtlsClientHelloProfile`, `UtlsKeyShare`, `UtlsApplicationSettings`, `UtlsExtension`) and `profile_for_fingerprint`. Their fields are already `pub`.

```bash
sed -i '' 's/^pub(super) /pub(crate) /' crates/xray-transport/src/utls_profiles.rs
grep -c '^pub(crate) ' crates/xray-transport/src/utls_profiles.rs
```

Expected: `5`.

- [ ] **Step 3: Update the module declaration and the import**

In `crates/xray-transport/src/lib.rs`, replace line 26:

```rust
mod reality_utls_profiles;
```

with (keeping modules alphabetical, so it moves below `tls`):

```rust
mod utls_profiles;
```

In `crates/xray-transport/src/reality_rustls.rs`, replace line 37:

```rust
    reality_utls_profiles::{profile_for_fingerprint, UtlsClientHelloProfile},
```

with:

```rust
    utls_profiles::{profile_for_fingerprint, UtlsClientHelloProfile},
```

- [ ] **Step 4: Verify nothing broke**

```bash
cargo test -p xray-transport
```

Expected: PASS, the same test count as before the rename. If the compiler reports an unresolved `reality_utls_profiles`, a reference was missed — find it with `grep -rn reality_utls_profiles crates/`.

- [ ] **Step 5: Commit**

```bash
git add -A crates/xray-transport/src/
git commit -m "refactor(transport): rename reality_utls_profiles to utls_profiles

The table describes uTLS ClientHello profiles; nothing in it is
REALITY-specific. Widen pub(super) to pub(crate) so the plain-TLS path
can reach it."
```

---

### Task 3: Move the shaping helpers into `utls_shaping.rs`

Another pure move. `apply_utls_profile` and its helpers translate a profile into a `ClientHelloPlan` and touch nothing REALITY-specific; only their location does.

**Files:**
- Create: `crates/xray-transport/src/utls_shaping.rs`
- Modify: `crates/xray-transport/src/reality_rustls.rs` (delete the moved items, import them back)
- Modify: `crates/xray-transport/src/lib.rs` (declare the module)

- [ ] **Step 1: Create the new module with the moved items**

Create `crates/xray-transport/src/utls_shaping.rs` containing, **verbatim and unchanged except for the visibility noted below**, these items cut from `reality_rustls.rs`:

Constants (currently lines 47–73) — all of them **except** the six REALITY-specific ones that stay behind (`TLS_RECORD_HANDSHAKE`, `TLS_HANDSHAKE_SERVER_HELLO`, `TLS_RECORD_HEADER_LEN`, `TLS_HANDSHAKE_HEADER_LEN`, `REALITY_SESSION_ID_LEN`, `TLS_CLIENT_HELLO_SESSION_ID_OFFSET`):

`EXT_SERVER_NAME`, `EXT_STATUS_REQUEST`, `EXT_SUPPORTED_GROUPS`, `EXT_EC_POINT_FORMATS`, `EXT_SIGNATURE_ALGORITHMS`, `EXT_ALPN`, `EXT_SIGNED_CERTIFICATE_TIMESTAMP`, `EXT_PADDING`, `EXT_EXTENDED_MASTER_SECRET`, `EXT_CERTIFICATE_COMPRESSION`, `EXT_RECORD_SIZE_LIMIT`, `EXT_DELEGATED_CREDENTIALS`, `EXT_SESSION_TICKET`, `EXT_SUPPORTED_VERSIONS`, `EXT_PSK_KEY_EXCHANGE_MODES`, `EXT_KEY_SHARE`, `EXT_ENCRYPTED_CLIENT_HELLO`, `EXT_RENEGOTIATION_INFO`, `GROUP_X25519`, `GROUP_SECP256R1`, `GROUP_SECP384R1`, `GROUP_X25519_MLKEM768`, `GROUP_X25519_MLKEM768_DRAFT`, `TLS_VERSION_1_3`, `BROTLI_CERTIFICATE_COMPRESSION`, `BORINGSSL_PADDING_TARGET_HANDSHAKE_SIZE`, `STRUCTURED_OPTIONAL_EXTENSIONS`.

Nine of these are still referenced by the REALITY code left behind, so declare **all** of them `pub(crate)` for uniformity: `pub(crate) const EXT_SERVER_NAME: u16 = 0x0000;` and so on.

Functions (currently lines 507–1044), moved unchanged, all becoming `pub(crate) fn` only where `reality_rustls.rs` still calls them — that is `apply_utls_profile` alone; the rest stay private `fn`:

`apply_utls_profile`, `advertised_cipher_suites`, `supported_versions`, `advertised_supported_versions`, `supported_groups`, `advertised_supported_groups`, `key_share_plan`, `raw_key_shares`, `alpn_protocols`, `certificate_compression`, `extension_order`, `extension_plan`, `forced_extensions`, `extension_payloads`, `encrypted_client_hello_payload`, `grease_plan`, `signature_algorithms_payload`, `certificate_compression_payload`, `application_settings_payload`, `push_exact_or_raw_extension`, `is_structured_extension`, `profile_has_extension`, `profile_uses_structured_certificate_compression`, `real_supported_group`, `real_key_share_group`, `is_grease_value`.

Head the file with the imports those items need:

```rust
use rustls::{
    client::{
        ClientHelloAdvertisedCipherSuites, ClientHelloAdvertisedSupportedGroups,
        ClientHelloAdvertisedSupportedVersions, ClientHelloAlpnProtocols,
        ClientHelloCertificateCompressionAlgorithms, ClientHelloExactExtension,
        ClientHelloExactExtensions, ClientHelloExtensionOrder, ClientHelloExtensionPlan,
        ClientHelloForcedExtensions, ClientHelloGreaseExtension, ClientHelloGreasePlan,
        ClientHelloKeySharePlan, ClientHelloPaddingPlan, ClientHelloPlan, ClientHelloRawExtension,
        ClientHelloRawExtensions, ClientHelloRawKeyShare, ClientHelloRawKeyShares,
        ClientHelloSupportedGroups, ClientHelloSupportedVersions,
    },
    CertificateCompressionAlgorithm, CipherSuite, Error as RustlsError, NamedGroup,
    ProtocolVersion, SignatureScheme,
};

use crate::utls_profiles::UtlsClientHelloProfile;
```

- [ ] **Step 2: Delete the moved items from `reality_rustls.rs` and import them back**

Remove the constants and functions listed above from `crates/xray-transport/src/reality_rustls.rs`. Then extend its `use crate::{...}` block (currently at line 30) with:

```rust
    utls_shaping::{
        apply_utls_profile, EXT_ALPN, EXT_CERTIFICATE_COMPRESSION, EXT_EC_POINT_FORMATS,
        EXT_EXTENDED_MASTER_SECRET, EXT_PSK_KEY_EXCHANGE_MODES, EXT_RENEGOTIATION_INFO,
        EXT_SERVER_NAME, EXT_SESSION_TICKET, EXT_STATUS_REQUEST, EXT_SUPPORTED_GROUPS,
    },
```

Then delete from `reality_rustls.rs`'s top-level `use rustls::{...}` block any name that is now unused. `cargo build` will name each one as an `unused import` warning — remove exactly those, and no others.

- [ ] **Step 3: Declare the module**

In `crates/xray-transport/src/lib.rs`, next to `mod utls_profiles;`, add:

```rust
mod utls_shaping;
```

- [ ] **Step 4: Verify nothing broke**

```bash
cargo test -p xray-transport 2>&1 | tail -30
```

Expected: PASS with the same test count as Task 2, and **no warnings**. In particular `reality_clienthello_tests`, `reality_rustls_tests`, and `reality_runtime_tests` must be unchanged — they assert exact ClientHello bytes, so any accidental edit during the move shows up here.

- [ ] **Step 5: Commit**

```bash
git add -A crates/xray-transport/src/
git commit -m "refactor(transport): move uTLS shaping out of the REALITY module

apply_utls_profile and its helpers translate a uTLS profile into a
ClientHelloPlan and contain nothing REALITY-specific. No behavior change:
the REALITY ClientHello byte assertions are untouched and still pass."
```

---

### Task 4: The plain-TLS ClientHello customizer

The REALITY customizer builds a plan with a fixed hello random, a session id carrying the auth key, and a fixed X25519 key share, then applies the profile. The plain-TLS one applies only the profile, and additionally honors the ALPN override.

**Files:**
- Create: `crates/xray-transport/src/utls_tls.rs`
- Modify: `crates/xray-transport/src/lib.rs`
- Test: `crates/xray-transport/tests/utls_tls_shaping_tests.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/xray-transport/tests/utls_tls_shaping_tests.rs`:

```rust
mod utls_tls_shaping_tests {
    use xray_transport::{plain_tls_client_hello_bytes, TlsClientConfig};

    const EXT_ALPN: u16 = 0x0010;
    const CHROME_GREASE_CIPHER: u16 = 0x0a0a;

    fn config(fingerprint: &str, alpn: &[&str]) -> TlsClientConfig {
        TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            alpn: alpn.iter().map(|value| (*value).to_owned()).collect(),
            fingerprint: Some(fingerprint.to_owned()),
        }
    }

    /// Walks the ClientHello extension list and returns the ALPN protocol
    /// names, in order. Layout: record header (5) + handshake header (4) +
    /// version (2) + random (32) + session id + cipher suites + compression
    /// methods + extensions.
    fn alpn_protocols(hello: &[u8]) -> Vec<String> {
        let mut cursor = 5 + 4 + 2 + 32;
        let session_id_len = usize::from(hello[cursor]);
        cursor += 1 + session_id_len;
        let cipher_suites_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2 + cipher_suites_len;
        let compression_len = usize::from(hello[cursor]);
        cursor += 1 + compression_len;
        let extensions_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2;
        let end = cursor + extensions_len;

        while cursor + 4 <= end {
            let extension_type = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
            let payload_len = usize::from(u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]));
            let payload = &hello[cursor + 4..cursor + 4 + payload_len];
            cursor += 4 + payload_len;

            if extension_type != EXT_ALPN {
                continue;
            }

            let mut protocols = Vec::new();
            let mut offset = 2;
            while offset < payload.len() {
                let len = usize::from(payload[offset]);
                offset += 1;
                protocols.push(String::from_utf8_lossy(&payload[offset..offset + len]).into_owned());
                offset += len;
            }
            return protocols;
        }

        Vec::new()
    }

    fn cipher_suites(hello: &[u8]) -> Vec<u16> {
        let mut cursor = 5 + 4 + 2 + 32;
        cursor += 1 + usize::from(hello[cursor]);
        let len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 2;
        hello[cursor..cursor + len]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect()
    }

    #[test]
    fn chrome_fingerprint_shapes_the_client_hello() {
        let hello = plain_tls_client_hello_bytes(&config("chrome", &[]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(
            cipher_suites(&hello).first().copied(),
            Some(CHROME_GREASE_CIPHER),
            "a shaped Chrome hello leads with a GREASE cipher suite"
        );
    }

    #[test]
    fn alpn_defaults_to_the_profile_list() {
        let hello = plain_tls_client_hello_bytes(&config("chrome", &[]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), vec!["h2", "http/1.1"]);
    }

    #[test]
    fn http11_alpn_overrides_the_profile_list() {
        let hello = plain_tls_client_hello_bytes(&config("chrome", &["http/1.1"]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), vec!["http/1.1"]);
    }

    #[test]
    fn other_alpn_lists_do_not_override_the_profile() {
        // Xray only rebuilds the hello when the configured list is exactly
        // ["http/1.1"]; every other list leaves the profile's ALPN in place.
        let hello = plain_tls_client_hello_bytes(&config("chrome", &["h2"]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), vec!["h2", "http/1.1"]);
    }

    #[test]
    fn unsafe_fingerprint_leaves_the_hello_unshaped() {
        let hello = plain_tls_client_hello_bytes(&TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: Some("unsafe".to_owned()),
        })
        .expect("unshaped ClientHello must be produced");

        assert_ne!(
            cipher_suites(&hello).first().copied(),
            Some(CHROME_GREASE_CIPHER),
            "the unsafe sentinel must leave rustls' own hello alone"
        );
    }

    #[test]
    fn reality_incapable_fingerprints_are_usable_on_plain_tls() {
        let hello = plain_tls_client_hello_bytes(&config("hellochrome_58", &[]))
            .expect("a REALITY-incapable fingerprint must still shape plain TLS");

        assert!(!hello.is_empty());
    }

    #[test]
    fn unknown_fingerprints_are_rejected() {
        let error = plain_tls_client_hello_bytes(&config("nosuchbrowser", &[]))
            .expect_err("an unknown fingerprint must not silently fall back");

        assert!(
            error.to_string().contains("nosuchbrowser"),
            "the error must name the offending fingerprint, got: {error}"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p xray-transport --test utls_tls_shaping_tests
```

Expected: compile error, `cannot find function 'plain_tls_client_hello_bytes'` and `struct 'TlsClientConfig' has no field named 'alpn'`.

- [ ] **Step 3: Extend `TlsClientConfig`**

In `crates/xray-transport/src/lib.rs`, replace the struct at line 54:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientConfig {
    pub server_name: String,
    pub allow_insecure: bool,
    /// `tlsSettings.alpn`. Reaches the ClientHello only when it is exactly
    /// `["http/1.1"]`; otherwise the fingerprint profile's own ALPN wins.
    /// It still selects the HTTP version for transports that ask.
    pub alpn: Vec<String>,
    /// Normalized `tlsSettings.fingerprint`. `None` and `Some("unsafe")` both
    /// mean no shaping; `None` is the value used by call sites that predate
    /// fingerprint support.
    pub fingerprint: Option<String>,
}
```

Every existing construction of `TlsClientConfig` now fails to compile. Fix each by adding `alpn: Vec::new(), fingerprint: None,` — the compiler lists them; expect sites in `crates/xray-core-rs/src/outbound.rs`, `crates/xray-core-rs/src/dns.rs`, and several test files. Leave their behavior unchanged for now; Task 6 wires the real values through.

- [ ] **Step 4: Write the customizer**

Create `crates/xray-transport/src/utls_tls.rs`:

```rust
use std::fmt;
use std::sync::{Arc, Mutex};

use rustls::client::{
    CapturesClientHello, ClientHelloAlpnProtocols, ClientHelloContext, ClientHelloCustomizer,
    ClientHelloPlan,
};
use rustls::Error as RustlsError;

use crate::utls_profiles::{profile_for_fingerprint, UtlsClientHelloProfile};
use crate::utls_shaping::apply_utls_profile;
use crate::TransportError;

/// The one configured ALPN list Xray rebuilds the ClientHello for. Anything
/// else leaves the fingerprint profile's own ALPN in place.
const ALPN_OVERRIDE_TRIGGER: &str = "http/1.1";

/// Resolves a normalized fingerprint to a shaping profile.
///
/// `None` means the hello is left unshaped: either no fingerprint was
/// configured, or it was Xray's `unsafe` sentinel.
pub(crate) fn shaping_profile(
    fingerprint: Option<&str>,
) -> Result<Option<&'static UtlsClientHelloProfile>, TransportError> {
    let Some(fingerprint) = fingerprint else {
        return Ok(None);
    };
    if fingerprint == xray_utls::UNSAFE_TLS_FINGERPRINT {
        return Ok(None);
    }

    profile_for_fingerprint(fingerprint)
        .map(Some)
        .ok_or_else(|| TransportError::UnsupportedTlsFingerprint(fingerprint.to_owned()))
}

/// Applies the fingerprint's ClientHello shape to an ordinary TLS handshake.
///
/// Unlike the REALITY customizer this sets no hello random, no session id, and
/// no fixed key share — those carry REALITY's authentication and have no place
/// in a plain handshake.
pub(crate) struct UtlsClientHelloCustomizer {
    profile: &'static UtlsClientHelloProfile,
    alpn_override: Option<Vec<Vec<u8>>>,
    capture: Option<Arc<PlainClientHelloCapture>>,
}

impl UtlsClientHelloCustomizer {
    pub(crate) fn new(profile: &'static UtlsClientHelloProfile, alpn: &[String]) -> Self {
        Self {
            profile,
            alpn_override: alpn_override_for(alpn),
            capture: None,
        }
    }

    fn with_capture(mut self, capture: Arc<PlainClientHelloCapture>) -> Self {
        self.capture = Some(capture);
        self
    }
}

/// Mirrors `UConn.WebsocketHandshakeContext`: the hello is rebuilt with ALPN
/// forced to `http/1.1` only when the configured list is exactly that.
fn alpn_override_for(alpn: &[String]) -> Option<Vec<Vec<u8>>> {
    match alpn {
        [only] if only == ALPN_OVERRIDE_TRIGGER => {
            Some(vec![ALPN_OVERRIDE_TRIGGER.as_bytes().to_vec()])
        }
        _ => None,
    }
}

impl fmt::Debug for UtlsClientHelloCustomizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UtlsClientHelloCustomizer")
            .field("profile", &self.profile)
            .field("alpn_override", &self.alpn_override)
            .field("capture", &self.capture.is_some())
            .finish()
    }
}

impl ClientHelloCustomizer for UtlsClientHelloCustomizer {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        let mut plan = apply_utls_profile(ClientHelloPlan::new(), self.profile)?;

        if let Some(protocols) = &self.alpn_override {
            plan = plan.with_alpn_protocols(ClientHelloAlpnProtocols::try_from(protocols.clone())?);
        }
        if let Some(capture) = &self.capture {
            plan = plan.with_capture(capture.clone());
        }

        Ok(Some(plan))
    }
}

#[derive(Debug, Default)]
pub(crate) struct PlainClientHelloCapture {
    bytes: Mutex<Option<Vec<u8>>>,
}

impl PlainClientHelloCapture {
    fn take(&self) -> Result<Vec<u8>, TransportError> {
        let mut bytes = self.bytes.lock().map_err(|_| {
            TransportError::TlsConfig("ClientHello capture lock was poisoned".to_owned())
        })?;
        bytes.take().ok_or_else(|| {
            TransportError::TlsConfig("rustls did not capture a ClientHello".to_owned())
        })
    }
}

impl CapturesClientHello for PlainClientHelloCapture {
    fn capture_client_hello(&self, bytes: &[u8]) -> Result<(), RustlsError> {
        let mut captured = self
            .bytes
            .lock()
            .map_err(|_| RustlsError::General("ClientHello capture lock was poisoned".to_owned()))?;
        *captured = Some(bytes.to_vec());
        Ok(())
    }
}
```

- [ ] **Step 5: Add the test entry point**

Producing a hello needs no network: build a `ClientConnection` and drain its first flight. Append to `crates/xray-transport/src/utls_tls.rs`:

```rust
/// Produces the ClientHello a plain-TLS connection would send, without opening
/// a socket. Exposed for byte-parity tests against Xray-core.
pub fn plain_tls_client_hello_bytes(
    config: &crate::TlsClientConfig,
) -> Result<Vec<u8>, TransportError> {
    use rustls::pki_types::ServerName;
    use rustls::ClientConnection;

    let capture = Arc::new(PlainClientHelloCapture::default());
    let mut client_config = crate::tls::base_client_config(config.allow_insecure)?;
    if let Some(profile) = shaping_profile(config.fingerprint.as_deref())? {
        client_config.client_hello_customizer = Some(Arc::new(
            UtlsClientHelloCustomizer::new(profile, &config.alpn).with_capture(Arc::clone(&capture)),
        ));
    } else {
        // Unshaped: rustls emits its own hello, so capture the raw first flight.
        let server_name = ServerName::try_from(config.server_name.clone())
            .map_err(|_| TransportError::InvalidTlsServerName(config.server_name.clone()))?;
        let mut connection = ClientConnection::new(Arc::new(client_config), server_name)
            .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
        let mut record = Vec::new();
        connection
            .write_tls(&mut record)
            .map_err(TransportError::Tcp)?;
        return Ok(record);
    }

    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| TransportError::InvalidTlsServerName(config.server_name.clone()))?;
    let mut connection = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
    let mut record = Vec::new();
    connection
        .write_tls(&mut record)
        .map_err(TransportError::Tcp)?;

    capture.take()
}
```

The capture hook yields the handshake message without the record header, while the unshaped branch returns the full record. Both start with the same offsets the test walks past record + handshake headers, so keep the shaped branch consistent by prepending the record header:

```rust
    let mut hello = capture.take()?;
    let mut framed = Vec::with_capacity(hello.len() + 5);
    framed.extend_from_slice(&[0x16, 0x03, 0x01]);
    framed.extend_from_slice(&u16::try_from(hello.len()).unwrap_or(u16::MAX).to_be_bytes());
    framed.append(&mut hello);
    Ok(framed)
```

Replace the trailing `capture.take()` with that block.

- [ ] **Step 6: Wire up the module and the error variant**

In `crates/xray-transport/src/lib.rs` add the module beside the others:

```rust
mod utls_tls;
```

export the test entry point next to `pub use tls::TlsConnector;`:

```rust
pub use utls_tls::plain_tls_client_hello_bytes;
```

and add to the `TransportError` enum, after `UnsupportedRealityFingerprint`:

```rust
    #[error("unsupported TLS fingerprint {0}")]
    UnsupportedTlsFingerprint(String),
```

In `crates/xray-transport/src/tls.rs`, make the config builders reachable from `utls_tls.rs` by replacing the two private functions' signatures with one shared helper. Add:

```rust
pub(crate) fn base_client_config(
    allow_insecure: bool,
) -> Result<rustls::ClientConfig, TransportError> {
    if allow_insecure {
        return insecure_rustls_client_config();
    }

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls_client_config(root_store)
}
```

and change `mod tls;` in `lib.rs` to `pub(crate) mod tls;` so `crate::tls::base_client_config` resolves.

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cargo test -p xray-transport --test utls_tls_shaping_tests
```

Expected: PASS, 7 tests.

- [ ] **Step 8: Run the full crate suite**

```bash
cargo test -p xray-transport
```

Expected: PASS, no regressions in the REALITY tests.

- [ ] **Step 9: Commit**

```bash
git add -A crates/xray-transport/
git commit -m "feat(transport): shape plain-TLS ClientHellos with uTLS profiles

Adds UtlsClientHelloCustomizer, which applies a fingerprint profile
without REALITY's random, session id, or fixed key share, plus the
http/1.1 ALPN override Xray applies via WebsocketHandshakeContext."
```

---

### Task 5: `TlsConnector` builds configs per fingerprint and ALPN

`TlsConnector` currently holds two fixed `rustls::ClientConfig`s. Shaping makes the config depend on `(allow_insecure, alpn, fingerprint)`, so it needs to build them on demand and memoize.

**Files:**
- Modify: `crates/xray-transport/src/tls.rs:21-142`
- Test: `crates/xray-transport/tests/transport_tests.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/xray-transport/tests/transport_tests.rs`, inside its existing test module:

```rust
    #[test]
    fn tls_connector_memoizes_configs_per_shape() {
        let connector = xray_transport::TlsConnector::system()
            .expect("system roots must load");

        let chrome = xray_transport::TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: false,
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
        };
        let firefox = xray_transport::TlsClientConfig {
            fingerprint: Some("firefox".to_owned()),
            ..chrome.clone()
        };

        let first = connector.client_config_for(&chrome).expect("chrome config");
        let again = connector.client_config_for(&chrome).expect("chrome config");
        let other = connector.client_config_for(&firefox).expect("firefox config");

        assert!(
            std::sync::Arc::ptr_eq(&first, &again),
            "the same shape must reuse one config"
        );
        assert!(
            !std::sync::Arc::ptr_eq(&first, &other),
            "different fingerprints must not share a config"
        );
    }

    #[test]
    fn tls_connector_rejects_unknown_fingerprints() {
        let connector = xray_transport::TlsConnector::system()
            .expect("system roots must load");

        let error = connector
            .client_config_for(&xray_transport::TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                alpn: Vec::new(),
                fingerprint: Some("nosuchbrowser".to_owned()),
            })
            .expect_err("an unknown fingerprint must fail");

        assert!(error.to_string().contains("nosuchbrowser"));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p xray-transport --test transport_tests
```

Expected: compile error, `no method named 'client_config_for'`.

- [ ] **Step 3: Replace the fixed configs with a memoizing cache**

In `crates/xray-transport/src/tls.rs`, replace the struct and its constructors (lines 21–62):

```rust
/// Identifies one rustls configuration shape. Two connections that agree on
/// all three fields can share a config, which matters because building one
/// parses the whole root store.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ClientConfigKey {
    allow_insecure: bool,
    alpn: Vec<String>,
    fingerprint: Option<String>,
}

#[derive(Clone)]
pub struct TlsConnector {
    configs: Arc<Mutex<HashMap<ClientConfigKey, Arc<rustls::ClientConfig>>>>,
    override_config: Option<Arc<rustls::ClientConfig>>,
    socket_protector: Option<Arc<dyn SocketProtector>>,
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsConnector")
            .field("socket_protector", &self.socket_protector.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsConnector {
    pub fn system() -> Result<Self, TransportError> {
        Ok(Self {
            configs: Arc::new(Mutex::new(HashMap::new())),
            override_config: None,
            socket_protector: None,
        })
    }

    /// Pins one prebuilt config for every connection, bypassing shaping.
    /// Used by tests that supply their own roots.
    pub fn with_client_config(client_config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            configs: Arc::new(Mutex::new(HashMap::new())),
            override_config: Some(client_config),
            socket_protector: None,
        }
    }

    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.socket_protector = Some(protector);
        self
    }

    /// Returns the config for one connection shape, building and caching it on
    /// first use.
    pub fn client_config_for(
        &self,
        config: &TlsClientConfig,
    ) -> Result<Arc<rustls::ClientConfig>, TransportError> {
        if let Some(override_config) = &self.override_config {
            return Ok(Arc::clone(override_config));
        }

        let key = ClientConfigKey {
            allow_insecure: config.allow_insecure,
            alpn: config.alpn.clone(),
            fingerprint: config.fingerprint.clone(),
        };

        let mut configs = self
            .configs
            .lock()
            .map_err(|_| TransportError::TlsConfig("TLS config cache lock was poisoned".to_owned()))?;
        if let Some(cached) = configs.get(&key) {
            return Ok(Arc::clone(cached));
        }

        let client_config = match crate::utls_tls::shaping_profile(config.fingerprint.as_deref())? {
            Some(profile) => {
                // Shaping needs aws-lc-rs: the modern profiles plan an
                // X25519MLKEM768 key share, and ring does not carry that group.
                let mut client_config = shaped_client_config(config.allow_insecure)?;
                client_config.client_hello_customizer = Some(Arc::new(
                    crate::utls_tls::UtlsClientHelloCustomizer::new(profile, &config.alpn),
                ));
                client_config
            }
            None => base_client_config(config.allow_insecure)?,
        };

        let client_config = Arc::new(client_config);
        configs.insert(key, Arc::clone(&client_config));
        Ok(client_config)
    }
}
```

Two things here that Task 4 established and that are easy to get wrong:

**Use `shaped_client_config`, not `base_client_config`, on the shaping branch.** Task 4 discovered that `rustls::crypto::ring` carries only X25519/secp256r1/secp384r1, while the current Chrome profile plans an X25519MLKEM768 key share; building a shaped config on ring fails the handshake with "ClientHello key share group is not supported by this config". `tls.rs` therefore has two builders — `base_client_config` on ring, byte-identical to the pre-shaping behavior, and `shaped_client_config` on aws-lc-rs with REALITY's key-exchange group list. The unshaped branch (`fingerprint: None` or `"unsafe"`) must stay on ring so that asking for no shaping really does reproduce today's ClientHello.

**Resumption is already disabled inside `shaped_client_config`** — Task 4 landed it there, so this task does not repeat it. The reason is worth knowing anyway: a resumed session emits a second ClientHello carrying `pre_shared_key`, an extension the fingerprint profile never described, which would defeat the shaping on exactly the connections a long-lived client makes most. `reality_rustls.rs` disables it for the same reason, in its own builder rather than at the call site — the builder owning its shaping invariants is this crate's established pattern.

Add to the imports at the top of the file:

```rust
use std::collections::HashMap;
use std::sync::Mutex;
```

- [ ] **Step 4: Use the cache at the handshake site**

Replace `connect_stream_with_server_name` (lines 124–141):

```rust
    async fn connect_stream_with_server_name(
        &self,
        stream: BoxedTransportStream,
        config: &TlsClientConfig,
        server_name: ServerName<'static>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let client_config = self.client_config_for(config)?;
        let stream = TokioTlsConnector::from(client_config)
            .connect(server_name, stream)
            .await
            .map_err(TransportError::Tls)?;

        Ok(Box::new(stream))
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p xray-transport
```

Expected: PASS. `TlsConnector::system()` no longer builds a config eagerly, so a failure here means a call site relied on that — the compiler names it.

- [ ] **Step 6: Commit**

```bash
git add -A crates/xray-transport/src/
git commit -m "feat(transport): build TLS configs per fingerprint and ALPN shape

rustls::ClientConfig is immutable behind an Arc, so shaping needs one
config per (allow_insecure, alpn, fingerprint). Memoize them instead of
holding two fixed instances."
```

---

### Task 5A: Pin the extension order for TLS-1.2-era profiles

**This task was added mid-execution, after Task 4's review found a pre-existing defect. It must land before Task 6, because Task 6 is what first lets a user select the affected fingerprints.**

`apply_utls_profile` pins the ClientHello extension order only when the profile declares `supported_versions` (`crates/xray-transport/src/utls_shaping.rs:110-112`, and the parallel gate at `:83-85`). **8 of the 34 distinct profiles — 14 of the 61 fingerprint names — declare none**, and they are all REALITY-incapable, which is why nothing has caught this: `rustls_reality_provider_matches_utls_xray_fingerprints_in_order` iterates only `XRAY_REALITY_CAPABLE_FINGERPRINTS`, *and* it is `#[ignore]`d because it needs the Go oracle, so it does not run in `cargo test` at all.

Two defects follow for those profiles, both measured during Task 4's review:

1. **The extension order is randomized per connection.** Dumping `android`'s hello twice gives two different orders. Real clients have a stable order; per-connection shuffling is itself a distinguishing signal, and arguably a worse one than a wrong-but-stable order.
2. **The extension set is wrong.** They emit `supported_versions` (0x002b), which they never declare. `android` declares `[0000, 0017, ff01, 000a, 000b, 0005, 000d]` and emits `[ff01, 000b, 000d, 0005, 0017, 000a, 0000, 002b]`. `hellochrome_58` is a 2017 TLS-1.2-era fingerprint whose real ClientHello carries no such extension at all.

**Acceptance criteria:**

- For every profile with empty `supported_versions`, the emitted extension order is stable across connections and matches what uTLS emits for that fingerprint.
- Those profiles no longer emit a `supported_versions` extension they do not declare.
- Profiles that *do* declare `supported_versions` are byte-identical to today — verify by dumping the emitted order for all 47 affected fingerprint names before and after, as Task 4's review did, and diffing.
- Coverage runs in CI. Reuse Task 9's pattern — a checked-in shape fixture consumed with `include_str!` — rather than adding to the `#[ignore]`d live-oracle test. Fixture at least `android` and `hellochrome_58`.

**Likely design question, which is why this task is scoped rather than specified:** suppressing `supported_versions` may require configuring rustls to TLS 1.2 only for these profiles, since rustls emits that extension whenever TLS 1.3 is offered. That would mean the shaped config's protocol versions become profile-dependent, which reaches into `shaped_client_config` and therefore into Task 5's memoization key. **If the fix needs that, stop and escalate rather than deciding alone** — it changes the shape of `TlsConnector`'s cache and I want to weigh it.

**Standing hazard this exposed, worth remembering beyond this task:** "the oracle test passes" has been treated as evidence about shaping fidelity throughout this plan. It is not, while that test is `#[ignore]`d and scoped to REALITY-capable names. Any claim of fingerprint parity needs a test that actually runs.

---

### Task 6: Accept `fingerprint` and `alpn` in config parsing

**Files:**
- Modify: `crates/xray-config/src/model.rs:908-914`
- Modify: `crates/xray-config/src/parser.rs:2669-2698` and `2736-2766`
- Test: `crates/xray-config/tests/parser_tests.rs`

- [ ] **Step 1: Write the failing tests**

Append to `crates/xray-config/tests/parser_tests.rs`, following the file's existing helper conventions:

```rust
#[test]
fn tls_settings_accept_a_fingerprint() {
    let config = parse_config_value(json!({
        "inbounds": [minimal_socks_inbound()],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{"id": TEST_UUID}]
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": "example.com", "fingerprint": "firefox"}
            }
        }]
    }))
    .expect("a TLS fingerprint must be accepted");

    let StreamSecurity::Tls(tls) = &config.outbounds[0].stream.security else {
        panic!("expected TLS security");
    };
    assert_eq!(tls.fingerprint.as_deref(), Some("firefox"));
}

#[test]
fn tls_settings_default_the_fingerprint_to_chrome() {
    let config = parse_config_value(json!({
        "inbounds": [minimal_socks_inbound()],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{"id": TEST_UUID}]
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": "example.com"}
            }
        }]
    }))
    .expect("TLS without a fingerprint must parse");

    let StreamSecurity::Tls(tls) = &config.outbounds[0].stream.security else {
        panic!("expected TLS security");
    };
    assert_eq!(
        tls.fingerprint.as_deref(),
        Some("chrome"),
        "an absent fingerprint means chrome, matching Xray's GetFingerprint(\"\")"
    );
}

#[test]
fn tls_settings_accept_an_alpn_list() {
    let config = parse_config_value(json!({
        "inbounds": [minimal_socks_inbound()],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{"id": TEST_UUID}]
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": "example.com", "alpn": ["http/1.1"]}
            }
        }]
    }))
    .expect("a TLS alpn list must be accepted");

    let StreamSecurity::Tls(tls) = &config.outbounds[0].stream.security else {
        panic!("expected TLS security");
    };
    assert_eq!(tls.alpn, vec!["http/1.1".to_owned()]);
}

#[test]
fn tls_settings_reject_an_unknown_fingerprint() {
    let errors = parse_config_value(json!({
        "inbounds": [minimal_socks_inbound()],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{"id": TEST_UUID}]
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": "example.com", "fingerprint": "nosuchbrowser"}
            }
        }]
    }))
    .expect_err("an unknown fingerprint must be rejected");

    assert!(
        errors.iter().any(|error| error.message.contains("nosuchbrowser")),
        "the error must name the fingerprint, got: {errors:?}"
    );
}
```

If `parse_config_value`, `minimal_socks_inbound`, or `TEST_UUID` are named differently in that file, use its existing helpers — match the surrounding tests rather than introducing new ones.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p xray-config --test parser_tests
```

Expected: FAIL — the fingerprint tests report the `tls fingerprint is unsupported` error, and the ALPN test reports `tls alpn is unsupported`.

- [ ] **Step 3: Extend the model**

In `crates/xray-config/src/model.rs`, replace the `TlsSettings` struct (line 908):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    pub server_name: Option<String>,
    /// Normalized uTLS fingerprint. Always populated: an absent
    /// `tlsSettings.fingerprint` means `chrome`, and `unsafe` means no shaping.
    pub fingerprint: Option<String>,
    pub allow_insecure: bool,
    /// `tlsSettings.alpn`, verbatim.
    pub alpn: Vec<String>,
}
```

- [ ] **Step 4: Accept both keys in the parser**

In `crates/xray-config/src/parser.rs`, inside `validate_tls_settings`, delete the whole `if settings.get("fingerprint").is_some() { ... }` block (lines 2752–2757) and replace the ALPN block (lines 2759–2765) with a shape check only:

```rust
        if let Some(alpn) = settings.get("alpn") {
            if !alpn.is_array() {
                self.error(format!("{settings_path}.alpn"), "tls alpn must be an array");
            }
        }
```

Then in `parse_security`'s `"tls"` arm, replace the `TlsSettings` construction (lines 2689–2697):

```rust
                let raw_fingerprint = tls_settings
                    .and_then(|settings| self.string_at(settings, "fingerprint"))
                    .unwrap_or_default();
                let fingerprint = match xray_utls::normalize_tls_fingerprint(raw_fingerprint) {
                    Some(fingerprint) => Some(fingerprint.to_owned()),
                    None => {
                        self.error(
                            format!("$.outbounds[{index}].streamSettings.tlsSettings.fingerprint"),
                            format!("unsupported tls fingerprint `{raw_fingerprint}`"),
                        );
                        None
                    }
                };
                let alpn = tls_settings
                    .and_then(|settings| settings.get("alpn"))
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();

                Some(StreamSecurity::Tls(TlsSettings {
                    server_name: tls_settings
                        .and_then(|settings| self.string_at(settings, "serverName"))
                        .map(ToOwned::to_owned),
                    fingerprint,
                    allow_insecure,
                    alpn,
                }))
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p xray-config
```

Expected: PASS. Existing tests asserting that a fingerprint is rejected will now fail — those assertions encoded the old limitation and must be deleted, not worked around. Search for them with `grep -rn "fingerprint is unsupported\|alpn is unsupported" crates/`.

- [ ] **Step 6: Commit**

```bash
git add -A crates/xray-config/
git commit -m "feat(config): accept tlsSettings.fingerprint and tlsSettings.alpn

An absent fingerprint normalizes to chrome, matching Xray's
GetFingerprint(\"\"). Unknown names are rejected by name."
```

---

### Task 7: Pass the fingerprint through the outbound builders

Two sites reject a non-empty TLS fingerprint. Both must forward it instead.

**Files:**
- Modify: `crates/xray-core-rs/src/outbound.rs:1497-1515` and `1551-1566`
- Test: `crates/xray-core-rs/src/outbound.rs` (inline test module, the file's convention)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `crates/xray-core-rs/src/outbound.rs`:

```rust
    #[test]
    fn tls_outbound_carries_the_fingerprint_into_the_connector() {
        let stream = StreamSettings {
            network: Network::Tcp,
            security: StreamSecurity::Tls(TlsSettings {
                server_name: Some("example.com".to_owned()),
                fingerprint: Some("firefox".to_owned()),
                allow_insecure: false,
                alpn: vec!["http/1.1".to_owned()],
            }),
            socket_options: None,
        };

        let connector = dns_tcp_connector(&stream).expect("a TLS fingerprint must be accepted");

        let DnsTcpConnector::Static(ConnectorConfig::Tls(tls)) = connector else {
            panic!("expected a static TLS connector");
        };
        assert_eq!(tls.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(tls.alpn, vec!["http/1.1".to_owned()]);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p xray-core-rs tls_outbound_carries_the_fingerprint
```

Expected: FAIL — `dns_tcp_connector` returns `Err(UnsupportedOutboundSecurity)`.

- [ ] **Step 3: Forward the fingerprint at both sites**

In `crates/xray-core-rs/src/outbound.rs`, in the `StreamSecurity::Tls(tls)` arm around line 1497, delete the three-line rejection and extend the constructed config:

```rust
        StreamSecurity::Tls(tls) => {
            let server_name = match tls.server_name.as_deref() {
                Some(name) if !name.is_empty() => name.to_owned(),
                Some(_) => return Err(CoreError::UnsupportedOutboundSecurity),
                None => match &settings.server {
                    TargetAddr::Domain(domain) => domain.clone(),
                    TargetAddr::Ip(_) => return Err(CoreError::UnsupportedOutboundSecurity),
                },
            };

            ConnectorConfig::Tls(TlsClientConfig {
                server_name,
                allow_insecure: tls.allow_insecure,
                alpn: tls.alpn.clone(),
                fingerprint: tls.fingerprint.clone(),
            })
        }
```

And in `dns_tcp_connector` around line 1551:

```rust
        StreamSecurity::Tls(tls) => match tls.server_name.as_deref() {
            Some(server_name) if !server_name.is_empty() => Ok(DnsTcpConnector::Static(
                ConnectorConfig::Tls(TlsClientConfig {
                    server_name: server_name.to_owned(),
                    allow_insecure: tls.allow_insecure,
                    alpn: tls.alpn.clone(),
                    fingerprint: tls.fingerprint.clone(),
                }),
            )),
            Some(_) | None => Ok(DnsTcpConnector::TlsFromTarget {
                allow_insecure: tls.allow_insecure,
            }),
        },
```

`DnsTcpConnector::TlsFromTarget` defers its config to dial time, so it must carry the shape too. Change the variant declaration (line 272):

```rust
    TlsFromTarget {
        allow_insecure: bool,
        alpn: Vec<String>,
        fingerprint: Option<String>,
    },
```

populate it in the arm above:

```rust
            Some(_) | None => Ok(DnsTcpConnector::TlsFromTarget {
                allow_insecure: tls.allow_insecure,
                alpn: tls.alpn.clone(),
                fingerprint: tls.fingerprint.clone(),
            }),
```

and consume it in `tcp_connector_for` (line 402), replacing that match arm:

```rust
            DnsTcpConnector::TlsFromTarget {
                allow_insecure,
                alpn,
                fingerprint,
            } => {
                let RoutingTargetAddr::Domain(server_name) = &target.addr else {
                    return Err(CoreError::UnsupportedOutboundSecurity);
                };
                Ok(ConnectorConfig::Tls(TlsClientConfig {
                    server_name: server_name.clone(),
                    allow_insecure: *allow_insecure,
                    alpn: alpn.clone(),
                    fingerprint: fingerprint.clone(),
                }))
            }
```

Keep whatever the existing arm does for the non-domain case; only the `TlsClientConfig` construction and the destructuring change. The variant is `Clone`-derived through `DnsOutboundPayload`, so no other site needs touching.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p xray-core-rs
```

Expected: PASS. Any test asserting `UnsupportedOutboundSecurity` for a TLS fingerprint encoded the old limitation — delete it.

- [ ] **Step 5: Commit**

```bash
git add -A crates/xray-core-rs/
git commit -m "feat(core): carry the TLS fingerprint into the connector

Both the VLESS and DNS outbound builders rejected a non-empty
tlsSettings.fingerprint; they now forward it, together with alpn."
```

---

### Task 8: End-to-end shaping check against a local TLS listener

The unit tests assert bytes from a synthesized hello. This asserts the bytes that actually leave the socket, so a future change to the connector cannot silently unshape the handshake.

**Files:**
- Modify: `crates/xray-transport/tests/utls_tls_shaping_tests.rs`

- [ ] **Step 1: Write the failing test**

Append inside the test module:

```rust
    #[tokio::test]
    async fn dialed_connections_send_the_shaped_hello() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use xray_routing::{Network, Target, TargetAddr};

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener must bind");
        let addr = listener.local_addr().expect("listener must report its address");

        let recorded = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a client must connect");
            let mut buffer = vec![0u8; 4096];
            let read = stream.read(&mut buffer).await.expect("the hello must arrive");
            buffer.truncate(read);
            buffer
        });

        let connector = xray_transport::TlsConnector::system().expect("system roots must load");
        let config = xray_transport::TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: true,
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
        };
        // The listener never replies, so the handshake fails; the bytes we care
        // about are already on the wire by then.
        let _ = connector
            .connect(
                &Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp),
                &config,
            )
            .await;

        let hello = recorded.await.expect("the recording task must finish");
        assert_eq!(
            cipher_suites(&hello).first().copied(),
            Some(CHROME_GREASE_CIPHER),
            "the hello on the wire must be shaped"
        );
        assert_eq!(alpn_protocols(&hello), vec!["h2", "http/1.1"]);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

If Tasks 4–5 are complete this test should pass immediately; run it first to confirm it is not passing for the wrong reason by temporarily setting `fingerprint: Some("unsafe".to_owned())` and checking that it fails, then restore `"chrome"`.

```bash
cargo test -p xray-transport --test utls_tls_shaping_tests dialed_connections_send_the_shaped_hello
```

Expected with `"unsafe"`: FAIL on the cipher-suite assertion. Expected with `"chrome"`: PASS.

- [ ] **Step 3: Run the whole workspace**

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 4: Run clippy and fmt**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add -A crates/xray-transport/tests/
git commit -m "test(transport): assert the shaped hello reaches the wire"
```

---

### Task 9: Oracle parity for the ALPN override

The shaping itself is already byte-verified: `rustls_reality_provider_matches_utls_xray_fingerprints_in_order` in `crates/xray-transport/tests/reality_rustls_tests.rs` compares our output against a uTLS oracle for every Xray fingerprint, and Tasks 2 and 3 are pure moves guarded by it. The one genuinely new shape is the `http/1.1` ALPN override, which no fixture covers yet.

**Files:**
- Modify: `tools/reality-oracle/clienthello_shape.go`
- Create: `tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn.json`
- Modify: `crates/xray-transport/tests/utls_tls_shaping_tests.rs`

- [ ] **Step 1: Add a websocket-ALPN mode to the Go oracle**

In `tools/reality-oracle/clienthello_shape.go`, add a flag beside the existing ones and apply Xray's override before emitting the shape:

```go
	websocketALPN := flag.Bool("websocket-alpn", false,
		"rebuild the hello with ALPN forced to http/1.1, as UConn.WebsocketHandshakeContext does")
```

After the `UConn` is built and `BuildHandshakeState()` has run, and before the shape is serialized:

```go
	if *websocketALPN {
		forced := []string{"http/1.1"}
		hasALPN := false
		for _, extension := range conn.Extensions {
			if alpn, ok := extension.(*utls.ALPNExtension); ok {
				hasALPN = true
				alpn.AlpnProtocols = forced
				break
			}
		}
		if !hasALPN {
			conn.Extensions = append(conn.Extensions, &utls.ALPNExtension{AlpnProtocols: forced})
		}
		if err := conn.BuildHandshakeState(); err != nil {
			return err
		}
	}
```

This mirrors `Xray-core/transport/internet/tls/tls.go:96-131` exactly, minus the ECH branch, which no supported profile reaches.

- [ ] **Step 2: Generate the fixture**

```bash
go run -tags reality_oracle_clienthello_shape ./tools/reality-oracle/clienthello_shape.go \
  -fingerprint chrome -websocket-alpn \
  > tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn.json
```

If the existing generator takes different flag names for the fingerprint, use those — read the `flag.` declarations at the top of the file first.

- [ ] **Step 3: Write the failing parity test**

Append to `crates/xray-transport/tests/utls_tls_shaping_tests.rs`, mirroring how `reality_rustls_tests.rs` decodes and compares a shape fixture:

```rust
    const WEBSOCKET_ALPN_SHAPE_JSON: &str =
        include_str!("../../../tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn.json");

    #[test]
    fn http11_override_matches_the_utls_oracle() {
        #[derive(serde::Deserialize)]
        struct ShapeFixture {
            alpn_protocols: Vec<String>,
        }

        let expected: ShapeFixture = serde_json::from_str(WEBSOCKET_ALPN_SHAPE_JSON)
            .expect("the websocket-ALPN shape fixture must decode");
        let hello = plain_tls_client_hello_bytes(&config("chrome", &["http/1.1"]))
            .expect("chrome ClientHello must be produced");

        assert_eq!(alpn_protocols(&hello), expected.alpn_protocols);
    }
```

Match the fixture's actual field name for the ALPN list — inspect the generated JSON and adjust `ShapeFixture` to it rather than assuming.

**Generate a second fixture for `android`, not just `chrome`.** A `chrome`-only fixture proves very little: Chrome's profile already declares `["h2", "http/1.1"]`, so the override merely narrows a list that was there. The `android` profile declares no ALPN extension at all, which means the override has to *insert* one — the case Xray handles with its `if !hasALPNExtension` append, and the case Task 4 had to add support for after a review found we silently emitted no ALPN there. Fixture both, and assert both, or this test passes without exercising the code path it exists to protect.

- [ ] **Step 4: Run the test**

```bash
cargo test -p xray-transport --test utls_tls_shaping_tests http11_override_matches_the_utls_oracle
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/reality-oracle/clienthello_shape.go \
        tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn.json \
        crates/xray-transport/tests/utls_tls_shaping_tests.rs
git commit -m "test(transport): oracle parity for the http/1.1 ALPN override

The shaping itself is already covered by the per-fingerprint oracle; the
WebsocketHandshakeContext ALPN rebuild was not."
```

---

### Task 10: Update the compatibility documentation

**Files:**
- Modify: `docs/config-compatibility.md:76-95`

- [ ] **Step 1: Replace the fingerprint and ALPN claims**

The document currently reads "TLS fingerprint shaping and non-empty custom ALPN lists are not supported." Replace that sentence with:

```markdown
`tlsSettings.fingerprint` selects the uTLS ClientHello shape, using the same
names Xray accepts. An absent value means `chrome`, matching Xray's own
default; `unsafe` disables shaping and sends rustls' own ClientHello. Unlike
`realitySettings.fingerprint`, no X25519 key share is required, so the
fingerprints REALITY rejects are usable here.

`tlsSettings.alpn` is accepted. It reaches the ClientHello only when it is
exactly `["http/1.1"]`, which mirrors Xray: uTLS takes ALPN from the
fingerprint profile and overwrites the configured list, except on the
`WebsocketHandshakeContext` path.
```

- [ ] **Step 2: Verify the surrounding text still reads correctly**

```bash
sed -n 70,100p docs/config-compatibility.md
```

Expected: no leftover claim that fingerprints are unsupported.

- [ ] **Step 3: Commit**

```bash
git add docs/config-compatibility.md
git commit -m "docs: document TLS fingerprint and ALPN support"
```

---

## Verification

Before declaring this plan complete:

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

All three must pass. Additionally confirm the REALITY ClientHello byte assertions are untouched — they are the regression net for Tasks 2 and 3:

```bash
cargo test -p xray-transport --test reality_clienthello_tests
cargo test -p xray-transport --test reality_rustls_tests
```

The live interop check (`cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored`) requires a Go toolchain and the `Xray-core/` checkout; run it if available, since it exercises a real TLS handshake against a real Xray server with the shaped hello.
