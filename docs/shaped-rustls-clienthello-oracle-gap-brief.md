# shaped-rustls ClientHello Parity Gap Brief

This note is for the agent working in `aimalygin/shaped-rustls`, branch
`xray/rustls-0.23.40`.

The consumer project is `xray-rust`. It uses the fork through rustls-compatible
APIs and currently targets:

- `rustls`: `0.23.40`, patched to `aimalygin/shaped-rustls`
- `shaped-rustls` branch: `xray/rustls-0.23.40`
- currently tested shaped-rustls commit in `xray-rust`: `11d5691f1284f15f985167bd1ba03ddc5f304735`
- `tokio`: `1.52.3`
- `tokio-rustls`: `0.26.4`

The goal is still full xray-core/uTLS ClientHello shape compatibility through
generic rustls shaping primitives. The fork must not contain xray-specific
fingerprint registries or runtime Go/uTLS dependencies.

## Current Oracle Workflow

`xray-rust` has a structural Go uTLS oracle for `hellochrome_100`.

Check the Go-side fixture:

```sh
go run -tags reality_oracle_clienthello_shape ./tools/reality-oracle/clienthello_shape.go \
  -fingerprint hellochrome_100 \
  -check tests/fixtures/reality/clienthello_shape_hellochrome_100.json
```

Run the Rust-side comparison:

```sh
cargo test -p xray-transport --test reality_rustls_tests \
  rustls_reality_provider_matches_utls_hellochrome_100_shape_oracle -- --ignored
```

Normal transport tests should remain green:

```sh
cargo test -p xray-transport --test reality_rustls_tests
cargo test -p xray-transport
```

## Current Status After shaped-rustls `11d5691f`

The latest fork update closed the original large blockers for
`hellochrome_100`. `xray-rust` now exercises these APIs in
`crates/xray-transport/src/reality_rustls.rs`.

The current Rust-generated `hellochrome_100` ClientHello already matches the
Go uTLS structural oracle for:

- handshake length: `512`
- advertised cipher suites, including GREASE and advertise-only legacy/static
  RSA suites
- `supported_versions`: GREASE, TLS 1.3, TLS 1.2
- `supported_groups`: GREASE, X25519, P-256, P-384
- key shares: GREASE plus fixed X25519
- signature algorithm ordering
- ALPN: `h2`, `http/1.1`
- certificate compression: Brotli
- ALPS/application settings extension `0x4469` with `h2`

The ignored oracle test is still red, but the mismatch is now narrow and
actionable.

## Remaining hellochrome_100 Mismatch

Expected Go uTLS extension order:

```text
GREASE,
0x0000 server_name,
0x0017 extended_master_secret,
0xff01 renegotiation_info,
0x000a supported_groups,
0x000b ec_point_formats,
0x0023 session_ticket,
0x0010 alpn,
0x0005 status_request,
0x000d signature_algorithms,
0x0012 signed_certificate_timestamp,
0x0033 key_share,
0x002d psk_key_exchange_modes,
0x002b supported_versions,
0x001b compress_certificate,
0x4469 application_settings,
GREASE,
0x0015 padding
```

Current Rust extension order:

```text
GREASE,
0x0000 server_name,
0x0017 extended_master_secret,
0x000a supported_groups,
0x000b ec_point_formats,
0x0010 alpn,
0x0005 status_request,
0x000d signature_algorithms,
0x0033 key_share,
0x002d psk_key_exchange_modes,
0x002b supported_versions,
0x001b compress_certificate,
0x4469 application_settings,
0x0015 padding
```

Missing items:

- `0xff01` `renegotiation_info`, expected extension length `1`
- `0x0023` `session_ticket`, expected extension length `0`
- `0x0012` `signed_certificate_timestamp`, expected extension length `0`
- a second GREASE extension after ALPS and before padding, expected extension
  length `1`

Because those 18 bytes of extension overhead/body are missing, padding is
currently `222` bytes. The uTLS fixture expects padding length `204`. The total
handshake length is already `512`, so padding calculation itself is probably
correct; it should naturally become `204` once the missing extensions are
emitted before padding.

## Required Work In shaped-rustls

### 1. Force known ClientHello extensions from ClientHelloPlan

`ClientHelloRawExtension` is not suitable for this work because it correctly
rejects known extension IDs. The missing extensions are known TLS extension
types and should be handled through structured/profile-safe controls.

Add generic shaping controls that can force these known extensions:

- `renegotiation_info` (`0xff01`)
- `session_ticket` (`0x0023`)
- `signed_certificate_timestamp` / SCT (`0x0012`)

For `hellochrome_100`, the desired wire shapes are:

- `renegotiation_info`: extension body `00`, length `1`
- `session_ticket`: empty extension body, length `0`
- `SCT`: empty extension body, length `0`

Implementation notes:

- `ClientExtensions` already has internal fields for `renegotiation_info` and
  `session_ticket`.
- `renegotiation_info` can likely be represented internally with an empty
  `PayloadU8`, because that serializes to body `00`.
- `session_ticket` can likely use `ClientSessionTicket::Request`.
- SCT is a known `ExtensionType`, but `ClientExtensions` currently does not
  expose a dedicated field for emitting it in ClientHello. Add a small
  structured field/control rather than abusing unknown raw extensions.
- Forcing an empty `session_ticket` extension must not enable ticket storage or
  resumption behavior by itself. It is a wire-shaping control, not a policy
  change.
- Keep existing default rustls behavior unchanged when no shaping plan requests
  these extensions.

Suggested API shape:

```rust
pub struct ClientHelloForcedExtensions { ... }

impl ClientHelloForcedExtensions {
    pub fn new() -> Self;
    pub fn with_renegotiation_info_empty(self) -> Self;
    pub fn with_session_ticket_request(self) -> Self;
    pub fn with_signed_certificate_timestamp_empty(self) -> Self;
}

impl ClientHelloPlan {
    pub fn with_forced_extensions(self, extensions: ClientHelloForcedExtensions) -> Self;
}
```

The exact names can differ. The important part is that the controls are
generic, profile-driven, and structured around known extension semantics.

Acceptance criteria:

- xray-rust can request `0xff01`, `0x0023`, and `0x0012` through
  `ClientHelloPlan`.
- The extensions participate in `ClientHelloExtensionOrder`.
- The serialized lengths match uTLS: `1`, `0`, and `0`.
- Default clients without a plan do not gain these extensions.

### 2. Support multiple GREASE extensions with independent payload length

Current `ClientHelloGreasePlan` can insert one GREASE extension into the
ClientHello extension list, and that extension is serialized with an empty body.
`hellochrome_100` needs two GREASE extensions:

- first extension at position `0`, length `0`
- second extension after ALPS/application_settings and before padding, length
  `1`

The existing `ClientHelloRawExtension` path rejects GREASE values, so this also
needs a structured GREASE API.

Suggested API shape:

```rust
pub struct ClientHelloGreaseExtension {
    pub value: u16,
    pub position: usize,
    pub payload: Vec<u8>,
}

impl ClientHelloGreasePlan {
    pub fn with_extension(mut self, extension: ClientHelloGreaseExtension) -> Self;
}
```

Design requirements:

- Allow more than one GREASE extension entry.
- Allow each GREASE extension to choose its own RFC 8701 GREASE value.
- Allow each GREASE extension to choose its own payload bytes.
- Reject duplicate extension type values in the same ClientHello.
- Preserve the current simpler API if possible for compatibility.
- Make insertion positions deterministic and well documented when a custom
  extension order is also active.

For the current structural oracle, only extension position and payload length
are compared. For future byte-level parity, the payload bytes should be
profile-controlled as well.

Acceptance criteria:

- xray-rust can emit the first GREASE extension with length `0`.
- xray-rust can emit the second GREASE extension after ALPS and before padding
  with length `1`.
- Both GREASE extensions are visible in final extension ordering.
- Existing GREASE support for cipher suites, supported versions, supported
  groups, and key shares remains unchanged.

### 3. Preserve exact extension-order validation

The stricter `ClientHelloExtensionOrder` validation in `11d5691f` is useful:
the order must contain every non-final emitted extension exactly once. Keep that
behavior.

When adding forced known extensions and multiple GREASE extensions:

- forced known extensions should be part of the required custom-order set;
- GREASE extension insertions should remain separate from the custom-order set,
  as they are today;
- padding must remain ordered after all profile-shaped extensions for
  `hellochrome_100`;
- ECH/PSK final-position semantics must not regress.

Acceptance criteria:

- With the `hellochrome_100` plan, the final extension order can exactly match
  the Go uTLS oracle.
- Incorrect custom orders still fail fast with a clear error.

### 4. Do not change padding logic yet

Do not special-case `hellochrome_100` padding.

`ClientHelloPaddingPlan::pad_to_handshake_size(512)` already produces total
handshake length `512`. The only reason the observed padding length is `222`
instead of `204` is that three known extensions and the second GREASE extension
are missing.

Acceptance criteria:

- After the missing extensions are emitted before padding, padding length
  becomes `204` without a special-case padding formula.

## Suggested shaped-rustls Tests

Add focused tests in shaped-rustls before relying on the xray-rust integration
oracle.

Recommended unit tests:

- A plan can force empty `renegotiation_info`, empty `session_ticket`, and empty
  SCT into ClientHello.
- Forced known extensions are included in custom extension-order validation.
- A plan can emit two GREASE extensions with different GREASE values and
  different payload lengths.
- Duplicate GREASE extension type values are rejected.
- Padding-to-handshake-size is calculated after forced known extensions and
  both GREASE extensions.
- Default rustls ClientHello output is unchanged when no shaping plan is
  provided.
- Forcing `session_ticket` as a wire-shaping extension does not enable actual
  resumption/ticket persistence.

Recommended integration check from `xray-rust`:

```sh
cargo test -p xray-transport --test reality_rustls_tests \
  rustls_reality_provider_matches_utls_hellochrome_100_shape_oracle -- --ignored
```

The target is exact equality with
`tests/fixtures/reality/clienthello_shape_hellochrome_100.json`.

## What Is Already Done

Do not spend time reimplementing these unless tests show a regression:

- advertise-only cipher suites
- GREASE in cipher suites
- GREASE in supported_versions
- GREASE in supported_groups
- GREASE key share
- explicit supported versions
- explicit supported groups
- explicit key share plan
- explicit signature algorithm order
- explicit ALPN list
- Brotli certificate compression advertisement
- raw unknown ALPS/application_settings extension
- padding-to-handshake-size
- fixed X25519 key share for X25519-only profiles
- GREASE ECH that does not force TLS 1.3-only supported_versions

## Still Out Of Scope For This Immediate Task

These are still important for later profiles, but they are not required to make
`hellochrome_100` pass:

- fixed classical X25519 inside hybrid `X25519MLKEM768` key shares for
  Chrome 131-style profiles
- full `hellochrome_120+` ECH fixture comparison
- xray-core fingerprint registry
- randomized profile selection
- runtime Go/uTLS dependency

