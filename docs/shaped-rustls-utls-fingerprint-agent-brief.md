# shaped-rustls uTLS Fingerprint Implementation Brief

## Purpose

This document is a handoff brief for implementing full xray-core/uTLS-compatible
TLS ClientHello fingerprints in Rust.

The current `xray-rust` project can parse and accept the same REALITY
fingerprint names as xray-core, but it does not yet generate wire-level
ClientHello messages that match every uTLS profile. The next work belongs
primarily in the `shaped-rustls` fork, because the missing behavior is inside
rustls ClientHello construction.

The implementation must not rely on a separate Go process, cgo, or embedded Go
code. The goal is a native Rust path that remains compatible with `tokio-rustls`
and keeps runtime memory/performance overhead low.

## Current State

`xray-rust` currently uses:

- `rustls 0.23.40`
- `tokio 1.52.3`
- `tokio-rustls 0.26.4`
- `shaped-rustls` via:

```toml
[patch.crates-io]
rustls = { git = "https://github.com/aimalygin/shaped-rustls", branch = "xray/rustls-0.23.40" }
```

`shaped-rustls` currently exposes a ClientHello customization API:

- `ClientHelloCustomizer`
- `ClientHelloPlan`
- fixed ClientHello random
- fixed legacy session id
- fixed X25519 key share
- ClientHello capture callback
- explicit extension ordering

This is enough for the basic REALITY handshake mechanics, but not enough for
full browser/uTLS impersonation.

`xray-rust` also has a small `xray-utls` crate that contains the xray-core
REALITY fingerprint registry and validation helpers. It accepts xray-core names
such as `chrome`, `firefox`, `hellochrome_131`, `hellosafari_16_0`,
`randomizednoalpn`, etc. This is name-level compatibility only.

## xray-core Reference Behavior

xray-core uses Go uTLS for ClientHello shaping. The reference points are:

- `transport/internet/tls/tls.go::GetFingerprint`
- `transport/internet/tls/tls.go::PresetFingerprints`
- `transport/internet/tls/tls.go::ModernFingerprints`
- `transport/internet/tls/tls.go::OtherFingerprints`
- `infra/conf/transport_internet.go` REALITY fingerprint validation

At the time this brief was written, the inspected xray-core revision was:

```text
153468dc86e8d2cdd5e1908f68c17faf2d0b4b47
```

xray-core REALITY rejects `unsafe` and `hellogolang`, and rejects unknown
fingerprints. Empty fingerprint resolves to Chrome auto behavior.

## What "Full Fingerprint Support" Means

Supporting a fingerprint means generating a TLS ClientHello whose relevant
wire-level structure matches the corresponding uTLS profile closely enough for
REALITY/uTLS compatibility.

It is not enough to accept the string `firefox` or `hellochrome_131`. The
generated ClientHello must match the browser profile in fields such as:

- cipher suite list and ordering
- TLS supported versions
- extension set
- extension ordering
- supported groups and ordering
- key share groups and ordering
- GREASE values and GREASE positions
- signature algorithms and ordering
- ALPN presence and protocol ordering
- certificate compression extension behavior
- PSK and PSK key exchange mode behavior
- padding extension behavior
- legacy session id behavior
- SNI behavior
- random/session id/key share interaction required by REALITY

## Missing shaped-rustls Capabilities

The following knobs need to be added to `ClientHelloPlan` or an adjacent
profile API inside `shaped-rustls`.

### Cipher Suites

Add control over the exact cipher suite list and order emitted in ClientHello.

rustls currently derives this from `CryptoProvider`. uTLS profiles require
profile-specific ordering, including TLS 1.3 suites, legacy TLS 1.2 suites, and
possibly GREASE entries.

The implementation must still reject suites that rustls cannot actually support
for the configured provider/protocol version.

### Supported Versions

Add explicit control over `supported_versions`.

REALITY requires TLS 1.3-capable ClientHellos. Some legacy profiles may include
TLS 1.2 in supported versions or legacy version fields, and the emitted shape
must match the target uTLS profile.

### Supported Groups

Add explicit control over the `supported_groups` extension order.

This is critical for Chrome, Firefox, Safari, Android, and PQ/hybrid profiles.
Chrome PQ profiles may involve `X25519MLKEM768` style groups.

### Key Shares

Current support can fix one X25519 key share. Full uTLS support needs more:

- choose the first key share group
- emit multiple key shares when the profile requires it
- emit GREASE key share entries
- support hybrid/PQ key shares where rustls/provider support exists
- keep fixed X25519 private key material for REALITY auth key derivation
- expose enough observer/capture hooks to validate emitted public keys

The REALITY path must still be able to derive the shared secret from the same
X25519 private key represented in the generated ClientHello.

### Signature Algorithms

Add explicit control over the `signature_algorithms` extension.

Different browser profiles use different lists and different ordering. This is
visible in ClientHello fingerprints and should be part of the profile spec.

### Extension Set

Current `ClientHelloExtensionOrder` only controls ordering for extensions that
rustls already emits. Full uTLS support needs control over whether extensions
exist at all.

Likely required extension controls include:

- `server_name`
- `status_request`
- `supported_groups`
- `ec_point_formats`
- `signature_algorithms`
- `alpn`
- `signed_certificate_timestamp`
- `extended_master_secret`
- `session_ticket`
- `supported_versions`
- `psk_key_exchange_modes`
- `key_share`
- `compress_certificate`
- `application_settings` / ALPS if supported
- `padding`
- GREASE extensions
- raw/unknown extension payloads where needed

Where possible, prefer structured APIs over raw bytes. Raw extension support is
still useful as an escape hatch for profile parity, but it should be bounded and
validated.

### GREASE

Add a GREASE policy layer.

Chrome-like profiles use GREASE in several places:

- cipher suites
- extensions
- supported groups
- key shares
- possibly supported versions-like slots depending on the profile

The profile API should express GREASE placement and value generation. Tests
should not assume a single fixed GREASE value unless the profile explicitly
does so; they should validate GREASE shape and position.

### ALPN

rustls already exposes `ClientConfig.alpn_protocols`, but profile-level support
should make ALPN behavior explicit.

Profiles may require:

- no ALPN
- `h2`, `http/1.1`
- `http/1.1` only
- browser-specific ordering

REALITY configs may not always use application ALPN, so the profile API should
be able to suppress ALPN when the xray-core/uTLS behavior does.

### Padding

Add control over ClientHello padding extension behavior.

Some browser profiles use padding to influence ClientHello length. Padding must
be computed after other extensions are known, so this likely needs a late
ClientHello construction hook rather than a static byte list.

### Certificate Compression

rustls may emit certificate compression support depending on config/features.
uTLS browser profiles differ here. The profile API should allow enabling,
disabling, and ordering certificate compression algorithms when rustls supports
them.

## Proposed API Shape

Keep `tokio-rustls` compatibility by preserving the standard rustls
`ClientConfig` and `ClientConnection` flow. The shaping should remain inside
rustls ClientHello construction.

One possible direction:

```rust
pub struct ClientHelloPlan {
    pub random: Option<[u8; 32]>,
    pub session_id: Option<ClientHelloSessionId>,
    pub fixed_x25519: Option<FixedX25519KeyShare>,
    pub capture: Option<Arc<dyn CapturesClientHello>>,
    pub extension_order: Option<ClientHelloExtensionOrder>,
    pub cipher_suites: Option<ClientHelloCipherSuites>,
    pub supported_versions: Option<ClientHelloSupportedVersions>,
    pub supported_groups: Option<ClientHelloSupportedGroups>,
    pub signature_algorithms: Option<ClientHelloSignatureAlgorithms>,
    pub key_share_plan: Option<ClientHelloKeySharePlan>,
    pub extensions: Option<ClientHelloExtensionPlan>,
    pub grease: Option<ClientHelloGreasePlan>,
    pub padding: Option<ClientHelloPaddingPlan>,
}
```

The exact types can differ, but the design should keep these principles:

- use structured enums/newtypes for known TLS values
- validate duplicates and unsupported values early
- avoid heap allocations in the hot path where static slices are enough
- keep raw extension support isolated and explicit
- do not break existing rustls behavior when no custom plan is supplied
- do not require `tokio-rustls` changes

## Profile Registry

After the low-level knobs exist, add profile specs that map xray-core
fingerprint names to concrete ClientHello plans.

This mapping can live in `xray-utls` or a separate profile crate. The low-level
rustls fork should not know about xray-core names directly unless we decide to
make `shaped-rustls` a product-specific fork rather than a generally useful
library.

Recommended split:

- `shaped-rustls`: generic ClientHello shaping primitives
- `xray-utls`: xray-core/uTLS fingerprint registry and profile specs
- `xray-rust`: config parsing, REALITY setup, and passing the selected profile
  into `ClientConfig.client_hello_customizer`

## Implementation Order

Start with Chrome-like profiles because REALITY deployments most commonly use
`chrome` and `hellochrome_*`.

Recommended phases:

1. Add cipher suite, supported group, signature algorithm, and supported version
   controls to `shaped-rustls`.
2. Add structured extension set controls, not only extension ordering.
3. Add GREASE placement support.
4. Add key share plan support beyond single fixed X25519.
5. Add padding and certificate compression controls.
6. Build `hellochrome_120`, `hellochrome_131`, and `hellochrome_133` profile
   specs.
7. Add Firefox profiles.
8. Add Safari/iOS/Edge/Android/360/QQ profiles.
9. Add randomized profile behavior compatible with xray-core constraints.

## Testing Strategy

Testing should use Go uTLS as an oracle, but not at runtime.

Recommended approach:

1. Add a small oracle generator that uses xray-core's pinned uTLS version to
   produce ClientHello bytes for each fingerprint.
2. Store generated fixtures or normalized structural snapshots.
3. Parse both Go uTLS and Rust-generated ClientHello bytes into a structural
   representation.
4. Compare fields that matter for fingerprint compatibility:
   - cipher suites
   - extension order
   - extension presence
   - supported versions
   - supported groups
   - key share groups and lengths
   - signature algorithms
   - ALPN
   - GREASE positions
   - padding length/shape
5. Avoid brittle tests for values that are intentionally randomized, especially
   GREASE values and ClientHello random.
6. Keep separate REALITY tests that verify the patched session id and auth key
   derivation still use the emitted X25519 key share correctly.

The Rust test suite should not depend on network I/O for profile shape tests.
It should generate ClientHello bytes locally and compare parsed structures.

## Benchmarking Requirements

The project cares about RAM and performance. Add benchmarks before and after
the shaping changes for:

- ClientConfig construction where profiles are applied
- ClientConnection creation
- first ClientHello generation
- memory allocations during ClientHello generation
- REALITY preparation path

Use release-mode benchmarks. The goal is not zero overhead, but the overhead
should be bounded, measured, and mostly paid during setup rather than per byte
of proxied traffic.

## Important Constraints

- No Go subprocess in production.
- No cgo/Go code embedded in Rust.
- Keep `tokio-rustls` compatibility.
- Preserve normal rustls behavior when no ClientHello customizer is configured.
- Prefer static profile data and slices over runtime maps where possible.
- Do not silently accept a profile whose required features cannot be emitted.
- Fail early with clear errors when a profile requires unsupported TLS features.
- Keep REALITY-specific fixed X25519 handling compatible with auth key
  derivation.

## Current Limitation in xray-rust

`xray-rust` now accepts the xray-core REALITY fingerprint names, but until the
fork gains the knobs above, most profiles still generate the same rustls-shaped
ClientHello.

That is useful as a configuration compatibility milestone, but it is not yet
wire-level uTLS compatibility.

