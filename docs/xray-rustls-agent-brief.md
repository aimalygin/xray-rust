# shaped-rustls Agent Brief

## Purpose

This document defines the intended shape of a maintained `rustls` fork used by
`xray-rust`.

The fork repository name is `shaped-rustls`.

Important naming rule: the repository may be named `shaped-rustls`, but the Cargo
package and library crate inside the fork must remain named `rustls`.

The goal is to support Xray-core compatible REALITY/uTLS-style ClientHello
behavior in Rust without:

- running a separate helper process,
- embedding Go code,
- depending on Go uTLS,
- switching the whole transport stack to BoringSSL.

The fork must provide a small, generic ClientHello customization surface inside
`rustls`. `xray-rust` will use that surface to implement Xray-core fingerprint
profiles and REALITY handshake behavior.

This repository is not an Xray implementation. It is a TLS customization layer.

## Desired End State

`xray-rust` should be able to build a TLS connection through `tokio-rustls`
while still controlling the exact ClientHello shape required by Xray-core
REALITY fingerprints.

The intended dependency graph is:

```text
xray-rust
  |-- rustls        -> this fork
  `-- tokio-rustls
       `-- rustls   -> this same fork
```

The fork must remain a drop-in replacement for upstream `rustls`, so
`tokio-rustls` can keep using its normal public API.

## Non-Negotiable Constraints

- The package name must remain `rustls`.
- The repository/fork name should be `shaped-rustls`.
- The public API used by `tokio-rustls 0.26.4` must remain compatible.
- Default behavior must match upstream `rustls` when no customizer is installed.
- The fork must not introduce Xray-specific concepts into the `rustls` API.
- The patch surface should be as small as possible.
- The code should be easy to rebase onto upstream `rustls` security releases.
- The first maintained line should start from upstream `rustls 0.23.40` and keep
  tracking the `0.23.x` line.
- Any custom behavior must be opt-in.

## Baseline Versions

As of 2026-06-17, use these concrete baseline versions:

```toml
tokio = "1.52.3"
tokio-rustls = "0.26.4"
rustls = "0.23.40"
```

`tokio-rustls 0.26.4` depends on `rustls 0.23.x` and has a minimum dependency
of `rustls 0.23.27`. The fork should start from the current stable compatible
release, `rustls 0.23.40`.

Do not use `rustls 0.24.0-dev.0` as the baseline. It is a development
pre-release, and `tokio-rustls 0.26.4` targets the `rustls 0.23.x` API line.

`xray-rust` should consume the fork through Cargo patching:

```toml
[patch.crates-io]
rustls = { git = "https://github.com/<org>/shaped-rustls", branch = "xray/rustls-0.23.40" }
```

For the current repository, use:

```toml
[patch.crates-io]
rustls = { git = "https://github.com/aimalygin/shaped-rustls", branch = "xray/rustls-0.23.40" }
```

Do not rename the Cargo package or library crate to `shaped-rustls`. That would
produce different Rust types from the ones expected by `tokio-rustls`.

## What Belongs In This Fork

This fork should expose generic TLS ClientHello customization hooks.

It may include support for controlling or observing:

- ClientHello random bytes.
- Session ID bytes.
- Key share generation, initially X25519.
- Key share private material for transcript-continuity use cases.
- Cipher suite ordering.
- Supported TLS versions.
- Supported groups.
- Signature algorithms.
- ALPN protocol list and ordering.
- Extension ordering.
- GREASE values and GREASE placement where applicable.
- Padding extension behavior.
- Certificate compression extension presence and ordering, if needed later.
- Raw ClientHello bytes before they are written to the transport.
- A way to ensure the exact emitted ClientHello is the one used by the TLS
  transcript.

The API should be generic enough to support browser-like profiles, but it should
not encode Xray-core fingerprint names directly.

## What Must Stay Outside This Fork

The following belong in `xray-rust`, not in this `rustls` fork:

- Xray JSON config parsing.
- VLESS.
- REALITY config fields such as `publicKey`, `shortId`, `serverName`,
  `spiderX`, or `flow`.
- Xray outbound and inbound tags.
- Xray routing rules.
- geosite or geoip handling.
- The Xray-core fingerprint registry.
- Mapping strings such as `hellochrome_120`, `hellofirefox_120`,
  `randomizednoalpn`, or `safari` to concrete ClientHello profiles.

This fork should provide the mechanism. `xray-rust` should provide the policy.

## Why This Exists

Xray-core uses Go uTLS for REALITY client fingerprints. In Xray-core, a
fingerprint string selects a uTLS `ClientHelloID`. During REALITY setup, Xray
builds a uTLS handshake state, mutates the ClientHello SessionId with REALITY
authentication data, and then continues the same TLS handshake.

For compatibility, `xray-rust` needs more than ordinary TLS configuration. It
needs controlled ClientHello construction and exact transcript continuity.

Plain `rustls` is excellent as a TLS implementation, but it is intentionally not
a uTLS-style ClientHello impersonation library. This fork exists to add a narrow
extension point while preserving the rest of the `rustls` state machine.

## Why Not BoringSSL

BoringSSL-based approaches can shape some ClientHello properties, such as cipher
lists, curves, GREASE, and extension permutation. This is useful for approximate
fingerprinting, but it does not naturally expose the exact REALITY hooks needed
by Xray-core:

- deterministic ClientHello random,
- patchable SessionId,
- controlled key share private/public material,
- raw ClientHello capture,
- transcript continuity after patching.

BoringSSL is also a larger dependency and changes the memory/build profile of
the project. C/C++ dependencies may be acceptable in general, but the preferred
path for `xray-rust` is a Rust-first implementation that keeps the current
`rustls`/`tokio-rustls` architecture.

## Why Not craftls Directly

`craftls` is a useful reference because it demonstrates ClientHello
customization inside a `rustls` fork. However, it should not be used directly:

- it is based on `rustls 0.22`,
- it appears stale,
- it has only a small set of predefined profiles,
- it does not expose the full REALITY hooks required by `xray-rust`,
- `xray-rust` should use `tokio 1.52.3`, `tokio-rustls 0.26.4`, and
  `rustls 0.23.40` for this integration line.

This fork can learn from the craftls approach, but it should be maintained as a
fresh, minimal fork of current upstream `rustls 0.23.40`.

## Why Not A Full Custom TLS Engine

Projects such as `cfal/shoes` show that a pure Rust REALITY implementation can
be built with manual TLS 1.3 message construction and a custom state machine.
That approach is useful as a reference for REALITY details, especially raw
ClientHello handling and transcript usage.

However, a full custom TLS 1.3 engine has a higher security and maintenance
cost. The preferred design is to reuse `rustls` for the TLS state machine and
only add the minimal hooks required for ClientHello customization.

## Tokio Compatibility

`tokio-rustls` is an async adapter between `rustls` and Tokio streams. It wraps
`rustls::ClientConnection` and `rustls::ServerConnection` in types that
implement Tokio `AsyncRead` and `AsyncWrite`.

This fork should not require a `tokio-rustls` fork.

That means:

- keep the crate name `rustls`,
- keep the public types expected by `tokio-rustls`,
- keep features expected by the downstream dependency graph,
- add custom behavior through optional fields or extension points on existing
  config/connection paths.

The normal downstream call should continue to work:

```rust
let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
let stream = connector.connect(server_name, tcp_stream).await?;
```

The difference is that `client_config` may contain an optional ClientHello
customizer.

## Configuration Flow

The customization flow should look like this:

```text
Xray JSON config
  |
  v
xray-config parses fingerprint, REALITY public key, short id, server name, ALPN
  |
  v
xray-transport builds a rustls::ClientConfig
  |
  v
ClientConfig contains an optional generic ClientHello customizer
  |
  v
tokio-rustls receives Arc<rustls::ClientConfig>
  |
  v
rustls::ClientConnection::new builds a per-connection ClientHello plan
  |
  v
patched rustls emits the planned ClientHello and continues the TLS transcript
```

Tokio itself should not know about fingerprints, REALITY, or ClientHello plans.

## Per-Connection Planning

The custom ClientHello must be planned per connection, not once per
`ClientConfig`.

Static configuration may include:

- selected fingerprint name,
- server public key,
- short id,
- target SNI,
- ALPN policy,
- selected profile family.

Per-connection values include:

- ClientHello random,
- X25519 private key,
- X25519 public key,
- REALITY encrypted SessionId,
- GREASE values,
- randomized profile selection,
- extension permutation,
- raw ClientHello capture.

Therefore, `ClientConfig` should hold a provider/factory, not a finished
ClientHello.

## Suggested API Shape

Exact names are not fixed, but the design should look conceptually like this:

```rust
pub trait ClientHelloCustomizer: Send + Sync {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, Error>;
}
```

`None` means use upstream `rustls` behavior.

`ClientHelloContext` should contain generic information available at handshake
construction time, such as:

- server name,
- ALPN from `ClientConfig`,
- supported protocol versions,
- crypto provider information if needed.

`ClientHelloPlan` should describe generic TLS details, such as:

- random,
- session id,
- cipher suites,
- supported versions,
- supported groups,
- signature algorithms,
- key shares,
- extension order,
- extension payload overrides where needed,
- optional callback for raw ClientHello capture.

The plan should not contain Xray-specific fields.

## REALITY Requirements From The Consumer Side

The fork should be able to support this downstream sequence:

1. `xray-rust` selects a fingerprint profile.
2. `xray-rust` generates or requests a ClientHello plan.
3. The plan fixes ClientHello random and X25519 key share material.
4. `xray-rust` derives the REALITY auth key from the local X25519 private key
   and server public key.
5. `xray-rust` constructs and encrypts the REALITY SessionId.
6. The fork emits a ClientHello containing that encrypted SessionId.
7. The exact emitted ClientHello bytes are captured.
8. The TLS handshake continues using those exact bytes in the transcript.

The fork does not need to understand REALITY. It only needs to provide enough
mechanism for `xray-rust` to do this safely.

## Fingerprint Compatibility Target

The downstream target is Xray-core's supported REALITY fingerprint behavior.

Xray-core maps fingerprint strings to uTLS `ClientHelloID` values. The
downstream `xray-rust` profile registry should eventually cover all names that
Xray-core accepts for REALITY, excluding values that Xray-core itself rejects in
REALITY mode.

At the time of this design, the important profile families include:

- Chrome profiles such as `chrome`, `hellochrome_120`, `hellochrome_131`.
- Firefox profiles such as `firefox`, `hellofirefox_120`.
- Safari and iOS profiles.
- Android and Edge profiles.
- Randomized profiles.
- No-ALPN randomized variants.
- Legacy uTLS profile names where Xray-core still accepts them.

The profile registry belongs in `xray-rust`. The fork should only make these
profiles possible to express.

## Implementation Principles

Keep the patch boring.

Prefer:

- optional fields,
- small internal hooks,
- narrow customization structs,
- default paths unchanged,
- low allocation overhead,
- per-connection planning,
- tests around byte-level behavior.

Avoid:

- broad handshake rewrites,
- global mutable state,
- Xray-specific naming,
- changing default ClientHello behavior,
- adding heavy dependencies,
- forking `tokio-rustls`,
- changing public APIs unrelated to ClientHello customization.

## Memory And Performance Expectations

`xray-rust` is performance and memory sensitive. The fork must avoid unnecessary
runtime cost on the default path.

Requirements:

- No measurable overhead when no customizer is installed.
- No large per-connection allocations beyond what is required for the planned
  ClientHello.
- Per-connection randomization should be cheap.
- Raw ClientHello capture should be opt-in.
- Any extra profile data should be static or shared where possible.

The customization layer should not cause a broad RAM regression compared with
plain `rustls`.

## Security Expectations

This fork modifies TLS handshake internals, so security discipline matters.

Rules:

- Keep upstream security fixes easy to merge.
- Do not weaken certificate verification.
- Do not change default cipher suite behavior unless a custom plan explicitly
  requests it.
- Do not silently fall back from a requested custom plan to a different
  ClientHello.
- Return hard errors for unsupported custom plans.
- Avoid unsafe code unless upstream already requires it.
- Preserve transcript correctness.

## Testing Requirements

The test suite should include:

1. Full upstream `rustls` tests.
2. A smoke test proving `tokio-rustls` works with this fork.
3. Regression tests proving default ClientHello behavior is unchanged without a
   customizer.
4. Tests for fixed ClientHello random.
5. Tests for fixed SessionId.
6. Tests for fixed X25519 key share private material producing the expected
   public key.
7. Tests for extension ordering.
8. Tests for raw ClientHello capture.
9. Tests proving the captured ClientHello is the one used in the transcript.
10. Negative tests for unsupported or internally inconsistent plans.

Downstream `xray-rust` should add:

- Xray-core/uTLS byte fixtures,
- REALITY interop tests,
- config parser tests for accepted and rejected fingerprint names,
- runtime tests through `tokio-rustls`.

## Maintenance Policy

Use a branch per upstream baseline:

```text
xray/rustls-0.23.40
```

Maintenance flow:

1. Track upstream `rustls 0.23.x`, starting from `rustls 0.23.40`.
2. Keep custom patches small and reviewable.
3. When upstream releases a security update, merge or rebase promptly.
4. Run upstream tests.
5. Run custom ClientHello tests.
6. Run downstream `xray-rust` integration tests.
7. Document any conflict caused by upstream handshake changes.

Do not let this fork drift into an unrelated TLS implementation.

## First Milestone

Milestone 1 should prove that the architecture works without implementing the
full Xray fingerprint set.

Tasks:

- Fork upstream `rustls 0.23.40`.
- Keep `package.name = "rustls"`.
- Add a no-op optional `ClientHelloCustomizer` to `ClientConfig`.
- Wire the customizer into the client handshake path.
- Prove default behavior is unchanged when no customizer is installed.
- Add one customizer test that fixes ClientHello random.
- Add one customizer test that fixes SessionId.
- Add one customizer test that captures raw ClientHello bytes.
- Prove `tokio-rustls` compiles and performs a basic client connection using
  the fork.

Do not implement Xray-specific profile names in milestone 1.

## Second Milestone

Milestone 2 should prove that the hook surface is sufficient for REALITY.

Tasks:

- Add fixed X25519 key share support.
- Expose enough key share material for downstream REALITY auth derivation.
- Ensure the emitted ClientHello is the transcript ClientHello.
- Add tests for transcript continuity.
- Add tests for extension order customization.
- Add tests for GREASE placeholders if required by the selected first profile.

The first downstream profile should be a single Chrome-like profile, enough to
replace the current `chrome`-only behavior in `xray-rust`.

## Third Milestone

Milestone 3 should expand downstream compatibility.

Tasks:

- Keep fork API stable.
- Add missing generic hooks only when required by real Xray-core profiles.
- Build the Xray/uTLS profile registry in `xray-rust`.
- Add byte-level fixtures against Xray-core or Go uTLS output.
- Add REALITY interop tests.

The fork should still avoid knowing Xray fingerprint names.

## Useful References

- Upstream rustls: https://github.com/rustls/rustls
- tokio-rustls: https://github.com/rustls/tokio-rustls
- Xray-core: https://github.com/XTLS/Xray-core
- Go uTLS: https://github.com/refraction-networking/utls
- craftls reference: https://github.com/3andne/craftls
- shoes reference: https://github.com/cfal/shoes

## Working Rule For Future Agents

If a proposed change adds Xray concepts to the `rustls` fork, stop and move that
logic to `xray-rust`.

If a proposed change breaks default `rustls` behavior, stop and redesign it as
an opt-in customization.

If a proposed change requires forking `tokio-rustls`, stop and first prove why
the normal `rustls` public API cannot support the required hook.

The fork should be a maintained TLS extension point, not a proxy implementation.
