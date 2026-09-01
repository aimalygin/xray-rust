# Verification

## Compatibility contracts

### Ordinary CI

The ordinary pull-request and branch compatibility contract is hermetic: its
runtime tests do not need a live proxy, external test targets, or a Go
Xray-core checkout. Tests that require one of those inputs remain ignored in
this path. Workflow setup can still download pinned actions, toolchains, and
dependencies, so this does not mean that provisioning a fresh CI runner is an
offline operation.

### Tagged release candidates

A tagged release candidate adds a blocking `rc-interop` gate. That job checks
out Xray-core `v26.7.28` at the exact commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c` and invokes only
`scripts/check-rc-interop.sh` for release interoperability. The script verifies
the checkout independently and does not accept a revision override. A tagged
RC therefore cannot publish unless this exact compatibility gate passes.

### Weekly scheduled compatibility

The weekly schedule runs two contracts that are independent of RC
publication. `scheduled-pinned-interop` uses the same exact Xray-core commit as
the RC gate, but exercises the broader ignored interop matrix and bounded
resource workloads. It is blocking for that scheduled run only; it is not a
prerelease dependency and cannot substitute for `rc-interop`.

Reproduce the pinned scheduled gate from the xray-rust repository root with a
clean checkout at the audited commit:

```sh
git -C "/absolute/path/to/Xray-core-v26.7.28" switch --detach \
  5ca6f4b7d4dc20a881d4330e498892697627ec0c
XRAY_CORE_CHECKOUT="/absolute/path/to/Xray-core-v26.7.28" \
  bash scripts/check-scheduled-pinned-interop.sh
```

`xray-core-main-smoke` is a warning-only early-compatibility signal. It tests
the Xray-core `main` checkout's resolved commit, but it cannot satisfy or fail
an RC publication gate. Resolve the clean checkout's `HEAD` before invoking
the focused smoke locally:

```sh
xray_main_revision="$(git -C "/absolute/path/to/Xray-core-main" rev-parse --verify HEAD)"
XRAY_CORE_CHECKOUT="/absolute/path/to/Xray-core-main" \
XRAY_CORE_EXPECTED_REVISION="$xray_main_revision" \
  bash scripts/check-xray-main-smoke.sh
```

`XRAY_CORE_EXPECTED_REVISION` accepts only the resolved, full 40-character
lowercase commit that equals the checkout's `HEAD`. Symbolic names such as
`main` and `HEAD`, abbreviated commits, uppercase hashes, and malformed values
are rejected. Callers must resolve a symbolic ref before passing the override.

## Rust CI checks

After selecting the pinned Rust toolchain, the `rust` job in
`.github/workflows/ci.yml` runs these repository checks. Run them from the
repository root; the workflow remains authoritative if this list changes:

```sh
for script in scripts/*.sh scripts/tests/*.sh; do
  bash -n "$script"
done
bash scripts/tests/check-release-version.test.sh
bash scripts/tests/check-prerelease-workflow.test.sh
bash scripts/tests/check-rc-interop.test.sh
bash scripts/tests/check-scheduled-pinned-interop.test.sh
bash scripts/tests/check-xray-main-smoke.test.sh
bash scripts/tests/check-scheduled-interop-workflow.test.sh
bash scripts/tests/check-public-fixtures.test.sh
bash scripts/tests/check-benchmark-publication.test.sh
bash scripts/tests/bench-xhttp-memory.test.sh
if [[ -f docs/benchmarks/results/2026-08-31-v26.7.28/manifest.json ]]; then
  python3 scripts/check-benchmark-publication.py docs/benchmarks/results/2026-08-31-v26.7.28
fi
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- \
  -D warnings -W clippy::perf -W clippy::suspicious
cargo test --workspace --exclude xray-rust-fuzz --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
bash scripts/tests/check-mobile-toolchains.test.sh
```

The workspace test command excludes `xray-rust-fuzz` because `--all-targets`
would otherwise build and launch libFuzzer binaries as ordinary test targets.
Those targets have their own bounded RC gate and explicit longer-run workflow.

Tests marked `#[ignore]` are intentionally excluded because they require a
local reference binary, live credentials, or external network access. The
fixture safety check rejects routable endpoints and unreviewed
credential-shaped values without printing their contents.

Release-candidate tags also add the `fuzz-smoke` blocking job after the
ordinary jobs pass. It runs bounded libFuzzer campaigns and, like
`rc-interop`, does not run for an ordinary branch or pull request.

## Release-candidate fuzz gate

Four `cargo-fuzz` targets cover the configuration parser, DNS wire parser and
response builder, Vision plus UDP/XUDP framing, and the public FFI
create/load/free lifecycle. The corpus and targets live under `fuzz/`. To
reproduce a bounded configuration-parser campaign:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-05-22 fuzz run config_json -- \
  -runs=512 -max_len=65536 -timeout=10
```

Use the same command with `dns_wire`, `vless_wire`, or `ffi_lifecycle`. The CI
run counts are smoke gates, not a claim of exhaustive fuzzing; longer local or
scheduled campaigns should retain a crashing input, minimize it, and add a
deterministic regression before closing the finding.

The supply-chain CI job additionally runs:

```sh
cargo audit
cargo deny --locked check advisories bans licenses sources
```

CI installs `cargo-audit` 0.22.2 and `cargo-deny` 0.19.4. Install those tools
before reproducing this part locally.

The dedicated secret-scan job checks the complete reachable history:

```sh
XRAY_FIXTURE_SCAN_HISTORY=1 \
  bash scripts/tests/check-public-fixtures.test.sh
gitleaks git --config .gitleaks.toml --redact=100 --no-banner \
  --log-opts="--all" .
```

CI downloads Gitleaks 8.30.1 and verifies its release SHA-256 before use. The
custom check covers retired VLESS/REALITY values that generic token scanners do
not recognize; Gitleaks covers common credential formats.

The custom check attributes each hit to the commit carrying it and reports
every commit except the two pre-release ones grandfathered by commit id in
`scripts/tests/check-json-fixture-safety.py` (see the disclosure section of
`SECURITY.md`). It also fails if a grandfathered commit stops matching, since
that means the allowlist no longer describes the history it was derived from.

## Focused runtime checks

The main local integration target exercises SOCKS, HTTP CONNECT, TUN,
Freedom/VLESS, TLS, routing, DNS, UDP/XUDP, Vision, backpressure, and ICMP:

```sh
cargo test --locked -p xray-core-rs --test runtime_data_path_tests
```

Protocol/transport tests can be run separately:

```sh
cargo test --locked -p xray-proxy
cargo test --locked -p xray-transport
cargo test --locked -p xray-config
```

The C header, exported artifacts, adapter contracts, and build-script target
matrices are covered by:

```sh
cargo test --locked -p xray-ffi --test ffi_tests
cargo test --locked -p xray-ffi --test mobile_artifacts_tests -- --nocapture
```

## Deterministic REALITY checks

These tools and tests do not open a connection to a live node:

```sh
go run ./tools/reality-oracle/session_id_vectors.go \
  --check tests/fixtures/reality/session_id_vectors.json
go run ./tools/reality-oracle/clienthello_fixture.go \
  --check tests/fixtures/reality/clienthello_chrome_auto.json
cargo test --locked -p xray-transport reality
```

They cover session-ID sealing, ClientHello shaping/patching, certificate
binding, connector validation, and the Rust REALITY transport path.

## Go-oracle fixtures

The fixtures under `tests/fixtures/reality`, `tests/fixtures/masquerade` and
`tests/fixtures/grpc` are what pins our ClientHello shaping, masquerade headers
and gRPC wire shape to the Go reference implementations, and the Rust suite
asserts against them without ever running the oracles that produced them. This
replays every oracle and compares:

```sh
bash scripts/verify-oracle-fixtures.sh
```

It discovers the fixtures itself and reads each one's generation flags out of
the fixture's own contents, so a new fixture is covered as soon as it is
committed and a fixture no oracle claims fails the run. It needs Go and
`python3`, and is what the `go-oracles` CI job runs. Measured on an M-series
Mac: about 17 s against a cold Go build cache, 3-5 s once the oracles' packages
are cached. CI pays the cold price on every run unless the Go cache is
restored.

One family cannot be reproduced byte for byte away from the machine that
generated it: Xray derives browser versions from the current date offset by a
draw from a CPU-seeded PRNG, so `tests/fixtures/masquerade/headers_*.json`
report `drift` on any other host. Header keys, their order, and every value the
draw does not reach are still checked strictly; anything left unverified is
named in the output.

### The gRPC oracle

`tools/reality-oracle/grpc/grpc_wire.go` makes one real gRPC dial through
grpc-go v1.81.0 over an in-memory pipe whose client end is tapped, opens `Tun`
and then `TunMulti` on it, and reads everything the client wrote back as HTTP/2
frames. All four fixtures come off that one connection rather than from four
separate transcriptions, and each claims a different amount:

| Fixture | What it pins |
| --- | --- |
| `connection_preamble.json` | The 24-byte client preface and the client's own SETTINGS frame, byte for byte. The rest of the burst before the first HEADERS is compared as decoded frame descriptors — type, flags, stream, payload length — not bytes, with SETTINGS ACKs filtered out of both sides because ours races the request where grpc-go's is always first. The expectation is the fixture's burst *plus* one `WINDOW_UPDATE(stream 0)` that is ours and not grpc-go's, whose increment is asserted separately; see [status](status.md). So an added frame on either side still fails |
| `request_headers.json` | The first call's HEADERS as a decoded field list in order — not the HPACK bytes, which diverge in three known places; see the divergences in [status](status.md) |
| `hunk_framing.json` | Each `Tun` message as it left the wire, byte for byte, reassembled across DATA frames |
| `multi_hunk_framing.json` | The same for `TunMulti`, with mostly multi-element `MultiHunk` messages — the shape a single-element writer cannot produce — and the `:path` read back off the call's own HEADERS |

The oracle lives in a Go module of its own. Both `google.golang.org/grpc` and
xray-core raise the root module's `golang.org/x/crypto`, and uTLS compiled
against a different `x/crypto` emits different ClientHello bytes, which would
break the committed REALITY fixtures. Read the comment in that directory's
`go.mod` before moving it.

`scripts/verify-oracle-fixtures.sh` regenerates and compares all four, so
running the oracle by hand is only needed when changing what it captures:

```sh
go run -C tools/reality-oracle/grpc -tags reality_oracle_grpc_wire . \
  -wire connection_preamble \
  -check ../../../tests/fixtures/grpc/connection_preamble.json
```

`-C` moves Go rather than the shell, so `-check` takes a path relative to the
oracle's directory while a redirect would still be relative to the repository
root.

## Local Xray-core interoperability

By default, the local interop suite pins Xray-core `v26.7.28` at
`5ca6f4b7d4dc20a881d4330e498892697627ec0c` and rejects a checkout at any
other `HEAD`. The scheduled `main` smoke may override that default only with
the full lowercase commit already resolved from, and equal to, the selected
checkout's `HEAD`; it never accepts `main` or `HEAD` as the override. Provide an
absolute checkout path and record its full commit SHA in the test report. The
tests build their reference binaries in temporary directories, so keep the
checkout itself clean:

```sh
export XRAY_CORE_CHECKOUT="/absolute/path/to/Xray-core"
git -C "$XRAY_CORE_CHECKOUT" switch --detach v26.7.28
git -C "$XRAY_CORE_CHECKOUT" rev-parse --verify HEAD
```

Run a focused REALITY+Vision interoperability test:

```sh
XRAY_CORE_CHECKOUT="$XRAY_CORE_CHECKOUT" \
cargo test --locked -p xray-core-rs \
  --test local_xray_interop_tests \
  rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision \
  -- --ignored --nocapture
```

Or run all ignored local Xray-core scenarios:

```sh
XRAY_CORE_CHECKOUT="$XRAY_CORE_CHECKOUT" \
cargo test --locked -p xray-core-rs \
  --test local_xray_interop_tests -- --ignored --nocapture
```

These tests generate loopback server/client configurations and ephemeral TLS or
REALITY test material. They cover VLESS TCP, TLS, TLS+Vision, REALITY+Vision,
selected fingerprints, parallel flows, round-robin across two local Xray VLESS
members, a two-hop transport-layer VLESS chain, and the WebSocket, HTTPUpgrade
and gRPC stream transports, plus the 15-case XHTTP H1/H2/H3 matrix below. They
do not establish compatibility with every Xray-core revision or configuration.

The ordinary Rust CI job still excludes these `#[ignore]`d tests. An RC tag is
different: the blocking `rc-interop` job runs every interop test function with
two selected REALITY fingerprints, an eight-flow burst, and five XHTTP cases
covering all three modes plus H1/H2/H3. Before the live suite, the pinned Xray
binary validates `tests/fixtures/configs/v05_phase2_oracle.json`; the Rust
parser test asserts the balancer, chain, observatory, encrypted-DNS transports,
and stale-cache model produced from that exact document. The gate then runs
bounded VLESS UDP and XUDP process-level workloads through both implementations,
the end-to-end DNS outbound runtime slice, and explicit protocol-library oracle
filters for DoT/DoH/DoQ framing and failover, configured-DNS policy/bootstrap,
negative caching, singleflight, and bounded stale refresh. Reproduce that exact
gate with:

```sh
XRAY_CORE_CHECKOUT="$XRAY_CORE_CHECKOUT" \
  bash scripts/check-rc-interop.sh
```

The encrypted-DNS wire servers use the independent rustls, h2, and quinn
protocol implementations as local oracles. This is explicit Rust wire/runtime
evidence rather than a claim of a cross-process Xray DNS-policy test; the
current process harness has no compatible Xray boundary for that policy.

### XHTTP interoperability

The XHTTP matrix has 15 cases: `packet-up`, `stream-up`, and `stream-one` over
cleartext H1, TLS H1, TLS H2, REALITY H2, and TLS H3.

Every `stream-up` case also sends an 8 MiB sustained uplink before reading its
completion marker. This crosses repeated HTTP flow-control windows and guards
against a concurrent downlink poll cancelling and stranding the uplink's
pending reservation; the fast H2 transport suite reproduces the same split
read/write ordering without a local Xray process.

#### VLESS share-link boundary

The Apple share-link importer and the Rust transport are separate compatibility
layers. For the VLESS model currently implemented by xray-rust
(`encryption=none`, and no Vision flow on XHTTP), their supported combinations
are:

| Share-link security and ALPN | Imported security fields | Runtime HTTP version | Live matrix ids |
| --- | --- | --- | --- |
| `security=none` | no security settings | H1 | `h1-none-*` |
| `security=tls&alpn=http/1.1` | `sni`, `fp`, `alpn`; `allowInsecure=true` is rejected by canonical parsing | H1 | `h1-tls-*` |
| `security=tls` with absent `alpn`, `h2`, or any non-special list | same TLS fields | H2 | `h2-tls-*` |
| `security=tls&alpn=h3` as the exact one-element list | same TLS fields | H3 over QUIC/UDP | `h3-tls-*` |
| `security=reality` | `sni`, `fp`, `pbk`, `sid`, `spx`, `pqv` | H2 | `h2-reality-*` |

`type=xhttp` and the legacy `type=splithttp` alias both emit
`streamSettings.network: "xhttp"`. `host`, `path`, and `mode` remain outer
XHTTP settings. `extra` is a URL-encoded JSON object and follows Xray's
one-level replacement rule; only the outer identity fields survive that
replacement. An omitted XHTTP path reaches the transport as an empty string
and is normalized to `/`, matching Xray's wire behavior.

For TLS, an omitted `sni` reuses the remote host and an omitted `fp` selects
`chrome`; `alpn` is a comma-separated list without whitespace. For REALITY,
`fp` and `pbk` are required, `sni` defaults to the remote host, and a present
`sid=` is a valid empty short ID. The current Xray share-link proposal calls
`pbk` a `realitySettings.password`; xray-rust stores it in the legacy
`publicKey` model field. Xray-core v26.7.28 accepts that alias and decodes the
same 32-byte key, so this difference does not change the handshake wire.

This is deliberately not a claim of complete support for every field in the
current Xray share-link proposal. Non-`none` VLESS encryption is not
implemented. The Apple share-link importer still rejects non-empty modern TLS
`pcs`, `vcn`, and `ech`/`echQuery` rather than guessing a host-verification
policy; canonical Xray JSON supports `pinnedPeerCertSha256` directly, while
canonical Xray JSON also supports comma-separated `verifyPeerCertByName` with
ORed DNS/IP SAN checks independent of SNI. The Apple importer still rejects a
non-empty `vcn` because it has no explicit host-policy seam; ECH remains
fail-closed in both paths. An explicitly empty share parameter is treated as
absent. Canonical `allowInsecure: true`, including
legacy importer output, is rejected. XHTTP with a Vision
flow is rejected; current Xray guidance pairs XHTTP with VLESS encryption
rather than the raw-transport Vision flow. The importer also retains its
pre-existing case-insensitive query-name lookup even though the current share
proposal specifies case-sensitive names; duplicate consumed fields are rejected.

Coverage is layered rather than one cross-language executable test. Apple
tests verify URL-to-JSON mapping and fail-closed behavior, the
`vless_xhttp_tls_importer.json` and `vless_xhttp_reality_importer.json`
fixtures cover fail-closed legacy TLS import and dial-ready REALITY transport,
and the ignored matrix below exchanges bytes with a real local Xray-core. The live
matrix starts from a Rust `CoreConfig`; it does not invoke the Swift importer.
The supplemental `vless_xhttp_tls_h2.json` and
`vless_xhttp_reality_h2.json` fixtures pin a normally verified TLS/H2 shape
and the REALITY/H2 parser-model shape independently of the importer snapshots.
Keep all three layers when changing this boundary.

The parameter mapping follows the official
[VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716),
while the H1/H2/H3 selection follows
[XHTTP: Beyond REALITY](https://github.com/XTLS/Xray-core/discussions/4113)
and `Xray-core/transport/internet/splithttp/dialer.go` in the recorded oracle
checkout.

Run the exact complete matrix with the stable `all` selector:

```sh
XRAY_CORE_CHECKOUT="$XRAY_CORE_CHECKOUT" \
XRAY_XHTTP_INTEROP_CASES=all \
cargo test --locked -p xray-core-rs \
  --test local_xray_interop_tests \
  rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases \
  -- --ignored --nocapture
```

Omitting `XRAY_XHTTP_INTEROP_CASES` also selects all 15. For a stable subset,
pass comma-separated case ids; for example, the exact H3 slice is:

```sh
XRAY_CORE_CHECKOUT="$XRAY_CORE_CHECKOUT" \
XRAY_XHTTP_INTEROP_CASES=h3-tls-packet-up,h3-tls-stream-up,h3-tls-stream-one \
cargo test --locked -p xray-core-rs \
  --test local_xray_interop_tests \
  rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases \
  -- --ignored --nocapture
```

The full 15-case matrix, including all three H3 cases, passed on 2026-08-27
against Xray-core `1bdb488c9ec09ea51e6899697d5b7437f3cf6eb2` (`v26.5.9`),
from the dirty xray-rust worktree based on
`e8825ed92f558b870ed5448f9da97df7e0b3bbcd`, in 77.37 seconds.
This is functional interoperability evidence only; it is not an H3
throughput, resource-use, congestion-controller, or performance-parity claim.

The complete 20-case ignored suite passed again on 2026-08-28 against the
pinned Xray-core `v26.7.28` commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c` in 236.02 seconds. That run
included the full 15-case XHTTP matrix. A separate explicit 11-fingerprint
REALITY/Vision run passed in 94.54 seconds. These are functional compatibility
results from the migration worktree, not benchmark measurements.

### gRPC interoperability

Five ignored scenarios reach a real Xray gRPC inbound. Run them together with:

```sh
XRAY_CORE_CHECKOUT="$XRAY_CORE_CHECKOUT" \
cargo test --locked -p xray-core-rs \
  --test local_xray_interop_tests grpc -- --ignored --nocapture
```

| Scenario | What it adds |
| --- | --- |
| `..._vless_grpc` | Plaintext h2c, and a `serviceName` with a space in it, so both ends have to agree on Go's `url.PathEscape` |
| `..._vless_grpc_tls` | TLS under gRPC. The ClientHello has to offer `h2`, because a gRPC inbound closes a connection that negotiates no ALPN — and does it silently, so the failure arrives as a bare EOF |
| `..._vless_grpc_reality` | REALITY under gRPC, the pairing ws and httpupgrade are refused |
| `rust_socks_client_reads_a_server_greeting_...grpc` | A tunnel whose *peer* speaks first, which every echo scenario hides: a write that is reported accepted before `h2` has taken it deadlocks here and nowhere else |
| `..._grpc_multi_mode` | A megabyte through `multiMode`, which is the only way to make the server batch several elements into one `MultiHunk` and so the only end-to-end cover for the multi-element read path |

The REALITY scenario dials a live cover origin (`www.google.com:443`) during
its warm-up, so it needs outbound network access on top of the Go toolchain and
the checkout. REALITY-fronted scenarios in this suite have been observed to
fail in a full sequential `--ignored` run of every test while passing in
isolation and as a filtered subset — a live origin and ephemeral-port
contention, not a regression — so read a failure there against a subset run
before believing it.

If the checkout is placed at `./Xray-core`, the lightweight default-suite smoke
test also detects it. Set `XRAY_RUST_REQUIRE_XRAY_CORE=1` to make absence of
that fixed-path checkout a failure.

## Live-node tests

`live_reality_node_tests` are ignored and require a config supplied locally via
`XRAY_REALITY_LIVE_CONFIG_JSON` or `XRAY_REALITY_LIVE_CONFIG_PATH`. They also
require an explicit comma-separated `XRAY_REALITY_LIVE_TARGETS` value; the test
suite has no built-in external targets. Do not put live credentials or targets
in `tests/fixtures` or commit them to Git.

Example for the Rust client only:

```sh
XRAY_REALITY_LIVE_CONFIG_PATH=/absolute/path/to/private-config.json \
XRAY_REALITY_LIVE_TARGETS=host-you-control.example:8080 \
cargo test --locked -p xray-core-rs \
  --test live_reality_node_tests \
  rust_core_live_reality_node_reads_parallel_speedtest_http_responses \
  -- --ignored --nocapture
```

Replace the reserved example target with an endpoint you are authorized to
exercise. The live tests require external network access and are not CI
evidence.

## Mobile verification

On a provisioned macOS host:

```sh
scripts/check-mobile-toolchains.sh --all
scripts/build-apple-xcframework.sh
scripts/check-apple-adapter-link.sh
scripts/build-android-adapter.sh
```

Run Swift and Android unit tests:

```sh
HOME=target/mobile/apple-swiftpm-home \
CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache \
swift test --disable-sandbox --package-path platform/apple

platform/android/gradlew -p platform/android \
  :xraymobile:testDebugUnitTest --no-daemon
```

The Apple link check covers iOS/tvOS device and both simulator architectures,
plus macOS `arm64` and `x86_64`. Android artifact scripts verify all four ABIs,
native-library provenance, and 16 KiB ELF LOAD alignment.

### Gradle dependency verification

The Android build pins every resolved artifact by SHA-256 in
`platform/android/gradle/verification-metadata.xml`. A warm Gradle cache hides
missing entries, so reproduce CI with a cold one before trusting a green local
build:

```sh
GRADLE_USER_HOME="$(mktemp -d)" platform/android/gradlew \
  -p platform/android --no-daemon help
```

When an artifact legitimately needs a new entry, do **not** run
`--write-verification-metadata`: it records whatever the network served, which
turns the control into a formality. Authenticate the artifact first, then add
the entry by hand:

1. Download it from Maven Central and compute its SHA-256.
2. Verify the publisher's detached PGP signature (`.asc`) against a key fetched
   from an independent keyserver, and confirm that key already signs artifacts
   this file trusts.
3. Re-download through a different operator (for example the Google-hosted
   Maven Central mirror) and confirm the bytes are identical.
4. As an end-to-end control, recompute the checksums of entries already in the
   file and confirm your pipeline reproduces them.
5. Record the entry in sorted position with an `origin` naming the signing key
   fingerprint, not `Generated by Gradle`.

See [mobile testing](mobile-testing.md) for prerequisites, outputs, and
on-device responsibilities.
