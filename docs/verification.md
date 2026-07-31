# Verification

The default verification path is hermetic: it does not need a live proxy,
external network access, or a Go Xray-core checkout.

## CI-equivalent Rust checks

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- \
  -D warnings -W clippy::perf -W clippy::suspicious
cargo test --workspace --all-targets --locked
bash scripts/tests/check-public-fixtures.test.sh
bash scripts/tests/check-mobile-toolchains.test.sh
```

These commands match the Rust job in `.github/workflows/ci.yml`. Tests marked
`#[ignore]` are intentionally excluded because they require a local reference
binary, live credentials, or external network access. The fixture safety check
rejects routable endpoints and unreviewed credential-shaped values without
printing their contents.

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

## Local Xray-core interoperability

The repository does not vendor or declare a pinned Xray-core oracle revision.
For reproducible results, choose a revision yourself, record its full commit
SHA in the test report, and provide an absolute checkout path. The tests expect
an `xray` executable at the checkout root:

```sh
export XRAY_CORE_CHECKOUT=/absolute/path/to/Xray-core
git -C "$XRAY_CORE_CHECKOUT" rev-parse HEAD
(
  cd "$XRAY_CORE_CHECKOUT"
  go build -o xray ./main
)
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
selected fingerprints, and parallel flows. They do not establish compatibility
with every Xray-core revision or configuration.

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
