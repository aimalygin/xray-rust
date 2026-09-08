# v0.6 implementation plan and initial review

Initial review: 2026-09-04, development version `0.6.0-dev.0`.

Current status (2026-09-08 UTC): the selected Milestones A–E scope is frozen
and matching core/mobile `v0.6.0-rc.1` prereleases are published. Scoped
integration review, release CI and exact-candidate performance/device evidence
are complete; see [published evidence](v06-release-evidence.md#published-v060-rc1).
The dated increments below retain their original development observations;
statements about pending work describe that point in time. Additional host
capability providers and IPv6 Fake IP remain deferred. Stable publication is
not part of this completion record.

## Compatibility decision

Retain Xray-core `v26.7.28`, full commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, as the implementation and oracle
contract. The local reference checkout is clean at that commit, and the
existing [migration audit](xray-core-v26.7.28-migration-audit.md), wire
fixtures, interop gates, and benchmark evidence use it.

The public GitHub `releases/latest` endpoint queried on this review date
reported `v26.3.27`, older than the repository's pinned reference. That result
does not establish a newer stable baseline and is not used to roll the
contract backward. This is an explicit retention decision, not a claim that
`v26.7.28` is the latest upstream release. Any subsequent migration requires
its own exact-commit delta audit and regenerated oracle evidence.

Keep `v0.5.0` (`549807d621fadc618e6d0bab75f9e58ef35a7fc1`) and its named
performance/ABI evidence immutable. The distribution repository remains pinned
to that published release until a reviewed core candidate can supply all tag,
tree, lockfile, header, artifact, and adapter checksums together. Development
does not retag the published SDK or label its old binary as `0.6`.

## Review findings and delivery order

1. **Routing can precede the new crypto and XHTTP work.** The managed resolver,
   single-flight cache, graph/factory ownership, and atomic routing revision
   already exist. Milestone letters describe scope, not a serial dependency
   chain. Implement `IPOnDemand` as the first complete increment.
2. **Lazy resolution has observable ordering.** In the pinned Xray source,
   `app/router/config.go:BuildCondition` orders the supported fields as
   inbound, network, port, destination IP, then domain. A combined rule whose
   domain does not match can still trigger DNS. Prechecking its domain would
   change upstream behavior.
3. **Resolver results need an explicit work bound.** `DnsLookup` also accepts
   injected platform answers, which are not necessarily bounded by DNS packet
   size. The new strategy must reject oversized results, not truncate them and
   accidentally choose a different route.
4. **Snapshot enums cross the SDK boundary.** Swift and Kotlin reject unknown
   domain-strategy values. Add `ipOnDemand` to both with the Rust/FFI change;
   keep existing ABI symbols, layouts, and snapshot schema version unchanged.
5. **Refactors belong immediately before their feature.** Extract routing
   parsing and rule evaluation now. Extract VLESS config/secret ownership and
   XHTTP download/session ownership before those respective increments; avoid
   requiring a repository-wide rewrite before the first feature.
6. **Encryption strings become secrets.** The current `VlessUser::Debug`
   includes the `encryption` string because only `none` is accepted. The crypto
   increment must replace that assumption before accepting key-bearing values,
   including parser warnings/errors, FFI diagnostics, importers, and ownership
   of derived keys. Merely accepting new strings is not an implementation.
7. **Conditional scope must remain conditional.** Host process/network inputs
   need an identified consumer and versioned provider design. IPv6 Fake IP,
   QUIC v2/hopping, and adaptive H3 experiments do not block this routing
   increment. Bounded device evidence is still required before the release;
   there is no fixed six-hour campaign.
8. **The contributor test command had drifted from CI.** `--all-targets`
   overrides the fuzz binaries' `test = false` and starts unbounded libFuzzer
   mains. Align `CONTRIBUTING.md` with CI by excluding `xray-rust-fuzz`; keep
   fuzzing in its separate bounded campaign.

After the routing increment, implement VLESS non-`none` encryption, then
the supported XHTTP `downloadSettings` subset, then configuration tooling and
any selected host-policy input. Freeze features before the first RC. All
remaining required Milestone B/D/E work remains required for `v0.6`; this
initial increment does not declare the release complete.

## Second increment: bounded VLESS 1-RTT

Implemented the first subset described in the
[VLESS encryption design](vless-encryption-design.md): one NFS public key,
`native`/`xorpub`/`random`, AES-256-GCM/ChaCha20-Poly1305, default padding,
raw TCP without Vision, and TCP/UDP/XUDP framing. A separate
`xray-vless-encryption` crate owns typed configuration, hybrid key exchange,
and bounded async record state. `VlessUser.encryption` now uses the redacted
`VlessEncryption` enum instead of retaining the raw string. C ABI remains 1.4.

The pinned Go oracle checks binary-context KDF and both AEADs, plus actual
1-RTT exchanges, corruption, wrong keys, and truncated responses. Record tests
cover replay/reflection, partial I/O, cancelled reads/flushes, bidirectional
backpressure, half-close, and counter wrap. Ordinary CI runs the oracle gate;
config and FFI fuzz seeds reach the new typed parser. Unsupported 0-RTT,
relay chains, custom padding, non-raw carriers, and Vision fail explicitly.

Milestone B remains open for those unsupported combinations and independent
security review. The next increment below adds mobile import, dedicated
fuzzing, and local REALITY/full-process interop for the supported subset. No new mobile release tag/artifacts are
produced by this working-tree increment.

Second-increment validation: 2,149 Rust workspace tests passed (38 explicitly
ignored), 68 pinned Go interop scenarios passed including outer TLS and runtime
TCP/UDP/XUDP, 297 SwiftPM and 79 Kotlin tests passed, and workspace Clippy and
format/fixture/workflow guards passed. The full evidence boundary is recorded
in the design. At that point mobile imports still accepted only `none`; the
third increment below adds the supported 1-RTT projection.

## Third increment: 1-RTT validation and mobile import

- Added common Swift/Kotlin/Rust key-validation and profile-projection fixtures;
  encrypted `tcp`/`raw` links support none, TLS, or REALITY with no Vision.
  Unsupported encryption stays redacted in typed importer errors.
- Review identified that AWS-LC's raw ML-KEM public-key constructor only checks
  length. Added an explicit modulus check before dialing; boundary fixtures
  cover both packed coefficients and the first/last polynomial positions.
- Added dedicated handshake/record fuzz targets with valid authenticated
  envelopes, raw bytes, targeted mutation/truncation, partial I/O, and rekey.
  Extended the existing bounded host-hardening script to include both targets
  and the encryption crate's ASan library tests.
- The pinned Go gate now also builds/runs the full Xray process for 18
  mode/key/security combinations, using a local TLS cover origin for REALITY.
  These supplement the 68 existing library/runtime interop scenarios.
- Disabled ThinLTO and retained symbols in fuzz runs after the pinned local
  build showed missing dependency coverage. Corrected ASan runs completed
  29,324 handshake and 59,665 record executions in 61 seconds each without
  crashes/timeouts; these are smoke checks, not the release campaign.
- The mobile distribution remains on the published `v0.5.0` candidate. No
  Apple/Android release artifact or physical-device evidence is implied.

Third-increment validation: 2,150 Rust workspace tests passed (39 explicitly
ignored), 14 encryption library/fuzz-driver tests passed, and 86 pinned Go
interop scenarios passed. The common fixture contains 38 key cases and 58
profile cases; SwiftPM passed 298 tests and Kotlin 80. Clippy, formatting,
fixture safety, and the updated workflow/toolchain guards passed. See the
design for the local-only artifact and release-evidence boundaries.

## Fourth increment: 0-RTT, relay chains, and configurable padding

- Added the pinned cold-to-resumed 0-RTT lifecycle. Each runtime outbound owns
  one bounded in-memory ticket; tickets are published only after authenticated
  peer padding and invalidated on expiry, rejection, cancellation, EOF, or drop
  before the first authenticated resumed response. Early application bytes are
  never replayed automatically.
- Added ordered chains of one to eight mixed X25519/ML-KEM-768 NFS keys,
  including continuous inter-relay hash/relay masking compatible with the
  pinned implementation.
- Added upstream-compatible configurable padding draws with stricter resource
  ceilings: 32 parts, 65,553 total bytes, one second per gap, and five seconds
  total. The 30-second handshake deadline remains the outer bound.
- Extended the exact Go oracle to distinguish cold and resumed wire paths by
  bytes consumed. It covers both AEADs, all three modes, mixed three-key chains,
  configured fragmentation, expired-ticket failure, cancelled resumption, and
  a cold recovery connection. Runtime outbound reuse is checked separately.
- Updated Rust/Swift/Kotlin parsing, shared fixtures, FFI checks, and mobile
  share-link import to the same bounds. Raw TCP without Vision remains the
  accepted carrier boundary.

Milestone B remains open for encrypted Vision/non-raw carriers, independent
review, broader full-process application coverage, release-candidate fuzz and
sanitizer campaigns, and exact-candidate mobile/performance evidence.

## First increment: IPOnDemand contract

- Accept canonical `routing.domainStrategy: "IPOnDemand"`. Unknown values
  retain a `$.routing.domainStrategy` error; no alias to `IPIfNonMatch`.
- Evaluate rules in declaration order. Resolve only when a reached rule's
  inbound, network, and port predicates pass and its IP matcher needs a domain
  address. An earlier domain-only match performs no lookup.
- Use the existing managed `resolve_all(domain, port)` path once per selection;
  retain all returned IPv4/IPv6 addresses and the original destination. Rules
  take priority over address order. Existing DNS query-family settings apply.
- At most 256 unique socket-address candidates may enter on-demand matching.
  More returns a redacted routing error before matching or selecting a
  fallback. The parser's existing 4,096-rule limit is unchanged. No extra
  result-vector copy or detached routing task is introduced. The resolver owns
  allocation of its answer; this cap bounds routing work, not arbitrary memory
  allocated inside an injected host resolver.
- Remember lookup failure/empty answers for the selection. IP rules then
  fail to match; later domain/metadata rules can still win, otherwise use the
  configured default. Never retry once per IP rule. Normalizing an injected
  successful empty answer to failure is a deliberate bounded edge contract.
- Literal IP destinations and the resolver-free internal DNS bootstrap paths
  do not resolve. Existing `AsIs` and `IPIfNonMatch` behavior is retained.
- Hold one immutable routing-policy `Arc` across the await. Cancellation drops
  the inline lookup; cache leader cleanup permits later callers to proceed.
  Stale answers and background refresh continue to belong to the shared cache.
- C ABI 1.4 routing replacement accepts the new config and emits `ipOnDemand`
  in schema-1 snapshots. Updated Swift/Kotlin decoders recognize all three
  strategies. Older wrappers must be updated before opting into the new value.

## Verification and remaining evidence

The common fixture at `tests/fixtures/routing/domain_strategy.json` is checked
both by Rust router tests and by `tools/routing-oracle/main.go`, which imports
the clean pinned Xray checkout itself. It covers 23 cases including rule/IP
priority, combined predicates, DNS failure, IPv4/IPv6/mapped addresses, TCP/UDP,
and `SkipDNSResolve`. The oracle performs no network DNS queries. Run:

```sh
bash scripts/check-routing-oracle.sh
cargo test --locked -p xray-core-rs --lib outbound::routing
cargo test --locked -p xray-core-rs --test runtime_data_path_tests ip_on_demand
```

Additional Rust regressions cover address-limit edges, empty answers,
single-flight/cache reuse, cancellation/retry, stale refresh ownership, and
policy replacement during a pending lookup. Adapter and FFI tests cover the
new snapshot value alongside the old values. The routing oracle is part of
the existing blocking `go-oracles` CI job, including normal PR/push runs.
The existing config and FFI fuzz corpora include an `IPOnDemand` seed with
combined domain/IP and TCP/UDP selectors; ASan's core-library gate also runs
the new routing tests.

Routing-only working-tree validation on 2026-09-04, before the encryption
increment (retained as the first-increment evidence):

| Check | Result |
| --- | --- |
| Rust 1.96 workspace tests, `--exclude xray-rust-fuzz --all-targets --locked` | 2,131 passed; 34 explicitly ignored; no failures |
| Workspace Clippy, all targets/features, warnings denied | Passed |
| Pinned Go routing oracle | All 23 shared cases passed |
| SwiftPM tests with the current Rust library, local macOS arm64 XCFramework | 296 passed; Xcode 26.6; no failures |
| Android Kotlin `:xraymobile:testDebugUnitTest`, JDK 17 | 78 passed; no failures |
| Formatting, diff whitespace, fixture safety, mobile toolchain guards, release-version and workflow policy checks | Passed |

The local XCFramework contains only the macOS test slice. These results are
development checks from an uncommitted tree, not distributable Apple/Android
artifacts, clean performance evidence, or physical-device tunnel evidence.

Before the RC, collect exact-candidate Apple and Android evidence for routing
after DNS/network changes, cancellation, and hot policy replacement. Full
release interop, sanitizers/fuzz/Loom, controlled-network, performance, and
platform artifact matrices remain release gates; passing the local increment
tests does not claim those campaigns have run for `0.6`.


## Vision/carrier increment (2026-09-04)

Implemented encryption on raw, WS, HTTPUpgrade, gRPC, and XHTTP with optional
Vision, preserving outer carrier/security during Direct mode and continuous
random-mode header masking. Raw/XHTTP Swift/Kotlin imports preserve both flow
variants. The pinned gate now covers 540 full-Xray application flows across
204 profiles, in addition to library/runtime oracle cases, and runs on normal
PRs/pushes. The shared fixtures contain 38 key and 96 profile cases.

Independent review and exact-candidate mobile/performance/release evidence
remain open. Earlier
increment descriptions and counts above are historical; current contracts
and evidence are in [the encryption design](vless-encryption-design.md).


## XHTTP download increment (2026-09-05)

IR-01–IR-13 remediation is recorded in the independent review. The next
increment implements the bounded `downloadSettings` contract in
[xhttp-download-design.md](xhttp-download-design.md): independent target,
security, HTTP version and pool, one shared logical session, protected/resolved
dialing, server-first reads, cancellation, errors and packet-uploader rollover.
Nested stacks, stream-one and chaining combinations fail closed. XHTTP parser
and core carrier compilation were extracted before adding the new feature.
Canonical JSON exposes the feature without changing C ABI symbols or layout.

`scripts/check-xhttp-download-oracle.sh` validates shared configuration fixtures
against the pinned Go builder, then runs actual full-Xray application traffic
through loopback TLS H1/H2/H3 frontends and a local REALITY origin. It is a
blocking ordinary CI gate. The generic RC/scheduled interop scripts omit the
VLESS-encryption and XHTTP-download modules because their dedicated blocking
oracle steps provide the required local processes and exact-reference guards.

## Configuration tooling increment (2026-09-05)

Milestone E now provides a generated executable configuration contract and
parser-backed CLI/Rust tooling, as detailed in [config-tooling.md](config-tooling.md).
The parser and discovery document share 41 recognized object-key sets; complete
inputs are validated by the actual parser, including aliases, geodata, encryption
keys and XHTTP download constraints. Compatibility-only and ignored fields are
identified explicitly. Canonical examples, JSON reports, stdin/file validation
and exclusive resource-directory lookup have hermetic fixture/process coverage.

DNS and stream/security parsing were extracted without changing behavior before
adding this increment. Routing, VLESS and XHTTP were already extracted by their
feature increments; further TUN/runtime-DNS/FFI splits follow their next feature.
No C ABI or mobile adapter migration is required. Ordinary CI verifies contract
freshness and acceptance/rejection parity and publishes the validated artifact.

The subsequent release freeze and scoped integration review are recorded in
[candidate review](v06-candidate-review.md). Physical-device/performance and
publication gates passed for the exact published RC; their results and limits
are recorded in [release evidence](v06-release-evidence.md#published-v060-rc1).
