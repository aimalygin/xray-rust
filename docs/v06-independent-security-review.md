# v0.6 independent security review

Status: completed against the `0.6.0-dev.0` development tree on 2026-09-04.

Release decision: **NO-GO for a v0.6 release candidate or stable release**.
Continued development is reasonable. No Critical finding, and no High or Medium
remotely exploitable defect in the reviewed VLESS wire/cryptographic runtime,
was identified. Three High release-integrity findings, five Medium assurance
findings, and five Low runtime or verification findings remain open.

> Remediation update (2026-09-05): the implementation and release-pipeline
> controls for IR-01 through IR-13 have been added and verified. The finding
> statuses below describe the original reviewed tree. See
> [Remediation verification](#remediation-verification--2026-09-05) for the
> current status. The release decision remains NO-GO until a clean immutable
> v0.6 candidate supplies the required physical-device and performance evidence.

This is an independent, tool-assisted source and release-engineering review,
not a contracted third-party audit or a formal cryptographic proof. Three
read-only review tracks separately covered (1) cryptography and wire behavior,
(2) FFI, TUN, and mobile adapters, and (3) dependencies and release provenance.
The findings were then reproduced or cross-checked by a fourth integration
pass. None of the review tracks authored the implementation under review.

## Review subject

The core review does not describe an immutable release candidate. The v0.6
implementation is an uncommitted development delta on top of the v0.5.0 commit:

- repository: `xray-rust`;
- HEAD: `549807d621fadc618e6d0bab75f9e58ef35a7fc1` (`v0.5.0`);
- tracked binary-diff SHA-256, excluding this report:
  `a73cac7bdfa6d4e87530b9ba91b43f336f602828f2a15ed8c56e9fb6673a6887`;
- untracked-file manifest: 168 files, sorted path-and-content SHA-256:
  `15fcf3e3e868a288b72c96fd1fd7b6d75039eed13f1bcfb28c19bc0c5e80b5aa`.

The sibling distribution repository was clean and still represented v0.5.0:

- repository: `xray-rust-mobile`;
- HEAD: `377bc2523a97b4faf3b039b65dce2a94381c2e6e` (`v0.5.0`).

The tracked-diff digest is the SHA-256 of `git diff --binary`. The untracked
digest is the SHA-256 of a lexically sorted manifest containing each untracked
file's SHA-256 and path. `docs/v06-independent-security-review.md` is excluded
from both so that adding the report does not change the reviewed subject.

A final sign-off must be repeated against a clean, immutable v0.6 RC commit.

## Scope and method

The review covered:

- VLESS `mlkem768x25519plus` configuration, relay construction, 1-RTT and
  0-RTT handshakes, AEAD records, padding, tickets, cache/lease behavior,
  cancellation, Vision transitions, and all integrated carriers;
- VLESS TCP, UDP, and XUDP outbound integration and downgrade boundaries;
- `IPOnDemand` parsing, lazy resolution, bounded address evaluation, cache and
  policy-revision behavior, and the pinned Xray-core routing contract;
- Rust C ABI ownership, panic containment, error redaction, socket protection,
  TUN descriptor ownership, Swift lifecycle serialization, JNI bridging, and
  the Apple/Android configuration projections;
- Cargo, Gradle, vendored-source, GitHub Actions, Apple XCFramework, Android
  AAR, signing, checksum, and release-publication controls;
- negative tests, fuzz entry points, dependency policy, source formatting,
  lints, pinned Go oracles, and release-gate wiring.

Not covered by direct execution were physical Apple/Android scenarios,
production infrastructure, GitHub repository settings, environment protection,
extended ASan/Miri/Loom campaigns, long fuzz campaigns, or clean-candidate
performance measurements. Those remain release evidence, not facts inferred
from source review.

## Finding summary

| ID | Severity | Area | Status |
| --- | --- | --- | --- |
| IR-01 | High | v0.6 release gates are not bound to publication | Open, RC blocker |
| IR-02 | High | Apple release binary is not bound to its source revision | Open, RC blocker |
| IR-03 | High | Mobile Gradle artifacts are not authenticated | Open, RC blocker |
| IR-04 | Medium | Vendored crypto/QUIC provenance is not machine-verified | Open |
| IR-05 | Medium | Core Gradle verification metadata is predominantly TOFU | Open |
| IR-06 | Medium | Android AAR verification has no exact-content allowlist | Open |
| IR-07 | Medium | Core checkout verification ignores untracked build inputs | Open |
| IR-08 | Medium | Mobile release CI has no mandatory history secret scan | Open |
| IR-09 | Low | Resumed 0-RTT confirmation is outside the 30-second deadline | Open |
| IR-10 | Low | Some VLESS credential/ticket copies are not zeroized | Open |
| IR-11 | Low | FFI returns string panic payloads verbatim | Open |
| IR-12 | Low | Android memory-pressure paths can terminate the VPN process | Open |
| IR-13 | Low | The canonical workspace test gate was not deterministic | Open, RC blocker |

## Detailed findings

### IR-01: v0.6 release gates are not bound to publication — High

The roadmap requires candidate-specific physical Apple/Android evidence and a
clean performance gate in addition to pinned interoperability, sanitizers,
fuzzing, controlled-network, supply-chain, and platform builds
(`docs/roadmap.md:540-570`). The `publish-prerelease` job depends on the latter
CI jobs but has no job that consumes physical-device or clean-performance
evidence (`.github/workflows/ci.yml:657-670`).

The Rust job runs tests of the evidence validators, not candidate evidence.
`scripts/tests/check-mobile-device-evidence.test.sh:14-201` constructs a
synthetic campaign, while `scripts/tests/check-v05-performance.test.sh:10-152`
constructs synthetic benchmark summaries. These are useful regression tests
for the validators, but they cannot prove that a v0.6 candidate was exercised.
The mobile publication workflow also does not consume a core v0.6 evidence
manifest.

Impact: an RC can be published while the exact candidate has never passed the
device/resource boundaries named by the roadmap. This is a release-integrity
failure even if every implemented source test is green.

Required remediation: add candidate-bound evidence jobs or an authenticated
evidence-verification job, make it a direct prerequisite of publication, and
bind the mobile release to the same verified core candidate and gate result.

### IR-02: Apple release binary is not bound to its source revision — High

The mobile preparation workflow records an Actions run ID, artifact name, and
XCFramework checksum (`xray-rust-mobile/.github/workflows/prepare-release.yml:
56-88`; `xray-rust-mobile/release/artifacts.env:1-3`). It does not record the
source commit/tree or workflow identity that produced the archive.

The release workflow downloads that blob by run ID and verifies its stored
checksum and structure (`xray-rust-mobile/.github/workflows/release.yml:
95-135`). A separate job rebuilds the tagged sources, but the result is not
byte-compared or otherwise proven equivalent to the downloaded archive
(`release.yml:61-94`). A checksum authenticates the selected blob, not its
correspondence to the published tag.

Impact: a correctly checksummed XCFramework built from an older or different
revision can be shipped under a later tag. The normal prepare/PR flow reduces
accidental mismatch but does not prevent changes between artifact preparation
and tagging.

Required remediation: lock and verify the producing commit/tree, workflow,
event, attempt, and successful conclusion; allow only an explicitly reviewed
metadata-only delta; and publish a signed artifact attestation. If reproducible
Apple archives are achievable, compare the tagged-source rebuild byte for byte.

### IR-03: mobile Gradle artifacts are not authenticated — High

The mobile build pins Android Gradle Plugin and Kotlin versions
(`xray-rust-mobile/android/build.gradle.kts:1-4`) and resolves plugins and
dependencies from remote repositories (`android/settings.gradle.kts:1-14`).
The repository has neither Gradle dependency-verification metadata nor
dependency locks.

Impact: exact versions prevent version drift but do not authenticate bytes. A
repository, publisher, mirror, or resolution-path compromise can execute plugin
code on the release runner and alter the AAR.

Required remediation: add reviewed SHA-256 dependency-verification metadata,
exercise it from a cold cache in CI, lock all resolvable configurations where
applicable, and make verification a publication prerequisite.

### IR-04: vendored crypto/QUIC provenance is not machine-verified — Medium

`Cargo.toml:81-84` replaces crates.io `blake3` and `h3-quinn` with local path
trees. Path dependencies have no registry checksum in `Cargo.lock`.
`vendor/blake3/XRAY-PATCH.md:3-16` records an upstream commit and archive hash,
but no CI guard verifies the full tree plus the allowed patch. The
`vendor/h3-quinn/README.md:10-25` describes its source release and code change
without an archive checksum or upstream commit, and likewise has no verifier.

Impact: an unintended change to KDF or HTTP/3 transport code can pass Cargo's
ordinary advisory/source policy because the local tree is the trusted source.

Required remediation: pin authenticated upstream archives, store a sorted file
manifest, and verify an exact, reviewable patch for both vendored trees in CI.

### IR-05: core Gradle verification metadata is predominantly TOFU — Medium

The core Android project has 490 SHA-256 entries in
`platform/android/gradle/verification-metadata.xml`; 485 carry
`origin="Generated by Gradle"` and only five have a separately attributed
origin. This directly conflicts with the documented procedure, which says not
to use `--write-verification-metadata` and requires independent authentication
before recording a checksum (`docs/verification.md:549-563`).

Impact: the metadata detects later byte changes but does not establish that the
first observed artifacts were authentic. No current compromise was found.

Required remediation: authenticate and re-attribute every release-reachable
entry, then enforce cold-cache resolution in the blocking Android job.

### IR-06: Android AAR verification has no exact-content allowlist — Medium

Gradle packages the supplied external `jniLibs` tree
(`xray-rust-mobile/android/xraymobile/build.gradle.kts:34-37`). The verifier
checks archive integrity, required permissions, required native libraries,
alignment, selected dependencies, and Rust-library equality, but never rejects
unexpected archive entries or all unexpected manifest components
(`xray-rust-mobile/scripts/verify-android-aar.sh:43-99`).

Impact: a poisoned prepared tree, plugin, or AAR can add code, assets, native
libraries, or a manifest surface while retaining all required entries and
passing the current verifier.

Required remediation: enforce a normalized archive-entry allowlist, validate
the complete merged manifest surface, and check allowed JNI exports and native
dependencies for every ABI.

### IR-07: core checkout verification ignores untracked build inputs — Medium

`xray-rust-mobile/scripts/_common.sh:96-99` calls Git status with
`--untracked-files=no`. An untracked `.cargo/config.toml`, compiler wrapper,
linker configuration, or other discovered build input can therefore affect a
local SDK build while the claimed commit/tree verification still passes.

Fresh hosted runners mitigate the default CI path, but the verifier's stated
clean-checkout property is not true for local preparation or a reused runner.

Required remediation: build from an isolated clean clone or reject every
untracked path except a small, explicit, non-build allowlist.

### IR-08: mobile release CI has no mandatory history secret scan — Medium

The core CI performs a checksum-pinned Gitleaks scan over full history
(`.github/workflows/ci.yml:108-150`). The mobile CI and release workflows have
no equivalent blocking control, even though they contain release/signing and
adapter integration logic.

A high-confidence local scan did not find a private key or recognizable AWS,
GitHub, OpenAI, Google, or Slack token. This is a process gap, not evidence of a
current credential leak.

Required remediation: add a pinned, full-history secret scanner plus the
repository-native provider scanning/push-protection controls.

### IR-09: resumed 0-RTT confirmation is outside the 30-second deadline — Low

`ClientConfig::connect_cached` wraps handshake construction in a 30-second
timeout (`crates/xray-vless-encryption/src/handshake.rs:60-76`). A resumed
0-RTT path returns an `EncryptedStream` immediately after preparing the client
prefix (`handshake.rs:128-157`). Reading the server random and the first
authenticated record happens only on later stream I/O
(`crates/xray-vless-encryption/src/stream.rs:402-488`). Ticket expiry is checked
when the resumption is prepared, not while it waits for confirmation
(`session.rs:89-110`). The existing deadline regression covers a cold
handshake (`src/tests.rs:284-293`).

Impact: in the public crate, a blackhole peer can retain the carrier, lease,
ticket/PFS, and AEAD state until the caller supplies its own I/O deadline. Early
data prepared before expiry may be sent after expiry and then lost if the peer
rejects it. Core call sites have outer open/idle policies, which lowers the
integrated impact.

Required remediation: carry a bounded confirmation deadline in the resumed
stream or make the caller-owned deadline contract explicit and enforced at all
core call sites. Add paused-time tests for a blackholed peer and expiry between
`connect()` and first write/read.

### IR-10: some VLESS credential/ticket copies are not zeroized — Low

The cached resumption ticket is held in `Zeroizing<[u8; 16]>`, but the handshake
copies it to an ordinary `Vec` and appends an AEAD tag
(`crates/xray-vless-encryption/src/handshake.rs:141-147`). Reallocation can
leave the plaintext ticket in freed allocator memory. The VLESS UUID is also
stored as a normal `Uuid`, encoded into an ordinary header `Vec`, and written
without clearing that buffer (`crates/xray-config/src/model.rs:674-679`;
`crates/xray-proxy/src/vless/wire.rs:59-74`;
`crates/xray-core-rs/src/outbound.rs:3814-3823,3898-3911`).

Impact: crash dumps, allocator reuse, or another same-process memory disclosure
can recover credentials after their required-use lifetime. No remote read
primitive was identified. The UUID residual was already described by the v0.5
credential-boundary audit; the ticket copy is new to v0.6.

Required remediation: use a capacity-reserved `Zeroizing<Vec<u8>>` for the
ticket and clear request-header buffers after completion or cancellation. Add
fault/cancellation lifetime regressions.

### IR-11: FFI returns string panic payloads verbatim — Low

The panic boundary converts `&str` and `String` payloads directly into a public
FFI error (`crates/xray-ffi/src/lib.rs:3618-3643`). No current production panic
containing a key or complete configuration was identified, but a future assert
or dependency panic can cross into a mobile log with its payload intact.

Required remediation: return a fixed public panic message, retain detail only
in a separately controlled diagnostic channel, and add a marker-secret test.

### IR-12: Android memory-pressure paths can terminate the VPN process — Low

JNI entry points allocate `std::string`, `std::vector`, and `unique_ptr` without
a C++ exception boundary, and at least one `NewLongArray` result is used without
an explicit null check (`platform/android/xraymobile/src/main/cpp/
xray_mobile_jni.cpp:113,266,834,1183`). Allocation failure can therefore escape
through an `extern "C"` JNI frame or dereference a null JNI result.

The device-gate encrypted profile loader also calls `AtomicFile.readFully()`
before applying its 1 MiB limit
(`platform/android/devicehost/src/main/java/org/xrayrust/devicehost/
EncryptedProfileStore.kt:46-55`). A corrupted or oversized private file can
allocate enough memory to kill the process before validation.

Required remediation: contain C++ exceptions at every JNI entry point, check
JNI allocation/exception results, use bounded file reads, and add OOM and
oversized-file fault-injection tests.

### IR-13: the canonical workspace test gate was not deterministic — Low

With loopback access permitted, the documented command

```sh
cargo test --workspace --exclude xray-rust-fuzz --all-targets --locked
```

failed three runtime-data-path tests in a parallel run:

- `tun_tcp_timings_record_when_runtime_logger_enabled`;
- `tun_reality_bridge_panic_isolated_and_logged_without_stopping_runtime`;
- `tun_regular_vision_udp443_storm_releases_flows_with_logging_on_and_off`.

Each test passed when rerun individually. The relevant definitions are at
`crates/xray-core-rs/tests/runtime_data_path_tests.rs:2379,2459,3445`.

Impact: this is not a demonstrated runtime vulnerability, but a release gate
that intermittently fails or passes cannot be treated as reproducible evidence.
The symptoms involve timeouts/global logging and therefore overlap lifecycle
and failure-observability assertions that matter to the security case.

Required remediation: remove shared global-state/test-port contention or
serialize the affected fixtures, then require repeated green canonical runs on
the clean candidate.

## Positive results

The review confirmed the following controls:

- VLESS encryption configuration is canonical, bounded, and fail closed;
  unsupported encryption, security, and transport combinations do not silently
  fall back to plaintext in the Rust runtime.
- Relay keys are chained in order, the final NFS authenticates the handshake,
  peer PFS is consumed only after authentication, and client/server AEAD state
  is directionally separated.
- Clear record headers are authenticated as AAD; plaintext is not released
  before tag verification; corruption poisons the stream; and nonce wrap
  rekeys only through an authenticated record.
- Ticket and padding fields are authenticated. A new ticket is published only
  after authenticated peer padding; failed/cancelled resumption invalidates its
  lease and does not automatically replay early data.
- Record, relay, padding, address, and configuration allocations have explicit
  bounds. `IPOnDemand` caps address work at 256 and preserves the original
  destination after ordered rule evaluation.
- The C ABI catches Rust panics, clears owned error strings on free, documents
  raw-handle concurrency preconditions, and keeps TUN/socket callback ownership
  ordered. The Swift lifecycle gate serializes destructive transitions.
- TUN reads are bounded, Darwin output validates IP version, runtime log records
  escape control characters, and secure log paths reject symlink traversal.
- Apple profile material uses a non-sync, device-only Data Protection Keychain
  item. The Android device harness uses Keystore AES-256-GCM with AAD and
  no-backup storage.
- GitHub Actions are pinned to full commit SHAs. `shaped-rustls` is pinned to
  commit `3a131beaef0183b0cb61e5a9070a703b6be39ed3`, and arbitrary Git sources are
  denied by policy.

## Executed evidence

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Pass |
| `git diff --check` | Pass |
| workspace Clippy with `-D warnings`, `perf`, and `suspicious` | Pass |
| `cargo audit` | Pass: zero known vulnerabilities; one allowed unmaintained warning for `proc-macro-error2` (`RUSTSEC-2026-0173`) |
| `cargo deny --locked check advisories bans licenses sources` | Pass; duplicate-version warnings remain |
| `scripts/check-vless-encryption-oracle.sh` | Pass: library/fuzz-driver, live Go 1-RTT/0-RTT, runtime, negative, and full-Xray matrices |
| Full-Xray VLESS carrier matrix reported by the oracle | Pass: 540 application flows across 204 profiles |
| `scripts/check-routing-oracle.sh` | Pass: 23 cases against exact Xray-core commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c` |
| Swift package tests for the v0.6 adapter tree | Pass: 299/299 |
| Canonical Rust workspace test | Not clean: three parallel failures; each passed in isolation |

The local Android AAR/Gradle build, physical-device scenarios, and long-running
sanitizer/fuzz/performance gates were not rerun as part of this assessment.
Their absence cannot be replaced by source inspection.

## Release decision and required closure

The current development increment may continue, but it must not be tagged as an
RC. Before an independent RC sign-off:

1. Freeze a clean, immutable candidate and publish its commit/tree plus complete
   source and vendored-tree manifests.
2. Close IR-01 through IR-03. These High findings are unconditional release
   blockers.
3. Close or explicitly risk-accept IR-04 through IR-12 with an owner, rationale,
   regression, and expiry date. IR-04, IR-05, and IR-06 should be closed before
   accepting any remaining supply-chain risk.
4. Stabilize IR-13 and obtain repeated green canonical workspace runs.
5. Run the roadmap's exact-candidate pinned interop, ASan, Miri, Loom, extended
   fuzz, controlled-network, supply-chain, Apple, four-ABI Android, and clean
   performance gates.
6. Produce candidate-bound physical Apple and Android evidence for VLESS
   encryption, `IPOnDemand`, cancellation, and the changed adapter lifecycle.
7. Repeat this review on the final delta. Any wire, cryptographic primitive,
   unsafe/FFI ownership, vendored dependency, or release-workflow change
   invalidates the corresponding part of this assessment.

At the time of this review, milestones D and E (`downloadSettings`
completeness and configuration tooling/maintainability) were also unfinished.
That product scope was separate from the findings above and independently
prevented a v0.6 feature freeze. Subsequent implementation status is recorded
in [the increment plan](v06-implementation-plan.md); completion of those
increments does not replace review of the final candidate delta.

## Remediation verification — 2026-09-05

All source-level and release-pipeline defects identified by this review have
been remediated. IR-01 is closed at the control-design level: a v0.6 publication
now depends on an exact commit/tree-bound evidence workflow, strict manifest
validation, artifact hashes, physical Apple and Android runs, and
direction-aware performance thresholds. It cannot be operationally satisfied
until those results exist for the final clean candidate. This is an outstanding
release-evidence condition, not an unimplemented bypass.

| ID | Remediation status | Enforced closure |
| --- | --- | --- |
| IR-01 | Control closed; candidate evidence pending | Exact revision/tree evidence schema, fail-closed artifact validation, performance comparison direction, and mobile publication dependency |
| IR-02 | Closed | Apple artifact workflow run, head repository, commit/tree, artifact identity, expiry, and SHA-256 are bound to the mobile release |
| IR-03 | Closed | Strict Gradle verification plus canonical HTTPS repository and published-sidecar validation for main and consumer builds |
| IR-04 | Closed | Vendored BLAKE3 and H3/QUIC trees are checked against exact upstream archives and the declared local patch |
| IR-05 | Closed | Core Gradle artifacts are checked against canonical repository content and recorded SHA-256 values; a legacy weak sidecar is accepted only when the repository publishes no stronger sidecar |
| IR-06 | Closed | AAR ZIP structure, manifest, permissions, native dependencies, JNI exports, size, compression, and four-ABI surface are exact-allowlisted |
| IR-07 | Closed | Mobile builds reject any tracked or untracked change in the pinned core checkout, with clean/dirty regression tests |
| IR-08 | Closed | Full-history Gitleaks scanning is mandatory and pinned in mobile CI/release policy |
| IR-09 | Closed | Resumed 0-RTT confirmation remains inside the handshake deadline and has a paused-time expiry regression |
| IR-10 | Closed | VLESS request headers and resumption-ticket material use zeroizing storage |
| IR-11 | Closed | FFI panic payloads are replaced by a fixed redacted public error and covered by tests |
| IR-12 | Closed | Encrypted-profile reads are bounded before allocation; JNI entry points contain exceptions and explicitly handle allocation failures |
| IR-13 | Closed | The canonical workspace suite passes, including three repeated parallel runtime data-path runs and isolated former failure cases |

Remediation verification included:

- the locked full Rust workspace test suite and strict workspace Clippy;
- 30/30 mobile-artifact tests, 17/17 VLESS-encryption tests, and 13/13 FFI
  library tests;
- seven evidence-validator tests and the scheduled-workflow policy test;
- canonical online provenance validation for core and mobile Gradle metadata;
- a cold strict four-ABI Android release build, exact AAR verification, Android
  unit tests, Maven staging publication, and a minified consumer build;
- eight mobile policy tests and a full-history scan of all 42 mobile commits
  with pinned Gitleaks 8.30.1.

The release remains fail-closed until the final candidate is committed, clean,
and immutable and the roadmap evidence command accepts its real device and
performance archive. Any subsequent security-sensitive delta still requires
the scoped repeat review described above.

## Residual protocol risks

Even after the findings are closed, the supported protocol retains deliberate
properties that applications must account for:

- 0-RTT data can be replayed or lost and must be application-idempotent;
- EOF at an authenticated-record boundary does not prove application-message
  completeness;
- Vision direct-mode integrity depends on the real inner TLS/REALITY carrier;
- VLESS UUIDs are required-use credentials retained for the outbound lifetime;
- multi-node replay-state behavior and multiple concurrent leases of one ticket
  need deployment-level evidence in addition to single-process tests.

`SECURITY.md` should continue to state that the project has not received an
independent security **audit** until an external audit is actually commissioned
and completed. This review satisfies a focused independent engineering-review
step; it does not make that broader claim.
