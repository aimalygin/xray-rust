# v0.6 release evidence

The v0.6 release pipeline accepts only a bounded ZIP produced for the exact
clean release-candidate commit. The authoritative schema and security checks
are implemented by `scripts/check-v06-release-evidence.py`.

## Published v0.6.0-rc.1

Matching [core](https://github.com/aimalygin/xray-rust/releases/tag/v0.6.0-rc.1)
and [mobile SDK](https://github.com/aimalygin/xray-rust-mobile/releases/tag/v0.6.0-rc.1)
prereleases are published; publication and public-consumer verification
completed on 2026-09-08 UTC. The selected Milestones A–E scope is frozen.
`v0.5.0` remains the stable release. This record closes the RC evidence work;
it does not promote either package to stable or authorize registry publication.

### Exact source and automated gates

| Record | Immutable identity or result |
| --- | --- |
| Core commit | `1e713ca3e6c57be5747b4915b31e0db040a01c0c` |
| Core tree | `69fe0a56ce5bcbd178d8326e32d15dfab660b99c` |
| Core annotated tag object | `3578dda8475198f19d6be97f310769c36794e9e1` |
| Mobile commit | `5a00f89a444f017030c2c6fcf04baabbb9f671f9` |
| Mobile annotated tag object | `a9a1eb9d2c56d301bb45449fe052dba2b03e42e6` |
| Reference Xray-core | `v26.7.28`, commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c` |
| [Core release CI](https://github.com/aimalygin/xray-rust/actions/runs/34168235914) | All 12 required gates and source publication passed on the recorded core commit |
| [Candidate evidence validation](https://github.com/aimalygin/xray-rust/actions/runs/34168148305) | Physical Apple/Android and performance archive passed exact commit/tree validation |
| [Mobile release CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/34177249987) | All seven required jobs passed; Maven publication was skipped by RC policy |

Core CI includes pinned Go oracles and release interop, ASan/Miri/Loom,
bounded fuzz campaigns, controlled RTT/loss, dependency/provenance checks,
Rust tests/lints, Apple builds and four-ABI Android verification. Scheduled
broad interop and upstream-main smoke were skipped by the tag workflow;
they are not included in the passing-gate claim.

The [published evidence ZIP](https://raw.githubusercontent.com/aimalygin/xray-rust/278d4d2324a689815641ec2d13acdc8e0244ec28/v06-release-evidence.zip)
is pinned to commit `278d4d2324a689815641ec2d13acdc8e0244ec28`, with SHA-256
`5dab7e06b72af9a8fef1524a7271afe97ca8ff0df893c46a8ab7678921cec490`.
Its nine members comprise the manifest, six device artifacts and two
performance artifacts. The downloaded public ZIP matched the reviewed bytes.
The [candidate integration review](v06-candidate-review.md) records the final
source/release-tooling review following IR-01–IR-13 remediation; this is not a
contracted external security audit.

### Physical and performance coverage

Each physical device passed all five required scenarios: VLESS encryption,
`IPOnDemand`, independent XHTTP download/session lifecycle, cancellation and
host adapter projection. Both used the same recorded core commit.

| Device | OS | Campaign duration | Observed resident-memory growth | Thread growth | Fatal errors / unrecovered transitions |
| --- | --- | --- | --- | --- | --- |
| iPhone 13 | iOS 18.6.2 (22G100), arm64 | 188 s | 1,998,848 bytes | 0 | 0 / 0 |
| Samsung SM-A145F | Android 15 (API 35), arm64-v8a | 260 s | 8,990,720 bytes | 0 | 0 / 0 |

Each declared a maximum resident-memory growth of 33,554,432 bytes and thread
growth of 8; fatal errors and unrecovered transitions had zero tolerance.
The timelines record connect, traffic, cancellation and disconnect behavior,
including an `AsIs` negative control and the supported host adapter paths.
They do not represent Wi-Fi/cellular transitions or recovery from process death.

The clean release-profile feature gate used five fresh-process samples for
each measurement and passed every declared threshold:

| Measurement | Median | Required bound |
| --- | --- | --- |
| Direct SOCKS process throughput | 518.43 MiB/s | At least 10 MiB/s |
| Encrypted VLESS throughput | 277.03 MiB/s | At least 241.43 MiB/s (half the matched plaintext baseline) |
| `IPOnDemand` connection-and-echo latency | 0.210 ms | At most 1.221 ms (matched direct baseline plus 1 ms) |
| XHTTP peak resident memory, 32 split sessions | 19.08 MiB | At most 64 MiB |

The calibrated v0.5 regression-performance gate also passed on the same clean
core commit. The measurements above use the named local workloads documented
below; they are not WAN performance or new cross-product benchmark claims.
Long soak tests were omitted by owner decision. Six-hour operation, WAN,
network switching, sleep/wake, energy/thermal behavior and process-death
recovery are not established by these campaigns.

### Published mobile artifacts and consumers

The mobile release is immutable on GitHub and contains exactly six assets:
`XrayRust.xcframework.zip`, `xray-rust-mobile-0.6.0-rc.1.aar`, `LICENSE`,
`THIRD_PARTY_NOTICES.md`, `release-manifest.json` and `SHA256SUMS`.
All six public downloads were verified against GitHub asset digests; the
checksum file, manifest provenance and tagged licenses also matched.

- Apple ZIP SHA-256:
  `868abc6eabff884c6fb058b53e8a0ed5d7cd3dda1e6fc7349b3957f766cdc3eb`.
  It matches the canonical artifact from the successful Apple producer job in
  [Prepare release 34171517903](https://github.com/aimalygin/xray-rust-mobile/actions/runs/34171517903),
  built from commit `18bae4a2266854880f9f534c5189abe03e9cadf7` and tree
  `edd9264d233fcc4c13baa4e1f74137e560a1e329`. The parent preparation workflow
  reported failure only because the Actions bot could not open a PR; the
  documented manual path completed through [checksum PR #24](https://github.com/aimalygin/xray-rust-mobile/pull/24)
  after all four checks passed.
- Public Android AAR SHA-256:
  `3ef46a76886ca3b70028d16929f3fb4a53ca430f9368e470ed1dd49ec5dd3648`.
  This is the artifact rebuilt by the release workflow, distinct from the
  earlier local preparation build.
- After publication, a clean SwiftPM consumer resolved exact version
  `0.6.0-rc.1` at the recorded mobile commit, downloaded the public XCFramework,
  linked all three SDK products and executed a native FFI call reporting ABI
  `1.4`. No local XCFramework override was present in the dependency checkout.
- A separate Android consumer used the downloaded standalone AAR and passed
  release APK assembly with minification and strict dependency verification.
  Its merged VPN manifest and all eight native libraries across arm64-v8a,
  armeabi-v7a, x86 and x86_64 were checked. These consumer checks ran on a macOS
  host and are separate from the earlier physical-device campaigns.

The RC is distributed through GitHub only; neither Maven Central nor GitHub
Packages received an RC coordinate. Subsequent documentation/main integration
does not retag these releases or transfer their device evidence to a different
core commit. A changed candidate must follow the exact-source procedure below.

## Required evidence

Before connecting physical devices, freeze the sources on
`codex/v06-candidate` with the intended RC package version, dated changelog and
regenerated configuration contract already committed, then push that branch.
Changing release metadata after collecting evidence would invalidate the
commit/tree binding. Create the annotated RC tag only after all required
evidence passes, without changing that commit. CI runs the ordinary Rust, pinned
Go oracle, dependency, Apple, and four-ABI Android checks, plus the complete
RC interoperability, Loom/Miri/ASan, fuzz, and controlled-network jobs on the
same commit. Record the successful run URL, commit, and tree. A manual CI
dispatch also runs these gates. Neither candidate mechanism publishes a
release or requires device evidence; publication remains exclusive to an RC
tag push and still requires the validated archive below.

Run clean release-profile performance measurements on that commit before
the device campaign. Any source fix requires a new candidate and a fresh
automated run; do not combine results from different commits.

`manifest.json` must identify the candidate's full commit and tree with
`dirty: false`. It must contain exactly one physical Apple report and one
physical Android report. Each device report covers exactly these scenarios:

- `vless-encryption`;
- `ip-on-demand`;
- `xhttp-download-session`;
- `cancellation`;
- `host-adapter-projection`.

Every scenario records a positive duration, a non-empty transition timeline,
and passing traffic and overall results. Each device declares and stays within
explicit limits for resident-memory growth, thread growth, fatal errors, and
unrecovered transitions. Fatal and unrecovered transition limits are zero.

The clean release-profile performance report contains at least five samples
for each of these measurements:

| Measurement | Required comparison |
| --- | --- |
| `process-throughput` | median at least the declared threshold |
| `vless-encryption-throughput` | median at least the declared threshold |
| `ip-on-demand-latency` | median at most the declared threshold |
| `xhttp-memory` | median at most the declared threshold |

Comparison directions are fixed by the validator, so an evidence producer
cannot make a throughput regression pass by changing it to an upper bound.

On the macOS publication host, run both collectors from the frozen checkout:

```sh
bash scripts/run-v05-pre-device-benchmarks.sh /tmp/v06-regression-performance
python3 scripts/run-v06-feature-benchmarks.py /tmp/v06-feature-performance
```

The first preserves the previously calibrated regression budgets. The second
adds five fresh-process repetitions against the pinned local Xray server and
records the binary, lockfile, harness, commit and tree provenance. Its initial
feature budgets are declared before running the candidate:

- Direct SOCKS TCP: at least 10 MiB/s, using 32 MiB of verified echo payload.
- Encrypted raw VLESS: at least half the matched plaintext VLESS throughput;
  both use the same server, payload and candidate. This bounds the additional
  encryption cost; it is not a WAN throughput or handshake-latency claim.
- `IPOnDemand`: median connection-and-echo latency no more than 1 ms above the
  matched direct baseline, with a local DNS hosts entry and 100 timed flows.
  The default route cannot carry traffic, so success also checks IP selection.
- XHTTP: peak RSS at most 64 MiB with 32 live split sessions, H1 packet upload
  and a separate authenticated TLS/H2 download pool, held for 30 seconds.
  This is a host envelope; device-specific growth budgets remain separate.

Use the collector's `performance.json` as the manifest's `performance` object
and include its two hashed artifacts. Keep the regression report with the CI
run record. These are initial v0.6 feature envelopes, not historical v0.5
comparisons for features that did not exist there; future candidates retain
the same workload and budgets unless a reviewed change justifies an update.

Device reports each reference exactly `resource-profile`, `sanitized-log`, and
`transition-timeline` artifacts. The performance report references exactly
`benchmark-raw` and `build-manifest` artifacts. Every referenced file has a
lowercase SHA-256 in the manifest, and no additional file is allowed in the
archive.

## Validate and submit

Build the ZIP without symlinks, duplicate names, encrypted members, traversal
paths, or unlisted files. The compressed and expanded archive limits are both
256 MiB. Then validate it locally against the frozen candidate:

```sh
candidate="$(git rev-parse HEAD)"
tree="$(git rev-parse 'HEAD^{tree}')"
test -z "$(git status --porcelain --untracked-files=all)"
python3 scripts/check-v06-release-evidence.py evidence.zip "$candidate" "$tree"
shasum -a 256 evidence.zip
```

Place the immutable ZIP at an HTTPS URL and dispatch the GitHub Actions
workflow **v0.6 release evidence** on that exact candidate, supplying the URL
and ZIP SHA-256. The workflow revalidates the archive and retains it under the
candidate-specific artifact name.

An RC tag can publish only when the blocking CI run finds that successful
workflow at the same commit, downloads its retained artifact, and revalidates
it against the tag's commit and tree. The mobile v0.6 release independently
requires the same successful, non-expired core evidence run and artifact for
its locked core commit and tree.
