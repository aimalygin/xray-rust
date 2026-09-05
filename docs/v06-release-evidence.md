# v0.6 release evidence

The v0.6 release pipeline accepts only a bounded ZIP produced for the exact
clean release-candidate commit. The authoritative schema and security checks
are implemented by `scripts/check-v06-release-evidence.py`.

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
