# v0.6 candidate integration review

Date: 2026-09-05. Scope: Milestones D/E and the pre-device release gates,
following the independent development-tree review and its IR-01–IR-13
remediation. This is an integration review, not an additional independent
cryptographic audit or physical-device sign-off.

The D review checked the bounded download parser, alias/extra precedence,
diagnostic remapping, rejection of recursive/chained downloads and protected
upload/plaintext download combinations, independent connector and pool
ownership, shared session identity, socket protection, failure propagation,
and cancellation cleanup. Freedom and DNS reject non-raw transports during
runtime compilation. The split-carrier regression tests and pinned full-Xray
matrix exercise the corresponding runtime boundaries.

The E review checked that discovery and validation use the parser's shared
field registry, that the extracted DNS/stream parser bodies preserve their
previous behavior, and that file/stdin, geodata lookup, diagnostics and exit
codes are consistent. The machine contract explicitly limits validation to
the parser; runtime graph compilation, host policy and network reachability
remain outside that result. No C ABI entry point or header was changed.

Release-tooling findings addressed during candidate verification:

- The first clean GitHub checkout exposed five omitted upstream BLAKE3
  files: its crate lockfile and four CMake modules. They existed locally but
  were hidden by the vendored ignore rules (including a case-insensitive
  `blake3` directory match on macOS). The canonical files are now tracked;
  provenance validation also rejects untracked files, including ignored
  files, in either vendor tree before comparing the pinned archives. This
  guard reproduced the omission locally and passed after the files were
  added to the index. Runtime Rust sources and dependency versions did not
  change as part of this correction.
- Host hardening, fuzz and controlled-network jobs previously required an RC
  tag. The candidate branch and manual CI now run these same checks before
  device evidence exists. Executed classifier regressions distinguish RC tag
  pushes, stable tags, similarly named branches, manual tag runs and ordinary
  CI. Only RC tag pushes can enter the publication/evidence path.
- The fuzz runner removed crash reproducers on failure. Failed local runs and
  every CI campaign now retain evidence, with an always-run artifact upload.
  A deliberately failing mock target verifies both exit status and retained
  reproducer contents without substituting for a real fuzz campaign.
- The new split-XHTTP oracle omitted the bounded REALITY listener warm-up
  already used by the other interop gates. A cold run completed its first 60
  profiles and then saw an HTTP/2 reset on the first REALITY contact; an
  isolated unchanged rerun passed all 66. The matrix now requires a successful
  preparation probe through the exact split profile (at most two attempts),
  then creates fresh pools and DNS/protection counters for the measured
  scenario. Its 264 asserted application flows are never retried. Persistent
  preparation failures and TCP scenario I/O failures include the Go server log.

The clean feature-performance collector adds actual process measurements for
the four v0.6 release metrics. Its workload, baseline comparisons and initial
budgets are documented in [release evidence](v06-release-evidence.md). It does
not produce device results. The calibrated v0.5 regression gate also remains
required.

The frozen sources include the intended `0.6.0-rc.1` package version, lockfile,
dated changelog and regenerated configuration contract. This prepares the
candidate without publishing a tag; a later version-only commit would break
the exact-commit evidence binding and require all campaigns to be repeated.

This document is source-review context, not evidence that a future commit has
passed. Bind the automated run, raw benchmarks and physical-device campaign
to the frozen full commit and tree. A fix invalidates that candidate's combined
gate result and requires a new run.

Publication update (2026-09-08 UTC): the frozen core commit
`1e713ca3e6c57be5747b4915b31e0db040a01c0c` passed the complete release CI and
exact-candidate archive validation, including both physical-device reports and
performance artifacts. Matching core/mobile `v0.6.0-rc.1` prereleases are
published. See [release evidence](v06-release-evidence.md#published-v060-rc1)
for the immutable inputs, artifact verification and explicit coverage limits.
This closes the RC evidence condition; it does not extend this review to a
future revision or constitute an external security audit.
