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

This document is source-review context, not evidence that a future commit has
passed. Bind the automated run, raw benchmarks and subsequent physical-device
campaign to the frozen full commit and tree. A fix invalidates that candidate's
combined gate result and requires a new run. Release remains blocked until
both physical-device reports and performance artifacts pass the existing
exact-candidate archive validator.
