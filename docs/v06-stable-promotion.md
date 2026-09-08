# v0.6.0 stable promotion

Status: preparation and final automated verification in progress, authorized
by the owner on 2026-09-08. The published packages remain `v0.6.0-rc.1` until
stable release publication completes. Milestones A–E and RC distribution are
complete; see [published RC evidence](v06-release-evidence.md#published-v060-rc1).

## Application acceptance

On 2026-09-08 the owner reported completing the proposed real-application RC
checks: profile import, connect, disconnect and reconnect. No corrective issue
was reported in that acceptance message. The application, platform and raw
logs were not supplied; this is an owner report, not an additional instrumented
device campaign or automated test result.

The owner also removed long device soak checks from the current work list.
The completed bounded iPhone 13 and Samsung campaigns remain the device
evidence. Their exclusions and resource limits remain unchanged.

## Source and evidence boundary

The measured core remains commit `1e713ca3e6c57be5747b4915b31e0db040a01c0c`,
tree `69fe0a56ce5bcbd178d8326e32d15dfab660b99c`, annotated RC tag object
`3578dda8475198f19d6be97f310769c36794e9e1`. Its
[public evidence ZIP](https://raw.githubusercontent.com/aimalygin/xray-rust/278d4d2324a689815641ec2d13acdc8e0244ec28/v06-release-evidence.zip)
has SHA-256 `5dab7e06b72af9a8fef1524a7271afe97ca8ff0df893c46a8ab7678921cec490`.

`scripts/check-v06-stable-promotion.py` verifies the original ZIP and exact
RC tag, commit and tree. It requires a clean stable checkout descended from
that RC. All runtime, adapter, build and dependency files must match the RC;
only an explicit list of documentation/release-tooling files may differ.
`Cargo.toml` may change only the workspace version, `Cargo.lock` only matching
workspace-package versions, and the generated contract only `coreVersion`.
New source files, compiler flags, dependency changes, removed files and file
mode changes are rejected. The original exact-candidate validator is unchanged.

The existing `v0.6 release evidence` workflow runs on the stable source and
retains the original RC archive plus a validation report distinguishing the
stable commit from the measured candidate. Stable tag CI repeats that check.
The mobile SDK still requires a successful evidence run/artifact bound to
its exact locked stable core commit and tree.

## Remaining release work

- Run the full automated core release matrix on the final stable revision and
  publish the annotated source-only `v0.6.0` GitHub release after it passes.
- Pin the mobile SDK to that stable core tag/commit/tree and prepare the
  canonical Apple archive, checksum PR and final Apple/Android release tests.
- Publish the immutable mobile GitHub release and GitHub Packages mirror,
  then the signed `io.github.aimalygin:xray-rust-mobile:0.6.0` Maven Central
  coordinate through the protected publishing environment.
- Verify public hashes/provenance and clean SwiftPM/Maven Central consumers.

Publication is authorized by the owner. Required GitHub reviewer/environment
approvals remain explicit checks; previous one-time PR review bypasses do not
apply to new PRs. Existing RC tags and assets must remain unchanged.
