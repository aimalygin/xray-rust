# 0.7.0 stable release evidence

Measured core: `353316687b22c2fabbaf37ab5668dda05a972f46`, tree
`f5aacb1fb5a5bbda9eac83a7330059219ce6b0ce`, clean, version 0.7.0-rc.1.
The owner selected direct stable publication without a public RC.

Archive: `v07-release-evidence.zip`, SHA-256
`b10aa3e1c6c0451f0d52b0ed13b0272d805fb88cbdbebd94f7c7069cb531330b`.
Schema 3 result: **accepted-with-exceptions**. It contains 12 top-level files,
including 1,079 files in the comparison/diagnostic package plus the original
historical protocol archive. Original source identities and failures remain intact.

- iPhone 17 Pro Max: nine scenarios, including both protocols, cellular/Wi-Fi,
  lock/wake, legacy transports and retained features; RSS growth 3.25 MiB,
  native thread growth 0, fatal/unrecovered errors 0.
- Samsung SM-A145F: eleven scenario groups, both protocol adapter paths,
  Wi-Fi lock/wake/reconnect, cancellation and resource recovery; maximum
  observed RSS growth 14,159,872 bytes (13.5 MiB), native thread growth 2,
  fatal/unrecovered errors 0 in the passing bounded campaigns.
- Four frozen release-budget gates passed five samples each. Historical
  comparisons, host noise, failed attempts and deferred performance gaps remain.
- Android cellular was **not tested**, by explicit owner decision.
- The investigated rare Android WireGuard timeout case is accepted for 0.7.
  No root cause or product fix is claimed. Official WireGuard had 0 / 3000
  timeouts, xray-rust 1 / 3000, direct UDP 1 / 5000; no statistical equivalence
  or complete CPU/RSS/throughput parity follows from those results.

The archive preserves measured candidate identity. The stable source validator
separately requires a clean descendant with only approved metadata/documentation
and evidence tooling changes. Runtime, dependency, ABI or build-input changes
require new evidence. No new physical-device campaign is claimed.

The assembler, manifest, scoped decisions (inside the archive), limitations and
checksums make the package reviewable. This evidence snapshot creates no release
tag and publishes no SDK package. Canonical builds and final CI are separate gates.

## Successful final automated validation

Core preparation: `eaad8a9359d6da8956d0e0699a60864ccd4be5e9`.
Mobile preparation: `9d656838822b930ba837ea78f14700818fca8453`.

- Full core release-branch CI: [36341111142](https://github.com/aimalygin/xray-rust/actions/runs/36341111142), all 11 applicable jobs passed.
- Core PR CI: [36341113954](https://github.com/aimalygin/xray-rust/actions/runs/36341113954), all 6 applicable jobs passed.
- Mobile PR CI: [36341138442](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36341138442), all 4 jobs passed, including Apple Swift product tests and the Android Maven consumer check.

`v07-automated-validation.tar.gz` retains 6,626 files: full logs for all three
runs, fuzz/network/contract artifacts, their GitHub identities and file hashes,
and the clean stable-source validation report. SHA-256:
`58cc5896662addd1a5dcb93002e3be2bf8d186bf0963205f50f89b2944a81885`.
The original measured ZIP above retains its exact bytes and source identity.
The assembly scripts use the original mobile workspace's Artifacts directory
layout; their manifests map the retained inputs.

Local validation also passed all 59 evidence/promotion tests, the complete
core repository-script checks, all 28 mobile release-script tests and the
mobile metadata/adapter synchronization checks.

## Publication status

Core PR #37 is ready and still requires one approving review under the main
branch protection rule. The owner is arranging that review. Mobile PR #31
retains an explicit preparation commit pin until the stable core tag exists.

After review/merge, the versioned evidence workflow must run on the exact final
core release source; the annotated tag and applicable tag CI must be verified.
Canonical SDK preparation, checksum locking, stable package publication and
consumer verification follow the existing two-phase release process. No release
tag or package has been published by this preparation. The retained measurements
remain accepted-with-exceptions, and no new physical-device run is claimed.
