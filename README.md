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

## Stable 0.7.0 publication completed

- [Core source release](https://github.com/aimalygin/xray-rust/releases/tag/v0.7.0): exact commit `67969094b352f948c6b8b9e2ac75402c577cb7f7`, annotated tag object `f1c59308012efad0e7b9b60c2a9976906b9dba9b`.
- [Mobile SDK release](https://github.com/aimalygin/xray-rust-mobile/releases/tag/v0.7.0): exact commit `82dd22531256e5d089917e55e9588f29e525f542`, annotated tag object `4a0aa16ec5116d1c1a6721b7cbf923a1cb850ae2`. GitHub reports the SDK release immutable. The core source release does not have that GitHub flag; its tag and every uploaded asset were independently verified.
- Maven Central coordinate: `io.github.aimalygin:xray-rust-mobile:0.7.0`. [Publication workflow](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36359920594) confirmed PUBLISHED. All five anonymously downloaded Maven files match the immutable SDK release bundle.

Final core candidate CI, versioned evidence and tag CI passed on the exact core release commit: [36344835351](https://github.com/aimalygin/xray-rust/actions/runs/36344835351), [36344840384](https://github.com/aimalygin/xray-rust/actions/runs/36344840384), [36355379619](https://github.com/aimalygin/xray-rust/actions/runs/36355379619). The narrowly scoped scanner correction in merged PR #39 recognizes nine historical file digests; runtime and dependencies remained unchanged.

Canonical Apple producer job 108723554449 in [36355936115](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36355936115) passed on source fba37e6. Its later automatic PR creation failed because Actions cannot open PRs in this repository. The exact generated checksum branch was reviewed and merged through PR #32; permissions were not changed. The full source CI and exact tagged SDK CI passed. [Stable SDK release workflow](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36357889566) passed all eight jobs and verified downloaded release bytes plus the GitHub Packages mirror.

Independent public consumers passed on this Mac:

- SwiftPM resolved remote version 0.7.0 and the exact SDK commit, downloaded its public XCFramework, linked all three Swift products, and executed ABI 1.7 plus Hysteria2/WireGuard capability and profile-import checks.
- A fresh Android dependency cache resolved 0.7.0 from Maven Central with exact SHA-256 verification. The release app built with R8; all four ABIs contain both native libraries and the merged manifest contains one correctly declared application VPN service. This is a consumer build check, not a new physical-device campaign.

`publication-confirmation.json` identifies the public assets, workflows and 59 retained confirmation files. `v07-publication-confirmation.tar.gz` includes those files and its internal manifest: complete CI logs, release identities, public-consumer source/logs and verification tooling. The previous measured and automated archives remain byte-for-byte unchanged in this branch's history. Original failures and accepted limitations remain applicable, including the Android cellular waiver, rare timeout decision and deferred performance gaps.

SHA-256 of the final confirmation archive:
`89b16f66f06ae83867bdea256da20af0c95affa1227f771dd7ef29497b455283`.

The complete confirmation archive was scanned through nested CI log archives. Four matches are the two public artifact SHA-256 values, verified by recomputing both original archives; there are no unexplained findings. `publication-secret-scan-review.json` records this review. Scanner rules and repository security configuration were not changed.
