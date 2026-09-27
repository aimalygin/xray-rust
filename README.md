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
