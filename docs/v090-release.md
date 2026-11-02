# 0.9.0 release preparation

Requested on 2026-11-01 in
[#136](https://github.com/aimalygin/xray-rust/issues/136). The owner chose
0.9.0 over 0.8.2 for the scope below. Publication is pending.

The candidate is the 0.9.0 release commit: `main` through
`96cff12be7ad9a902191739f4c0648e18a66f96a` plus the workspace version,
lockfile, generated configuration contract, dated changelog section and this
document. Its exact revision and tree are recorded here once it merges; every
later step binds to them. The README install snippets keep the published
0.8.1 until the 0.9.0 packages exist.

## Scope

Everything merged into `main` since 0.8.1, listed under 0.9.0 in the
[changelog](../CHANGELOG.md). Highlights:

- SOCKS and HTTP outbounds with Swift/Kotlin link import, classic Shadowsocks
  AEAD, VLESS Mux, compatibility with Xray-core v26.10.21.
- The R8 keep rules for JNI classes, which every minified app built from
  `main` needs ([#125](https://github.com/aimalygin/xray-rust/pull/125)).
- Trust-store and zstd security updates.
- Transport memory and CPU reductions
  ([#132](https://github.com/aimalygin/xray-rust/pull/132)).
- Additive C ABI 1.13–1.15; no public Swift or Kotlin API was removed.

## Pre-release review

The review on 2026-11-01 covered `main` at
`49b3e34871602dc0bc188d0f7ea9cc0042a24ad2`. A manual CI dispatch with release
gates passed everything except `fuzz-smoke`, which had two breaks: the
vendored `h2` did not build with `--cfg fuzzing`, and the `profile_import`
target asserted against the import advisories. Both were fixed in
[#147](https://github.com/aimalygin/xray-rust/pull/147), which also makes
ordinary CI catch either kind of break. All release gates then passed on its
head.

## Evidence contract

Releases 0.9.x use the schema-4 `v09` profile in
[check-v09-release-evidence.py](../scripts/check-v09-release-evidence.py),
validated by [v09-release-evidence.yml](../.github/workflows/v09-release-evidence.yml).
The owner decided on 2026-11-01:

- **New client protocols take the full device transition set.** SOCKS, HTTP and
  classic Shadowsocks AEAD (`shadowsocks-aead`) each pass all twelve
  transitions on Apple, including Wi-Fi/cellular and lock/wake, and both TUN
  backends on Android. Each needs throughput, latency and memory comparisons.
- **HTTP proves UDP refusal.** HTTP `CONNECT` relays no UDP, here or in
  Xray-core, so HTTP replaces `ipv4-udp` and `ipv6-udp` with the negative
  controls `ipv4-udp-refused` and `ipv6-udp-refused`: every UDP probe through
  the HTTP outbound must go unanswered. SOCKS and classic Shadowsocks carry real
  UDP.
- **Android Wi-Fi/cellular and lock/wake remain not tested.** This is a new
  decision for 0.9, not the v0.8 decision carried forward; release known
  limitations must state it. The physical check for the Android network-change
  coordinator stays open in
  [#89](https://github.com/aimalygin/xray-rust/issues/89).
- Profile import covers the SOCKS, HTTP and classic Shadowsocks links plus
  malformed-input redaction. Trojan, SS2022 and VMess join the legacy
  regression with VLESS REALITY, XHTTP H1/H2/H3, Hysteria2 and WireGuard.

A v0.8 archive does not satisfy the profile, and v0.8 owner decisions are
historical records, not 0.9 decisions.

## Remaining work, in order

1. ~~Extend the Apple and Android device fixtures and harnesses to the three
   new protocols and their links.~~ Done in
   [#149](https://github.com/aimalygin/xray-rust/pull/149); see
   [v0.9 evidence collection](v09-release-evidence.md).
2. ~~Bump the workspace to 0.9.0, date the changelog section and regenerate
   the configuration contract.~~ Done in the release commit.
3. Pin that exact revision in `xray-rust-mobile`, synchronize the canonical
   adapters, header and tests, add the `v09` profile there, and pass both
   repositories' CI.
4. Run full core release CI, collect the candidate-bound device and host
   evidence, and pass `v09-release-evidence.yml` on that exact commit.
5. Verify and publish the annotated core tag, then the SDK tag, XCFramework,
   four-ABI AAR and Maven artifacts; resolve the published packages from clean
   external consumers.

Until those steps pass, there is no public 0.9.0 release.
