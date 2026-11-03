# 0.9.0 release preparation

Requested on 2026-11-01 in
[#136](https://github.com/aimalygin/xray-rust/issues/136). The owner chose
0.9.0 over 0.8.2 for the scope below. Published on 2026-11-03 as core
[v0.9.0](https://github.com/aimalygin/xray-rust/releases/tag/v0.9.0) and SDK
[v0.9.0](https://github.com/aimalygin/xray-rust-mobile/releases/tag/v0.9.0).

The candidate is the 0.9.0 release commit: `main` through
`96cff12be7ad9a902191739f4c0648e18a66f96a` plus the workspace version,
lockfile, generated configuration contract, dated changelog section and this
document: revision `30928ad51b4a434546cf143f8e385a8746523172`, tree
`e55a6c3f021643bd507a611c247f2781aaabbb83`, merged in
[#150](https://github.com/aimalygin/xray-rust/pull/150). Every later step
binds to them; documentation commits after it do not replace that identity.
The README install snippets use 0.9.0 now that its packages are published.

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

On 2026-11-02 the owner limited performance to the 13 schema-4 metrics, with
the full comparison against 0.8.1 planned for 0.9.1, and accepted the known
limitations in the [0.9.0 decision record](releases/v0.9.0-owner-decisions.json):
REALITY fingerprints without ML-KEM, SOCKS UDP relay ports on the server,
Shadowsocks xchacha20-poly1305 at 59% of Xray-core throughput and the
campaign-local harness fixes. Asked whether to release 0.9.0 with these
limitations and publish the evidence, the owner answered “Да, публикуй”.

## Remaining work, in order

1. ~~Extend the Apple and Android device fixtures and harnesses to the three
   new protocols and their links.~~ Done in
   [#149](https://github.com/aimalygin/xray-rust/pull/149); see
   [v0.9 evidence collection](v09-release-evidence.md).
2. ~~Bump the workspace to 0.9.0, date the changelog section and regenerate
   the configuration contract.~~ Done in the release commit.
3. ~~Pin that exact revision in `xray-rust-mobile`, synchronize the canonical
   adapters, header and tests, add the `v09` profile there, and pass both
   repositories' CI.~~ Done in
   [xray-rust-mobile#42](https://github.com/aimalygin/xray-rust-mobile/pull/42),
   SDK candidate `9e030609c5734616cf79ee900abeaddfea0cfe0a`.
4. ~~Run full core release CI, collect the candidate-bound device and host
   evidence, and pass `v09-release-evidence.yml` on that exact commit.~~
   Release CI passed on the candidate
   ([run 41445033781](https://github.com/aimalygin/xray-rust/actions/runs/41445033781)).
   The device and host evidence is in the
   [2026-11-02 report](device-results/2026-11-02-v090-candidate/README.md) and
   the [archive record](releases/v0.9.0-device-evidence.json);
   `v09-release-evidence.yml` validated the archive on the candidate
   ([run 41562578452](https://github.com/aimalygin/xray-rust/actions/runs/41562578452)).
5. ~~Verify and publish the annotated core tag, then the SDK tag, XCFramework,
   four-ABI AAR and Maven artifacts; resolve the published packages from clean
   external consumers.~~ The annotated core tag `v0.9.0` (object
   `ceca89c26ae05878b9b9d970839723c2732a0bdb`) points at the candidate. Tag CI
   ([run 41569997838](https://github.com/aimalygin/xray-rust/actions/runs/41569997838))
   passed every job except `secrets`, which failed as expected because the tag's
   gitleaks policy predates the evidence allowlists;
   [`verify-source-tag.yml`](https://github.com/aimalygin/xray-rust/actions/runs/41574394029)
   rescanned the tag with the current policy and verified the other gates. The
   immutable [core release](https://github.com/aimalygin/xray-rust/releases/tag/v0.9.0)
   carries the source tarball, the device evidence and report archives, and
   the source and tag validation records. The SDK pinned the tag in
   [xray-rust-mobile#43](https://github.com/aimalygin/xray-rust-mobile/pull/43),
   locked the Apple artifact from
   [run 41574529308](https://github.com/aimalygin/xray-rust-mobile/actions/runs/41574529308)
   in [xray-rust-mobile#44](https://github.com/aimalygin/xray-rust-mobile/pull/44)
   and tagged the result `52fbde68` as SDK `v0.9.0`;
   [its release run](https://github.com/aimalygin/xray-rust-mobile/actions/runs/41582066264)
   published the immutable GitHub release and GitHub Packages. A clean SwiftPM
   project resolved `exact: "0.9.0"`, verified the XCFramework checksum and
   reported C ABI 1.15 with outbound probe cancellation and HTTP profile import.
   [Publish Maven Central](https://github.com/aimalygin/xray-rust-mobile/actions/runs/41636902197)
   released `io.github.aimalygin:xray-rust-mobile:0.9.0`; its AAR is
   byte-identical to the GitHub release asset (SHA-256 `8f882b5b…`). A clean
   Gradle project with only `google()` and `mavenCentral()` and an empty Gradle
   home resolved it, built the minified release APK with both native libraries
   for all four ABIs and kept the JNI callback names through R8.
