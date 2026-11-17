# 0.10.0 release preparation

Preparation started on 2026-11-11 on the owner's word, with `main` at
`fb3a27f57595e140128e219209bc0ca2a02d51a0`. 0.10.0 is published: the core
on 2026-11-15, the SDK and the KMP library on 2026-11-16. See
[Publication](#publication).
The shared steps are in the [release process](release-process.md); this page
holds what is specific to 0.10.0.

The candidate is the fourth 0.10.0 release commit: `main` through pull
request [#300](https://github.com/aimalygin/xray-rust/pull/300) plus the
changelog section, now dated 2026-11-15, and this document. The workspace
version, lockfile and generated configuration contract are already 0.10.0
from the first release commit and do not change. It merged as
`7eb199bba2562659fdbf0bcde9820e016dd8530c` (tree
`b637ff77211f6dc1aa865779d42b0325a7c7cc86`), the merge of
[#301](https://github.com/aimalygin/xray-rust/pull/301); every later step
binds to that commit and tree. The README install snippets keep the published
0.9.0 until the 0.10.0 packages exist.

### The candidate's qualification

- **CI.** The full release CI passed on the candidate (run 43748376213).
- **SDK.** `xray-rust-mobile` pins it by commit and tree since
  [xray-rust-mobile#52](https://github.com/aimalygin/xray-rust-mobile/pull/52)
  (`main` at `86abc0be5dcfc0a1b4f3b75b47e07a769135ca97`).
- **Devices and host.** The campaign of 2026-11-15 is in the
  [report](device-results/2026-11-15-v0100-candidate/README.md): the iPhone's
  runs against a public host and every Android run on the candidate, the
  iPhone's LAN runs carried over from the third candidate, the ten
  measurements of the gate and the comparison against 0.9.0.
- **Evidence.** The schema-5 archive is
  [v0.10.0-device-evidence.zip](releases/v0.10.0-device-evidence.zip), with
  its [record](releases/v0.10.0-device-evidence.json). The candidate's
  unchanged checker validates it, locally and in `v010-release-evidence.yml`
  on the candidate (run 43768546896).
- **Decisions.** Asked on 2026-11-15 «Выпускать 0.10.0 с этими ограничениями и
  публиковать свидетельства?», the owner answered «Да, публикуй». The
  [decision record](releases/v0.10.0-owner-decisions.json) holds that answer,
  the owner's eight decisions and the nine accepted known limitations.

Three of those decisions were made during the campaign, on 2026-11-15:

- **Android MASQUE stress** («Ограничение и перепрогон»). A MASQUE or
  WireGuard tunnel carries at most 16 TCP flows at once and refuses the next.
  Android's resource stress opened 32 and failed for MASQUE; it was run again
  with 8, and the bound is a known limitation of 0.10.0. After the release a
  flow past the bound waits for a place, and the bound follows the runtime
  profile (see the changelog's Unreleased section).
- **The iPhone's resource bound** («Без прогона, в ограничения»). MASQUE's
  resident memory grew 8.25 MiB in the iPhone's resource run, 0.26 MiB over
  the 8 MiB the 0.9.0 evidence used; footprint and threads, the documented
  criterion, passed. The archive bounds it by Android's rule, set after the
  number was seen, and says so.
- **Publication**, above.

### The superseded first candidate

The first candidate was `9455450d83583ab1f2f7ffec8dc0a2d6dc8b571a` (tree
`e4d3df6d5cf7a0d3e0ee5a15d807d8a683c24bf8`), the merge of
[#284](https://github.com/aimalygin/xray-rust/pull/284). Its full CI passed
(run 43352360291), the SDK pinned it in
[xray-rust-mobile#49](https://github.com/aimalygin/xray-rust-mobile/pull/49),
and the host measurements and device stands were made from it.

On 2026-11-13 its first device run, on an iPhone, found that the Apple and
Android adapters did not start a profile whose VLESS outbound is in the
simplified form, and every v0.10 fixture for mKCP, the masks, XDRIVE and the
reverse bridge writes that form. The fix is
[#292](https://github.com/aimalygin/xray-rust/pull/292). Since a new candidate
was needed, the owner also took what had merged or been reviewed since:
[#291](https://github.com/aimalygin/xray-rust/pull/291) (graceful stop of
`xray-rust run` on SIGTERM) and the contributor fixes #285 to #289, merged as
[#293](https://github.com/aimalygin/xray-rust/pull/293).

No result bound to the first candidate counts for 0.10.0. Its CI, SDK pin,
performance measurements and device stands were repeated on the second.

### The superseded second candidate

The second candidate was `4a61b057e97042396ec1a03fa8a0699919c42d64` (tree
`764bee7817e1a184a9a0c5e2ba0cfbdcb79932a5`), the merge of
[#294](https://github.com/aimalygin/xray-rust/pull/294). Its full CI passed
(run 43528798851), the SDK pinned it in
[xray-rust-mobile#50](https://github.com/aimalygin/xray-rust-mobile/pull/50),
and the host measurements and device stands were made from it.

On 2026-11-14 its device campaign found that the `xicmp` mask did not work
inside the Apple Network Extension. On an iPhone mKCP under `xicmp` failed at
its first exchange, while Android and the macOS CLI worked against the same
server. The fixes are
[#295](https://github.com/aimalygin/xray-rust/pull/295), which gives the
client's ICMP sockets the interface the system gives its UDP sockets, and
[#296](https://github.com/aimalygin/xray-rust/pull/296), which leaves them
unconnected on Apple systems. A diagnostic build with both passed the `xicmp`
smoke set on the iPhone against Xray-core's server on a Linux host. A
diagnostic is not evidence; the run is repeated on the candidate.

No result bound to the second candidate counts for 0.10.0 either. On
2026-11-14 the owner chose a full repeat («Полный повтор»): CI, the SDK pin,
the performance measurements, the device stands and every device run were
made again on the third.

### The superseded third candidate

The third candidate was `706a766cb68c0a2d571d0c0c3532d7cd508cc34c` (tree
`c9a8f38535c0aedbcfb8865fc74224afc008dc4c`), the merge of
[#297](https://github.com/aimalygin/xray-rust/pull/297). It stood on `main`
through `23fcbc2a1f1d8851cd231c687c33a9bd7bc42f11`, the merge of
[#298](https://github.com/aimalygin/xray-rust/pull/298); this page named
`46c38c19ef473ab756a6f12526405566928ab0ac` then, one merge short. Its full
CI passed (run 43663383151), the SDK pinned it in
[xray-rust-mobile#51](https://github.com/aimalygin/xray-rust-mobile/pull/51),
and the host measurements and device stands were made from it.

On 2026-11-15 its device campaign passed the iPhone's LAN runs, `xicmp` and
the WAN mKCP run. The WAN MASQUE run then failed twice on the return from
cellular to Wi-Fi, and passed in four diagnostic repeats. One DNS answer had
been lost when the tunnel moved to its Wi-Fi socket: the vendored Quinn
closed the socket a connection had left at the first packet on the new one,
with the answer still on its way to it. The core's resolver failed the lookup
after four seconds, and iOS kept that failure for the name for half a minute.
[#299](https://github.com/aimalygin/xray-rust/pull/299) keeps the old socket
for what is on its way, sends a DNS query again over a carrier that can lose
it, and lets a lookup past the resolver's operation cap wait for a place.
In three diagnostic runs on the iPhone its builds lost no lookup around the
return to Wi-Fi, where the third candidate's core lost five in one such run.
A diagnostic is not evidence; the run is repeated on the candidate.

The same day the owner took the network change out of the Android part of
the evidence profile, since the Android test device has no cellular data
([#300](https://github.com/aimalygin/xray-rust/pull/300); item 5 of the
contract below).

This time the owner chose to repeat what the changes touch («Только
затронутое»), not everything. The fourth candidate differs from the third by
#299, #300, which changes release tooling only, and the release commit.

- Counted from the third candidate: the iPhone's LAN runs. The evidence
  report and the release's owner-decision record name the build each of them
  ran.
- Made again on the fourth: full CI, the SDK pin, the host measurements, the
  device stands, every run against a public host (`xicmp` and the WAN runs)
  and every Android run. No Android run had been made on the third.

## Scope

Everything merged into `main` since 0.9.0, listed under 0.10.0 in the
[changelog](../CHANGELOG.md). What the device evidence has to cover:

- Two new carriers: mKCP and the MASQUE client (CONNECT-IP over HTTP/3 and
  HTTP/2).
- Masks: `xdns`, `xicmp`, `realm`, `sudoku`, `xmc` and `header-custom`.
- The XDRIVE transport and the VLESS reverse proxy's bridge.
- ChromeParrot, on by default for Hysteria and XHTTP over HTTP/3, and the QUIC
  carriers' move to a fresh socket when the network changes
  ([#263](https://github.com/aimalygin/xray-rust/pull/263)).
- Profile import: `vless://` links in the core (C ABI 1.17,
  [#217](https://github.com/aimalygin/xray-rust/pull/217)), Trojan, VMess and
  Hysteria2 links as panels write them, and Remnawave's JSON profiles
  ([#199](https://github.com/aimalygin/xray-rust/pull/199)).
- Compatibility with Xray-core v26.11.9
  (`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`), the reference every fixture
  runs.

Lua noise scripts, xdns over DNS over HTTPS and realm's `portMapping`
([#235](https://github.com/aimalygin/xray-rust/issues/235)) come after 0.10.0.

## Evidence contract

Releases 0.10.x use the schema-5 `v010` profile in
[check-v010-release-evidence.py](../scripts/check-v010-release-evidence.py),
validated by
[v010-release-evidence.yml](../.github/workflows/v010-release-evidence.yml).
The owner accepted this contract on 2026-11-11 («Принимаю»):

1. **mKCP and MASQUE take the full device transition set.** Scenarios `mkcp`
   and `masque` pass all twelve transitions on Apple: `ipv4-tcp`, `ipv6-tcp`,
   `ipv4-udp`, `ipv6-udp`, `domain-destination`, `routed-dns`, `start-stop`,
   `cancel-active-flow`, `reconnect`, `wifi-cellular-wifi`, `lock-wake` and
   `resource-recovery`. On Android each runs on both TUN backends, as
   `mkcp-file-descriptor`, `mkcp-packet-pump`, `masque-file-descriptor` and
   `masque-packet-pump`, without `wifi-cellular-wifi` and `lock-wake`; see
   item 5.
2. **The masks, XDRIVE and the reverse bridge take a LAN smoke set on both
   platforms.** Scenarios `xdns`, `xicmp`, `realm`, `sudoku`, `xmc`,
   `header-custom`, `xdrive` and `vless-reverse` each pass `ipv4-tcp`,
   `ipv6-tcp`, `ipv4-udp`, `ipv6-udp`, `domain-destination`, `routed-dns` and
   `start-stop`. XDRIVE meets its server in a storage on the fixture host,
   never in a cloud account. For `vless-reverse` the device is the bridge.
3. **Legacy regression covers every protocol 0.9.0 shipped:** `vless-reality`,
   `xhttp-h1`, `xhttp-h2`, `xhttp-h3`, `hysteria2`, `wireguard`, `trojan`,
   `shadowsocks2022`, `vmess`, `socks`, `http` and `shadowsocks-aead`.
   Hysteria2 and XHTTP H3 run with ChromeParrot, their default now, and
   `xhttp-h3-network-change` shows XHTTP H3 keeping its connection across a
   network change. It is required on Apple; see item 5 for Android.
4. **Profile import covers every kind added since 0.9.0:** `vless-link`,
   `trojan-link`, `vmess-link`, `hysteria2-link` and `remnawave-json`, plus
   `invalid-input-redaction`.
5. **The network change is not tested on Android.** The contract accepted
   on 2026-11-11 had Android Wi-Fi/cellular tested this time, driven over
   adb. The owner changed that on 2026-11-15: the Android test device has no
   cellular data. As in 0.7 to 0.9, the Android mKCP and MASQUE scenarios do
   not need `wifi-cellular-wifi`, and Android's `legacy-regression` does not
   need `xhttp-h3-network-change`, which is the same step. Apple keeps both.
   These are checks that were not made, not transitions that passed, and
   release known limitations must say so. Android `lock-wake` is not decided;
   see the open questions.
6. **Performance.** The gate holds `mkcp-` and `masque-` `throughput`,
   `latency` and `memory` against Xray-core v26.11.9, next to the four
   measurements every release carries. The full comparison deferred from
   0.9.0 travels in the archive too, as described next.

A v0.9 archive does not satisfy the profile, and v0.9 owner decisions are
historical records, not 0.10 decisions.

### The comparison against 0.9.0

On 2026-11-02 the owner limited 0.9.0 to the gate's measurements and deferred
the full comparison. For 0.10.0 it is the twelve legacy protocols above, this
candidate against a build of the published `v0.9.0` tag
(`30928ad51b4a434546cf143f8e385a8746523172`), measured in one run on one
machine.

The archive carries it as a performance artifact of kind `release-comparison`,
a JSON document:

```json
{
  "schemaVersion": 1,
  "baseline": {"version": "0.9.0", "revision": "30928ad5…", "tree": "e55a6c3f…"},
  "candidate": {"revision": "<candidate>", "tree": "<its tree>"},
  "measurements": [
    {"id": "trojan-throughput", "unit": "MiB/s",
     "baseline": [1, 2, 3, 4, 5], "candidate": [1, 2, 3, 4, 5],
     "verdict": "within-budget"}
  ]
}
```

The checker requires the exact v0.9.0 revision and tree, the candidate's own,
and one row for each of the 36 `<protocol>-throughput`, `-latency` and
`-memory` ids with at least five runs a side. It computes each verdict from
the medians and refuses a row that states another. A `regression` does not
fail the gate. It must be named, by its id, in the archive's
`known-limitations` artifact: the release may ship a measured regression, but
not an undisclosed one.

## Proposals awaiting the owner

The contract left these open. Each was implemented as proposed so the work
could go on. On 2026-11-13 the owner accepted them as implemented
(«Принимаю»).

1. **Android `lock-wake`.** Not decided. The profile keeps it not tested on
   Android, as v0.9 did, and release known limitations must say so. If the
   owner wants it tested, `ANDROID_OWNER_SKIPPED_TRANSITIONS` loses
   `lock-wake` and the Android driver needs a lock step (`input keyevent`).
2. **Verdict budgets of the 0.9.0 comparison.** Proposed: a candidate median
   of at least 90% of the baseline's throughput, and at most 110% of its
   latency and of its memory. Outside them a row is a `regression`.
3. **One carrier per mask.** The profile has one scenario per mask; the
   fixtures run each on one carrier, named in the case label:
   - `xdns`, `xicmp` and `realm` on mKCP. It is the carrier with live
     Xray-core interoperability for all three, and a failure there points at
     the mask, not at QUIC.
   - `sudoku`, `xmc` and `header-custom` as TCP masks on raw VLESS, the form
     every TCP carrier shares. The UDP forms of `sudoku` and `header-custom`
     are not device scenarios.
   - `xdrive` on the `s3` service, against the signature-checking stand-in of
     `tools/xdrive-oracle` on the fixture host. `local` needs a folder both
     ends share, which a phone does not have.
4. **Where `xicmp`'s server runs.** Xray-core's server reads raw ICMP sockets,
   which need root on macOS and `CAP_NET_RAW` on Linux, so the `xicmp` fixture
   runs alone and refuses to start without them. Docker on a Mac cannot serve
   it: ICMP to the Mac's address never reaches a container. The second
   candidate's campaign showed that the Mac cannot serve it under `sudo`
   either: macOS answers echo requests in the kernel and does not hand them
   to a raw socket, so the server received nothing. The server therefore
   runs on a Linux host the devices can reach.
   [#236](https://github.com/aimalygin/xray-rust/issues/236) stays open until
   the device evidence is published.
5. **How the device is the bridge.** No transition is replaced by a negative
   control. The device's own probe traffic enters the portal (Xray-core on the
   fixture host) as an ordinary VLESS client, comes back down the reverse
   tunnel to the bridge on the device, and leaves through the device's
   freedom outbound, which is redirected to the fixture's echo and DNS
   listeners. TCP and UDP of both families, the name and routed DNS all cross
   the tunnel; the portal's access log names every flow
   `reverse-entry -> r-out`.
6. **Smoke scenarios on Android** have one id each, without a backend suffix.
   The driver still runs every case on both backends.
7. **`vless-link`.** The Swift and Kotlin SDKs keep their own VLESS importers,
   and the device harness calls those. On a device `vless-link` therefore
   exercises the SDK importer, and the Apple probe reports the library's ABI
   version. Since the owner's word of 2026-11-11 the SDKs also expose the
   core's `vless` format (`XrayProfileFormat.vless` / `.Vless`). Host tests
   cover that path (Rust, Swift on macOS, the Android host JNI test); devices
   do not. Covering it there is one more import call per `vless` case in each
   probe.
8. **`xhttp-h3-network-change` on Android** needs the Device Gate to opt in
   to the network-change coordinator, which 0.9.0's harness did not. The
   opt-in stays in the harness. Since 2026-11-15 the profile does not require
   the transition on Android; see item 5 of the contract.

Not a decision, but found while building the fixtures: a MASQUE tunnel
carries 1280-byte packets and its stack does not fragment, so a UDP datagram
above 1252 bytes (IPv4) or 1232 bytes (IPv6) is not delivered, where
Xray-core's stack would fragment it. The MASQUE cases send datagrams of
exactly those sizes. This belongs in release known limitations unless it is
fixed first.

## xray-rust-mobile

The SDK repository selects its evidence profile on its own. For 0.10.0 it
needs, in `aimalygin/xray-rust-mobile`:

- `scripts/release-evidence-profile.sh`: accept minor `10` and print `v010`.
  The pattern there is `0\.(6|7|8|9)` too, and a two-digit minor must not
  match `0.1`.
- Its selector tests: `0.10.0` is an invalid version in them today and needs
  another example; add the `v010` cases this repository's
  `test_v010_release_evidence.py` has.
- The core pin, `scripts/sync-upstream.sh --force` (adapters, tests, header,
  fixtures; C ABI 1.17), the version files, and the JNI export allowlist if
  the sync brings new JNI functions.

Nothing in that repository is changed by this work.
[xray-rust-kmp](https://github.com/aimalygin/xray-rust-kmp) joins the release
after the SDK publishes, since it pins the published SDK.

## Remaining work, in order

1. ~~Add the `v010` evidence profile and map 0.10.x to it.~~ This change.
2. ~~Extend the device fixtures and Debug harnesses to every scenario of the
   profile, with a host loopback check per new case.~~ Done; see
   [v0.10 evidence collection](v010-release-evidence.md). The `v010`
   performance comparison suite and the collector for the comparison against
   0.9.0 followed in their own change; the same page has their commands.
3. ~~Pre-release fixes on `main`, then the release commit: workspace version
   0.10.0, dated changelog section, regenerated configuration contract.~~
   Done in the release commit. The fourth release commit, after the fixes
   above, is the candidate.
4. ~~Full release CI on the candidate.~~ Passed, run 43748376213.
5. ~~`xray-rust-mobile`: pin the candidate, synchronize, add the `v010`
   profile, pass SDK CI.~~ Done in xray-rust-mobile#52. The SDK carries no
   copy of the evidence checker, so #300 needed no change there.
6. ~~The owner's decisions on the proposals above, then the device and host
   campaign on the candidate: Apple and Android runs, the gate's performance
   measurements (`run-v08-protocol-comparison.py --suite v010` for mKCP and
   MASQUE), the comparison against 0.9.0
   (`run-v010-release-comparison.py`), the archive.~~ Done on 2026-11-15; see
   "The candidate's qualification" above. The gate also needs the four
   common measurements of `run-v06-feature-benchmarks.py`, which
   [v0.10 evidence collection](v010-release-evidence.md) does not list yet.
7. ~~`v010-release-evidence.yml` on the candidate, with the published
   archive.~~ Passed on `7eb199bb`, run 43768546896.
8. ~~Tag the candidate, publish the core release, the SDK and then the KMP
   library, and resolve the packages from clean consumers.~~ Done; see
   "Publication".

## Publication

On 2026-11-15 the owner authorized the rest of the sequence in one word
(«вливай и делай все по порядку, можешь через подсессии»).

**Core.**

- Evidence on `main`: [#302](https://github.com/aimalygin/xray-rust/pull/302),
  merge `b9eebe06c5999a5033db16c95ee1cc9481a927a0`.
- Tag `v0.10.0`: annotated, tag object
  `f8155747923cf2a35f0ef231179f328d157a4298`, at the candidate
  `7eb199bba2562659fdbf0bcde9820e016dd8530c`.
- Tag CI, run 43769140895, passed its four gates: the tag and changelog, the
  tag's own history, the device evidence again, and the binding to candidate
  CI run 43748376213.
- [GitHub release](https://github.com/aimalygin/xray-rust/releases/tag/v0.10.0),
  published 2026-11-15 22:33Z: the source archive, the evidence archive, the
  report, the validation records and `SHA256SUMS`, made by
  `scripts/make-release-records.py`. Every uploaded file was downloaded again
  and checked before publishing.

**SDK (xray-rust-mobile).**

- The pin moved to the core tag in
  [#53](https://github.com/aimalygin/xray-rust-mobile/pull/53). Prepare
  release, run 43770265684, built the Apple artifact; its lock is
  [#54](https://github.com/aimalygin/xray-rust-mobile/pull/54).
- Tag `v0.10.0`: tag object `73357d33d2ddd8a0648d70c8d9f875e4a14f71d5`, commit
  `af77304f17aefe3fb817fbb1a868d203b697434e`.
- Release run 43774414001 published the
  [GitHub release](https://github.com/aimalygin/xray-rust-mobile/releases/tag/v0.10.0)
  on 2026-11-16 00:12Z and the GitHub Packages coordinate.
- Maven Central has `io.github.aimalygin:xray-rust-mobile:0.10.0`. The owner
  approved the `maven-central` environment on 2026-11-16 («Я одобряю, делай»).
  The run's `maven-central / publish` job is marked failed: its ten-minute
  wait ended before Central finished publishing a bundle it had accepted.
  The version is published and must not be retried. Central's AAR is
  byte-identical to the GitHub release asset.
- Clean consumers passed: SwiftPM at exactly 0.10.0 (the tagged commit, the
  locked checksum, C ABI 1.17), and a minified Gradle build that resolves the
  coordinate from Maven Central alone, with all four ABIs in the APK.

**KMP (xray-rust-kmp).** The owner chose a tag and a GitHub release, without
Maven Central («Тег и GitHub-релиз»).

- [xray-rust-kmp#2](https://github.com/aimalygin/xray-rust-kmp/pull/2) pins
  SDK 0.10.0 and makes the library version 0.10.0; merge
  `053780c6b6ddb69d4cad00352da80d80f8185429`.
- Tag `v0.10.0`: tag object `0092e2b54cd8192ea2c38c44ae10eebffc61f6f9`.
  [GitHub release](https://github.com/aimalygin/xray-rust-kmp/releases/tag/v0.10.0),
  published 2026-11-16 01:29Z.
- The library is consumed from a checkout of the tag. It has not run on a
  device.

## After 0.10.0

- Done: a MASQUE or WireGuard tunnel lets a TCP flow past its bound wait for
  a place instead of refusing it at once, and takes 32, 64 or 128 TCP flows by
  runtime profile ([flow limits](config-compatibility.md#wireguard-flow-limits)).
  Android's MASQUE resource stress can go back to 32 connections at once.
- The SDK's Maven Central job should wait longer than ten minutes, so a slow
  publication does not end a successful release run as failed.
- Lua noise scripts, `xdns` over DNS over HTTPS and `realm`'s `portMapping`
  ([#235](https://github.com/aimalygin/xray-rust/issues/235)).
- The measurements the release accepted as limitations: memory against 0.9.0,
  MASQUE's one-flow download, and the slow first exchange after an iOS tunnel
  start.
