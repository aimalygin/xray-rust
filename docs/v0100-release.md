# 0.10.0 release preparation

Preparation started on 2026-11-11 on the owner's word, with `main` at
`fb3a27f57595e140128e219209bc0ca2a02d51a0`. Publication is pending, and no
device result exists.
The shared steps are in the [release process](release-process.md); this page
holds what is specific to 0.10.0.

The candidate is the second 0.10.0 release commit: `main` through
`0598c13f05928934be559a91ae2e1ecf7fef3d25` plus the changelog section, now
dated 2026-11-13, and this document. The workspace version, lockfile and
generated configuration contract are already 0.10.0 from the first release
commit and do not change. Its exact revision and tree are recorded here once
it merges; every later step binds to them. The README install snippets keep
the published 0.9.0 until the 0.10.0 packages exist.

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
performance measurements, device stands and device runs are all repeated on
this one.

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
   `masque-packet-pump`.
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
   network change.
4. **Profile import covers every kind added since 0.9.0:** `vless-link`,
   `trojan-link`, `vmess-link`, `hysteria2-link` and `remnawave-json`, plus
   `invalid-input-redaction`.
5. **Android Wi-Fi/cellular is tested this time**, driven over adb. In v0.9 it
   was not tested. Android `lock-wake` is not decided; see the open questions.
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

The contract leaves these open. Each is implemented as proposed so the work
can go on, and each can change without touching the rest.

1. **Android `lock-wake`.** Not decided. The profile keeps it not tested on
   Android, as v0.9 did, and release known limitations must say so. If the
   owner wants it tested, `ANDROID_OWNER_SKIPPED_TRANSITIONS` becomes empty
   and the Android driver needs a lock step (`input keyevent`).
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
   it: ICMP to the Mac's address never reaches a container. The options are
   the Mac fixture host under `sudo`, or a Linux host on the same LAN.
   [#236](https://github.com/aimalygin/xray-rust/issues/236) is still open:
   the client has never run on a device.
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
   to the network-change coordinator, which 0.9.0's harness did not.

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
   Done in the release commit. The second release commit, after the fixes
   above, is the candidate.
4. Full release CI on the candidate.
5. `xray-rust-mobile`: pin the candidate, synchronize, add the `v010`
   profile, pass SDK CI.
6. The owner's decisions on the proposals above, then the device and host
   campaign on the candidate: Apple and Android runs, the gate's performance
   measurements (`run-v08-protocol-comparison.py --suite v010` for mKCP and
   MASQUE), the comparison against 0.9.0
   (`run-v010-release-comparison.py`), the archive, and
   `v010-release-evidence.yml` on the candidate.
7. Publish the evidence on `main`, tag, publish the core release, the SDK and
   then the KMP library, and resolve the packages from clean consumers.
