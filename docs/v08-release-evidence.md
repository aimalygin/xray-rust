# v0.8 evidence assembly

This is the collection/assembly inventory. The Android readiness-wait fix
advances the development SDK source pin to
`0d788564d85505ba0e2778320a561bc3d6500346`, tree
`f71235a8b17a5e5e88809ada36ce4efc19f29b00`. Earlier device measurements retain
native candidate `de33998158e84c03f280f979ba2d4212072e5bc4`, tree
`3d628e533f68671721ecf2e6ad786c15ce6f7291`. The Android follow-up combines that
exact Rust/JNI binary with the separately hashed corrected Kotlin adapter.
Reassess candidate evidence after this adapter change; do not relabel old
binaries as fresh exact-new-pin builds.
The [machine-readable inventory](releases/v0.8.0-rc.1-evidence-inventory.json)
lists the current policy requirements and supporting reports; it is not a
passing release manifest or an evidence ZIP.

On 2026-10-04 the owner deferred further investigation of the remaining SS2022
UDP losses and directed work to continue. Retain those failed trials and path
conditions as known limitations. Do not rerun that investigation as the next
task. This scheduling decision does not turn failed trials into passes or
authorize a release. That SS2022 deferral does not waive failed trials.

Separately, on 2026-10-04 the owner instructed “для android пропускаем” for
Wi-Fi ↔ cellular transitions and screen lock/wake. For v0.8 these two checks
are **owner-skipped / not tested** on Android FileDescriptor and PacketPump.
The v0.8 policy excludes only these two Android transition requirements; Apple
coverage and every other acceptance requirement remain unchanged. Preserve
these omissions in the final known-limitations artifact. A pass under this
reduced scope must not be described as Android network/lock coverage.

Before the regression-report changes, ordinary CI passed for core `3c7b1628544dc64ffc6f1284169c5bf6ac136c48`
([run 37253541471](https://github.com/aimalygin/xray-rust/actions/runs/37253541471))
and SDK `90355c5f4d11bed53dfe4748a262521044a87407`
([run 37253545430](https://github.com/aimalygin/xray-rust-mobile/actions/runs/37253545430)).
Optional/full core release jobs were skipped.
These later source/diagnostic checks do not relabel measured native binaries.
Full candidate CI remains recorded in [release readiness](v08-release-readiness.md).

## Current inventory

| Area | Available evidence | Assembly/collection still needed |
| --- | --- | --- |
| Apple new protocols | [LAN and WAN](device-results/2026-10-03-iphone17-v08/README.md), [lifecycle/resources](device-results/2026-10-04-iphone17-lifecycle-resources/README.md), [direct SS2022 transitions](device-results/2026-10-04-iphone17-ss2022-mtu/README.md) | Map each required transition to its actual run and fixture; retain SS2022 conditions and failed controls. Startup cancellation alone is not evidence of every active-flow cancellation case. |
| Apple shared scenarios | Legacy smoke and connection-close/recovery observations; successful shared imports | Complete the distinct VLESS-encryption, IP-on-demand, XHTTP download-session and host-adapter-projection scenarios; map general cancellation explicitly. A VLESS/REALITY smoke result does not by itself cover VLESS encryption. Physical invalid-input/redaction evidence is not established by successful imports. |
| Apple legacy reliability | [0.7/0.8 controls](device-results/2026-10-04-iphone17-wg-baseline/README.md), [ten further repeats](device-results/2026-10-04-iphone17-reliability-deployment/README.md) | Preserve the original WireGuard/Trojan failures and unresolved causes; passing repeats do not erase them. The SS2022 deferral does not decide these separate issues. |
| Android | [Physical Samsung LAN baseline and follow-up](device-results/2026-10-04-android-v08/README.md): all ciphers on both paths, import, IPv4/IPv6/domain, close/restart, bounded request/resource checks and invalid-input controls | Preserve original UDP timeouts and the PacketPump idle-CPU finding. Wi-Fi/cellular and lock/wake are owner-skipped, not tested. The [legacy and active-flow follow-up](device-results/2026-10-04-android-regressions/README.md) separates local cancellation, remote EOF and traffic recovery; preserve WireGuard/SS2022 remote-close failures and the Trojan UDP recovery timeout. Review these findings and complete the other shared scenarios; LAN checks do not complete the physical gate. |
| Device resource profiles | Bounded iPhone CPU, RSS, footprint, threads and recovery observations | Bind raw intervals, thermal state, load definitions, predeclared limits and observed deltas to each device report. Sparse samples are not continuous peaks or energy measurements. Keep CPU and memory visible together. |
| Performance gate | [Historical comparisons](v08-performance.md) with exact source/binary identities, including accepted VMess AES tradeoff | Collect/identify five clean exact-candidate samples for each of the 13 required measurements. Historical benchmark identities and two-interval phone loads must not be relabeled as these samples. Freeze workloads and thresholds before collection. |
| Distribution | Candidate source/CI consumer validation | Prepare canonical artifacts and clean consumers only in the release order; current artifact locks remain unprepared. No tag, merge or publication is authorized. |

The iPhone reports include both iOS 27.0 / 24A437 and 27.0.1 / 24A446. Preserve
each run's OS/build and Debug harness identity when assembling them; do not
describe all runs as performed on one OS/build. The linked Rust library is
identified separately from the signed Debug application.

## Schema-4 contract

The source of truth is [check-v08-release-evidence.py](../scripts/check-v08-release-evidence.py)
and its [shared validator](../scripts/check-v06-release-evidence.py). Exactly one
physical Apple and one physical Android report are required. Each report must
include all scenarios for its platform: **10 Apple and 13 Android scenario IDs**.

Both platforms require `vless-encryption`, `ip-on-demand`,
`xhttp-download-session`, `cancellation`, `host-adapter-projection`,
`profile-import` and `legacy-regression`. Apple additionally requires `trojan`,
`shadowsocks2022`, `vmess`; Android requires each protocol with both
`-file-descriptor` and `-packet-pump` suffixes.

Each Apple new protocol requires these 12 transitions, without duplicates.
Android protocol/path scenarios require the same set **except**
`wifi-cellular-wifi` and `lock-wake`, owner-skipped for v0.8:

```text
ipv4-tcp, ipv6-tcp, ipv4-udp, ipv6-udp, domain-destination,
routed-dns, start-stop, cancel-active-flow, reconnect,
wifi-cellular-wifi, lock-wake, resource-recovery
```

Profile imports require `trojan-link`, `shadowsocks2022-link`, `vmess-link` and
`invalid-input-redaction`. Legacy regression requires `vless-reality`,
`xhttp-h1`, `xhttp-h2`, `xhttp-h3`, `hysteria2` and `wireguard`.
The other shared scenarios require nonempty, accurate transition records.
There is no fixed six-hour or other minimum soak duration: record actual
positive durations and the tested bounds.

Each device report references exactly three hashed artifacts:
`resource-profile`, `sanitized-log`, `transition-timeline`. Record explicit
limits and observations for `residentMemoryGrowthBytes`, `threadGrowth`,
`fatalErrors`, `unrecoveredTransitions`; the last two have zero allowed limit.
Do not derive memory growth from an isolated maximum or assume a hard-coded
zero telemetry field proves recovery.

Performance needs a clean release-profile build and at least five positive
samples per measurement, with an explicit positive threshold and median check:

| Measurements | Direction |
| --- | --- |
| `process-throughput`, `vless-encryption-throughput` | at-least |
| `ip-on-demand-latency`, `xhttp-memory` | at-most |
| `trojan-throughput`, `shadowsocks2022-throughput`, `vmess-throughput` | at-least |
| Each protocol's `-latency` and `-memory` | at-most |

The four performance artifacts are `benchmark-raw`, `build-manifest`,
`protocol-comparisons`, `known-limitations`. Include CPU data and accounted
memory tradeoffs in the raw/resource reports even though the schema's named
threshold IDs do not include a standalone CPU metric. The accepted VMess AES
deficit and deferred SS2022 investigation remain explicit limitations.

The final ZIP must contain exactly `manifest.json` and its referenced files,
with matching SHA-256s. Both compressed and expanded limits are 256 MiB. Do not
add synthetic successful device records or reuse unit-test manifest fixtures.
The validator checks structure and thresholds; measurements still need review.

## Next execution order

1. Preserve the [Android baseline and follow-up](device-results/2026-10-04-android-v08/README.md)
   with their exact APK/native/adapter hashes. The original PacketPump busy loop
   is a separate finding from intermittent small-UDP stress failures. Do not
   infer that correcting CPU also corrects packet loss. Reassess exact-candidate
   coverage after the Kotlin change and SDK source repin.
2. Review the [Android legacy/active-flow findings](device-results/2026-10-04-android-regressions/README.md):
   remote-close limits for WireGuard/SS2022 and the failed Trojan UDP recovery
   remain explicit. Complete the distinct VLESS-encryption, IP-on-demand,
   XHTTP download-session and host-adapter-projection scenarios. Retain every failed attempt. Do not request a SIM or run the
   owner-skipped network/lock checks; record them as not tested.
3. Assemble Apple transition/resource references and collect the missing shared
   scenarios. Prepare calibrated exact-candidate host samples in a quiet window,
   recording CPU and memory together. Do not reopen the deferred SS2022 work.
4. Build a schema-4 ZIP only after the required data is complete. Validate with
   `python3 scripts/check-v08-release-evidence.py evidence.zip REVISION TREE`,
   then use the exact-candidate evidence workflow. No passing ZIP or evidence
   workflow dispatch has been produced by this inventory.
