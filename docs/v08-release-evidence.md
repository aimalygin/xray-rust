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
authorize a release. The schema-4 validator is unchanged.

Before the Android follow-up, ordinary CI passed for core `2c04d987fdc9a1312d0d7a799d6fcd3c1e2c6478`
([run 37232384891](https://github.com/aimalygin/xray-rust/actions/runs/37232384891))
and SDK `f18254a6571a0165c6ecb557d57bc87ad688818e`
([run 37232264692](https://github.com/aimalygin/xray-rust-mobile/actions/runs/37232264692)).
These later source/diagnostic checks do not relabel measured native binaries.
Full candidate CI remains recorded in [release readiness](v08-release-readiness.md).

## Current inventory

| Area | Available evidence | Assembly/collection still needed |
| --- | --- | --- |
| Apple new protocols | [LAN and WAN](device-results/2026-10-03-iphone17-v08/README.md), [lifecycle/resources](device-results/2026-10-04-iphone17-lifecycle-resources/README.md), [direct SS2022 transitions](device-results/2026-10-04-iphone17-ss2022-mtu/README.md) | Map each required transition to its actual run and fixture; retain SS2022 conditions and failed controls. Startup cancellation alone is not evidence of every active-flow cancellation case. |
| Apple shared scenarios | Legacy smoke and connection-close/recovery observations; successful shared imports | Complete the distinct VLESS-encryption, IP-on-demand, XHTTP download-session and host-adapter-projection scenarios; map general cancellation explicitly. A VLESS/REALITY smoke result does not by itself cover VLESS encryption. Physical invalid-input/redaction evidence is not established by successful imports. |
| Apple legacy reliability | [0.7/0.8 controls](device-results/2026-10-04-iphone17-wg-baseline/README.md), [ten further repeats](device-results/2026-10-04-iphone17-reliability-deployment/README.md) | Preserve the original WireGuard/Trojan failures and unresolved causes; passing repeats do not erase them. The SS2022 deferral does not decide these separate issues. |
| Android | [Physical Samsung LAN baseline and follow-up](device-results/2026-10-04-android-v08/README.md): all ciphers on both paths, import, IPv4/IPv6/domain, close/restart, bounded request/resource checks and invalid-input controls | Preserve original UDP timeouts and the PacketPump idle-CPU finding. Complete Wi-Fi/cellular, lock/wake, active-flow cancellation and shared/legacy scenarios; these LAN checks do not complete the physical gate. |
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

Each new protocol/path requires these 12 transitions, without duplicates:

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
2. Complete user-assisted Android network/lock scenarios once a working SIM is
   confirmed, then the missing shared/legacy scenarios and active-flow controls.
   Retain every failed attempt. The local Mac fixture cannot establish cellular
   reachability; the separate reserved VPS endpoint is needed for transitions.
3. Assemble Apple transition/resource references and collect the missing shared
   scenarios. Prepare calibrated exact-candidate host samples in a quiet window,
   recording CPU and memory together. Do not reopen the deferred SS2022 work.
4. Build a schema-4 ZIP only after the required data is complete. Validate with
   `python3 scripts/check-v08-release-evidence.py evidence.zip REVISION TREE`,
   then use the exact-candidate evidence workflow. No passing ZIP or evidence
   workflow dispatch has been produced by this inventory.
