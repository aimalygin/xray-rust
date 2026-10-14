# 0.8.0 exact-candidate device and host measurements — 2026-10-12

This is a measured evidence inventory with a [locally validated schema-4 archive](../../releases/v0.8.0-device-evidence.json). [GitHub evidence validation](https://github.com/aimalygin/xray-rust/actions/runs/38288094780) passed for the exact candidate. Publication is pending. Apple cellular transitions passed for Trojan/VMess and conditionally for SS2022; its default-policy failure is retained. Canonical distribution artifacts, verified immutable tags, source locks and clean package-consumer checks are still required. Failed measurements stay failed under the scoped [owner decisions](../../releases/v0.8.0-owner-decisions.json).

## Identity and scope

- Core `fcce4be2771c1fb3f11e9503741d39a4d8df314e`, tree `820cbdc251861d02c93ed007015e5c6109baa3c0`; PR #42 merged with the identical runtime tree as `48df785d7ce1bed66379ed1ec1ebd596c0e5615c`.
- SDK `12fdfa14136e57024d46ace66c84bdbf3dc1d7c7`; PR #33 is open. Production adapter/provider sources are unchanged during this campaign.
- iPhone 17 Pro Max, iOS 27.0.1, signed Debug host/extension with release Rust; Samsung SM-A145F, Android 15 / API 35 arm64, Debug host/probe with release Rust/JNI. These are device-test harnesses, not canonical distribution products.
- Pinned Xray-core reference source `5ca6f4b7d4dc20a881d4330e498892697627ec0c` (26.7.28). Separate macOS and Android binary/toolchain hashes remain in their manifests.
- CI-only PR #55 is merged. PR run [38273709221](https://github.com/aimalygin/xray-rust/actions/runs/38273709221), full run [38273707002](https://github.com/aimalygin/xray-rust/actions/runs/38273707002) and post-merge main [38279427577](https://github.com/aimalygin/xray-rust/actions/runs/38279427577) passed. Runtime and SDK pin remain unchanged.

[inventory.json](inventory.json) binds each sanitized file to both its original private-source SHA-256 and published SHA-256. Private addresses, device serials and local path prefixes are replaced; configurations, share links, credentials, raw system logs and app bundles are excluded. Full Apple bundle inventories supplement the original executable-stub-only manifest. Harness-only source patches and the final provider source manifest are separate from production sources.

## Android

All **32 functional protocol/cipher/shared/legacy × FileDescriptor/PacketPump cases passed**. The original [14-case snapshot](android-functional-summary.json) retains its historical `resourceSeries=in-progress` field; subsequent shared, legacy and v0.7 phase results bring the total to 32. Invalid imports/redaction, VPN-off expected failure, AsIs expected failure and IPOnDemand positive recovery are retained in the raw events.

All twelve bounded RSS/thread recovery criteria passed; maximum recovery-median RSS growth was 9,097,216 bytes within the predeclared 25% allowance, with no thread growth. Recovery CPU was measured separately (median 2.404%, maximum 3.163% of one core). Canonical stress retains **HTTP 6,720/6,720 and UDP 13,437/13,440**, including three VMess AES UDP timeouts. See [resource summary](android-resource-summary.json), [follow-up](android-vmess-diagnostic/summary.json) and [#56](https://github.com/aimalygin/xray-rust/issues/56).

Independent pinned Xray-core on the same Android device, via native Go/localhost SOCKS, passed HTTP 480/480 and UDP 959/960. The missing nonce-matched reply reached the backend and its send call. This bypasses Rust/VpnService/TUN but uses different ingress and scheduling; it neither localizes the missing reply nor proves Wi-Fi causation. The owner's explicit 0.8.0 release decision keeps #56 open and documented.

A diagnostic JNI follow-up had zero observed budget/error/eviction counters and HTTP 480/480, UDP 960/960; it does not erase the canonical failures. Its APK identity differs and the canonical APK was restored. Local active-flow cancellation passed 12/12 within 3 seconds; SS2022 remote EOF retained its separate 20-second server hold. Admission accepted ordinary TCP/UDP and bound UDP for the included UID; bound TCP was strictly denied on INVALID_UID. Android network/lock checks remain owner-skipped, not tested.

## Apple

New cipher smoke, three-protocol lifecycle, legacy REALITY/XHTTP H1/H2/H3/Hysteria2/WireGuard and shared VLESS encryption/IPOnDemand/split-XHTTP passed. Explicit AsIs negative and IPOnDemand recovery controls passed. Three bounded resource runs passed with thermal state 0, no thread growth, and at most 278,528 bytes recovered-footprint growth. CPU and RSS/footprint are retained together in [resource results](ios-resource-corrected/resources/result.json).

Signed production provider hooks were exercised through both FD and PacketPump: default/explicit admission, stream limits, deny-all, TCP-port deny with UDP allowed, timeout fail-closed/fail-open, recovery, and Trojan/SS2022/VMess projection. **21/22 traffic cases passed**. The first FD Hysteria default case retains TCP and UDP receive timeouts; later passing controls do not fix that original failure. This falls under the recorded iPhone Hysteria deferral. All 22 hook-count/tuple checks passed; three invalid-input and four valid-import redaction checks passed. [Results](ios-provider/summary.json), [raw](ios-provider/result.json), [tuple assertions](ios-provider/tuple-summary.json).

All three LAN lock/wake cases passed, with the same runtime, zero recovery retries and verified active-connection closure. The prompt requested 30 seconds; the existing harness requires at least 15 seconds of observed protected-data lock state. Actual intervals are reported below, not relabeled as 30 seconds. Lock notifications do not establish deep sleep, continuous background traffic or cellular coverage.

| Protocol | Observed lock, seconds | Unlock to completed traffic, seconds | Active traffic check, seconds | Retries |
| --- | ---: | ---: | ---: | ---: |
| trojan | 24.76 | 1.89 | 0.83 | 0 |
| shadowsocks2022 | 24.51 | 1.63 | 0.73 | 0 |
| vmess | 21.90 | 1.83 | 0.79 | 0 |

[Lock summary](ios-lock-wake/summary.json) and [raw timeline](ios-lock-wake/lock-wake/result.json) retain TCP/UDP/DNS results and connection IDs.

## Apple WAN transitions

Trojan and VMess passed Wi-Fi → cellular → Wi-Fi and lock/wake with the default Xray server socket policy. **SS2022 default-policy baseline failed** on the 1,372-byte logical IPv6 UDP exchange before cellular transitions. TCP and the IPv4 UDP baseline passed; failed/retried attempts remain in the raw timeline.

A separate SS2022 invocation passed all stages only after the documented [native server UDP PMTU workaround](../../ss2022-server-udp-pmtu.md). The pinned helper changed only the owned temporary IPv4 SS2022 UDP listener from `IP_MTU_DISCOVER=1` to `0`; audits before traffic and after completion verify that condition. This is conditional deployment evidence, not a fix for the original failure or a claim that the default path now works. The signed client, release native library, ABI and public SDK were unchanged.

| Protocol | Server policy | Cellular traffic complete, seconds | Wi-Fi traffic complete, seconds | After unlock, seconds |
| --- | --- | ---: | ---: | ---: |
| trojan | default | 5.48 | 4.51 | 5.55 |
| vmess | default | 4.03 | 3.53 | 4.37 |
| shadowsocks2022 | IP_PMTUDISC_DONT on the owned native IPv4 UDP listener | 3.74 | 3.33 | 4.17 |

Times include the full fresh TCP/UDP/DNS exchange suite after each signal, not only reconnect latency. All successful stages used zero retries and preserved runtime identity. Established-session continuity and deep sleep were not tested. [Summary](ios-wan/summary.json) links every raw verdict, including the failed default SS2022 attempt.

Both temporary fixture directories were removed. Original test services were restored; the production service and separate loopback control kept their original PIDs. No route, firewall, sysctl, production service or production Xray binary was changed.

## Explicit RSS acceptance follow-up

A fresh series declared separate RSS and physical-footprint growth limits of 8 MiB, plus at most eight threads, before collection. The signed harness and native release library were unchanged. Each protocol completed four 20-second load intervals (two cycles of one/eight connections) and twenty recovery samples. All passed. Maximum recovered RSS growth: Trojan 3,358,720 bytes; SS2022 4,538,368; VMess 3,801,088. Maximum footprint growth was 147,456 bytes; no thread growth or runtime restart occurred. The earlier footprint-only check is preserved separately and is not relabeled as a predeclared RSS gate.

[Predeclared plan](ios-resource-final/plan.json), [derived summary](ios-resource-final/summary.json), [raw intervals](ios-resource-final/resources/result.json).

## Host performance

All **140 predeclared protocol trials** passed: seven profiles, two workloads, five fresh paired repetitions, alternating candidate/Xray order. Single-flow localhost SOCKS; full-duplex 256 MiB per direction or 1,000 × 1 KiB TCP ping-pong. Release Rust 1.96.0 and pinned Go 1.26.5 reference. Nine protocol metric IDs and four feature metric IDs each have five samples.

Predeclared protocol bounds: throughput at least 50% of the paired Xray sample, p95 latency at most 2×, sampled RSS at most 64 MiB. Group measurements use the worst cipher per repetition. These are operational budgets, **not a calibrated 5% regression check or universal performance parity**. The calibrated 5% confirmation remains owner-deferred; comparisons against Xray are not comparisons against a previous Rust release. CPU, memory, sample order and outliers remain in the raw reports.

| Profile | Median duplex MiB/s, Rust / Xray | Median p95 microseconds, Rust / Xray |
| --- | ---: | ---: |
| trojan-tls | 1950.5 / 1680.5 | 184 / 177 |
| ss2022-aes128 | 1843.2 / 2201.7 | 224 / 230 |
| ss2022-aes256 | 1876.4 / 2111.1 | 206 / 216 |
| ss2022-chacha20 | 923.2 / 1293.8 | 197 / 185 |
| vmess-aes128 | 1930.9 / 2558.0 | 187 / 198 |
| vmess-chacha20 | 1279.9 / 1332.8 | 181 / 190 |
| vmess-auto | 2011.8 / 2565.5 | 185 / 192 |

[Protocol comparisons](performance-protocols/protocol-comparisons.json), [140 raw results](performance-protocols/benchmark-raw.json), [build/plan](performance-protocols/manifest.json), [feature samples](performance-features/benchmark-raw.json).

## Preserved limitations and interrupted attempts

The original wrong 1 MiB resource-fixture cap, missing FakeIP assertion, Android USB disconnection, diagnostic Activity routing failure and provider launch-hook failure are retained as fixture/control failures. Corrected runs carry separate paths and identities. The independent Android Xray startup configuration failure generated no traffic and is separate from its measured UDP loss. Historical Hysteria, SS2022 WAN/MTU and VMess performance findings keep their original source identities and scoped decisions. Neither a successful retry nor this report claims those causes are fixed.

The explicit RSS series and local/GitHub schema-4 validation passed. The immutable core tag `v0.8.0` points to the measured candidate. Canonical distribution and package-consumer checks remain outstanding.
