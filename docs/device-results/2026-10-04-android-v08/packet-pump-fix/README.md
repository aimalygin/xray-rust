# Android PacketPump readiness-wait follow-up

The empty-read busy loop is corrected in the Kotlin adapter. On the same
Samsung SM-A145F, a fresh idle control changes PacketPump process CPU from
12.86 seconds / 12.72 wall seconds (~101% of one core) to 0.51 / 14.84 (~3.4%).
The `xray-tun-in` thread itself changes from 10.95 to 0.05 CPU seconds in the
separately captured thread intervals. The follow-up FileDescriptor control
uses 0.36 / 14.57 seconds (~2.5%). This is a bounded process observation,
including Debug UI/sampling overhead, not a battery/energy or throughput claim.

## Change and build identity

Core adapter commit `0d788564d85505ba0e2778320a561bc3d6500346`, tree
`f71235a8b17a5e5e88809ada36ce4efc19f29b00`, waits with `Os.poll` for at most
250 ms after a zero-byte TUN read. Android maps nonblocking `EAGAIN` to zero
in `FileInputStream.read`; retrying immediately consumed a core. The bounded
wait retains interruption/active checks, handles terminal poll errors through
the existing teardown path and does not enlarge packet buffers. The same
source is synchronized in the SDK and becomes its development core pin.

The [build identity](build-identity.json) contains the exact APK/source hashes.
The Rust library remains the clean `de339981` arm64 release binary with SHA-256
`470eae963080b245b782c6f16a72f6af66b12e4d4f5cd23b417309b0eb900f67`;
JNI is byte-identical to the baseline. Only `XrayVpnService.kt` differs from
the previous diagnostic build. Both test apps retain their `.v08` IDs; Android
VPN consent is preserved. Kotlin checks declare 115 tests: 110 execute
successfully, five are skipped by the existing host/native test conditions.
Exact new-pin header/adapter/source and SDK preparation metadata checks pass
against a clean checkout. Artifact locks are unprepared.

These are separately identified adapter-on-native-baseline measurements, not
fresh exact-new-pin native device builds. The earlier iPhone and Android
reports keep their original identities. Release evidence applicability must
be reviewed after this adapter change; no schema-4 exception is introduced.

## Physical regression and resource results

The complete functional matrix repeats **14/14
combinations**, with **182 HTTP and
182 nonce-checked UDP round trips**, and
**0 functional failures**. It includes both adapter
paths, Trojan, all three SS2022 methods, VMess auto/AES/ChaCha, synthetic
IPv4/IPv6/domain targets, close/recovery, startup cancellation, restart and stop.
The import and canonical TLS-pinned fixture distinction is the same as in the
[baseline method](../README.md). No outer IPv6 or WAN claim is implied.

The two 240-HTTP/480-UDP bursts per row use 32 workers, probe-only VPN scope,
15 seconds of recovery followed by five samples, and the original limits:
RSS growth ≤ max(8 MiB, 25% of first recovery median), thread growth ≤ 4.
CPU seconds cover each burst observation interval; recovery CPU is percent
of one core between the first and last recovery samples. All values are
process-level, with ADB/control overhead and sparse peak visibility. Sanitized
logs merge retained ring-buffer snapshots; they are not guaranteed continuous.

| Configuration | Path | HTTP | UDP | CPU seconds, cycles 1/2 | Recovery CPU %, 1/2 | Recovered RSS MiB | Native allocated MiB | Thread delta |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Trojan | FD | 480/480 | 960/960 | 3.65/3.64 | 2.4/2.1 | 164.3 → 171.9 | 18.2 → 17.9 | -1 |
| Trojan | PP | 480/480 | 960/960 | 4.37/4.36 | 3.1/2.9 | 172.6 → 160.2 | 17.7 → 18.3 | -1 |
| SS2022 chacha20-poly1305 | FD | 480/480 | 960/960 | 1.80/1.79 | 2.0/2.2 | 168.8 → 169.1 | 26.4 → 25.1 | -1 |
| SS2022 chacha20-poly1305 | PP | 480/480 | 960/960 | 2.34/2.31 | 3.1/2.9 | 169.5 → 168.0 | 25.6 → 25.6 | -1 |
| SS2022 aes-128-gcm | FD | 480/480 | 960/960 | 1.87/1.81 | 2.4/2.0 | 168.1 → 168.9 | 26.8 → 25.5 | -1 |
| SS2022 aes-128-gcm | PP | 480/480 | 959/960 | 2.44/2.31 | 3.1/2.9 | 161.5 → 168.0 | 26.3 → 25.2 | +0 |
| SS2022 aes-256-gcm | FD | 480/480 | 960/960 | 1.87/1.82 | 2.2/1.8 | 167.7 → 168.0 | 26.3 → 25.2 | -1 |
| SS2022 aes-256-gcm | PP | 480/480 | 959/960 | 2.34/2.38 | 3.1/2.8 | 168.9 → 160.3 | 26.4 → 26.2 | -1 |
| VMess aes-128-gcm | FD | 480/480 | 960/960 | 2.19/2.16 | 2.2/2.4 | 158.9 → 155.5 | 17.1 → 17.1 | -1 |
| VMess aes-128-gcm | PP | 480/480 | 960/960 | 2.67/2.73 | 2.6/2.8 | 151.8 → 158.4 | 16.9 → 16.8 | -1 |
| VMess chacha20-poly1305 | FD | 480/480 | 960/960 | 2.14/2.18 | 2.2/2.2 | 160.4 → 158.9 | 17.3 → 16.9 | -1 |
| VMess chacha20-poly1305 | PP | 480/480 | 960/960 | 2.72/2.73 | 3.1/2.7 | 153.7 → 158.6 | 16.9 → 16.8 | -1 |

All twelve predeclared RSS/thread criteria **passed**. The maximum
positive recovery-median RSS delta is **7.61 MiB**. This does not prove
absence of leaks or zero allocator retention. The resource matrix retains
**2 failed UDP attempts**; successful repetitions do not erase original
losses, and fixing the idle CPU loop does not establish their root cause.
The follow-up retains SS2022 AES-128 and AES-256 PacketPump timeouts.
For the correlated AES-128 timeout, the backend submitted the matching
83-byte reply about 5.1 seconds before the timeout. Core counters include all
483 requests (warm-up, ordinary and stress) but only 482 decoded replies, with
zero sampled TUN drops. Backend `sendto` telemetry is not proof of NIC delivery;
the exact dropping hop remains unresolved. See [correlation](udp-correlation.json).
Read the [raw events](events.jsonl) and [manifest](manifest.json), rather than
interpreting resource collection completion as a universal traffic pass.

Malformed Trojan/SS2022/VMess imports are rejected without changing the stored
ciphertext, their plaintext pending files are removed, and the nonsecret input
marker is absent from host logs. A VPN-off control cannot reach either
synthetic target, as expected. Its timeout is an intentional negative control.
The hard-coded `unrecoveredTransitions` field is not an observed verdict.

## Cleanup, reproduction and limits

The test VPN/probe services and owned app processes are stopped, temporary
`.v08` profile/pending files are removed, and all four owned fixtures have
stopped with their keys/configs deleted. Previous base/rc07 test apps and
profiles are untouched. No VPS or user network settings were changed.
Final battery/thermal conditions are recorded in the manifest; USB-powered
bounded tests are not an energy benchmark.

Use the [parameterized replay scripts](../reproduce/README.md), the same
candidate native hash and corrected adapter source. Build the identified
arm64 test APKs and run idle, matrix, resources and controls sequentially.
The recorded scripts keep failed events and separate memory/traffic verdicts.
No formal release performance thresholds, sustained bulk transfer, Go/sing-box
phone comparisons, Android Wi-Fi/cellular transitions, lock/wake, complete
shared/legacy matrix or exact-candidate schema-4 archive are claimed.
No merge, tag, release or package publication was performed.
