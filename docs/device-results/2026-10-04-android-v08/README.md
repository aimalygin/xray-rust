# Android v0.8 LAN protocols, lifecycle and resource observations

On a physical Samsung SM-A145F, Android 15/API 35, all **14 functional
protocol/path combinations passed**: seven configurations through FileDescriptor
and PacketPump. This report records **182 HTTP checks and 182 nonce-checked UDP
round trips**, with zero failures in that functional matrix. It also retains
Trojan and SS2022 AES-128 UDP stress timeouts, and identifies a PacketPump
idle CPU defect. This is **not complete release acceptance**.

## Identity and method

The release Rust library comes from a clean checkout of candidate
`de33998158e84c03f280f979ba2d4212072e5bc4`, tree
`3d628e533f68671721ecf2e6ad786c15ce6f7291`. Its SHA-256 is
`470eae963080b245b782c6f16a72f6af66b12e4d4f5cd23b417309b0eb900f67`.
NDK 26.3.11579264, API 24, Rust 1.96.0 and 16-KiB ELF LOAD alignment were
verified. This rehearsal packages **arm64 only**. The JNI and SDK runtime
sources for this baseline match the frozen candidate. A separate follow-up
changes only the Android readiness wait; these baseline results retain their
original source and binary identities.

The Debug host/probe APKs use separate `.v08` application IDs and preserve
previous installed test applications/profile stores. Host and probe have
different UIDs. The owner accepted Android's VPN consent prompt. The host
excludes itself from the VPN, and all probes run in the separate application.
The device remained connected to USB power and local Wi-Fi. Initial thermal
status was 0, battery temperature 28.2°C and charge 100%; this is not proof of
constant thermals or an energy measurement.

Three app-only diagnostic generations are identified separately:

- [Full VPN build](identity-full-vpn.json): functional matrix and first failed
  request-stress attempt. Background applications generated substantial traffic
  that the reference fixture blocked, so this attempt is not a controlled CPU
  comparison.
- [First isolated build](identity-isolated-first.json): VPN restricted to the
  matching probe UID and sanitized failure classes. A Trojan FD resource repeat
  passed, followed by a retained Trojan PP UDP timeout.
- [UDP diagnostic build](build-identity.json): same native/JNI binaries, with
  UDP byte counters and a hash of failed synthetic queries. Used for order
  controls and the complete bounded resource matrix below.

The server is the pinned Xray-core v26.7.28 revision
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, binary SHA-256
`fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99`.
Fresh private credentials and a pinned self-signed TLS leaf authenticate the
local fixture. Synthetic IPv4/IPv6 destinations redirect to controlled local
HTTP and UDP backends; other destinations are blocked. Inner IPv6 coverage
does not establish an outer IPv6 carrier or a real Internet IPv6 target.

## Functional matrix

Configurations are Trojan TLS; SS2022 ChaCha20, AES-128 and AES-256; and VMess
auto, AES-128 and ChaCha20. Each of their two paths verifies:

- share-link import, encrypted storage and pending plaintext deletion;
- three HTTP/UDP pairs each for IPv4, IPv6 and the fixture's fresh domain;
- connection-snapshot close and two fresh HTTP/UDP pairs afterward;
- service-level startup cancellation and two successful pairs after restart;
- stop/teardown with the selected backend recorded by the host.

HTTP checks return 204 and prove availability, not bulk payload integrity.
Each UDP query/response is exactly 67/83 bytes with a fresh transaction ID and
nonce and an exact response check. This is not an MTU or fragmentation sweep.
Traffic uses canonical fixture JSON after separately testing link import,
because the short-lived TLS leaf pin is not represented by the Trojan link.
Connecting cancellation does not cover every active-flow cancellation case.

## Bounded resource matrix

Each explicit cipher runs two cycles of 240 HTTP and 480 UDP attempts with 32
workers. Close the connection snapshot after each cycle, wait 15 seconds, then
take five recovery samples one second apart. The two recovery medians must
grow by no more than `max(8 MiB, 25% of cycle-one RSS)` and four process
threads. These limits were recorded before the first load, following the
existing diagnostic policy. Memory and successful packet delivery have
separate verdicts: a resource pass cannot excuse a failed query.

FD = FileDescriptor; PP = PacketPump. CPU is total host-process user+system
time for each burst's observation interval, measured from `/proc` at 100 Hz.
It includes Java/JNI and control overhead. RSS includes shared code; native
allocated bytes from `dumpsys meminfo` help distinguish live allocations from
retained allocator capacity. Sampled values are not continuous peaks. Sanitized logs combine retained
ring-buffer snapshots, not a guaranteed continuous log capture.

| Configuration | Path | HTTP | UDP | CPU seconds, cycles 1/2 | Recovered RSS MiB | Native allocated MiB | Thread delta |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Trojan | FD | 480/480 | 960/960 | 3.63/3.65 | 154.2 → 173.7 | 18.1 → 17.8 | -1 |
| Trojan | PP | 480/480 | 959/960 | 10.04/7.07 | 162.4 → 163.2 | 18.3 → 17.8 | +0 |
| SS2022 chacha20-poly1305 | FD | 480/480 | 960/960 | 1.80/1.75 | 167.6 → 166.3 | 25.9 → 25.8 | -1 |
| SS2022 chacha20-poly1305 | PP | 480/480 | 960/960 | 3.87/3.88 | 153.1 → 160.4 | 26.5 → 24.4 | -1 |
| SS2022 aes-128-gcm | FD | 480/480 | 960/960 | 1.85/1.83 | 166.2 → 168.0 | 26.8 → 25.6 | -1 |
| SS2022 aes-128-gcm | PP | 480/480 | 959/960 | 9.55/3.89 | 161.0 → 160.2 | 25.8 → 25.6 | +0 |
| SS2022 aes-256-gcm | FD | 480/480 | 960/960 | 1.86/1.84 | 165.7 → 167.1 | 26.0 → 24.9 | -1 |
| SS2022 aes-256-gcm | PP | 480/480 | 960/960 | 3.93/3.95 | 159.8 → 152.1 | 26.7 → 25.2 | -1 |
| VMess aes-128-gcm | FD | 480/480 | 960/960 | 2.24/2.20 | 151.2 → 157.6 | 16.9 → 16.7 | -1 |
| VMess aes-128-gcm | PP | 480/480 | 960/960 | 4.42/4.33 | 150.6 → 154.1 | 17.0 → 16.4 | -1 |
| VMess chacha20-poly1305 | FD | 480/480 | 960/960 | 2.18/2.18 | 152.4 → 158.8 | 16.7 → 16.6 | -1 |
| VMess chacha20-poly1305 | PP | 480/480 | 960/960 | 4.30/4.26 | 153.4 → 154.0 | 17.2 → 16.4 | -1 |

The resource series contains 2 failed UDP attempts. Inspect every row
and the [machine-readable report](manifest.json), including failed trials;
there is no claim of universal delivery, zero RSS growth or Go/sing-box CPU
parity. Two request bursts per configuration are not the five calibrated
samples required by the performance gate. The earlier successful isolated
Trojan FD repeat is retained separately, not averaged into this series.

## Idle CPU finding

Across all twelve PacketPump recovery intervals the process still consumed
100.5–101.6% of one core, versus 2.0–2.6% with FileDescriptor. A fresh idle
control attributed 10.95 CPU seconds to `xray-tun-in`; the corresponding FD
control consumed 0.31 process CPU seconds over 14.63 wall seconds. On Android,
`FileInputStream.read` returns zero for an empty nonblocking descriptor
(`EAGAIN`). The previous inbound loop retried immediately, without waiting.

The separately identified [readiness-wait follow-up](packet-pump-fix/README.md)
uses bounded `Os.poll` only after empty reads, with unchanged packet buffers.
CPU and memory are both acceptance concerns: passing the bounded RSS/thread
criteria below does **not** make this original CPU behavior acceptable.

## Retained UDP timeouts

The initial full-VPN Trojan FD load passed 240/240 HTTP and 479/480 UDP.
An isolated-UID repeat passed both FD cycles, then PP returned 479/480 UDP.
In six alternating diagnostic trials, three FD runs returned 480/480 and
three PP runs 479/480. Four reordered controls (PP, PP, FD, FD) all returned
480/480. This does not establish a PacketPump-specific defect.

For the three correlated losses, the backend submitted the matching 83-byte
response to its UDP transport about five seconds before the client timed out.
This is application send telemetry, not a packet capture proving NIC delivery. The core recorded
all 481 UDP requests (one ordinary plus 480 stress) but only 480 decoded
responses, with no sampled TUN drops. The loss is before decoded UDP delivery
to Android; its exact location between the backend, Go server, carrier and
native reader remains unresolved. There is no equivalent physical Go client
control, so this report does not claim Xray-core clients reproduce the loss.
The all-cipher series also retained one Trojan PP and one SS2022 AES-128 PP
timeout. These small-packet observations are separate from the owner-deferred
SS2022 WAN/DF investigation.

## Negative controls and cleanup

Malformed Trojan, SS2022 and VMess links were rejected on the device without
changing the encrypted profile. The pending plaintext was deleted and the
nonsecret redaction marker was absent from host logs. With the VPN stopped,
the synthetic HTTP and UDP targets both failed as expected; neither succeeded.
The hard-coded `unrecoveredTransitions` telemetry field is not used as proof.
Fixture credentials from all three baseline servers were removed when stopped.
Phone-profile cleanup is recorded in the follow-up manifest, which reuses the
same isolated test applications; see its final cleanup verdict. Original base/rc07 applications remain untouched.

## Reproduction and remaining work

Use the checked-in [Android fixture](../../../scripts/run-v08-android-protocol-fixture.py)
with `--protocol v08`, a LAN address, the pinned reference binary/hash and a
new private output directory. Its lifetime is bounded to 1–1800 seconds.
Build host/probe Debug APKs with `-PdeviceGateApplicationIdSuffix=.v08` and
`-Pandroid.injected.build.abi=arm64-v8a`, pointing `XRAY_FFI_ANDROID_DIR` to
the verified candidate native directory. Install test-only APKs with `adb
install -t` and obtain the ordinary Android VPN consent.

The older full-VPN and first isolated harnesses can be reconstructed by
applying their respective included patches to core `2c04d98`. Every changed
source hash was checked against its original build identity, and both patches
passed `git apply --check` against the candidate. The third diagnostic
harness is preserved in `diagnostic-harness.patch`, also relative to `2c04d98`. Controls use the documented activity
commands in [Android integration](../../../platform/android/README.md), with
`tun-backend` explicit and `probe-only=true` for controlled loads.

The [parameterized replay scripts](reproduce/README.md) preserve the measured
controller logic with private device/address settings supplied at run time.
Run `python3 docs/device-results/2026-10-04-android-v08/verify.py` to verify
artifact hashes, event aggregates and the native/adapter identity distinction.

Android WAN transitions, lock/wake, the complete shared/legacy matrix and
formal profiler/evidence archive remain open. Wi-Fi/cellular coverage requires
a working SIM and operator actions; it is not inferred from local tests.
No merge, release or package publication was performed. A later SDK pin must
identify the readiness-wait adapter change separately from this native baseline.
