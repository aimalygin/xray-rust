# iPhone 17 Pro Max: lifecycle, CPU, memory and legacy checks

Physical follow-up on 2026-10-04, iPhone 17 Pro Max (`iPhone18,2`), now running
**iOS 27.0.1 / 24A446**. These observations are separate from the
[2026-10-03 campaign](../2026-10-03-iphone17-v08/README.md) on iOS 27.0.
This is bounded device evidence, not a complete v0.8 release archive.

The later [0.7/0.8 WireGuard baseline and Trojan repeats](../2026-10-04-iphone17-wg-baseline/README.md)
passed without reproducing the failures retained here. They do not establish a
root cause or replace these original verdicts.

The release Rust iOS-arm64 library is unchanged from runtime candidate
`de33998158e84c03f280f979ba2d4212072e5bc4`, SHA-256
`94e80251e1e4f867c23339455c5cfcad4cb429aafe3e2739fb5e9b1d0da6ab2d`.
SDK HEAD `923aaaa7113d27f8e6191af358c0bd2918ddc395` still pins that candidate.
The host app and extension are fresh signed **Debug** builds. Local changes add
reference-app instrumentation and test scenarios; the Rust library, vendored
SDK sources, public ABI, shipping tunnel provider and SDK pin are unchanged.
The app was built with Xcode 27.0 / 27A266a.
The exact modified source files and binaries are hashed in
[manifest.json](manifest.json). The source tree was dirty when built; no clean
candidate or canonical XCFramework publication is claimed.

## Results

Across completed lifecycle series: **24 cancellations while connecting and 40
rapid restart cycles passed**, including all seven new protocol/cipher
configurations and the extra Trojan control. Each configuration passed at
least three cancellations and five rapid restarts with traffic after each start.
Nine complete invocations passed; three failed and one was interrupted by the
collector. Completed Trojan/SS2022 resource sub-runs in the interrupted
invocation are counted separately from full-run verdicts.

Hysteria2, VLESS/REALITY and XHTTP over HTTP/1.1, HTTP/2 and HTTP/3 each passed
three smoke/close/recovery cycles. WireGuard passed its third three-cycle run,
but failed the two earlier invocations described below. A passing repeat does
not resolve those intermittent failures.

All **28 completed load intervals** (seven configurations, two cycles, two
concurrency levels) passed payload verification and the memory/recovery budgets.
All resource samples retained one runtime per configuration, zero TUN dropped
packets and zero TUN read/write loop exits. A zero TUN counter does not prove
zero packet loss on Wi-Fi or in the encrypted carrier.

Sampled extension memory, MiB. Recovered is the final sample after the second
eight-flow stage; all four recovery checkpoints are retained in the manifest.

| Configuration | Baseline footprint | Peak footprint | Recovered footprint | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| Trojan | 4.25 | 4.69 | 4.10 | 36.27 |
| SS2022 ChaCha | 3.83 | 4.41 | 3.80 | 31.55 |
| SS2022 AES-128 | 3.81 | 4.45 | 3.85 | 31.61 |
| SS2022 AES-256 | 3.74 | 4.50 | 3.85 | 31.30 |
| VMess auto | 3.88 | 4.19 | 3.91 | 31.98 |
| VMess AES-128 | 3.78 | 4.55 | 3.81 | 31.28 |
| VMess ChaCha | 3.75 | 4.53 | 3.80 | 30.92 |

CPU and completed echo rates: ranges are the **two observed intervals**, not
confidence intervals. These workloads do not establish maximum tunnel throughput.
The four explicit cipher runs and part of the VMess-auto repeat recorded
thermal state `fair`; the initial Trojan/SS2022 runs recorded `nominal`. The phone remained USB-connected. There is
no cold-device, energy, cross-protocol ranking or Xray/sing-box comparison claim.

| Configuration | CPU, 1 flow | Echo MiB/s, 1 flow | CPU, 8 flows | Echo MiB/s, 8 flows |
| --- | ---: | ---: | ---: | ---: |
| Trojan | 5.12–7.83% | 1.87–2.20 | 18.84–31.31% | 8.83–11.87 |
| SS2022 ChaCha | 9.24–9.60% | 2.56–2.66 | 36.11–41.22% | 10.55–12.54 |
| SS2022 AES-128 | 6.24–8.43% | 1.49–2.43 | 29.05–32.08% | 9.33–10.37 |
| SS2022 AES-256 | 8.34–9.20% | 2.26–2.28 | 24.35–29.31% | 7.39–9.35 |
| VMess auto | 5.05–9.57% | 2.01–2.40 | 18.99–24.77% | 7.49–9.87 |
| VMess AES-128 | 8.00–8.96% | 2.15–2.34 | 24.99–28.04% | 7.90–8.88 |
| VMess ChaCha | 7.78–7.92% | 1.73–1.90 | 12.46–20.82% | 3.06–5.49 |

The largest observed load footprint was **4.69 MiB**; final recovered footprints
were **3.80–4.10 MiB**, differing from their baselines by **−0.16 to +0.11 MiB**.
Peak RSS was **30.92–36.27 MiB** across configurations. These load numbers exclude
the separate lifecycle/legacy smoke samples, whose peaks remain in the raw events.

## Method

The existing DEBUG probe uses a separate `Xray v0.7 Device Probe` VPN manager,
Swift profile import, the FFI and the file-descriptor TUN path. It preserves the
user's stored profiles. TLS fixtures authenticate a fresh pinned certificate;
REALITY uses fresh X25519 keys and the existing `www.google.com:443` TLS decoy.
The clean local Xray-core peer remains revision
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, with its binary SHA-256 pinned.
Application echo/DNS traffic stays on the local fixture. No VPS service is used.

Lifecycle mode cancels `controller.start` only after observing **connecting**,
requires `CancellationError`, checks disconnected/invalid status again after
one second, then reconnects and verifies traffic. It repeats three times per
configuration, followed by five start/traffic/stop cycles without an added
pause. A missed cancellation race fails the test instead of counting as a pass.
Cancellation event durations include the deliberate one-second settling check;
they are not raw stop latency.
Every traffic sequence verifies three exact 65,536-byte TCP echoes (IPv4/IPv6
literals and a fresh domain), two UDP echoes (1,392/1,372 bytes), and routed DNS.
These checks establish observable tunnel cancellation and usable subsequent
starts; they do not prove deallocation of every OS-owned object after stop.

Resource mode keeps one runtime per configuration. Each of two cycles runs
1 and 8 persistent TCP echo connections for a target of 20 seconds per stage,
using 64 KiB blocks with exact byte verification. Eight-flow stages alternate
IPv4 and IPv6 destinations; the single-flow stage is IPv4. Each lane is capped
at 512 MiB and has a total timeout of target duration plus 10 seconds; the
fixture's load-only TCP cap is 1 GiB. Completed bytes and actual measured wall
intervals are retained. These are sequential request/echo workloads on each
connection, not independent upload/download saturation benchmarks.

The reference app's DEBUG extension subclass answers an on-demand `getrusage`
request. User and system CPU time belong to the **VPN extension process**, not
the SwiftUI host app, and include all process threads and diagnostic overhead.
CPU percentage is `(delta user + delta system) / delta monotonic wall * 100`;
**100% means one fully occupied core**. PID and runtime identity must remain
unchanged across each measurement. Raw counters, delivered bytes, MiB/s and
CPU-seconds per GiB echoed are retained; echoed bytes count one direction,
although each byte traverses both directions. Wi-Fi throughput varies, so the
CPU percentages alone cannot rank protocol efficiency or establish Go parity.

RSS, physical footprint, threads and TUN counters are sampled about once per
second. After every stage, the probe closes the observed connection IDs,
verifies their disappearance, and samples five seconds of recovery. Budgets
were set in the harness before the run: footprint below 45 MiB, recovered
footprint no more than baseline + 8 MiB, recovered threads no more than
baseline + 8, and zero TUN read/write loop exits. Samples are not continuous
peaks, and two cycles do not establish a long-term leak bound. Thermal state
is recorded. This is not an energy/battery measurement, a 100+ flow stress
test, or a five-sample performance acceptance campaign.

## Preserved failures and collection limits

- [Initial Trojan lifecycle run](lifecycle-defaults-events.jsonl): real startup
  cancellation and the subsequent IPv4 echo passed, but the following IPv6 TCP
  echo timed out. A plain three-cycle control and two complete lifecycle series
  subsequently passed. The first failure remains failed; its cause is unknown.
- [First WireGuard run](legacy-wireguard-hysteria-events.jsonl): the initial TCP
  connection closed after approximately ten seconds. Hysteria was not reached
  in that combined run and was tested separately.
- [Second WireGuard run](legacy-wireguard-repeat-events.jsonl): full traffic and
  explicit connection cleanup passed in cycles 1 and 2. Cycle 3 also passed
  initial traffic and all TCP checks after cleanup, but the single 1,392-byte
  IPv4 UDP reply timed out. A third complete three-cycle run passed, with
  [backend length/timing metadata](wireguard-backend-metadata.json). Those
  metadata describe the successful third run and cannot locate the earlier
  failures. Intermittent WireGuard reliability is still unresolved; neither a
  newly introduced regression nor absence of regression is established.
- [First resource collection](resources-defaults-events.jsonl): Trojan and
  SS2022 ChaCha each finished all four stages, recovery, final traffic and stop.
  The collector then aborted during VMess after parsing a console JSON record
  interleaved with an OS log. Their completed per-protocol measurements remain
  usable; the unfinished VMess sequence is excluded from the resource summary.
  Its complete repeat is retained separately. This was a host collection bug,
  not a device protocol failure.

The corrected collector uses the atomic JSON report copied from the device as
its source of truth. Valid console JSON events are checked as an ordered subset
of that report; exact equality is reported separately for each run. A damaged
console line never becomes a fabricated event or a success verdict. All failed
and interrupted reports remain in the manifest. Private credentials, raw
console/server logs, signing profiles and physical device identifiers are not
published.

The previous SS2022 WAN size/DF condition is unchanged by these LAN tests.
Android acceptance, the exact-candidate schema-4 archive, calibrated performance
requirements and canonical SDK artifacts remain separate release gates.

## Reproduce

Build/install the Debug `XrayClient` scheme for a signed physical iPhone using
the matching release iOS-arm64 Rust slice and the source identities in the
manifest. Do not replace the other XCFramework slices with unverified files.
Use a new private fixture directory for every invocation:

```sh
python3 scripts/run-v07-apple-protocol-fixture.py \
  --bind "$MAC_LAN_IPV4" --reference-binary "$PINNED_XRAY" \
  --reference-sha256 "$PINNED_XRAY_SHA256" \
  --output "$NEW_PRIVATE_DIRECTORY" --protocol v08 \
  --mode lifecycle --seconds 900
```

Use `--mode resources` for the 20-second load stages. For the four explicit
SS2022/VMess cipher configurations, replace the script with
`scripts/run-v08-apple-acceptance-fixture.py --suite ciphers`. For the four
VLESS/REALITY/XHTTP legacy controls, use that script with `--suite legacy
--mode smoke`. These multi-profile wrappers allocate separate LAN carrier ports; use the base
fixture for a single reserved VPS port. The original fixture's
`--protocol both --mode smoke` covers
WireGuard and Hysteria2; a failed first profile stops that invocation, so test
unreached profiles separately. The third WireGuard run used [this metadata wrapper](wireguard-metadata-fixture.py),
placed under `target/<campaign>/` so its relative root lookup resolves the core
checkout. It logs only backend byte counts and timing.
The fixture has a maximum lifetime of 1,800 s
and removes ephemeral configuration/keys on exit.

Copy the generated `v07-probe.json` to `Documents/v07-probe.json` in the app's
container, launch with `XRAY_V07_DEVICE_PROBE=1`, and copy
`Documents/v07-result.json` **before another probe run overwrites it**. Leave
Xray foreground; the probe temporarily disables automatic screen locking and
restores that setting on completion. Stop the owned fixture, verify removal of
the probe manager/input, and launch the app normally without the probe flag.
Do not run builds or competing load tests while collecting CPU evidence.

## Cleanup and validation

All runs used existing device signing. No account/device registration, release,
merge, tag, VPS configuration or production SDK source changed. The probe
removed its test manager, keychain config and input file; the host driver
stopped each owned fixture and relaunched the normal app. Device Documents
contained only result files at the final check, and no campaign process or
fixture credential file remained. Existing user profiles and old result files
were preserved.

Validation rehashed the measured source/binary inputs and every published event
file, recomputed the resource budgets, checked runtime identity and sampled TUN
counters, and retained all original verdicts. The physical Debug app build
succeeded. Canonical Swift/Kotlin/JNI/header sources (25 files) match the exact
SDK core pin. Gitleaks 8.30.1 reports no leaks in the published report; two app
SHA-256 digests required exact value/path/rule exceptions after rehashing the
binaries. All 18 scanner allowlist/positive-leak-control tests passed.
This report does not waive the unresolved failures or the remaining
[release gates](../../v08-release-readiness.md).
