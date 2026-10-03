# iPhone 17 Pro Max: v0.8 client protocols

On 2026-10-03, a physical iPhone 17 Pro Max (`iPhone18,2`, iOS 27.0 / 24A437)
tested Trojan, Shadowsocks 2022 and VMess AEAD through the Swift adapter,
FFI and file-descriptor TUN path. All LAN checks passed, including the three
SS2022 methods and explicit VMess AES/ChaCha. Trojan and VMess passed the public
VPS transition sequence. SS2022 passed that sequence **only with the diagnostic
UDP fragmentation relay described below**; its original VPS baseline failed.
This is bounded device evidence, not complete v0.8 release acceptance.

The unchanged, clean runtime source is core
`de33998158e84c03f280f979ba2d4212072e5bc4`, tree
`3d628e533f68671721ecf2e6ad786c15ce6f7291`, with SDK pin
`0148543fef8736e01625bc678ca321cc483e1e12`. The freshly built release
`aarch64-apple-ios` library has SHA-256
`94e80251e1e4f867c23339455c5cfcad4cb429aafe3e2739fb5e9b1d0da6ab2d`.
The signed app/extension are Debug builds, ABI 1.8, with iOS 15 deployment target.
Only the device slice of the local XCFramework was refreshed; no current identity
is claimed for its other slices or for a publishable SDK artifact.

[manifest.json](manifest.json) binds sources, binaries, reports, counts, timings
and cleanup. Each of the nine device JSON reports was compared exactly with
its console events before conversion to the published JSONL format. Raw console
logs, packet headers containing endpoint addresses, credentials and signing
profiles are not published. The harness retains its historical `v07` names.

## Completed observations

| Scenario | Result |
| --- | --- |
| LAN smoke | Trojan, SS2022 ChaCha, VMess auto: three start/traffic/close/recovery/stop cycles each |
| LAN explicit ciphers | SS2022 AES-128-GCM and AES-256-GCM; VMess AES-128-GCM and ChaCha20-Poly1305: three cycles each |
| LAN lock/wake | All three protocols passed; complete traffic after unlock took 2.027 / 1.864 / 1.858 s respectively |
| Original VPS Trojan | Wi-Fi → cellular → Wi-Fi and lock/wake passed |
| Original VPS VMess auto | Wi-Fi → cellular → Wi-Fi and lock/wake passed |
| Original VPS SS2022 ChaCha | **Failed** on IPv6 UDP during Wi-Fi baseline; no transition was reached |
| VPS SS2022 with diagnostic fragmentation relay | Three smoke cycles and the full transition/lock sequence passed |

Across the seven passed runs: **30 starts/stops, 198 TCP echoes, 132 UDP echoes,
66 explicit DNS queries, 30 verified connection closures and 96 resource samples**.
The two failed runs remain separate and are excluded from these totals.

| VPS protocol / fixture | Cellular | Return to Wi-Fi | After unlock | Observed lock |
| --- | ---: | ---: | ---: | ---: |
| Trojan / original | 4.908 s | 4.402 s | 4.240 s | 45.932 s |
| VMess auto / original | 3.944 s | 3.340 s | 3.466 s | 36.380 s |
| SS2022 ChaCha / fragmentation relay | 3.535 s | 3.277 s | 3.431 s | 47.792 s |

These are **active recovery durations to completion of the entire TCP/UDP/DNS
sequence**, not first-packet latency or seamless handover measurements. All
listed stages passed without retries and retained the core runtime identifier.
Path/unlock-to-completion times, including foreground delay, are recorded
separately in the events and manifest.

Maximum sampled extension RSS / physical footprint across passed runs:
Trojan **34.67 / 4.88 MiB**, SS2022 **28.75 / 4.49 MiB**, VMess **31.64 / 5.13 MiB**.
Every such sample reported zero dropped packets and zero TUN read/write loop
exits. These are sparse samples, not continuous peaks or a leak/CPU/energy claim.

## Preserved failures and UDP diagnosis

The first Trojan run passed its Wi-Fi baseline but did not observe cellular
within the 180-second action timeout. No cellular traffic was attempted in
that run. The owner confirmed Wi-Fi was off after completion; the timing of
the switch relative to the timeout was not established. A fresh launch observed
cellular before VPN startup, and the complete repeat passed. The original
[timeout verdict](trojan-transition-timeout-events.jsonl) remains failed.

The original [SS2022 VPS run](ss2022-baseline-failure-events.jsonl) passed TCP
and 1,392-byte IPv4 UDP echoes but timed out on the 1,372-byte IPv6 UDP echo on
four attempts. The same phone, binary and payload sizes had passed on LAN.
The server accepted the requests. A Go control using the pinned peer's
`sing-shadowsocks` implementation reproduced size-dependent losses, excluding
a Rust-only explanation for that observed failure.

The [size sweep](ss2022-go-size-control.jsonl) passed 32/40 exchanges. Captured
headers show the VPS emitted the problematic replies: encrypted UDP lengths
1,454/1,466 bytes, IPv4 total lengths 1,482/1,494, with DF set. Smaller replies
and some larger fragmented exchanges succeeded. The exact dropping hop and
path MTU were not determined; the capture is evidence of emitted packets,
not delivery to the phone.

A temporary UDP relay on the **same reserved public port 53053** forwarded
encrypted packets unchanged to the unmodified Xray peer on loopback. It set
Linux `IP_MTU_DISCOVER=IP_PMTUDISC_DONT` on its own public socket, permitting
fragmentation. TCP continued directly to Xray on 53053. No host routes,
firewall, sysctl, production service or client code was changed.

The first relay control passed [40/40 Go exchanges](ss2022-go-dffree-control.jsonl)
and [three unchanged iPhone smoke cycles](ss2022-fragmentation-smoke-events.jsonl).
A subsequent A/B/A test changed only that relay socket option, with the same
running fixture and credentials:

| Setting | IPv6 target, 1,372-byte payload | Whole 40-case sweep |
| --- | ---: | ---: |
| Allow fragmentation, before | 2/2 passed | 34/40 |
| Linux default DF behavior | 0/2 passed | 34/40 |
| Allow fragmentation, after | 2/2 passed | 36/40 |

The larger sweep retains additional/intermittent losses, including fragmented
requests that may not reach the server. Allowing fragmentation addresses the
specific original response failure in this control; it is **not a universal
UDP reliability fix**. The successful [SS2022 transition run](ss2022-fragmentation-transitions-events.jsonl)
uses this explicit relay condition. It does not turn the original failure into
a pass or justify weakening client authentication/address checks. Production
SS2022 native UDP acceptance still needs a suitable path/MTU setup and separate
validation of larger datagrams. No client fix is claimed by this campaign.

## Reproduction and limits

The [fixture generator](../../../scripts/run-v07-apple-protocol-fixture.py)
starts bounded loopback echo/DNS backends, routes only documentation address
ranges to them, blocks other destinations and creates ephemeral credentials.
The local clean Xray reference is revision
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. The existing VPS binary reports
26.7.28 / 5ca6f4b, and its SHA-256 is pinned in the manifest. Its full clean Go
VCS stamp was not verified; binary identity does not establish provenance.

Build the iOS device library with `--locked --offline --release -p xray-ffi
--target aarch64-apple-ios`, refresh that XCFramework slice, then build/install
the signed Debug `XrayClient` scheme for the physical device. Existing signing
profiles included this iPhone; no account/device registration change was made.

For a new private fixture directory on the reserved VPS port:

```sh
python3 scripts/run-v07-apple-protocol-fixture.py \
  --bind "$VPS_IPV4" --reference-binary "$XRAY_REFERENCE" \
  --reference-sha256 "$EXPECTED_REFERENCE_SHA256" \
  --output "$NEW_PRIVATE_DIRECTORY" --protocol trojan --port 53053 \
  --mode transitions --seconds 780
```

Run one protocol at a time. The bounded transient service pauses only the old
test services using the needed TCP/UDP port and restores them with `ExecStopPost`.
Use `vmess` or `shadowsocks2022` for the other profiles. The published
[cipher fixture](run-cipher-fixture.py) is the exact LAN wrapper; place it under
`target/<campaign>/` in the core checkout to retain its relative root lookup.

For the fragmentation diagnostic, place the unchanged fixture generator next
to [fixture-dffree.py](fixture-dffree.py) as `fixture.py`, and invoke the wrapper
with the same SS2022 arguments. Its private `df-mode` file selects Linux socket
values 0/1; `df-applied.json` reports the actual value. The earlier smoke control
used a fixed-0 version without the mode-file loop. Build
[ss2022-udp-control.go](ss2022-udp-control.go) with `go -C Xray-core build
-mod=readonly`, using an absolute source path and the pinned checkout, then
pass the private `v07-probe.json` path to the resulting binary. It tests two
fresh associations for each family/size. The preliminary eight-case control
used four sizes, one association each and a three-second timeout; all 40-case
sweeps use the published source and a 1.5-second timeout.

Copy the generated profile to the app's `Documents/v07-probe.json`, launch via
`devicectl` with `XRAY_V07_DEVICE_PROBE=1`, follow the prompts, and retrieve
`Documents/v07-result.json` before another launch overwrites it. The harness
performs three exact 65,536-byte TCP echoes (IPv4/IPv6 literals and a test domain),
two UDP echoes (1,392/1,372 bytes) and an explicit A query through tunnel DNS.
Imports use the real Swift→FFI importer; runtime JSON separately supplies the
fixture DNS port and TLS pin. This does not validate the profile-import UI.

Transitions open fresh flows, so established-session continuity is untested.
Lock notifications do not prove hardware deep sleep or continuous background
traffic. WAN checks cover SS2022 ChaCha and VMess auto; explicit cipher variants
were tested on LAN. Startup cancellation, broader resource/performance and
shared legacy scenarios are not closed by this report. Android hardware and
the complete exact-candidate schema-4 release archive remain outstanding.

Final cleanup was verified: all temporary units are inactive and the remote
private directory is removed; the original TCP/UDP test services are active.
Production and the separate loopback service retain their original process IDs.
The phone has no input fixture and was relaunched without the probe flag.
Only the separate test VPN manager/keychain configuration was removed; normal
profiles were preserved. No merge, tag, release or package publication occurred.
