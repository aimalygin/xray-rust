# iPhone 17 Pro Max: WireGuard carrier-rebind fix

On 2026-09-14 the installed development candidate passed the full bounded
Wi-Fi → cellular → Wi-Fi and lock/wake sequence against the owner's public
IPv4 VPS. This addresses the reproduced [2026-09-13 cellular recovery
blocker](../2026-09-13-iphone17-v07/README.md) in this scenario. It is one completed
physical-device run, not a v0.7 release qualification or a seamless-handover claim.

## Device result

| Stage | Result | Time to finish the complete traffic check |
| --- | --- | --- |
| Initial Wi-Fi | Passed | 5.88 s active check time |
| Wi-Fi → cellular | Passed, no retry | 12.13 s after path event |
| Cellular → Wi-Fi | Passed, no retry | 6.25 s after path event |
| Unlock after 108.76 s locked | Passed, no retry | 5.28 s after unlock |
| Close active connections / stop | Passed | TCP/UDP counters return to zero, VPN disconnects |

Every stage checks three exact 65,536-byte TCP echoes (inner IPv4, inner IPv6,
test hostname), two UDP echoes (1,392 and 1,372 bytes), and an explicit A query
through the tunnel DNS anchor. The complete run has 12 TCP, 8 UDP and 4 DNS
successes. The recovery timings include the whole traffic sequence; they are
not handshake latency or measured outage duration.

The runtime identifier stays unchanged across all stages. Five samples show
maximum resident memory of 25.91 MiB, physical footprint of 4.22 MiB and 9
threads. All report zero dropped packets and zero TUN read/write loop exits.
These are sparse samples, not continuous resource peaks. Lock duration comes
from protected-data and app lifecycle notifications, not a hardware sleep trace.

All 86 events in the [event file](wireguard-transitions-events.jsonl) match the
retrieved device JSON and console exactly. The run starts at 14:11:07 UTC and
finishes successfully at 14:14:46 UTC. [manifest.json](manifest.json) records
hashes, timings, source snapshot, checks and cleanup.

## Change and scope

Previously a live cached WireGuard device retained its outer UDP sockets when
the Apple network path changed. Closing application connections alone did not
recover cellular traffic in the failed campaign. The fix makes the packet-tunnel
runtime own an `NWPathMonitor`. It coalesces path changes for 500 ms, then asks
WireGuard to bind fresh carrier sockets through the original socket protector
and establish a fresh cryptographic session. The inner stack and flow objects
remain alive; the VPN core is not restarted.

Notifications that race lazy client creation are retained by a generation check.
Idle clients remain lazy. Bind or socket-protection failure closes the affected
client and releases flow budgets. The observer fences callbacks before core
teardown. C and Swift expose the request through additive ABI 1.6; the returned
count means accepted requests, not completed recovery.

The passed run supports carrier socket replacement as a remedy for the reproduced
failure. No packet capture established the exact OS routing/NAT mechanism.
Current peer endpoints are retained: this does not add endpoint DNS refresh,
DNS64/NAT64-prefix adaptation or Android/JNI network notifications. The Apple
path observer is production provider code; it does not depend on the DEBUG
probe UI remaining open.

Device checks open fresh application connections. Separate host tests retain
existing TCP/UDP objects across rebinds, but that does not establish uninterrupted
existing application sessions on this physical carrier. The stable runtime
identifier also does not imply a stable cryptographic session.

## Verification and build identity

[Host checks](host-checks.txt) passed on macOS arm64:

- Official `wireguard-go` reference/source checks and 18 live Rust scenarios,
  including existing TCP/UDP flows across two rebind bursts for each outer IP
  family, protection failure, roaming, server restart and timed rekey.
- Four core unit tests, including a network notification injected during first
  socket creation; 85 FFI tests; 30 final mobile artifact checks including the C
  harness and native symbol export.
- 164 selected Swift tests: 29 packet-pump, 133 provider, two network-observer.
- Strict Clippy for the changed Rust packages, formatting and diff checks.

An existing source guard still expected the old IPv6 interface prefix `/128`.
It was updated to the previously device-validated `/120`; outer-server route
exclusions remain `/128`. The final artifact run passed all 30 tests. No
production code changed during this resumed run after the device test started.

The phone is an iPhone 17 Pro Max (`iPhone18,2`) on iOS 26.6.2 / 23G90. It ran
the signed Debug app with release iOS-arm64 Rust library installed during the
2026-09-13 fix work and reports ABI 1.6. The prior `target/` directory was removed
before resumption, so original app/library hashes and build logs are unavailable.
The manifest hashes the inspected current sources; those hashes do not prove a
byte-for-byte match to the installed executable. There was no fresh iOS build in
this resumed run. A fresh macOS release library with deployment target 11.0 and
macOS-only XCFramework was built for the Swift tests; it is not a complete mobile
SDK artifact. Package version remains 0.6.1 while development targets 0.7.

Hysteria's earlier result remains in the previous report; this campaign does
not rerun its device scenario. Linux CI, Android, broader carriers, endpoint
address-family changes, sustained load, energy and recovery-latency work remain
open.

## Fixture and cleanup

The previously authorized temporary fixture used UDP 53053 and the existing VPS
Xray binary (`26.7.28 5ca6f4b`, Go 1.26.5 linux/amd64), with its SHA-256 pinned in
the manifest. Its full clean upstream VCS provenance was not established; no new
binary was uploaded. The [fixture script](../../../scripts/run-v07-apple-protocol-fixture.py)
generates ephemeral keys/PSK, directs documentation-address traffic to loopback
echo/DNS services, and blocks unrelated destinations. Run it with `--protocol
wireguard --mode transitions` using a new private output directory, then copy its
private input to `Documents/v07-probe.json` and launch the signed Debug app with
`XRAY_V07_DEVICE_PROBE=1`. Follow the on-device instructions and retrieve
`Documents/v07-result.json` after completion.

The temporary service was stopped, its unit and private VPS directory removed,
and the original UDP 53053 listener restored. The two other pre-existing test
services remain active with their original PIDs. The test input, temporary local
fixture and SSH helpers were removed. Normal app launch loads the one existing
VPN manager; the app was left open without probe flags or console attachment.
Credentials and raw device/server logs are not included in this report.
