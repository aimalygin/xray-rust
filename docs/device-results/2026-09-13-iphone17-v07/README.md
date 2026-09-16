# iPhone 17 Pro Max: v0.7 network transitions and lock/wake

On 2026-09-13 a physical iPhone 17 Pro Max (`iPhone18,2`, iOS 26.6.2 /
23G90) tested the development WireGuard and Hysteria 2 clients against an
owner-controlled public IPv4 VPS. Hysteria 2 passed the bounded Wi-Fi →
cellular → Wi-Fi and lock/wake sequence. WireGuard did not recover traffic
within 45 seconds after leaving Wi-Fi; its separate Wi-Fi lock/wake check passed.
This campaign identified a v0.7 release blocker; its failed verdicts remain unchanged.
The subsequent [carrier-rebind fix and device check](../2026-09-14-iphone17-wireguard-rebind/README.md)
passed the same bounded transition sequence on 2026-09-14.

The package remains 0.6.1 and the ABI is 1.5. Signed Debug app/extension builds
use the release iOS-arm64 Rust library and iOS 15.0 deployment target. This is
a dirty development tree, not an RC. See [manifest.json](manifest.json) for
source/binary identities, event hashes, timings and resource samples.

## Completed observations

| Check | WireGuard | Hysteria 2 |
| --- | --- | --- |
| Wi-Fi baseline: IPv4/IPv6 TCP/UDP and tunnel DNS | Passed | Passed |
| Automatic recovery after Wi-Fi → cellular | Failed: no full traffic recovery within 45 s | Passed in 34.07 s, after three retries |
| Cellular → Wi-Fi | Passed in 4.28 s in the diagnostic repeat | Passed in 2.71 s |
| Wi-Fi lock/wake | Passed twice: 90.54/53.80 s locked; full traffic in 5.33/6.59 s after unlock | Passed after 50.51 s locked; full traffic in 4.07 s after unlock |

Recovery times end after the **whole** TCP/UDP/DNS sequence succeeds, not at
the first packet or handshake. The test allows 45 seconds of active recovery.
The Hysteria cellular result meets that test budget but includes a noticeable
34-second interruption; it is not a seamless handover claim. A later
[Hysteria carrier-migration fix](../2026-09-14-iphone17-hysteria-rebind/README.md)
addresses this delay; the measurements here describe the original build. Runtime identifiers
remain unchanged across its successful stages and the separate WireGuard lock
check. Connection closure returns active TCP/UDP counters to zero before stop.

The first valid WireGuard cellular failure is in
[wireguard-cellular-events.jsonl](wireguard-cellular-events.jsonl), 18:37:58–18:39:12
UTC. Wi-Fi baseline completes at 18:38:07, cellular is observed at 18:38:26,
and recovery ends with a network timeout at 18:39:11. The core remains alive,
with the same runtime identifier and no sampled TUN loop exits. That harness
version stops on the cellular failure, so it does not measure return to Wi-Fi.
The separate [lock run](wireguard-lock-events.jsonl) and the complete
[Hysteria sequence](hysteria-transitions-events.jsonl) retain their own verdicts.

In the [WireGuard diagnostic repeat](wireguard-reset-events.jsonl), the Wi-Fi
baseline passed before the operator disabled Wi-Fi. Automatic cellular recovery
again timed out after 45 seconds. The provider then accepted a request to close
active connections; fresh flows still failed for another 45 seconds. Returning
to Wi-Fi restored the full traffic sequence in 4.28 seconds with the same core
identifier. This intervention closes application connections; it does not
establish that the underlying WireGuard carrier sockets were rebound. The
overall result remains failed regardless of the later successful Wi-Fi stages.

Across the four completed evidence runs, sampled maximum extension resident
memory was 27.94 MiB for WireGuard and 27.00 MiB for Hysteria; maximum physical
footprint was 4.52/4.33 MiB respectively. All samples reported zero dropped
packets and zero TUN read/write loop exits. These counters do not prove that
carrier packets were delivered during the failed transition.

## Network diagnosis and limits

Before enabling the VPN, the default cellular path reports IPv6 support and
no IPv4 support. A separate payload-free UDP `NWConnection` targeting the
literal IPv4 VPS reports an unavailable route. The owner confirmed LTE/5G was
visible with Wi-Fi disabled and ordinary Safari pages loaded with the VPN off.
The VPS has no global IPv6 address. These are observations, not proof that
all IPv4 transport is impossible on the carrier: Hysteria subsequently exchanges
the full controlled payload set over cellular to this same IPv4 server.

The provider resolves carrier domains at tunnel startup and excludes literal
carrier addresses directly. It has no path-change rebootstrap. WireGuard keeps
one shared device and protected UDP sockets while the device remains live;
Hysteria can replace a closed cached QUIC session. Those differences guide the
next investigation. The exact network mechanism, NAT64 prefix and packet-level
cause were not established by these tests. A no-payload route diagnostic must
not be treated as proof that the actual protocol transport cannot work.

The DEBUG harness now separates physical Wi-Fi/cellular availability from
reachability of the IPv4 carrier destination, waits for a stable Wi-Fi route
before starting, and retries the full traffic sequence with a shared 45-second
deadline. Its diagnostic reset mode explicitly closes connections after a
failed cellular stage; success after that intervention does not turn the
automatic transition verdict into a pass.

Earlier diagnostic runs are preserved separately:

- [Route-gating run](diagnostic-route-gating-events.jsonl): a flawed observer
  waited for a usable IPv4 carrier route before recognizing cellular, so no
  cellular traffic attempt took place. This is a harness failure.
- [Pre-VPN cellular observation](diagnostic-cellular-before-vpn-events.jsonl):
  interrupted diagnostic run; no completion verdict is claimed.
- [Startup run](diagnostic-startup-events.jsonl): the first TCP request timed
  out while Wi-Fi was still settling. Later runs add a stable-route wait and
  bounded baseline retry. This startup observation does not prove a handover
  failure and its underlying cause is not claimed to be fixed in production.
- [Premature-switch run](diagnostic-premature-switch-events.jsonl): Wi-Fi was
  disabled before baseline TCP/UDP/DNS completed. The first TCP attempt also
  needed a retry before the switch. Neither the cellular transition nor the
  diagnostic intervention was reached; this run is excluded from their verdicts.

Each traffic sequence opens fresh connections: three exact 65,536-byte TCP
echoes (IPv4 literal, IPv6 literal, test hostname), two UDP echoes (1,392/1,372
bytes), and one explicit A query through the tunnel DNS anchor. It does not
establish continuity of an existing TCP/UDP application session across a network
change. A stable core identifier does not establish a stable cryptographic
session. Protected-data notifications and foreground/background events bound
the lock interval; this does not measure hardware deep sleep or continuous
background traffic. Memory figures are sparse extension samples, not continuous
peaks, throughput, energy, memory-pressure or soak measurements. No Android
device or independent native protocol server was used in this campaign.

## Fixture and reproduction

The owner authorized the temporary fixture script/systemd unit on UDP 53053.
Only the pre-existing UDP test service is paused; the existing TCP service on
the same numeric port and the separate loopback test service remain unchanged.
The unit has a lifetime limit and an `ExecStopPost` restoration action.

The existing VPS Xray binary reports `Xray 26.7.28 5ca6f4b`, Go 1.26.5,
linux/amd64. Its SHA-256 is pinned in the manifest. Its complete clean Go VCS
stamp could not be verified; a binary hash pins identity and does not establish
upstream provenance. The locally rebuilt clean Linux reference was not uploaded.

The [fixture generator](../../../scripts/run-v07-apple-protocol-fixture.py)
generates private ephemeral WireGuard keys/PSK or Hysteria authentication and
a pinned one-day TLS certificate. Documentation destination ranges route to
loopback TCP/UDP echo and DNS backends; other destinations are blocked. No
production proxy configuration, host routing, firewall or external DNS records
are changed. Use one protocol at a time on the reserved UDP port:

```sh
python3 scripts/run-v07-apple-protocol-fixture.py \
  --bind "$VPS_IPV4" --reference-binary "$XRAY_REFERENCE" \
  --reference-sha256 "$EXPECTED_REFERENCE_SHA256" \
  --output "$NEW_PRIVATE_DIRECTORY" --protocol wireguard --port 53053 \
  --mode transitions --seconds 1200
```

Modes are `smoke`, `transitions`, `lock-wake`, and `transitions-reset` (the last
adds a WireGuard-only diagnostic intervention). The deployed script predates
the last two CLI choices; the corresponding downloaded private JSON `mode`
was set locally before copying it to the phone. No authentication fields were
changed. The manifest preserves the deployed script hash separately.

Install the signed Debug app and copy the fixture to `Documents/v07-probe.json`
in its data container. Launch with `XRAY_V07_DEVICE_PROBE=1` via `devicectl` and
follow the on-device instructions. After completion, retrieve
`Documents/v07-result.json`; the published event files are compared with console
events. Runtime JSON adds the fixture DNS port and TLS pin, so this is separate
from the share-link/file importer check and does not validate the import UI.

The probe removes only its separate test VPN manager, keychain configuration
and input fixture on completion. Normal app launch never enters the probe.
Credentials and raw console/server logs are excluded from published evidence.

Cleanup was verified after the final run: the original UDP 53053 test service
is active again; the other TCP and loopback test services retain their original
process IDs. Both temporary instances are stopped and their unit, directory
and credentials are removed. Local temporary profiles and SSH helpers were
deleted. The device reports no input fixture, normal launch loads the one
pre-existing VPN manager, and the app was relaunched without the debug flag or
console attachment. The manifest records these checks.
