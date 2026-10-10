# iPhone reliability repeats and SS2022 startup policy

The two ordered checks ran on 2026-10-04 using the unchanged native candidate.
The first completed **10/10** WireGuard/Trojan diagnostic invocations. The second
validated automatic SS2022 UDP socket configuration on **five starts, including
two restarts**, but retained new WAN losses. Neither result closes full release
acceptance or establishes a client runtime fix.

## 1. Bounded WireGuard / Trojan repeats

Five alternating pairs ran on the physical iPhone 17 Pro Max, each with fresh
ephemeral credentials and the same pinned local Go peer. WireGuard uses three
start/traffic/close/recovery/stop cycles per invocation. Trojan uses three actual
connecting cancellations with recovery, then five rapid restarts per invocation.

| Protocol | Complete invocations | Lifecycle operations | TCP echoes | UDP echoes | DNS checks |
| --- | ---: | --- | ---: | ---: | ---: |
| WireGuard | 5/5 | 15 starts and 15 verified close/recovery cycles | 90 | 60 | 30 |
| Trojan | 5/5 | 15 cancellations and 25 rapid restarts | 120 | 80 | 40 |

Every TCP exchange verifies 65536 bytes; UDP payloads are 1392 bytes for the
IPv4 target and 1372 for IPv6. Backend read/write/echo metadata independently
matches **all 210 TCP and 140 UDP exchanges**. All ten atomic device reports
exactly match valid console events. No timeout or acceptance budget was widened.

The first WireGuard TCP exchange takes 5.732 seconds, within the existing
10-second bound. The first accepted Go handshake appears about five seconds
after the device's connected/TCP-start events, followed by the backend open.
Without a client packet trace this does not determine which component caused
the delay. A [previous 0.7 control](../2026-10-04-iphone17-wg-baseline/README.md)
also took 7.264 seconds. No claim of a diagnosed startup regression is made.

The [original Trojan timeout and two WireGuard failures](../2026-10-04-iphone17-lifecycle-resources/README.md)
did not recur in this bounded series. Their failed verdicts and unknown causes
remain open; passing repeats do not prove they were fixed or quantify a failure
rate. macOS packet capture was unavailable to the current user. Normal GUI
workloads continued; this was a correctness campaign, not a CPU comparison.

## 2. Native SS2022 policy across server restarts

The [earlier A/B/A socket experiment](../2026-10-04-iphone17-ss2022-mtu/README.md)
localized a DF-dependent reply boundary. This campaign adds a service startup
hook for that same setting; see the [deployment recipe](../../ss2022-server-udp-pmtu.md).
The server binary, direct IPv4 carrier and reserved public port 53053 stay fixed.
No UDP relay, global sysctl, route, firewall or production service change is used.

`ExecStartPost` selects only the named service's single pinned Xray process and
native SS2022 UDP FD. Each of five successful starts records default 1 changing
to 0; read-only checks before/after traffic record 0. Each uses a distinct PID.
The controller PID is zero after startup: the helper exits. A wrong-hash negative
control fails startup, stops its fixture, removes ephemeral credentials and
restores the two reserved-port test services. Unit/audit data are published.

| Sequence | Service action / cipher | Go size trials | iPhone result |
| --- | --- | ---: | --- |
| 1 | start / ChaCha20-Poly1305 | **40/44** | 40/40 size trials |
| 2 | start / ChaCha20-Poly1305, header capture | **40/44** | 40/40 size trials |
| 3 | restart / AES-128-GCM | 44/44 | **38/40 size trials, failed verdict** |
| 4 | start / AES-256-GCM | 44/44 | 40/40 size trials |
| 5 | restart / AES-128-GCM | **43/44** | smoke passed: 18 TCP, 12 UDP, 6 DNS, 3 close/recovery cycles |

The Go sweep uses payload sizes 32, 1200, 1300, 1320, 1340, 1350, 1360, 1372,
1392, 1420 and 1450 bytes. The iPhone sweep omits 1320. Each tests both logical
target families twice with fresh associations, exact echo comparison and
1.5-second Go / 2-second iPhone deadlines. Both target families use an **IPv4
outer carrier**. Sequence 5's phone smoke uses the original 1392/1372-byte UDP
payloads; it is not another passing AES-128 full sweep. All failed trials remain
in the data, including ones in a batch that continued independent cipher checks.

### Remaining losses and capture limits

- Both ChaCha Go sweeps lose IPv4-target payloads 1420 and 1450, twice each.
  The captured repeat has no matching requests at the VPS interface or echo
  backend for those four trials. These requests would require IPv4 fragmentation.
  iPhone ChaCha passes both 40-case sweeps.
- AES-128 loses the iPhone's two IPv6-target 1420-byte requests. The backend
  has only the 38 successful echoes, and no corresponding large incoming packet
  appears during the failing interval; small background DNS exchanges continue.
  Its Go control passes those same payload sizes, including the small final
  fragments. A universal tiny-fragment filter is therefore not established.
- The last AES-128 Go repeat loses one **1300-byte IPv6-target** response. Its
  1390-byte outer request reaches the backend, and an unfragmented 1398-byte
  reply leaves the server with DF clear. The client receives no UDP response
  before timeout. Thus not all remaining loss is a large-fragment issue, nor
  does setting DONT eliminate every reply loss.

The startup hook cannot repair a request that never reaches its server socket.
These observations do not locate the exact dropping hop, distinguish client
send/path causes for absent requests, or exclude a client issue for the new
iPhone AES case. A client capture or a second controlled path is needed for
that distinction. No further retry-to-green campaign was performed.

The private capture records only Ethernet plus the first 20 IPv4 header bytes
(`snaplen=34`), with no UDP/application payload. The filter includes the reserved
UDP port and non-first UDP fragments from the known client NAT address. Such
non-first fragments could include other traffic from that address; attribution
uses direction, IP ID, length, ordering and the isolated Go interval. Published
metadata removes IP/MAC addresses. Kernel capture drops are zero. Three captures
miss the first **successful** Go exchange; the exact capture-start cause is not
established. This is explicitly recorded rather than claiming complete captures.

The verifier reconstructs and matches **169 captured Go request/reply pairs**
against wire lengths and ordered trials, including the failed 1300-byte reply.
Backend metadata accounts for every Go trial that reached the echo server,
including the three uncaptured successes. A 0.25-second window margin allows
for the two host clocks; cross-host timestamps are not network-latency evidence.
The AES-128 phone's coarse timestamps and packet window support absence at the
server capture point, not an end-to-end packet trace.

## Identities, reproduction and limits

The device is `iPhone18,2`, iOS 27.0.1 / 24A446. The existing Debug reference app
links the release Rust library from `de33998158e84c03f280f979ba2d4212072e5bc4`,
SHA-256 `94e80251e1e4f867c23339455c5cfcad4cb429aafe3e2739fb5e9b1d0da6ab2d`,
ABI 1.8 and TUN MTU 1500. App binary hashes match the previous campaign.
Runtime, canonical Swift/Kotlin source snapshots, SDK pin and artifact locks
are unchanged. The new executable code is a server administration helper.

The peer reports Xray-core 26.7.28 / 5ca6f4b, pinned binary SHA-256
`64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d`.
Its full clean Go VCS stamp was not verified. The Go client control and local
peer use the pinned `5ca6f4b7d4dc20a881d4330e498892697627ec0c` checkout/locked
dependencies recorded in the preceding report. The local step-1 peer's binary
SHA-256 is `fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99`;
the diagnostic wrapper enables private debug logs. The VPS runs Linux 6.8.0-79,
x86_64, systemd 255, interface MTU 1500. The helper is scoped to this platform;
its guard tests are included in ordinary repository CI.

For step 1 use the published [diagnostic fixture](../2026-10-04-iphone17-wg-baseline/diagnostic-fixture.py)
around [the base fixture](../../../scripts/run-v07-apple-protocol-fixture.py),
five alternating `wireguard --mode smoke` / `trojan --mode lifecycle` invocations.
Copy the fresh private envelope to `Documents/v07-probe.json`, launch with
`XRAY_V07_DEVICE_PROBE=1`, and collect `Documents/v07-result.json`. Never publish
the envelope or credentials. Each invocation removes its own test VPN entry
and returns to the normal app.

For step 2 the exact [initial](service-fixture.py) and
[captured](service-fixture-capture.py) fixture wrappers and
[temporary unit](test-fixture.service) are retained for reproducing the isolated
campaign. They expect the base fixture as `fixture.py`, the helper as
`set-pmtu.py`, private `bind`, `method` and (for capture) `capture-client` files,
and the explicit test directory in the wrapper. The wrappers generate fresh
keys, allow only synthetic echo/DNS destinations, record backend metadata and
expire after 780 seconds. The unit expires after 900 seconds and restores only
the two original test services on the reserved port. **Do not install this
test unit on another host unchanged.** Use the separately documented deployment
recipe for a managed service.

Build the [Go size control](../2026-10-04-iphone17-ss2022-mtu/ss2022-size-control.go)
against the pinned checkout with `go -C Xray-core build -mod=readonly`, putting
source/output paths outside that reference repository. Run it with the private
envelope path; retain every JSONL row even when its process exits zero. Its
process exit status alone does not mean all trials passed. For iPhone use
`mode=udp-sweep` or `smoke` as specified in the table. Wait for successful service
startup before traffic and run the helper with `--check` afterward.

`python3 verify-evidence.py` verifies hashes, all device verdicts, step-1 byte
counts, five startup audits, backend trial ordering, failed Go controls and
the captured request/reply correlations. Manifest source hashes bind the helper
and fixtures to this campaign. Sparse device memory observations remain in the
events; they do not establish peak-memory, CPU, energy, leak or performance
acceptance. No runtime optimization or throughput improvement is claimed.

Local validation passes the seven helper selector tests, 13 public-fixture
tests, 18 secret-scanner policy tests and the evidence verifier. Changed public
files pass secret scanning with no new exceptions. This validates the added
helper/report scope; native platform CI remains tied to its recorded revisions.

Cleanup is verified in [cleanup.json](cleanup.json). Temporary units/files and
remote credentials are removed, original reserved-port services are active,
production and unrelated loopback service PIDs are unchanged, and the host
PMTU sysctl remains unchanged. Local ephemeral profiles/SSH helpers are removed;
the phone input is absent and its normal app was restored. No merge, tag,
release, package publication or production deployment occurred. Android,
schema-4 evidence, remaining reliability causes and calibrated resource gates
remain separate acceptance work.
