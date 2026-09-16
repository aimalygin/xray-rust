# iPhone 17 Pro Max: Hysteria2 network recovery

The Hysteria2 carrier socket now updates when the Apple network path changes.
On 2026-09-14 two device runs completed the cellular traffic check without a
retry: the first in 3.81 seconds, the final repeat in
3.65 seconds, compared with 34.07 seconds
and three retries in the [previous build](../2026-09-13-iphone17-v07/README.md).
The final full sequence passed. The first run's overall failed verdict is
preserved separately because its aggregate-zero cleanup assertion failed.

## Final physical-device sequence

| Stage | Complete TCP/UDP/DNS check | First 64 KiB TCP exchange | Retries |
| --- | --- | --- | --- |
| Initial Wi-Fi | 2.57 s active test time | 0.98 s | 0 |
| Wi-Fi → cellular | 3.65 s after path event | 1.25 s | 0 |
| Cellular → Wi-Fi | 15.08 s after path event | 0.74 s | 1 |
| Unlock after 30.58 s locked | 3.04 s after unlock | 0.66 s | 0 |

Each stage exchanges exact 65,536-byte TCP payloads through inner IPv4, inner
IPv6 and a hostname; 1,392/1,372-byte UDP payloads; and an A query through the
VPN DNS anchor. The run records 15 TCP, 8 UDP and 4 DNS successes. These timings
include completed payload exchanges, not just a handshake or first packet.
The comparison is observational, not a controlled latency benchmark or a
performance guarantee across carriers. The final return to Wi-Fi needed one
retry and 15.08 seconds, versus 2.79 seconds in the first run. All three initial
TCP exchanges had already passed within roughly two seconds of the Wi-Fi path
event, but the first UDP echo did not complete before the retry. The sequence
and probe's ten-second UDP timeout locate this residual delay in the UDP check;
the event log does not establish the packet-loss cause. That return-path
variability remains open and is not presented as solved by this increment.

The final run spans 2026-09-14T14:40:06Z–2026-09-14T14:42:21Z. Its 95
[events](hysteria-transitions-events.jsonl) match the retrieved device JSON and
console exactly. All stages retain one core runtime identifier. Maximum sampled
RSS is 30.08 MiB, physical footprint
4.45 MiB and thread count
11; sampled dropped packets and TUN loop exits are zero.
These are sparse samples, not continuous peaks. Lock timing comes from protected-
data and app lifecycle notifications, not a hardware deep-sleep trace.

## Cause and change

The old client reused its cached QUIC connection while `is_live()` remained
true. The old device log has three failed TCP attempts across roughly 30
seconds, followed by a successful complete payload sequence in about three
seconds. Hysteria's QUIC idle timeout is 30 seconds, and no carrier-change
notification reached the connection. This timing and the code identify waiting
for stale connection expiry as the recovery bottleneck; no packet capture
establishes the precise OS routing/NAT failure on the phone.

The packet-tunnel runtime's existing 500 ms debounced path observer now queues
Hysteria rebinding alongside WireGuard. A worker on the connection's Tokio
runtime binds and protects a new UDP socket, then calls
[Quinn 0.11.9 `Endpoint::rebind`](https://docs.rs/quinn/0.11.9/quinn/struct.Endpoint.html#method.rebind).
It retains the QUIC connection, authenticated state and inner flow objects.
A bind/protection/rebind failure closes the client. Requests coalesce, work from
ordinary host threads, and preserve notifications racing initial authentication.
Unused outbounds remain lazy. C/Swift expose this as additive ABI 1.7.

An independent host test blackholes the previous carrier in both directions
and gives each new client source port a different server-visible relay socket.
The same TCP stream and UDP session survive two rebind bursts against both
native Hysteria and pinned Xray, within the eight-second recovery budget.
Device traffic uses fresh application connections, so it does not independently
prove uninterrupted existing sessions on the carrier. A stable core identifier
also does not prove the same QUIC session survived the lock interval.

## Cleanup assertion diagnosis

The [first run](diagnostic-aggregate-counter-events.jsonl) passed every traffic
stage: cellular 3.81 s, return to Wi-Fi 2.79 s, unlock 2.99 s. Its one-shot close
requested five connections. Two seconds later TCP was zero but the aggregate
UDP-task counter was six, then three. The original harness treated any nonzero
aggregate as retained connections and marked the whole run failed.

The aggregate counts admitted UDP tasks, including internal DNS work; iOS may
also create new flows after a close request. It is insufficient evidence that
the requested connections were retained. The DEBUG harness now gets opaque IDs
from the same snapshot used to close connections, waits for those exact IDs to
disappear, and separately records subsequent IDs and aggregate counters. It
never repeats close to hide a retained original ID and fails after ten seconds
if one remains. No destination addresses or credentials are exposed by this
DEBUG diagnostic.

In the final run, 10 requested IDs disappeared within
2.07 seconds; subsequent snapshot IDs were
`[]`. Aggregate counts at the following sample were
TCP=0, UDP=3.
VPN stop/disconnection and removal of its separate test profile also passed.
The original failed verdict is preserved; this report claims closure of the
requested IDs, not perpetual absence of system background work.

## Verification, build and limits

[Host checks](host-checks.txt) include native Hysteria source guards and nine live
cases, pinned Xray source guards and seven live cases, four core unit tests per
reference (including a notification during authentication), 11 transport-client
tests, 86 FFI tests, 30 mobile-artifact tests, 164 selected Swift tests, strict
Clippy, formatting and shell syntax. The final DEBUG diagnostic build repeats
the selected Swift tests and signed iPhone build. Existing C symbol/header
checks passed for ABI 1.7. Linux CI and Android acceptance are not claimed.

The iPhone is `iPhone18,2`, iOS 26.6.2 / 23G90. Both signed Debug app/extension
builds use the same freshly built release iOS-arm64 Rust library (deployment
target 15.0). [manifest.json](manifest.json) records the source/library and six
signed code hashes for each device run. The final change between runs only adds
DEBUG closure diagnosis. A fresh macOS-arm64 library (deployment target 11.0)
and two-slice local XCFramework supported Swift verification; no complete
multi-platform release artifact was built. Package version remains 0.6.1 while
development targets 0.7.

Current endpoint addresses and DNS pins remain fixed. This does not add DNS64/
NAT64 rebootstrap, cross-family migration, Android network notifications,
sustained-load/energy acceptance or universal/seamless handover guarantees.

The owner-authorized fixture used the existing hash-pinned VPS Xray binary on
reserved UDP 53053. The complete clean upstream stamp of that existing binary
was not established; no new binary was uploaded. Only the old UDP test service
was paused. Temporary keys, unit and VPS directory were removed, its UDP
listener restored, and the two other test services retain their original PIDs.
The device input and local fixture/SSH helpers were removed. Normal launch
loads the one pre-existing VPN manager and leaves Xray open without probe flags
or console attachment. Raw device/server logs and credentials are unpublished.
