# iPhone 17 Pro Max: WireGuard after the shared observer fix

Two WireGuard regression sequences passed within the 45-second recovery budget on the exact signed Debug build used
for the [latest Hysteria2 passes](../2026-09-15-iphone17-hysteria-udp/README.md).
This verifies WireGuard after physical-path deduplication and offline cancellation
were added to the shared Apple network observer. No production or test code changed and no binary rebuild was needed; the
already tested app was reinstalled.


The first return to Wi-Fi took 15.68 seconds with one TCP retry. The first
IPv4 TCP exchange timed out after ten seconds; the subsequent full sequence
passed. The repeat also needs one TCP retry. This is a reproduced latency concern, not a clean no-retry result. The previous
WireGuard campaign recorded 6.25 seconds on return, but that was a different run
and build; this is not a controlled performance comparison.

## First physical result

| Stage | Full TCP/UDP/DNS check | Retries |
| --- | --- | --- |
| Initial Wi-Fi (active check) | 10.57 s | 0 |
| Wi-Fi → cellular | 8.90 s | 0 |
| Cellular → Wi-Fi | 15.68 s | 1 |
| After unlock | 5.86 s | 0 |

Transition timings start at the observed path event; unlock timing starts at
protected-data availability. The lock interval was 60.14 seconds. Every
stage checks exact 65,536-byte TCP payloads through inner IPv4/IPv6/a hostname,
1,392/1,372-byte UDP payloads and a query through the VPN DNS anchor. Timeouts
remain ten seconds per exchange and 45 seconds per recovery sequence.
The run has 12 TCP, 8 UDP and 4 DNS-anchor successes.

5 requested connection IDs disappeared within 2.06 seconds;
subsequent snapshot IDs were `[]`. The following aggregate sample
was TCP=0, UDP=3; exact IDs, rather
than permanent aggregate zero, determine successful closure. VPN stop and test
profile removal also passed. All resource samples retain one core runtime ID.

Maximum sampled RSS was 28.39 MiB, physical
footprint 4.38 MiB and threads
8; sampled drops and TUN-loop exits were zero. The
observer recorded 4 applied callbacks and ignored
9 duplicate physical-path events. Applied means
a callback was executed, not that a handshake completed at that instant.

The 102 [events](wireguard-transitions-events.jsonl) span
2026-09-15T13:41:53Z–2026-09-15T13:45:56Z and exactly match the downloaded device JSON
and app console. [manifest.json](manifest.json) records current source, static
library and six signed-code hashes. WireGuard-specific production source hashes
also match the [earlier WireGuard fix](../2026-09-14-iphone17-wireguard-rebind/README.md).
The library is the fresh ABI 1.7 build from the Hysteria work; this run does not
inherit the earlier WireGuard report's historical installed-build uncertainty.

## Same-build repeat

The [repeat](wireguard-repeat-events.jsonl) spans 2026-09-15T13:46:33Z–2026-09-15T13:48:26Z and exactly matches
the downloaded device JSON and app console. It uses the same fixture and code.

| Stage | Full TCP/UDP/DNS check | Retries |
| --- | --- | --- |
| Initial Wi-Fi (active check) | 6.05 s | 0 |
| Wi-Fi → cellular | 6.71 s | 0 |
| Cellular → Wi-Fi | 16.36 s | 1 |
| After unlock | 5.28 s | 0 |

The lock interval was 44.29 seconds. All 7 requested connection IDs
disappeared within 2.05 seconds. The observer ignored
7 duplicate callbacks; all samples retain one core ID.
The repeat's sampled RSS/footprint maxima were
26.17/4.45 MiB,
with 10 threads and zero sampled drops/TUN-loop exits.
The first run's TCP timeout is preserved; two recovered runs do not prove that
the reproduced TCP delay is resolved. No production fix is claimed by this retest.

## Scope and cleanup

The current build's prior 167 selected Swift tests and Debug/Release build checks
remain referenced through the Hysteria report. They were not rerun for this
unchanged-code physical regression. These are two bounded development sequences,
not release qualification, a controlled performance comparison or proof of
uninterrupted existing application streams. Lock timing is not a deep-sleep
trace, and memory observations are sparse. Load/energy, broader fault/carrier,
Android and full release checks remain separate work.

The authorized fixture used only reserved UDP 53053 and the existing hash-pinned
VPS Xray binary. Full clean upstream VCS provenance of that binary was not checked;
no binary was uploaded. Temporary keys, unit and directory were removed, the
original UDP service restored, and all three original services are active. The
other two service PIDs are unchanged. Device input and its separate test profile
were removed; normal app launch sees the one pre-existing VPN manager. Local
fixture/SSH helpers were removed. Raw server logs and credentials remain private.
