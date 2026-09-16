# iPhone 17 Pro Max: WireGuard recovery and TCP backpressure

The final build passed Wi-Fi → cellular → Wi-Fi, lock/wake and exact-ID
connection closure. Return to Wi-Fi completed the full TCP/UDP/DNS check in
**4.48 seconds without a retry**, compared with the previous build's reproduced
15.68/16.36 seconds and one failed TCP attempt in each run.
The same final build also passed three Hysteria2 smoke cycles.

## Changes and evidence

- WireGuard replaces its protected outer sockets while retaining authenticated
  sessions, timers, pending packets and inner TCP/UDP flows. It no longer
  suspends/resumes the engine for a path notification. New sends use the current
  socket set. Receive drains at most one previous set for three seconds, then
  releases it even with no traffic. Authentication/replay checks are unchanged.
- The shared TUN TCP bridge polls upload beside download, cancellation and its
  idle deadline. Previously an awaited upload batch inside a select branch could
  block reading the response and handling host close. Two bounded-duplex tests
  reproduced both failures before the change and pass afterward. This preserves
  the existing batching buffers/reservations without adding a worker task.

The investigation retained all three physical runs, including the failed one.
Candidate 1 preserves WireGuard sessions but immediately retires old sockets;
it still uses the old TCP bridge. Its cellular hostname TCP exchange reached
54,672 of 65,536 bytes at the echo server before stalling, and a connection ID
remained after host close. The full run failed. This was a transfer stall,
not merely an unresolved DNS name; the retained ID is opaque and was not mapped
to that specific exchange.

Candidate 2 adds the TCP bridge fix. All traffic and closure checks pass, but
Wi-Fi return still takes 13.85 seconds. The server capture shows the complete
request and echo in roughly two seconds while phone completion occurs later,
across two carrier socket changes. The final build adds the bounded old-socket
drain. The independent delayed-packet test also improves from about 5.15 seconds
to 2.82 seconds in each outer family. These observations support the fix; they
do not identify every lost packet in the encrypted physical path.

## Physical results

Each table cell gives full traffic-check duration / application retry count.

| Stage | Candidate 1 | Candidate 2 | Final build |
| --- | --- | --- | --- |
| Wi-Fi → cellular | 21.13 s / 1 | 8.14 s / 0 | 6.38 s / 0 |
| Cellular → Wi-Fi | 6.57 s / 0 | 13.85 s / 0 | 4.48 s / 0 |
| After unlock | 5.60 s / 0 | 5.25 s / 0 | 5.51 s / 0 |

Final baseline active traffic check: 4.69 seconds.
Transition timing begins at the observed path event, and unlock timing at
protected-data availability; these include the entire traffic sequence, not
just socket migration. Probe exchange timers remain ten seconds (scheduled on
the app queue), with a 45-second recovery budget. No thresholds were loosened.

The final sequence checks three exact 65,536-byte TCP echoes (IPv4, IPv6 and a
synthetic hostname), 1,392/1,372-byte UDP echoes and the VPN DNS anchor at each
stage. All 12 TCP, eight UDP and four DNS checks pass without a retry. The
observed lock interval is 32.72 seconds. All seven requested connection
IDs disappear within 2.05 seconds; the later ID snapshot is empty.
All resource samples retain one core runtime ID. Sampled drops and TUN-loop
exits are zero; maximum RSS/physical footprint is
29.59/4.63 MiB and maximum thread count is 11.

[Final WireGuard events](wireguard-events.jsonl) span
2026-09-15T14:32:01Z–2026-09-15T14:33:58Z.
[Hysteria2 events](hysteria-smoke-events.jsonl) record three start/traffic/close/
traffic-again/stop cycles on Wi-Fi: 18 TCP, 12 UDP and six DNS successes.
This is a smoke regression of the shared bridge, not another Hysteria handover
or sleep campaign. [Candidate 1](candidate1-wireguard-events.jsonl) and
[candidate 2](candidate2-wireguard-events.jsonl) remain part of the evidence.
All published event arrays exactly match both downloaded device JSON and console.

## Host checks and build identity

- Final WireGuard unit tests: two passes, including idle receive migration,
  delayed replies and socket expiration in IPv4/IPv6.
- Final native-reference checks: three carrier cases, two roaming/replay cases
  and six core integration cases pass. The full 19-case native gate, including
  the 120-second rekey, passed at the initial candidate stage; only affected
  cases were repeated after the later changes.
- Shared bridge: both new reproductions fail before / pass after; all 172
  non-native runtime data-path tests and 73 TUN unit tests pass.
- Four native Hysteria core integration cases pass after the shared bridge fix.
- Strict WireGuard/core Clippy, formatting and whitespace checks pass.
- Fresh iOS arm64 and macOS arm64 release static libraries and the signed iPhone
  Debug app build pass; C ABI remains 1.7. The Apple observer and probe code are
  unchanged in this investigation.

[manifest.json](manifest.json) retains source/library/code hashes and event
hashes. The final build records all six signed code files; intermediate snapshots
recorded five (including both main debug dylibs). Host logs and raw server
captures stay in the private temporary directory and are represented by hashes.

## Cleanup and limits

The fixture used the already installed, hash-pinned VPS Xray binary on reserved
UDP 53053. No server binary was uploaded; full clean VCS provenance of that
installed binary was not established. Temporary keys, unit and remote directory
were removed, the original UDP service restored and all three original services
are active; the other two service PIDs are unchanged. Device input and separate
test VPN were removed. Normal Xray launch sees the one pre-existing manager and
runs without the probe or console. Local fixture credentials and SSH helpers
were removed.

This final build has one full physical WireGuard sequence plus the Hysteria smoke
regression. It is bounded development evidence, not broad carrier/Android,
long-sleep, energy/load or release qualification. Existing application TCP/UDP
flow preservation is exercised by host tests; the device probe opens fresh
application flows at each stage. Endpoint DNS/NAT64 refresh remains outside scope.
