# iPhone 17 Pro Max: Hysteria2 UDP return to Wi-Fi

The Apple carrier observer now filters path updates that do not change the
physical interface or its assigned addresses. Two complete device sequences on
2026-09-15 passed without traffic retries. Return to Wi-Fi completed in
2.79/2.78 seconds; the earlier intermittent case took
15.08 seconds after a UDP timeout. The previous build also had a 2.79-second
successful return, so these observations establish bounded acceptance and
absence of a reproduced timeout in two repeats, not a guaranteed latency gain.

## Physical results

| Stage | Run 1 | Run 2 |
| --- | --- | --- |
| Wi-Fi baseline, active test time | 2.76 s | 3.02 s |
| Wi-Fi → cellular, since path event | 5.17 s | 6.44 s |
| Cellular → Wi-Fi, since path event | 2.79 s | 2.78 s |
| After unlock | 2.84 s | 3.02 s |
| Observed lock interval | 38.98 s | 57.85 s |
| Requested connection IDs gone | 7 in 2.06 s | 5 in 2.11 s |
| Ignored duplicate path callbacks | 9 | 6 |

Every stage checks exact 65,536-byte TCP payloads over inner IPv4/IPv6/a hostname,
1,392/1,372-byte UDP payloads and an A query through the VPN DNS anchor. Each run
has 12 TCP, 8 UDP and 4 anchor-query successes, zero retries and one core runtime
identifier. The probe still uses ten-second per-exchange timeouts and a 45-second
recovery budget. No retries, payload reductions or relaxed verdicts were added.

[Run 1](transitions-1-events.jsonl) spans 2026-09-15T13:29:21Z–2026-09-15T13:31:01Z;
[run 2](transitions-2-events.jsonl) spans 2026-09-15T13:31:26Z–2026-09-15T13:33:06Z.
Both event logs exactly match their downloaded device reports and app consoles.
Maximum sampled RSS is 29.47 MiB;
footprint 4.66 MiB;
threads 10. Sampled drops and TUN-loop
exits are zero. These are sparse samples, not continuous peak/energy measurements.
Connection closure checks exact requested IDs; aggregate UDP counts may include
internal DNS or new background work, as documented in the prior report.

## Change and evidence

The old observer scheduled a fresh protected carrier socket whenever whole-NWPath
equality changed. The previous server log showed several peer-port changes during
one Wi-Fi return. Quinn's pinned endpoint retains an old socket only until traffic
arrives on the new one, so redundant rebinding is a plausible contributor to
unreliable datagram loss. There is no packet capture proving the exact fate of
the original missing UDP response; the old report remains unchanged.

The new signature follows the first physical interface in Apple's documented
[interface preference order](https://developer.apple.com/documentation/network/nwpath/availableinterfaces),
plus its name, index and sorted/deduplicated numeric IPv4/IPv6 addresses obtained
with getifaddrs. DNS, tunnel-route and secondary-interface updates alone no longer
cause migration. Address changes on the same interface still do. Offline updates
cancel queued work and clear the signature so returning to the same network acts.
Unknown interfaces/enumeration failures retain the prior raw-path fallback.

The 500 ms debounce remains. A return can still have two necessary callbacks as
an interface and its addresses settle; this change does not force one callback
per user action. The DEBUG-only, bounded 64-event history records scheduled,
applied, offline and unchanged callbacks without addresses or credentials.
"Applied" records the observer callback, not proof of QUIC path validation.
The filtering is shared with WireGuard, but no new WireGuard device acceptance
is claimed here. There are no Rust-library or ABI changes from the 09-14 build.

## Independent DNS test issue

Two initial diagnostics failed during the baseline hostname TCP check, while
IPv4/IPv6 TCP continued working. Both report NoSuchRecord for the reused
v07-probe.test. The second run's bounded server capture contains 160 loopback
packets and no query for that name. OS negative caching is the supported working
explanation, not proof that UDP transport caused the failure.

The fixture now generates a fresh synthetic .test name with matching exact routing
and A/AAAA responses. The Swift probe accepts that optional bounded ASCII name;
old fixtures retain the legacy default. TLS/SNI identity remains v07-probe.test.
The new name passed immediately in the final two runs. The original diagnostic
verdicts remain **failed**: [diagnostic 1](diagnostic-1-events.jsonl),
[diagnostic 2](diagnostic-2-events.jsonl). Neither is counted as a handover pass.

## Verification and cleanup

167 selected Swift tests passed: 29 pump, 133 provider, 5 observer. The new tests
cover duplicate address ordering, interface/address changes, offline return and
cancellation of a queued callback. Signed iPhone Debug and macOS Release tunnel
builds passed; DEBUG diagnostics are excluded in Release. Fixture A/AAAA response
shape and unknown-name rejection were checked for fresh and legacy names.
[manifest.json](manifest.json) preserves both diagnostic and final source/signed
code identities and private log hashes. The final iOS Rust library is identical
to the previously tested ABI 1.7 library; no new Rust test result is claimed.

The temporary VPS service/directory and ephemeral keys were removed. The original
three services are active; UDP 53053 is restored, with the other two PIDs unchanged.
The bounded packet capture was stopped and remains private with raw server logs.
Device probe input and its separate VPN manager were removed; normal app launch
loads one pre-existing manager. Local fixture and SSH helpers were removed.
No Android/Linux CI, sustained-load/energy or release acceptance is claimed.
