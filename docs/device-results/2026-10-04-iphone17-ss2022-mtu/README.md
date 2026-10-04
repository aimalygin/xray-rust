# SS2022: direct UDP socket, DF boundary and iPhone transitions

On 2026-10-04, the original native SS2022 WAN size failure reproduced with
both the pinned Go implementation and the iPhone Rust client. Changing only
`IP_MTU_DISCOVER` on the running test Xray-core UDP socket from Linux default
`WANT` (1) to `DONT` (0) removed the observed losses. Restoring 1 brought them
back; restoring 0 passed the detailed boundary sweep. **No UDP relay was used.**

The iPhone then passed Wi-Fi → cellular → Wi-Fi and lock/wake against a fresh
direct Xray-core fixture with the same socket setting. This diagnoses and
mitigates the observed DF-dependent path failure. It does not establish a
general large-UDP reliability fix or a persistent production configuration.

## Controls and localization

All automatic controls below use the same running Xray process, public port
53053, credentials, echo backend and native ChaCha SS2022 codec. The only server
change between conditions is the socket option, recorded in
[socket-option-audit.json](socket-option-audit.json). Both logical target
families use an **IPv4 outer carrier**; an IPv6 target is not an IPv6 WAN path.

| Sequence / client | Server socket mode | Passed / attempted |
| --- | --- | ---: |
| Original Go sweep | 1 / WANT | 32 / 40 |
| iPhone size sweep | 1 / WANT | 31 / 40 |
| Expanded Go sweep | 0 / DONT | 44 / 44 |
| iPhone size sweep | 0 / DONT | 40 / 40 |
| Expanded Go sweep after restoring default | 1 / WANT | 37 / 44 |
| Detailed Go boundary sweep | 1 / WANT | 36 / 56 |
| Same detailed sweep after restoring DONT | 0 / DONT | 56 / 56 |

The original sweep tests payloads 32, 1200, 1300, 1340, 1350, 1360, 1372,
1392, 1420 and 1450 bytes; the expanded Go sweep adds 1320. The boundary
sweep tests 1348–1374 bytes in steps of two. Each uses two fresh associations
per family/size, 1.5-second Go deadlines or 2-second iPhone deadlines, and
exact echo verification. All successful Go rows also match the target address.
Every timeout and failed iPhone verdict remains in the published data.

The [boundary correlation](boundary-correlation.json) matches **all 56 requests,
56 backend echoes and 56 emitted server replies** to the ordered Go trials
in each condition. Requests and replies share the anonymized flow identifier;
request wire lengths and echo payload lengths match. A 0.25-second margin
around each isolated run accounts for the two host clocks; their timestamps
are not used to infer network latency.

| Default-mode response boundary | IPv4 target payload | IPv6 target payload |
| --- | ---: | ---: |
| Last tested passing DF reply: 1480-byte outer IPv4 packet | 1370 | 1358 |
| First tested failing DF reply: 1482-byte outer IPv4 packet | 1372 | 1360 |

All 20 failures in that detailed default-mode sweep have emitted DF replies
of 1482–1496 bytes. The client's raw UDP socket delivers no response before
timeout, so these failures precede SS2022 decryption. The corresponding
20 trials pass with DF clear. Together with the Go/iPhone agreement, this
localizes this boundary failure to the return path after the server capture,
not a Rust-only codec or TUN explanation. A path limit around 1480 bytes is
consistent with the observations; the exact dropping hop and exact PMTU
remain unmeasured, and 1481 bytes was not tested.

The VPS interface MTU is 1500. No ICMP fragmentation-needed packet was seen
in the server capture. Larger datagrams can succeed after fragmentation, so
success is not monotonic with payload size. In the broader default-mode
44-case repeat, only 43 requests reach the echo backend and 37 replies reach
the client: additional request-path/intermittent losses remain possible.
The successful DONT trials do not erase those failures or the
[earlier relay campaign's variable results](../2026-10-03-iphone17-v08/README.md).

Only header metadata is published. The capture filter misses non-first IP
fragments, so its packet counts are not complete fragment counts. No client
packet capture was available; an attempted unprivileged capture could not
obtain the required macOS privilege. Capture-local flow aliases replace
endpoint addresses and ports. Private capture hashes and exact metadata files
are indexed in [manifest.json](manifest.json).

## Physical iPhone result

The physical iPhone 17 Pro Max (`iPhone18,2`, iOS 27.0.1 / 24A446) uses the
unchanged release Rust library from `de33998158e84c03f280f979ba2d4212072e5bc4`,
SHA-256 `94e80251e1e4f867c23339455c5cfcad4cb429aafe3e2739fb5e9b1d0da6ab2d`,
with the same canonical SDK sources recorded at `0148543`. The signed Debug
reference app adds only bounded `udp-sweep` instrumentation; its new executable
identities are in the manifest. ABI 1.8, client TUN MTU 1500, native runtime,
SDK pin and artifact locks are unchanged. Other XCFramework slices were not
rebuilt or qualified by this campaign.

The [direct-socket transition run](iphone-native-dont-transitions.jsonl)
passes 12 TCP echoes, eight UDP echoes (1392-byte IPv4 / 1372-byte IPv6), four
DNS queries, one connection closure and stop. Each transition opens fresh
flows; established-session continuity is not claimed.

| Stage | Active time to complete TCP/UDP/DNS sequence | Retries |
| --- | ---: | ---: |
| Initial Wi-Fi | 3.842 s | 0 |
| Cellular | 3.335 s | 0 |
| Return to Wi-Fi | 3.390 s | 0 |
| After unlock | 3.085 s | 0 |

Observed lock duration is 39.016 s. The runtime identifier remains unchanged
through all stages. These are complete-sequence durations, not first-packet
latency; path/unlock-to-completion values are preserved separately. Lock
notifications do not establish hardware deep sleep.

The transition run's maximum sampled RSS / physical footprint is
28.765625 / 4.142 MiB; all five samples report zero dropped packets and zero
TUN read/write loop exits. The DONT size sweep samples at most 28.547 / 5.267
MiB, versus 28.688 / 5.095 MiB in the failed default sweep. These sparse
observations are not a leak, peak-memory, CPU, energy or comparative performance
claim. This WAN campaign covers SS2022 ChaCha; AES methods retain separate LAN
evidence. It does not close the full Apple, Android or schema-4 release gate.

## Reproduce the diagnostic

Use the pinned Xray checkout `5ca6f4b7d4dc20a881d4330e498892697627ec0c` and
its locked Go dependencies. The existing VPS binary reports 26.7.28 / 5ca6f4b
and has the hash in the manifest; its full clean Go VCS stamp was not verified.
Build [ss2022-size-control.go](ss2022-size-control.go) with `go -C Xray-core
build -mod=readonly`, using absolute source/output paths outside the reference
checkout. Pass the private fixture JSON path, optionally followed by a
comma-separated size list. The original 40-row run uses the previously
published [Go source](../2026-10-03-iphone17-v08/ss2022-udp-control.go).

Place [fixture-metadata.py](fixture-metadata.py) beside a copy of
[the fixture generator](../../../scripts/run-v07-apple-protocol-fixture.py)
named `fixture.py`. Invoke the wrapper with:

```sh
python3 fixture-metadata.py --bind "$TEST_VPS_IPV4" \
  --reference-binary "$PINNED_XRAY" --reference-sha256 "$PINNED_SHA256" \
  --output /tmp/xray-v08-ss2022-mtu-20261004/shadowsocks2022-native \
  --protocol shadowsocks2022 --port 53053 --mode transitions --seconds 780
```

The campaign used bounded transient units (900 seconds maximum) with
`ExecStopPost` restoring only the two previously active test services on this
reserved TCP/UDP port. Loopback echo/DNS ports are ephemeral. Routing permits
only synthetic test destinations to the echo backend and otherwise blocks.
The wrapper records echo metadata and a private header capture. For an iPhone
sweep set the generated envelope's `mode` to `udp-sweep`; optional
`udpPayloadSizes` and `udpRepeats` are bounded to 16 sizes of 1–4096 bytes and
1–3 repeats. The generator now accepts `--mode udp-sweep` directly as well.

[socket-option.py](socket-option.py) is the exact Linux x86_64 diagnostic used
on the isolated `shadowsocks2022-native` fixture. It discovers the process by
its **exact temporary config path and executable**, finds its single UDP
53053 FD, and uses `pidfd_getfd` to inspect that socket. With no environment
override it reads only; `XRAY_TEST_DF_MODE=0` or `1` sets only that socket.
Privileged access is required. For the fresh transition fixture the sole
script substitution was `run='shadowsocks2022-native-transitions'`.
The PID/FD and before/after values are retained. Stopping the fixture removes
the socket and the change. No production socket, host route, firewall or
sysctl was modified.

This is a **temporary test-socket mitigation**, not a supported configuration
recipe for arbitrary production servers. In the pinned Xray source,
`transport/internet/sockopt_linux.go` applies inbound `customSockopt` inside
the TCP-only branch, so that JSON option does not configure the UDP listener.
Persistent deployment needs a separately selected and validated server/path
solution. A global client TUN MTU reduction or weakened UDP authentication is
not justified by these measurements; no client runtime fix is claimed.

Copy the private envelope to `Documents/v07-probe.json`, launch the reference
app with `XRAY_V07_DEVICE_PROBE=1`, and retrieve `Documents/v07-result.json`.
All three atomic device reports exactly match their console events. The
original JSON and derived JSONL are published with hashes, including the
failed default sweep. The physical Debug build passed, and the linked device
library hash matches the unchanged native candidate.

Run `python3 verify-evidence.py` from this report directory to recheck the
published hashes, verdict counts, same-socket changes and all 112 correlated
boundary trials. All 52 canonical SDK source/fixture files checked against
the exact native pin match byte-for-byte. The changed public files pass secret
scanning, 18 scanner-policy tests and 13 public-fixture tests; no scanner
exception was added for this report.

Final cleanup is verified in [cleanup.json](cleanup.json): both temporary
units are inactive, the remote directory and local ephemeral profiles/SSH
helpers are removed, original reserved-port services are active, and the
production/loopback service PIDs are unchanged. The input profile is absent
from the phone; the probe removed its own VPN/keychain entry and the normal
app was relaunched. Normal profiles remain intact. No merge, tag, release or
package publication occurred.
