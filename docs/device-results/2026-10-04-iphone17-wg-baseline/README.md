# iPhone 17 Pro Max: WireGuard 0.7 baseline and Trojan repeat

All nine diagnostic invocations passed on the same physical iPhone 17 Pro Max,
iOS 27.0.1 / 24A446, over the same local Wi-Fi fixture. WireGuard alternated
**0.7, 0.8, 0.7, 0.8, 0.7, 0.8**. Three Trojan lifecycle invocations followed
on 0.8. Device events span 2026-10-04T19:21:38Z–19:25:57Z.

The [earlier two WireGuard failures and one Trojan timeout](../2026-10-04-iphone17-lifecycle-resources/README.md#preserved-failures-and-collection-limits)
did not recur. They remain failed observations with unresolved causes. This
series neither establishes a 0.8 regression nor excludes an intermittent one;
no protocol/runtime fix or complete release acceptance is claimed.

## Results

Counts below include only this new series, not earlier passing controls.
Each WireGuard invocation has three VPN starts, and verifies traffic both
before and after closing the observed connection IDs on every start.

| Build / scenario | Complete invocations | TCP echoes | UDP echoes | DNS checks | Other checks |
| --- | ---: | ---: | ---: | ---: | --- |
| 0.7.0 WireGuard | 3 / 3 | 54 | 36 | 18 | 9 starts, 9 close/recovery cycles |
| 0.8 WireGuard | 3 / 3 | 54 | 36 | 18 | 9 starts, 9 close/recovery cycles |
| 0.8 Trojan lifecycle | 3 / 3 | 72 | 48 | 24 | 9 connecting cancellations, 15 rapid restarts |

Every TCP echo is exactly 65,536 bytes (IPv4, IPv6 and synthetic hostname);
UDP payloads are 1,392 bytes over inner IPv4 and 1,372 over inner IPv6. Each
Trojan invocation performs three cancellations after observing `connecting`,
then verifies recovery traffic, followed by five rapid start/traffic/stop cycles.
No traffic retries or timeout relaxation were added.

Server metadata independently records all **180 complete 64 KiB request/echo
pairs and 120 UDP echoes**. All device reports match the complete valid console
events exactly. Sampled TUN drops and read/write loop exits were zero. These
counters do not establish zero Wi-Fi/carrier packet loss.

One 0.7.0 cold-start TCP exchange took **7.264 seconds**, still within the
unchanged ten-second budget. Its server log first records a handshake at
19:21:43.648Z and the backend TCP opens at 19:21:45.451Z; subsequent request/echo
work completes quickly. Device `connected` and `tcp-start` events are dated
19:21:38Z (one-second timestamp precision). Thus a slow first exchange is also
observable in 0.7.0. There is no packet capture proving whether the preceding
delay was client scheduling, initial route setup, handshake loss, or another
cause. In particular this does not explain the earlier post-close UDP timeout.

| WireGuard invocation | 0.7.0 slowest TCP | 0.8 slowest TCP |
| --- | ---: | ---: |
| 1 | 7.264 s | 0.220 s |
| 2 | 0.278 s | 0.352 s |
| 3 | 1.531 s | 0.205 s |

These are observed maxima in small correctness runs, not a latency benchmark or
proof that 0.8 is faster. The diagnostic server uses debug logging and records
backend timing/lengths, which can affect timing. The production WireGuard
crate, its core outbound and vendored GotaTun source are unchanged between the
two runtime revisions; changes elsewhere in the runtime could still matter.

## Build and fixture identity

- Baseline source is tag `v0.7.0`, commit
  `67969094b352f948c6b8b9e2ac75402c577cb7f7`, archived into an isolated directory.
  Rust 1.96.0 built its locked release `aarch64-apple-ios` static library with
  `IPHONEOS_DEPLOYMENT_TARGET=15.0`. The linked library hash matches that output.
- Both apps use the same three DEBUG harness files from core `13fc81f`:
  `XrayProtocolDeviceProbe.swift`, `XrayClientTunnelController.swift` and the
  reference app's `PacketTunnelProvider.swift`. Only the DEBUG CPU message was
  added to the latter two baseline files. The original 0.7 production core and
  tunnel provider remain intact. This is a baseline runtime with an identical
  diagnostic harness, not an unchanged App Store/release application artifact.
- Candidate app/library are the unchanged
  [earlier measured build](../2026-10-04-iphone17-lifecycle-resources/manifest.json),
  runtime `de33998158e84c03f280f979ba2d4212072e5bc4`. The new CI fix below is test-only.
  No native SDK pin, source snapshot, ABI or artifact lock changes are needed.
- Xcode 27.0 / 27A266a built the signed Debug baseline app. Existing signing
  identities were reused. The same geodata and physical device were used.
- The peer is pinned Xray-core revision
  `5ca6f4b7d4dc20a881d4330e498892697627ec0c`. Every invocation starts a fresh
  local fixture with ephemeral credentials and synthetic echo/DNS destinations.
  No VPS, WAN handover, packet relay, or physical interface transition is used.

[manifest.json](manifest.json) records baseline binary hashes, shared harness
hashes, per-run counts, timing, memory samples and raw event/metadata hashes.
The `*-events.jsonl` files are the authoritative device reports. The matching
`*-backend.json` files record only flow ordinals, byte counts and timestamps.
Raw Go debug logs remain private because they can contain peer and DNS data;
their hashes are retained. No encryption keys or signing material are published.

## CI accounting test

[Linux CI 37226367836](https://github.com/aimalygin/xray-rust/actions/runs/37226367836/job/111506737175)
failed `duplex_admission_releases_on_quiet_reacquires_and_aborts_without_leaks`
with the uplink counter 16 KiB behind the bytes already received by the test.
A reader on another worker can consume the final write before `write_all`
returns and the relay updates its counter. Reader completion is not a barrier
for observing that accounting.

Commit `f90006b95c5407269d11d5c78cb58abcb11a40c8` waits, with a two-second
bound, for both exact counters before aborting the still-open relay. Missing
accounting still fails, and cancellation/permit-return checks are preserved.
Only the test changes; production counters and memory use are untouched.

The unmodified test passed 100 local repeats, so the Linux failure was not
locally reproduced. After the change, another 100 repeats and all 504 active
core unit tests passed (two manual benchmarks ignored), along with formatting
and whitespace checks. An initial sandboxed full run failed local socket
permission checks; the run with local networking enabled passed.
The new [CI run 37227881810](https://github.com/aimalygin/xray-rust/actions/runs/37227881810)
validates the pushed test fix separately from this physical evidence.

## Reproduce and cleanup

Build the two release iOS-arm64 libraries from the exact revisions above in
separate directories. Apply only the three shared DEBUG harness files from
`13fc81f` to the baseline app, supply the existing local signing configuration
and identical pinned geodata, then build the `XrayClient` Debug scheme for the
physical device. Record hashes of both libraries and signed app binaries.
Alternate app installs without uninstalling or opening the baseline profile-store
UI; launch its DEBUG probe directly. Restore the current app when finished.

Use the [diagnostic wrapper](diagnostic-fixture.py) in its repository location:

```sh
python3 docs/device-results/2026-10-04-iphone17-wg-baseline/diagnostic-fixture.py \
  --bind "$MAC_LAN_IPV4" --reference-binary "$PINNED_XRAY" \
  --reference-sha256 "$PINNED_XRAY_SHA256" \
  --output "$NEW_PRIVATE_DIRECTORY" --protocol wireguard --mode smoke --seconds 300
```

Copy its private `v07-probe.json` into the app's `Documents`, launch with
`XRAY_V07_DEVICE_PROBE=1` and capture the console. Download `v07-result.json`
after its `complete` event, compare the full reports, and stop the fixture.
Repeat with fresh directories/keys for all six alternating invocations. For
Trojan use the current 0.8 app, `--protocol trojan --mode lifecycle`, three times.
The original fixture bounds, cleanup and reference-binary validation remain in
force. Preserve failures and stop for inspection if the collector is incomplete.

All nine invocations completed cleanup. The original current 0.8 app was
reinstalled and launched normally. The probe input, separate test VPN manager,
keychain entry and local ephemeral credential/configuration files were removed;
user profiles were preserved. No fixture, console collector or build remains
running. The earlier unresolved failures, SS2022 WAN/MTU condition, Android
hardware and release-artifact/performance gates remain open.
