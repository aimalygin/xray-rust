# v0.11 evidence collection

Status on 2026-11-28: the fixtures and Debug harnesses below can produce the
scenarios of the v0.11 profile. **No v0.11 device result exists.** The owner
runs the physical devices; nothing here is device coverage.

The contract is the schema-5 `v011` profile in
`scripts/check-v011-release-evidence.py`, accepted by the owner on 2026-11-28
and described in [0.11.0 release preparation](v0110-release.md):

- `vless-reality`, `hysteria2` and `wireguard` take all twelve transitions on
  Apple. On Android they run on both TUN backends, with `lock-wake` and
  without `wifi-cellular-wifi`. `wireguard` adds `idle-device-restart` on
  both platforms.
- `tun-sniffing` takes six transitions on both platforms.
- `legacy-regression` needs every carrier, mask and bridge 0.10.x shipped
  (22 ids) and, on Apple, `xhttp-h3-network-change`.
- `profile-import` needs `vmess-link-plain`, `xray-json-subscription` and
  `invalid-input-redaction`.
- `vless-reality-`, `hysteria2-` and `wireguard-` `throughput`, `latency` and
  `memory` against Xray-core v26.11.9, and the `release-comparison` artifact
  against the published 0.10.1.

The shared scenarios (`vless-encryption`, `ip-on-demand`,
`xhttp-download-session`, `cancellation`, `host-adapter-projection`) are
collected as in 0.9.0 and 0.10.0.

## What the fixtures generate

| Fixture | Cases | For |
| --- | --- | --- |
| `run-v07-apple-protocol-fixture.py --protocol sniff-v011` | `sniff:route-only`, `sniff:imported`, `sniff:name-dial` | `tun-sniffing` |
| `--protocol import-v011` | `xray-json-subscription`, plus one `imports` row and five malformed links | `profile-import` |
| `--protocol wireguard-idle` | `wireguard:idle`, WireGuard without `keepAlive` behind a relay | `wireguard`'s transitions, `idle-device-restart` included |
| `--protocol both`, `hysteria2`, `wireguard` | Hysteria2 and WireGuard with `keepAlive` | the full set's other runs |
| `run-v08-apple-acceptance-fixture.py --suite reality-v011` | `vless-reality` alone; takes `--port` | `vless-reality` |
| the 0.10 fixtures: `--protocol v010`, `smoke-v010`, `xicmp`, `--suite legacy-v010`, `xhttp-h3-v010` | as in 0.10 | `legacy-regression` |

The Android fixture (`run-v08-android-protocol-fixture.py`) takes the same
selections under `--suite v011` and `--suite reality-v011`; `caseId` is the
label with `-` for `:`. For `sniff-v011` it keeps the base TCP echo instead of
its HTTP availability check, since the sniffing probes send raw first bytes.

### The sniffing cases

Each case has the TUN inbound the SDK importers wrote from 0.7.0 to 0.10.1
(`listen`, `port: 0`, empty `settings`), with its own sniffing. One plain VLESS
server carries all three. It echoes `198.51.100.0/24`, `2001:db8::/32` and the
one name `byname.<probe>`, and refuses everything else. Each probe connects to
an address and sends, as its first bytes, an HTTP/1.1 request naming a host
under the probe name or a ClientHello that Python's TLS stack built with it.
The table of probes and what each shows is in
[the release page](v0110-release.md#the-sniffing-scenario).
`test_v011_device_fixtures.py` models Xray-core's routing to show that each
expectation follows from its case, and that each would fail if what it
checks were broken.

### WireGuard's idle case

- **No `keepAlive`**, since a peer with one keeps its device open. Its
  wg-quick text has no `PersistentKeepalive` either.
- **Nothing else reaches the device while it idles.** Every flow but the
  probe's goes to a blackhole. The fixture's DNS server answers the probe
  name only (`domains` with `skipFallback`), so a phone's background lookups
  fail instead of opening a WireGuard flow.
- **The idle time is seven minutes**: 420 s in `idleRestartSeconds`, where the
  contract said six. A TUN UDP flow lingers up to a minute after its last
  datagram, and the device then waits out five minutes without a flow.
- **The evidence of a fresh device.**
  - The reference server listens on loopback behind a relay that the fixture
    runs on `--bind` and `--port`.
  - The relay logs each client source address and each handshake initiation
    to `wireguard-sources.jsonl`, never a payload, and keeps the file after
    shutdown.
  - A device that was closed and started again sends from a new socket.
    `scripts/check-v011-wireguard-restart.py <log> <since>` passes only for a
    handshake from a source the relay had not seen before `since`.

## Host loopback check

```bash
python3 scripts/check-v011-fixture-loopback.py --suite sniff-v011 --reference-binary <xray> --client-binary target/release/xray-rust --work-dir <new-dir>
```

For `sniff-v011` each case's sniffing moves to the SOCKS ingress, and each
probe must be echoed or refused as its case says. The CLI has no SDK start
path, so `sniff:imported` is not migrated there, and its decoy must be
refused. The other suites run the traffic checks of 0.9 and 0.10.
`--idle-restart` adds the WireGuard idle restart to `wireguard-idle`: seven
minutes, then TCP, then the relay check. It is not device evidence.

Results on 2026-11-28 against Xray-core v26.11.9 (pin `676eaf66`, named by
`--reference-sha256`) and a debug CLI of this branch, on macOS arm64:

| Suite | Result |
| --- | --- |
| `sniff-v011` | 3 of 3: route-only echo, echo, refused, echo; imported refused, as the CLI must; name-dial echo |
| `import-v011` | 1 of 1 |
| `wireguard-idle` | 1 of 1 |
| `wireguard-idle --idle-restart` | 1 of 1. The next flow, after seven idle minutes, came from a new client source with a fresh handshake |
| `reality-v011` | 1 of 1 |

## Apple

As in 0.10: the Debug `XrayClient` app with the candidate XCFramework, the
fixture's `v07-probe.json` in Documents, and `XRAY_V07_DEVICE_PROBE=1`. Rows
carry `protocol` = the case label.

| Transition | Run | Events |
| --- | --- | --- |
| The twelve of the full set | as in 0.10, for `vless-reality`, `hysteria2` and `wireguard` | as in 0.10 |
| `idle-device-restart` | `--protocol wireguard-idle --mode transitions` | `idle-start`, `transition-recovered` `after-idle` on the same runtime, `idle-restart`; then the relay check from `idle-start`'s `time` |
| The six of `tun-sniffing` | `--protocol sniff-v011` | `sniff` rows with the `transition` and `result` `passed`, after one `connected` per case |
| `vmess-link-plain` | `--protocol import-v011` | `link-import` |
| `xray-json-subscription` | the same run | the case's smoke rows |
| `invalid-input-redaction` | the same run | `invalid-import-redaction` rows |

Runs:

1. **Full set, LAN**: `--protocol both` and `--suite reality-v011` with
   `--mode smoke`, `lifecycle` and `resources`.
2. **Full set, WAN**, one carrier per run on the public host's open port:
   `--suite reality-v011`, `--protocol hysteria2` and `--protocol
   wireguard-idle`, each `--mode transitions`. That yields `wifi-cellular-wifi`
   and `lock-wake`, and, for WireGuard, the idle step after them. With the
   relay, the WireGuard server listens on loopback and only `--port` needs to
   be open.
3. **Sniffing, LAN**: `--protocol sniff-v011`. The `sniff:imported` case
   passes only through `XrayPacketTunnelProvider`'s migration after its
   keychain read; the provider logs a line when it adds `routeOnly`.
4. **Import, LAN**: `--protocol import-v011`.
5. **Legacy**: the 0.10 runs 3 to 5, with the `v010` fixture for mKCP and
   MASQUE in smoke.

## Android

Build the Device Gate and Device Probe with `-PdeviceGateApplicationIdSuffix=.v011`.
The driver is `run-v09-android-device-matrix.py`, as in 0.10, with these
additions:

- **Sniffing cases** (`sniffProbes`) run no traffic sweep. After connecting,
  the Device Probe's `exchange` command sends each probe's bytes to its
  address over a raw TCP socket and records `echo`, `refused`, `partial` or
  `mismatch`. `sniff` events carry the transition. The case's JSON reaches
  `startXrayTunnel` unchanged, so `sniff:imported` passes only through
  `XrayVpnService`'s migration.
- **`--lock-wake`** adds a step to every other case, after its traffic:
  - the screen goes off over adb (`input keyevent KEYCODE_SLEEP`), and
    `dumpsys power` must no longer read awake;
  - after 60 seconds the phone wakes (`KEYCODE_WAKEUP`, `wm
    dismiss-keyguard`);
  - TCP and UDP must pass on IPv4 within 90 seconds, then on IPv6, on the
    same runtime generation.

  The phone is woken whatever fails.
- **The idle case** (`idleRestartSeconds`) then waits that long without probe
  traffic and passes both families again on the same runtime. It needs
  `--wireguard-sources <fixture dir>/wireguard-sources.jsonl`, and passes only
  for a handshake from a new source after the idle time began. Driver and
  fixture share the host's clock.

| Transition | Run |
| --- | --- |
| The full set without `wifi-cellular-wifi` | `--suite reality-v011` and `--suite v07` (Hysteria2 and WireGuard) with `--lock-wake`; `cancel-active-flow` and `resource-recovery` in separate runs, as in 0.9.0 |
| `idle-device-restart` | `--suite v011 --protocol wireguard-idle`, `--lock-wake --wireguard-sources …` |
| The six of `tun-sniffing` | `--suite v011 --protocol sniff-v011`, both backends |
| `profile-import` | `--suite v011 --protocol import-v011` |
| `legacy-regression` | the 0.10 fixtures, without `xhttp-h3-network-change` |

## Performance

### The three carriers against Xray-core

```bash
python3 scripts/run-v08-protocol-comparison.py --suite v011 --inputs <inputs.json> --output <new-dir>
```

It measures VLESS over REALITY with Vision, Hysteria2 and WireGuard, each as
its device fixture configures it. The candidate runs against the pinned
Xray-core client, with inputs from `prepare-v08-protocol-comparison.py`
without sing-box. `measurement_groups` names the gate's
`vless-reality`, `hysteria2` and `wireguard` ids. REALITY's decoy needs
`www.google.com:443`, and its server waits eight seconds before the first
client.

On 2026-11-28 each profile, with Xray-core as client and server, carried a
TCP echo to a target on the host's own address. That is where the driver
places its targets: WireGuard's user-space stack keeps loopback for itself.
No measured run has been made.

### The comparison against 0.10.1

```bash
python3 scripts/run-v011-release-comparison.py --campaign <dir> --reference <xray> --output <new-dir>
```

It is the 0.10 collector, run with v0.11's policy:

- the baseline is a build of the published `v0.10.1` tag;
- it covers fourteen carriers: the twelve legacy protocols, plus mKCP and
  MASQUE as their device fixtures configure them;
- mKCP and MASQUE run the carrier-paced work of the 0.10 comparison;
- only a complete run writes `release-comparison.json`.

## What is not device coverage

- The host loopback results above.
- The DNS changes, RAW's `http` header, `sockopt.domainStrategy`,
  `burstObservatory` and the runtime worker count, as the release page says.

## Remaining

The release commit, the candidate CI, `xray-rust-mobile`'s `v011` selector,
then the device and host campaign on the candidate. The order is on
[the release page](v0110-release.md#remaining-work-in-order).
