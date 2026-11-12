# v0.10 evidence collection

Status on 2026-11-11: the fixtures and Debug harnesses below can produce the
scenarios of the v0.10 profile. **No v0.10 device result exists.** The owner
runs the physical devices; nothing here is device coverage.

The contract is the schema-5 `v010` profile in
`scripts/check-v010-release-evidence.py`, accepted by the owner on 2026-11-11
and recorded with its open proposals in
[0.10.0 release preparation](v0100-release.md):

- `mkcp` and `masque` take all twelve transitions on Apple and both TUN
  backends on Android, where `wifi-cellular-wifi` is tested this time and
  `lock-wake` is not.
- `xdns`, `xicmp`, `realm`, `sudoku`, `xmc`, `header-custom`, `xdrive` and
  `vless-reverse` take seven smoke transitions on a LAN, on both platforms.
- `legacy-regression` needs the twelve protocols 0.9.0 shipped and
  `xhttp-h3-network-change`; `profile-import` needs `vless-link`,
  `trojan-link`, `vmess-link`, `hysteria2-link`, `remnawave-json` and
  `invalid-input-redaction`.
- `mkcp-` and `masque-` `throughput`, `latency` and `memory`, and the
  `release-comparison` artifact against 0.9.0.

The shared scenarios (`vless-encryption`, `ip-on-demand`,
`xhttp-download-session`, `cancellation`, `host-adapter-projection`) are
collected as in 0.9.0; see [v0.9 evidence collection](v09-release-evidence.md)
and the [0.9.0 report](device-results/2026-11-02-v090-candidate/README.md).

## What the fixtures generate

Every fixture runs the pinned Xray-core v26.11.9 server
(`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`), verified by its clean Go build
stamp or `--reference-sha256`, with fresh credentials in a new private
directory that is removed on shutdown. Synthetic destinations `198.51.100.7`,
`2001:db8::7` and a fresh `*.test` name are redirected to local echo and DNS
listeners; host routes never change.

No v0.10 case has a share link: mKCP, MASQUE, the masks, XDRIVE and the
reverse bridge are not expressible in one. Their cases carry canonical JSON
and no `text`, and the harnesses record the import as not applicable.

| Case label | Server | Client | Why this carrier |
| --- | --- | --- | --- |
| `mkcp:vless` | VLESS inbound, `network: kcp` | VLESS in the flat form over mKCP | the carrier itself |
| `masque:h3` | `masque` inbound, one user, IPv4 and IPv6 pools, HTTP/3 | `masque` outbound, Basic auth, pinned certificate | HTTP/3 is MASQUE's default |
| `xdns:mkcp` | mKCP under `xdns`, answering for `t.v010-probe.test` | the same, its resolver the inbound itself | live Xray-core interoperability exists for the mask on mKCP; a LAN has no recursive resolver |
| `xicmp:mkcp` | mKCP under `xicmp` on raw ICMP sockets | `dgram: true`, `ips` the fixture address | as above; QUIC adds nothing the mask is checked for |
| `realm:mkcp` | mKCP under `realm`, registered with the fixture's rendezvous | the same mask; the outbound names a port nothing listens on | as above; the decoy port makes the introduction the only way in |
| `sudoku:tcp` | raw VLESS under the TCP mask | the same | the TCP form is the one every TCP carrier shares |
| `xmc:tcp` | raw VLESS under the mask, two synthetic profiles | the same | TCP only |
| `header-custom:tcp` | raw VLESS under a two-round handshake reading `local_port` | the same reading `remote_port` | as for sudoku |
| `xdrive:s3` | VLESS with encryption over XDRIVE, service `s3` | the same, Mux on | a phone shares no folder with the host, so `local` cannot run; the stand-in checks every SigV4 signature |
| `vless-reverse:bridge` | the portal: a VLESS inbound whose user may reverse, and an entry inbound routed into `r-out` | entry outbound, bridge outbound with `reverse`, and a freedom redirected to the fixture | below |

Which carrier each mask rides is a proposal awaiting the owner. The UDP forms
of `sudoku` and `header-custom` are not device scenarios.

Host services the fixture starts with a case, all on the `--bind` address:

- **realm**: a STUN responder and a rendezvous speaking Hysteria's realm HTTP
  API, ported from `tests/support/realm_rendezvous.rs`. The fixture waits for
  Xray-core to register before it reports ready. The rendezvous carries no
  traffic.
- **XDRIVE**: the S3 stand-in of `tools/xdrive-oracle/standin`, with a fresh
  key pair and bucket. The fixture builds it with `go` unless
  `--xdrive-standin <binary>` names one. Both ends reach
  `http://<bind>:<port>`; no cloud account is involved. Its keys travel on its
  command line, visible to the host's other processes while the fixture runs.
  Refused requests go to the private `xdrive-standin.log`.
- **reverse bridge**: the echo and DNS listeners also listen on the bind
  address, because the device's own freedom outbound dials them.

### The device as the bridge

The device's probe traffic enters the portal as an ordinary VLESS client (the
`proxy` outbound), the portal routes all of it into the reverse tunnel, the
bridge on the device serves each session, and the device's `home` freedom,
redirected to the fixture address and allowed to reach only it, delivers it to
the echo and DNS listeners. TCP and UDP of both families, the name and routed
DNS all cross the tunnel, so no transition is replaced by a negative control.
The portal's private `server.log` names every flow `reverse-entry -> r-out`.
The case carries `settleSeconds: 5`: the bridge opens its first tunnel two
seconds after the core starts, and both harnesses wait before the first probe.

### Datagram sizes over MASQUE

A MASQUE tunnel carries 1280-byte packets and its stack does not fragment.
The Apple probe's usual 1392-byte (IPv4) and 1372-byte (IPv6) datagrams are
not delivered; the case sets `udpPayloadBytes` to 1252 and 1232, the largest
that fit. Known limitations must say that larger datagrams are dropped, where
Xray-core's stack fragments them.

### Suites

| Fixture and selection | Cases |
| --- | --- |
| `run-v07-apple-protocol-fixture.py --protocol v010` | `mkcp:vless`, `masque:h3` |
| `--protocol mkcp` or `masque` | one case; accepts `--port` for a WAN host |
| `--protocol smoke-v010` | the seven smoke cases other than xicmp |
| `--protocol xicmp` | `xicmp:mkcp`; refuses to start without raw ICMP sockets |
| `--protocol import-v010` | `remnawave-json`, four `imports`, four `invalidImports` |
| `run-v08-apple-acceptance-fixture.py --suite legacy-v010` | the twelve legacy protocols, labelled by transition id |
| `--suite xhttp-h3-v010` | `xhttp-h3` alone; accepts `--port` |
| `run-v08-android-protocol-fixture.py --suite v010 --protocol <as above>` | the same cases, `caseId` such as `mkcp-vless` |
| `run-v08-android-protocol-fixture.py --suite legacy-v010` or `xhttp-h3-v010` | the same, `caseId` = transition id |

In `legacy-v010` nothing sets `disableChromeParrot`, so Hysteria2 and XHTTP H3
run with ChromeParrot. HTTP keeps `"udp": false`: its UDP probes must go
unanswered, as in v0.9, but the legacy regression has one `http` id and no
refusal ids.

### xicmp needs raw ICMP sockets on the fixture host

Xray-core's xicmp server opens `ip4:icmp` and `ip6:ipv6-icmp` sockets. They
need root on macOS and `CAP_NET_RAW` on Linux, so the case runs in a fixture
of its own. Docker on a Mac cannot serve a phone: ICMP sent to the Mac's
address is answered by the Mac's kernel and never reaches a container. For
the device run the fixture host is either the Mac under `sudo` or a Linux
host on the same LAN; which one is the owner's choice. The client has never
run on a device ([#236](https://github.com/aimalygin/xray-rust/issues/236)).

## Host loopback check

Before touching a phone, check the candidate CLI against each suite:

```bash
python3 scripts/check-v010-fixture-loopback.py --suite v010 --reference-binary <xray> --client-binary target/release/xray-rust --work-dir <new-dir>
```

It runs each client config with a SOCKS ingress instead of TUN and checks TCP
echoes to both synthetic addresses, UDP echoes of the Apple probe's sizes (or
the case's own), the probe name through the core's routed DNS and a TCP echo
to its answer. The reverse bridge is the CLI itself. It is not device
evidence.

Results on 2026-11-11 against the pinned Xray-core v26.11.9 and a debug build
of `main` at `fb3a27f5` with this change:

| Suite | Host | Result |
| --- | --- | --- |
| `v010` | macOS arm64 | 2 of 2 |
| `smoke-v010` | macOS arm64 | 7 of 7 |
| `import-v010` | macOS arm64 | 1 of 1 |
| `legacy-v010` | macOS arm64 | 12 of 12 |
| `xhttp-h3-v010` | macOS arm64 | 1 of 1 |
| `xicmp` | Linux arm64 container, as root | 1 of 1 |

The `xicmp` suite could not run on the Mac itself, which gave this work no
root. It ran in a Docker container (Debian, root, `ping_group_range` open)
against Xray-core built for Linux from the same pinned checkout and named by
`--reference-sha256`, with the CLI built in the container. That checks the
fixture case and the client's datagram sockets on Linux; it says nothing
about Xray-core's server on macOS.

The four import links and the four malformed ones were also given to the
core's importer on the host: all four import with the fixture address, and
all four are refused without the marker in the error. The SDKs' own VLESS
importers were read, not run.

## Apple

Build the Debug `XrayClient` app with the candidate XCFramework. Copy the
fixture's private `v07-probe.json` into the app's Documents and launch it with
`XRAY_V07_DEVICE_PROBE=1`; the app writes `v07-result.json`, removes the input
and the test VPN, and logs `XRAY_V07_DEVICE` rows. The probe accepts up to
sixteen cases. Rows carry `protocol` = the case label, so a scenario's rows
are those whose label starts with its name.

| Transition | Run | Events |
| --- | --- | --- |
| `ipv4-tcp`, `ipv6-tcp` | `--mode smoke` (LAN) | `tcp` to `198.51.100.7` / `2001:db8::7`, 64 KiB echo |
| `ipv4-udp`, `ipv6-udp` | smoke | `udp` echo, `transition` `ipv4-udp` / `ipv6-udp` |
| `domain-destination` | smoke | `tcp` to the probe name |
| `routed-dns` | smoke | `dns-anchor` |
| `start-stop` | smoke, three cycles | `connected` / `disconnected` |
| `cancel-active-flow` | smoke | `connection-close-verified`, then `traffic-after-close` |
| `reconnect` | `--mode lifecycle` | `startup-cancelled`, then traffic after restart |
| `wifi-cellular-wifi` | `--mode transitions` on a WAN host | `transition-recovered` for `cellular` and `wifi`, same runtime |
| `lock-wake` | the same run, or `--mode lock-wake` | `lock-interval` of at least 15 s, `transition-recovered` `after-unlock` |
| `resource-recovery` | `--mode resources` | `load-result` for 1 and 8 flows, `resource-complete` |

Runs:

1. **Full set, LAN**, with the Mac's LAN address as `--bind`: `--protocol v010`
   with `--mode smoke`, `lifecycle` and `resources`.
2. **Full set, WAN**: on a public host, `--protocol mkcp` and `--protocol
   masque`, each with `--bind <public IPv4> --port <open UDP port> --mode
   transitions`. Both carriers are UDP only. mKCP does not move to the new
   network; it recovers when new flows dial.
3. **Smoke, LAN**: `--protocol smoke-v010 --mode smoke`, and `--protocol xicmp
   --mode smoke` from a fixture with raw ICMP sockets.
4. **Legacy, LAN**: `run-v08-apple-acceptance-fixture.py --suite legacy-v010`,
   smoke. REALITY's decoy handshake reaches `www.google.com:443`.
5. **`xhttp-h3-network-change`, WAN**: `--suite xhttp-h3-v010 --bind <public
   IPv4> --port <open UDP port> --mode transitions`. The evidence is
   `transition-recovered` for `cellular` and `wifi` on the same runtime. A
   connection that moved recovers within seconds; one that waited out its
   30-second idle timeout and dialed again also passes the 45-second deadline,
   so read `activeRecoverySeconds` and the provider's `network-observer` rows
   before calling it a rebind.
6. **Import, LAN**: `--protocol import-v010`, smoke. `link-import` rows carry
   the `transition` id and require the imported server address to be the
   fixture's; `remnawave-json` is the case's own smoke run;
   `invalid-input-redaction` is the `invalid-import-redaction` rows. VLESS
   links go through the SDK's own importer, the other three through Swift,
   the FFI and Rust.

## Android

Build `:devicehost:assembleDebug :deviceprobe:assembleDebug` with
`-PdeviceGateApplicationIdSuffix=.v010` and the candidate's
`XRAY_FFI_ANDROID_DIR`. Start a fixture, then:

```bash
ANDROID_SERIAL=<serial> python3 scripts/run-v09-android-device-matrix.py --fixture <dir>/v07-probe.json --work-dir <new-dir> --package-suffix .v010
```

For every case on both backends it imports the canonical JSON, connects,
waits the case's `settleSeconds`, drives IPv4, IPv6 and domain traffic, closes
connections and recovers, and rapid-stops and restarts. `--backend` limits the
backends. After the matrix it imports each of the envelope's `imports`
(`link-import` events with the `transition` id) and runs the malformed-link
controls.

| Transition | Source |
| --- | --- |
| `ipv4-tcp`, `ipv6-tcp`, `domain-destination` | `traffic` events, HTTP 204 from the fixture |
| `ipv4-udp`, `ipv6-udp` | `traffic` events, nonce-checked DNS-shaped UDP |
| `routed-dns` | the `domain` target, resolved through the VPN's DNS |
| `start-stop`, `reconnect` | `running`, `cancel-start-recovery` after `rapid-stop` |
| `cancel-active-flow`, `resource-recovery` | separate runs, as in 0.9.0 |
| `wifi-cellular-wifi` | `--network-change`: `transition-recovered` for `cellular` and `wifi`, then `network-change` |
| `xhttp-h3-network-change` | the same step on the `xhttp-h3` case |
| `lock-wake` | not tested, pending the owner's decision |

### Wi-Fi/cellular over adb

`--network-change` adds a step to every case, after its traffic. With the VPN
running the driver runs `svc wifi disable`, waits until `settings get global
wifi_on` reads 0, and requires traffic to pass again within 90 seconds:
traffic that passes while Wi-Fi is off left by another network. It then runs
`svc wifi enable`, waits for `cmd wifi status` to report a connection, and
requires recovery again. The step fails unless the runtime generation is
unchanged, the Device Gate counted at least one rebind request and no
coordinator error. Wi-Fi is switched back on whatever fails.

It needs:

- adb over USB. The driver refuses a network serial, which Wi-Fi off would cut.
- A SIM with mobile data.
- A fixture the phone reaches from both networks: a public host with
  `--protocol mkcp` or `masque`, or `--suite xhttp-h3-v010`, and `--port`.
- This change's Device Gate, which opts in to the network-change coordinator.
  An older build reports no rebind request and fails the step.

A rebind request is not a completed handshake. As on Apple, the recovery time
tells a moved connection from a redial.

## Lessons from the 0.9.0 campaign

All three are in the tree now; the campaign had patched them in locally.

- **REALITY warm-up.** REALITY's first decoy handshake is slow. A matrix
  started right after the fixture is ready times out the first `vless-reality`
  probe. The Android driver waits until the envelope is `--warmup-seconds` old
  (10 by default), and the loopback check waits 8 seconds for `legacy-v010`.
  On Apple, start the app a few seconds after the fixture.
- **Held flow on iOS.** The probe verifies connection closure on a live flow.
  A case that leaves none open after its traffic (HTTP, with no UDP
  association) holds an idle TCP echo for the close request to cancel. Every
  v0.10 case carries UDP, so only the legacy `http` case uses it.
- **Bridge bind address.** The XHTTP download bridge of the shared scenarios
  listens on `XRAY_FIXTURE_BIND`, so a phone reaches it over the LAN. The same
  rule holds for the v0.10 host services: the rendezvous, STUN, the storage
  stand-in and the reverse bridge's echo all listen on `--bind`.

Two more from that campaign apply unchanged: a new package's first launch
shows a notifications dialog that swallows `am start` intents, which the
driver's `POST_NOTIFICATIONS` grant prevents, and on a WAN lock step the owner
must return to the app after unlocking.

## Performance

Two collectors, both run from the candidate's checkout on one quiet machine.
Neither starts while a compiler runs, and both stop at the first failed run,
keeping what they measured.

### Builds

Every Rust binary is a `build-isolated-release.py` build: a fresh export of
one commit, an empty target directory, no inherited flags. `$C` is a campaign
directory outside version control.

```sh
python3 scripts/build-isolated-release.py --rev v0.9.0 --name baseline --campaign "$C"
python3 scripts/build-isolated-release.py --rev <candidate> --name candidate --campaign "$C"
python3 scripts/build-isolated-release.py --rev <candidate> --name harness --campaign "$C" \
    --package xray-bench --binary xray-bench
```

`baseline` is the published `v0.9.0` tag, which the comparison against 0.9.0
needs; `harness` is the candidate's traffic driver. On an Apple M-series Mac
the three builds took about four minutes and left 56 MiB in `$C`.

The reference client and server is the pinned Xray-core v26.11.9. The
preparer takes only a CGO-disabled Go 1.27.3 build that names the exact
commit and a clean tree:

```sh
CGO_ENABLED=0 go -C <pinned Xray-core checkout> build -o "$C/xray" ./main
```

### mKCP and MASQUE against Xray-core

The gate's `mkcp-` and `masque-` measurements come from the `v010` suite of
`run-v08-protocol-comparison.py`:

```sh
python3 scripts/prepare-v08-protocol-comparison.py --root "$C/comparison" \
    --candidate "$C/bin/candidate" --candidate-build "$C/build/candidate.json" \
    --harness "$C/bin/harness" --harness-build "$C/build/harness.json" --xray "$C/xray"
python3 scripts/run-v08-protocol-comparison.py --suite v010 \
    --inputs "$C/comparison/inputs.json" --output "$C/v010"
```

Without `--singbox` the preparer writes inputs that hold no sing-box client.
The `v010` suite needs none: sing-box implements neither carrier, so the suite
measures the candidate against Xray-core's own client, over a common Xray-core
server. The `v08` and `v09` suites refuse such inputs.

The suite has two profiles, each the device fixture's own case on the
loopback:

| Profile | What it is | Measurement prefix |
| --- | --- | --- |
| `mkcp-vless` | plain VLESS over mKCP at Xray-core's default capacities | `mkcp` |
| `masque-h3` | MASQUE over HTTP/3, Basic authentication, pinned certificate | `masque` |

Each runs the usual ten cases: upload, download, full-duplex, TCP latency and
UDP, on one flow and on eight. The work per flow is smaller than the other
suites' where the carrier sets the pace: mKCP moves 32 MiB and makes 200
round trips, MASQUE moves 64 MiB. mKCP's default capacity holds a flow to a
few MiB/s and its 50 ms interval holds a round trip near 100 ms for either
client, so its throughput and latency ratios show parity at that limit, not
headroom above it.

The manifest's `measurement_groups` maps `mkcp` and `masque` to their
profiles. Five rotating-order repeats become `<prefix>-throughput` (% of
paired Xray-core, at least), `-latency` (% of paired Xray-core p95, at most)
and `-memory` (MiB, at most) the way the 0.9.0 campaign's
`summarize_protocols_v09.py` computed them.
`run-v08-comparison-blocks.py` still collects the `v08` profiles only.

### The comparison against 0.9.0

```sh
python3 scripts/run-v010-release-comparison.py --campaign "$C" \
    --reference "$C/xray" --output "$C/release-comparison"
```

It checks that `baseline` is the revision and tree the checker names and that
every build is an isolated one, then runs five repeats. Each repeat starts a
fresh Xray-core server with fresh keys, carrying the twelve `legacy-v010`
cases, and runs both builds on one SOCKS flow per protocol, full-duplex bulk
and TCP latency, in alternating order: 240 runs. Throughput is the bulk run's
MiB/s, latency the latency run's p95, memory the larger sampled peak RSS of
the two runs.

`release-comparison.json` in the output directory is the archive's
`release-comparison` artifact. Each verdict is computed by the checker's own
function from the checker's budgets; the collector holds no threshold, so a
budget the owner changes is changed in one place. It validates the document
before writing it and prints the rows that are a `regression`: the release's
`known-limitations` must name each by its id.

`--smoke`, `--protocol` and fewer than five `--repeats` are diagnostics. They
write `diagnostic-comparison.json`, never the artifact.

REALITY's decoy handshake needs `www.google.com:443` reachable from the host,
as in the device fixture; each repeat waits eight seconds for it.

### What was run for this change

On macOS arm64 on 2026-11-11, with isolated builds of `main` at `0c0664fe`
and of `v0.9.0`. None of it is release evidence.

| Run | Result |
| --- | --- |
| `run-v010-release-comparison.py --smoke --repeats 5` | 240 of 240 runs in 7 minutes; the checker accepts the document once its regressions are named |
| The same at full size, `--repeats 1` | 48 of 48 runs in 3 minutes; the slowest took 34 seconds (`xhttp-h1` latency) |
| `--suite v010 --smoke`, three attempts | none completed: 31, 8 and 35 runs passed before a candidate run stalled |
| `--suite v010` at full size, mKCP: three cases, three repeats | 18 of 18 runs, 14 to 22 seconds each, the two clients level |
| `--suite v010` at full size, MASQUE: two cases, three repeats | download on eight flows 6 of 6; full-duplex on one flow 3 of 3 for Xray-core, 1 of 3 for the candidate |

Xray-core's client served as the peer on both carriers: every one of the 20
cases passed for it, and none of its runs failed.

The candidate stalled in some runs. Each time its flows had opened, it then
moved nothing, and the driver gave up after its 120 seconds:

- **MASQUE, traffic that uploads.** At full size on one flow, two of three
  full-duplex runs stalled and the third moved 13.5 MiB/s against Xray-core's
  175. At smoke size on eight flows, full-duplex stalled in two runs of two
  and upload in one of four. Downloads never stalled and were faster than
  Xray-core's: 248 against 166 MiB/s on eight flows.
- **mKCP, UDP on one flow.** One smoke run of three stalled. The driver waits
  for each echo and does not resend, so one lost datagram ends a run. The
  eight-flow runs at full size passed three times of three.

Until the MASQUE stall is fixed the `v010` suite does not pass, and the
gate's `masque-throughput` would not hold at these numbers. The suite keeps
every failed run and reports it; it does not retry one.

The single full-size repeat of the comparison against 0.9.0 is one sample a
side, not a verdict. It showed throughput within 5% of 0.9.0 on all twelve
protocols, p95 latency between 90% and 113% of it, and sampled peak memory 3
to 20% above it on eleven.

## What is not device coverage

- Every loopback result above.
- The Kotlin and Swift harness changes were compiled, not run on a device:
  `:devicehost:compileDebugKotlin` and its unit tests, and the iOS Debug build
  of `XrayAppleClient` against a stub framework. The adb Wi-Fi step was run
  only against the tests' fake adb.
- The xicmp client on iOS and Android, and Xray-core's xicmp server on macOS.

## Remaining for the owner

1. Decide the proposals in [0.10.0 release preparation](v0100-release.md).
2. Fix the candidate commit, build the Debug harnesses from it and record
   their hashes.
3. Apple, iPhone: runs 1 to 6 above, preserving every failed attempt.
4. Android: the `v010`, `smoke-v010`, `legacy-v010` and `import-v010` matrices,
   the `--network-change` runs for `mkcp`, `masque` and `xhttp-h3` against a
   WAN host, and the cancellation and resource runs.
5. Shared scenarios, as in 0.9.0.
6. Performance: the builds, the `v010` suite and the comparison against 0.9.0
   above, five repeats each, on the candidate in a quiet window.
7. Map the results into a schema-5 archive and validate it with
   `check-v010-release-evidence.py` and `v010-release-evidence.yml`.
