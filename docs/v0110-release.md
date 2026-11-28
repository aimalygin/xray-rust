# 0.11.0 release preparation

Preparation started on 2026-11-27 on the owner's word, with `main` at
`880c680176199341a7994bb352e503755ae44222`.

**Status: the owner accepted the evidence contract below on 2026-11-28.**
Nothing is bound to a candidate yet. The shared steps are in the
[release process](release-process.md); this page holds what is specific to
0.11.0.

## Decisions so far

- **Version.** On 2026-11-27 the owner was asked about the release that
  brings C ABI 1.18 to the SDK and the KMP library. The owner chose 0.11.0
  («0.11.0») over a 0.10.2 patch.
- **TUN TCP sniffing is in 0.11.0.**
  - On 2026-11-16 the owner moved
    [#310](https://github.com/aimalygin/xray-rust/pull/310) out of 0.10.1.
    It had to wait until profiles the SDK importers had saved could be
    migrated.
  - On 2026-11-27 the owner took it into 0.11.0 with that migration and a
    device scenario for it («сделаем это в 0.11.0»).
  - [#385](https://github.com/aimalygin/xray-rust/pull/385) merged it the same
    day as `880c680176199341a7994bb352e503755ae44222`. It brings #310's
    sniffing, `routeOnly` in both SDK importers, and a migration at start
    for profiles they saved before 0.11.0.
- **Sniffing as in Xray-core.** On 2026-11-27 the owner had the TCP sniff
  wait aligned with Xray-core's 200 ms (it was 250 ms), and the migration of
  saved profiles recorded as a deliberate difference from Xray-core
  («Да, выровнять»). That is
  [#387](https://github.com/aimalygin/xray-rust/pull/387).
- **The evidence contract.** On 2026-11-28 the owner accepted the contract
  below («Принимаю») and had Android test `lock-wake` for the three full-set
  scenarios («Да, добавить»).
- **Not in 0.11.0.** [#383](https://github.com/aimalygin/xray-rust/pull/383)
  skips observatory probes nobody used. It stays a draft because its gain
  with the screen off is not measured (2026-11-27, «Да, так»).

## Scope

Everything merged into `main` since 0.10.1
(`3cef7c42c2fd296afd27ab0b6435c632842e1a26`, tree
`d430ce5f1c106b48ba9ecc55a25455f0a201c50f`), as listed under Unreleased in
the [changelog](../CHANGELOG.md). No carrier, transport or mask is added.
The changes are:

- **TUN sniffing.** A TCP flow to an IP address is sniffed for `http` and
  `tls` and routed by the name it sends. Profiles the SDK importers saved
  before 0.11.0 get `routeOnly` at every start.
- **The TUN loop and its flows.**
  - The loop sleeps until it has work, instead of waking every second.
  - An idle TCP flow gives back its send buffer.
  - A UDP flow's queue is bounded in bytes.
  - A MASQUE tunnel or a WireGuard device takes more TCP flows, by runtime
    profile, and a flow past the limit waits for a place.
  - A WireGuard device with no flow for five minutes is closed. The next
    flow starts a new one.
- **TLS, REALITY and QUIC dependencies.**
  - The rustls fork is shaped-rustls 0.23.4600 from crates.io.
  - TLS and REALITY sessions run through a new adapter in `xray-transport`.
  - Quinn, h2, h3 and smoltcp are the `xray-*` packages from crates.io.
  - AWS-LC is 5.12 and tokio 1.54.1.
- **C ABI 1.18.** It adds the runtime worker count, which hosts can set
  through `XrayPacketTunnelProvider` and `XrayVpnService`.
- **Import.**
  - A `vmess://` link without TLS that carries `sni`, `alpn` or `fp` now
    imports.
  - Full Xray JSON subscriptions now start when they carry fields that
    Xray-core accepts and that change nothing here.
- **DNS and routing compatibility.**
  - `localhost` and `fakedns` work as DNS servers, and `dns.servers` takes up
    to 32 entries.
  - DNS over HTTPS and DNS over QUIC reuse their connection.
  - SRV and TXT `addressPortStrategy` work.
  - RAW's `http` header and `sockopt.domainStrategy` work.
  - `burstObservatory` works, and the observatory probes again after a
    failure.

## Evidence contract

Releases 0.11.x use a schema-5 `v011` profile in
`scripts/check-v011-release-evidence.py`, validated by
`.github/workflows/v011-release-evidence.yml`. It follows the `v010`
profile. What 0.11 changes:

- which protocols take the full transition set;
- a new sniffing scenario;
- the baseline of the comparison.

1. **VLESS+REALITY, Hysteria2 and WireGuard take the full device transition
   set.**
   - **On Apple:** scenarios `vless-reality`, `hysteria2` and `wireguard`
     pass all twelve transitions: `ipv4-tcp`, `ipv6-tcp`, `ipv4-udp`,
     `ipv6-udp`, `domain-destination`, `routed-dns`, `start-stop`,
     `cancel-active-flow`, `reconnect`, `wifi-cellular-wifi`, `lock-wake`
     and `resource-recovery`.
   - **On Android:** each runs on both TUN backends, for example as
     `vless-reality-file-descriptor` and `vless-reality-packet-pump`. Unlike
     0.10, they include `lock-wake`, run as described
     [below](#android-lock-wake). Item 7 lists the transitions Android does
     not run.
   - **Why these three:**
     - VLESS+REALITY: TLS and REALITY moved to the new adapter over the
       crates.io fork.
     - Hysteria2: its QUIC runs on the crates.io Quinn fork, with
       ChromeParrot.
     - WireGuard: it has the new flow-limit wait and the idle device close.
     - All three run through the TUN loop that no longer ticks. Lock/wake,
       reconnect and the network change are the transitions that exercise
       its sleep.
   - **One extra transition for WireGuard, `idle-device-restart`.** The
     tunnel stays up with no flow for six minutes. Then TCP and UDP of both
     families pass again, over a fresh handshake. Its case sets no
     `keepAlive`, since `keepAlive` keeps a device open.
2. **TUN sniffing gets its own scenario on both platforms.** It is called
   `tun-sniffing` and has six transitions, described
   [below](#the-sniffing-scenario). On Android it has one id, and the driver
   runs every case on both backends.
3. **Regression covers everything 0.10.x shipped, with one smoke pass each
   on both platforms.**
   - **The smoke pass:** connect, IPv4 and IPv6 TCP and UDP, a name, routed
     DNS, stop.
   - **What it covers:**
     - the twelve protocols of 0.9.0;
     - `mkcp` and `masque`;
     - the masks `xdns`, `xicmp`, `realm`, `sudoku`, `xmc` and
       `header-custom`;
     - `xdrive` and `vless-reverse`.
   - **How it is recorded:** `legacy-regression` holds them as transitions,
     plus `xhttp-h3-network-change` on Apple.
   - **The `xicmp` server** still has to run on a Linux host the phones
     can reach.
4. **Profile import covers what changed since 0.10.1.**
   - `vmess-link-plain`: a `vmess://` link without TLS that carries `fp`, as
     V2Board writes it. It is imported through Swift or Kotlin, the FFI and
     Rust.
   - `xray-json-subscription`: a full Xray JSON profile with `stats`, `api`,
     `metrics`, `routing.domainMatcher` and TLS `minVersion`, run as its own
     smoke case.
   - `invalid-input-redaction`.
5. **The common scenarios** of every release stay: `vless-encryption`,
   `ip-on-demand`, `xhttp-download-session`, `cancellation` and
   `host-adapter-projection`.
6. **Performance.**
   - The gate holds `vless-reality-`, `hysteria2-` and `wireguard-`
     `throughput`, `latency` and `memory` against Xray-core v26.11.9, next
     to the four measurements every release carries.
   - The archive carries a `release-comparison` against the published 0.10.1,
     described [below](#the-comparison-against-0101).
7. **Not tested on Android, as in 0.10:** `wifi-cellular-wifi` and
   `xhttp-h3-network-change`. The test device has no cellular data (the
   owner's decision of 2026-11-15). Release known limitations must say so.

A v0.10 archive does not satisfy the profile. 0.10 owner decisions are
historical records, not 0.11 decisions.

### The sniffing scenario

`tun-sniffing` checks what #385 changed, through the real tunnel on each
phone:

- a TCP flow to an address is routed by the name it sends;
- a decoy name, the case `routeOnly` exists for, stays on its address;
- a saved importer profile is migrated in the platform's start path;
- an explicit `"routeOnly": false` still dials the sniffed name.

**The probe.**
- The probe opens a TCP connection to an address. As its first bytes it
  sends an HTTP/1.1 request or a TLS ClientHello that the fixture built with
  the transition's name.
- The fixture's echo returns the bytes.
- A refusal is a connection closed or reset without them, as for HTTP's UDP
  refusals.
- No case resolves a name: every flow goes to an address.

**The fixture's server.**
- It routes `198.51.100.0/24`, `2001:db8::/32` and the one name
  `byname.<probe>.test` to its echo, and everything else to a blackhole.
- So a flow the client dials by a decoy name, or by an address outside those
  ranges, is refused at the server.

There are three client cases. Each has a `tun` inbound tagged `tun-in` whose
sniffing has `destOverride` `http`, `tls` and `quic`:

| Case | Sniffing | Client routing, first match wins |
| --- | --- | --- |
| `sniff:route-only` | `routeOnly: true` | `routed.<probe>.test` → proxy; `refused.<probe>.test` → block; `198.51.100.7` and `2001:db8::7` → proxy; anything else → block |
| `sniff:imported` | exactly what the importers of 0.7.0 to 0.10.1 wrote: `enabled: true`, `destOverride`, `metadataOnly: false`, and nothing else | as `sniff:route-only` |
| `sniff:name-dial` | `routeOnly: false`, set explicitly | `byname.<probe>.test` → proxy; anything else → block |

| Transition | Case | Flow | Passes when | What it shows |
| --- | --- | --- | --- | --- |
| `http-host-route` | route-only | TCP to `198.51.100.8`, HTTP `Host: routed.<probe>.test` | echoed | An IP flow is routed by its HTTP Host. No address rule carries `198.51.100.8`. |
| `tls-sni-route` | route-only | TCP to `2001:db8::8`, ClientHello SNI `routed.<probe>.test` | echoed | The same for TLS, over IPv6. |
| `domain-rule-refusal` | route-only | TCP to `198.51.100.7`, HTTP `Host: refused.<probe>.test` | refused | The rule for the sniffed name wins over the address rule that would carry the flow. |
| `decoy-sni-address` | route-only | TCP to `198.51.100.7`, ClientHello SNI `decoy.<probe>.test` | echoed | No rule names the decoy, so the flow keeps its address rule and is dialed by its address. Dialed by the name, it would be refused at the server. This is MTProxy FakeTLS, and also how a private-address rule keeps a LAN flow that sends a name. |
| `saved-profile-migration` | imported | as `decoy-sni-address` | echoed | The start path added `routeOnly`: `XrayPacketTunnelProvider` after its keychain read on Apple, `XrayVpnService` on Android. Without it the flow would be dialed by the decoy name and refused. The Apple provider also logs a line when it adds `routeOnly`. |
| `sniffed-name-dial` | name-dial | TCP to `203.0.113.7`, HTTP `Host: byname.<probe>.test` | echoed | Without `routeOnly`, the flow is dialed by its sniffed name, as in Xray-core. The migration leaves an explicit `false` alone. Dialed by the address, the flow would be refused at the server. |

The scenario runs against the LAN fixture. A public host adds nothing that
the sniffer or the router reads.

### The comparison against 0.10.1

It works like 0.10's comparison against 0.9.0:

- **The builds.** The candidate against a build of the published `v0.10.1`
  tag (`3cef7c42c2fd296afd27ab0b6435c632842e1a26`, tree
  `d430ce5f1c106b48ba9ecc55a25455f0a201c50f`), measured in one run on one
  machine.
- **The artifact.** It travels in the archive as `release-comparison`.
- **The rows.** One row for each `throughput`, `latency` and `memory` of
  the fourteen carriers 0.10.1 shipped: the twelve protocols of 0.9.0 plus
  mKCP and MASQUE. That makes 42 rows, each with at least five runs a side.
- **The budgets.** The candidate's median must be at least 90% of the
  baseline's throughput, and at most 110% of its latency and memory. The
  owner accepted these budgets for 0.10 on 2026-11-13.
- **A regression.** It does not fail the gate, but `known-limitations` must
  name it by its id.

### Android lock-wake

0.10 left it untested on Android. The TUN loop that no longer ticks is
0.11's main change to how the process sleeps, and until now only the
iPhone's lock/wake exercised it.

- **How it runs.** For the three full-set scenarios, on both backends:
  - the driver turns the screen off over adb (`input keyevent
    KEYCODE_SLEEP`);
  - it waits 60 seconds and wakes the phone (`KEYCODE_WAKEUP`);
  - TCP and UDP of both families must then pass on the same runtime, without
    a restart of the tunnel.
- **What it checks.** A short screen-off does not enter Doze, so this checks
  the loop's own wake-up, not the system's idle mode.

## Not on devices

- **The DNS changes** are covered by core tests, the SDK's host tests and CI.
  Every `routed-dns` transition goes through the TUN DNS proxy, but no device
  case uses these server kinds. SRV and TXT `addressPortStrategy` call the
  platform resolvers on Android, iOS and tvOS, and have only host tests.
- **RAW's `http` header, `sockopt.domainStrategy`, `burstObservatory` and the
  re-probes** are covered by core tests and the Xray-core interop suites in
  CI.
- **The runtime worker count** is covered by core and SDK host tests. Every
  device run uses the default, and the Apple probe reports the ABI version it
  loaded.
- **Server-first flows wait 200 ms.** A TCP flow to a real address whose
  server speaks first, such as SSH or SMTP, now waits out the 200 ms sniff
  window, as in Xray-core. No fixture listener speaks first. Release known
  limitations should name it.

## Harness and tooling work this needs

1. **The `v011` profile**, following
   [497bfb29](https://github.com/aimalygin/xray-rust/commit/497bfb294a052e0abf2bc7a5bb46ac07679fa13e):
   - the checker, the workflow, `check-release-evidence.sh`,
     `make-release-records.py`, `ci.yml` and the tests;
   - `release-evidence-profile.sh` mapping minor 11 to `v011`.
2. **Fixtures.**
   - `--protocol sniff-v011`, with the three cases and the server routing
     above. The ClientHello is built by Python's `ssl` with the transition's
     name. Both platforms' fixtures need the echo.
   - An `import-v011` suite.
   - A WireGuard case without `keepAlive`, for `idle-device-restart`.
   - A `v011` suite in `run-v08-protocol-comparison.py` for the three
     full-set protocols.
   - The release-comparison collector pointed at 0.10.1, with mKCP and
     MASQUE added.
3. **The Apple probe** (`XrayProtocolDeviceProbe.swift`): sniff probes per
   case (an address, a payload, an echo or a refusal expected), and the idle
   step.
4. **The Android Device Gate and `run-v09-android-device-matrix.py`.**
   - The same raw TCP exchange. The probe checks HTTP 204 today.
   - The idle step and `lock-wake`.
   - The case's JSON goes to `startXrayTunnel` unchanged, so `sniff:imported`
     reaches `XrayVpnService` in the form the importers saved.
5. **A host loopback check** of every new case, as for 0.10.

## xray-rust-mobile

- `scripts/release-evidence-profile.sh` maps minor `11` to `v011`, and its
  selector tests get the `v011` cases.
- Then the core pin, the synchronization and the version files. C ABI 1.18
  is already there since
  [xray-rust-mobile#63](https://github.com/aimalygin/xray-rust-mobile/pull/63).

[xray-rust-kmp](https://github.com/aimalygin/xray-rust-kmp) joins after the
SDK publishes.
[xray-rust-kmp#4](https://github.com/aimalygin/xray-rust-kmp/pull/4) then
moves to the SDK release.

## Remaining work, in order

1. ~~The owner accepts the contract and answers the open question.~~ Done
   on 2026-11-28.
2. The `v011` profile, the fixtures and the harness work above, with host
   loopback checks.
3. The release commit:
   - workspace version 0.11.0;
   - a dated changelog section;
   - the regenerated configuration contract.

   Then the full release CI on the candidate.
4. `xray-rust-mobile` pins the candidate and adds the `v011` selector; SDK CI
   passes.
5. The device and host campaign on the candidate, the archive, and
   `v011-release-evidence.yml`.
6. Owner decisions, the tag, the core release, the SDK release (Maven Central
   approval is the owner's), then the KMP library.
7. After 0.11.0: #383's measurement with the screen off.
