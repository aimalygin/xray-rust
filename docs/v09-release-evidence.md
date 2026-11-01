# v0.9 evidence collection

Status on 2026-11-01: the fixtures and Debug harnesses below can produce the
scenarios of the v0.9 profile. **No v0.9 device result exists yet.** The
owner runs the physical devices; nothing here is device coverage.

The contract is the schema-4 `v09` profile in `scripts/check-v09-release-evidence.py`
([#148](https://github.com/aimalygin/xray-rust/pull/148)), with the owner's
decisions of 2026-11-01 recorded in `docs/v090-release.md` on that branch:

- SOCKS, HTTP and classic Shadowsocks AEAD (`shadowsocks-aead`) take all twelve
  transitions on Apple and both TUN backends on Android. For HTTP, which has no
  UDP relay, `ipv4-udp-refused` and `ipv6-udp-refused` replace `ipv4-udp` and
  `ipv6-udp` (decided on 2026-11-01, below).
- Android `wifi-cellular-wifi` and `lock-wake` are not tested, decided again
  for 0.9. Known limitations must say so.
- `profile-import` needs `socks-link`, `http-link`, `shadowsocks-aead-link` and
  `invalid-input-redaction`; `legacy-regression` needs `vless-reality`,
  `xhttp-h1`, `xhttp-h2`, `xhttp-h3`, `hysteria2`, `wireguard`, `trojan`,
  `shadowsocks2022` and `vmess`.
- `socks-`, `http-` and `shadowsocks-aead-` `throughput`, `latency` and `memory`.

The shared scenarios (`vless-encryption`, `ip-on-demand`,
`xhttp-download-session`, `cancellation`, `host-adapter-projection`) are
unchanged from v0.8. This change does not touch them; the 0.8.1 campaign's
`shared-fixture.py` and projection patches in
[device-results/2026-10-18-v081-candidate](device-results/2026-10-18-v081-candidate/README.md)
show how they were collected.

## HTTP UDP: refusal as a negative control

Xray's `http` outbound is HTTP/1.1 `CONNECT`. It has no UDP relay, here or in
Xray-core. The owner decided on 2026-11-01 that HTTP proves refusal instead:
for `http`, `http-file-descriptor` and `http-packet-pump` the profile requires
`ipv4-udp-refused` and `ipv6-udp-refused` in place of `ipv4-udp` and
`ipv6-udp`. SOCKS and `shadowsocks-aead` still require real UDP echoes.

The fixtures mark the HTTP cases `"udp": false`, and both harnesses then
require every UDP probe to the synthetic echo to go unanswered. The events
carry the transition ids: Apple `udp-refused` rows have `transition`
`ipv4-udp-refused` or `ipv6-udp-refused` (echo rows `udp` have `ipv4-udp` or
`ipv6-udp`), and Android `traffic` events list theirs under `transitions`.
This is a fail-closed negative control, not UDP coverage; known limitations
should say that HTTP carries no UDP.

HTTP DNS resolves over `tcp://` through the proxy, as the HTTP link importer
configures it, so `routed-dns` for HTTP is DNS over TCP.

## What the fixtures generate

All fixtures run the pinned Xray-core v26.10.21 server
(`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`), verified by its clean Go build
stamp or `--reference-sha256`, with fresh credentials in a new private
directory that is removed on shutdown. Synthetic destinations `198.51.100.7`,
`2001:db8::7` and a fresh `*.test` name are redirected to local echo and DNS
listeners; host routes never change.

| Case label | Server inbound | Client outbound | Link | UDP |
| --- | --- | --- | --- | --- |
| `socks:password` | `socks`, `auth: password`, `udp: true`, `ip` = bind | flat `socks` with `user`/`pass` | `socks5://user:pass@host:port` | echo |
| `http:plain` | `http` with Basic `accounts` | flat `http` with `user`/`pass` | `http://user:pass@host:port` | refused |
| `http:tls` | same, TLS, ALPN `http/1.1` | same, TLS pinned by `pinnedPeerCertSha256` | `https://user:pass@host:port` | refused |
| `shadowsocks-aead:<method>` | `shadowsocks`, `network: tcp,udp` | `shadowsocks` with the method | SIP002 `ss://base64url(method:password)@host:port` | echo |

The main suite uses `aes-256-gcm`; the cipher suites add `aes-128-gcm`,
`chacha20-poly1305` (linked as `chacha20-ietf-poly1305`) and
`xchacha20-poly1305`. Links import with the `socks`, `http` and
`shadowsocks2022` formats; the last covers both Shadowsocks families.

Every v0.9 envelope also carries `invalidImports`: one malformed link per
scenario (an empty SOCKS host, an HTTPS link with a query, a `rc4-md5` stream
cipher), each containing the non-secret marker `NONSECRET-V09-IMPORT-CONTROL`
in place of a credential.

| Fixture and selection | Cases |
| --- | --- |
| `run-v07-apple-protocol-fixture.py --protocol v09` | the four cases above |
| `--protocol socks`, `http`, `https` or `shadowsocks-aead` | one case; accepts `--port` for a WAN host |
| `run-v08-apple-acceptance-fixture.py --suite ciphers-v09` | the four AEAD methods |
| `run-v08-apple-acceptance-fixture.py --suite legacy-v09` | the nine legacy-regression protocols, labelled by transition id |
| `run-v08-android-protocol-fixture.py --suite v09 --protocol v09` | the four cases plus three AEAD variants, `caseId` such as `http-tls` |
| `run-v08-android-protocol-fixture.py --suite legacy-v09` | the nine legacy protocols, `caseId` = transition id |

Before touching a phone, check the candidate CLI against each Apple suite on
the host:

```bash
python3 scripts/check-v09-fixture-loopback.py --suite v09 --reference-binary <xray> --client-binary target/release/xray-rust --work-dir <new-dir>
```

It runs each client config with a SOCKS ingress instead of TUN and checks TCP
echoes to both synthetic addresses, UDP echoes or refusals, the probe name
through the core's own routed DNS and a TCP echo to its answer. On 2026-11-01
it passed for `v09` (4 cases), `ciphers-v09` (4) and `legacy-v09` (9) against
a `main` build. It is not device evidence.

## Apple

Build the Debug `XrayClient` app with the candidate XCFramework. Copy the
fixture's private `v07-probe.json` into the app's Documents and launch it with
`XRAY_V07_DEVICE_PROBE=1`; the app writes `v07-result.json`, removes the input
and the test VPN, and logs `XRAY_V07_DEVICE` rows. `ios-wan-manual.py` in the
0.8.1 directory shows the `devicectl` steps. The probe accepts up to ten cases.

Each case first imports its link through the Swift → FFI → Rust importer
(`import` event). Rows carry `protocol` = the case label, so a scenario's rows
are those whose label starts with `socks`, `http` or `shadowsocks-aead`.

| Transition | Run | Events |
| --- | --- | --- |
| `ipv4-tcp`, `ipv6-tcp` | `--mode smoke` (LAN) | `tcp` to `198.51.100.7` / `2001:db8::7`, 64 KiB echo |
| `ipv4-udp`, `ipv6-udp` | smoke | `udp` echo, `transition` `ipv4-udp` / `ipv6-udp` |
| HTTP: `ipv4-udp-refused`, `ipv6-udp-refused` | smoke | `udp-refused`, no datagram answered |
| `domain-destination` | smoke | `tcp` to the probe name, resolved through the tunnel |
| `routed-dns` | smoke | `dns-anchor`: an A query to `198.18.0.1` answered through the proxy |
| `start-stop` | smoke, three cycles; `--mode lifecycle` | `connected`/`disconnected`, `rapid-restart` |
| `cancel-active-flow` | smoke | `connection-close-verified`, then `traffic-after-close`; local closure, not remote EOF |
| `reconnect` | lifecycle | `startup-cancelled`, then traffic after restart |
| `wifi-cellular-wifi` | `--mode transitions` on a WAN host | `transition-recovered` for `cellular` and `wifi`, same runtime |
| `lock-wake` | the same transitions run, or `--mode lock-wake` | `lock-interval` ≥ 15 s, `transition-recovered` `after-unlock` |
| `resource-recovery` | `--mode resources` | `load-result` for 1 and 8 flows, `resource-complete`; recovery ≤ baseline + 8 MiB footprint and 8 threads |

Runs, per protocol unless noted:

1. LAN, with the Mac's LAN address as `--bind`: `--protocol v09` with
   `--mode smoke`, `lifecycle` and `resources`.
1. Ciphers: `run-v08-apple-acceptance-fixture.py --suite ciphers-v09`, smoke.
2. WAN: on a public host, one run each for `--protocol socks`, `http`, `https`
   and `shadowsocks-aead` with `--bind <public IPv4> --port <open TCP+UDP port>
   --mode transitions`. Cellular cannot reach a LAN fixture. The 0.8.1 runs
   used a bounded `systemd-run` unit; see `ios-wan-manual.py`. SOCKS UDP
   crosses carrier NAT here for the first time; Xray-core's SOCKS inbound
   answers each datagram's observed source, not the port the client declares.
3. Legacy: `run-v08-apple-acceptance-fixture.py --suite legacy-v09`, smoke.
   REALITY's decoy handshake reaches `www.google.com:443`.

`profile-import`: `socks-link`, `http-link` and `shadowsocks-aead-link` are the
`import` events of those cases; `invalid-input-redaction` is the
`invalid-import-redaction` events, one per selected scenario, emitted before
any VPN starts. Each requires rejection and no marker in the error or its
description.

## Android

Build `:devicehost:assembleDebug :deviceprobe:assembleDebug` with
`-PdeviceGateApplicationIdSuffix=.v09` and the candidate's
`XRAY_FFI_ANDROID_DIR` (CI only; no local JDK). The Device Gate now accepts
`socks`, `socks5`, `http` and `https` links. Start the fixture, then:

```bash
ANDROID_SERIAL=<serial> python3 scripts/run-v09-android-device-matrix.py --fixture <dir>/v07-probe.json --work-dir <new-dir>
```

For every case on both backends it imports the link, then the core JSON,
connects, drives IPv4, IPv6 and domain traffic, closes connections and
recovers, and rapid-stops and restarts. HTTP cases must see three refused UDP
probes and no answered one per step. Each `traffic` event lists the profile
transition ids it evidences, such as `ipv4-tcp` and `ipv4-udp-refused`. With
`invalidImports` it then runs the malformed-link controls: the import fails,
the stored profile ciphertext is unchanged, the pending plaintext is removed
and the marker is absent from the host's log. Events go to `events.jsonl`.

| Transition | Source |
| --- | --- |
| `ipv4-tcp`, `ipv6-tcp`, `domain-destination` | `traffic` events, HTTP 204 from the fixture |
| `ipv4-udp`, `ipv6-udp` | `traffic` events, nonce-checked DNS-shaped UDP |
| HTTP: `ipv4-udp-refused`, `ipv6-udp-refused` | `traffic` events with `udp: refused`: three unanswered probes, none answered |
| `routed-dns` | the `domain` target, resolved through the VPN's DNS |
| `start-stop`, `reconnect` | `running`, `cancel-start-recovery` after `rapid-stop` |
| `cancel-active-flow` | separate run as in 0.8.1 `android-cancellation`: `/v08-hold/N` for TCP, `--udp-delay-seconds 3` for UDP (not HTTP) |
| `resource-recovery` | separate resource run as in 0.8.1 `android/events.jsonl` (`resource-*`) |
| `wifi-cellular-wifi`, `lock-wake` | not tested (owner decision for 0.9) |

Run `--suite v09` for the protocol scenarios and `profile-import`, and
`--suite legacy-v09` for `legacy-regression`. WireGuard has no share-link
import in the Device Gate; its case uses canonical JSON, as in 0.8.1.

## Performance

`run-v08-protocol-comparison.py --suite v09` compares the candidate with the
pinned Xray-core (and sing-box) clients over a common Xray-core server, on
seven profiles: `socks-auth`, `http-basic`, `http-basic-tls`, `ss-aes128gcm`,
`ss-aes256gcm`, `ss-chacha20`, `ss-xchacha20`. HTTP profiles have no UDP case.
The manifest's `measurement_groups` maps each schema measurement prefix to its
profiles. The 0.8.1 `summarize-performance.py` shows how five rotating-order
repeats become `<prefix>-throughput` (% of paired Xray, at least),
`-latency` (% of paired Xray p95, at most) and `-memory` (MiB, at most), the
worst profile per repeat. `prepare-v08-protocol-comparison.py` now expects the
v26.10.21 Xray-core commit built with Go 1.27.3, which the device fixture
already required. `run-v07-performance.py --suite v09` adds candidate-only
SOCKS and TUN runs for the same protocols.

## Remaining for the owner

1. Fix the candidate commit, build the Debug harnesses from it (Apple locally,
   Android in CI) and record their hashes.
2. Apple, iPhone: the LAN, cipher, WAN and legacy runs above, preserving every
   failed attempt.
3. Android, Samsung: `v09` and `legacy-v09` matrices on both backends, plus the
   cancellation and resource runs; Wi-Fi/cellular and lock/wake stay not
   tested.
4. Shared scenarios, as in 0.8.1.
5. Performance: five clean repeats of the `v09` comparison and of the existing
   measurements on the candidate, in a quiet window.
6. Map the results into a schema-4 archive, as the 0.8.1 `assemble-evidence.py`
   did, with HTTP's refusals under `ipv4-udp-refused` and `ipv6-udp-refused`
   and known limitations covering Android network/lock and HTTP's missing UDP.
   Validate it with `check-v09-release-evidence.py` and `v09-release-evidence.yml`.
