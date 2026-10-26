# Xray-core differences and verification gaps

This records compatibility decisions and unfinished integration work from
[issues #79](https://github.com/aimalygin/xray-rust/issues/79) and
[#81](https://github.com/aimalygin/xray-rust/issues/81), and PRs
[#74](https://github.com/aimalygin/xray-rust/pull/74),
[#80](https://github.com/aimalygin/xray-rust/pull/80),
[#82](https://github.com/aimalygin/xray-rust/pull/82),
[#84](https://github.com/aimalygin/xray-rust/pull/84),
[#86](https://github.com/aimalygin/xray-rust/pull/86), and
[#87](https://github.com/aimalygin/xray-rust/pull/87).
The [configuration contract](config-compatibility.md) remains authoritative for
accepted fields. This document records consequences, evidence, and follow-up
checks; it does not expand the supported configuration surface.

## Reference and evidence

Integration status reviewed on 2026-10-25 against xray-rust main
`957827b26c3afdc3420f85bb7ef0568824cebfa5` and Xray-core **v26.7.28**,
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. The upstream pin is enforced by
[verify-oracle-fixtures.py](../scripts/verify-oracle-fixtures.py). These findings
do not establish compatibility with every later Xray-core revision.

The [main CI run](https://github.com/aimalygin/xray-rust/actions/runs/40207537967)
passed rust, android, apple, go-oracles, supply-chain, and secrets after #85,
#86, and #87 were merged. Passing a job establishes the scenarios it exercises,
not every protocol/platform/transport/API combination or physical-device routing.
The tests described below are now integrated in that main revision.

These changes are in main; this evidence is not a release qualification.
The [changelog](../CHANGELOG.md#unreleased) tracks them as unreleased.

### Integrated follow-ups

| Change | Evidence | Integration state |
| --- | --- | --- |
| [#86: mobile SOCKS carrier bootstrap](https://github.com/aimalygin/xray-rust/pull/86), `312f26477b696789a7978e71e7b293fadcc74127` | Flat/legacy server settings, static mappings and aliases, IPv4/IPv6 literals, and tunnel-owned address rejection; [PR CI](https://github.com/aimalygin/xray-rust/actions/runs/40120289548) and combined main CI passed | Merged |
| [#87: SOCKS UDP outbound](https://github.com/aimalygin/xray-rust/pull/87), final head `08eba9d87f22c3e5a02a1795a889dd33f4c6c40c` | Declared UDP endpoint and association lifecycle, both relay-address review fixes, pinned UDP/TLS/TUN interop, and the reverse-direction restriction test below; [final PR CI](https://github.com/aimalygin/xray-rust/actions/runs/40157752393) and combined main CI passed | Merged |

The combined main run passed all four pinned SOCKS interop tests, both
relay-address regressions, the foreign-first-sender isolation tests, and the
Android/Apple bootstrap tests. It also passed the WireGuard rebind test that
had failed on an earlier #87 revision while binding an occupied local UDP port.
This establishes the listed tests on the combined tree, not NAT or device proof.

## Decisions at a glance

| Area | Behavior at the reviewed main snapshot | Relationship to the reference |
| --- | --- | --- |
| #74 / #83: dependencies and Tokio descriptors | Updated dependency locks, private CLOEXEC descriptor duplicates, corrected Gradle checksum retry handling | Internal Rust/build changes; no intended Xray JSON or wire-format change |
| #80 / #78: SOCKS inbound authentication | SOCKS5 username/password; stricter credential/configuration validation | RFC 1929 TCP authentication; authenticated UDP has the deliberate restriction below |
| #84 / #87 / #79: SOCKS outbound | TCP CONNECT and UDP ASSOCIATE, noauth or password, flat or legacy settings, raw TCP with none/TLS control security | Tested subset of Xray-core; UDP relay datagrams remain plain and transport restrictions remain |
| #82 / #81: Android fixes | VPN metering policy, cached native FFI information, checked stats array length | Host SDK behavior, not an Xray network protocol extension |
| #81: Android cleanup/helpers | Stage 1 merged in #82; stage 2 cleanup follows separately; stage 3 helpers remain optional | Host SDK work; preserve documented ownership and lifecycle rules |
| #79: HTTP outbound | Not implemented | Proposed CONNECT/Basic-auth/TLS support; scope decisions and checks remain below |
| #86: mobile SOCKS bootstrap | Android and Apple prepare SOCKS carrier hosts/literals before VPN setup; Apple excludes carrier routes | Integration gap fixed; destination DNS remains at the proxy |
| SOCKS inbound `udp` | `"udp": false` refuses `UDP ASSOCIATE` without a relay; an absent `udp` keeps it enabled | Explicit `false` matches the reference; the absent default differs and is an open question below |

## Password-protected SOCKS UDP: deliberate restriction

RFC 1929 authenticates the TCP control connection. SOCKS UDP datagrams do not
carry that username/password authentication. Our password-protected inbound
therefore requires a nonzero client UDP port in `UDP ASSOCIATE` and admits only
the declared endpoint. An unspecified IP can use the TCP peer's IP with the
declared port. A zero port, including `0.0.0.0:0`, is refused before a relay is
created. This prevents a different local socket from claiming the association
by sending the first datagram. The rule applies to password mode.

This is narrower than the reference and the zero-address client case described
by [RFC 1928 section 6](https://www.rfc-editor.org/rfc/rfc1928.html#section-6):

- The pinned Xray-core [SOCKS client](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/socks/protocol.go#L490)
  sends `0.0.0.0:0` for UDP association.
- Its [server](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/socks/protocol.go#L198)
  accepts that case and [learns the UDP port](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/socks/temp_udp_listen.go#L30)
  from the first matching source IP.
- Consequently, that Xray-core client cannot relay UDP through our
  password-protected SOCKS inbound. The #87 review follow-up test
  `socks_runtime_pinned_xray_client_preserves_password_udp_restriction`
  confirms this against the pinned Go client: TCP authentication and echo pass,
  while UDP is rejected. It passed in the combined main CI run.

Declaring a local port also does not guarantee operation across NAT: a NAT
that rewrites the UDP source port makes it differ from the declared endpoint.
The loopback tests do not establish NAT interoperability. Do not restore
first-sender learning to address that limitation without a replacement for the
isolation this policy provides.

Existing Rust [runtime tests](../crates/xray-core-rs/tests/runtime_data_path_tests.rs)
cover `socks_password_udp_association_refuses_undeclared_client_endpoint` and
`socks_password_udp_association_ignores_other_local_senders`, including a foreign
sender arriving first. Preserve those tests if this policy changes. Accepting
the first local sender again would remove the protection; any proposal to
broaden compatibility must explain how it retains the intended isolation.

## SOCKS inbound `udp`: `false` and the absent default

Earlier releases only type-checked `settings.udp` and answered `UDP ASSOCIATE`
whatever its value, so profiles that set `"udp": false` to keep UDP off the
local proxy got no effect. The runtime now honours it.

Source-derived: the pinned Xray-core [server](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/socks/protocol.go#L171-L175)
checks `UdpEnabled` right after the command byte, writes `REP = 0x07` with a
`0.0.0.0:0` bind address and fails the handshake before it
[creates a relay socket](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/socks/protocol.go#L206); the inbound then
closes the connection. Its [JSON loader](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/infra/conf/socks.go#L34) reads
`udp` into a Go `bool`, so an absent field means `false`.

Tested on loopback against the pinned v26.7.28 binary: with `"udp": false`, an
absent `udp`, or no `settings` object, `UDP ASSOCIATE` for `0.0.0.0:0` or for
a declared `127.0.0.1` endpoint is answered `05 07 00 01 00 00 00 00 00 00` and
the connection is closed. Under `password` the same reply follows a successful
login. `CONNECT` succeeds on each of these inbounds; `"udp": true` relays.

xray-rust now gives the explicit `false` case the same reply, creates no relay
socket, dials nothing and closes the control connection, for noauth and
password inbounds; `CONNECT` is unchanged. The
[runtime tests](../crates/xray-core-rs/tests/runtime_data_path_tests/socks_inbound_udp.rs)
`socks_udp_false_refuses_udp_associate_without_relay_or_dial`,
`socks_password_udp_false_refuses_udp_associate_after_login` and
`socks_udp_true_or_absent_keeps_relaying` cover this with a counting socket
protector. Two differences remain:

- An absent `udp` keeps `UDP ASSOCIATE` enabled; Xray-core refuses it.
  Adopting the reference default would turn UDP off for existing profiles that
  omit the field, so it is left for a maintainer decision rather than changed
  silently.
- Xray-core replies as soon as it has read the command byte; xray-rust first
  reads the complete request, including the address. A client that sends the
  request in one write sees the same bytes. A malformed address after the UDP
  command gets the general failure reply (`0x01`) here.

## SOCKS outbound: supported subset and evidence

The [parser contract](config-compatibility.md#socks-outbound) records the exact
limits. Both flat settings and one legacy `servers` entry with at most one user
match the reference's supported shapes. Our parser additionally rejects mixed
forms, zero ports, incomplete/empty credentials, and unknown fields instead of
silently accepting or ignoring them. `level` also applies without credentials;
`email` is type-checked but does not supply upstream user-identity accounting.

At the reviewed main snapshot, the outbound implements TCP CONNECT and UDP
ASSOCIATE. It rejects enabled Mux, non-raw transports, and REALITY. UDP proxy
chaining remains rejected. Xray-core has a broader transport surface. SOCKS
support does not imply `socks://` or `socks5://` import support in our mobile
profile importers.

[check-socks-interop.sh](../scripts/check-socks-interop.sh) runs a real pinned
Xray-core SOCKS server against the Rust client. Its
[runtime test](../crates/xray-core-rs/tests/socks_runtime_tests.rs) covers both
settings shapes, password/noauth, wrong/missing credentials, IPv4 and remote
domain resolution, 64 KiB payloads, socket protection, and connection inventory.
Separate [client tests](../crates/xray-proxy/tests/socks_client_tests.rs) cover
IPv6 address encoding, malformed/truncated replies, and preserving tunnel data
after the reply. These are different evidence levels: this TCP test does not
currently cover IPv6 destinations, TLS, `proxySettings`, or `probeOutboundUrl`. The UDP test
coverage below does not establish those TCP combinations.

The merged #87 follow-up extends the pinned script with UDP in both settings
forms, password/noauth and wrong/missing credentials, plain/TLS control
connections, IPv4/IPv6/domain destinations, the 8 KiB datagram framing boundary,
socket protection, host close, and TUN UDP/DNS under `StaticOnly` bootstrap.
It resolves destination names at the proxy. Separate regressions show that an
unspecified relay IP must use the actual connected TCP peer after a candidate
fallback, and that an IPv4-mapped IPv6 proxy literal needs an IPv4 UDP socket,
matching the TCP connection and #86's Apple carrier exclusions.

These tests passed locally and in combined main CI against the pinned Go
revision. They do not prove physical-device routing, NAT traversal, an IPv6
proxy carrier, TLS TCP CONNECT,
`proxySettings` or `probeOutboundUrl` interoperability. TLS protects only the
SOCKS control connection; UDP relay datagrams remain plain. UDP proxy chaining
and Mux remain rejected. No C ABI or host ownership contract changes are needed.

## Mobile SDK and the resolved SOCKS bootstrap gap

`setMetered(false)`, FFI caching, stats decoding, and the proposed #81 helpers
belong to the Kotlin SDK. They do not add a protocol to Xray-core. Stage 1 is
merged in #82. Stage 2 is a separate cleanup of snapshot/enum decoding, importer
validation, and service shutdown diagnostics. It must preserve accepted values,
error handling, cancellation, and descriptor shutdown order; secondary cleanup
errors can be retained as suppressed exceptions on the first failure.

Stage 3 helpers are optional follow-ups, not prerequisites for the cleanup.
A descriptor helper must preserve BORROWED/OWNED lifetime rules; a network-change
helper must preserve the [host's network selection and shutdown rules](../platform/android/README.md#network-changes-and-hysteria-limits).
Coroutines remain a separate dependency/API decision.

Before #86, Android's `collectOutboundBootstrapDomains` in
[XrayAndroidDnsBootstrap.kt](../platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayAndroidDnsBootstrap.kt)
and Apple's `outboundBootstrapAddresses` in
[XrayPacketTunnelProvider.swift](../platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift)
omitted `socks`. The merged fix prepares the proxy's carrier hostname before
installing the VPN in `StaticOnly` mode and applies Apple carrier exclusions.
Destination domains in CONNECT and UDP relay datagrams remain the proxy's
responsibility.

Permanent Android and Apple regressions cover both settings forms, static
hosts/aliases, literal normalization, and tunnel-owned address rejection.
They passed in combined main CI. Physical-device routing is not established by
those host tests.

## HTTP outbound: proposed scope, not implemented support

The #79 request for CONNECT, optional Basic authentication, TCP-only operation,
and plain TCP or TLS follows the pinned
[Xray HTTP client](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/http/client.go).
The [next-PR proposal](https://github.com/aimalygin/xray-rust/issues/79#issuecomment-6400188060)
requests HTTP/1.1 with matching ALPN and status 200, plus chain/probe/mobile
integration. Contributor confirmation and implementation are still pending.
Record the final decisions for these differences before claiming support:

- HTTP/1.1 versus HTTP/2: the reference supports both. If the first version
  implements only HTTP/1.1, constrain TLS ALPN accordingly and document the
  unsupported HTTP/2 path rather than negotiating a protocol it cannot speak.
- CONNECT success: the reference accepts only status 200; the issue sketch
  accepts all 2xx, consistent with
  [RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).
  Choose and test the behavior explicitly.
- The reference accepts flat and legacy settings and custom `headers`. Define
  the initial parser surface, including `level`/`email`, and reject unsupported
  options rather than implying that accepting them implements their behavior.
- Bound response-header parsing and retain bytes immediately following the
  CONNECT response. Cover authentication failure, malformed responses, TLS,
  IPv4/IPv6/domain authorities, chaining, probes, and mobile carrier bootstrap.

## Follow-up checks

- [x] Integrate the #87 review follow-up, including both relay-address fixes,
  pinned UDP/TLS/TUN tests, and the direct Go-client password-UDP restriction
  regression. The foreign-first-sender protection tests remain green.
- [x] Integrate #86 Android and Apple SOCKS bootstrap fixes and verify the
  combined #86/#87 main tree without changing destination DNS semantics.
- [ ] Add live TCP CONNECT over TLS, an IPv6 proxy carrier, `proxySettings`, and
  `probeOutboundUrl` coverage; distinguish them from UDP TLS control and IPv6
  destination coverage already added in the #87 follow-up.
- [ ] Resolve and implement the HTTP scope above before claiming #79 complete.
- [ ] Track SOCKS share-link import separately from outbound protocol support.
- [ ] Decide whether an absent SOCKS inbound `udp` should follow Xray-core's
  `false` default; see [SOCKS inbound `udp`](#socks-inbound-udp-false-and-the-absent-default).
- [ ] Keep #81 cleanup separate from new SDK API/lifecycle behavior and verify
  each against the documented FFI/host contract.

When an item is resolved, update its status, the tested xray-rust and upstream
revisions, and links to durable tests/results in the same PR. Update
[config-compatibility.md](config-compatibility.md) and the generated parser
contract whenever supported fields change. A green workflow alone does not
close an untested compatibility item.
