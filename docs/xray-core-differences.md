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

## v26.10.21 migration in progress

The active oracle pin is now `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`
(v26.10.21), built with Go 1.27.3. The dated main evidence below remains
historical. See the [migration checklist](xray-core-v26.10.21-migration.md)
for completion and pending checks.

REALITY draws `random`/`randomized` from the four hybrid profiles that the new
server accepts. Explicit X25519-only and draft-Kyber profiles still parse and
dial, as with Xray-core's client, but with a warning that v26.10.21 servers
refuse them; only profiles with no X25519 key share are rejected before
dialing. Plain TLS keeps its existing profile support. The new SS2022 oracle
imports Xray's replacement implementation directly; its deterministic vectors
canonicalize only its internal wall-clock timestamp after authenticating the
generated ciphertext.
Oversized SS2022 keys are no longer accepted upstream; Rust's legacy key
normalization remains a compatibility difference, not proof that such a
profile can be loaded unchanged in the new Xray.

The new SS2022 server also updates a UDP session's return connection after an
authenticated packet arrives from a new source address. The recovery matrix
checks roaming against Xray and retains the older fixed-return-address
expectation for the independent sing-box pin; both also test session reopening,
peer restart, response authentication and replay rejection.

## Reference and evidence

Integration status reviewed on 2026-10-25 against xray-rust main
`957827b26c3afdc3420f85bb7ef0568824cebfa5` and Xray-core **v26.7.28**,
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. The active (newer) pin is enforced by
[verify-oracle-fixtures.py](../scripts/verify-oracle-fixtures.py). These historical findings
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
| #79: HTTP outbound | HTTP/1.1 CONNECT, optional Basic auth, flat or legacy settings, raw TCP with none/TLS (`http/1.1` ALPN), TCP only | Tested subset of the pinned Xray client; status 200 only, no HTTP/2 or custom headers, bounded head, early bytes kept |
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
chaining remains rejected. Xray-core has a broader transport surface.
Development mobile profile import additionally accepts `socks://` and
`socks5://` through the shared Rust parser and Swift/Kotlin APIs under ABI 1.13;
see the [accepted link subset and capability guard](socks-profile-import.md).

[check-socks-interop.sh](../scripts/check-socks-interop.sh) runs a real pinned
Xray-core SOCKS server against the Rust client. Its
[runtime test](../crates/xray-core-rs/tests/socks_runtime_tests.rs) covers both
settings shapes, password/noauth, wrong/missing credentials, IPv4/IPv6 and remote
domain destinations, 64 KiB payloads, socket protection, and connection inventory.
The TCP matrix runs over both plain TCP and TLS, using an IPv4 carrier resolved
through the injected bootstrap resolver and a real IPv6 proxy listener on `::1`.
Separate [client tests](../crates/xray-proxy/tests/socks_client_tests.rs) cover
IPv6 address encoding, malformed/truncated replies, and preserving tunnel data
after the reply.

The [integration tests](../crates/xray-core-rs/tests/socks_runtime/integration.rs)
add these independently exercised cases:

- TCP TLS rejects both an untrusted certificate and a trusted certificate with
  the wrong server name.
- SOCKS carried over HTTP and HTTP carried over SOCKS use two real pinned Go
  proxies, with password authentication at both hops. Both legacy
  `proxySettings` and `sockopt.dialerProxy` run with plain and TLS SOCKS carriers.
  Each proxy receives its expected domain target; the local resolver accepts
  only the outer carrier name. Invalid credentials at either hop fail the flow.
- `probeOutboundUrl` explicitly selects SOCKS while the default outbound is
  Blackhole. HTTP health requests traverse IPv4/IPv6, plain/TLS SOCKS carriers,
  both settings forms and password/noauth servers. The endpoint records the
  original path, query and Host; 204 is reachable, 503 is an HTTP-status failure,
  and a wrong proxy password produces a transport failure without reaching the
  endpoint. The health URL in this matrix is HTTP; TLS here protects the proxy
  connection.

The merged #87 follow-up extends the pinned script with UDP in both settings
forms, password/noauth and wrong/missing credentials, plain/TLS control
connections, IPv4/IPv6/domain destinations, the 8 KiB datagram framing boundary,
socket protection, host close, and TUN UDP/DNS under `StaticOnly` bootstrap.
It resolves destination names at the proxy. Separate regressions show that an
unspecified relay IP must use the actual connected TCP peer after a candidate
fallback, and that an IPv4-mapped IPv6 proxy literal needs an IPv4 UDP socket,
matching the TCP connection and #86's Apple carrier exclusions.

The earlier UDP/TUN cases passed locally and in combined main CI. On 2026-10-28,
the extended suite passed locally at xray-rust
[`b39987b560b59a213cd0f22e56cd2b208bd3678f`](https://github.com/aimalygin/xray-rust/commit/b39987b560b59a213cd0f22e56cd2b208bd3678f)
against the clean Xray-core v26.10.21 checkout
`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`: eight SOCKS runtime tests and the
separate TUN UDP/DNS test, with no failures or skips in that script. The affected
data-path suite passed 203 tests; 14 external-fixture tests were left to their
dedicated scripts. Targeted all-feature Clippy and workflow-policy checks passed.
The existing `go-oracles` CI job runs the same pinned script, including the new
TCP, chain and probe cases.

These loopback tests do not establish physical-device routing or NAT traversal.
For UDP, TLS protects only the SOCKS control connection; relay datagrams remain
plain. UDP proxy chaining and Mux remain rejected. The interoperability tests
do not change host ownership contracts. The separate share-link importer adds
the ABI 1.13 capability and retains those runtime limits.

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

## HTTP outbound: implemented scope

Development ABI 1.14 additionally imports `http://` and `https://` proxy links
through the shared Rust parser and Swift/Kotlin APIs. See the
[URI subset, TCP DNS and capability guard](http-profile-import.md). This retains
the HTTP/1.1 CONNECT runtime limits below. Imported profiles are exercised by
`check-http-interop.sh` against the currently pinned Xray-core v26.10.21; HTTPS
trust/name failures are covered by the local TLS fixture.

The [#79 proposal](https://github.com/aimalygin/xray-rust/issues/79#issuecomment-6400188060)
is implemented against the HTTP/1.1 path of the pinned
[Xray HTTP client](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/http/client.go).
The decisions it asked for, with their evidence:

- HTTP/1.1 only. TLS always offers exactly `http/1.1`, also for a shaped uTLS
  hello whose profile carries `h2`, and `tlsSettings.alpn` is limited to absent,
  `[]` or `["http/1.1"]`. The reference also negotiates `h2` and then sends an
  HTTP/2 `CONNECT`; a proxy that accepts only HTTP/2 therefore fails the
  handshake here. `http_runtime_offers_only_http11_over_tls` checks the agreed
  protocol against a server that prefers `h2` with unshaped, `chrome` and
  `firefox` hellos; without the forced offer the shaped hello agrees `h2`.
- Status 200 only, as in the reference, rather than every 2xx that
  [RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
  allows. 204 is refused like 403, 407 and 502 (`connect_accepts_only_status_200`,
  `http_runtime_refuses_every_status_but_200`).
- Parser surface: flat and legacy `servers` forms; `level` selects policy with
  or without credentials; `email` is type-checked and ignored; `headers` is
  accepted only as `null` or `{}`. The reference's custom headers are Go
  templates expanded per flow; any header fails parsing instead of being
  ignored. A lone `pass`, an empty `user`, a `user` containing `:` and a
  `users` entry without `user` are rejected, where the reference drops or
  sends them. Credentials are limited to 1024 bytes each, the reference has no
  limit.
- Request: byte-for-byte the pinned Go client's, including the browser
  masquerade block and header order, except the browser versions drawn per
  process (`http_runtime_request_matches_the_pinned_go_client`). Non-ASCII
  destination domains are refused instead of converted to Punycode.
- Response: the head is limited to 16 KiB, where Go has no limit, and bytes
  after the head in the same read are delivered, where the reference loses them
  in a discarded `bufio.Reader`. Malformed status lines and header lines, 407,
  5xx and truncated heads are covered by `http_client_tests`; IPv4, IPv6 and
  domain authorities and early bytes also run end to end.
- Integration: TCP `proxySettings` in both directions, `probeOutboundUrl`, UDP
  refusal without dialing, and Android/Apple carrier bootstrap that resolves
  only the proxy name. Destination domains stay with the proxy.

`scripts/check-http-interop.sh` runs the pinned Go HTTP inbound with Basic and
open listeners over plain TCP and TLS, in both settings forms, with refused
wrong and missing credentials, and the Go-client request comparison. Physical
device routing and HTTP/2 `CONNECT` are not established.

## Follow-up checks

- [x] Integrate the #87 review follow-up, including both relay-address fixes,
  pinned UDP/TLS/TUN tests, and the direct Go-client password-UDP restriction
  regression. The foreign-first-sender protection tests remain green.
- [x] Integrate #86 Android and Apple SOCKS bootstrap fixes and verify the
  combined #86/#87 main tree without changing destination DNS semantics.
- [x] Add live TCP CONNECT over TLS, IPv6 proxy carriers and destinations,
  `proxySettings` / `sockopt.dialerProxy`, and `probeOutboundUrl` coverage. The
  TCP cases are separate from UDP TLS-control coverage; see the evidence above.
- [x] Resolve and implement the HTTP scope above; HTTP/2 `CONNECT` and custom
  `headers` remain unimplemented extensions.
- [x] Add bounded SOCKS share-link import separately from outbound protocol
  support, with native SDK capability checks; see [the contract](socks-profile-import.md).
- [ ] Decide whether an absent SOCKS inbound `udp` should follow Xray-core's
  `false` default; see [SOCKS inbound `udp`](#socks-inbound-udp-false-and-the-absent-default).
- [ ] Keep #81 cleanup separate from new SDK API/lifecycle behavior and verify
  each against the documented FFI/host contract.

When an item is resolved, update its status, the tested xray-rust and upstream
revisions, and links to durable tests/results in the same PR. Update
[config-compatibility.md](config-compatibility.md) and the generated parser
contract whenever supported fields change. A green workflow alone does not
close an untested compatibility item.
