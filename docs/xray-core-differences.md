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

## Reference revision

The active oracle pin is `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`
(v26.11.9), built with Go 1.27.3; see the
[v26.11.9 migration record](xray-core-v26.11.9-migration.md) and, before it,
the [v26.10.31 one](xray-core-v26.10.31-migration.md). The
[v26.10.21 migration](xray-core-v26.10.21-migration.md) introduced the REALITY
and SS2022 changes described next. The dated main evidence below remains
historical.

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
| #84 / #87 / #79: SOCKS outbound | TCP CONNECT and UDP ASSOCIATE, noauth or password, flat or legacy settings; since 0.10.0 every transport with none/TLS/REALITY control security | Tested subset of Xray-core; UDP relay datagrams remain plain, as there |
| #82 / #81: Android fixes | VPN metering policy, cached native FFI information, checked stats array length | Host SDK behavior, not an Xray network protocol extension |
| #81: Android cleanup/helpers | Stage 1 merged in #82; stage 2 cleanup follows separately; stage 3 helpers remain optional | Host SDK work; preserve documented ownership and lifecycle rules |
| #79: HTTP outbound | HTTP/1.1 and HTTP/2 CONNECT, optional Basic auth and custom headers, flat or legacy settings, every transport with none/TLS/REALITY since 0.10.0, TCP only | Tested subset of the pinned Xray client; status 200 only, one try, bounded head, early bytes kept, HTTP/2 tunnels end with `END_STREAM` |
| #86: mobile SOCKS bootstrap | Android and Apple prepare SOCKS carrier hosts/literals before VPN setup; Apple excludes carrier routes | Integration gap fixed; destination DNS remains at the proxy |
| SOCKS inbound `udp` | `"udp": false` refuses `UDP ASSOCIATE` without a relay; an absent `udp` keeps it enabled | Explicit `false` matches the reference; the absent default differs and is an open question below |
| Policy half-close timeouts | SOCKS and HTTP relays switch from `connIdle` to `downlinkOnly` after the client finished sending and to `uplinkOnly` after the server did; both default to 1 s | Source-derived from the outbound timers (`proxy/freedom/freedom.go`, `proxy/vless/outbound/outbound.go`) and `SessionDefault` in `features/policy/policy.go`; covered by paused-clock unit tests, not by interop. Stricter: the inbound level also bounds each phase, while the reference SOCKS/HTTP inbounds run no timer of their own |

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
protector. As in Xray-core, the refusal goes out once the command byte is
read, before the address. One difference remains: an absent `udp` keeps
`UDP ASSOCIATE` enabled; Xray-core refuses it. Adopting the reference default
would turn UDP off for existing profiles that omit the field, so it is left
for a maintainer decision rather than changed silently.

## SOCKS inbound handshake deadline

The `handshake` timeout of the SOCKS inbound starts when it accepts the
connection and covers the wait for the first byte as well as the rest of the
handshake, whichever of SOCKS 5, SOCKS 4/4a or HTTP that byte selects.
Xray-core's SOCKS inbound (`Process` in `proxy/socks/server.go`) reads the
first byte without a deadline and sets the handshake deadline only after it,
in `processTCP` and in the HTTP server's `ProcessWithFirstbyte`. There a
client may wait as long as it likes before its first byte and then gets a
whole handshake timeout for the rest. Ours is stricter on purpose: a
connection that sends nothing is closed after one timeout, and a first byte
sent late leaves only what is left of it. Earlier releases bounded the first
byte by one timeout and gave the rest a second one. Each later request on a
kept-alive HTTP connection, and every request on the HTTP inbound, still gets
the timeout from the start of its wait, as in Xray-core. The test
`the_wait_for_the_first_byte_counts_against_the_deadline` in
[socks_inbound_wire.rs](../crates/xray-core-rs/tests/runtime_data_path_tests/socks_inbound_wire.rs)
sends the first byte of each protocol 0.9 s into a one-second timeout and
expects the close at one second, not 1.9 s.

## SOCKS inbound `ip`

`ip` binds the `UDP ASSOCIATE` relay and is the address the reply names, as
Xray-core's `proxy/socks/protocol.go` uses it. Two inputs Xray-core accepts
are refused when the config loads:

- A domain. Xray-core reads `ip` as an IP or a domain, and a domain makes the
  first `UDP ASSOCIATE` call `IP()` on a domain address, which panics.
- An IP outside loopback, `0.0.0.0` included, unless the inbound sets
  `allowUnauthenticatedLan`. On a loopback listener such a relay would expose
  the UDP side of the proxy to the network, which the listen address rule
  exists to prevent.

The parser test `parses_socks_inbound_udp_relay_ip` covers both refusals,
and `the_ip_setting_names_the_udp_relay` an IPv6 control connection answered
with the configured IPv4 relay.

## SOCKS outbound: supported subset and evidence

The [parser contract](config-compatibility.md#socks-outbound) records the exact
limits. Both flat settings and one legacy `servers` entry with at most one user
match the reference's supported shapes. Our parser additionally rejects mixed
forms, zero ports, incomplete/empty credentials, and unknown fields instead of
silently accepting or ignoring them. `level` also applies without credentials;
`email` is type-checked but does not supply upstream user-identity accounting.

At the reviewed main snapshot, the outbound implements TCP CONNECT and UDP
ASSOCIATE over every transport, with none, TLS or REALITY, as Xray-core does
since 0.10.0. It rejects enabled Mux, and UDP proxy chaining remains
rejected.
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
`check-http-interop.sh` against the currently pinned Xray-core v26.11.9; HTTPS
trust/name failures are covered by the local TLS fixture.

The [#79 proposal](https://github.com/aimalygin/xray-rust/issues/79#issuecomment-6400188060)
is implemented against the HTTP/1.1 path of the pinned
[Xray HTTP client](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/http/client.go).
The decisions it asked for, with their evidence:

- HTTP/1.1 or HTTP/2, as TLS decides. TLS offers what the reference offers,
  so a shaped hello carries its profile's `h2`, and the tunnel is an HTTP/2
  `CONNECT` stream when the proxy picks it
  ([details](config-compatibility.md#http2-connect)). A capture of both clients
  against a TLS proxy that offers `h2` matched the opening SETTINGS, the
  request's fields in 23 cases and connection sharing. The differences: 16 MiB
  of connection credit where Go grants 1 GiB, a `TE` other than `trailers`
  refused, a refused tunnel failing alone where the reference closes the shared
  connection, `END_STREAM` where the reference resets with `CANCEL`, and the
  first bytes sent after the 200 rather than with the request.
  `http_runtime_tunnels_over_http2_when_tls_picks_it` and
  `http_runtime_stays_on_http11_unless_tls_picks_h2` run them end to end. With
  `fingerprint: "unsafe"` and no `alpn`, no protocol is offered, where the
  reference offers `h2` and `http/1.1`, so such a profile stays on HTTP/1.1.
- Status 200 only, as in the reference, rather than every 2xx that
  [RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
  allows. 204 is refused like 403, 407 and 502 (`connect_accepts_only_status_200`,
  `http_runtime_refuses_every_status_but_200`).
- Parser surface: flat and legacy `servers` forms; `level` selects policy with
  or without credentials; `email` is type-checked and ignored; `headers` are
  Go templates filled in per flow, as in the reference, except that template
  actions other than the `Source` and `Target` fields, invalid names and most
  control characters are refused when the profile is read, and a profile takes
  at most 64 headers of 8 KiB. A lone `pass`, an empty `user`, a `user` containing `:` and a
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
  only the proxy name. Destination domains stay with the proxy. The reference
  tries a failed tunnel five times, a refusal included; this client tries once.

`scripts/check-http-interop.sh` runs the pinned Go HTTP inbound with Basic and
open listeners over plain TCP and TLS, in both settings forms, with refused
wrong and missing credentials, and the Go-client request comparison. That
inbound reads HTTP/1.1 only, so its TLS sets `alpn: ["http/1.1"]`; with the
default list it picks `h2`, and the reference's own HTTP outbound fails on it
too. No pinned HTTP/2 `CONNECT` server exists in the reference, so HTTP/2 is
checked against the reference client's capture. Physical device routing is
not established.

## Shadowsocks classic AEAD: implemented scope

The `shadowsocks` outbound accepts the classic AEAD ("AEAD-2017") methods of
the pinned client (`proxy/shadowsocks`, `infra/conf/shadowsocks.go` at
v26.10.21) next to Shadowsocks 2022. Tested against the reference:

- Method names, aliases and rejections: the oracle runs Xray's own config
  builder over 21 strings (`tools/v08-protocol-oracle/ssaead.go`), including
  `none`, `plain`, stream ciphers, an empty name and a leading space, and the
  Rust classifier must agree (`accepted_method_names_match_pinned_go_config_builder`).
  Both families are matched case-insensitively, as upstream lowercases them;
  SS2022 names were previously case-sensitive here.
- Wire bytes from the pinned Go code for all four ciphers and two passwords:
  EVP_BytesToKey master keys, the request (salt, sealed address record), the
  next payload record, the chunk boundaries of a 20000-byte write (8158-byte
  records), UDP packets, and a server response ending in an empty record
  followed by bytes that must not be read.
- Live TCP, native UDP, TUN and Mux/XUDP through the pinned Go server
  (`scripts/check-shadowsocks2022-interop.sh`, `check-mux-interop.sh`): all
  four ciphers and two aliases on raw, one cipher on each other carrier, and
  the native UDP codec up to the 8192-byte peer limit with forged and
  wrong-key replies rejected.

Deliberate differences, source-derived:

- Records above the SIP004 0x3FFF limit fail the stream; upstream's reader
  accepts lengths up to 65519. Conforming writers, Xray's included, never
  exceed the limit, and the cap bounds per-stream memory.
- A datagram whose framing exceeds 8192 bytes is refused before sending.
  Upstream's encoder writes into an 8192-byte buffer and fails on overflow,
  and its server reads into one; the limit is the same, the failure is local.
- The nonce counter fails closed at exhaustion instead of wrapping.
- Like upstream's client, salts are not replay-filtered and UDP replies have
  no replay window; the format carries no identifier to bind them to.
  Shadowsocks 2022 remains the recommended family.

Pending: `check-v08-independent-interop.sh` now also runs the raw classic AEAD
cases against sing-box, but that run is not yet recorded; no physical-device
run yet; the legacy fully-base64 `ss://` form and SIP003 plugins are not
imported.

## VLESS and VMess settings

VLESS and VMess outbound settings are read as Xray-core v26.10.31 reads them,
in the simplified form and in `vnext`, with ids as its `uuid.ParseString`
reads them ([details](config-compatibility.md#outbounds-and-streams)).
Deliberate differences:

- A VLESS user without `encryption` is read as `none`, and a `vnext` server
  with several VLESS users dials as the first. Xray-core refuses both
  profiles; accepting them breaks none it accepts.
- A server port of 0 fails parsing, as before. Xray-core accepts it and
  dials port 0.
- VLESS `reverse` makes the outbound the bridge of a reverse proxy; its
  differences are listed [below](#vless-reverse-proxy).
- VLESS `testpre` is at most 64 here; Xray-core starts any number of dialers.
- A `testpre` dialer whose dial fails waits 200 ms before the next, twice as
  long after each further failure, up to ten seconds. Xray-core dials again at
  once, without end, while the server is unreachable.
- A request waits sixteen seconds for a `testpre` connection, the time
  Xray-core's system dialer gives a dial, and then fails. Xray-core's request
  waits until a connection comes.
- Xray-core panics when a `testseed` range is zero, and writes a negative
  padding length when a short record is longer than its third number. Here a
  zero range pads nothing and that part of the padding is zero.

## mKCP

mKCP and its `mkcp-legacy` masks are read and run as Xray-core v26.10.31's
([details](config-compatibility.md#mkcp)). Deliberate differences:

- `mtu` is at most 8192. Xray-core accepts more, then panics on the first
  segment that does not fit its 8192-byte buffer.
- A `dns` header whose labels fill all 256 bytes of the name fails the dial.
  Xray-core panics there.
- Gecko, Salamander's `packetSize`, `udphop` and TCP masks are refused on
  mKCP, and `mkcp-legacy` on any other transport. Xray-core applies every UDP
  mask to mKCP's socket, ignores TCP masks on it, and ignores UDP masks on
  TCP transports. Plain Salamander applies, a header mask grouped with
  `mkcp-legacy`'s as in Xray-core.
- mKCP over another outbound, through `dialerProxy` or `proxySettings`, is
  refused. Xray-core dials its datagrams through the chain.
- A datagram the system refuses to send counts as lost, and goes again when
  its retransmission timeout passes. Xray-core retries it five times 100 ms
  apart, holding the connection's writer meanwhile.
- `kcpSettings.header` and `kcpSettings.seed` warn that they are ignored.
  Xray-core v26 ignores them silently.

Xray-core's own SOCKS inbound panics over mKCP, taking its local address for
a TCP one (`proxy/socks/server.go:112`), so the SOCKS outbound over mKCP has
no Xray-core server to talk to.

Evidence, against Xray-core v26.10.31:

- Byte for byte, its finalmask code and ours wrap and unwrap the same
  datagrams for every `mkcp-legacy` mask, with the header counters, the DNS
  names Xray packs oddly, groups split by noise, and the 4096-byte drops
  (`tools/kcp-oracle`, `tests/fixtures/kcp/mask-vectors.json`).
- Live, its mKCP server carried VLESS, VMess, Trojan, Shadowsocks and HTTP
  from our client, plain and under TLS, with each mask, noise between masks,
  Mux with XUDP, and Vision through a direct-mode switch under inner TLS
  (`scripts/check-kcp-interop.sh`).
- Its client and ours, through a relay in front of its server: neither sent
  anything before the first request; both sent the same 53 data segments for
  a 64 KiB echo, then a terminate 1.0 s after the request closed, then two
  pings in 12 idle seconds; both finished the echo through 10% loss each way;
  and both ended a read about 30 seconds after the server fell silent.
- Both resend segments the server already has on loopback, where the
  retransmission timeout falls to about a millisecond after the first sample:
  over seven echoes its client sent 53 to 98 data segments for the 53 it
  needed, ours 53 to 74. The protocol is the same; when acks are read
  relative to flushes differs.

Deliberate differences, both against a peer that misbehaves:

- A repeated data segment is acknowledged again in its place in the ack
  list. Xray-core's `AckList.Add` lists the number once more each time, and
  entries leave only when the peer's `sending_next` passes them, so one
  repeated segment grows the list, and with it every ack flush, without
  bound; with the `original` or a header mask alone that needs no secret.
- A datagram that an `mkcp-legacy` AES mask opens to less than the masks
  inside it reserve is dropped before they read it.

## header-custom TCP

The `header-custom` TCP mask is read and run as Xray-core v26.10.31's
([details](config-compatibility.md#header-custom-tcp-mask)). Deliberate
differences:

- The client's handshake runs as soon as TCP connects, where Xray-core runs it
  on the first write. Every client protocol writes first, so the bytes and
  their order are the same; only a carrier opened and never written, such as
  a `testpre` connection without TLS, sends its handshake sooner.
- One `header-custom` TCP mask, and a `fragment` mask only before it. After
  it, Xray-core's fragment mask would split the handshake instead of the TLS
  ClientHello.
- `rand` is at most 65536 bytes, and an item sent or read and a `pad` at
  most 1 MiB, where Xray-core allocates whatever is asked, even when
  captures double an item at every step. A `slice` whose offset and length
  overflow fails, where Xray-core panics.
- Only the carriers of proxying outbounds run it. Xray-core runs TCP masks on
  freedom and DNS dials too, and ignores them on UDP carriers, which refuse
  them here.

Xray-core's own REALITY server panics on a `header-custom` connection, which
lacks the `CloseWrite` it asserts
(`reality@v0.0.0-20261014101318-83f621788ca8/tls.go:187`), so REALITY with
`header-custom` has no Xray-core server to talk to.

Evidence, against Xray-core v26.10.31:

- Its client and server connections, run over a pipe for 23 configs, wrote
  the bytes ours writes and read (`tools/header-custom-oracle`,
  `tests/fixtures/header-custom/tcp-vectors.json`): every packet type, every
  transform op, the metadata, captures each way, rounds of every length,
  delays, the server's errors sequence, and each kind of failure.
- 55 of 55 parity configs get the verdict `xray run -test` gives.
- Live, its server took the handshake from our client on raw, raw TLS,
  WebSocket, HTTPUpgrade, gRPC and XHTTP, and refused a wrong one each time
  (`scripts/check-header-custom-interop.sh`).

## header-custom UDP

The mKCP, Hysteria, XHTTP over HTTP/3, MASQUE over HTTP/3, freedom and
WireGuard clients support Xray-core v26.10.31's prefix and standalone UDP
custom masks, including captures, expressions, address metadata on writes,
five-second per-peer state and mask ordering. The parser accepts one custom
mask on those carriers; other UDP carriers, multiple custom masks and a
custom mask with `udphop` are rejected. Under `udphop` Xray-core writes to `0.0.0.0:0` but reads from the
hop's address, so its standalone reply never completes and prefix captures
never match. The same item and expression limits as the TCP implementation
apply.

Custom headers are limited to 4096 bytes. Prefix writes whose combined
header and payload exceed 4096 bytes are dropped; Xray-core sends stale
bytes of its pooled buffer in place of everything past 4096 bytes, and
panics past 8192. Standalone reads are truncated to its 4096-byte
buffer, and dropping a Rust stream releases a pending standalone handshake.
A standalone request unanswered for a second goes out again. On mKCP,
Xray-core blocks its data updater on the reply for good; its ping updater's
next write sends a new request, and once that is answered, data goes out
only at the ping updater's five-second pace. On QUIC, quic-go's send loop
waits for the reply for good. Freedom and WireGuard read the reply while
the send waits; see
[UDP masks on freedom and WireGuard](#udp-masks-on-freedom-and-wireguard).

Thirteen client/server exchanges recorded directly from Xray-core are
checked byte for byte (`tools/header-custom-udp-oracle`,
`tests/fixtures/header-custom/udp-vectors.json`); one is a standalone client
sequence that only Xray-core's client accepts, recorded against a scripted
peer because its server measures the client sequence and refuses it. Tests
also cover expiry, wrong peers, malformed replies, cancellation, the
dual-stack local address and ordering with noise and legacy masks. Live mKCP interop covers both modes, each alone and with noise
on either side and an additional legacy mask. Live Hysteria interop covers
both modes alone and on either side of Salamander, and live XHTTP H3 interop
both modes alone and with noise on either side; on both, a client whose
sequence the server does not expect never connects. See
[configuration](config-compatibility.md#header-custom-udp-mask).

## sudoku

The `sudoku` TCP and mKCP masks build Xray-core v26.10.31's tables: the 288
4x4 grids, the clue sets only one grid has, and the order Go's `math/rand`
gives them for the password, reimplemented here with Go's own constants.
Deliberate differences:

- The TCP mask must be the last one in `finalmask.tcp`; Xray-core also
  accepts it before other TCP masks.
- An unknown `ascii` mode or a malformed custom table fails the
  configuration, where Xray-core accepts it and fails every dial.

On Hysteria and XHTTP over HTTP/3 sudoku makes each QUIC packet at least four
times its size, which only IP fragmentation carries past the path MTU.
quic-go writes to Xray's masked conn, whose don't-fragment bit it cannot
set, so the system fragments and quic-go turns its path MTU discovery off.
Quinn sets that bit on its sockets, so the carrier clears it again on every
socket, the rebound ones included, and Quinn's path MTU discovery is off too.
Xray-core's Salamander sits in its group of header masks, which takes at most
4096 bytes, so when Salamander comes after sudoku its server drops every
reply; the same happens on mKCP with legacy masks after sudoku.

Evidence: `tools/sudoku-oracle` records Xray-core's own classic datagrams and
packed server writes for entropy, ASCII, custom and rotating custom tables,
an empty password and padding, and every byte decodes; its output is
random, so `scripts/check-sudoku-interop.sh` decodes a fresh run each time.
Live against Xray-core's server, raw (plain, TLS and REALITY), WebSocket,
HTTPUpgrade, gRPC and XHTTP each carry a TCP echo and UDP, as do ASCII mode
and a `header-custom` handshake inside sudoku; a client with another
password never gets through. mKCP carries the same with sudoku alone, behind
noise, and around a legacy mask; Hysteria with sudoku alone and outside
Salamander, before and after a rebind; and XHTTP over HTTP/3 with sudoku
alone and with noise on either side.

## xmc

The `xmc` TCP mask logs in as Xray-core v26.10.31's client does: its
handshake and Login Start, the RSA key `DeriveRSAKey` derives from the
password (primes from a SHA-256 stream, reimplemented here), PKCS #1 v1.5,
AES-128-CFB8, the Minecraft 26.1.2 padding schedule with its burst choices
and timing bands, then custom payload packets of at most 24 KiB with the
server's keep-alives answered. Deliberate differences:

- It must be the last mask in `finalmask.tcp`; Xray-core also accepts it
  before other TCP masks.
- REALITY cannot run over it. Xray-core's REALITY server asserts that its
  connection can half-close, which xmc's server connection cannot, so every
  connection through both panics the server process, on RAW, gRPC and XHTTP
  alike.
- A password over 113 bytes fails the configuration: PKCS #1 v1.5 with the
  1024-bit key carries 117 bytes, and the server's verify token takes four.
  Xray-core accepts the configuration and fails every login.
- The login runs as the carrier connects. Xray-core's runs on the first read
  or write, which every client protocol makes at once.

Evidence: `tools/xmc-oracle` records the key Xray-core derives from four
passwords, which `scripts/check-xmc-interop.sh` compares on every run. Live
against Xray-core's server, raw (plain and TLS), WebSocket, HTTPUpgrade,
gRPC and XHTTP each carry a TCP echo and UDP, as does a `header-custom`
handshake inside xmc; a client with another password, or with a profile the
server does not hold, never gets through.

## xdns

The `xdns` UDP mask queries resolvers as Xray-core v26.10.31's client does:
its domain capacities, base32 names under the domain, the client id with
the query type in its low bits, padding and fragments, polls whose delay
doubles to ten seconds, the resolver balance, and answers read as Go's
`dnsmessage` unpacks them, base32 and IDNA quirks included. Deliberate
differences:

- DNS over TCP sends each message after its two-byte length. Xray-core's
  `TCPResolver` hands an `int` to `binary.Write`, which writes nothing, so it
  sends bare messages no real resolver reads.
- A domain with an empty label or one longer than 63 bytes fails the
  configuration. Xray-core accepts it and its client panics at the first
  query, when the name does not pack.
- An unknown record type, no domain name and no resolver fail the
  configuration; Xray-core fails every dial.
- It must be the last UDP mask, and runs neither with udphop nor, on QUIC,
  with sudoku: Xray-core dials the masks after it for nothing, and sudoku's
  datagrams exceed the 4096 bytes an xdns packet takes.
- Resolvers are IP addresses over UDP or TCP. Names, DNS over HTTPS and its
  `tlsConfig` and `quicConfig` are not supported yet.
- A packet waiting for a full resolver queue is dropped, as a datagram
  would be; Xray-core's writer waits.

Evidence: `tools/xdns-oracle` records `NewDomain`'s verdicts, encoded names,
queries, the server's answers and the client's reading of mutated answers,
which the tests replay; `scripts/check-xdns-interop.sh` regenerates a larger
corpus each run. Live against Xray-core's server, mKCP carries a TCP echo and
UDP through UDP and TCP resolvers, both at once, with extra polls and with
AES and noise inside xdns; XHTTP over HTTP/3 and Hysteria, alone and with
Salamander inside, before and after a rebind, carry the same. A client with
another domain never gets through.

Deliberate difference: a UDP resolver's socket reads answers from that
resolver's address alone. Xray-core's socket is unconnected and reads from
any source, and an answer is matched to nothing but the tunnel's domain in
its question, so anyone who knows the domain and reaches the port can feed
the carrier packets and set off a poll for each.

## MASQUE

The `masque` outbound runs Xray-core v26.10.31's MASQUE client over HTTP/3
and HTTP/2: its configuration checks and defaults, the CONNECT-IP request
with its authority, path, User-Agent presets and Basic authorization, the
server settings it waits for, the address request and assignment rules, the
datagram and capsule formats and packet admission, ICMP Packet Too Big, the
tunnel pool of its `xmux` with the one-second retry rule, and the stack over
each tunnel with `remoteDNS`, and `warp` for Cloudflare WARP: its key and
address checks, the device certificate, the endpoint key check and both
Cloudflare request forms. Over HTTP/2 it runs Xray-core's own HTTP/2
client: its SETTINGS, connection window and header block byte for byte, its
stream windows, the 32 KiB write buffer, the 128 queued packets and the
keepalive. Deliberate differences:

- A WARP TLS session is never resumed: its client certificate is part of
  it, and the dial that resumes one would not show a fresh certificate.
- Unknown fields in `warp` fail the configuration, as everywhere; Go's
  JSON ignores them.
- The stack is the WireGuard outbound's smoltcp stack, not gVisor: 16 TCP
  and 512 UDP flows a tunnel, its buffers and its TCP. smoltcp does not act
  on ICMP Packet Too Big; the QUIC connection never goes below its 1350-byte
  first packets, so the stack's 1280-byte packets always fit.
- A name tries up to eight addresses, three seconds each and ten for the
  last, as the WireGuard outbound does; Xray's stack divides the handshake
  timeout between them. A flow's open deadline is the handshake timeout plus
  the ten-second tunnel dial.
- An empty `address` fails the configuration; Xray-core accepts it and fails
  every dial. `remoteDNS` takes at most 8 servers and no scoped IPv6
  address; Xray-core takes any.
- Chaining (`proxySettings`, `dialerProxy`) and Mux fail the configuration,
  as for Hysteria and WireGuard, and so does the TCP fragment mask, which
  Xray-core's HTTP/3 dial ignores; over HTTP/3 the other TCP masks fail
  when the core starts. Unknown fields fail, as everywhere.
- The HTTP/3 request lists its pseudo-fields in h3's order and its fields
  sorted; quic-go starts with `:authority` and sends fields in map order.
  Neither is visible outside the TLS session.
- Over HTTP/3 the UDP masks follow the rules of every QUIC carrier, with
  [realm's](#realm) and [xicmp's](#xicmp) differences: an xicmp outbound
  whose address is a name, with no `ips`, fails when the core starts. A
  realm introduction counts toward the ten-second tunnel dial, as in
  Xray-core, whose introduction runs under the dial's context; one that
  overruns is cancelled here, where Xray-core's finishes before its QUIC dial
  fails.
- Over HTTP/2, UDP masks and a `TE` header other than `trailers` fail the
  configuration: Xray-core ignores the masks on its TCP dial and sends the
  header, which this HTTP/2 client refuses to.
- The HTTP/2 keepalive counts any bytes from the server as a frame, where
  Xray-core counts whole frames, and keeps one PING outstanding, with h2's
  own payload; Xray-core sends a zero payload and may send another while the
  first is unanswered. Neither is visible outside the TLS session.
- Over HTTP/2 the stream's window also opens once an update would double
  what the server may still send, Go's rule; Xray-core waits for 1 MiB read
  each time. The connection's window opens once what was read reaches half
  of what the server may still send, h2's rule, where Xray-core opens it
  with the stream's. One tunnel's stream stays the tighter limit either
  way.
- A closing HTTP/2 tunnel closes its TCP connection; Xray-core first ends
  its request stream and resets it. A non-ASCII authority goes out in
  punycode, as over HTTP/3; Xray-core's HTTP/2 client sends it as it is.

Evidence: `tools/masque-oracle` runs inside Xray-core's `connectip` package
through a `go test -overlay` and records its capsule encodings, its reading
of valid and mutated capsules, the datagrams `composeDatagram` builds, its
ICMP messages and which packets it admits; the tests replay them and
`scripts/check-masque-interop.sh` regenerates a corpus ten times larger each
run. A second oracle in the `masque` package records the frames Xray-core's
HTTP/2 client writes up to its request for eight requests; ours match them
byte for byte. 137 configuration cases
carry `xray run -test` verdicts, rechecked with the binary each run: 124
match and 13 differ as listed above and in the mask rules; every case the
configuration takes also builds a core, but the xicmp one to a name without
`ips` and the TCP masks over HTTP/3. Live against
Xray-core's MASQUE server over HTTP/3: TCP with a 128 KiB echo to IPv4, IPv6
and a name resolved through the tunnel, UDP to the same three, TCP through
the HTTP inbound, TCP and UDP through the TUN, eight parallel flows sharing
one tunnel, the default path with a preset User-Agent, the `conservative` and
`aggressive` BBR profiles, and a wrong password refused; under the
header-custom and sudoku UDP masks, noise inside sudoku, with another sudoku
password carrying nothing; introduced by realm through a local rendezvous;
and, as root on Linux (`scripts/check-xicmp-interop.sh`), inside xicmp.
Over HTTP/2 the same flows run live, through a uTLS fingerprint as well,
plus the default path with Go's User-Agent and no keepalive, and under the
sudoku and header-custom TCP masks, another sudoku password carrying
nothing.
Mutating 22 key branches (TTL, checksum, admission, capsule
checks, address choice, authority, User-Agent, the pool's limits and retry,
the host and path checks) fails the tests each time, and so does mutating
27 of the HTTP/2 path (capsule framing, the bare read rule, the
write buffer and windows, the keepalive, the extended CONNECT check, the
header block options and field order, ALPN, keepalive defaults and the TE
check), or dropping each mask's wiring, the xicmp address check,
MASQUE's place among the UDP carriers or HTTP/2's among the TCP-mask
carriers. For `warp`, a third oracle runs inside Xray-core's `infra/conf`
and records its verdict on 156 private keys, 108 public keys and 22 address
lists, well-formed and damaged, and ours match all of them; the HTTP/2
oracle's WARP requests match byte for byte; and UDP of both families runs
live over HTTP/3 with draft and RFC 9297 datagrams and over HTTP/2 with and
without ALPN against a stand-in built from Xray-core's own warp tests, which
checks the device certificate with Go's TLS, while an endpoint with another
key is refused. 16 of its branches (key, curve and range
checks, PEM and base64 rules, point validation, address rules, the
certificate's validity and serial, the draft datagram setting, the
Cloudflare protocol and request) fail the tests when mutated.

Deliberate difference: the control capsules that wait for the request
stream are bounded at 256 KiB as well as at Xray-core's 128. The answer to
an ADDRESS_REQUEST is as large as the request, so a proxy that grants the
stream no credit and keeps asking would otherwise have the client hold 128
answers of about 200 KiB each. Over HTTP/2, a DATAGRAM capsule longer than
the 8,192-byte packets the tunnel reads is skipped as it arrives; Xray-core
buffers one up to 65,535 bytes and drops it on read. A tunnel the proxy
closes within five seconds of establishing it counts as a failed dial: flows
take the failure for a second, as after a refused dial, where Xray-core
dials again for the next flow at once.

## XDRIVE

The `xdrive` transport runs Xray-core v26.10.31's XDRIVE client with all
four services, `local`, `google-drive`, `s3` and `template`: its
configuration checks and
defaults, `validateXDrive`'s rules for the outbound it carries, the session
announcement, the segment names and marks, the writer's cuts and eight-tick
coalescing, the reader's polling, batches, hole timeout, failure marks and
deletes, the local folder's names and atomic writes, and the HTTP storages
as its Go client reaches them: TLS, ALPN, Go's HTTP/2 settings, windows,
pseudo-header order and HPACK choices, its HTTP/1.1 framing, Chrome's
`fetch` headers, gzip, stalls, XMUX, fronting through
`streamSettings.address` and `port`, SigV4, S3 listings, template
operations, Drive's files, tokens and queries, sessions in rings of slots,
HTTP/3 storages, auth, retries and redirects. The server address is never
looked up, as in Xray-core. Deliberate differences:

- A storage over HTTP/3 writes its request headers in the vendored `h3`'s
  order (`:method`, `:scheme`, `:authority`, `:path`), where quic-go writes
  `:authority`, `:method`, `:path`, `:scheme`, as for XHTTP over HTTP/3. A
  storage over HTTP/3 cannot go through another outbound; Xray-core dials
  its UDP with the stream's socket options.
- A storage is shared by the sessions of its outbound only. Xray-core shares
  one process-wide by the service, folder, S3 addressing, secrets, security
  type and fronting address, a key without the template, TLS settings or
  `xmux`, so a second outbound differing only there runs on the first one's
  storage; here each outbound has its own.
- A template's answer is read up to 64 MiB; Xray-core reads it whole.
  Drive's has Xray-core's own cap of 32 MiB since v26.11.9, and S3 answers
  keep Xray-core's limits.
- A Drive listing and the children a delete removes are taken in name
  order; Xray-core takes them in Go's random map order.
- A slot writer that finds a full segment no slot is free for waits before
  it adds a write to its buffer, where Xray-core's `Write` adds it and then
  waits for the slot; the backpressure is the same.
- `{folder}`, `{name}` and the other placeholders are replaced in one fixed
  order; Xray-core replaces them in Go's random map order, which differs
  only when a value holds another placeholder. HTTP/2 regular headers are
  written in one fixed order, after Go's pseudo-headers, where Go's map
  order varies with each request, and a `Cookie` header stays one field
  where Go's HTTP/2 splits it.
- A template naming one field twice in different case (`put` and `PUT`)
  takes the one in exact case; Go takes the later in the text.
- A token lifetime at `expiryPath` past the int64 range saturates, as Go's
  conversion does on arm64, where phones and Apple's computers run
  Xray-core; on amd64 Go makes it the minimum, and the token keeps the
  default hour. The lifetime then wraps through Go's nanoseconds as in
  Xray-core rather than panicking, so a saturated one has already run out.
- A `Retry-After` date in RFC 850 form whose zone abbreviation names the
  device's own time zone is read as UTC; Go's `http.ParseTime` takes that
  zone's offset. Every other date reads as Go reads it.
- A redirect to a host that is not ASCII leaves auth and cookie headers
  behind even within the same domain; Go compares the Punycode forms.
- A `namesRegex` naming a Unicode 17 script newer than the `regex` crate's
  tables fails, and Go's and the crate's size limits for huge expressions
  differ; everything else of Go's RE2 syntax is translated, its errors
  included.
- `streamSettings.address` read from the environment (`env:`) is refused,
  as are `address` and `port` under any other transport, which Xray-core
  reads and ignores.
- No `xdriveSettings` under `network: "xdrive"`, and `local` with an empty
  `remoteFolder`, fail when the core starts; Xray-core accepts both and
  fails every dial.
- A writer holds the sender back once twice `concurrency` segments are cut
  and not yet stored; Xray-core starts a goroutine for each and lets them
  pile up. Only then can a flush tick find a full segment in the buffer, so
  under such back pressure segment boundaries may fall elsewhere than
  Xray-core's would; the bytes of the stream do not change.
- Shutting a stream down ends only its own direction (its buffer, then
  `.end`) and keeps reading the server's; Xray-core's `Close` ends both,
  which its server sees the same way. A stream dropped without a shutdown
  stores its buffer and `.end` in the background for up to two minutes,
  where Xray-core's `Close` blocks until they are stored.
- VLESS `reverse`, which lets Xray-core run XDRIVE without Mux, is refused,
  as on every VLESS outbound here.
- Google Drive's spare rings that no dial took are deleted when their
  outbound goes away (the core stops); Xray-core keeps them as long as its
  process runs and leaves them in the folder when it exits. A token fetch
  that every waiter gave up on still completes and keeps its token, as in
  Xray-core, and Drive's throttle counter, which only its tests read, is not
  kept. The `local` service's retry of Windows sharing violations has no
  counterpart: xray-rust does not run on Windows.
- Unknown fields in `xdriveSettings`, `s3` and `xmux` fail, as everywhere;
  Go's JSON ignores them and matches field names in any case. Over
  `tlsSettings.alpn` other than exactly `["h3"]` the UDP masks, Salamander
  among them, fail, and the TCP fragment mask needs TLS, as on the other
  carriers; Xray-core accepts them and the masks do nothing there.
  `disableChromeParrot` is read there as Xray-core reads it.

Evidence: `tools/xdrive-oracle` runs inside Xray-core's `xdrive` package
through a `go test -overlay` and records `paramsFromConfig` on 11 inputs,
`objectName`, `parseEntry` on 33 names, `announceName`, the local storage's
`resolve` on 22 names, and replays of its segment writer on 17 sequences of
writes, flush ticks and closes (with refused segments and end marks) and of
its reader on 18 sequences of listings (holes, entries behind the head, end
and failure marks, inline payloads, failing and missing objects, duplicate
spellings, a full discard queue). A second overlay records the HTTP
storages: the URL and SigV4 headers `s3Storage.target` and `sign` give five
requests at a fixed time and `objectKey`'s two refusals, 22 S3 answers read
through `s3ListPage` and `s3ErrorCode`, 26 templates through
`newTemplateStorage`, `subst` on 6 and `jsonString` and `jsonNumber` on 20
inputs, `http.ParseTime` on 78 `Retry-After` dates, 61 `namesRegex` patterns
through Go's `regexp` (matches and error texts), 46 `net/url` resolutions,
16 redirect chains through Go's `http.Client` and a scripted RoundTripper,
and the frames Go's HTTP/2 client writes for 7 requests over TLS on a pipe
(SETTINGS, the connection WINDOW_UPDATE, the pseudo-header bytes, the
fields, the DATA frames); then the slot frames `newSlotFrame` encodes for 7
segments and what `decodeSlot` makes of 14 descriptions, 9 rings through
`json.Marshal` and `decodeRing`, Drive's query quoting, multipart bodies and
rate limits, and a scenario of eleven `driveStorage` calls against canned
answers, whose 19 requests the tests compare one by one (method, path and
query, content type, token, body). The tests replay them all, and
`scripts/check-xdrive-interop.sh` regenerates them each run, byte for byte.
228 configuration cases carry `xray run -test` verdicts, rechecked with the
binary each run: 217 match and 11 differ as listed above; every case both
accept also builds a core, but the 4 the core refuses as listed above. Live
against Xray-core's XDRIVE server, the two meeting in a temporary folder:
TCP with a 128 KiB echo and UDP to IPv4 and IPv6 through Mux, eight parallel
TCP flows on at most four sessions, the server deleting every segment the
client stored, X25519 and ML-KEM-768 authentication, and 4 KiB segments two
at a time. Then in the stand-in of `tools/xdrive-oracle/standin`, written
from the AWS documentation apart from Xray-core's signer, which Xray-core's
own client crosses first with this client's configuration, so that a
stand-in Xray-core cannot use fails the test before this client is held to
it: an S3 bucket checking every signature, Xray-core path-style over
HTTP/1.1, this client virtual-hosted over HTTPS and HTTP/2 through
`streamSettings.address` and then path-style over HTTP/1.1, with a session
token and one-key pages that make every listing continue; and a template's
REST store, Xray-core with a static token over HTTP/1.1, this client with
OAuth 2 over HTTPS and HTTP/2 through the stream's address, tokens fetched
again each second and forgotten by the store, objects as base64 in JSON,
two-step reads through a link that redirects, and retries after a 403 naming
a rate limit, a 429 and a 401; the stand-in's log shows each of these
crossed the wire. Then in Xray-core's own fakeDrive, served on Google
Drive's real paths over TLS and HTTP/3 by a third overlay: both in rings of
eight slots over HTTP/2, the server taking this client's sessions in slots,
and this client over HTTP/3 through a noise mask while Xray-core stays on
HTTP/2; there too Xray-core's own client goes first, in slots and over
HTTP/3. A flow through the core announces its session and stores its request
with a resolver that fails every lookup. Mutating 54 branches of the
sessions and the folder fails the tests each time: 26 of the configuration
(services, secrets, the template and `s3` presence, each `ValidateS3Config`
rule, the xmux defaults and conflict, the HTTP/3 rules, every
`validateXDrive` rule), 23 of the transport (names and their parsing, the
tuning's defaults, caps and floor, the writer's coalescing, cuts, end and
failure marks, the reader's holes, end marks, missing objects, discards and
wake-up, the local folder's names and temporary files, the end a shutdown or
a drop stores) and 5 of the core (both refusals, the skipped lookup, XDRIVE
over HTTP/3 among the UDP carriers, the build at start). So does mutating 82
branches of the HTTP storages: redirects (9), URL resolution (3), S3
addressing, signing, listings, deletes, missing objects and retries (13),
templates' decoding, limits, 404s, flat listings, retries, tokens, lifetimes
and two-step reads (13), the client's headers, fronting and SNI (4), the
HTTP/2 settings, windows, framing, pseudo-header order and HPACK choices (9,
two in the vendored `h2`), S3 answers (2), JSON numbers (2), `namesRegex`
(3), XMUX draws (1), the keepalive (1), Go's wrapping of token lifetimes
(1), `Retry-After` dates (12), answers read under their limit, gzip decoded
as it arrives over HTTP/1.1 and HTTP/2 (5, a sixth equivalent), the fronting
fields (2) and the core's TLS for a storage and its refusal of HTTP/3
storages, until they were built (2); five of them only the live tests catch.
Mutating 33 branches of Drive, the slots and HTTP/3 fails them as well: the
slots' depth, inline limit, ramp, bursts, magic, checksum, ring keys, laps
and watermark, end and failure marks and stale bodies (13), Drive's inline
limit, multipart boundary, query quoting, rate limits, rejected and expired
tokens, description fallback, children, listings, upload URL and token form
(12), Go's JSON escapes and case folding (2), the client's HTTP/3 (1, which
only the live test catches), its answers read under their limit and stopped
with H3_REQUEST_CANCELLED when cut short (2), Drive's secrets kept out of
`Debug` (1) and the core's masks over HTTP/3 and its Drive build (2).

## realm

The `realm` UDP mask introduces the carrier's socket as Xray-core
v26.10.31's client does: its URL read with Go's `url.Parse`, STUN answers
read as pion/stun reads them, the rendezvous request written as Go's HTTP
client writes it over HTTP/1.1 and its answer read as `encoding/json` reads
it, the candidates and predictable symmetric-NAT ports it punches, and punch
packets with their salt, padding and SHA-256 mask. Deliberate differences:

- `portMapping` is not acted on yet: no UPnP or NAT-PMP mapping is made and
  the gateway's external address is never offered, as when Xray-core finds
  no gateway. Xray-core spends up to twice the timeout looking for one at
  every dial.
- It must be the last UDP mask, and runs neither with udphop, xdns nor
  header-custom: Xray-core sends STUN and punch packets through the masks
  after it, udphop and xdns send elsewhere, and header-custom keys its state
  by the server's address while replies come from the peer's.
- A URL port of 0 or above 65535, a host with a colon that is no IPv6
  address, a token with control characters, a token or name that does not
  unescape to UTF-8, and a STUN server whose port does not read as 1 to
  65535 fail the configuration. Xray-core accepts them, then fails every
  dial or skips the server.
- The rendezvous is spoken over HTTP/1.1, where Go's client may negotiate
  HTTP/2 over TLS, and over rustls's TLS, unshaped, where Xray-core uses
  Go's own. `tlsConfig.alpn` is read and not used.
- Names are resolved like the outbound's server address; Xray-core asks
  Go's resolver.
- The rendezvous call gives up after 20 seconds; Go's client waits for good.
- The socket closes with the connection; Xray-core leaves it open until the
  garbage collector finds it.
- With `ipMode` `dual` on a system without IPv6 sockets, STUN servers
  resolve to IPv4 only.
- A Hysteria connection whose network changes closes, and the next dial is
  introduced again: a new socket needs a new hole.
- A peer address with a named IPv6 zone does not parse, which loses the
  whole list, as any address Go cannot parse does there.

Deliberate difference: one attempt punches the first 64 candidates, in the
order above. Xray-core punches every address the rendezvous lists, a hello
of up to 1,057 bytes to each ten times a second for ten seconds, so a
rendezvous, or anyone who can answer for one reached over plain HTTP, picks
where that traffic goes and how much of it there is.

Evidence: `tools/realm-oracle` records `Realm.Build`'s verdicts on 77 URLs,
23 STUN servers and 29 settings, 720 STUN answers read by
`parseSTUNBindingResponse`, 138 punch packets read by `DecodePunchPacket`,
18 candidate sets and 31 rendezvous exchanges with Go's `realm.Client`; the
tests replay them all, the requests byte for byte. Live against Xray-core's
server through a local rendezvous speaking Hysteria's realm API, mKCP
carries a TCP echo and UDP over a dual-stack and an IPv4 socket, with AES
and noise inside realm; XHTTP over HTTP/3 and Hysteria, alone and with
Salamander inside, and MASQUE over HTTP/3 carry the same; an unknown realm
name gets no introduction.

## xicmp

The `xicmp` UDP mask writes and reads echo messages as Xray-core
v26.10.31's client does: its identifier, sequence, client id and checksum,
x/net/icmp's reading of replies, the drop of the system's own echo and of a
raw socket's foreign identifiers, and Go's stripping of a raw IPv4 header.
Deliberate differences:

- Each server address gets its own socket, never bound and connected to it.
  Xray-core binds one unconnected socket per family to the wildcard, which a
  Network Extension refuses; replies here come only from the address each
  packet went to, as Xray-core's Linux server sends them. A family the
  addresses do not use needs no socket, where Xray-core fails every dial
  unless sockets of both families open.
- It must be the last UDP mask, and runs neither with udphop, xdns, realm
  nor header-custom, nor on QUIC with sudoku: Xray-core fails every dial
  with it anywhere else, the others send elsewhere, header-custom keys its
  state by the server's port while replies come without one, and sudoku's
  datagrams exceed what an echo carries.
- An outbound address that is a name, with no `ips`, is refused when the
  core starts; Xray-core never resolves it and fails every dial. With `ips`,
  a name there must still resolve.
- An Apple datagram socket keeps the client's identifier and receives every
  reply from its address, so replies are told apart by identifier, as on a
  raw socket. Xray-core's datagram sockets there also read the replies meant
  for other connections to the same server.
- An echo the socket has no room for is dropped, as a datagram would be;
  Xray-core's writer waits.

Evidence: `tools/xicmp-oracle` records `Xicmp.Build`'s verdicts on 36
addresses and 13 settings, 44 echoes from Xray-core's `marshal`, 32
checksums and 160 messages read by x/net/icmp's `ParseMessage`; the tests
replay them all. Live against Xray-core's server on Linux, which reads ICMP
on raw sockets, mKCP carries a TCP echo and UDP over datagram sockets, to
the outbound's address and to two listed ones, and over raw sockets, with
AES and noise inside xicmp; XHTTP over HTTP/3 and Hysteria, alone and with
Salamander inside, before and after a rebind, and MASQUE over HTTP/3 carry
the same.

## UDP masks on freedom and WireGuard

Freedom's UDP flows and WireGuard's socket take the UDP masks, as
Xray-core v26.10.31's `FinalMask.DialUDP` wraps every UDP socket it dials.
They run the QUIC carriers' masks one datagram at a time: noise,
header-custom, Salamander with Gecko, sudoku, xdns and xicmp, in Xray-core's
order. Deliberate differences:

- A masked freedom flow takes replies only from the address it sends to.
  Xray-core's masked socket also takes another sender's datagrams, which
  most masks cannot unmask anyway.
- WireGuard's masks take one peer, and a second peer fails the core at
  start. Xray-core dials its masked socket to the first peer's endpoint and
  writes every peer's packets to it.
- udphop and realm are refused on both, since each needs a driver that
  replaces or introduces the socket, which only the QUIC carriers have here;
  `mkcp-legacy` is refused, as on every carrier but mKCP. Xray-core applies
  each of them.
- Sudoku cannot run under xdns or xicmp: its datagrams exceed what an xdns
  packet or an echo carries. Xray-core fails each write that does not fit.
- A datagram under Salamander may exceed 4096 bytes here. Xray-core's header
  masks, Salamander among them, write at most 4096 bytes a datagram, so its
  server cannot answer one that large, for example a 1200-byte payload
  under sudoku inside Salamander.
- A send that a standalone header-custom holds for the server's answer reads
  in the receiver's place meanwhile. It keeps up to 256 KiB of datagrams for
  the receiver and drops the rest. Xray-core's mask reads in a goroutine of
  its own, which holds up to 16 datagrams for the receiver and stops reading
  while they wait. An unanswered request goes out again after a second, as
  on the QUIC carriers; Xray-core's write waits for the answer for good.

Evidence: unit tests drive the masked socket against a plain one, noise
inside and outside Salamander, salted replies, another sender's datagrams
and unmaskable ones dropped, a datagram longer than the receiver's buffer
cut, or dropped under Salamander. A send a standalone header holds takes the
answer in itself, keeps an earlier reply for the next receive, and hands a
receiver in another task what it read, that receiver waiting on the socket
again once the send is through. A TUN flow through freedom runs under noise
and a header-custom prefix, and waits out a standalone header; a query the
TUN DNS proxy sends through freedom goes under a standalone header too.
Live against Xray-core's `tunnel` inbound under the same masks, freedom
carries UDP under Salamander, noise inside it, header-custom in prefix and
standalone mode, sudoku and sudoku inside Salamander. Against its WireGuard
inbound, WireGuard carries TCP and UDP under Salamander with noise on
either side, header-custom in both modes and sudoku. Another Salamander
password carries nothing on either.

## filter

The `filter` mask is read and validated as Xray-core v26.11.9's
`Filter.Build` reads it, in `finalmask.tcp` and `finalmask.udp` of any
outbound, and then dropped: Xray-core's client wrappers return every
connection unchanged. With only filters, Xray-core's carriers take their
masked dial path, which dials what their plain path dials. Deliberate
differences:

- A filter after udphop or xicmp is refused. Xray-core accepts it, and then
  fails every dial with `incorrect index`, since it finds those masks by
  their place in the list.
- A field the object spells several ways, such as `blockedSourceIPs` and
  `BlockedSourceIPs`, has every spelling checked. Go keeps the last one it
  decodes, an order serde_json does not keep.

Evidence: `tests/fixtures/filter/config-verdicts.json` holds what the pinned
`xray run -test` says of 117 cases: carriers and outbounds, settings and
list shapes, the rules `geodata.ParseIPRules` takes and refuses, field
spellings, and filters among other masks. The parser gives each its
verdict but for the two differences above; with its filters taken out, each
accepted case parses to the same configuration and warnings, and each builds
a core. Through freedom's UDP and a VLESS TCP carrier, filters among noise
and header-custom send the same bytes as the masks alone, and a reply from
an address a filter blocks still arrives. Rules naming geodata were checked
against the binary with files under `XRAY_LOCATION_ASSET`, and udphop and
xicmp before a filter by dialing it.

## VLESS reverse proxy

A VLESS outbound with `reverse` is the bridge of Xray-core v26.10.31's VLESS
reverse proxy, as its outbound and `app/reverse` bridge worker are: the same
monitor (every 2 seconds from 2 seconds after the start, a new tunnel when
none is active or each holds more than 16 sessions), the reverse command with
its header held 500 ms and five dials, a Mux.Cool server reading the portal's
client and local addresses and its control session, sessions dispatched as
from the reverse tag with the outbound's email and the reverse sniffing, and
freedom's default final rule for them, which blocks every address. The legacy
root `reverse`, removed upstream in v26.4.25, fails with upstream's message;
the portal's side is not supported. Deliberate differences:

- A tunnel holds at most 512 sessions at once and a bridge keeps at most 16
  tunnels, draining ones included. A session past the bound is refused with
  an error End. Xray-core sets no bound; its portal drains a tunnel once more
  than 256 sessions, its control session included, were opened on it, so its
  own never reach these.
- Under an XHTTP link of a `dialerProxy` chain, and through a dedicated
  freedom fragment outbound that `dialerProxy` names (folded into the outbound
  here), the portal's sessions and the tunnel are refused always, before
  anything is dialed, unless the freedom's `finalRules` allow the server:
  the freedom the chain ends on for XHTTP, the fragment freedom otherwise.
  Xray-core refuses them only on the dials that carry the session, so a
  session reusing an XHTTP connection another opened passes there. XHTTP's
  connections are shared across flows here, and refusing at the dial would
  stall the others. (Over Mux, `testpre` and gRPC neither refuses: Xray-core
  opens those connections without the session's context.)
- Each destination of a UDP session is a flow of its own, routed and relayed
  as a SOCKS association's flows are, and the session ends once its flows went
  idle, after 60 seconds. Xray-core routes the session once by its target and
  sends each datagram through that route to the address its frame names; with
  routing per destination the bridge opens nothing that routing would refuse
  on its own.
- With `dns.fakeIp` on, a fake IP in a session's target turns back into its
  domain, as for every inbound here; Xray-core does that only when sniffing
  names `fakedns`.
- A bridge whose outbound cannot be built, such as Vision without TLS or
  REALITY, fails the core's start. Xray-core starts and fails every dial of
  the tunnel, every two seconds.
- A frame payload over 8 KiB, metadata after the portal's client and local
  address other than zero padding, or a session ID used twice closes the
  tunnel. Xray-core's portal writes none of these; its bridge reads stream
  chunks up to 64 KiB and ignores trailing metadata.
- The bridge sends no End back for a session the portal ended. Xray-core's
  sends one with the error flag, which the portal discards.
- Unknown fields in `reverse` fail parsing, as everywhere here.

Evidence: `tools/reverse-oracle` records what Xray-core's own mux, reverse
and VLESS code write: the portal's frames, with its client's addresses, its
control session and a UDP session; the bridge's answers; control messages;
and the tunnel request with and without Vision. The tests read the portal's
frames back as written and write the bridge's byte for byte
(`tests/fixtures/reverse/vectors.json`). 47 configuration cases carry
`xray run -test`'s verdicts; 45 match and the parser refuses two that Xray
takes (an unknown field in `reverse`, a VLESS inbound), and each case the
parser takes builds a core but two with Vision on a raw carrier. A portal
written in the tests from the same sources drives the core's monitor, Mux
server and routing: TCP and UDP, freedom's refusal, routing by tag, source
and email, a drained and a lost tunnel, the freedom a chain ends on, under one
freedom and under two, refusing sessions and a tunnel until it allows the next
hop. Xray-core as the bridge, checked first against its own portal, refuses
sessions at the freedom a chain ends on over raw, WebSocket, HTTPUpgrade,
XHTTP, HTTP and SOCKS links and a tunnel through a freedom, and refuses none
over Mux, gRPC or `testpre`. Live, with Xray-core as the portal,
TCP and UDP services behind the bridge answer over raw, VLESS encryption,
TLS with Vision, WebSocket, gRPC and XHTTP; freedom without final rules
dials nothing; a wrong UUID gets no tunnel; and after 260 sessions the
portal drains the first tunnel and the bridge opens a second; chains through
one and two freedoms are refused until the last allows the relay, Mux and gRPC
links are not, and a tunnel through a freedom opens once it allows the portal;
over XHTTP a session through a freedom and a tunnel are refused until it
allows the relay or the portal (`scripts/check-reverse-interop.sh`). Unit
tests and the portal written here refuse sessions, UDP flows and the tunnel
through a folded freedom fragment until it allows the server.

Deliberate difference: the bridge fails a tunnel once 2,048 session Ends
wait for a portal that reads none of them, rather than queueing one for
every frame of a session it does not hold.

## QUIC BBR profiles

`quicParams.bbrProfile` `conservative` and `aggressive` run a port of
Xray-core v26.10.31's BBR sender with the profile's settings, on Hysteria and
XHTTP H3, from where Xray's dialers install it: after the handshake on XHTTP,
after the authentication reply on Hysteria. Before that the connection runs
Quinn's NewReno, as Xray's runs quic-go's Reno. Deliberate differences:

- `standard`, the default, still runs Quinn's BBR from the first packet. The
  port runs `standard` as well; switching the default is a separate decision.
- Quinn paces from the sender's rate with its own token bucket, which caps a
  burst at 256 datagrams; Xray's pacer has no cap.
- Quinn lowers the datagram size after detecting a black hole. Xray's sender
  panics if asked to; the port scales its windows down.
- Quinn's startup NewReno starts at quic-go's 32 datagrams of the initial
  size but follows Quinn's Reno rules. `congestion: reno` keeps that sender.
- The sender knows each packet by its place among all the connection sent,
  not by its packet number. quic-go hands its sender packet numbers, and QUIC
  numbers the Initial, Handshake and 1-RTT spaces from zero each: when the
  acknowledgement of the client's Finished, Handshake packet 1, arrives after
  the switch, the sender takes it for 1-RTT packet 1: it counts that packet's
  bytes as delivered and closes a delivery sample from its send time, before
  the packet itself is acknowledged. The numbers of 1-RTT packets keep their
  order, so rounds and recovery end
  where they would; only a comparison with the sender's initial zero can
  move, by one packet in the first round.
- A lost MTU probe is not listed for the sender. The apernet quic-go fork
  lists it in `OnCongestionEventEx`, though it keeps it from its own
  senders, and Xray's BBR then enters recovery for a probe that was larger
  than the path carries: a loss by design, which RFC 9000 section 14.4
  keeps out of the congestion response.
- The bytes a bandwidth should deliver over an interval
  (`bytesFromBandwidthAndTimeDelta`) are computed in 128 bits. Xray-core's
  int64 product wraps once bandwidth times interval passes 2^63, which
  100 Mbit/s reaches after 92 seconds: the first ACK after such an idle then
  finds a negative count, the ack-aggregation epoch stays open, and the
  extra acked bytes lift the cap off the congestion window. Every product
  short of the wrap is the same as Xray-core's, so the oracle traces still
  replay.

Evidence: `tools/bbr-oracle` records Xray-core's own sender over fifteen
simulated paths, and the port replays every call to the same 54 state values
after each congestion event; `scripts/check-bbr-interop.sh` regenerates the
trace each run and runs every profile live against Xray-core's Hysteria and
XHTTP H3 servers. `xray run -test` and the parser agree on 184 configurations
of `bbrProfile` and `congestion`.

## ChromeParrot

Hysteria, XHTTP H3 and XDRIVE's storages over HTTP/3 shape their QUIC
handshake like Chrome's, as Xray-core v26.10.31's dialers do through the
apernet quic-go fork, unless `quicParams.disableChromeParrot` is true;
MASQUE never does, as there.
`disableChromeParrot` is a Go `bool`: `null` is false and any other type
fails the configuration on every transport. The vendored `quinn-proto` ports
the fork's packet shaping and transport parameter encoding, and a rustls
ClientHello customizer sends uTLS's Chrome QUIC spec. Differences:

- A prebuilt rustls configuration from an embedding application keeps its own
  ClientHello, as under a fingerprint; the packet shaping still applies.
- After the handshake, packet number lengths follow the running congestion
  controller's window, which differs from Xray's where the controller does.
- After a Retry the whole ClientHello is queued again from its start and
  goes out in order. quic-go resends the CRYPTO frames it first wrote, the
  head and the tail of a ClientHello too large for one Initial before its
  middle. Nothing is lost or counted twice either way.
- Not ChromeParrot's own: quic-go shuffles every packet's frames and starts
  its loss timer from a 100 ms RTT estimate (Quinn 333 ms), and
  `disableChromeParrot: true` gives Quinn's handshake rather than quic-go's.

Evidence: `tools/chrome-parrot-oracle` runs Xray-core's own Hysteria dialer
under `testing/cryptotest` and records its first four Initial datagrams and
every `crypto/rand` read; given the same reads the client produces the same
transport parameters and encrypted datagrams byte for byte, and the same
ClientHello but for the key material. `scripts/check-chrome-parrot-interop.sh`
regenerates the fixture each run, rechecks 35 `xray run -test` verdicts, and
runs Hysteria (also under Salamander) and XHTTP H3 live against Xray-core's
servers with ChromeParrot on and off, checking the first flight on the wire;
`scripts/check-xdrive-interop.sh` checks every QUIC connection of a storage
over HTTP/3 the same way, Xray-core's own XDRIVE client first.

## DNS `UseSystem` route probe

`queryStrategy: "UseSystem"` narrows each lookup to the address families the
system has a route for, as Xray-core v26.10.31's `checkSystem` does
([details](config-compatibility.md#dns)). Both probe with a UDP `connect`
toward a root DNS server of each family and keep the result for 100 ms on
mobile and desktop platforms.

Deliberate difference: the probe sockets go through the socket protector.
On Android, Xray-core's probe is not protected, so inside the VPN it reads
the VPN's own routes, which usually include IPv6 even on an IPv4-only
network. Ours reads the network the core dials over, where a missing family
would fail the connection anyway.

Evidence: live against Xray-core v26.10.31 with a recording DNS server and
`freedom` resolving with `UseIP`, five profiles (global `UseIP`, `UseIPv4`,
`UseSystem`, a server's `UseSystem`, and the `use-sys` spelling under a
server's `UseIP`) ask for the same record types in both cores. That holds
on macOS, which routes both families, and in a Linux container without IPv6,
where `UseSystem` asks for `A` alone.

Deliberate difference: when the system routes neither family, a server with
its own `UseSystem` leaves the lookup unanswered. Xray-core returns an empty
response there and keeps no record of it; here an empty answer would be
cached for 30 seconds, past the moment the routes are back.

## DNS hosts `"#N"` RCODE answers

`dns.hosts` reads a `"#N"` value as Xray-core's `app/dns/hosts.go` does: the
name is answered with DNS RCODE `N` and no records, and internal lookups see
it as a failed lookup with no addresses. `"#0"` is an empty answer.

Deliberate differences, source-derived:

- `N` must be 0 through 15. Xray-core accepts any `strconv.Atoi` integer and
  casts it to `uint16`; `golang.org/x/net/dns/dnsmessage` then ORs that value
  into the header flags, so a value above 15 also sets opcode, AA, TC, RD or
  QR bits, and a negative value wraps. Here such a value is a config error.
- One `dns.hosts` entry answers a name: an explicit `full:` key first, then the
  first matching rule. Xray-core checks every matching rule and returns the
  RCODE if any of them is `"#N"`.
- An array value keeps accepting only IP strings. Xray-core would read a
  non-IP first element, including `"#N"`, as the whole value.
- The fixed TUN FakeDNS mode (`dns.fakeIp` without a DNS outbound) does not
  read `dns.hosts`, for IP values as for `"#N"`.

## UDP-hop modes

The `udphop` UDP mask reads Xray-core v26.10.31's `intervalLocal`,
`intervalRemote` and `perConnRemote` modes and its `remoteIPs`
([details](config-compatibility.md#v08-hysteria-carrier-additions)). Deliberate differences:

- A remote hop takes a fresh local socket too. Xray-core keeps its socket when
  only `intervalRemote` is set; the QUIC carrier here is rebound to move the
  connection.
- Every remote hop changes the port. Xray-core draws with replacement, so
  with two ports half of its hops keep the same one.
- `remoteIPs` of the other address family than the server's are never drawn,
  since the QUIC endpoint keeps its socket family; Xray-core dials either.
- A mask after `udphop` is refused when the configuration is read. Xray-core's
  `xray run -test` accepts it, then fails every dial with `incorrect index`,
  because it reverses the list and dials only an outermost `udphop`.

Evidence: live against Xray-core v26.10.31, a Hysteria client of each core went
through two UDP relays in front of an Xray Hysteria server with a 5-second
interval, echoing over SOCKS for 13 seconds. Both cores:
- with `intervalLocal`, took a new socket at the server's own port every 5
  seconds;
- with `perConnRemote`, used one socket at one drawn port;
- with both interval modes, took a new socket at every hop.

With `intervalRemote` alone Xray-core kept one socket and ours took a new one
at each hop. Every echo came back in every mode.

## Socket options

`streamSettings.sockopt` is read and applied as Xray-core v26.10.31 applies it
on Linux, Android and Apple platforms
([details](config-compatibility.md#socket-options)), including the default
TCP keepalive, the order of the options, an option that fails stopping the
rest, and an interface that cannot be bound failing the dial. Deliberate
differences:

- `addressPortStrategy` with a `dialerProxy` chain fails parsing. Xray-core
  hands the address and port it looks up to the `dialerProxy` outbound;
  here a chain hands the proxy the configured server.
- An `addressPortStrategy` SRV name whose first or second part is empty,
  such as `.tcp.example.com`, dials the configured server. Xray-core panics
  on it.
- The `addressPortStrategy` lookup protects its sockets with the platform's
  protector, so inside a mobile VPN it bypasses the tunnel, and applies the
  outbound's `sockopt` to them; Go's resolver in Xray-core sets nothing on
  them. The connection to a `realm` rendezvous takes both as well.
- `interface` is bound before every other option. In Xray-core the binding
  follows `mark` on Linux and the TCP options on Apple platforms, and an
  option that fails stops the rest: with `tcpFastOpen` on an Apple platform,
  where the kernel refuses it on a dialing socket, or a `mark` the process
  may not set, the socket stays unbound and the dial goes on.
- The raw socket of an `xicmp` mask without `dgram` takes the options a UDP
  socket takes. Xray-core's sets none.
- A `dialerProxy` inside an XHTTP `downloadSettings` fails parsing. Xray-core
  would carry the download leg through that outbound. Here the leg either
  takes the outbound's own chain, with `penetrate`, or dials directly.
- WireGuard reads no `streamSettings` field other than `sockopt` and
  `finalmask.udp`, and its other fields, TCP masks and `quicParams` among
  them, fail parsing, as does a `dialerProxy`. Xray-core ignores the
  transport settings and the unused masks, and carries the UDP through the
  `dialerProxy` outbound.
- A WireGuard peer endpoint that is a domain dials the first address its
  `domainStrategy` keeps. Xray-core picks one of them at random.
- An option that fails is logged at debug level; Xray-core logs it at info,
  a level the runtime log here does not have.
- Xray-core's outbound UDP sockets are IPv6 sockets that also carry IPv4, so
  its `customSockopt` entries for `udp4` never apply to them. Here a UDP
  socket has its destination's address family, and such entries apply to the
  IPv4 ones.

## VLESS share-link import

Development ABI 1.17 imports `vless://` links through the shared Rust parser
(format `vless`, `VLESS_PROFILE_IMPORT`, bit 30); see the
[accepted subset](vless-profile-import.md). Xray-core itself reads no share
links. The importer applies Xray-core's configuration semantics: Vision only
on RAW with TLS or REALITY unless VLESS encryption carries it, REALITY only on
RAW, gRPC and XHTTP, and cleartext VLESS only to private destinations.

## Panel subscription fields Xray-core does not read

Remnawave's XRAY_JSON subscriptions (`xray-json.generator.service.ts`) put a
root `remarks` label on every profile, and a `meta` object for some clients.
They write `tlsSettings.enableSessionResumption` into every TLS host, and
sing-box `uot`/`UoTVersion` into every Shadowsocks server. 3x-ui offers the
same Shadowsocks pair. These fields used to fail parsing. Source-derived from
v26.10.31:

- `remarks` and `meta` are absent from Xray-core's root `Config`
  (`infra/conf/xray.go`), which is decoded without `DisallowUnknownFields`
  (`infra/conf/serial/loader.go`). They are now type-checked and ignored.
- `uot` and `UoTVersion` are absent from `ShadowsocksServerTarget` and
  `ShadowsocksClientConfig` (`infra/conf/shadowsocks.go`); Xray-core sends UDP
  as native Shadowsocks datagrams, as this client does. They are ignored, and
  `uot: true` raises a warning. This client is stricter on types:
  `uot` must be a boolean and `UoTVersion` a nonnegative integer.
- `enableSessionResumption` sets `SessionTicketsDisabled` on Go's TLS config
  (`transport/internet/tls/config.go`), but `copyConfig` does not pass the
  session cache to uTLS (`transport/internet/tls/tls.go`), so shaped
  handshakes never resume there. They never resume here either. The known
  difference: with `fingerprint: "unsafe"`, and on XHTTP HTTP/3 and Hysteria,
  rustls keeps its session cache whatever the value, while Xray-core resumes
  only when the value is `true`.

Other panel TLS fields, such as `cipherSuites` and `echConfigList`, are still
rejected.

## REALITY real-certificate crawl

When a REALITY server answers with a real certificate instead of a REALITY
one (an active prober, a MITM or a redirect to the real site), Xray-core's
client does not hang up mid-handshake. It verifies the certificate as
ordinary Web PKI for the server name, finishes TLS, crawls the site over
HTTP/2 like a browser and only then fails the connection
(`transport/internet/reality/reality.go` `UClient` and `VerifyPeerCertificate`,
v26.10.31 lines 101-140 and 207-298). xray-rust does the same:

- a certificate that fails Web PKI verification still aborts the handshake,
  as Go's `x509` check does (against the bundled Web PKI roots the TLS
  transport also uses, where Go reads the system roots); one that passes
  completes it, and the
  connection fails with "processed invalid connection" without carrying any
  user data;
- the crawl requests `spiderX` with Chrome's navigation headers, a `padding`
  cookie per request and the `Referer` chain, learns `href` links without a
  dot, shares them per server name across connections, and spawns `c`
  follow-up crawlers of `t` requests each, `i` milliseconds apart; the error
  is returned after `r` milliseconds.

It is bounded where Go is not: `c` and `t` are capped at 32, the padding at
16 KiB, each delay at 30 s, a scanned response body at 1 MiB, the remembered
paths at 256 per server name, and the crawl's connection, which Go never
closes itself, is closed after 120 s. The process runs at most four crawls at
once, two on a phone (the constrained memory class): a connection answered
with a real certificate while that many are running is closed instead of
crawled, and still fails with the same error after `r` milliseconds. Whoever
stands between the client and its server can answer every dial with the real
site, as can a server the profile no longer matches, so without this each
dial would leave a connection held for those 120 s.

The HTTP/2 client is the `h2` crate set
to Go's transport window and header-list defaults, so its frames are close to,
not byte-identical with, `golang.org/x/net/http2`. As in Xray-core, an empty
`spiderX` is crawled as `/` and any other value without a leading slash is a
configuration error.

## Request header and first payload

VLESS (including Vision) and Trojan outbounds hold the request header until the
first client payload and hand both to the carrier in one write, so TLS and
REALITY seal them into one record. If no payload arrives, the header is sent
alone after Xray-core's wait: 500 ms for VLESS
(`proxy/vless/outbound/outbound.go:311-345`, `ReadMultiBufferTimeout`), 100 ms
for Trojan (`proxy/trojan/client.go:102-123`, `buf.CopyOnceTimeout`). With
Vision, the empty long-padding frame is written only on that timeout, behind
the header, as in Xray-core; the first payload otherwise carries the UUID and
the first padding block. Server-first flows therefore see the same first-byte
delay as with Xray-core.

Differences: the wait is driven from the stream's read side, which the relay
always polls; a client that closes before sending anything still gets the
header and a clean close, where Xray-core drops the request. Trojan holds the
header on every open, including native UDP and Mux parents, as Xray-core does,
and so does VLESS for its UDP and Mux commands. VMess and Shadowsocks still
send the header eagerly.

## Outbound URL probes

Xray-core's observatory probes with Go's `net/http` client: a `GET` of the
probe URL carrying `utils.TryDefaultHeadersWith(req.Header, "nav")`, the same
Chrome navigation persona as its other masqueraded requests, and any response
counts as alive, the status is never read (`app/observatory/observer.go`
lines 177-200; `burstObservatory` does the same in
`app/observatory/burst/ping.go`). xray-rust's observatory now does both: the
request head is Xray's `nav` persona in `net/http` order (`Host`,
`User-Agent`, the sorted map, then the transport's `Accept-Encoding: gzip`),
and a `503` from the probe URL keeps the outbound healthy. The startup probe
and the on-demand `probeOutboundUrl` send the same head, so no probe names the
client, but they are xray-rust APIs with no Go counterpart and keep their
documented 2xx/3xx rule and `HTTP_STATUS` failure.

Differences: probes still speak HTTP/1.1 over a TLS handshake without ALPN,
where Go's transport offers `h2, http/1.1` for an `https` probe URL, and they
stop reading after the status line.

## burstObservatory

xray-rust reads `burstObservatory` as Xray-core v26.11.9 does and feeds the
same statistics to the balancer strategies. From the reference:

- `pingConfig` is required (`infra/conf/observatory.go` lines 29-32). Defaults
  and lower bounds are `NewHealthPing`'s (`app/observatory/burst/healthping.go`
  lines 40-79): destination `https://connectivitycheck.gstatic.com/generate_204`,
  interval `1m` with a nonzero one below `10s` raised to `10s`, sampling 10,
  timeout `5s`, method `HEAD`.
- One ping per subject at start (`healthping.go` lines 99-107), then `sampling`
  pings per subject at uniformly random points of `interval * sampling`
  (lines 95 and 180-186). The next period cancels what is pending (lines
  116-121).
- A failed ping is a failure sample unless the `connectivity` URL, requested
  through no outbound, fails too; then nothing is recorded (lines 190-224 and
  274-286).
- An outbound keeps its latest `sampling` samples, each valid for two periods
  (lines 241-248; `healthping_result.go` lines 81-124). It is alive while
  `All != Fail`, its delay is the average of the successes
  (`burstobserver.go` lines 44-45), and the deviation of a single success is
  half of it. `leastLoad` ranks by that deviation, average, failures and count
  and applies `tolerance` to `Fail / All` (`app/router/strategy_leastload.go`
  lines 168-174 and 185-199); `leastPing` and `maxRTT` compare the average.
- With `observatory` also present both are registered as the observatory
  feature (`infra/conf/xray.go` lines 689-703) and every strategy receives the
  first, `observatory` (`core/xray.go` `getFeature` and `callbackResolution`,
  lines 38-58). xray-rust selects on `observatory` too.

Deliberate differences:

- **Unused burst observatory.** With both present Xray-core still starts the
  burst scheduler, whose results nothing reads (`burstobserver.go` lines
  68-81). xray-rust validates it, warns, and sends no ping.
- **Upper bounds.** Xray-core has none (`healthping.go` lines 66-79).
  xray-rust lowers `interval` above `24h`, `sampling` above 100 and `timeout`
  above `60s` to those values with a warning. They bound an outbound's window
  and the pings scheduled for one period.
- **Method.** Xray-core accepts any string and, when `net/http` refuses it,
  fails every ping (`ping.go` line 61). xray-rust refuses a method that is
  not an HTTP token when it reads the configuration.
- **URLs.** A URL the probe cannot request (another scheme, user info, an IPv6
  literal) fails every ping in Xray-core and is refused by `Core::new` here.
- **Concurrency.** Xray-core fires every timer on its own goroutine
  (`healthping.go` line 186). xray-rust runs at most four pings at once, as
  its `observatory` does; a ping whose turn comes late leaves late, and one
  not sent by the end of the period is dropped.
- **No network.** After a failed connectivity check Xray-core keeps sending
  every scheduled ping, and a connectivity request after each (`healthping.go`
  lines 190-203). xray-rust holds the scheduled pings back and lets one
  through after 5 seconds, then 10, doubling up to `interval`; a ping that
  produces a sample, success or counted failure, resumes the schedule. Nothing
  is recorded meanwhile, as in Xray-core, and samples expire as there.
- **Network change.** Xray-core keeps balancing on samples of the network the
  device left until the random schedule replaces them, up to two periods
  (`healthping.go` lines 241-248). When the host reports a change through
  `rebind_quic`, xray-rust starts a new period, pings every subject 1 to 3
  seconds later, and lets an outbound's first sample on the new network
  replace its window. Old samples drive selection only until then.
- **Expiry.** Xray-core ages samples out when a strategy reads them
  (`healthping_result.go` line 91). xray-rust does at every recorded sample
  of that outbound, at the start of a period and at every failed connectivity
  check, so an outbound that stopped being pinged can stay alive up to one
  period longer.
- **Resolution.** Statistics are kept in milliseconds, as for `observatory`;
  Xray-core compares nanoseconds. A ping stops at the status line, so a `GET`
  does not time the body (`ping.go` lines 72-77).

Not done: re-probing a dead outbound sooner than the schedule, limiting
subjects to the members of a balancer, and counting real dial failures as
samples. Each would change what a window of `sampling` pings means to
`leastLoad`.

## XHTTP HTTP/2 connection preface

Xray's XHTTP client dials HTTP/2 with a bare `golang.org/x/net/http2`
`Transport` (`transport/internet/splithttp/dialer.go`, only `IdleConnTimeout`
and `ReadIdleTimeout` set). With x/net v0.62.0, the version v26.11.9 pins
(its `http2` package is the one v0.61.0 shipped),
its first SETTINGS frame is ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=4 MiB,
MAX_FRAME_SIZE=1 MiB, MAX_HEADER_LIST_SIZE=10 MiB, in that order
(`http2/transport.go` `newClientConn`). xray-rust's XHTTP HTTP/2 client sends
the same four settings in the same order (INITIAL_WINDOW_SIZE follows
`xhttpSettings` when a smaller stream window is configured).

Differences: the connection WINDOW_UPDATE that follows opens 16 MiB of credit
where Go opens 1 GiB, a deliberate memory bound; h2 writes the client preface
in its own write where Go buffers it together with SETTINGS and
WINDOW_UPDATE; and h2 sends that WINDOW_UPDATE once the read side goes idle,
so a server SETTINGS that is already buffered is acknowledged first.

## XHTTP HTTP/3 control stream

quic-go's `http3` client, which Xray's XHTTP H3 dial uses, opens its control
stream with a SETTINGS frame holding only MAX_FIELD_SECTION_SIZE = 10 MiB
(`http3/client.go`, `defaultMaxResponseHeaderBytes`; datagrams and extended
CONNECT are off, so their settings are absent). xray-rust now announces the
same 10 MiB limit, where h3 used to announce 2^62-1, and the vendored h3 no
longer sends ENABLE_CONNECT_PROTOCOL, ENABLE_WEBTRANSPORT, H3_DATAGRAM and
WEBTRANSPORT_MAX_SESSIONS as 0 (`vendor/h3/XRAY-PATCH.md`).

Difference: h3's GREASE is still on, so the frame also carries one reserved
setting, the client opens one GREASE unidirectional stream and writes one
GREASE frame on a request stream, none of which quic-go sends. Turning it off
needs the h3-quinn adapter's `poll_finish` to report a STOP_SENDING that
already arrived (quinn's `finish` maps it to success); today the GREASE write
in h3's `finish` is what surfaces it for unknown-length uploads.

## uTLS per-connection draws

uTLS draws three parts of every hello per connection, and so does
xray-rust, on TLS and REALITY alike (resolved in 0.10.0, against uTLS
20261108164504):

- GREASE values. Each hello reads sixteen bytes of BoringSSL GREASE seeds, as
  uTLS's `ApplyPreset` does, and fills each slot from its own seed: the cipher
  suite, the group (supported_groups and the GREASE key share carry the same
  one), supported_versions, signature_algorithms (Chrome 155) and the two
  GREASE extensions, the second moved off the first's value when they agree.
  Every profile with GREASE draws them, not only Chrome's.
- Extension order. The ten Chrome profiles whose uTLS spec runs
  `ShuffleChromeTLSExtensions`, from `hellochrome_106_shuffle` to
  `hellochrome_155` and so `chrome`, shuffle the spec's own order with Go's
  `math/rand` from a `crypto/rand.Int` seed, skipping every swap that would
  move a GREASE extension, padding or pre_shared_key. Other profiles keep
  their fixed order.
- ECH GREASE payload length. The Chrome profiles carrying ECH GREASE draw
  one of `BoringGREASEECH`'s four payload lengths, 128, 160, 192 or 224
  bytes, which makes the extension 186, 218, 250 or 282 bytes long. Chrome
  120's hello is padded with the shortest and goes unpadded with the others,
  past BoringSSL's padding window, as uTLS sends it.

Until then every profile sent `0x0a0a` in each GREASE slot (`0x1a1a` for the
second GREASE extension), the order of the zero-seed shuffle and, on Chrome,
the shortest ECH length, so several hellos from one client looked alike where
real Chrome and Xray-core vary.
The zero draws remain the reference: each spec order shuffled with seed 0 is
the order of its raw oracle fixture, for all ten profiles, and the byte
comparisons with those fixtures write every GREASE value as `0x0a0a` and,
for the shuffling profiles, compare the extensions in a canonical order
(`crates/xray-transport/tests/support/client_hello_draws.rs`). Unit tests in
`utls_shaping.rs` hold the GREASE seeds to `getBoringGREASEValue` and show
that GREASE, padding and pre_shared_key stay in place while every other
extension reaches every other place; `utls_tls_shaping_tests` shows two
hellos in a row differ in exactly these draws and that each GREASE slot is
drawn on its own.

The ECH GREASE length is the one draw a byte comparison keeps: each length
has a raw fixture of its own (`clienthello_shape.go -ech-payload-length`),
and a hello is held to the fixture of the length it drew; see
[ECH GREASE](config-compatibility.md#ech-grease).
`scripts/check-xray-default-fingerprint.py` holds the pinned Xray-core
binary's own hellos for `""`, `chrome`, `hellochrome_155` and `hellochrome_133`
to the fixtures with the per-connection draws set aside, any of the four ECH
lengths accepted.

## QUIC carriers and a change of network

When the host reports that the OS network changed, XHTTP, MASQUE and
XDRIVE's storages over HTTP/3 take a fresh protected socket towards the same
peer and keep their streams and tunnels; QUIC validates the new path. This
is a deliberate addition: Xray-core keeps the socket whose network is gone,
and the connection sits out its idle timeout before the next flow dials
again. Hysteria and WireGuard moved already, each through its own call; the
others follow the request `xray_core_rebind_hysteria` carries, which the
mobile wrappers make on every network change ([details](ffi.md#hysteria-network-changes)).

Not moved: a connection behind a `realm` mask, whose socket was introduced
to the server and would need a new introduction; one behind `xdns` or
`xicmp`, which carry nothing over the UDP socket; and mKCP, whose server
tells sessions apart by the client's address.

Evidence: `xhttp_h3_takes_a_fresh_socket_when_the_network_changes` moves a
live connection to a new local port through a relay that counts its sources,
with the socket protected again and a request before and after. Against
Xray-core's own XHTTP H3 server, `xhttp_h3_chrome_parrot_keeps_a_flow_across_network_changes`
(in `scripts/check-chrome-parrot-interop.sh`) keeps one flow alive across two
changes. Each change goes through a fresh socket that the relay hands Xray as
a new path. ChromeParrot is on, so quic-go's server migrates a client whose
connection ID is zero-length. Against Xray-core's own MASQUE server,
`masque::masque_h3_keeps_a_flow_across_network_changes` (in
`scripts/check-masque-interop.sh`) keeps a TCP flow through the tunnel alive
across two changes. Each change moves the socket that carries the tunnel's
QUIC datagrams.

## Linux splice

On Linux, a connection from a SOCKS, HTTP or transparent inbound has its
download moved with `splice(2)` through a pipe once what the outbound has
yet to deliver is a bare TCP socket's bytes: a freedom outbound from its
first byte, and VLESS Vision after its download switches to direct mode.
Xray-core's `proxy.CopyRawConnIfExist` moves the same two cases. Upload is
copied, as in Xray-core; TUN flows, encrypted streams and other platforms
never splice. Differences:

- Idle timers and counters. Xray-core parks its idle timers for 24 hours
  while it splices and adds the transfer to its counters when the copy ends.
  Here every spliced chunk counts as activity and reaches the connection's
  counters at once, so `connIdle`, the half-close timeouts and live traffic
  statistics stay what they are on the copying path.
- The switch. `xray.buf.splice` (or `XRAY_BUF_SPLICE`) is read as Xray-core
  reads it: unset, `auto` and `enable` splice, any other value copies. It is
  read once per process. Xray-core applies it to freedom alone and splices
  Vision's direct download whatever it says; here it turns both off.
- Pipes. A pipe is asked to grow to 1 MiB, Go's `maxSpliceSize`. Without
  `CAP_SYS_RESOURCE` the kernel grows about 62 such pipes per user
  (`fs.pipe-user-pages-soft`), then refuses growth and later hands out
  two-page pipes. A connection whose pipe holds less than 64 KiB copies
  instead, as does one whose `splice` the kernel refuses (`EINVAL`,
  `ENOSYS`, `EPERM`, `EOPNOTSUPP`).

Measured on a loopback in Docker (aarch64, medians of five runs) against
Xray-core v26.11.9: a saturated single download ran 1.9 to 2.4 times faster
than copying, with 50 to 66% less client CPU per byte, about level with
Xray-core. Known limits: at a paced 10 Gbit/s splicing costs the whole
machine more than copying (as it does for Xray-core); a real network
interface, x86-64 and a freedom outbound with `fragment` were not measured.

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
- [x] Decide whether Chrome-family hellos should draw their GREASE values and
  extension order per connection, as uTLS does: they do, as the owner chose
  for 0.10.0, against uTLS 20261108164504 (Xray-core v26.11.9); see
  [uTLS per-connection draws](#utls-per-connection-draws).

When an item is resolved, update its status, the tested xray-rust and upstream
revisions, and links to durable tests/results in the same PR. Update
[config-compatibility.md](config-compatibility.md) and the generated parser
contract whenever supported fields change. A green workflow alone does not
close an untested compatibility item.
