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

The active oracle pin is `a4a3dff5b20c2faae567b742c172c7b95e75c083`
(v26.10.31), built with Go 1.27.3; see the
[v26.10.31 migration record](xray-core-v26.10.31-migration.md). The
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
`check-http-interop.sh` against the currently pinned Xray-core v26.10.31; HTTPS
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
- VLESS `reverse` fails parsing: the reverse proxy is not implemented.
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
- Only `mkcp-legacy` and `noise` masks apply to mKCP; Salamander, `udphop`
  and TCP masks are refused on it, and `mkcp-legacy` on any other transport.
  Xray-core applies every UDP mask to mKCP's socket, ignores TCP masks on it,
  and ignores UDP masks on TCP transports.
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

The mKCP, Hysteria and XHTTP over HTTP/3 clients support Xray-core
v26.10.31's prefix and standalone UDP custom masks, including captures,
expressions, address metadata on writes, five-second per-peer state and mask
ordering. The parser accepts one custom mask on those carriers; other UDP
carriers, multiple custom masks and a custom mask with `udphop` are
rejected. Under `udphop` Xray-core writes to `0.0.0.0:0` but reads from the
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
waits for the reply for good.

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
  protector, so inside a mobile VPN it bypasses the tunnel; Go's resolver in
  Xray-core sets nothing on them.
- A `dialerProxy` inside an XHTTP `downloadSettings` fails parsing. Xray-core
  would carry the download leg through that outbound. Here the leg either
  takes the outbound's own chain, with `penetrate`, or dials directly.
- WireGuard reads no `streamSettings` field other than `sockopt`, and its
  other fields, `finalmask` among them, fail parsing, as does a
  `dialerProxy`. Xray-core ignores the transport settings, masks the UDP with
  `finalmask`, and carries it through the `dialerProxy` outbound.
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
closes itself, is closed after 120 s. The HTTP/2 client is the `h2` crate set
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
header on every open, including native UDP and Mux parents, as Xray-core does.
VMess, Shadowsocks, and VLESS UDP and Mux parent opens still send the header
eagerly.

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

## XHTTP HTTP/2 connection preface

Xray's XHTTP client dials HTTP/2 with a bare `golang.org/x/net/http2`
`Transport` (`transport/internet/splithttp/dialer.go`, only `IdleConnTimeout`
and `ReadIdleTimeout` set). With x/net v0.61.0, the version v26.10.31 pins,
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
