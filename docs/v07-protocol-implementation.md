# v0.7 Hysteria 2 and WireGuard implementation

Started on 2026-09-08. The owner selected both client protocols for v0.7 and
explicitly retained Xray-core **v26.7.28**, commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. Go remains 1.26.5 in the oracle
workflow. The v26.9.8 migration is deferred. Hysteria 2 and WireGuard now have
bounded JSON/core runtime outbounds. Swift/Kotlin import and protocol capability
discovery are available through ABI 1.5; release acceptance remains pending.

## First implemented increment

### Hysteria 2

`xray-proxy::hysteria` now implements:

- TCP request and response encoding/decoding. Request bytes include the QUIC
  stream type `0x401`; the pinned Xray transport writes it separately from the
  proxy codec. Decoders return the consumed offset without consuming application
  bytes. All legal QUIC varint widths, including non-minimal encodings, work.
- Complete UDP message encoding/decoding including the actual session ID.
  Xray's serializer leaves the first four bytes to its UDP transport, which
  must not be mistaken for a protocol requirement to emit zeros.
- Zero-copy outgoing fragmentation with explicit datagram-size checks and a
  checked 255-fragment ceiling. The caller assigns packet IDs and serializes
  each borrowed fragment into a QUIC datagram.
- Reassembly tied to one session on one authenticated connection. It accepts
  out-of-order/identical duplicate fragments, discards an incomplete packet
  when a different packet ID arrives, and checks address, count and duplicate
  payload consistency. A completed packet immediately releases partial state.

Bounds: 2,048 address bytes, 2,048 response-message bytes and 4,096 padding
bytes match the pinned proxy codec. UDP payload/reassembly is capped at 65,535
bytes, before any smaller limit imposed by the IP adapter. One partial packet
retains at most 255 fragment slots plus one address and the configured payload
budget. Assembly temporarily needs an additional complete payload allocation.
The caller supplies a positive expiry duration and calls `expire` from a timer;
the deadline starts with the first fragment and duplicates cannot prolong it.
The future connection manager must bound the number of live sessions globally.

Intentional validation differences from the pinned Go implementation:

- Fragment count zero and out-of-range fragmented indices fail immediately.
  The fragment ID remains irrelevant for an unfragmented message, per the
  protocol. Conflicting addresses/counts/duplicate data clear partial state.
- Address bytes must be UTF-8; host:port validation belongs to the runtime.
- Oversized UDP payloads and more than 255 fragments return errors rather than
  relying on integer truncation. Empty UDP payloads are rejected because the
  pinned Xray parser requires at least one payload byte.
- Response messages stay opaque bytes and are omitted from Debug. Only status
  zero is successful; arbitrary nonzero statuses retain Xray's failure behavior.

The [Hysteria protocol specification](https://v2.hysteria.network/docs/developers/Protocol/)
is supplementary. The exact oracle, rather than today's expanded specification,
defines this increment's version identity. HTTP/3 authentication, QUIC sockets,
congestion control, Salamander and hopping are not implemented by this codec.

### WireGuard

`xray-proxy::wireguard` now implements:

- Fixed-size decoded key material accepting 64-character hex, standard base64
  and URL-safe base64, with optional single `=` padding. Errors omit input;
  Debug is redacted; decoded storage is zeroized on drop. Unlike Xray's config
  helper, parsing checks the decoded 32-byte length immediately. Public-point
  and key-role checks still belong to the eventual crypto engine.
- A validated, normalized `AllowedIp` prefix preserving IPv4/IPv6 identity,
  including IPv4-mapped IPv6. The existing general-purpose routing `Cidr`
  unmaps these addresses and cannot be reused for cryptokey routing.
- Immutable longest-prefix peer selection. Identical normalized prefixes use
  the last inserted peer, matching the exact wireguard-go dependency. Source
  validation uses the same lookup, so a less-specific peer cannot impersonate
  the source space assigned to a more-specific peer.

Initial construction budgets are 128 peers and 4,096 input allowed-IP entries.
The compact sorted lookup has bounded linear work; benchmark it with realistic
peer sets before connecting it to the per-packet runtime. No-route means denial.
The caller must provide an authenticated engine peer identity for source checks;
an endpoint IP or the claimed source in a packet is insufficient.

This is not an implementation of WireGuard cryptography, handshakes, rekeying,
or a TUN device. Existing workspace `base64` and `zeroize` dependencies are reused;
no new crypto-engine dependency or version is introduced.

## Executable evidence

The generator in `tools/v07-protocol-oracle/main.go` imports the pinned Xray
TCP/UDP codecs, key parser and its actual wireguard-go `AllowedIPs` table.
Deterministic generated fixtures cover both IP families, IPv4-mapped IPv6,
overlapping/identical prefixes, TCP framing and UDP fragmentation. All test
keys are synthetic public vectors generated from bytes `0xe0` through `0xff`.

`scripts/check-v07-protocol-oracle.sh` verifies the exact clean checkout using
the existing oracle guard, regenerates and byte-compares the fixtures, then
runs the Rust differential tests. The existing CI Go-oracles job runs it
without changing the reference revision or Go version.

The new `v07_protocols` fuzz target covers raw wire/key/prefix parsing, sequences
of UDP fragments, bounded round trips and routing/source checks. Deterministic
seeds are committed; the existing bounded fuzz campaign runs the new target.
Negative tests cover truncation, oversized varints, cross-session fragments,
conflicting duplicates, expiry, memory budgets, malformed keys and redaction.

Reproduce from the repository root:

```sh
cargo test --locked -p xray-proxy
cargo clippy --locked -p xray-proxy --all-targets -- -D warnings -W clippy::perf -W clippy::suspicious
XRAY_CORE_CHECKOUT=/path/to/pinned/Xray-core bash scripts/check-v07-protocol-oracle.sh
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=none cargo +nightly-2026-05-22 fuzz run v07_protocols fuzz/corpus/v07_protocols -- -max_total_time=30 -max_len=65536 -timeout=10
```

These are codec and policy comparisons. Live protocol connections and device
acceptance remain separate evidence requirements.

Observed locally on macOS arm64, 2026-09-08: all 90 `xray-proxy` tests passed
(18 new); the regenerated pinned Go fixture matched; proxy Clippy, formatting,
the fixture-safety check and the hardening-script guard passed. The new ASan
fuzz target completed 1,230,557 executions in 31 seconds with no crash. This is
a bounded smoke run, not comprehensive fuzz coverage or a memory benchmark.

## Remaining implementation boundaries

1. Native Hysteria v2.12.2 is now pinned for independent transport/core checks;
   see [coverage and reference limitations](v07-native-hysteria-interop.md).
   Physical-device memory, network transitions and throughput remain pending.
2. Direct official wireguard-go now covers live TCP/UDP, wrong keys/PSK, peer
   routing/isolation and core/TUN/DNS paths independently of Xray integration;
   see [reference provenance and coverage](v07-native-wireguard-interop.md).
   Protected UDP/IP, smoltcp TCP/UDP and cancellation are integrated; see the
   [runtime contract](v07-wireguard-runtime.md). Process/device memory still needs
   measurement.
3. Preserve separate WireGuard bootstrap and routed destination DNS. The runtime
   follows v26.7.28; v26.9.8-only `remoteDNS`, ChromeParrot and `dialerProxy` remain
   outside this work.
4. Swift/Kotlin configuration, capability discovery and profile import are
   implemented; application integration and device acceptance remain pending.
5. Direct WireGuard lifecycle checks now exercise authenticated server-port
   changes, replay/bad-tag rejection, persistent keepalive, real-time rekey and
   existing UDP flows across a server restart. Broader interface/NAT transitions,
   cross-family roaming, key-expiry/replay-window boundaries, fragmentation/PMTU,
   TCP crash recovery and physical-device tests remain before mobile artifact
   publication. Host checks for either protocol do not replace device evidence.

Release criteria remain in the [roadmap](roadmap.md#phase-4-v07-hysteria-2-and-wireguard-clients).

## Second implemented increment: live Hysteria transport

`xray-transport::hysteria` exposes a single authenticated QUIC client and TCP/UDP
flow leases. It reuses the existing TLS trust/SNI/verification policy and socket
protector. Authentication is an HTTP/3 POST to `https://hysteria/auth`, with status
233, bounded headers, credential redaction and Go-compatible boolean/rate parsing.
Duplicate/missing/malformed protocol response headers fail closed. Authentication
and each TCP open/UDP send have deadlines; caller cancellation closes pending
connections or resets pending streams. No destination traffic is sent before auth.

The initial accepted transport subset is QUIC v1 with stock TLS 1.3/H3 and Quinn
BBR or Reno, one already-resolved server endpoint, TCP streams and QUIC UDP
datagrams. ALPN must be absent or exactly `h3`; TLS fingerprints are rejected.
Existing H3 diagnostics reject unsupported congestion/hopping settings. Salamander,
Brutal bandwidth mode, hopping, QUIC v2 and Xray's autogrowing receive windows are
not implemented. Defaults use fixed 2 MiB stream/3 MiB connection windows and a
30-second idle timeout; these are an explicit bounded subset, not full Xray
transport-parameter or congestion-algorithm parity. Endpoint bootstrap DNS and
automatic reconnection are provided by the third increment below.

Default budgets per connection: 64 TCP streams, 32 UDP sessions, four queued
packets per UDP session, a shared 1 MiB queued-payload budget, at most one 65,535-byte
partial reassembly per session, five-second fragment expiry, and 256 KiB each for
QUIC receive/send datagrams. Config validation caps these respectively at 256,
128, 16, 4 MiB, 65,535 bytes and 30 seconds. Reassembly metadata and temporary
completed payload allocations are additional bounded storage; these are logical
buffer budgets, not a measured process-memory limit. Excess incoming UDP is
dropped without blocking other sessions. Session IDs are never reused within a
connection; dropping a UDP flow removes its routing/reassembly state.

Clones and open flows retain the connection. Explicit `close()` closes all flows,
aborts workers, removes registry state and releases the client's socket references.
Quinn drains asynchronously; already-returned TCP handles/queued UDP receivers must
also be dropped to release their own retained storage. Dropping the final lease
closes the connection. TCP FIN preserves reads; prefetched response bytes are
returned to the caller. Stream errors omit untrusted server text. UDP receive is
cancel-safe; its idle policy is left to the runtime.

Live testing uncovered two pinned-Xray behaviors and one compatibility issue:

- Hysteria destinations in private address space are blocked by Xray's default
  freedom policy. The synthetic test server explicitly permits loopback.
- Xray writes a successful TCP response before dialing the destination. A refused
  target therefore fails on the data stream, not necessarily during `open_tcp`.
- The pinned quic-go fork may accept a datagram up to the discovered MTU and then
  discard it when packet overhead makes it too large. Advertising Quinn's usual
  65,535-byte limit lost full-size reply fragments locally. Hysteria now advertises
  Xray's 1,200-byte frame limit while retaining its separate 256 KiB receive queue.
  A [minimal patch to unchanged Quinn 0.11.16](../vendor/quinn-proto/XRAY-PATCH.md)
  exposes that separation. XHTTP/H3 and DoQ leave the optional cap unset.

`scripts/check-hysteria-interop.sh` verifies the exact clean Xray checkout, builds
the full reference binary, and runs local TCP/UDP echo tests. It covers 4 KiB
fragmentation in both directions, simultaneous UDP flows, TCP/UDP slot limits,
flow removal, cancelled receives, explicit close, wrong credentials, refused TCP
destinations, fresh reconnect and stream ownership after client drop. Mock QUIC/H3
tests cover auth failure/timeout/cancellation, malformed headers, socket-protection
failure and success, untrusted certificates, TCP rejection/timeout/cancellation,
half-close, prefetched bytes, and eventual socket release while a closed client
handle remains alive. Registry tests cover shared/per-flow queue limits.

Observed locally on macOS arm64, 2026-09-08: the transport test suite and all 32
existing XHTTP/H3 tests passed, including DoQ unit coverage; both full pinned-Xray
Hysteria scenarios passed. Strict transport Clippy passed. The vendored-source
provenance gate verified the complete published Quinn archive and exact patch, and
the new transport-parameter unit test passed. The Go-oracles CI job now includes
the live Hysteria script. This is transport evidence, not runtime/SDK, independent
native-server, throughput, physical-device or release acceptance.

Additional reproduction commands:

```sh
cargo test --locked -p xray-transport
XRAY_CORE_CHECKOUT=/path/to/pinned/Xray-core bash scripts/check-hysteria-interop.sh
bash scripts/check-vendored-sources.sh
```


## Third implemented increment: Hysteria core runtime

The [canonical JSON profile](../tests/fixtures/configs/hysteria2.json) is now
accepted by `xray-config` and the executable config contract/tooling. Both
`settings.version` and `streamSettings.hysteriaSettings.version` must be 2.
The outbound has one `address`/nonzero `port`; authentication lives in the
transport's `auth`. Authentication is bounded to 1..4096 bytes with no control
characters, zeroized in the typed model and omitted from Debug/diagnostics.

The runtime subset requires the Hysteria transport and TLS together. ALPN may
be omitted or exactly `h3`; generic TCP TLS's default Chrome fingerprint is
not inherited. Explicit nonempty fingerprints, insecure TLS, incompatible
security/carriers, outbound chaining, QUIC/socket overrides, hopping, bandwidth
and obfuscation options fail validation. This initial runtime selects the
transport's fixed-window BBR defaults. Reno remains a native-transport option,
not an accepted JSON setting. Typed invalid Hysteria configs also fail core
construction before listeners start. The core/package version remains 0.6.0
until the separate release/versioning work.

`OutboundFactory` retains one lazily authenticated session per configured
Hysteria node, shared by TCP and UDP. Endpoint DNS uses the bootstrap resolver;
destination domains remain encoded for the remote server unless routing or a
selected direct outbound separately requires local resolution. Concurrent opens
coalesce through one admission lock. A ten-second total connection deadline
includes lock contention, DNS and at most eight endpoint candidates, each with
at most three seconds for connection establishment. These shorter candidate
attempts do not shorten the transport's TCP-open/UDP-send deadlines.

New flows reuse a live connection; a stale connection is replaced after fresh
endpoint resolution. There is no replay of application traffic. Cached sessions
are reusable only under the same TLS connector family and socket-protector
identity. A different policy fails closed, including when a caller reuses a
public `TcpOutbound` with a different dialer. Core stop cancels pending auth/DNS,
closes initialized sessions and rejects subsequent session opens.

SOCKS TCP/UDP, HTTP CONNECT, TUN TCP/UDP, routed managed DNS and wire-preserving
TUN DNS now dispatch through Hysteria. UDP adapters retain bounded native
sessions/queues, existing inbound idle timeouts, connection inventory and
accounting, host-close cancellation and TUN telemetry. FakeDNS-visible TUN/UDP
reply identities remain those of the original flow. UDP DNS ignores unmatched
responses; oversized-response handling keeps the existing bounded validation
prefix. Internal DNS sessions are released after each exchange.

Observed on macOS arm64: **675 core tests**, **370 config tests**, strict Clippy
for config/core/transport and the workspace check passed. Four additional live
runtime scenarios against exact Xray v26.7.28 passed: SOCKS/HTTP/4 KiB UDP with
shared QUIC and accounting; concurrent opens with trust/protector isolation;
TUN TCP/UDP and host close; TUN wire DNS plus routed managed destination lookup.
The guarded Hysteria interop script runs these along with the two native
transport scenarios. Deterministic tests cover typed preflight, the total DNS
operation deadline, caller cancellation and closing concurrent pending opens.

This enables raw JSON profiles through the core API. It does not yet update
Swift/Kotlin profile import, publish mobile binaries or complete v0.7 acceptance.

## Fourth implemented increment: WireGuard core runtime

`xray-wireguard` connects the exact patched GotaTun engine to protected UDP and a
bounded smoltcp client interface. JSON and typed configuration now dispatch TCP
and UDP through SOCKS, HTTP CONNECT, TUN and routed DNS, with accounting and host
close. TCP and UDP share one device per configured outbound. See the
[accepted settings, resource budgets and test evidence](v07-wireguard-runtime.md).

The engine reference and Xray-core reference remain unchanged. The current subset
accepts up to eight peers with optional per-peer PSK, longest-prefix routing and
authenticated source isolation. Reserved-byte extensions and custom
stream/chaining settings are rejected. Subsequent increments add mobile SDK
profiles and direct reference coverage; physical-device acceptance remains pending.

## Mobile DNS bootstrap increment

The Swift provider and Kotlin VPN preflight now pin Hysteria server domains and
all WireGuard peer endpoint hosts before installing tunnel DNS. Apple excludes
all outer carrier candidates; Android retains protected sockets. FakeDNS-only
profiles reject default/domain-capable Freedom or WireGuard paths, including
balancer candidates and fallbacks, because those outbounds need real destination
IPs. The [mobile bootstrap contract](v07-mobile-bootstrap.md) records tests,
unchanged lifecycle bounds and remaining SDK/device work.

## Mobile profile import increment

One Rust parser imports the supported Hysteria2 URI and WireGuard `.conf`
subsets into TUN configs. ABI 1.5 validates the generated config and runtime
key/policy constraints without starting a core, and advertises independent
outbound/import capability bits. Swift and Kotlin share the FFI implementation,
preserve Unicode credentials and reject unsupported settings with redacted
errors. WireGuard retains multi-peer/PSK/AllowedIPs policy and requires explicit
real DNS; Hysteria uses remote resolution through bounded FakeIP by default.
See [source syntax, SDK APIs, limits and tests](v07-profile-import.md).

## Independent native Hysteria increment

The official Hysteria v2.12.2 application is now pinned by full commit and built
without source changes. The shared transport/core interoperability suites run
against both it and the unchanged Xray v26.7.28 reference. Native-only tests
cover the UDP-disabled capability and its exact UDP serialization-buffer boundary.
The blocking CI job verifies source cleanliness and runs both references.
See [reproduction, supported scenarios and observed differences](v07-native-hysteria-interop.md).

## Direct official WireGuard increment

A dedicated test executable now uses the unmodified official wireguard-go
0.0.20250522 engine without Xray imports. Exact module versions and checksums,
replacement rejection and module-cache verification guard the reference build.
Shared adapter/core tests run through its in-memory IP interface; raw authenticated
peer tests use a Unix packet bridge to exercise source isolation with the official
engine. Twelve live scenarios cover both IP families, TCP/UDP, wrong keys/PSK,
peer routing/isolation, MTU bounds, recovery and core/TUN/DNS integration.
The existing engine/Xray gate remains mandatory alongside the new CI gate.
See [provenance, reproduction and remaining acceptance work](v07-native-wireguard-interop.md).

## Direct WireGuard lifecycle increment

Implemented 2026-09-13 without changing production protocol code, dependency
pins or accepted configuration. Four additional native-reference tests cover
authenticated server UDP-port changes and replay/bad-tag rejection in both outer
families, existing IPv4/IPv6 UDP flows across a server process restart, one-second
persistent keepalive and a real 120-second rekey. They retain the same client and
protected socket and check flow-slot reclamation on shutdown.

All sixteen direct-reference scenarios passed locally on macOS arm64. Server
recovery took approximately 15.5 seconds in each outer family and timed rekey
completed in 120.4 seconds. The engine/Xray baseline, strict Clippy and workflow
guards also passed. The [native reference contract](v07-native-wireguard-interop.md)
records exact coverage and remaining network/device limits. The existing CI gate
runs the new tests; no remote CI or physical-device result is claimed.

## First bounded iPhone check — 2026-09-13

The [physical iPhone 13 report](device-results/2026-09-13-iphone13-v07/README.md)
records two passing final runs against the unchanged Xray-core reference. Each
run covers three VPN cycles per protocol, IPv4/IPv6 TCP/UDP, DNS, zero active
flows after provider connection closure and successful traffic recovery in the
same tunnel. ABI 1.5 import is exercised separately from the fixture runtime JSON.

The device run exposed an unused GotaTun helper that broke strict iOS compilation
and an Apple IPv6 interface prefix that produced ENETDOWN at `/128`. The helper
now compiles only for its callers; the local virtual interface uses `/120`, with
carrier exclusions still `/128`. Vendor provenance and 147 targeted Swift tests
passed. The saved DEBUG probe and private LAN fixture make the check repeatable.
This is a dirty development build with sparse resource samples, not an RC or
release artifact. Network transitions, sleep/wake, load and Android device
acceptance remain pending.

## iPhone 17 Pro Max transitions — 2026-09-13

The [public-VPS device campaign](device-results/2026-09-13-iphone17-v07/README.md)
passed Hysteria 2 Wi-Fi → cellular → Wi-Fi recovery and Wi-Fi lock/wake for
both protocols. Hysteria needed 34 seconds for cellular recovery, 2.7 seconds
for the return to Wi-Fi and 4.1 seconds after unlocking, measured through the
complete TCP/UDP/DNS sequence. No core restart occurred in those checks.

WireGuard repeatedly failed the 45-second cellular recovery budget. Closing
active connections and opening fresh flows did not restore traffic during a
second 45-second window. Returning to Wi-Fi restored the traffic sequence in
4.3 seconds with the same core identifier. Its independent 90-second lock
check passed. Cellular reported IPv6-only support before the VPN; this does
not establish the root cause, since Hysteria reached the same IPv4 VPS.

The DEBUG harness now distinguishes interface availability from a payload-free
carrier route observation, waits for stable initial Wi-Fi, records lock and
application lifecycle events, and preserves per-stage failures while continuing
independent checks. An explicit diagnostic mode closes connections after a
cellular failure without changing the overall failed verdict. No production
network-change recovery fix was included in that campaign. It identified the
WireGuard cellular blocker addressed by the following increment; its historical
failed verdicts remain unchanged.


## WireGuard carrier rebind — 2026-09-14

The Apple provider now observes network paths for the lifetime of its runtime.
After a coalesced usable-path change it requests fresh protected WireGuard UDP
sockets and a handshake, retaining the inner stack and existing flow objects.
The observer stops before core teardown; a generation check retains notifications
that race lazy client creation. Socket protection or bind failure closes the
client rather than leaving an unprotected fallback.

C/Swift expose this request through additive ABI 1.6. Its count means accepted
requests, not completed recovery. Peer endpoints remain unchanged; this increment
does not add DNS refresh, NAT64 synthesis or Android/JNI path notifications.

The [iPhone 17 Pro Max retest](device-results/2026-09-14-iphone17-wireguard-rebind/README.md)
passed Wi-Fi → cellular → Wi-Fi and lock/wake with one unchanged core identifier.
The whole fresh-flow TCP/UDP/DNS check completed 12.13 seconds after the cellular
path event, 6.25 seconds after return to Wi-Fi and 5.28 seconds after unlock.
The phone was locked for 108.76 seconds. This is bounded development evidence,
with the installed-build identity limitation recorded in the report, not a v0.7
release qualification. Existing-flow continuity is exercised separately by the
independent native rebind test; the device harness opens new application flows.


## Hysteria carrier migration — 2026-09-14

The previous iPhone run spent about 30 seconds in three failed TCP attempts
before the full traffic sequence completed at 34.07 seconds. A cached QUIC
connection remained live until its 30-second idle timeout; the provider did not
notify Hysteria of a changed carrier path. The new bounded host reproduction
blackholes the old client path, gives each new client socket a distinct server-
visible NAT address, and verifies that existing TCP/UDP flows recover after a
protected `Endpoint::rebind`, before the idle timeout.

The Apple runtime now queues Hysteria rebinding alongside WireGuard. It retains
the QUIC connection, authenticated state and flow objects; lazy outbounds remain
lazy and a network generation protects connection-creation races. Rebinding
runs on Tokio even when requested by a Swift/FFI host thread. A replacement bind
or protection failure closes the client. C/Swift expose this as additive ABI
1.7; the endpoint address and DNS pin are retained.

See the [fresh iPhone build and retest](device-results/2026-09-14-iphone17-hysteria-rebind/README.md)
for results, exact binary/source hashes and remaining limits. This increment
adds neither Android path notifications nor endpoint DNS/NAT64 rebootstrap.

### Apple carrier observation follow-up (2026-09-15)

The [UDP return-path investigation](device-results/2026-09-15-iphone17-hysteria-udp/README.md)
adds physical-interface/address deduplication, offline cancellation, and bounded
DEBUG path/UDP diagnostics. It keeps the prior Rust library and ABI 1.7. The
fixture uses a fresh synthetic DNS name to avoid cross-run negative name caching.
Host checks and two complete physical sequences pass. Return to Wi-Fi took
2.79/2.78 seconds without UDP retries; the original intermittent packet-loss
cause is not proven and broader carrier coverage remains pending.

### WireGuard regression on the shared observer (2026-09-15)

The [same-build WireGuard device sequence](device-results/2026-09-15-iphone17-wireguard-observer/README.md)
passes two Wi-Fi/cellular/Wi-Fi, lock/wake and exact-ID connection-closure sequences
after the shared observer change. The first Wi-Fi return required one TCP retry
and 15.68 seconds; the repeat took 16.36 seconds. This retest preserves the
latency concern; no further production change or rebuild was made.
The report retains the source/signed-code identity and bounded acceptance limits.


### WireGuard TCP recovery fix (2026-09-15)

The [recovery investigation and final build](device-results/2026-09-15-iphone17-wireguard-recovery/README.md)
replaces protected carrier sockets without resetting WireGuard sessions or packet
queues, drains at most one previous socket set for three seconds, and fixes a
shared TUN bridge deadlock: a blocked upload no longer prevents download or host
cancellation. Two deterministic bridge reproductions failed before and pass
afterward. Delayed-packet/rebind tests, replay tests, core protocol integration,
172 data-path tests, 73 TUN unit tests and strict Clippy pass.

The final iPhone WireGuard sequence completes cellular/Wi-Fi/unlock traffic checks
in 6.38/4.48/5.51 seconds without retries, preserves one core ID and closes all
seven requested connections in 2.05 seconds. The same build passes three Hysteria
smoke cycles. The report retains intermediate failures, source/signed-code
identity, cleanup and the bounded acceptance limits; ABI stays 1.7.
