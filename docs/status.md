# Project status

`xray-rust` is a mobile/client-first core with a focused compatibility surface
for local proxy and mobile TUN integrations. The architecture is designed for
an embeddable client runtime today and can grow to cover server-side protocols
in future releases.

The implementation has extensive automated tests, including optional local
interoperability tests against a user-supplied Xray-core checkout. It has not
been independently security audited. “Supported” below means implemented in
this repository and covered by tests; it does not imply complete behavioral
parity with every Xray-core release.

## Runtime capabilities

| Capability | Status | Verification boundary |
| --- | --- | --- |
| SOCKS5 no-auth TCP `CONNECT` | Supported | Local echo and routing integration tests |
| SOCKS5 `UDP ASSOCIATE` | Supported | Freedom, VLESS datagram, XUDP, and Vision XUDP tests |
| HTTP `CONNECT` | Supported | Local VLESS and routing integration tests |
| Platform-neutral TUN packet boundary | Supported | TCP, UDP, routing, backpressure, malformed-packet, and ICMP tests |
| Direct fd-backed TUN | Supported | Raw-IP Android and Darwin-utun framing paths; host integration is platform-owned |
| Freedom/direct outbound | Supported | TCP and UDP integration tests |
| VLESS over TCP | Supported | Local fake-server and optional Xray-core interoperability tests; plaintext public servers fail closed while Xray's private/reserved/test IP and private/test/dotless domain set remains available for local fixtures. The guard intentionally covers legacy `vnext`, which the pinned Xray release leaves unguarded. |
| VLESS over WebSocket / HTTPUpgrade | Supported subset | Browser-masqueraded HTTP/1.1 upgrade with early data and keepalive; REALITY and Vision are refused on both, matching Xray; live Xray-core interoperability tests |
| VLESS over gRPC | Supported subset | One pooled HTTP/2 connection per outbound carrying `Hunk` or `MultiHunk` messages, with grpc-go's keepalive gate and dormancy; REALITY is accepted and Vision refused, matching Xray; Go-oracle wire fixtures and live Xray-core interoperability tests |
| VLESS over XHTTP | Supported subset | All three modes over production HTTP/1.1, pooled HTTP/2, and protected HTTP/3 over QUIC v1, including UUID/custom-table `sessionID*` generation, xmux, hermetic wire/lifecycle/pooling coverage, and live Xray-core interoperability for `packet-up`, `stream-up`, and `stream-one` |
| TLS | Supported subset | Certificate-verified local integration tests; the uTLS-shaped ClientHello sent by default is covered by per-fingerprint shape tests. Canonical `allowInsecure: true` fails closed. `pinnedPeerCertSha256` supports Xray's full-DER leaf short-circuit and presented-CA pin; comma-separated `verifyPeerCertByName` supports ORed DNS/IP SAN verification against system roots or the pinned CA without changing SNI. |
| REALITY client | Supported subset | Deterministic primitive tests and optional local Xray-core REALITY+Vision interoperability tests |
| TCP Happy Eyeballs | Supported subset | Opt-in Xray-compatible Freedom/VLESS raw-TCP candidate race; bounded and cancellation-safe, with one TLS/REALITY handshake after connect |
| `xtls-rprx-vision` | Supported subset | TCP and XUDP paths; UDP/443 behavior follows the selected Vision flow |
| Domain/IP/network/port routing | Supported subset | Ordered `field` rules with inbound tags, domain/CIDR/private/geodata matchers, network selectors, and numeric/range port selectors; populated selectors inside one rule are ANDed |
| Outbound selector groups and chaining | Supported subset | Xray `routing.balancers` prefix selectors, random/round-robin/`leastPing`, bounded rolling-window `leastLoad`, fallback tags, `balancerTag` rules, atomic validated host overrides, bounded `observatory` URL probes, typed health snapshots, and health-aware failover over shared handler pools; ABI 1.2 plus Swift/Kotlin expose capability-gated override and versioned selection/health snapshots. Explicit `proxySettings.transportLayer: true` adds validated cycle-free TCP Freedom/VLESS edges; UDP/protocol-layer, REALITY, and XHTTP HTTP/3 chains remain pending. |
| Configured DNS | Supported subset | Static single/ordered-array hosts, global `UseIP`/`UseIPv4`/`UseIPv6`, routed multi-address A/AAAA/CNAME resolution with one per-Core family-aware TTL cache/single-flight shared by TUN/SOCKS/HTTP/probes, ordered upstream failover, valid UDP-truncation/TCP retry, all-IP `IPIfNonMatch`, and a hybrid TUN anchor with managed ordinary A/AAAA Hijack, raw DNSSEC/non-IP forwarding, bounded persistent RFC 7766 connections, query-aware TCP failover, and transparent zone-transfer fallback for IP/domain servers. Xray DNS-outbound Direct/Drop/Return/Hijack with `qType`/`rCode`, component rewrite, own-link recursion escape, TLS/REALITY stream security, and bounded UDP-to-TCP session reuse execute through one core-wide TUN/SOCKS/HTTP runtime. |
| Fake IP | Supported subset | Bounded per-Core IPv4 pool with TTL-leased mappings and UDP/TCP synthesis shared by DNS outbound plus TUN/SOCKS/HTTP reverse routing |
| `geosite.dat` / `geoip.dat` | Supported | Xray-style protobuf data is loaded on demand with size and matcher budgets |
| Startup probe and runtime stats | Supported | Core and FFI integration tests |

## Configuration scope

The parser intentionally accepts only the modeled Xray JSON subset and reports
unsupported fields with JSON paths. The first outbound is the default unless a
routing rule selects another tagged outbound.

See [configuration compatibility](config-compatibility.md) for accepted values.
Notable unsupported areas include:

- VMess, Trojan, Shadowsocks, WireGuard, and server-side VLESS;
- generic HTTP/2, QUIC and KCP transports, and stream transports beyond raw,
  WebSocket, HTTPUpgrade, gRPC and XHTTP;
- mux, reverse proxy, observatory command/API services, regex `leastLoad`
  costs, and outbound chaining outside the documented transport-layer TCP
  subset;
- SOCKS/HTTP authentication and HTTP transparent proxy mode;
- full Xray DNS, policy/statistics, sniffing, and routing semantics.

## Platform status

| Platform | Repository integration | Artifact |
| --- | --- | --- |
| iOS 15+ | Swift Package, SwiftUI sample host, Packet Tunnel provider | Static XCFramework device and universal simulator slices |
| tvOS 17+ | Swift Package, SwiftUI sample host, Packet Tunnel provider | Static XCFramework device and universal simulator slices |
| macOS 13+ | Swift Package, app/menu-bar sample, Packet Tunnel provider | Universal `arm64 + x86_64` static XCFramework slice |
| Android API 24+ | Kotlin wrapper, JNI bridge, `VpnService` adapter | Four-ABI AAR with 16 KiB-aligned native libraries |

These are reference integrations. Production applications must provide their
own signing, entitlements or manifest policy, secure profile UX, VPN consent,
foreground/background behavior, release hardening, and distribution.

The lower-level Apple artifacts have wider deployment floors than the reference
hosts: the Rust XCFramework targets iOS 15, tvOS 14, and macOS 11, while the
Swift Package declares iOS 15, tvOS 17, and macOS 11. On macOS 11 and 12 only
the lower-level adapter/shared products are in scope; the checked-in UI and
Packet Tunnel provider APIs require macOS 13.

## Compatibility evidence

The default test suite is hermetic and does not require a network connection.
Local tests that directly launch a user-supplied Go reference binary remain
ignored by default. Release-candidate tags add a blocking `rc-interop` job that
checks out exact Xray-core `v26.7.28` commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, builds the release xray-rust
binary, and runs the bounded supported-surface matrix. A weekly pinned job runs
the broader ignored matrix and resource checks; a separate warning-only weekly
smoke records the resolved Xray-core `main` revision. Upstream-main evidence
cannot satisfy or fail the pinned RC contract. Live-node tests remain ignored
and require credentials supplied through local environment variables.

The fresh [RC4 benchmark publication](benchmarks/results/2026-08-31-v26.7.28/README.md)
adds 139 five-run release series against the exact pinned Xray-core and stable
sing-box v1.13.20, with fail-closed provenance validation and explicit
comparator omissions. This is process-level loopback evidence, not controlled
RTT/loss or mobile energy evidence.

REALITY ClientHello shaping currently depends on a full, immutable Git revision
of the maintainer's public `shaped-rustls` fork rather than the crates.io
`rustls` release. The revision is pinned in `Cargo.toml`, recorded in
`Cargo.lock`, and constrained by `deny.toml`; consumers should include that fork
in dependency and security reviews.

### XHTTP HTTP/3 phase-one limits

XHTTP over HTTP/1.1 and HTTP/2 is the complete production path for the modeled
client-side surface: `packet-up`, `stream-up`, and `stream-one`, the request
composer and padding/metadata placements, HTTP connection reuse, and Xray's
xmux slot policy are all active. Plain security selects HTTP/1.1; TLS with the
exact configured ALPN list `["http/1.1"]` also selects HTTP/1.1; REALITY and
every TLS ALPN list other than the exact H1/H3 cases select HTTP/2. REALITY is
accepted, but Vision remains refused because XHTTP returns an HTTP wrapper
rather than the security connection Vision needs to splice into.

The production HTTP/3 branch is intentionally narrower. It is selected only by
TLS with the exact configured ALPN list `["h3"]`, opens a protected UDP socket,
races resolved candidates with the normal Happy Eyeballs policy, requires
negotiated ALPN `h3`, and never downgrades to TCP. It uses stock TLS 1.3, as
Xray's QUIC path does, so `tlsSettings.fingerprint` does not shape this
ClientHello. QUIC v1, Xray's default 300-second idle timeout, keepalive,
path-MTU control, stream limits, Reno, and all three XHTTP modes are
implemented.

Three performance details are explicit approximations rather than parity
claims. First, Quinn uses static receive windows (2 MiB per stream and 3 MiB
per connection by default), while quic-go adapts those initial values toward
6 MiB and 15 MiB. Second, Xray's standard BBR selection maps to Quinn BBR with
Xray's initial window, not quic-go's controller. Third, the pool conservatively
allows one active HTTP request per QUIC connection, opening another connection
for concurrent work instead of claiming broader request multiplexing. Explicit
unequal initial/maximum receive windows, QUIC v2, conservative/aggressive BBR
profiles, Brutal/force-Brutal, non-empty UDP hopping, and QUIC debug side
effects fail closed before a socket is opened. The ignored live Xray-core
matrix has passed all three XHTTP modes, establishing functional
interoperability for those cases. RC4 publishes five-run H3 upload, download,
full-duplex, and packet-pressure evidence at one and 32 flows. The 32-flow
upload/full-duplex RSS values are explicitly reported as an optimization
target, and the pinned Xray-core pressure/32 reset/timeout boundary is recorded
as an omission rather than replaced by a reduced-load result. Controlled
RTT/loss and mobile-device measurements remain open, so this is not a broad
performance-parity claim.

### Known gRPC opening-wire divergences from grpc-go

The first request's opening burst has four declared wire-shape differences.
Three are at the HPACK layer, all measured against a live grpc-go v1.81.0
client making the same call, and none of those three is reachable without
forking the `h2` crate:

- **Pseudo-header order.** `h2` writes `:method`, `:scheme`, `:authority`,
  `:path`; grpc-go writes `:method`, `:scheme`, `:path`, `:authority`.
- **`:path` indexing.** grpc-go encodes it as a literal *with* incremental
  indexing, so the value also enters the dynamic table. `h2` hard-codes `:path`
  as a literal *without* indexing, so the table never sees it — which makes the
  two encodings diverge further over the life of a connection rather than
  converge.
- **Huffman coding of `te`.** grpc-go's encoder codes a string only when coding
  shortens it, and the two-byte name `te` is not shortened, so it goes out raw.
  `h2` codes it regardless.

The two HEADERS payloads are the same length — 65 bytes each for the captured
call — and differ in exactly those three places.

The fourth opening-wire difference is not an HPACK question and is not forced
on us; it is chosen:

- **One extra `WINDOW_UPDATE(stream 0)` in the opening burst.** We open the
  connection-level receive window at 16 MiB, so a `WINDOW_UPDATE` with an
  increment of `16 MiB − 65535` follows the SETTINGS frame. A grpc-go client
  under Xray writes no such frame, because Xray never sets
  `InitialConnWindowSize`. The reason we do is that `h2` pins its
  connection-level receive window at 65535 whatever SETTINGS say and releases
  it only from the application's read path, while the pool puts every flow of
  an outbound on one connection: at the default, one flow whose consumer stops
  reading holds the window every other flow on that outbound needs, and the
  outbound's whole downlink is capped at 65535 bytes per round trip. Both
  relays in this repository stop reading under backpressure, so that is an
  ordinary state rather than a pathological one. grpc-go avoids it by
  returning the connection window as frames are parsed
  (`internal/transport/http2_client.go:1183-1203`).

  It is worth being clear about what the alternative was. Under Xray's default
  `grpcSettings`, grpc-go's BDP estimator is live and grows *both* windows
  mid-connection up to the same 16 MiB, so a connection window that never moves
  is also a divergence — a later and quieter one. The choice is an earlier,
  smaller, constant divergence over a starvation bug and a throughput ceiling,
  not a divergence over none.

The parity bar is set to what can actually be held. The connection preface and
the client's own SETTINGS frame are compared byte for byte; the burst around
them is compared against grpc-go's plus that one declared frame, so a second
divergence — or a change to this one's stream, length or increment — still
fails. The `Hunk` and `MultiHunk` message framing is compared byte for byte.
The first HEADERS block is compared by its decoded fields and their order, not
by its bytes, with each client's pseudo-header order pinned separately so ours
cannot drift into a third order that neither client emits. **Nothing past the
first request on a connection carries a parity claim**: by the second stream
most of the block is back-references into a dynamic table the two clients
filled differently, and no fixture covers that.

Use [verification](verification.md) for exact commands and prerequisites.
