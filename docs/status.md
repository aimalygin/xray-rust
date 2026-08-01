# Project status

`xray-rust` is an experimental mobile/client-first core, not a complete Rust
port of Xray-core. The current objective is a small, testable surface for local
proxy and mobile TUN integrations. The architecture is intended to grow into
one embeddable client/server library; server-side Xray protocols are not
implemented yet.

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
| VLESS over TCP | Supported | Local fake-server and optional Xray-core interoperability tests |
| TLS | Supported | Certificate-verified local integration tests; `allowInsecure` is accepted with a warning |
| REALITY client | Supported subset | Deterministic primitive tests and optional local Xray-core REALITY+Vision interoperability tests |
| `xtls-rprx-vision` | Supported subset | TCP and XUDP paths; UDP/443 behavior follows the selected Vision flow |
| Domain/IP routing | Supported subset | `field` rules, inbound tags, domain/CIDR/private/geodata matchers |
| Configured DNS | Supported subset | Static hosts, routed multi-address A/AAAA/CNAME resolution with TTL-aware single-flight cache for TUN/SOCKS/HTTP/probes, ordered upstream failover, valid UDP-truncation/TCP retry, all-IP `IPIfNonMatch`, and routed UDP/TCP TUN proxy for IP/domain upstreams |
| Fake IP | Supported subset | Bounded IPv4 pool with UDP/TCP synthesis used by the TUN routing path |
| `geosite.dat` / `geoip.dat` | Supported | Xray-style protobuf data is loaded on demand with size and matcher budgets |
| Startup probe and runtime stats | Supported | Core and FFI integration tests |

## Configuration scope

The parser intentionally accepts only the modeled Xray JSON subset and reports
unsupported fields with JSON paths. The first outbound is the default unless a
routing rule selects another tagged outbound.

See [configuration compatibility](config-compatibility.md) for accepted values.
Notable unsupported areas include:

- VMess, Trojan, Shadowsocks, WireGuard, DNS outbound, and server-side VLESS;
- WebSocket, HTTP/2, gRPC, QUIC, KCP, and other non-TCP stream transports;
- mux, balancers, reverse proxy, observatory/API services, and outbound chaining;
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
REALITY and VLESS interoperability tests that launch the Go reference binary are
ignored by default because the repository does not vendor or pin an Xray-core
checkout. Live-node tests are also ignored and require credentials supplied
through local environment variables.

REALITY ClientHello shaping currently depends on a full, immutable Git revision
of the maintainer's public `shaped-rustls` fork rather than the crates.io
`rustls` release. The revision is pinned in `Cargo.toml`, recorded in
`Cargo.lock`, and constrained by `deny.toml`; consumers should include that fork
in dependency and security reviews.

Use [verification](verification.md) for exact commands and prerequisites.
