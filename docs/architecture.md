# Architecture

The workspace separates configuration, protocol encoding, transport, runtime,
platform ABI, and host adapters. The split keeps mobile code thin and lets most
behavior run in hermetic Rust integration tests.

```mermaid
flowchart LR
    Host["CLI / Swift / Kotlin"] --> Config["xray-config"]
    Host --> FFI["xray-ffi"]
    FFI --> Core["xray-core-rs"]
    Config --> Core
    Proxy["SOCKS5 / HTTP CONNECT"] --> Core
    Tun["TUN packet API or fd"] --> Core
    Core --> Routing["xray-routing"]
    Core --> ProxyWire["xray-proxy"]
    Core --> Transport["xray-transport"]
    Transport --> Network["TCP / TLS / REALITY"]
```

## Workspace crates

| Crate | Responsibility |
| --- | --- |
| `xray-config` | Parses the supported Xray JSON subset, diagnostics, geodata lookup, and resource budgets |
| `xray-routing` | Platform-neutral target/session types and router contracts |
| `xray-proxy` | SOCKS/HTTP parsing plus VLESS, Vision, UDP, and XUDP wire framing |
| `xray-utls` | Supported REALITY fingerprint names and normalization |
| `xray-transport` | DNS, socket protection, TCP, TLS, REALITY handshake, and shaped ClientHello support |
| `xray-tun` | Bounded packet queues, counters, and diagnostic events |
| `xray-runtime` | Cooperative shutdown primitive |
| `xray-core-rs` | Lifecycle, listeners, routing, outbound selection, policy, TUN TCP/UDP/ICMP runtime |
| `xray-ffi` | Stable C ABI and embedded Tokio runtime |
| `xray-cli` | `xray-rust run -config …` executable |
| `xray-bench` | Local workload and comparison harness |

## Configuration path

1. JSON is parsed into `CoreConfig`.
2. Unsupported modeled fields become path-aware errors; security-sensitive
   compatibility choices such as `allowInsecure` become warnings.
3. `geosite` and `geoip` references are resolved during parsing from configured
   search directories.
4. `Core` builds the DNS resolver, outbound router, TUN queues, and listeners
   from the immutable config.

A core is not hot-reloaded. The FFI intentionally permits one successful config
load per handle; replacing a config requires a new handle.

## Data paths

### Local proxy

SOCKS5 and HTTP listeners parse a target, optionally sniff an initial payload,
select a routing rule, then open either a Freedom stream/socket or a VLESS
stream. The selected VLESS stream may use plain TCP, TLS, or REALITY and may add
Vision framing.

### TCP candidate dialing

Resolved Freedom and VLESS TCP targets retain their ordered socket-address
candidates. An explicitly enabled `streamSettings.sockopt.happyEyeballs` policy
reorders those candidates by stable address-family chunks and races raw TCP
connects with a bounded stagger. IPv4 is preferred by default;
`prioritizeIPv6` reverses that preference, `interleave` controls the family
chunk size, and `interleave: 0` exhausts the preferred family before the
alternate family. A fast TCP failure starts the next candidate immediately.

TLS and REALITY are deliberately outside the race: configuration and SNI are
validated first, raw TCP candidates race, and exactly one cryptographic
handshake runs on the winning stream. The scheduler owns its connect futures
directly rather than spawning detached tasks. Success, fatal socket-protection
failure, caller cancellation, or dropping the dial future therefore cancels
all losing attempts in place.

### TUN

The host either pushes and polls raw IP packets through the C ABI or registers a
platform TUN file descriptor. `xray-core-rs` drives the userspace TCP/UDP path,
applies sniffing and routing, and emits response packets through bounded
`xray-tun` queues. Android uses raw-IP fd framing; Darwin's optional direct path
uses the four-byte utun address-family header.

The packet-pump and fd-backed modes are alternatives for the same `TunEndpoint`.
Android defaults to fd-backed operation. The Apple provider uses a discovered
Darwin utun fd when enabled and available, otherwise it falls back to the
`NEPacketTunnelFlow` packet pump.

### DNS

DNS is split at the wire-transport boundary instead of being owned by TUN.
`xray-transport` builds and validates DNS messages, retains ordered A/AAAA
candidates with authoritative or remaining TTL metadata, handles CNAME
resolution, server failover, UDP truncation with same-server TCP retry, and the
bounded resolver cache. Static `dns.hosts` entries can supply one IP, an alias
domain, or an ordered nonempty IP array; every IP remains a dial candidate.
Unprefixed host keys follow Xray's exact/full semantics, while explicit matcher
prefixes retain their normal meaning.
`xray-core-rs` supplies a routed query transport that opens each DNS exchange
through the normal outbound router. `IPIfNonMatch` tests rules in configuration
order against every resolved candidate. SOCKS, HTTP, TUN, startup probes, and
future server inbounds can therefore share the same DNS semantics without
depending on a packet adapter.

Each runtime keeps destination and bootstrap resolution as separate roles.
Destination resolution answers where application traffic should go and may use
routed `dns.servers`. Bootstrap resolution answers how to reach the outer proxy
or DNS-upstream endpoint needed to open that route and must not call back into
destination DNS. This non-recursive split belongs to the universal core, not to
the mobile adapter: TUN's raw DNS proxy and fake-IP engine are consumers of the
roles, while future server inbounds can reuse destination resolution without
inheriting mobile bootstrap policy.

The generic core and C ABI retain system bootstrap as their default for
desktop, command-line, and future server embeddings. Mobile full-tunnel
adapters resolve and pin all usable bootstrap addresses before installing the
interface, then select the fail-closed static policy so captured system DNS
cannot recurse into the tunnel. Android protects every launched candidate
socket. Apple installs excluded `/32` and `/128` routes only for pinned VLESS
carrier addresses before starting the core. Pinned `dns.servers` addresses are
not globally excluded and therefore retain normal outbound routing. A carrier
answer containing a tunnel-owned interface or DNS-anchor address fails closed,
and the route builder defensively refuses to exclude those addresses. This
platform preflight is deliberately outside the Rust DNS service and does not
change the original domain targets.

## Concurrency and lifecycle

Each FFI handle owns a Tokio runtime. Listener, DNS, outbound, and TUN work runs
as asynchronous tasks with cooperative shutdown. Flow budgets, bounded packet
queues, timeouts, and backpressure bound the TUN path and the SOCKS UDP relay;
inbound TCP concurrency has no application-level cap and is bounded by the
process file-descriptor limit, with accept errors retried under backoff.

Lifecycle/configuration operations are serialized by the host adapters.
Documented data-path calls may run concurrently, but never concurrently with
load/start/stop/set/free operations. See [the C ABI contract](ffi.md).

## Platform boundary

- Apple builds `xray-ffi` as static-library XCFramework slices and exposes
  Swift wrappers plus `NEPacketTunnelProvider` reference code.
- Android builds `libxray_ffi.so`, links a small C++ JNI bridge, and exposes a
  Kotlin wrapper plus `VpnService`.
- Outbound socket protection is injected before config load so Android can call
  `VpnService.protect(fd)` for every launched TCP/UDP candidate before that
  socket enters the VPN route.

The repository distributes source, not a hosted binary SDK. Native artifacts
are generated locally and are deliberately outside the source package.
