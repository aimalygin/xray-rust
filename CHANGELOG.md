# Changelog

All notable changes will be documented in this file.

The project has not made a stable release. Until the first tagged release,
development changes are recorded under `Unreleased`.

## Unreleased

- Added global Xray-compatible `dns.queryStrategy` for `UseIP`, `UseIPv4`, and
  `UseIPv6`, including common Xray aliases. The policy controls configured DNS
  wire queries, destination static host arrays, and destination fallback
  results; wrong-family static mappings remain terminal NODATA. Bootstrap
  resolution keeps all pinned/system candidates for IPv6-only and DNS64/NAT64
  carrier reachability. IPv4-mapped AAAA answers are discarded before server
  failover, while mapped socket candidates otherwise follow their IPv4
  semantics. IPv4 fake-IP returns NODATA without allocating a mapping under
  `UseIPv6`; the byte-transparent raw TUN DNS proxy preserves client qtypes.
  `UseSystem` fails config validation until route capability can be supplied by
  the embedding platform instead of being approximated.
- Added Xray-compatible `streamSettings.sockopt.happyEyeballs` for Freedom and
  VLESS TCP carriers. The modeled defaults are IPv4 preference,
  `interleave: 1`, `tryDelayMs: 0`, and `maxConcurrentTry: 4`; zero delay or
  zero concurrency is the feature-off sentinel, while `interleave: 0`
  exhausts the preferred address family before trying the alternate family.
  When enabled with multiple candidates, the scheduler races raw TCP only,
  accelerates the next candidate after a fast failure, bounds concurrency, and
  performs exactly one TLS or REALITY handshake on the winning socket. Losing
  and caller-cancelled attempts are dropped in place without detached tasks;
  socket protection is applied independently to every launched candidate.
- Added ordered multi-address DNS results with TTL metadata. Configured A and
  AAAA lookups run concurrently, preserve every usable candidate, apply the
  Xray-core 300-second answer/cache cap and 10-second static-host TTL, and
  expose remaining TTL on cache hits. `IPIfNonMatch` now evaluates rules in
  configuration order against all resolved IPs instead of only the first.
  Xray-compatible `dns.hosts` values may now be a single IP/domain string or a
  nonempty ordered array of IP strings; every array candidate is retained. Bare
  host keys now use Xray's exact/full default instead of routing keyword
  semantics, including during Android and Apple bootstrap.
  Authoritative NXDOMAIN/NODATA advances to later configured upstreams before
  becoming terminal, while the bounded cancellation-safe cache remains
  mobile-friendly.
- Added a reusable DNS query-transport boundary: query construction and strict
  A/AAAA/CNAME parsing stay in `xray-transport`, while TUN, SOCKS, HTTP, and
  startup probes can send configured DNS through routed Freedom or VLESS.
  Valid truncated UDP answers retry over TCP, results are bounded/cached with
  cancellation-safe typed single-flight plus one-at-a-time LRU eviction, and
  fake-IP-restored Freedom targets resolve through `dns.servers` even in mobile
  `StaticOnly` mode. Exact `full:` hosts mappings win over broader rules, and
  managed/cache identities are canonicalized across case and a terminal dot.
- Made configured-DNS failure semantics explicit: NXDOMAIN and A+AAAA NODATA
  are terminal, SERVFAIL/invalid/transport failures advance to the next
  upstream, one server shares an A/AAAA timeout budget, and the total lookup
  deadline now includes any operating-system fallback.
- Extended routed DNS to preserve domain upstreams. VLESS sends them for remote
  resolution; Freedom uses the separate bootstrap resolver and fails over when
  `StaticOnly` has no terminal `dns.hosts` IP or IP array. After domain rules
  miss, DNS-upstream `IPIfNonMatch` routing uses only that bootstrap role for
  its IP pass and cannot recurse through destination DNS. Like Xray-core, a failed
  `IPIfNonMatch` lookup continues to the default outbound instead of aborting
  routing, so a default VLESS can still resolve the domain remotely.
- Added fake-IP DNS-over-TCP and Xray-style bounded LRU mappings through
  `dns.fakeIp.poolSize`; reserved `198.18.0.1` for the local DNS anchor and
  `198.18.0.2` for the TUN client address. A pool covering its complete address
  range now reuses the evicted LRU address without scanning the exhausted range.
- Fixed Apple full-tunnel DNS without selecting a public resolver: fake-IP and
  any valid IP/domain `dns.servers` profile advertise the tunnel-local
  `198.18.0.1` interception anchor, while explicit host IPv4/IPv6 DNS overrides
  remain supported. Before applying the anchor, the provider resolves domain
  VLESS servers and domain DNS upstreams, installs every ordered IPv4/IPv6
  bootstrap result as canonical exact `dns.hosts` arrays, preserves VLESS
  addresses exactly, bounds alias traversal, accepts DNS64 results, and fails
  startup on cycles or unresolved bootstrap. The asynchronous preflight has
  one shared five-second deadline, exactly-once lifecycle completion, and a
  process-wide gated resolver worker so a non-interruptible `getaddrinfo`
  cannot block the provider callback or create an unbounded queue. Before the
  core starts, Apple installs an excluded `/32` or `/128` route for every VLESS
  carrier candidate alongside both default tunnel routes. Pinned DNS-upstream
  addresses remain routed through the tunnel instead of gaining a global
  privacy-bypassing exclusion, and tunnel-owned addresses fail closed instead
  of becoming route-poisoning carrier exclusions. IPv4-mapped IPv6 carriers
  are normalized consistently before both Rust dialing and Apple route setup.
  Missing or conflicting host DNS modes still fail closed.
  Fake-IP DNS returns NODATA for supported non-A queries sent to the anchor.
- Made fake-only mobile profiles topology-aware without choosing a public DNS:
  default VLESS plus IP-only Freedom rules remains valid because VLESS resolves
  restored domains remotely, while default or domain-routed Freedom requires
  explicit `dns.servers` and is rejected before the VPN interface is installed.
  The Apple direct reference profile no longer auto-enables fake-IP and instead
  requires a host-selected DNS override.
- Made Android reference VPN startup asynchronous and cancellation-safe. DNS
  bootstrap lookups share one five-second deadline; start and blocking resolver
  workers use bounded zero-queue pools, stop never waits for a pending lookup,
  token-scoped state transitions prevent late publication or rapid-restart
  races, and every ordered A/AAAA bootstrap result is pinned in a `dns.hosts`
  array. Each Happy Eyeballs TCP candidate is protected separately through
  `VpnService.protect(fd)` before connect.
- Added a bounded tunnel-local UDP/TCP DNS proxy for IP/domain `dns.servers`.
  Upstream attempts follow configured order and use the existing outbound
  router (including VLESS and protected Freedom sockets); failures return
  SERVFAIL or reset TCP without silently selecting a public resolver. UDP
  ignores unrelated replies from the selected peer until the attempt deadline;
  raw and fake DNS/TCP share a dedicated flow limit, and raw TCP inactivity is
  bounded by `connIdle` with a five-second ceiling.
- Fixed a Vision direct-mode read switching the whole connection to cleartext:
  the TLS session now survives a direct read so the uplink stays encrypted
  until Vision switches that direction too, matching Xray-core's per-direction
  reader/writer swap.
- Added the first interop coverage that carries a real TLS session through
  REALITY Vision, exercising the direct-mode path that echo workloads skip.
- Hardened FFI, DNS, logging, geodata, and mobile lifecycle boundaries.
- Added bounded routing and TUN data paths.
- Added reproducible mobile artifact and supply-chain checks.
- Added open-source licensing, security, contribution, and release
  documentation.
- Recorded the pre-release live-profile disclosure in `SECURITY.md` and made
  the history secret scan attribute hits to individual commits.
