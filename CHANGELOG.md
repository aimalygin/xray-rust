# Changelog

All notable changes will be documented in this file.

The project has not made a stable release. Until the first tagged release,
development changes are recorded under `Unreleased`.

## Unreleased

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
  `StaticOnly` has no terminal `dns.hosts` IP. After domain rules miss,
  DNS-upstream `IPIfNonMatch` routing uses only that bootstrap role for its IP
  pass and cannot recurse through destination DNS. Like Xray-core, a failed
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
  VLESS servers and domain DNS upstreams, installs canonical exact `dns.hosts`
  bootstrap mappings, preserves VLESS addresses exactly, bounds alias
  traversal, accepts IPv4/IPv6/DNS64 bootstrap results, and fails startup on
  cycles or unresolved bootstrap. The asynchronous preflight has one shared
  five-second deadline, exactly-once lifecycle completion, and a process-wide
  gated resolver worker so a non-interruptible `getaddrinfo` cannot block the
  provider callback or create an unbounded queue. Apple now installs IPv4 and
  IPv6 default routes with a matching `/32` or `/128` proxy-server exclusion.
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
  and token-scoped state transitions prevent late publication or rapid-restart
  races.
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
