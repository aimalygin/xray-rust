# Development roadmap

Status: living document, last reviewed 2026-08-31.

This roadmap describes the intended product direction after `v0.4.0`. It is
not a promise that every item will ship in the named release. Security,
interoperability findings, and measured mobile behavior may reorder work.

The current compatibility baseline is Xray-core `v26.7.28` at full commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. See the
[migration audit](xray-core-v26.7.28-migration-audit.md) for the exact upstream
delta and completed local verification.

## Product direction

`xray-rust` aims to be a compact, fail-closed, Xray-compatible client core for
embedded and mobile applications. Its primary product surface is:

- VLESS with TLS, REALITY, Vision, UDP/XUDP, and XHTTP;
- a bounded TUN data plane suitable for iOS, tvOS, macOS, and Android;
- a stable, typed embedding boundary rather than an in-core web control plane;
- low and predictable memory use with mobile-specific diagnostics;
- explicit compatibility evidence against pinned Xray-core releases.

The project does not aim to match the complete protocol and server feature
count of Xray-core or sing-box. Protocol breadth follows measured client demand
after the supported surface is secure, interoperable, and reliable on devices.

## Decision principles

1. **Compatibility before breadth.** A supported Xray configuration must work
   against the pinned upstream release or fail with a precise error.
2. **Mobile reliability before synthetic feature count.** Network changes,
   sleep/wake, memory pressure, cancellation, and long-lived tunnels are
   release-critical behavior.
3. **Fail closed at security boundaries.** Unsupported security settings must
   not silently downgrade transport or certificate verification.
4. **Measure before claiming parity.** Performance and wire-compatibility
   claims require versioned, reproducible evidence.
5. **Keep the control plane host-owned.** The core should expose typed APIs for
   selection, health, statistics, and connection control without embedding a
   REST dashboard or remote-control service.

## Current baseline

The implemented client surface includes SOCKS5, HTTP CONNECT, packet and
fd-backed TUN operation, Freedom, DNS and VLESS outbounds, raw TCP, WebSocket,
HTTPUpgrade, gRPC, and XHTTP over HTTP/1.1, HTTP/2, and HTTP/3. TLS, REALITY,
Vision, XUDP, routing, Xray geodata, IPv4 Fake IP, Apple artifacts, and an
Android AAR are part of the tested repository surface.

The main release risks are:

- live Xray-core interoperability is optional and does not currently block
  every merge;
- bounded RC fuzz smoke exists, but no long-running fuzz, sanitizer, Miri, or
  concurrency-model gate exists;
- the supported DNS, TLS, and routing subsets trail current Xray-core behavior;
- node selection, health checking, failover, chaining, and hot rule updates are
  not available through the embedding API;
- the pinned `shaped-rustls` fork expands the security and maintenance surface;
- the project has not received an independent security audit.

See [project status](status.md),
[configuration compatibility](config-compatibility.md), and
[verification](verification.md) for the detailed current boundary.

## Phase 1: `v0.4.1` pre-release hardening

Goal: publish aligned Xray-core `v26.7.28` release candidates from `xray-rust`
and `xray-rust-mobile` before adding another proxy protocol or making a stable
public package release.

The release history is intentionally immutable:

- `v0.4.1-rc.1` failed the supply-chain gate on the fuzz package's undeclared
  license/NCSA allowance and was not published;
- `v0.4.1-rc.2` fixed that gate, then failed because clean-runner interop had
  relied on a stale local debug binary, and was not published;
- `v0.4.1-rc.3` fixed the clean-runner contract and was successfully published
  for both the core and mobile repositories;
- `v0.4.1-rc.4` is the final hardening candidate on the `0.4` development
  line. The frozen benchmark candidate is
  `5895b09239ea6d957a3fead814804e361ee6ef6d`. Development proceeds directly to
  `v0.5.0`; a stable `v0.4.1` promotion is not planned unless a distinct
  maintenance need is identified.

Both repositories use the same pre-release version whenever the core or its
adapters change.

### Completed in RC3

- source-only, non-latest GitHub RC publication for `xray-rust`, with an
  idempotent draft/resume/verify path and no registry publication;
- matching mobile RC packaging with XCFramework, standalone AAR, raw
  `LICENSE`, third-party notices, manifest, and checksums; GitHub Packages and
  Maven Central are stable-only paths;
- canonical DNS-outbound `qType`, `Return`, and `rCode` behavior, retaining
  lower-case `qtype` and `Reject` only as warned input aliases;
- fail-closed public plaintext VLESS policy with Xray's exemption set,
  deliberately applied to the supported legacy `vnext` shape that Xray
  v26.7.28 itself leaves unguarded;
- canonical rejection of `allowInsecure: true`, full-DER leaf/CA certificate
  pinning, and independent OR-based DNS/IP `verifyPeerCertByName` verification;
- target-compatible custom XHTTP session IDs, including all nine aliases,
  literal ASCII tables, half-open lengths, UUID fallback, placement keys, and
  conditional path normalization;
- RC-only blocking interop and bounded libFuzzer gates. The interop slice pins
  the audited Xray-core commit, builds and passes an explicit release-profile
  Rust client on clean runners, and covers every supported stream family plus
  VLESS UDP/XUDP and the DNS-outbound runtime; fuzzing starts with config JSON,
  DNS wire, Vision/UDP/XUDP, and the FFI lifecycle.

### Completed in the RC4 candidate

- safe pre-commit H2 GOAWAY retry with non-replay, cancellation, and buffer
  ownership regressions;
- fixes for sustained H2 packet-up flow-control completion and completed H3
  request resets, including local Xray-core interop coverage;
- weekly broad pinned compatibility/resource coverage plus a distinct
  warning-only Xray-core `main` smoke;
- a fresh release-mode publication against exact Xray-core v26.7.28 and stable
  sing-box v1.13.20: 139 validated five-run series, 695 embedded results,
  deterministic raw-archive provenance, and reviewed REALITY, gRPC/32, and
  Xray-core H3 pressure/32 boundaries;
- corrected roadmap, status, verification, configuration, migration, and
  release documentation.

### Deferred beyond RC4

- long-running fuzz campaigns, sanitizers, Miri, and concurrency-model
  exploration beyond the bounded blocking RC smoke;
- controlled RTT/loss and wide-area performance experiments;
- physical-device energy, thermal, memory-pressure, sleep/wake, and network
  transition campaigns;
- an independent security audit and a long-term replacement/upstreaming plan
  for the pinned `shaped-rustls` fork;
- broader parser fuzz targets for SOCKS/HTTP, QUIC sniffing, and XHTTP framing;
- stable-channel registry publication, which remains a separate explicitly
  approved step after RC feedback. Here “stable channel” means a
  non-prerelease tag eligible for registry publication; a version below 1.0 is
  still pre-1.0 in API and security maturity.

### Pre-release packaging policy

- Create matching annotated `v0.4.1-rc.N` tags and GitHub pre-releases in
  `xray-rust` and `xray-rust-mobile`. Do not mark either candidate as the latest
  stable release.
- Add or parameterize a pre-release workflow that stops after verified GitHub
  assets are uploaded. Do not invoke the current stable-publication path for an
  `-rc.N` tag.
- The mobile candidate must pin the exact core tag, commit, tree, lockfile,
  header, and module-map checksums before artifacts are built.
- Attach the checksum-verified Apple XCFramework, standalone Android AAR, raw
  licenses/notices, checksums, and release manifest to the mobile GitHub
  pre-release.
- Build the Android Maven layout locally and use it for the external Gradle
  consumer smoke test, but do not publish the candidate to Maven Central or any
  remote Maven repository.
- Keep Maven Central publication as a separate, explicitly approved stable
  release step after the release-candidate feedback and compatibility gates
  are complete.

### Exit criteria

- The blocking supported-surface interop matrix passes on release CI.
- Known `v26.7.28` security/configuration deltas in the supported surface are
  implemented or documented as deliberate fail-closed boundaries.
- Initial parser, wire, and FFI fuzz targets complete the release campaign with
  no unresolved crash, memory-safety, or unbounded-resource finding.
- Matching GitHub pre-releases exist in both repositories, and the mobile
  candidate artifacts are built from the same pinned core release candidate.
- The standalone AAR passes the locally staged Maven consumer test, and no
  remote Maven coordinate has been published for the candidate.
- Published benchmark results identify current comparator versions and exact
  source provenance.

## Phase 2: `v0.5` reliable multi-node mobile client

Goal: add the client features that improve daily mobile reliability more than
another transport or server protocol would.

The final `v0.5.0` release requires the complete DNS, outbound-selection, and
mobile-SDK scope below. Release candidates begin only after feature freeze;
`v0.5.0-rc.N` is a stabilization channel, not the development channel for
adding unfinished Phase 2 features.

### Carried hardening requirements

- Run extended fuzz campaigns plus sanitizer, Miri, and concurrency-model
  coverage for the parser, wire, TUN, DNS, and FFI lifecycle boundaries.
- Add controlled RTT/loss coverage for the supported stream transports and
  long-lived XHTTP HTTP/2 and HTTP/3 sessions.
- Expand parser/wire fuzzing to SOCKS/HTTP input, QUIC sniffing, and XHTTP
  framing.
- Exercise physical-device energy, thermal, memory-pressure, sleep/wake, and
  Wi-Fi/cellular transition behavior on the supported Apple and Android
  integration paths.
- Audit credential redaction, zeroization, and secret lifetime at config,
  diagnostic, REALITY, and FFI error boundaries. The independent external
  audit and long-term `shaped-rustls` upstreaming/replacement decision remain
  tracked before `1.0` and do not silently become feature-completeness claims
  for `v0.5.0`.

### DNS

- Keep the implemented routed managed DoT/DoH and provider-local DoQ paths
  hardened, including their bounded connection lifecycles.
- Keep the implemented typed negative cache and bounded positive-answer
  stale-while-revalidate behavior hardened.
- Keep the implemented injectable platform resolver and explicit
  `System`/`StaticOnly` bootstrap-route behavior hardened.
- Preserve bounded query concurrency, cancellation, cache ownership, and
  recursion protection across TUN, SOCKS, HTTP, and probes.

### Outbound selection and routing

- Maintain the explicit outbound graph/factory ownership seam added at the
  start of `v0.5` before adding protocol breadth: one immutable graph and one
  shared lazy factory are owned by each core.
- Add selector groups, URL tests, health state, deterministic failover, and
  bounded load balancing.
- Add outbound chaining only through validated, cycle-free graph edges.
- Expose atomic group selection and health snapshots through the C ABI without
  requiring full core teardown.
- Maintain the small mutable overlay for group selection, counters, and
  atomically replaced rule/geodata snapshots. Full configuration replacement
  continues to use a new core handle.

The planned selector, health, chaining, connection-management, and hot-policy
increments are now implemented on the `v0.5` development line. Xray-compatible
prefix selector groups, random/round-robin/
`leastPing`, bounded rolling-window `leastLoad`, fallback tags, atomic validated
overrides, bounded lifecycle-owned URL tests, typed health snapshots, and
deterministic health failover share the graph's existing leaf handler pools.
ABI 1.2 exposes capability-gated atomic override/clear plus versioned,
redacted selection and health snapshots through equivalent Swift and Kotlin
APIs. Xray `proxySettings` with explicit
`transportLayer: true` now creates validated cycle-free TCP graph edges and
layers supported security/stream transports over the nested carrier without
bypassing socket protection. UDP/protocol-layer, REALITY, and XHTTP HTTP/3
chaining remain fail-closed subsets. Connection inventory now also covers TUN
TCP/UDP transport sessions with addressable cancellation and byte accounting.
ABI 1.3 projects its versioned inventory, accounting, and close operations
through equivalent Swift and Kotlin APIs. ABI 1.4 adds scoped routing-policy
replacement: rules, `domainStrategy`, and freshly compiled geodata matchers are
published as one immutable revision for new flows, while the outbound/balancer
graph and existing flows stay intact. Unknown targets and topology changes are
rejected without advancing the revision, and Swift/Kotlin expose the same
replacement plus a redacted versioned snapshot. SOCKS UDP now registers one managed
connection per admitted `(client, target)` flow across Freedom, VLESS/XUDP, and
DNS outbound paths. The existing seven typed TUN diagnostic queues have
equivalent Swift and Kotlin/JNI polling surfaces under the original diagnostic
capability bit. Routed `tls://` managed name servers now use port 853 by
default and layer certificate-verified DNS-over-TLS over the selected
Freedom/VLESS/chained TCP carrier; the TUN raw-DNS proxy applies the same
bootstrap, socket-protection, bounded pooling, and cancellation rules.
Routed `https://` and provider-local `https+local://` managed name servers now
use port 443 by default, preserve path/query, negotiate certificate-verified
HTTP/2, and exchange bounded RFC 8484 POST messages. Both the UDP and TCP sides
of the TUN DNS anchor translate through the same managed operation cap; DoH
currently opens one HTTP/2 connection per exchange rather than retaining a
pool.
Provider-local `quic+local://` name servers now default to port 853, advertise
exact ALPN `doq`, and exchange one RFC 9250 length-prefixed query on one QUIC v1
bidirectional stream. The initial lifecycle remains deliberately bounded to one
protected QUIC connection per query; routed DoQ and connection pooling are not
claimed.
The Core-owned destination cache now retains authoritative NXDOMAIN/NODATA for
30 seconds, never caches transport failures, and can serve expired positive
answers while a single-flight refresh runs in the background. Global
`disableCache`, `serveStale`, and `serveExpiredTTL` are parsed; stale service
requires an explicit 1-through-86400-second window. Xray's unbounded zero value
and per-server overrides remain fail-closed until their lifecycle/resource
ownership can be represented safely.
Managed Rust embeddings can now inject a platform resolver without discarding
`dns.hosts`, configured `dns.servers`, routed query transport, or the shared
destination cache. `System` uses that dependency only as the no-server
destination fallback and the non-recursive upstream/carrier bootstrap;
`StaticOnly` ignores it and remains fail-closed outside pinned hosts. The same
dependency is preserved when `Core::start` rebuilds the routed runtime resolver.
Deterministic fault injection now exercises post-handshake DoT failure, DoH
HTTP failure, invalid DoQ framing, ordered encrypted-server fail-forward,
bootstrap exhaustion without destination-name leakage, failed bounded stale
refresh, and cache-owner cancellation. Direct TCP, DoT, and DoH bootstrap
candidates remain eligible after a connected peer fails its protocol exchange;
detached stale refreshes are cancelled when their owning cache is dropped.
The remaining `v0.5.0` DNS release evidence is part of the physical Apple and
Android transition/soak gate rather than another protocol implementation slice.

### Mobile SDK and management API

- Keep the implemented ABI minor-version/capability discovery, ABI 1.2
  selector/health projection, ABI 1.3 connection-management projection, and
  ABI 1.4 routing-policy replacement backward-compatible while extending the
  FFI.
- Expose typed connection inventory, connection close, per-outbound accounting,
  health, and structured diagnostic events. Do not add an in-core HTTP server.
- Keep Android VLESS share-link import, statistics, and event coverage at
  parity with the supported portable Apple surface where platform APIs permit.
- Add physical-device transition and soak coverage: Wi-Fi/cellular changes,
  sleep/wake, memory pressure, extension/service restart, DNS64/NAT64,
  cancellation, and long-lived XHTTP H2/H3 sessions.

The version/capability foundation and cross-platform selection/health surface
are implemented. A core-owned registry now supplies typed connection
inventory, addressable cancellation, and cumulative per-outbound accounting
for routed SOCKS TCP/UDP, HTTP TCP, and TUN TCP/UDP flows. ABI 1.3 and
equivalent Swift/Kotlin models expose inventory, cumulative per-outbound
accounting, and close. ABI 1.4 and equivalent Swift/Kotlin APIs expose scoped
atomic routing/geodata replacement plus a redacted revision snapshot.
The seven essential TUN diagnostic queues now have equivalent typed Swift and
Kotlin polling APIs. Android also exposes the same fail-closed raw-REALITY and
XHTTP none/TLS/REALITY share-link import subset as Apple, including bounded
XHTTP `extra` decoding and mobile TUN config generation. The repository now
ships separate-UID, test-only Android host and traffic-probe applications with
Keystore-backed no-backup profile persistence, foreground-service lifecycle
controls, strict HTTP/UDP reachability, aggregate bounded load, and host-driven
connection closure. They are release-gate tools, not production profile UI or
distribution policy. A fail-closed physical-device evidence
validator now pins the clean candidate revision, requires separate Apple and
Android six-hour reports, verifies the complete transition scenario matrix,
checks bounded steady-state memory/thread growth, and authenticates sanitized
profiler/log/timeline artifacts. This makes the remaining hardware campaign a
reproducible release gate; it does not count offline devices, simulators, or an
unexecuted template as passing evidence.

A short physical Android 15 XHTTP/H2 REALITY rehearsal now covers strict HTTP
and UDP traffic, airplane-mode recovery, background foreground-service
operation, repeated connect cycles, process termination and encrypted-profile
recovery, critical memory pressure, service-level cancellation before runtime
publication, connection inventory closure, and controlled remote packet loss.
Two identical TCP-240/UDP-480 stress cycles completed without probe failures;
489 connection closes were accepted after each, the inventory returned to the
ordinary-probe baseline, and settled recovery RSS grew by about 1.4 MiB in
`dumpsys` (about 1.9 MiB in the internal sampler) with a stable 19 threads. This
is dirty-revision diagnostic evidence, not the clean six-hour Android report.
Wi-Fi/cellular, sleep/wake, IPv6/Happy-Eyeballs, captive-network, DNS64/NAT64,
long-lived XHTTP/H3, release signing, and the rest of the formal matrix remain
open.

A supplemental physical Android XHTTP/H3 rehearsal now closes the short-form
device transport check. An owner-controlled Xray-core v26.7.28 server listened
only on the already approved UDP port, used `stream-one` with exact TLS ALPN
`h3`, and authenticated a short-lived self-signed leaf through
`pinnedPeerCertSha256` rather than `allowInsecure`. The owner-only Mac oracle
passed before device import. Android then completed 660/660 bounded HTTP
attempts, including a disconnect/reconnect generation change, with zero probe,
fatal-TUN, or unrecovered-transition failures. Comparable 240-request settled
RSS samples differed by about 1.0 MiB with 19 threads. The endpoint and secret
material were removed and the prior H2 plus strict UDP environment passed its
rollback check. This is still dirty-revision diagnostic evidence; long-lived
H3 under controlled loss and the clean six-hour report remain required.

An opt-in owner-controlled remote XHTTP oracle now reuses an owner-only client
JSON outside the repository and proves either a public HTTP target or an
authenticated hold endpoint through the Rust SOCKS-to-XHTTP path before a
device run. A short physical Apple H2/REALITY `stream-one` rehearsal has also
passed HTTPS carriage, TUN accounting, connection closure, and clean tunnel
teardown. Its preceding fail-closed run traced a pre-first-byte reset to a
share link that omitted the server's non-default `xPaddingBytes`; the importer
correctly preserved `extra` once the link supplied it. This is diagnostic
rehearsal evidence from a dirty development revision, not the required clean
six-hour Apple report, and it provides no Android release evidence.

The supplemental physical Apple XHTTP/H2 memory rehearsal now uses two
identical TCP-240/UDP-480 load-and-recovery cycles in one extension runtime.
The original cold-baseline check correctly exposed retained memory but was not
a valid leak oracle: a five-minute idle observation stayed flat at about
32.2 MiB because the warmed H2 carrier and background flows remained live. In
the corrected two-cycle run, physical footprint peaked at 42.1 MiB then
36.7 MiB, and recovered from 31.22 MiB to 31.50 MiB, only about 0.28 MiB of
cycle-over-cycle growth against an 8 MiB allowance. Both cycles reached all
TCP and UDP stages below the 48 MiB protective ceiling; the provider accepted
1,670 closes, stayed at runtime generation one with no fatal TUN telemetry, and
disconnected cleanly. This is still dirty-revision diagnostic evidence on one
iPhone 13, not the clean six-hour Apple report or any Android evidence.

A clean, five-run macOS pre-device performance gate now covers the v0.4.0
shared routing, DNS-selector, process RSS, plain TCP, and inherited-fd TUN
anchors plus the new Phase 2 selector/chaining, cache, inventory/accounting,
close, health/selection snapshot, diagnostic, and TUN-stat paths. The
pre-v0.5 small-matcher regression was traced to applying geosite/geoip indexes
to tiny per-rule sets and corrected with bounded linear/single-range fast
paths. Remaining outbound-graph cost and per-flow management memory have
explicit ceilings; only clean same-revision evidence passes. This host gate is
required before, and does not substitute for, the Apple/Android hardware gate.

### Exit criteria

- A host can switch between healthy nodes atomically without restarting the
  tunnel or losing unrelated flows.
- Encrypted DNS, failover, cache, and bootstrap behavior pass fault-injection
  tests and remain within explicit memory and concurrency budgets.
- Apple and Android expose the same versioned core capabilities, selection
  state, health state, and essential diagnostics.
- An extended device soak shows no unexplained memory growth, task leak, stuck
  TUN pump, or unrecoverable network-transition failure.

## Phase 3: `v0.6` modern VLESS and richer client policy

Goal: follow the modern Xray client surface after the verification and mobile
reliability foundation is in place.

- Implement current client-side VLESS post-quantum encryption only with an
  upstream oracle, deterministic negative tests, fuzz coverage, and a focused
  security review. Do not design an independent wire variant.
- Add `IPOnDemand` and selected low-cost routing inputs that are useful on
  mobile. Platform identity and network-state values must come from an
  explicit host capability provider.
- Complete the supported XHTTP session and download behavior before pursuing
  rarely deployed transport extensions.
- Evaluate adaptive HTTP/3 windows, multiple active requests per connection,
  QUIC v2, and UDP hopping with controlled RTT/loss and device resource tests.
  Only ship behavior that improves measured workloads without violating mobile
  budgets.
- Add IPv6 Fake IP if application and DNS64/NAT64 tests demonstrate a coherent
  end-to-end mapping and restore model.
- Provide JSON Schema or equivalent tooling for the supported Xray JSON subset.
- Split the largest parser, TUN, DNS, outbound, and FFI modules along existing
  ownership boundaries before they acquire additional major features.

### Exit criteria

- New VLESS encryption interoperates with the pinned Xray-core release across
  positive, downgrade, replay, corruption, cancellation, and resource tests.
- New routing and XHTTP options have explicit configuration, wire, and device
  verification boundaries.
- The stable C ABI remains backward compatible or follows a documented major
  version transition.

## Deferred security work before `1.0`

The first `v0.4.1` release candidate does not block on the following broader
reviews. They remain tracked hardening work and must be scheduled before a
stable `1.0` claim:

- audit configuration and diagnostic formatting for credential redaction,
  zeroization, and secret lifetime, including REALITY and FFI log/error
  boundaries;
- define a maintenance and upstream-sync policy for `shaped-rustls` and review
  its exact delta from the pinned rustls release;
- complete an independent security review of the supported wire, TUN, and FFI
  surfaces after fuzz coverage and release behavior have stabilized.

## Protocol expansion after `v0.6`

Protocol work is demand-driven and begins only after the previous release
gates are sustained in CI.

Recommended order:

1. **Trojan client.** It can reuse the existing TLS, stream, DNS, routing, and
   outbound lifecycle while exercising the new outbound factory seam.
2. **Shadowsocks 2022.** Add it as an optional client component if profile
   corpus and integrator demand justify the crypto and compatibility surface.
3. **VMess.** Implement only if real migration data shows material active use.
4. **WireGuard or Hysteria.** Treat either as a separately designed project,
   not a small protocol adapter, because each adds a substantial networking,
   platform, performance, and security surface.

Each protocol requires a pinned reference implementation, fixture corpus,
blocking interop coverage, fuzz targets, resource budgets, mobile lifecycle
tests, and a configuration compatibility section before it is called
supported.

## Explicit non-goals

The following are out of scope unless the project deliberately changes from an
embedded mobile client core into a general proxy gateway or server:

- matching every Xray-core or sing-box inbound and outbound;
- server-side VLESS or Trojan, reverse proxy, and a server ecosystem;
- legacy transports such as mKCP solely for feature-count parity;
- a Clash-compatible dashboard, embedded REST/gRPC daemon, or remote-control
  server;
- Linux gateway features such as nftables auto-redirect, network namespaces,
  and layer-2 bridging;
- a second configuration language or sing-box SRS compatibility;
- dependencies such as an embedded browser engine or CGO components that
  materially compromise memory, reproducibility, or the pure-Rust data plane;
- presenting ClientHello shaping as invisibility rather than measured Xray wire
  compatibility.

## Success metrics

The roadmap is evaluated by outcomes, not only completed features:

| Area | Measure |
| --- | --- |
| Compatibility | Blocking supported-surface interop against the exact stable Xray-core reference; scheduled early warning against upstream `main` |
| Reliability | No unexplained memory/task growth or unrecoverable tunnel failure in transition, fault-injection, and extended device-soak tests |
| Security | Fuzz and dependency gates for parser/wire/FFI surfaces; tracked review of `unsafe`, secrets, and pinned forks; independent audit before a stable 1.0 claim |
| Performance | Reproducible current-version results with raw provenance; no regression outside an explicitly justified budget |
| Mobile SDK | Versioned capability discovery and equivalent essential lifecycle, selection, health, and diagnostic APIs on Apple and Android |
| Configuration UX | Precise JSON-path errors, fail-closed unsupported fields, and machine-readable schema for the supported subset |

## Review cadence

- Audit each stable Xray-core release against the modeled configuration and
  wire surface before changing the pinned oracle.
- Track Xray-core `main` with non-blocking smoke results rather than treating a
  moving branch as a release contract.
- Re-run comparative benchmarks only against named stable releases; pre-release
  results must be labelled separately.
- Review this roadmap at every minor release and whenever interop, security, or
  device evidence invalidates its ordering.
