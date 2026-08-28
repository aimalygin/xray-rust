# Development roadmap

Status: living document, last reviewed 2026-08-28.

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

The initial `v0.4.1-rc.1` tag exercised the release gates; its supply-chain job
correctly rejected an undeclared fuzz-package license and the missing NCSA
allowlist entry. The corrected delivery target is `v0.4.1-rc.2`, followed by
later `-rc.N` tags when another fix requires a candidate. Both repositories use
the same pre-release version whenever the core or its adapters change.

### Current execution status (2026-08-28)

Implemented in the `v0.4.1-rc.2` candidate source:

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
  the audited Xray-core commit and covers every supported stream family plus
  VLESS UDP/XUDP and the DNS-outbound runtime; fuzzing starts with config JSON,
  DNS wire, Vision/UDP/XUDP, and the FFI lifecycle.

Release procedure for `v0.4.1-rc.2`:

- bump the core version and dated changelog, create the reviewed annotated core
  tag, then pin and rebuild the mobile SDK from that exact tag/commit/tree and
  create the matching mobile tag;
- run both tag workflows and verify the GitHub prereleases without invoking a
  remote Maven publication path.

### Compatibility and security

- Complete the DNS outbound migration to canonical `qType`, `Return`, and
  `rCode` behavior. Deprecated input aliases may remain only when they are
  unambiguous and tested.
- Adopt Xray's fail-closed rejection of plaintext VLESS connections to public
  destinations while retaining explicit local, private, reserved, and test
  exemptions. Apply it explicitly to the supported legacy `vnext` shape too;
  Xray v26.7.28 guards only its simplified top-level VLESS settings.
- Reject `allowInsecure: true` for the canonical `v26.7.28` surface. If legacy
  import support remains, isolate it behind an explicit host policy and never
  enable it by default.
- Implement the minimum modern certificate model, including peer certificate
  pinning and name verification behavior required by supported Xray profiles.
- Implement target-compatible custom XHTTP session ID generation for accepted
  `sessionIDTable` and `sessionIDLength` settings.
- Add XHTTP regressions for HTTP/2 GOAWAY replay, concurrent close/write, buffer
  lifetime, and cancellation.

### Verification and release engineering

- Run a small blocking interoperability matrix against the exact pinned
  Xray-core tag for raw TLS, REALITY, Vision, WebSocket, HTTPUpgrade, gRPC,
  XHTTP H1/H2/H3, UDP/XUDP, and DNS outbound behavior.
- Run the broader interop and resource matrix on a schedule. Add a separate
  non-blocking smoke job against Xray-core `main` for early warning.
- Add fuzz targets for configuration JSON, SOCKS/HTTP parsing, DNS wire data,
  VLESS/Vision/XUDP framing, QUIC sniffing, XHTTP framing, and the FFI
  lifecycle. Add sanitizers where the supported CI runners permit them.
- Repin and rebuild the companion mobile SDK from the exact core release
  candidate commit.
- Publish fresh, repeated benchmarks against Xray-core `v26.7.28` and the then
  current stable sing-box release. Record full revisions, build options, raw
  results, RSS, CPU/GiB, latency, loss, TUN behavior, and device energy where
  available. Historical benchmark charts must remain labelled with their
  original versions.

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

### DNS

- Add managed DoH and DoT, followed by DoQ where the existing QUIC stack can be
  reused without increasing lifecycle risk.
- Add negative caching and bounded stale-while-revalidate behavior.
- Provide an injectable platform system resolver and explicit bootstrap route
  behavior.
- Preserve bounded query concurrency, cancellation, cache ownership, and
  recursion protection across TUN, SOCKS, HTTP, and probes.

### Outbound selection and routing

- Introduce an explicit outbound graph/factory seam before adding protocol
  breadth.
- Add selector groups, URL tests, health state, deterministic failover, and
  bounded load balancing.
- Add outbound chaining only through validated, cycle-free graph edges.
- Expose atomic group selection and health snapshots through the C ABI without
  requiring full core teardown.
- Add a small mutable overlay for group selection, counters, and atomically
  replaced rule/geodata snapshots. Full configuration replacement may continue
  to use a new core handle.

### Mobile SDK and management API

- Add ABI minor-version and capability discovery before extending more FFI
  structures.
- Expose typed connection inventory, connection close, per-outbound accounting,
  health, and structured diagnostic events. Do not add an in-core HTTP server.
- Bring Android profile import, statistics, and event coverage to parity with
  the supported Apple surface where platform APIs permit it.
- Add physical-device transition and soak coverage: Wi-Fi/cellular changes,
  sleep/wake, memory pressure, extension/service restart, DNS64/NAT64,
  cancellation, and long-lived XHTTP H2/H3 sessions.

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
