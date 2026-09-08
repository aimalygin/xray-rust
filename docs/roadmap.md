# Development roadmap

Status: living document, last reviewed 2026-09-08 (UTC).

`v0.5.0` is the current stable release. Matching core and mobile
`v0.6.0-rc.1` prereleases are published. Phases 1 and 2 below are retained as
release history; Phase 3 is in RC stabilization before a separate stable
release decision. This roadmap is not a
promise that every conditional item will ship in the named release. Security,
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
- release candidates now block on extended ASan fuzz campaigns, sanitizer and
  Miri tests, a Loom routing-publication model, and controlled network tests;
- the supported DNS, TLS, and routing subsets trail current Xray-core behavior;
- physical-device evidence is based on bounded, named Apple and Android
  scenarios rather than a fixed-duration clean soak; each release must state
  the devices, duration, transitions, and resource limits it actually covered;
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

Status: released as stable `v0.5.0` on 2026-09-03.

The release added the DNS, outbound-selection, and mobile-SDK scope below.
The complete automated release matrix passed. The release accepted the
completed bounded physical-device rehearsals instead of the proposed clean
six-hour Apple and Android campaigns. The fixed-duration campaign was dropped
as a release requirement and is not retroactively claimed.

### Carried hardening requirements

- Keep the implemented extended ASan fuzz campaigns, sanitizer/Miri tests, and
  Loom concurrency model blocking for parser, wire, TUN, DNS, FFI, and atomic
  routing-policy publication boundaries.
- Keep the Linux controlled RTT/loss matrix blocking for every supported
  stream transport and long-lived XHTTP HTTP/2 and HTTP/3 sessions.
- Keep the SOCKS/HTTP, QUIC sniffing, XHTTP framing, TUN queue, DNS, VLESS, and
  FFI fuzz targets in the release campaign.
- Exercise physical-device energy, thermal, memory-pressure, sleep/wake, and
  Wi-Fi/cellular transition behavior on the supported Apple and Android
  integration paths.
- Maintain the completed focused credential redaction, zeroization, and secret
  lifetime audit at config, diagnostic, REALITY, and FFI error boundaries.
  The independent external audit and long-term `shaped-rustls`
  upstreaming/replacement decision remain
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
The planned final `v0.5.0` DNS evidence belonged to the physical Apple and
Android transition/soak gate rather than another protocol implementation
slice. The clean six-hour campaigns were not completed before the release and
will not be run as a retrospective or `v0.6` release gate.

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
distribution policy. The repository also contains a fail-closed validator for
the former six-hour campaign. It pins a clean candidate revision, verifies the
transition scenario matrix and bounded memory/thread growth, and authenticates
sanitized profiler/log/timeline artifacts. That harness remains available for
optional long-run diagnostics, but its fixed-duration campaign is not a
`v0.6` release gate.

A short physical Android 15 XHTTP/H2 REALITY rehearsal now covers strict HTTP
and UDP traffic, airplane-mode recovery, background foreground-service
operation, repeated connect cycles, process termination and encrypted-profile
recovery, critical memory pressure, service-level cancellation before runtime
publication, connection inventory closure, and controlled remote packet loss.
Two identical TCP-240/UDP-480 stress cycles completed without probe failures;
489 connection closes were accepted after each, the inventory returned to the
ordinary-probe baseline, and settled recovery RSS grew by about 1.4 MiB in
`dumpsys` (about 1.9 MiB in the internal sampler) with a stable 19 threads. This
is dirty-revision diagnostic evidence, not a clean long-run Android report.
Wi-Fi/cellular, sleep/wake, IPv6/Happy-Eyeballs, captive-network, DNS64/NAT64,
long-lived XHTTP/H3, release signing, and the rest of the formal matrix were
not completed for `v0.5.0`; `v0.6` selects targeted device scenarios according
to its changed high-risk surfaces instead of carrying the full matrix forward.

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
H3 under controlled loss and the clean six-hour report were not completed for
`v0.5.0` and are not fixed-duration gates for `v0.6`.

An opt-in owner-controlled remote XHTTP oracle now reuses an owner-only client
JSON outside the repository and proves either a public HTTP target or an
authenticated hold endpoint through the Rust SOCKS-to-XHTTP path before a
device run. A short physical Apple H2/REALITY `stream-one` rehearsal has also
passed HTTPS carriage, TUN accounting, connection closure, and clean tunnel
teardown. Its preceding fail-closed run traced a pre-first-byte reset to a
share link that omitted the server's non-default `xPaddingBytes`; the importer
correctly preserved `extra` once the link supplied it. This is diagnostic
rehearsal evidence from a dirty development revision, not a clean long-run
Apple report, and it provides no Android release evidence.

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
iPhone 13, not a clean long-run Apple report or any Android evidence.

A clean, five-run macOS pre-device performance gate now covers the v0.4.0
shared routing, DNS-selector, process RSS, plain TCP, and inherited-fd TUN
anchors plus the new Phase 2 selector/chaining, cache, inventory/accounting,
close, health/selection snapshot, diagnostic, and TUN-stat paths. The
pre-v0.5 small-matcher regression was traced to applying geosite/geoip indexes
to tiny per-rule sets and corrected with bounded linear/single-range fast
paths. Remaining outbound-graph cost and per-flow management memory have
explicit ceilings; only clean same-revision evidence passes. This host gate is
required before, and does not substitute for, the Apple/Android hardware gate.

### Release outcome

- Atomic healthy-node switching, encrypted DNS, failover, caching, bootstrap,
  and the versioned Apple/Android management surfaces shipped in `v0.5.0` with
  their automated fault, resource, and interoperability gates passing.
- Short Apple and Android rehearsals covered the accepted release boundary and
  are documented in [mobile testing](mobile-testing.md).
- The proposed clean extended device soak was not executed for `v0.5.0` and is
  not carried forward as a `v0.6` gate. Later releases use bounded physical
  scenarios targeted at the subsystems and lifecycle risks they change.

## Phase 3: `v0.6` modern VLESS and richer client policy

Status: feature freeze completed and matching core/mobile `v0.6.0-rc.1`
prereleases published. The selected scope includes `IPOnDemand`, bounded
VLESS 1-RTT/0-RTT with relay chains and padding, independent XHTTP downloads,
mobile projection, and Milestone E configuration tooling. The exact-candidate
release gates passed; see [published evidence](v06-release-evidence.md#published-v060-rc1).
The [initial review and implementation plan](v06-implementation-plan.md)
retains the baseline decision and delivery history. Stable promotion and
registry publication remain separate from this RC completion.

Goal: add the modern VLESS encryption and client-policy capabilities with the
same fail-closed configuration, pinned interoperability, and bounded mobile
resource contracts established by `v0.5`.

`v0.6` is a compatibility and policy release, not a protocol-expansion
release. Trojan, Shadowsocks, VMess, WireGuard, Hysteria, server features, and
an in-core control plane remain outside this phase.

### Milestone A: freeze the compatibility contract

Initial decision: retain the audited exact `v26.7.28` baseline. The new routing
and encryption oracles use that checkout. The focused
[VLESS encryption design](vless-encryption-design.md) records the implemented subset
and verification boundaries. The [XHTTP download design](xhttp-download-design.md) defines its bounded
independent transport and lifecycle contract.

- Audit the stable Xray-core release selected when `v0.6` development begins
  against the current pinned `v26.7.28` baseline. Either pin the new exact
  commit and regenerate fixtures/oracles or record an explicit decision to
  retain `v26.7.28`; never use moving `main` as the release contract.
- Write and approve focused designs for VLESS non-`none` encryption and the
  supported XHTTP `downloadSettings` lifecycle before implementation. Record
  exact configuration names, wire behavior, secrets, downgrade boundaries,
  allocation limits, and reference-oracle provenance.
- Preserve the `v0.5.0` benchmark and ABI results as named baselines. New
  measurements must come from a clean, exact revision and must not replace a
  missing comparator with an inferred result.

### Milestone B: VLESS post-quantum encryption

Implemented: bounded `mlkem768x25519plus.{native|xorpub|random}.{1rtt|0rtt}`
with one-to-eight mixed X25519/ML-KEM-768 NFS relay keys, bounded configurable
padding, all implemented stream carriers with optional Vision, both AEADs,
TCP/UDP/XUDP integration, redacted
typed configuration, and bounded record/session state. The 0-RTT ticket is
memory-only, publishes after authenticated padding, invalidates on failed or
cancelled resumption, and never triggers automatic early-data replay. See the
[design and evidence boundary](vless-encryption-design.md). Equivalent mobile
share-link projection and shared Rust/Swift/Kotlin validation are implemented,
together with dedicated record/handshake fuzz targets and 540 full-Xray
application flows across 204 profiles, including local REALITY. The exact Go oracle now proves
real cold/resumed paths, mixed chains, custom padding, expiry, cancellation,
and cold recovery. Review also added pre-dial ML-KEM coefficient validation.
The focused independent review, IR-01–IR-13 remediation and
[exact-candidate release evidence](v06-release-evidence.md#published-v060-rc1)
are complete for the published RC's bounded scope. This is not an external
security audit or a stable-release declaration.

- Implement only the client-side VLESS post-quantum encryption modes present in
  the pinned Xray-core contract. Do not invent a Rust-specific wire variant,
  alias, or fallback to `encryption: "none"`.
- Cover positive interoperability plus wrong-key, downgrade, replay,
  corruption, truncation, cancellation, and bounded-resource cases with a Go
  oracle, deterministic fixtures, fuzzing, and a focused security review.
- Keep keys and derived secrets out of configuration warnings, debug output,
  FFI errors, snapshots, and mobile logs; zeroize bounded derived material when
  ownership ends.
- Add equivalent Swift and Kotlin share-link/config projection only for the
  combinations the Rust runtime actually supports. Unsupported combinations
  continue to fail at configuration time with a JSON path or typed import
  error.

### Milestone C: routing and host policy

First increment implemented: canonical `IPOnDemand`, ordered lazy resolution,
a 256-address fail-closed work cap, managed cache/cancellation and policy
revision tests, a pinned Go oracle, and equivalent Swift/Kotlin snapshot
decoding. The targeted physical-device scenarios passed for the published
RC. A new host capability provider was not selected for this release; process,
user, interface and network-state routing inputs remain deferred.

- Preserve Xray-compatible `IPOnDemand`: delay resolution until an IP rule
  needs it, evaluate every bounded returned address, preserve ordered rule
  matching, and keep the original destination for the selected outbound. Match
  the pinned predicate order: inbound/network/port before IP, domain after IP.
- Use the existing managed resolver/cache and recursion protections. DNS
  failure, cancellation, stale data, policy hot replacement, and concurrent
  flow behavior require deterministic tests.
- Select only low-cost routing inputs with demonstrated mobile demand.
  Process, user, interface, and network-state facts must enter through an
  explicit versioned host capability provider; unavailable facts must not be
  guessed from global process state.
- Preserve atomic routing-policy publication: new flows see one complete
  revision, existing flows retain their decision, and invalid updates do not
  advance the revision.

### Milestone D: XHTTP completeness before transport breadth

Published in `v0.6.0-rc.1`: one independently addressed XHTTP download
stack for packet-up/stream-up, with independent security/HTTP version, resolver
and protected dialing, XMUX pooling, shared-session failure/cancellation and
upload rollover. Config parsing and carrier compilation live in dedicated
modules. The supported subset and pinned verification command are described in
[the download design](xhttp-download-design.md). Exact-candidate device and
performance gates passed within the [published limits](v06-release-evidence.md#published-v060-rc1).
Adaptive H3 windows and multiple active H3 requests stay deferred until the
stated measurements justify them.

- Implement a documented, bounded client subset of populated
  `downloadSettings` with an independently validated transport configuration
  and lifecycle. Reject recursive, cyclic, security-weakening, or unbounded
  combinations before opening a socket.
- Complete session creation, server-first download, cancellation, rollover,
  pooling, accounting, and teardown tests across every supported XHTTP mode and
  HTTP version. Maintain the pinned live Xray-core matrix for each claimed
  combination.
- Measure adaptive HTTP/3 receive windows and more than one active request per
  connection under loopback impairment, wide-area tests, and physical-device
  memory/energy budgets. Ship either only when it improves the named workloads
  without exceeding the budgets.
- QUIC v2, non-empty UDP hopping, additional congestion-control profiles, and
  other phase-one H3 exclusions are conditional experiments, not `v0.6`
  release requirements. Unshipped values remain fail closed.

### Milestone E: configuration tooling and maintainability

Completed and published in `v0.6.0-rc.1`: the generated
[executable configuration contract](config-contract.json) and
[CLI/Rust tooling](config-tooling.md) share the parser's object-field registry
and exact acceptance rules. CI checks canonical/rejected fixtures, unknown-field
mutations at every registered grammar node, VLESS/XHTTP oracle inputs and CLI
reports/resource lookup. DNS and stream/security parsing are now separate modules
alongside routing, VLESS and XHTTP. The C ABI is unchanged. The ongoing pre-feature
refactor obligation for other large runtime modules remains in force.

- Publish machine-readable JSON Schema, or equivalent generated tooling, for
  the exact supported Xray JSON subset. Parser acceptance/rejection fixtures
  must check that the tooling neither advertises unsupported behavior nor
  rejects a supported canonical configuration.
- Split the largest parser, TUN, DNS, outbound, and FFI modules along their
  existing ownership boundaries. Refactors must be behavior-preserving and
  land before the affected subsystem receives another major feature. Routing
  parsing and rule evaluation are the first extracted modules; other splits
  follow the feature that needs them instead of blocking unrelated work.
- Keep the C ABI backward compatible through minor-version and capability
  discovery. Any unavoidable major transition requires a migration document
  and parallel Swift/Kotlin updates before an RC.

### Conditional IPv6 Fake IP increment

IPv6 Fake IP is deferred beyond the frozen `v0.6.0-rc.1` scope. A future
increment requires an approved mapping/lease/restore design and end-to-end
Apple and Android coverage for IPv6-only, dual-stack, DNS64/NAT64, network
transition, restart, and pool exhaustion. IPv4 Fake IP behavior must not
regress.

### Release gates

- Run bounded physical Apple and Android scenarios for the high-risk behavior
  changed by `v0.6`: VLESS encryption, resolver-driven `IPOnDemand`, XHTTP
  download/session lifecycle, cancellation, and host adapter projection. There
  is no fixed six-hour minimum. Each report identifies the exact candidate,
  device and OS, scenario duration, transitions, traffic result, and explicit
  resource limits; simulator results cannot replace claimed device evidence.
  The candidate-bound archive format and submission procedure are documented
  in `docs/v06-release-evidence.md`; the RC publication workflow revalidates
  that archive against the exact tagged commit and tree.
- Keep the pinned interop, ASan/Miri/Loom, fuzz, controlled RTT/loss,
  supply-chain, Apple build, four-ABI Android, and clean performance gates
  blocking. Extend them for every new parser, wire, crypto, routing, and XHTTP
  boundary introduced in this phase.
- Publish an RC only after feature freeze. RC builds are for stabilization and
  evidence collection, not unfinished feature development.

### Exit criteria

- The selected Xray-core baseline, full commit, audit delta, regenerated
  fixtures, and blocking supported-surface interop results are published.
- VLESS non-`none` encryption interoperates with that baseline and passes the
  negative, fuzz, secret-lifetime, cancellation, and resource gates above.
- `IPOnDemand` and each added host-policy input have exact configuration,
  resolution, hot-reload, and mobile lifecycle evidence.
- The claimed XHTTP `downloadSettings` and session surface has explicit config,
  wire, pool, cancellation, teardown, and device boundaries; every other value
  still fails closed.
- Configuration tooling matches the supported parser surface, and the touched
  large modules no longer accumulate the new feature behind unrelated
  ownership boundaries.
- Targeted physical-device evidence passes for the changed high-risk surfaces,
  and the stable C ABI remains backward compatible or follows a documented
  major transition.

## Deferred security work before `1.0`

`v0.5.0` completed the focused credential redaction, zeroization, and secret
lifetime review for its supported config, diagnostic, REALITY, QUIC, and FFI
boundaries. Those tests remain blocking. The following broader work is still
required before a stable `1.0` claim:

- complete an independent security review of the supported crypto, wire, TUN,
  and FFI surfaces after fuzz coverage and release behavior have stabilized,
  including the VLESS encryption added in `v0.6`.

A replacement, upstreaming effort, or new long-term maintenance strategy for
`shaped-rustls` is not scheduled for `v0.6`. Continue to use the exact immutable
revision and existing dependency/security gates. Reconsider that decision only
during `1.0` planning or earlier if a concrete security finding, upstream
incompatibility, or maintenance failure invalidates the current pin.

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
