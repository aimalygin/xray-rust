# Changelog

All notable changes will be documented in this file.

The project has not made a stable release. Versions before 1.0 are
prerelease-quality and do not establish a supported release series.

## Unreleased

- Retargeted the Xray-core oracle, ignored interoperability suite, and
  benchmark harness from v26.5.9 to exact v26.7.28 commit
  `5ca6f4b7d4dc20a881d4330e498892697627ec0c`. Oracle Go modules and committed
  REALITY/gRPC fixtures now use the target dependency graph, while benchmark
  auto-builds reject any other or source-modified checkout.
- Synchronized supported v26.7.28 behavior for `streamSettings.method`, XHTTP
  `sessionID*` names and `maxConnections=3` explicit-settings default, and DNS
  TTLs above 300 seconds. Target DNS `qType`/`Return`/`rCode`, plaintext-public
  destination policy, and non-empty selected XHTTP session-ID tables remain
  documented compatibility boundaries.

## 0.4.0 - 2026-08-27

- Added Apple VLESS share-link import for `xhttp`/`splithttp` with plaintext,
  TLS, or REALITY transport security, including bounded single- or
  double-percent-decoded `extra` JSON. TLS/REALITY fields are preserved and
  unsupported non-empty certificate-pin/ECH parameters fail closed. XHTTP
  profiles never acquire a raw-only Vision flow from the Apple profile
  migration helpers. The core now applies Xray's one-level `extra` replacement
  rule for the modeled v26.5.9 XHTTP surface, preserving outer `host`, `path`,
  and `mode`. Removed `scMaxConcurrentPosts` values remain import-compatible
  but are explicitly ignored rather than being misread as
  `scMaxBufferedPosts`.
- Reduced plaintext H1 XHTTP packet-up memory pressure: body buffers now grow
  in Xray-sized 8 KiB steps only while data is available, so a 500000-byte
  `scMaxEachPostBytes` ceiling is not pinned by every active flow. Body-mode
  POSTs also reuse the actual allocation instead of cloning every payload;
  H2/H3 behavior is unchanged. Added an exact-profile RSS harness with
  held-flow, 16 KiB control, settle, and ACK-gated rollover phases.
- Updated `h2` to 0.4.16 for its upstream RustSec fix and refreshed the
  transitive `chacha20` lock entry to 0.10.2 after 0.10.1 was yanked.

## 0.3.2 - 2026-08-16

- Preserved an omitted VLESS `flow` when importing Apple share links instead
  of silently enabling `xtls-rprx-vision`. This matches the link semantics and
  prevents an early EOF when the server-side client is configured without a
  flow. Explicit Vision and Vision UDP/443 values remain supported.

## 0.3.1 - 2026-08-16

- Updated the REALITY client version advertised in the authenticated handshake
  from `1.8.0` to the implemented Xray-core compatibility baseline `26.7.28`.
  This prevents current Xray-core servers from rejecting xray-rust under the
  default `minClientVer` of `26.3.27`.
- Synchronized the uTLS fingerprint namespace and `ModernFingerprints` pool
  with Xray-core v26.7.28. The explicit `hellochrome_133`,
  `hellofirefox_148`, and `hellosafari_26_3` names are accepted again, while
  `random` now draws from the current eleven-profile pool. Older profiles that
  moved out of that pool remain available by explicit name. All supported
  REALITY-capable shapes match the Go uTLS oracle, and all eleven modern
  profiles complete VLESS + REALITY + Vision interoperability against
  Xray-core v26.7.28.
- Added optional Android `XrayCore.create(fileLoggingDirectory = ...)` support
  for bounded, app-controlled diagnostic exports. File logging remains off
  unless the host supplies an existing private directory.

## 0.3.0 - 2026-08-10

- Fixed the fd-backed TUN pump giving up permanently on a single transient I/O
  error. Both the read and the write loop used to break on anything that was
  not `EINTR`, and nothing supervises those tasks, so one `ENOBUFS` or
  `ENETDOWN` — ordinary conditions while a phone moves between Wi-Fi and
  cellular — stopped all packet flow for good while the tunnel went on
  reporting itself connected. Errors are now classified: an interrupted
  syscall is reissued for free, a packet that cannot be encoded is dropped
  without consuming the retry budget, a genuinely transient failure backs off
  and retries, and only a closed descriptor ends the loop.
- Added `tunFdReadLoopExits`, `tunFdWriteLoopExits` and
  `tunFdTransientIoErrors`, surfaced through the FFI, the periodic debug log
  and the Swift adapter. A pump that gives up is no longer silent: a non-zero
  exit counter means the tunnel has stopped moving packets while still
  reporting connected, and transient errors growing without an exit means the
  descriptor is unhealthy but recovering. The packet-I/O log line now also
  records which utun descriptor and interface the pump bound to.
- Apple utun discovery now identifies the interface by its kernel control id
  rather than by an interface-name prefix. Option 2 on `SYSPROTO_CONTROL` is
  defined per control, and an ordinary `AF_UNIX` socket answers it with four
  unrelated bytes instead of failing — so a successful lookup never implied
  "this is a utun". This is the same technique WireGuard adopted after
  73 minutes with the prefix version, and the one sing-box and Tun2SocksKit
  use today. It still returns the first match; proving the interface belongs
  to this provider needs `virtualInterface`, which is iOS 18 and later.
- `XrayCoreError` now carries its status code and message through the NSError
  bridge. It conformed only to `Error`, so Swift bridged it using the type
  name and case index alone and a real engine failure reached the user as
  "The operation couldn't be completed. (XrayMobileAdapter.XrayCoreError
  error 0.)", discarding the one thing that said what went wrong.
- Imported VLESS configs now enable `http`, `tls` and `quic` sniffing and pin
  `dns.queryStrategy` to `UseIPv4`, and a DNS mode switch no longer discards
  that pin. Sniffing is the only way a flow recovers its domain when the
  fake-IP mapping is gone — after a tunnel restart the table is empty while
  clients still hold cached fake IPs, and without it those connections are
  dialled literally as unroutable `198.19.x.y`. Existing profiles keep the
  config they were imported with; re-import the share link to pick this up.
- The Apple full tunnel continues to install both IPv4 and IPv6 default
  routes. An earlier implementation of this work removed `::/0` because the
  fake-IP pool is IPv4-only, but that made IPv6 literals and AAAA destinations
  bypass the VPN. The Rust TUN data path supports literal IPv6 TCP/UDP, so the
  privacy-preserving default is to capture it; only resolved outer proxy
  endpoints receive narrow `/128` bootstrap exclusions.
- Added the WebSocket and HTTPUpgrade stream transports for VLESS outbounds.
  `streamSettings.network` now accepts `ws`/`websocket` and `httpupgrade`
  alongside `tcp`/`raw`, with `wsSettings` and `httpupgradeSettings` carrying
  `path`, `host`, `headers` and — for WebSocket — `heartbeatPeriod`. Both
  transports send Xray's browser-masquerade header block and serialize the
  request the way Go writes an `http.Request`, and both are verified against a
  live xray-core rather than against a reading of it.
  `?ed=N` in the path means different things on the two despite the shared
  spelling: on WebSocket it is an early-data budget carried in
  `Sec-WebSocket-Protocol`; HTTPUpgrade retains the spelling for config
  compatibility but waits for the `101` because sending payload before it can
  strand bytes in Xray's inbound buffered reader. `docs/config-compatibility.md`
  has the full surface, including the
  header-casing split between the two and the one place the masqueraded
  browser version diverges from Xray's.
- Rejected two transport pairings that would otherwise build here and then
  fail on the wire: REALITY with `ws` or `httpupgrade`, which xray-core
  answers with "REALITY only supports RAW, XHTTP and gRPC for now", and
  `xtls-rprx-vision` with anything but raw under `tls` or `reality`, because
  Vision splices itself into the security connection's internals and breaks
  when a transport wraps it. The second is narrower than xray-core's own rule
  rather than a copy of it — xray-core asks whether the transport dialer
  handed the security conn straight back, which mKCP does and raw with a
  `tcpSettings.header.type` authenticator does not, and it skips the question
  entirely when VLESS `encryption` is on. Neither case arises here: no
  transport we implement hands the conn back except raw, and
  `encryption: "none"` is the only value we accept.
  `docs/config-compatibility.md` has the full account. A `freedom` outbound
  also refuses ws and httpupgrade; they are implemented for VLESS only, and
  refusing beats silently dialling plain TCP.
- TLS connections are now shaped to look like a browser.
  `tlsSettings.fingerprint` selects a uTLS ClientHello shape from the same 58
  names xray-core accepts, and an absent or empty value means `chrome` rather
  than no shaping, which is the default xray-core itself applies.
  `fingerprint: "unsafe"` is the opt-out and sends the TLS stack's own hello.
  Fourteen of the 58 names are TLS-1.2-era: eleven of those are shaped but not
  byte-exact, because rustls emits a `supported_versions` extension uTLS does
  not and nothing in the shaping API can suppress it, and the other three — the
  `hello360_7_5` aliases refused below — build no ClientHello at all.
  `docs/config-compatibility.md` carries the detail and the full name list.
- Shaped connections handshake on the aws-lc-rs crypto backend rather than
  ring, and offer the post-quantum key share their profile plans:
  X25519MLKEM768 for `chrome`, none at all for a TLS-1.2-era profile. Matching
  a current browser requires both, and both are real changes — in what goes on
  the wire, and in which backend performs the handshake.
  `fingerprint: "unsafe"` keeps the previous ring path.
- Session resumption is disabled on shaped connections. A resumed handshake
  emits a second ClientHello carrying `pre_shared_key`, an extension the
  fingerprint never described, so shaping and resumption cannot both hold.
  Every reconnect is now a full handshake where it previously resumed, which
  costs a round trip and a signature verification on links that reconnect
  often. `fingerprint: "unsafe"` keeps resumption.
- `fingerprint: "random"` and `fingerprint: "randomized"` now draw a real
  fingerprint per process instead of both resolving to one frozen shape. Every
  install used to send the same ClientHello for these names — the opposite of
  what someone selecting them is asking for. Each name now draws independently
  from xray-core's `ModernFingerprints` on first use and keeps that draw for
  the life of the process, so two installs differ while one install never
  changes between connections. `randomized` diverges from xray-core in kind:
  xray-core hands it to uTLS's randomized-spec generator, which has no port
  here, so a real browser shape is drawn rather than a novel one synthesized.
  `randomizednoalpn` stays pinned to a fixed shape, because every modern
  fingerprint carries the ALPN extension that name exists to suppress.
- Removed three `fingerprint` names that xray-core does not accept:
  `hellochrome_133`, `hellofirefox_148` and `hellosafari_26_3`. They are real
  uTLS `ClientHelloID`s but appear in none of the three maps Xray's
  `GetFingerprint` consults, so a profile naming one parsed here and then
  failed on xray-core with `unknown "fingerprint"`. The accepted set is now
  exactly Xray's, and `tlsSettings.fingerprint` / `realitySettings.fingerprint`
  reject the three at parse time. Replace them with `chrome`, `firefox` and
  `safari` respectively — those are the shapes the dropped names already
  resolved to, byte for byte, so the ClientHello on the wire does not change.
  The Apple `XrayRealityFingerprintMode` constants and picker entries are gone
  with them; a stored profile still naming one reads back as no selection.
- Added the gRPC stream transport for VLESS outbounds.
  `streamSettings.network` now accepts `grpc`, with `grpcSettings` carrying
  Xray's own eight keys — `serviceName`, `multiMode`, `authority`,
  `user_agent`, `idle_timeout`, `health_check_timeout`,
  `permit_without_stream` and `initial_windows_size`. Unlike the other stream
  transports it does not wrap one socket: every flow to one server becomes
  another stream on one shared HTTP/2 connection, opened by the first flow and
  held between them, with grpc-go's keepalive gate and its dormancy on a
  connection carrying no call. The reusable connection is also retired after
  grpc-go's independent 30-minute no-RPC timeout, which Xray leaves at its
  default; active streams are not interrupted, and the next flow performs a
  fresh bounded dial. A camelCase `idleTimeout` is rejected rather than
  accepted, because Go matches on the struct tag and drops that key in silence,
  leaving a profile that looks configured and dials with no keepalive.
  The `:path`, the `Hunk` and `MultiHunk` framing and the first HEADERS block
  are pinned against a live grpc-go v1.81.0 oracle, and five ignored scenarios
  carry real traffic through an xray-core gRPC inbound over plaintext, TLS and
  REALITY. One thing is deliberately not grpc-go's: the connection-level
  receive window is opened to 16 MiB, because `h2` pins it at 65535 whatever
  SETTINGS say and releases it only from the application's read path, so on a
  connection every flow of an outbound shares, one flow whose consumer stops
  reading would hold the window all the others need. It costs one extra
  `WINDOW_UPDATE` in the opening burst. `docs/config-compatibility.md` has the
  full surface, `docs/status.md` the four differences that remain.
- REALITY is now accepted with `network: "grpc"`, where it was refused. The
  guard allowed only the raw transport while its own error message read
  "REALITY only supports RAW, XHTTP and gRPC for now" — the message quoted
  Xray's rule correctly and the condition did not. REALITY over gRPC is the
  deployment gRPC mostly exists for, so this is the pairing that unblocks it.
  `xtls-rprx-vision` is still refused alongside it, and xray-core refuses it
  over gRPC too: the gRPC dialer returns a `Hunk` wrapper rather than the
  security conn, so the connection under Vision is neither a `*tls.Conn`, a
  `*tls.UConn` nor a `*reality.UConn`. That is a fact about the dialer, not
  about the network name — mKCP hands its TLS conn straight back and carries
  Vision fine — and it holds only because VLESS `encryption` is off, which is
  the sole setting we accept. `docs/config-compatibility.md` has the full
  account.
- Added two direct dependencies for the gRPC transport: `h2` 0.4.15 for the
  HTTP/2 client it speaks over, and `http` 1 for the request and header types
  that client takes — `grpcSettings.authority` is parsed and stored as an
  `http::uri::Authority`, so the type is part of the transport's public
  surface. Six more crates land in the lockfile behind them — `atomic-waker`,
  `fnv`, `futures-sink`, `tokio-util`, `tracing` and `tracing-core` — and
  `cargo deny check advisories bans licenses sources` is clean against the
  existing allow-list.
- Added the XHTTP stream transport for VLESS outbounds. `network` accepts
  `xhttp` and the legacy `splithttp` alias, with Xray-compatible priority
  between their settings blocks and all three modes: `packet-up`, `stream-up`,
  and `stream-one`. The runtime normalizes the complete modeled padding,
  metadata-placement, packet-pacing, and xmux surface instead of accepting
  those settings and ignoring them. HTTP/1.1 has safe packet-connection reuse;
  HTTP/2 uses capacity-aware pooled connections; the xmux manager persists
  across every cached selection of one outbound. H1/H2 mode, wire, lifecycle,
  and live Xray-core interoperability matrices cover the production paths.
- Replaced the public one-shot `select_*` helpers with methods on a long-lived
  `OutboundRouter`. Callers embedding `xray-core-rs` must construct one
  `Arc<OutboundRouter>` from their immutable `Arc<CoreConfig>`, retain it for
  that configuration's lifetime, and call its selector methods. Reconstructing
  a router for each selection discards the gRPC and XHTTP connection pools, so
  compatibility wrappers would preserve source syntax while silently losing
  the lifecycle behavior this release adds.
- Added phase-one XHTTP over HTTP/3. Exact TLS `alpn: ["h3"]` selects a
  protected UDP/QUIC v1 path with no TCP downgrade, stock TLS 1.3, Happy
  Eyeballs candidate racing, reusable H3 connections, and all three XHTTP
  modes. Its declared limits fail closed: receive windows are static in Quinn
  rather than quic-go-adaptive, standard BBR is a Quinn approximation, and
  the pool conservatively permits one active HTTP request per QUIC connection.
  QUIC v2, unequal adaptive maxima, non-standard BBR profiles, Brutal,
  UDP-hop, and debug side effects are not accepted. Hermetic H3 wire and
  lifecycle tests plus live Xray-core `packet-up`, `stream-up`, and
  `stream-one` cases pass. The generic stream benchmark now exposes
  `xhttp-h3` with an exact `h3`/UDP fixture and default QUIC parameters. Actual
  release and controlled-RTT/loss runs remain required before any H3
  performance-parity claim.
- Patched the vendored `h3-quinn` 0.0.10 receive adapter so cancelling a
  pending response read can send `STOP_SENDING(H3_REQUEST_CANCELLED)` instead
  of panicking on an empty internal stream slot. Focused regressions cover the
  pending-poll edge, the exact cancellation code, and reuse of the same QUIC
  connection for a later request.
- Matched Go's XHTTP automatic gzip behavior across H1, H2, and H3, including
  Range/HEAD and explicit-header suppression, H1/H2 versus H3 casing rules,
  raw H1 packet bypass, concatenated gzip members, and stream-local malformed
  response errors that do not retire a healthy multiplexed connection.
- Fixed nine uTLS profiles — eleven of the accepted `fingerprint` names — being
  unable to complete a plain-TLS handshake at all. Their parrot sends a
  TLS-1.2-era ClientHello with no `supported_versions` extension while the
  rustls config still offered TLS 1.3, so a 1.3-capable server answered with
  TLS 1.2, its ServerHello carried the RFC 8446 §4.1.3 downgrade sentinel, and
  rustls read that as an attack. The config is now capped at the version the
  hello actually claims, as uTLS caps its own, and the 32-byte legacy session
  id rustls drops along with TLS 1.3 is redrawn per connection so the hello
  does not change shape in exchange. Nothing had exercised these before
  `security: "tls"` started shaping: REALITY has always refused them for
  lacking an X25519 key share, which is the same fact from the other side.
- `fingerprint: "hello360_7_5"`, and its aliases `360` and `hello360_auto`, are
  now refused with a reason instead of dialling. All twenty of that profile's
  cipher suites are CBC, RC4 or 3DES and this client implements none of them,
  so whichever the server picked was one it could not speak and the connection
  died at ServerHello under an error naming neither the fingerprint nor the
  cause. The refusal happens where the rustls config is built, so the TCP
  socket is still opened but no ClientHello is sent. xray-core completes that
  handshake, because Go still ships the legacy suites; this is our limit rather
  than the parrot's, and saying so beats discovering it a round trip later.

## 0.2.0 - 2026-08-05

- Fixed file logging initialization inside the iOS Network Extension sandbox.
  `xray_core_new` failed with "Operation not permitted" because runtime log
  files were opened by walking every ancestor directory with read access,
  which the sandbox denies outside the app-group container. Apple platforms
  now resolve the log path with a single `O_NOFOLLOW_ANY` open, which keeps
  rejecting symlinks in any path component; other unix targets keep the
  hardened directory walk.

## 0.1.1 - 2026-08-03

- Added Packet Tunnel support for loading verified geodata generations from a
  shared App Group directory. Explicit App Group generations are searched
  exclusively so missing assets fail closed instead of mixing with bundle or
  process-default geodata; configurations without App Group settings preserve
  the existing bundle-resource fallback.
- Stabilized the Packet Tunnel provider's cross-process `NSError` domain and
  codes, and expanded tests for App Group path validation, start configuration,
  DNS pinning, and runtime geodata loading. Swift clients with an exhaustive
  switch over `XrayPacketTunnelProviderError` must handle the new
  `invalidGeodataConfiguration` case.
- Documented an atomic, immutable-generation workflow for host-managed geodata.

## 0.1.0 - 2026-08-02

- Added a sample-only `Default DNS` preset (`FakeDNS` with routed
  `tcp://1.1.1.1`) and shared mobile DNS preflight so invalid full-tunnel DNS
  topologies are rejected by the host before Network Extension startup. The
  Apple client now waits for a real connected or failed status and surfaces the
  provider's last disconnect error instead of treating submission of the start
  request as success.
- Added non-destructive DNS test controls to the Apple reference client. A
  saved profile can switch at reconnect between its original JSON, the fixed
  sample preset, FakeDNS, and the local DNS proxy over classic, routed TCP, or
  provider-local TCP;
  an optional FakeDNS upstream also enables restored-domain resolution when
  routing selects Freedom. Manual modes keep the trusted upstream
  user-supplied; generated effective DNS settings retain `dns.hosts` bootstrap
  pins and the routed-DNS tag, and never overwrite the source profile JSON.
- Kept the DNS outbound TCP handler out of ordinary SOCKS connection futures,
  allocating its type-erased future only after a DNS route is selected. This
  removes 1.2 KiB from both enclosing async states and brought the same-machine
  1000-flow RSS median from 20.52 MiB back to 18.27 MiB without detached tasks
  or changed cancellation behavior.
- Extended the process benchmark harness with a strict, repeatable DNS matrix
  covering FakeDNS and proxied UDP/TCP clients, plus latency, query-rate,
  CPU-per-1000-query, and RSS charts. Raw artifacts now carry run IDs, DNS
  transport, Git/worktree provenance, canonical CLI arguments, and SHA-256
  hashes for the measured binaries; incompatible series fail chart generation.
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
