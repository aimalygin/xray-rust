# Android integration

This Gradle project builds an Android library around the Rust C ABI. It provides
a Kotlin wrapper, JNI bridge, and reference `VpnService`. Two test-only
application targets, `devicehost` and `deviceprobe`, support physical-device
release-gate rehearsals; neither is a production VPN application.

For development inside this source tree, build the AAR locally as described
below. Prebuilt, versioned AAR and Maven release bundles are published from
[`xray-rust-mobile`](https://github.com/aimalygin/xray-rust-mobile).

## Prerequisites

- JDK 17 or newer;
- Android SDK platform 35 and Build Tools 36.0.0;
- Android SDK CMake 3.22.1;
- Android NDK 26.3.11579264;
- Rust Android targets for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`.

Check the complete host setup:

```sh
scripts/check-mobile-toolchains.sh --android
```

The wrapper pins Gradle 9.8.1. Both Android plugins use AGP 9.4.1 and
[AGP built-in Kotlin](https://developer.android.com/build/migrate-to-built-in-kotlin),
with Kotlin 2.4.21 pinned on the buildscript classpath. Do not apply the legacy
`org.jetbrains.kotlin.android` plugin alongside built-in Kotlin. Update the
wrapper checksums, dependency verification metadata and toolchain guards together.

## Build the AAR

```sh
scripts/build-android-adapter.sh
```

Output:

```text
platform/android/xraymobile/build/outputs/aar/xraymobile-debug.aar
```

The script builds Rust libraries for all four ABIs, compiles
`libxray_mobile_jni.so`, packages both native libraries, verifies that the
packaged FFI binaries match the selected Rust artifacts, and checks 16 KiB ELF
LOAD alignment.

To build only the Rust artifacts:

```sh
scripts/build-android-libs.sh
```

They are written to `target/mobile/android/jniLibs`. The Gradle module reads
that path by default; `XRAY_FFI_ANDROID_DIR` can select another already-built
artifact directory.

## Library surface

- `XrayCore`: lifecycle, config warnings, atomic routing-policy replacement and
  snapshots, packet push/batched poll, stats, selection/health snapshots,
  connection inventory/accounting/close, seven typed TUN diagnostic queues,
  startup probe with a pre-start preflight (ABI 1.12), blocking on-demand
  outbound probe (ABI 1.9), runtime profiles, DNS bootstrap policy, and socket
  protection.
- `XrayVlessUrlImporter`: fail-closed VLESS share-link conversion into a
  self-contained mobile TUN profile.
- `XrayVpnService`: reference VPN interface setup and lifecycle coordination.
- `XrayTunInterface` and `VpnService.Builder.applyXrayTunInterface(dnsAnchor)`:
  the interface addresses, MTU and DNS anchor that `XrayVpnService` uses, for
  hosts that run their own `VpnService`.
- `XrayNetworkChangeCoordinator`: opt-in underlying-network observation and
  Hysteria2/WireGuard rebind requests with application-owned selection/binding.
- `XrayTunBackend.FileDescriptor`: default direct borrowed raw-IP fd path.
- `XrayTunBackend.PacketPump`: fallback with reusable direct buffers and
  batched blocking poll.
- `xray_mobile_jni.cpp`: checked JNI-to-C-ABI bridge with ABI major/minor
  validation and public capability discovery.

When `XrayCore.create` receives a `VpnService`, outbound TCP and UDP sockets are
passed through `VpnService.protect(fd)` before use. With
`sockopt.happyEyeballs`, protection is applied separately to every launched raw
TCP candidate before connect; cancelled and losing candidates are not detached.
This prevents proxy sockets from being routed back into the VPN.

PacketPump waits up to 250 ms for TUN readability after a zero-byte
nonblocking read. This avoids the Android `EAGAIN` busy loop while preserving
MTU-sized buffers and bounded worker teardown. `EINTR` retries respect the
active/interrupted checks; terminal poll errors use the existing fatal path.
FileDescriptor remains the default path. See the separately identified
[physical Android baseline and follow-up](../../docs/device-results/2026-10-04-android-v08/README.md).

A host that establishes the interface in its own `VpnService` can apply the
same values instead of copying them:

```kotlin
val tunnel = Builder()
    .setSession("my-vpn")
    .applyXrayTunInterface(dnsAnchor = true)
    .addRoute("0.0.0.0", 0)
    .addRoute("::", 0)
    .establish()
```

`XrayTunInterface.MTU` (1500) equals the core's TUN MTU: longer packets are
dropped, so do not raise it. Pass `dnsAnchor = true` only when the config
enables `dns.fakeIp` or a non-empty `dns.servers` list; the core answers DNS at
`XrayTunInterface.DNS_ANCHOR` (`198.18.0.1`) only then. The IPv4 and IPv6
addresses are the reference service's choice and the core does not depend on
them. Routes, session name, metering and application rules stay with the host.

For a live traffic meter, sample `XrayCore.stats()` and take the difference of
`XrayTunStats.uplinkBytes` and `downlinkBytes` between samples. They add the TCP
(`tcpRemoteWrittenBytes`, `tcpRemoteReadBytes`) and UDP remote payload counters
of every TUN flow, including direct ones, and only grow while the core exists.
They exclude proxy protocol overhead, probes and SOCKS/HTTP inbounds.
`outboundAccountingSnapshot()` adds a connection's bytes only when it closes, so
it suits per-outbound totals rather than a live rate. The Swift adapter exposes
the same TCP counters in `XrayTunStatsSnapshot`.

## VLESS share-link import

Development ABI 1.14 provides `XrayProfileFormat.Http` for `http://` and
`https://` proxy links. Check `supportsProfileImport(XrayProfileFormat.Http)`
before importing; it requires `HttpProfileImport` and `ProfileImport`. HTTPS
retains certificate/name verification; explicit DNS uses TCP. See the
[HTTP import contract](../../docs/http-profile-import.md).

Development additionally provides `XrayProfileFormat.Socks` for `socks://` and
`socks5://` through the shared parser. It requires ABI 1.13 and the
`SocksProfileImport` capability; use `supportsProfileImport` before importing.
See the [SOCKS link contract](../../docs/socks-profile-import.md).

Development v0.7 additionally provides
`XrayProfileImporter.profile(text, XrayProfileFormat.Hysteria2)` and `.Wireguard`
for Hysteria2 links and WireGuard `.conf` text through shared Rust/C ABI 1.5.
Check `XrayCore.ffiInfo().supportsProfileImport(format)`. WireGuard requires
literal IP DNS servers in the file or `dnsServers` and preserves AllowedIPs
split routing; unsupported parameters fail explicitly. Host UI and secure
storage remain caller-owned. See the [import contract](../../docs/v07-profile-import.md).
Use a matching freshly built native library, header and JNI bridge.

`XrayVlessUrlImporter.profile(rawUrl)` returns an `XrayImportedProfile` with a
display name, server address, and JSON config ready for `XrayCore.create` or
`XrayVpnService.startXrayTunnel`. It accepts a bare link, a link embedded in
pasted text, or a scheme-less UUID authority. The supported subset matches the
Apple importer: `tcp`/`raw` with REALITY, and `xhttp`/`splithttp` with no
security, TLS, or REALITY. The generated profile uses the TUN inbound, VLESS
`proxy`, private-address Freedom split, and bounded IPv4 fake-IP defaults.

Development `0.6` also imports bounded
`mlkem768x25519plus.{native|xorpub|random}.{1rtt|0rtt}` with one-to-eight
canonical X25519/ML-KEM-768 relay keys and optional bounded padding over
`tcp`/`raw` and `xhttp`/`splithttp`, with none, TLS, or REALITY security and
optional Vision/Vision-UDP443. WS/HTTPUpgrade/gRPC profiles use JSON. Encrypted
links reject irrelevant raw transport fields and insecure TLS. Key encodings,
padding limits, and low-order/modulus checks match shared Rust fixtures; error
messages redact rejected encryption values. This does not change the published
`v0.5.0` distribution.

Security- and transport-critical query values are unique and validated.
Unsupported transports, security fields, modes, and flow values fail closed.
XHTTP `extra` must be a JSON object no larger than 64 KiB after either the
normal URL decode or exactly one compatibility decode; recursively encoded or
non-object payloads are rejected. Errors for unsupported security parameters
name the field without including its value. The library does not persist the
result or log the source link; profile storage and UI remain host-owned.

`XrayCore.create` defaults to `XrayDnsBootstrapMode.System`, which preserves the
generic library/server behavior. Embedders that make system DNS unreachable
after installing their network interface can select `StaticOnly`, but then
every proxy and DNS-upstream hostname must resolve through an exact or otherwise
applicable `dns.hosts` rule. Bare host keys use Xray's exact/full semantics.

## Reference VPN DNS bootstrap

`XrayVpnService` uses the stricter mobile policy automatically. Before calling
`Builder.establish()`, it resolves domain-valued VLESS, VMess, Trojan, Shadowsocks,
SOCKS, HTTP, and Hysteria 2 server addresses, all WireGuard peer endpoint hosts, and
domain-valued `dns.servers` with Android's system resolver. SOCKS and HTTP
preparation supports both flat settings and the legacy single-entry `servers`
form; it resolves only the proxy endpoint, leaving destination-domain
resolution to the proxy. DNS upstream preparation includes
`tcp://`, `tcp+local://`, `tls://`, `https://`, `https+local://`, and
`quic+local://` endpoints;
an IP-literal URL needs no
bootstrap lookup. It preserves every usable A/AAAA result in resolver order,
removes duplicates, and writes a nonempty exact `full:` IP array under
`dns.hosts`, then creates the core with `XrayDnsBootstrapMode.StaticOnly`. The
original carrier address/endpoint strings, authentication, DNS server URI, and
DNS object policy fields remain unchanged. Literal, resolved, and aliased carrier
addresses that point to a tunnel-owned address fail preparation. Every outer
WireGuard/Hysteria UDP socket still uses `VpnService.protect(fd)`; no global
route exclusions are added. See the [v0.7 bootstrap contract](../../docs/v07-mobile-bootstrap.md).

`tcp://`, `tls://`, and `https://` use normal Freedom/VLESS selection and an
object server's `tag`. A `+local` URL instead bypasses the Xray router and opens
a system/local transport socket passed through `VpnService.protect(fd)`. Every
domain host still uses mobile bootstrap pinning. Schemes are case-insensitive;
default ports are 53 for TCP, 853 for TLS/DoQ, and 443 for HTTPS. TCP/TLS/DoQ
accept only an IPv4/domain/bracketed-IPv6 authority with an optional nonzero
port. HTTPS also
accepts an ASCII path/query (default `/`) but rejects userinfo, fragments,
backslashes, unbracketed IPv6, whitespace/control characters, and malformed
brackets. For an object server the URL port wins.
A sibling `port` is still validated as an integer from 0 through 65535 and
preserved in the config, but is ignored when selecting that endpoint. A TCP URL
pointing directly to, or pinning a domain onto, a tunnel-owned address is
rejected on every URL port; classic non-URL servers retain their legacy port-53
check.

`startXrayTunnel` is asynchronous: it returns after scheduling startup on a
bounded daemon worker pool. DNS preflight, the startup probe, tunnel
establishment, core startup, and the protected `onXrayTunnelStarted` /
`onXrayTunnelStartFailed` callbacks do not run on the main thread. A host that updates UI from either callback must
dispatch that work to its main-thread executor. Failure to schedule a worker is
reported synchronously by `startXrayTunnel` instead of invoking the failure
callback on the caller's thread. The coordinator releases the completed attempt
before invoking either callback, so a callback may synchronously stop or retry
without colliding with the previous start task.

An existing exact `full:` mapping is authoritative and is never overwritten.
It may end in one IP or an ordered nonempty IP array. Domain aliases are
followed to such a terminal target; cycles and chains longer than eight entries
are rejected. If any required domain cannot be resolved, tunnel startup fails
before Android installs the VPN interface. All lookups in one start attempt
share a five-second monotonic deadline that begins as soon as the lifecycle
accepts the attempt. A stop during startup marks that attempt as cancelled,
interrupts its wait, and returns without joining the start worker. The token is
checked again after preflight and before publication, so a late resolver result
cannot establish or publish a cancelled session. A new start remains rejected
until pre-publication cleanup has finished.

Android's `InetAddress.getAllByName` is blocking and may ignore interruption.
The deadline therefore bounds how long VPN startup waits, but cannot guarantee
that the platform lookup itself has returned. At most two daemon DNS workers can
remain blocked; the resolver uses a zero-capacity handoff and fails a later
lookup instead of growing a queue. The start-worker pool is likewise limited to
two threads so host callbacks that ignore cancellation cannot create unbounded
threads. The preflight pins all returned candidates for the tunnel lifetime.
An explicitly enabled `sockopt.happyEyeballs` policy can race those candidates;
its Xray-compatible `tryDelayMs: 0` default is disabled. Network-migration DNS
refresh still requires a new tunnel start or host-specific policy.

When enabled `dns.fakeIp` or a non-empty `dns.servers` list activates the core's
local DNS endpoint, the reference service also installs `198.18.0.1`
(`XrayTunInterface.DNS_ANCHOR`) with `Builder.addDnsServer`. Apps that override `buildTunnel()` retain control of all
other addresses, routes, and application exclusions. On Android 10 and later
the default `buildTunnel()` also calls `setMetered(false)`: a VPN of an app
targeting API 29+ is otherwise metered even on Wi-Fi. An override decides this
itself. The endpoint accepts UDP
and length-prefixed TCP queries. UDP clients are translated to the configured
TCP, DoT, DoH, or DoQ transport. TCP clients remain length-prefixed for TCP/DoT
and are translated frame-by-frame into bounded HTTP/2 DoH POST requests or
single-stream DoQ exchanges.

The Core-owned destination cache supports global `disableCache`, `serveStale`,
and `serveExpiredTTL`. Stale service requires an explicit bounded 1-through-
86400-second window; zero/unbounded and per-server cache overrides fail config
validation. NXDOMAIN/NODATA are cached for 30 seconds, while transport failures
are never cached.

Fake-IP does not provide the real destination address needed by Freedom or
WireGuard. When `dns.fakeIp.enabled` is true and `dns.servers` is empty, the
reference service rejects either protocol as the default or through a
TUN-applicable domain-capable rule, including balancer prefix candidates and
`fallbackTag`, before `Builder.establish()`. VLESS/Hysteria defaults with IP-only
Freedom/WireGuard split routes remain valid. Configuring a `dns.servers`
upstream permits domain routes through these protocols. The preflight never inserts or substitutes a public
DNS server.

### Startup probe before the VPN interface

The startup probe is opt-in: without `startXrayTunnel(startupProbe = ...)` the
reference service contacts no connectivity-check endpoint. A probe requires
ABI 1.12+ and runs after DNS bootstrap and before `Builder.establish()`, on a
separate unstarted `XrayCore` with the prepared config, socket protection and
`StaticOnly` DNS policy. That core has no TUN fd, listeners, packet I/O or
`tunAdmissionOptions()` policy. A failed, timed-out or cancelled probe therefore
leaves Android routes and DNS untouched; a failure or timeout reaches
`onXrayTunnelStartFailed`. After success the service closes the preflight
core, establishes the VPN interface and starts the data-path core without
repeating the probe. `stopXrayTunnel()` during the probe cancels the native
request without waiting for the start worker. Custom integrations can call
`XrayCore.preflightStartupProbe()` themselves; the probe inside `XrayCore.start()`
is unchanged.

### Network changes and Hysteria limits

`XrayCore.rebindHysteria()` (ABI >=1.7) and `rebindWireGuard()` (ABI >=1.6)
request fresh protected carrier sockets while retaining live inner flows and
current endpoints. Each returns accepted/coalesced requests, not completed
path validation or handshakes. Idle outbounds return zero without connecting.

Apps owning the TUN fd can opt into `XrayNetworkChangeCoordinator`. Add
`android.permission.ACCESS_NETWORK_STATE` to the host manifest and supply the
app's serial VPN control executor. The reference `XrayVpnService` does not enable
this helper automatically. The
[compiled fd-session example](xraymobile/src/test/java/org/xrayrust/mobile/examples/NetworkChangeFdSession.kt)
shows startup failure cleanup and the required teardown order.

```kotlin
val coordinator = XrayNetworkChangeCoordinator(
    connectivityManager, vpnControlExecutor,
    selectAndApply = { candidates, previous ->
        // App-owned policy: filter/rank candidates, apply carrier settings and
        // actual socket-binding policy, then return the chosen Network or null.
        carrierPolicy.selectAndApply(candidates, previous)
    },
    onError = { error -> diagnostics.controlFailure(error) },
    onResult = { result -> diagnostics.rebindRequests(result) },
)
core.start()
coordinator.start(core, carrierPolicy.actualNetworkOrNull())
// On the same control worker, before core.stop()/close() and borrowed fd close:
coordinator.close()
```

`carrierPolicy` and `diagnostics` above belong to the application. Selection runs
on the control worker, must be quick/idempotent, and must not wait for work on
that same executor. It receives copied capabilities/link properties for usable,
unblocked, non-VPN Internet networks. The host decides further requirements
such as validation, metering, transport preference or endpoint reachability.
Return only a supplied candidate, after applying the policy, or `null` when no
carrier is usable. Errors are reported without requesting rebind. Callback
metadata is used directly, following Android's
[NetworkCallback ordering contract](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback);
the helper does not synchronously query network properties from `onAvailable`
on API 26+. Before API 26 Android follows `onAvailable` with no capability or
link-property callback until a value changes, so there the helper reads the
network's current state once in `onAvailable`; later change callbacks replace
it. API 29+ also waits for the initial blocked-status callback. Android reports
existing networks one at a time, so until the network passed to `start` reports
its own callbacks or is lost, the control worker reads its current capabilities
and link properties and offers it as a candidate; a network that is already
gone is handled as lost. Another network reporting first therefore does not
look like a migration away from the actual carrier.

Duplicate observations and bursts share one pending task and use the latest
snapshot. Without an initial network, the first usable selection establishes a
baseline without rebind; pass the actual already-applied network to `start` if
it is known. Losing the selected network with no replacement records an offline
state without rebind. A replacement or later online recovery requests both
protocols independently; losing an unrelated network does not change the
carrier. Metadata updates on the same selected network do not request rebind.

`XrayNetworkRebindResult` contains the session generation and an independent
`Accepted(requests)` or `Failed(error)` for each protocol. Zero is normal for
idle/unconfigured outbounds, which remain lazy. Existing ABI/capability and
closed-core guards are preserved. Acceptance is not evidence of a completed
handshake or recovered TCP/UDP traffic. Callbacks should not throw or log
credentials. `onError` handles policy/scheduling failures; executor rejection
stops observation and can report from the Android callback thread. Registration
and unregistration failures throw to the lifecycle caller.

`close()` unregisters the observer, invalidates queued work and waits for
in-flight policy/rebind calls before returning. Call it before closing the core
or its borrowed fd. If unregister fails, queued events are still fenced; retry
`close()` to release the observer. A subsequent `start` first retries pending
unregistration. Each start has a new generation, so old callbacks cannot touch
a new core. The helper does not own the core, fd or executor.

Socket protection remains mandatory. The helper does not bind sockets, select
the host's carrier, call `bindProcessToNetwork`, or call `setUnderlyingNetworks`.
For ordinary system-default routing, retain `setUnderlyingNetworks(null)`.
An explicit list must reflect the networks actually used by the app's
`Network.bindSocket` policy, including overlapping carriers during asynchronous
replacement. As documented by
[VpnService](https://developer.android.com/reference/android/net/VpnService#setUnderlyingNetworks(android.net.Network%5B%5D)),
this list only reports routing to Android; updating it does not move sockets.
The application must safely publish its binding policy for native socket
protection callbacks before returning from `selectAndApply`.

Version 1 changes no C ABI, wire format, fd ownership, defaults or coroutine
dependencies. It retains endpoints; DNS/NAT64 refresh and protocols without
rebind need a separate host restart policy. Unit and host JNI tests establish
event/lifecycle/request behavior, not physical Wi-Fi/cellular recovery. That
requires a device campaign with active TCP/UDP, both transition directions,
offline/recovery and rapid stop/restart, recording API level, configuration,
actual binding/routing, request outcomes and independently measured traffic.

To increase Hysteria concurrency, pass
`hysteriaStreamLimits = XrayHysteriaStreamLimits(maxTcpStreams = 128, maxUdpSessions = 64)`
to `XrayCore.create`. This requires ABI 1.10 plus `HysteriaStreamLimits` capability.
The defaults remain 64/32; bounds are 1..256 and 1..128. Limits are shared by
all inbounds using one outbound. TUN admission limits remain separate: choose
an appropriate runtime profile for large simultaneous connection bursts.
Higher concurrency can consume more memory; per-flow queues and the Xray wire
format do not change. Recreate the core to change limits.

## Host application responsibilities

A host app must:

1. request user consent with `VpnService.prepare`;
2. start and bind/drive the service using an application-owned lifecycle;
3. provide the required foreground-service notification and permissions for
   its target Android version;
4. supply profile storage and UI without placing credentials in logs,
   resources, fixtures, or source control;
5. choose routes, addresses, DNS behavior, and excluded applications suitable
   for the product;
6. test process death, rapid start/stop, network changes, sleep, and upgrades.

The library manifest declares the non-exported service with
`BIND_VPN_SERVICE` and the base foreground-service permission. The consuming
application must review the merged manifest and add any target-version-specific
foreground service declarations required by its distribution policy.

## Physical-device gate applications

Build the two debug applications with:

```sh
platform/android/gradlew -p platform/android \
  :devicehost:assembleDebug :deviceprobe:assembleDebug
```

For a separate physical campaign, append
`-PdeviceGateApplicationIdSuffix=.v08` to the debug build. Both application IDs
then end in `.v08`, with separate UIDs, Keystore entries and profile storage;
component class names retain their original namespaces. Omit the property for
the original IDs. Supply `XRAY_FFI_ANDROID_DIR` from the verified candidate build.
An arm64-only device rehearsal can use `-Pandroid.injected.build.abi=arm64-v8a`;
it does not qualify the other release ABIs.

`devicehost` is a minimal `VpnService` owner. It imports the supported VLESS
share-link subset and Trojan, SS2022, VMess and Hysteria2 links through their
existing SDK importers, immediately converts them to core JSON, encrypts that JSON with
an Android Keystore AES-GCM key, and stores the ciphertext under the app's
no-backup directory. Backup and device-to-device transfer are disabled. The
profile input and clipboard are cleared after import, and structured
`XrayDeviceGate` logs contain only lifecycle state, runtime generation, resource
counts, TUN counters, and sanitized error classes. The app can connect,
disconnect, cancel an asynchronous start from the same service command, close
one inventory snapshot through the public connection-management API, and reset
campaign counters while stopped.

The two connect buttons select FileDescriptor or PacketPump. The selected path
is retained through VPN-consent activity recreation and recorded as `tunBackend`
in lifecycle/resource logs. Automation `connect` and `rapid-stop` commands accept
the string extra `tun-backend` with exactly `file-descriptor` or `packet-pump`;
omission preserves the original FileDescriptor default, and unknown values are
rejected. Switching paths requires a separate stopped/started test cycle. A
compile/unit-test pass for this harness does not establish device-path coverage.
Resource samples include all process threads from `/proc/self/status`, resident
memory, dropped TUN packets, cumulative process CPU milliseconds and monotonic
elapsed time. CPU deltas must be compared within one process lifetime.
For controlled resource loads, automation can add the boolean extra
`probe-only=true`. Only the matching `deviceprobe` application ID is then
included in the VPN, keeping other apps out of the measured workload. Interface
addresses, routes and MTU match the SDK default. Missing probe packages fail
closed. The running status and resource samples identify this scope. Normal
connect buttons restore the full VPN scope; keep both scopes distinct in reports.

`deviceprobe` has a separate UID, so its traffic traverses `devicehost`'s TUN
instead of being excluded with the VPN owner. Its ordinary loop drives an HTTP
request plus a strict DNS-shaped UDP round trip. Each datagram has a fresh
transaction ID and nonce; success requires an owner-controlled response that
repeats the question and returns the zero-TTL documentation address. The
bounded stress action defaults to 240 HTTP attempts, 480 UDP attempts, and 32
workers. Either protocol count may be zero for a transport-specific rehearsal,
but a cycle must contain at least one attempt. Attempts and concurrency are
validated against hard upper bounds, a second stress request is rejected while
one is active. Logs expose counts, elapsed time and sanitized failure classes;
they never include failed URLs or remote addresses. A failed UDP query also
records its SHA-256 prefix and local source port to correlate the synthetic
request with the controlled backend without logging payloads.

Both activities accept test-automation commands through the string extra
`command`. Host commands are `connect`, `disconnect`, `rapid-stop`,
`close-connections`, `reset`, `import-pending`, and `import-pending-config`;
probe commands are `start`, `stop`, `reset`, and `stress`. Stress overrides use
the integer extras
`stress-cycle`, `stress-http-attempts`, `stress-udp-attempts`, and
`stress-concurrency`. Keep raw links and endpoints out of shell history and
logs. For unattended import, place the link in the host app's private
`noBackupFilesDir/profile-import.pending`; `import-pending` encrypts it and
overwrites then deletes the plaintext file.

The test-only `import-pending-config` command reads canonical core JSON from
`noBackupFilesDir/profile-config-import.pending`, requires non-empty inbound and
outbound arrays, encrypts it with the same Keystore key, then overwrites and
deletes the plaintext. This path exists for owner-controlled device profiles
whose security cannot be represented by the supported share-link subset, such
as a short-lived H3 endpoint authenticated with `pinnedPeerCertSha256`. It is
not a general application import API. Canonical parsing remains fail-closed;
do not use `allowInsecure` for a device rehearsal.

These applications produce diagnostic rehearsal telemetry. They do not create
the checksum-authenticated report required by the release-evidence validator,
replace Perfetto, or waive the full scenario matrix in
[mobile testing](../../docs/mobile-testing.md).
The current v0.8 gate has no fixed soak duration; retain actual durations,
independently verified recovery and resource limits. In particular, the host's
placeholder `unrecoveredTransitions` telemetry field is not a measured verdict.
See [v0.8 evidence assembly](../../docs/v08-release-evidence.md).

For the new protocols, `scripts/run-v08-android-protocol-fixture.py --protocol
v08` uses the same pinned Xray-core and private cleanup rules as the Apple
fixture. It provides HTTP `/v08-probe` (204), the nonce-checked UDP oracle and
routed DNS on synthetic IPv4/IPv6 destinations. The private envelope includes
Trojan, all three SS2022 ciphers, and VMess auto/AES/ChaCha. HTTP success is an
availability check, not byte-integrity or throughput evidence. Explicitly set
both probe endpoints to this fixture before starting the probe app.

For legacy regression, select `--suite legacy` (VLESS/REALITY and XHTTP
H1/H2/H3) or `--suite v07` (WireGuard and Hysteria2). These suites require
dynamically allocated ports. `/v08-hold/NUMBER` withholds an HTTP response for
up to twenty seconds and records peer EOF separately from the fixture timeout.
`--udp-delay-seconds 3` submits the same nonce-checked UDP response after three
seconds, so an active receive can be cancelled before the response. Run a
no-cancellation control and fresh traffic after cancellation; an intentional
timeout alone is not proof of working teardown or recovery. The
[physical regression report](../../docs/device-results/2026-10-04-android-regressions/README.md)
preserves separate local, remote-close and recovery verdicts and replay scripts.

## Geodata

Geodata databases are not bundled. Configs that use `geosite:`, `geoip:` or
`ext:` references need the host to supply Xray-format `geosite.dat`,
`geoip.dat` or named `ext:` files in one directory and pass it to the core:

```kotlin
val generation = File(noBackupFilesDir, "xray-geodata/$version-$sha256")
XrayCore.create(configJson, geodataSearchDirectory = generation).use { core ->
    core.start()
}
```

`XrayVpnService` subclasses override `geodataSearchDirectory()` instead. The
service reads it once per start and passes it to both cores it creates: the
startup-probe preflight core before `establish()` and the data-path core after
it. A missing file or code fails whichever is created first, before routes and
DNS are installed when a startup probe is configured, and is reported through
`onXrayTunnelStartFailed`.

The directory must already exist; otherwise `create` throws
`IllegalArgumentException`. The default `XrayGeodataSearchPolicy.Exclusive`
searches only that directory. `FallbackToDefaults` also searches the core's
process defaults, the working directory and the executable directory, which in
an Android app process are `/` and `/system/bin`; it exists for parity with the
Swift adapter and host-side tests. Without a directory only those defaults are
searched, so geodata references fail to load.

APK `assets/` entries cannot be opened by path. Copy bundled files, or download
them, into a directory under `noBackupFilesDir`, which keeps large regenerable
data out of backups:

- Write into a staging directory next to the target, verify the SHA-256 of each
  file, then rename the staging directory to an immutable
  `<version>-<sha256>` generation. Never rewrite a published generation in
  place.
- The generation directory itself and its `.dat` files must be real
  directories and regular files, not symlinks; the core opens them with
  `O_NOFOLLOW`. `ext:` names are relative to the directory and cannot escape it.
- The directory is fixed for the lifetime of a core. Referenced files are read
  when `create` loads the config and again on every `replaceRoutingPolicy`, so
  keep a generation until no core uses it and switch generations by creating a
  new core.

Each load scans the whole referenced file once to index its codes and then
decodes only the referenced entries; nothing is cached between loads. Parsing
enforces per-entry budgets of 200,000 domains, 500,000 CIDRs and 32 MiB, a
128 MiB file limit, and per-config budgets of 250,000 domain matchers and
750,000 IP matchers. A code over a budget fails the load with a config error.
For example, in the October 2026 runetfreedom `geosite.dat`, `ru-blocked-all`
and `antifilter-download` (about 1.37 million domains each) exceed these
limits, while `ru-blocked` (about 75,000 domains), `category-ru` and
`geoip:ru` (about 25,000 CIDRs) fit. Because that file is 74 MB, smaller
purpose-built files referenced through `ext:` reduce startup I/O.

Xray-core reads `geoip:private` from `geoip.dat` everywhere. Here routing
rules use a built-in private-network set and need no file, while DNS
`expectedIPs`, `expectIPs` and `unexpectedIPs` read it from `geoip.dat`, as in
Xray.

## Tests

Run Kotlin unit tests:

```sh
platform/android/gradlew -p platform/android \
  :xraymobile:testDebugUnitTest --no-daemon
```

Run ABI/artifact contract tests from the workspace root:

```sh
cargo test --locked -p xray-ffi --test mobile_artifacts_tests -- --nocapture
bash scripts/tests/check-mobile-toolchains.test.sh
```

See [mobile testing](../../docs/mobile-testing.md) for the full native artifact
matrix and on-device checklist.

## Current limits

- The checked-in host and probe apps are debug release-gate tools, not reusable
  production UI, profile management, or distribution policy.
- The AAR is built locally and is not signed or published.
- The adapter is a reference integration, not a production VPN product.
- Device behavior and performance must be verified with the consuming
  application's release configuration and supported Android versions.

## Per-app TUN enforcement (Android 10+)

ABI 1.11 and `TunAdmission` add an optional check before new TCP/UDP flows open
outbound connections, including DNS/FakeDNS. Pass `XrayTunAdmissionOptions` to
`XrayCore.create`, or override `XrayVpnService.tunAdmissionOptions()`. Keep the
normal `VpnService.Builder` app list too. For an active VPN, the supplied
`XrayAndroidUidAdmission(connectivityManager, allowedUids)` calls Android's
[`getConnectionOwnerUid`](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress)) with the original application tuple. It denies unknown
owners and lookup errors by default, and handles packages sharing a UID as one
identity. Android versions below 10 cannot provide this enforcement; the helper
rejects construction rather than claiming protection.

The callback runs on up to four native host workers, never on the packet loop.
It may run concurrently and must not call core lifecycle methods. The default
100 ms timeout denies; `failOpen` is explicit. Java exceptions deny even when
fail-open is selected. Timeout and core close do not interrupt a blocked host
callback; JNI retains its object until the call returns. Use the bounded native
fd backend normally: no packet-mode JNI filtering is needed. See the
[C ABI ownership and resource bounds](../../docs/ffi.md#optional-tun-flow-admission-abi-111).

Device Gate accepts `--ez probe-only true --ez tun-admission true`. The matching
Device Probe package is the allowed UID. Its `AdmissionProbeActivity` performs a
bounded TCP/UDP echo probe; `bind-device=tun0` uses `SO_BINDTODEVICE`. Install a
second probe under a different application suffix to test an excluded UID and
compare filter-off/filter-on runs. Results are written to the probe's private
`files/admission-result.json`; Device Gate samples record allow/deny counters.

On the tested Samsung SM-A145F (API 35, Linux 5.10), Android also returned
`INVALID_UID` for an included app's TCP socket explicitly bound to `tun0`.
Strict admission consequently rejects that socket too; ordinary included-app
TCP/UDP and its bound UDP traffic passed. Unknown owners cannot safely be
classified as included, so do not enable `allowUnknownUid` to hide this result.
The hook is opt-in and does not change hosts that leave it disabled.
