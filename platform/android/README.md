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
- Android SDK platform 35;
- Android SDK CMake 3.22.1;
- Android NDK 26.3.11579264;
- Rust Android targets for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`.

Check the complete host setup:

```sh
scripts/check-mobile-toolchains.sh --android
```

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

- `XrayCore`: lifecycle, config warnings, packet push/batched poll, stats,
  selection/health snapshots, connection inventory/accounting/close, seven
  typed TUN diagnostic queues, startup probe, runtime profiles, DNS bootstrap
  policy, and socket protection.
- `XrayVlessUrlImporter`: fail-closed VLESS share-link conversion into a
  self-contained mobile TUN profile.
- `XrayVpnService`: reference VPN interface setup and lifecycle coordination.
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

## VLESS share-link import

`XrayVlessUrlImporter.profile(rawUrl)` returns an `XrayImportedProfile` with a
display name, server address, and JSON config ready for `XrayCore.create` or
`XrayVpnService.startXrayTunnel`. It accepts a bare link, a link embedded in
pasted text, or a scheme-less UUID authority. The supported subset matches the
Apple importer: `tcp`/`raw` with REALITY, and `xhttp`/`splithttp` with no
security, TLS, or REALITY. The generated profile uses the TUN inbound, VLESS
`proxy`, private-address Freedom split, and bounded IPv4 fake-IP defaults.

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
`Builder.establish()`, it resolves domain-valued VLESS server addresses and
domain-valued `dns.servers` with Android's system resolver. This includes
`tcp://`, `tcp+local://`, `tls://`, `https://`, `https+local://`, and
`quic+local://` endpoints;
an IP-literal URL needs no
bootstrap lookup. It preserves every usable A/AAAA result in resolver order,
removes duplicates, and writes a nonempty exact `full:` IP array under
`dns.hosts`, then creates the core with `XrayDnsBootstrapMode.StaticOnly`. The
original VLESS address, DNS server URI, and DNS object policy fields remain
unchanged, so TLS/REALITY server names, DNS tags, and domain routing are not
changed.

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
bounded daemon worker pool. DNS preflight, tunnel establishment, core startup,
and the protected `onXrayTunnelStarted` / `onXrayTunnelStartFailed` callbacks do
not run on the main thread. A host that updates UI from either callback must
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
local DNS endpoint, the reference service also installs `198.18.0.1` with
`Builder.addDnsServer`. Apps that override `buildTunnel()` retain control of all
other addresses, routes, and application exclusions. The endpoint accepts UDP
and length-prefixed TCP queries. UDP clients are translated to the configured
TCP, DoT, DoH, or DoQ transport. TCP clients remain length-prefixed for TCP/DoT
and are translated frame-by-frame into bounded HTTP/2 DoH POST requests or
single-stream DoQ exchanges.

The Core-owned destination cache supports global `disableCache`, `serveStale`,
and `serveExpiredTTL`. Stale service requires an explicit bounded 1-through-
86400-second window; zero/unbounded and per-server cache overrides fail config
validation. NXDOMAIN/NODATA are cached for 30 seconds, while transport failures
are never cached.

Fake-IP does not itself provide the real address needed by a Freedom outbound.
When `dns.fakeIp.enabled` is true and `dns.servers` is empty, the reference
service therefore rejects the config before `Builder.establish()` if Freedom is
the default outbound or a TUN-applicable rule can route domain traffic to
Freedom. A VLESS default with IP-only Freedom split-routing rules remains valid,
because domain targets stay on the proxy while literal IP destinations can be
sent directly. Configuring at least one `dns.servers` upstream also makes these
Freedom topologies valid. The preflight never inserts or substitutes a public
DNS server.

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

`devicehost` is a minimal `VpnService` owner. It imports the supported VLESS
share-link subset, immediately converts it to core JSON, encrypts that JSON with
an Android Keystore AES-GCM key, and stores the ciphertext under the app's
no-backup directory. Backup and device-to-device transfer are disabled. The
profile input and clipboard are cleared after import, and structured
`XrayDeviceGate` logs contain only lifecycle state, runtime generation, resource
counts, TUN counters, and sanitized error classes. The app can connect,
disconnect, cancel an asynchronous start from the same service command, close
one inventory snapshot through the public connection-management API, and reset
campaign counters while stopped.

`deviceprobe` has a separate UID, so its traffic traverses `devicehost`'s TUN
instead of being excluded with the VPN owner. Its ordinary loop drives an HTTP
request plus a strict DNS-shaped UDP round trip. Each datagram has a fresh
transaction ID and nonce; success requires an owner-controlled response that
repeats the question and returns the zero-TTL documentation address. The
bounded stress action defaults to 240 HTTP attempts, 480 UDP attempts, and 32
workers. Attempts and concurrency are validated against hard upper bounds, a
second stress request is rejected while one is active, and logs expose only
aggregate counts and elapsed time.

Both activities accept test-automation commands through the string extra
`command`. Host commands are `connect`, `disconnect`, `rapid-stop`,
`close-connections`, `reset`, and `import-pending`; probe commands are `start`,
`stop`, `reset`, and `stress`. Stress overrides use the integer extras
`stress-cycle`, `stress-http-attempts`, `stress-udp-attempts`, and
`stress-concurrency`. Keep raw links and endpoints out of shell history and
logs. For unattended import, place the link in the host app's private
`noBackupFilesDir/profile-import.pending`; `import-pending` encrypts it and
overwrites then deletes the plaintext file.

These applications produce diagnostic rehearsal telemetry. They do not create
the checksum-authenticated six-hour report required by the release-evidence
validator, replace Perfetto, or waive the full scenario matrix in
[mobile testing](../../docs/mobile-testing.md).

## Geodata

Geodata databases are not bundled. The current Kotlin wrapper does not expose a
packaged-assets geodata directory, so configs using `geosite:` or non-private
`geoip:` references require a host-specific JNI/FFI resource-directory
integration. `geoip:private` does not require an external file.

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
