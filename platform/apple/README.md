# Apple integration

This directory contains a local Swift Package and an Xcode reference app for
iOS, tvOS, and macOS. It embeds the Rust core through the C ABI and a locally
built static XCFramework.

For development inside this source tree, `Package.swift` points to:

```text
target/mobile/apple/XrayRust.xcframework
```

Swift Package Manager does not download or build this local binary target.
Build it before opening or building the package:

```sh
scripts/check-mobile-toolchains.sh --apple
scripts/build-apple-xcframework.sh
```

The XCFramework contains iOS/tvOS device and universal simulator slices plus a
universal macOS `arm64 + x86_64` slice. Rerun the build after changing Rust code
or `xray_ffi.h`; Xcode does not rebuild it automatically. Its slices use
Xcode's static-library-plus-headers layout, so the Rust archive is linked into
the host executable rather than embedded as a runtime framework.

## Deployment targets

The runnable reference app and Packet Tunnel provider support iOS 15+, tvOS
17+, and macOS 13+. These are the deployment targets checked into the Xcode
project and match the availability annotations on the client/provider APIs.

The lower-level Rust XCFramework is built with iOS 15, tvOS 14, and macOS 11
deployment targets. `Package.swift` declares iOS 15, tvOS 17, and macOS 11 so
the lower-level `XrayMobileAdapter` and `XrayAppleShared` products remain usable
on macOS 11 and 12. The macOS `XrayAppleClient` UI and
`XrayAppleTunnel` provider entry points are available from macOS 13.

## Run the reference app

```sh
open platform/apple/XrayClient/XrayClient.xcodeproj
```

In Xcode:

1. copy `XrayClient/Config/Local.xcconfig.example` to
   `XrayClient/Config/Local.xcconfig` and set `XRAY_BUNDLE_ID_PREFIX` to a
   prefix you own plus `DEVELOPMENT_TEAM` to your Apple Developer team — every
   target derives its identifier from that prefix, and the file is git-ignored
   so it never lands in a commit;
2. choose `XrayClient`, `XrayClientTv`, or `XrayClientMac`;
3. select a matching simulator/device or “My Mac”;
4. keep the profile's provider bundle identifier aligned with the extension;
5. run the containing app.

Without `Local.xcconfig` the project still builds unsigned under the
placeholder `org.example` identifiers, which is how CI builds it.

The local package dependency resolves the already-built XCFramework
automatically. A UI-only simulator run can exercise profile editing and config
validation. Starting a real system tunnel requires valid signing, the Packet
Tunnel Network Extension entitlement, provisioning, and platform user approval.

Do not use the synthetic test credentials as a live profile. Import or enter a
profile you control without committing it to the repository.

## Swift Package products

- `XrayMobileAdapter`: `XrayCore`, atomic routing-policy replacement and
  snapshots, packet batching/pump, stats/events, startup probe, and optional
  Darwin-utun fd discovery.
- `XrayAppleShared`: profile/config models, secure config storage, sanitized
  logging, and app-to-extension message keys.
- `XrayAppleClient`: SwiftUI profile editor and `NETunnelProviderManager`
  control plane.
- `XrayAppleTunnel`: reusable `NEPacketTunnelProvider`.

The provider prefers direct borrowed Darwin-utun fd I/O when enabled and a
usable fd can be discovered. It falls back to `NEPacketTunnelFlow` packet
pumping otherwise.

## Network privacy defaults

The reference provider does not contact a connectivity-check service during
startup. A startup probe is strictly opt-in: set `startupProbeEnabled` to
`true` and provide an explicit `http` or `https` `startupProbeURL` in the
provider configuration. Per-start overrides use
`xrayStartupProbeEnabled` and `xrayStartupProbeURL`. Enabling a probe without a
valid URL, or with a timeout outside `1...60000` milliseconds, fails tunnel
startup instead of selecting a third-party endpoint.

The provider also does not select a public DNS operator. Network Extension
advertises the tunnel-local `198.18.0.1` interception anchor when
`dns.fakeIp` is enabled with a usable IPv4 pool, or when `dns.servers` contains
any supported nonempty upstream list. Classic IPv4 and IPv6 literals use port
53; socket-address and `domain:port` strings can select another nonzero port.
The strict `tcp://host[:port]` form selects routed DNS-over-TCP, so normal
Freedom/VLESS outbound selection and an object server's `tag` still apply.
`tcp+local://host[:port]` instead opens a provider-local/system TCP socket and
bypasses the Xray router; Network Extension's provider-process routing policy
keeps that connection off the provider's own tunnel interface. The anchor is
handled inside the tunnel and is not itself an upstream resolver. VLESS
receives routed domain upstreams unchanged for remote resolution. Freedom uses
the separate mobile `StaticOnly` bootstrap populated during the provider
preflight described below. Domains restored from fake-IP and sent through
Freedom resolve through the routed `dns.servers` list without a system-DNS
fallback.

`tls://host[:port]` uses the same routed carrier with certificate-verified DoT
and defaults to port 853. `https://host[:port][/path][?query]` adds
certificate-verified HTTP/2 DoH over the routed carrier; `https+local://...`
uses the provider-local protected socket instead. HTTPS defaults to port 443
and path `/`.
`quic+local://host[:port]` uses a protected provider-local UDP socket with
QUIC v1 and exact ALPN `doq`; it defaults to port 853 and is authority-only.

Stream URL schemes are case-insensitive. TCP/TLS intentionally accept only an
authority: IPv4, a domain, or bracketed IPv6, followed by an optional nonzero
port. HTTPS additionally accepts an ASCII path/query but rejects userinfo,
fragments, backslashes, unbracketed IPv6, whitespace/control characters, and
malformed brackets before network settings are applied. In an
object server, the URL's embedded/default port is authoritative. A sibling
`port` is still validated as an integer from 0 through 65535 and preserved, but
is ignored when selecting that endpoint. A TCP URL pointing directly to, or
pinning a domain onto, a tunnel-owned address is rejected on every URL port;
classic non-URL servers retain their legacy port-53 check.

Fake-IP without `dns.servers` is accepted only when TUN domain traffic cannot
select Freedom. Before applying Network Extension settings, the provider
rejects a Freedom default outbound and any TUN-applicable Freedom rule that is
not strictly IP-only. A VLESS default outbound is valid, and private/CIDR
Freedom rules containing `ip` selectors but no domain selectors remain valid.
This prevents a restored fake-IP domain from reaching Freedom without a routed
resolver.

A host can instead set `dnsServers` in provider configuration, or
`xrayDNSServers` in start options, to one IPv4 or IPv6 address string or a
non-empty property-list array of at most eight IP address strings. When
fake-IP is disabled, this explicit setting takes precedence over JSON
`dns.servers`.
Combining an explicit host override with fake-IP, or configuring none of the
supported modes, fails before network settings are applied. The provider
validates the full JSON config through the Rust parser before applying those
settings. The provider installs IPv4 and IPv6 default routes; the tunnel IPv6
interface uses `fd00:7872::2/128`, while the DNS interception anchor remains
IPv4 `198.18.0.1`. Invalid explicit values fail startup, and start options take
precedence over persistent provider configuration. The local anchor proxies
both UDP and TCP/53. A `tcp://` upstream uses the configured outbound route;
`tcp+local://` is the explicit routing exception described above. UDP client
messages are translated onto configured TCP, DoT, DoH, or DoQ upstreams. TCP
clients remain length-prefixed for TCP/DoT and are translated frame-by-frame
into bounded HTTP/2 DoH POST requests or single-stream DoQ exchanges. Fake-IP
profiles keep local synthesis precedence for every transport at the anchor.

The Core-owned destination cache supports global `disableCache`, `serveStale`,
and `serveExpiredTTL`. Stale service requires an explicit bounded 1-through-
86400-second window; zero/unbounded and per-server cache overrides fail config
validation. NXDOMAIN/NODATA are cached for 30 seconds, while transport failures
are never cached.

The checked-in `directTunConfigJSON` intentionally has no fake-IP DNS. Direct
profiles are not automatically migrated to fake-IP; when used unchanged they
require an explicit host `dnsServers` or `xrayDNSServers` override. The
reference UI's **Default DNS** and **DNS Proxy** test overrides described below
are explicit alternatives. Imported VLESS profiles keep VLESS as the default
outbound and only bypass private IP ranges through Freedom; the importer does
not add domain-based captive-portal bypasses.

The VLESS URL importer accepts raw/TCP + REALITY links and `xhttp`/`splithttp`
links with `security=none`, TLS, or REALITY. XHTTP `host`, `path`, and `mode`
remain outer settings. TLS imports preserve `sni`, `fp`, comma-separated
`alpn`, and a valid legacy `allowInsecure`; absent `sni` and `fp` use the share
format defaults (the remote host and `chrome`). REALITY imports preserve
`pbk`, `fp`, `sni`, `sid`, `spx`, and `pqv`; an absent `sni` also defaults to
the remote host. Vision flow is rejected for every XHTTP security mode because
the runtime only supports it on raw/TCP.

An XHTTP `extra` JSON object is decoded from the usual single URL encoding or
one additional percent-encoding layer and passed to the core for Xray-compatible
replacement. The importer caps `extra` at 64 KiB, never logs its contents, and
does not recursively percent-decode it. Duplicate security-critical query
fields and non-empty unsupported `pcs`, `vcn`, or ECH settings fail closed
rather than producing a partial config; explicitly empty values are harmless
no-ops. Raw/TCP + `security=none` remains rejected.

The reference XrayClient UI includes a sample-only **DNS Testing** section.
`Config JSON` adds no DNS override and leaves DNS behavior to the stored JSON.
`Default DNS` is an explicit convenience preset for manual testing: it creates
FakeDNS with `tcp://1.1.1.1`, and is selected for a newly created sample profile.
Legacy and explicitly constructed profiles retain `Config JSON` semantics.
`FakeDNS` and `DNS Proxy` instead build a temporary effective `dns` object from
the selected transport and user-supplied upstream.
All generated modes apply only to the next connection; the JSON editor and
saved credential-bearing config are not rewritten. Existing `dns.hosts` entries
and the top-level `dns.tag` are retained so bootstrap pins and routed-DNS
outbound selection are not discarded. The transport picker covers classic UDP
with TCP truncation retry, routed `tcp://`, and provider-local `tcp+local://`.
The upstream is optional for manual FakeDNS when restored domains cannot select
Freedom, and required for DNS Proxy. Supplying it in FakeDNS mode enables routed
resolution when a restored domain is sent through Freedom. Changes take effect
after reconnecting; `TCP (local)` intentionally bypasses Xray routing and
therefore is not a DNS-leak-safe mode.
The selected test mode, transport, and trusted upstream remain selected when a
new VLESS URL is imported; choose `Config JSON` to disable the override.

Before applying Network Extension DNS and routes, the provider bootstraps every
domain VLESS server and every domain-valued classic, TCP, DoT, DoH, or DoQ DNS
endpoint. An IP-literal stream URL needs no system lookup. URL modes use their
embedded/default port for endpoint safety checks and pin a domain host
into `dns.hosts`; the original server URI, object policy fields, and `tag` stay
unchanged. Existing bare or `full:<domain>` exact `dns.hosts` mappings are
canonicalized and followed for at most eight mapping steps; cycles and deeper
chains fail tunnel startup. When an alias chain has no terminal mapping, the
provider resolves that terminal domain with the then-current system resolver
and writes every ordered A/AAAA result into a canonical exact IP array.
Existing terminal IP arrays are retained and deduplicated in order.
IPv4-mapped IPv6 carrier addresses are normalized to IPv4 so Rust socket
selection and Apple `/32` exclusions stay aligned.
DNS64-synthesized IPv6 results are accepted on IPv6-only networks. The original VLESS address string and
`NETunnelProviderProtocol.serverAddress` remain metadata rather than being
replaced by one candidate, so exact-domain routing, SNI, and other metadata do
not change.

The provider collects every IPv4/IPv6 outer carrier endpoint from VLESS
servers, their existing bootstrap mappings, and the configured server address.
Before creating the Rust core it installs an excluded `/32` or `/128` route for
each carrier candidate alongside both default tunnel routes. `dns.servers`
domains, including local TCP URL hosts, are still pinned for fail-closed
bootstrap, but their resolved addresses are not globally excluded. Routed DNS
remains subject to outbound policy; a `tcp+local://` socket bypasses that policy
and relies on the Network Extension provider-process routing policy. A carrier
resolution containing a tunnel-owned DNS or interface address fails closed
before network settings are installed. An explicitly enabled
`sockopt.happyEyeballs` policy can then race the pinned raw TCP candidates and
perform one TLS/REALITY handshake on the winner; `tryDelayMs: 0` leaves that
race disabled by default. Resolution failure fails tunnel startup. This
pre-bootstrap happens before the local anchor exists; after Rust starts, mobile
`StaticOnly` does not call the system resolver.

Bootstrap preflight runs asynchronously with one absolute five-second deadline
shared by validation and every required lookup. Timeout, provider stop, and a
superseding start each complete the affected start request exactly once; a late
resolver result is generation-guarded and cannot apply Network Extension
settings or create a runtime. Because Darwin `getaddrinfo` is not
interruptible, all lookups use one process-wide gated worker. A timed-out or
cancelled lookup may keep that worker occupied until the system call returns,
but it cannot block provider lifecycle callbacks or create additional resolver
threads. Starts made while the worker remains occupied are not queued behind
it and expire on their own overall deadline.

## Host target requirements

Both the containing app and Packet Tunnel extension need the appropriate
Network Extension capability. The extension entitlement value is:

```text
com.apple.developer.networking.networkextension = packet-tunnel-provider
```

The default provider identifier convention is:

```text
<containing-app-bundle-id>.Tunnel
```

The checked-in `HostApp/` directory contains thin entry-point, entitlement, and
extension plist templates for custom host projects. The checked-in
`XrayClient/XrayClient.xcodeproj` is the runnable reference project.

Profiles are metadata in preferences while credential-bearing config JSON is
stored in the Data Protection Keychain. Host applications remain responsible
for their own threat model, access controls, backup policy, and migration
testing.

## Geodata resources

`geosite.dat` and `geoip.dat` are not distributed with the repository. If a
profile uses geodata routing, install the pinned, checksum-verified sample
assets:

```sh
scripts/fetch-geodata.sh
```

The checked-in reference project adds the resulting files under
`platform/apple/XrayClient/dat` to both the app and Packet Tunnel bundles. When
no explicit shared directory is configured, the adapter retains this behavior
and uses `Bundle.main.resourceURL`.

Custom hosts that download or share geodata should instead give the containing
app and Packet Tunnel extension the same App Group entitlement:

```xml
<key>com.apple.security.application-groups</key>
<array>
    <string>group.com.example.xray</string>
</array>
```

Publish each verified generation into its own real directory inside that
container, for example:

```text
Library/Application Support/XrayGeodata/<version>-<sha256>/
  geosite.dat
  geoip.dat
```

Set both provider-configuration keys to select that exact generation:

```swift
providerConfiguration[
    XrayTunnelProviderMessage.providerGeodataAppGroupIdentifierKey
] = "group.com.example.xray"
providerConfiguration[
    XrayTunnelProviderMessage.providerGeodataRelativeDirectoryKey
] = "Library/Application Support/XrayGeodata/<version>-<sha256>"
```

Both values are required together. The relative path must already exist, stay
inside the App Group, contain no empty, `.` or `..` components, and contain no
symbolic-link directory components. Invalid explicit settings fail before
Packet Tunnel network settings are applied.

Download into a sibling staging directory, verify the expected checksums, and
atomically rename the completed directory to its final generation name. Treat
published generations as immutable: do not replace their files or point the
provider at a mutable `current` symlink. Retain the selected generation until
the tunnel has stopped and no saved provider configuration refers to it.

The App Group is a trusted cooperation boundary. The adapter validates the
selected path when the tunnel starts, but it does not hold directory file
descriptors or defend against another App Group writer replacing a published
generation concurrently. Under the host-enforced immutability and retention
contract above, preflight and runtime select the same generation path.

Host-side validation must use the same published directory exclusively so it
cannot mix generations with bundle resources:

```swift
try XrayConfigValidator.validate(
    configJSON,
    geodataSearchDirectory: publishedGenerationURL,
    geodataSearchPolicy: .exclusive
)
```

`XrayClientViewModel` accepts the same `geodataSearchDirectory` and
`geodataSearchPolicy` arguments for host-side validation only. They do not
modify the Packet Tunnel provider configuration; inject a custom tunnel
controller that writes the two App Group keys above when using a shared
generation. Review
[third-party notices](../../THIRD_PARTY_NOTICES.md) before redistribution.

Profiles without `geosite:` or non-private `geoip:` references do not need
these files. `geoip:private` is built in.

## Build and test

Build the package against the generated XCFramework:

```sh
scripts/build-apple-adapter.sh
```

Verify linking for iOS/tvOS device and simulator architectures and both macOS
architectures:

```sh
scripts/check-apple-adapter-link.sh
```

Run Swift tests:

```sh
HOME=target/mobile/apple-swiftpm-home \
CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache \
swift test --disable-sandbox --package-path platform/apple
```

CI also downloads the pinned geodata into the ignored `dat` directory and
builds the shared `XrayClient`, `XrayClientTv`, and `XrayClientMac` schemes for
generic simulators or macOS with code signing disabled. This verifies that a
clean checkout can compile the complete reference hosts and their embedded
Packet Tunnel extensions without requiring an Apple Developer account.

See [mobile testing](../../docs/mobile-testing.md) for the full artifact matrix.

## macOS Packet Tunnel debugging

macOS discovers Packet Tunnel extensions inside installed, signed containing
apps. A copy that exists only under DerivedData may not be selected reliably.
For a local signed debug build:

```sh
platform/apple/scripts/install-macos-debug-app.sh \
  DEVELOPMENT_TEAM=<YOUR_TEAM_ID>
open "/Applications/XrayClientMac.app"
```

Attach Xcode manually to `XrayClientMacTunnel`, then press Connect in the app.
If the provider is not discovered, verify that only the intended app copy is
registered and that both targets use matching signing and bundle identifiers.

Prebuilt, versioned XCFramework releases for remote Swift Package Manager
integration are published from
[`xray-rust-mobile`](https://github.com/aimalygin/xray-rust-mobile).

## Current limits

- The local package in this repository expects a locally built XCFramework;
  use `xray-rust-mobile` for remote binary distribution.
- Signing/provisioning and App Store policy are not automated.
- The reference UI and provider are integration samples, not a production VPN
  product.
- Real-device lifecycle, network transition, energy, memory, and packet-loss
  behavior must be tested by each host application.
