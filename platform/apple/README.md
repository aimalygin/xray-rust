# Apple integration

This directory contains a local Swift Package and an Xcode reference app for
iOS, tvOS, and macOS. It embeds the Rust core through the C ABI and a locally
built static XCFramework.

The integration is source-only. `Package.swift` points to:

```text
target/mobile/apple/XrayRust.xcframework
```

Swift Package Manager does not download or build that binary target. Build it
before opening or building the package:

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

- `XrayMobileAdapter`: `XrayCore`, packet batching/pump, stats/events, startup
  probe, and optional Darwin-utun fd discovery.
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

The provider also does not select a public DNS operator. When `dns.fakeIp` is
enabled with a usable IPv4 pool, Network Extension advertises the tunnel-local
`198.18.0.1` interception anchor; it is not contacted as an upstream resolver.
A host can instead set `dnsServers` in provider configuration, or
`xrayDNSServers` in start options, to one IPv4 address string or a non-empty
property-list array of at most eight IPv4 address strings. If neither fake-IP
nor an explicit override is available—or if both modes are configured—tunnel
startup fails before network settings are applied. The provider validates the
full JSON config through the Rust parser before applying those settings. IPv6
resolver overrides are rejected until the provider also installs an IPv6
tunnel route. Invalid explicit values fail startup; start options take
precedence over persistent provider configuration. The first local-anchor
implementation covers ordinary single-question UDP DNS; TCP/53 and a full
upstream DNS proxy remain future work.

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

The Xcode project already references the resulting files under
`platform/apple/XrayClient/dat` from its app and Packet Tunnel targets. Custom
host projects must add verified files to both the containing app resources (for
validation) and extension resources (for runtime loading). The adapter passes
each bundle's resource directory to the core. Review
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

## Current limits

- The package is not published as a remote binary Swift Package.
- Signing/provisioning and App Store policy are not automated.
- The reference UI and provider are integration samples, not a production VPN
  product.
- Real-device lifecycle, network transition, energy, memory, and packet-loss
  behavior must be tested by each host application.
