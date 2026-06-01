# Apple Client

This Swift Package contains the Apple-side client pieces for embedding
`xray-ffi` in iOS and tvOS apps.

Build the Rust XCFramework first:

```sh
scripts/build-apple-xcframework.sh
```

The package expects:

```text
target/mobile/apple/XrayRust.xcframework
```

Provided pieces:

- `XrayMobileAdapter`: `XrayCore`, `XrayPacketTunnelPump`, and
  `XrayDarwinTunFileDescriptor` wrappers over the stable C ABI.
- `XrayAppleShared`: profile, connection status, runtime stats, and app-to-extension
  message keys shared by the host app and Packet Tunnel extension.
- `XrayAppleClient`: SwiftUI root view, profile persistence, config validation, and
  `NETunnelProviderManager` control-plane wiring.
- `XrayAppleTunnel`: reusable `NEPacketTunnelProvider` implementation that starts
  `XrayCore`, connects it to `packetFlow`, and answers runtime stats requests from
  the host app.
- `HostApp/`: thin app and extension source/entitlement/plist templates for Xcode
  host targets.

Check the package locally with:

```sh
scripts/build-apple-adapter.sh
```

Run Swift package tests with:

```sh
HOME=target/mobile/apple-swiftpm-home \
CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache \
swift test --disable-sandbox --package-path platform/apple
```

## Xcode Host Targets

Create an iOS app target and a tvOS app target that both depend on the local
Swift package product:

```text
XrayAppleClient
```

Use `HostApp/XrayClientApp.swift` as the app entry point for each target.

Create a Packet Tunnel extension target for each platform that depends on:

```text
XrayAppleTunnel
```

Use `HostApp/PacketTunnelProvider.swift` as the extension provider file and
`HostApp/PacketTunnelInfo.plist` as the extension plist shape.

Both the app and extension targets need the Network Extension packet-tunnel
entitlement:

```text
com.apple.developer.networking.networkextension = packet-tunnel-provider
```

The default provider bundle identifier is derived as:

```text
<host app bundle id>.Tunnel
```

The in-app profile editor exposes this value so local development builds can
match whatever bundle identifier Xcode and provisioning use.

## macOS System VPN Target

The Xcode project also contains native macOS targets:

```text
XrayClientMac
XrayClientMacTunnel
```

`XrayClientMac` is a normal macOS app with a main window and a SwiftUI
`MenuBarExtra`. `XrayClientMacTunnel` is the macOS Packet Tunnel extension and
depends on the shared `XrayAppleTunnel` package product.

The default macOS provider bundle identifier follows the same convention as the
iOS and tvOS hosts:

```text
org.texforge.XrayClientMac.Tunnel
```

Build locally without signing checks:

```sh
xcodebuild -project platform/apple/XrayClient/XrayClient.xcodeproj \
  -scheme XrayClientMac \
  -sdk macosx \
  -configuration Debug \
  CODE_SIGNING_ALLOWED=NO \
  build
```

Starting the system VPN requires a signed build with the Packet Tunnel
NetworkExtension entitlement and local user approval in macOS System Settings.

## Current Limits

- Provisioning profiles and signing are still local Apple Developer account
  setup, not something this repository can complete automatically.
- The default checked-in profile is a direct `tun` + `freedom` config for smoke
  testing. Real proxy profiles should replace the JSON in the app.
- The Packet Tunnel provider currently uses the packet-boundary pump. The
  fd-backed Darwin utun path remains available through `XrayDarwinTunFileDescriptor`
  for a later native integration.
