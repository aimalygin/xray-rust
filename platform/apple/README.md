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

For local debugging, install the signed debug app into a stable app location
before starting the VPN. macOS discovers Packet Tunnel providers from installed
containing apps; running the app only from Xcode's DerivedData can leave Xcode
waiting for a provider process that macOS never launches.

```sh
platform/apple/scripts/install-macos-debug-app.sh
open "$HOME/Applications/XrayClientMac.app"
```

The helper builds the `XrayClientMac` scheme with signing enabled, copies the
app to `~/Applications/XrayClientMac.app`, and registers it with
LaunchServices. Pass extra `xcodebuild` settings at the end if your local
signing setup needs them, for example:

```sh
platform/apple/scripts/install-macos-debug-app.sh DEVELOPMENT_TEAM=9QF29ADW72
```

After the installed app is running, choose **Debug > Attach to Process by PID or
Name...** in Xcode, enter `XrayClientMacTunnel`, then press Connect in the app.
The Packet Tunnel provider is launched by macOS only after the app starts the
VPN configuration.

If Xcode stays at "Waiting to attach to XrayClientMacTunnel", check the
NetworkExtension logs:

```sh
/usr/bin/log show --last 5m --style compact --predicate \
  'eventMessage CONTAINS[c] "org.texforge.XrayClientMac.Tunnel" OR eventMessage CONTAINS[c] "[XrayRust]"'
```

Messages such as `Found 0 extension(s)` or `The VPN app used by the VPN
configuration is not installed` mean macOS has not discovered the embedded
`.appex`. Quit the DerivedData-launched app, run the installed app from
`~/Applications`, and delete the old "Xray Rust" entry in System Settings > VPN
once if the stale configuration keeps being reused.

## Current Limits

- Provisioning profiles and signing are still local Apple Developer account
  setup, not something this repository can complete automatically.
- The default checked-in profile is a direct `tun` + `freedom` config for smoke
  testing. Real proxy profiles should replace the JSON in the app.
- The Packet Tunnel provider currently uses the packet-boundary pump. The
  fd-backed Darwin utun path remains available through `XrayDarwinTunFileDescriptor`
  for a later native integration.
