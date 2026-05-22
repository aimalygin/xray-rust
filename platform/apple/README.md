# Apple Adapter

This Swift Package is the first iOS/tvOS host adapter skeleton for `xray-ffi`.

Build the Rust XCFramework first:

```sh
scripts/build-apple-xcframework.sh
```

The package expects:

```text
target/mobile/apple/XrayRust.xcframework
```

Provided pieces:

- `XrayCore`: lifecycle, config loading, TUN packet push/poll, stats, and FFI errors.
- `XrayPacketTunnelPump`: `NEPacketTunnelProvider.packetFlow` bridge to the Rust TUN packet boundary.

A real app still needs a host app plus packet-tunnel extension target, entitlements, provisioning, user profile storage, and platform-specific network settings.
