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

- `XrayCore`: lifecycle, config loading, TUN packet push/poll, optional fd-backed TUN registration, stats, and FFI errors.
- `XrayPacketTunnelPump`: `NEPacketTunnelProvider.packetFlow` bridge to the Rust TUN packet boundary.
- `XrayDarwinTunFileDescriptor`: helper for advanced integrations that discover an existing utun fd and pass it to `XrayCore` with `XRAY_TUN_FD_PACKET_FORMAT_DARWIN_UTUN`.

A real app still needs a host app plus packet-tunnel extension target, entitlements, provisioning, user profile storage, and platform-specific network settings.
