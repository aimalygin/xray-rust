# Android Adapter

This Gradle project is the first Android host adapter skeleton for `xray-ffi`.

Build Rust shared libraries first:

```sh
scripts/build-android-libs.sh
```

The Gradle module reads generated libraries from:

```text
target/mobile/android/jniLibs
```

Provided pieces:

- `XrayCore`: Kotlin wrapper over the JNI bridge.
- `XrayVpnService`: minimal `VpnService` integration with either the default packet pump or `XrayTunBackend.FileDescriptor` for direct Rust fd-backed TUN I/O.
- `xray_mobile_jni.cpp`: JNI bridge to the stable C ABI.
- `VpnService.protect(fd)` wiring through `xray_core_set_socket_protect_callback` before config load.
- `xray_core_set_tun_fd` wiring for passing `ParcelFileDescriptor.fd` to Rust before config load.

A real app still needs VPN consent flow, foreground-service notification behavior, user profile storage, and release packaging.
