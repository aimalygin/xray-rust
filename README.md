# xray-rust

`xray-rust` is a Rust mobile/client core aiming for protocol compatibility with Xray-core. This repository is currently an early mobile/client slice, not a full replacement for Xray-core.

The Go checkout in `Xray-core/` is a read-only compatibility oracle. It is ignored by the root Git repository and should be used for reference behavior and oracle tests rather than edited from this workspace.

First implementation targets:

- Xray JSON subset.
- SOCKS5 and HTTP local inbound parsing.
- Platform-neutral TUN packet API.
- Executable SOCKS5 -> VLESS over raw TCP data path for local/test traffic.
- TLS/REALITY client mode.
- `xtls-rprx-vision`.
- C ABI for mobile embedding.

Current runtime status: local SOCKS and HTTP CONNECT inbounds can route traffic to Freedom direct egress or VLESS outbounds over TCP, TLS, TLS+Vision, and REALITY+Vision for the supported client-side profile. Process-level tests exercise the `xray-rust` binary against local echo targets and the cloned Go Xray-core oracle, including REALITY+Vision. The mobile FFI exposes lifecycle, structured errors, socket-protection callback wiring, a platform-neutral TUN packet boundary, and optional fd-backed TUN I/O for Android and advanced Darwin integrations. The TUN runtime is runnable for TCP, UDP, VLESS UDP, Vision XUDP, and ICMP echo through checked-in Apple `NEPacketTunnelProvider` and Android `VpnService` adapter skeletons. Apple iOS/tvOS and Android artifact scripts can build `XrayRust.xcframework` and Android `jniLibs` on a provisioned macOS host. Full Xray DNS behavior, geosite/geoip data loading, and broad protocol parity remain future work.

See:

- [Mobile client core design](docs/superpowers/specs/2026-05-19-mobile-client-core-design.md)
- [Mobile client core implementation plan](docs/superpowers/plans/2026-05-19-mobile-client-core.md)
- [Mobile testing](docs/mobile-testing.md)
- [Benchmarks](docs/benchmarks.md)
- [Verification matrix](docs/verification.md)
