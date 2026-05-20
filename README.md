# xray-rust

`xray-rust` is a Rust mobile/client core aiming for protocol compatibility with Xray-core. This repository is currently a first mobile/client slice and skeleton, not a full replacement for Xray-core.

The Go checkout in `Xray-core/` is a read-only compatibility oracle. It is ignored by the root Git repository and should be used for reference behavior and oracle tests rather than edited from this workspace.

First implementation targets:

- Xray JSON subset.
- SOCKS5 and HTTP local inbounds.
- Platform-neutral TUN packet API.
- VLESS outbound over TCP.
- TLS/REALITY client mode.
- `xtls-rprx-vision`.
- C ABI for mobile embedding.

See:

- [Mobile client core design](docs/superpowers/specs/2026-05-19-mobile-client-core-design.md)
- [Mobile client core implementation plan](docs/superpowers/plans/2026-05-19-mobile-client-core.md)
- [Verification matrix](docs/verification.md)
