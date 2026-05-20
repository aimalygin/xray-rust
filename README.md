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

Current runtime status: the raw TCP VLESS path is executable for a local SOCKS5 client and covered by an end-to-end Rust test with a fake VLESS server. TLS, REALITY, and Vision live traffic remain future work and are rejected by the raw runtime path rather than silently falling back to plaintext.

See:

- [Mobile client core design](docs/superpowers/specs/2026-05-19-mobile-client-core-design.md)
- [Mobile client core implementation plan](docs/superpowers/plans/2026-05-19-mobile-client-core.md)
- [Verification matrix](docs/verification.md)
