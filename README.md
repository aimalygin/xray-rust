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

Current runtime status: raw TCP VLESS and plain rustls-backed VLESS over TLS are executable for local/test traffic and covered by end-to-end Rust tests with fake VLESS servers. VLESS outbound servers may be configured as IP addresses or, when a resolver is available, domains. REALITY configs can be selected into the transport boundary, prepared from a validated ClientHello provider, and driven through an explicitly injected runtime engine up to DNS/TCP connection setup. `xtls-rprx-vision` has a bounded Tokio stream wrapper, and `VLESS + REALITY + Vision` can be exercised through an explicitly injected REALITY protected-stream engine. The default system dialer still rejects live REALITY networking until a real Chrome/uTLS-compatible TLS completion path exists. Full Xray DNS behavior and local Xray-core interoperability run remain future work.

See:

- [Mobile client core design](docs/superpowers/specs/2026-05-19-mobile-client-core-design.md)
- [Mobile client core implementation plan](docs/superpowers/plans/2026-05-19-mobile-client-core.md)
- [Verification matrix](docs/verification.md)
