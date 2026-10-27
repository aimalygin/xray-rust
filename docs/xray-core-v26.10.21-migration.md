# Xray-core v26.10.21 migration

Source baseline: v26.7.28 (`5ca6f4b7d4dc20a881d4330e498892697627ec0c`).
Target: v26.10.21 (`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`),
with Go 1.27.3. This is a compatibility migration; the existing dated benchmark
and device reports retain their original source identities.

## Stage 1: compatibility and security

- [x] Remove distrusted emSign C1/C3 roots with webpki-roots 1.0.11;
  regression test checks trust-anchor keys. PR #94; 42 transport tests passed.
- [x] Move active oracle modules, CI and interop guards to the target revision;
  regenerate fixtures against that exact, clean source checkout.
- [x] Restrict REALITY profiles and random selection to compatible hybrid
  X25519MLKEM768 ClientHellos; verify Vision and ML-DSA with the new server.
- [x] Support ordinary outbound chaining through `sockopt.dialerProxy` and
  the UDP-hop mask form; document compatibility diagnostics for old inputs.
- [x] Resolve WireGuard destination domains through `remoteDNS` in the tunnel,
  with bounded TTL caching; keep peer endpoint bootstrap separate.
- [x] Add HTTPUpgrade handshake headers and QUIC v2 sniffing; check lifecycle
  regressions for HTTP, XHTTP, Hysteria, Vision, Mux and gRPC.
- [x] Define and test supported QUIC configuration for Hysteria and XHTTP H3;
  explicitly document ChromeParrot fingerprint limitations.
- [ ] Synchronize supported configuration docs, generated contract and mobile
  SDK pin; complete Rust, oracle, live interop and available mobile checks.

## Stage 2: new capabilities

These remain planned separately: MASQUE/WARP, XDRIVE, Lua for DNS/routing/noise,
new XDNS and Finalmask capabilities, localOS, and arbitrary Blackhole replies.
Each needs a supported configuration contract, bounded runtime implementation,
interop tests and mobile integration where relevant. The upstream replacement
of gVisor calls for a behavior/performance comparison with the existing Rust
stack, not an automatic stack replacement.

## Evidence

The target executable was built locally from the exact clean Git checkout with
Go 1.27.3. Completion boxes above distinguish finished work from pending work;
successful compilation alone does not establish interoperability.

Local evidence on macOS arm64 (Rust 1.96.0, Go 1.27.3):

- 32 generated browser/header oracle fixtures: 24 exact, 8 accepted browser-version variations; no failures.
- Routing oracle: 23 cases; independent XHTTP configuration oracle: 33 cases.
- REALITY/ML-DSA65/Vision: six profiles, plain and inner TLS, invalid verify-key rejection.
- VLESS encrypted carrier matrix: 168 profiles, 504 application flows.
- Live VMess, Trojan, SOCKS, HTTP, Mux/XUDP, v0.8 REALITY/split-XHTTP/chains,
  SS2022 restart/roaming and Hysteria suites pass against the target.
- WireGuard remote DNS: positive TTL expiry, negative cache, unrelated-response
  filtering, UDP truncation/TCP fallback and close cancellation pass over a
  real encrypted tunnel. Four existing runtime/lifecycle tests also pass.
- HTTPUpgrade and QUIC v2 RFC 9369 Initial fixture tests pass.

The complete Rust workspace and all-target/all-feature Clippy pass locally.
CI guard checks pass. Native WireGuard recovery/roaming and the updated DNS/TUN
fixture pass as well; the fixture redirects DNS/53 to an unprivileged loopback
server while preserving ordinary destination ports. Mobile checks and PR CI
are being completed on this candidate. Physical-device routing and new performance
numbers have not been requalified; historical reports are not relabeled.
C ABI remains 1.12. QUIC transport is v1/native Quinn TLS, without ChromeParrot;
new protocol families and scripting remain stage 2.
