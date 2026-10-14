# UDP noise and Linux TPROXY validation

This implementation extends the 0.8.0 candidate in PR #42. The owner requested
both remaining features before publication. The commit introducing this report
contains the corresponding source, tests and configuration contract; SDK PR #33
must pin that commit (or a later verified candidate) before publication.

## Implemented scope

- Issue #52: bounded FinalMask UDP noise on protected Hysteria2 and XHTTP H3
  sockets. Random/array/string/hex/base64 packets, delay ranges, sliding idle
  reset and ordering around Salamander follow pinned Xray-core v26.7.28.
  Legacy freedom `settings.noises` is not accepted; the issue explicitly allows
  the FinalMask alternative. Existing TLS/REALITY fragmentation remains supported.
- Issue #47: Linux `dokodemo-door` with `followRedirect: true` and
  `sockopt.tproxy: "tproxy"`, IPv4/IPv6 TCP and UDP, original-destination routing
  and source-preserving UDP replies. Socket setup is explicit; the core does
  not install firewall or policy-routing rules. Other platforms reject startup.

See [configuration compatibility](config-compatibility.md) for exact bounds and
operator requirements. TPROXY uses the existing routing, DNS, protocol, traffic
accounting and relay handlers. It does not promise a speed advantage over TUN.
Disabled noise adds no socket wrapper; enabled noise has no background task or
application packet queue. Default Hysteria stream limits are unchanged.

## Local checks

- macOS Rust 1.96.0: 1,836 passing config/transport/core tests, 88 external or
  separately exercised ignored tests; full workspace/all-targets/all-features
  Clippy passed with warnings denied.
- Linux ARM64 Rust 1.96.0: full workspace/all-targets/all-features Clippy passed
  with warnings denied. Ancillary original-destination, truncation and listener
  loop checks passed for IPv4 and IPv6.
- Isolated Linux network: real iptables/ip6tables TPROXY interception passed
  with 1 MiB TCP, 128 UDP datagrams, two destination addresses per family,
  exact upstream destinations, exact UDP reply sources and bounded shutdown.
  This test is now mandatory in the Linux CI job in a disposable network namespace.
- Pinned Xray-core `5ca6f4b7d4dc20a881d4330e498892697627ec0c`: both
  noise/Salamander orders passed with Hysteria hopping and rebind. XHTTP H3
  passed in all three modes. Wire-capture tests separately verify the prelude,
  delay, payload identity, cancellation, sliding reset and WouldBlock retry.
- Configuration contract and workflow-policy checks passed.

These are functional/compatibility checks, not calibrated throughput results.
The prior iPhone Hysteria startup failure and unconfirmed 5% performance gate
remain recorded in [the scoped owner decisions](releases/v0.8.0-owner-decisions.json).
No older device result is relabeled as evidence for this new runtime candidate.
Release CI, exact SDK pins, canonical package artifacts and unrelated release
acceptance requirements still apply.

## Noise lifetime correction

The final source audit found that pinned Xray wraps its hopping connection in
FinalMask once, whereas the initial implementation allocated fresh noise state
for every replacement socket. That could repeat the configured delay on each
hop or host rebind. The corrected Hysteria connection shares its noise progress
and sliding idle deadline across socket replacements. Separate QUIC connections
retain independent state; disabled noise allocates no state.

A live wire-capture regression test counts the literal prelude through automatic
hopping and host rebind while the existing TCP stream continues to exchange
payloads. The same test fails against the initial `34df245` runtime (three
preludes instead of one) and passes with the correction. A paused-clock unit test
also covers positive idle reset across replacement and a fresh connection's
new prelude. Both Salamander orders and all XHTTP H3 modes pass live pinned
interoperability checks with the corrected code. The first implementation's
CI and measurements retain their source identity; the SDK must pin the corrected
commit before publication.

The corrected candidate passes all 1,837 config/transport/core tests (88
separately gated cases ignored), the five focused noise transport tests, all
three live noise interop cases and strict workspace Clippy on macOS.
