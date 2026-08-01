# Changelog

All notable changes will be documented in this file.

The project has not made a stable release. Until the first tagged release,
development changes are recorded under `Unreleased`.

## Unreleased

- Fixed Apple full-tunnel DNS without selecting a public resolver: fake-IP
  profiles now advertise the tunnel-local `198.18.0.1` interception anchor,
  explicit IPv4 DNS overrides remain supported, and profiles with neither
  mode—or both conflicting modes—fail closed before applying network settings.
  Fake-IP DNS now returns NODATA for supported non-A queries sent to the anchor
  instead of forwarding them back into the tunnel.
- Added a bounded tunnel-local UDP/TCP DNS proxy for IP-literal `dns.servers`.
  Upstream attempts follow configured order and use the existing outbound
  router (including VLESS and protected Freedom sockets); failures return
  SERVFAIL or reset TCP without silently selecting a public resolver.
- Fixed a Vision direct-mode read switching the whole connection to cleartext:
  the TLS session now survives a direct read so the uplink stays encrypted
  until Vision switches that direction too, matching Xray-core's per-direction
  reader/writer swap.
- Added the first interop coverage that carries a real TLS session through
  REALITY Vision, exercising the direct-mode path that echo workloads skip.
- Hardened FFI, DNS, logging, geodata, and mobile lifecycle boundaries.
- Added bounded routing and TUN data paths.
- Added reproducible mobile artifact and supply-chain checks.
- Added open-source licensing, security, contribution, and release
  documentation.
- Recorded the pre-release live-profile disclosure in `SECURITY.md` and made
  the history secret scan attribute hits to individual commits.
