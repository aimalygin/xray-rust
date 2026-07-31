# Changelog

All notable changes will be documented in this file.

The project has not made a stable release. Until the first tagged release,
development changes are recorded under `Unreleased`.

## Unreleased

- Fixed the Apple packet tunnel advertising no DNS servers by default, which
  blackholed every DNS query on device (IP-literal traffic kept working) once
  the open-source preparation made `NEDNSSettings` opt-in.
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
