# v0.7 upstream protocol support check

Checked on 2026-09-08 (UTC). The owner selected Hysteria and WireGuard for
`v0.7`; the Xray-compatible Hysteria target is **Hysteria 2**. This initial
check establishes upstream availability and the starting points for design.
It does not report an implementation or interoperability run in `xray-rust`.

## References checked

| Reference | Exact commit | Evidence |
| --- | --- | --- |
| Current pinned Xray-core `v26.7.28` | `5ca6f4b7d4dc20a881d4330e498892697627ec0c` | Clean local source checkout; inbound/outbound registration, configuration builders, client/server handlers, transport and dependency inspection |
| Newly published Xray-core `v26.9.8` | `37ceb8b4b65ee919fb772a8034e572f76a6e87a2` | Public GitHub release and commit APIs; published 2026-09-08 at 09:49:08 UTC, marked prerelease; no full source audit in this check |
| Upstream `main` snapshot | `c037ccd98d1a22e7248c8bf4ff617f2e861c4571` | Public commit API and exact-revision `infra/conf/xray.go`; both inbound and outbound registrations remain present |

The [v26.9.8 release](https://github.com/XTLS/Xray-core/releases/tag/v26.9.8)
was the newest entry returned by the public release API during this check.
The moving `main` snapshot is supplementary evidence, not a release contract.
The owner subsequently decided to retain exact `v26.7.28` for this work.

The subsequent [v26.9.8 source delta audit](xray-core-v26.9.8-migration-audit.md)
records the 43-commit comparison, including new WireGuard `remoteDNS`, Hysteria
2.12.2 changes, REALITY key-share requirements and chaining configuration
removal. Its source review is complete; migration and new-version runtime
verification are deferred by the owner's decision. The findings below retain their
original `v26.7.28` identity.

## Confirmed support in the existing baseline

| Protocol | Client/outbound | Server/inbound | Configuration identity |
| --- | --- | --- | --- |
| Hysteria 2 | Present | Present | `protocol: "hysteria"`, `settings.version: 2`; Hysteria transport with `hysteriaSettings.version: 2` |
| Standard WireGuard | Present | Present | `protocol: "wireguard"`; keys, addresses and peers in outbound `settings` |

The pinned [configuration registry](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/infra/conf/xray.go)
registers both directions for both protocols. Current upstream documentation
also lists [Hysteria outbound](https://xtls.github.io/en/config/outbounds/hysteria.html)
and [WireGuard outbound](https://xtls.github.io/en/config/outbounds/wireguard.html).
Server support supplies potential reference peers for our client tests; the
selected Rust/mobile product scope remains client-side.

## Hysteria 2 findings

- The [v26.1.23 release](https://github.com/XTLS/Xray-core/releases/tag/v26.1.23)
  introduced the Hysteria 2 outbound and transport, including UDP hopping and
  Salamander support. They predate our existing baseline.
- The pinned [outbound config builder](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/infra/conf/hysteria.go)
  requires version 2. Hysteria 1 is not the target established by this check.
- Xray separates proxy control from the QUIC transport. The pinned
  [client constructor](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/hysteria/client.go)
  rejects a non-Hysteria transport, and the
  [transport dialer](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/transport/internet/hysteria/dialer.go)
  requires TLS configuration. Authentication belongs in `hysteriaSettings`.
- Congestion, bandwidth and hopping settings use `streamSettings.finalmask.quicParams`:
  `congestion`, `brutalUp`, `brutalDown`, and `udpHop`. The old fields in
  `hysteriaSettings` only produce a migration warning in the inspected builder;
  new fixtures must follow the exact source contract. See the pinned
  [transport builder](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/infra/conf/transport_method.go)
  and [FinalMask configuration](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/infra/conf/transport_finalmask.go).
- The [transport documentation](https://xtls.github.io/en/config/transports/hysteria.html)
  describes compatibility with the official Hysteria 2 implementation when
  paired with the Hysteria proxy protocol. Our release must establish its own
  compatibility evidence for the chosen subset.

Existing Rust QUIC/XHTTP machinery is a possible reuse point. Hysteria-specific
authentication, stream/datagram handling, fragmentation and congestion
behavior still need their own design and validation.

## WireGuard findings

- The pinned [configuration builder](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/infra/conf/wireguard.go)
  exposes `secretKey`, `address`, `peers`, `mtu`, `reserved`, `domainStrategy`,
  and `noKernelTun`. Peers include `publicKey`, `preSharedKey`, `endpoint`,
  `keepAlive`, and `allowedIPs`.
- The [client](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/wireguard/client.go)
  uses `wireguard-go` and a packet network stack. It selects a kernel TUN when
  supported and permitted, otherwise a gVisor-backed userspace TUN. The
  [non-Linux implementation](https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/wireguard/tun_default.go)
  reports kernel TUN support as false.
- These Go implementation dependencies are reference details, not a Rust SDK
  dependency decision. The mobile design must select a Rust WireGuard engine
  and account for packet-to-flow integration, memory, peer state, rekeying,
  endpoint changes, and protected UDP sockets.

## Next design decisions

1. Retain the selected exact `v26.7.28` oracle while implementing both clients;
   follow the [implementation record](v07-protocol-implementation.md).
2. Define the accepted configuration and wire subset for each client, including
   unsupported options and precise validation errors.
3. Select implementation dependencies and module boundaries; define equivalent
   Swift/Kotlin configuration and import support.
4. Pin Xray and native-protocol reference peers, then establish automated
   interoperability, resource budgets, and targeted mobile acceptance cases.

No Rust runtime, SDK API, release version, or oracle pin changes are made by
this support check. The selected release target is recorded in the
[roadmap](roadmap.md#phase-4-v07-hysteria-2-and-wireguard-clients).
