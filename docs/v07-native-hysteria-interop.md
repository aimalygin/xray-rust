# v0.7 independent Hysteria 2 interoperability

The native reference is the unmodified official
[Hysteria app/v2.12.2](https://github.com/apernet/hysteria/releases/tag/app/v2.12.2),
commit [`619a6f856b69fb7ee6a7a379e810e68b84004605`](https://github.com/apernet/hysteria/tree/619a6f856b69fb7ee6a7a379e810e68b84004605).
It supplements the existing Xray-core v26.7.28 reference; the Xray baseline,
production dependencies and accepted configuration subset are unchanged.

## Reproduction and provenance

```sh
git clone --depth 1 --branch app/v2.12.2 https://github.com/apernet/hysteria.git target/references/hysteria-2.12.2
bash scripts/check-native-hysteria-interop.sh
```

An existing checkout can be selected with `HYSTERIA_CHECKOUT=/absolute/path`.
The script requires the exact commit and a clean repository root, including no
ignored/untracked files that could change a Go build. It builds the full official
application with Go 1.26.5, `GOWORK=off`, `GOENV=off`, cleared build flags and
`-mod=readonly`. The upstream local module replacements bind `core` and `extras`
to that same verified source tree. A second guard checks that the build did not
change the reference. Binaries and generated certificates/configs stay in temporary
directories. Servers listen on loopback and automatic update checks are disabled.

The mandatory `go-oracles` CI job checks out the full commit, tests the source
guard, and runs the native suite. The existing Xray suite remains mandatory.
Each runner selects exactly one reference binary, clearing the other selector;
direct ambiguous selections fail. The seven guard tests cover clean trees,
wrong commits, tracked/staged edits, ignored/untracked Go files and subdirectories.

## Live coverage

The same transport and core scenarios run against both references:

- Authenticated TCP echo, wrong credentials and refused TCP destinations.
- UDP fragmentation in both directions, concurrent sessions, session/stream
  budgets, cancelled receive, flow removal and explicit connection close.
- A fresh connection after close and a TCP stream retaining its connection after
  the client handle is dropped.
- Core SOCKS/HTTP/UDP dispatch, shared protected QUIC sockets, endpoint bootstrap,
  connection inventory/accounting, host flow close, core stop and fresh startup.
- Concurrent core opens and isolation of TLS trust/socket-protection policies.
- Userspace TUN TCP/UDP, routed wire DNS and managed destination resolution.

Two additional native scenarios verify TCP remains usable when the server
advertises UDP disabled, without allocating UDP sessions, and a fragmented reply
at the reference's exact serialization-buffer boundary.

These scenarios use authenticated TLS with a generated test trust root, password
authentication, QUIC v1, unshaped H3 and `ignoreClientBandwidth: true`. They do not
claim Salamander, hopping, Brutal, Realm or full native-option parity.

## Reference differences discovered by the tests

Native v2.12.2 allocates a 4096-byte receive buffer and a **4096-byte serialization
buffer including the Hysteria header** in
[`core/server/udp.go`](https://github.com/apernet/hysteria/blob/619a6f856b69fb7ee6a7a379e810e68b84004605/core/server/udp.go).
[`SendMessage`](https://github.com/apernet/hysteria/blob/619a6f856b69fb7ee6a7a379e810e68b84004605/core/server/server.go)
silently drops a reply that does not fit before attempting fragmentation.
A 4096-byte echo payload therefore reaches the target but never returns. The
supported reply size for this reference is at most
`4096 - (8 + QUIC-varint-length(address-byte-length) + address-byte-length)`.
For the loopback test this is about 4072 bytes, depending on the port length.
Larger native UDP replies are not validated or promised by this increment.

The shared native tests use 4000-byte payloads, which still require several QUIC
datagrams; the existing Xray tests retain 4096-byte payloads. The separate native
boundary test derives the exact header size from the echo address and checks an
echo whose serialized reply is exactly 4096 bytes. No patch is applied to the
reference, and the Rust client's existing payload budget is unchanged.

Native Hysteria rejects a refused TCP destination in the protocol response;
Xray acknowledges first and then closes the data stream. Tests require the correct
failure at each boundary. The native server also closes both relay directions
when one copy finishes; these live cases read replies before sending TCP FIN.
The existing mock tests continue to check the Rust stream's own half-close behavior.

## Acceptance boundary

Observed on macOS arm64, 2026-09-11: all eight native live scenarios, all six
existing Xray live scenarios and all seven source-guard tests passed. Strict
Clippy for `xray-transport` and `xray-core-rs` test targets, Rust formatting,
shell syntax and the scheduled/prerelease workflow guards passed. The workflow
includes the new gate; a remote CI run has not been performed here.

This is host interoperability evidence. [Direct official WireGuard
coverage](v07-native-wireguard-interop.md) is also implemented. Application
integration, physical Apple/Android network transitions and measured resource
recovery remain release work. Reconnecting a fresh client/core is not evidence
of recovery from every server crash or mobile network transition.


## Carrier migration increment — 2026-09-14

The shared reference suite now includes an explicit lost-path relay. It discards
packets on the previous carrier in both directions and uses a separate upstream
UDP socket for each client source port, requiring the reference to recognize a
new QUIC peer address. The same TCP stream and UDP session survive two bursts of
20 rebind requests; each burst invokes protection once and completes exact
payload exchange within an eight-second budget. The client remains live while
the old path is lost, before its 30-second idle timeout.

Both official Hysteria v2.12.2 and pinned Xray v26.7.28 pass this scenario. Core
checks cover a burst through the public API without reconnecting application
flows or resolving DNS again, plus an update during first-socket protection
before authentication/caching completes. The gate now includes the latter core
unit suite. Transport tests check calls from a plain host thread and closure on
replacement protection failure. These loopback cases do not measure cellular
latency or address-family/DNS64 changes; the separate
[iPhone report](device-results/2026-09-14-iphone17-hysteria-rebind/README.md)
records physical network observations.
