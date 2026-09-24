# Pinned native WireGuard benchmark adapters

This Go module pins official `wireguard-go` and gVisor in `go.mod`/`go.sum`.
The root fixture serves interoperability tests. `cmd/bench-client` supplies a
small SOCKS5 front end for the same library so the protocol benchmark can use
the same TCP/UDP application workloads as Xray and sing-box. It is a library
adapter, not an official WireGuard GUI or a kernel WireGuard benchmark.

Build with the pinned Go toolchain, from this directory:

```sh
go test -mod=readonly ./...
go build -mod=readonly -trimpath -o /tmp/native-wireguard-client ./cmd/bench-client
```

The parity preparation script writes a JSON configuration and launches this
binary through `scripts/v07-reference-client.py`. Only loopback SOCKS and
WireGuard fixture addresses are accepted by the launcher. No host tunnel or
route is created. The upstream userspace stack handles IPv4/IPv6, encryption,
TCP congestion control, and UDP. The configured MTU is identical across
comparators. TCP supports concurrent bidirectional copies and half-close.
The benchmark UDP adapter uses one fixed IP destination and one outstanding
request per SOCKS association, matching the echo benchmark. It does not
implement a general purpose multi-destination SOCKS UDP proxy.

Use `scripts/prepare-v07-protocol-parity.py` with explicit binary paths, then
`scripts/run-v07-protocol-parity.py`. The collector records actual executable
hashes and excludes Python configuration translation from measured client CPU.
