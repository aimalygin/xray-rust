# Xray-core v26.10.31 migration

Source baseline: v26.10.21 (`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`).
Target: v26.10.31 (`a4a3dff5b20c2faae567b742c172c7b95e75c083`), with Go
1.27.3. Upstream withdrew v26.10.29 in favour of this release. The range has
28 commits; `go.mod` adds `bufbuild/protocompile`, the gRPC/protobuf code
generators as tools, and `pires/go-proxyproto` 0.16.0. uTLS,
`golang.org/x/crypto` and REALITY are unchanged, so the ClientHello oracle
fixtures reproduce byte for byte. Dated benchmark and device reports keep
their original source identities.

## Changes that affect the Rust client

- **Plaintext server exemption narrowed** (`infra/conf/xray.go`,
  `requiresTransportSecurity`). VLESS without TLS or VLESS encryption, and
  Trojan without TLS, now accept an IP server address only when Go's
  `IsPrivate`, `IsLoopback` or `IsLinkLocalUnicast` holds, and a missing
  address requires security. v26.10.21 exempted the whole built-in
  `geoip:private` set, including 0.0.0.0/8, 100.64.0.0/10, 192.0.0.0/24,
  the TEST-NETs, 192.88.99.0/24, 198.18.0.0/15, multicast, broadcast and
  `::`. `TargetAddr::is_xray_plaintext_server_exempt` now follows Go; the
  parser applies it to the VLESS server, the Trojan server and an unencrypted
  XHTTP download address, as before.
- **Built-in private set rewritten** (`common/geodata/consts.go`) from the
  IANA special-purpose registries. Upstream uses it only for Freedom's default
  block-private rule on server inbounds (VLESS, VMess, Trojan, Hysteria,
  WireGuard and Shadowsocks), which xray-rust does not have; its
  `geoip:private` still comes from `geoip.dat`. Routing keeps the existing
  `PRIVATE_NETWORKS` set.
- **XHTTP server `h2Params`** and **OPTIONS uplinks**. The new server option is
  accepted and ignored in client `xhttpSettings` (and `extra`), like
  `serverMaxHeaderBytes`. The server no longer answers every OPTIONS request as
  a CORS preflight, so `uplinkHTTPMethod: "OPTIONS"`, which the client
  already sent, now carries uploads; `xhttp_options_uplink_interop` covers
  packet-up, stream-up and stream-one over H1, plus H2 and H3.
- **Freedom `fragment`/`noises` deprecated** in favour of FinalMask. The
  bounded `fragment` subset parses with the same deprecation warning. Since
  0.10.0 `noises` does too, and the removed `noise` object fails as upstream.
- **MPTCP off by default on listeners** (security release, Linux kernel MPTCP
  issue). xray-rust never enables MPTCP on its SOCKS, HTTP or TPROXY listeners
  and does not accept `tcpMptcp`; no change.

## Reviewed without a change

- WebSocket close frames 1000/1005 now end the stream as `io.EOF`; ours
  already treats a close frame as end of stream.
- The TLS sniffer refuses an empty SNI `host_name`, which QUIC CRYPTO gaps
  produce; ours already returns no domain for an empty name. Upstream also
  joins several Initial datagrams before giving up. xray-rust sniffed only the
  first until 0.10.0, which now reassembles them too, parsing only the
  gap-free part of the CRYPTO stream (see
  [QUIC sniffing](config-compatibility.md#inbounds)).
- DNS outbound drops a hijacked A/AAAA reply larger than its buffer; ours
  bounds the reply and sets TC instead.
- HTTP inbound forwards a short `100 Continue` promptly on its plain-HTTP
  proxy path; the Rust HTTP inbound forwards plain HTTP since 0.10.0 and
  passes one informational head on the same way.
- Not applicable: Darwin keepalive idle/interval swap (no `tcpKeepAlive*`
  support), Darwin and Windows TUN interface binding, WFP leak blocking, Linux
  IPv6 `process` routing, geodata download limits and gzip, inbound module
  initialization order, file-loader extension checks, API commands and
  protobuf regeneration.
- XDRIVE's `s3` service and Google Drive's session slots arrived upstream in
  this range. 0.10.0 brings the XDRIVE client with the `local` service (see
  [XDRIVE](config-compatibility.md#xdrive)); `s3` is read and checked as
  v26.10.31 checks it, with `google-drive` and `template`, and refused when
  the core starts until their HTTP clients land.

## Still out of scope

The v26.10.21 record's stage 2 remains planned separately: MASQUE/WARP,
XDRIVE's `google-drive`, `template` and `s3` services, Lua for
DNS/routing/noise, the newer FinalMask type filter, DNS over HTTPS resolvers
for xdns and realm's UPnP/NAT-PMP `portMapping`.
`localOS` and custom Blackhole responses arrived in 0.10.0, and so did the
mKCP transport with its `mkcp-legacy` masks and the `header-custom`,
`sudoku`, `xmc`, `xdns`, `realm` and `xicmp` masks, and the bridge side of the
VLESS reverse proxy (an outbound's `reverse`). Its portal side stays out of
scope; the legacy root `reverse`, which upstream removed in v26.4.25, fails
parsing with upstream's message.

## Evidence

Local evidence on macOS arm64 (Rust 1.96.0, Go 1.27.3), against a clean
checkout of the target built with Go 1.27.3:

- Go-oracle fixtures: 34 checked, 26 reproduced exactly, 8 apart from the
  date-seeded browser-version draw, none failed.
- Every Xray-pinned step of the `go-oracles` job passes: routing,
  VLESS encryption, XHTTP download, v0.7 and v0.8 protocol primitives,
  Trojan, Shadowsocks 2022 and AEAD, VMess, SOCKS, HTTP, Mux/XUDP, v0.8
  REALITY/split-XHTTP/chain carriers, Hysteria and the WireGuard runtime.
- `xhttp_options_uplink_interop` passes all five cases against v26.10.31 and
  fails against v26.10.21 (its first case times out after 60 seconds).
- The workspace passes `cargo clippy --all-targets --all-features` and its
  tests, except `compat_smoke`, which needs a `./Xray-core` checkout at the pin
  and gets one in CI. The CI script tests pass under Python 3.12, and both
  published migration reports still verify against their v26.10.21 server.

Not run locally: the independent sing-box and native Hysteria/WireGuard
references (no Xray-core in them), the release-gate jobs, and the Apple and
Android builds; CI runs them. Physical-device and performance evidence is not
requalified here.
