# Initial WireGuard client runtime for v0.7

Implemented 2026-09-08. Xray-core remains **v26.7.28**, commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. GotaTun is pinned to **v0.9.1**,
commit `dab390cdf9dcfb7a6fa85dd8798db92b681ad296`, with the reviewed
[bounded-memory and PSK ownership patches](v07-wireguard-adapter.md). `xray-wireguard` provides a
userspace smoltcp 0.13.1 TCP/UDP interface; no system WireGuard/TUN device or host
route is created by the outbound. Workspace package versions remain 0.6.0 until
release preparation.

The workspace lockfile adds GotaTun's dependencies and advances `socket2` from
0.6.3 to 0.6.5, required by the pinned upstream manifest. Other existing package
versions are retained.

## Accepted contract

The [synthetic JSON example](../tests/fixtures/configs/wireguard.json) is accepted
by the parser, CLI examples/contract, and core. The
[PSK example](../tests/fixtures/configs/wireguard-psk.json) is exported with
`xray-rust config example wireguard-psk`. The
[multi-peer example](../tests/fixtures/configs/wireguard-multi-peer.json) is exported
with `xray-rust config example wireguard-multi-peer` and demonstrates a specific
route over a default peer. These keys are synthetic test data. Typed invalid
configurations also fail core construction before sockets or listeners start.

- 1..8 peers with distinct decoded public keys, a 32-byte device private key,
  and per-peer public keys in the existing validated hex/base64 formats. Each
  peer requires a nonzero-port endpoint IP or ASCII domain and nonempty allowed
  IPs; the aggregate limit is 256 prefixes, including repeated prefixes. Missing
  allowed IPs default to both families' default route. Each peer has its own PSK
  and keepalive setting.
- One or two local addresses, at most one per family. Optional CIDR suffixes are
  validated while preserving the host address. Omitted addresses use Xray's
  `10.0.0.1` and `fd59:7153:2388:b5fd::1` defaults. Unspecified, multicast,
  broadcast, mapped and scoped/link-local IPv6 endpoints/addresses are rejected.
- MTU 1280..1420, default 1420 (`0` also selects the default). `keepAlive` is a
  u16 number of seconds, with `0` disabling persistent keepalive.
- `ForceIP`, `ForceIPv4`, `ForceIPv6`, `ForceIPv4v6` and `ForceIPv6v4` destination
  DNS strategies. Omitted strategy uses `ForceIP`. Local address families and
  allowed IPs constrain destination candidates; literal destinations bypass DNS.
- `noKernelTun` may be a boolean; the implementation always uses userspace.
  `reserved` may be absent, empty or `[0,0,0]`.

Nonzero reserved bytes, obfuscation, `streamSettings`, outbound
chaining, `remoteDNS`, `dialerProxy` and all other unknown settings fail validation.
`peers[].preSharedKey` accepts the same exact 32-byte hex, standard-base64 and
URL-base64 forms as other keys. Omitted, empty and all-zero PSKs mean unset,
matching the pinned Xray/WireGuard behavior. Malformed lengths/encodings and
non-string values, including null, fail validation without echoing the value.
Decoded key storage in our typed model is zeroized on drop and redacted;
contribution/self-peer checks precede engine construction.

The engine uses an owned `PresharedKey` with stable heap storage, cleanup before
deallocation and redacted Debug in peer snapshots and Noise state. Handshake KDFs
borrow the bytes. Clones own independently cleaned storage; replacement/removal
drop the old owner. Input JSON and any retained typed config/client clones still
belong to their caller. No memory-locking or whole-process secret-erasure claim is
made. Mobile bounded mode rejects UAPI and its plaintext key export.

## Ownership and DNS

One lazy device per configured outbound is shared by TCP/UDP, including internal
DNS flows. Concurrent creation uses one admission lock. Only the same socket
protector identity can reuse a cached device. All peers share the device and its
flow/packet budgets. There is one UDP socket per configured endpoint family
(maximum two); the IPv6 socket is explicitly IPv6-only. Both families share one
receive buffer and alternate polling priority. Every socket is protected before
Tokio registration and all handshake/keepalive/data I/O. A protection failure
closes the entire partially built socket set before the device starts.

All peer endpoints are resolved through bootstrap DNS, in configuration order,
before any device sockets are created. The [mobile preflight](v07-mobile-bootstrap.md)
now pins all peer hosts before tunnel setup. A failed/cancelled lookup discards the
whole initialization. Only the first candidate for each endpoint is used;
endpoint failover/re-resolution on network transitions is still
release work. Destination DNS uses the managed resolver and routing policy before
acquiring the device-creation lock, permitting DNS and subsequent traffic to share
the same WireGuard outbound without deadlock. Managed DNS server hostnames use
bootstrap resolution to avoid recursive resolution of the DNS server itself.

A total ten-second open deadline covers destination DNS, admission, endpoint DNS
and TCP establishment. Earlier destination candidates get up to three seconds;
the final candidate can use the remaining total deadline so WireGuard handshake
retransmission can recover after an immediate core restart. UDP pins the first
allowed destination. UDP send has its own ten-second queue deadline. Failed or
cancelled opens release their flow slot; application traffic is not replayed.

Core stop cancels pending resolution/opens and closes initialized devices. Every
injected I/O wait observes cancellation, so stopping cannot wait on a full packet
queue. Native `shutdown().await` also waits for engine worker termination. Last
client-owner drop closes retained flows; dropping one flow preserves other flows.
There is no public runtime suspend/resume API in this increment; a fresh core
creates a new protected device. The lower-level adoption probe separately tests
engine suspend/resume.

SOCKS TCP/UDP, HTTP CONNECT, TUN TCP/UDP, managed DNS and wire-preserving TUN DNS
use the same outbound routing, connection inventory, accounting and host-close
interfaces as existing protocols. Hysteria and WireGuard share the inbound UDP
relay; native per-protocol transports retain their own framing and budgets.

## Peer routing and isolation

Configuration order is preserved when installing peers in GotaTun's shared
cryptokey routing table. The most specific matching `allowedIPs` prefix selects
an outbound peer. For identical normalized prefixes, the last configured peer
owns the prefix, matching the pinned Xray `wireguard-go` insertion behavior.
For example, a later `198.51.100.99/24` replaces the owner of
`198.51.100.1/24`, but does not replace another peer's `198.51.100.7/32`.
IPv4 and IPv6 tables remain distinct.

The same engine table checks the source IP after packet authentication. Only the
peer that owns that source prefix may inject the packet. A broad/default peer
cannot impersonate a peer with a more specific prefix, and a replaced equal-prefix
owner cannot impersonate the new owner. Authorization uses the authenticated key,
not the outer UDP address. The adapter keeps one engine for all peers so this
reverse-path check sees every prefix. No separate adapter routing table is used.

An unreachable selected peer does not fall back to a broader peer. Handshake and
pending-packet budgets stay bounded; other peers can continue while aggregate
flow slots remain. Closing a flow leaves flows through other peers running.
Authenticated endpoint roaming is still limited to the families opened for the
configured endpoint set; network-transition acceptance remains release work.

## Resource limits and packet behavior

| Per configured WireGuard outbound | Bound |
| --- | --- |
| Peers / total configured prefixes | 8 / 256 |
| Outer UDP sockets / receive packet buffers | Up to 2 / 1 |
| TCP flows, including pending opens | 16 |
| UDP flows, including internal DNS | 16 |
| TCP smoltcp buffers | 16 KiB receive + 16 KiB send per flow |
| TCP application bridge | 8 KiB in each direction per flow |
| UDP smoltcp buffers | 8 packet metadata slots and `8 × MTU` bytes in each direction per flow |
| UDP application receive queue | 8 datagrams per flow |
| Command channel | 32 commands; send storage reserved before payload copy |
| Each external IP channel | 8 packets; at most one additional input retained by the stack |

The [engine's separate limits](v07-wireguard-adapter.md#implemented-bounded-memory-increment)
remain enabled. These are bounds on requested storage and counts, not measured
RSS. Runtime metadata, keys, tasks, sockets and allocator overhead are additional.

TCP supports segmentation, backpressure and half-close. Unexpected RST is reported
as a connection-reset error. UDP is unfragmented: maximum payload is `MTU − 28`
for IPv4 and `MTU − 48` for IPv6 (1392/1372 bytes at MTU 1420). Larger sends return
an explicit error before allocating their payload. Fragmented IP replies are not
reassembled. Replies from an endpoint other than the flow's pinned remote are
dropped. UDP queue pressure drops datagrams, preserving bounded storage and other
flows' progress; counters at the core relay measure accepted traffic, not network
acknowledgements.

## Verification

```sh
# Go 1.26.5 on PATH; Rust 1.96.0. Reference is built by the guard.
bash scripts/check-wireguard-runtime.sh
cargo +1.96.0 test --locked -p xray-config -p xray-core-rs -p xray-cli
cargo +1.96.0 clippy --locked -p xray-wireguard -p xray-config -p xray-core-rs --tests -- -D warnings
```

The guard verifies the exact source archive, zero-fuzz patch and regenerated
vendor tree, runs the 89 engine tests and bounded IP probe, then the native and
core runtime tests. Scenarios cover 256 KiB TCP/half-close and UDP through both
inner IP families, SOCKS/HTTP/UDP session sharing and accounting, concurrent opens
and protector isolation, host-close and fresh-core recovery, TUN TCP/UDP and TUN
wire DNS plus routed destination lookup. Deterministic tests cover typed preflight,
DNS timeout/cancellation, flow-budget exhaustion and reclamation, blocked-queue
shutdown, socket-protector rejection, no-route and TCP reset propagation.

The local server binds only loopback. Inner documentation destinations
`198.51.100.7` and `2001:db8::7` are redirected by Xray Freedom to loopback echo
listeners. No packets are sent to those addresses on the host network.

Independent WireGuard/Hysteria servers, broader key/rekey/roaming cases,
mobile SDK profile import, cross-compilation and physical
Apple/Android memory/network acceptance remain release work. No mobile binaries
or stable v0.7 artifacts are published by this increment.

Initial runtime evidence on macOS arm64: all 678 core, 372 config and 26 CLI tests passed;
WireGuard's 86 engine tests, IP probe, four native tests and five live scenarios
passed. All six existing pinned Hysteria scenarios passed after the shared UDP
relay extraction. Strict Clippy, workspace compilation, fixture safety, exact
GotaTun source provenance and cargo-deny checks (advisories, bans, licenses and
sources) also passed locally. Linux CI and
physical-device results are not claimed.

PSK increment: the guarded native suite additionally covers TCP/half-close and
MTU-sized UDP for both inner IP families with PSK, wrong and missing PSK with no
application delivery, timeout/slot reclamation, and a fresh correct-key client
without replaying failed-device pending packets. The core scenario uses PSK
through JSON for SOCKS/HTTP/UDP sharing, accounting, host close and immediate fresh
core recovery. No-PSK scenarios remain in the same guard. Engine tests cover
matching, mismatching, one-sided and rekeyed PSK ownership; parser tests cover key
spellings, unset normalization, bounds and redaction.

Observed locally for the PSK increment: 89 engine tests, 374 config tests,
678 core tests and 26 CLI tests passed; all eight native/core live WireGuard
scenarios passed against the unchanged Xray reference. Strict Clippy passed for
the patched engine and config/client/core tests; the workspace and the engine's
ring-only build passed. The final vendor tree matches the checksum-pinned source
plus both zero-fuzz patches. The PSK example is also a seed in the existing
`config_json` fuzz corpus; no additional fuzz-campaign result is claimed here.

Multi-peer increment: native tests use three independent pinned Xray processes
with different PSKs to identify selected TCP/UDP peers for inner IPv4 and IPv6,
including narrower and identical normalized prefixes and mixed outer families.
Controlled authenticated peers additionally send correctly checksummed replies
with the exact victim flow tuple under the wrong peer key. Every pair is tested
in both families, followed by successful legitimate replies. An unreachable
specific peer is flooded while a default peer progresses; no application payload
falls back to the default peer, and the 16-slot UDP limit remains shared.
Core JSON tests cover two bootstrap-resolved peers, concurrent opens, mixed
endpoint families, SOCKS TCP/UDP, shared accounting, host close and stop.
Validation tests cover the final peer, normalized duplicate keys, the eight-peer
and aggregate-prefix limits, and rejection of the second socket's protection
before either socket sends anything.

Observed locally for the multi-peer increment: 375 config tests, 678 core tests,
26 CLI tests, eight native client/lifecycle/isolation tests and ten pinned-Xray
live WireGuard scenarios passed. The unchanged engine's 89 tests and pressure
probe passed; the source/vendor guard and regenerated Go protocol oracle matched.
Strict Clippy, workspace/all-target compilation (including FFI and fuzz), formatting
and all 13 fixture-safety checks passed. Linux and physical-device acceptance
remain unverified here.
