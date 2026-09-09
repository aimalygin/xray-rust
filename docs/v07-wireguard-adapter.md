# WireGuard adapter boundary for v0.7

Reviewed 2026-09-08. Xray-core remains v26.7.28,
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

## Concrete engine candidate

Use **GotaTun v0.9.1**, commit
`dab390cdf9dcfb7a6fa85dd8798db92b681ad296`, as the vendored runtime engine
reference. The [immutable release](https://github.com/mullvad/gotatun/releases/tag/v0.9.1)
was published 2026-08-27. The production dependency now uses this exact vendored source plus the bounded-memory
patch below; its manifest normalization and source comparison are reproducible.
See [provenance](../vendor/gotatun/XRAY-PATCH.md), retained MPL/BSD notices and the
[runtime contract](v07-wireguard-runtime.md). This is not a completed cryptographic audit.

The exact release offers `ring` as an AEAD backend, with
`default-features = false` to avoid its default `aws-lc-rs` backend. `device`
enables the async runtime and socket support; `tun`, DAITA, PCAP and UAPI listeners
are unnecessary for a mobile client adapter. Declared MSRV is Rust 1.95; the core
uses 1.96. Platform declarations include Apple and Android library use, which is
not a substitute for our cross-compilation and physical-device tests.

Local build evidence on macOS arm64: the exact source archive above passed
`cargo +1.96.0 check --locked -p gotatun --no-default-features --features ring,device --lib`
using its own lockfile in an isolated directory. This initial evidence is supplemented by the TCP/UDP/core runtime tests below.

Source paths below refer to that exact commit:

- [`device/builder.rs`](https://github.com/mullvad/gotatun/blob/dab390cdf9dcfb7a6fa85dd8798db92b681ad296/gotatun/src/device/builder.rs):
  `DeviceBuilder::with_udp`, `with_ip_pair`, `with_private_key`, `with_peers`,
  `suspended` and async `build` permit injected transports without creating a
  system TUN device or starting a UAPI server.
- [`udp/mod.rs`](https://github.com/mullvad/gotatun/blob/dab390cdf9dcfb7a6fa85dd8798db92b681ad296/gotatun/src/udp/mod.rs):
  `UdpTransportFactory::bind` can own bind/protect/nonblocking conversion. The
  initial bind and every resume/rebind must invoke our existing socket protector
  before any handshake or keepalive. Implement bounded `UdpSend`/`UdpRecv` on this
  socket; do not select `with_default_udp` and bypass protection.
- [`tun/mod.rs`](https://github.com/mullvad/gotatun/blob/dab390cdf9dcfb7a6fa85dd8798db92b681ad296/gotatun/src/tun/mod.rs):
  `IpSend`/`IpRecv` carry complete validated IP packets; `MtuWatcher` supplies MTU
  updates. Connect these through bounded queues to a separate smoltcp client
  interface. The core already uses smoltcp 0.13.1; it needs an outbound client
  adapter, not reuse of a VPN inbound flow as though it were a remote socket.
- [`device/mod.rs`](https://github.com/mullvad/gotatun/blob/dab390cdf9dcfb7a6fa85dd8798db92b681ad296/gotatun/src/device/mod.rs):
  async `stop`, `suspend`, and `resume` own background tasks. Resume clears old
  sessions and rebinds sockets. Preserve this ownership in the core runtime;
  cancellation of a start/stop future must not strand detached workers.

Prefer the device adapter for the first prototype, preserving the engine's
handshake, rate-limiter, rekey, replay and peer-validation paths. Its lower-level
`noise::Tunn` API also exists, but wrapping it directly would make our code own
receiver-index demultiplexing, cookie/rate checks, timers, queued-packet draining,
endpoint roaming and authenticated source validation. That is a materially larger
implementation and review surface.

## Memory and contract work before adoption

The device has a fixed `MAX_PACKET_BUFS = 4000`, reused for packet-pool and I/O
buffer capacities. The pool allocates lazily but can allocate additional buffers
when empty; its capacity is a recycling limit, not a hard total-memory limit.
The isolated prototype now applies the bounded-memory patch described below.
Production now enables that patch; physical-device memory acceptance remains a separate gate.
Do not infer a process memory ceiling from a pool capacity or from bounded external
channels.

Prototype one peer first, then test multiple peers. Existing Rust `PeerRoutes`
matches the pinned wireguard-go longest-prefix and identical-prefix precedence.
Compare GotaTun's actual device ordering with those fixtures before accepting
overlapping/equal prefixes across peers; reject unsupported ambiguous configs
explicitly until equivalent behavior is established. Never substitute a UDP
endpoint address for authenticated peer identity when checking decrypted sources.

Endpoint bootstrap DNS stays outside the tunnel, under the selected core resolver
and protected-socket policy. Target DNS follows the outbound's tunnel/routing
contract. Do not import v26.9.8-only `remoteDNS` or `dialerProxy` options. Standard
WireGuard is the initial protocol: Xray reserved-byte extensions and nonstandard
obfuscation are separate explicitly rejected options until implemented and tested.

The initial runtime has real TCP/UDP coverage against the pinned Xray WireGuard
server. Before release, extend it against an independently pinned WireGuard
reference. Required cases include wrong keys/PSK, source spoofing between peers,
allowed-IP overlap, authenticated roaming, replay, keepalive/rekey, IPv4/IPv6,
MTU/fragmentation, exhausted queues, socket-protector rejection, cancellation,
suspend/resume and repeated stop/start. No crypto protocol is implemented anew in
this repository.


## Executed IP/UDP adoption probe

The [standalone probe](../tools/wireguard-adapter-prototype/main.rs) now implements
GotaTun's `UdpTransportFactory`, `UdpSend`/`UdpRecv` and `IpSend`/`IpRecv` boundary
against checksum-pinned v0.9.1 sources plus the
[bounded-memory patch](../tools/wireguard-adapter-prototype/patches/gotatun-mobile-memory.patch).
Its external IP channels hold eight packets,
MTU is 1420, socket creation has an explicit rejection gate before nonblocking
conversion/I/O, and resume recreates that gated socket. It uses one peer and
synthetic test keys. The gate is a test double at the future host-protection call
site; the production adapter now invokes the actual `SocketProtector`.

The [guarded script](../scripts/check-wireguard-adapter-prototype.sh) downloads the
exact GotaTun commit archive and verifies SHA-256
`2a2745851b2989b6d388330b3b9ccfa180ecd12260014b708e01489abae02722`, then builds the
probe using that archive's unchanged Cargo.lock with `ring,device` and no default
features. It applies the local patch with zero fuzz, runs the library tests, verifies
the clean exact Xray checkout and builds the reference itself.
Upstream's Cargo example runner invokes sudo for system TUN examples; this script
overrides the runner for library tests, then builds and executes its injected probe
directly. It creates
no system TUN or routes and keeps reference configuration in a private temporary
directory, removed on exit. The same guard verifies the production vendor tree
and runs native TCP/UDP and core integration tests.

Observed locally on macOS arm64, 2026-09-08: the guarded script passed encrypted
IPv4 UDP exchange, a 1392-byte UDP payload (1420-byte inner IP packet), replay
rejection, unauthorized inner-source rejection, suspend/resume followed by a new
handshake and data exchange, socket release after stop, and rejection before the
first send. A loopback echo server observes that replay/spoof probes do not
arrive. These are point scenarios, not a comprehensive replay/crypto audit.

Pinned Xray's gVisor stack rejects inner IP packets addressed to loopback as
martian traffic. The fixture therefore sends to documentation address
`198.51.100.7` inside WireGuard, with Xray Freedom redirecting it to
`127.0.0.1` at the original destination port. No traffic is sent to that
documentation address over the host network. The response retains the inner
virtual destination as its source.

Reproduce with Go 1.26.5 on PATH and Rust 1.96.0:

```sh
bash scripts/check-wireguard-adapter-prototype.sh
```

`GOTATUN_ARCHIVE` optionally supplies a local archive, still verified by checksum;
`WIREGUARD_PROBE_TARGET_DIR` selects a reusable build cache. Reference binaries
cannot bypass the script's checkout/version guard.

## Implemented bounded-memory increment

The local patch adds opt-in `DeviceBuilder::with_limits(DeviceLimits::mobile())`.
Its packet allocation and transport changes leave the Noise/WireGuard algorithms,
crypto dependencies, upstream revision and lockfile unchanged. The patch and tests
are applied to the vendored production engine as well as the isolated probe; see the
[patch provenance](../tools/wireguard-adapter-prototype/patches/README.md).

| Resource | Mobile limit |
| --- | --- |
| Each internal I/O queue | 16 packets |
| Shared packet reservations | 64, including 8 reserved for handshake/cookies |
| Recycling cache | 32 buffers of 4096 bytes |
| Pending handshake backlog | 16 packets across all peers |
| Pending backlog per peer | 8 packets and 12 KiB |
| Inner IP / outer UDP admission | 1420 / 1500 bytes |
| Configured peers / total allowed-IP prefixes | 8 / 256 |
| Handshake source-IP counters | 128 entries |

Each reservation accounts for a normalized allocation of up to 4096 bytes and a
simultaneously live encryption copy of up to 4096 bytes. Thus the reservation
budget is **512 KiB**, plus up to **128 KiB** of cached pool storage. These are
bounds on requested packet-buffer storage, **not process RSS**. Fixed receive and
handshake working buffers, allocator metadata, queue/table metadata, crypto state,
tasks, caller adapters, sockets and the userspace TCP/UDP stack require
separate accounting and measurement. No whole-device memory ceiling is claimed.

Admission copies externally supplied packets into a normalized allocation, so a
small slice cannot retain a huge backing allocation. Reservations survive IP/WG
casts, in-place decryption and the encryption copy; they are released only when
packet storage is dropped. Replies retained by the caller keep their reservations.
Oversized or excess packets are dropped as packet loss. Full channels apply
backpressure; pressure does not terminate the device's I/O workers.

The shared budget and recycling cache persist across suspend/resume. Pending
packets and sessions are cleared on suspend/stop, including when diagnostic state
owners remain alive. UDP receive uses one packet per call and send batching is
clamped. Injected adapters must themselves bound their allocations and input
batches; our probe returns one IP packet and uses eight-packet external channels.

When the source counter table is full, a new source must prove a valid cookie,
without adding an entry or evicting another source's counter. Expired receiver-index
mappings are pruned whenever a new handshake index is registered. Peer/prefix caps
and immutable configuration prevent dynamic configuration from bypassing limits.
Bounded mode rejects UAPI, external index tables, custom timer parameters and
TUN/DAITA feature combinations. Core reconfiguration will rebuild the device.

Observed locally on macOS arm64, 2026-09-08:

- All 86 library tests pass, including 12 new memory/pressure tests. They cover
  160,000 contended admissions, all 64 slots including the control reserve,
  normalization of a slice from a 4 MiB buffer, lease ownership through real
  encryption/decryption, global/per-peer pending limits, and cookie acceptance
  when the source table is full.
- 50,000 MTU-sized packets to an unreachable peer across five suspend/resume
  cycles keep the per-peer backlog at eight and release all reservations on each
  suspend. Blocked UDP send cancellation also releases queued reservations.
- Source-table flooding stays at 128 entries; 10,000 forced handshakes keep the
  receiver map limited to live indices without relying on timer cleanup.
- The live Xray probe floods up to 10,000 MTU-sized packets while the application
  does not drain replies. One observed run reached 56 data reservations and
  dropped 9,936 excess admissions. Reading replies again restores encrypted UDP
  exchange; suspend drains the remaining reservations and resume performs a fresh
  handshake. Scheduling can produce backpressure before admission saturation;
  both pressure paths are accepted, and successful recovery is required.
- Strict Clippy passes for the library, tests and probe. The guarded script is
  included in the Go-oracle CI job. Only the local macOS run is reported here;
  Linux CI and physical Apple/Android results are not claimed.

The subsequent [PSK ownership patch](../tools/wireguard-adapter-prototype/patches/gotatun-psk-hygiene.patch)
replaces plain PSK arrays in peer, update, inspection and Noise state with a
redacted boxed zeroizing owner. KDF calls borrow its bytes. Three additional
ownership/redaction tests join the existing PSK/rekey cases; the full engine suite
now has 89 tests. The runtime accepts optional PSK; see its
[configuration and lifetime contract](v07-wireguard-runtime.md).

The [runtime increment](v07-wireguard-runtime.md) now adds protected sockets,
cancellation ownership, smoltcp TCP/UDP, IPv4/IPv6 and JSON/core registration.
The runtime now covers up to eight peers, prefix overlap and authenticated source
isolation. Remaining work includes independent reference coverage, mobile SDK
profiles and physical-device acceptance.
