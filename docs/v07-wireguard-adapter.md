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
  interface. The core uses smoltcp 0.14; it needs an outbound client
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

The runtime has real TCP/UDP coverage against pinned Xray and
[direct official wireguard-go](v07-native-wireguard-interop.md). Both gates cover
wrong keys/PSK, allowed-IP overlap, IPv4/IPv6, MTU payload bounds and fresh startup;
the direct gate also replaces controlled GotaTun peers for source-spoofing and
unavailable-peer isolation tests. Existing client tests cover exhausted queues,
socket-protector rejection and cancellation. Broader independent authenticated
roaming, replay, timed keepalive/rekey, fragmentation and physical suspend/resume
remain release work. No crypto protocol is implemented anew in this repository.


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

| Resource | Production adapter limit |
| --- | --- |
| Each internal I/O queue | 16 packets |
| Shared packet reservations | 256, including 8 reserved for handshake/cookies (generic preset: 64) |
| Recycling cache | 32 buffers of 4096 bytes |
| Pending handshake backlog | 16 packets across all peers |
| Pending backlog per peer | floor(16 / configured peers) packets and 12 KiB |
| Inner IP / outer UDP admission | 1420 / 1500 bytes |
| Configured peers / total allowed-IP prefixes | 8 / 256 |
| Handshake source-IP counters | 128 entries |

Each reservation accounts for a normalized allocation of up to 4096 bytes and a
simultaneously live encryption copy of up to 4096 bytes. Thus the reservation
budget is **2 MiB**, plus up to **128 KiB** of cached pool storage. These are
bounds on requested packet-buffer storage, **not process RSS**. Fixed receive and
handshake working buffers, allocator metadata, queue/table metadata, crypto state,
tasks, caller adapters, sockets and the userspace TCP/UDP stack require
separate accounting and measurement. No whole-device memory ceiling is claimed.

The production adapter keeps sixteen packets per engine queue. Both carrier
families, the two 32-packet inner queues, one bounded 32-packet IP batch,
in-flight operations and the handshake backlog have headroom inside 248 data
reservations. The IP reader drains already available packets into a reused vector
and notifies newly available capacity once per batch; it never waits to fill a
batch. Each TCP application bridge has 64 KiB per direction (2 MiB maximum across
16 admitted flows), separate from the TCP socket buffers below. A decrypted
packet no longer holds the peer/device locks while waiting for inner delivery.
TCP uses Reno with 1 MiB send and receive backing buffers per admitted flow
(32 MiB maximum across the existing 16 TCP slots). These are storage capacity
bounds, separate from sampled process RSS. New flows start with a 64 KiB receive
advertisement. The adapter divides a 1 MiB receive allowance among bulk-active
flows and a 1 MiB transmit allowance among flows with queued data. Idle open
connections do not divide a transferring flow's allowance. Newly active flows
receive bounded initial credit; a one-second receive activity grace interval
avoids reallocating the window between every small read.

Rebalancing never retracts credit already advertised to a peer or discards
already queued sends. Outstanding allowances can therefore temporarily exceed
the shared targets; the per-flow physical buffers remain the hard bounds.
Window scaling cannot round credit beyond available storage. This replaces the
rejected experiment that advertised large windows to all flows immediately and
then suffered burst loss and long stalls. The idle-flow control keeps fifteen
echo-verified connections open while the sixteenth transfers data.

WireGuard opts into a bounded ten-segment initial window and RFC 3465 byte
counting; post-RTO slow start retains a one-segment growth cap. Writes fill the
TCP buffer directly; Nagle is disabled. The packet adapter preserves the socket's receive
window advertisement instead of clamping it to packet-queue depth. smoltcp 0.14
includes corrections for duplicate-data ACKs, fast retransmit timing and Reno's
congestion window accounting; wire-level tests cover window advertisement and
repeated acknowledgement after lost ACKs. Round-robin socket egress prevents
bounded packet queues from starving later flows. Negotiated TCP timestamps let
peers measure RTT during retransmission; tests also cover peers without timestamps.
SACK reports retained ranges and assembler overflow sends duplicate ACK feedback.
The handshake backlog is divided among configured peers, so an unreachable peer
cannot starve a healthy peer's first UDP packet. Tests saturate one, two and seven
unreachable peers without losing the healthy peer's response.
The stack consumes a bounded batch of incoming packets before scanning sockets
for egress. The final full poll still handles timers and reset packets. The UDP
sender also dequeues up to sixteen already available packets at a time, without
waiting for a full batch; per-packet destination selection, cancellation and
carrier replacement remain intact. This amortizes queue and socket-scan work,
not the kernel's datagram system calls. Queue limits are unchanged.
The adapter emits at most 32 consecutive TCP packets per socket during an
egress scan. This gives the receiver an opportunity to acknowledge queued packets
together. A partial burst yields to the next socket when the bounded device fills;
even a one-packet device cannot let one sender starve the other. The shared IP
queue remains 32 packets and TCP congestion/receive windows still cap flight.
The optional smoltcp burst setting defaults to one packet for other callers.
Each enabled carrier family requests 7 MiB kernel UDP receive and send buffers,
matching the pinned wireguard-go requests. The OS can clamp or reject them;
kernel storage is excluded from process RSS. During carrier
replacement, the existing three-second drain can temporarily retain an old
socket set as well.

The core TUN bridge limits Hysteria2/WireGuard upload queues to eight messages
of at most 32 KiB, with a 64 KiB write-batch target (a final message can overshoot
that target). Transport windows remain separately bounded. Releasing upload
capacity explicitly wakes a backpressured TUN stack without waiting for another
packet or TCP probe. Other outbounds retain their existing bridge limits.


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

Observed locally on macOS arm64, 2026-09-08, with the earlier 64-reservation
probe configuration (current production bounds are listed above):

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
has 90 tests including the receive-backpressure regression. The runtime accepts optional PSK; see its
[configuration and lifetime contract](v07-wireguard-runtime.md).

The [runtime increment](v07-wireguard-runtime.md) now adds protected sockets,
cancellation ownership, smoltcp TCP/UDP, IPv4/IPv6 and JSON/core registration.
The runtime now covers up to eight peers, prefix overlap and authenticated source
isolation. Direct reference coverage and mobile SDK profiles are implemented;
broader independent protocol cases, application integration and physical-device
acceptance remain pending.

Already writable UDP sockets use a nonblocking send before registering a
cancellation waiter. Each call still consumes Tokio's cooperative budget and
checks stop state. A blocked send keeps the cancelable async path; each packet
selects the current protected carrier and its own destination. Tests cover ready
socket cancellation, carrier replacement, separate destinations, and progress
of another task during continuous sending.

The one-way stop state uses an atomic flag and a notification shared by all
waiters. Waiters register before rechecking the flag, so closure racing with
subscription cannot lose the wakeup; late subscribers observe the permanent
closed state. Closure wakes every waiter, including when another waiter was
canceled. This removes the stop-state read lock from per-packet checks without
changing restart, suspend or transport ownership.
