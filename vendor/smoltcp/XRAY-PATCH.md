# smoltcp 0.14.0: bounded WireGuard TCP and loss recovery

Upstream archive: https://static.crates.io/crates/smoltcp/smoltcp-0.14.0.crate

SHA256: `b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f`

The default Reno initial-window behavior remains unchanged. `Socket::set_reno_initial_window`
permits 1–10 segments only on a closed Reno socket. The opt-in initial window
follows the negotiated MSS and the byte bound in experimental RFC 6928. The
first acknowledgement of new data, fast loss recovery, or retransmission timeout
disables initial-window recalculation; later MSS changes cannot reinflate it.
RTO still collapses the congestion window to one MSS.

WireGuard opts into ten segments before connect. The wire-level regression test
observes 2048 bytes with upstream and 13800 bytes after this patch for MSS 1380,
without receiving another ACK. Controller tests cover MSS negotiation, the byte
cap, zero-length ACKs, and preserving the post-loss window.

TCP also accepts valid reverse-direction data carrying an ACK older than
SND.UNA, as specified in RFC 9293 section 3.10.7.4. The old ACK and window are
ignored: they cannot rewind the send sequence, dequeue additional bytes, alter
the congestion window, or enter a zero-window probe. Previously the entire
data segment was discarded. A wire regression sends an old ACK with new data
after a newer ACK and verifies delivery and preserved sender state. It fails
before the fix.

`Interface::set_round_robin_egress` opts into resuming at the socket that could
not obtain a device transmit slot. Fixed-order iteration remains the upstream
default. WireGuard enables this because its bounded packet channel otherwise
allows early sockets to starve later sockets' data and acknowledgements. The
wire test uses one transmit slot, checks alternation, removed slots, an empty
set, and the unchanged disabled behavior. No per-poll allocation is introduced.

Out-of-order input receives a duplicate ACK even when the bounded assembler
cannot retain another disjoint range, following RFC 5681 section 3.2. SACK
reports up to three distinct retained ranges, with the triggering range first
and then the lowest remaining ranges (RFC 2018 section 4). Range matching is
half-open and handles sequence wrap. No rejected payload is falsely SACKed.
Tests verify overflow feedback and three-block reporting across sequence wrap;
both fail before the fix. Exact selected-feature test counts are recorded in the
performance report for each measured source revision.

WireGuard also opts into RFC 3465 Appropriate Byte Counting on its closed Reno
sockets. Slow start counts newly acknowledged bytes with a two-MSS cap; the
entire slow-start phase after RTO keeps a one-MSS cap. Congestion avoidance
adds one MSS per acknowledged window, avoiding delayed-ACK undergrowth and
ACK-division overgrowth. Credit is cleared on loss. Upstream defaults remain
unchanged. Four regression tests fail before the implementation and pass after.

Apply `XRAY-PATCH.diff` to the checksum-verified published archive with zero fuzz.
All other upstream files, including licenses and Cargo.lock, are unchanged.


## Shared receive budgets without retracting advertised credit

`Socket::set_receive_window_limit` lets the WireGuard adapter share a bounded
receive budget among active flows. A socket remembers the right edge actually
advertised to its peer. Shrinking its current allocation cannot retract that
previous promise: still-valid arriving bytes remain acceptable within physical
buffer capacity. Windows are rounded for scaling only when the rounded credit
fits, and SYN advertisements use their unscaled wire value. Connection reset
clears the remembered edge. The default unset budget retains upstream behavior.
Wire tests cover an arriving previously advertised flight, sequence wrap,
non-aligned scaled budgets, SYN scaling and out-of-order credit.

The adapter shares its transmit/receive allowance among flows carrying data,
rather than dividing it by every open socket. Newly active transmitters receive
a bounded initial allowance and queued data is never discarded; receive activity
uses a bounded threshold and grace interval. A benchmark holds 15 echo-verified
idle connections open while the sixteenth transfers data, and compares it with
the identical engine without the idle connections. This exposed and then removed
an eightfold WAN throughput collapse. Physical per-socket storage and active
budgets are documented separately in the performance report.

## Bounded TCP egress bursts

`Interface::set_tcp_egress_burst` permits one to 32 consecutive TCP dispatches per
socket, with an upstream-compatible default of one. The WireGuard adapter uses
32, bounded by its existing 32-packet device queue and each socket's congestion
and receive windows. This gives a receiver a chance to coalesce acknowledgments
without enlarging flight or disabling congestion control. When the device fills
after a partial burst, round-robin iteration resumes at the next socket; with
no progress it retries the current socket. A one-packet device still alternates
active sockets. Tests exercise burst sizes 1, 8, 16 and 32, removed socket slots,
per-scan bounds and progress of both senders.

## Reuse drained receive storage

Before placing payload, an empty readable ring resets its storage position only
when the out-of-order assembler is also empty. Repeated small exchanges then
reuse already touched pages instead of gradually faulting in the full backing
allocation. Capacity, sequence accounting and advertised receive credit are
unchanged. Resetting a readable-empty queue while its assembler still holds
bytes beyond a hole would corrupt payload and is explicitly forbidden.
Tests cover repeated prefix reuse, partial reads, a remaining out-of-order
range after draining readable bytes, hole completion, and subsequent reuse.
The unsafe queue-only variant fails the reassembly test. The focused full
default-feature suite passed 685 tests; final selected-feature reconstruction
tests and workload-specific memory measurements are recorded separately.

## A fast retransmit survives a device without a transmit slot

Upstream clears `pending_fast_retransmit` while it builds the segment, before
`emit`. A device with no transmit slot refuses that segment, and nothing
brings it back: the retransmit timer went idle when the fast retransmit was
taken up, the whole flight is outstanding, and the halved congestion window
admits no new data whose transmission would start the timer again. The socket
then reports `PollAt::Ingress` with data in flight, and waits for a peer that
has nothing more to say. The flag is now cleared only after `emit` succeeds.
Until then the socket keeps reporting `PollAt::Now`, the segment leaves with
the next slot, and sending it starts the retransmit timer as upstream does.
The bounded adapters hit this under upload: a MASQUE flow through Xray-core's
server, which drops bursts of tunnel packets, stopped for good. A wire test
refuses the emit of a fast retransmit and checks that it is still owed and
then sent; it fails before the fix.

## A burst loss is repaired without the retransmission timer

Upstream resends one segment for three duplicate ACKs, and its fast recovery
ends with the first ACK of new data. A flight that lost several segments has
the first one repaired; the others wait for the retransmission timer, unless
three more duplicate ACKs happen to arrive, and those halve the Reno window
again. The timer waits at least a second. A peer that drops bursts, as
Xray-core's MASQUE server does with more than 32 datagrams queued for a
stream, made every such flight pay that second: a 64 MiB upload over a
loopback waited for it nine times and more.

The sender now follows NewReno (RFC 6582) and reads the SACK blocks the peer
already sends. It keeps no table of what the peer holds: every decision is
taken from the segment that arrives.

All of it is behind `Socket::set_loss_recovery` and off by default. A socket
that does not ask for it treats a loss as upstream does: none of the state
below is set and none of the rules applies. The adapter's sockets ask for it,
for WireGuard and for a CONNECT-IP tunnel alike. The sockets that terminate
the TUN link in `xray-core-rs` do not.

- `recover` is the end of what had been sent when a fast retransmit
  started. An ACK of new data short of it is a partial ACK:
  the segment that now leads the flight was lost with the one just repaired,
  and is resent at once, a FIN included. `Controller::on_partial_ack` (by
  default `on_ack`) lets Reno take the acknowledged octets off its inflated
  window, give one segment back, and stay in fast recovery, so one loss event
  halves the window once. Duplicate ACKs that arrive meanwhile start no second
  fast retransmit. An ACK that reaches `recover` ends the recovery as before.
- A segment whose SACK blocks report more than two segments' worth beyond its
  cumulative ACK starts a fast retransmit like a third duplicate ACK (RFC 6675
  section 4, `IsLost`, applied to the blocks of that one segment). It is what
  finds a hole in the data sent during a recovery: the ACK that ends the
  recovery reports it, the deflated window admits nothing new, and no
  duplicate ACK would follow. Blocks at or below the ACK (RFC 2883), blocks
  that reach past what was sent, and blocks from a peer that did not offer
  SACK count for nothing.
- `resent_at` is the end of what had been sent when the leading segment was
  last resent. SACK blocks that report more than two segments' worth beyond
  it are of data sent after that retransmission, which was therefore lost,
  and it is resent. Before, duplicate ACKs went on opening the window for new
  data, up to the peer's whole receive window, while the segment it waited
  for was left to the timer.
- After a retransmission timeout the flight is sent again from its start, and
  the peer answers what it already had with duplicate ACKs and SACK blocks.
  Neither starts a fast retransmit until an ACK passes `timeout_recover`, the
  end of what had been sent before the timeout (RFC 6582 section 3.2, steps 2
  and 4). Upstream had no such bound; with the SACK rule above it would have
  halved a window measured on the one segment just resent.

`Socket::set_retransmission_timeout_floor` replaces the one-second lower
bound of RFC 6298 (2.4), which stays the default. With a floor the timeout is
the smoothed round-trip time plus the larger of four times its variance and
the floor, which is how Linux applies its 200 ms: the timer never fires
sooner than the floor after an ACK was expected, so a peer that delays its
ACK by less causes no retransmission. A connection without a round-trip
sample still waits the initial second, and the setting outlives `reset`. The
adapter sets 200 ms on the sockets of a CONNECT-IP tunnel (MASQUE) only.
WireGuard's keep the default until the shorter timer is measured on a real
network: a timeout that turns out spurious is not undone here, it rewinds the
flight and collapses the Reno window. The timer remains the only answer where
the peer has nothing to say: a flight lost whole or at its tail, a FIN lost
on its own, a retransmission lost with nothing sent after it. A tail loss
probe (RFC 8985) would cover those and is not implemented; nor are limited
transmit and early retransmit, and holes are still repaired one per round
trip.

`reset` now also clears a pending fast retransmit together with the new
state, so a socket that is opened again does not start with a retransmission
owed by its previous connection. It is the one change here that reaches a
socket whatever its settings.

Wire tests cover a burst of three lost segments and two separate holes
repaired by partial ACKs, a lost FIN, a recovery that ends and a later one
that starts, the Reno window across a recovery, the timeout taking over, the
SACK threshold and the blocks that do not count, the hole behind a finished
recovery, a retransmission lost again, the bound after a timeout, and the
floor. Those of the new behavior fail without it. Three more run a burst
loss, SACK blocks, and duplicate ACKs with only a FIN in flight on a socket
that did not ask for the recovery, and find what upstream does: the next hole
waits for the timer, duplicate ACKs after a timeout start a fast retransmit,
SACK blocks start none, and no FIN is resent for duplicates. Controller tests
cover the partial ACK. With the adapter's features the library suite runs 471
tests.
