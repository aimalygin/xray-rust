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
