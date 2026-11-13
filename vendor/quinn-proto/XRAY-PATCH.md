# quinn-proto 0.11.16: bounded Hysteria DATAGRAMs, BBR corrections and ChromeParrot

Source: the complete unchanged-version crates.io `quinn-proto` **0.11.16** archive,
SHA256 `2f4bfc015262b9df63c8845072ce59068853ff5872180c2ce2f13038b970e560`.
Upstream licenses and the published lockfile remain intact. `XRAY-PATCH.diff`
reconstructs the local source from that archive with zero fuzz. Run
`scripts/check-vendored-sources.sh` to verify the archive, exact reconstruction,
and the protocol tests from an isolated copy.

## Independent DATAGRAM advertisement limit

The optional `TransportConfig::advertised_datagram_frame_size` caps the advertised
frame size without reducing the aggregate receive queue. `None` retains upstream
behavior; a cap cannot enable disabled datagrams or exceed the receive budget.
Hysteria advertises 1,200 bytes with a separate 256 KiB receive queue. This avoids
pinned Xray-core v26.7.28 / apernet-quic-go fragmentation interoperability loss:
its size estimate may reach the path MTU before its packet packer accounts for
frame overhead. Xray's own Hysteria client advertises the same cap. Real
bidirectional 4 KiB fragmentation tests cover the unchanged Xray implementation.
Other callers leave the field unset.

## Congestion accounting and delivery sampling

The transport now reports each encrypted, ack-eliciting packet exactly once at
packet finalization, including MTU probes and excluding pure ACK packets. The
callback's byte count excludes other coalesced packets and other GSO segments.
This specifies and tests byte accounting; it is not a claim that the previous
implementation generally counted every GSO packet twice.

The bandwidth estimator retains the acknowledged packet's own delivery snapshot,
then takes the minimum of its send and ACK slopes. This prevents later sends,
compressed ACKs, equal-timestamp batches, reordering and loss from inventing a
higher delivery rate. An eight-byte token follows each sent packet. Shared
same-timestamp snapshots are stored in a BTreeMap capped at 4,096 entries;
eviction skips an obsolete rate sample while preserving acknowledged-byte
accounting. Loss cannot retain unbounded history. The send-time application
limit flag survives until acknowledgement, including the legacy callback path.

Valid non-application-limited observations update the ten-round maximum filter;
an application-limited observation is accepted only when it raises the estimate.
This allows the filter to age down after a real bandwidth decrease. Startup
compares the byte congestion window with the byte model target, fixing the
previous gain-versus-bytes comparison.

`Controller::on_sent_with_in_flight`, `on_ack_with_token`, `on_rtt_sample`, and
`pacing_rate` have compatibility defaults for other controllers. Tests exercise
packet token round trips through the connection, coalescing, ACK-only sends,
loss, reordering, and ordinary congestion-controller callbacks.

## Lost-packet counts

`Controller::on_packets_lost(now, packets, bytes)` reports how many
ack-eliciting packets one loss-detection pass declared lost, and their total
size, just before `on_congestion_event` for the same batch. That callback
carries only the bytes, while Hysteria's Brutal sender compensates for loss by
packet counts: acknowledged against lost packets over five one-second slots.
Lost MTU probes and ECN signals are not reported, and the default ignores the
call, so other controllers are unchanged.
`lost_packets_are_reported_with_their_count_and_size` drops two real stream
datagrams and checks the callback's totals against the connection's loss
statistics; it fails when the call is removed. The complete 300-test library
suite passes in the reconstruction.

## quic-go's congestion event

Xray-core's BBR sender takes what quic-go hands a controller: every sent
packet with its number, ACK-only packets included, and one
`OnCongestionEventEx` per ACK frame or loss timeout listing the packets it
acknowledged and lost, by number, with the bytes in flight before it. Three
callbacks, each ignored by default, report the same from quinn:
`Controller::on_sent_not_ack_eliciting` for a sent packet that elicits no
acknowledgement, `on_packet_lost_with_token` for each lost ack-eliciting
packet with the token recorded when it was sent, and
`on_congestion_event_end(now, prior_in_flight)` once an ACK frame that
acknowledged new packets, or a loss-detection timeout, has been processed.
Lost MTU probes are reported per packet, as quic-go reports them, while
`on_packets_lost` and `on_congestion_event` still leave them out. Other
controllers are unchanged. `acknowledgements_and_losses_close_in_one_congestion_event`
drops two real datagrams and checks that every acknowledgement and loss is
closed by an event, that the per-packet losses carry the dropped packets'
tokens and add up to the connection's loss statistics, that the flight
before each event holds what it removed, and that ACK-only packets are
reported; `lost_mtu_probes_are_reported_per_packet_only` checks that an
oversized probe's loss reaches the per-packet callback alone. The complete
302-test library suite passes in the reconstruction.

## Measured RTT and periodic probing

An unset RTT epoch is a fresh connection, not an expired sample. The initial
pacing rate waits for an actual measured RTT rather than the configured initial
RTT prior. A new callback supplies fresh raw RTT after the path estimator has
been updated, before the end-of-ACKs decision; unvalidated migration paths and
inferred Retry acknowledgements cannot manufacture a fresh measurement.
The windowed minimum can track increases after a path change instead of reading
the path's all-time minimum forever. Lower fresh samples refresh a live epoch;
an already-expired epoch remains expired until the periodic-probe decision.

The BBR profile uses the standard two-BDP congestion-window gain and advances
from the low-gain cycle when flight has drained to the model target. ProbeRTT
uses the four-datagram minimum and starts its 200 ms measurement only after
queued flight drains. Deliberately sparse probing and the first post-probe
flight are marked application-limited until new flight is acknowledged, so the
probe cannot falsely age bandwidth down on a short-RTT path. Later genuine
bandwidth reductions still expire the old peak. Periodic probing and loss
recovery remain enabled.

These choices were checked against the pinned sing-quic implementation used by
sing-box v1.13.15 (`congestion_meta2/bbr_sender.go`), and deterministic regressions
fail before the corresponding corrections. The comparison report records exact
source and executable identities and real measurements; algorithm similarity
alone does not establish performance parity.

## Pacing

BBR exposes its calculated pacing rate to the transport. The rate-based bucket
refills from bytes/second, clamps credit after a rate decrease, and schedules
wakeups for a packet rather than waiting for an entire bucket. Its bounded
four-millisecond credit accommodates coarse userspace wakeups; the existing
256-packet cap remains. Other controllers retain their window/RTT pacer.
The four-millisecond experiment alone did not demonstrate a clear speed gain;
it must not be presented as an independently proven optimization.

The final source must pass the full selected-feature protocol suite and exact
vendor reconstruction. Host benchmark results do not replace mobile-device,
real-WAN, path-change or broader congestion-fairness validation. Remove local
overrides when an upstream version provides equivalent behavior and passes the
same regressions and interoperability checks.

## Ready ACKs when outgoing data is blocked

A ready standalone, unpadded 1-RTT ACK may bypass a full congestion window or
an exhausted pacer even when stream data is queued. Only the ACK frame is
populated in this path. Stream/control data, off-path responses and packets
requiring explicit padding retain their normal congestion/pacing rules; the
pacing timer remains armed for blocked data. Two deterministic regressions
reproduce ACK suppression before this change and check that the queued stream
does not advance and the ACK is not reported as congestion-controlled delivery.
The complete 298-test protocol suite passed in the focused source copy.
The paired WAN control did not demonstrate a throughput improvement; this
correction must not be advertised as a measured speed gain.

## Resizing the stream receive window

`Connection::set_stream_receive_window` sets the window every receive stream
offers past the bytes it has read, for open and new streams alike. A read
sends a larger MAX_STREAM_DATA once it frees an eighth of the window. Credit
already sent is never withdrawn: `Recv::max_stream_data` never offers less
than the stream's last sent limit, so under a smaller window a stream grants
nothing new until its reader catches up, and a lost update is resent whole.
A new stream, or a reused one, starts from the handshake's stream window,
which is exactly the credit the peer holds on it, whatever the window is when
it opens.

XHTTP H3 calls it to auto-tune its download window as quic-go does, and to
hold each download to its share of a receive budget shared by concurrent
downloads; upstream only allows `set_receive_window` for the connection. The
unit test `a_resized_stream_window_is_offered_from_the_next_read` covers a
grown window, a smaller one with a resent update and the reader catching up,
and a stream that opens under the smaller window; each of the three changes
fails it when reverted. The complete 299-test library suite passes.

## Xray-core's ChromeParrot client handshake

Xray-core v26.10.31 dials Hysteria and HTTP/3 over the apernet quic-go fork
(v0.61.1-0.20260806010916-184d081eef3e) with its `ChromeParrot` option on
unless `quicParams.disableChromeParrot` is set. `TransportConfig::chrome_parrot`
reproduces what that option does below TLS for a client connection; servers
ignore it. `src/chrome_parrot.rs` ports each piece from the fork:

- Transport parameters encoded as `marshalChrome` does: thirteen parameters
  shuffled per connection, `version_information` (v1, then v1 and a GREASE
  version in random order), `google_connection_options` = "ORIG", a GREASE
  parameter whose identifier fills an 8-byte varint, and `ack_delay_exponent`,
  `max_ack_delay`, `disable_active_migration`, `active_connection_id_limit`,
  `min_ack_delay` and `grease_quic_bit` left out (their defaults are what this
  end does). `max_datagram_frame_size` is 65536 whenever datagrams can be
  received. Random bytes are read in the fork's order;
  `chrome_parrot_transport_parameters` takes them from the caller for tests.
- Initial packet numbers start at 1; every packet number takes the fork's
  length (one, two or four bytes from the larger of the unacknowledged range
  and the congestion window in packets, the window measured in the room an
  Initial left in the last handshake datagram while that is at least 40
  bytes, else in the MTU).
- Until the handshake is confirmed, one packet per datagram (one datagram per
  `poll_transmit`), Initial datagrams padded to the current MTU, loss probes
  clamped to the minimum MTU rather than 1200, and a Handshake ACK sent on its
  own before new Handshake CRYPTO data.
- A ClientHello too large for one Initial goes out head (55..86 bytes) and
  tail first, the middle in the next packet (`chromeCryptoSplit`).
- An Initial packet with CRYPTO data and padding is rewritten with the fork's
  chaos protection at finish time: the ACK first, the CRYPTO frames cut 2..10
  times, 2..10 PINGs, the padding split into runs and the lot shuffled with
  Go's `math/rand/v2` PCG, seeded per connection from 16 random bytes
  (`chrome_parrot_seed` for tests). Retransmissions carry the frames as they
  were written, shuffled afresh.

The workspace test `crates/xray-transport/tests/chrome_parrot_tests.rs`
replays the random reads recorded from Xray's own Hysteria dialer
(`tools/chrome-parrot-oracle`) and gets the same transport parameters and the
same four encrypted Initial datagrams, first flight and probes, byte for byte.
`chrome_parrot_handshake_packs_one_packet_per_datagram` checks the handshake
datagrams against a stock server, `chrome_parrot_numbers_initial_packets_from_one`
the packet numbers, and the module's own tests Go's PCG values, the split,
the chaos sizes, the ACK in front, a cut paid by a budget of exactly one frame
header and the packet number lengths. The complete 311-test library suite
passes in the reconstruction.

A connection that is closing packs its packets as stock quinn does, whatever
the handshake's state: `chrome_handshake` is false while `close` is set. With
one packet per datagram the close stopped at the first space that had keys;
the highest space never carried its CONNECTION_CLOSE, so `close` stayed set
and every `poll_transmit` returned another close packet, as fast as the
socket took them, until the close timer. Any close before the handshake was
confirmed did it: a certificate the client refuses, or a dial given up after
the Finished. `chrome_parrot_close_before_the_handshake_is_confirmed_is_sent_once`
fails with sixteen datagrams, where it stops counting, when the condition is
removed. The complete 312-test library suite passes in the reconstruction.

## A ChromeParrot Handshake ACK alone elicits no acknowledgement

`poll_transmit` decides whether a packet is ack-eliciting before it is
filled, from what is pending in its space. A ChromeParrot client sends its
Handshake ACK in a packet of its own while the Finished is still pending, so
that packet was tracked as ack-eliciting: 50 bytes in flight, the loss timer
armed for it and a delivery token taken, for a packet the server never has
to acknowledge. quic-go tracks it as the ACK-only packet it is. After `populate_packet`, a Handshake packet of an unconfirmed
ChromeParrot handshake that carries an ACK alone clears the builder's
`ack_eliciting`; it is then reported through `on_sent_not_ack_eliciting`.
`chrome_parrot_handshake_ack_alone_is_not_ack_eliciting` checks that the
second ack-eliciting packet a controller is told of is the Finished; without
the change it is the 50-byte ACK.

## Lost MTU probes have their own callback

`Controller::on_mtu_probe_lost_with_token` reports a lost MTU probe. Its
default calls `on_packet_lost_with_token`, so every controller sees what it
saw before; a controller that reacts to each loss it is told of overrides it
and leaves the probe out, as RFC 9000 section 14.4 asks. The port of Xray's
BBR sender does. `lost_mtu_probes_are_reported_per_packet_only` also checks
that every lost probe comes through the new callback. The complete 313-test
library suite passes in the reconstruction.

A Retry was checked and left as it is: `space.take(0)` finds no packet under
ChromeParrot, whose Initial numbers start at 1, so the first Initial is not
credited to the congestion controller as acknowledged, which is what quic-go's
`ResetForRetry` does; `discard_space` takes every sent Initial out of the
bytes in flight once, and the ClientHello is queued again whole.
