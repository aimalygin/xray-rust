# quinn-proto 0.11.16: bounded Hysteria DATAGRAMs and BBR corrections

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
