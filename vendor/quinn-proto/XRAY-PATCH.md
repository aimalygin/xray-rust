# Independent DATAGRAM advertisement cap

Source: unchanged-version crates.io `quinn-proto` **0.11.16**, archive SHA-256
`2f4bfc015262b9df63c8845072ce59068853ff5872180c2ce2f13038b970e560`.
Both upstream licenses and the complete published source are retained.

The local patch adds one optional `TransportConfig` field/setter,
`advertised_datagram_frame_size`. It caps the advertised QUIC transport parameter
without shrinking the aggregate datagram receive queue. `None` preserves upstream
behavior. A cap cannot enable disabled datagrams or exceed the queue budget.
The unit test checks the encoded-parameter source, unchanged default, queue
independence, a smaller receive buffer and disabled receiving.

Why: pinned Xray-core v26.7.28 uses apernet/quic-go commit
`6c6cc9bcb716` (from its go.mod). Its `SendDatagram` size estimate can rise to the
whole discovered MTU, while `packetPacker` subsequently drops frames that do not
fit after packet overhead. Quinn normally advertises up to 65,535 bytes, based on
its receive queue. This reproduced as loss of full-size fragments while the final
short fragment arrived. Xray's own client advertises/assumes a 1,200-byte limit.
Hysteria now advertises that same frame cap with a separate 256 KiB receive queue.

`check-hysteria-interop.sh` verifies real 4 KiB bidirectional UDP fragmentation
against the unchanged Xray reference. Existing XHTTP/H3 and DoQ callers leave the
new field unset. No congestion, stream, crypto or packet serialization algorithm
is changed. The existing receive validation and aggregate memory bound remain.

`scripts/check-vendored-sources.sh` verifies the canonical archive checksum,
applies `XRAY-PATCH.diff` with zero fuzz, compares the complete source tree, and
runs the focused parameter test from an isolated copy using the upstream lockfile.
Remove this override once a compatible Quinn release exposes independent
advertisement and receive-buffer limits; do not reduce the receive queue to 1,200
bytes as a substitute because fragmented bursts would then evict each other.
