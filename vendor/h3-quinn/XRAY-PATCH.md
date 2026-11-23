# h3-quinn 0.0.10: a receive stream that stays stoppable while a read is pending

Source: the crates.io `h3-quinn` **0.0.10** archive, SHA256
`8b2e732c8d91a74731663ac8479ab505042fbf547b9a207213ab7fbcbfc4f8b4`. Upstream's
license is retained. `scripts/check-vendored-sources.sh` downloads the
archive, applies `XRAY-PATCH.diff` with zero fuzz, and requires the manifest,
license, README and `src` to equal this copy.

## Package

The copy is the package `xray-h3-quinn` 0.0.1000: h3-quinn 0.0.10, fork
release 0 (`docs/vendored-forks.md`). The library is still named `h3_quinn`.
`XRAY-PATCH.diff` carries that in the manifest (name, version, description,
`documentation`, `repository`) and in a notice above upstream's README.

## Stopping a receive stream with a read pending

`RecvStream` keeps the Quinn receive stream in the adapter while it polls the
cancellation-safe `read_chunk` future. Upstream 0.0.10 moves that stream into
the pending future for the duration of the read, so an HTTP/3
`STOP_SENDING(H3_REQUEST_CANCELLED)` sent at that moment unwraps an empty
`Option` and panics.

`h3_quinn_recv_stream_remains_stoppable_after_a_pending_read` and
`response_drop_after_upload_fin_cancels_stream_and_reuses_connection` in
`crates/xray-transport/tests/stream_xhttp_h3_tests.rs` pin the adapter's
behavior and the reuse of the connection afterwards. Upstream fixed the same
panic another way after 0.0.10; no release carries it yet.

## Built on the forks of h3 and quinn

The `h3` dependency is the package `xray-h3` and the `quinn` dependency is
`xray-quinn`, both by path in this repository and by version when published.
The workspace builds its HTTP/3 client on those two, and an adapter built on
upstream's would implement the traits of a different h3 for the connections
of a different quinn. No source file changes for this.

## No `datagram` feature

Upstream's optional `datagram` feature implements the traits of the
h3-datagram crate, which is built on upstream's h3. With `xray-h3` in its
place the module does not compile: h3-datagram's error type and this crate's
are then types of two different crates. The feature, its dependency and
`src/datagram.rs` are removed. The workspace never enabled it: its MASQUE
client reads and writes QUIC datagrams on the quinn connection.
