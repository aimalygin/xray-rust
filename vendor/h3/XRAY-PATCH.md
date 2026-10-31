# h3 0.0.8: bounded frame read-ahead

Source: the complete unchanged-version crates.io `h3` **0.0.8** archive,
SHA256 `10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be`.
Upstream licenses and the published lockfile remain intact. `XRAY-PATCH.diff`
reconstructs the local source from that archive with zero fuzz. Run
`scripts/check-vendored-sources.sh` to verify the archive, exact reconstruction,
and the library tests from an isolated copy.

## Frame read-ahead

`FrameStream::poll_next` read a chunk from the QUIC stream before decoding,
and `poll_data` read one before handing out each piece of a DATA frame, even
when the bytes they needed were already buffered. Each piece leaves with one
chunk, so a frame boundary inside a chunk left one more chunk buffered, and
`poll_next` added another per frame. While the peer keeps the stream full,
every read finds a chunk and the buffer only grows. Those bytes have already
left the QUIC receive window, so nothing bounds them: in 32 XHTTP H3
downloads from Xray-core on Linux they reached 19.6 MiB in a six-second
transfer and 46 MiB in a 28-second one, on top of the 57.5 MiB the full
receive windows held.

`poll_next` now decodes a buffered frame before it reads, as upstream did in
hyperium/h3#344 (issue #308, merged after 0.0.8). `poll_data` reads only while
part of the current frame is still missing, so a truncated frame is still
reported as `UnexpectedEnd`. Upstream's `poll_data` still reads on every call,
which with small DATA frames grows the buffer by a chunk per frame. The buffer
now holds at most the chunk being decoded and the one after it.
`poll_next_decodes_buffered_frames_before_reading` and
`poll_data_reads_only_what_the_current_frame_needs` in `src/frame.rs` cover
both; the second fails with upstream's fix alone. The verification script runs
them with the crate's other unit tests, after emptying `src/tests/mod.rs` in
its copy: that module includes h3-quinn from upstream's repository layout,
which no release ships.

## Lints

crates.io builds cap lints. This path override builds under the workspace's
`-Dwarnings`, and rustc 1.96 reports `dead_code`, `mismatched_lifetime_syntaxes`,
`unused_imports` and `unused_variables` in upstream code, so `src/lib.rs`
allows those four.

All other source is unchanged. Remove this copy and its `[patch.crates-io]`
entry once a compatible h3 release bounds both reads.
