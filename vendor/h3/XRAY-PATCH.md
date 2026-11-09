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

## Extension settings at their defaults

`Config` used to put `ENABLE_CONNECT_PROTOCOL`, `ENABLE_WEBTRANSPORT`,
`H3_DATAGRAM` and `WEBTRANSPORT_MAX_SESSIONS` into every SETTINGS frame, as 0
when disabled. quic-go's `http3`, which Xray-core's XHTTP H3 client uses, only
sends the ones that are enabled, so an XHTTP client that disables GREASE still
announced four settings Xray never sends. Each of them now goes out only when
nonzero; 0 is the protocol default for all four, so peers read the same
configuration. `MAX_FIELD_SECTION_SIZE` and GREASE are unchanged.
`xray_tests` in `src/config.rs` covers both cases.

## CONNECT-IP for the MASQUE client

Xray-core's MASQUE client opens a CONNECT-IP tunnel (RFC 9484) as an HTTP/3
extended CONNECT with quic-go's `http3`. Four additions let this crate do the
same; each is used only by `crates/xray-transport/src/masque` and changes
nothing for other callers:

- `ext::Protocol::CONNECT_IP` and `CF_CONNECT_IP` send the `:protocol`
  values `connect-ip` and Cloudflare WARP's `cf-connect-ip`; `FromStr`
  reads them too. Upstream knows only `webtransport` and `connect-udp`.
- `client::Builder::enable_datagram_draft00` announces setting `0x276`
  (draft-ietf-masque-h3-datagram-00) with value 1, after the other settings,
  where Xray's WARP dial puts it. The setting is now kept when a peer sends
  it, and `Settings::enable_datagram_draft00` reports whether its value is
  exactly 1, which is all Xray's client accepts.
- `client::SendRequest::peer_settings` waits for the server's SETTINGS
  frame, or for the connection to fail first. Xray's client checks extended
  CONNECT and datagram support before it sends the request; upstream gives no
  way to wait for them. A waker in `SharedState` is woken when the settings
  or a connection error arrive; one task waits at a time.
- `Settings` is exported, as the type `peer_settings` returns.

`draft_datagram_setting_goes_last_and_reads_back_only_as_one` in
`src/config.rs` covers the setting's encoding and reading.
