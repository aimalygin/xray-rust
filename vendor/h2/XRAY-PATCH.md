# h2 0.4.20: Go's stream WINDOW_UPDATE policy

Source: the complete unchanged-version crates.io `h2` **0.4.20** archive,
SHA256 `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118`.
Upstream licenses and the published lockfile remain intact. `XRAY-PATCH.diff`
reconstructs the local source from that archive with zero fuzz. Run
`scripts/check-vendored-sources.sh` to verify the archive, exact reconstruction,
and the library tests from an isolated copy.

## Stream window update threshold

`client::Builder::stream_window_update_threshold(size)` makes a stream's
WINDOW_UPDATE due once `size` bytes of released capacity have accumulated, or
once the update would at least double the window the peer sees. This is the
policy of Go's `x/net/http2` (`inflow.add`, `inflowMinRefresh` = 4 KiB).

Upstream waits until released capacity reaches half of the remaining window.
With a reader that keeps up, that returns about a third of the initial window
at a time: 1.4 MB of a 4 MiB window. At an added 113 ms the sender then runs
short of credit while each update crosses the link, and XHTTP H2 downloads
measured 28% slower than Go's client (`docs/issue28-client-comparison.md`).

The XHTTP H2 client sets a sixteenth of its opening stream window, at least
4 KiB: an update for every read cost a fast download 16% of its throughput.
Connection-level updates, the server, and every caller that leaves the option
unset keep upstream behavior. Unit tests in
`proto/streams/flow_control.rs` cover the threshold, the doubling rule and the
unchanged default.
