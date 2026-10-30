# Transport window and pacing follow-ups

Decision recorded on 2026-09-09 after issue #28 and the
[Rust/Go client comparison](issue28-client-comparison.md).

The current implementation scope is **XHTTP over HTTP/2 only**: retain the
4 MiB stream receive window and the 16 MiB connection receive window, and
add an optional per-carrier JSON override for the stream window. No BDP
estimator is part of this change. The TUN isolation repair remains in place.

## Deferred decisions

| Mechanism | Direction | Existing configuration and constraints |
| --- | --- | --- |
| gRPC/H2 | **Done (2026-10-30):** windows grow by grpc-go's BDP estimator from 65,535 bytes up to 16 MiB, or 1 MiB on a constrained host (`crates/xray-transport/src/stream/h2_bdp.rs`). | Any `grpcSettings.initial_windows_size` above zero still pins the windows, as grpc-go's `StaticWindowSize` does. The opening SETTINGS are unchanged; growth is sent as `SETTINGS_INITIAL_WINDOW_SIZE`. h2 returns connection credit only as streams are read, so the connection window grows to sixteen stream windows and never fewer than sixteen stalled flows can exhaust it. |
| XHTTP/H3 | **Done (2026-10-30):** receive windows auto-tune as apernet/quic-go tunes them, from 2 MiB / 3 MiB up to 6 MiB / 15 MiB or the configured maxima. | A constrained host keeps unconfigured windows fixed at their initial size. A maximum below its initial window is the only rejected combination. Vendored quinn gained `set_stream_receive_window`. The QUIC send window starts at 2 MiB and grows with the congestion window up to 10 MB. |
| XHTTP packet-up | Keep the 30 ms minimum POST interval and 1,000,000-byte maximum. First investigate actual POST sizes and batching of small writes. | Reuse `scMinPostsIntervalMs` and `scMaxEachPostBytes`. Lower intervals increase request frequency; gathering a full large POST must not delay interactive traffic. Check H1, H2 and H3 separately. Numeric zero for the interval currently selects the default rather than disabling pacing. |
| XHTTP/H2 fast-path difference | **Done (2026-10-30):** stream credit returns once a sixteenth of the window has been read, at least 4 KiB (x/net/http2's `inflowMinRefresh`), through a vendored h2 option. | The 2026-09-09 comparison measured 184 Mbit/s for Rust and 257 Mbit/s for Go at an added 113 ms without a byte-rate limit, with 1.4 MB versus 8 KiB credit updates; see the re-measurement in the benchmark results. On a constrained host an unconfigured XHTTP H2 stream opens at 1 MiB and grows to 4 MiB for a reader that keeps up. |

## Validation before changing another default

For each carrier separately, compare a single sustained flow and concurrent
flows at low and high RTT. Include packet loss for QUIC, and both bulk and
small-write traffic for packet-up. Verify data integrity, EOF ordering,
cancellation, a neighboring active flow while others stop reading, and
physical iPhone memory. Retain explicitly configured values and verify
opening-wire compatibility changes rather than merely updating snapshots.

XHTTP/H2's passing tests and device campaign do not validate larger gRPC or
QUIC windows. Receive credit is not a process-memory limit, and multiple
connections have separate credit allowances. Future BDP work needs explicit
memory limits and coordination with existing PING/keepalive behavior.
