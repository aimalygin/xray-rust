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
| gRPC/H2 | Evaluate a 4 MiB default stream window while retaining 16 MiB connection credit. This is a candidate, not a validated new default. | Reuse `grpcSettings.initial_windows_size` and preserve explicit values' semantics. grpc-go grows its default windows through BDP; our 65,535-byte default remains static. A new default changes the opening SETTINGS and the number of stalled streams needed to exhaust shared credit. |
| XHTTP/H3 | Keep the current fixed 2 MiB stream / 3 MiB connection defaults pending direct throughput and memory measurements. | `streamSettings.finalmask.quicParams` already exposes initial/max receive-window fields. Our supported mode is static; distinct initial/max values remain rejected until actual adaptation is implemented. Do not silently reinterpret adaptive maxima as supported behavior. |
| XHTTP packet-up | Keep the 30 ms minimum POST interval and 1,000,000-byte maximum. First investigate actual POST sizes and batching of small writes. | Reuse `scMinPostsIntervalMs` and `scMaxEachPostBytes`. Lower intervals increase request frequency; gathering a full large POST must not delay interactive traffic. Check H1, H2 and H3 separately. Numeric zero for the interval currently selects the default rather than disabling pacing. |
| XHTTP/H2 fast-path difference | Investigate receive-credit update batching before raising default windows further. | At added 113 ms without a byte-rate limit, our comparison measured 184 Mbit/s for Rust and 257 Mbit/s for Go. The diagnostic trace showed roughly 1.4 MB versus 8 KiB stream-credit updates. This is a candidate explanation, not proof that batching accounts for the entire gap. |

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
