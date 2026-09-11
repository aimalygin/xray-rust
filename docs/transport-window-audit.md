# Transport window audit — issue #28

Source baseline: `8a86a7f` (v0.6.0), reviewed 2026-09-09 UTC.
Report: [issue #28](https://github.com/aimalygin/xray-rust/issues/28).

## XHTTP/H2 change

`crates/xray-transport/src/stream/xhttp/h2.rs` now advertises a 4 MiB
per-stream receive window through `h2::client::Builder::initial_window_size`.
This is the default used by the pinned Go `x/net/http2` client. The old
65,535-byte stream window survived even though the connection window had
already been raised to 16 MiB. For a continuously read response, the old
stream window imposed a bandwidth-delay-product ceiling of about 4.64 Mbit/s
at RTT 113 ms. Increasing the number of concurrent downloads hid that ceiling
in aggregate benchmarks.

All XHTTP modes using an H2 response, including an independent H2 download
carrier, use this handshake. Upload credit is advertised by the server and
is not changed. The optional Rust-specific `h2StreamReceiveWindow` JSON field
overrides the stream credit for one carrier; absent/null retains 4 MiB. Valid
integer values are 65,535 through 16,777,216 bytes. The connection window
stays 16 MiB. See [configuration semantics](config-compatibility.md) for
`extra`, aliases and independent downloads. H1, H3, gRPC, TLS/REALITY,
dependencies, the C ABI and platform adapters are unchanged.

The device and Rust/Go throughput campaigns below measured the 4 MiB policy
before the optional field was added. Their archived binaries remain the
evidence for those campaigns; custom windows are covered by separate host
configuration, flow-control and pool regressions.

### Memory and stalled readers

- The window is permission to send DATA, not an eager allocation. A new or
  idle connection does not allocate 4 MiB per open stream for this setting.
- A peer can now send **4 MiB instead of 65,535 bytes** into one unread
  response. Aggregate unconsumed DATA credit remains **16 MiB per H2
  connection**. This is not a process RSS bound: framing, TLS, allocator,
  application buffers and additional connections consume memory separately.
- Three full unread responses leave one complete window for a fourth stream
  to continue. Four full unread responses can exhaust connection credit;
  reading or cancelling a response restores it. The previous window allowed
  about 256 stalled streams before this shared limit, so isolation under
  many stalled readers is a real tradeoff, not an unchanged guarantee.
- The implementation continues to return credit only for bytes handed to
  the caller. It does not drain stalled streams into an unbounded side queue
  or raise the connection window to Go's approximately 1 GiB.
- On mobile, the transport budget is additional to TUN's remote-data budget.
  The [initial physical iPhone A/B](issue28-iphone-validation.md) measured this
  increase and exposed shared TUN backpressure. The accompanying TUN repair
  limits remote prefetch to 256 KiB per flow and keeps the shared event receiver
  active. The [repeated campaign](issue28-tun-validation.md) passed both H2 and
  raw TCP isolation/cancellation checks with lower observed footprint. This
  does not remove H2's shared-credit limit or establish device-level OOM safety.

### Regression evidence

`tests/stream_xhttp_h2_tests/receive_window.rs` exercises actual h2 client and
server state machines. Three tests fail against the original implementation:

1. A single 8 MiB download through a bounded delay line at RTT 113 ms took
   **14.706 seconds of simulated time** before the fix and **342 ms** after.
   The acceptance bound is deliberately loose (under 2 seconds). Independent
   arrival times allow pipelining; the fixture does not sleep once per DATA
   chunk. This isolates flow control and is **not** a real network, CDN,
   congestion-control, throughput or iPhone benchmark.
2. One unread stream accepts a full 4 MiB window, then stops. Partial reads
   replenish exactly the consumed credit; dropping the body sends CANCEL.
3. Three unread streams allow a neighboring response to transfer more than
   16 MiB. A fourth unread stream can fill connection credit; cancelling one
   restores a fifth stream's progress without closing the connection.

## Other throughput constraints

The [recorded follow-up decisions](transport-window-followups.md) separate
the current XHTTP/H2 scope from deferred gRPC, H3 and packet-up work.

These are source findings and existing behavioral checks, not claims of
measured throughput on all carriers. `window * 8 / RTT` is only a rough
upper bound: update batching, framing, congestion, receiver scheduling and
other bottlenecks can lower it.

| Path | Finding | Consequence / follow-up |
| --- | --- | --- |
| XHTTP/H2 after the 4 MiB fix | The [direct Rust/Go client comparison](issue28-client-comparison.md) reaches about 140 Mbit/s in both clients with a 150 Mbit/s byte-rate limit and added 113 ms. Without that rate limit, Rust reaches 184 Mbit/s versus Go's 257. A separate trace observes roughly 1.4 MB Rust stream-credit updates versus 8 KiB in Go. | Equal initial windows do not imply equal replenishment behavior. The pinned `h2` library batches returned credit much more coarsely than `x/net/http2`; this is a candidate explanation for the remaining fast-path gap, not a proven attribution of the entire difference. Compare update policies while preserving credit bounds before raising windows further. These measurements bypass TUN. |
| gRPC/H2 | `stream/grpc/h2client.rs` also keeps a 65,535-byte stream window by default and a fixed 16 MiB connection window. There is no BDP estimator. | The same per-stream RTT ceiling is present. Existing `grpcSettings.initial_windows_size` can raise stream credit, e.g. to `4194304`; it carries the same stalled-reader memory tradeoff. Changing the default needs a separate design because the opening SETTINGS is checked against grpc-go and explicit values must retain their meaning. |
| XHTTP/H3 | `stream/xhttp/h3.rs` explicitly uses fixed 2 MiB stream / 3 MiB connection windows, while the reference grows toward 6 MiB / 15 MiB. The pool allows one active request per QUIC connection. | At RTT 113 ms, the rough stream/connection ceilings are 148/223 Mbit/s. This can bind fast or high-RTT paths, but is not the 64 KiB defect. Adaptive windows require QUIC implementation work. Explicit static window settings exist; unequal initial/max values deliberately fail closed. |
| XHTTP packet-up | `stream/xhttp/config.rs` defaults to a 1,000,000-byte POST maximum and 30 ms minimum POST interval. H1 waits for the preceding POST response; H2/H3 allow response monitors to overlap after upload completes. | Upload can be limited by pacing, POST size and (for H1) request/response RTT. Even full 1 MB POSTs imply about 267 Mbit/s at 30 ms pacing; small packets can be slower. This is configured/reference-compatible behavior, not a receive-window fix. |
| Raw TCP, TLS/REALITY, WebSocket, HTTPUpgrade, XHTTP/H1 downlink | No additional fixed application-level acknowledgement window found. `connect_tcp_stream` enables TCP_NODELAY and leaves TCP send/receive buffer tuning to the OS. WebSocket frame and relay chunk sizes do not require one network RTT per chunk. | There can still be framing/CPU/TCP bottlenecks; increasing every small buffer is not justified by issue #28. Preserve the current behavior and verify carrier/lifecycle tests. |
| TUN TCP | smoltcp has two 32 KiB socket buffers; its TCP peer is the local application, not the remote origin. Previously, one blocked `RemoteData` event stopped the shared event receiver. The repair retries deferred flows independently, caps remote prefetch at 256 KiB per flow and preserves existing global byte policies. | The 32 KiB is not a 113 ms origin receive window. New tests cover TCP/UDP/control progress, cancellation, DNS ordering, FIN and budget pressure. The [repeated device campaign](issue28-tun-validation.md) passed 16 neighboring-download/cancellation checks across H2 and raw TCP. |
| Whole-TUN output suspension | `PacketDevice.outbound` has no intrinsic byte cap. This predates issue #28 and remains separate from per-flow remote prefetch. | Sustained UDP delivery while the host stops draining all TUN output needs a separate egress-budget investigation. The slow-reader campaign does not establish safety for whole-device output suspension. |
| TUN simultaneous upload/download | Download delivery now waits inside the bridge select loop, preserving upload and host cancellation. The existing upload branch still awaits its remote write inline. | A blocked remote upload can still delay downlink on that same flow. This source finding is separate from shared-channel isolation; saturated bidirectional throughput was not measured in this campaign. |
| VLESS / Vision / encryption, SOCKS / HTTP relays, UDP/XUDP | These paths inherit their carrier's flow control; the audit found no second fixed 64 KiB remote receive window in their production code. Relay chunk sizes and bounded queues are local memory/work limits. | Run their existing integrity, cancellation, shutdown, routing and budget tests; this source audit does not rule out every performance bottleneck. UDP/QUIC loss/congestion and real device throughput need separate experiments. |

gRPC's existing wire-setting tests cover zero, small/default and explicit
large windows, and its stalled-stream test checks that one unread flow does
not starve its neighbor. H3's existing tests cover static-window validation,
flow control and cancellation. These guards should stay separate from the
XHTTP/H2 policy change.

## Validation commands

```sh
cargo test -p xray-transport --test stream_xhttp_h2_tests --locked --offline
cargo test --workspace --exclude xray-rust-fuzz --all-targets --locked --offline
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings -W clippy::perf -W clippy::suspicious
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked --offline
cargo fmt --all -- --check
git diff --check
```

Completed validation before adding the optional setting:

- Focused H2: **29 passed**, including all three new regressions. The new
  tests were first run against the original source and all three failed.
- Workspace after the TUN repair: **2,189 passed, 0 failed, 45 ignored**. This includes transport,
  TUN, configuration, routing, proxy/encryption, runtime, FFI and native ABI
  symbol checks. Ignored tests require separate environments/oracles.
- Additional local Go interoperability: **20 passed**, including the full
  **15-case XHTTP H1/H2/H3 × security × mode matrix**, gRPC (including TLS,
  REALITY, server-first and multi-mode), WebSocket, HTTPUpgrade, raw VLESS,
  TLS, Vision, and routing/chaining cases. The Go checkout was clean at the
  pinned `5ca6f4b7d4dc20a881d4330e498892697627ec0c`; the test binary was built by
  the workspace run. It used `XRAY_VLESS_FULL_BINARY` built from that checkout,
  `XRAY_XHTTP_INTEROP_CASES=all` and `XRAY_REALITY_INTEROP_FINGERPRINTS=chrome`.
  Remote-profile, parallel-burst, dedicated encryption-oracle and independent
  download-oracle cases were excluded from this additional run; their normal
  non-ignored Rust tests are included in the workspace result.
- Workspace Clippy (including fuzz, all targets/features), API documentation
  with warnings denied, formatting and whitespace checks: **passed**.

Logs for the TUN repair and fixed 4 MiB policy are in `target/issue28-tun-workspace.log`,
`target/issue28-tun-interop.log`, `target/issue28-tun-clippy.log` and
`target/issue28-tun-doc.log`. The original failed physical campaign is retained
[separately](issue28-iphone-validation.md); the repair and successful repeated
checks are in the [follow-up report](issue28-tun-validation.md).
WAN/CDN and long soak results are not claimed. No release, remote push or
issue comment was made as part of this work.

### Optional H2 window validation

The optional `h2StreamReceiveWindow` implementation was then checked with:

- Configuration: **369 passed**, including integer bounds and invalid types,
  null/default handling, aliases, `extra`, independent downloads and the
  generated configuration contract snapshot.
- H2 engine and XHTTP orchestration: **69 passed**. Custom-window tests
  exercise actual receive credit, partial reads, cancellation and the fixed
  16 MiB connection limit. Pool tests cover all three XHTTP modes, connection
  reuse, idle eviction and GOAWAY replacement. The reuse/eviction test uses
  an injected clock and passed again after removing its wall-clock dependency.
- Outbound compilation: **143 passed**, including independent carrier
  settings and unchanged H1/H3 selection and QUIC window defaults.
- Full workspace: **2,196 passed, 0 failed, 45 ignored**. These include the
  previous TUN, other-transport, routing, encryption and ABI regressions.
- Local Go interoperability: **20 passed** using the same selection, pinned
  Go binary and environment listed above, including all **15 XHTTP cases**.
  The `local_xray_interop_tests` executable built by the workspace run was
  invoked with `--ignored --exact` and those 20 test names.
- Workspace Clippy (all targets/features, including fuzz) and API docs with
  warnings denied, formatting and whitespace checks: **passed**.

Logs use the `target/issue28-h2-setting-` prefix: `config.log`,
`transport.log`, `pool-clock.log`, `core.log`, `workspace.log`, `interop.log`,
`clippy.log` and `doc.log`. The physical-device and throughput reports above retain their
original archived binaries; this optional-setting addition was validated on
the host and does not claim a new iPhone memory or throughput campaign.
