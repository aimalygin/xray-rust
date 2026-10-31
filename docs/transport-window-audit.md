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
- h2 keeps received DATA frames as slices of its shared read buffer, so
  frames waiting for a slow reader pinned roughly twice their size. A
  per-response task now takes DATA from h2 as it arrives and copies only
  frames that must wait into exact-size buffers. The queue is still bounded
  by the unreturned credit. Eight stalled downloads through TUN fell from a
  65 MiB to a 44 MiB footprint.
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
| XHTTP/H2 after the 4 MiB fix | The 2026-09-09 [direct Rust/Go client comparison](issue28-client-comparison.md) reached about 140 Mbit/s in both clients with a 150 Mbit/s byte-rate limit at an added 113 ms, but 184 versus 257 Mbit/s without it; Rust returned stream credit in 1.4 MB steps against Go's 8 KiB. | **Fixed 2026-10-30:** a vendored h2 option returns stream credit once a sixteenth of the window has been read, at least 4 KiB (x/net/http2's `inflowMinRefresh`, which Go uses alone). The re-measurement on the same runner reached 261.9 Mbit/s for Rust and 253.0 for Go without a rate limit. A 4 KiB threshold measured 268.5, but its WINDOW_UPDATE per read cost fast local downloads 16%. These measurements bypass TUN. |
| gRPC/H2 | `stream/grpc/h2client.rs` kept a 65,535-byte stream window with no BDP estimator, while grpc-go under Xray's default `grpcSettings` grows its windows up to 16 MiB. At an added 113 ms the 2026-10-30 runner measured 4.4 Mbit/s for Rust against about 125 for Go. | **Fixed 2026-10-30:** `stream/h2_bdp.rs` grows the windows as grpc-go's estimator does, up to 16 MiB, or 1 MiB on a constrained host. Any `initialWindowsSize` above zero still pins them; the opening SETTINGS are unchanged. The connection window grows to sixteen stream windows, so never fewer than sixteen stalled flows can block the rest. |
| XHTTP/H3 | `stream/xhttp/h3.rs` used fixed 2 MiB stream / 3 MiB connection windows, while the reference grows toward 6 MiB / 15 MiB. The pool allows one active request per QUIC connection. | **Fixed 2026-10-30:** downloads auto-tune the windows by quic-go's rule up to 6 MiB / 15 MiB or the configured maxima; a constrained host keeps them fixed. Vendored quinn gained `set_stream_receive_window`. The send window starts at 2 MiB and grows toward twice the congestion window (at most 10 MB), as Hysteria's does; connections that upload at the same time share 16 MiB (4 MiB on a constrained host), each keeping its share between 128 KiB and 2 MiB and growing to at most 10 MB divided among them ([2026-10-30 report](benchmarks/results/2026-10-30-xhttp-h3-send-budget/README.md)). **2026-10-31:** downloads share 16 MiB of stream credit (4 MiB on a constrained host) the same way, but a download is held to its share only while its reader falls behind, and never below 128 KiB or what its reader took in the last two round trips; vendored quinn's `set_stream_receive_window` can now lower a window without withdrawing credit ([2026-10-31 report](benchmarks/results/2026-10-31-xhttp-h3-receive-budget/README.md)). One request per connection remains a deliberate guard against peers advertising one bidirectional stream. |
| XHTTP packet-up | `stream/xhttp/config.rs` defaults to a 1,000,000-byte POST maximum and 30 ms minimum POST interval. H1 waits for the preceding POST response; H2/H3 allow response monitors to overlap after upload completes. | Upload can be limited by pacing, POST size and (for H1) request/response RTT. Even full 1 MB POSTs imply about 267 Mbit/s at 30 ms pacing; small packets can be slower. This is configured/reference-compatible behavior, not a receive-window fix. |
| Raw TCP, TLS/REALITY, WebSocket, HTTPUpgrade, XHTTP/H1 downlink | No additional fixed application-level acknowledgement window found. `connect_tcp_stream` enables TCP_NODELAY and leaves TCP send/receive buffer tuning to the OS. WebSocket frame and relay chunk sizes do not require one network RTT per chunk. | There can still be framing/CPU/TCP bottlenecks; increasing every small buffer is not justified by issue #28. Preserve the current behavior and verify carrier/lifecycle tests. |
| TUN TCP | smoltcp has two 32 KiB socket buffers; its TCP peer is the local application, not the remote origin. Previously, one blocked `RemoteData` event stopped the shared event receiver. The repair retries deferred flows independently, caps remote prefetch at 256 KiB per flow and preserves existing global byte policies. In the upload direction each flow holds at most 512 KiB (desktop), 256 KiB (mobile) or 128 KiB (low memory) between smoltcp and its outbound, written in coalesced chunks of at most 64 KiB; the earlier message-count bound allowed 8 MiB. | The 32 KiB is not a 113 ms origin receive window. New tests cover TCP/UDP/control progress, cancellation, DNS ordering, FIN and budget pressure. The [repeated device campaign](issue28-tun-validation.md) passed 16 neighboring-download/cancellation checks across H2 and raw TCP. |
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
