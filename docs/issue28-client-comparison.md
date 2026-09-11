# Issue #28: Rust versus Go client throughput

This experiment compares **actual Rust and Go clients** on the same Mac.
The earlier [iPhone measurements](issue28-tun-validation.md) compared two
Rust builds; their Go process was the server, not the client.

The reporter's CDN profile and download endpoint were not available. This
local experiment cannot establish performance on their iPhone 14 Pro or
route. The connected iPhone 13's TUN and memory evidence remains in the
separate device report. No device app or profile was changed for this run.

## Method

- macOS, ARM64; optimized Rust CLI built with `cargo build --release
  --locked --offline -p xray-cli`, including the final H2 and TUN repairs.
  Base revision: `8a86a7f762aba919ff75cad5980a28612ba2dfe8` (v0.6.0).
- Go client **and** server: Xray-core 26.7.28,
  `5ca6f4b7d4dc20a881d4330e498892697627ec0c`, Go 1.26.0, `x/net` v0.57.0.
- Equivalent generated client configurations: SOCKS5 inbound, VLESS,
  XHTTP `packet-up`, TLS with certificate pinning, Chrome fingerprint,
  ALPN `h2`, `xmux.maxConnections="2-3"`, `scMinPostsIntervalMs=1`.
  All listeners and destinations use loopback. The same Go server stays
  running across both clients and all repetitions.
- One proxied TCP download at a time. Each engine starts fresh, downloads
  a 16 MiB warmup, waits 300 ms, then downloads a new 64 MiB response.
  Six paired rounds alternate Rust/Go and Go/Rust order. Each response is
  checked for exact length and SHA-256, including an excess-data check.
  This warms the engine but does not promise reuse of the same pooled H2
  connection; actual transport connection counts are retained per run.
- The relay adds 56.5 ms to application bytes in each direction. Its
  pipelined queues hold at most 256 chunks of 16 KiB per direction and
  connection. One condition also limits the combined encrypted byte stream
  to 150 Mbit/s per direction; another has no configured rate limit.
  Direct payload and ping controls calibrate the relay in each condition.
- The relay terminates TCP on each side. It delays **application bytes**,
  including H2 flow-control messages; it does not delay TCP ACKs, model
  packet loss, or reproduce a mobile TCP congestion controller. It is not
  Linux netem, WAN/CDN or cellular evidence.
- Throughput is decimal Mbit/s, from sending the download request to
  receiving its last payload byte, including time to first byte. SOCKS
  setup and the subsequent wait for EOF are recorded separately. Both
  clients must produce the correct bytes and clean EOF to pass. This is
  neither aggregate throughput nor a peak over a selected interval.
- Builds and verbose protocol tracing are finished before timed runs.
  A separate short trace confirms both clients advertise a 4 MiB stream
  receive window. Rust retains 16 MiB connection credit; Go advertises
  1 GiB. Trace runs do not contribute throughput samples.

## Results, 2026-09-09 UTC

Host OS was macOS 26.6.2 on ARM64. All **24 measured transfers and 24
warmups** passed exact-length, SHA-256 and EOF checks. Each table cell is
the median of six separate 64 MiB downloads; parentheses show the full
observed range. No timing samples were discarded.

| Relay condition, same added 113 ms | Rust, Mbit/s | Go, Mbit/s |
| --- | ---: | ---: |
| 150 Mbit/s encrypted-byte rate limit | **140.144** (140.098–140.272) | **140.243** (140.138–140.305) |
| No configured rate limit | **184.080** (183.733–184.552) | **256.984** (256.681–257.275) |

Measured ping medians through the delay relay were 116.179 and 116.138 ms,
respectively. Direct relay payload controls reached 145.298 and 541.035
Mbit/s using the same request-to-last-byte metric. That control includes
request/response latency, so its 150 Mbit/s case is expected to measure
below the configured byte rate. Both client engines opened the requested
single flow; Rust opened four transport connections across warmup plus
measurement, Go two, in every engine run.

At the configured 150 Mbit/s rate, Rust was 0.071% below Go by the ratio of
medians, and the observed ranges overlap. **This confirms roughly
140 Mbit/s on our controlled single-connection path.** The rate limit was
chosen for the experiment; it does not confirm the reporter's actual
CDN/device throughput.

Without that rate limit, Rust's payload throughput was **28.37% lower**
than Go's. The ranges do not overlap. The 64 KiB ceiling has been removed,
but equal 4 MiB window settings do not establish equal performance on
faster paths. These SOCKS measurements bypass TUN, so this gap cannot be
attributed to the new TUN prefetch mechanism.

Completion latency is a different result and is retained explicitly:

| Condition | Engine | Median request to last byte, s | Median EOF tail, s | Median full operation including SOCKS and EOF, s |
| --- | --- | ---: | ---: | ---: |
| 150 Mbit/s | Rust | 3.831 | 0.903 | 4.854 |
| 150 Mbit/s | Go | 3.828 | 1.894 | 5.723 |
| No rate limit | Rust | 2.917 | 0.998 | 4.034 |
| No rate limit | Go | 2.089 | 2.003 | 4.094 |

Median SOCKS setup took about 120 ms for Rust and 1 ms for Go. The engines
acknowledge SOCKS setup at different points; the payload-throughput table
therefore does not represent full connection establishment or EOF latency.

## Remaining flow-control difference

A separate 8 MiB diagnostic trace, excluded from the timing results,
observed Rust returning stream credit in increments of **1,400,832 to
1,409,024 bytes** (five updates across its warmup and measured flow).
Go returned **8,190 to 8,194 bytes** per update (1,152 updates). Both
advertised `INITIAL_WINDOW_SIZE=4194304`.

This agrees with the pinned library sources: `h2` 0.4.16's
`proto/streams/flow_control.rs::unclaimed_capacity` waits until returned
credit reaches half the remaining peer-visible window. With immediate
consumption, that is approximately one third of the initial window.
`x/net` v0.57.0's `http2/flow.go::inflow.add` normally sends an update once
at least 4 KiB is accumulated. Our Rust response reader already releases
credit as it copies bytes to the caller.

Coarser credit replenishment is a concrete candidate explanation for the
high-bandwidth gap: it leaves less credit available while updates travel
back to the sender. **The trace and source comparison are not a controlled
proof that this is the entire cause.** Isolating it requires changing only
the update policy and repeating the comparison. Blindly enlarging the
stream window would also increase the stalled-reader memory allowance;
these results do not justify doing that without the separate memory and
isolation checks. No production window, dependency or TUN code was changed
during this measurement campaign.

## Reproduce

Build the Rust CLI and the pinned Go binary, then run:

```sh
python3 scripts/bench-issue28-clients.py \
  --rust-bin target/release/xray-rust \
  --go-bin target/issue28-xray-core \
  --out target/issue28-client-ab-repeat \
  --rounds 6 --payload-mib 64 --warmup-mib 16 \
  --rtt-ms 113 --rates-mbps 150 0
```

The output directory must be new. It retains the runner snapshot, binary
hashes, client/server logs, generated fixture configurations, full per-run
timings, payload hashes and `results.json`. Fixture credentials and keys
are generated locally with private permissions. The runner stops its
child processes and relays on completion or cancellation.

The initial short smoke and pilot runs included the EOF wait in their
throughput denominator. Their lower figures are retained for diagnostics
and are excluded from the final comparison. In the final schema,
`seconds`/`mbps` end at the last payload byte; `eof_seconds` and
`eof_tail_seconds` retain the additional completion delay explicitly.

Final local evidence is in `target/issue28-client-ab-final/`; protocol
diagnostics are in `target/issue28-client-ab-wire/` and
`target/issue28-client-ab-window-trace/`. The final directory's
`manifest.json` records the source, binary, runner, result and log hashes.
No GitHub comment, release, push or device installation was performed.
