# Benchmarks

The benchmark harness compares `xray-rust`, the cloned Xray-core, and sing-box under the same local workloads. It is a process-level harness: each engine runs as a child process with an equivalent generated config, the workload sends validated traffic through SOCKS5, and the harness samples OS RSS/CPU counters while the process is alive.

## First Slice

Supported workloads:

- `idle`
- `tcp-freedom`
- `tcp-bulk-throughput`
- `routed-tcp-freedom`
- `many-idle-flows`
- `reconnect-burst`
- `mixed-long-lived`
- `udp-freedom`
- `tun-udp-freedom`
- `tun-tcp-freedom`
- `tun-tcp-stale-flows`
- `tun-reality-blackhole`
- `udp-vless`
- `udp-xudp`
- `vision-xudp`
- `reality-vision-xudp`

The harness writes results under:

```text
target/benchmarks/<run-id>/<engine>/<workload>/
```

For one run, the workload directory contains:

- `config.json`: generated engine config.
- `result.json`: summary RSS, CPU, throughput bytes, status, and workload metadata.
- `samples.csv`: raw timestamped process samples.
- `stdout.log` and `stderr.log`: child process logs.
- `summary.json`: min/median/p95 aggregate summary. With one run, all three values match the single run.

When `--runs N` is greater than `1`, the workload directory contains `summary.json` plus one subdirectory per raw run:

```text
target/benchmarks/<run-id>/<engine>/<workload>/run-001/
target/benchmarks/<run-id>/<engine>/<workload>/run-002/
target/benchmarks/<run-id>/<engine>/<workload>/run-003/
```

## Run xray-rust Only

```sh
cargo run -p xray-bench -- run --engine xray-rust --workload idle --duration-ms 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tcp-freedom --connections 1 --iterations 10 --payload-size 1024
cargo run --release -p xray-bench -- run --engine xray-rust --workload tcp-bulk-throughput --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
scripts/fetch-geodata.sh --output-dir /private/tmp/bench-geodata
cargo run --release -p xray-bench -- run --engine xray-rust --workload routed-tcp-freedom --geodata-dir /private/tmp/bench-geodata --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000
cargo run -p xray-bench -- run --engine xray-rust --workload many-idle-flows --connections 100 --duration-ms 1000
cargo run -p xray-bench -- run --engine xray-rust --workload reconnect-burst --connections 16 --iterations 25
cargo run -p xray-bench -- run --engine xray-rust --workload mixed-long-lived --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload udp-freedom --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-udp-freedom --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-tcp-freedom --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-tcp-stale-flows --connections 500 --iterations 1 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-reality-blackhole --connections 500 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload udp-vless --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload udp-xudp --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload vision-xudp --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload reality-vision-xudp --xray-core-bin /path/to/xray-core --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tcp-freedom --runs 5 --connections 8 --iterations 1000 --payload-size 4096
cargo run -p xray-bench -- route-probe --iterations 100000 --rules 64 --outbounds 8
```

By default, the harness uses `target/debug/xray-rust` or builds it with:

```sh
cargo build -p xray-cli --bin xray-rust
```

Use `--xray-rust-bin <path>` to point at an already built binary.

## REALITY Fingerprint Matrix

`reality-matrix` is an in-process `xray-rust` functional/benchmark matrix for
VLESS `xtls-rprx-vision` over REALITY against a real local Xray-core server
fixture. It starts `Core` directly with `StartupProbeOptions`, so the connection
startup path includes the same startup probe hook used by the Apple packet tunnel
extension. The startup probe is always run first for each fingerprint as an
active REALITY/Vision readiness probe for the Xray-core fixture; if
`startup-probe` is not selected in `--traffic`, the warmup result is omitted
unless it fails. The local topology is:

```text
traffic client -> SOCKS 127.0.0.1:<ephemeral> -> xray-rust Core
  -> VLESS REALITY Vision -> local xray-core server fixture -> local target
```

By default, the command runs every `XRAY_REALITY_CAPABLE_FINGERPRINTS`
fingerprint and every traffic kind:

- `startup-probe`: HTTP `204` probe through the REALITY outbound.
- `tcp-connect`: SOCKS CONNECT to a local TCP target, then close.
- `tcp-echo-small`: validated small TCP echo payload.
- `tcp-echo-body`: validated larger TCP echo payload.
- `http-first-byte`: HTTP GET through the tunnel, wait for first response body byte.
- `http-body`: HTTP GET through the tunnel, read and validate the full response body.
- `udp-xudp-echo`: SOCKS UDP ASSOCIATE through Vision/XUDP to a local UDP echo target.

Examples:

```sh
cargo run -p xray-bench -- reality-matrix --xray-core-dir Xray-core
cargo run -p xray-bench -- reality-matrix --xray-core-dir Xray-core --fingerprints chrome,hellochrome_120_pq --traffic startup-probe,tcp-connect,http-body,udp-xudp-echo --iterations 3 --body-bytes 1048576
```

Useful options:

- `--fingerprints <csv>`: comma-separated supported fingerprints, or `all`.
- `--traffic <csv>`: comma-separated traffic kinds, or `all`.
- `--iterations <n>`: repeat each traffic case.
- `--small-payload-size <bytes>`: payload for `tcp-echo-small` and `udp-xudp-echo`.
- `--body-bytes <bytes>`: payload/body size for `tcp-echo-body` and `http-body`.
- `--probe-timeout-ms <ms>`: startup probe timeout. The matrix default is
  15000ms because the local Xray-core REALITY fixture can spend up to about 5s
  preparing its first post-handshake record detector path; pass `5000` for
  strict Apple extension default-timeout coverage.
- `--run-timeout-ms <ms>`: watchdog per startup or traffic case.
- `--xray-core-bin <path>` / `--xray-core-dir <path>` / `--no-auto-build`: Xray-core fixture selection.

Results are written to:

```text
target/benchmarks/<run-id>/reality-matrix/
```

The directory contains `result.json` with every fingerprint/traffic case status,
per-case latency/setup summaries, byte counts, and error messages. Generated
per-fingerprint client configs are stored under `configs/`.

## Run sing-box Only

Point `SING_BOX_BIN` at a local sing-box executable. Use any location on the
host; `/path/to/sing-box` below is only a placeholder:

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo run -p xray-bench -- run --engine sing-box --sing-box-bin "$SING_BOX_BIN" --workload idle --duration-ms 1000 --no-auto-build
cargo run -p xray-bench -- run --engine sing-box --sing-box-bin "$SING_BOX_BIN" --workload many-idle-flows --connections 100 --duration-ms 1000 --no-auto-build
```

The first sing-box slice supports the SOCKS/process-level workloads: `idle`, `tcp-freedom`, `tcp-bulk-throughput`, `many-idle-flows`, `reconnect-burst`, `mixed-long-lived`, `udp-freedom`, and `reality-vision-xudp`. The Reality/Vision workload starts an Xray-core VLESS Reality server fixture and samples only the client engine process. The sing-box binary must include `with_utls`; the harness uses `with_gvisor,with_utls,badlinkname,tfogo_checklinkname0` when auto-building sing-box. TUN and fake VLESS/XUDP sing-box workloads are intentionally not part of this slice because they need a different topology than the rootless fd-backed harness.

Each run has a watchdog timeout. The default is 30 seconds; override it with
`--run-timeout-ms <milliseconds>` when exercising intentionally slow workloads.
On timeout, the harness drops the running engine handle so the child process is
terminated instead of leaving a stuck benchmark behind.

## Compare Engines

From the main repository checkout, these process-level workloads compare all three engines:

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 10 --payload-size 1024
cargo run --release -p xray-bench -- compare --workload tcp-bulk-throughput --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
cargo run -p xray-bench -- compare --workload many-idle-flows --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 100 --duration-ms 1000
cargo run -p xray-bench -- compare --workload reconnect-burst --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 16 --iterations 25
cargo run -p xray-bench -- compare --workload mixed-long-lived --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-freedom --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload reality-vision-xudp --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 1000 --payload-size 512
```

The TUN and fake VLESS/XUDP workloads remain comparable between `xray-rust` and Xray-core in this slice. The compare command skips sing-box for these workloads because sing-box's CLI TUN path uses a real platform TUN topology, while the older VLESS/XUDP fake-server workloads use Xray JSON configs instead of sing-box outbound schema. `routed-tcp-freedom` is also xray-rust vs Xray-core only: sing-box ≥1.8 does not read Xray-format `.dat` geodata, and semantically equivalent `.srs` rule-sets cannot be guaranteed.

```sh
cargo run -p xray-bench -- compare --workload tun-udp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 100 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-stale-flows --xray-core-dir Xray-core --runs 5 --connections 500 --iterations 1 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-reality-blackhole --xray-core-dir Xray-core --runs 5 --connections 500 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-vless --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload vision-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run --release -p xray-bench -- compare --workload routed-tcp-freedom --xray-core-dir Xray-core --geodata-dir /private/tmp/bench-geodata --runs 5 --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000
```

The TUN workloads can also be run with xray-rust runtime profiles. The harness
passes `--tun-profile` through as `XRAY_TUN_PROFILE` for the engine process, so
the same TUN fd workload can be sampled under `default`, `low-memory`, or
`throughput` queue/budget presets:

```bash
cargo run -p xray-bench -- run --engine xray-rust --workload tun-udp-freedom --tun-profile low-memory --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tun-tcp-freedom --tun-profile throughput --connections 1 --iterations 100 --payload-size 1024
```

From an isolated worktree under `.worktrees/`, pass the main checkout's Xray-core path:

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir ../../Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 10 --payload-size 1024
cargo run -p xray-bench -- compare --workload many-idle-flows --xray-core-dir ../../Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 100 --duration-ms 1000
cargo run -p xray-bench -- compare --workload reconnect-burst --xray-core-dir ../../Xray-core --runs 5 --connections 16 --iterations 25
cargo run -p xray-bench -- compare --workload mixed-long-lived --xray-core-dir ../../Xray-core --runs 5 --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload reality-vision-xudp --xray-core-dir ../../Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-udp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 100 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-stale-flows --xray-core-dir ../../Xray-core --runs 5 --connections 500 --iterations 1 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-reality-blackhole --xray-core-dir ../../Xray-core --runs 5 --connections 500 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-vless --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload vision-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
```

The compare command auto-builds `target/debug/xray-rust`, an Xray-core binary, and a sing-box binary under the run directory unless `--no-auto-build` is provided. Repeated runs reuse binaries built for that benchmark group. Use `--xray-core-bin <path>` and `--sing-box-bin <path>` to benchmark existing binaries without rebuilding.

## Publishing Numbers and Charts

Numbers quoted in the README must come from release builds on both sides. The
harness's default debug auto-build of `xray-rust` is for development only; Go
engines are always optimized builds, so a debug Rust binary makes whichever
number you quote untrustworthy. Build and pass the release binary explicitly,
and run the harness itself in release so client-side stream validation is not
the bottleneck:

```sh
export SING_BOX_BIN=/path/to/sing-box
cargo build --release -p xray-cli --bin xray-rust
cargo run --release -p xray-bench -- compare --workload tcp-bulk-throughput \
  --xray-rust-bin target/release/xray-rust --xray-core-dir Xray-core \
  --sing-box-bin "$SING_BOX_BIN" \
  --runs 5 --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
```

Run the same release-binary compare for each charted workload — `idle`,
`many-idle-flows` ×100 and ×1000 (the ×1000 run needs a raised `ulimit -n`;
see the workload note), `tcp-freedom`, `reality-vision-xudp`,
`tcp-bulk-throughput`, and `routed-tcp-freedom` (seven series in total; the
last needs `--geodata-dir` after fetching geodata with
`scripts/fetch-geodata.sh --output-dir /private/tmp/bench-geodata`, see
above). Each compare invocation writes one `target/benchmarks/<run-id>`
group; the `--group` flags passed to `chart` must jointly cover all seven
series.

`chart` renders the README SVG charts from one or more compare run groups:

```sh
cargo run --release -p xray-bench -- chart \
  --group target/benchmarks/<run-id-1> --group target/benchmarks/<run-id-2> \
  --date 2026-07-29 \
  --hardware "Apple M4 Pro, 24 GB RAM, macOS 15.5" \
  --xray-rust-version <git-short-rev> \
  --xray-core-version v26.5.9 \
  --sing-box-version <sing-box-tag> \
  --geodata-version "geosite-<tag> geoip-<tag>"
```

It reads `<group>/<engine>/<workload>/summary.json` for `idle`,
`many-idle-flows` (once per charted connection count), `tcp-freedom`,
`reality-vision-xudp`, `tcp-bulk-throughput` across all three engines, and
`routed-tcp-freedom` across xray-rust and Xray-core only, and writes
light/dark SVG pairs (`memory-rss`, `latency`, `throughput`, `cpu-per-gib`,
`geo-setup-latency`, `geo-memory`) to `docs/benchmarks/media/` (override with
`--out-dir`). Charts select `many-idle-flows` summaries by their recorded
connection count, so both scales come from separate compare runs; geo charts
read the `routed-tcp-freedom` summaries (xray-rust and Xray-core only — no
sing-box series, and the setup-latency chart carries the reply-time caveat,
see the routed-tcp-freedom workload note in the Metrics section below).
Metadata is passed by flags rather than sniffed so regeneration is
deterministic; `--geodata-version` is
optional and only prints a warning if omitted, since it labels the geo charts
rather than gating them. The command fails if any required summary is
missing or its status is not `ok`. Bars show the median across runs;
whiskers span min to p95 (for latency: min run median up to the median run
p95).

## Metrics

The first scoreboard is intentionally portable and comparable across Go and Rust:

- peak resident set size from `ps` RSS.
- CPU time delta from `ps` cumulative process time.
- CPU milliseconds per GiB transferred when a workload moves payload bytes.
- throughput megabits per second when a workload moves payload bytes, computed from validated bytes over measured wall time. The byte count aggregates both directions, matching the CPU-per-GiB convention, so echo-style workloads read roughly twice their one-way goodput; quote streaming throughput from `tcp-bulk-throughput`, where traffic is one-directional.
- thread count when the local `ps` implementation exposes it.
- validated bytes sent and received by the workload.
- latency microsecond percentiles for traffic workloads. For `many-idle-flows`, latency is SOCKS TCP flow setup time.
- setup microsecond breakdown for SOCKS TCP setup workloads: local TCP connect to the inbound, SOCKS method negotiation, SOCKS CONNECT request/response, full SOCKS setup, and total setup time.
- min, median, and p95 aggregates across repeated runs.

`tcp-freedom`, `udp-freedom`, `tun-udp-freedom`, `udp-vless`, `udp-xudp`, `vision-xudp`, and `reality-vision-xudp` record one round-trip latency sample per validated payload iteration. `summary.json` aggregates each run's latency min/median/p95/p99 across repeated runs.
`tcp-bulk-throughput` streams a deterministic byte pattern from a local TCP source through SOCKS5 CONNECT as one continuous transfer per connection (`--iterations` chunks of `--payload-size` bytes). The client validates the pattern chunk-by-chunk while reading, so throughput covers only verified bytes. Unlike `tcp-freedom` it has no per-iteration round trip, making it the workload to quote for streaming throughput.
`routed-tcp-freedom` is `tcp-freedom` with SOCKS5 domain CONNECT through a
config carrying real geosite/geoip routing rules
(`geosite:category-ads-all`, `geoip:private`, `geoip:cn`, `geosite:cn`) and
several tagged `freedom` outbounds. Connections alternate between a domain
that matches the last geosite rule and one that falls through every rule to
the default outbound; both resolve to `127.0.0.1` via `dns.hosts`, so no
packet leaves the machine. `--geodata-dir` must contain `geosite.dat` and
`geoip.dat` (fetch pinned, checksum-verified files with
`scripts/fetch-geodata.sh --output-dir <dir>`). Headline numbers:
`setup_socks_connect_us` (time from SOCKS CONNECT request to the engine's
reply) and `peak_rss_kib` (matcher memory for the loaded geodata).

**Measurement asymmetry:** the two engines send the SOCKS reply at different
pipeline stages — xray-rust replies after rule evaluation, hosts resolution,
and the local dial complete (`crates/xray-core-rs/src/socks.rs`, non-sniffing
path), while Xray-core replies during the SOCKS handshake before routing and
dialing (`proxy/socks/protocol.go` → `writeSocks5Response`, dispatch
afterwards). The chart therefore compares different spans of work and must
not be read as a pure routing-cost comparison; it is published as "time to
SOCKS reply" with this note.

`many-idle-flows` opens `--connections` SOCKS TCP flows to a local target, keeps them idle for `--duration-ms`, and reports RSS/CPU while those flows are held. This is the first local memory-slope workload; compare its peak RSS against `idle` and divide the delta by the connection count for an approximate per-flow resident-memory cost. For a scale point, the publication charts also run `many-idle-flows` with
`--connections 1000`. xray-rust's inbounds have no application-level
connection cap (matching Xray-core and sing-box); the ceiling is the
process's file-descriptor limit, which the CLI raises to the hard limit at
startup the way the Go runtime does. The harness side needs a
file-descriptor limit of several thousand (`ulimit -n`).
`reconnect-burst` repeatedly opens and closes SOCKS TCP flows with `--connections` parallel workers and `--iterations` reconnects per worker. It is intended to separate base setup cost from the memory slope of held idle flows.
`mixed-long-lived` keeps TCP and UDP SOCKS flows open together, paces `--iterations` across `--duration-ms`, and validates both echo paths. It is a local mobile-like foreground/background traffic mix.
`udp-freedom` uses SOCKS5 UDP ASSOCIATE with the inbound configured as `{ "udp": true, "ip": "127.0.0.1" }`, then validates echoed UDP payloads through a local UDP target.
`tun-udp-freedom` uses a Unix `socketpair` as an inherited fd-backed TUN device, sends Darwin utun-framed IPv4/UDP packets into a `tun` inbound, and validates echoed payloads from a local UDP server. It does not create a real system utun interface, install routes, or require root. To stay compatible with Xray-core's gVisor martian-packet filter, the UDP target is the host's local non-loopback IPv4 address rather than `127.0.0.1`.
`tun-tcp-freedom` uses the same inherited fd-backed TUN path with a smoltcp TCP client on the benchmark side. It completes a TCP handshake through the TUN inbound, sends echo payloads, validates the returned TCP stream data, and sends a final RST so each measured flow is released before the next one starts.
`tun-tcp-stale-flows` uses the same path but deliberately drops each synthetic client without FIN or RST, then holds the engine for `--duration-ms`. It measures the RSS/CPU cost of TUN flows whose client disappeared before TCP teardown reached the tunnel.
`tun-reality-blackhole` routes those synthetic TUN TCP flows through VLESS Reality Vision to a local TCP server that accepts connections but never sends a TLS ServerHello. Its generated policy sets `handshake` to one second, while the workload holds the process for `--duration-ms`. Compare it with `tun-tcp-stale-flows` to separate userspace TCP flow memory from pending Reality/TLS-open memory and to check whether each engine enforces the configured handshake deadline. For xray-rust, a hold interval longer than the configured handshake must report zero active blackhole connections. The CLI and `result.json` report blackhole connections as accepted/active after the hold interval, so socket cleanup is observable even when an allocator keeps process RSS high. macOS runs use the desktop TUN profile; Apple mobile builds additionally cap active TCP flows and concurrent pending opens according to their mobile runtime profile.
`udp-vless` uses the same SOCKS5 UDP client path, but routes through a local fake VLESS UDP server over TCP before validating echoed UDP payloads. It targets UDP/53 to keep the VLESS UDP framing length-prefixed.
`udp-xudp` targets a non-DNS UDP port and validates XUDP/Mux frames through the local fake VLESS server.
`vision-xudp` uses VLESS over local TLS with `xtls-rprx-vision` and XUDP/Mux
frames against a local fake Vision server. The xray-rust benchmark config uses
`allowInsecure` for that local self-signed certificate; the Xray-core config uses
`pinnedPeerCertSha256`, matching newer Xray-core releases where `allowInsecure`
has been removed.
`reality-vision-xudp` uses VLESS Reality with `xtls-rprx-vision` and XUDP/Mux frames against an Xray-core server fixture, then validates echoed UDP payloads through the same SOCKS5 UDP client path. The fixture process is not sampled in RSS/CPU; only the selected client engine is sampled.

`route-probe` is an in-process xray-rust microprobe for setup-path routing cost. It builds a synthetic config with IP/CIDR routing rules and tagged freedom outbounds, then repeatedly calls the same TCP outbound selection path used by SOCKS CONNECT. This isolates routing/outbound selection from TCP accept, SOCKS parsing, and outbound socket connect noise.

Later benchmark slices should add TCP-over-TUN workloads and mobile-native traces from Instruments or Perfetto. This harness keeps those paths open without putting benchmark logic into the production runtime.
