# Benchmarks

The benchmark harness compares `xray-rust`, the cloned Xray-core, and sing-box under the same local workloads. It is a process-level harness: each engine runs as a child process with an equivalent generated config, the workload sends validated traffic through SOCKS5, and the harness samples OS RSS/CPU counters while the process is alive.

## First Slice

Supported workloads:

- `idle`
- `tcp-freedom`
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

```sh
cargo run -p xray-bench -- run --engine sing-box --sing-box-bin /private/tmp/sing-box-bench/sing-box --workload idle --duration-ms 1000 --no-auto-build
cargo run -p xray-bench -- run --engine sing-box --sing-box-bin /private/tmp/sing-box-bench/sing-box --workload many-idle-flows --connections 100 --duration-ms 1000 --no-auto-build
```

The first sing-box slice supports the SOCKS/process-level workloads: `idle`, `tcp-freedom`, `many-idle-flows`, `reconnect-burst`, `mixed-long-lived`, `udp-freedom`, and `reality-vision-xudp`. The Reality/Vision workload starts an Xray-core VLESS Reality server fixture and samples only the client engine process. The sing-box binary must include `with_utls`; the harness uses `with_gvisor,with_utls,badlinkname,tfogo_checklinkname0` when auto-building sing-box. TUN and fake VLESS/XUDP sing-box workloads are intentionally not part of this slice because they need a different topology than the rootless fd-backed harness.

Each run has a watchdog timeout. The default is 30 seconds; override it with
`--run-timeout-ms <milliseconds>` when exercising intentionally slow workloads.
On timeout, the harness drops the running engine handle so the child process is
terminated instead of leaving a stuck benchmark behind.

## Compare Engines

From the main repository checkout, these process-level workloads compare all three engines:

```sh
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 1 --iterations 10 --payload-size 1024
cargo run -p xray-bench -- compare --workload many-idle-flows --xray-core-dir Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 100 --duration-ms 1000
cargo run -p xray-bench -- compare --workload reconnect-burst --xray-core-dir Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 16 --iterations 25
cargo run -p xray-bench -- compare --workload mixed-long-lived --xray-core-dir Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-freedom --xray-core-dir Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload reality-vision-xudp --xray-core-dir Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 1 --iterations 1000 --payload-size 512
```

The TUN and fake VLESS/XUDP workloads remain comparable between `xray-rust` and Xray-core in this slice. The compare command skips sing-box for these workloads because sing-box's CLI TUN path uses a real platform TUN topology, while the older VLESS/XUDP fake-server workloads use Xray JSON configs instead of sing-box outbound schema.

```sh
cargo run -p xray-bench -- compare --workload tun-udp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 100 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-stale-flows --xray-core-dir Xray-core --runs 5 --connections 500 --iterations 1 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-reality-blackhole --xray-core-dir Xray-core --runs 5 --connections 500 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-vless --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload vision-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
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
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir ../../Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 1 --iterations 10 --payload-size 1024
cargo run -p xray-bench -- compare --workload many-idle-flows --xray-core-dir ../../Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 100 --duration-ms 1000
cargo run -p xray-bench -- compare --workload reconnect-burst --xray-core-dir ../../Xray-core --runs 5 --connections 16 --iterations 25
cargo run -p xray-bench -- compare --workload mixed-long-lived --xray-core-dir ../../Xray-core --runs 5 --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload reality-vision-xudp --xray-core-dir ../../Xray-core --sing-box-bin /private/tmp/sing-box-bench/sing-box --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-udp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 100 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-stale-flows --xray-core-dir ../../Xray-core --runs 5 --connections 500 --iterations 1 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-reality-blackhole --xray-core-dir ../../Xray-core --runs 5 --connections 500 --duration-ms 5000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-vless --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload vision-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
```

The compare command auto-builds `target/debug/xray-rust`, an Xray-core binary, and a sing-box binary under the run directory unless `--no-auto-build` is provided. Repeated runs reuse binaries built for that benchmark group. Use `--xray-core-bin <path>` and `--sing-box-bin <path>` to benchmark existing binaries without rebuilding.

## Metrics

The first scoreboard is intentionally portable and comparable across Go and Rust:

- peak resident set size from `ps` RSS.
- CPU time delta from `ps` cumulative process time.
- CPU milliseconds per GiB transferred when a workload moves payload bytes.
- thread count when the local `ps` implementation exposes it.
- validated bytes sent and received by the workload.
- latency microsecond percentiles for traffic workloads. For `many-idle-flows`, latency is SOCKS TCP flow setup time.
- setup microsecond breakdown for SOCKS TCP setup workloads: local TCP connect to the inbound, SOCKS method negotiation, SOCKS CONNECT request/response, full SOCKS setup, and total setup time.
- min, median, and p95 aggregates across repeated runs.

`tcp-freedom`, `udp-freedom`, `tun-udp-freedom`, `udp-vless`, `udp-xudp`, `vision-xudp`, and `reality-vision-xudp` record one round-trip latency sample per validated payload iteration. `summary.json` aggregates each run's latency min/median/p95/p99 across repeated runs.
`many-idle-flows` opens `--connections` SOCKS TCP flows to a local target, keeps them idle for `--duration-ms`, and reports RSS/CPU while those flows are held. This is the first local memory-slope workload; compare its peak RSS against `idle` and divide the delta by the connection count for an approximate per-flow resident-memory cost.
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
