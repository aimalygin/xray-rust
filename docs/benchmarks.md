# Benchmarks

The benchmark harness compares `xray-rust` and the cloned Xray-core under the same local workloads. It is a process-level harness: each engine runs as a child process with an equivalent generated Xray JSON config, the workload sends validated traffic through SOCKS5, and the harness samples OS RSS/CPU counters while the process is alive.

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
- `udp-vless`
- `udp-xudp`
- `vision-xudp`

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
cargo run -p xray-bench -- run --engine xray-rust --workload udp-vless --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload udp-xudp --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload vision-xudp --connections 1 --iterations 10 --payload-size 512
cargo run -p xray-bench -- run --engine xray-rust --workload tcp-freedom --runs 5 --connections 8 --iterations 1000 --payload-size 4096
```

By default, the harness uses `target/debug/xray-rust` or builds it with:

```sh
cargo build -p xray-cli --bin xray-rust
```

Use `--xray-rust-bin <path>` to point at an already built binary.

Each run has a watchdog timeout. The default is 30 seconds; override it with
`--run-timeout-ms <milliseconds>` when exercising intentionally slow workloads.
On timeout, the harness drops the running engine handle so the child process is
terminated instead of leaving a stuck benchmark behind.

## Compare With Xray-core

From the main repository checkout:

```sh
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 10 --payload-size 1024
cargo run -p xray-bench -- compare --workload many-idle-flows --xray-core-dir Xray-core --runs 5 --connections 100 --duration-ms 1000
cargo run -p xray-bench -- compare --workload reconnect-burst --xray-core-dir Xray-core --runs 5 --connections 16 --iterations 25
cargo run -p xray-bench -- compare --workload mixed-long-lived --xray-core-dir Xray-core --runs 5 --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-udp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-freedom --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 100 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-vless --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload vision-xudp --xray-core-dir Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
```

From an isolated worktree under `.worktrees/`, pass the main checkout's Xray-core path:

```sh
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 10 --payload-size 1024
cargo run -p xray-bench -- compare --workload many-idle-flows --xray-core-dir ../../Xray-core --runs 5 --connections 100 --duration-ms 1000
cargo run -p xray-bench -- compare --workload reconnect-burst --xray-core-dir ../../Xray-core --runs 5 --connections 16 --iterations 25
cargo run -p xray-bench -- compare --workload mixed-long-lived --xray-core-dir ../../Xray-core --runs 5 --connections 8 --iterations 20 --duration-ms 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-udp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload tun-tcp-freedom --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 100 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-vless --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload udp-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
cargo run -p xray-bench -- compare --workload vision-xudp --xray-core-dir ../../Xray-core --runs 5 --connections 1 --iterations 1000 --payload-size 512
```

The compare command auto-builds `target/debug/xray-rust` and an Xray-core binary under the run directory unless `--no-auto-build` is provided. Repeated runs reuse the Xray-core binary built for that benchmark group. Use `--xray-core-bin <path>` to benchmark an existing Xray-core binary without rebuilding.

## Metrics

The first scoreboard is intentionally portable and comparable across Go and Rust:

- peak resident set size from `ps` RSS.
- CPU time delta from `ps` cumulative process time.
- CPU milliseconds per GiB transferred when a workload moves payload bytes.
- thread count when the local `ps` implementation exposes it.
- validated bytes sent and received by the workload.
- latency microsecond percentiles for traffic workloads. For `many-idle-flows`, latency is SOCKS TCP flow setup time.
- setup microsecond breakdown for SOCKS TCP setup workloads: local TCP connect to the inbound, SOCKS setup including CONNECT response, and total setup time.
- min, median, and p95 aggregates across repeated runs.

`tcp-freedom`, `udp-freedom`, `tun-udp-freedom`, `udp-vless`, `udp-xudp`, and `vision-xudp` record one round-trip latency sample per validated payload iteration. `summary.json` aggregates each run's latency min/median/p95/p99 across repeated runs.
`many-idle-flows` opens `--connections` SOCKS TCP flows to a local target, keeps them idle for `--duration-ms`, and reports RSS/CPU while those flows are held. This is the first local memory-slope workload; compare its peak RSS against `idle` and divide the delta by the connection count for an approximate per-flow resident-memory cost.
`reconnect-burst` repeatedly opens and closes SOCKS TCP flows with `--connections` parallel workers and `--iterations` reconnects per worker. It is intended to separate base setup cost from the memory slope of held idle flows.
`mixed-long-lived` keeps TCP and UDP SOCKS flows open together, paces `--iterations` across `--duration-ms`, and validates both echo paths. It is a local mobile-like foreground/background traffic mix.
`udp-freedom` uses SOCKS5 UDP ASSOCIATE with the inbound configured as `{ "udp": true, "ip": "127.0.0.1" }`, then validates echoed UDP payloads through a local UDP target.
`tun-udp-freedom` uses a Unix `socketpair` as an inherited fd-backed TUN device, sends Darwin utun-framed IPv4/UDP packets into a `tun` inbound, and validates echoed payloads from a local UDP server. It does not create a real system utun interface, install routes, or require root. To stay compatible with Xray-core's gVisor martian-packet filter, the UDP target is the host's local non-loopback IPv4 address rather than `127.0.0.1`.
`tun-tcp-freedom` uses the same inherited fd-backed TUN path with a smoltcp TCP client on the benchmark side. It completes a TCP handshake through the TUN inbound, sends echo payloads, and validates the returned TCP stream data without installing host routes.
`udp-vless` uses the same SOCKS5 UDP client path, but routes through a local fake VLESS UDP server over TCP before validating echoed UDP payloads. It targets UDP/53 to keep the VLESS UDP framing length-prefixed.
`udp-xudp` targets a non-DNS UDP port and validates XUDP/Mux frames through the local fake VLESS server.
`vision-xudp` uses VLESS over local TLS with `xtls-rprx-vision`, `allowInsecure`, and XUDP/Mux frames against a local fake Vision server.

Later benchmark slices should add TCP-over-TUN workloads and mobile-native traces from Instruments or Perfetto. This harness keeps those paths open without putting benchmark logic into the production runtime.
