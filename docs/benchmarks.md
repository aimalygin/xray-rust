# Benchmarks

The benchmark harness compares `xray-rust` and the cloned Xray-core under the same local workloads. It is a process-level harness: each engine runs as a child process with an equivalent generated Xray JSON config, the workload sends validated traffic through SOCKS5, and the harness samples OS RSS/CPU counters while the process is alive.

## First Slice

Supported workloads:

- `idle`
- `tcp-freedom`

The harness writes results under:

```text
target/benchmarks/<run-id>/<engine>/<workload>/
```

Each run directory contains:

- `config.json`: generated engine config.
- `result.json`: summary RSS, CPU, throughput bytes, status, and workload metadata.
- `samples.csv`: raw timestamped process samples.
- `stdout.log` and `stderr.log`: child process logs.

## Run xray-rust Only

```sh
cargo run -p xray-bench -- run --engine xray-rust --workload idle --duration-ms 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tcp-freedom --connections 1 --iterations 10 --payload-size 1024
```

By default, the harness uses `target/debug/xray-rust` or builds it with:

```sh
cargo build -p xray-cli --bin xray-rust
```

Use `--xray-rust-bin <path>` to point at an already built binary.

## Compare With Xray-core

From the main repository checkout:

```sh
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir Xray-core --connections 1 --iterations 10 --payload-size 1024
```

From an isolated worktree under `.worktrees/`, pass the main checkout's Xray-core path:

```sh
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir ../../Xray-core --connections 1 --iterations 10 --payload-size 1024
```

The compare command auto-builds `target/debug/xray-rust` and an Xray-core binary under the run directory unless `--no-auto-build` is provided. Use `--xray-core-bin <path>` to benchmark an existing Xray-core binary without rebuilding.

## Metrics

The first scoreboard is intentionally portable and comparable across Go and Rust:

- peak resident set size from `ps` RSS.
- CPU time delta from `ps` cumulative process time.
- thread count when the local `ps` implementation exposes it.
- validated bytes sent and received by the workload.

Later benchmark slices should add UDP/XUDP, VLESS/Vision, TUN packet-path workloads, latency percentiles, and mobile-native traces from Instruments or Perfetto. This first harness keeps those paths open without putting benchmark logic into the production runtime.
