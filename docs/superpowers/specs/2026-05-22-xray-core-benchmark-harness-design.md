# Xray Core Benchmark Harness Design

## Goal

Build a reproducible benchmark harness that compares this Rust core against the cloned Xray-core on the metrics that matter for mobile: resident memory, CPU cost, latency, throughput, startup cost, idle overhead, and per-flow memory growth.

The harness must answer a practical question: for the same supported profile and the same traffic, is `xray-rust` faster and more memory-efficient than Xray-core?

## Non-Goals

- Do not build platform adapters for iOS, tvOS, or Android in this milestone.
- Do not claim full Xray-core parity outside the already supported profile set.
- Do not rely only on Rust microbenchmarks or Go `testing.B` numbers.
- Do not compare different protocols, TLS backends, payload mixes, or routing behavior as if they were the same workload.
- Do not include real remote Internet targets; the baseline must be local and repeatable.

## Xray-core Baseline

The cloned Xray-core already has useful pieces, but not a complete end-to-end mobile benchmark suite:

- About 51 Go `Benchmark*` functions for package-level work such as buffers, crypto, mux framing, geodata matchers, and address parsing.
- `app/metrics`, which imports `net/http/pprof` and exposes `/debug/pprof/*` plus `/debug/vars`.
- Stats API `GetSysStats`, which returns Go runtime memory and GC fields from `runtime.ReadMemStats`: `Alloc`, `TotalAlloc`, `Sys`, `Mallocs`, `Frees`, `LiveObjects`, `NumGC`, `PauseTotalNs`, `NumGoroutine`, and `Uptime`.

These are useful observability inputs, but the comparison should be driven by an external workload harness so both cores are measured under the same traffic.

## Measurement Principles

The primary scoreboard is OS-level, because it is portable across Go and Rust and closest to mobile constraints:

- Peak RSS and sampled RSS over time.
- CPU time and normalized CPU seconds per GiB transferred.
- Wall-clock throughput.
- Latency p50, p95, p99.
- Startup time until the core can accept traffic.
- Idle CPU and memory after warmup.
- Per-flow memory slope: `(RSS_after_N_flows - RSS_idle) / N`.
- Thread count for Rust and goroutine count for Xray-core when available.

Runtime-specific metrics are secondary:

- Xray-core: `statssys`, `/debug/vars`, CPU profile, heap profile, goroutine profile.
- xray-rust: internal counters exposed by a small diagnostics surface in a later implementation step: task counts where available, TUN queue depths/drops, bytes in/out, active flows, and optional allocator snapshots.

## Benchmark Topology

Use one traffic generator for both implementations:

```text
traffic generator
  -> core under test
  -> local echo target
  -> core under test
  -> traffic generator
```

The harness owns the echo target and the traffic generator. It starts either `xray-rust` or Xray-core with equivalent config, waits for readiness, runs the workload, samples metrics, stores artifacts, and then shuts the process down.

For the Rust core, prefer the CLI/runtime binary path for process-level benchmarks. Keep direct library benchmarks as a separate microbench layer so process RSS and startup numbers stay honest.

For Xray-core, build or use the local binary from the cloned checkout and enable only the features needed for each workload. Enable metrics only for runs that collect Xray-specific runtime diagnostics, because metrics/pprof itself has overhead.

## Workloads

Start with workloads that match current Rust support and mobile priorities:

1. Idle core
   - Start with config loaded.
   - No traffic for a fixed duration.
   - Measures base RSS, idle CPU, and background runtime overhead.

2. Startup
   - Measure process spawn to ready-to-accept-traffic.
   - Repeat enough times to report median and p95.

3. TCP Freedom echo
   - Local SOCKS or TUN TCP path depending on both sides' supported entrypoint for that run.
   - Payload sizes: 64 B, 1 KiB, 16 KiB, 128 KiB.
   - Concurrency: 1, 10, 100, 1000 where stable.

4. VLESS TCP echo
   - Rust VLESS TCP client path versus Xray-core VLESS TCP profile.
   - Same payload sizes and concurrency.

5. UDP Freedom echo
   - Datagram sizes: 32 B, 128 B, 1200 B.
   - Packet rates: fixed low-rate mobile-like, medium, and saturation.

6. TUN UDP Freedom echo
   - Use inherited fd-backed TUN instead of a real OS route so local runs stay safe and rootless.
   - macOS/iOS-style runs use Darwin utun framing around raw IPv4 packets.
   - The local UDP target must avoid `127.0.0.1` for Xray-core because its gVisor stack drops loopback destinations as martian packets.

7. VLESS UDP echo
   - Length-prefixed VLESS UDP over TCP transport.
   - Same UDP payload sizes and rates.

8. Vision XUDP UDP echo
   - Protected stream boundary with Vision padding and XUDP framing.
   - Local TLS test mode first; REALITY/uTLS live comparisons become a later slice once the production REALITY provider is implemented.

9. Many idle flows
   - Establish N flows and keep them mostly idle.
   - Primary output is memory slope and task/thread/goroutine behavior.

## Result Format

Each run writes a self-contained result directory:

```text
target/benchmarks/<timestamp>/<engine>/<workload>/
  config.json
  result.json
  samples.csv
  stdout.log
  stderr.log
  profiles/
```

`result.json` should include:

- Git commit for `xray-rust`.
- Xray-core commit.
- OS, CPU model, memory size, kernel version.
- Build profile and binary path.
- Workload parameters.
- Summary metrics.
- Pass/fail status and error details.

`samples.csv` should include timestamped RSS, CPU, thread count, and runtime-specific fields when available.

## Architecture

Create a benchmark crate or tool that stays outside the core data path. The recommended shape is:

- `crates/xray-bench`: Rust CLI harness for orchestration, traffic generation, metric sampling, and result writing.
- `benches/` or `crates/xray-bench/benches`: Criterion or iai-style microbenchmarks for packet/frame/routing hot paths.
- `tests/fixtures/benchmarks`: equivalent Xray JSON configs for both engines.
- `docs/benchmarks.md`: how to run and interpret results.

The harness should have these internal boundaries:

- `Engine`: starts/stops `xray-rust` or Xray-core, reports readiness, exposes diagnostics endpoints.
- `Workload`: generates traffic and validates responses.
- `Sampler`: captures OS process metrics and optional runtime diagnostics.
- `Reporter`: writes JSON/CSV summaries and profile artifacts.

## Error Handling

- A benchmark run fails if the traffic validation fails, the process exits early, readiness times out, metrics cannot be sampled, or the workload does not complete within its deadline.
- Partial results should still be written with `status = "failed"` so regressions can be inspected.
- The harness must not silently fall back from one engine or workload to another.

## First Implementation Slice

The first slice should be intentionally small:

- Add the benchmark design and plan.
- Add `xray-bench` with one idle benchmark and one TCP Freedom echo benchmark.
- Sample RSS and CPU for both `xray-rust` and Xray-core processes.
- Write `result.json` and `samples.csv`.
- Document how to run the comparison locally.

After that, add UDP, VLESS UDP, Vision XUDP, and many-idle-flow workloads in separate commits.

## Acceptance Criteria

- A developer can run one command to compare `xray-rust` and Xray-core for the first supported workload.
- The output includes OS-level memory and CPU numbers for both engines.
- Results are reproducible enough to compare multiple runs on the same host.
- The harness stores raw samples, not just summaries.
- The design leaves room for iOS Instruments, tvOS, Android Perfetto, and allocator-specific profiling without forcing mobile adapters into this milestone.
