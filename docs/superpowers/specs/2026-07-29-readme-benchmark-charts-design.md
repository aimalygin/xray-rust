# README Benchmark Comparison Charts Design

## Goal

Add a `Benchmarks` section to the repository `README.md` with comparison charts
of `xray-rust`, Xray-core, and sing-box, generated from real `xray-bench`
compare runs. The charts must be reproducible from one documented command
chain, honestly labeled as synthetic localhost benchmarks, and annotated with
the exact engine versions, hardware, run count, and date they came from.

## Scope

This slice delivers:

- one new process-level workload, `tcp-bulk-throughput`, that measures
  streaming throughput through SOCKS for all three engines;
- a `throughput_mbps` aggregate in the benchmark summary output;
- a new `xray-bench chart` subcommand that renders committed SVG charts from a
  compare run group;
- a fresh published data set produced with `--runs 5` and a release
  `xray-rust` binary;
- a README `Benchmarks` section embedding the charts with a methodology
  paragraph and reproduction commands;
- documentation updates in `docs/benchmarks.md`.

Out of scope: a startup-time metric, CI-driven chart regeneration, mermaid
fallbacks, mobile-native traces, and any benchmark logic inside the production
runtime.

## New Workload: `tcp-bulk-throughput`

The existing `tcp-freedom` workload is a request/response echo loop with one
round-trip latency sample per iteration. It understates streaming throughput,
so published "speed" numbers need a dedicated bulk workload.

Behavior:

- The harness starts a local TCP source server that, after accepting a
  connection, streams `--payload-size` bytes per iteration for `--iterations`
  iterations as one continuous transfer per connection.
- The benchmark client opens `--connections` SOCKS5 CONNECT flows through the
  engine under test and reads the full stream from each.
- The stream carries a deterministic byte pattern (position-derived, e.g.
  `byte[i] = f(flow_seed, i)`), and the client validates it while reading, so
  the workload keeps the harness's "validated bytes" property.
- Default publication shape targets about 1 GiB total transfer, e.g.
  `--connections 1 --iterations 256 --payload-size 4194304`.
- The workload is SOCKS-level only, so `WorkloadKind::supports_sing_box_process_engine`
  includes it and all three engines are comparable. It does not use the TUN fd
  path.
- Download direction only (local server to client through the proxy). Upload
  can be added later if a real question needs it.

## Metrics Changes

`BenchSummary` gains `throughput_mbps: Option<MetricSummary>` in megabits per
second, computed per run as `validated received bytes / wall duration`,
aggregated min/median/p95 across runs like the existing metrics. Charts
convert to Gbps for display. It is populated for workloads that move
payload bytes and `None` otherwise, mirroring `cpu_millis_per_gib`. The field
is additive, so existing `summary.json` consumers keep working.

## Chart Subcommand: `xray-bench chart`

Input and output:

- `xray-bench chart --group target/benchmarks/<run-id> --out docs/benchmarks/media`
- The command reads `<group>/<engine>/<workload>/summary.json` for the engines
  and workloads it charts, and fails with a clear error when a required
  summary is missing or reports `status != "ok"`.
- Engine version metadata (xray-rust commit, Xray-core commit, sing-box
  version) and host hardware (chip, RAM, OS version) are passed as explicit
  CLI flags rather than sniffed, so regeneration is deterministic and the
  operator consciously asserts what was measured.

Rendered charts, each as a light and a dark SVG variant:

1. peak RSS in MiB: grouped bars for `idle` and `many-idle-flows`, three
   engines, min-p95 whiskers around the median;
2. round-trip latency in microseconds: median bars with whiskers to p95 for
   `tcp-freedom` and `reality-vision-xudp`;
3. bulk throughput in Gbps for `tcp-bulk-throughput`: one bar per engine with
   min-p95 whiskers;
4. CPU milliseconds per GiB for `tcp-bulk-throughput`: one bar per engine.

SVG requirements:

- pure text generation in the `xray-bench` crate, no new dependencies;
- deterministic output: stable element ordering, fixed canvas size, no
  render-time timestamps or random ids in the markup, so re-running on the
  same data and flags produces byte-identical files and clean git diffs;
- every chart carries a footer with: the measurement date (from an explicit
  CLI flag, like the other metadata, never from the render-time clock),
  hardware, engine versions, `--runs` count, and the label "synthetic
  localhost benchmark";
- axis starts at zero for bar charts; value labels printed on bars so the
  chart is readable without gridline squinting;
- the light/dark pair is two separate files (`<name>-light.svg`,
  `<name>-dark.svg`) consumed by GitHub's `<picture>` +
  `prefers-color-scheme` pattern.

## Publication Data Run

Numbers embedded in the README must come from one fresh compare series:

- `compare --runs 5` for `idle`, `many-idle-flows`, `tcp-freedom`,
  `reality-vision-xudp`, and `tcp-bulk-throughput`;
- `xray-rust` measured as a release build via
  `--xray-rust-bin target/release/xray-rust`. The harness's default debug
  auto-build is fine for development but must not be published: Go engines
  are always optimized builds, so a debug Rust binary would make the
  comparison dishonest in both directions. `docs/benchmarks.md` documents
  this requirement.
- Xray-core pinned to the commit of the local `Xray-core/` clone; sing-box
  auto-built by the harness at a pinned release tag with its documented build
  tags; both recorded in the chart footers.

## README Section

A `Benchmarks` section after `Current scope`:

- four `<picture>` blocks embedding the light/dark SVGs from
  `docs/benchmarks/media/`;
- one methodology paragraph: synthetic localhost workloads, process-level
  sampling, what is compared (SOCKS-level subset for sing-box; TUN workloads
  are xray-rust vs Xray-core only and are not charted here), and the exact
  hardware/version line;
- the reproduction command chain and a link to `docs/benchmarks.md`.

The tone stays consistent with the existing README: experimental project,
numbers are informative rather than promotional.

## Error Handling

- `chart` refuses to render when any charted engine/workload summary is
  missing, unreadable, or not `ok`, and names the offending path.
- `chart` warns (does not fail) when run counts differ across engines in the
  same group.
- The bulk workload validates the byte pattern during read; any mismatch
  fails the run rather than recording bogus throughput.
- The existing per-run watchdog applies; bulk publication runs pass an
  explicit `--run-timeout-ms` sized for ~1 GiB transfers.

## Testing

- Unit test for `tcp-bulk-throughput` config generation for all three
  engines.
- Smoke test running `tcp-bulk-throughput` against `xray-rust` with a small
  transfer size, asserting validated bytes and a non-zero throughput
  aggregate.
- Golden-file test for the chart renderer: fixture `summary.json` inputs in
  the repo, byte-exact expected SVG output for one light and one dark chart.
- A determinism test rendering the same fixture twice and asserting identical
  bytes.

## Boundaries

All new code lives in `crates/xray-bench`. The production runtime crates are
untouched. Chart generation depends only on serialized `summary.json` files,
never on in-process benchmark state, so charts can be regenerated from any
archived run directory.
