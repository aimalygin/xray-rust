# UDP Latency and REALITY Bulk Benchmarks Design

## Goal

Extend the published benchmark story with two dimensions before the next
chart refresh: the plain SOCKS-UDP relay path (the code most recently
reworked — flow budgets, in-association eviction) and bulk throughput through
a full VLESS + REALITY + Vision tunnel. Publish one new group on the existing
latency chart and one new chart, both reproducible through the existing
`compare` → `chart` pipeline.

## Scope

This slice delivers:

- a third group on the latency chart: the existing `udp-freedom` workload
  (SOCKS5 UDP ASSOCIATE, freedom outbound, all three engines);
- a new `reality-vision-bulk-throughput` workload: the one-directional bulk
  stream of `tcp-bulk-throughput` pushed through VLESS + REALITY + Vision
  with uTLS fingerprint `chrome`, against the existing Xray-core REALITY
  server fixture, all three engines;
- a new chart pair `reality-throughput-{light,dark}.svg` and README updates.

Out of scope: a UDP saturation/throughput workload (the existing UDP drivers
are strictly serialized ping-pong; a windowed sender with loss accounting is
a separate project), changing the existing `throughput` chart (it keeps
isolating relay overhead over `freedom`/`direct` with no TLS), a REALITY
group on the `cpu-per-gib` chart, and any production-runtime changes.

## UDP Latency Group

No new workload and no new harness code: `udp-freedom` already exists
(`WorkloadKind::UdpFreedom`), drives SOCKS5 UDP ASSOCIATE with a local UDP
echo server, measures per-iteration round-trip latency, and is in
`supports_sing_box_process_engine`. Changes:

- `CHART_SLOTS` gains `(WorkloadKind::UdpFreedom, None)`;
- the latency chart calls the existing generic `latency_group` for it, group
  label `udp-freedom`, after `reality-vision-xudp`;
- publication recipe row (already the documented reference command):
  `compare --workload udp-freedom --runs 5 --connections 1 --iterations 1000
  --payload-size 512`.

The measured path for xray-rust includes the loopback relay socket, the
per-association flow table, and the per-flow bridge task; for the Go engines
it is their native full-cone single-socket relay. That asymmetry is the
point of the comparison, not a flaw; flow-budget caps (128/association,
1024 global) are far above the 1-connection × 1-target load and never
trigger here.

## REALITY Bulk Workload: `reality-vision-bulk-throughput`

Topology is `tcp-bulk-throughput` (local TCP source server streaming a
deterministic pattern, SOCKS CONNECT, chunk-by-chunk validation via
`read_and_validate_bulk_stream`, throughput from one-directional bytes) with
the transport swapped: the engine under test carries the stream through a
VLESS + REALITY + Vision outbound to a Go Xray-core server fixture, whose
`freedom` outbound dials back to the loopback source server.

Reused pieces, all existing:

- client configs: `reality_vision_xudp_config` for xray-rust and Xray-core
  (identical JSON, `fingerprint: chrome`), `sing_box_reality_vision_xudp_config`
  for sing-box (`utls.enabled`, `fingerprint: chrome`) — they already route
  all SOCKS traffic through the VLESS outbound, so no new config generators;
- server fixture: `start_xray_core_reality_vision_server` /
  `xray_core_reality_vision_server_config`, spawned from the same
  `WorkloadFixture::start` arm as `reality-vision-xudp`;
- workload driver: the `tcp-bulk-throughput` connection loop, dispatched for
  the new `WorkloadKind` variant.

New surface is limited to: the `WorkloadKind::RealityVisionBulk` variant
(CLI name `reality-vision-bulk-throughput`, parse + `as_str`), its dispatch
in `run_engine_once` and `engine_config`/`sing_box_config` selection, and
membership in `supports_sing_box_process_engine`.

Publication parameters mirror bulk: `--runs 5 --connections 1
--iterations 256 --payload-size 4194304 --run-timeout-ms 120000` (1 GiB per
run; even at ~1 Gbps through the crypto path a run is under 10 s).

Documented caveats (docs/benchmarks.md):

- the server fixture process is not sampled but shares loopback CPU with the
  client engine, so absolute numbers understate a dedicated-server setup —
  same wording as `reality-vision-xudp`;
- Vision does not splice here: the bulk pattern is not inner TLS, so the
  stream stays REALITY-encrypted end to end. The chart measures the
  encrypted relay path; splice-path throughput would need inner-TLS traffic
  and is out of scope;
- environment requirements are identical to `reality-vision-xudp` (Xray-core
  checkout / Go toolchain for the fixture, egress to the REALITY cover
  origin `www.google.com` where the handshake requires it).

## Chart Module Changes

`CHART_SLOTS` grows to 9 entries (adds `UdpFreedom` and
`RealityVisionBulk`, both `connections: None`). New chart builder
`reality_throughput_chart`: one group (`reality-vision-bulk-throughput`),
three engine bars, Gbps, same `optional_metric_group` machinery and styling
as the existing throughput chart; stems `reality-throughput-{light,dark}`.
The existing six charts are unchanged except the latency chart's third
group. No `load_summary` changes — neither new slot needs a connections
filter.

## README and Docs

- README latency block: alt text and numbers gain the `udp-freedom` group.
- README new picture block after the throughput chart: REALITY tunnel
  throughput, with the one-paragraph explanation of what the tunnel path is
  and the shared-loopback-CPU caveat.
- docs/benchmarks.md: workload description for
  `reality-vision-bulk-throughput`, its compare recipe row, charted-series
  list 7 → 9, sing-box supported-workload list gains the new workload.

## Testing

- Workload name parse/`as_str` round-trip for the new variant.
- Golden charts regenerated (`UPDATE_CHART_GOLDENS=1`); chart e2e/determinism
  tests extended for the new stem and the 3-group latency chart.
- Chart error paths (missing summary for a slot) already cover the new slots
  generically; no new error machinery.
- The new workload's data path is exercised end to end by running it —
  protocol pieces (REALITY handshake, Vision, bulk validation) all have
  existing coverage; no new protocol code is written.

## Boundaries

All changes live in `crates/xray-bench` (plus README/docs/media). The
production runtime is untouched — SOCKS UDP, VLESS, REALITY, and Vision are
existing runtime features; the bench only exercises them.
