# Benchmark results

Synthetic localhost comparison of `xray-rust`, Xray-core, and sing-box using
the process-level [benchmark harness](../benchmarks.md). Each engine runs as
a child process with an equivalent generated config while the harness samples
OS RSS/CPU counters and validates every payload byte. Bars are medians across
5 runs; whiskers span min to p95 (for latency, the whisker top is the median
run p95). Measured 2026-07-31 on Apple M3 Pro, 18 GB RAM, macOS 26.5.2 with
release builds: xray-rust `3f70759`, Xray-core `v26.5.9`, sing-box
`v1.13.15`. The routing memory chart loads real, pinned V2Fly geodata
(`geosite 20260727084448`, `geoip 202607171233`); sing-box is absent
from that chart because it does not read Xray-format `.dat` rule data.

The headline memory, REALITY tunnel throughput, and geodata memory charts are
shown in the [README](../../README.md#benchmarks); this page carries the full
narrative and the remaining series.

In this run xray-rust holds the resident-memory edge at every scale: at idle
and 100 held flows by a wide margin, and at 1000 flows it now stays lowest
too — 17.9 MiB against Xray-core's 80.1 and sing-box's 46.8. Earlier
publications showed sing-box pulling level at 1000 flows; that slope was
dominated by two eagerly allocated 16 KiB relay copy buffers per flow, and
`3f70759` starts them at 4 KiB instead (they still grow to 128 KiB under
load), cutting the ×1000 peak from 41.4 MiB without moving any throughput or
latency series. With real geodata loaded xray-rust uses about 4× less memory
than Xray-core. Round-trip latency is comparable to both Go engines on the
TCP echo path (38.0 vs 35.0/32.0 µs), clearly the fastest on the plain SOCKS
UDP relay (38.0 vs 61.0/46.0 µs), and in front on the REALITY + Vision XUDP
path (85.0 vs 101/87.0 µs). On plain bulk throughput through SOCKS xray-rust
and sing-box are effectively tied — 58.8 vs 59.2 Gbps with overlapping run
ranges — both ahead of Xray-core's 50.3; bulk medians on this workload swing
with machine state between publications, but the relative order has been
stable. CPU per GiB on that workload puts xray-rust between the two (185 vs
Xray-core's 239 and sing-box's 153 ms). Through a full VLESS + REALITY +
Vision tunnel xray-rust leads on both axes: 13.0 Gbps against Xray-core's
12.4 and sing-box's 12.5, at the lowest CPU cost per GiB (840 vs 890/880 ms).
Earlier publications had xray-rust clearly slowest here (8.36 Gbps at about
1270 ms per GiB); the gap was work per byte on the tunnel's read path —
socket reads forced to TLS record boundaries plus per-read buffer zeroing
and copying — removed in `05c33ac`. Throughput is measured over the transfer
window only (first byte to last validated byte) on an 8 GiB stream (1 GiB for
the tunnel chart): a gigabyte crosses loopback in roughly 150 milliseconds,
short enough that TCP window growth and CPU frequency scaling weighed on the
result, and per-engine setup cost was otherwise amortized into the rate.
Excluding setup helps Xray-core rather than us: the harness
fixture is identical for all three engines, but Xray-core answers SOCKS
eagerly and finishes its REALITY handshake lazily, spending about 640 ms
before its first byte against roughly 90–120 ms for the other two. On the
REALITY chart the Xray-core server fixture terminating the tunnel is not
sampled, but it shares loopback CPU with the measured client.
These are microbenchmarks of local proxy paths, not wide-area VPN performance;
TUN workloads (xray-rust vs Xray-core only) are not charted here.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/latency-dark.svg">
  <img alt="Round-trip latency medians, lower is better. tcp-freedom: xray-rust 38.0 µs, Xray-core 35.0, sing-box 32.0. udp-freedom: xray-rust 38.0 µs, Xray-core 61.0, sing-box 46.0. reality-vision-xudp: xray-rust 85.0 µs, Xray-core 101, sing-box 87.0." src="media/latency-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/throughput-dark.svg">
  <img alt="Bulk TCP throughput through SOCKS, higher is better: xray-rust 58.8 Gbps, Xray-core 50.3, sing-box 59.2." src="media/throughput-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/cpu-per-gib-dark.svg">
  <img alt="CPU cost per GiB transferred on the plain bulk workload, lower is better: xray-rust 185 ms, Xray-core 239, sing-box 153." src="media/cpu-per-gib-light.svg">
</picture>

Reproduce with the release-build compare series and render charts with
`xray-bench chart`; the exact command chain and methodology are in
[Publishing Numbers and Charts](../benchmarks.md#publishing-numbers-and-charts).
