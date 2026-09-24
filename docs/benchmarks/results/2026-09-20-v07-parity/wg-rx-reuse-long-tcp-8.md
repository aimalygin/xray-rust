# wg-rx-reuse-long-tcp-8

Scope: **predecessor / separate experiment**. Candidate SHA256: `a6e1e11555c0972d3757f5c08a54d67c566a61f531377cfa9059a45680c9b017`.

25 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `unproven`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-tcp-latency-8 | candidate | 79.033 | 1380.000 | 6.688 | 187.000 | 281.000 | 432.000 | 5 |
| wireguard-socks-tcp-latency-8 | native | 65.219 | 2000.000 | 14.719 | 223.000 | 373.000 | 533.000 | 5 |
| wireguard-socks-tcp-latency-8 | previous | 78.266 | 1390.000 | 14.484 | 188.000 | 281.000 | 422.000 | 5 |
| wireguard-socks-tcp-latency-8 | singbox | 67.711 | 1880.000 | 30.656 | 219.000 | 332.000 | 485.000 | 5 |
| wireguard-socks-tcp-latency-8 | xray | 65.396 | 1980.000 | 36.328 | 220.000 | 375.000 | 550.000 | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

