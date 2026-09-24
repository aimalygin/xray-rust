# quic-ack-wan-duplex-1

Scope: **predecessor / separate experiment**. Candidate SHA256: `2785fafb9bf68795ebbb03a5e1ee4c1756b1f4bd5944627ad30e1290b49d49d8`.

25 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-full-duplex-1 | candidate | 20.060 | 1320.000 | 17.281 | — | — | — | 5 |
| hysteria2-socks-full-duplex-1 | native | 20.831 | 2280.000 | 29.906 | — | — | — | 5 |
| hysteria2-socks-full-duplex-1 | previous | 20.181 | 1310.000 | 17.453 | — | — | — | 5 |
| hysteria2-socks-full-duplex-1 | singbox | 19.412 | 1960.000 | 29.891 | — | — | — | 5 |
| hysteria2-socks-full-duplex-1 | xray | 21.089 | 2330.000 | 37.344 | — | — | — | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

