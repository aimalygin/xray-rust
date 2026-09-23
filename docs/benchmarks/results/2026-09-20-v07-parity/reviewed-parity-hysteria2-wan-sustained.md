# reviewed-parity-hysteria2-wan-sustained

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

12 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-full-duplex-8 | candidate | 21.464 | 12560.000 | 17.625 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | native | 21.877 | 18160.000 | 31.453 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | singbox | 20.016 | 17150.000 | 32.125 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | xray | 21.786 | 18680.000 | 39.219 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

