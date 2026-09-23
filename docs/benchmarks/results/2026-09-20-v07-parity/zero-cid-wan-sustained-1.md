# zero-cid-wan-sustained-1

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

15 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-full-duplex-1 | candidate | 21.866 | 10180.000 | 18.969 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | native | 21.819 | 17490.000 | 30.000 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | previous | 21.435 | 10030.000 | 18.328 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | singbox | 20.864 | 15590.000 | 30.125 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | xray | 21.902 | 17770.000 | 37.656 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

