# zero-cid-wan-bulk-1

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

45 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-1 | candidate | 11.224 | 780.000 | 17.250 | — | — | — | 3 |
| hysteria2-socks-upload-1 | native | 11.168 | 1960.000 | 29.250 | — | — | — | 3 |
| hysteria2-socks-upload-1 | previous | 11.237 | 770.000 | 17.094 | — | — | — | 3 |
| hysteria2-socks-upload-1 | singbox | 11.176 | 1300.000 | 29.547 | — | — | — | 3 |
| hysteria2-socks-upload-1 | xray | 11.168 | 1930.000 | 36.297 | — | — | — | 3 |
| hysteria2-socks-download-1 | candidate | 11.277 | 1630.000 | 7.781 | — | — | — | 3 |
| hysteria2-socks-download-1 | native | 11.288 | 2530.000 | 28.203 | — | — | — | 3 |
| hysteria2-socks-download-1 | previous | 11.214 | 1630.000 | 7.859 | — | — | — | 3 |
| hysteria2-socks-download-1 | singbox | 11.261 | 2130.000 | 28.016 | — | — | — | 3 |
| hysteria2-socks-download-1 | xray | 11.241 | 2420.000 | 33.469 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | candidate | 20.216 | 1570.000 | 16.672 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | native | 21.204 | 2240.000 | 29.938 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | previous | 19.695 | 1310.000 | 17.203 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | singbox | 19.656 | 2080.000 | 30.031 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | xray | 20.995 | 2360.000 | 37.156 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

