# reviewed-parity-hysteria2-wan-bulk-1

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-1 | candidate | 11.195 | 640.000 | 16.797 | — | — | — | 3 |
| hysteria2-socks-upload-1 | native | 11.175 | 1450.000 | 29.578 | — | — | — | 3 |
| hysteria2-socks-upload-1 | singbox | 11.177 | 1030.000 | 29.359 | — | — | — | 3 |
| hysteria2-socks-upload-1 | xray | 11.175 | 1450.000 | 36.500 | — | — | — | 3 |
| hysteria2-socks-download-1 | candidate | 11.278 | 1110.000 | 7.828 | — | — | — | 3 |
| hysteria2-socks-download-1 | native | 11.276 | 1670.000 | 28.344 | — | — | — | 3 |
| hysteria2-socks-download-1 | singbox | 11.276 | 1470.000 | 27.891 | — | — | — | 3 |
| hysteria2-socks-download-1 | xray | 11.254 | 1700.000 | 33.562 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | candidate | 20.673 | 1380.000 | 17.469 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | native | 21.198 | 2570.000 | 30.328 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | singbox | 19.865 | 2330.000 | 30.062 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | xray | 21.347 | 2530.000 | 37.625 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

