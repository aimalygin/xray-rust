# reviewed-parity-hysteria2-local-stress-16

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-16 | candidate | 435.764 | 670.000 | 18.094 | — | — | — | 3 |
| hysteria2-socks-upload-16 | native | 237.977 | 1660.000 | 28.438 | — | — | — | 3 |
| hysteria2-socks-upload-16 | singbox | 333.316 | 1110.000 | 30.344 | — | — | — | 3 |
| hysteria2-socks-upload-16 | xray | 227.019 | 1720.000 | 36.078 | — | — | — | 3 |
| hysteria2-socks-download-16 | candidate | 351.972 | 1130.000 | 8.453 | — | — | — | 3 |
| hysteria2-socks-download-16 | native | 286.211 | 1610.000 | 28.031 | — | — | — | 3 |
| hysteria2-socks-download-16 | singbox | 286.991 | 1500.000 | 29.516 | — | — | — | 3 |
| hysteria2-socks-download-16 | xray | 288.222 | 1610.000 | 34.750 | — | — | — | 3 |
| hysteria2-socks-full-duplex-16 | candidate | 390.609 | 1810.000 | 17.938 | — | — | — | 3 |
| hysteria2-socks-full-duplex-16 | native | 340.301 | 2690.000 | 28.938 | — | — | — | 3 |
| hysteria2-socks-full-duplex-16 | singbox | 375.390 | 2280.000 | 31.219 | — | — | — | 3 |
| hysteria2-socks-full-duplex-16 | xray | 329.424 | 2760.000 | 36.328 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

