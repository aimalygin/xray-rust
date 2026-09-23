# reviewed-parity-hysteria2-local-bulk-1

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

45 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `unproven`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-1 | candidate | 507.316 | 1070.000 | 14.562 | — | — | — | 3 |
| hysteria2-socks-upload-1 | native | 225.013 | 3500.000 | 28.297 | — | — | — | 3 |
| hysteria2-socks-upload-1 | previous | 491.481 | 1090.000 | 14.969 | — | — | — | 3 |
| hysteria2-socks-upload-1 | singbox | 342.405 | 2170.000 | 28.141 | — | — | — | 3 |
| hysteria2-socks-upload-1 | xray | 220.358 | 3600.000 | 33.953 | — | — | — | 3 |
| hysteria2-socks-download-1 | candidate | 314.808 | 2090.000 | 8.000 | — | — | — | 3 |
| hysteria2-socks-download-1 | native | 300.585 | 2730.000 | 28.453 | — | — | — | 3 |
| hysteria2-socks-download-1 | previous | 311.727 | 2100.000 | 7.938 | — | — | — | 3 |
| hysteria2-socks-download-1 | singbox | 293.460 | 2570.000 | 28.016 | — | — | — | 3 |
| hysteria2-socks-download-1 | xray | 300.391 | 2800.000 | 33.812 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | candidate | 439.634 | 2870.000 | 16.812 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | native | 338.033 | 5170.000 | 28.562 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | previous | 431.826 | 2890.000 | 16.250 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | singbox | 434.956 | 3790.000 | 28.734 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | xray | 325.679 | 5450.000 | 34.453 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

