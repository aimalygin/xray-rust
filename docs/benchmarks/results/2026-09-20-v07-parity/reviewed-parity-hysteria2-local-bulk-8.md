# reviewed-parity-hysteria2-local-bulk-8

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

45 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-8 | candidate | 378.379 | 2900.000 | 18.500 | — | — | — | 3 |
| hysteria2-socks-upload-8 | native | 177.170 | 8360.000 | 28.266 | — | — | — | 3 |
| hysteria2-socks-upload-8 | previous | 374.029 | 2960.000 | 18.641 | — | — | — | 3 |
| hysteria2-socks-upload-8 | singbox | 297.873 | 4900.000 | 29.000 | — | — | — | 3 |
| hysteria2-socks-upload-8 | xray | 197.883 | 7630.000 | 35.031 | — | — | — | 3 |
| hysteria2-socks-download-8 | candidate | 294.700 | 4990.000 | 8.109 | — | — | — | 3 |
| hysteria2-socks-download-8 | native | 265.853 | 6490.000 | 28.688 | — | — | — | 3 |
| hysteria2-socks-download-8 | previous | 289.214 | 5120.000 | 8.234 | — | — | — | 3 |
| hysteria2-socks-download-8 | singbox | 267.495 | 6170.000 | 28.359 | — | — | — | 3 |
| hysteria2-socks-download-8 | xray | 258.691 | 6690.000 | 34.594 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | candidate | 353.586 | 7600.000 | 18.719 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | native | 291.179 | 12100.000 | 28.609 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | previous | 352.443 | 7560.000 | 18.844 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | singbox | 321.150 | 10520.000 | 29.703 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | xray | 279.643 | 12490.000 | 35.594 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

