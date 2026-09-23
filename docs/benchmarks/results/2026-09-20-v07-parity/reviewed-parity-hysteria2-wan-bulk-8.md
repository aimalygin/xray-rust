# reviewed-parity-hysteria2-wan-bulk-8

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-8 | candidate | 11.179 | 1650.000 | 16.828 | — | — | — | 3 |
| hysteria2-socks-upload-8 | native | 11.142 | 2790.000 | 30.672 | — | — | — | 3 |
| hysteria2-socks-upload-8 | singbox | 11.167 | 1970.000 | 31.078 | — | — | — | 3 |
| hysteria2-socks-upload-8 | xray | 11.155 | 2830.000 | 38.062 | — | — | — | 3 |
| hysteria2-socks-download-8 | candidate | 11.205 | 2520.000 | 8.125 | — | — | — | 3 |
| hysteria2-socks-download-8 | native | 11.228 | 4770.000 | 28.188 | — | — | — | 3 |
| hysteria2-socks-download-8 | singbox | 11.222 | 4200.000 | 26.938 | — | — | — | 3 |
| hysteria2-socks-download-8 | xray | 11.190 | 3780.000 | 33.500 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | candidate | 20.789 | 3410.000 | 18.453 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | native | 21.334 | 4860.000 | 30.094 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | singbox | 20.588 | 4840.000 | 32.141 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | xray | 21.265 | 5110.000 | 38.719 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

