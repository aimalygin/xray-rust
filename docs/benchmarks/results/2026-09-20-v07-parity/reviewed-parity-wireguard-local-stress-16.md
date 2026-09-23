# reviewed-parity-wireguard-local-stress-16

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `unproven`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-16 | candidate | 222.148 | 1950.000 | 30.906 | — | — | — | 3 |
| wireguard-socks-upload-16 | native | 177.951 | 2820.000 | 178.578 | — | — | — | 3 |
| wireguard-socks-upload-16 | singbox | 224.751 | 2240.000 | 100.047 | — | — | — | 3 |
| wireguard-socks-upload-16 | xray | 163.770 | 3080.000 | 219.438 | — | — | — | 3 |
| wireguard-socks-download-16 | candidate | 215.724 | 2110.000 | 8.781 | — | — | — | 3 |
| wireguard-socks-download-16 | native | 194.418 | 2580.000 | 103.625 | — | — | — | 3 |
| wireguard-socks-download-16 | singbox | 182.042 | 2750.000 | 88.375 | — | — | — | 3 |
| wireguard-socks-download-16 | xray | 193.993 | 2550.000 | 114.438 | — | — | — | 3 |
| wireguard-socks-full-duplex-16 | candidate | 260.330 | 3670.000 | 32.797 | — | — | — | 3 |
| wireguard-socks-full-duplex-16 | native | 232.025 | 4380.000 | 216.141 | — | — | — | 3 |
| wireguard-socks-full-duplex-16 | singbox | 266.032 | 3810.000 | 121.234 | — | — | — | 3 |
| wireguard-socks-full-duplex-16 | xray | 67.585 | 4570.000 | 213.141 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

