# reviewed-parity-wireguard-local-bulk-1

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

45 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-1 | candidate | 174.681 | 1190.000 | 8.203 | — | — | — | 3 |
| wireguard-socks-upload-1 | native | 70.214 | 2890.000 | 89.766 | — | — | — | 3 |
| wireguard-socks-upload-1 | previous | 176.916 | 1180.000 | 8.234 | — | — | — | 3 |
| wireguard-socks-upload-1 | singbox | 120.431 | 2020.000 | 61.328 | — | — | — | 3 |
| wireguard-socks-upload-1 | xray | 58.120 | 3390.000 | 105.500 | — | — | — | 3 |
| wireguard-socks-download-1 | candidate | 183.261 | 1030.000 | 6.625 | — | — | — | 3 |
| wireguard-socks-download-1 | native | 157.145 | 1450.000 | 55.250 | — | — | — | 3 |
| wireguard-socks-download-1 | previous | 182.801 | 1020.000 | 7.688 | — | — | — | 3 |
| wireguard-socks-download-1 | singbox | 155.570 | 1450.000 | 47.688 | — | — | — | 3 |
| wireguard-socks-download-1 | xray | 162.525 | 1410.000 | 79.172 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | candidate | 187.284 | 2160.000 | 8.703 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | native | 157.226 | 2970.000 | 108.703 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | previous | 191.641 | 2130.000 | 9.766 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | singbox | 170.707 | 2760.000 | 73.156 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | xray | 133.413 | 3220.000 | 117.172 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

