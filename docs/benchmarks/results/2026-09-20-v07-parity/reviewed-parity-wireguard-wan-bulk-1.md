# reviewed-parity-wireguard-wan-bulk-1

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-1 | candidate | 10.567 | 1300.000 | 8.344 | — | — | — | 3 |
| wireguard-socks-upload-1 | native | 10.646 | 3100.000 | 24.156 | — | — | — | 3 |
| wireguard-socks-upload-1 | singbox | 10.658 | 2750.000 | 39.891 | — | — | — | 3 |
| wireguard-socks-upload-1 | xray | 10.556 | 3350.000 | 48.297 | — | — | — | 3 |
| wireguard-socks-download-1 | candidate | 10.648 | 1840.000 | 6.219 | — | — | — | 3 |
| wireguard-socks-download-1 | native | 10.649 | 2870.000 | 17.156 | — | — | — | 3 |
| wireguard-socks-download-1 | singbox | 10.647 | 2580.000 | 33.984 | — | — | — | 3 |
| wireguard-socks-download-1 | xray | 10.638 | 2850.000 | 36.438 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | candidate | 18.228 | 2420.000 | 8.531 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | native | 15.355 | 4900.000 | 54.625 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | singbox | 16.072 | 4730.000 | 61.141 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | xray | 15.530 | 5420.000 | 87.438 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

