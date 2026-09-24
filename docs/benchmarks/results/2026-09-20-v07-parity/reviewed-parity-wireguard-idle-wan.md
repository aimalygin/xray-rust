# reviewed-parity-wireguard-idle-wan

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

18 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-1 | candidate | 10.566 | 1310.000 | 9.172 | — | — | — | 3 |
| wireguard-socks-upload-1 | no_idle | 10.602 | 1300.000 | 8.266 | — | — | — | 3 |
| wireguard-socks-upload-1 | singbox | 10.651 | 2410.000 | 42.688 | — | — | — | 3 |
| wireguard-socks-download-1 | candidate | 10.649 | 1810.000 | 7.172 | — | — | — | 3 |
| wireguard-socks-download-1 | no_idle | 10.654 | 1840.000 | 6.297 | — | — | — | 3 |
| wireguard-socks-download-1 | singbox | 10.647 | 2620.000 | 31.672 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

