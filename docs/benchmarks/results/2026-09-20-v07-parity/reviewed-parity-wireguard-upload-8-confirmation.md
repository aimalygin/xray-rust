# reviewed-parity-wireguard-upload-8-confirmation

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

25 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `unproven`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-8 | candidate | 222.851 | 3850.000 | 18.812 | — | — | — | 5 |
| wireguard-socks-upload-8 | native | 170.625 | 5860.000 | 127.531 | — | — | — | 5 |
| wireguard-socks-upload-8 | previous | 223.616 | 3850.000 | 18.703 | — | — | — | 5 |
| wireguard-socks-upload-8 | singbox | 220.991 | 4570.000 | 114.953 | — | — | — | 5 |
| wireguard-socks-upload-8 | xray | 148.660 | 6610.000 | 157.969 | — | — | — | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

