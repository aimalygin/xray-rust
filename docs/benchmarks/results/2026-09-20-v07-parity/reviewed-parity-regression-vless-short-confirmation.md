# reviewed-parity-regression-vless-short-confirmation

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

30 runs; 10 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| vless-tls-tun-full-duplex-1 | baseline | 528.655 | 70.000 | 8.984 | — | — | — | 10 |
| vless-tls-tun-full-duplex-1 | candidate | 578.695 | 60.000 | 8.688 | — | — | — | 10 |
| vless-tls-tun-full-duplex-1 | workers12 | 533.027 | 70.000 | 9.094 | — | — | — | 10 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

