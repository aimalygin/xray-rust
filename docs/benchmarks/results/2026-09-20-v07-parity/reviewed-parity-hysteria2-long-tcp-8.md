# reviewed-parity-hysteria2-long-tcp-8

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

25 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-tcp-latency-8 | candidate | 95.470 | 1080.000 | 8.016 | 157.000 | 241.000 | 339.000 | 5 |
| hysteria2-socks-tcp-latency-8 | native | 87.115 | 1340.000 | 28.172 | 168.000 | 265.000 | 408.000 | 5 |
| hysteria2-socks-tcp-latency-8 | previous | 94.509 | 1090.000 | 8.031 | 155.000 | 244.000 | 359.000 | 5 |
| hysteria2-socks-tcp-latency-8 | singbox | 94.477 | 1190.000 | 28.125 | 156.000 | 233.000 | 363.000 | 5 |
| hysteria2-socks-tcp-latency-8 | xray | 82.076 | 1430.000 | 33.828 | 176.000 | 307.000 | 439.000 | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

