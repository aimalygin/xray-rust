# rc-parity-wireguard-long-tcp-8

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

20 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-tcp-latency-8 | candidate | 76.997 | 1400.000 | 14.469 | 191.000 | 289.000 | 427.000 | 5 |
| wireguard-socks-tcp-latency-8 | native | 64.881 | 2000.000 | 15.094 | 222.000 | 375.000 | 519.000 | 5 |
| wireguard-socks-tcp-latency-8 | singbox | 67.290 | 1880.000 | 30.578 | 222.000 | 332.000 | 463.000 | 5 |
| wireguard-socks-tcp-latency-8 | xray | 65.628 | 1980.000 | 36.281 | 220.000 | 373.000 | 549.000 | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

