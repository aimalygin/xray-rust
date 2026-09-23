# rc-parity-hysteria2-workers-6

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

12 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-full-duplex-8 | candidate | 417.386 | 6740.000 | 17.938 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | native | 263.240 | 26230.000 | 30.641 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | singbox | 314.313 | 19430.000 | 32.109 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | xray | 264.946 | 26510.000 | 37.797 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

