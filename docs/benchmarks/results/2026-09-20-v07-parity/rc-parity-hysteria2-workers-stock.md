# rc-parity-hysteria2-workers-stock

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

12 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-full-duplex-8 | candidate | 422.085 | 6640.000 | 17.328 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | native | 275.094 | 26480.000 | 32.016 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | singbox | 309.329 | 19670.000 | 33.531 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | xray | 260.791 | 28290.000 | 39.781 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

