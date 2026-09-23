# rc-parity-wireguard-workers-6

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

12 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-full-duplex-8 | candidate | 272.684 | 6930.000 | 28.656 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | native | 159.510 | 29190.000 | 300.484 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | singbox | 161.094 | 28020.000 | 204.219 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | xray | 151.343 | 28800.000 | 268.578 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

