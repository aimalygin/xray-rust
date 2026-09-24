# rc-parity-wireguard-workers-rust6-go6

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

12 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-full-duplex-8 | candidate | 232.385 | 13280.000 | 28.828 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | native | 159.557 | 29420.000 | 295.859 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | singbox | 176.279 | 24990.000 | 212.859 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | xray | 139.202 | 31180.000 | 303.766 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

