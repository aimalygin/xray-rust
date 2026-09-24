# rc-parity-wireguard-local-bulk-1

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-1 | candidate | 221.217 | 970.000 | 8.203 | — | — | — | 3 |
| wireguard-socks-upload-1 | native | 71.558 | 2870.000 | 103.312 | — | — | — | 3 |
| wireguard-socks-upload-1 | singbox | 170.568 | 1480.000 | 63.266 | — | — | — | 3 |
| wireguard-socks-upload-1 | xray | 62.396 | 3230.000 | 99.016 | — | — | — | 3 |
| wireguard-socks-download-1 | candidate | 217.962 | 910.000 | 7.500 | — | — | — | 3 |
| wireguard-socks-download-1 | native | 186.959 | 1280.000 | 69.906 | — | — | — | 3 |
| wireguard-socks-download-1 | singbox | 178.357 | 1320.000 | 46.000 | — | — | — | 3 |
| wireguard-socks-download-1 | xray | 190.026 | 1250.000 | 86.281 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | candidate | 242.768 | 1730.000 | 9.672 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | native | 135.149 | 3250.000 | 149.547 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | singbox | 218.454 | 2230.000 | 60.422 | — | — | — | 3 |
| wireguard-socks-full-duplex-1 | xray | 125.003 | 3450.000 | 121.547 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

