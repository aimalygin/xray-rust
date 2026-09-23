# rc-parity-wireguard-local-bulk-8

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-8 | candidate | 228.637 | 3760.000 | 18.594 | — | — | — | 3 |
| wireguard-socks-upload-8 | native | 182.894 | 5490.000 | 149.266 | — | — | — | 3 |
| wireguard-socks-upload-8 | singbox | 223.287 | 4530.000 | 115.375 | — | — | — | 3 |
| wireguard-socks-upload-8 | xray | 152.227 | 6310.000 | 137.922 | — | — | — | 3 |
| wireguard-socks-download-8 | candidate | 227.555 | 3950.000 | 15.859 | — | — | — | 3 |
| wireguard-socks-download-8 | native | 194.805 | 5110.000 | 153.875 | — | — | — | 3 |
| wireguard-socks-download-8 | singbox | 170.111 | 5610.000 | 123.359 | — | — | — | 3 |
| wireguard-socks-download-8 | xray | 199.410 | 5000.000 | 192.906 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | candidate | 263.239 | 7110.000 | 28.219 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | native | 192.816 | 10340.000 | 177.438 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | singbox | 259.645 | 7700.000 | 143.266 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | xray | 182.302 | 10850.000 | 200.594 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

