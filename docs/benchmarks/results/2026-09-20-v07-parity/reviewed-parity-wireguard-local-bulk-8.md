# reviewed-parity-wireguard-local-bulk-8

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

45 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-8 | candidate | 168.335 | 5000.000 | 18.828 | — | — | — | 3 |
| wireguard-socks-upload-8 | native | 140.878 | 6880.000 | 160.594 | — | — | — | 3 |
| wireguard-socks-upload-8 | previous | 168.666 | 5010.000 | 18.859 | — | — | — | 3 |
| wireguard-socks-upload-8 | singbox | 168.506 | 5870.000 | 107.094 | — | — | — | 3 |
| wireguard-socks-upload-8 | xray | 114.216 | 8240.000 | 129.312 | — | — | — | 3 |
| wireguard-socks-download-8 | candidate | 188.632 | 4610.000 | 8.125 | — | — | — | 3 |
| wireguard-socks-download-8 | native | 179.675 | 5180.000 | 145.000 | — | — | — | 3 |
| wireguard-socks-download-8 | previous | 186.941 | 4610.000 | 15.797 | — | — | — | 3 |
| wireguard-socks-download-8 | singbox | 174.030 | 5490.000 | 106.578 | — | — | — | 3 |
| wireguard-socks-download-8 | xray | 172.881 | 5460.000 | 205.516 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | candidate | 215.049 | 8500.000 | 20.797 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | native | 158.741 | 12200.000 | 213.281 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | previous | 185.360 | 9150.000 | 28.516 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | singbox | 195.744 | 10000.000 | 138.547 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | xray | 144.136 | 12870.000 | 199.312 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

