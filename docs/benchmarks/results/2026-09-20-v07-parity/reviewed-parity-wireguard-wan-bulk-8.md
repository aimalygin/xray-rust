# reviewed-parity-wireguard-wan-bulk-8

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-8 | candidate | 11.067 | 2890.000 | 18.828 | — | — | — | 3 |
| wireguard-socks-upload-8 | native | 10.632 | 5270.000 | 53.641 | — | — | — | 3 |
| wireguard-socks-upload-8 | singbox | 10.431 | 4520.000 | 57.734 | — | — | — | 3 |
| wireguard-socks-upload-8 | xray | 10.845 | 5790.000 | 97.078 | — | — | — | 3 |
| wireguard-socks-download-8 | candidate | 11.015 | 4760.000 | 6.969 | — | — | — | 3 |
| wireguard-socks-download-8 | native | 11.016 | 6150.000 | 17.328 | — | — | — | 3 |
| wireguard-socks-download-8 | singbox | 10.927 | 6020.000 | 30.969 | — | — | — | 3 |
| wireguard-socks-download-8 | xray | 10.881 | 6030.000 | 38.906 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | candidate | 20.943 | 4980.000 | 19.125 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | native | 14.951 | 8830.000 | 81.906 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | singbox | 13.779 | 8220.000 | 144.422 | — | — | — | 3 |
| wireguard-socks-full-duplex-8 | xray | 15.552 | 8860.000 | 156.812 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

