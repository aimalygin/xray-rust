# bbr-margin-wan-bulk-1

Scope: **predecessor / separate experiment**. Candidate SHA256: `d8e4248760f23ff82924d911f6c1d90ed1325e0e3afdb7b41b6491d107a325d2`.

45 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-1 | candidate | 11.220 | 880.000 | 17.016 | — | — | — | 3 |
| hysteria2-socks-upload-1 | native | 11.168 | 2000.000 | 29.344 | — | — | — | 3 |
| hysteria2-socks-upload-1 | previous | 11.215 | 820.000 | 17.484 | — | — | — | 3 |
| hysteria2-socks-upload-1 | singbox | 11.178 | 1140.000 | 29.484 | — | — | — | 3 |
| hysteria2-socks-upload-1 | xray | 11.166 | 1850.000 | 36.516 | — | — | — | 3 |
| hysteria2-socks-download-1 | candidate | 11.210 | 1600.000 | 7.875 | — | — | — | 3 |
| hysteria2-socks-download-1 | native | 11.289 | 2530.000 | 28.188 | — | — | — | 3 |
| hysteria2-socks-download-1 | previous | 11.216 | 1560.000 | 7.859 | — | — | — | 3 |
| hysteria2-socks-download-1 | singbox | 11.264 | 2250.000 | 27.719 | — | — | — | 3 |
| hysteria2-socks-download-1 | xray | 11.246 | 2640.000 | 33.641 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | candidate | 20.053 | 1330.000 | 17.453 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | native | 20.701 | 2270.000 | 29.656 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | previous | 20.219 | 1380.000 | 17.516 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | singbox | 19.507 | 2070.000 | 29.750 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | xray | 20.757 | 2420.000 | 36.547 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

