# rc-parity-hysteria2-wan-bulk-1

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-1 | candidate | 11.216 | 860.000 | 16.594 | — | — | — | 3 |
| hysteria2-socks-upload-1 | native | 11.172 | 1900.000 | 29.469 | — | — | — | 3 |
| hysteria2-socks-upload-1 | singbox | 11.173 | 1280.000 | 29.469 | — | — | — | 3 |
| hysteria2-socks-upload-1 | xray | 11.171 | 1940.000 | 36.453 | — | — | — | 3 |
| hysteria2-socks-download-1 | candidate | 11.199 | 1480.000 | 7.812 | — | — | — | 3 |
| hysteria2-socks-download-1 | native | 11.280 | 2520.000 | 28.094 | — | — | — | 3 |
| hysteria2-socks-download-1 | singbox | 11.263 | 2310.000 | 27.781 | — | — | — | 3 |
| hysteria2-socks-download-1 | xray | 11.237 | 2520.000 | 33.609 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | candidate | 19.075 | 1400.000 | 16.953 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | native | 21.098 | 2260.000 | 29.672 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | singbox | 20.087 | 2020.000 | 30.000 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | xray | 21.465 | 2320.000 | 37.062 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

