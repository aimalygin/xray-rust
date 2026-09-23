# rc-parity-hysteria2-local-bulk-1

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `unproven`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-1 | candidate | 508.059 | 1100.000 | 18.859 | — | — | — | 3 |
| hysteria2-socks-upload-1 | native | 242.771 | 3320.000 | 28.062 | — | — | — | 3 |
| hysteria2-socks-upload-1 | singbox | 386.974 | 1980.000 | 28.359 | — | — | — | 3 |
| hysteria2-socks-upload-1 | xray | 239.586 | 3410.000 | 33.938 | — | — | — | 3 |
| hysteria2-socks-download-1 | candidate | 352.568 | 2040.000 | 7.938 | — | — | — | 3 |
| hysteria2-socks-download-1 | native | 340.754 | 2620.000 | 28.281 | — | — | — | 3 |
| hysteria2-socks-download-1 | singbox | 343.401 | 2360.000 | 27.969 | — | — | — | 3 |
| hysteria2-socks-download-1 | xray | 340.216 | 2640.000 | 33.891 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | candidate | 496.232 | 2680.000 | 16.062 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | native | 382.977 | 4720.000 | 28.672 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | singbox | 501.623 | 3390.000 | 28.438 | — | — | — | 3 |
| hysteria2-socks-full-duplex-1 | xray | 368.320 | 4940.000 | 34.156 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

