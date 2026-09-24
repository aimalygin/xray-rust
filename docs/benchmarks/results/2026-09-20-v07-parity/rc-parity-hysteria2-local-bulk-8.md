# rc-parity-hysteria2-local-bulk-8

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `observed_targets_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-upload-8 | candidate | 434.894 | 2680.000 | 19.312 | — | — | — | 3 |
| hysteria2-socks-upload-8 | native | 240.234 | 6550.000 | 28.203 | — | — | — | 3 |
| hysteria2-socks-upload-8 | singbox | 350.012 | 4300.000 | 28.984 | — | — | — | 3 |
| hysteria2-socks-upload-8 | xray | 228.464 | 6780.000 | 34.750 | — | — | — | 3 |
| hysteria2-socks-download-8 | candidate | 363.163 | 4320.000 | 8.234 | — | — | — | 3 |
| hysteria2-socks-download-8 | native | 316.302 | 5780.000 | 28.109 | — | — | — | 3 |
| hysteria2-socks-download-8 | singbox | 311.323 | 5550.000 | 28.188 | — | — | — | 3 |
| hysteria2-socks-download-8 | xray | 300.291 | 6040.000 | 34.359 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | candidate | 435.478 | 6470.000 | 17.906 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | native | 353.727 | 10240.000 | 28.391 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | singbox | 417.164 | 8330.000 | 29.438 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | xray | 336.525 | 10700.000 | 35.609 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

