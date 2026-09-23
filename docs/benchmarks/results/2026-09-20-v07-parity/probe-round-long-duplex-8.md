# probe-round-long-duplex-8

Scope: **predecessor / separate experiment**. Candidate SHA256: `daa43dbb46239ea534721b2700cd6bd29af5d64a1fe6c4603cb97806b0d8d80e`.

15 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-full-duplex-8 | candidate | 21.446 | 12590.000 | 20.312 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | native | 22.004 | 18100.000 | 31.359 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | previous | 21.642 | 12430.000 | 20.531 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | singbox | 20.228 | 16270.000 | 33.016 | — | — | — | 3 |
| hysteria2-socks-full-duplex-8 | xray | 21.982 | 18410.000 | 38.891 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

