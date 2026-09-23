# reviewed-parity-regression-steady-confirmation-tun

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: True.

**Measurement limitation:** build/compiler-related background activity was observed. Retained timings are exploratory and cannot establish small protocol differences. Original observations and the supplementary ambient audit remain unchanged.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| vless-tls-tun-full-duplex-1 | baseline | 151.945 | 3110.000 | 9.688 | — | — | — | 3 |
| vless-tls-tun-full-duplex-1 | candidate | 639.385 | 1880.000 | 9.391 | — | — | — | 3 |
| vless-tls-tun-full-duplex-1 | workers12 | 705.131 | 1970.000 | 9.578 | — | — | — | 3 |
| xhttp-h1-tun-download-1 | baseline | 565.294 | 1100.000 | 9.406 | — | — | — | 3 |
| xhttp-h1-tun-download-1 | candidate | 551.562 | 1050.000 | 9.359 | — | — | — | 3 |
| xhttp-h1-tun-download-1 | workers12 | 546.099 | 1100.000 | 9.703 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-1 | baseline | 537.171 | 3380.000 | 18.266 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-1 | candidate | 601.735 | 2400.000 | 17.938 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-1 | workers12 | 536.532 | 3330.000 | 18.297 | — | — | — | 3 |
| xhttp-h2-tun-upload-8 | baseline | 694.360 | 12640.000 | 15.266 | — | — | — | 3 |
| xhttp-h2-tun-upload-8 | candidate | 801.115 | 8280.000 | 14.250 | — | — | — | 3 |
| xhttp-h2-tun-upload-8 | workers12 | 730.059 | 12200.000 | 16.078 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

