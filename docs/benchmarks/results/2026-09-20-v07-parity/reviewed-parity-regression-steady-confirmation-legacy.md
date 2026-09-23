# reviewed-parity-regression-steady-confirmation-legacy

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

27 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| grpc-download-1 | baseline | 843.525 | 5190.000 | 8.359 | — | — | — | 3 |
| grpc-download-1 | candidate | 855.327 | 4820.000 | 8.266 | — | — | — | 3 |
| grpc-download-1 | workers12 | 845.671 | 5230.000 | 8.672 | — | — | — | 3 |
| xhttp-h2-download-1 | baseline | 911.713 | 6460.000 | 10.531 | — | — | — | 3 |
| xhttp-h2-download-1 | candidate | 909.686 | 5950.000 | 9.156 | — | — | — | 3 |
| xhttp-h2-download-1 | workers12 | 912.905 | 6460.000 | 10.500 | — | — | — | 3 |
| xhttp-h2-download-8 | baseline | 1827.359 | 65710.000 | 18.953 | — | — | — | 3 |
| xhttp-h2-download-8 | candidate | 1685.262 | 32390.000 | 20.688 | — | — | — | 3 |
| xhttp-h2-download-8 | workers12 | 1631.498 | 64950.000 | 22.078 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

