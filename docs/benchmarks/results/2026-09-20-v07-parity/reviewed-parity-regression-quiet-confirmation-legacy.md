# reviewed-parity-regression-quiet-confirmation-legacy

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

15 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: True.

**Measurement limitation:** build/compiler-related background activity was observed. Retained timings are exploratory and cannot establish small protocol differences. Original observations and the supplementary ambient audit remain unchanged.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| xhttp-h2-download-8 | baseline | 1529.455 | 68080.000 | 35.516 | — | — | — | 5 |
| xhttp-h2-download-8 | candidate | 1944.661 | 30900.000 | 24.094 | — | — | — | 5 |
| xhttp-h2-download-8 | workers12 | 1655.817 | 67100.000 | 30.344 | — | — | — | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

