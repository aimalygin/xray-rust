# reviewed-parity-regression-quiet-confirmation-tun

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

36 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| vless-tls-tun-full-duplex-1 | baseline | 700.681 | 2100.000 | 9.656 | — | — | — | 3 |
| vless-tls-tun-full-duplex-1 | candidate | 725.435 | 1750.000 | 9.125 | — | — | — | 3 |
| vless-tls-tun-full-duplex-1 | workers12 | 712.205 | 2010.000 | 9.891 | — | — | — | 3 |
| xhttp-h1-tun-download-1 | baseline | 584.318 | 1030.000 | 9.422 | — | — | — | 3 |
| xhttp-h1-tun-download-1 | candidate | 568.497 | 990.000 | 9.391 | — | — | — | 3 |
| xhttp-h1-tun-download-1 | workers12 | 576.118 | 1050.000 | 9.812 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-1 | baseline | 688.315 | 2680.000 | 18.078 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-1 | candidate | 718.245 | 2080.000 | 19.812 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-1 | workers12 | 700.449 | 2610.000 | 19.312 | — | — | — | 3 |
| xhttp-h2-tun-upload-8 | baseline | 778.702 | 11400.000 | 20.781 | — | — | — | 3 |
| xhttp-h2-tun-upload-8 | candidate | 820.753 | 8030.000 | 24.875 | — | — | — | 3 |
| xhttp-h2-tun-upload-8 | workers12 | 738.853 | 11950.000 | 25.656 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

Historical review flags (not external-parity allowances):

- xhttp-h2-tun-upload-8: rss_mib; {"cpu_ms": 0.7043859649122807, "cpu_ms_per_mib": 0.7043859649122807, "rss_mib": 1.1969924812030075, "throughput_mib_s": 1.054001187045891}
