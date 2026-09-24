# reviewed-parity-regression-tun

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

180 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| freedom-tun-upload-1 | baseline | 252.587 | 20.000 | 6.078 | — | — | — | 3 |
| freedom-tun-upload-1 | candidate | 268.930 | 20.000 | 5.734 | — | — | — | 3 |
| freedom-tun-download-1 | baseline | 221.106 | 20.000 | 6.000 | — | — | — | 3 |
| freedom-tun-download-1 | candidate | 223.236 | 20.000 | 5.875 | — | — | — | 3 |
| freedom-tun-full-duplex-1 | baseline | 331.513 | 30.000 | 6.703 | — | — | — | 3 |
| freedom-tun-full-duplex-1 | candidate | 367.388 | 30.000 | 6.484 | — | — | — | 3 |
| freedom-tun-upload-8 | baseline | 525.398 | 80.000 | 8.562 | — | — | — | 3 |
| freedom-tun-upload-8 | candidate | 669.574 | 60.000 | 8.047 | — | — | — | 3 |
| freedom-tun-download-8 | baseline | 425.196 | 70.000 | 11.141 | — | — | — | 3 |
| freedom-tun-download-8 | candidate | 436.777 | 60.000 | 10.828 | — | — | — | 3 |
| freedom-tun-full-duplex-8 | baseline | 539.298 | 130.000 | 13.672 | — | — | — | 3 |
| freedom-tun-full-duplex-8 | candidate | 615.195 | 110.000 | 12.703 | — | — | — | 3 |
| vless-tls-tun-upload-1 | baseline | 492.798 | 50.000 | 8.312 | — | — | — | 3 |
| vless-tls-tun-upload-1 | candidate | 486.440 | 40.000 | 8.188 | — | — | — | 3 |
| vless-tls-tun-download-1 | baseline | 559.760 | 40.000 | 8.359 | — | — | — | 3 |
| vless-tls-tun-download-1 | candidate | 546.255 | 40.000 | 8.203 | — | — | — | 3 |
| vless-tls-tun-full-duplex-1 | baseline | 704.926 | 50.000 | 8.828 | — | — | — | 3 |
| vless-tls-tun-full-duplex-1 | candidate | 369.224 | 50.000 | 8.859 | — | — | — | 3 |
| vless-tls-tun-upload-8 | baseline | 607.612 | 120.000 | 12.234 | — | — | — | 3 |
| vless-tls-tun-upload-8 | candidate | 677.829 | 90.000 | 10.953 | — | — | — | 3 |
| vless-tls-tun-download-8 | baseline | 468.363 | 120.000 | 14.328 | — | — | — | 3 |
| vless-tls-tun-download-8 | candidate | 510.670 | 90.000 | 13.484 | — | — | — | 3 |
| vless-tls-tun-full-duplex-8 | baseline | 623.231 | 200.000 | 16.172 | — | — | — | 3 |
| vless-tls-tun-full-duplex-8 | candidate | 668.998 | 150.000 | 14.500 | — | — | — | 3 |
| xhttp-h1-tun-upload-1 | baseline | 3.697 | 50.000 | 17.953 | — | — | — | 3 |
| xhttp-h1-tun-upload-1 | candidate | 21.197 | 50.000 | 18.328 | — | — | — | 3 |
| xhttp-h1-tun-download-1 | baseline | 510.087 | 40.000 | 9.297 | — | — | — | 3 |
| xhttp-h1-tun-download-1 | candidate | 476.091 | 50.000 | 9.281 | — | — | — | 3 |
| xhttp-h1-tun-full-duplex-1 | baseline | 42.226 | 60.000 | 19.641 | — | — | — | 3 |
| xhttp-h1-tun-full-duplex-1 | candidate | 42.147 | 60.000 | 20.125 | — | — | — | 3 |
| xhttp-h1-tun-upload-8 | baseline | 169.217 | 130.000 | 85.625 | — | — | — | 3 |
| xhttp-h1-tun-upload-8 | candidate | 170.334 | 110.000 | 73.766 | — | — | — | 3 |
| xhttp-h1-tun-download-8 | baseline | 498.975 | 140.000 | 16.172 | — | — | — | 3 |
| xhttp-h1-tun-download-8 | candidate | 530.637 | 110.000 | 14.609 | — | — | — | 3 |
| xhttp-h1-tun-full-duplex-8 | baseline | 338.682 | 230.000 | 65.297 | — | — | — | 3 |
| xhttp-h1-tun-full-duplex-8 | candidate | 341.788 | 180.000 | 54.938 | — | — | — | 3 |
| xhttp-h2-tun-upload-1 | baseline | 383.532 | 60.000 | 10.000 | — | — | — | 3 |
| xhttp-h2-tun-upload-1 | candidate | 390.787 | 50.000 | 9.750 | — | — | — | 3 |
| xhttp-h2-tun-download-1 | baseline | 443.054 | 50.000 | 12.156 | — | — | — | 3 |
| xhttp-h2-tun-download-1 | candidate | 439.008 | 50.000 | 10.984 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-1 | baseline | 448.343 | 90.000 | 11.438 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-1 | candidate | 508.644 | 70.000 | 13.297 | — | — | — | 3 |
| xhttp-h2-tun-upload-8 | baseline | 553.120 | 190.000 | 14.078 | — | — | — | 3 |
| xhttp-h2-tun-upload-8 | candidate | 605.291 | 140.000 | 19.844 | — | — | — | 3 |
| xhttp-h2-tun-download-8 | baseline | 452.151 | 170.000 | 52.141 | — | — | — | 3 |
| xhttp-h2-tun-download-8 | candidate | 474.452 | 130.000 | 49.609 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-8 | baseline | 546.286 | 320.000 | 54.906 | — | — | — | 3 |
| xhttp-h2-tun-full-duplex-8 | candidate | 563.448 | 220.000 | 57.125 | — | — | — | 3 |
| xhttp-h3-tun-upload-1 | baseline | 54.652 | 70.000 | 15.844 | — | — | — | 3 |
| xhttp-h3-tun-upload-1 | candidate | 86.959 | 60.000 | 9.281 | — | — | — | 3 |
| xhttp-h3-tun-download-1 | baseline | 73.479 | 140.000 | 11.734 | — | — | — | 3 |
| xhttp-h3-tun-download-1 | candidate | 107.124 | 70.000 | 9.938 | — | — | — | 3 |
| xhttp-h3-tun-full-duplex-1 | baseline | 105.303 | 180.000 | 17.688 | — | — | — | 3 |
| xhttp-h3-tun-full-duplex-1 | candidate | 143.316 | 90.000 | 12.078 | — | — | — | 3 |
| xhttp-h3-tun-upload-8 | baseline | 158.657 | 590.000 | 43.016 | — | — | — | 3 |
| xhttp-h3-tun-upload-8 | candidate | 175.106 | 350.000 | 14.531 | — | — | — | 3 |
| xhttp-h3-tun-download-8 | baseline | 133.858 | 870.000 | 12.344 | — | — | — | 3 |
| xhttp-h3-tun-download-8 | candidate | 163.943 | 340.000 | 12.000 | — | — | — | 3 |
| xhttp-h3-tun-full-duplex-8 | baseline | 193.033 | 1240.000 | 73.688 | — | — | — | 3 |
| xhttp-h3-tun-full-duplex-8 | candidate | 197.763 | 560.000 | 17.719 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

Historical review flags (not external-parity allowances):

- vless-tls-tun-full-duplex-1: throughput_mib_s; {"cpu_ms": 1.0, "cpu_ms_per_mib": 1.0, "rss_mib": 1.0035398230088495, "throughput_mib_s": 0.5237774738137985}
- xhttp-h1-tun-download-1: cpu_ms_per_mib, cpu_ms; {"cpu_ms": 1.25, "cpu_ms_per_mib": 1.25, "rss_mib": 0.9983193277310924, "throughput_mib_s": 0.9333522182878567}
- xhttp-h2-tun-full-duplex-1: rss_mib; {"cpu_ms": 0.7777777777777778, "cpu_ms_per_mib": 0.7777777777777778, "rss_mib": 1.1625683060109289, "throughput_mib_s": 1.1344992816671122}
- xhttp-h2-tun-upload-8: rss_mib; {"cpu_ms": 0.7368421052631579, "cpu_ms_per_mib": 0.7368421052631579, "rss_mib": 1.409544950055494, "throughput_mib_s": 1.0943205070928048}
