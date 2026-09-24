# reviewed-parity-regression-legacy

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

222 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| reality-vision-bulk-1 | baseline | 1592.636 | 820.000 | 7.422 | — | — | — | 3 |
| reality-vision-bulk-1 | candidate | 1628.041 | 820.000 | 7.297 | — | — | — | 3 |
| ws-upload-1 | baseline | 561.476 | 90.000 | 8.375 | — | — | — | 3 |
| ws-upload-1 | candidate | 566.483 | 80.000 | 8.266 | — | — | — | 3 |
| ws-download-1 | baseline | 1015.902 | 100.000 | 7.344 | — | — | — | 3 |
| ws-download-1 | candidate | 1015.902 | 100.000 | 7.297 | — | — | — | 3 |
| ws-full-duplex-1 | baseline | 1040.697 | 160.000 | 8.609 | — | — | — | 3 |
| ws-full-duplex-1 | candidate | 1049.280 | 160.000 | 8.516 | — | — | — | 3 |
| ws-upload-8 | baseline | 558.972 | 660.000 | 17.250 | — | — | — | 3 |
| ws-upload-8 | candidate | 723.243 | 650.000 | 15.938 | — | — | — | 3 |
| ws-download-8 | baseline | 1219.153 | 1040.000 | 9.344 | — | — | — | 3 |
| ws-download-8 | candidate | 1475.573 | 680.000 | 8.844 | — | — | — | 3 |
| ws-full-duplex-8 | baseline | 944.734 | 1230.000 | 16.344 | — | — | — | 3 |
| ws-full-duplex-8 | candidate | 921.726 | 1110.000 | 15.312 | — | — | — | 3 |
| httpupgrade-upload-1 | baseline | 1306.176 | 50.000 | 7.531 | — | — | — | 3 |
| httpupgrade-upload-1 | candidate | 1306.176 | 50.000 | 7.453 | — | — | — | 3 |
| httpupgrade-download-1 | baseline | 1280.069 | 80.000 | 7.250 | — | — | — | 3 |
| httpupgrade-download-1 | candidate | 1333.356 | 80.000 | 7.125 | — | — | — | 3 |
| httpupgrade-full-duplex-1 | baseline | 1561.046 | 100.000 | 7.625 | — | — | — | 3 |
| httpupgrade-full-duplex-1 | candidate | 1542.211 | 110.000 | 7.484 | — | — | — | 3 |
| httpupgrade-upload-8 | baseline | 1984.596 | 310.000 | 10.781 | — | — | — | 3 |
| httpupgrade-upload-8 | candidate | 2015.829 | 290.000 | 10.328 | — | — | — | 3 |
| httpupgrade-download-8 | baseline | 1646.399 | 720.000 | 8.953 | — | — | — | 3 |
| httpupgrade-download-8 | candidate | 1861.930 | 530.000 | 8.453 | — | — | — | 3 |
| httpupgrade-full-duplex-8 | baseline | 1422.286 | 750.000 | 10.781 | — | — | — | 3 |
| httpupgrade-full-duplex-8 | candidate | 1467.109 | 720.000 | 10.500 | — | — | — | 3 |
| grpc-upload-1 | baseline | 1361.728 | 80.000 | 9.266 | — | — | — | 3 |
| grpc-upload-1 | candidate | 1422.286 | 80.000 | 9.234 | — | — | — | 3 |
| grpc-download-1 | baseline | 744.224 | 110.000 | 8.109 | — | — | — | 3 |
| grpc-download-1 | candidate | 703.335 | 110.000 | 7.984 | — | — | — | 3 |
| grpc-full-duplex-1 | baseline | 1057.863 | 160.000 | 9.641 | — | — | — | 3 |
| grpc-full-duplex-1 | candidate | 1075.745 | 150.000 | 9.812 | — | — | — | 3 |
| grpc-upload-8 | baseline | 1896.381 | 540.000 | 16.266 | — | — | — | 3 |
| grpc-upload-8 | candidate | 1984.596 | 420.000 | 16.625 | — | — | — | 3 |
| grpc-download-8 | baseline | 1158.476 | 1280.000 | 9.344 | — | — | — | 3 |
| grpc-download-8 | candidate | 1462.936 | 580.000 | 9.344 | — | — | — | 3 |
| grpc-full-duplex-8 | baseline | 1430.273 | 1970.000 | 17.219 | — | — | — | 3 |
| grpc-full-duplex-8 | candidate | 1759.529 | 980.000 | 17.781 | — | — | — | 3 |
| xhttp-h1-upload-1 | baseline | 2.027 | 290.000 | 9.391 | — | — | — | 3 |
| xhttp-h1-upload-1 | candidate | 2.027 | 290.000 | 9.250 | — | — | — | 3 |
| xhttp-h1-download-1 | baseline | 653.148 | 80.000 | 8.062 | — | — | — | 3 |
| xhttp-h1-download-1 | candidate | 666.738 | 80.000 | 7.953 | — | — | — | 3 |
| xhttp-h1-full-duplex-1 | baseline | 3.934 | 350.000 | 9.422 | — | — | — | 3 |
| xhttp-h1-full-duplex-1 | candidate | 3.934 | 340.000 | 9.484 | — | — | — | 3 |
| xhttp-h1-upload-8 | baseline | 15.736 | 1470.000 | 13.969 | — | — | — | 3 |
| xhttp-h1-upload-8 | candidate | 15.736 | 1200.000 | 12.875 | — | — | — | 3 |
| xhttp-h1-download-8 | baseline | 1084.805 | 630.000 | 10.500 | — | — | — | 3 |
| xhttp-h1-download-8 | candidate | 1280.069 | 380.000 | 9.734 | — | — | — | 3 |
| xhttp-h1-full-duplex-8 | baseline | 31.114 | 1940.000 | 13.969 | — | — | — | 3 |
| xhttp-h1-full-duplex-8 | candidate | 31.471 | 1500.000 | 13.297 | — | — | — | 3 |
| xhttp-h2-upload-1 | baseline | 831.246 | 100.000 | 9.531 | — | — | — | 3 |
| xhttp-h2-upload-1 | candidate | 831.246 | 100.000 | 9.281 | — | — | — | 3 |
| xhttp-h2-download-1 | baseline | 790.238 | 130.000 | 9.672 | — | — | — | 3 |
| xhttp-h2-download-1 | candidate | 780.582 | 120.000 | 9.625 | — | — | — | 3 |
| xhttp-h2-full-duplex-1 | baseline | 969.768 | 200.000 | 11.391 | — | — | — | 3 |
| xhttp-h2-full-duplex-1 | candidate | 948.191 | 190.000 | 10.562 | — | — | — | 3 |
| xhttp-h2-upload-8 | baseline | 1135.349 | 1080.000 | 13.500 | — | — | — | 3 |
| xhttp-h2-upload-8 | candidate | 1236.796 | 690.000 | 12.703 | — | — | — | 3 |
| xhttp-h2-download-8 | baseline | 1575.470 | 1050.000 | 13.531 | — | — | — | 3 |
| xhttp-h2-download-8 | candidate | 1828.671 | 520.000 | 18.062 | — | — | — | 3 |
| xhttp-h2-full-duplex-8 | baseline | 1073.480 | 2350.000 | 15.484 | — | — | — | 3 |
| xhttp-h2-full-duplex-8 | candidate | 1265.764 | 1290.000 | 17.031 | — | — | — | 3 |
| xhttp-h3-upload-1 | baseline | 147.223 | 490.000 | 10.562 | — | — | — | 3 |
| xhttp-h3-upload-1 | candidate | 220.776 | 320.000 | 10.672 | — | — | — | 3 |
| xhttp-h3-download-1 | baseline | 200.629 | 760.000 | 13.000 | — | — | — | 3 |
| xhttp-h3-download-1 | candidate | 275.970 | 360.000 | 8.219 | — | — | — | 3 |
| xhttp-h3-full-duplex-1 | baseline | 213.742 | 1230.000 | 15.422 | — | — | — | 3 |
| xhttp-h3-full-duplex-1 | candidate | 324.965 | 520.000 | 11.172 | — | — | — | 3 |
| xhttp-h3-upload-8 | baseline | 248.790 | 6740.000 | 28.250 | — | — | — | 3 |
| xhttp-h3-upload-8 | candidate | 295.639 | 3160.000 | 27.234 | — | — | — | 3 |
| xhttp-h3-download-8 | baseline | 210.881 | 5380.000 | 10.297 | — | — | — | 3 |
| xhttp-h3-download-8 | candidate | 249.863 | 3090.000 | 9.953 | — | — | — | 3 |
| xhttp-h3-full-duplex-8 | baseline | 276.685 | 11330.000 | 28.406 | — | — | — | 3 |
| xhttp-h3-full-duplex-8 | candidate | 310.540 | 5640.000 | 27.594 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

Historical review flags (not external-parity allowances):

- xhttp-h2-download-8: rss_mib; {"cpu_ms": 0.49523809523809526, "cpu_ms_per_mib": 0.49523809523809526, "rss_mib": 1.3348729792147807, "throughput_mib_s": 1.1607142857142858}
