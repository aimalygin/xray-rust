# reviewed-parity-regression-reality

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

72 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| reality-vision-socks-upload-1 | baseline | 881.131 | 80.000 | 8.062 | — | — | — | 3 |
| reality-vision-socks-upload-1 | candidate | 882.307 | 70.000 | 7.984 | — | — | — | 3 |
| reality-vision-socks-download-1 | baseline | 833.000 | 90.000 | 7.391 | — | — | — | 3 |
| reality-vision-socks-download-1 | candidate | 830.225 | 90.000 | 7.391 | — | — | — | 3 |
| reality-vision-socks-full-duplex-1 | baseline | 1121.532 | 110.000 | 7.875 | — | — | — | 3 |
| reality-vision-socks-full-duplex-1 | candidate | 1120.156 | 110.000 | 7.750 | — | — | — | 3 |
| reality-vision-socks-upload-8 | baseline | 1631.936 | 320.000 | 11.547 | — | — | — | 3 |
| reality-vision-socks-upload-8 | candidate | 1609.181 | 290.000 | 11.438 | — | — | — | 3 |
| reality-vision-socks-download-8 | baseline | 1412.929 | 440.000 | 9.359 | — | — | — | 3 |
| reality-vision-socks-download-8 | candidate | 1455.516 | 360.000 | 8.672 | — | — | — | 3 |
| reality-vision-socks-full-duplex-8 | baseline | 892.140 | 640.000 | 11.109 | — | — | — | 3 |
| reality-vision-socks-full-duplex-8 | candidate | 1109.330 | 650.000 | 10.656 | — | — | — | 3 |
| reality-vision-tun-upload-1 | baseline | 501.384 | 60.000 | 8.625 | — | — | — | 3 |
| reality-vision-tun-upload-1 | candidate | 513.501 | 50.000 | 8.422 | — | — | — | 3 |
| reality-vision-tun-download-1 | baseline | 518.678 | 60.000 | 8.547 | — | — | — | 3 |
| reality-vision-tun-download-1 | candidate | 543.506 | 50.000 | 8.344 | — | — | — | 3 |
| reality-vision-tun-full-duplex-1 | baseline | 636.050 | 70.000 | 9.250 | — | — | — | 3 |
| reality-vision-tun-full-duplex-1 | candidate | 660.132 | 70.000 | 8.906 | — | — | — | 3 |
| reality-vision-tun-upload-8 | baseline | 558.419 | 130.000 | 12.219 | — | — | — | 3 |
| reality-vision-tun-upload-8 | candidate | 690.258 | 120.000 | 11.953 | — | — | — | 3 |
| reality-vision-tun-download-8 | baseline | 545.017 | 130.000 | 14.078 | — | — | — | 3 |
| reality-vision-tun-download-8 | candidate | 521.664 | 110.000 | 12.969 | — | — | — | 3 |
| reality-vision-tun-full-duplex-8 | baseline | 627.130 | 220.000 | 15.859 | — | — | — | 3 |
| reality-vision-tun-full-duplex-8 | candidate | 701.750 | 180.000 | 15.078 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

