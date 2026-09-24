# reviewed-parity-regression-new-tun

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

72 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: True.

**Measurement limitation:** build/compiler-related background activity was observed. Retained timings are exploratory and cannot establish small protocol differences. Original observations and the supplementary ambient audit remain unchanged.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-tun-upload-1 | before | 108.587 | 320.000 | 24.594 | — | — | — | 3 |
| hysteria2-tun-upload-1 | candidate | 260.501 | 160.000 | 10.750 | — | — | — | 3 |
| hysteria2-tun-download-1 | before | 195.314 | 380.000 | 11.078 | — | — | — | 3 |
| hysteria2-tun-download-1 | candidate | 221.112 | 210.000 | 10.250 | — | — | — | 3 |
| hysteria2-tun-full-duplex-1 | before | 197.118 | 670.000 | 23.344 | — | — | — | 3 |
| hysteria2-tun-full-duplex-1 | candidate | 283.531 | 330.000 | 12.062 | — | — | — | 3 |
| hysteria2-tun-upload-8 | before | 199.697 | 2380.000 | 47.359 | — | — | — | 3 |
| hysteria2-tun-upload-8 | candidate | 319.890 | 1130.000 | 19.797 | — | — | — | 3 |
| hysteria2-tun-download-8 | before | 236.160 | 3910.000 | 13.781 | — | — | — | 3 |
| hysteria2-tun-download-8 | candidate | 299.026 | 1410.000 | 11.719 | — | — | — | 3 |
| hysteria2-tun-full-duplex-8 | before | 264.510 | 4970.000 | 41.422 | — | — | — | 3 |
| hysteria2-tun-full-duplex-8 | candidate | 333.467 | 2310.000 | 21.172 | — | — | — | 3 |
| wireguard-tun-upload-1 | before | 103.876 | 680.000 | 9.016 | — | — | — | 3 |
| wireguard-tun-upload-1 | candidate | 138.124 | 420.000 | 9.578 | — | — | — | 3 |
| wireguard-tun-download-1 | before | 109.284 | 1000.000 | 8.281 | — | — | — | 3 |
| wireguard-tun-download-1 | candidate | 148.983 | 340.000 | 8.781 | — | — | — | 3 |
| wireguard-tun-full-duplex-1 | before | 126.980 | 1490.000 | 10.109 | — | — | — | 3 |
| wireguard-tun-full-duplex-1 | candidate | 183.469 | 610.000 | 10.750 | — | — | — | 3 |
| wireguard-tun-upload-8 | before | 111.004 | 5650.000 | 16.234 | — | — | — | 3 |
| wireguard-tun-upload-8 | candidate | 167.299 | 2700.000 | 21.250 | — | — | — | 3 |
| wireguard-tun-download-8 | before | 130.773 | 7170.000 | 12.094 | — | — | — | 3 |
| wireguard-tun-download-8 | candidate | 186.940 | 2460.000 | 10.844 | — | — | — | 3 |
| wireguard-tun-full-duplex-8 | before | 131.141 | 12060.000 | 19.312 | — | — | — | 3 |
| wireguard-tun-full-duplex-8 | candidate | 211.690 | 4480.000 | 25.078 | — | — | — | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

