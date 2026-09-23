# reviewed-parity-wireguard-long-echo

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

80 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: True.

**Measurement limitation:** build/compiler-related background activity was observed. Retained timings are exploratory and cannot establish small protocol differences. Original observations and the supplementary ambient audit remain unchanged.

External comparison with 3% performance allowance and strictly lower RSS: `invalid_measurements`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-tcp-latency-1 | candidate | 18.361 | 300.000 | 6.094 | 98.000 | 126.000 | 290.000 | 5 |
| wireguard-socks-tcp-latency-1 | native | 16.342 | 500.000 | 13.719 | 110.000 | 141.000 | 315.000 | 5 |
| wireguard-socks-tcp-latency-1 | singbox | 16.615 | 480.000 | 27.000 | 110.000 | 134.000 | 301.000 | 5 |
| wireguard-socks-tcp-latency-1 | xray | 16.395 | 500.000 | 33.156 | 110.000 | 148.000 | 302.000 | 5 |
| wireguard-socks-tcp-latency-8 | candidate | 63.444 | 1660.000 | 6.609 | 230.000 | 380.000 | 494.000 | 5 |
| wireguard-socks-tcp-latency-8 | native | 64.846 | 2010.000 | 14.781 | 223.000 | 378.000 | 537.000 | 5 |
| wireguard-socks-tcp-latency-8 | singbox | 60.139 | 2040.000 | 30.312 | 242.000 | 409.000 | 575.000 | 5 |
| wireguard-socks-tcp-latency-8 | xray | 65.438 | 1990.000 | 36.234 | 220.000 | 375.000 | 539.000 | 5 |
| wireguard-socks-udp-1 | candidate | 18.527 | 230.000 | 6.328 | 117.000 | 136.000 | 345.000 | 5 |
| wireguard-socks-udp-1 | native | 17.246 | 330.000 | 13.984 | 125.000 | 159.000 | 322.000 | 5 |
| wireguard-socks-udp-1 | singbox | 17.595 | 330.000 | 27.594 | 122.000 | 158.000 | 360.000 | 5 |
| wireguard-socks-udp-1 | xray | 16.829 | 360.000 | 33.547 | 128.000 | 173.000 | 349.000 | 5 |
| wireguard-socks-udp-8 | candidate | 80.353 | 1280.000 | 6.891 | 215.000 | 307.000 | 448.000 | 5 |
| wireguard-socks-udp-8 | native | 75.575 | 1680.000 | 14.594 | 226.000 | 361.000 | 490.000 | 5 |
| wireguard-socks-udp-8 | singbox | 76.572 | 1620.000 | 29.078 | 223.000 | 344.000 | 501.000 | 5 |
| wireguard-socks-udp-8 | xray | 71.867 | 1860.000 | 35.641 | 235.000 | 398.000 | 639.000 | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

