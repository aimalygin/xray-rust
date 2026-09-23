# reviewed-parity-wireguard-long-echo-ambient-confirmation

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

80 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `unproven`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-tcp-latency-1 | candidate | 17.487 | 310.000 | 6.078 | 102.000 | 143.000 | 312.000 | 5 |
| wireguard-socks-tcp-latency-1 | native | 15.732 | 530.000 | 14.016 | 114.000 | 166.000 | 336.000 | 5 |
| wireguard-socks-tcp-latency-1 | singbox | 16.123 | 510.000 | 27.219 | 112.000 | 155.000 | 309.000 | 5 |
| wireguard-socks-tcp-latency-1 | xray | 15.647 | 530.000 | 33.203 | 114.000 | 172.000 | 335.000 | 5 |
| wireguard-socks-tcp-latency-8 | candidate | 69.546 | 1520.000 | 6.594 | 210.000 | 351.000 | 480.000 | 5 |
| wireguard-socks-tcp-latency-8 | native | 58.084 | 2190.000 | 14.812 | 246.000 | 452.000 | 619.000 | 5 |
| wireguard-socks-tcp-latency-8 | singbox | 59.848 | 2070.000 | 30.469 | 244.000 | 417.000 | 571.000 | 5 |
| wireguard-socks-tcp-latency-8 | xray | 57.853 | 2190.000 | 35.844 | 247.000 | 457.000 | 633.000 | 5 |
| wireguard-socks-udp-1 | candidate | 17.947 | 240.000 | 6.344 | 119.000 | 147.000 | 357.000 | 5 |
| wireguard-socks-udp-1 | native | 16.866 | 350.000 | 14.000 | 126.000 | 155.000 | 356.000 | 5 |
| wireguard-socks-udp-1 | singbox | 16.908 | 350.000 | 27.234 | 126.000 | 161.000 | 356.000 | 5 |
| wireguard-socks-udp-1 | xray | 15.918 | 390.000 | 33.594 | 133.000 | 179.000 | 387.000 | 5 |
| wireguard-socks-udp-8 | candidate | 73.414 | 1390.000 | 6.859 | 232.000 | 391.000 | 533.000 | 5 |
| wireguard-socks-udp-8 | native | 68.131 | 1860.000 | 14.578 | 246.000 | 433.000 | 592.000 | 5 |
| wireguard-socks-udp-8 | singbox | 70.881 | 1750.000 | 29.328 | 239.000 | 397.000 | 564.000 | 5 |
| wireguard-socks-udp-8 | xray | 64.565 | 2090.000 | 35.812 | 254.000 | 496.000 | 754.000 | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

