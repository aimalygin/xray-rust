# reviewed-parity-wireguard-local-echo

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

48 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-tcp-latency-1 | candidate | 13.203 | 80.000 | 6.062 | 116.000 | 270.000 | 471.000 | 3 |
| wireguard-socks-tcp-latency-1 | native | 12.071 | 130.000 | 13.703 | 132.000 | 295.000 | 451.000 | 3 |
| wireguard-socks-tcp-latency-1 | singbox | 12.435 | 120.000 | 25.562 | 123.000 | 270.000 | 456.000 | 3 |
| wireguard-socks-tcp-latency-1 | xray | 11.933 | 140.000 | 32.797 | 129.000 | 321.000 | 472.000 | 3 |
| wireguard-socks-tcp-latency-8 | candidate | 56.855 | 370.000 | 6.609 | 255.000 | 439.000 | 586.000 | 3 |
| wireguard-socks-tcp-latency-8 | native | 46.354 | 530.000 | 14.422 | 300.000 | 587.000 | 772.000 | 3 |
| wireguard-socks-tcp-latency-8 | singbox | 46.142 | 520.000 | 28.844 | 304.000 | 578.000 | 806.000 | 3 |
| wireguard-socks-tcp-latency-8 | xray | 46.125 | 530.000 | 35.672 | 291.000 | 626.000 | 888.000 | 3 |
| wireguard-socks-udp-1 | candidate | 13.666 | 60.000 | 6.297 | 133.000 | 317.000 | 501.000 | 3 |
| wireguard-socks-udp-1 | native | 13.150 | 80.000 | 13.891 | 143.000 | 351.000 | 500.000 | 3 |
| wireguard-socks-udp-1 | singbox | 13.167 | 90.000 | 26.547 | 138.000 | 330.000 | 641.000 | 3 |
| wireguard-socks-udp-1 | xray | 12.849 | 90.000 | 33.594 | 146.000 | 358.000 | 549.000 | 3 |
| wireguard-socks-udp-8 | candidate | 52.412 | 340.000 | 6.875 | 294.000 | 588.000 | 880.000 | 3 |
| wireguard-socks-udp-8 | native | 47.822 | 490.000 | 14.219 | 326.000 | 659.000 | 953.000 | 3 |
| wireguard-socks-udp-8 | singbox | 51.466 | 440.000 | 29.000 | 311.000 | 590.000 | 826.000 | 3 |
| wireguard-socks-udp-8 | xray | 46.590 | 510.000 | 35.328 | 322.000 | 739.000 | 1042.000 | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

