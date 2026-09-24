# reviewed-parity-wireguard-wan-echo

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

48 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `unproven`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-tcp-latency-1 | candidate | 0.036 | 20.000 | 6.062 | 52671.000 | 54362.000 | 54517.000 | 3 |
| wireguard-socks-tcp-latency-1 | native | 0.035 | 30.000 | 9.406 | 53148.000 | 54392.000 | 54465.000 | 3 |
| wireguard-socks-tcp-latency-1 | singbox | 0.036 | 30.000 | 24.688 | 52889.000 | 54303.000 | 55007.000 | 3 |
| wireguard-socks-tcp-latency-1 | xray | 0.036 | 20.000 | 30.203 | 53010.000 | 54408.000 | 105056.000 | 3 |
| wireguard-socks-tcp-latency-8 | candidate | 0.281 | 60.000 | 6.625 | 53677.000 | 55644.000 | 57792.000 | 3 |
| wireguard-socks-tcp-latency-8 | native | 0.282 | 100.000 | 12.141 | 53450.000 | 55364.000 | 58526.000 | 3 |
| wireguard-socks-tcp-latency-8 | singbox | 0.279 | 110.000 | 25.438 | 54077.000 | 55813.000 | 58015.000 | 3 |
| wireguard-socks-tcp-latency-8 | xray | 0.278 | 100.000 | 32.406 | 53953.000 | 58012.000 | 114032.000 | 3 |
| wireguard-socks-udp-1 | candidate | 0.043 | 10.000 | 6.312 | 53128.000 | 54396.000 | 55552.000 | 3 |
| wireguard-socks-udp-1 | native | 0.043 | 20.000 | 9.422 | 52889.000 | 54738.000 | 55480.000 | 3 |
| wireguard-socks-udp-1 | singbox | 0.043 | 30.000 | 25.031 | 53192.000 | 54818.000 | 56233.000 | 3 |
| wireguard-socks-udp-1 | xray | 0.043 | 20.000 | 30.562 | 53144.000 | 54446.000 | 55285.000 | 3 |
| wireguard-socks-udp-8 | candidate | 0.337 | 50.000 | 6.859 | 54212.000 | 55815.000 | 56256.000 | 3 |
| wireguard-socks-udp-8 | native | 0.337 | 90.000 | 12.344 | 54113.000 | 56073.000 | 57512.000 | 3 |
| wireguard-socks-udp-8 | singbox | 0.339 | 90.000 | 25.625 | 53867.000 | 55357.000 | 56950.000 | 3 |
| wireguard-socks-udp-8 | xray | 0.336 | 100.000 | 32.953 | 54364.000 | 56270.000 | 57735.000 | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

