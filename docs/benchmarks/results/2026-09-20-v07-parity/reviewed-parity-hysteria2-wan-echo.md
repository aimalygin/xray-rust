# reviewed-parity-hysteria2-wan-echo

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

48 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: True.

**Measurement limitation:** build/compiler-related background activity was observed. Retained timings are exploratory and cannot establish small protocol differences. Original observations and the supplementary ambient audit remain unchanged.

External comparison with 3% performance allowance and strictly lower RSS: `invalid_measurements`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-tcp-latency-1 | candidate | 0.035 | 10.000 | 7.688 | 53179.000 | 54154.000 | 55385.000 | 3 |
| hysteria2-socks-tcp-latency-1 | native | 0.036 | 30.000 | 23.500 | 52941.000 | 53828.000 | 54188.000 | 3 |
| hysteria2-socks-tcp-latency-1 | singbox | 0.037 | 20.000 | 24.594 | 52963.000 | 54190.000 | 54524.000 | 3 |
| hysteria2-socks-tcp-latency-1 | xray | 0.037 | 20.000 | 30.969 | 53065.000 | 54237.000 | 54627.000 | 3 |
| hysteria2-socks-tcp-latency-8 | candidate | 0.286 | 30.000 | 7.938 | 52739.000 | 53969.000 | 54419.000 | 3 |
| hysteria2-socks-tcp-latency-8 | native | 0.285 | 50.000 | 24.094 | 52813.000 | 53933.000 | 54132.000 | 3 |
| hysteria2-socks-tcp-latency-8 | singbox | 0.295 | 40.000 | 24.797 | 52770.000 | 53811.000 | 55522.000 | 3 |
| hysteria2-socks-tcp-latency-8 | xray | 0.298 | 30.000 | 31.156 | 52521.000 | 53919.000 | 55033.000 | 3 |
| hysteria2-socks-udp-1 | candidate | 0.043 | 10.000 | 7.891 | 53344.000 | 55138.000 | 55727.000 | 3 |
| hysteria2-socks-udp-1 | native | 0.043 | 30.000 | 23.750 | 53519.000 | 54430.000 | 55097.000 | 3 |
| hysteria2-socks-udp-1 | singbox | 0.043 | 30.000 | 24.688 | 53072.000 | 54968.000 | 56236.000 | 3 |
| hysteria2-socks-udp-1 | xray | 0.043 | 30.000 | 31.188 | 53348.000 | 54904.000 | 56441.000 | 3 |
| hysteria2-socks-udp-8 | candidate | 0.342 | 30.000 | 8.250 | 53562.000 | 54776.000 | 55173.000 | 3 |
| hysteria2-socks-udp-8 | native | 0.341 | 60.000 | 26.312 | 53579.000 | 55525.000 | 55744.000 | 3 |
| hysteria2-socks-udp-8 | singbox | 0.342 | 50.000 | 26.250 | 53323.000 | 55501.000 | 56035.000 | 3 |
| hysteria2-socks-udp-8 | xray | 0.341 | 70.000 | 33.438 | 53487.000 | 55161.000 | 55932.000 | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

