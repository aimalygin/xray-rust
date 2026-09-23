# rc-parity-wireguard-local-echo

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

48 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-tcp-latency-1 | candidate | 14.657 | 70.000 | 7.078 | 101.000 | 276.000 | 488.000 | 3 |
| wireguard-socks-tcp-latency-1 | native | 12.939 | 120.000 | 13.594 | 114.000 | 276.000 | 832.000 | 3 |
| wireguard-socks-tcp-latency-1 | singbox | 13.375 | 120.000 | 25.547 | 112.000 | 279.000 | 857.000 | 3 |
| wireguard-socks-tcp-latency-1 | xray | 13.139 | 120.000 | 32.891 | 114.000 | 277.000 | 436.000 | 3 |
| wireguard-socks-tcp-latency-8 | candidate | 72.412 | 300.000 | 14.375 | 193.000 | 361.000 | 499.000 | 3 |
| wireguard-socks-tcp-latency-8 | native | 58.622 | 440.000 | 14.531 | 229.000 | 456.000 | 676.000 | 3 |
| wireguard-socks-tcp-latency-8 | singbox | 60.345 | 420.000 | 29.031 | 227.000 | 426.000 | 711.000 | 3 |
| wireguard-socks-tcp-latency-8 | xray | 59.747 | 430.000 | 35.609 | 226.000 | 448.000 | 640.000 | 3 |
| wireguard-socks-udp-1 | candidate | 14.902 | 50.000 | 6.312 | 119.000 | 357.000 | 622.000 | 3 |
| wireguard-socks-udp-1 | native | 14.152 | 70.000 | 13.734 | 127.000 | 379.000 | 637.000 | 3 |
| wireguard-socks-udp-1 | singbox | 13.957 | 80.000 | 26.328 | 126.000 | 354.000 | 601.000 | 3 |
| wireguard-socks-udp-1 | xray | 13.990 | 80.000 | 33.031 | 134.000 | 337.000 | 422.000 | 3 |
| wireguard-socks-udp-8 | candidate | 68.067 | 290.000 | 6.859 | 234.000 | 448.000 | 742.000 | 3 |
| wireguard-socks-udp-8 | native | 65.017 | 360.000 | 14.375 | 245.000 | 453.000 | 789.000 | 3 |
| wireguard-socks-udp-8 | singbox | 65.959 | 350.000 | 28.859 | 241.000 | 467.000 | 724.000 | 3 |
| wireguard-socks-udp-8 | xray | 61.947 | 400.000 | 35.203 | 253.000 | 531.000 | 878.000 | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

