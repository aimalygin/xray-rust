# reviewed-parity-wireguard-stress-16-confirmation

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

40 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `unproven`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| wireguard-socks-upload-16 | candidate | 221.431 | 1940.000 | 30.875 | — | — | — | 5 |
| wireguard-socks-upload-16 | native | 188.744 | 2680.000 | 186.266 | — | — | — | 5 |
| wireguard-socks-upload-16 | singbox | 224.449 | 2240.000 | 101.062 | — | — | — | 5 |
| wireguard-socks-upload-16 | xray | 168.188 | 2990.000 | 195.844 | — | — | — | 5 |
| wireguard-socks-full-duplex-16 | candidate | 262.265 | 3610.000 | 33.109 | — | — | — | 5 |
| wireguard-socks-full-duplex-16 | native | 239.786 | 4230.000 | 254.766 | — | — | — | 5 |
| wireguard-socks-full-duplex-16 | singbox | 261.478 | 3850.000 | 151.500 | — | — | — | 5 |
| wireguard-socks-full-duplex-16 | xray | 81.946 | 4590.000 | 204.422 | — | — | — | 5 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

