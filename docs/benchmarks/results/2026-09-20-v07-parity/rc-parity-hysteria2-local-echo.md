# rc-parity-hysteria2-local-echo

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

48 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-tcp-latency-1 | candidate | 17.454 | 40.000 | 7.703 | 84.000 | 249.000 | 494.000 | 3 |
| hysteria2-socks-tcp-latency-1 | native | 15.648 | 70.000 | 23.797 | 90.000 | 269.000 | 720.000 | 3 |
| hysteria2-socks-tcp-latency-1 | singbox | 16.213 | 70.000 | 24.672 | 88.000 | 260.000 | 740.000 | 3 |
| hysteria2-socks-tcp-latency-1 | xray | 17.195 | 60.000 | 31.125 | 90.000 | 244.000 | 424.000 | 3 |
| hysteria2-socks-tcp-latency-8 | candidate | 85.388 | 240.000 | 7.969 | 160.000 | 307.000 | 509.000 | 3 |
| hysteria2-socks-tcp-latency-8 | native | 78.275 | 300.000 | 27.688 | 169.000 | 335.000 | 621.000 | 3 |
| hysteria2-socks-tcp-latency-8 | singbox | 84.352 | 260.000 | 27.297 | 160.000 | 312.000 | 509.000 | 3 |
| hysteria2-socks-tcp-latency-8 | xray | 80.676 | 290.000 | 33.156 | 168.000 | 327.000 | 502.000 | 3 |
| hysteria2-socks-udp-1 | candidate | 15.091 | 40.000 | 7.875 | 112.000 | 355.000 | 685.000 | 3 |
| hysteria2-socks-udp-1 | native | 13.599 | 100.000 | 27.984 | 131.000 | 346.000 | 722.000 | 3 |
| hysteria2-socks-udp-1 | singbox | 14.221 | 90.000 | 27.484 | 128.000 | 329.000 | 599.000 | 3 |
| hysteria2-socks-udp-1 | xray | 12.557 | 120.000 | 33.641 | 149.000 | 392.000 | 585.000 | 3 |
| hysteria2-socks-udp-8 | candidate | 65.199 | 250.000 | 8.312 | 239.000 | 461.000 | 655.000 | 3 |
| hysteria2-socks-udp-8 | native | — | — | — | — | — | — | 2 |
| hysteria2-socks-udp-8 | singbox | 65.582 | 350.000 | 28.516 | 242.000 | 480.000 | 764.000 | 3 |
| hysteria2-socks-udp-8 | xray | 57.513 | 480.000 | 34.906 | 279.000 | 568.000 | 778.000 | 3 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

Observed failures:

```json
[
  {
    "case": "hysteria2-socks-udp-8",
    "version": "native",
    "repeat": 2,
    "returncode": 1,
    "error": "protocol benchmark exceeded 120 seconds"
  }
]
```

