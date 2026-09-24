# reviewed-parity-hysteria2-local-echo

Scope: **selected executable**. Candidate SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.

48 runs; 3 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-tcp-latency-1 | candidate | 17.395 | 40.000 | 7.688 | 88.000 | 224.000 | 322.000 | 3 |
| hysteria2-socks-tcp-latency-1 | native | 16.061 | 70.000 | 23.938 | 96.000 | 235.000 | 393.000 | 3 |
| hysteria2-socks-tcp-latency-1 | singbox | 16.168 | 70.000 | 24.656 | 92.000 | 243.000 | 383.000 | 3 |
| hysteria2-socks-tcp-latency-1 | xray | 16.235 | 70.000 | 31.141 | 96.000 | 230.000 | 343.000 | 3 |
| hysteria2-socks-tcp-latency-8 | candidate | 66.095 | 270.000 | 7.938 | 209.000 | 393.000 | 518.000 | 3 |
| hysteria2-socks-tcp-latency-8 | native | 63.762 | 330.000 | 28.000 | 233.000 | 370.000 | 496.000 | 3 |
| hysteria2-socks-tcp-latency-8 | singbox | 64.795 | 320.000 | 27.344 | 215.000 | 396.000 | 536.000 | 3 |
| hysteria2-socks-tcp-latency-8 | xray | 62.650 | 360.000 | 33.266 | 223.000 | 417.000 | 611.000 | 3 |
| hysteria2-socks-udp-1 | candidate | 15.328 | 30.000 | 7.906 | 122.000 | 315.000 | 475.000 | 3 |
| hysteria2-socks-udp-1 | native | 13.279 | 110.000 | 27.875 | 141.000 | 324.000 | 487.000 | 3 |
| hysteria2-socks-udp-1 | singbox | 14.026 | 100.000 | 27.484 | 137.000 | 302.000 | 479.000 | 3 |
| hysteria2-socks-udp-1 | xray | 12.075 | 130.000 | 33.844 | 159.000 | 344.000 | 527.000 | 3 |
| hysteria2-socks-udp-8 | candidate | 57.168 | 300.000 | 8.312 | 286.000 | 527.000 | 738.000 | 3 |
| hysteria2-socks-udp-8 | native | — | — | — | — | — | — | 2 |
| hysteria2-socks-udp-8 | singbox | 47.134 | 440.000 | 28.578 | 337.000 | 680.000 | 929.000 | 3 |
| hysteria2-socks-udp-8 | xray | — | — | — | — | — | — | 2 |

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
  },
  {
    "case": "hysteria2-socks-udp-8",
    "version": "xray",
    "repeat": 3,
    "returncode": 1,
    "error": "protocol benchmark exceeded 120 seconds"
  }
]
```

