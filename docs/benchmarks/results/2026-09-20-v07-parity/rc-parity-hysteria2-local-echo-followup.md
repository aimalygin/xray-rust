# rc-parity-hysteria2-local-echo-followup

Scope: **predecessor / separate experiment**. Candidate SHA256: `ec91384cc94c6b3154416c6b08286ad7d232f873c246a0ac1f5e73034be88ae4`.

80 runs; 5 repeats per workload/client; flagged build/compiler-process activity including the expanded audit: False.

External comparison with 3% performance allowance and strictly lower RSS: `not_met`.

| Workload | Client | MiB/s | CPU ms | RSS MiB | Median µs | p95 µs | p99 µs | Passed repeats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| hysteria2-socks-tcp-latency-1 | candidate | 22.165 | 160.000 | 7.641 | 80.000 | 100.000 | 261.000 | 5 |
| hysteria2-socks-tcp-latency-1 | native | 20.816 | 270.000 | 26.406 | 87.000 | 105.000 | 264.000 | 5 |
| hysteria2-socks-tcp-latency-1 | singbox | 21.259 | 270.000 | 26.219 | 84.000 | 109.000 | 255.000 | 5 |
| hysteria2-socks-tcp-latency-1 | xray | 20.555 | 280.000 | 32.953 | 88.000 | 112.000 | 256.000 | 5 |
| hysteria2-socks-tcp-latency-8 | candidate | 97.154 | 1070.000 | 8.000 | 153.000 | 223.000 | 322.000 | 5 |
| hysteria2-socks-tcp-latency-8 | native | 91.559 | 1260.000 | 28.047 | 162.000 | 233.000 | 357.000 | 5 |
| hysteria2-socks-tcp-latency-8 | singbox | 95.744 | 1170.000 | 28.125 | 154.000 | 227.000 | 368.000 | 5 |
| hysteria2-socks-tcp-latency-8 | xray | 93.005 | 1250.000 | 33.688 | 159.000 | 233.000 | 366.000 | 5 |
| hysteria2-socks-udp-1 | candidate | 19.125 | 150.000 | 7.906 | 111.000 | 130.000 | 336.000 | 5 |
| hysteria2-socks-udp-1 | native | 16.549 | 420.000 | 28.109 | 130.000 | 151.000 | 337.000 | 5 |
| hysteria2-socks-udp-1 | singbox | 17.042 | 390.000 | 28.344 | 125.000 | 148.000 | 331.000 | 5 |
| hysteria2-socks-udp-1 | xray | 14.793 | 510.000 | 34.203 | 145.000 | 184.000 | 366.000 | 5 |
| hysteria2-socks-udp-8 | candidate | 74.247 | 1190.000 | 8.312 | 231.000 | 356.000 | 497.000 | 5 |
| hysteria2-socks-udp-8 | native | — | — | — | — | — | — | 1 |
| hysteria2-socks-udp-8 | singbox | 72.193 | 1590.000 | 29.109 | 236.000 | 373.000 | 503.000 | 5 |
| hysteria2-socks-udp-8 | xray | — | — | — | — | — | — | 4 |

Original strict summaries remain in data/*-summary.json. Separate data/*-allowance-summary.json files apply the requested 3% performance allowance; samples, ratios and intervals are unchanged. Memory, failed trials and quality flags receive no allowance.

Observed failures:

```json
[
  {
    "case": "hysteria2-socks-udp-8",
    "version": "native",
    "repeat": 1,
    "returncode": 1,
    "error": "protocol benchmark exceeded 120 seconds"
  },
  {
    "case": "hysteria2-socks-udp-8",
    "version": "native",
    "repeat": 3,
    "returncode": 1,
    "error": "protocol benchmark exceeded 120 seconds"
  },
  {
    "case": "hysteria2-socks-udp-8",
    "version": "native",
    "repeat": 4,
    "returncode": 1,
    "error": "protocol benchmark exceeded 120 seconds"
  },
  {
    "case": "hysteria2-socks-udp-8",
    "version": "xray",
    "repeat": 4,
    "returncode": 1,
    "error": "protocol benchmark exceeded 120 seconds"
  },
  {
    "case": "hysteria2-socks-udp-8",
    "version": "native",
    "repeat": 5,
    "returncode": 1,
    "error": "protocol benchmark exceeded 120 seconds"
  }
]
```

