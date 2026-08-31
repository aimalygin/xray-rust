# RC4 benchmark evidence: Xray-core v26.7.28

This immutable result group contains the publication-quality localhost
benchmark campaign for xray-rust `v0.4.1-rc.4`, candidate
`5b8dca35af08eddd42fdb648a1347ff896b0c59f`. Every published series has five
successful release runs with embedded clean-source and binary-hash provenance.
The manifest contains 139 series and 695 per-run results.

The campaign identifier and publication date are 2026-08-29. The frozen
campaign completed on 2026-08-31 UTC after the machine returned to AC power.
It ran on a MacBook Pro (Mac15,7) with an Apple M3 Pro (12 cores), 18 GB RAM,
and macOS 26.5.2. Comparators are Xray-core `v26.7.28` at
`5ca6f4b7d4dc20a881d4330e498892697627ec0c` and stable sing-box `v1.13.20` at
`56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778`.

These are same-host process microbenchmarks. They validate payload bytes and
measure process RSS, CPU, setup, and transfer timing; they do not represent a
controlled WAN, packet-loss experiment, mobile energy test, or cross-engine
TUN comparison. Values below are five-run medians. RSS is peak resident memory.

## Headline charts

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/memory-rss-dark.svg">
  <img alt="Peak RSS at idle and with 100 and 1000 idle flows. xray-rust: 4.1, 6.2, and 20.9 MiB; Xray-core: 29.5, 36.4, and 80.8 MiB; sing-box: 21.9, 27.4, and 48.9 MiB." src="media/memory-rss-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/latency-dark.svg">
  <img alt="Median localhost round-trip latency. TCP: xray-rust 40 microseconds, Xray-core 35, sing-box 37. UDP: 37, 58, and 46. REALITY Vision XUDP: xray-rust 83 and Xray-core 95; sing-box omitted." src="media/latency-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/throughput-dark.svg">
  <img alt="Plain TCP bulk throughput: xray-rust 73.6 Gbps, Xray-core 57.5 Gbps, sing-box 83.5 Gbps." src="media/throughput-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/reality-throughput-dark.svg">
  <img alt="VLESS REALITY Vision bulk throughput: xray-rust 15.1 Gbps and Xray-core 14.4 Gbps; stable sing-box omitted at the recorded client-version boundary." src="media/reality-throughput-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/cpu-per-gib-dark.svg">
  <img alt="CPU milliseconds per GiB on plain TCP bulk: xray-rust 159, Xray-core 213, sing-box 139." src="media/cpu-per-gib-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/geo-setup-latency-dark.svg">
  <img alt="Total setup time with real geodata: xray-rust 1243 microseconds and Xray-core 1153 microseconds." src="media/geo-setup-latency-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="media/geo-memory-dark.svg">
  <img alt="Peak RSS with real geodata: xray-rust 9.5 MiB and Xray-core 35.4 MiB." src="media/geo-memory-light.svg">
</picture>

## Base and reconnect results

| Scenario | Median metric | xray-rust | Xray-core | sing-box |
| --- | --- | ---: | ---: | ---: |
| idle | RSS, MiB | 4.1 | 29.5 | 21.9 |
| many-idle-flows-100 | RSS, MiB | 6.2 | 36.4 | 27.4 |
| many-idle-flows-1000 | RSS, MiB | 20.9 | 80.8 | 48.9 |
| tcp-freedom | RTT, µs | 40 | 35 | 37 |
| udp-freedom | RTT, µs | 37 | 58 | 46 |
| reconnect-burst | total setup, µs | 1,293 | 1,383 | 1,247 |
| reality-vision-xudp | RTT, µs | 83 | 95 | omitted |
| tcp-bulk-throughput | throughput, Gbps | 73.6 | 57.5 | 83.5 |
| reality-vision-bulk-throughput | throughput, Gbps | 15.1 | 14.4 | omitted |
| routed-tcp-freedom | total setup, µs | 1,243 | 1,153 | unsupported |
| routed-tcp-freedom | RSS, MiB | 9.5 | 35.4 | unsupported |

## Stream transport results

Each cell is `throughput Mbps / peak RSS MiB`. The workload transfers 4,096 ×
64 KiB per flow in the selected direction; full-duplex transfers that amount
in both directions.

| Scenario | xray-rust | Xray-core | sing-box |
| --- | ---: | ---: | ---: |
| stream-ws-upload-1 | 5,608 / 8.1 | 4,949 / 33.2 | 12,272 / 23.7 |
| stream-ws-upload-32 | 9,998 / 32.2 | 8,847 / 46.2 | 13,917 / 36.8 |
| stream-ws-download-1 | 9,587 / 7.0 | 7,509 / 33.4 | 8,166 / 26.5 |
| stream-ws-download-32 | 11,943 / 11.7 | 11,376 / 44.7 | 10,817 / 36.2 |
| stream-ws-full-duplex-1 | 9,297 / 8.2 | 3,628 / 34.4 | 12,596 / 27.0 |
| stream-ws-full-duplex-32 | 8,726 / 31.3 | 8,193 / 47.1 | 10,326 / 42.7 |
| stream-httpupgrade-upload-1 | 14,036 / 7.3 | 11,865 / 33.2 | 13,422 / 23.6 |
| stream-httpupgrade-upload-32 | 14,255 / 17.0 | 13,755 / 45.3 | 13,684 / 36.5 |
| stream-httpupgrade-download-1 | 14,413 / 6.9 | 12,202 / 32.9 | 14,811 / 25.8 |
| stream-httpupgrade-download-32 | 13,422 / 10.6 | 13,454 / 44.2 | 13,808 / 36.7 |
| stream-httpupgrade-full-duplex-1 | 18,434 / 7.3 | 14,269 / 33.9 | 16,208 / 26.0 |
| stream-httpupgrade-full-duplex-32 | 10,825 / 18.1 | 8,314 / 47.2 | 5,547 / 42.4 |
| stream-grpc-upload-1 | 17,896 / 9.3 | 12,559 / 36.6 | 10,130 / 24.5 |
| stream-grpc-upload-32 | 16,872 / 29.9 | 12,311 / 53.1 | 10,576 / 37.4 |
| stream-grpc-download-1 | 7,111 / 7.9 | 12,937 / 92.2 | 5,465 / 38.8 |
| stream-grpc-download-32 | 11,075 / 10.8 | 12,644 / 371.1 | 5,262 / 401.1 |
| stream-grpc-full-duplex-1 | 10,901 / 9.8 | 14,269 / 98.4 | 7,041 / 41.1 |
| stream-grpc-full-duplex-32 | 10,800 / 34.9 | 8,509 / 282.4 | omitted |
| stream-xhttp-h1-upload-1 | 9,419 / 8.0 | 5,451 / 34.3 | unsupported |
| stream-xhttp-h1-upload-32 | 11,923 / 19.6 | 10,698 / 54.3 | unsupported |
| stream-xhttp-h1-download-1 | 7,065 / 7.8 | 6,469 / 33.7 | unsupported |
| stream-xhttp-h1-download-32 | 10,745 / 14.5 | 11,106 / 52.2 | unsupported |
| stream-xhttp-h1-full-duplex-1 | 9,784 / 8.1 | 5,999 / 34.8 | unsupported |
| stream-xhttp-h1-full-duplex-32 | 10,492 / 20.4 | 10,002 / 55.1 | unsupported |
| stream-xhttp-h2-upload-1 | 9,943 / 9.1 | 7,457 / 34.6 | unsupported |
| stream-xhttp-h2-upload-32 | 8,404 / 18.5 | 8,654 / 60.8 | unsupported |
| stream-xhttp-h2-download-1 | 6,261 / 8.3 | 5,535 / 35.1 | unsupported |
| stream-xhttp-h2-download-32 | 13,391 / 13.8 | 7,176 / 60.6 | unsupported |
| stream-xhttp-h2-full-duplex-1 | 8,472 / 9.2 | 6,950 / 36.0 | unsupported |
| stream-xhttp-h2-full-duplex-32 | 7,838 / 20.7 | 4,990 / 63.5 | unsupported |
| stream-xhttp-h3-upload-1 | 1,639 / 10.6 | 1,816 / 37.8 | unsupported |
| stream-xhttp-h3-upload-32 | 1,579 / 163.4 | 1,866 / 49.8 | unsupported |
| stream-xhttp-h3-download-1 | 1,660 / 20.6 | 2,259 / 37.9 | unsupported |
| stream-xhttp-h3-download-32 | 2,180 / 15.6 | 2,028 / 46.8 | unsupported |
| stream-xhttp-h3-full-duplex-1 | 2,182 / 26.3 | 2,375 / 38.6 | unsupported |
| stream-xhttp-h3-full-duplex-32 | 1,935 / 188.2 | 2,123 / 50.6 | unsupported |

The H3 32-flow upload and full-duplex RSS values are a visible optimization
target: the candidate completed all five runs, but its concurrent QUIC stream
state is substantially larger than Xray-core's in those two cases. They are
published unchanged rather than filtered out.

## XHTTP packet pressure

Each cell is `throughput Mbps / peak RSS MiB / CPU ms`. Every flow uploads
4,096 × 16 KiB paced packet-up writes.

| Scenario | xray-rust | Xray-core |
| --- | ---: | ---: |
| xhttp-pressure-xhttp-h1-1 | 5 / 8.6 / 2,780 | 4 / 37.0 / 5,750 |
| xhttp-pressure-xhttp-h1-32 | 130 / 18.2 / 35,450 | 116 / 57.5 / 93,980 |
| xhttp-pressure-xhttp-h2-1 | 5 / 9.3 / 3,700 | 4 / 37.0 / 6,480 |
| xhttp-pressure-xhttp-h2-32 | 130 / 16.8 / 35,710 | 116 / 77.4 / 49,880 |
| xhttp-pressure-xhttp-h3-1 | 5 / 9.4 / 9,800 | 4 / 38.8 / 16,870 |
| xhttp-pressure-xhttp-h3-32 | 135 / 29.6 / 77,130 | omitted |

The H3/32 xray-rust series passed 5/5 at the full load. The pinned Xray-core
comparison is omitted because its preserved campaign reset the completion
marker connection after the candidate finished, an exact retry timed out at
300 seconds, and reduced-load diagnostics failed above four flows. No reduced
or isolated result is substituted into this table.

## XHTTP bounded-memory profile

Each cell is `peak RSS MiB / duration ms`; packet-up rows also show throughput.

| Scenario | xray-rust | Xray-core |
| --- | ---: | ---: |
| held-open, 1 flow, max 500000 | 5.5 / 35,018 | 30.2 / 35,521 |
| held-open, 16 flows, max 500000 | 7.4 / 35,021 | 34.9 / 35,527 |
| held-open, 32 flows, max 500000 | 8.8 / 35,027 | 37.2 / 35,532 |
| held-open, 16-flow control, max 16384 | 7.5 / 35,017 | 34.8 / 35,523 |
| packet-up, 1 flow, max 500000 | 6.4 / 67,808 / 3 Mbps | 33.7 / 76,386 / 2 Mbps |
| packet-up, 16 flows, max 500000 | 9.8 / 67,849 / 34 Mbps | 41.4 / 80,835 / 28 Mbps |

The 16-flow held-open control and 500000-byte ceiling are effectively equal
for xray-rust (7.5 versus 7.4 MiB median), which supports the intended bounded
allocation behavior: the ceiling is not eagerly pinned per idle flow.

## Reviewed omissions

- Stable sing-box `v1.13.20` is omitted from both REALITY workloads. Its
  REALITY `ClientVer` 1.8.1 is rejected by Xray-core v26.7.28's default
  `minClientVer` 26.3.27. The generic harness still supports compatible or
  patched sing-box builds; this publication used `--skip-sing-box` and did not
  change the fixture or timeout.
- sing-box is omitted only from `stream-grpc-full-duplex-32` after two frozen
  five-run campaigns timed out after three and four successful sing-box runs.
  Later isolated diagnostics passed, demonstrating a nondeterministic stall;
  they were not substituted into either failed campaign.
- Xray-core is omitted only from `xhttp-pressure-xhttp-h3-32` under the reset,
  exact-retry timeout, and reduced-load boundary described above.
- sing-box is structurally unsupported for XHTTP and cannot consume the Xray
  `.dat` geodata fixture, so those are compatibility boundaries rather than
  failed performance series.

## Review against the historical v26.5.9 group

The [2026-08-01 publication](../../results.md) remains immutable and is not a
same-binary comparison: RC4 adds WebSocket, HTTPUpgrade, gRPC, XHTTP, expanded
TLS/uTLS, routing, and DNS behavior, and also changes comparator revisions.
The material deltas are disclosed here instead of relabelling old charts:

- xray-rust RSS moved from 3.84 to 4.14 MiB at idle, 5.50 to 6.16 MiB at 100
  idle flows, and 18.27 to 20.88 MiB at 1,000. The tightly grouped RC4 repeats
  make this a real footprint increase for the expanded runtime, not a selected
  outlier. It remains the lowest RSS engine at all three scales.
- plain TCP bulk moved from 57.7 to 73.6 Gbps while CPU cost fell from 190 to
  159 ms/GiB. REALITY/Vision bulk moved from 14.3 to 15.1 Gbps and 770 to
  760 ms/GiB.
- median TCP, UDP, and REALITY/XUDP latency stayed near the historical values:
  40/37/83 µs now versus 39/37/83 µs before.
- geodata RSS moved from 8.62 to 9.54 MiB for xray-rust and from 34.7 to
  35.4 MiB for Xray-core; xray-rust remains about 3.7× smaller in this local
  profile.

## Evidence and replay

- [`manifest.json`](manifest.json) is the machine-validated index of every
  series, exact comparator identities, environment, archive digest, and the
  two reviewed runtime omissions.
- [`commands.sh`](commands.sh) records the exact absolute inputs and benchmark
  argument matrix used by the frozen campaign.
- `chart-inputs/` contains only the reviewed aggregate summaries; every file
  embeds its five raw results and provenance.
- The raw result directories are retained outside Git as
  `target/benchmarks/xray-rust-rc4-2026-08-29.tar.gz`, SHA-256
  `966bfa4e1b6edcb1264bac2ea5bbfcc094b763e34be878642e2db0849095cfeb`.
  The archive is deterministic and excludes comparator checkouts, binaries,
  `measurement.env`, and orchestration logs.

Validate the committed evidence with:

```sh
python3 scripts/check-benchmark-publication.py \
  docs/benchmarks/results/2026-08-29-v26.7.28
```
