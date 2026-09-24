# v0.7 development performance verification — 2026-09-19

**The candidate fails the unchanged historical memory budgets and has repeatable WireGuard load-completion failures and an XHTTP H1 TUN throughput regression.** This campaign does not establish a regression-free RC. Both old release gates and clean transport/protocol measurements are retained. Earlier transport/protocol collections were invalidated after a driver child-process leak was discovered and are excluded from conclusions.

- Baseline: tag `v0.6.1`, commit `ed5258a3a589c2a1f9330142f37c8f3d28a640fa`.
- Candidate: v0.7 development commit `7f87ffe7eaf4ed088a45172d2468df956f26550b` (Cargo package version remains `0.6.1`).
- Reference: clean Xray-core `v26.7.28`, commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.
- Same Apple M3 Pro host, 12 logical CPUs, 18 GiB RAM; Rust 1.96.0; release, thin LTO, one codegen unit. Exact [host/build identity](data/host-build.json).
- Immutable external client binaries, serial measurements, five fresh-process repeats. Baseline/candidate order alternates in paired matrices. [Method and reproduction commands](../../../v07-performance.md).

## Historical release gates

Original v0.5 pre-device and v0.6 feature scripts ran from each clean source checkout. Their thresholds were not changed. v0.6.1 passes both gates; the candidate passes v0.6 features but fails v0.5 memory limits. The validator stops at its first budget failure; independent inspection of all completed raw results also finds the 1000-flow failure.

| Measurement (median of five) | v0.6.1 | v0.7 candidate | Change | Existing maximum |
| --- | ---: | ---: | ---: | ---: |
| idle-peak_rss_kib (KiB) | 4,480.000 | 4,768.000 | +6.4% | 5120 |
| flows-100-peak_rss_kib (KiB) | 6,848.000 | 8,304.000 | +21.3% | 7500 |
| flows-100-cpu_millis (ms) | 10.000 | 20.000 | +100.0% | — |
| flows-1000-peak_rss_kib (KiB) | 23,632.000 | 31,680.000 | +34.1% | 25000 |
| tcp-latency (us) | 41.000 | 41.000 | +0.0% | 55 |
| tun-fd-peak_rss_kib (KiB) | 5,936.000 | 6,416.000 | +8.1% | 8192 |
| tun-fd-cpu_millis (ms) | 130.000 | 320.000 | +146.2% | — |
| tun-fd-latency (us) | 2,375.000 | 2,475.000 | +4.2% | — |
| connection_close (ns) | 1,149.000 | 3,521.000 | +206.4% | 4000 |
| v06-process-throughput (MiB/s) | 495.252 | 529.116 | +6.8% | — |
| v06-vless-encryption-throughput (MiB/s) | 286.264 | 278.796 | -2.6% | — |
| v06-ip-on-demand-latency (ms) | 0.216 | 0.214 | -1.0% | — |
| v06-xhttp-memory (MiB) | 19.109 | 19.922 | +4.3% | — |

Full sample ranges, every original gate metric and original artifact hashes: [original-summary.json](data/original-summary.json). The connection-close probe remains under its 4000 ns budget despite a roughly threefold slowdown. TUN CPU time rose from 130 to 320 ms on the unchanged echo workload; its latency changed much less. These findings require investigation, not relaxed limits. The 100-flow CPU median changed from 10 to 20 ms, a single timing-quantization step; this short sample alone does not establish a doubled sustained CPU cost.

## Completed matrices

| Suite | Cases | Scheduled runs | Failed runs | Evidence |
| --- | ---: | ---: | ---: | --- |
| legacy | 37 | 370 | 0 | [manifest](data/legacy-manifest.json), [summary](data/legacy-summary.json) |
| tun | 30 | 300 | 0 | [manifest](data/tun-manifest.json), [summary](data/tun-summary.json) |
| new | 40 | 200 | 17 | [manifest](data/new-manifest.json), [summary](data/new-summary.json) |
| reality | 12 | 120 | 1 | [manifest](data/reality-manifest.json), [summary](data/reality-summary.json) |

### Main observations

- Hysteria2 passed all 100 clean measured runs. WireGuard passed 83/100: SOCKS upload/eight flows and full-duplex/eight flows completed 0/5 each; TUN upload/eight flows completed 2/5, and TUN full-duplex/eight flows completed 1/5. All 17 failed runs exceeded the unchanged 120-second driver limit. The other WireGuard groups passed.
- All 300 paired TUN runs completed. The four screened cases are VLESS/TLS single-flow upload/full-duplex CPU and XHTTP H1 single-flow download/full-duplex throughput. The H1 short full-duplex medians are about 41.66 → 7.33 MiB/s; all five candidate samples show the slowdown. The larger-volume diagnostic confirmed the drop: 57.58 → 8.73 MiB/s, about 85% lower.
- The additional REALITY/Vision matrix completed 119/120 runs: candidate SOCKS full-duplex/eight flows, repeat one, returned early EOF before the completion marker. The group receives no passing median; an independent five-pair repeat completed successfully. No completed REALITY group crossed the 15% screen.
- Clean Freedom TUN full-duplex comparisons did not reproduce the preliminary slowdown; its median throughput ratios were about 1.00× and 1.02× for one/eight flows. Neither XHTTP H2 nor H3 TUN crossed the screening threshold.
- The historical transport matrix completed all 370 paired measured runs, with no failed run and no case crossing the 15% screen. This is bounded evidence for the listed workloads, not a general proof of no regression.

Legacy uses the original per-version harness: REALITY/Vision bulk plus WebSocket, HTTPUpgrade, gRPC and XHTTP H1/H2/H3. TUN adds Freedom, VLESS/TLS and XHTTP through a common fd-backed driver. The additional REALITY/Vision matrix covers SOCKS and TUN, one/eight flows, upload/download/full-duplex. New protocols cover Hysteria2/WireGuard, SOCKS/TUN, one/eight flows, all three bulk directions, TCP echo latency and UDP echo.

## Hysteria2 and WireGuard

Throughput counts validated application bytes in both directions. UDP is request/reply with one outstanding packet per flow, not a maximum one-way packet-rate measurement. TCP latency under TUN uses the historical sequential driver (`concurrent_flows: 1`); bulk TCP and UDP are concurrent. All new-protocol results below are candidate measurements: v0.6.1 has neither protocol.

| Case | MiB/s median [min–max] | Echo median (µs) | RSS median (MiB) | CPU median (ms/MiB) |
| --- | ---: | ---: | ---: | ---: |
| hysteria2-socks-upload-1 | 119.68 [118.01–134.24] | — | 24.72 | 7.50 |
| hysteria2-socks-download-1 | 266.16 [262.39–269.37] | — | 8.75 | 8.75 |
| hysteria2-socks-full-duplex-1 | 237.73 [230.60–304.97] | — | 21.47 | 6.09 |
| hysteria2-socks-tcp-latency-1 | 16.06 [15.68–16.79] | 89 | 8.17 | 35.84 |
| hysteria2-socks-udp-1 | 14.18 [14.02–14.75] | 125 | 8.52 | 26.21 |
| hysteria2-socks-upload-8 | 221.92 [213.50–226.09] | — | 41.89 | 7.19 |
| hysteria2-socks-download-8 | 286.99 [282.52–288.38] | — | 10.41 | 11.52 |
| hysteria2-socks-full-duplex-8 | 353.59 [343.08–356.27] | — | 41.55 | 5.70 |
| hysteria2-socks-tcp-latency-8 | 61.28 [60.20–61.71] | 223 | 9.14 | 42.88 |
| hysteria2-socks-udp-8 | 56.30 [55.83–56.63] | 287 | 9.52 | 28.40 |
| hysteria2-tun-upload-1 | 98.73 [58.90–103.87] | — | 13.64 | 20.00 |
| hysteria2-tun-download-1 | 131.18 [128.10–170.12] | — | 9.97 | 25.00 |
| hysteria2-tun-full-duplex-1 | 170.95 [147.47–198.60] | — | 19.31 | 15.00 |
| hysteria2-tun-tcp-latency-1 | 0.75 [0.74–0.76] | 2099 | 8.86 | 230.40 |
| hysteria2-tun-udp-1 | 15.40 [15.05–16.29] | 111 | 8.62 | 26.21 |
| hysteria2-tun-upload-8 | 147.37 [116.37–155.95] | — | 69.97 | 11.25 |
| hysteria2-tun-download-8 | 246.30 [232.72–272.67] | — | 12.81 | 15.94 |
| hysteria2-tun-full-duplex-8 | 248.64 [245.82–269.15] | — | 66.61 | 10.62 |
| hysteria2-tun-tcp-latency-8 | 0.74 [0.74–0.75] | 2131 | 9.11 | 218.88 |
| hysteria2-tun-udp-8 | 58.48 [57.98–60.30] | 269 | 9.55 | 28.40 |
| wireguard-socks-upload-1 | 129.93 [126.62–131.22] | — | 6.98 | 13.12 |
| wireguard-socks-download-1 | 108.02 [107.13–109.79] | — | 6.80 | 16.25 |
| wireguard-socks-full-duplex-1 | 156.27 [155.57–157.72] | — | 7.28 | 12.66 |
| wireguard-socks-tcp-latency-1 | 14.15 [14.08–14.41] | 102 | 6.52 | 40.96 |
| wireguard-socks-udp-1 | 14.13 [13.95–14.72] | 123 | 6.81 | 26.21 |
| wireguard-socks-upload-8 | **INCOMPLETE: 0/5 passed** | — | — | — |
| wireguard-socks-download-8 | 166.45 [163.95–168.20] | — | 8.09 | 18.01 |
| wireguard-socks-full-duplex-8 | **INCOMPLETE: 0/5 passed** | — | — | — |
| wireguard-socks-tcp-latency-8 | 66.72 [63.69–68.81] | 210 | 7.34 | 26.88 |
| wireguard-socks-udp-8 | 62.45 [62.11–62.87] | 259 | 7.84 | 20.21 |
| wireguard-tun-upload-1 | 75.88 [72.79–108.02] | — | 14.09 | 25.00 |
| wireguard-tun-download-1 | 67.23 [63.67–70.65] | — | 7.67 | 30.00 |
| wireguard-tun-full-duplex-1 | 107.50 [105.10–111.80] | — | 15.41 | 22.50 |
| wireguard-tun-tcp-latency-1 | 0.76 [0.75–0.77] | 2072 | 7.25 | 240.64 |
| wireguard-tun-udp-1 | 16.46 [15.25–16.92] | 104 | 6.92 | 21.85 |
| wireguard-tun-upload-8 | **INCOMPLETE: 2/5 passed** | — | — | — |
| wireguard-tun-download-8 | 142.24 [138.53–147.01] | — | 9.89 | 24.69 |
| wireguard-tun-full-duplex-8 | **INCOMPLETE: 1/5 passed** | — | — | — |
| wireguard-tun-tcp-latency-8 | 0.76 [0.75–0.76] | 2092 | 7.45 | 238.08 |
| wireguard-tun-udp-8 | 68.98 [67.84–71.17] | 229 | 7.86 | 19.11 |

## Comparisons requiring review

The predeclared screening threshold is >15% throughput loss or >15% latency/CPU/RSS growth. This screen is not itself proof of regression. Short CPU measurements have 10 ms quantization and RSS samples are discrete; raw ranges and repeatability matter. Failed groups receive no passing median.

| Suite / case | Threshold crossings (candidate/baseline median) |
| --- | --- |
| tun / vless-tls-tun-upload-1 | cpu_ms_per_mib: 1.200× |
| tun / vless-tls-tun-full-duplex-1 | cpu_ms_per_mib: 1.167× |
| tun / xhttp-h1-tun-download-1 | throughput_mib_s: 0.830× |
| tun / xhttp-h1-tun-full-duplex-1 | throughput_mib_s: 0.176× |

## WireGuard client isolation control

The same generic SOCKS driver, 32 MiB per flow/direction, eight flows and fresh pinned server were repeated five times with the pinned Go Xray-core client (`noKernelTun: true`). This isolates the Rust-client path without changing the traffic generator or server. It does not identify the defective function or prove all reference behavior correct.

| Case | Go client completed | MiB/s median [min–max] |
| --- | ---: | ---: |
| wireguard-socks-upload-8 | 5/5 | 91.37 [20.59–97.99] |
| wireguard-socks-full-duplex-8 | 5/5 | 133.06 [121.02–139.74] |

[Control manifest](data/wireguard-control-manifest.json), [all control measurements](data/wireguard-control-summary.json).


## Diagnostic repeat: h1-download-diagnostic-clean

4096 iterations per flow; five paired repeats. This supplements the original group; it does not replace it. [Manifest](data/h1-download-diagnostic-clean-manifest.json), [summary](data/h1-download-diagnostic-clean-summary.json).

| Case / metric | Baseline median [min–max] | Candidate median [min–max] | Candidate/baseline |
| --- | ---: | ---: | ---: |
| xhttp-h1-tun-download-1 / throughput_mib_s | 534.09 [526.72–554.99] | 530.66 [521.13–549.34] | 0.994× |
| xhttp-h1-tun-download-1 / cpu_ms_per_mib | 2.30 [2.19–2.46] | 2.42 [2.38–2.50] | 1.051× |
| xhttp-h1-tun-download-1 / rss_mib | 9.38 [9.23–9.48] | 10.02 [9.91–10.23] | 1.068× |

## Diagnostic repeat: h1-duplex-diagnostic-clean

512 iterations per flow; five paired repeats. This supplements the original group; it does not replace it. [Manifest](data/h1-duplex-diagnostic-clean-manifest.json), [summary](data/h1-duplex-diagnostic-clean-summary.json).

| Case / metric | Baseline median [min–max] | Candidate median [min–max] | Candidate/baseline |
| --- | ---: | ---: | ---: |
| xhttp-h1-tun-full-duplex-1 / throughput_mib_s | 57.58 [57.22–57.74] | 8.73 [7.75–8.81] | 0.152× |
| xhttp-h1-tun-full-duplex-1 / cpu_ms_per_mib | 2.81 [2.66–2.97] | 2.97 [2.97–2.97] | 1.056× |
| xhttp-h1-tun-full-duplex-1 / rss_mib | 25.59 [24.44–26.73] | 26.28 [23.92–29.53] | 1.027× |

## Diagnostic repeat: reality-duplex-diagnostic-clean

512 iterations per flow; five paired repeats. This supplements the original group; it does not replace it. [Manifest](data/reality-duplex-diagnostic-clean-manifest.json), [summary](data/reality-duplex-diagnostic-clean-summary.json).

| Case / metric | Baseline median [min–max] | Candidate median [min–max] | Candidate/baseline |
| --- | ---: | ---: | ---: |
| reality-vision-socks-full-duplex-8 / throughput_mib_s | 914.68 [535.33–1126.89] | 890.94 [701.87–1138.96] | 0.974× |
| reality-vision-socks-full-duplex-8 / cpu_ms_per_mib | 1.29 [1.25–1.50] | 1.19 [1.13–1.29] | 0.924× |
| reality-vision-socks-full-duplex-8 / rss_mib | 11.08 [11.02–11.30] | 11.86 [11.75–12.14] | 1.071× |

## Diagnostic repeat: vless-duplex-diagnostic-clean

4096 iterations per flow; five paired repeats. This supplements the original group; it does not replace it. [Manifest](data/vless-duplex-diagnostic-clean-manifest.json), [summary](data/vless-duplex-diagnostic-clean-summary.json).

| Case / metric | Baseline median [min–max] | Candidate median [min–max] | Candidate/baseline |
| --- | ---: | ---: | ---: |
| vless-tls-tun-full-duplex-1 / throughput_mib_s | 680.78 [675.43–685.78] | 677.21 [665.16–684.03] | 0.995× |
| vless-tls-tun-full-duplex-1 / cpu_ms_per_mib | 2.09 [2.07–2.15] | 2.23 [2.21–2.30] | 1.065× |
| vless-tls-tun-full-duplex-1 / rss_mib | 9.52 [9.19–11.09] | 9.75 [9.69–11.19] | 1.025× |

## Diagnostic repeat: vless-upload-diagnostic-clean

4096 iterations per flow; five paired repeats. This supplements the original group; it does not replace it. [Manifest](data/vless-upload-diagnostic-clean-manifest.json), [summary](data/vless-upload-diagnostic-clean-summary.json).

| Case / metric | Baseline median [min–max] | Candidate median [min–max] | Candidate/baseline |
| --- | ---: | ---: | ---: |
| vless-tls-tun-upload-1 / throughput_mib_s | 586.62 [542.49–605.09] | 586.25 [560.89–600.06] | 0.999× |
| vless-tls-tun-upload-1 / cpu_ms_per_mib | 2.27 [2.11–2.27] | 2.58 [2.42–2.66] | 1.138× |
| vless-tls-tun-upload-1 / rss_mib | 8.56 [8.50–8.84] | 9.27 [9.06–9.30] | 1.082× |

## Interpretation of the follow-up measurements

- **WireGuard:** the Go client completed 10/10 controls with the same driver, payload, server implementation and fresh-fixture policy. The Rust client completed 0/10 corresponding primary SOCKS upload/full-duplex runs. This supports investigating the Rust-client path and its interaction with the server; it does not by itself locate a faulty function. Rust TUN upload/full-duplex failures remain open as well.
- **XHTTP H1 TUN full-duplex/one flow:** the larger workload confirmed the slowdown in all five pairs. At 32 MiB per direction, median throughput fell from 57.58 to 8.73 MiB/s (candidate/baseline 0.152×, about 85% lower); sample ranges do not overlap. At 4 MiB per direction it was 41.66 → 7.33 MiB/s. This is a repeatable regression in the measured path, not merely a short-window CPU artifact. CPU per MiB changed much less (+5.6% in the larger diagnostic); TUN upload batching and packet-up timing are investigation starting points, not established causes.
- **VLESS/TLS TUN CPU:** at 256 MiB per direction, upload CPU per MiB remained 13.8% higher and full-duplex 6.5% higher. Those increases are below the 15% screening threshold but are retained as measured cost changes; the result does not mean CPU usage is identical. Throughput ratios were 0.999× and 0.995×.
- **XHTTP H1 TUN download/one flow:** increasing the volume from 4 to 256 MiB removed the 17% median throughput loss; the larger-workload ratio was 0.994×, with overlapping sample ranges. The primary short group remains in the report.
- **REALITY/Vision:** an independent repeat of the same eight-flow SOCKS full-duplex case passed all five baseline/candidate pairs. The original early EOF therefore did not reproduce in that repeat. It remains a recorded failure requiring triage; a successful repeat does not turn the original group into a pass.
- **Before RC:** resolve the unchanged 100/1000-flow RSS-budget failures, the repeated WireGuard upload/full-duplex timeouts and the confirmed H1 TUN slowdown. Investigate the old TUN echo CPU/connection-close increases and the isolated REALITY EOF. Repeat the affected cases and original gates on each proposed fix without changing their limits.

## Failed measured runs

| Suite / case / version / repeat | Result |
| --- | --- |
| new / wireguard-socks-upload-8 / candidate / 1 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-upload-8 / candidate / 2 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-upload-8 / candidate / 3 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-upload-8 / candidate / 4 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-upload-8 / candidate / 5 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-full-duplex-8 / candidate / 1 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-full-duplex-8 / candidate / 2 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-full-duplex-8 / candidate / 3 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-full-duplex-8 / candidate / 4 | protocol benchmark exceeded 120 seconds |
| new / wireguard-socks-full-duplex-8 / candidate / 5 | protocol benchmark exceeded 120 seconds |
| new / wireguard-tun-upload-8 / candidate / 2 | protocol benchmark exceeded 120 seconds |
| new / wireguard-tun-upload-8 / candidate / 3 | protocol benchmark exceeded 120 seconds |
| new / wireguard-tun-upload-8 / candidate / 5 | protocol benchmark exceeded 120 seconds |
| new / wireguard-tun-full-duplex-8 / candidate / 1 | protocol benchmark exceeded 120 seconds |
| new / wireguard-tun-full-duplex-8 / candidate / 3 | protocol benchmark exceeded 120 seconds |
| new / wireguard-tun-full-duplex-8 / candidate / 4 | protocol benchmark exceeded 120 seconds |
| new / wireguard-tun-full-duplex-8 / candidate / 5 | protocol benchmark exceeded 120 seconds |
| reality / reality-vision-socks-full-duplex-8 / candidate / 1 | io error while reading stream-transport completion marker: early eof |

## Harness verification and limitations

- Release Clippy for all xray-bench targets passed; 207 release library tests and nine Python evidence/process-lifetime tests passed. Clean smoke controls passed for Hysteria2 TUN upload/eight flows, WireGuard SOCKS upload/one flow, Freedom TUN full-duplex/one flow in both versions, and all 24 paired REALITY scenarios.
- The initial generic driver mistakenly used a fixture handle without a destructor, leaving engine processes alive. Inventory found 669 orphan engines; all campaign processes were stopped. All affected transport/protocol collections carry `quality.json` with `usable_for_performance: false` and are excluded from conclusions. The original release gates ran before the leak. The corrected driver kills/waits on every exit path; the collector checks process groups and engine inventory after every run. Dedicated success/failure/interruption tests cover cleanup.
- Initial smoke runs exposed ENOBUFS handling in the new driver and the Darwin socketpair 2/4 KiB defaults. The driver now retains backpressured frames and requests 1 MiB send/receive queues at both ends, recording accepted sizes. Preliminary default-buffer throughput is excluded from capacity comparisons. Original regression workloads were not modified.
- Generic Hysteria/WireGuard/TUN runs use a fresh reference server and synthetic keys per repeat. Pre-clean protocol findings are invalidated and provide no performance evidence. The extra REALITY suite shares one freshly started server after the original eight-second warmup, with fresh client processes.
- Generic bulk traffic is a validated raw byte pattern, not an inner HTTPS workload; do not interpret its REALITY results as a dedicated TLS zero-copy benchmark. The original REALITY bulk workload is retained separately.
- Engine RSS and CPU exclude driver/server processes. Those processes still share host CPU, and the desktop host was not isolated from other activity. Generic sampling is every 100 ms, with 500 ms pre/post intervals; CPU includes sampled setup and settling work. Driver TCP buffers are 64 KiB per direction/flow, with a bounded output queue.
- Local IPv4 synthetic origins and fd-backed Darwin-utun frames only; no real OS TUN interface or host routes were created. These are not phone, WAN, energy, loss or network-transition results. REALITY may contact its cover destination during setup; application payload remains on this host.
- Open release work: resolve unchanged memory-budget failures, investigate TUN CPU/connection-close changes and every failed or repeatable screened transport regression; rerun affected cases and original gates against any fix.

## Raw evidence

`raw-evidence.tar.gz` retains manifests, requests/configs, raw result JSON/resource samples, logs, preliminary diagnostics, collector snapshots and host/build identity. The [benchmark source patch](benchmark-source.patch) applies to the candidate commit and preserves the measured driver plus the final collector extensions. The archive excludes executable binaries and build caches. Synthetic fixture keys are test-only and local. SHA-256 is recorded in [artifact-hashes.json](artifact-hashes.json). Extract into a directory to inspect raw results; full-suite manifests provide `output_relative` so the summarizer works after relocation. Older preliminary runs retain their original absolute paths.
