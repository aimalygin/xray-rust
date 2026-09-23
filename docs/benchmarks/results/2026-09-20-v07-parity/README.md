# v0.7 protocol efficiency and regression comparisons

**Target: strictly lower client memory; up to 3% lower throughput or higher CPU/latency/startup is acceptable on this Mac; no reliability allowance. Overall status: Not established across all measured cases.**

The 34 comparison groups that use the selected candidate contain 1620 retained client/control runs, 0 candidate failures, 2 total failures, and 5 groups with flagged background build/compiler-related activity in the expanded audit. The report retains 195 original strict external-comparison point differences, of which 33 are outside the requested allowance. A 3.16% loss is outside the 3% limit; displayed rounding never changes acceptance. Functional success and lower memory do not establish complete parity. Every deficit, interval and incomplete comparator remains in [acceptance.json](acceptance.json) and [point-deficits.md](point-deficits.md).

Selected runtime commit: `b9577f874b3f102880ae078038855803d85f5d04`; tree: `1a8d391146eaf898e2b4824c736391fbdccb8f4f`; executable SHA256: `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`. [Build metadata](data/selected-build.json) and [the complete source patch](selected-source.patch) identify the measured code. Vendor documentation and reconstruction patches do not change the executable relative to its focused build. [Integration metadata](data/delivery-runtime-integration.json) verifies that the private delivery runtime tree was identical to the measured tree. A subsequent [analysis-only update](data/delivery-analysis-update.json) changes only the Python comparison checker, its tests and performance documentation to support the user-approved allowance; [its separate patch](analysis-update.patch) is not relabeled as measured runtime code. Both trees are independently reconstructed during delivery verification.

This directory is named for the investigation's start date. Per-run timestamps record actual measurement times. Predecessors and rejected experiments have separate identities and are never pooled into selected-build medians. See [all result pages](results-index.md); the evidence archive retains raw logs, requests, payload validation, process-cleanup audits, diagnostics and failed attempts.

## Reference implementations

| Client | Pinned version / source |
|---|---|
| Xray-core | v26.7.28 / `5ca6f4b7d4dc20a881d4330e498892697627ec0c` |
| Native Hysteria | app/v2.12.2 / `619a6f856b69fb7ee6a7a379e810e68b84004605` |
| sing-box | v1.13.15 / `3708fa18766cda1f11b77f6ed9c7bd61688f17df` |
| Native WireGuard adapter | wireguard-go `v0.0.0-20250521234502-f333402bd9cb`, gVisor `v0.0.0-20260122175437-89a5d21be8f0` |

The native WireGuard comparison is a small SOCKS adapter over these libraries, separate from Xray and sing-box. It is not kernel WireGuard. Frozen executable hashes and Go module/compiler records are in the adjacent `data/reference-*` files. These are comparisons to specific versions, not claims about every subsequent release.

## Local transfer results

Medians of three repeats. The table selects the strongest complete reference separately for throughput and CPU; linked pages retain every client, range and paired interval. Local bulk groups also include the c33 predecessor as a same-run control for the final fixes.

| Workload | Rust MiB/s | Fastest reference MiB/s | Rust CPU ms | Lowest reference CPU ms | Rust RSS MiB | Reference RSS range MiB |
|---|---:|---:|---:|---:|---:|---:|
| [hysteria2-socks-upload-1](reviewed-parity-hysteria2-local-bulk-1.md) | 507.316 | 342.405 (singbox) | 1070.000 | 2170.000 (singbox) | 14.562 | 28.141–33.953 |
| [hysteria2-socks-download-1](reviewed-parity-hysteria2-local-bulk-1.md) | 314.808 | 300.585 (native) | 2090.000 | 2570.000 (singbox) | 8.000 | 28.016–33.812 |
| [hysteria2-socks-full-duplex-1](reviewed-parity-hysteria2-local-bulk-1.md) | 439.634 | 434.956 (singbox) | 2870.000 | 3790.000 (singbox) | 16.812 | 28.562–34.453 |
| [hysteria2-socks-upload-8](reviewed-parity-hysteria2-local-bulk-8.md) | 378.379 | 297.873 (singbox) | 2900.000 | 4900.000 (singbox) | 18.500 | 28.266–35.031 |
| [hysteria2-socks-download-8](reviewed-parity-hysteria2-local-bulk-8.md) | 294.700 | 267.495 (singbox) | 4990.000 | 6170.000 (singbox) | 8.109 | 28.359–34.594 |
| [hysteria2-socks-full-duplex-8](reviewed-parity-hysteria2-local-bulk-8.md) | 353.586 | 321.150 (singbox) | 7600.000 | 10520.000 (singbox) | 18.719 | 28.609–35.594 |
| [wireguard-socks-upload-1](reviewed-parity-wireguard-local-bulk-1.md) | 174.681 | 120.431 (singbox) | 1190.000 | 2020.000 (singbox) | 8.203 | 61.328–105.500 |
| [wireguard-socks-download-1](reviewed-parity-wireguard-local-bulk-1.md) | 183.261 | 162.525 (xray) | 1030.000 | 1410.000 (xray) | 6.625 | 47.688–79.172 |
| [wireguard-socks-full-duplex-1](reviewed-parity-wireguard-local-bulk-1.md) | 187.284 | 170.707 (singbox) | 2160.000 | 2760.000 (singbox) | 8.703 | 73.156–117.172 |
| [wireguard-socks-upload-8](reviewed-parity-wireguard-local-bulk-8.md) | 168.335 | 168.506 (singbox) | 5000.000 | 5870.000 (singbox) | 18.828 | 107.094–160.594 |
| [wireguard-socks-download-8](reviewed-parity-wireguard-local-bulk-8.md) | 188.632 | 179.675 (native) | 4610.000 | 5180.000 (native) | 8.125 | 106.578–205.516 |
| [wireguard-socks-full-duplex-8](reviewed-parity-wireguard-local-bulk-8.md) | 215.049 | 195.744 (singbox) | 8500.000 | 10000.000 (singbox) | 20.797 | 138.547–213.281 |

## Shaped WAN transfer results

The controlled relay adds 25 ms in each direction and limits outer UDP payload to 100 Mbit/s per direction. It does not charge outer IP headers. The common Xray server, workload and relay remain identical between clients. The 32 MiB relay queues model a buffered link; this is not a real Internet route.

| Workload | Rust MiB/s | Fastest reference MiB/s | Rust CPU ms | Lowest reference CPU ms | Rust RSS MiB | Reference RSS range MiB |
|---|---:|---:|---:|---:|---:|---:|
| [hysteria2-socks-upload-1](reviewed-parity-hysteria2-wan-bulk-1.md) | 11.195 | 11.177 (singbox) | 640.000 | 1030.000 (singbox) | 16.797 | 29.359–36.500 |
| [hysteria2-socks-download-1](reviewed-parity-hysteria2-wan-bulk-1.md) | 11.278 | 11.276 (native) | 1110.000 | 1470.000 (singbox) | 7.828 | 27.891–33.562 |
| [hysteria2-socks-full-duplex-1](reviewed-parity-hysteria2-wan-bulk-1.md) | 20.673 | 21.347 (xray) | 1380.000 | 2330.000 (singbox) | 17.469 | 30.062–37.625 |
| [hysteria2-socks-upload-8](reviewed-parity-hysteria2-wan-bulk-8.md) | 11.179 | 11.167 (singbox) | 1650.000 | 1970.000 (singbox) | 16.828 | 30.672–38.062 |
| [hysteria2-socks-download-8](reviewed-parity-hysteria2-wan-bulk-8.md) | 11.205 | 11.228 (native) | 2520.000 | 3780.000 (xray) | 8.125 | 26.938–33.500 |
| [hysteria2-socks-full-duplex-8](reviewed-parity-hysteria2-wan-bulk-8.md) | 20.789 | 21.334 (native) | 3410.000 | 4840.000 (singbox) | 18.453 | 30.094–38.719 |
| [wireguard-socks-upload-1](reviewed-parity-wireguard-wan-bulk-1.md) | 10.567 | 10.658 (singbox) | 1300.000 | 2750.000 (singbox) | 8.344 | 24.156–48.297 |
| [wireguard-socks-download-1](reviewed-parity-wireguard-wan-bulk-1.md) | 10.648 | 10.649 (native) | 1840.000 | 2580.000 (singbox) | 6.219 | 17.156–36.438 |
| [wireguard-socks-full-duplex-1](reviewed-parity-wireguard-wan-bulk-1.md) | 18.228 | 16.072 (singbox) | 2420.000 | 4730.000 (singbox) | 8.531 | 54.625–87.438 |
| [wireguard-socks-upload-8](reviewed-parity-wireguard-wan-bulk-8.md) | 11.067 | 10.845 (xray) | 2890.000 | 4520.000 (singbox) | 18.828 | 53.641–97.078 |
| [wireguard-socks-download-8](reviewed-parity-wireguard-wan-bulk-8.md) | 11.015 | 11.016 (native) | 4760.000 | 6020.000 (singbox) | 6.969 | 17.328–38.906 |
| [wireguard-socks-full-duplex-8](reviewed-parity-wireguard-wan-bulk-8.md) | 20.943 | 15.552 (xray) | 4980.000 | 8220.000 (singbox) | 19.125 | 81.906–156.812 |

The [short zero-CID control](zero-cid-wan-bulk-1.md) and [512 MiB control](zero-cid-wan-sustained-1.md) separate startup-sensitive duplex results from sustained behavior. Both retain all five clients. A longer transfer does not erase a short-transfer deficit. The separate final eight-flow sustained group exercises repeated BBR ProbeRTT cycles.

## Host activity and remaining measured gaps

The original observer covered Rust/Go/C/C++/Swift compiler processes. A later audit of its retained snapshots also found `xcodebuild` and `ANECompilerService` activity in these groups: reviewed-parity-hysteria2-wan-echo, reviewed-parity-regression-new-tun, reviewed-parity-regression-quiet-confirmation-legacy, reviewed-parity-regression-steady-confirmation-tun, reviewed-parity-wireguard-long-echo. The former is a build controller; the latter compiles neural models. Their presence is a potential confound, not proof of a particular project build or the cause of a speed change. Other application/system CPU activity was also visible during the first long WireGuard echo confirmation. Those groups are flagged as exploratory, with all raw values retained. See [the expanded audit](data/ambient-evidence-audit.json) and the separate [fresh WireGuard echo confirmation](reviewed-parity-wireguard-long-echo-ambient-confirmation.md). No user processes were stopped or system scheduling settings changed.

The following core-metric deficits have a paired bootstrap interval wholly beyond the requested 3% performance allowance (or the unchanged memory target). They are priorities for further investigation, not universal bounds: three-repeat series have limited statistical power. Short and long follow-up controls remain separate workloads, and one does not cancel the other. Startup and every other point deficit remain in the complete appendix.

| Workload | Comparator | Metric | Candidate / reference | Paired 95% interval |
|---|---|---|---:|---|
| [hysteria2-socks-tcp-latency-8](reviewed-parity-hysteria2-local-echo.md) | native | latency_p99_us | 1.04435 | [1.04234, 1.11879] |

The fresh 80-run WireGuard echo confirmation completed every trial with no sampled compiler flag. All external-comparison medians meet the 3% performance allowance and strictly lower RSS requirement. Six metric intervals still cross their acceptance boundary, so its overall statistical status is `unproven`. The older confounded echo group remains separate.

For Hysteria, the original one-flow shaped-WAN duplex median is 20.673 versus Xray’s 21.347 MiB/s, a 3.159% decrease, slightly outside the allowance; its paired ratio interval [0.878244, 0.997049] leaves the size of that gap uncertain. The sustained eight-flow comparison is within the allowance: 21.464 versus native’s 21.877 MiB/s (1.886% lower), with 17.625 versus 31.453 MiB RSS and 12,560 versus 18,160 ms CPU. Tail latency remains workload-sensitive: primary local TCP8 p99 is 518 versus native’s 496 µs, while the separate longer TCP8 control has p99 339 versus native’s 408 µs but p95 241 versus sing-box’s 233 µs (3.433% higher). These are distinct workloads, not a single pooled pass.

## Changes and causal evidence

- WireGuard reuses the prefix of a drained TCP receive ring only when both the readable queue and out-of-order assembler are empty. It preserves capacity, sequence state and advertised credit. Two tests cover repeated small exchanges, partial reads, holes and reassembly; an unsafe queue-only mutation corrupts payload and fails. The focused five-repeat TCP8 comparison reduced RSS from 14.484 to 6.688 MiB while throughput changed from 78.266 to 79.033 MiB/s. Native WireGuard used 14.719 MiB at 65.219 MiB/s in that same control. See [the focused results](wg-rx-reuse-long-tcp-8.md). Large-transfer behavior is measured separately above.
- QUIC sends a ready standalone, unpadded 1-RTT ACK even when queued stream data is blocked by congestion control or pacing. Two deterministic tests fail before the correction and pass afterward; data and padded packets remain controlled. The [WAN control](quic-ack-wan-duplex-1.md) did not demonstrate a speed gain, so this is a correctness fix rather than a claimed throughput optimization.
- A dedicated Hysteria endpoint uses an empty local connection ID, saving eight bytes per server packet. There is exactly one connection per endpoint and a stable server address. The real Initial-packet test, socket protection tests and native/Xray blackholed-path tests verify TCP/UDP recovery on local rebinding. Generic XHTTP H3 retains its previous endpoint policy. The short paired download control measured 11.277 versus 11.214 MiB/s for the preceding build; full results and duplex variation remain linked above.
- The CLI defaults to two Tokio workers while preserving `TOKIO_WORKER_THREADS`; its predecessor used Tokio's available-core default. The unchanged FFI policy remains 2–6 workers. Same-binary worker controls are reported separately, so improvements from scheduling are not all attributed to protocol algorithms.
- TUN bounds the additional upload queue to eight messages and upload batches to 64 KiB only for Hysteria/WireGuard, whose packet transports already have their own send windows. The shared TCP bridge also polls download and cancellation while an upload batch is pending, returns to selection after each bounded batch, and arms a capacity wakeup after backpressure. The legacy TCP path shares these bridge/wakeup changes; it is not unchanged code. An earlier directory-only inspection missed `tun.rs`, so regression conclusions rely on the actual full-file diff, tests and retained measurements. The local TUN socket explicitly retains its no-congestion-control policy when WireGuard enables Internet TCP features in smoltcp.
- Existing WireGuard fixes provide bounded TCP bursts, round-robin fairness, shared active-flow budgets, byte-counting Reno, protected carrier handling and cancellation without lost wakeups. Physical per-flow backing remains 1 MiB RX plus 1 MiB TX. Shared active budgets are not an absolute aggregate memory ceiling: queued data and previously advertised credit must be preserved.
- Existing QUIC fixes account encrypted ack-eliciting packet bytes once, retain bounded send-time delivery snapshots, use fresh RTT measurements, preserve bandwidth through deliberately sparse ProbeRTT, and apply BBR's pacing rate. They do not disable congestion control, loss recovery or periodic probing. The report does not claim that every old GSO packet was double-counted or that the four-millisecond pacing credit independently improved speed.
- XHTTP H3 combines only immediately ready response chunks, bounded to 16 KiB / 16 chunks and a one-slot response queue. This addressed the large receive-allocation regression. It never waits for future data to fill a batch. Prefix delivery, trailers, partial reads and cancellation are tested. Historical H3 RSS differences versus 0.6.1 remain in the regression pages.

The separate completed-round ProbeRTT variant was also rejected for this delivery. It remembers a round completed before the 200 ms deadline, matching the state-machine condition in native Hysteria and [Linux BBR](https://raw.githubusercontent.com/torvalds/linux/master/net/ipv4/tcp_bbr.c). Two behavioral tests fail before the change, 300 release protocol tests pass afterward, and deleting the per-probe reset fails the next-probe test. However, its [three-repeat sustained control](probe-round-long-duplex-8.md) measured 21.446 versus 21.642 MiB/s for b957, with workload CPU 12,590 versus 12,430 ms. The speed ratio interval [0.956655, 1.010494] does not establish an improvement, and native/Xray remain faster. The experimental source patch and tests are retained, but this variant is not part of the selected executable. [The delivery decision](data/delivery-runtime-decision.json) keeps that distinction explicit.

The one-percent BBR pacing-margin experiment was rejected: its paired duplex median was 20.053 versus 20.219 MiB/s for the preceding build. Larger H3 receive batches and adaptive H3 send windows were also rejected when their controls failed to show a useful tradeoff. Instrumented Rust/native BBR and direction traces are diagnostic evidence only, excluded from performance medians. Both implementations developed loaded queues; these traces do not support blaming queueing solely on Rust. No observed peer DATA_BLOCKED/STREAM_DATA_BLOCKED frames justified increasing receive windows in the tested Hysteria traces.

## Regression and correctness checks

The allowance update passed all 43 Python script tests, including threshold boundaries, strict memory, failed trials, interference and uncertainty. All 20 final runtime validation groups passed, including transport/core/benchmark libraries, TUN data paths, WireGuard native/Xray interoperability, rekey/restart/network-change cases, Hysteria native/Xray transport/core/outbound tests, XHTTP transports, Clippy, formatting and benchmark-checker tests. Commands, environments and return codes are in [reviewed-tests.json](data/reviewed-tests.json). Test logs remain in the evidence archive; overlapping test invocations are not added into a misleading unique-test count.

The validation driver's final clean-tree check stopped on an untracked `vendor/gotatun/Cargo.lock` generated by its standalone test. All 20 test commands had passed. The lockfile was retained separately with its hash, removed from the source checkout, and the unchanged tracked tree was verified again. The original stop is retained in the log; [cleanup provenance](data/reviewed-validation-cleanup.json) records the resolution.

The final vendor check downloaded checksum-pinned published archives, reconstructed local changes with zero fuzz, compared exact sources, and ran their protocol suites in isolated directories. Both original v0.5 and v0.6 benchmark gates passed under their unchanged rules; these historical rules do not relax the external-parity target. See [the build and gate record](data/reviewed-build-and-gates.json).

The first remaining-control driver collected all 233 scheduled client/control runs and both collection phases returned success, but its final quality gate rejected the steady TUN group after observing background Xcode/neural-model compiler activity. This stop is retained in the archive and `remaining-controls.json` stays incomplete under its original quality rule. The report includes the results as exploratory, not as a passed quality gate. A separate 131-run follow-up repeats long WireGuard echo, H2 download with eight connections, and the four steady TUN cases. Before each run it requires three consecutive one-second samples without listed compiler activity above 10% CPU and with the sum of sampled processes above 10% totaling less than 100% of one CPU. This precondition reduces observed interference; the within-run observer and any remaining quality flags still apply. The first quiet-start driver stopped before a trial after its 180-second precondition timeout; all 34 completed WireGuard trials were retained and the remaining trials were appended after the user chose to continue on this Mac. The original incomplete driver record and timeout observations remain archived. See [resumed collection metadata](data/quiet-resume-controls.json), [original stopped driver](data/quiet-final-controls.json), [H2 results](reviewed-parity-regression-quiet-confirmation-legacy.md), and [TUN results](reviewed-parity-regression-quiet-confirmation-tun.md). No attempts are discarded.

The exact short VLESS/TLS TUN duplex confirmation completed 30/30 runs with medians 578.695 MiB/s for b957, 528.655 for v0.6.1 and 533.027 for the byte-identical 12-worker control. Candidate/baseline's paired interval [0.857595, 1.219877] includes both sides. The severe deficit in the original three-repeat, 4 MiB-per-direction case did not recur as a stable loss; the original slow samples remain recorded. This is not proof of equivalence. The separate [short confirmation](reviewed-parity-regression-vless-short-confirmation.md), [long legacy controls](reviewed-parity-regression-steady-confirmation-legacy.md), and [long TUN controls](reviewed-parity-regression-steady-confirmation-tun.md) retain their own workload sizes and all worker controls.

Every historical-control point regression is retained in [the deficit appendix](point-deficits.md) with a paired interval where measurable; the old 15% review threshold is not used to hide smaller changes. The full legacy, TUN and REALITY groups compare the selected executable with frozen v0.6.1 `ed5258a3a589c2a1f9330142f37c8f3d28a640fa` on the same host. New-protocol TUN controls compare with the earlier fix candidate M `61373052dc8b6784162c81650faa6bd92f0604aa`, not original v0.7. The predecessor worker-count and cold-stress controls are identified separately in the result index. They are not relabeled as measurements of the final executable.

### Later steady regression controls

H2 download with eight connections uses five repeats of 4 GiB per flow; TUN uses three repeats of 512 MiB per flow. These are the separate runs with a quiet-start guard described above. The linked pages retain the byte-identical 12-worker control, all samples and paired intervals. Any within-run background flag still makes its group exploratory; the table does not supersede earlier results.

| Workload | Rust MiB/s | v0.6.1 MiB/s | Rust CPU ms | v0.6.1 CPU ms | Rust RSS MiB | v0.6.1 RSS MiB |
|---|---:|---:|---:|---:|---:|---:|
| [xhttp-h2-download-8](reviewed-parity-regression-quiet-confirmation-legacy.md) | 1944.661 | 1529.455 | 30900.000 | 68080.000 | 24.094 | 35.516 |
| [vless-tls-tun-full-duplex-1](reviewed-parity-regression-quiet-confirmation-tun.md) | 725.435 | 700.681 | 1750.000 | 2100.000 | 9.125 | 9.656 |
| [xhttp-h1-tun-download-1](reviewed-parity-regression-quiet-confirmation-tun.md) | 568.497 | 584.318 | 990.000 | 1030.000 | 9.391 | 9.422 |
| [xhttp-h2-tun-full-duplex-1](reviewed-parity-regression-quiet-confirmation-tun.md) | 718.245 | 688.315 | 2080.000 | 2680.000 | 19.812 | 18.078 |
| [xhttp-h2-tun-upload-8](reviewed-parity-regression-quiet-confirmation-tun.md) | 820.753 | 778.702 | 8030.000 | 11400.000 | 24.875 | 20.781 |

H2 download8 varied materially across the two retained long collections. The first had candidate/baseline medians of 1,685/1,827 MiB/s and 20.688/18.953 MiB RSS; the later five-repeat guarded group has 1,945/1,529 MiB/s and 24.094/35.516 MiB RSS. Baseline RSS in the latter ranges from 16.172 to 43.594 MiB. Its fourth baseline trial also sampled ANECompilerService at up to 19.5% CPU after the quiet-start guard, so the entire latter group stays exploratory. The earlier point regression is therefore not stable across these collections; the later result does not erase it or prove universally lower memory. Both include the byte-identical 12-worker control. Attribution solely to an allocator, dependency or worker policy is not established.

The fresh TUN group has no sampled compiler flag but still records H2 RSS increases: duplex1 uses 19.812 versus 18.078 MiB (+9.59%), and upload8 uses 24.875 versus 20.781 MiB (+19.70%). Throughput and workload CPU improve in those medians. The earlier longer TUN group had lower candidate RSS but was confounded in other trials; neither collection cancels the other. These historical memory signals remain open and receive no 3% allowance. H1 TUN download is 568.497 versus 584.318 MiB/s (2.708% lower), within the requested performance allowance.

## Measurement boundaries

- Host: Apple M3 Pro, 12 CPU cores, 18 GiB, macOS 26.6.2 (25G83); Rust 1.96 and Go 1.26.5. External protocol CLI comparisons use two Rust workers and GOMAXPROCS=2. Historical v0.6.1 and M executables retain their stock Tokio worker policy (available cores), while the selected CLI defaults to two; their comparisons include that deliberate runtime-policy change. The byte-identical 12-worker controls separate this effect in the short and steady regression follow-ups. Predecessor controls also measure Rust=2/Go=6, Rust=2/stock Go and Rust=6/Go=6 separately. FFI's existing 2–6-worker policy is unchanged; these are not device measurements.
- RSS is the actual client process, sampled every 100 ms, expressed as KiB/1024. It excludes server, driver and kernel buffers. Requested socket buffer sizes are not measured kernel allocation; [socket-budget provenance](data/reference-socket-budgets.json) records that distinction.
- CPU is client CPU time for the same payload volume. The workload counter spans sampling before and after the workload, including its settling intervals and any flow setup inside the workload; throughput can start later at the ready marker. Startup and lifetime counters are retained separately. Zero 10 ms CPU ticks cannot establish equality. Startup includes readiness polling, a verified echo and EOF handling, including about one second of fixed protocol checking; it is not pure process launch time.
- Payloads are validated. Any deliberate relay drop, relay error or surviving owned process invalidates a run. Kernel UDP drops are not directly counted. The same server/fixtures and MTU/TLS policy are used for each client. UDP echo uses 1,200-byte messages with one outstanding request per association; it is not maximum-PPS or saturated UDP throughput. Primary WAN echo uses 30 exchanges per flow per repeat: a one-flow p99 is close to the largest observed sample and cannot establish a stable rare-event tail. Local primary echo uses 1,000 exchanges; the separate local confirmation groups use 5,000.
- Timed groups run serially without our builds, tests, profiling or compression. Process samples observe an explicit compiler set at a stated threshold; the supplemental audit also covers Xcode build-controller and neural-model compiler activity. Flagged groups remain exploratory, and unflagged samples do not prove a completely idle host. Three-repeat groups have limited statistical power; small point differences can remain unresolved. The checker retains paired bootstrap intervals and every deficit under the explicit 3% performance allowance requested for this Mac. The default checker remains strict unless `--max-regression-pct 3` is supplied, and `--output` can keep the derived summary separate. The allowance never waives memory, failed trials, environmental quality or uncertainty.
- Reference failures remain failures. In the predecessor long Hysteria echo control, native completed 16/20 and Xray 19/20 while candidate and sing-box completed 20/20. Incomplete client/workload aggregates are withheld. These observations do not identify a particular packet-loss location. Final-build failures, if any, are listed separately in its own pages.
- TUN workloads exercise the engine through a supplied datagram socketpair and Darwin TUN framing. They measure the engine TUN path, not a routed system utun interface or an iOS NetworkExtension end-to-end path. External client comparisons use the common SOCKS path.
- No claim is made about iOS device RSS/battery use, real WAN loss/reordering beyond the tests, kernel WireGuard, arbitrary high-bandwidth-delay paths or cross-traffic fairness. The measured advantages do not establish the requested target outside this scope.

## Reproduce a comparison

Build the named pinned reference versions first, using the retained compiler/module records. The repository preparation script only creates launchers for explicitly supplied binaries; it does not download or modify the references. Use a fresh output directory for each group and keep builds, profiling and other benchmarks stopped during collection.

```sh
cargo build --locked --release -p xray-cli -p xray-bench
python3 scripts/prepare-v07-protocol-parity.py \
  --root /tmp/v07-parity \
  --rust "$PWD/target/release/xray-rust" \
  --harness "$PWD/target/release/xray-bench" \
  --xray /path/to/pinned-xray \
  --singbox /path/to/pinned-sing-box \
  --hysteria /path/to/pinned-hysteria \
  --wireguard /path/to/pinned-wireguard-adapter
python3 scripts/run-v07-protocol-parity.py \
  --root /tmp/v07-parity --output /tmp/v07-parity/wan-hysteria \
  --protocol hysteria2 --traffic full-duplex --connections 8 \
  --one-way-ms 25 --rate-mbps 100 --bulk-mib 16 --repeats 5 \
  --reference-go-workers 2
python3 scripts/summarize-v07-protocol-parity.py /tmp/v07-parity/wan-hysteria --max-regression-pct 3 --output /tmp/v07-parity/wan-hysteria/summary-mac-3pct.json
```

Repeat with `--protocol wireguard` and a new output path. Upload, download, TCP echo and UDP echo have separate `--traffic` values. The archived final sequence records all actual group sizes, repetitions, controls and process-sampling wrappers used for this report; the example above is a single reproducible group.
