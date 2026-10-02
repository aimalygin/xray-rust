# Bounded VMess writes and Apple padding CSPRNG — Apple M3 Pro

Combining two full VMess records per send with Apple’s system padding CSPRNG reduces upload CPU in repeated ordinary-release controls. The write buffer remains bounded at 16 KiB and grows to that size only when a caller supplies two full records. Short transfers retain the single-record allocation. The extra retained RSS after large transfers is measured below; this is not a zero-memory-cost optimization.

## Identity and method

Baseline runtime `1804e17890baf4c3a587fbd86d6a17a0787ce9dd`; candidate runtime `f930d10dba9831315cc16a709576f521a322dea5`, tree `1b28a8b420c0adf7363e43137502932bf1945876`. Candidate release SHA-256 `1d518f043d68e901918211e265c0f9c057862ba3e04961e1a8e989ea63289436`. The committed release rebuild is byte-identical to the frozen measured candidate. All binaries use normal release optimization and stock workers.

Xray-core v26.7.28 and sing-box 1.13.20 retain the pinned executables and common harness from the preceding reports. Exact commits, hashes, build flags and compiler versions are in [inputs](data/inputs.json) and [builds](data/builds.json). This is desktop SOCKS loopback on M3 Pro/macOS 26.6.2, with a common fresh Xray fixture. Each bulk flow verifies 256 MiB per direction, with one or eight flows. Variant/client order rotates between repeated fresh processes.

All 214 accepted paired normal-release trials, 24 held-memory clients, 270 fresh three-client VMess trials and 12 separate diagnostic trials pass. Timing campaigns do not overlap local compilation or diagnostic instrumentation. Two initial short-transfer memory campaigns were interrupted by observed `ANECompilerService` activity and are excluded in full. Their completed/partial measurements and failure logs remain archived; the replacement campaign ran after a quiet interval. The whole-case reference collector retains any rejected attempts and its selection decisions.

## What changed

- On Apple targets only, AES public body padding calls `arc4random_buf`, the system CSPRNG also used by the pinned Go runtime. Empty requests are skipped for older Apple OS compatibility. Session keys, IVs, request authentication, nonce allocation and header randomness retain the existing path. Non-Apple AES padding and the measured ChaCha entropy cache are unchanged. No application RNG state or new buffer is added per connection for this change.
- TCP writes accept at most two full records from the caller’s available data. The ciphertext shares one bounded allocation and is sent together; each record keeps its own nonce, masked/authenticated length and AEAD tag. Plaintext is encrypted in place after reserving the complete bound. A short request progresses immediately. Partial socket writes resume without accepting more plaintext or duplicating bytes. Any encoding failure clears pending data and poisons the stream. UDP remains one datagram per write.
- The earlier two-record receive limit remains unchanged. Maximum individual wire-record size remains 8 KiB; pending TCP ciphertext may now retain 16 KiB after bulk writes.

## Paired upload confirmation

Medians of five independent repeats, after the exploratory three-repeat campaigns. CPU is process time for the verified workload, not instantaneous CPU utilization. All samples and ranges, including conflicting exploratory points, are in [control summaries](data/control-summary.json).

| Cipher / flows | Baseline CPU ms | Candidate CPU ms | CPU change | Baseline MiB/s | Candidate MiB/s | Speed change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| aes128 / 1 | 250 | 160 | -36.0% | 1369.2 | 1965.4 | +43.5% |
| aes128 / 8 | 1430 | 1200 | -16.1% | 2847.6 | 3202.9 | +12.5% |
| chacha20 / 1 | 270 | 240 | -11.1% | 758.0 | 791.6 | +4.4% |
| chacha20 / 8 | 2120 | 1870 | -11.8% | 1918.5 | 2163.0 | +12.7% |

The standalone Apple padding change is not a stable eight-flow optimization: its first campaign improves AES upload CPU from 1,340 to 1,210 ms and speed from 3,026.8 to 3,253.3 MiB/s, but the subsequent three-way campaign regresses to 1,470 ms / 2,286.4 MiB/s versus the simultaneous baseline’s 1,350 ms / 3,027.9 MiB/s. Both sets are retained. Only the combined implementation is selected, based on its repeated controls; fewer entropy calls alone do not establish a speed benefit.

The three-way combined AES campaign improves one-flow full-duplex CPU 400 → 330 ms and throughput 1,649.0 → 2,015.6 MiB/s; eight-flow full-duplex improves CPU 2,870 → 2,640 ms, with a smaller speed gain. Download medians are near the baseline. ChaCha has no padding-source change; its separate controls isolate the bounded write batching effect, with lower upload/full-duplex CPU and little download change. These small desktop series do not promise the same percentage across hosts or workloads.

## Short-request controls

Three fresh paired repeats cover TCP request/response and UDP at one/eight flows for both ciphers. This checks short-message effects separately from bulk transfer. CPU snapshots have 10 ms granularity; very short runs should not be interpreted as precise zero-cost results. All median/p95/p99 samples are retained in the control data.

| Cipher / traffic / flows | Baseline p95 µs | Candidate p95 µs | Change | Baseline CPU ms | Candidate CPU ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| aes128 / tcp-latency-1 | 219 | 235 | +7.3% | 40 | 40 |
| aes128 / tcp-latency-8 | 317 | 302 | -4.7% | 200 | 190 |
| aes128 / udp-1 | 319 | 319 | +0.0% | 40 | 40 |
| aes128 / udp-8 | 384 | 398 | +3.6% | 200 | 190 |
| chacha20 / tcp-latency-1 | 232 | 237 | +2.2% | 40 | 40 |
| chacha20 / tcp-latency-8 | 337 | 288 | -14.5% | 200 | 200 |
| chacha20 / udp-1 | 328 | 346 | +5.5% | 40 | 40 |
| chacha20 / udp-8 | 399 | 362 | -9.3% | 200 | 200 |

Typical latency medians differ by only 0–2 µs. P95 changes are mixed (−14.5% to +7.3%) and the three-repeat ranges overlap in every case. The worse point estimates remain visible; no general latency improvement or strict latency non-regression is claimed.

## Retained memory at 512 connections

Each fresh client holds 0/32/128/512 payload-verified connections. Every connection exchanges the stated payload in each direction before five settled RSS samples. Medians below cover three rotating repeats; all sizes, sample times and ranges are archived.

| Cipher | Exchange per direction | Baseline RSS MiB | Candidate RSS MiB | Difference MiB | Difference |
| --- | --- | ---: | ---: | ---: | ---: |
| aes128 | 8 KiB | 27.84 | 27.86 | +0.02 | +0.1% |
| chacha20 | 8 KiB | 27.80 | 27.86 | +0.06 | +0.2% |
| aes128 | 1 MiB | 92.41 | 96.44 | +4.03 | +4.4% |
| chacha20 | 1 MiB | 92.38 | 96.31 | +3.94 | +4.3% |

These deltas are relative to runtime `1804e17`, which already includes the retained two-record receive batch. They are additional to that earlier optimization’s documented memory cost. The 16-record buffering variant rejected in the previous investigation is not reinstated.

## Separate call census

Twelve trials interpose libc calls on the frozen baseline and candidate, for AES upload at one/eight flows and three repeats. Only call/byte counts are used here; every instrumented timing, CPU and RSS value is excluded from performance claims. Calibration and coverage limits are documented in the [preceding census](../2026-10-01-v08-census/README.md). `send` forwards to `sendto`; the table counts only the lower layer to avoid double-counting. These are library entry counts, not a complete kernel syscall trace.

| Flows | Version | Write calls | Mean KiB per call | getentropy calls | arc4random_buf calls |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | baseline | 34,831 | 7.57 | 34,297 | 0 |
| 1 | pair | 18,447 | 14.30 | 4 | 34,278 |
| 8 | baseline | 278,646 | 7.57 | 274,238 | 0 |
| 8 | pair | 147,627 | 14.30 | 33 | 274,282 |

The count changes verify the intended mechanism, while the separate normal-release controls establish the measured CPU/speed effect. This is not evidence that Go has no syscalls, nor an attribution of a fixed CPU percentage to a particular call family.

## Fresh Xray-core / sing-box comparison

All 270 trials cover AES, ChaCha and auto; upload, download, full-duplex, TCP latency and UDP; one/eight flows; three clients and three rotating repeats. The exact point ratios and strict/3% desktop-allowance judgments are in [comparison data](data/summary-mac-3pct.json). Earlier Trojan/SS2022 comparisons remain tied to their own runtime identities; they are not relabeled as measurements of this candidate.

Rust uses lower RSS in **60/60** reference comparisons, and meets **30/36** bulk CPU and **25/36** bulk speed point targets with the explicit 3% desktop allowance. Overall parity is **not_met**; point medians alone do not waive uncertainty or remaining latency/startup deficits.

Fresh AES bulk medians (same candidate; not the paired-control baseline campaign):

| Traffic / flows | Rust CPU ms | Xray CPU ms | sing-box CPU ms | Rust MiB/s | Xray MiB/s | sing-box MiB/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| upload-1 | 170.0 | 160.0 | 190.0 | 1946.0 | 1997.4 | 1776.7 |
| download-1 | 180.0 | 130.0 | 290.0 | 1812.9 | 2113.7 | 1181.9 |
| full-duplex-1 | 330.0 | 270.0 | 420.0 | 2044.1 | 2729.5 | 1812.0 |
| upload-8 | 980.0 | 1890.0 | 1810.0 | 4017.6 | 3004.6 | 2839.3 |
| download-8 | 1180.0 | 2090.0 | 2930.0 | 3245.9 | 2532.8 | 2000.7 |
| full-duplex-8 | 2450.0 | 3210.0 | 3810.0 | 1938.5 | 1821.6 | 1649.7 |

The remaining deficits are workload-specific: consult all cases and intervals in the JSON rather than extrapolating upload improvements to download or declaring universal parity.

## Validation and remaining scope

136 protocol tests, 493 core library tests, formatting, Clippy and ten local Xray/sing-box carrier, TUN/DNS/lifecycle and Xray Mux integration tests pass. Tests cover both ciphers/length encodings, record boundaries within a write pair, partial writes, short allocations, UDP, nonce exhaustion within a pair and authenticated termination. The initial sandboxed core test run could not bind sockets; its failure log and the successful unrestricted rerun are both retained.

Candidate-bound CI and the SDK pin are recorded with exact identities in this report’s data. Physical Apple acceptance remains deferred by the owner and Android hardware is unavailable. Host results do not establish phone energy, WAN or TUN performance, or publication-artifact acceptance. Both PRs remain drafts.

[Full core CI](https://github.com/aimalygin/xray-rust/actions/runs/36953755247) at `f930d10dba9831315cc16a709576f521a322dea5`: **in_progress**. [SDK CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36954326794) at `5d14eb785f9fa2e6893f3daf134623bc6772a175`: **in_progress**. SDK core metadata pins the measured runtime; canonical adapters match it. ABI/version and unprepared artifact locks are unchanged.

## Evidence

[Archive](measurements.tar.gz), [member checksums](evidence-index.json), [independent verification](data/verification-evidence.json). The verifier reconstructs complete matrices, byte counts, case selection, all numeric summaries and libc counts from archived results, and checks the release hash and exact core/SDK CI identities. Generated connection credentials/configurations and executables remain local.
