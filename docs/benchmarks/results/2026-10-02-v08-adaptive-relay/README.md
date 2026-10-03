# Adaptive VMess duplex relay — Apple M3 Pro

The retained change enables independent codec directions for **SOCKS → direct raw-TCP VMess ChaCha**. In ordinary paired controls, one duplex flow is **58–60% faster and uses 10–11% less CPU** than runtime `9198a8f`. An independent longer diagnostic confirms a 14% CPU reduction. Physical-footprint overhead is **0.92–1.11 MiB across 512 ChaCha connections**; record and relay buffer limits are unchanged.

AES keeps the combined relay. Running AES in parallel improved speed but repeatedly cost **7–8% more CPU for the same payload**, beyond identical-binary control variation. Earlier unconditional splitting also hurt eight-flow AES speed. Those variants are archived and rejected. The final build avoids that CPU tax, while retaining the existing single-flow AES speed deficit versus Xray. A small short-request tail tradeoff is explicit: eight-flow ChaCha p95 rises **13–27 µs** relative to the two identical baseline controls. This is a useful CPU/throughput improvement, **not all-metric parity**.

## Implementation and boundaries

Read/write codec state moves into independently owned halves. The combined stream and split halves share one parser/encryptor; pending buffers and partial-write cursors are moved, not copied. Native TCP halves avoid a codec-wide lock. Both copy futures initially run in their parent task. Only after both directions transfer at least 64 KiB in chunks of at least 4 KiB, with recent activity within 100 ms, can upload move into one child task. A per-core semaphore admits at most two such connections across all inbounds. I/O continues locally while admission is unavailable, and single-worker runtimes do not admit parallel work.

After either direction becomes quiet for 100 ms, the entire pinned upload future returns to the parent, including any unfinished `write_all`. Small RPCs keep the connection alive but cannot earn or retain bulk admission. Separate activity clocks avoid a notification for every chunk. Complete writes, including short requests, attempt immediate nonblocking drain; partially accepted bulk input drains on the next poll. Sniffed initial data is flushed before waiting for more inbound data.

The relay aborts/joins children on error, explicit close or idle timeout; normal half-close lets the peer direction finish. Stronger live interop exposed an existing shutdown race: `Core.stop()` aborted inbound owners before their child cleanup. Stop now signals and awaits owners, then waits for admitted relay leases to drain, so it cannot return while those I/O owners remain active.

No cipher/authentication/nonce/padding or plaintext erasure is weakened. Write batching stays at two 8 KiB records within 16 KiB pending storage; output batching stays at four records below a 32 KiB byte budget; 16 KiB read-ahead still begins only after 64 KiB of authenticated TCP response. Relay vectors start at 4 KiB with the existing adaptive cap. `auto` keeps the existing cipher selection; on this AES-capable host it stays on the combined AES path. HTTP, TUN, TLS, other carriers, UDP, Mux and chains use the combined relay. **These results establish no TUN, mobile-device or battery improvement.** Both SDKs consume the same core; their ABI and canonical adapter sources are unchanged.

## Final ordinary controls

The frozen final `chacha` binary is SHA-256 `67ab56775c772481f0ec715afdcc47065e796f0b34dae05cc75b766f5abf8ad9`; [inputs](data/inputs.json) records its full patch at base commit `5a42b627e12b0783567027f55e8e96d64d1e4abc`, build arguments and all earlier variants. Baseline runtime `9198a8f2770496199022b531b01b3a2b35ec1bcc` is frozen separately. Baseline and control below are the **same executable**, used to expose A/A variation. Compiler is Rust 1.96.0 on aarch64-apple-darwin, locked release with incremental compilation disabled.

Each bulk flow validates 256 MiB per active direction: 512 MiB total for one duplex flow, 4 GiB for eight. CPU is process CPU per complete payload, in milliseconds, with 10 ms accounting granularity; speed is summed MiB/s across directions. Both clients use a common pinned Xray server. The broad matrix covers AES/ChaCha × upload/download/duplex/1 KiB request-response × 1/8 flows × four repeats (128 trials). A six-repeat duplex confirmation adds 72 trials with identical-binary control. Every client occupies every order position equally.

Six-repeat confirmation, **CPU ms / MiB/s**:

| Cipher / flows | Baseline | Identical control | Final |
| --- | ---: | ---: | ---: |
| AES / 1 | 350 / 1,781 | 355 / 1,764 | 350 / 1,772 |
| AES / 8 | 2,800 / 1,580 | 2,890 / 1,561 | 2,760 / 1,655 |
| ChaCha / 1 | 620 / 843 | 620 / 841 | 555 / 1,330 |
| ChaCha / 8 | 4,460 / 1,655 | 4,440 / 1,662 | 4,420 / 1,676 |

The paired 95% bootstrap interval for one-flow ChaCha is −12.7…−8.9% CPU and +54.6…+62.4% speed; the point estimates are −10.5% / +57.7%. These intervals resample repeat indexes together, not individual packets, and quantify within-session variation only. [All final intervals and the deterministic calculation](data/intervals.json) retain uncertainty, including wide reference throughput ranges. Twelve repeats cannot remove host/session bias.

Final broad one-direction changes are small: AES speed −1.6…+0.1%, CPU 0…+2.7% (the single-download difference is half an accounting quantum in the median). ChaCha upload/download speed −0.6…+1.3%; one-flow CPU improves about 5–6%, while eight-flow CPU stays within 1%. Eight-flow duplex shows no repeat of the earlier large speed penalty. A further 16 trials with 15 idle peers retain the one-flow benefit: ChaCha 610 → 545 ms CPU and 852 → 1345 MiB/s; AES 350 → 350 ms and 1782 → 1772 MiB/s.

## Latency tradeoff

A separate 12-repeat A/A confirmation validates all 144 trials. Cells are medians across runs of **median / p95 / p99**, µs (rounded here; exact half-microsecond medians and every sample are retained in [summary](data/summary.json)).

| Cipher / flows | Baseline | Identical control | Final |
| --- | ---: | ---: | ---: |
| AES / 1 | 75 / 222 / 352 | 75 / 226 / 348 | 75 / 228 / 344 |
| AES / 8 | 156 / 399 / 616 | 154 / 394 / 608 | 154 / 392 / 624 |
| ChaCha / 1 | 79 / 238 / 352 | 79 / 239 / 358 | 75 / 234 / 362 |
| ChaCha / 8 | 162 / 386 / 641 | 162 / 400 / 606 | 156 / 412 / 636 |

ChaCha median RTT improves 3–5%, but eight-flow p95 is 412.5 µs versus 386/400 µs: +6.9%/+3.1%. Against baseline its paired interval is +0.9…+12.7%, so it is retained as a measured tail cost, not dismissed as noise. The initial broad series also showed higher p95/p99. In confirmation, p99 is mixed and its interval crosses zero; no stable p99 improvement or regression is established. Short-request ChaCha CPU falls 40 → 30 ms at one flow and 215 → 180 ms at eight, but the one-flow percentage represents only one 10 ms quantum. AES latency and CPU remain close to its identical-binary controls.

## Held memory and resume

Four balanced campaigns use 512 persistent connections, either 1 MiB or 8 KiB warm exchanges, and two 11-second idle/resume cycles on those same connections. Each resume verifies a 1 KiB first request and another warm-sized exchange. All 16 final clients pass. macOS physical footprint is collected through the SDK's 96-byte `rusage_info_v0`, separately from RSS. Cells are **footprint MiB, baseline → final (increment)**.

| Warm exchange / cipher | After warmup | First resumed bulk | Second resumed bulk |
| --- | ---: | ---: | ---: |
| 1 MiB / AES | 105.29 → 105.65 (+0.36) | 105.29 → 105.66 (+0.37) | 105.29 → 105.66 (+0.37) |
| 1 MiB / ChaCha | 105.17 → 106.27 (+1.09) | 105.17 → 106.27 (+1.10) | 105.17 → 106.28 (+1.11) |
| 8 KiB / AES | 24.75 → 24.78 (+0.03) | 40.67 → 40.70 (+0.02) | 40.85 → 40.94 (+0.09) |
| 8 KiB / ChaCha | 24.76 → 25.68 (+0.92) | 40.66 → 41.72 (+1.06) | 40.81 → 41.82 (+1.01) |

ChaCha adds about 2 KiB per connection, roughly 1% after large transfers or 2.5–3.7% after small ones. AES adds 0.02–0.37 MiB across the entire 512-connection process. The large-transfer footprint remains almost unchanged through both resumes; the small-transfer case retains the existing adaptive-buffer/allocator growth in both clients. All final idle-CPU increments are zero at the 10 ms resolution; this is not zero power or a battery measurement. First-request Python echo timings are diagnostics and do not replace the Rust latency controls above.

## Fresh Xray-core / sing-box comparison

Unchanged pins: Xray-core v26.7.28 (`5ca6f4b7d4dc20a881d4330e498892697627ec0c`) and sing-box v1.13.20 (`56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778`), Go 1.26.0. Six balanced permutations per case give 72 passing trials with the same payload/server. Cells are **CPU ms / MiB/s / peak RSS MiB**.

| Cipher / flows | Final Rust | Xray-core | sing-box |
| --- | ---: | ---: | ---: |
| AES / 1 | 350 / 1,806 / 5.56 | 345 / 2,332 / 33.55 | 495 / 1,609 / 27.52 |
| AES / 8 | 2,695 / 1,656 / 7.26 | 3,540 / 1,491 / 37.89 | 4,160 / 1,402 / 32.39 |
| ChaCha / 1 | 560 / 1,329 / 5.71 | 780 / 1,335 / 34.17 | 1,085 / 1,009 / 27.94 |
| ChaCha / 8 | 4,420 / 1,662 / 7.43 | 7,845 / 1,604 / 39.14 | 8,895 / 1,360 / 32.63 |

One-flow ChaCha is 0.5% slower than Xray by the median, with 28.2% less CPU and about sixfold lower RSS. Its speed interval spans −7.4…+1.1%, so this is not proof of exact parity. AES one-flow remains 22.6% slower, with CPU +1.4% (interval −2.8…+2.9%). Eight-flow medians favor Rust, but ChaCha speed has a wide −19.4…+10.7% interval against Xray; do not generalize the favorable point estimate. RSS is lower in all eight final reference/case comparisons. This four-case matrix does not replace the earlier complete protocol comparisons or establish overall parity.

## Experiments retained and rejected

All campaign names, identities, sample ranges and failures remain in [inputs](data/inputs.json), [summary](data/summary.json) and [the archive](measurements.tar.gz). Earlier exploratory series guarded compiler activity but did not guard rendering; they are not relabelled as proven render-free. Later series require twelve quiet samples five seconds apart, detect active headless Chrome/ffmpeg/remotion at ≥5% CPU, and observe interference during each run. No builds, tests, profiles or archive work overlap measurements. Sampling cannot prove a perfectly idle shared host.

- Fixed admission caps and separate activity accounting (`cap1`, `cap2`, `separate-activity`) did not solve idle quota occupancy; demand-driven admission replaces them.
- `adaptive-wide` tested larger records without increasing pending allocation; AES results deteriorated, so 8 KiB records remain. `serial` native halves gave little reliable single-AES CPU benefit.
- `selected` adds quiet return and excludes small RPCs from admission. Its ordinary/diagnostic AES CPU tax persisted. `deferred` avoids an unnecessary eager write attempt on partial bulk acceptance: it repaired the earlier ChaCha upload concern, but did not eliminate AES duplex CPU cost.
- All-cipher `deferred` broad/confirmation/long diagnostic series show AES one-flow CPU +8.1%, about +7–8.5%, and +7.1% respectively. The longer diagnostic uses eight fresh 256 MiB connections, not one invalid oversized VMess session. Final ChaCha-only long diagnostics give AES 2340/2345 → 2330 ms and ChaCha 4630/4630 → 3970 ms. **Diagnostic speed/CPU are kept separate from ordinary throughput.**
- `quota-long-aes` attempted 1 GiB per direction in one session and failed with a reset. This workload exceeds the known 65,536-record counter bound at these record sizes; the log does not claim an explicitly captured nonce-limit error. The invalid workload is excluded; nonce behavior is unchanged.
- `final-broad` stopped after 70 rows to fix small-RPC admission. Three renderer-overlapped campaigns retain 4, 11 and 39 successful payload rows but are excluded as whole campaigns. Their clean retries are distinct, not replacements hidden in the same dataset.
- One held-stage launch failed before payload because its wrapper imported the wrong collector. The original log/wrapper is retained; corrected `guarded-held-v2.py` and `guarded-reference-v2.py` dispatch to the intended collectors. No performance sample comes from that failure. Earlier compile/test failures and their repaired reruns remain visible too.

## Validation and reproduction

Final core validation: 504 unit tests pass (two manual tests ignored), eight live VMess tests pass against the pinned Xray/sing-box references, three targeted TUN stop tests pass, Clippy denies warnings and formatting passes. The unchanged shared codec passes 143 protocol tests. Tests cover partial writes and migration, half-close, explicit close/idle/error cleanup, parent cancellation, shared and isolated admission budgets, small-RPC exclusion, initial buffered data, exact traffic accounting and synchronous stop completion.

[Source and validation metadata](data/runtime-validation.json) confirms that the production source exactly matches the measured patch. Eleven collector tests and sixteen narrow secret-scanner exception tests pass; the scoped source/archive scan is clean. Exceptions cover only rehashed public reference/log digests and the existing fixed public loopback fixture, with unrelated values and synthetic credentials still detected.

The archive contains **1,132 successful ordinary trials, 158 separate diagnostic trials and 32 held-memory clients**, including the earlier exploration. The exact final binary accounts for 432 ordinary trials, 36 diagnostics and 16 held clients. Ten complete prototype patches/build identities are retained. Generated credentials/configurations, executables and inherited environments are excluded. Failed and contaminated attempts remain separately labelled; an archive verifier checks hashes, identities, bytes, ordering, cleanup, phase structure and every reconstructed summary.

```sh
python3 docs/benchmarks/results/2026-10-02-v08-adaptive-relay/data/verify.py
python3 docs/benchmarks/results/2026-10-02-v08-adaptive-relay/data/intervals.py
```

To rerun, apply the chosen archived patch to its recorded base commit, use the recorded compiler and build arguments, freeze the resulting binary, and update local paths in the archived measurement drivers. `measure-chacha-full.py` contains the preserved held dispatch failure; use the corrected `measure-chacha-remaining.py` for held/reference/latency stages. Neither driver should run over an existing attempt or concurrently with another workload. Physical Apple testing remains deferred; release, publication artifacts and merge are outside this change.
