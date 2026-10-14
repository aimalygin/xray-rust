# Idle relay buffer reclamation — rejected on Apple M3 Pro

None of the three idle-shrink prototypes is retained. Reducing the live relay buffer to 4 KiB does **not** produce a reliable reduction in process footprint in these controls. After the first idle interval, all three candidates have about **4 MiB more footprint at 512 held connections**. Later cycles vary, sometimes improving individual samples, but none establishes a repeatable memory benefit without additional idle CPU and allocation churn. Runtime `9198a8f` and SDK `7b84921` remain unchanged.

## Experiment and identity

Baseline is the ordinary release from [bounded VMess download batching](../2026-10-02-v08-download/README.md), SHA-256 `528e6532d6919bc867dc0c7993bc090125ed3a725c0ebbc12db02791f60ff8e8`. Prototypes are patches against source HEAD `dc70c1edcb832e7e88671daceab325e899f79d79`; that HEAD has the same runtime source as `9198a8f`. Build commands, compiler/OS and all executable/patch digests are in [inputs](data/inputs.json). The reference is the same pinned Xray-core v26.7.28 used by the preceding report. No sing-box comparison or general throughput claim is made here.

All prototypes add one progress timer per relay direction, sampled every five seconds while the buffer is grown. An unchanged byte counter across an interval permits reclamation after roughly 5–10 idle seconds. Reclamation runs only between completed `write_all` operations; small buffers do not arm it. Protocol buffers, encrypted records and the VMess read-ahead floor are untouched.

- `trim`: erase the old relay allocation, replace it with a new 4 KiB vector.
- `shrink`: erase, resize to 4 KiB and call `shrink_to_fit` on the vector.
- `untouched`: truncate and `shrink_to_fit` without first rewriting the old allocation. This matches the baseline relay's normal teardown behavior; protocol plaintext erasure is unchanged. It isolates the extra cost of the first two prototypes' wiping.

Each prototype passes the 16 focused policy tests (one manual benchmark ignored), including a new paused-clock test of growth, continued traffic, reclamation, regrowth, verified bytes and blocked writes across idle intervals. Their code and tests are preserved as rejected patches in the archive, not applied to the runtime.

## Workload and measurement

Each fresh client opens **512 connections** and verifies a 1 MiB echo in both directions per connection. It then repeats twice on those **same connections**: idle for 11 seconds, verify the first 1 KiB request, then verify another 1 MiB echo. Each completed client verifies 1,611,661,312 bytes in each direction. Samples are collected at 1, 2, 5 and 11 idle seconds. All connections remain open and payload failures/timeouts fail the campaign.

The first completed campaign covers baseline/trim/shrink × AES/ChaCha × three repeats (18 clients). Its order varies and is recorded, but first-position counts are not perfectly balanced. The separate untouched control uses four AES repeats with balanced AB/BA order (8 clients). All 26 clients pass, with no compiler interference or surviving benchmark engines. No compilation overlaps these campaigns.

RSS alone is inadequate for this idle experiment: in one unchanged baseline trial it fell from **108.4 to 5.9 MiB**, while footprint remained **105.3 MiB** and all connections successfully resumed. The collector therefore also reads `ri_phys_footprint` via macOS `proc_pid_rusage`, using the SDK's 96-byte `rusage_info_v0` layout. Apple's footprint model includes dirty and compressed memory; RSS excludes compressed pages ([Apple's memory explanation](https://developer.apple.com/videos/play/wwdc2018/416/)). This observation is consistent with compression, but these counters do not isolate allocator caches, fragmentation or every kernel mechanism.

The initial RSS-only pilot was deliberately stopped after eight complete clients plus one partial client and is excluded from acceptance. Its samples, source and stop log are retained. It also exposed an AB-order issue inherited from the older helper: rotating two variants and then reversing every even repeat cancels alternation. The retained collector uses rotation alone; the final AB/BA control is balanced. Earlier reports are not retroactively relabeled as balanced.

## Results

All memory columns are median **footprint in MiB**, not RSS. Idle CPU is process CPU in milliseconds during each 11-second pause at 512 connections; `ps` quantizes this counter to 10 ms, so baseline zero means below that resolution.

| Cipher / variant | Warm | First idle | First resumed bulk | Second idle | Second resumed bulk | Idle CPU ms, first / second |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| aes128 / baseline | 105.31 | 105.31 | 105.31 | 105.31 | 105.31 | 0 / 0 |
| aes128 / trim | 105.53 | 109.48 | 113.41 | 113.41 | 97.33 | 200 / 150 |
| aes128 / shrink | 105.55 | 109.34 | 102.97 | 102.97 | 106.47 | 150 / 140 |
| chacha20 / baseline | 105.17 | 105.17 | 105.17 | 105.17 | 105.17 | 0 / 0 |
| chacha20 / trim | 105.50 | 109.50 | 113.80 | 113.39 | 109.55 | 220 / 140 |
| chacha20 / shrink | 105.17 | 109.11 | 113.16 | 113.16 | 108.55 | 180 / 170 |
| aes128 / baseline (separate control) | 105.28 | 105.28 | 105.29 | 105.29 | 105.29 | 0 / 0 |
| aes128 / untouched (separate control) | 105.43 | 109.38 | 113.51 | 109.38 | 107.85 | 30 / 30 |

The no-wipe control reduces idle CPU from roughly 150–220 ms in the wiping prototypes to **30 ms**, but does not solve the first-idle footprint increase. Its AES first-request p95 medians are 334.7 → 358.9 µs on the first resume and 326.1 → 339.8 µs on the second; individual trial tails vary. These Python echo timings are end-to-end diagnostics, not evidence of a precise throughput or latency regression. [All medians and individual samples](data/untouched-summary.json) and [both-cipher results](data/footprint-summary.json) remain available.

Some later cycles use less footprint; all are retained. Selection is rejected because the intended reliable memory reduction is absent, even before requiring the broader throughput gate. No new full throughput/reference matrix or platform CI is claimed for these rejected prototypes. This does not prove that all idle reclamation or other allocators/platforms must fail. A smaller vector capacity is not itself proof of a smaller process footprint.

## Reproduction and verification

The retained collector is `scripts/run-v08-idle-buffer-controls.py`. Compile all candidates beforehand; do not compile during measurement. Example for an ordinary baseline and the no-wipe candidate:

```sh
python3 scripts/run-v08-idle-buffer-controls.py \
  --binary baseline=/path/to/frozen-baseline \
  --binary untouched=/path/to/frozen-candidate \
  --reference /path/to/pinned-xray \
  --profile vmess-aes128 --repeats 4 --output /path/to/new-output
```

The archive contains every completed/partial trial and the source/build/test evidence, excluding ephemeral credential configs and binaries. The index hashes every archived member. The verifier checks all hashes, trial completeness, payload accounting, idle intervals, source patch identities and independently reconstructs the published footprint/idle-CPU table:

```sh
python3 docs/benchmarks/results/2026-10-02-v08-idle-buffers/data/verify.py
```

Production source was restored exactly. The restored release is rebuilt and compared byte-for-byte with the frozen baseline; the [verification record](data/verification.json) records that check. Previous download improvements and their documented memory costs remain; this investigation does not claim a new optimization or device acceptance.
