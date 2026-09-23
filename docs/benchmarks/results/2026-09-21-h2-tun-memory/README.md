# H2/TUN retained-memory investigation — 2026-09-21

The higher sampled RSS reproduces, especially with eight upload flows. The post-transfer heap profiles locate most malloc-zone backing in free/fragmented space, while live allocations are similar between versions. This is evidence for allocator retention and allocation/scheduling patterns, not evidence of an extra multi-MiB collection of live application objects. It does **not** establish absence of a long-term leak, identify a specific allocation call stack, or close the memory target.

The previous 1.7–4.1 MiB difference was a measurement from one series, not a fixed allocation size. New differences vary between series. The selected runtime is unchanged. No production allocator setting, memory-flush call, or worker-policy change is accepted from these diagnostic experiments.

This follow-up contains **50 unprofiled timed runs and 12 separate diagnostic runs**, all with validated payloads and successful completion. The original [2026-09-20 report](../2026-09-20-v07-parity/README.md) and its raw evidence are retained unchanged. H2 here means the **XHTTP HTTP/2 transport**, not Hysteria2.

## Conditions and identities

- Same Apple M3 Pro Mac: 12 cores, 18 GiB, macOS 26.6.2 (25G83). Rust 1.96, Go 1.26.5; frozen binaries from the preceding campaign.
- Candidate runtime source: `b9577f874b3f102880ae078038855803d85f5d04`, tree `1a8d391146eaf898e2b4824c736391fbdccb8f4f`. CLI SHA256 `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e`.
- Baseline 0.6.1 source: `ed5258a3a589c2a1f9330142f37c8f3d28a640fa`. CLI SHA256 `d77931ce0905e08de84303e98870201b32c65288910086e0e25dbe2d2e4a5c3d`.
- Common Xray server source: `5ca6f4b7d4dc20a881d4330e498892697627ec0c`; SHA256 `2a950beafa07ecd4bebbcaced9ad677d7ac48a65c2e8861f21b7f78717ef56fb`.
- Timed harness SHA256: `dd41949758574eca8f00651ef6d2fdc57e579d78859800b9a1c213e1a2ecea2d`. Worker/allocator variants use byte-identical client binaries.
- Every flow transfers 512 MiB per active direction: 8192 × 65536 bytes. Upload8 sends 4 GiB; duplex1 sends and receives 512 MiB. Each timed case/configuration has five repetitions, with versions interleaved by repeat.
- RSS is the maximum sampled client `ps` RSS, approximately every 100 ms, including startup/traffic/post-work samples; it is not a continuous peak or a measurement of the server/kernel. CPU is client cumulative CPU time. Throughput is the aggregate validated workload throughput.
- Before each timed run, three quiet samples are required. Compiler observation during runs detected no qualifying compiler load. This sampling does not prove an idle host. No builds, profiling, or compression ran concurrently with the timed series.
- The user-approved 3% allowance applies only to performance metrics. Memory still requires a strictly lower RSS. Different runtime/environment groups are kept separate; the diagnostic allocator setting cannot establish acceptance of the default runtime.

## Unprofiled reproduction: 30 runs

Candidate uses its default two Tokio workers; baseline uses its default twelve on this host. `workers12` uses the same candidate binary with twelve workers. Harness/server policy is twelve/default in these three configurations.

Each number below is a median of five runs. RSS is MiB; throughput is MiB/s; CPU is milliseconds.

| Case | Configuration | RSS MiB | Throughput MiB/s | CPU ms |
| --- | --- | ---: | ---: | ---: |
| xhttp-h2-tun-full-duplex-1 | baseline | 18.469 | 627.267 | 3030 |
| xhttp-h2-tun-full-duplex-1 | candidate | 19.391 | 667.954 | 2210 |
| xhttp-h2-tun-full-duplex-1 | workers12 | 18.625 | 639.698 | 2920 |
| xhttp-h2-tun-upload-8 | baseline | 19.828 | 712.305 | 12570 |
| xhttp-h2-tun-upload-8 | candidate | 22.984 | 810.341 | 8010 |
| xhttp-h2-tun-upload-8 | workers12 | 17.438 | 752.672 | 11900 |

Candidate minus baseline RSS is **+0.922 MiB (+4.99%) for duplex1**, and **+3.156 MiB (+15.92%) for upload8**. The paired bootstrap 95% RSS-ratio intervals are 0.964–1.075 and 0.958–1.496: neither establishes a stable size for the difference in this series. Throughput improves by 6.49% and 13.76%, and CPU decreases by 27.06% and 36.28%.

The same candidate with twelve workers has a lower upload8 RSS median (17.438 versus 22.984 MiB), at the cost of lower throughput and higher CPU. The candidate2/candidate12 RSS-ratio interval is 1.110–2.012 in this series. Scheduling policy contributes to the observed tradeoff; this does not imply that all remaining differences come from the worker default.

## Heap and region profiles: eight diagnostic runs

A private harness pauses before traffic, after validated TUN completion/flow teardown, and after ten seconds idle. It also takes an active `vmmap` snapshot around 0.9 seconds into traffic. `heap --sortBySize --showSizes`, `vmmap -summary`, and `ps` inspect only the owned test client. These pauses and inspections disturb memory/timing; **none of these runs is used for performance or RSS acceptance**.

The diagnostic harness changes only `crates/xray-bench/src/protocol_bench.rs`, in private commit `cac1b3f424ce7ce5f8db85869b6616c46cf4de60`. Its recorded patch reconstructs tree `f9dad7484718e1d1faed9266d861bb93f2550da1` from the measured runtime source. The client binaries remain unchanged.

Exact live heap after transfer, from `heap` (all zones):

| Case | Configuration | Live bytes after transfer | Live MiB | Malloc-zone fragmentation after transfer |
| --- | --- | ---: | ---: | ---: |
| duplex1 | baseline | 665888 | 0.635 | 95% |
| duplex1 | baseline2 | 701024 | 0.669 | 96% |
| duplex1 | candidate | 567744 | 0.541 | 96% |
| duplex1 | workers12 | 609840 | 0.582 | 95% |
| upload8 | baseline | 772512 | 0.737 | 89% |
| upload8 | baseline2 | 803344 | 0.766 | 95% |
| upload8 | candidate | 800800 | 0.764 | 95% |
| upload8 | workers12 | 797344 | 0.760 | 96% |

In upload8, candidate2 has 800,800 live bytes versus baseline12's 772,512: **only 28,288 bytes (27.6 KiB) more**, not the multiple MiB seen in RSS. With twelve workers in both clients, the difference is 24,832 bytes. Candidate duplex1 has fewer live bytes than baseline. Live allocation bytes and counts remain exactly constant from the post-transfer checkpoint to ten seconds idle in every plain profile.

`vmmap` reports **89–96% fragmentation in the post-transfer malloc zone's dirty+swapped backing**. This percentage is not a fraction of the whole process RSS, nor a promise that all of that space can be returned immediately. Live objects may be spread over partially occupied pages. The snapshots directly locate substantial free backing in `MALLOC_SMALL` / empty regions; they do not attribute allocation stacks.

The physical footprint and sampled RSS are different measurements. For example, candidate upload8 live heap stays at 800,800 bytes while its `ps` RSS falls from 25.281 MiB after transfer to 12.359 MiB after idle. The associated physical-footprint snapshots change from approximately 14.7 MiB to 9.03 MiB. Profiler activity and OS reclamation make these diagnostic observations unsuitable as a performance result. Apple explains dirty/swapped backing, live heap, and fragmentation in [Analyze heap memory](https://developer.apple.com/videos/play/wwdc2024/10173/).

The H2 transport implementation itself has no diff against 0.6.1. Shared TUN bridging and the CLI worker default did change. The bridge reuses buffers and keeps upload work alive across polling; H2 still copies granted write data into its send buffer. These are possible contributors to allocation lifetime/placement under load; the present data does not select one exact code allocation as the cause.

Profile limitations:

- `baseline2` in these plain and relief profiles inherits two workers into the harness as well as the client. Its snapshots record real heap contents but cannot isolate client worker effects. The subsequent timed control fixes this by applying overrides only to `client_env`.
- Active snapshots occur at a fixed time, not at identical byte progress. Their live allocation sizes cannot be interpreted as matched queue occupancy.
- One relief-profile startup `vmmap` (`upload8-baseline2/before`) ran before libSystem initialization and has no malloc-zone data despite exit code zero. It is retained and explicitly excluded as an initialized allocator baseline. All relevant post-transfer/idle/relieved snapshots contain valid zone data.
- No long-running repeated-transfer leak test or allocation-stack attribution was performed. Ten seconds of stable live allocations does not rule out every leak.

## Pressure-relief control: four diagnostic runs

A private injected helper calls `malloc_zone_pressure_relief(NULL, 0)` on the owned test client after transfer and ten seconds idle. It creates no system-wide memory pressure. The [Apple API declaration](https://github.com/apple-oss-distributions/libmalloc/blob/main/include/malloc/malloc.h) describes a best-effort release across zones; the return value is released bytes.

All four configurations returned **zero released bytes**. Each RSS changed by only **−16 KiB**, with exactly unchanged live heap. This is no useful demonstrated reduction. The helper thread itself terminates at this point, so the tiny RSS movement is not proof of effective allocator flushing. **No production flush is proposed or installed.**

## Client-only allocator/worker control: 20 timed runs

Upload8, five repeats per configuration. Parent/harness/server worker policy is held constant. Only `request.client_env` is changed:

- `candidate`: two workers, default allocator.
- `candidate_mag1`: the same candidate binary, two workers, `MallocMaxMagazines=1`.
- `baseline2`: the same 0.6.1 binary, two workers.
- `baseline`: 0.6.1 with twelve workers, matching its host default.

The optional magazine-count control exists in [Apple's published allocator source](https://raw.githubusercontent.com/apple-oss-distributions/libmalloc/main/src/magazine_malloc.c). This does not assert that the source revision is identical to the installed macOS library or independently verify how many arenas the installed allocator created.

| Case | Configuration | RSS MiB | Throughput MiB/s | CPU ms |
| --- | --- | ---: | ---: | ---: |
| xhttp-h2-tun-upload-8 | baseline | 15.547 | 713.991 | 12360 |
| xhttp-h2-tun-upload-8 | baseline2 | 17.594 | 766.011 | 8440 |
| xhttp-h2-tun-upload-8 | candidate | 21.891 | 832.215 | 7940 |
| xhttp-h2-tun-upload-8 | candidate_mag1 | 18.969 | 819.700 | 7940 |

Candidate minus stock baseline is now **+6.344 MiB (+40.80%)**, RSS-ratio interval **1.093–1.473**. This independently confirms that the RSS signal cannot be dismissed entirely as host noise, while showing that the original 1.7–4.1 MiB was not a stable bound.

With both clients at two workers, candidate remains +4.297 MiB at the median, but its ratio interval 0.931–1.756 crosses equality. Thus the worker default does not account for the entire observed point difference, and the residual size is uncertain.

The allocator setting lowers the candidate's RSS median from 21.891 to 18.969 MiB (−13.35%); throughput changes from 832.215 to 819.700 MiB/s (−1.50%), and CPU medians are both 7940 ms. However, RSS samples overlap substantially and the default/setting ratio interval is **0.896–1.783**. This is an inconclusive experiment, not an accepted fix. Its RSS median also remains above stock baseline's 15.547 MiB.

## What is resolved and what remains open

The reproducibility question is answered: upload8 can show materially higher client RSS while speed and CPU improve. Post-transfer profiling narrows the extra memory primarily to allocator-backed free/fragmented regions, rather than an equivalent growth in retained live objects. Worker policy changes the tradeoff. Neither tested allocator control demonstrates a reliable fix.

The strict memory objective remains open. There is no runtime patch from this investigation. The next code-level optimization would need allocation/lifetime attribution under the TUN upload load, followed by unprofiled repeated comparisons on the same frozen configurations. Reverting to twelve workers or forcing allocator environment variables globally is not justified by this limited case matrix. This report makes no new Hysteria2/WireGuard parity or mobile-device claim.

## Evidence and verification

- [analysis.json](analysis.json): separate timed groups, every sample, candidate/reference ratios and deterministic paired bootstrap 95% intervals (4000 resamples), exact profile heap counts/bytes, region summaries, and caveats.
- [input-verification.json](input-verification.json): 50 timed and 12 diagnostic payload/identity checks, binary/source hashes, reconstruction of the private harness patch, and the unchanged 566-file core guard before report installation.
- [raw-evidence.tar.gz](raw-evidence.tar.gz): raw results, requests/configurations, logs, checkpoint files, `heap`/`vmmap` output, drivers, collector scripts, diagnostic helper source/build records, and source patch. Build targets and full engine executables are omitted; their frozen hashes and prior build provenance are retained.
- [raw-evidence-index.json](raw-evidence-index.json) and [archive-verification.json](archive-verification.json): every archive member's size and SHA256, checked without extraction. [SHA256SUMS](SHA256SUMS) checks the delivered artifacts.

To recalculate this analysis, unpack the raw archive into a fresh directory and run `python3 analyze-memory.py` there. The archived reader uses the included summary helper. Collection drivers retain their original absolute campaign paths for audit; re-running workloads requires restoring or adjusting those paths and rebuilding the pinned sources using the prior report's provenance. Profiles and timed runs must remain separate. Raw manifests' collector `source_commit` fields are not substitutes for the measured client source identities above.
