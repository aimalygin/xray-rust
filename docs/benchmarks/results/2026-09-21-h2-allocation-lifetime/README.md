# H2/TUN allocation sites and lifetimes — 2026-09-21

The upload path has four dominant sources of allocation traffic: the TUN input arena, TCP receive-to-upload copying, H2 DATA copying, and TLS record buffers. Native stacks now identify those sites; Instruments provides two concrete allocation/free lifetime examples. Large payload allocations are absent from the post-transfer live-stack snapshot, apart from the current 64 KiB input arena.

Two private arena-reuse prototypes were evaluated. Immediate reuse did not reduce allocation traffic in the measured load. Retaining two retired arenas reduced 64 KiB allocation requests by **64.3%**, but **did not improve unprofiled RSS**: its median was 28.328 MiB versus the unchanged parent's 25.797 MiB. Neither prototype is accepted into the runtime.

The parent still exceeds 0.6.1's RSS in the new repeated screen. This investigation does **not** fully attribute that difference to a particular call site, prove the absence of a long-term leak, or close the memory objective. It extends the [preceding heap/region investigation](../2026-09-21-h2-tun-memory/README.md), whose measurements and artifacts remain unchanged. H2 here is **XHTTP HTTP/2**, not Hysteria2.

## Workload and measurement boundaries

- Same Apple M3 Pro Mac, 12 cores, 18 GiB, macOS 26.6.2 (25G83); Rust 1.96 and Go 1.26.5.
- **15 completed unprofiled timed runs**: upload8, 512 MiB per flow, 4 GiB validated per run, five repetitions of parent/pool/baseline interleaved by repetition. All payload and owned-process cleanup checks passed. Parent and pool use two client Tokio workers; baseline uses its host default of twelve. Overrides apply only through `request.client_env`; the common harness/server worker policy is unchanged.
- **Six completed diagnostic runs**, separately: one native live-only capture, four native full-history captures, and one Instruments Allocations capture. A seventh diagnostic attempt failed to attach Instruments and is retained as an instrumentation failure, not a protocol result.
- Full native histories send 16 MiB per flow, 128 MiB total. The initial live-only attempt sends 64 MiB per flow. Instruments sends 512 MiB per flow and records for 15 seconds.
- Timed RSS is maximum sampled client `ps` RSS, roughly every 100 ms, including startup, traffic and settling. It is neither continuous peak memory nor server/kernel memory. CPU is cumulative client CPU time; throughput uses validated aggregate bytes. No builds, profiling, export, compression or heavy analysis ran concurrently with timed runs.
- The quiet guard requires three consecutive samples before each run. Compiler observation detected no qualifying load during the completed screen; this does not prove a perfectly idle host. A preceding direct-reclaim screen timed out at the quiet guard **before any timed run**. Its zero-run manifest and 180 seconds of load observations are retained.
- Performance allowance remains 3%. RSS must be strictly lower. The collector's historical 15% review flags are not acceptance criteria. Diagnostic profiler RSS/timing is never used for acceptance.

## What allocates under load

The symbolized candidate's native full history has 89,220 allocation records and 88,490 free records. The table counts **cumulative requested bytes** across the run, not simultaneous live memory, RSS, or allocator-rounded usable sizes. Startup requests are included.

| Allocation site / stack group | Requests | Cumulative requested MiB |
| --- | ---: | ---: |
| TUN input arena, `PacketReader` in `tun_fd.rs`, inlined into `read_loop` | 2,141 | 133.813 |
| rustls `PrefixedPayload::with_capacity`, outbound TLS record payload | 16,240 | 128.466 |
| TCP receive-to-upload copy, inlined into `drive_tun_tcp_stack` | 8,095 | 128.012 |
| `Bytes::copy_from_slice` under `H2Upload::poll_write` | 11,974 | 128.000 |
| Upload batch scratch growth | 33 | 0.700 |
| Per-flow bridge read buffers | 8 | 0.500 |
| Other allocation requests | 50,729 | 5.202 |

Together these request 550,180,259 bytes (524.693 MiB) for 128 MiB of payload. The four large groups each account for roughly one payload volume over the run; **this does not mean four full payload copies coexist in RAM**. Call-site attribution and representative stacks are preserved in [native-attribution.json](native-attribution.json). Small metadata requests in an inlined call-site group are not separately classified as payload.

The immutable source snapshots are archived. In the parent source, TCP copies into `Bytes` at `tun.rs:2571`; H2's granted write data is copied at `h2.rs:616`. Native optimization/inlining can report the surrounding function instead of those exact lines.

## What stays alive, and for how long

In the symbolized native run, the live-stack groups are byte-for-byte unchanged from post-transfer to ten seconds idle. They contain one 65,536-byte current TUN arena. There are no remaining groups at the four named payload-copy sites other than that arena, and no per-flow 64 KiB bridge read buffers. The remaining requested-byte groups include approximately 128.6 KiB of AWS-LC entropy state, 108.0 KiB of TLS deframer buffers, and 284.8 KiB classified as other H2 connection state/capacity. These are retained connection/runtime allocations, not multi-MiB payload buffers.

Native `-allBySize` also reports some mmap/thread-stack regions. The analysis explicitly separates those from malloc allocations; it does not add their virtual reservation sizes to the live heap. `heap` reports 788,320 live allocator bytes for this symbolized run after idle. Requested bytes, usable heap bytes and RSS have different meanings.

Two individual lifetime examples were inspected in Instruments' allocation history and symbolized with `atos`:

| Allocation | Size | Allocated at | Freed at | Observed lifetime |
| --- | ---: | ---: | ---: | ---: |
| Input-arena example, address `0xaf48a4000` | 64 KiB | 1.538861 s | 1.539043 s | **182 µs** |
| Per-flow bridge read buffer, address `0xaf4834000` | 64 KiB | 1.535427 s | 7.802174 s | **6.266747 s** |

These timestamps are relative to that instrumented trace. They are **examples, not a distribution or average**, and profiling changes scheduling/timing. The first attribution is inferred from the 64 KiB reader allocation site and the symbolized `PacketRxToken`/`Bytes` free stack; the allocation caller is an inlined Tokio poll frame. The second resolves to bridge creation and teardown. Debug level 1 did not retain every inlined allocation frame. [sampled-lifetimes.json](sampled-lifetimes.json) records the addresses, callers and limits; the raw archive includes symbolication output.

The native `malloc_history -allEvents` export itself does not provide lifetime timestamps. Simple address pairing encounters interleaved reuse/free records, so no exact whole-heap peak or lifetime distribution is reconstructed from it. The large Instruments allocation-list export also lacked a free-time column; it is not substituted for paired lifetime records.

## Controlled code experiments

Both patches affect only private copies of `crates/xray-core-rs/src/tun_fd.rs` and reconstruct from the same measured parent. The original reader's allocation policy and the H2 transport file are byte-identical between 0.6.1 and the parent: these allocation sites were **not newly introduced by v0.7**. Shared TUN bridging and worker policy did change, as documented in the preceding report. This investigation has no paired symbolized 0.6.1 trace that would isolate their causal contribution.

**Immediate reclaim:** call `BytesMut::try_reclaim` before replacing an exhausted arena. Unit checks include pointer reuse after every packet owner releases the arena and preservation of a still-held packet. All 23 filtered `tun_fd` tests pass. In the same production release profile, native full logging records 2,149 requests of 65,536 bytes for both parent and prototype. It does not help this workload: packets can still own the arena when the next one is needed.

**Two retired arenas:** retain at most two exhausted arenas in addition to the current one, checking whether their last packet has been consumed before reuse. This permits reuse without overwriting shared packet contents. All 24 filtered `tun_fd` tests pass, including reuse of a retired arena while another packet remains held.

| Production-profile native diagnostic | 64 KiB allocation requests | Total cumulative requested bytes | Live heap bytes after idle |
| --- | ---: | ---: | ---: |
| Unchanged parent | 2,149 | 550,205,343 | 784,496 |
| Immediate reclaim | 2,149 | 550,181,415 | 787,408 |
| Two retired arenas | 767 | 459,398,954 | 915,472 |

Pool requests of 64 KiB fall by 64.31%; total requested bytes fall by 16.50%. Its extra live heap is 130,976 bytes, consistent with keeping two extra 64 KiB arenas plus small allocation differences. This is a diagnostic comparison, not RSS acceptance evidence. Live-stack groups are stable after transfer to idle in all four full-history runs.

## Unprofiled comparison: pool rejected

Each value is the median of five completed runs in the same screen.

| Runtime | RSS MiB | Throughput MiB/s | CPU ms |
| --- | ---: | ---: | ---: |
| 0.6.1, 12 workers | 18.969 | 774.478 | 11,620 |
| Unchanged 0.7 parent, 2 workers | 25.797 | 886.108 | 7,430 |
| Two retired arenas, 2 workers | 28.328 | 890.599 | 7,420 |

The pool's RSS median is **+2.531 MiB / +9.81%** versus its parent. Its paired bootstrap 95% RSS-ratio interval is **0.985–1.279**; the worsening is not established throughout the interval, but there is no supported memory improvement. Throughput changes +0.51% (ratio interval 0.977–1.012), and CPU −0.13% (0.983–1.007). Fewer allocation requests alone did not deliver a useful memory result.

The parent versus 0.6.1 has RSS **+6.828 MiB / +36.00%**, ratio interval **1.072–1.821**; throughput +14.41%, CPU −36.06%. These are this series' values, not a revision of previous measurements or a claim that the difference is always this size. The pool is also above 0.6.1 in RSS, by 49.34% at the median.

All samples and deterministic paired bootstrap intervals (4,000 resamples) are in [analysis.json](analysis.json). Pairing is by repeat index; these runs share a noisy host and are not independent machine replications. No latency claim comes from this bulk-upload screen.

**Decision:** retain both patches as rejected experiments; install no runtime change. The prepared broader H2 and Hysteria2/WireGuard validation scripts were **not run**, because the pool already failed its memory purpose. This follow-up makes no new Hysteria2/WireGuard external-library parity claim. Existing results for those protocols remain in the prior campaign.

## Instrumentation corrections and retained failures

- On the installed SDK, `MallocStackLogging=1` selects lite/live logging and takes precedence over `MallocStackLoggingNoCompact`. The first attempt therefore contains live records only. Full runs use `MallocStackLoggingNoCompact=1` without `MallocStackLogging`, with the pre-existing log directory and the recorder's compaction-off message retained. The installed SDK and `malloc_history` manpages are archived; older online examples can differ.
- Initial Instruments attachment to the private symbolized binary failed. A separate profiling-only copy was ad-hoc signed with `com.apple.security.get-task-allow`, then attached successfully. Original and timed release binaries were unchanged. No production signing or entitlement change was made.
- A transient-allocation XML export exceeded 4 GiB without the needed free-time field and was stopped. `xctrace` removed its incomplete output on interruption. `large-export-stopped.json` records this explicitly; the original trace and native histories remain intact.
- The failed attachment and zero-run quiet-guard timeout remain evidence. They are not converted into successful performance runs, omitted from the attempt history, or counted as transport failures.

## Identities and reproducibility

| Artifact | Source / identity | CLI SHA256 |
| --- | --- | --- |
| Parent release | `b9577f874b3f102880ae078038855803d85f5d04`, tree `1a8d391146eaf898e2b4824c736391fbdccb8f4f` | `49500f291e28ca21fff288e858e67757eafe01931fee8ec1eb2fb66ce2ea8d6e` |
| 0.6.1 release | `ed5258a3a589c2a1f9330142f37c8f3d28a640fa` | `d77931ce0905e08de84303e98870201b32c65288910086e0e25dbe2d2e4a5c3d` |
| Immediate reclaim release | `449469ae3dcd1dd9fbf5388160af513ff8ab440d` | `b74c56078d1a4f2583534f536e429f8a4c1d14c07faf2f47e827b78dabf95552` |
| Two retired arenas release | `10dda33f17fc9ce13687f812d22836485573262e`, tree `a2c32a8b91de2cf967561bd430256a84424b0ec2` | `f5bae363c33231937d5cd8a414241eb166f4d7f8472752b606f2c364d06f576c` |
| Symbolized parent, diagnostic only | Parent source, release debug=1, strip=none | `47f88953b19f484c43163bd23a611941215e71a8ea252463f31128a328cc3071` |
| Separately signed Instruments copy | Same diagnostic build plus profiling entitlement | `a8c9b1225734c56218b99d2b09e67cd7ea25b718f7e76461fc80aacf399fef6c` |

Common Xray server source `5ca6f4b7d4dc20a881d4330e498892697627ec0c`, binary SHA256 `2a950beafa07ecd4bebbcaced9ad677d7ac48a65c2e8861f21b7f78717ef56fb`. Timed harness SHA256 `dd41949758574eca8f00651ef6d2fdc57e579d78859800b9a1c213e1a2ecea2d`. Private checkpoint harness source `cac1b3f424ce7ce5f8db85869b6616c46cf4de60`, binary SHA256 `ecc253389b010412a34359c602cbdc3bbfcbbbcb659e5a71c76a638b52ad4252`.

[input-verification.json](input-verification.json) verifies client/harness hashes, completed payloads, owned cleanup, patch-to-tree reconstruction, and the unchanged 573-file core guard before report installation. Builds used locked offline dependencies. The two prototypes used the same isolated target sequentially in the same source checkout; immutable binaries were copied out before the next build.

[raw-evidence.tar.gz](raw-evidence.tar.gz) includes native histories, safe Instruments exports, diagnostic/timed results, configurations and logs, scripts, source/build records, both patches, and the attempt history. [raw-evidence-index.json](raw-evidence-index.json) and [archive-verification.json](archive-verification.json) verify all member bytes and archive-only reanalysis. [SHA256SUMS](SHA256SUMS) checks delivered artifacts.

The opaque original Instruments traces and full TOC remain private under `/private/tmp/xray-h2-allocation-lifetime-20260921/traces/`; they can contain unrelated inherited environment. [private-trace-index.json](private-trace-index.json) records their file hashes. The delivered TOC removes the entire 63-item environment section; the allocation-list export contains stacks and allocation metadata, not that environment. Build trees and executable binaries are omitted. Individual UI-inspected lifetimes require the original trace to inspect again; they cannot be reconstructed from the live-only XML list.

For archive-only recalculation, extract into a fresh directory and run:

```sh
python3 analyze-native-history.py
python3 analyze-allocation-lifetime.py
```

Collection/build/identity-verification drivers preserve original absolute paths and require the recorded source repositories and frozen binaries. The analysis scripts use archive-relative inputs. This report narrows the allocation mechanisms and rejects an ineffective fix; exact attribution of the **RSS difference between versions during load** remains open.
