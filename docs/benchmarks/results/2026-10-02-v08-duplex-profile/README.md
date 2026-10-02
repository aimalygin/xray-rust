# VMess AES full-duplex CPU profile — Apple M3 Pro

The remaining one-connection throughput gap is reproducible; a fixed total-CPU deficit is not. Two ordinary six-repeat series put Rust **22.1% and 24.6% below Xray in throughput**, but total CPU changes from **11.3% higher to 10.1% lower**. All samples are retained. The stable diagnostic finding is substantially more socket/event work in Rust, alongside a serial per-connection relay architecture. No runtime optimization is selected by this investigation; runtime `9198a8f` and SDK `7b84921` remain unchanged.

## Ordinary controls

Current ordinary release, pinned Xray-core v26.7.28 and sing-box v1.13.20 use identical loopback SOCKS workloads against the pinned Xray server. Each flow transfers and verifies 256 MiB per active direction; duplex transfers 512 MiB total. The first matrix is upload/download/duplex × three engines × six repeats (54 trials); the later confirmation repeats duplex × three engines × six (18). All 72 pass. Within each case, the six client-order permutations are balanced. No build, profiler, counter campaign or archive processing overlaps either ordinary series.

Medians below: process CPU in milliseconds per complete workload, throughput in MiB/s summed across directions, peak RSS in MiB. CPU is the normal collector's 10 ms-quantized `ps` accounting. RSS is not physical footprint or mobile memory acceptance.

| Series / traffic | Rust CPU / speed / RSS | Xray CPU / speed / RSS | sing-box CPU / speed / RSS |
| --- | ---: | ---: | ---: |
| Initial upload | 160 / 1,961 / 5.40 | 160 / 1,994 / 32.59 | 180 / 1,787 / 26.77 |
| Initial download | 170 / 1,953 / 5.28 | 130 / 2,115 / 32.73 | 280 / 1,216 / 26.94 |
| Initial duplex | 295 / 2,215 / 5.45 | 265 / 2,846 / 33.45 | 400 / 1,871 / 27.40 |
| Later duplex confirmation | 310 / 1,916 / 5.45 | 345 / 2,541 / 33.77 | 510 / 1,655 / 27.80 |

The confirmation was required because the separate OS-counter campaign reversed the initial duplex CPU ranking. This is a real limitation of these desktop measurements, not a reason to discard a series. The runs do not isolate the cause of the shift (for example, CPU frequency or core placement), and those causes are not claimed. Throughput, syscall patterns and the low one-flow RSS remain consistent findings. [All samples, ranges and medians](data/summary.json) are reproducible from the archive.

## On-CPU profiles

Apple Time Profiler sampled the target client at 1 ms with **kernel stacks enabled and waiting threads disabled**. This measures active CPU stacks, unlike the earlier wall-stack `sample` diagnostics. Three repeated 10-second captures per engine follow one pilot each. The harness gates traffic until Instruments signals recording has started. Each repeated capture runs 96 fresh, bounded 256 MiB-per-direction duplex connections sequentially, verifying 24 GiB each way; a 10-second profile covers a subset of this traffic. The Rust pilot uses 64 cycles and the Xray pilot 96; neither enters the repeated-profile median.

Rust uses the same source with symbols retained and CLI debug information; Xray uses the unchanged pinned executable with native symbols. Profiling timings are diagnostic only, never a performance claim or normalized cost per GiB. Default worker policies remain: two Tokio workers for the Rust CLI and Go's default for Xray. Recorded active OS thread counts do not establish goroutine/task concurrency.

| CPU sample attribution | Rust median (range) | Xray median (range) |
| --- | ---: | ---: |
| Kernel as leaf frame | 58.9% (56.7–61.2) | 46.1% (46.0–48.5) |
| AES-GCM assembly as leaf frame | 20.2% (18.6–21.3) | 26.9% (26.1–27.6) |
| Memory-copy leaf functions | 4.7% | 4.5% |
| `kevent` anywhere in stack | 15.2% (12.9–16.3) | 4.9% (4.9–5.0) |
| Socket-write wrapper anywhere in stack | 29.7% | 24.3% |
| Padding RNG subtree | 2.6% | 2.9% |

Leaf rows are exclusive categories; inclusive rows overlap them and must not be added together. The parser resolves XML references, selects the exact client PID, requires every sample to be `Running`, weights by the recorded sample weight and counts an inclusive frame at most once per stack. It preserves unknown kernel symbols rather than guessing their names. Per-capture leaf and inclusive function rankings are archived. Repeated captures contain 10,236–11,604 Rust and 13,808–17,101 Xray samples. Different work completes within these windows: the smaller Rust AES percentage alone does **not** prove faster encryption.

One attempt stopped at the preflight ambient/compiler-or-engine guard before starting a workload; immediate inspection found neither. The empty attempt is recorded separately and excluded. Native `.trace` bundles and full TOCs remain local because TOCs include the inherited environment. The published `time-profile` tables contain target stacks and binary metadata, without that environment.

## Independent call counts

Two separate four-repeat campaigns use the ordinary clients: OS task counters (24 trials), then a partial libc interposer (24). Every trial verifies the same payload and passes. OS CPU converts Mach ticks using the recorded timebase and cross-checks against `ps`. Counters exclude warmup and include connection setup/settle. None of these instrumented timings replace the ordinary performance series.

| AES full-duplex, 512 MiB total | Rust | Xray | Rust / Xray |
| --- | ---: | ---: | ---: |
| Unix syscalls, OS task counter | 68,560 | 27,243 | 2.52× |
| Context switches, OS task counter | 14,248 | 5,954 | 2.39× |
| Socket-write calls, deduplicated libc entries | 27,811 | 9,237 | 3.01× |
| `kevent` libc entries | 19,918 | 5,245 | 3.80× |
| Mean returned bytes per write call | 19,366 | 58,329 | 0.33× |

Rust mostly writes through `sendto`; Xray predominantly uses `writev`. Nested Rust `send`/`sendto` and `recv`/`recvfrom` are not double-counted. Xray's direct `SYS_READV` bypasses libc, so zero intercepted `readv` calls would not mean it does no read syscalls. The total OS Unix counter is complete for its window; libc attribution is deliberately partial.

In the OS-counter duplex series, median user/system CPU is **113.5/198.9 ms** for Rust and **160.6/175.5 ms** for Xray; total-CPU medians are 311.7 and 336.0 ms. Medians of components need not sum to the median total. This corroborates extra Rust kernel work, while again showing that total CPU is not consistently worse. Counts and system time do not prove that all extra syscalls are avoidable.

## Architectural finding and next experiment

The current [relay](../../../../crates/xray-core-rs/src/policy.rs) splits the streams, then polls both copy futures inside one parent task via `tokio::select!`. VMess encryption and decryption for that connection therefore do not execute concurrently. The generic split also serializes access to the combined protocol stream. Pinned Xray's `proxy/vmess/outbound/outbound.go` passes request and response functions to `common/task.Run`, which launches separate goroutines. The local reference source was verified at the pinned commit recorded in [inputs](data/inputs.json).

This is a credible throughput constraint, not a quantified causal explanation of the entire 22–25% gap. A controlled prototype should separate VMess read/write codec state for raw TCP and run the directions independently while retaining bounded buffers. Merely spawning two tasks around the existing generic split would preserve the codec lock and is not a convincing test. More global worker threads would not make the existing single task parallel.

The other concrete target is fewer readiness/event cycles and socket calls per byte. Evaluate that with the same counters, and reject changes that obtain speed by materially growing memory. Do not remove plaintext erasure or weaken padding randomness based on these samples. Keep the existing memory bounds, measure footprint after large exchanges and at idle with 512 held connections, and require small-message latency, backpressure, cancellation, half-close and both-cipher regressions before retaining a change. No buffers or worker defaults are enlarged in this report.

## Reproduction and verification

The archive includes all 72 ordinary trials, 48 counter trials, eight target CPU tables, the rejected preflight record, exact diagnostic harness patch and capture/build sources. Frozen binary identities, symbol-build arguments and the byte-identical restored ordinary release are recorded in [inputs](data/inputs.json). The parser and summarizer are shipped beside the report; no runtime dependency is added.

```sh
python3 docs/benchmarks/results/2026-10-02-v08-duplex-profile/data/verify.py
```

The verifier rehashes every archive member, checks trial completeness/bytes/identities, validates the on-CPU options and reconstructs every published numeric summary. Repeating captures requires macOS Instruments access; the as-run capture launcher and synchronized harness patch are under `investigation/` in the archive. These loopback desktop results do not establish WAN/TUN parity, device energy usage, or physical Apple acceptance.
