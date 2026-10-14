# Independent VMess read/write states — Apple M3 Pro

The split-codec experiment improves **single-flow AES duplex speed by 15–20%** and **single-flow ChaCha speed by 58–59%, with 14% less CPU**. Memory cost is modest: **0.55–0.91 MiB at 512 held connections**. However, two final series show **4.7–10.8% lower eight-flow AES duplex speed**, with essentially unchanged CPU. The unconditional parallel relay is therefore **not retained**: production runtime `9198a8f` and SDK pin `7b84921` remain unchanged. The complete tested implementation and evidence are preserved for a follow-up that limits parallel work under contention; that policy has not been tested here.

## Implementation tested

The [complete shared-codec prototype](data/shared-codec.patch) moves the existing response and request state into independent halves, without duplicating encryption, parsing or record buffers. The combined stream and independent halves share the same codec implementation. Raw TCP uses native owned socket halves; two relay tasks can execute encryption and decryption concurrently on the existing two Tokio workers. A parent joins both directions and aborts/joins the peer on error, explicit close or idle timeout. Normal write half-close lets the response continue.

Pending writes retain their allocation and partial-write cursor. The independent writer makes an immediate nonblocking drain attempt, so a short request need not wait for the relay's flush timer. Previously buffered sniffed payload is flushed before waiting for additional input. An atomic monotonic activity timestamp avoids waking the parent after every copied chunk, while retaining the last-activity idle deadline. No cipher, authentication, padding randomness or plaintext erasure is weakened.

Buffer limits stay unchanged: two encoded write records within 16 KiB; up to four output records with a byte budget below 32 KiB; 16 KiB read-ahead only after 64 KiB of authenticated TCP response data; the same adaptive relay buffers and caps. The active experiment is limited to **SOCKS → direct VMess over raw TCP**. HTTP, TUN, TLS, other carriers, native UDP, Mux and chained outbounds do not use the parallel relay. Their combined codec is still covered by regression/interop tests, but this is not evidence of faster TUN or mobile SDKs.

## Paired ordinary controls

Frozen baseline runtime `9198a8f` is compared with the frozen shared-codec release (v4, SHA-256 in [inputs](data/inputs.json)). Compilation, tests, profiling and archive work do not overlap any measurement campaign. Both clients use the same pinned Xray server, ordinary uninstrumented harness, wire settings and verified payload. Each bulk flow transfers 256 MiB per active direction: 512 MiB total for one duplex connection, 4 GiB for eight. CPU is process CPU per complete workload in milliseconds, using 10 ms-quantized `ps` accounting. Speed is total MiB/s across both directions.

The broad matrix contains AES/ChaCha × upload/download/duplex/1 KiB request-response × 1/8 connections × two clients × four repeats (128 successful trials). A separate six-repeat duplex confirmation adds 48 trials. Pair order alternates AB/BA; every client occupies every position equally. The reusable paired collector's old rotate-then-reverse logic cancelled this alternation for two clients; this investigation uses the corrected order throughout, with order checks in the verifier. Earlier reports retain their as-run order and are not relabelled balanced.

| Series / cipher / connections | CPU ms, baseline → split | Speed MiB/s, baseline → split |
| --- | ---: | ---: |
| Broad controls (4 repeats) / AES / 1 | 310 → 310 (+0.0%) | 2,137 → 2,560 (+19.8%) |
| Broad controls (4 repeats) / AES / 8 | 2,515 → 2,520 (+0.2%) | 2,012 → 1,795 (-10.8%) |
| Broad controls (4 repeats) / ChaCha / 1 | 590 → 510 (-13.6%) | 909 → 1,438 (+58.2%) |
| Broad controls (4 repeats) / ChaCha / 8 | 4,180 → 3,975 (-4.9%) | 1,931 → 2,042 (+5.7%) |
| Confirmation (6 repeats) / AES / 1 | 310 → 305 (-1.6%) | 2,127 → 2,453 (+15.4%) |
| Confirmation (6 repeats) / AES / 8 | 2,390 → 2,420 (+1.3%) | 1,959 → 1,867 (-4.7%) |
| Confirmation (6 repeats) / ChaCha / 1 | 590 → 510 (-13.6%) | 913 → 1,449 (+58.8%) |
| Confirmation (6 repeats) / ChaCha / 8 | 3,970 → 3,970 (+0.0%) | 2,054 → 2,060 (+0.3%) |

These are medians of complete repeated workloads, not a guarantee or a confidence interval. All ranges and individual values are retained in [the reconstructed summary](data/summary.json). The broad controls show little one-direction benefit: single AES upload +1.3% speed / −3.0% CPU, download effectively unchanged; single ChaCha upload +1.5% / −4.0%, download −0.4% / −3.2%. AES eight-flow download is 3.7% slower with 0.8% more CPU. Short-request tails are mixed: single ChaCha p95 is 246.5 → 253 µs and p99 619 → 702 µs; other p95 medians improve. Small CPU percentage changes can be just one accounting quantum.

Three earlier prototypes are preserved separately: v1 separates state/tasks with a progress channel; v2 also flushes buffered initial payload; v3 uses the atomic activity clock; v4 removes duplicated codec code. The one-flow AES speed improvement appears in all of them, but CPU varies across series. In particular, v2's +9% AES CPU in the broad matrix does not repeat in the three-way baseline/v2/v3 campaign. This does not prove that the channel alone caused the earlier CPU result. Prototype results are not substituted for v4 results.

## Fresh reference comparison

Pinned Xray-core v26.7.28 and sing-box v1.13.20, unchanged from earlier reports, are measured against v4 in six balanced permutations for each of four duplex cases: 72 successful trials. All three clients use the same workload and server. Cells are CPU ms / speed MiB/s / peak RSS MiB; RSS is distinct from physical footprint.

| Cipher / connections | Split Rust | Xray-core | sing-box |
| --- | ---: | ---: | ---: |
| AES / 1 | 305 / 2,480 / 5.84 | 270 / 2,683 / 33.68 | 400 / 1,848 / 27.64 |
| AES / 8 | 2,515 / 1,712 / 7.40 | 3,125 / 1,779 / 37.78 | 3,830 / 1,591 / 32.31 |
| ChaCha / 1 | 520 / 1,440 / 5.83 | 720 / 1,435 / 34.63 | 970 / 1,120 / 27.88 |
| ChaCha / 8 | 3,985 / 2,031 / 7.48 | 7,425 / 2,715 / 48.66 | 8,575 / 1,668 / 33.17 |

For one AES duplex connection, split Rust is 7.6% slower than Xray and uses 13.0% more CPU in this series; the previous ordinary baseline report found a 22–25% speed deficit. This is not a claim that subtracting percentages across different sessions isolates one cause. The paired controls above establish the change's effect more directly. Nor does this four-case comparison establish overall protocol parity.

## Held memory and resume

Two balanced repetitions per cipher/client hold 512 connections, warm each with either 1 MiB or 8 KiB, then perform two 11-second idle/resume cycles. Each cycle verifies a 1 KiB first request and another warm-sized exchange on the same connections. Sixteen v4 memory clients and sixteen earlier v2 clients pass. The macOS collector records physical footprint through the SDK's 96-byte `rusage_info_v0` structure, alongside RSS. The table shows footprint MiB for baseline → split, with the increment in parentheses.

| Warm exchange / cipher | After warmup | After first resume | After second resume |
| --- | ---: | ---: | ---: |
| 1 MiB / AES | 105.37 → 106.00 (+0.63) | 105.38 → 106.00 (+0.62) | 105.38 → 106.00 (+0.62) |
| 1 MiB / ChaCha | 105.18 → 105.75 (+0.57) | 105.18 → 105.75 (+0.57) | 105.18 → 105.75 (+0.57) |
| 8 KiB / AES | 24.72 → 25.27 (+0.55) | 40.48 → 41.39 (+0.91) | 40.86 → 41.44 (+0.58) |
| 8 KiB / ChaCha | 24.71 → 25.27 (+0.55) | 40.52 → 41.30 (+0.78) | 40.68 → 41.38 (+0.70) |

The v4 increment is about 0.55–0.91 MiB for the entire 512-connection process across warm/idle/resume phases, roughly 1.1–1.8 KiB per connection. Large-transfer footprint stays stable after both resumes. In the 8 KiB test, both clients grow from about 25 to 41 MiB after repeated bursts; the split does not eliminate existing adaptive-buffer/allocator growth. Idle CPU is quantized: phase medians are zero except 5 ms for split AES's first small-exchange idle (samples 0 and 10 ms). This is not a device battery measurement. Resume p95 values and all intermediate RSS/footprint samples are retained; Python echo timings are diagnostic and do not replace the Rust bulk/latency harness.

## Validation and evidence

The v4 shared-codec prototype passes 142 protocol tests, 498 core unit tests (two manual tests ignored), Clippy with warnings denied, formatting and eight live VMess tests against the pinned Xray/sing-box binaries, including HTTP, UDP, TUN, accounting and close. New tests exercise blocked writes while reading, authenticated-prefix/deferred-error behavior and erasure, small-write progress, partial-write resumption without duplicate ciphertext, half-close, traffic accounting, timeout/activity from either direction, external cancellation and flushing previously buffered payload.

The archive contains **460 successful ordinary trials and 32 held-memory clients**, all four exact source patches and frozen binary identities, collectors and validation logs. An initial pilot could not execute a copied baseline because its executable mode was missing; it failed before payload, is archived separately, and contributes no measurement. A first sandboxed core test attempt failed local socket binds; the unsandboxed rerun passes and both logs are preserved. Generated credentials/configurations, executables and inherited environments are not published.

The production source is restored, and its ordinary release rebuild is byte-identical to the frozen baseline; [restoration metadata](data/restored-runtime.json) records the digest. Only two verification fixes are retained alongside the report: balanced paired-client order (11 collector tests pass), and a negative Trojan test that accepts authentication rejection during either the write or the read. The latter fixes the [previous Linux CI failure](https://github.com/aimalygin/xray-rust/actions/runs/37031950337/job/110920888242), where sing-box reset the connection before the payload write completed. Both Trojan tests pass against each pinned reference; runtime authentication behavior is unchanged.

```sh
python3 docs/benchmarks/results/2026-10-02-v08-split/data/verify.py
```

The verifier rehashes every archive member, checks complete case/repeat sets, payload totals, frozen client identities, absence of leftover processes or detected compiler/observer failures, balanced order and both resume cycles, and reconstructs all summaries. To repeat workloads, apply a variant patch to its recorded base commit, build with the recorded compiler/arguments and rerun the archived collectors with local paths. These loopback desktop results do not establish WAN/TUN performance, mobile memory acceptance or physical-device energy usage.
