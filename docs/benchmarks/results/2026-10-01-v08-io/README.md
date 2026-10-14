# v0.8 record I/O and plaintext-erasure follow-up — Apple M3 Pro

This investigation follows the first ARM AEAD optimization. It tests three
separate hypotheses: write backpressure blocking reads, per-record read calls,
and the cost of erasing delivered plaintext. Memory remains a measured constraint.
The default two CLI workers, record limits, nonce/replay behavior, cryptographic
provider and reference implementations are unchanged.

## Identity and method

Measured runtime: `5e32972976074551aea4ce42e98f5e0dde7159c9`, tree
`3c1993a1b1ce6ba68ea102caa6547346c8ac1c83`. Release executable SHA-256:
`e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab`.
Rust 1.96.0, locked release build, incremental compilation disabled. The SDK
pin is commit `a735aae5e7916f18c0125afa28e509a9ddd48c2c` in xray-rust-mobile.
The host is an Apple M3 Pro (12 cores, 18 GiB), macOS 26.6.2, AC power.

The baseline is the previously optimized runtime `ce6deef3fe1b3f8536c471235dd2a6c003e7e9e5`
(binary `2180631c4187dd3cd85fda27d06c3b98a22f92c0954b841d3a1c13d9bd1beb04`),
not the original software-AEAD implementation. The unchanged harness and pinned
Xray-core v26.7.28 / sing-box 1.13.20 identify the same path as the previous
[CPU report](../2026-09-30-v08-cpu/README.md). Compiler, host and binary/source
identities are retained under `data/`.

The full matrix uses seven profiles, one/eight SOCKS flows, upload/download/
full-duplex/TCP echo/UDP echo, three clients and three fresh-process repeats.
Bulk transfers check 256 MiB per flow and direction. CPU measures client CPU
for the completed bytes, not CPU percentage or battery power. RSS is sampled
at 100 ms and excludes the shared server, driver and kernel socket memory.
Separate paired variants rotate within each fresh common server/repeat.
Compilation, other benchmarks and profiling do not overlap measurements.

## What the controlled experiments establish

1. Both record codecs previously required the entire pending write to drain
   before attempting a read. A stalled outbound direction could therefore
   prevent consuming an available valid response. The fix attempts the write,
   propagates write errors, and allows reading when that write is pending.
   Tests force backpressure and verify no duplicated outgoing bytes. The
   48 paired loopback trials show no material general speedup from this alone;
   this is a progress/correctness fix, not the principal CPU explanation.
2. A shared record buffer reads length/body bytes into the same bounded storage
   and decrypts only the current authenticated frame. It avoids an extra read
   when the next body is already buffered. Its isolated 48 trials show small
   VMess gains and little SS2022 gain while byte-at-a-time erasure remains.
   No blanket syscall-frequency claim is made for all live transports: the
   deterministic coalescence test counts inner reads, not kernel system calls.
3. In locked zeroize 1.8.2, a byte slice is cleared by a volatile byte store per
   byte. After accelerating AEAD this remaining plaintext cleanup is significant.
   The new helper partitions an exclusive slice into aligned `u64` words and
   byte prefix/suffix, and calls the same Zeroize implementation on every part.
   Volatile stores and compiler fences remain; there is no ordinary memset,
   skipped erasure, new allocation, custom cipher or key-cleanup change.
   All `u64` bit patterns are valid and its alignment is provided by
   `align_to_mut`; the tiny unsafe conversion is checked with strict-provenance
   Miri and boundary tests and is included in the canonical Miri job.

The erasure microbenchmark uses a reused 8 KiB buffer, fills then clears it
32768 times, and checks zeroed output. Median of three release runs:
**3575 MiB/s byte stores → 22548 MiB/s word stores (6.3×)**. This isolates erasure;
it is not an end-to-end speedup. A further 72 trials compare old erasure,
word erasure alone, and word erasure plus read-ahead. Both contributions and
intermediate source patches/binary identities are retained in the archive.

## Memory and correctness constraints

The new record buffer is a single lazily grown allocation, rounded by 64 bytes
for variable VMess padding. The prefix budget is 18 bytes for SS2022 and
VMess authenticated lengths, and two bytes for ordinary VMess lengths. This
keeps an ordinary 8192-byte VMess wire record within 8192 bytes of storage,
rather than unnecessarily crossing the allocator size class. The maximum
storage length is 65535 + 16 + 18 bytes, within the accepted wire bounds.

Partial plaintext reads erase exactly the delivered bytes; later ciphertext
is neither decrypted nor exposed prematurely. Compaction only moves unconsumed
ciphertext. Wire/authentication errors poison both stream directions; failed
authentication wipes its input, and full storage is still zeroized on drop. TCP fragmentation,
truncation, cancellation, maximum frames, per-record authentication, UDP
message boundaries and nonce exhaustion remain covered. There is no background
pump, global buffer pool, eager maximum allocation or worker-count increase.

## Results

### Isolating erasure and read-ahead

One download, 256 MiB, three rotating repeats; each cell is **CPU ms / MiB/s**. All variants below include the backpressure fix. The combined variant precedes the final two-byte VMess prefix allocation refinement.

| Profile | Byte erasure, old reads | Word erasure, old reads | Word erasure + read-ahead |
| --- | ---: | ---: | ---: |
| SS2022 AES-128 | 250 / 1221 | 160 / 1899 | 160 / 2098 |
| SS2022 ChaCha20 | 400 / 726 | 350 / 727 | 340 / 735 |
| VMess AES-128 | 310 / 1017 | 230 / 1401 | 210 / 1534 |
| VMess ChaCha20 | 500 / 642 | 370 / 687 | 350 / 693 |

The main additional CPU benefit comes from word erasure. Read-ahead adds a smaller benefit, especially on VMess. The separate 48-trial read-only and 48-trial backpressure experiments remain in the [control summary](data/control-summary.json).

### Paired previous optimized runtime → final runtime

The 144 paired trials include upload, download and full duplex at both one and eight flows for four profiles. Tables are medians of three repeats. Each flow checks 256 MiB per direction. Negative CPU change is better. The baseline already contains the first ARM AEAD/buffer optimization.

#### upload, 1 flow(s)

| Profile | CPU ms, before → after | CPU change | MiB/s, before → after | Speed change | RSS MiB, before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 120 → 130 | +8.3% | 1488 → 1471 | -1.2% | 5.297 → 5.359 |
| SS2022 ChaCha20 | 270 → 270 | +0.0% | 594 → 592 | -0.3% | 5.172 → 5.234 |
| VMess AES-128 | 250 → 250 | +0.0% | 1330 → 1356 | +2.0% | 5.469 → 5.484 |
| VMess ChaCha20 | 310 → 310 | +0.0% | 753 → 746 | -0.9% | 5.406 → 5.500 |

#### download, 1 flow(s)

| Profile | CPU ms, before → after | CPU change | MiB/s, before → after | Speed change | RSS MiB, before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 230 → 160 | -30.4% | 1292 → 2082 | +61.1% | 5.312 → 5.375 |
| SS2022 ChaCha20 | 390 → 340 | -12.8% | 733 → 738 | +0.8% | 5.234 → 5.281 |
| VMess AES-128 | 310 → 210 | -32.3% | 1029 → 1563 | +51.8% | 5.266 → 5.328 |
| VMess ChaCha20 | 500 → 360 | -28.0% | 634 → 677 | +6.6% | 5.266 → 5.281 |

#### full-duplex, 1 flow(s)

| Profile | CPU ms, before → after | CPU change | MiB/s, before → after | Speed change | RSS MiB, before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 390 → 290 | -25.6% | 1567 → 2139 | +36.4% | 5.484 → 5.531 |
| SS2022 ChaCha20 | 680 → 610 | -10.3% | 803 → 981 | +22.2% | 5.391 → 5.422 |
| VMess AES-128 | 540 → 440 | -18.5% | 1230 → 1543 | +25.5% | 5.469 → 5.531 |
| VMess ChaCha20 | 840 → 710 | -15.5% | 714 → 757 | +5.9% | 5.453 → 5.484 |

#### upload, 8 flow(s)

| Profile | CPU ms, before → after | CPU change | MiB/s, before → after | Speed change | RSS MiB, before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 1540 → 1550 | +0.6% | 1778 → 1765 | -0.8% | 6.594 → 6.641 |
| SS2022 ChaCha20 | 2440 → 2380 | -2.5% | 1609 → 1662 | +3.3% | 6.562 → 6.562 |
| VMess AES-128 | 1350 → 1350 | +0.0% | 3012 → 3010 | -0.1% | 6.828 → 6.797 |
| VMess ChaCha20 | 2450 → 2410 | -1.6% | 1642 → 1683 | +2.5% | 6.734 → 6.734 |

#### download, 8 flow(s)

| Profile | CPU ms, before → after | CPU change | MiB/s, before → after | Speed change | RSS MiB, before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 1570 → 1390 | -11.5% | 2573 → 2525 | -1.8% | 6.422 → 6.547 |
| SS2022 ChaCha20 | 2490 → 1840 | -26.1% | 1645 → 2191 | +33.2% | 6.328 → 6.406 |
| VMess AES-128 | 1900 → 1530 | -19.5% | 2149 → 2282 | +6.2% | 5.703 → 5.703 |
| VMess ChaCha20 | 2900 → 2280 | -21.4% | 1397 → 1767 | +26.5% | 5.719 → 5.688 |

#### full-duplex, 8 flow(s)

| Profile | CPU ms, before → after | CPU change | MiB/s, before → after | Speed change | RSS MiB, before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 3310 → 2690 | -18.7% | 1567 → 1674 | +6.8% | 7.453 → 7.719 |
| SS2022 ChaCha20 | 5030 → 4550 | -9.5% | 1562 → 1486 | -4.8% | 7.469 → 7.453 |
| VMess AES-128 | 3610 → 3140 | -13.0% | 1681 → 1687 | +0.4% | 6.875 → 6.891 |
| VMess ChaCha20 | 5460 → 4980 | -8.8% | 1484 → 1601 | +7.8% | 6.844 → 6.906 |

Upload is a useful control: delivered-plaintext erasure and record read-ahead primarily affect downloads and full duplex. Upload CPU is broadly unchanged; small 10 ms differences are at the process-counter granularity.

### SS2022 ChaCha eight-flow duplex confirmation

The first three-repeat group had a −4.8% throughput point difference, with overlapping ranges (baseline 1502–1665 MiB/s; final 1467–1786 MiB/s). It remains in the primary table. A separate fresh five-repeat confirmation was collected after the full matrix; it does not replace those samples.

| Version | Throughput MiB/s, median [min, max] | CPU ms, median [min, max] | RSS MiB, median [min, max] |
| --- | ---: | ---: | ---: |
| baseline | 1536.188 [1376.239, 1644.849] | 5160.000 [4890.000, 5370.000] | 7.422 [7.297, 7.688] |
| candidate | 1544.626 [1401.522, 1743.687] | 4640.000 [4520.000, 4830.000] | 7.500 [7.469, 7.531] |

The confirmation has essentially unchanged median throughput (+0.5%) with
10.1% lower CPU. The broad overlapping ranges do not establish a stable speed
regression or a speed gain for this case. Both batches remain visible; no
sample is dropped to improve the result.

### RSS scaling with held connections

Each fresh client is sampled at 0, 32, 128 and 512 held TCP connections. Every connection first echoes 8192 checked bytes each way. Each point uses five RSS samples after settling; the table is the median across three clients. These are retained-RSS observations, not saturated-transfer peaks. No throughput is inferred from the Python memory driver.

| Profile | 0 connections | 32 connections | 128 connections | 512 connections |
| --- | ---: | ---: | ---: | ---: |
| SS2022 AES-128 | 4.188 → 4.266 | 6.891 → 6.938 | 11.094 → 11.141 | 27.656 → 27.734 |
| SS2022 ChaCha20 | 4.172 → 4.266 | 6.828 → 6.859 | 10.984 → 11.016 | 27.562 → 27.656 |
| VMess AES-128 | 4.172 → 4.250 | 7.047 → 7.141 | 11.297 → 11.344 | 28.234 → 28.266 |
| VMess ChaCha20 | 4.172 → 4.250 | 7.062 → 7.109 | 11.297 → 11.344 | 28.281 → 28.297 |

All cells are MiB, baseline → final. At 512 connections the measured extra RSS is 0.016–0.094 MiB. The fixed struct fields and bounded storage have a small cost; reuse does not mean zero additional memory. Active eight-flow RSS differences are shown separately above.

### Full clients on the final runtime

**629/630 primary trials pass; xray-rust passes all 210 of its trials.**
The single failure is sing-box, Trojan UDP, eight flows, repeat 1: the workload
hit the 120-second harness timeout. Client stderr is empty, process cleanup
passes, and no compiler/observer interference is detected. Its next two primary
repeats pass. A separate fresh five-repeat confirmation of the same case, with
all three clients, passes **15/15**; its results and selection script are retained.
The cause of the original timeout is unresolved. It is not replaced by the
confirmation and is not attributed conclusively to the client or driver.
Consequently the primary sing-box comparison for that case is incomplete.
RSS is lower in all **139/139 available complete case/reference comparisons**;
the missing comparison is not counted as a pass.

SS2022/VMess meet **56/72 CPU and 26/72 throughput** Mac point targets,
compared with 45/72 and 18/72 in the prior optimized-runtime report.
The paired controls above isolate our code changes; cross-campaign scoreboard
counts alone are not causal proof or confidence-interval claims.

 The table counts point targets only; three samples and their confidence intervals do not establish universal parity. RSS requires a strictly lower value; the Mac policy allows up to 3% lower throughput or higher CPU. Echo is excluded from bulk counts.

| Metric scope | Meets strict point target | Meets Mac point target | Comparisons |
| --- | ---: | ---: | ---: |
| all_rss | 139 | 139 | 139 |
| ss2022_vmess_bulk_cpu_ms | 55 | 56 | 72 |
| ss2022_vmess_bulk_throughput_mib_s | 22 | 26 | 72 |
| trojan_bulk_cpu_ms | 12 | 12 | 12 |
| trojan_bulk_throughput_mib_s | 10 | 12 | 12 |

**Overall parity remains `not_met`.** All workloads, raw repeats, ranges and ratio intervals are in [all metrics](all-metrics.md), [point deficits](point-deficits.md), and the [full summary](data/summary-mac-3pct.json). The slices below help distinguish one-flow limitations from aggregate throughput. Each cell is **MiB/s / workload CPU ms / sampled peak RSS MiB**.

#### Download, 1 flow(s)

| Profile | xray-rust | Xray-core | sing-box |
| --- | ---: | ---: | ---: |
| Trojan TLS | 1478 / 210 / 7.23 | 1372 / 230 / 32.41 | 1522 / 220 / 27.02 |
| SS2022 AES-128 | 1997 / 160 / 5.42 | 1807 / 170 / 32.11 | 2268 / 110 / 24.67 |
| SS2022 AES-256 | 1767 / 180 / 5.38 | 1666 / 180 / 32.48 | 2087 / 120 / 24.55 |
| SS2022 ChaCha20 | 745 / 330 / 5.30 | 694 / 430 / 31.70 | 735 / 390 / 24.64 |
| VMess AES-128 | 1487 / 220 / 5.31 | 2140 / 120 / 32.70 | 1153 / 290 / 26.78 |
| VMess ChaCha20 | 685 / 350 / 5.31 | 713 / 390 / 32.66 | 554 / 580 / 26.70 |
| VMess auto | 1452 / 220 / 5.31 | 2126 / 120 / 32.84 | 1172 / 290 / 26.81 |

#### Download, 8 flow(s)

| Profile | xray-rust | Xray-core | sing-box |
| --- | ---: | ---: | ---: |
| Trojan TLS | 1982 / 2030 / 8.41 | 1546 / 2350 / 36.69 | 1485 / 2440 / 30.78 |
| SS2022 AES-128 | 2625 / 1330 / 6.56 | 2225 / 2080 / 38.88 | 2126 / 1940 / 30.58 |
| SS2022 AES-256 | 2424 / 1360 / 6.50 | 2136 / 2160 / 39.05 | 2081 / 2100 / 30.66 |
| SS2022 ChaCha20 | 2100 / 1920 / 6.39 | 2450 / 3790 / 40.97 | 2501 / 3490 / 29.95 |
| VMess AES-128 | 2215 / 1600 / 5.73 | 2218 / 2180 / 37.39 | 1841 / 3030 / 29.41 |
| VMess ChaCha20 | 1755 / 2290 / 5.72 | 2501 / 3650 / 40.77 | 1820 / 5210 / 31.19 |
| VMess auto | 2205 / 1570 / 5.72 | 2235 / 2130 / 36.88 | 1918 / 3110 / 30.30 |


## Validation and reproducibility

- `cargo test --locked --offline -p xray-proxy --all-targets`: **128 tests pass**,
  including backpressure, partial erasure, later-record authentication, bounded
  compaction, fragmentation/cancellation and the 8 KiB VMess storage check.
  The custom microbenchmark's debug invocation is a smoke check only.
- Proxy all-target clippy with `-D warnings`, formatting and the `fuzzing`
  feature check pass. Strict-provenance Miri passes the erasure helper across
  all 32 starting offsets and 260 partial lengths; the test is now included in
  the canonical host-hardening job.
- Complete [core CI at 5e32972](https://github.com/aimalygin/xray-rust/actions/runs/36899854548)
  passes Rust, pinned/independent interoperability, Miri/Loom/ASan, fuzz smoke,
  controlled-network, release interop, supply-chain, secrets and Apple/Android
  builds. This is automated validation, not physical-device or release acceptance.
- [SDK CI at a735aae](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36899932350)
  passes for the new pin. Canonical source-sync/core verification passes;
  ABI 1.8 and version 0.8.0-rc.1 are unchanged, artifact locks remain unprepared.
- A post-commit locked release rebuild gives exactly the measured executable
  digest. Later report edits do not change the measured runtime or mobile pin.
- **1036 archive members** are individually rehashed and both full summaries are
  independently recomputed from extracted numeric results with exact equality.
  [Control reconstruction](data/summarize-controls.py) checks hashes, identities,
  cleanup and declared repeats before deriving medians/ranges. The
  [verification record](data/verification.json) and source/build/test/CI records
  remain in the report and archive.

All numeric raw results, source snapshots, successful/failed statuses and
quality/cleanup checks are retained in the verified archive. Generated fixture
credentials and binaries remain local. The strict and 3% comparison summaries
are separately reproducible; three repeats and coarse CPU counters do not
justify universal claims or treating small point differences as certain.

Reproduction from the repository root (use fresh output paths and frozen
inputs; do not compile or run other heavy loads during measurement):

```sh
CARGO_INCREMENTAL=0 cargo build --locked --release -p xray-cli
CARGO_INCREMENTAL=0 cargo bench --locked -p xray-proxy --bench record_erasure --no-run
# Run the release record_erasure executable three times:
/absolute/record_erasure
python3 scripts/run-v08-protocol-comparison.py \
  --inputs /absolute/frozen/inputs.json --output /absolute/new/full --repeats 3
python3 scripts/run-v08-cpu-controls.py \
  --binary baseline=/absolute/baseline --binary candidate=/absolute/candidate \
  --reference /absolute/xray --harness /absolute/harness \
  --output /absolute/new/final-controls --repeats 3
python3 scripts/run-v08-cpu-controls.py \
  --binary baseline=/absolute/baseline --binary candidate=/absolute/candidate \
  --reference /absolute/xray --harness /absolute/harness \
  --profile ss2022-chacha20 --traffic full-duplex --flows 8 --repeats 5 \
  --output /absolute/new/duplex-confirmation
# held-memory.py is included in measurements.tar.gz:
python3 /absolute/extracted/investigation/held-memory.py \
  --repo /absolute/xray-rust --baseline /absolute/baseline \
  --candidate /absolute/candidate --reference /absolute/xray \
  --output /absolute/new/held-memory
python3 docs/benchmarks/results/2026-10-01-v08-io/data/summarize-controls.py \
  docs/benchmarks/results/2026-10-01-v08-io --output /absolute/control-summary.json
```

The separate failed-case confirmation is reproducible when the primary matrix
contains failed trials (the wrapper only filters case selection):

```sh
python3 docs/benchmarks/results/2026-10-01-v08-io/data/confirm-failures.py \
  /absolute/xray-rust /absolute/new/full/manifest.json \
  --inputs /absolute/frozen/inputs.json --output /absolute/new/failure-confirmation \
  --repeats 5
```

The archived stage patches are against `c6c1c90a6214d1d7550c8fd2c9352e96ee12cd70`.
They record diagnostic builds, not separately supported releases. The word-only
patch retains an unused experimental record_buffer.rs file that is not imported
or compiled in that variant. Source and executable hashes identify each stage;
the collector commit is not the engine's source identity. Reference preparation,
exact profiles and harness build identity are described in
[v08-performance.md](../../../v08-performance.md).

## Remaining scope

The experiments identify avoidable implementation costs, without evidence
of an unavoidable Rust or Tokio limitation. Plaintext erasure was the largest
additional cost isolated in this round; coalescing record reads provides a
smaller complementary benefit. Removing read/write coupling addresses progress
under backpressure but is not a demonstrated general speedup on this loopback.

- **Remaining measured differences:** see the full per-case deficit table.
  VMess AES/auto one-flow download uses 220 ms versus Xray's 120 ms (+83%),
  while beating sing-box's 290 ms. SS2022 AES one-flow download still uses
  45–50% more CPU than sing-box. VMess ChaCha one-flow full duplex reaches
  755 versus Xray's 1428 MiB/s (−47%). Eight-flow ChaCha downloads trail the
  faster reference by 16–30% while using less CPU. Startup/echo-tail differences
  and the incomplete primary reference group also prevent a general parity claim.
- **Scheduling and memory:** the prior worker-count experiment already showed
  a CPU/RSS cost for more parallel workers. The two-worker CLI default remains;
  this round does not buy throughput with more workers or larger buffer pools.
- **Protocol work:** VMess masking/padding, small records, AEAD and the 65536
  nonce-counter bound still apply. Changing framing or reconnect semantics
  would be a separate compatibility change. The remaining copies, wakeups and
  record work need targeted measurements before claiming another root cause.
- **Coverage:** SS2022 native XChaCha UDP still uses its existing backend; UDP
  here measures echo latency, not saturation. CPU per completed workload is not
  battery consumption. x86, WAN, SDK/device and TUN competitor performance need
  separate evidence.

These are macOS CLI host measurements. The unchanged FFI 2–6-worker policy,
physical Apple/Android performance, energy use, WAN conditions and TUN competitor
parity need their own evidence. Physical Apple testing remains deferred by the
owner; Android hardware is unavailable. No tag, release or accepted device
archive is created, and old artifact evidence is not relabeled for this source.
