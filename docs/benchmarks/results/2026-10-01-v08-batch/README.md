# Bounded VMess receive batching — Apple M3 Pro

Runtime `1804e17890baf4c3a587fbd86d6a17a0787ce9dd`, tree `8501825d7a40170ca192269b9ec7657fbb721663`;
release executable SHA-256 `784ce279f375de47332cfb3efa7dd90905767fdd226f8cf5364f27263eb3d937`.
SDK commit `a67a60c52f82de8d77b175ad3246ca2b08a18b80` pins this exact runtime. The preceding runtime
is `fdc0dad1aa1ffe39d3621008ab66512b30ccf452`, already optimized for accelerated
AEAD, record I/O, erasure and relay allocation; see the
[previous report](../2026-10-01-v08-relay/README.md).
The baseline source `00f660b` adds only the previously documented test/report fixes.
The normal committed release rebuild is byte-identical to the measured candidate.

Rust 1.96.0, locked offline release build, incremental compilation disabled.
M3 Pro, 12 cores, 18 GiB, macOS 26.6.2, AC power. The common harness, Xray-core
v26.7.28 and sing-box 1.13.20 remain frozen at the previous pins; exact source,
module and binary identities are in [inputs](data/inputs.json).
These are desktop SOCKS loopback results, not physical-device, energy or WAN results.

## Decision and mechanism

Keep **at most two available VMess TCP records per read**. Previously each
successful read returned at most one record fragment. The new reader can deliver
a second authenticated record into the caller's existing buffer, reducing relay
iterations and writes when data is ready. It immediately returns bytes already
obtained when the next record would block; there is no batching delay. The poll
budget is bounded, UDP still delivers one whole datagram, and every record is
authenticated before delivery. Plaintext is erased as it is copied, including
partial reads. If a later record fails after progress, the valid prefix is returned
first and the original error is delivered on the next read; the failed stream
cannot resume writes. Keys, nonces, crypto providers, record limits, worker counts
and relay buffer caps are unchanged.

The 16-record experiment improved AES one-flow download from 1591 to 2104 MiB/s
and reduced CPU from 210 to 150 ms, but increased settled RSS by **33–41 MiB at
512 connections after 128 KiB exchanges**. It also had a one-flow AES upload
slowdown. It was rejected. No new payload buffer is allocated by either reader;
the cost comes with the shared relay growing its buffer more aggressively. Two
records retain a smaller, measured memory tradeoff.

Nine symbol-enabled native `sample` traces of the baseline show hardware AES
(`aesv8_gcm_8x_enc_128` / `aesv8_gcm_8x_dec_128`) and socket, entropy, copying and
erasure paths. Their top-of-stack counts are retained in
[the diagnostic summary](data/profile-summary.json). These are wall samples
including waiting threads, with small entries omitted by `sample`; they are not
CPU percentages. Instrumented timings are excluded. The initial oversized 1 GiB
profiling probe failed with a broken pipe and remains archived as a failed
probe; its exact cause was not established. Nine bounded 375 MiB probes passed.
The controlled normal-release measurements below determine the decision.

## Paired controls

Five campaigns contain **280 fresh-client trials**: 72 for the rejected 16-record
variant, 72 for two records, 48 latency/UDP trials, 60 independent five-repeat
confirmations and 28 seven-repeat upload checks. Client order rotates; both
variants use the identical fixture and verified payload. Each bulk flow transfers
256 MiB per direction, with one or eight flows. CPU means client CPU consumed for
completed work, not utilization. Startup CPU is separate; CPU counter granularity
is 10 ms. RSS samples are process RSS, excluding driver, server and kernel memory.
This interactive desktop is not a CPU-isolated host. All samples and ranges,
including conflicting upload results, are in [control data](data/control-summary.json).
Compilation, tests, profiling and archive generation do not overlap accepted
performance measurements.

Initial two-record controls (three repeats):

| Profile / flows / workload | CPU ms, baseline → candidate | CPU change | MiB/s, baseline → candidate | Speed change |
| --- | ---: | ---: | ---: | ---: |
| vmess-aes128 / download-1 | 210 → 190 | -9.5% | 1547 → 1701 | +9.9% |
| vmess-aes128 / download-8 | 1530 → 1330 | -13.1% | 2405 → 2738 | +13.9% |
| vmess-aes128 / full-duplex-1 | 440 → 420 | -4.5% | 1516 → 1613 | +6.4% |
| vmess-aes128 / full-duplex-8 | 3270 → 3060 | -6.4% | 1636 → 1736 | +6.1% |
| vmess-aes128 / upload-1 | 250 → 250 | +0.0% | 1319 → 1341 | +1.7% |
| vmess-aes128 / upload-8 | 1480 → 1370 | -7.4% | 2704 → 2982 | +10.3% |
| vmess-chacha20 / download-1 | 360 → 340 | -5.6% | 674 → 682 | +1.2% |
| vmess-chacha20 / download-8 | 2240 → 2180 | -2.7% | 1800 → 1823 | +1.3% |
| vmess-chacha20 / full-duplex-1 | 670 → 660 | -1.5% | 803 → 797 | -0.8% |
| vmess-chacha20 / full-duplex-8 | 4740 → 4610 | -2.7% | 1655 → 1714 | +3.6% |
| vmess-chacha20 / upload-1 | 270 → 280 | +3.7% | 754 → 750 | -0.6% |
| vmess-chacha20 / upload-8 | 2180 → 2240 | +2.8% | 1857 → 1799 | -3.1% |

Independent five-repeat confirmation:

| Profile / flows / workload | CPU ms, baseline → candidate | CPU change | MiB/s, baseline → candidate | Speed change |
| --- | ---: | ---: | ---: | ---: |
| vmess-aes128 / download-1 | 230 → 190 | -17.4% | 1384 → 1546 | +11.7% |
| vmess-aes128 / download-8 | 1540 → 1240 | -19.5% | 2294 → 2881 | +25.6% |
| vmess-aes128 / upload-1 | 250 → 250 | +0.0% | 1231 → 1229 | -0.1% |
| vmess-aes128 / upload-8 | 1880 → 1960 | +4.3% | 2091 → 2005 | -4.1% |
| vmess-chacha20 / upload-1 | 270 → 260 | -3.7% | 751 → 769 | +2.4% |
| vmess-chacha20 / upload-8 | 2260 → 2170 | -4.0% | 1778 → 1873 | +5.3% |

AES download improves in both independent campaigns: one-flow speed +9.9% and +11.7%, eight-flow speed +13.9% and +25.6%; CPU also falls in both. Upload is less stable. The five-repeat AES eight-flow point regressed 4.1% in speed after improving in the first controls. A further seven-repeat check was run to investigate that concern, retaining every original point:

| Profile / flows / workload | CPU ms, baseline → candidate | CPU change | MiB/s, baseline → candidate | Speed change |
| --- | ---: | ---: | ---: | ---: |
| vmess-aes128 / upload-8 | 1720 → 1500 | -12.8% | 2049 → 2660 | +29.8% |
| vmess-chacha20 / upload-8 | 2310 → 2340 | +1.3% | 1749 → 1708 | -2.3% |

The AES upload slowdown did not reproduce. Its seven-repeat throughput ranges are broad and overlap (baseline 1970–2719, candidate 1973–2728 MiB/s); the positive median is not treated as a reliable upload improvement. ChaCha eight-flow upload changes sign between campaigns as well; the final point is −2.3% in speed and +1.3% CPU. The repeatable result supporting this change is AES download, with a bounded memory cost, rather than uniform gains across traffic.

## Memory after short and long transfers

42 fresh clients hold 0, 32, 128 and 512 verified TCP connections. Each connection first echoes 8 KiB, 128 KiB or 1 MiB in each direction. Three rotating repeats, five RSS samples per point. This includes memory retained after bulk activity, which the previous 8 KiB-only check did not characterize. These are settled RSS points, not saturation peaks or exact heap allocations.

| Warmup per connection / profile | Baseline at 512, MiB | Two records, MiB | Delta | 16 records, MiB |
| --- | ---: | ---: | ---: | ---: |
| 8 KiB / vmess-aes128 | 27.891 | 27.828 | -0.062 MiB (-0.2%) | — |
| 8 KiB / vmess-chacha20 | 27.906 | 27.812 | -0.094 MiB (-0.3%) | — |
| 128 KiB / vmess-aes128 | 88.078 | 90.219 | +2.141 MiB (+2.4%) | 121.328 |
| 128 KiB / vmess-chacha20 | 88.312 | 92.344 | +4.031 MiB (+4.6%) | 128.922 |
| 1 MiB / vmess-aes128 | 88.531 | 92.250 | +3.719 MiB (+4.2%) | — |
| 1 MiB / vmess-chacha20 | 88.422 | 92.234 | +3.812 MiB (+4.3%) | — |

Small exchanges show no higher median RSS. After 1 MiB exchanges, the retained variant adds 3.7–3.8 MiB at 512 connections (about 4.2–4.3%). This is a real tradeoff, not a claim of free batching. Adaptive buffer growth and OS RSS make individual runs variable: one AES candidate point was 70.33 MiB versus the other two near 92 MiB; its cause was not established and it is retained. All four connection counts and every sample remain in the data.

## Short-request latency

Three repeats per case; median of per-trial latency statistics, microseconds. TCP median changes are 0–3 µs. Tail points are mixed and are not claimed to improve uniformly. UDP packet semantics are unchanged.

| Profile / workload / flows | Median, baseline → candidate | p95 | p99 |
| --- | ---: | ---: | ---: |
| vmess-aes128 / tcp-latency-1 | 79 → 78 | 246 → 233 | 385 → 332 |
| vmess-aes128 / tcp-latency-8 | 135 → 138 | 318 → 291 | 495 → 463 |
| vmess-aes128 / udp-1 | 104 → 107 | 321 → 294 | 456 → 516 |
| vmess-aes128 / udp-8 | 210 → 210 | 370 → 373 | 770 → 808 |
| vmess-chacha20 / tcp-latency-1 | 80 → 81 | 238 → 230 | 309 → 330 |
| vmess-chacha20 / tcp-latency-8 | 139 → 138 | 296 → 301 | 510 → 492 |
| vmess-chacha20 / udp-1 | 106 → 106 | 307 → 323 | 450 → 508 |
| vmess-chacha20 / udp-8 | 216 → 219 | 381 → 444 | 814 → 629 |

## Frozen three-client VMess comparison

270/270 trials pass: AES, ChaCha and auto × five workloads × one/eight flows × three clients × three repeats. All 90 Rust trials pass. Whole-case selection preserves original client rotation and all attempts; a complete case may be retried only for observed compiler interference. No result is selected by performance. This new comparison covers VMess; the preceding report retains the full earlier Trojan/SS2022/VMess matrix at its own runtime identity.

| AES, one flow | Rust CPU ms / MiB/s / RSS MiB | Xray-core | sing-box |
| --- | ---: | ---: | ---: |
| upload | 250 / 1279 / 5.34 | 180 / 1733 / 32.77 | 190 / 1570 / 26.78 |
| download | 200 / 1606 / 5.22 | 130 / 2042 / 32.58 | 310 / 1098 / 26.44 |
| full-duplex | 420 / 1503 / 5.41 | 330 / 2346 / 33.23 | 460 / 1664 / 27.14 |

RSS is strictly lower in **60/60** VMess case/reference comparisons. Under the explicit 3% desktop allowance, 27/36 bulk CPU and 15/36 throughput point targets are met. Overall measured parity status: **not_met**. These point counts do not remove three-repeat uncertainty or establish full-product parity. See [all medians](comparison.csv), [strict results](data/summary-strict.json) and [3% results](data/summary-mac-3pct.json).

## Validation and reproduction

133 proxy tests and 493 core library tests pass (two existing manual core tests
ignored), along with all-target proxy clippy and formatting. The two new unit
tests cover bounded batching, prompt return after progress, partial records,
deferred EOF errors and plaintext erasure. Existing forged-frame, authenticated
length, fragmented I/O, backpressure and UDP boundary tests also pass. Ten
additional local integration tests cover pinned Xray and independent sing-box
VMess carriers, TCP/UDP/TUN/DNS/lifecycle, and Xray Mux.

[Full core CI](https://github.com/aimalygin/xray-rust/actions/runs/36940779744) targets this exact runtime; recorded status:
**success**. The first supply-chain
job stopped on a partial crates.io download of `futures-lite` (curl error 18),
after the vendored archive checksums passed. The failed log and original status
are retained; only failed CI work was retried at the same commit. This is not a
source or dependency update. [SDK CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36941828458) recorded status:
**success**. Canonical adapter/source identity checks
pass. ABI 1.8 and 0.8.0-rc.1 metadata are unchanged.

The [archive index](evidence-index.json) authenticates each archived numeric
result, manifest, attempted block, rejected patch, diagnostic trace and test log.
Generated fixture credentials and executables remain local. Verification
reconstructs both parity summaries and every control/memory summary, proves
complete-case selection, checks exact runtime/SDK CI identities and the normal
release rebuild digest. Debug benchmark smoke output in test logs is correctness
evidence only.

```sh
python3 docs/benchmarks/results/2026-10-01-v08-batch/data/verify.py \
  --repo "$PWD" --report docs/benchmarks/results/2026-10-01-v08-batch \
  --rebuild target/v08-comparison-driver/release/xray-rust
```

Physical Apple testing remains deferred by the owner; Android hardware and
candidate-bound publication artifacts remain outstanding. These host results
do not inherit earlier device evidence or establish mobile battery performance.
