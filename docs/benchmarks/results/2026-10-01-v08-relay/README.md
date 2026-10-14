# Relay allocations and VMess padding follow-up — Apple M3 Pro

Runtime `fdc0dad1aa1ffe39d3621008ab66512b30ccf452`, tree `fec66ef23ea8512f97c123d090ca889a1501b77e`;
release executable SHA-256 `1ed77d5b5afbf4fe466dde699442d3d6938c8e7ffd12b20f5cf987ab355c797d`. The SDK pins this
runtime at `874cc8e8103ade25b8ea3e53938e826431a9aeee`. Rust 1.96.0, locked release build,
incremental compilation disabled; rebuilding the committed source reproduces
the frozen executable. Host: M3 Pro, 12 cores, 18 GiB, macOS 26.6.2, AC power.

The baseline is `5e32972976074551aea4ce42e98f5e0dde7159c9`, already optimized for
ARM AEAD, bounded record buffers, coalesced reads and plaintext erasure. See the
[preceding report](../2026-10-01-v08-io/README.md). The harness, Xray-core v26.7.28
and sing-box 1.13.20 pins and binaries are unchanged; their exact identities
are retained in [inputs](data/inputs.json). These are local SOCKS loopback results,
not physical-device, battery, TUN or WAN measurements.

## What was retained and rejected

- The shared TCP relay pins the two copy futures and idle sleep inside its
  enclosing task rather than allocating three separate boxes. The original
  activity channel, `tokio::select!` polling behavior and timer resets are
  retained, along with buffer growth/caps, flush thresholds, two CLI workers,
  traffic accounting and half-close behavior. Tokio split wrappers also remain.
  A larger relay rewrite using a flag, alternating polling and lazy timer resets
  saved 8–12% settled RSS at 512 connections, but reduced one-flow SS2022 ChaCha
  duplex throughput from about 954 to 863 MiB/s. It was rejected. The conservative
  variant restores that case to 953 vs baseline 953 MiB/s; its own final memory
  measurements, rather than the rejected variant's savings, are reported below.
- Only VMess **ChaCha20-Poly1305 record padding** reads OS randomness in 256-byte
  batches, held in one zeroizing thread-local array. No cache is allocated per
  connection. A failed refill exposes no bytes and forces another fresh refill.
  Session keys, IVs, authentication material, padding lengths, nonces and wire
  framing retain their previous paths. This is entropy batching, not a new cipher
  or pseudorandom generator.
- Replacing padding's OS source with the already linked AWS-LC RNG was rejected:
  the isolated 54-trial experiment increased one-flow upload CPU by 26–29% and
  raised RSS. Its results and source patch are retained.
- Applying the 256-byte cache to AES was also rejected. Seven further paired
  eight-flow AES upload repeats show baseline **2939 MiB/s / 1370 ms CPU**,
  relay alone **2947 / 1370**, but AES padding batching **2157 / 1520**. The
  roughly 27% throughput regression is repeatable despite a one-flow gain.
  The deeper scheduling/socket-pacing cause has not been established; no blanket
  claim that fewer entropy calls always improve throughput is made. A separate
  five-repeat one-flow AES download check shows relay 1550 vs baseline 1510 MiB/s,
  with overlapping ranges and CPU 210 vs 220 ms.

The first batching campaign stopped after 48 runs when its observer detected an
external `xcodebuild` during a trial. That entire group remains archived and is
excluded from performance conclusions. The fresh 108-trial group completed with
no compiler overlap. A later intermediate final-control campaign stopped after
82 runs on an active `ANECompilerService`. Complete clean case blocks were
retained; the affected incomplete case was rerun in full. The block collector
retains original case indexes/client rotation and retries a whole case (all
clients and repeats) only for observed compiler interference, at most three
times. Protocol errors, process leaks and observer failures are never retried.
The final three-client matrix likewise rejected two compiler-contaminated attempts of the eight-flow SS2022 ChaCha duplex case. Its third complete attempt was clean; both exclusions and the accepted replacement remain identified in `full/selection.json`. Every attempt and the selection map are archived. This is a predeclared
measurement-quality rule, not selection by favorable performance. Nine native `sample` runs are diagnostic only: stripped Rust
frames cannot identify detailed Rust hotspots, and their timings are never used
as benchmark evidence. Visible entropy calls motivated a hypothesis; controlled
trials, rather than sampled wall-time percentages, selected the implementation.

## Paired final results

144 fresh-client trials, three rotating repeats, four profiles, one/eight flows,
upload/download/full duplex. Each flow verifies 256 MiB per direction. CPU is
client CPU for completed work, not utilization; 10 ms counter granularity limits
small differences. RSS is sampled at 100 ms and excludes server, driver and kernel
socket memory. This is an interactive desktop with ordinary OS/GUI activity,
not a CPU-isolated host; small point differences should be read with their
three-repeat ranges. Compilation, tests, profiling and compression do not overlap
the accepted measurements. All medians, ranges, samples and startup CPU are retained
in the [control summary](data/control-summary.json).

| Profile / flows / traffic | CPU ms, old → new | CPU change | MiB/s, old → new | Speed change | Peak RSS MiB, old → new |
| --- | ---: | ---: | ---: | ---: | ---: |
| ss2022-aes128 / 1 / upload | 120 → 130 | +8.3% | 1554 → 1605 | +3.3% | 5.359 → 5.359 |
| ss2022-aes128 / 1 / download | 160 → 160 | +0.0% | 2105 → 2129 | +1.1% | 5.406 → 5.391 |
| ss2022-aes128 / 1 / full-duplex | 290 → 300 | +3.4% | 2187 → 2084 | -4.7% | 5.516 → 5.516 |
| ss2022-aes128 / 8 / upload | 1520 → 1520 | +0.0% | 1869 → 1843 | -1.4% | 6.688 → 6.625 |
| ss2022-aes128 / 8 / download | 1430 → 1440 | +0.7% | 2442 → 2490 | +1.9% | 6.469 → 6.484 |
| ss2022-aes128 / 8 / full-duplex | 2650 → 2580 | -2.6% | 1600 → 1544 | -3.5% | 7.641 → 7.578 |
| ss2022-chacha20 / 1 / upload | 280 → 280 | +0.0% | 586 → 589 | +0.5% | 5.234 → 5.234 |
| ss2022-chacha20 / 1 / download | 340 → 330 | -2.9% | 719 → 752 | +4.6% | 5.281 → 5.266 |
| ss2022-chacha20 / 1 / full-duplex | 610 → 610 | +0.0% | 953 → 953 | -0.0% | 5.422 → 5.422 |
| ss2022-chacha20 / 8 / upload | 2410 → 2400 | -0.4% | 1582 → 1609 | +1.7% | 6.625 → 6.562 |
| ss2022-chacha20 / 8 / download | 1900 → 1850 | -2.6% | 2093 → 2206 | +5.4% | 6.438 → 6.312 |
| ss2022-chacha20 / 8 / full-duplex | 4260 → 4220 | -0.9% | 1893 → 1911 | +0.9% | 7.453 → 7.438 |
| vmess-aes128 / 1 / upload | 250 → 250 | +0.0% | 1338 → 1335 | -0.3% | 5.516 → 5.469 |
| vmess-aes128 / 1 / download | 220 → 220 | +0.0% | 1541 → 1559 | +1.2% | 5.328 → 5.328 |
| vmess-aes128 / 1 / full-duplex | 440 → 420 | -4.5% | 1538 → 1582 | +2.8% | 5.531 → 5.531 |
| vmess-aes128 / 8 / upload | 1310 → 1330 | +1.5% | 3102 → 3088 | -0.5% | 6.766 → 6.734 |
| vmess-aes128 / 8 / download | 1470 → 1460 | -0.7% | 2467 → 2483 | +0.7% | 5.750 → 5.672 |
| vmess-aes128 / 8 / full-duplex | 2960 → 2860 | -3.4% | 1741 → 1743 | +0.1% | 6.875 → 6.859 |
| vmess-chacha20 / 1 / upload | 300 → 270 | -10.0% | 765 → 757 | -1.0% | 5.484 → 5.484 |
| vmess-chacha20 / 1 / download | 350 → 360 | +2.9% | 690 → 674 | -2.4% | 5.297 → 5.312 |
| vmess-chacha20 / 1 / full-duplex | 700 → 670 | -4.3% | 762 → 803 | +5.4% | 5.484 → 5.453 |
| vmess-chacha20 / 8 / upload | 2290 → 2110 | -7.9% | 1779 → 1941 | +9.1% | 6.734 → 6.766 |
| vmess-chacha20 / 8 / download | 2180 → 2150 | -1.4% | 1876 → 1898 | +1.2% | 5.688 → 5.672 |
| vmess-chacha20 / 8 / full-duplex | 4540 → 4270 | -5.9% | 1797 → 1913 | +6.5% | 6.859 → 6.844 |

The initial SS2022 AES duplex medians were 4.7% and 3.5% slower (one/eight flows), with overlapping ranges. A separate five-repeat paired confirmation was added to investigate that concern; it does not replace the original controls. All 20 trials passed without compiler interference.

| SS2022 AES duplex confirmation | CPU ms, old → new | MiB/s, old → new | Speed change |
| --- | ---: | ---: | ---: |
| 1 flow | 280 → 280 | 2208 → 2194 | -0.6% |
| 8 flows | 2660 → 2590 | 1588 → 1701 | +7.1% |

The earlier 3–5% slowdown did not reproduce in this confirmation. The one-flow result is essentially unchanged; the eight-flow point improves with partly overlapping ranges. These controls support retaining the conservative allocation change, while the full original samples remain visible.

## Memory scaling

Each of 24 fresh final-control clients holds 0, 32, 128 and 512 connections. Each connection first echoes 8192 verified bytes in each direction. Five RSS samples per point and three rotating client repeats are retained. These are settled RSS measurements, not saturated-transfer peaks. Earlier three-variant memory controls (36 clients) are also archived.

| Profile | 0 connections, old → new MiB | 32 | 128 | 512 | 512 delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| ss2022-aes128 | 4.250 → 4.250 | 6.953 → 6.891 | 11.156 → 11.031 | 27.719 → 27.375 | -0.344 MiB (-1.2%) |
| ss2022-chacha20 | 4.250 → 4.266 | 6.797 → 6.812 | 11.031 → 10.891 | 27.609 → 27.250 | -0.359 MiB (-1.3%) |
| vmess-aes128 | 4.250 → 4.250 | 7.141 → 7.031 | 11.375 → 11.234 | 28.312 → 27.906 | -0.406 MiB (-1.4%) |
| vmess-chacha20 | 4.234 → 4.234 | 7.078 → 7.016 | 11.344 → 11.219 | 28.234 → 27.844 | -0.391 MiB (-1.4%) |

## Frozen three-client comparison

630/630 trials pass, including 210/210 Rust trials. Seven profiles × five workloads × one/eight flows × three clients × three repeats. No failed or contaminated run is silently replaced. See [all medians](comparison.csv), the [strict summary](data/summary-strict.json) and the [3% Mac summary](data/summary-mac-3pct.json); the allowance never waives lower-RSS requirements or incomplete trials.

| VMess profile / flows / traffic | Rust CPU ms / MiB/s / RSS MiB | Xray-core | sing-box |
| --- | ---: | ---: | ---: |
| vmess-aes128 / upload-1 | 250 / 1349 / 5.52 | 150 / 1975 / 32.45 | 180 / 1767 / 26.78 |
| vmess-aes128 / download-1 | 220 / 1498 / 5.31 | 120 / 2105 / 32.67 | 280 / 1176 / 26.66 |
| vmess-aes128 / full-duplex-1 | 440 / 1480 / 5.52 | 290 / 2557 / 33.41 | 440 / 1708 / 27.61 |
| vmess-aes128 / upload-8 | 1390 / 2914 / 6.77 | 1920 / 2557 / 36.89 | 1900 / 2506 / 31.62 |
| vmess-aes128 / download-8 | 1610 / 2203 / 5.69 | 2190 / 2256 / 36.80 | 2960 / 1783 / 29.59 |
| vmess-aes128 / full-duplex-8 | 3290 / 1582 / 6.88 | 3340 / 1658 / 37.75 | 3880 / 1593 / 32.53 |
| vmess-chacha20 / upload-1 | 280 / 755 / 5.48 | 420 / 691 / 32.52 | 470 / 666 / 27.05 |
| vmess-chacha20 / download-1 | 350 / 688 / 5.31 | 390 / 720 / 32.91 | 600 / 551 / 27.03 |
| vmess-chacha20 / full-duplex-1 | 670 / 802 / 5.50 | 740 / 1422 / 34.72 | 1000 / 1088 / 27.98 |
| vmess-chacha20 / upload-8 | 2220 / 1823 / 6.70 | 3950 / 2438 / 39.56 | 4060 / 2349 / 33.11 |
| vmess-chacha20 / download-8 | 2290 / 1772 / 5.67 | 3630 / 2454 / 39.83 | 5150 / 1852 / 31.38 |
| vmess-chacha20 / full-duplex-8 | 4560 / 1777 / 6.84 | 7560 / 2335 / 52.73 | 9020 / 1992 / 35.08 |

RSS meets the strictly-lower target in 140/140 complete comparisons. SS2022/VMess meet 57/72 bulk CPU and 26/72 throughput point targets under the 3% Mac policy. Overall parity: **not met**. Point targets and three-repeat uncertainty are not universal speed claims.

## Validation and reproduction

493 core library tests pass (two existing manual tests ignored), as do 131 proxy tests and all-target clippy. Added tests cover bidirectional idle renewal, half-close with backpressure/counters, reverse progress during a blocked write, padding cache boundaries and entropy failure. [Full core CI](https://github.com/aimalygin/xray-rust/actions/runs/36917373651) and [SDK CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/36917477895) pass at the recorded source commits. ABI 1.8, dependency locks, worker defaults and record/relay buffer limits are unchanged.

The first Linux Rust CI attempt failed in the existing FFI descriptor-reuse test, before freeing the core. The test explicitly closed the destination before `dup2`, allowing other test threads to allocate the number in between. `dup2` already performs an atomic close/replacement ([Linux documentation](https://man7.org/linux/man-pages/man2/dup.2.html)); the follow-up test-only patch removes that gap and adds OS-error diagnostics. The original run did not print errno, so a specific kernel error is not established. Its failure log and initial CI snapshot are retained. The exact-runtime rerun passed. The corrected FFI suite passes locally: 86 tests plus ten further full-suite repeats with 16 test threads. The fixture-only commit `9c16a656c4102b150b744f652e1286fe96203cec` is checked separately by the [PR Rust job](https://github.com/aimalygin/xray-rust/actions/runs/36922034515). The verifier requires its Rust/secrets jobs to pass and proves that this commit changes only the test file; production platform validation comes from the complete exact-runtime CI. Full first-attempt status is retained in `data/ci-attempt-1-final.json`. Runtime source and the measured executable are unchanged by this test correction.

The archive contains exact numeric results and manifests, source patches for rejected variants, diagnostic samples and build/test logs. Ephemeral server credentials and executables remain local. The archive index authenticates every member. The verification script reconstructs both parity summaries and every control summary from the archive and checks the committed release digest and CI identities. Debug benchmark smoke output in test logs is correctness evidence only. Scanner guards, post-fixture clippy and the byte-identical rebuild logs are retained in `data/`.

```sh
python3 docs/benchmarks/results/2026-10-01-v08-relay/data/verify.py \
  --repo "$PWD" --report docs/benchmarks/results/2026-10-01-v08-relay \
  --rebuild target/v08-comparison-driver/release/xray-rust
```

Physical Apple testing remains deferred by the owner; Android hardware and publication artifacts remain outstanding. Earlier candidate device evidence is not inherited by this runtime.
