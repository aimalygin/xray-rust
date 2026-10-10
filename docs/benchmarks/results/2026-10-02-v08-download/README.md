# Bounded VMess download batching — Apple M3 Pro

The retained combination improves one-flow AES download in two ordinary-release campaigns. A 16 KiB ciphertext read-ahead floor after 64 KiB of authenticated TCP payload and a four-record output batch reduce both socket read and write calls. The five-repeat confirmation improves AES one-flow throughput 12.3% and CPU 14.3%. Neither standalone variant justifies selection on its own. The cost is real: about **12 MiB additional retained RSS at 512 connections after large exchanges**; the short-exchange campaign shows no increase.

## Identity and scope

- Measured/committed runtime: `9198a8f2770496199022b531b01b3a2b35ec1bcc`, tree `62ed0279dda3b0b94312bf0a806fc9eb4bf0a01b`.
- Ordinary release SHA-256: `528e6532d6919bc867dc0c7993bc090125ed3a725c0ebbc12db02791f60ff8e8`; committed rebuild is byte-identical.
- Baseline: `f930d10dba9831315cc16a709576f521a322dea5` from the [previous upload optimization](../2026-10-01-v08-send/README.md), including its existing read/write buffering.
- Same frozen harness, Xray-core v26.7.28 and sing-box 1.13.20 as that report. Complete compiler, source patches and executable identities are in [inputs](data/inputs.json).
- M3 Pro/macOS desktop SOCKS loopback; stock worker counts, verified 256 MiB per direction per flow, one/eight flows, rotating client order. All attempts and every repetition are retained. This is an interactive desktop, not an isolated CPU or device-energy measurement. Absolute numbers from different campaigns/dates are not interchangeable.

## Retained behavior and memory bounds

TCP emits at most four record fragments per poll and at most four local maximum payloads (below 32 KiB). The byte bound also handles a peer sending larger legal records, so the default adaptive relay cannot grow past 32 KiB on this read path. Already available bytes return immediately if the next record would block; no batching timer is introduced. UDP retains a whole datagram per read and never enables the read-ahead floor.

The existing ciphertext allocation gains a 16 KiB floor only after decoding 64 KiB of authenticated TCP payload in total. This threshold is cumulative over the connection, not a sustained-throughput detector. Growth occurs on a later socket read after consumed plaintext has been erased; the floor never requires reading 16 KiB before returning a complete record. Maximum accepted peer record sizes, authentication, nonce allocation and fail-closed behavior remain unchanged. No global pool or second plaintext buffer is introduced. Large legal peer records retain the pre-existing larger frame allowance.

## Five-repeat download confirmation

CPU means process CPU time for verified work, not instantaneous utilization. The harness CPU counter has 10 ms granularity. All samples, minima and maxima are in [control summaries](data/control-summary.json).

| Cipher / flows | CPU ms, baseline → combined | CPU change | MiB/s, baseline → combined | Speed change |
| --- | ---: | ---: | ---: | ---: |
| aes128 / 1 | 210 → 180 | -14.3% | 1484.1 → 1666.0 | +12.3% |
| aes128 / 8 | 1580 → 1500 | -5.1% | 2285.4 → 2300.5 | +0.7% |
| chacha20 / 1 | 350 → 330 | -5.7% | 655.4 → 673.5 | +2.8% |
| chacha20 / 8 | 2520 → 2390 | -5.2% | 1548.4 → 1627.0 | +5.1% |

One-flow AES baseline throughput ranges 1457–1507 MiB/s; combined ranges 1590–1738. CPU is 210 ms in all five baseline repeats, versus 160–190 ms combined. The earlier three-way campaign gives a larger one-flow gain (1401.5 → 1742.5 MiB/s, 220 → 170 ms); the smaller independent confirmation is the headline result. Eight-flow AES throughput is essentially unchanged. Upload and duplex exploratory results are mixed/small and do not establish a general improvement.

The input-only variant has only small download changes and an eight-flow AES duplex slowdown in its first campaign. Output-only gains do not consistently repeat: single AES download is 1446.1 → 1503.3 MiB/s initially, but 1484.1 → 1476.1 in confirmation. Both complete standalone campaigns remain archived; selection is the combination, not a claim that every individual change wins.

## Short requests

Three paired repeats cover TCP request/response and UDP for both ciphers and flow counts. Typical latency medians differ by 0–3 µs. Tail changes are mixed:

| Case | p95 µs, baseline → combined | Change |
| --- | ---: | ---: |
| aes128 / tcp-latency-1 | 240 → 232 | -3.3% |
| aes128 / tcp-latency-8 | 317 → 328 | +3.5% |
| aes128 / udp-1 | 322 → 295 | -8.4% |
| aes128 / udp-8 | 360 → 369 | +2.5% |
| chacha20 / tcp-latency-1 | 238 → 233 | -2.1% |
| chacha20 / tcp-latency-8 | 317 → 350 | +10.4% |
| chacha20 / udp-1 | 307 → 323 | +5.2% |
| chacha20 / udp-8 | 399 → 376 | -5.8% |

The initial ChaCha TCP eight-flow p95 increase prompted a separate five-repeat check: **310 → 309 µs (-0.3%)**. Both series, including every p99 and CPU value, remain in the summaries. These small desktop samples do not establish strict latency parity or a general latency improvement.

The first latency campaign stopped after three completed trials because the observer saw unrelated `xcodebuild` activity. All three are excluded from accepted performance results and archived under `latency-controls-rejected-1`; no protocol trial failed. The entire campaign was repeated after 30 consecutive compiler-free samples. No compilation overlaps accepted campaigns.

## Held memory

Each fresh client holds 0/32/128/512 verified connections, with five RSS samples at each point and three rotating repeats. `small-memory` exchanges 8 KiB in each direction per connection; `bulk-memory` exchanges 1 MiB. Numbers below are median settled RSS at 512 connections, in MiB.

| Exchange / cipher | Baseline | Output-only | Combined | Combined delta |
| --- | ---: | ---: | ---: | ---: |
| small-memory / vmess-aes128 | 27.891 | 27.828 | 27.828 | -0.062 |
| small-memory / vmess-chacha20 | 27.844 | 27.797 | 27.797 | -0.047 |
| bulk-memory / vmess-aes128 | 96.500 | 104.547 | 108.469 | +11.969 |
| bulk-memory / vmess-chacha20 | 96.453 | 104.391 | 108.312 | +11.859 |

Combined bulk RSS rises about 12.3–12.4%, on top of earlier retained buffering costs already present in baseline `f930d10`. Short 8 KiB exchanges differ by less than 0.1 MiB. These are retained process-memory measurements after traffic, not a claim of zero allocation cost or a device memory acceptance result. The previous rejected 16-record receive variant remains excluded.

## Separate call census

Twelve injected-counter trials cover single-flow AES download on all four frozen versions, three repeats each. **Only counts are used**; instrumented CPU, timing and RSS are excluded from performance claims. The calibrated counter library is the one from the [preceding census](../2026-10-01-v08-census/README.md).

| Version | Receive calls (`recvfrom`) | Socket write-family calls |
| --- | ---: | ---: |
| baseline | 36,878 | 18,586 |
| input-only | 18,465 | 18,458 |
| output-only | 36,885 | 9,435 |
| combined | 18,464 | 9,309 |

`recv` forwards to `recvfrom`, and `send` to `sendto`; wrappers are not double-counted. These are libc entry counts, not a complete kernel syscall trace or a per-call CPU attribution. They establish that the combination roughly halves both read and write calls; the separate normal-release controls establish the speed/CPU effect.

## Fresh three-client comparison

All 270 VMess trials pass: AES, ChaCha and auto × upload/download/full-duplex/TCP latency/UDP × one/eight flows × three clients × three repeats. Rust has lower RSS in **60/60** reference comparisons and meets **32/36** bulk CPU and **26/36** bulk throughput point targets under the explicit 3% desktop allowance. Overall parity remains **not_met**. Point medians do not waive interval uncertainty, startup/tail deficits or device acceptance.

| AES traffic / flows | Rust CPU ms | Xray CPU ms | sing-box CPU ms | Rust MiB/s | Xray MiB/s | sing-box MiB/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| upload-1 | 160 | 160 | 180 | 1987.3 | 2018.3 | 1814.9 |
| download-1 | 170 | 140 | 290 | 1971.2 | 2091.3 | 1212.6 |
| full-duplex-1 | 310 | 270 | 410 | 2180.8 | 2749.3 | 1838.3 |
| upload-8 | 1030 | 1910 | 1830 | 3819.5 | 2836.7 | 2732.0 |
| download-8 | 1180 | 2090 | 2950 | 3017.3 | 2485.8 | 1983.4 |
| full-duplex-8 | 2410 | 3060 | 3730 | 1907.2 | 1847.1 | 1674.1 |

See [strict results](data/summary-strict.json) and [3% results with intervals](data/summary-mac-3pct.json). Earlier Trojan/SS2022 reports retain their original runtime identities; they are not relabeled as measurements of this runtime.

## Verification and remaining gates

139 protocol tests, 493 core library tests (two existing manual tests ignored), formatting/Clippy and ten Xray/sing-box carrier, routing/DNS/TUN, lifecycle and Xray Mux integration tests pass. New tests cover deferred read-ahead allocation, coalesced reads without fill waits, the authenticated TCP threshold/UDP exclusion and large peer records with bounded TCP output and intact UDP.

[Full exact-runtime CI](https://github.com/aimalygin/xray-rust/actions/runs/37010970531) and [SDK CI](https://github.com/aimalygin/xray-rust-mobile/actions/runs/37011053907) pass. SDK `7b84921501348dc462d7b3527d09becb3bf86492` pins the measured core; canonical source and release metadata checks pass. ABI 1.8 and 0.8.0-rc.1 metadata are unchanged. Physical Apple acceptance remains deferred, Android hardware unavailable, and publication artifact locks unprepared. No release, device energy, WAN or TUN performance parity is claimed.

The archive contains **316 accepted normal paired trials**, **36 held-memory clients**, **12 diagnostic trials**, **270 fresh reference trials**, and the excluded latency attempt. Independent verification rehashes every member, reconstructs all summaries/selections, checks payload conservation and ties the release digest to the exact core/SDK CI identities. Generated connection credentials/configs and executables are excluded from the public archive.

```sh
python3 docs/benchmarks/results/2026-10-02-v08-download/data/verify.py \
  --repo "$PWD" --report docs/benchmarks/results/2026-10-02-v08-download \
  --rebuild target/v08-comparison-driver/release/xray-rust
```
